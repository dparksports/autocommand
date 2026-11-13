using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Whole-firewall baseline: the expected enabled/disabled state of every rule,
    /// captured after applying a profile (or manually via Re-baseline). Windows
    /// Update and reboots re-enable disabled rules and provision new ones —
    /// comparing live state against the baseline detects both.
    /// </summary>
    public static class FirewallBaselineManager
    {
        private sealed class BaselineFile
        {
            public DateTime CapturedAt { get; set; }
            public Dictionary<string, bool> Rules { get; set; } = FirewallBaselineLogic.CreateRulesMap();
        }

        public sealed class DriftReport
        {
            /// <summary>Rules the baseline expects disabled but which are now enabled.</summary>
            public List<string> ReEnabled { get; } = new List<string>();
            /// <summary>Rules the baseline expects enabled but which are now disabled.</summary>
            public List<string> UnexpectedlyDisabled { get; } = new List<string>();
            /// <summary>New rules not present in the baseline that are enabled.</summary>
            public List<Tuple<string, string>> SneakedIn { get; } = new List<Tuple<string, string>>();
            public int BaselineCount { get; set; }
            public int LiveCount { get; set; }
        }

        private static readonly string BaselinePath = Path.Combine(ProgramDataGuard.Root, "firewall_baseline.json");
        private static readonly object _gate = new object();
        private static readonly object _saveGate = new object();
        private static BaselineFile _cache;
        private static long _saveVersion;
        private static long _lastSavedVersion;

        private static bool IsOwnBlockRuleName(string name) =>
            FirewallBaselineLogic.IsOwnBlockRuleName(name);

        public static bool HasBaseline
        {
            get
            {
                lock (_gate)
                    return GetCachedBaselineLocked() != null;
            }
        }

        // While paused, baseline drift is neither fixed nor alerted — for users who
        // want to edit rules externally (wf.msc / netsh) without being fought. The
        // pause auto-expires; re-baseline afterwards to adopt the new state.
        public static DateTime PausedUntilUtc { get; private set; } = DateTime.MinValue;
        public static bool IsPaused => DateTime.UtcNow < PausedUntilUtc;
        public static void PauseForMinutes(int minutes) => PausedUntilUtc = DateTime.UtcNow.AddMinutes(minutes);

        /// <summary>
        /// Adopts a single-rule change made inside the app into the baseline, so the
        /// enforcer enforces the user's intent instead of reverting it.
        /// </summary>
        public static void UpdateRuleState(string ruleName, bool enabled)
        {
            if (string.IsNullOrEmpty(ruleName)) return;
            long version;
            BaselineFile snapshot;
            lock (_gate)
            {
                var b = GetCachedBaselineLocked();
                if (b == null) return; // no baseline yet — nothing to adopt into
                if (b.Rules.TryGetValue(ruleName, out bool prev) && prev == enabled) return;
                b.Rules[ruleName] = enabled;
                version = ++_saveVersion;
                snapshot = CloneBaselineLocked(b);
            }
            SaveBaselineVersioned(version, snapshot);
        }

        /// <summary>
        /// Adopts explicit own-block rule states (e.g. newly added IP/app block
        /// rule names returned directly from AddIpBlockWithRulesAsync /
        /// AddAppBlockWithPathAsync) into the cached baseline in O(1) with ZERO
        /// COM enumerations. Updates in-memory state synchronously under _gate
        /// and persists firewall_baseline.json off the UI thread.
        /// </summary>
        public static Task AdoptRuleStatesAsync(IEnumerable<(string Name, bool Enabled)> ruleStates)
        {
            if (ruleStates == null) return Task.CompletedTask;

            long version = 0;
            BaselineFile snapshot = null;
            lock (_gate)
            {
                var b = GetCachedBaselineLocked();
                if (b == null) return Task.CompletedTask;
                if (FirewallBaselineLogic.ApplyOwnBlockStates(b.Rules, ruleStates, isFullSnapshot: false))
                {
                    version = ++_saveVersion;
                    snapshot = CloneBaselineLocked(b);
                }
            }

            if (snapshot == null) return Task.CompletedTask;
            return Task.Run(() => SaveBaselineVersioned(version, snapshot));
        }

        /// <summary>
        /// Applies post-toggle rule states captured during a single-pass firewall
        /// toggle directly into the cached baseline with ZERO extra COM scans.
        /// Updates in-memory state SYNCHRONOUSLY under _gate so SecurityEnforcer's
        /// drift monitor can never observe stale pre-toggle entries, and persists
        /// firewall_baseline.json off the UI thread.
        /// </summary>
        public static Task ApplyToggleSnapshotAsync(AutoCommand.Engines.Firewall.TargetToggleSnapshot snap)
        {
            if (snap == null || snap.RuleStates == null || snap.RuleStates.Count == 0)
                return Task.CompletedTask;

            long version = 0;
            BaselineFile snapshot = null;
            lock (_gate)
            {
                var b = GetCachedBaselineLocked();
                if (b == null) return Task.CompletedTask;
                if (FirewallBaselineLogic.ApplyOwnBlockStates(b.Rules, snap.RuleStates, snap.IsFullSnapshot))
                {
                    version = ++_saveVersion;
                    snapshot = CloneBaselineLocked(b);
                }
            }

            if (snapshot == null) return Task.CompletedTask;
            return Task.Run(() => SaveBaselineVersioned(version, snapshot));
        }

        private static void ApplyBlockRuleStatesCore(
            IEnumerable<(string Name, bool Enabled)> liveStates,
            bool isFullSnapshot)
        {
            long version = 0;
            BaselineFile snapshot = null;
            lock (_gate)
            {
                var b = GetCachedBaselineLocked();
                if (b == null) return;
                if (FirewallBaselineLogic.ApplyOwnBlockStates(b.Rules, liveStates, isFullSnapshot))
                {
                    version = ++_saveVersion;
                    snapshot = CloneBaselineLocked(b);
                }
            }
            if (snapshot != null)
                SaveBaselineVersioned(version, snapshot);
        }

        /// <summary>
        /// Adopts the current live Enabled state of all AutoCommand block rules into
        /// the baseline (no-op when no baseline exists). Prevents SecurityEnforcer's
        /// 60s drift check from reverting intentional block pauses or restores made
        /// in the Blocks tab or via Restore Internet.
        /// </summary>
        public static Task AdoptLiveBlockRulesAsync()
        {
            if (!HasBaseline) return Task.CompletedTask;
            return Task.Run(() =>
            {
                if (!HasBaseline) return;
                try
                {
                    var liveStates = new List<(string Name, bool Enabled)>();
                    var fwPolicy = AutoCommand.Engines.Firewall.Com.getPolicy2();
                    foreach (var rule in AutoCommand.Engines.Firewall.Com.enumRules(fwPolicy.Rules))
                    {
                        try
                        {
                            string name = rule.Name;
                            if (IsOwnBlockRuleName(name))
                                liveStates.Add((name, rule.Enabled));
                        }
                        catch { }
                    }
                    ApplyBlockRuleStatesCore(liveStates, isFullSnapshot: true);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"FirewallBaseline block-adopt error: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Adopts a group-wide change made inside the app: every live rule in the
        /// group gets its baseline entry set to the new state.
        /// </summary>
        public static Task UpdateGroupStateAsync(string group, bool enabled)
        {
            if (string.IsNullOrEmpty(group)) return Task.CompletedTask;
            return Task.Run(() =>
            {
                if (!HasBaseline) return;
                try
                {
                    var matchedNames = new List<string>();
                    var fwPolicy = AutoCommand.Engines.Firewall.Com.getPolicy2();
                    foreach (var rule in AutoCommand.Engines.Firewall.Com.enumRules(fwPolicy.Rules))
                    {
                        try
                        {
                            string rawGroup = rule.Grouping ?? "";
                            string resolved = string.IsNullOrEmpty(rawGroup)
                                ? ""
                                : FirewallService.ResolveGroupName(rawGroup);
                            if (string.Equals(resolved, group, StringComparison.OrdinalIgnoreCase)
                                || string.Equals(rawGroup, group, StringComparison.OrdinalIgnoreCase))
                            {
                                string name = rule.Name;
                                if (!string.IsNullOrEmpty(name))
                                    matchedNames.Add(name);
                            }
                        }
                        catch { }
                    }
                    if (matchedNames.Count == 0) return;

                    long version = 0;
                    BaselineFile snapshot = null;
                    lock (_gate)
                    {
                        var b = GetCachedBaselineLocked();
                        if (b == null) return;
                        bool dirty = false;
                        foreach (string name in matchedNames)
                        {
                            if (!b.Rules.TryGetValue(name, out bool prev) || prev != enabled)
                            {
                                b.Rules[name] = enabled;
                                dirty = true;
                            }
                        }
                        if (dirty)
                        {
                            version = ++_saveVersion;
                            snapshot = CloneBaselineLocked(b);
                        }
                    }
                    if (snapshot != null)
                        SaveBaselineVersioned(version, snapshot);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"FirewallBaseline group-update error: {ex.Message}");
                }
            });
        }

        public static (DateTime CapturedAt, int Count)? BaselineInfo
        {
            get
            {
                lock (_gate)
                {
                    var b = GetCachedBaselineLocked();
                    return b == null ? null : (b.CapturedAt, b.Rules.Count);
                }
            }
        }

        /// <summary>
        /// Captures the current enabled/disabled state of every firewall rule as the
        /// expected baseline. Call after applying a profile or arranging rules manually.
        /// </summary>
        public static Task<(int Count, DateTime CapturedAt)> CaptureBaselineAsync()
        {
            return Task.Run(() =>
            {
                var rules = FirewallBaselineLogic.CreateRulesMap();
                var fwPolicy = AutoCommand.Engines.Firewall.Com.getPolicy2();
                foreach (var rule in AutoCommand.Engines.Firewall.Com.enumRules(fwPolicy.Rules))
                {
                    try
                    {
                        string name = rule.Name;
                        if (!string.IsNullOrEmpty(name))
                            rules[name] = rule.Enabled;
                    }
                    catch { }
                }

                var file = new BaselineFile { CapturedAt = DateTime.Now, Rules = rules };
                long version;
                BaselineFile snapshot;
                lock (_gate)
                {
                    _cache = file;
                    version = ++_saveVersion;
                    snapshot = CloneBaselineLocked(file);
                }
                SaveBaselineVersioned(version, snapshot);
                return (rules.Count, file.CapturedAt);
            });
        }

        /// <summary>
        /// Compares live rule state against the baseline. Always returns a report;
        /// without a baseline the lists stay empty.
        /// </summary>
        public static Task<DriftReport> GetDriftAsync()
        {
            return Task.Run(() =>
            {
                var report = new DriftReport();
                Dictionary<string, bool> baselineRules;
                lock (_gate)
                {
                    var baseline = GetCachedBaselineLocked();
                    if (baseline == null) return report;
                    baselineRules = FirewallBaselineLogic.CreateRulesMap(baseline.Rules);
                }
                report.BaselineCount = baselineRules.Count;

                try
                {
                    var fwPolicy = AutoCommand.Engines.Firewall.Com.getPolicy2();
                    var liveRules = new List<(string Name, bool Enabled, string Grouping)>();
                    foreach (var rule in AutoCommand.Engines.Firewall.Com.enumRules(fwPolicy.Rules))
                    {
                        try
                        {
                            string name = rule.Name;
                            if (string.IsNullOrEmpty(name)) continue;
                            bool enabled = rule.Enabled;
                            string group = "";
                            if (enabled && !baselineRules.ContainsKey(name))
                            {
                                try { group = rule.Grouping ?? ""; } catch { }
                            }
                            liveRules.Add((name, enabled, group));
                        }
                        catch { }
                    }

                    var eval = FirewallBaselineLogic.EvaluateDrift(baselineRules, liveRules);
                    report.ReEnabled.AddRange(eval.ReEnabled);
                    report.UnexpectedlyDisabled.AddRange(eval.UnexpectedlyDisabled);
                    report.SneakedIn.AddRange(eval.SneakedIn);
                    report.LiveCount = eval.LiveCount;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"FirewallBaseline drift error: {ex.Message}");
                }
                return report;
            });
        }

        /// <summary>Disables the named rules back to their baseline state. Returns how many were flipped.</summary>
        public static Task<int> ReDisableAsync(IEnumerable<string> ruleNames)
        {
            return Task.Run(() => SetEnabledState(ruleNames, false));
        }

        /// <summary>Re-enables the named rules back to their baseline state. Returns how many were flipped.</summary>
        public static Task<int> RestoreEnableAsync(IEnumerable<string> ruleNames)
        {
            return Task.Run(() => SetEnabledState(ruleNames, true));
        }

        private static int SetEnabledState(IEnumerable<string> ruleNames, bool enabled)
        {
            if (ruleNames == null) return 0;
            var targets = new HashSet<string>(ruleNames, StringComparer.OrdinalIgnoreCase);
            if (targets.Count == 0) return 0;
            int changed = 0;
            try
            {
                var fwPolicy = AutoCommand.Engines.Firewall.Com.getPolicy2();
                foreach (var rule in AutoCommand.Engines.Firewall.Com.enumRules(fwPolicy.Rules))
                {
                    try
                    {
                        string name = rule.Name;
                        if (string.IsNullOrEmpty(name) || !targets.Contains(name)) continue;
                        if (rule.Enabled != enabled)
                        {
                            rule.Enabled = enabled;
                            if (rule.Enabled == enabled)
                                changed++;
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"FirewallBaseline set-state error: {ex.Message}");
            }
            return changed;
        }

        private static BaselineFile CloneBaselineLocked(BaselineFile source) =>
            new BaselineFile
            {
                CapturedAt = source.CapturedAt,
                Rules = FirewallBaselineLogic.CreateRulesMap(source.Rules)
            };

        private static BaselineFile GetCachedBaselineLocked()
        {
            if (_cache != null) return _cache;
            try
            {
                if (File.Exists(BaselinePath))
                {
                    var loaded = JsonSerializer.Deserialize<BaselineFile>(File.ReadAllText(BaselinePath));
                    if (loaded != null)
                    {
                        loaded.Rules = FirewallBaselineLogic.CreateRulesMap(loaded.Rules);
                        _cache = loaded;
                    }
                }
            }
            catch { }
            return _cache;
        }

        private static void SaveBaselineVersioned(long version, BaselineFile snapshot)
        {
            if (snapshot == null) return;
            lock (_saveGate)
            {
                if (version < _lastSavedVersion) return;
                try
                {
                    var dir = Path.GetDirectoryName(BaselinePath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    string json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });
                    string tmp = BaselinePath + ".tmp";
                    File.WriteAllText(tmp, json);
                    if (File.Exists(BaselinePath))
                        File.Replace(tmp, BaselinePath, destinationBackupFileName: null);
                    else
                        File.Move(tmp, BaselinePath);
                    _lastSavedVersion = version;
                }
                catch { }
            }
        }
    }
}
