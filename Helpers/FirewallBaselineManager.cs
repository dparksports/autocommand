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
            public Dictionary<string, bool> Rules { get; set; } = new Dictionary<string, bool>();
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
        private static BaselineFile _cache;

        private static bool IsOwnBlockRuleName(string name) =>
            !string.IsNullOrEmpty(name) && (
                name.StartsWith(FirewallService.NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith(FirewallService.NewAppPrefix, StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("AutoCommand IP Block - ", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("AutoCommand Process Block - ", StringComparison.OrdinalIgnoreCase));

        public static bool HasBaseline => GetCachedBaseline() != null;

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
            lock (_gate)
            {
                var b = GetCachedBaseline();
                if (b == null || string.IsNullOrEmpty(ruleName)) return; // no baseline yet — nothing to adopt into
                b.Rules[ruleName] = enabled;
                SaveBaseline(b);
            }
        }

        /// <summary>
        /// Applies post-toggle rule states captured during a single-pass firewall
        /// toggle directly into the cached baseline with ZERO extra COM scans.
        /// Updates in-memory state immediately so SecurityEnforcer sees it at once,
        /// and persists firewall_baseline.json off the UI thread.
        /// </summary>
        public static Task ApplyToggleSnapshotAsync(AutoCommand.Engines.Firewall.TargetToggleSnapshot snap)
        {
            if (snap == null || snap.RuleStates == null || snap.RuleStates.Count == 0)
                return Task.CompletedTask;
            if (GetCachedBaseline() == null) return Task.CompletedTask;

            return Task.Run(() => ApplyBlockRuleStatesCore(snap.RuleStates, snap.IsFullSnapshot));
        }

        private static void ApplyBlockRuleStatesCore(
            IEnumerable<(string Name, bool Enabled)> liveStates,
            bool isFullSnapshot)
        {
            var b = GetCachedBaseline();
            if (b == null) return;
            lock (_gate)
            {
                bool dirty = false;
                HashSet<string> liveNames = isFullSnapshot
                    ? new HashSet<string>(StringComparer.Ordinal)
                    : null;

                foreach (var (name, enabled) in liveStates)
                {
                    if (string.IsNullOrEmpty(name) || !IsOwnBlockRuleName(name)) continue;
                    liveNames?.Add(name);
                    if (!b.Rules.TryGetValue(name, out bool prev) || prev != enabled)
                    {
                        b.Rules[name] = enabled;
                        dirty = true;
                    }
                }

                if (isFullSnapshot)
                {
                    // Prune deleted/retired AutoCommand block rules so permanent
                    // unblocks, legacy consolidation and dedup keep baseline clean.
                    var staleOwn = b.Rules.Keys
                        .Where(k => IsOwnBlockRuleName(k) && !liveNames.Contains(k))
                        .ToList();
                    foreach (string gone in staleOwn)
                    {
                        b.Rules.Remove(gone);
                        dirty = true;
                    }
                }

                if (dirty) SaveBaseline(b);
            }
        }

        /// <summary>
        /// Adopts the current live Enabled state of all AutoCommand block rules into
        /// the baseline (no-op when no baseline exists). Prevents SecurityEnforcer's
        /// 60s drift check from reverting intentional block pauses or restores made
        /// in the Blocks tab or via Restore Internet.
        /// </summary>
        public static Task AdoptLiveBlockRulesAsync()
        {
            if (GetCachedBaseline() == null) return Task.CompletedTask;
            return Task.Run(() =>
            {
                if (GetCachedBaseline() == null) return;
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
            return Task.Run(() =>
            {
                var b = GetCachedBaseline();
                if (b == null || string.IsNullOrEmpty(group)) return;
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
                    lock (_gate)
                    {
                        foreach (string name in matchedNames)
                            b.Rules[name] = enabled;
                        if (matchedNames.Count > 0) SaveBaseline(b);
                    }
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
                var b = GetCachedBaseline();
                return b == null ? null : (b.CapturedAt, b.Rules.Count);
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
                var rules = new Dictionary<string, bool>(StringComparer.Ordinal);
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
                lock (_gate)
                {
                    SaveBaseline(file);
                    _cache = file;
                }
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
                    var baseline = GetCachedBaseline();
                    if (baseline == null) return report;
                    baselineRules = new Dictionary<string, bool>(baseline.Rules, StringComparer.Ordinal);
                }
                report.BaselineCount = baselineRules.Count;

                try
                {
                    var fwPolicy = AutoCommand.Engines.Firewall.Com.getPolicy2();
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var rule in AutoCommand.Engines.Firewall.Com.enumRules(fwPolicy.Rules))
                    {
                        try
                        {
                            string name = rule.Name;
                            if (string.IsNullOrEmpty(name)) continue;
                            bool enabled = rule.Enabled;
                            if (!seen.Add(name)) continue;

                            if (!baselineRules.TryGetValue(name, out bool expected))
                            {
                                if (enabled)
                                {
                                    string group = "";
                                    try { group = rule.Grouping ?? ""; } catch { }
                                    report.SneakedIn.Add(Tuple.Create(name, group));
                                }
                                continue;
                            }

                            if (!expected && enabled)
                                report.ReEnabled.Add(name);
                            else if (expected && !enabled)
                                report.UnexpectedlyDisabled.Add(name);
                        }
                        catch { }
                    }
                    report.LiveCount = seen.Count;
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
            var targets = new HashSet<string>(ruleNames, StringComparer.Ordinal);
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

        private static BaselineFile GetCachedBaseline()
        {
            if (_cache != null) return _cache;
            try
            {
                if (File.Exists(BaselinePath))
                {
                    _cache = JsonSerializer.Deserialize<BaselineFile>(File.ReadAllText(BaselinePath));
                }
            }
            catch { }
            return _cache;
        }

        private static void SaveBaseline(BaselineFile file)
        {
            try
            {
                var dir = Path.GetDirectoryName(BaselinePath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(BaselinePath, JsonSerializer.Serialize(file, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }
    }
}
