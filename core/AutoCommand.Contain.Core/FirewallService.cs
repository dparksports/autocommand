using System;
using System.Collections.Generic;
using AutoCommand.Engines.Core;
using AutoCommand.Engines.Firewall;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// App-side facade over the F# firewall engine (Engines.Firewall): the
    /// engine is constructed once with AutoCommand's naming policy
    /// (AC-BLOCK, see Naming.autocommand()) and exposed exactly as the old
    /// C# FirewallService was — Instance plus the static helpers — so every
    /// caller compiles unchanged. The engine itself is app-agnostic COM
    /// management (strong-typed INetFwPolicy2, no `dynamic`).
    /// </summary>
    public class FirewallService
    {
        public const string NewIpPrefix = "AC-BLOCK-IP ";
        public const string NewAppPrefix = "AC-BLOCK-APP ";

        /// <summary>The single engine instance all app code goes through.</summary>
        public static AutoCommand.Engines.Firewall.FirewallService Instance { get; } =
            new AutoCommand.Engines.Firewall.FirewallService(Naming.autocommand());

        public static string ResolveGroupName(string grouping) => AutoCommand.Engines.Firewall.FirewallService.ResolveGroupName(grouping);

        public static string PrimaryAppRuleName(string exeName) => Instance.PrimaryAppRuleName(exeName);

        public static string SuffixedAppRuleName(string exeName, string appPath) =>
            Instance.SuffixedAppRuleName(exeName, appPath);

        public static Dictionary<string, FirewallLogHit> GetRecentLogHits(int minutes) =>
            AutoCommand.Engines.Firewall.FirewallService.GetRecentLogHits(minutes);

        public static bool FirewallDropLoggingOn() => AutoCommand.Engines.Firewall.FirewallService.FirewallDropLoggingOn();

        public static void EnsureDropLoggingOnce() => AutoCommand.Engines.Firewall.FirewallService.EnsureDropLoggingOnce();

        public static string SetDropLogging(bool enable) => AutoCommand.Engines.Firewall.FirewallService.SetDropLogging(enable);
    }

    /// <summary>
    /// Pure, case-insensitive baseline state &amp; drift evaluation shared by
    /// FirewallBaselineManager and offline self-tests. Windows Firewall rule
    /// lookup (INetFwRules.Item) and block-prefix matching are case-insensitive,
    /// so baseline maps must never split a rule across casing variants.
    /// </summary>
    public static class FirewallBaselineLogic
    {
        public static Dictionary<string, bool> CreateRulesMap(IDictionary<string, bool> source = null)
        {
            var map = new Dictionary<string, bool>(
                source != null ? source.Count : 0,
                StringComparer.OrdinalIgnoreCase);
            if (source != null)
            {
                foreach (var kv in source)
                {
                    if (!string.IsNullOrEmpty(kv.Key))
                        map[kv.Key] = kv.Value;
                }
            }
            return map;
        }

        public static bool IsOwnBlockRuleName(string name) =>
            !string.IsNullOrEmpty(name) && (
                name.StartsWith(FirewallService.NewIpPrefix, StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith(FirewallService.NewAppPrefix, StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("AutoCommand IP Block - ", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("AutoCommand Process Block - ", StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Adopts live own-block rule states into <paramref name="baselineRules"/>
        /// in-place (case-insensitively) and optionally prunes retired own-block
        /// rules when <paramref name="isFullSnapshot"/> is true. Returns true if
        /// any entry changed.
        /// </summary>
        public static bool ApplyOwnBlockStates(
            Dictionary<string, bool> baselineRules,
            IEnumerable<(string Name, bool Enabled)> liveStates,
            bool isFullSnapshot)
        {
            if (baselineRules == null || liveStates == null) return false;

            bool dirty = false;
            HashSet<string> liveNames = isFullSnapshot
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : null;

            foreach (var (name, enabled) in liveStates)
            {
                if (string.IsNullOrEmpty(name) || !IsOwnBlockRuleName(name)) continue;
                liveNames?.Add(name);
                if (!baselineRules.TryGetValue(name, out bool prev) || prev != enabled)
                {
                    baselineRules[name] = enabled;
                    dirty = true;
                }
            }

            if (isFullSnapshot)
            {
                List<string> staleOwn = null;
                foreach (string key in baselineRules.Keys)
                {
                    if (IsOwnBlockRuleName(key) && !liveNames.Contains(key))
                    {
                        staleOwn ??= new List<string>();
                        staleOwn.Add(key);
                    }
                }
                if (staleOwn != null)
                {
                    foreach (string gone in staleOwn)
                    {
                        baselineRules.Remove(gone);
                        dirty = true;
                    }
                }
            }

            return dirty;
        }

        public static (List<string> ReEnabled, List<string> UnexpectedlyDisabled, List<Tuple<string, string>> SneakedIn, int LiveCount)
            EvaluateDrift(
                IDictionary<string, bool> baselineRules,
                IEnumerable<(string Name, bool Enabled, string Grouping)> liveRules)
        {
            var reEnabled = new List<string>();
            var unexpectedlyDisabled = new List<string>();
            var sneakedIn = new List<Tuple<string, string>>();
            if (baselineRules == null || liveRules == null)
                return (reEnabled, unexpectedlyDisabled, sneakedIn, 0);

            var expectedMap = baselineRules is Dictionary<string, bool> d &&
                              Equals(d.Comparer, StringComparer.OrdinalIgnoreCase)
                ? d
                : CreateRulesMap(baselineRules);

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, enabled, grouping) in liveRules)
            {
                if (string.IsNullOrEmpty(name) || !seen.Add(name)) continue;

                if (!expectedMap.TryGetValue(name, out bool expected))
                {
                    if (enabled)
                        sneakedIn.Add(Tuple.Create(name, grouping ?? ""));
                    continue;
                }

                if (!expected && enabled)
                    reEnabled.Add(name);
                else if (expected && !enabled)
                    unexpectedlyDisabled.Add(name);
            }

            return (reEnabled, unexpectedlyDisabled, sneakedIn, seen.Count);
        }
    }
}
