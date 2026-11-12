// Windows Update support — the sanctioned way to update a machine this
// locked down. The session contract (mirrors the Update tab):
//   · scope is COMPUTED, never guessed: exactly the blocks whose service
//     attribution matches ServiceOutageMap's "updates"/"defender" symptoms
//     — everything else stays blocked the whole time;
//   · blocks lift as block gates (self-restoring at expiry / app exit /
//     startup reconcile), so a crashed app can't leave the door open;
//   · when the update finishes (or is restored early), every lifted block
//     is re-enabled, VERIFIED against the live firewall, the update's
//     side effects (moved Defender folder, dead paths) are repaired, and
//     the whole session lands in the audit trail as one incident.
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Sitedoctor.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AutoCommand.Services
{
    /// <summary>One session update, phase by phase — what the tab renders.</summary>
    public sealed class UpdateSessionReport
    {
        public string Phase = "";          // scanning | downloading | installing | closing | done | error
        public string Note = "";
        public int FoundUpdates;
        public bool RebootRequired;
        public List<string> Checklist = new();   // the after-state evidence lines
        public string Error;
    }

    public sealed class WindowsUpdateSession
    {
        public static WindowsUpdateSession Instance => _instance ??= new WindowsUpdateSession();
        private static WindowsUpdateSession _instance;

        private const int GateMinutes = 120;          // hard stop even if something goes wrong
        private const string Origin = "update-mode";

        public bool IsRunning { get; private set; }
        public DateTime HardStopUtc { get; private set; }
        private volatile bool _restoreRequested;
        private readonly List<(string Kind, string Key, string Display)> _widened = new();
        private readonly object _widenedGate = new();

        // ── scope ───────────────────────────────────────────────────────

        public sealed class ScopeGroup
        {
            public string Title;
            public string Detail;
            public List<(string Kind, string Key, string Display)> Targets = new();
        }

        public sealed class UpdateScope
        {
            public ScopeGroup UpdatePathway = new();
            public ScopeGroup Defender = new();
            public int CdnReserve;        // Akamai/Gcore edges: opened only on demand
            public int StayingOn;         // targets that never open for an update
            public int LiftedCount => UpdatePathway.Targets.Count + Defender.Targets.Count;
        }

        /// <summary>Exactly the blocks an update needs — computed live from
        /// service attribution (ServiceOutageMap, the same rule the restore
        /// guide uses), so new endpoints join the next session by themselves.</summary>
        public static async Task<UpdateScope> ComputeScopeAsync(bool includeDefender = true)
        {
            var scope = new UpdateScope();
            BlocksStore.Load();
            var records = BlocksStore.Records.ToList();

            static ServiceSymptom Symptom(string id) =>
                ServiceOutageMap.Symptoms.First(s => s.Id == id);

            var picked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void Add(ScopeGroup g, IEnumerable<BlockRecord> recs)
            {
                foreach (var r in recs)
                {
                    if (r.Status == "off") continue;    // paused blocks break nothing
                    string kind = r.IsIp ? "ip" : "proc";
                    if (!picked.Add(kind + ":" + r.Key)) continue;
                    g.Targets.Add((kind, r.Key,
                        r.IsIp ? r.Key : Path.GetFileName(r.Key)));
                }
            }

            Add(scope.UpdatePathway, ServiceOutageMap.MatchingBlocks(Symptom("updates"), records));
            if (includeDefender)
                Add(scope.Defender, ServiceOutageMap.MatchingBlocks(Symptom("defender"), records));

            scope.UpdatePathway.Title = "Windows Update & Store downloads";
            scope.UpdatePathway.Detail = "wuauserv · dosvc · usosvc · bits — scan, download, install.";
            scope.Defender.Title = "Defender protection";
            scope.Defender.Detail = "signature updates are security patches — included by default.";

            var inventory = await FirewallService.Instance.GetBlockedInventoryAsync();
            var lifted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var g in new[] { scope.UpdatePathway, scope.Defender })
                foreach (var t in g.Targets) lifted.Add(t.Key);
            foreach (var t in inventory)
            {
                if (t.EnabledRules == 0) continue;
                if (lifted.Contains(t.Ip) || lifted.Contains(t.AppPath)) continue;
                if ((t.Class ?? "").Contains("Akamai", StringComparison.OrdinalIgnoreCase) ||
                    (t.Class ?? "").Contains("Gcore", StringComparison.OrdinalIgnoreCase))
                    scope.CdnReserve++;
                else
                    scope.StayingOn++;
            }
            return scope;
        }

        /// <summary>The CDN tier is escalation, not a starting point: opened
        /// on explicit request (download stalled), announced, audited. The
        /// running session closes these with everything else.</summary>
        public async Task<int> WidenToCdnAsync()
        {
            BlocksStore.Load();
            var records = BlocksStore.Records.ToList();
            var cdnKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in await FirewallService.Instance.GetBlockedInventoryAsync())
            {
                if (t.EnabledRules == 0) continue;
                if ((t.Class ?? "").Contains("Akamai", StringComparison.OrdinalIgnoreCase) ||
                    (t.Class ?? "").Contains("Gcore", StringComparison.OrdinalIgnoreCase))
                    cdnKeys.Add(t.Ip);
            }
            var targets = records
                .Where(r => r.IsIp && r.Status != "off" && cdnKeys.Contains(r.Key))
                .Select(r => (r.Kind, r.Key, Path.GetFileName(r.Key)))
                .ToList();
            if (targets.Count > 0)
            {
                await LiftTargetsAsync(targets.Select(t => (t.Kind, t.Key)).ToList(), "update CDN escalation");
                lock (_widenedGate) _widened.AddRange(targets);
            }
            return targets.Count;
        }

        // ── session ─────────────────────────────────────────────────────

        public async Task<UpdateSessionReport> RunAsync(Action<UpdateSessionReport> progress,
                                                        bool includeDefender = true)
        {
            if (IsRunning) return null;
            IsRunning = true;
            _restoreRequested = false;
            HardStopUtc = DateTime.UtcNow.AddMinutes(GateMinutes);
            lock (_widenedGate) _widened.Clear();

            var report = new UpdateSessionReport();
            bool installRan = false;
            try
            {
                var scope = await ComputeScopeAsync(includeDefender);
                var targets = scope.UpdatePathway.Targets.Concat(scope.Defender.Targets).ToList();
                if (targets.Count == 0)
                {
                    report.Phase = "done";
                    report.Note = "Nothing to lift — no active update-pathway blocks found.";
                    progress(report);
                    return report;
                }

                await LiftTargetsAsync(targets.Select(t => (t.Kind, t.Key)).ToList(), "windows update");
                BlocksStore.AppendEvent("update-opened", "-", "-",
                    $"{targets.Count} target(s) lifted, hard stop {HardStopUtc.ToLocalTime():HH:mm}", Origin);

                report.Phase = "scanning"; report.Note = "Asking Windows what it needs…"; progress(report);
                List<string> titles = null;
                try { titles = await Task.Run(() => WuApi.Scan()); }
                catch (Exception ex) { report.Error = ex.Message; }

                if (titles != null)
                {
                    report.FoundUpdates = titles.Count;
                    report.Note = titles.Count == 0
                        ? "Windows reports nothing to install."
                        : $"{titles.Count} update(s): {string.Join(", ", titles.Take(3))}" +
                          (titles.Count > 3 ? "…" : "");
                    progress(report);

                    if (titles.Count > 0 && !_restoreRequested)
                    {
                        report.Phase = "downloading"; progress(report);
                        try { await Task.Run(() => WuApi.Download(titles)); }
                        catch (Exception ex) { report.Error = ex.Message; }
                    }
                    if (titles.Count > 0 && !_restoreRequested)
                    {
                        report.Phase = "installing";
                        report.Note = "The long part — the PC stays usable."; progress(report);
                        try
                        {
                            report.RebootRequired = await Task.Run(() => WuApi.Install(titles));
                            installRan = true;
                        }
                        catch (Exception ex) { report.Error = ex.Message; }
                    }
                }

                await CloseAsync(report, targets, scope, progress, installRan);
                return report;
            }
            finally { IsRunning = false; }
        }

        /// <summary>Early out: closes gates now; an install already applied
        /// stays applied, only a later download could stall.</summary>
        public void RequestRestore() => _restoreRequested = true;

        private static async Task LiftTargetsAsync(List<(string Kind, string Key)> targets, string reason)
        {
            var opened = new List<BlockGate>();
            foreach (var (kind, key) in targets)
                opened.Add(BlockGateService.Instance.OpenGate(kind, key, key, GateMinutes, "update-mode", reason));
            await FirewallService.Instance.SetTargetsEnabledAsync(
                targets.Select(t => (t.Kind, t.Key)).ToList(), false);
            BlocksStore.SetStatuses(targets, "off", Origin);
            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            if (opened.Count > 0)
                BlockGateService.Instance.NotifyGateOpened(opened[0], Origin);
        }

        // ── the post-update loop: close → verify → repair → report ──────

        private async Task CloseAsync(UpdateSessionReport report,
            List<(string Kind, string Key, string Display)> targets, UpdateScope before,
            Action<UpdateSessionReport> progress, bool installRan)
        {
            report.Phase = "closing"; report.Note = "Putting every block back…"; progress(report);

            // 1. close — gates restore rules + store status themselves. The
            //    widened CDN tier goes back with everything else.
            List<(string Kind, string Key, string Display)> widened;
            lock (_widenedGate) { widened = _widened.ToList(); _widened.Clear(); }
            foreach (var (kind, key, _) in targets.Concat(widened))
                await BlockGateService.Instance.CloseAsync(kind, key, Origin);

            // 2. verify — every lifted target must be enabled again; retry
            //    whatever didn't come back, then say so, never skip silently
            var (verified, fixedCount) = await VerifyRestoredAsync(targets.Concat(widened).ToList());
            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            report.Checklist.Add($"Re-applied and verified {verified}/{targets.Count + widened.Count} lifted blocks" +
                (fixedCount > 0 ? $" ({fixedCount} needed a second attempt)" : "") + ".");

            // 3. repair — Windows Update deletes Defender's versioned folder;
            //    retire inert dead-path rules (coverage re-points new paths on
            //    first run via the Sysmon watcher)
            try
            {
                var (touched, retired) = await FirewallService.Instance.RetireDeadAppBlockRulesAsync();
                if (retired > 0)
                    report.Checklist.Add($"Retired {retired} dead-path rule(s) across {touched} target(s) — " +
                        "Windows Update moved the binaries; new paths get blocked as they run.");
            }
            catch { /* best-effort; the coverage service retries */ }

            // 3b. sever stale flows — a re-enabled rule never cuts a socket
            //     that was established while it was off, so the update
            //     services get a clean restart after an install
            if (installRan)
            {
                int restarted = 0;
                foreach (var svc in new[] { "wuauserv", "dosvc", "bits" })
                    restarted += RestartService(svc) ? 1 : 0;
                if (restarted > 0)
                    report.Checklist.Add($"Restarted {restarted} update service(s) to sever lingering download connections.");
            }

            // 4. what's new — endpoints that appeared during the session are
            //    already blocked, and join the next session automatically
            try
            {
                var after = await ComputeScopeAsync();
                int beforeCount = before.LiftedCount, afterCount = after.LiftedCount;
                if (afterCount > beforeCount)
                    report.Checklist.Add($"{afterCount - beforeCount} new update endpoint(s) appeared and were " +
                        "blocked — included automatically next time.");
            }
            catch { /* scope recompute is informational */ }

            BlocksStore.AppendEvent("update-restored", "-", "-",
                $"{verified}/{targets.Count + widened.Count} target(s) restored · verified on", Origin);

            report.Phase = "done";
            report.Note = report.Error == null ? "Update session complete." : $"Finished with a note: {report.Error}";
            report.Checklist.Add("Recorded in Audit — one incident for the whole session.");
            progress(report);
        }

        /// <summary>Quiet `net stop`/`net start` round-trip; false if the
        /// service isn't running or the restart fails (not fatal).</summary>
        private static bool RestartService(string name)
        {
            try
            {
                // `net stop` returns non-zero when not running — that's the
                // common case and simply means nothing to sever.
                Run("net", $"stop {name}", out bool stopped);
                if (!stopped) return false;
                Run("net", $"start {name}", out bool started);
                return started;
            }
            catch { return false; }

            static void Run(string exe, string args, out bool ok)
            {
                using var p = Process.Start(new ProcessStartInfo(exe, args)
                { CreateNoWindow = true, UseShellExecute = false });
                p.WaitForExit(60_000);
                ok = p.ExitCode == 0;
            }
        }

        private static async Task<(int verified, int fixedCount)> VerifyRestoredAsync(
            List<(string Kind, string Key, string Display)> targets)
        {
            var inventory = await FirewallService.Instance.GetBlockedInventoryAsync();
            bool IsOn(string key) => inventory.Any(t => t.EnabledRules > 0 &&
                (string.Equals(t.Ip, key, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(t.AppPath, key, StringComparison.OrdinalIgnoreCase)));

            var pending = targets.Where(t => !IsOn(t.Key)).Select(t => (t.Kind, t.Key)).ToList();
            int initiallyOff = pending.Count;
            if (pending.Count > 0)
            {
                await FirewallService.Instance.SetTargetsEnabledAsync(pending, true);
                BlocksStore.SetStatuses(pending, "on", Origin);
                inventory = await FirewallService.Instance.GetBlockedInventoryAsync();
                pending = pending.Where(p => !IsOn(p.Key)).ToList();
            }
            return (targets.Count - pending.Count, initiallyOff - pending.Count);
        }

        // ── nightly Defender window (settings-backed) ───────────────────

        public sealed class UpdateSettings
        {
            public bool NightlyDefenderWindow { get; set; }
            public int WindowStartHour { get; set; } = 3;
            public int WindowMinutes { get; set; } = 20;
        }

        private Timer _nightlyTimer;
        private bool _nightlyOpen;
        private static string SettingsPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "update-settings.json");

        public UpdateSettings Settings { get; private set; } = new();

        public void LoadSettings()
        {
            try
            {
                if (File.Exists(SettingsPath))
                    Settings = JsonSerializer.Deserialize<UpdateSettings>(File.ReadAllText(SettingsPath)) ?? new();
            }
            catch { /* unreadable settings = defaults */ }
        }

        public void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath));
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(Settings, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* best-effort */ }
        }

        /// <summary>One-minute tick while the app runs: opens the standing
        /// Defender-signature window, closes it, verifies — same machinery
        /// as a manual session, no user action needed.</summary>
        public void EnsureNightlyTimer()
        {
            LoadSettings();
            if (_nightlyTimer != null) return;
            _nightlyTimer = new Timer(async _ =>
            {
                try
                {
                    if (!Settings.NightlyDefenderWindow || IsRunning) return;
                    var now = DateTime.Now;
                    var start = now.Date.AddHours(Settings.WindowStartHour);
                    var end = start.AddMinutes(Settings.WindowMinutes);

                    if (!_nightlyOpen && now >= start && now < end)
                    {
                        var scope = await ComputeScopeAsync();
                        var targets = scope.Defender.Targets;
                        if (targets.Count == 0) return;
                        _nightlyOpen = true;
                        await LiftTargetsAsync(targets.Select(t => (t.Kind, t.Key)).ToList(), "nightly defender window");
                        BlocksStore.AppendEvent("update-opened", "-", "-",
                            $"nightly Defender window · {targets.Count} target(s) lifted", Origin);
                        RunSignatureUpdate(end - now);
                    }
                    else if (_nightlyOpen && now >= end)
                    {
                        _nightlyOpen = false;
                        var scope = await ComputeScopeAsync();
                        var targets = scope.Defender.Targets;
                        foreach (var (kind, key, _) in targets)
                            await BlockGateService.Instance.CloseAsync(kind, key, Origin);
                        BlocksStore.AppendEvent("update-restored", "-", "-",
                            $"nightly Defender window · {targets.Count} target(s) restored", Origin);
                    }
                }
                catch { /* a missed night is not an outage */ }
            }, null, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1));
        }

        private static void RunSignatureUpdate(TimeSpan window)
        {
            try
            {
                var exe = LatestMpCmdRun();
                if (exe == null) return;
                var psi = new ProcessStartInfo(exe, "-SignatureUpdate")
                { CreateNoWindow = true, UseShellExecute = false };
                using var p = Process.Start(psi);
                _ = Task.Delay(window).ContinueWith(_ => { try { p?.Kill(); } catch { } });
            }
            catch { /* signature update is best-effort inside the window */ }
        }

        private static string LatestMpCmdRun()
        {
            try
            {
                var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Windows Defender", "Platform");
                if (Directory.Exists(platform))
                {
                    var exe = Directory.GetDirectories(platform)
                        .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "MpCmdRun.exe"))
                        .FirstOrDefault(File.Exists);
                    if (exe != null) return exe;
                }
            }
            catch { /* fall through to the static install */ }
            var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender", "MpCmdRun.exe");
            return File.Exists(fallback) ? fallback : null;
        }
    }

    /// <summary>
    /// Windows Update Agent (WUA API) via late-bound COM — no interop
    /// assembly, no build-time dependency. Synchronous calls run on a
    /// background thread; the session reports phase transitions. If WUApi
    /// is unavailable the session still closes and verifies normally.
    /// </summary>
    internal static class WuApi
    {
        private static dynamic NewSession()
        {
            var t = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (t == null) throw new InvalidOperationException("Windows Update Agent (WUA API) is not available.");
            return Activator.CreateInstance(t);
        }

        public static List<string> Scan()
        {
            dynamic session = NewSession();
            dynamic searcher = session.CreateUpdateSearcher();
            dynamic result = searcher.Search("IsInstalled=0 and IsHidden=0");
            var titles = new List<string>();
            int n = result.Updates.Count;
            for (int i = 0; i < n; i++)
                titles.Add((string)result.Updates.Item(i).Title);
            return titles;
        }

        public static void Download(List<string> titles)
        {
            dynamic session = NewSession();
            dynamic coll = session.CreateUpdateCollection();
            dynamic found = NewSession().CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0").Updates;
            int n = found.Count;
            for (int i = 0; i < n; i++)
            {
                var u = found.Item(i);
                if (titles.Contains((string)u.Title)) coll.Add(u);
            }
            if (coll.Count == 0) return;
            dynamic downloader = session.CreateUpdateDownloader();
            downloader.Updates = coll;
            downloader.Download();
        }

        public static bool Install(List<string> titles)
        {
            dynamic session = NewSession();
            dynamic coll = session.CreateUpdateCollection();
            dynamic found = NewSession().CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0").Updates;
            int n = found.Count;
            for (int i = 0; i < n; i++)
            {
                var u = found.Item(i);
                if (titles.Contains((string)u.Title)) coll.Add(u);
            }
            if (coll.Count == 0) return false;
            dynamic installer = session.CreateUpdateInstaller();
            installer.Updates = coll;
            dynamic result = installer.Install();
            return (bool)result.RebootRequired;
        }
    }
}
