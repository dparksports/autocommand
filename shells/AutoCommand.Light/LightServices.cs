using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AutoCommand.Light
{
    /// <summary>
    /// Light's single shared wiring: the engine firewall speaking AL-BLOCK
    /// (plus adopted AC-BLOCK), Light's own blocks ledger, the process
    /// watcher + packet sniffer over one tracked table, and the Sysmon
    /// installer probe. Initialized once from App.OnStartup BEFORE any of
    /// the facade-bound Contain services start, so they all speak Light's
    /// naming inside this process.
    ///
    /// Ownership rules this class encodes (see the design note):
    ///  · Light's data lives in %LOCALAPPDATA%\AutoCommandLight — never in
    ///    the Advanced app's per-user root; the shared machine store is
    ///    %PROGRAMDATA%\AutoCommand, written by Advanced only.
    ///  · Light creates AL-BLOCK rules and adopts AC-BLOCK in place;
    ///    mutual adoption means either app's panic button restores both.
    ///  · Light never installs/reconfigures Sysmon if it is already there
    ///    (Advanced owns it); it only offers a first install.
    /// </summary>
    public static class LightServices
    {
        public static string Root { get; private set; }
        public static BlocksLedger Ledger { get; private set; }
        public static EngineFirewall Firewall { get; private set; }
        public static SysmonInstallerService Installer { get; private set; }

        /// <summary>Description marker every Light-made block carries —
        /// how BlocksView tells Light's own rules from the Advanced app's
        /// adopted ones.</summary>
        public static string OwnMarker { get; private set; }

        /// <summary>The one live table: connections grid, overview report
        /// and the chat facts all read the same rows. Same pattern as the
        /// Advanced app's SvchostMonitorView — one source of truth.</summary>
        public static ConcurrentDictionary<string, SvchostMonitorItem> Tracked { get; }
            = new();

        private static SysmonWatcherService _watcher;
        private static RawSocketSnifferService _sniffer;
        private static bool _watching;

        public static bool Watching => _watching;

        public static void Initialize()
        {
            var identity = AutoCommand.Engines.Core.Identity.light();

            // The engines learn Light's identity before anything touches
            // them (data root, prefixes, branding — same call every shell
            // makes at startup).
            AutoCommand.Engines.Watch.WatchConfig.Configure(identity);

            Root = identity.DataRoot;
            Directory.CreateDirectory(Root);

            // The per-process naming seam: every facade-bound Contain
            // service (deny watcher, hit feed, domain sync, coverage) now
            // creates AL-BLOCK rules and lists adopted AC-BLOCK ones.
            // Advanced's process never calls this and keeps AC naming.
            FirewallService.UseNaming(LightNaming.light());

            OwnMarker = LightNaming.light().UserBlockDescription;
            Firewall = new EngineFirewall(LightNaming.light());
            Ledger = new BlocksLedger(Root);
            Ledger.Load();
            Installer = new SysmonInstallerService();

            var dns = DnsResolutionService.Instance;
            dns.Start();
            _watcher = new SysmonWatcherService(Tracked, dns);
            _watcher.MonitorAllProcesses = true;   // a novice's question is "what is connecting", not "what is svchost doing"
            _sniffer = new RawSocketSnifferService(Tracked);

            // Kernel-side denials stamp themselves onto the live rows so
            // "what is being blocked" is visible even when the deny
            // watcher's toasts are not running.
            BlockHitFeedService.Instance.HitArrived += OnBlockHit;
        }

        public static void StartWatch()
        {
            if (_watching || _watcher == null) return;
            _watcher.Start();
            _sniffer.Start();
            _watching = true;
            _ = Task.Run(() => _watcher.SeedBaseline());
        }

        public static void StopWatch()
        {
            if (!_watching) return;
            _watcher.Stop();
            _sniffer.Stop();
            _watching = false;
        }

        /// <summary>Stop listing a process in the Connections grid. The
        /// choice is recorded in Light's ignore list with its provenance
        /// trail, same as the Advanced app's ignore list.</summary>
        public static void IgnoreProcess(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return;
            _watcher?.AddIgnoredProcess(processName.Trim(), "Light Connections");
        }

        private static void OnBlockHit(BlockHitFeedService.BlockHit hit)
        {
            // Stamp the matching live row(s): by destination first, by
            // image name as the fallback. Fired on the feed's thread —
            // SvchostMonitorItem is thread-safe for these counters and the
            // UI reads them through INPC notifications it marshals.
            try
            {
                if (!string.IsNullOrEmpty(hit.DestIp) && Tracked.TryGetValue(hit.DestIp, out var byIp))
                {
                    byIp.RecordBlockHit(hit.DestIp, hit.DestPort, hit.Protocol, hit.TimeUtc);
                    return;
                }
                var baseName = ImageBaseName(hit.Image);
                foreach (var row in Tracked.Values)
                {
                    if (!string.IsNullOrEmpty(row.ProcessName) &&
                        row.ProcessName.Equals(baseName, StringComparison.OrdinalIgnoreCase))
                    {
                        row.RecordBlockHit(hit.DestIp, hit.DestPort, hit.Protocol, hit.TimeUtc);
                    }
                }
            }
            catch { // the stamp is best-effort; the feed's own store keeps the record
            }
        }

        private static string ImageBaseName(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            var name = path;
            var slash = name.LastIndexOfAny(new[] { '\\', '/' });
            if (slash >= 0) name = name[(slash + 1)..];
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        }

        /// <summary>Snapshot for the report/chat: category counts via the
        /// pure chip layer, computed off the UI thread.</summary>
        public static (int Windows, int Apps, int Unknown, List<string> UnknownNames, int Rows) Categorize()
        {
            int windows = 0, apps = 0, unknown = 0;
            var names = new List<string>();
            foreach (var row in Tracked.Values)
            {
                var facts = ChipFactsOf(row);
                switch (VerdictChip.Category(facts))
                {
                    case "windows":
                    case "wsl":
                        windows++;
                        break;
                    case "browser":
                    case "app":
                        apps++;
                        break;
                    default:
                        unknown++;
                        if (names.Count < LightFindings.MaxNamesShown &&
                            !string.IsNullOrWhiteSpace(row.ProcessName))
                            names.Add(row.ProcessName);
                        break;
                }
            }
            return (windows, apps, unknown, names, Tracked.Count);
        }

        public static ChipFacts ChipFactsOf(SvchostMonitorItem row) => new(
            row.ProcessName ?? "",
            row.IsSvchost,
            row.HostedServicesCsv,
            row.IdentitySuspicious,
            row.IsWslFamily,
            row.WslNote,
            row.HasExited,
            row.FirstSeenUtc,
            row.IsIpBlocked,
            row.IsProcessBlocked,
            row.ImagePath);

        /// <summary>The no-key chat's facts, gathered from live records.
        /// TelemetrySendsLast24h stays null on purpose — that cadence lives
        /// in the Advanced app for now, and the router says so honestly.</summary>
        public static async Task<LightChatFacts> ChatFactsAsync()
        {
            var (windows, apps, unknown, names, rows) = await Task.Run(Categorize);
            var inv = await Firewall.GetBlockedInventoryAsync();
            var active = inv.Where(b => b.EnabledRules > 0).ToList();
            var summaries = active.Take(3)
                .Select(b => $"{b.Target} ({(b.Kind == "ip" ? "address" : "program")})")
                .ToList();

            var feed = BlockHitFeedService.Instance.Recent(10, 500).Count;
            var denies = SafeDenyCount();
            int attempts = Math.Max(feed, denies);

            List<string> history = new();
            try
            {
                var events = AuditTrail.ReadEvents(Ledger.EventLogPath);
                var incidents = AuditTrail.BuildIncidents(events);
                foreach (var i in incidents.Skip(Math.Max(0, incidents.Count - 3)).Reverse())
                    history.Add(i.Sentence);
            }
            catch { // an empty ledger just means an empty history
            }

            return new LightChatFacts(rows, unknown, names, active.Count, summaries,
                attempts, null, history);
        }

        private static int SafeDenyCount()
        {
            try { return FirewallDenyWatchService.Instance.Recent(10, 500).Count; }
            catch { return 0; }
        }

        public static void Shutdown()
        {
            StopWatch();
            try { FirewallDenyWatchService.Instance.Stop(); } catch { }
            try { BlockHitFeedService.Instance.Stop(); } catch { }
            try { AppBlockCoverageService.Instance.Stop(); } catch { }
            Ledger?.FlushPending();
        }
    }
}
