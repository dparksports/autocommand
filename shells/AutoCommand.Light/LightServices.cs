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
    /// watcher that attributes every connection, and the Sysmon installer
    /// probe. Initialized once from App.OnStartup BEFORE any of the
    /// facade-bound Contain services start, so they all speak Light's
    /// naming inside this process.
    ///
    /// Ownership rules this class encodes:
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
        public static string Root { get; private set; } = "";
        public static BlocksLedger Ledger { get; private set; } = null!;
        public static EngineFirewall Firewall { get; private set; } = null!;
        public static SysmonInstallerService Installer { get; private set; } = null!;

        /// <summary>Description marker every Light-made block carries —
        /// how the gate tells its own rules from the Advanced app's
        /// adopted ones.</summary>
        public static string OwnMarker { get; private set; } = "";

        /// <summary>The one live table: the watcher writes, the gate reads
        /// (first-attempt detection) and the Apps page reads (what's
        /// running now). One source of truth.</summary>
        public static ConcurrentDictionary<string, SvchostMonitorItem> Tracked { get; }
            = new();

        public static SysmonWatcherService Watcher { get; private set; } = null!;

        /// <summary>Raised once the watcher exists so the gate can hook its
        /// event stream before the first event lands.</summary>
        public static event Action<SysmonWatcherService>? WatcherCreated;

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
            FirewallService.UseNaming(LightNaming.light());

            OwnMarker = LightNaming.light().UserBlockDescription;
            Firewall = new EngineFirewall(LightNaming.light());
            Ledger = new BlocksLedger(Root);
            Ledger.Load();
            Installer = new SysmonInstallerService();

            var dns = DnsResolutionService.Instance;
            dns.Start();
            Watcher = new SysmonWatcherService(Tracked, dns);
            Watcher.MonitorAllProcesses = true;   // a stranger's first attempt must be seen
            WatcherCreated?.Invoke(Watcher);
        }

        public static void StartWatch()
        {
            Watcher.Start();
            _ = Task.Run(() => Watcher.SeedBaseline());
        }

        /// <summary>The no-key chat's facts, gathered from the gate's own
        /// records. TelemetrySendsLast24h stays null on purpose — that
        /// cadence lives in the Advanced app, and the router says so
        /// honestly.</summary>
        public static async Task<LightChatFacts> ChatFactsAsync()
        {
            var attempts = LightGate.AttemptsToday();
            var asks = LightGate.PendingAsks();
            var gated = LightGate.Store.Entries.Where(e => e.Permission == Core.AppPermission.Never)
                .ToList();

            var summaries = gated.Take(3)
                .Select(e => $"{e.DisplayName} (never allowed)")
                .ToList();

            List<string> history = new();
            try
            {
                var events = AuditTrail.ReadEvents(Ledger.EventLogPath);
                var incidents = AuditTrail.BuildIncidents(events);
                for (var i = incidents.Count - 1; i >= 0 && history.Count < 3; i--)
                    history.Add(incidents[i].Sentence);
            }
            catch { // an empty ledger just means an empty history
            }

            var last10 = attempts.Count(a => a.TimeUtc >= DateTime.UtcNow.AddMinutes(-10));
            return await Task.Run(() => new LightChatFacts(
                Tracked.Count,
                asks.Count,
                asks.Select(a => a.DisplayName).ToList(),
                gated.Count,
                summaries,
                last10,
                null,
                history));
        }

        public static void Shutdown()
        {
            try { Watcher?.Stop(); } catch { }
            try { FirewallDenyWatchService.Instance.Stop(); } catch { }
            try { BlockHitFeedService.Instance.Stop(); } catch { }
            try { AppBlockCoverageService.Instance.Stop(); } catch { }
            Ledger?.FlushPending();
        }
    }
}
