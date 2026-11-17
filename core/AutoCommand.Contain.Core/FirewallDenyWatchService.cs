using AutoCommand.NetWatch.Core;
using System;
using AutoCommand.Contain.Core;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// The real firewall-denial telemetry the app never had. Windows Firewall
    /// blocks in the kernel — an AC-BLOCK hit fails the connect() with
    /// WSAEACCES and (unlike Sysmon, which sees the attempt) leaves nothing in
    /// the app's channels — so until now the only denial signal was inference
    /// (BlockHitFeedService joining Sysmon EID 3 against the inventory). This
    /// service closes that gap at the source:
    ///
    ///   · flips on the "Filtering Platform Connection" audit subcategory
    ///     (failure-only, idempotent, every start — GUID-addressed so the
    ///     command works on localized Windows), which makes the kernel write
    ///     Event 5157 "connection blocked" into the Security log;
    ///   · follows the Security log live (EventLogWatcher) and parses each
    ///     5157 — process image, destination IP:port, protocol, filter id;
    ///   · keeps ONLY denials whose destination is in AutoCommand's blocked
    ///     inventory (BlockHitFeedService.BlockedIp — everything else is
    ///     Windows' or other software's blocking, not ours to explain);
    ///   · raises DenyArrived (the push seam for the denied-connection toast)
    ///     rate-limited per (process, destination) so a browser that retries
    ///     a blocked CDN edge every second produces one notification, and
    ///     persists every matched denial to firewall-denies.jsonl beside the
    ///     block-hits archive, so "why did my download fail at 2 a.m." has a
    ///     kernel-level receipt even after a restart.
    ///
    /// Sysmon-independent by design: this works on machines where Sysmon was
    /// never installed, and it is the ground truth the inference feed is not
    /// (5157 fires only when the firewall actually refused the connect).
    /// </summary>
    public sealed class FirewallDenyWatchService
    {
        public static FirewallDenyWatchService Instance => _instance ??= new FirewallDenyWatchService();
        private static FirewallDenyWatchService _instance;

        private const int MaxDenies = 1000;
        private static readonly TimeSpan Retain = TimeSpan.FromHours(24);
        private static readonly TimeSpan SaveInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan ToastWindow = TimeSpan.FromMinutes(10);

        /// <summary>5157 "The Windows Filtering Platform has blocked a
        /// connection" — the only event the watcher subscribes to.</summary>
        internal const int BlockedConnectionEventId = 5157;

        /// <summary>"Filtering Platform Connection" audit subcategory GUID.
        /// The numeric GUID is used instead of the subcategory NAME because
        /// auditpol's text arguments are localized — the GUID is not.</summary>
        internal const string FilteringPlatformConnectionSubcategoryGuid =
            "{0CCE9226-69AE-11D9-BED3-505054503030}";

        /// <summary>One kernel-level firewall denial that matched our inventory.</summary>
        public sealed class DenyEvent
        {
            public DateTime TimeUtc { get; set; }
            public string Image { get; set; }       // full path of the denied process
            public string DestIp { get; set; }
            public int DestPort { get; set; }
            public string Protocol { get; set; }    // "TCP" | "UDP" | raw number
            public long FilterRtId { get; set; }    // WFP filter that denied it (no name without FWP APIs)
            public string LayerName { get; set; }
            public string BlockedClass { get; set; }// inventory class snapshot, e.g. "Akamai (MS CDN)"
            public int Rules { get; set; }          // rules on the matched target
            public int EnabledRules { get; set; }
        }

        private readonly object _gate = new();
        private readonly List<DenyEvent> _denies = new();
        private readonly ConcurrentDictionary<string, DateTime> _lastToast = new(StringComparer.OrdinalIgnoreCase);
        private EventLogWatcher _watcher;
        private Timer _saveTimer;
        private bool _running, _dirty;

        /// <summary>Raised on the watcher thread for EVERY matched denial
        /// (rate-limiting applies to toasts only) — the raw push seam for UI
        /// surfaces that want all kernel-level denials (badges, live lists).
        /// Subscriber exceptions are isolated: a UI lag must never take the
        /// watcher down.</summary>
        public event Action<DenyEvent> DenyArrived;

        /// <summary>Injection seam for the toast itself (house pattern:
        /// SecurityEnforcer.OnAdapterAlert). Null = toasts are dropped but
        /// detection, persistence and DenyArrived still run.</summary>
        public Action<string, string, Action> OnDenyToast { get; set; }

        public DateTime LastDenyUtc { get; private set; }
        public string WatcherError { get; private set; }
        public bool IsRunning { get { lock (_gate) return _running; } }

        /// <summary>Persistence root; settable for offline self-tests (house pattern).</summary>
        public static string StoreDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private static string StorePath => Path.Combine(StoreDirectory, "firewall-denies.jsonl");

        // ── enabled preference (Settings toggle; default ON) ─────────────

        private static string PrefPath => Path.Combine(StoreDirectory, "deny-watch.txt");

        private static bool LoadPersistedEnabled()
        {
            try
            {
                if (!File.Exists(PrefPath)) return true;   // default: on
                return File.ReadAllText(PrefPath).Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            }
            catch { return true; }   // unreadable preference must not silence the watcher
        }

        private static bool _enabled = LoadPersistedEnabled();

        /// <summary>Whether deny watching is on. Reads the persisted
        /// preference once at first touch; SetEnabled(bool) persists changes.</summary>
        public static bool Enabled => Volatile.Read(ref _enabled);

        /// <summary>Settings toggle: persists and starts/stops the watcher at
        /// runtime. Returns the effective state.</summary>
        public bool SetEnabled(bool value)
        {
            Volatile.Write(ref _enabled, value);
            try
            {
                Directory.CreateDirectory(StoreDirectory);
                File.WriteAllText(PrefPath, value ? "True" : "False");
            }
            catch { /* persistence is best-effort; the in-memory flag still governs */ }
            if (value) Start(); else Stop();
            return Enabled;
        }

        private FirewallDenyWatchService() { }

        /// <summary>Idempotent: safe to call from startup and the toggle. The
        /// audit-policy flip needs elevation (the app manifest guarantees it);
        /// without it the watcher still attaches but WatcherError says why
        /// nothing will arrive.</summary>
        public void Start()
        {
            bool shouldRun;
            lock (_gate)
            {
                if (_running) return;
                shouldRun = _enabled;
                if (shouldRun) _running = true;
            }
            if (!shouldRun) return;

            Load();
            BlockHitFeedService.Instance.Start();   // the inventory this joins against (idempotent)
            _saveTimer = new Timer(_ => SaveIfDirty(), null, SaveInterval, SaveInterval);
            _ = Task.Run(StartWatcherAsync);
        }

        public void Stop()
        {
            lock (_gate)
            {
                if (!_running) return;
                _running = false;
                _saveTimer?.Dispose(); _saveTimer = null;
            }
            try { if (_watcher != null) _watcher.Enabled = false; } catch { /* already gone */ }
            _watcher?.Dispose();
            _watcher = null;
            SaveIfDirty();
        }

        private async Task StartWatcherAsync()
        {
            string auditError = await EnsureAuditPolicyAsync();
            if (auditError != null)
            {
                WatcherError = $"Audit policy (Filtering Platform Connection) could not be enabled: {auditError}. " +
                               "Kernel-level deny detection needs it — blocks still work, only the notifications are off.";
                return;
            }

            try
            {
                var query = new EventLogQuery("Security", PathType.LogName,
                    $"*[System[(EventID={BlockedConnectionEventId})]]");
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_DenyWritten;
                _watcher.Enabled = true;
            }
            catch (UnauthorizedAccessException)
            {
                WatcherError = "The Security event log is not readable without elevation — run AutoCommand as administrator.";
            }
            catch (Exception ex)
            {
                WatcherError = $"Failed to follow the Security log: {ex.Message}";
            }
        }

        /// <summary>Idempotent per run: flips failure auditing on for the
        /// Filtering Platform Connection subcategory. The command is cheap and
        /// safe to re-run (running it every start beats parsing localized
        /// auditpol /get output to decide whether it is needed). Returns null
        /// on success, else the failure description.</summary>
        private static async Task<string> EnsureAuditPolicyAsync()
        {
            try
            {
                var psi = new ProcessStartInfo(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "auditpol.exe"))
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    ArgumentList =
                    {
                        "/set",
                        "/subcategory:" + FilteringPlatformConnectionSubcategoryGuid,
                        "/failure:enable",
                    },
                };
                using var process = Process.Start(psi);
                if (process == null) return "auditpol did not start";
                var stderrTask = process.StandardError.ReadToEndAsync();
                string output = await process.StandardOutput.ReadToEndAsync();
                string errors = await stderrTask;
                if (!process.WaitForExit(15000))
                {
                    try { process.Kill(true); } catch { /* already gone */ }
                    return "auditpol timed out";
                }
                if (process.ExitCode != 0)
                    return $"auditpol exited {process.ExitCode} ({(errors ?? output ?? "").Trim()})";
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        // ── event handling ────────────────────────────────────────────────

        private void Watcher_DenyWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventRecord == null) return;
                DenyEvent deny = ParseEventXml(e.EventRecord.ToXml());
                if (deny == null) return;

                // Only OUR blocks get explained — Windows' own policy denies
                // are noise for this feed (and would otherwise toast constantly).
                var blocked = BlockHitFeedService.Instance.BlockedIp(deny.DestIp);
                if (blocked == null) return;
                deny.BlockedClass = blocked.Class ?? "";
                deny.Rules = blocked.Rules;
                deny.EnabledRules = blocked.EnabledRules;

                bool isNewToast;
                lock (_gate)
                {
                    _denies.Add(deny);
                    if (_denies.Count > MaxDenies) _denies.RemoveRange(0, _denies.Count - MaxDenies);
                    _dirty = true;
                    LastDenyUtc = deny.TimeUtc;
                }
                isNewToast = ShouldToast(DateTime.UtcNow, deny.Image, deny.DestIp, ToastWindow);

                // Raised AFTER the record is durable in memory and OUTSIDE the
                // gate, per-subscriber try/catch — the same discipline the
                // block-hit feed uses.
                try { DenyArrived?.Invoke(deny); }
                catch { /* a subscriber failing must not fail the watcher */ }

                if (isNewToast && OnDenyToast != null)
                {
                    try { OnDenyToast("AutoCommand blocked a connection", BuildToastMessage(deny), null); }
                    catch { /* a toast failing must not fail the watcher */ }
                }
            }
            catch { /* a malformed record never takes the watcher down */ }
        }

        /// <summary>Rate limiter (pure decision + timestamp bookkeeping, split
        /// so the offline self-test can drive ShouldToast directly): one toast
        /// per (process image, destination) per window; re-arming after the
        /// window passes. Returns whether THIS event should toast.</summary>
        internal bool ShouldToast(DateTime nowUtc, string image, string destIp, TimeSpan window)
        {
            string key = $"{(image ?? "").ToLowerInvariant()}|{(destIp ?? "").ToLowerInvariant()}";
            while (true)
            {
                if (!_lastToast.TryGetValue(key, out var last))
                {
                    if (_lastToast.TryAdd(key, nowUtc)) return true;
                    continue;   // lost a race with a concurrent attempt — re-read
                }
                if (nowUtc - last < window) return false;
                if (_lastToast.TryUpdate(key, nowUtc, last)) return true;
                continue;   // another thread refreshed first — this one stays quiet
            }
        }

        /// <summary>Human sentence for the toast: who, where, why, and what
        /// will keep happening until the user decides.</summary>
        internal static string BuildToastMessage(DenyEvent d)
        {
            string proc = string.IsNullOrEmpty(d.Image)
                ? "A program"
                : Path.GetFileName(d.Image);
            string cls = string.IsNullOrEmpty(d.BlockedClass) ? "" : $" ({d.BlockedClass})";
            return $"{proc} tried to reach {d.DestIp}:{d.DestPort} over {d.Protocol} and was refused by your " +
                   $"AutoCommand block rule{cls}. This keeps failing until you unblock it — review in the Blocks tab.";
        }

        /// <summary>Pure parser, internal for the offline self-test: one 5157
        /// XML record → DenyEvent, or null when it is not usable. Parses
        /// EventData by NAME (never by position — Windows adds fields between
        /// builds) and maps the numeric protocol to its familiar name.</summary>
        internal static DenyEvent ParseEventXml(string xml)
        {
            try
            {
                var doc = XDocument.Parse(xml);
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var eventData = doc.Root?.Element(ns + "EventData");
                if (eventData == null) return null;

                string image = "", destIp = "", protocol = "", layerName = "";
                int destPort = 0;
                long filterRtId = 0;
                foreach (var data in eventData.Elements(ns + "Data"))
                {
                    switch (data.Attribute("Name")?.Value)
                    {
                        case "Application": image = data.Value; break;
                        case "DestAddress": destIp = data.Value; break;
                        case "DestPort": int.TryParse(data.Value, out destPort); break;
                        case "Protocol": protocol = data.Value; break;
                        case "FilterRTID": long.TryParse(data.Value, out filterRtId); break;
                        case "LayerName": layerName = data.Value; break;
                    }
                }
                if (string.IsNullOrEmpty(destIp) || !System.Net.IPAddress.TryParse(destIp, out _)) return null;

                return new DenyEvent
                {
                    TimeUtc = DateTime.UtcNow,
                    Image = image,
                    DestIp = destIp,
                    DestPort = destPort,
                    Protocol = ProtocolName(protocol),
                    FilterRtId = filterRtId,
                    LayerName = layerName,
                };
            }
            catch { return null; }
        }

        private static string ProtocolName(string numeric)
        {
            switch (numeric?.Trim())
            {
                case "6": return "TCP";
                case "17": return "UDP";
                case "1": return "ICMP";
                default: return string.IsNullOrEmpty(numeric) ? "?" : numeric;
            }
        }

        // ── queries ───────────────────────────────────────────────────────

        public List<DenyEvent> Recent(int minutes, int max = 200)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-Math.Max(1, minutes));
            lock (_gate)
                return _denies.Where(d => d.TimeUtc >= cutoff)
                              .OrderByDescending(d => d.TimeUtc)
                              .Take(max).ToList();
        }

        /// <summary>Recent per-destination denial counts (kernel ground truth
        /// for the Blocks tab's "why is this failing" moments).</summary>
        public Dictionary<string, int> DeniesByIp(int minutes)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-Math.Max(1, minutes));
            lock (_gate)
                return _denies.Where(d => d.TimeUtc >= cutoff && !string.IsNullOrEmpty(d.DestIp))
                              .GroupBy(d => d.DestIp, StringComparer.OrdinalIgnoreCase)
                              .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        }

        // ── persistence (house JSONL pattern, mirrors block-hits.jsonl) ──

        private void Load()
        {
            try
            {
                if (!File.Exists(StorePath)) return;
                var loaded = new List<DenyEvent>();
                foreach (string line in File.ReadLines(StorePath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var d = JsonSerializer.Deserialize<DenyEvent>(line);
                    if (d?.TimeUtc != null && d.TimeUtc > DateTime.UtcNow - Retain) loaded.Add(d);
                }
                lock (_gate)
                {
                    _denies.Clear();
                    // oldest-first, so append + front-eviction stay correct
                    // (the ordering bug class BlockHitFeedService documented)
                    _denies.AddRange(loaded.OrderByDescending(d => d.TimeUtc).Take(MaxDenies).OrderBy(d => d.TimeUtc));
                }
            }
            catch { /* a corrupt store starts fresh, never blocks startup */ }
        }

        private void SaveIfDirty()
        {
            List<DenyEvent> snapshot;
            lock (_gate)
            {
                if (!_dirty) return;
                _dirty = false;
                snapshot = _denies.ToList();
            }
            try
            {
                Directory.CreateDirectory(StoreDirectory);
                string tmp = StorePath + ".tmp";
                using (var w = new StreamWriter(tmp))
                    foreach (var d in snapshot)
                        w.WriteLine(JsonSerializer.Serialize(d));
                File.Delete(StorePath);
                File.Move(tmp, StorePath);
            }
            catch { /* offline disk is survivable — the feed stays in memory */ }
        }
    }
}
