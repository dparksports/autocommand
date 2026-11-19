using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AutoCommand.Light
{
    /// <summary>
    /// The gatekeeper. The world model in code: the internet is closed by
    /// default, the user's browsers talk, everything else asks first.
    ///
    ///  · PermissionStore carries the user's decisions (apps.json, plain
    ///    JSON, in Light's data folder).
    ///  · SweepAsync is the enforcement tick: expire allow-once grants,
    ///    resolve every known app through GatePolicy, and make the
    ///    firewall agree (AL-BLOCK-APP rule ensured or removed — the
    ///    engine's adds are idempotent, and a semaphore serializes them).
    ///  · A first attempt from an unknown app raises an AskTicket; the
    ///    dialog owns the 90-second countdown, and expiry means Never —
    ///    silence is an answer, and it is the safe one.
    ///  · PauseGuard is the panic action: open everything, temporarily,
    ///    re-announced on Today and the tray until it ends.
    ///
    /// Exemptions are named, never silent: svchost and Windows-dir images
    /// are "Windows (system)" in the UI — the honest fine print of
    /// "nobody transmits except you".
    /// </summary>
    public static class LightGate
    {
        private static PermissionStore _store = new();
        public static PermissionStore Store => _store;

        private static string StorePath => Path.Combine(LightServices.Root, "apps.json");

        private static readonly SemaphoreSlim RuleLock = new(1, 1);
        private static readonly HashSet<string> _gatedKeys = new(StringComparer.OrdinalIgnoreCase);
        private static readonly List<AskTicket> _tickets = new();
        private static readonly List<Core.AttemptFact> _attempts = new();
        private static readonly HashSet<string> _attemptSeen = new(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> _dismissedKeys = new(StringComparer.OrdinalIgnoreCase);
        private static DateTime? _openUntilUtc;
        private static bool _pausedExplicitly;

        public static bool IsOpen => _openUntilUtc.HasValue && DateTime.UtcNow < _openUntilUtc.Value;

        /// <summary>Injected by the shell: is this app user-driven right
        /// now (foreground, visible window, or launched from the user's
        /// terminal/IDE)? The gate uses the answer only for courtesy —
        /// promote the question to a balloon — never for auto-decisions.</summary>
        public static Func<string, bool>? InteractiveProbe { get; set; }

        /// <summary>Raised when a user-driven app is first held, so the
        /// tray can put the question where the person actually is.</summary>
        public static event Action<string, string>? HoldRaised;

        /// <summary>Fired on the UI dispatcher when asks or decisions
        /// change (the shell marshals before invoking).</summary>
        public static event Action? Changed;

        private static void FireChanged()
        {
            try { Changed?.Invoke(); } catch { /* a listener must not break the gate */ }
        }

        public static void Initialize()
        {
            if (File.Exists(StorePath))
            {
                _store = Core.PermissionStore.FromJson(File.ReadAllText(StorePath));
            }
            else
            {
                _store = Core.PermissionStore.Seeded(DateTime.UtcNow);
                Save();
            }
            LightServices.WatcherCreated += OnWatcherCreated;
            BlockHitFeedService.Instance.HitArrived += OnBlockHit;
            FirewallDenyWatchService.Instance.DenyArrived += OnDeny;
        }

        private static void OnWatcherCreated(SysmonWatcherService watcher)
        {
            watcher.OnNewConnectionTracked += item => OnAttempt(item);
        }

        private static void OnDeny(FirewallDenyWatchService.DenyEvent d) =>
            RecordAttempt(ImageBaseName(d.Image), d.DestIp, d.TimeUtc);

        private static void OnBlockHit(BlockHitFeedService.BlockHit hit) =>
            RecordAttempt(ImageBaseName(hit.Image), hit.DestIp, hit.TimeUtc);

        /// <summary>Any reach for the internet: new live row (first attempt)
        /// or a stopped attempt (hit/deny). Deduped per app+destination
        /// minute so a burst stays one fact.</summary>
        private static void OnAttempt(SvchostMonitorItem item)
        {
            try
            {
                RecordAttempt(ImageBaseName(item.ProcessName), item.RemoteIp, DateTime.UtcNow);
                var decision = Core.GatePolicy.Resolve(item.ProcessName, item.ImagePath,
                    item.IsSvchost, _store, DateTime.UtcNow);
                if (decision.ShouldGate && !string.IsNullOrWhiteSpace(item.ImagePath))
                {
                    var key = Core.PermissionStore.NormalizeKey(item.ProcessName);
                    EnsureBlocked(item.ImagePath, key);
                    if (decision.IsNew && !_tickets.Any(t => t.Key == key) &&
                        !_dismissedKeys.Contains(key))
                    {
                        var display = DisplayNameFor(key, item.ProcessName);
                        var userDriven = InteractiveProbe?.Invoke(key) ?? false;
                        _tickets.Add(new Core.AskTicket(key, display,
                            item.ImagePath, DateTime.UtcNow,
                            DateTime.UtcNow.AddSeconds(Core.AskTicket.TimeoutSeconds),
                            userDriven));
                        if (userDriven)
                            try { HoldRaised?.Invoke(key, display); } catch { }
                        FireChanged();
                    }
                }
            }
            catch { // the gate must never fall out of the event stream
            }
        }

        private static void RecordAttempt(string appKey, string destination, DateTime timeUtc)
        {
            if (string.IsNullOrWhiteSpace(appKey)) return;
            var fingerprint = $"{appKey}|{destination}|{timeUtc:yyyyMMddHHmm}";
            lock (_attemptSeen)
            {
                if (!_attemptSeen.Add(fingerprint)) return;
                lock (_attempts)
                {
                    _attempts.Add(new Core.AttemptFact(appKey, DisplayNameFor(appKey, appKey),
                        timeUtc, destination ?? ""));
                    // the ring holds the last two days; today's view only
                    // reads its own date, two days absorbs midnight rolls
                    if (_attempts.Count > 4000)
                        _attempts.RemoveRange(0, _attempts.Count - 2000);
                }
            }
            FireChanged();
        }

        /// <summary>The enforcement tick. Everything the gate does to the
        /// firewall happens here (plus the immediate ensure on first
        /// attempt, so the first handshake never escapes).</summary>
        public static async Task SweepAsync()
        {
            var now = DateTime.UtcNow;

            // 1. expire allow-once grants — the gate closes itself
            foreach (var entry in _store.Entries.Where(e => e.IsExpiredAllow(now)).ToList())
            {
                _store.Upsert(entry with { Permission = Core.AppPermission.Ask, AllowUntilUtc = null, Source = "allow-once-expired" });
                _gatedKeys.Remove(entry.Key);
                Save();
            }

            // 2. temporary open-everything: hold, then re-arm on expiry
            if (_openUntilUtc.HasValue)
            {
                if (now < _openUntilUtc.Value) return;
                _openUntilUtc = null;
                _pausedExplicitly = false;
                FireChanged();
            }
            if (_pausedExplicitly) return;

            // 3. resolve every app the machine is running
            var groups = LightServices.Tracked.Values
                .Where(r => !string.IsNullOrWhiteSpace(r.ImagePath))
                .GroupBy(r => Core.PermissionStore.NormalizeKey(r.ProcessName))
                .ToList();

            foreach (var g in groups)
            {
                var first = g.First();
                var decision = Core.GatePolicy.Resolve(first.ProcessName, first.ImagePath,
                    first.IsSvchost, _store, now);
                var path = first.ImagePath;
                if (decision.ShouldGate) await EnsureBlocked(path, g.Key);
                else await EnsureOpen(path, g.Key);
            }

            // 4. tickets past their deadline dismiss themselves — the app
            //    STAYS HELD as an Ask (the sweep keeps enforcing), and the
            //    decision waits in the digest. Never is explicit-only:
            //    silence keeps a person's tools safe, it never condemns
            //    them (the zcode incident is the reason this paragraph
            //    exists).
            var expired = _tickets.Where(t => t.Expired(DateTime.UtcNow)).ToList();
            foreach (var t in expired)
                _dismissedKeys.Add(t.Key);
            if (expired.Count > 0)
            {
                _tickets.RemoveAll(t => t.Expired(DateTime.UtcNow));
                Save();
                FireChanged();
            }
        }

        private static async Task EnsureBlocked(string imagePath, string key)
        {
            if (_gatedKeys.Contains(key)) return;
            await RuleLock.WaitAsync();
            try
            {
                await LightServices.Firewall.AddAppBlockAsync(imagePath, LightServices.OwnMarker + " · gate");
                _gatedKeys.Add(key);
                // the gate's own ledger line: Light's History/Attempts page
                // can explain every hold without guesswork
                LightServices.Ledger.AppendEvent("gate-hold", "proc", imagePath,
                    $"{DisplayNameFor(key, key)} is held by the gate", "light-gate");
            }
            finally { RuleLock.Release(); }
        }

        private static async Task EnsureOpen(string imagePath, string key)
        {
            if (!_gatedKeys.Contains(key)) return;
            await RuleLock.WaitAsync();
            try
            {
                await LightServices.Firewall.RemoveBlockRulesForAppAsync(imagePath);
                _gatedKeys.Remove(key);
                LightServices.Ledger.AppendEvent("gate-release", "proc", imagePath,
                    $"{DisplayNameFor(key, key)} may talk now", "light-gate");
            }
            finally { RuleLock.Release(); }
        }

        /// <summary>The user answered. One path for dialog, apps page,
        /// undo — the ledger of record is the store, and every decision
        /// also lands in the readable history. Explicit-only: there is no
        /// timeout path into this method anymore.</summary>
        public static void Decide(string key, Core.AppPermission permission, string displayName,
            string imagePath, string source, TimeSpan? allowFor = null)
        {
            var now = DateTime.UtcNow;
            _store.Upsert(new Core.PermissionEntry(key, permission, displayName, now,
                permission == Core.AppPermission.Always && allowFor.HasValue ? now.Add(allowFor.Value) : null,
                source));

            _dismissedKeys.Remove(key);
            _tickets.RemoveAll(t => t.Key == key);
            try
            {
                LightServices.Ledger.AppendEvent("gate-decide", "proc", imagePath ?? key,
                    $"{displayName} → {(permission == Core.AppPermission.Always ? "allowed" : permission == Core.AppPermission.Never ? "never" : "asks first")} ({source})",
                    "light-gate");
            }
            catch { // audit is best-effort; the store is the record
            }
            var apply = Task.Run(async () =>
            {
                // Always (standing or allow-once) opens the gate now; the
                // sweep closes it again when an allow-once deadline passes.
                var opens = permission == Core.AppPermission.Always;
                if (opens) await EnsureOpen(imagePath, key);
                else await EnsureBlocked(imagePath, key);
                await SweepAsync();
            });
            Save();
            FireChanged();
        }

        /// <summary>The panic action, reframed for the world model:
        /// "open the internet for everyone — temporarily". Everything the
        /// family made pauses; the gate stands down until it ends.</summary>
        public static async Task OpenForEveryoneAsync(TimeSpan duration)
        {
            _pausedExplicitly = true;
            _openUntilUtc = DateTime.UtcNow.Add(duration);
            await LightServices.Firewall.SetAllBlocksEnabledSnapshotAsync(false, false, true, null);
            LightServices.Ledger.AppendEvent("gate-open", "-", "-",
                $"internet opened for everyone for {(int)duration.TotalMinutes} min", "panic-button");
            FireChanged();
        }

        public static async Task CloseEveryoneAsync()
        {
            _pausedExplicitly = false;
            _openUntilUtc = null;
            await LightServices.Firewall.SetAllBlocksEnabledSnapshotAsync(true, false, true, null);
            LightServices.Ledger.AppendEvent("gate-closed", "-", "-",
                "blocks re-enabled from Settings", "settings");
            FireChanged();
        }

        public static IReadOnlyList<Core.AskTicket> PendingAsks()
        {
            lock (_tickets) { return _tickets.ToList(); }
        }

        /// <summary>A dialog closed without an answer (countdown ran out
        /// or the user dismissed it). The app stays HELD as an Ask — the
        /// sweep keeps enforcing — and the question moves to the digest.
        /// No timeout path ever reaches Decide().</summary>
        public static void TicketDismissed(AskTicket ticket)
        {
            _tickets.RemoveAll(t => t.Key == ticket.Key);
            _dismissedKeys.Add(ticket.Key);
            Save();
            FireChanged();
        }

        /// <summary>Today's attempts, as the Today view and the tray read
        /// them: the hit feed and the kernel deny watcher, deduped.</summary>
        public static IReadOnlyList<Core.AttemptFact> AttemptsToday()
        {
            lock (_attempts)
            {
                var today = DateTime.Today;
                return _attempts.Where(a => a.TimeUtc.ToLocalTime().Date >= today).ToList();
            }
        }

        public static void Save()
        {
            try { File.WriteAllText(StorePath, _store.ToJson()); }
            catch { // a read-only profile keeps its decisions for the session
            }
        }

        private static string DisplayNameFor(string key, string fallback)
        {
            var entry = _store.Find(key);
            if (entry != null && !string.IsNullOrWhiteSpace(entry.DisplayName)) return entry.DisplayName;
            if (Core.GatePolicy.IsBrowser(key)) return Cap(key) + " (browser)";
            return string.IsNullOrEmpty(fallback) ? Cap(key) : fallback;
        }

        private static string Cap(string s) =>
            string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];

        private static string ImageBaseName(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            var name = path;
            var slash = name.LastIndexOfAny(new[] { '\\', '/' });
            if (slash >= 0) name = name[(slash + 1)..];
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        }
    }
}
