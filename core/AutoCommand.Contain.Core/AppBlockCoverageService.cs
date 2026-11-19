using AutoCommand.NetWatch.Core;
using System;
using AutoCommand.Contain.Core;
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
    /// Keeps name-blocked apps blocked wherever they run from. Windows Firewall
    /// enforces an app rule by exact image path, and binaries move — WebView2
    /// lives in a versioned folder that is deleted on every runtime update, so
    /// a block pinned to the old path goes inert while the process keeps
    /// transmitting from the new one. This service closes that gap:
    ///
    ///   · watches Sysmon EID 1 (process create) — when an image whose exe NAME
    ///     is blocked appears at a path no rule covers, a sibling rule for that
    ///     path is added immediately, at the moment the new binary first runs;
    ///   · sweeps running processes at startup (covers processes created before
    ///     the watcher started);
    ///   · sweeps the DISK on a cadence — for every name-blocked exe, copies
    ///     that exist but have not run (sibling version folders of covered
    ///     paths, plus the binary's other documented install roots) get
    ///     covered before their first packet. This is the leg that holds
    ///     when Sysmon is absent: nothing has to spawn for coverage to hold.
    ///   · periodically retires dead-path rules once a live sibling exists
    ///     (FirewallService.RetireDeadAppBlockRulesAsync — never the last rule
    ///     of a target).
    ///
    /// Auto-extending only ever blocks MORE — a malware binary name-squatting a
    /// blocked exe in another folder gets blocked too — so no confirmation is
    /// needed. Every extension is appended to app-block-extensions.jsonl beside
    /// the block-hits archive (house persistence pattern) so the audit trail
    /// survives restarts.
    /// </summary>
    public sealed class AppBlockCoverageService
    {
        public static AppBlockCoverageService Instance => _instance ??= new AppBlockCoverageService();
        private static AppBlockCoverageService _instance;

        private const int MaxHistory = 500;
        private static readonly TimeSpan InventoryRefresh = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan FirstSweepDelay = TimeSpan.FromMinutes(1);
        private static readonly TimeSpan GcInterval = TimeSpan.FromHours(6);
        private static readonly TimeSpan DiskSweepInterval = TimeSpan.FromHours(1);

        /// <summary>One coverage extension / retirement, also persisted as JSONL.</summary>
        public sealed class CoverageEvent
        {
            public string TimeUtc { get; set; }
            public string Action { get; set; }      // "extended" | "retired" | "startup-sweep-extended" | "disk-sweep-extended"
            public string Exe { get; set; }
            public string Path { get; set; }
            public string RuleName { get; set; }
            public string Detail { get; set; }
        }

        private readonly object _gate = new();
        private HashSet<string> _blockedNames = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _coveredPaths = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Exe names whose ledger record is alive but whose path is
        /// gone (imported ledgers, moved programs). Derived from the store on
        /// every cache refresh — no persistence of its own, because the
        /// ledger is the source of truth. A dormant name trips the same
        /// three triggers a blocked name does; when it fires, the new path
        /// is blocked and the ledger record re-points to it (Resurrection).</summary>
        private HashSet<string> _dormantNames = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<CoverageEvent> _history = new();
        private EventLogWatcher _watcher;
        private Timer _refreshTimer, _gcTimer, _sweepTimer;
        private bool _running, _dirty;

        public string WatcherError { get; private set; }
        public DateTime LastRefreshUtc { get; private set; }
        public bool IsRunning { get { lock (_gate) return _running; } }

        /// <summary>Persistence root; settable for offline self-tests (house pattern).</summary>
        public static string StoreDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private static string StorePath => Path.Combine(StoreDirectory, "app-block-extensions.jsonl");

        private AppBlockCoverageService() { }

        /// <summary>Idempotent: safe to call from startup, the Blocks tab, bridge handlers.</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_running) return;
                _running = true;
            }
            Load();
            _ = RefreshCacheAsync();
            _ = Task.Run(StartupSweepAsync);

            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational",
                    PathType.LogName, "*[System[(EventID=1)]]");
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += Watcher_ProcessCreated;
                _watcher.Enabled = true;
            }
            catch (EventLogNotFoundException)
            {
                WatcherError = "Sysmon is not installed — live coverage extension is inactive " +
                    "(startup sweep and retire pass still run). Install Sysmon from the Sysmon Audit tab.";
            }
            catch (Exception ex)
            {
                WatcherError = $"Failed to start process-create watcher: {ex.Message}";
            }

            _refreshTimer = new Timer(_ => _ = RefreshCacheAsync(), null,
                InventoryRefresh, InventoryRefresh);
            _gcTimer = new Timer(_ => _ = RunRetirePassAsync(), null,
                FirstSweepDelay + TimeSpan.FromSeconds(30), GcInterval);
            // first disk sweep shortly after the cache has filled; hourly after
            _sweepTimer = new Timer(_ => _ = ProactiveSweepAsync(), null,
                FirstSweepDelay + TimeSpan.FromSeconds(15), DiskSweepInterval);
        }

        public void Stop()
        {
            lock (_gate)
            {
                if (!_running) return;
                _running = false;
                _refreshTimer?.Dispose(); _refreshTimer = null;
                _gcTimer?.Dispose(); _gcTimer = null;
                _sweepTimer?.Dispose(); _sweepTimer = null;
            }
            _watcher?.Dispose();
            _watcher = null;
            SaveIfDirty();
        }

        // ── cache ─────────────────────────────────────────────────────────

        private async Task RefreshCacheAsync()
        {
            try
            {
                BlocksStore.Load();   // idempotent; dormant names derive from the ledger
                var inv = await FirewallService.Instance.GetBlockedInventoryAsync();
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var t in inv)
                {
                    if (t.Kind != "app" || t.EnabledRules == 0) continue;   // paused blocks must not auto-extend
                    names.Add(t.Target);
                    if (!string.IsNullOrEmpty(t.AppPath))
                        paths.Add(t.AppPath.ToLowerInvariant());
                }
                var dormant = new HashSet<string>(
                    BlocksStore.Records
                        .Where(r => r.Kind == "proc" && r.Status != "off" && !File.Exists(r.Key ?? ""))
                        .Select(r => Path.GetFileName(r.Key ?? "")),
                    StringComparer.OrdinalIgnoreCase);
                dormant.Remove("");
                string[] newNames;
                lock (_gate)
                {
                    newNames = names.Except(_blockedNames).ToArray();   // both sets ignore case
                    _blockedNames = names;
                    _coveredPaths = paths;
                    _dormantNames = dormant;
                    LastRefreshUtc = DateTime.UtcNow;
                }
                // A name that just entered the block list gets its on-disk
                // copies covered immediately — a fresh block should not wait
                // for the hourly sweep to become multi-path.
                if (newNames.Length > 0) _ = ProactiveSweepAsync(newNames);
            }
            catch { /* cache stays at last good snapshot; next tick retries */ }
        }

        // ── triggers ──────────────────────────────────────────────────────

        private void Watcher_ProcessCreated(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e.EventRecord == null) return;
                var doc = XDocument.Parse(e.EventRecord.ToXml());
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var eventData = doc.Root?.Element(ns + "EventData");
                if (eventData == null) return;

                string image = "", parent = "";
                foreach (var data in eventData.Elements(ns + "Data"))
                {
                    switch (data.Attribute("Name")?.Value)
                    {
                        case "Image": image = data.Value; break;
                        case "ParentImage": parent = data.Value; break;
                    }
                }
                if (string.IsNullOrEmpty(image)) return;

                _ = EnsureCoveredAsync(image, "process create", parent);
            }
            catch { /* a malformed record never takes the watcher down */ }
        }

        /// <summary>
        /// Startup sweep: processes already running when the service starts were
        /// never seen by the EID 1 watcher — cover their paths too. MainModule
        /// needs access the app may lack for elevated processes; per-process
        /// failures are skipped silently.
        /// </summary>
        private async Task StartupSweepAsync()
        {
            try
            {
                await Task.Delay(FirstSweepDelay);   // let the cache fill first
                foreach (var proc in Process.GetProcesses())
                {
                    string path = null;
                    try { path = proc.MainModule?.FileName; }
                    catch { /* elevated / exited / protected — skip */ }
                    finally { proc.Dispose(); }
                    if (!string.IsNullOrEmpty(path))
                        await EnsureCoveredAsync(path, "startup sweep", null);
                }
            }
            catch { /* sweep is best-effort */ }
        }

        /// <summary>
        /// Binaries Microsoft ships in more than one install root, so a name
        /// block must cover every documented location, not just the path that
        /// was seen. WebView2 is the case that bit in the wild: a versioned
        /// folder under EdgeWebView\Application (deleted on every runtime
        /// update) plus a second copy under System32\Microsoft-Edge-WebView.
        /// Extend by exe name as new multi-root binaries are confirmed.
        /// </summary>
        private static readonly Dictionary<string, string[]> KnownMultiRootExes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["msedgewebview2.exe"] = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Microsoft-Edge-WebView"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\EdgeWebView\Application"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\EdgeWebView\Application"),
            },
        };

        /// <summary>
        /// Pure enumeration: every on-disk copy of the exe worth covering,
        /// given the paths already covered. Two sources: sibling version
        /// folders of each covered path (the Application\157.0.4341.42 →
        /// Application\* pattern — only when the parent folder is
        /// version-named, so a blocked C:\Tools\upd.exe never sweeps the
        /// whole drive), and the documented extra roots of known multi-root
        /// binaries (one wildcard level for versioned layouts). Extra roots
        /// are injectable so the offline self-test can point at a temp tree.
        /// </summary>
        public static List<string> EnumerateDiskCopies(string exe, IEnumerable<string> coveredPaths,
            IEnumerable<string> extraRoots = null)
        {
            var covered = new HashSet<string>(coveredPaths ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var results = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Consider(string candidate)
            {
                try
                {
                    if (string.IsNullOrEmpty(candidate)) return;
                    string path = Path.GetFullPath(candidate);
                    if (!seen.Add(path)) return;
                    if (covered.Contains(path)) return;
                    if (File.Exists(path)) results.Add(path);
                }
                catch { /* unmappable path (drive letter gone) — skip */ }
            }

            foreach (string coveredPath in covered)
            {
                try
                {
                    // the version folder the covered binary sits in
                    string versionDir = Path.GetDirectoryName(coveredPath.TrimEnd('\\'));
                    string versionName = string.IsNullOrEmpty(versionDir) ? "" : Path.GetFileName(versionDir);
                    if (versionName.Length == 0 || !char.IsDigit(versionName[0])) continue;
                    string appRoot = Path.GetDirectoryName(versionDir);   // e.g. ...\EdgeWebView\Application
                    if (string.IsNullOrEmpty(appRoot)) continue;
                    foreach (string dir in Directory.EnumerateDirectories(appRoot))
                        Consider(Path.Combine(dir, exe));
                }
                catch { /* unreadable anchor — skip it */ }
            }

            var roots = new List<string>();
            if (KnownMultiRootExes.TryGetValue(exe, out string[] known)) roots.AddRange(known);
            if (extraRoots != null) roots.AddRange(extraRoots);
            foreach (string root in roots)
            {
                try
                {
                    if (string.IsNullOrEmpty(root)) continue;
                    Consider(Path.Combine(root, exe));
                    foreach (string dir in Directory.EnumerateDirectories(root))
                        Consider(Path.Combine(dir, exe));
                }
                catch { /* root absent — skip */ }
            }

            return results;
        }

        /// <summary>
        /// Where do these exes live NOW, if anywhere? The re-point leg for
        /// dormant ledger records, so a decision whose path was wiped can be
        /// rescued instead of sitting dead. Two bounded sources: running
        /// processes (the exact answer when the program is active — one
        /// MainModule pass for every name at once), then a shallow walk
        /// (root + one level) of the documented install roots. Deliberately
        /// NOT a drive walk — the slow "arrives later" case belongs to the
        /// dormant tripwire, not to a blocking search.
        /// </summary>
        public static Dictionary<string, List<string>> FindLiveCopies(
            IEnumerable<string> exeNames, int budgetMsTotal = 6000)
        {
            var wanted = new HashSet<string>(exeNames ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            wanted.Remove("");
            var found = wanted.ToDictionary(n => n, _ => new List<string>(), StringComparer.OrdinalIgnoreCase);
            if (wanted.Count == 0) return found;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sw = Stopwatch.StartNew();

            void Consider(string path)
            {
                if (string.IsNullOrEmpty(path)) return;
                string name;
                try { name = Path.GetFileName(path); } catch { return; }
                if (wanted.Contains(name) && seen.Add(path)) found[name].Add(path);
            }

            try
            {
                // running processes first — highest-confidence, cheapest signal
                foreach (var proc in Process.GetProcesses())
                {
                    string path = null;
                    try { path = proc.MainModule?.FileName; }
                    catch { /* elevated / exited / protected — skip */ }
                    finally { proc.Dispose(); }
                    Consider(path);
                    if (sw.ElapsedMilliseconds > budgetMsTotal) return found;
                }

                string[] roots =
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                };
                foreach (string root in roots)
                {
                    if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
                    try
                    {
                        foreach (string dir in new[] { root }.Concat(Directory.EnumerateDirectories(root)))
                        {
                            try
                            {
                                foreach (string f in Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly))
                                    Consider(f);
                            }
                            catch { /* access denied — skip this folder */ }
                            if (sw.ElapsedMilliseconds > budgetMsTotal) return found;
                        }
                    }
                    catch { /* root absent — skip */ }
                    if (sw.ElapsedMilliseconds > budgetMsTotal) return found;
                }
            }
            catch { /* best-effort — partial results are still useful */ }
            return found;
        }

        /// <summary>
        /// The Sysmon-less leg: cover what exists on disk, not just what has
        /// run. Snapshots the cache under the gate, enumerates, then reuses
        /// EnsureCoveredAsync so the add/dedupe/record path stays
        /// single-tracked. Failures are swallowed per the service contract —
        /// the next cadence retries.
        /// </summary>
        private async Task ProactiveSweepAsync(IEnumerable<string> onlyNames = null)
        {
            try
            {
                string[] names;
                HashSet<string> paths;
                lock (_gate)
                {
                    names = _blockedNames.ToArray();
                    paths = new HashSet<string>(_coveredPaths, StringComparer.OrdinalIgnoreCase);
                }
                HashSet<string> filter = onlyNames == null
                    ? null
                    : new HashSet<string>(onlyNames, StringComparer.OrdinalIgnoreCase);
                foreach (string name in names)
                {
                    if (filter != null && !filter.Contains(name)) continue;
                    foreach (string copy in EnumerateDiskCopies(name, paths))
                        await EnsureCoveredAsync(copy, "disk sweep", null);
                }
            }
            catch { /* sweep is best-effort; the next cadence retries */ }
        }

        /// <summary>
        /// The shared decision: exe name blocked, this path not covered → add a
        /// sibling rule with full provenance. Cheap two-set lookup when nothing
        /// matches, so it is safe to call for every process create.
        /// </summary>
        public async Task EnsureCoveredAsync(string imagePath, string trigger, string parentImage)
        {
            try
            {
                if (string.IsNullOrEmpty(imagePath)) return;
                string exe = Path.GetFileName(imagePath);
                string pathKey = imagePath.ToLowerInvariant();
                bool dormantHit;
                lock (_gate)
                {
                    dormantHit = _dormantNames.Contains(exe);
                    if (!_blockedNames.Contains(exe) && !dormantHit) return;
                    if (_coveredPaths.Contains(pathKey)) return;
                }

                string utc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm");
                string desc = dormantHit
                    ? $"[blocked {utc} UTC] {exe} — dormant block re-armed: the ledger record's path was gone " +
                      $"(imported ledger or moved program) and this binary just appeared ({trigger}) · " +
                      $"parent: {parentImage ?? "unknown"} · AutoCommand AppBlockCoverageService"
                    : $"[blocked {utc} UTC] {exe} — coverage auto-extended to new path " +
                      $"({trigger}; app updated or moved) · parent: {parentImage ?? "unknown"} · " +
                      $"AutoCommand AppBlockCoverageService";

                var (created, _, ruleName) = await FirewallService.Instance.AddAppBlockWithPathAsync(imagePath, desc);
                if (created > 0)
                {
                    lock (_gate)
                    {
                        _blockedNames.Add(exe);
                        _dormantNames.Remove(exe);
                        _coveredPaths.Add(pathKey);
                    }
                    if (dormantHit)
                    {
                        // the decision transfers: ledger record(s) of this exe
                        // name re-point to the live path, and its other on-disk
                        // copies get covered in the same pass
                        BlocksStore.RepointDeadForExeName(exe, imagePath, "coverage-watch");
                        _ = ProactiveSweepAsync(new[] { exe });
                    }
                    Record(new CoverageEvent
                    {
                        TimeUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                        Action = dormantHit ? "dormant-extended"
                            : trigger switch
                            {
                                "startup sweep" => "startup-sweep-extended",
                                "disk sweep" => "disk-sweep-extended",
                                _ => "extended",
                            },
                        Exe = exe,
                        Path = imagePath,
                        RuleName = ruleName ?? "",
                        Detail = dormantHit
                            ? $"dormant ledger block resurrected at this path · trigger: {trigger} · parent: {parentImage ?? "unknown"}"
                            : $"trigger: {trigger} · parent: {parentImage ?? "unknown"}",
                    });
                }
            }
            catch { /* never let a coverage check disturb the caller */ }
        }

        /// <summary>
        /// Called immediately when an executable path is blocked so coverage
        /// tracking and disk-copy extension take effect in O(1) without waiting
        /// on or firing a full-firewall inventory scan.
        /// </summary>
        public void NotifyBlocked(string appPath)
        {
            if (string.IsNullOrEmpty(appPath)) return;
            string exe;
            try { exe = Path.GetFileName(appPath); } catch { return; }
            if (string.IsNullOrEmpty(exe)) return;

            bool isNewExe;
            lock (_gate)
            {
                isNewExe = _blockedNames.Add(exe);
                _coveredPaths.Add(appPath.ToLowerInvariant());
            }

            if (isNewExe)
                _ = ProactiveSweepAsync(new[] { exe });
        }

        /// <summary>
        /// Called the moment a target is unblocked: drops the exe name from
        /// the cached blocked-name set so a process-create arriving before
        /// the next 30 s inventory refresh cannot re-extend the block the
        /// user just lifted (for a constantly-spawning exe that window is a
        /// guaranteed resurrection, not a race). The next RefreshCacheAsync
        /// re-reads the firewall and restores truth — including a surviving
        /// sibling's rules, should any remain.
        /// </summary>
        public void NotifyUnblocked(string exeName)
        {
            if (string.IsNullOrEmpty(exeName)) return;
            lock (_gate)
            {
                _blockedNames.Remove(exeName);
            }
        }

        private async Task RunRetirePassAsync()
        {
            try
            {
                var (targets, retired) = await FirewallService.Instance.RetireDeadAppBlockRulesAsync();
                if (retired > 0)
                {
                    Record(new CoverageEvent
                    {
                        TimeUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                        Action = "retired",
                        Exe = "",
                        Path = "",
                        RuleName = "",
                        Detail = $"{retired} dead-path rule(s) retired across {targets} app target(s)",
                    });
                    await RefreshCacheAsync();
                }
            }
            catch { /* next pass retries */ }
        }

        // ── history + persistence (house JSONL pattern) ───────────────────

        public List<CoverageEvent> RecentEvents(int max = 100)
        {
            lock (_gate) return _history.TakeLast(max).Reverse().ToList();
        }

        private void Record(CoverageEvent e)
        {
            lock (_gate)
            {
                _history.Add(e);
                if (_history.Count > MaxHistory) _history.RemoveRange(0, _history.Count - MaxHistory);
                _dirty = true;
            }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(StorePath)) return;
                lock (_gate)
                {
                    foreach (string line in File.ReadAllLines(StorePath))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var e = JsonSerializer.Deserialize<CoverageEvent>(line);
                        if (e != null) _history.Add(e);
                    }
                    if (_history.Count > MaxHistory) _history.RemoveRange(0, _history.Count - MaxHistory);
                }
            }
            catch { /* unreadable history is not fatal */ }
        }

        private void SaveIfDirty()
        {
            try
            {
                List<CoverageEvent> snapshot;
                lock (_gate)
                {
                    if (!_dirty) return;
                    snapshot = _history.ToList();
                    _dirty = false;
                }
                Directory.CreateDirectory(StoreDirectory);
                File.WriteAllLines(StorePath, snapshot.Select(e => JsonSerializer.Serialize(e)));
            }
            catch { /* persistence is best-effort */ }
        }
    }
}
