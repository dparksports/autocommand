using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AutoCommand.Models;

namespace AutoCommand.Agent.Core
{
    /// <summary>
    /// Evaluates spawn-watch rules against Sysmon events AS THEY ARE
    /// ARCHIVED — the prefilter that means nobody has to chase a process
    /// after it is gone. The archive's Appended hook (the live watch AND
    /// Backfill both funnel through it) feeds every event here; EID-1
    /// process creates are matched against the rule files and each hit is
    /// appended to a per-day JSONL index (watches\hits\hits-yyyy-MM-dd.jsonl)
    /// with the full EventData, so a hit line is a complete substitute for
    /// the raw archive row.
    ///
    /// Decoupling from the archive lock: the hook handler only enqueues;
    /// one consumer task matches and writes. ReplayRecent re-runs the
    /// current rules over what the archive already holds (bounded window,
    /// deduped by record id), so a rule created now lights up history
    /// immediately instead of waiting for the next spawn.
    /// </summary>
    public static class SpawnWatchService
    {
        /// <summary>How far back ReplayRecent looks. The live channel only
        /// holds ~half a busy day anyway; one day is the honest window.</summary>
        private const int ReplayDays = 1;

        private static readonly object _gate = new();
        private static readonly object _writeGate = new();
        // replays serialize here: the UI's save-path replay and the
        // consumer's rule-change replay can race, and two concurrent
        // passes would both miss each other's hits in the dedupe set and
        // double-index. One gate, second pass sees the first's rows.
        private static readonly object _replayGate = new();
        private static readonly ConcurrentQueue<ArchiveEvent> _queue = new();
        private static bool _started;
        private static DateTime? _lastRuleStampUtc;
        // the day the retention pass last ran (UTC) — the consume loop
        // re-runs it when the date rolls over while the app stays up
        private static DateTime _lastPruneDayUtc = DateTime.MinValue;

        /// <summary>Rules directory. Settable so the offline self-test can
        /// redirect persistence to a temp dir (house pattern, same seam as
        /// SysmonArchiveService.ArchiveDirectory). Default matches
        /// SpawnWatchLibrary's machine location.</summary>
        public static string WatchesDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "watches");

        /// <summary>Per-day hit files live here, under the watches root.</summary>
        public static string HitsDirectory =>
            Path.Combine(WatchesDirectory, "hits");

        // ── lifecycle ─────────────────────────────────────────────────────

        /// <summary>Subscribes to the archive's Appended hook and starts the
        /// consumer. Idempotent; safe to call from the Sysmon startup path.</summary>
        public static void Start()
        {
            lock (_gate)
            {
                if (_started) return;
                _started = true;
                _lastRuleStampUtc = NewestRuleStamp();
                SysmonArchiveService.Appended += OnAppended;
                Prune(); // catch up on compression/pruning this launch skipped
                _lastPruneDayUtc = DateTime.UtcNow.Date;
                Task.Run(() =>
                {
                    try { ReplayRecent(); } catch { /* replay is best-effort */ }
                });
                Task.Run(ConsumeLoop);
            }
        }

        /// <summary>The hook handler. Runs while the archive lock is HELD —
        /// enqueue and return, nothing else.</summary>
        private static void OnAppended(object sender, ArchiveEvent e)
        {
            if (e != null) _queue.Enqueue(e);
        }

        /// <summary>Drains the queue against a fresh rule load each wake
        /// (rules are re-read per pass, so file edits take effect without a
        /// restart), and on idle wakes watches the rules directory for
        /// dropped-in or hand-edited files — a change triggers a replay so
        /// the new rules also cover the archive they were too late for.</summary>
        private static async Task ConsumeLoop()
        {
            while (true)
            {
                try
                {
                    if (_queue.IsEmpty)
                    {
                        // day rolled over while the app stayed up: yesterday's
                        // file is sealed now — compress it, prune old archives
                        if (_lastPruneDayUtc != DateTime.UtcNow.Date)
                        {
                            _lastPruneDayUtc = DateTime.UtcNow.Date;
                            Prune();
                        }
                        var stamp = NewestRuleStamp();
                        if (stamp != null && stamp != _lastRuleStampUtc)
                        {
                            _lastRuleStampUtc = stamp;
                            ReplayRecent();
                        }
                        await Task.Delay(2000).ConfigureAwait(false);
                        continue;
                    }

                    var rules = SpawnWatchLibraryRuleSnapshot();
                    var allowlist = RuleLibrary().LoadAllowlist();
                    while (_queue.TryDequeue(out var ev))
                    {
                        try { Evaluate(ev, rules, allowlist); }
                        catch { /* one bad event must not unwind the consumer */ }
                    }
                }
                catch
                {
                    // the loop itself must survive anything (disk errors,
                    // bad rule files) — pause briefly and keep going
                    try { await Task.Delay(5000).ConfigureAwait(false); } catch { }
                }
            }
        }

        private static SpawnWatchLibrary _ruleLibrary;
        private static SpawnWatchLibrary RuleLibrary() =>
            _ruleLibrary ??= new SpawnWatchLibrary(WatchesDirectory);

        private static List<SpawnWatch> SpawnWatchLibraryRuleSnapshot()
        {
            var lib = RuleLibrary();
            _lastRuleStampUtc = lib.NewestRuleStampUtc();
            return lib.Load().Where(w => w.Enabled).ToList();
        }

        private static DateTime? NewestRuleStamp()
        {
            try { return RuleLibrary().NewestRuleStampUtc(); }
            catch { return null; }
        }

        // ── matching ──────────────────────────────────────────────────────

        /// <summary>True when the event is a process create one of the rules
        /// wants. Pure — no I/O — so the self-test can drive it directly.</summary>
        public static bool MatchesAny(List<SpawnWatch> rules, List<string> allowlist,
            ArchiveEvent e, out List<SpawnWatch> matched)
        {
            matched = new List<SpawnWatch>();
            if (e == null || e.Eid != 1 || e.Data == null) return false;

            var image = e.Data.GetValueOrDefault("Image", "");
            var parent = e.Data.GetValueOrDefault("ParentImage", "");
            var cmd = e.Data.GetValueOrDefault("CommandLine", "");
            var parentCmd = e.Data.GetValueOrDefault("ParentCommandLine", "");
            var parentService = ServiceKeyFromParentCommandLine(parentCmd);

            foreach (var rule in rules)
            {
                if (!rule.Enabled) continue; // self-sufficient: direct callers may not pre-filter
                if (!WildcardMatches(rule.MatchProcess, image)) continue;
                if (!string.IsNullOrWhiteSpace(rule.MatchParent) &&
                    !WildcardMatches(rule.MatchParent, parent)) continue;
                if (!string.IsNullOrWhiteSpace(rule.ServiceKey) &&
                    !string.Equals(rule.ServiceKey.Trim(), parentService, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!string.IsNullOrWhiteSpace(rule.CommandLineContains) &&
                    (cmd ?? "").IndexOf(rule.CommandLineContains, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                if (rule.MinusAllowlist && allowlist != null &&
                    allowlist.Any(pattern => WildcardMatches(pattern, image)))
                    continue;
                matched.Add(rule);
            }
            return matched.Count > 0;
        }

        /// <summary>The -s token on a parent svchost command line ("C:\Windows\
        /// system32\svchost.exe -k netsvcs -p -s usosvc") — null when absent.</summary>
        public static string ServiceKeyFromParentCommandLine(string parentCommandLine)
        {
            if (string.IsNullOrEmpty(parentCommandLine)) return null;
            var idx = parentCommandLine.IndexOf("-s ", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;
            var rest = parentCommandLine.Substring(idx + 3).TrimStart();
            var end = rest.IndexOfAny(new[] { ' ', '"' });
            var key = end < 0 ? rest : rest.Substring(0, end);
            return key.Length == 0 ? null : key;
        }

        /// <summary>Case-insensitive '*' wildcard match, against the full
        /// path AND its leaf name — "svchost.exe" hits the System32 path,
        /// "C:\Windows\*\svchost.exe" hits it too, "*.exe" hits anything.</summary>
        public static bool WildcardMatches(string pattern, string value)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return false;
            var p = pattern.Trim().ToLowerInvariant();
            if (p == "*") return true;
            var full = (value ?? "").ToLowerInvariant();
            return MatchSegments(p, full) || MatchSegments(p, Leaf(full));
        }

        private static string Leaf(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            int i = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
            return i < 0 ? path : path[(i + 1)..];
        }

        private static bool MatchSegments(string p, string t)
        {
            int pi = 0, ti = 0, starP = -1, starT = 0;
            while (ti < t.Length)
            {
                if (pi < p.Length && p[pi] == t[ti]) { pi++; ti++; }
                else if (pi < p.Length && p[pi] == '*') { starP = pi++; starT = ti; }
                else if (starP >= 0) { pi = starP + 1; ti = ++starT; }
                else return false;
            }
            while (pi < p.Length && p[pi] == '*') pi++;
            return pi == p.Length;
        }

        // ── retention: compress sealed days, prune old archives ───────────

        /// <summary>How long compressed day archives are kept before
        /// deletion — matches the Sysmon and transmissions archives' 30-day
        /// retention, so every window the app keeps is one consistent span.</summary>
        public const int DefaultRetainDays = 30;

        /// <summary>
        /// Size management for the hits index, the house age-prune pattern
        /// (SysmonArchive.Prune / TransmissionsArchive.Prune) plus one step:
        /// day files older than yesterday are compressed to .jsonl.gz
        /// (~10x smaller), and archives older than <paramref name="retainDays"/>
        /// are deleted. Nothing reads beyond the 24 h tail window — today and
        /// yesterday stay hot — so compression costs no query any data, and
        /// the .gz files remain the manually openable record. Readers are
        /// naturally unaffected: the "hits-*.jsonl" glob never matches .gz.
        /// Tolerant of locked files (in use — try again next pass). Returns
        /// files compressed + removed.
        /// </summary>
        public static int Prune(int retainDays = DefaultRetainDays)
        {
            var actions = 0;
            try
            {
                if (!Directory.Exists(HitsDirectory)) return 0;
                var today = DateTime.UtcNow.Date;
                var compressCutoff = today.AddDays(-1); // day < cutoff ⇒ sealed and outside every read window
                var deleteCutoff = today.AddDays(-retainDays);

                foreach (var f in Directory.GetFiles(HitsDirectory, "hits-*.jsonl"))
                {
                    var day = DayOfFile(f);
                    if (day == null || day.Value >= compressCutoff) continue;
                    if (CompressDayFile(f)) actions++;
                }
                foreach (var f in Directory.GetFiles(HitsDirectory, "hits-*.jsonl.gz"))
                {
                    var day = DayOfFile(f);
                    if (day == null || day.Value >= deleteCutoff) continue;
                    try { File.Delete(f); actions++; }
                    catch { /* locked — next pass */ }
                }
            }
            catch { /* retention is opportunistic (house rule) */ }
            return actions;
        }

        /// <summary>"hits-yyyy-MM-dd.jsonl[.gz]" → its UTC day; null when the
        /// name doesn't carry a parseable day (those files are never touched).</summary>
        private static DateTime? DayOfFile(string file)
        {
            try
            {
                var name = Path.GetFileName(file);
                if (name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) name = name[..^3];
                const string ext = ".jsonl";
                if (!name.EndsWith(ext, StringComparison.OrdinalIgnoreCase) ||
                    !name.StartsWith("hits-", StringComparison.OrdinalIgnoreCase)) return null;
                var stem = name.Substring("hits-".Length, name.Length - "hits-".Length - ext.Length);
                return DateTime.TryParseExact(stem, "yyyy-MM-dd", null,
                    System.Globalization.DateTimeStyles.None, out var day) ? day : (DateTime?)null;
            }
            catch { return null; }
        }

        /// <summary>Gzip one day file beside itself and delete the original.
        /// A .gz already present (a previous pass died between the two steps)
        /// means the compression is done — just finish the delete.</summary>
        private static bool CompressDayFile(string file)
        {
            try
            {
                var gzPath = file + ".gz";
                if (!File.Exists(gzPath))
                {
                    var tmp = gzPath + ".tmp";
                    using (var src = File.OpenRead(file))
                    using (var dst = File.Create(tmp))
                    using (var gz = new GZipStream(dst, CompressionLevel.Optimal))
                        src.CopyTo(gz);
                    File.Move(tmp, gzPath);
                }
                File.Delete(file);
                return true;
            }
            catch { return false; } // locked / raced — next pass retries
        }

        // ── hit index ─────────────────────────────────────────────────────

        /// <summary>Evaluates one event and appends a hit line per matching
        /// rule. Reads are fresh; writes are serialized through _writeGate.</summary>
        private static void Evaluate(ArchiveEvent e,
            List<SpawnWatch> rules, List<string> allowlist)
        {
            if (!MatchesAny(rules, allowlist, e, out var matched)) return;

            var image = e.Data.GetValueOrDefault("Image", "");
            var pid = e.Data.GetValueOrDefault("ProcessId", "");
            var parent = e.Data.GetValueOrDefault("ParentImage", "");
            var cmd = e.Data.GetValueOrDefault("CommandLine", "");
            var service = ServiceKeyFromParentCommandLine(
                e.Data.GetValueOrDefault("ParentCommandLine", "")) ?? "";

            foreach (var rule in matched)
            {
                var line = new Dictionary<string, object>
                {
                    ["ts"] = e.TsUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    ["rule"] = rule.Name,
                    ["rid"] = e.RecordId,
                    ["image"] = image,
                    ["pid"] = pid,
                    ["parent"] = parent,
                    ["service"] = service,
                    ["cmd"] = cmd,
                    ["data"] = e.Data ?? new Dictionary<string, string>(),
                };
                lock (_writeGate)
                {
                    Directory.CreateDirectory(HitsDirectory);
                    File.AppendAllText(HitFilePath(e.TsUtc),
                        JsonSerializer.Serialize(line) + Environment.NewLine);
                }
            }
        }

        public static string HitFilePath(DateTime utc) => Path.Combine(
            HitsDirectory, "hits-" + utc.ToString("yyyy-MM-dd") + ".jsonl");

        /// <summary>One streaming pass over the archive's EID-1 window,
        /// re-running the current rules over spawns the rules were too late
        /// for. Already-indexed (rule, record id) pairs are skipped, so
        /// calling this repeatedly is safe. Serialized against itself (see
        /// _replayGate). Returns hits appended.</summary>
        public static int ReplayRecent()
        {
            lock (_replayGate)
            {
                var lib = RuleLibrary();
            var rules = lib.Load().Where(w => w.Enabled).ToList();
            if (rules.Count == 0) return 0;
            var allowlist = lib.LoadAllowlist();

                var since = DateTime.UtcNow.AddDays(-ReplayDays);
                var events = SysmonArchiveService.Search(1, null, since, int.MaxValue);

                var indexed = LoadIndexedPairs(since);
                int appended = 0;
                foreach (var ev in events)
                {
                    if (ev?.Data == null) continue;
                    if (!MatchesAny(rules, allowlist, ev, out var matched)) continue;
                    foreach (var rule in matched)
                    {
                        var key = (rule.Name, ev.RecordId);
                        if (indexed.Contains(key)) continue;
                        indexed.Add(key);
                        Evaluate(ev, new List<SpawnWatch> { rule }, allowlist);
                        appended++;
                    }
                }
                return appended;
            }
        }

        /// <summary>Every (rule, record id) pair already in the hit files
        /// inside the window — the replay dedupe set.</summary>
        private static HashSet<(string Rule, long Rid)> LoadIndexedPairs(DateTime sinceUtc)
        {
            var set = new HashSet<(string, long)>();
            try
            {
                if (!Directory.Exists(HitsDirectory)) return set;
                foreach (var f in Directory.GetFiles(HitsDirectory, "hits-*.jsonl"))
                {
                    foreach (var raw in File.ReadAllLines(f))
                    {
                        var row = ParseHitLine(raw);
                        if (row == null || row.TsUtc < sinceUtc) continue;
                        set.Add((row.Rule, row.RecordId));
                    }
                }
            }
            catch { /* unreadable hits — worst case is duplicate rows */ }
            return set;
        }

        // ── reading hits (tab + MCP) ──────────────────────────────────────

        public sealed class HitRow
        {
            public DateTime TsUtc;
            public string Rule;
            public long RecordId;
            public string Image;
            public string Pid;
            public string Parent;
            public string Service;
            public string CommandLine;
            public Dictionary<string, string> Data;
        }

        /// <summary>Hit rows, newest first. Empty rule name = all rules.</summary>
        public static List<HitRow> ReadHits(string rule, DateTime? sinceUtc, int max)
        {
            var result = new List<HitRow>();
            try
            {
                if (!Directory.Exists(HitsDirectory)) return result;
                foreach (var f in Directory.GetFiles(HitsDirectory, "hits-*.jsonl")
                             .OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    var lines = File.ReadAllLines(f);
                    for (var i = lines.Length - 1; i >= 0; i--)
                    {
                        var row = ParseHitLine(lines[i]);
                        if (row == null) continue;
                        if (sinceUtc != null && row.TsUtc < sinceUtc.Value) continue;
                        if (!string.IsNullOrEmpty(rule) &&
                            !string.Equals(row.Rule, rule, StringComparison.OrdinalIgnoreCase))
                            continue;
                        result.Add(row);
                        if (result.Count >= max) return result;
                    }
                }
            }
            catch { /* unreadable hits — empty list is honest */ }
            return result;
        }

        private static HitRow ParseHitLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                string Get(string key) =>
                    root.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String
                        ? v.GetString() : "";

                var row = new HitRow
                {
                    Rule = Get("rule"),
                    Image = Get("image"),
                    Pid = Get("pid"),
                    Parent = Get("parent"),
                    Service = Get("service"),
                    CommandLine = Get("cmd"),
                    RecordId = root.TryGetProperty("rid", out var rid) &&
                               rid.TryGetInt64(out var l) ? l : 0,
                    Data = new Dictionary<string, string>(),
                };
                if (root.TryGetProperty("ts", out var ts) &&
                    DateTime.TryParse(ts.GetString(), null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out var parsed))
                    row.TsUtc = parsed.ToUniversalTime();

                if (root.TryGetProperty("data", out var data) &&
                    data.ValueKind == JsonValueKind.Object)
                {
                    foreach (var kv in data.EnumerateObject())
                        row.Data[kv.Name] = kv.Value.ValueKind == JsonValueKind.String
                            ? kv.Value.GetString() : kv.Value.ToString();
                }
                return string.IsNullOrEmpty(row.Rule) ? null : row;
            }
            catch { return null; }
        }

        /// <summary>Per-rule hit counts over the recent window, for the tab
        /// cards and list_watches. Newest rules keep their file order.</summary>
        public static Dictionary<string, int> HitCounts(DateTime? sinceUtc)
        {
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var hit in ReadHits(null, sinceUtc, int.MaxValue))
            {
                counts.TryGetValue(hit.Rule, out var n);
                counts[hit.Rule] = n + 1;
            }
            return counts;
        }
    }
}
