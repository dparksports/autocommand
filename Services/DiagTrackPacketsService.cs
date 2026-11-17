using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace AutoCommand.Services
{
    /// <summary>
    /// Per-hour DiagTrack transmit activity for the Cadence tab, derived
    /// incrementally from the app's own Sysmon archive. Two things per
    /// local-day × hour: packet counts (EID-3 attempts) and session counts
    /// (bursts, same ProcessGuid with a >5-min gap between them — the same
    /// definition the calibration scripts used).
    ///
    /// How DiagTrack is isolated: the archive's EID-3 rows all say
    /// "svchost.exe" with no service name, so instances are resolved from
    /// EID-1 create events whose command line runs the utcsvc group
    /// (svchost.exe -k utcsvc -p hosts only DiagTrack). ProcessGuid — not
    /// PID — keys the instances, so PID recycling across boots cannot
    /// misattribute a packet. This is the same ProcessGuid method the
    /// calibration pass validated against the manual identities.
    ///
    /// Scanning is byte-offset incremental (diagtrack-scan.json), the
    /// events themselves persist to diagtrack-events.jsonl (rid-deduped,
    /// 8-day retention), and the whole thing is READ-ONLY against the
    /// archive. First run may take a while over a week of day files — it
    /// runs in the background and the view shows scanning progress.
    /// </summary>
    public sealed class DiagTrackPacketsService
    {
        public static DiagTrackPacketsService Instance { get; } = new();
        private DiagTrackPacketsService() { }

        private const int RetainedDays = 8;
        private const double SessionGapMinutes = 5;

        private static readonly Regex SvchostImage = new("\"Image\":\"[^\"]*svchost\\.exe\"", RegexOptions.Compiled);
        private static readonly Regex UtcTime = new("\"UtcTime\":\"(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3})\"", RegexOptions.Compiled);
        private static readonly Regex GuidRe = new("\"ProcessGuid\":\"([^\"]+)\"", RegexOptions.Compiled);
        private static readonly Regex RidRe = new("\"rid\":(\\d+)", RegexOptions.Compiled);
        private static readonly Regex DestIp = new("\"DestinationIp\":\"([^\"]+)\"", RegexOptions.Compiled);
        private const string TimeFmt = "yyyy-MM-dd HH:mm:ss.fff";

        private readonly object _gate = new();
        private readonly HashSet<string> _diagGuids = new(StringComparer.Ordinal);   // ProcessGuid of utcsvc instances
        private readonly List<DiagEvent> _events = new();
        private readonly HashSet<long> _seenRids = new();                            // rid-dedupe across rescans
        private readonly Dictionary<string, long> _offsets = new(StringComparer.Ordinal); // day file → byte offset
        private readonly HashSet<string> _scannedFileDays = new(StringComparer.Ordinal);  // UTC dates of day files processed

        private bool _loaded;
        private bool _scanning;
        private bool _initialized;

        /// <summary>Raised after any scan pass changed the data.</summary>
        public event Action? Changed;

        public bool FirstScanComplete { get; private set; }
        public int ScanDaysDone { get; private set; }
        public int ScanDaysTotal { get; private set; }

        private string DataDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private string ArchiveDir => Path.Combine(DataDir, "sysmon-archive");
        private string OffsetsPath => Path.Combine(DataDir, "diagtrack-scan.json");
        private string EventsPath => Path.Combine(DataDir, "diagtrack-events.jsonl");

        private sealed class DiagEvent
        {
            public DateTime TsLocal;
            public string Guid = "";
            public string Ip = "";
            public long Rid;
        }

        // ── lifecycle ────────────────────────────────────────────────────

        public void Initialize()
        {
            lock (_gate)
            {
                if (_initialized) return;
                _initialized = true;
            }
            InstrumentMetronome.Instance.Register(new InstrumentSpec
            {
                Id = "diagtrack-cadence-scan",
                Name = "DiagTrack cadence scan",
                Description = "Keeps the Exfil tab's DiagTrack per-hour packet and session counts " +
                              "current by incrementally scanning new Sysmon archive bytes. Read-only " +
                              "against the archive; typical cost is a few thousand small lines.",
                Cost = InstrumentCost.Light,
                DefaultSeconds = 300,
                MinSeconds = 30,
                MaxSeconds = 1800,
                Callback = () => { ScanNow(); return Task.CompletedTask; },
            });
            _ = Task.Run(() => { ScanNow(); });   // first scan (possibly long) off the UI thread
        }

        /// <summary>Run one scan pass. Safe to call from anywhere; concurrent
        /// calls collapse into the running one.</summary>
        public void ScanNow()
        {
            bool entered = false;
            lock (_gate)
            {
                if (_scanning) return;
                _scanning = true;
                entered = true;
            }
            try
            {
                if (!entered) return;
                LoadEventsFile();
                ScanArchive();
                RaiseChanged();
            }
            catch { /* a failed pass just retries on the next tick */ }
            finally
            {
                lock (_gate) _scanning = false;
            }
        }

        private void RaiseChanged()
        {
            try { Changed?.Invoke(); } catch { }
        }

        // ── persistence of the derived event list ────────────────────────

        private void LoadEventsFile()
        {
            lock (_gate)
            {
                if (_loaded) return;
                _loaded = true;
            }
            try
            {
                if (!File.Exists(EventsPath)) return;
                foreach (var line in File.ReadLines(EventsPath))
                {
                    var e = JsonSerializer.Deserialize<DiagEvent>(line);
                    if (e == null || e.TsLocal < DateTime.Now.AddDays(-RetainedDays)) continue;
                    lock (_gate)
                    {
                        if (e.Rid <= 0 || _seenRids.Add(e.Rid)) _events.Add(e);
                    }
                }
            }
            catch { /* unreadable — the archive rescan rebuilds what offsets allow */ }
        }

        private void AppendEventsFile(IEnumerable<DiagEvent> fresh)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var sb = new StringBuilder();
                foreach (var e in fresh)
                    sb.AppendLine(JsonSerializer.Serialize(e));
                File.AppendAllText(EventsPath, sb.ToString());
            }
            catch { /* best-effort; rid dedupe makes a retry harmless */ }
        }

        // ── archive scanning ─────────────────────────────────────────────

        private void ScanArchive()
        {
            var utcToday = DateTime.UtcNow.Date;
            var files = new List<string>();
            for (int d = -RetainedDays; d <= 0; d++)
            {
                // Invariant: the archive files are named invariantly, and a
                // calendar-default culture (th-TH, ar-SA) would format a
                // non-Gregorian year here that never matches them.
                var f = Path.Combine(ArchiveDir, "sysmon-archive-" + utcToday.AddDays(d).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) + ".jsonl");
                if (File.Exists(f)) files.Add(f);
            }

            lock (_gate) ScanDaysTotal = files.Count;

            foreach (var path in files)
            {
                long offset;
                lock (_gate)
                {
                    if (!_offsets.TryGetValue(path, out offset)) offset = 0;
                }
                ScanOneFile(path, ref offset);
                lock (_gate)
                {
                    _offsets[path] = offset;
                    _scannedFileDays.Add(Path.GetFileNameWithoutExtension(path).Replace("sysmon-archive-", ""));
                    ScanDaysDone++;
                    SaveOffsetsLocked();
                }
            }

            lock (_gate)
            {
                FirstScanComplete = true;
                PruneEventsLocked();
            }
        }

        private void ScanOneFile(string path, ref long offset)
        {
            var fresh = new List<DiagEvent>();
            long consumed = 0;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20);
                if (offset > fs.Length) offset = 0;           // file was pruned/replaced — rescan
                fs.Seek(offset, SeekOrigin.Begin);

                var buf = new byte[1 << 20];
                byte[] carry = Array.Empty<byte>();
                int read;
                while ((read = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    // last newline in this chunk bounds the complete lines
                    int lastNl = -1;
                    for (int i = read - 1; i >= 0; i--)
                        if (buf[i] == (byte)'\n') { lastNl = i; break; }

                    if (lastNl < 0)
                    {
                        // nothing complete yet — everything rides into carry,
                        // nothing is accounted consumed
                        var grown = new byte[carry.Length + read];
                        Array.Copy(carry, grown, carry.Length);
                        Array.Copy(buf, 0, grown, carry.Length, read);
                        carry = grown;
                        continue;
                    }

                    var all = new byte[carry.Length + lastNl + 1];
                    Array.Copy(carry, all, carry.Length);
                    Array.Copy(buf, 0, all, carry.Length, lastNl + 1);

                    // split into complete lines and process each
                    int lineStart = 0;
                    for (int i = 0; i < all.Length; i++)
                    {
                        if (all[i] != (byte)'\n') continue;
                        int len = i - lineStart;
                        if (len > 0)
                        {
                            var line = Encoding.UTF8.GetString(all, lineStart, len);
                            ProcessLine(line, fresh);
                        }
                        lineStart = i + 1;
                    }

                    consumed += carry.Length + lastNl + 1;    // carry + chunk prefix are now done
                    carry = new byte[read - lastNl - 1];
                    Array.Copy(buf, lastNl + 1, carry, 0, carry.Length);
                }
            }
            catch { /* a bad pass resumes from the same offset next tick */ }

            if (fresh.Count > 0)
            {
                lock (_gate)
                {
                    foreach (var e in fresh)
                        if (e.Rid <= 0 || _seenRids.Add(e.Rid)) _events.Add(e);
                }
                AppendEventsFile(fresh);
            }
            offset += consumed;
        }

        private void ProcessLine(string line, List<DiagEvent> fresh)
        {
            // cheap pre-filters before any regex work
            if (line.Contains("\"eid\":1,"))
            {
                if (!SvchostImage.IsMatch(line)) return;
                if (!line.Contains("utcsvc") && !line.Contains("DiagTrack")) return;
                var g = GuidRe.Match(line).Groups[1].Value;
                lock (_gate) _diagGuids.Add(g);
                return;
            }
            if (!line.Contains("\"eid\":3,")) return;
            if (!SvchostImage.IsMatch(line)) return;

            string guid;
            lock (_gate) guid = _diagGuids.FirstOrDefault(line.Contains) ?? "";
            if (guid.Length == 0) return;

            var m = UtcTime.Match(line);
            if (!m.Success) return;
            if (!DateTime.TryParseExact(m.Groups[1].Value, TimeFmt,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var utc)) return;
            var ridM = RidRe.Match(line);
            long rid = ridM.Success && long.TryParse(ridM.Groups[1].Value, out var r) ? r : 0;
            var ip = DestIp.Match(line).Groups[1].Value;

            fresh.Add(new DiagEvent
            {
                TsLocal = utc.ToLocalTime(),
                Guid = guid,
                Ip = ip,
                Rid = rid,
            });
        }

        // ── read model for the view ──────────────────────────────────────

        /// <summary>Local day ("yyyy-MM-dd") → 24 hourly packet counts, for
        /// days inside the retention window. Days absent = nothing recorded.</summary>
        public Dictionary<string, int[]> PacketsPerHour()
        {
            var days = new Dictionary<string, int[]>(StringComparer.Ordinal);
            lock (_gate)
            {
                foreach (var e in _events)
                {
                    var key = e.TsLocal.ToString("yyyy-MM-dd");
                    if (!days.TryGetValue(key, out var hours))
                    {
                        hours = new int[24];
                        days[key] = hours;
                    }
                    hours[e.TsLocal.Hour]++;
                }
            }
            return days;
        }

        /// <summary>Local days whose underlying archive files have been
        /// scanned — a scanned day with no events is a truthful 0, while an
        /// unscanned day is "no data" (the view renders those differently).</summary>
        public HashSet<string> ScannedLocalDays()
        {
            lock (_gate)
            {
                var set = new HashSet<string>(StringComparer.Ordinal);
                foreach (var f in _scannedFileDays)
                {
                    if (!DateTime.TryParseExact(f, "yyyy-MM-dd",
                            CultureInfo.InvariantCulture, DateTimeStyles.None, out var utc)) continue;
                    // a UTC day file spans (offset-dependent) parts of two local days
                    var baseDay = utc.ToLocalTime().Date;
                    set.Add(baseDay.ToString("yyyy-MM-dd"));
                    set.Add(baseDay.AddDays(1).ToString("yyyy-MM-dd"));
                }
                return set;
            }
        }

        /// <summary>Same shape, counting sessions: an event starts a session
        /// when the same ProcessGuid's previous event is more than 5 minutes
        /// older — the calibration definition.</summary>
        public Dictionary<string, int[]> SessionsPerHour()
        {
            var days = new Dictionary<string, int[]>(StringComparer.Ordinal);
            List<DiagEvent> sorted;
            lock (_gate) sorted = _events.OrderBy(e => e.TsLocal).ToList();

            DateTime? prevTs = null;
            string prevGuid = "";
            foreach (var e in sorted)
            {
                bool newSession = prevTs == null || prevGuid != e.Guid ||
                                  (e.TsLocal - prevTs.Value).TotalMinutes > SessionGapMinutes;
                prevTs = e.TsLocal;
                prevGuid = e.Guid;
                if (!newSession) continue;

                var key = e.TsLocal.ToString("yyyy-MM-dd");
                if (!days.TryGetValue(key, out var hours))
                {
                    hours = new int[24];
                    days[key] = hours;
                }
                hours[e.TsLocal.Hour]++;
            }
            return days;
        }

        private void PruneEventsLocked()
        {
            var cutoff = DateTime.Now.AddDays(-RetainedDays);
            if (_events.RemoveAll(e => e.TsLocal < cutoff) == 0) return;
            try
            {
                Directory.CreateDirectory(DataDir);
                var sb = new StringBuilder();
                foreach (var e in _events)
                    sb.AppendLine(JsonSerializer.Serialize(e));
                var tmp = EventsPath + ".tmp";
                File.WriteAllText(tmp, sb.ToString());
                File.Move(tmp, EventsPath, overwrite: true);
            }
            catch { /* best-effort */ }
        }

        private void SaveOffsetsLocked()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var tmp = OffsetsPath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(_offsets));
                File.Move(tmp, OffsetsPath, overwrite: true);
            }
            catch { /* worst case: a later pass rescans from 0 — rid dedupe absorbs it */ }
        }
    }
}
