using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AutoCommand.Contain.Core
{
    /// <summary>One revision of one ignore-list entry, straight from the
    /// append-only trail (ignored_processes-events.log): when it happened,
    /// which path did it, and what exactly changed.</summary>
    public class IgnoreRevision
    {
        public DateTime TimeUtc;
        public string Action = "";    // ignored | unignored | ignore-imported
        public string Key = "";
        public string Detail = "";
        public string Origin = "";

        public DateTime TimeLocal => TimeUtc.ToLocalTime();

        /// <summary>Plain-language "what": added / removed / pre-tracking.</summary>
        public string What => Action switch
        {
            "ignored" => "added",
            "unignored" => "removed",
            "ignore-imported" => "already on the list before tracking began",
            _ => Action
        };

        /// <summary>Plain-language "how" — the friendly actor for the origin
        /// (AuditTrail.ActorFor; "file-edit" maps to a hand edit outside the
        /// app).</summary>
        public string How => AuditTrail.ActorFor(Origin);
    }

    /// <summary>The current list plus what the trail knows about it — the
    /// "where does the list stand now" half of the history view.</summary>
    public class IgnoreOverview
    {
        public List<string> Entries = new();
        public DateTime? LastChangeUtc;
        public DateTime? EarliestRecordUtc;
        public int RevisionCount;

        /// <summary>Per-entry last revision (null = the trail has never
        /// seen this entry — it predates tracking and its only record is
        /// the one-time ignore-imported marker, if any).</summary>
        public Dictionary<string, IgnoreRevision> LastRevisionPerEntry = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>One file-write event from the USN journal — the "when" for
    /// revisions that predate the trail. Write times only: entry-level
    /// detail before tracking began is not recoverable and is never
    /// inferred here.</summary>
    public class IgnoreFileWrite
    {
        public DateTime TimeUtc;
        public string Reason = "";
    }

    /// <summary>
    /// Reads the Process Monitor's ignore-list trail into history views:
    /// per-entry revision timelines, the current-state overview, and — for
    /// changes that predate the trail — the USN journal's record of the
    /// state file's own write events (the app runs elevated, so the journal
    /// is readable in-process; the state dir's drive is used, not a
    /// hardcoded C:). Parsing reuses AuditTrail so the two views can never
    /// disagree about what a line says.
    /// </summary>
    public static class IgnoreHistoryService
    {
        private static readonly Regex TimeInCsv = new(
            @"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?", RegexOptions.Compiled);

        // ── trail access ─────────────────────────────────────────────────

        private static List<AuditEvent> ReadTrail()
        {
            // the trail is small (user-paced mutations), but reads want the
            // whole history, not AuditTrail's share-friendly 512 KB tail
            return AuditTrail.ReadEvents(
                AutoCommand.Engines.Watch.SysmonWatcherService.IgnoredEventsLogPath,
                maxBytes: 8 * 1024 * 1024);
        }

        /// <summary>Full revision timeline for one entry, newest first.
        /// Empty when the trail has never seen the key.</summary>
        public static List<IgnoreRevision> TimelineFor(string key)
        {
            var result = new List<IgnoreRevision>();
            if (string.IsNullOrWhiteSpace(key)) return result;
            foreach (var e in ReadTrail())
            {
                if (!string.Equals(e.Key, key, StringComparison.OrdinalIgnoreCase)) continue;
                result.Add(new IgnoreRevision
                {
                    TimeUtc = e.TimeUtc,
                    Action = e.Action,
                    Key = e.Key,
                    Detail = e.Detail,
                    Origin = e.Origin,
                });
            }
            result.Sort((a, b) => b.TimeUtc.CompareTo(a.TimeUtc));
            return result;
        }

        /// <summary>The ignore popup's one-line provenance for an entry:
        /// the newest add-side event, or the pre-tracking note. Same wording
        /// the popup has always shown — now from the shared service.</summary>
        public static string ProvenanceFor(string key)
        {
            try
            {
                var newest = TimelineFor(key)
                    .FirstOrDefault(r => r.Action == "ignored" || r.Action == "ignore-imported");
                if (newest == null) return "";
                if (newest.Action == "ignore-imported")
                    return "already on the list before tracking began";
                return $"added {newest.TimeLocal:M/d h:mm tt} · {newest.How}";
            }
            catch
            {
                return "";   // an unreadable trail must not break the popup
            }
        }

        /// <summary>Current-state overview for the history view. Entries the
        /// trail has never seen (hand edits from before tracking began)
        /// carry no revision — the view says so rather than inventing one.</summary>
        public static IgnoreOverview Overview(IEnumerable<string> currentEntries)
        {
            var trail = ReadTrail();
            var ov = new IgnoreOverview
            {
                Entries = (currentEntries ?? Array.Empty<string>())
                    .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
            };

            foreach (var e in trail)
            {
                ov.RevisionCount++;
                if (ov.LastChangeUtc == null || e.TimeUtc > ov.LastChangeUtc) ov.LastChangeUtc = e.TimeUtc;
                if (ov.EarliestRecordUtc == null || e.TimeUtc < ov.EarliestRecordUtc) ov.EarliestRecordUtc = e.TimeUtc;

                if (!ov.LastRevisionPerEntry.TryGetValue(e.Key, out var last) || e.TimeUtc > last.TimeUtc)
                    ov.LastRevisionPerEntry[e.Key] = new IgnoreRevision
                    {
                        TimeUtc = e.TimeUtc,
                        Action = e.Action,
                        Key = e.Key,
                        Detail = e.Detail,
                        Origin = e.Origin,
                    };
            }
            return ov;
        }

        // ── USN deep scan (the "when" for the pre-trail era) ─────────────

        /// <summary>Write events touching ignored_processes.txt recorded in
        /// the NTFS USN journal, newest first. Requires an elevated process
        /// (the app is requireAdministrator) and an unrotated journal; an
        /// empty result means "the journal no longer reaches back that
        /// far", not "the file was never written". Only write times come
        /// back — entry-level detail before tracking began is not
        /// recoverable and is never inferred.</summary>
        public static Task<List<IgnoreFileWrite>> UsnFileWritesAsync()
        {
            return Task.Run(() =>
            {
                var result = new List<IgnoreFileWrite>();
                try
                {
                    var dataDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "AutoCommand");
                    var drive = Path.GetPathRoot(Path.GetFullPath(dataDir)) ?? "C:\\";
                    drive = drive.TrimEnd('\\');

                    var psi = new ProcessStartInfo
                    {
                        FileName = "fsutil.exe",
                        Arguments = $"usn readjournal {drive} csv",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                    };
                    using var proc = new Process { StartInfo = psi };
                    proc.Start();

                    // stream the output — a busy journal prints millions of
                    // rows and only the ignore-file ones matter
                    string line;
                    var stdout = proc.StandardOutput;
                    while ((line = stdout.ReadLine()) != null)
                    {
                        if (line.IndexOf("ignored_processes", StringComparison.OrdinalIgnoreCase) < 0)
                            continue;

                        var t = TimeInCsv.Match(line);
                        if (!t.Success || !DateTime.TryParse(t.Value, CultureInfo.InvariantCulture,
                                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                                out var whenUtc)) continue;

                        result.Add(new IgnoreFileWrite
                        {
                            TimeUtc = DateTime.SpecifyKind(whenUtc, DateTimeKind.Utc),
                            Reason = UsnReasonWords(line),
                        });
                    }

                    proc.WaitForExit(60_000);
                    if (!proc.HasExited)
                    {
                        try { proc.Kill(); } catch { }
                    }
                }
                catch
                {
                    // not elevated / journal disabled / fsutil missing — the
                    // caller renders the honest empty state
                }

                result.Sort((a, b) => b.TimeUtc.CompareTo(a.TimeUtc));
                // collapse per-write event storms (extend + close for one write)
                return result
                    .GroupBy(w => (w.TimeUtc, w.Reason))
                    .Select(g => g.First())
                    .ToList();
            });
        }

        private static string UsnReasonWords(string csvLine)
        {
            var words = new List<string>();
            void Add(string keyword, string label)
            {
                if (csvLine.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0) words.Add(label);
            }
            Add("data_extend", "content added");
            Add("data_overwrite", "content overwrote");
            Add("data_truncation", "content truncated");
            Add("file_create", "file created");
            Add("close", "handle closed");
            return words.Count > 0 ? string.Join(", ", words) : "write";
        }
    }
}
