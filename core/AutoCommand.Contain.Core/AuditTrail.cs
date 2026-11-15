using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace AutoCommand.Contain.Core
{
    /// <summary>One parsed ledger line: utc|action|kind|key|detail|origin —
    /// the shared format of blocks-events.log and the Process Monitor's
    /// ignored_processes-events.log.</summary>
    public class AuditEvent
    {
        public DateTime TimeUtc;
        public string Action = "";
        public string Kind = "";
        public string Key = "";
        public string Detail = "";
        public string Origin = "";
    }

    /// <summary>
    /// A user-facing incident: consecutive log events of the same shape,
    /// collapsed into one plain-language sentence. The Audit tab never shows
    /// raw lines first — 948 pipe-delimited events are six sentences, and
    /// the sentence is what a returning user actually wants to read.
    /// </summary>
    public class AuditIncident
    {
        // Everything the Audit tab's XAML binds MUST be a property, not a
        // field — WPF {Binding} silently produces nothing on fields (the
        // 49-instance BlocksView bug class; this class shipped with it and
        // rendered blank rows before the fix). Members only touched from
        // code (StartUtc/EndUtc/Count/Events/KindCounts) can stay fields.
        public string Category { get; set; }        // auto | pause | fleet | external
        public string Severity { get; set; }        // routine | info | resolved | attention
        public string Sentence { get; set; } = "";  // one line, plain language, past tense
        public string Meta { get; set; } = "";      // time range · actor · counts
        public string DayHeader { get; set; } = ""; // TODAY · FRIDAY, OCT 30 (local)
        public DateTime StartUtc;
        public DateTime EndUtc;
        public int Count;              // targets/events the incident covers
        public List<string> EventLines { get; } = new();   // "3:47 PM  raw line"

        // Grouping state (what the events in this incident share).
        public string EventsAction { get; set; } = "";
        public string EventsOrigin { get; set; } = "";
        public readonly List<AuditEvent> Events = new();
        public readonly Dictionary<string, int> KindCounts = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Pure transform over blocks-events.log: parse, group into incidents,
    /// and say each one in one sentence. No I/O beyond the optional tail
    /// read, so ContainSelfTest feeds synthetic lines directly — the same
    /// offline contract the rest of the self-test suite keeps.
    /// </summary>
    public static class AuditTrail
    {
        /// <summary>Consecutive same-shape events this far apart still merge.</summary>
        private static readonly TimeSpan GroupWindow = TimeSpan.FromMinutes(5);

        private static readonly Regex LeadingInt = new Regex(@"^(\d+)", RegexOptions.Compiled);

        // ── parse ───────────────────────────────────────────────────────

        public static AuditEvent ParseLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            var f = line.Split('|');
            if (f.Length < 6) return null;
            if (!DateTime.TryParse(f[0], CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var utc)) return null;
            return new AuditEvent
            {
                TimeUtc = DateTime.SpecifyKind(utc, DateTimeKind.Utc),
                Action = f[1],
                Kind = f.Length > 2 ? f[2] : "",
                Key = f.Length > 3 ? f[3] : "",
                Detail = f.Length > 4 ? f[4] : "",
                Origin = f.Length > 5 ? f[5] : ""
            };
        }

        /// <summary>Tail read (share-friendly; the app appends while we read).
        /// Returns events oldest-first.</summary>
        public static List<AuditEvent> ReadEvents(string eventLogPath, int maxBytes = 512 * 1024)
        {
            var result = new List<AuditEvent>();
            try
            {
                if (!File.Exists(eventLogPath)) return result;
                using var fs = new FileStream(eventLogPath, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                int tail = (int)Math.Min(fs.Length, maxBytes);
                fs.Seek(-tail, SeekOrigin.End);
                using var sr = new StreamReader(fs);
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    var e = ParseLine(line);
                    if (e != null) result.Add(e);
                }
            }
            catch { /* unreadable history is not fatal — show what parsed */ }
            return result;
        }

        // ── grouping ────────────────────────────────────────────────────

        /// <summary>
        /// Collapse events (oldest-first input) into incidents: an event
        /// joins the previous one when action, origin and category match and
        /// the gap is under GroupWindow. Fleet ops always stand alone — one
        /// panic is one incident no matter what the monitor did meanwhile.
        /// </summary>
        public static List<AuditIncident> BuildIncidents(IEnumerable<AuditEvent> events)
        {
            var incidents = new List<AuditIncident>();
            AuditIncident current = null;

            foreach (var e in events)
            {
                string cat = CategoryOf(e.Action);
                // fleet ops stand alone — but an update session's opened and
                // restored halves are ONE incident ("You updated Windows…"),
                // so update-* events may join each other across actions.
                bool standalone = cat == "fleet" && !e.Action.StartsWith("update-", StringComparison.Ordinal);
                bool joinsAction = current != null &&
                    (e.Action == current.EventsAction ||
                     (e.Action == "update-restored" && current.EventsAction == "update-opened"));
                bool joins = current != null && !standalone && joinsAction &&
                             e.Origin == current.EventsOrigin &&
                             e.TimeUtc - current.EndUtc <= GroupWindow;

                if (!joins)
                {
                    current = new AuditIncident
                    {
                        Category = cat,
                        Severity = SeverityOf(e.Action, e.Detail),
                        StartUtc = e.TimeUtc,
                        EndUtc = e.TimeUtc,
                        Count = 0,
                        EventsAction = e.Action,
                        EventsOrigin = e.Origin
                    };
                    incidents.Add(current);
                }

                current.Events.Add(e);
                current.EndUtc = e.TimeUtc;
                // the restored half of an update session describes the SAME
                // targets the opened half counted — don't double-count them
                if (!(e.Action == "update-restored" && current.EventsAction == "update-opened"))
                    current.Count += CountIn(e.Action, e.Detail);
                current.KindCounts.TryGetValue(e.Kind, out var n);
                current.KindCounts[e.Kind] = n + 1;
                current.EventLines.Add($"{e.TimeUtc.ToLocalTime():h:mm tt}  {RawLine(e)}");
            }

            foreach (var inc in incidents)
            {
                inc.Sentence = SentenceFor(inc);
                inc.Meta = MetaFor(inc);
                inc.DayHeader = DayHeaderFor(inc.StartUtc);
            }
            return incidents;
        }

        // ── classification ──────────────────────────────────────────────

        public static string CategoryOf(string action) => action switch
        {
            "fleet-disabled" or "fleet-enabled" or "consolidated" or "imported"
                or "update-opened" or "update-restored" or "dedup-retired" => "fleet",
            "paused" or "resumed" or "rule-toggled" => "pause",
            "created" or "removed" or "attributed" => "auto",
            "ignored" or "unignored" or "ignore-imported" => "ignore",
            _ => "external"      // external-modified and anything the OS feed adds later
        };

        public static string SeverityOf(string action, string detail) => action switch
        {
            "created" => "routine",
            "removed" or "attributed" or "resumed" or "unignored" => "routine",
            "paused" or "rule-toggled" => "info",
            "ignored" or "ignore-imported" => "info",   // deliberate, reversible — same tier as a pause
            "fleet-disabled" or "fleet-enabled" or "consolidated" => "resolved",
            "update-opened" or "update-restored" => "resolved",
            "dedup-retired" => "resolved",
            "imported" => "routine",
            _ => detail != null && detail.Contains("restored", StringComparison.OrdinalIgnoreCase)
                ? "resolved"
                : "attention"    // an external change we could not confirm undone
        };

        /// <summary>Friendly actor for the "by" column / meta line.</summary>
        public static string ActorFor(string origin) => origin switch
        {
            "monitor" => "Process Monitor",
            "reconcile" => "tab reconcile",
            "repair" => "attribution repair",
            "migration" => "migration",
            "panic-button" => "you · panic button",
            "manage-all" => "you · Manage all",
            "restore-except-risky" => "you · restore except risky",
            "blocks-tab" => "you · Blocks tab",
            "firewall-tab" => "you · Firewall tab",
            "restore-guide" => "you · restore guide",
            "undo" => "you · undo",
            "mcp" => "AI session · gate",
            "update-mode" => "you · Windows Update",
            "pre-audit" => "unknown · before tracking",
            _ => origin.Length == 0 ? "unknown" : origin
        };

        // ── language ────────────────────────────────────────────────────

        private static string SentenceFor(AuditIncident inc)
        {
            string first = inc.Events[0].Key;
            switch (inc.EventsAction)
            {
                case "created":
                    int ips = inc.KindCounts.TryGetValue("ip", out var i) ? i : 0;
                    int procs = inc.KindCounts.TryGetValue("proc", out var p) ? p : 0;
                    string what = ips > 0 && procs > 0 ? $"{ips} addresses and {procs} programs"
                        : procs > 0 ? $"{procs} program block{(procs == 1 ? "" : "s")}"
                        : $"{inc.Count} address{(inc.Count == 1 ? "" : "es")}";
                    return inc.Count == 1
                        ? $"AutoCommand blocked {TargetName(inc.Events[0])}"
                        : $"AutoCommand blocked {what} over {SpanWords(inc)}";

                case "removed":
                    return inc.Count == 1
                        ? $"A block expired or was removed — {TargetName(inc.Events[0])}"
                        : $"{inc.Count} blocks expired or were removed over {SpanWords(inc)}";

                case "attributed":
                    return $"AutoCommand re-attributed {inc.Count} block{(inc.Count == 1 ? "" : "s")} to their owning services";

                case "paused":
                    string who = inc.EventsOrigin == "restore-guide" ? "The restore guide"
                        : inc.EventsOrigin == "mcp" ? "An AI session" : "You";
                    return $"{who} paused {Noun(inc.Count, "block")}";

                case "resumed":
                    return $"Blocking turned back ON for {Noun(inc.Count, "block")}";

                case "fleet-disabled":
                    return inc.EventsOrigin == "panic-button"
                        ? "You pressed the panic button — every block rule went off"
                        : $"All block rules were disabled ({ActorFor(inc.EventsOrigin)})";

                case "fleet-enabled":
                    return inc.EventsOrigin == "restore-except-risky"
                        ? "You restored every block except the risky Microsoft/Windows ones"
                        : "Every block rule was turned back ON";

                case "consolidated":
                    return "Legacy block rules were consolidated to the current scheme";

                case "dedup-retired":
                    return $"Duplicate block rules were cleaned up — {inc.Events[0].Detail}";

                case "update-opened":
                    // merged session (opened + restored halves): the one
                    // sentence the whole session is remembered by
                    if (inc.Events.Any(x => x.Action == "update-restored"))
                        return $"You updated Windows — {Noun(inc.Count, "block")} paused for " +
                               $"{Math.Max(1, (int)(inc.EndUtc - inc.StartUtc).TotalMinutes)} min, all restored";
                    return $"You started a Windows Update session — {inc.Events[0].Detail}";

                case "update-restored":
                    return $"Windows Update session finished — {inc.Events[0].Detail}";

                case "imported":
                    return "Blocks were imported from an older install";

                case "rule-toggled":
                    var e = inc.Events[0];
                    return $"You toggled a rule by hand in the Firewall tab — {e.Key} switched {(e.Detail == "enabled" ? "ON" : "OFF")}";

                case "ignored":
                    return inc.Count == 1
                        ? $"{TargetName(inc.Events[0])} was added to the process ignore list — its connections are no longer listed"
                        : $"{inc.Count} processes were added to the ignore list over {SpanWords(inc)}";

                case "unignored":
                    return inc.Count == 1
                        ? $"{TargetName(inc.Events[0])} was removed from the ignore list — it will be listed again"
                        : $"{inc.Count} processes were removed from the ignore list over {SpanWords(inc)}";

                case "ignore-imported":
                    // pre-existing entries the trail has no history for —
                    // the sentence IS the answer to "when was this added?"
                    return inc.Count == 1
                        ? $"{TargetName(inc.Events[0])} was already on the ignore list before tracking began — no record of when or by whom"
                        : $"{inc.Count} processes were already on the ignore list before tracking began (no record of when or by whom)";

                default:
                    return $"Something outside AutoCommand changed {Noun(inc.Count, "block rule")} — {inc.Events[0].Detail}";
            }
        }

        private static string MetaFor(AuditIncident inc)
        {
            var e = inc.Events[0];
            string time = inc.StartUtc == inc.EndUtc
                ? $"{inc.StartUtc.ToLocalTime():h:mm tt}"
                : $"{inc.StartUtc.ToLocalTime():h:mm tt} – {inc.EndUtc.ToLocalTime():h:mm tt}";
            string bits = $"{time} · {ActorFor(inc.EventsOrigin)}";
            if (inc.Count > 1) bits += $" · {inc.Count} event(s)";
            if (e.Detail.Length > 0 && inc.EventsAction is "fleet-disabled" or "fleet-enabled" or "removed")
                bits += $" · {e.Detail}";
            else if (e.Detail.Length > 0 && e.Detail.Contains('/'))
                bits += $" · {e.Detail.Split('/')[0]}";   // owning service key
            return bits;
        }

        private static string TargetName(AuditEvent e)
        {
            if (e.Kind == "proc" && e.Key.Length > 0)
            {
                var leaf = e.Key;
                var ix = leaf.LastIndexOfAny(new[] { '\\', '/' });
                if (ix >= 0) leaf = leaf[(ix + 1)..];
                return leaf;
            }
            return e.Key.Length > 0 ? e.Key : e.Detail;
        }

        private static string SpanWords(AuditIncident inc) =>
            inc.EndUtc - inc.StartUtc < TimeSpan.FromMinutes(2) ? "a quick burst"
            : inc.EndUtc - inc.StartUtc < TimeSpan.FromMinutes(30) ? "a few minutes"
            : $"the {inc.StartUtc.ToLocalTime():h:mm tt}–{inc.EndUtc.ToLocalTime():h:mm tt} window";

        private static string Noun(int n, string noun) => $"{n} {noun}{(n == 1 ? "" : "s")}";

        private static string DayHeaderFor(DateTime utc)
        {
            var local = utc.ToLocalTime();
            var today = DateTime.Today;
            if (local.Date == today) return $"TODAY · {local:dddd, MMM d}".ToUpperInvariant();
            if (local.Date == today.AddDays(-1)) return $"YESTERDAY · {local:dddd, MMM d}".ToUpperInvariant();
            return $"{local:dddd, MMM d}".ToUpperInvariant();
        }

        private static string RawLine(AuditEvent e) =>
            e.Action + (e.Key.Length > 0 ? $" · {TargetName(e)}" : "") +
            (e.Detail.Length > 0 ? $" · {e.Detail}" : "");

        /// <summary>How many targets one line represents: bulk lines carry
        /// "N target(s) …" in the detail; plain lines are one each.</summary>
        private static int CountIn(string action, string detail)
        {
            if (detail == null || detail.Length == 0) return 1;
            var m = LeadingInt.Match(detail);
            return m.Success && detail.Contains("target", StringComparison.OrdinalIgnoreCase)
                ? int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)
                : 1;
        }

        // ── visit marker (shared by the Blocks digest and the Audit tab) ──

        public static string VisitMarkerPath(string eventLogPath) =>
            Path.Combine(Path.GetDirectoryName(eventLogPath) ?? ".", "audit-seen.txt");

        /// <summary>Last time the user was shown audit events (DateTime.MinValue
        /// on first run — callers adopt history silently instead of replaying it).</summary>
        public static DateTime ReadSeenUtc(string markerPath)
        {
            try
            {
                if (File.Exists(markerPath) &&
                    DateTime.TryParse(File.ReadAllText(markerPath).Trim(), null,
                        DateTimeStyles.RoundtripKind, out var parsed))
                    return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
            }
            catch { /* unreadable marker = never seen */ }
            return DateTime.MinValue;
        }

        public static void MarkSeenUtc(string markerPath, DateTime utc)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(markerPath) ?? ".");
                File.WriteAllText(markerPath, utc.ToString("O", CultureInfo.InvariantCulture));
            }
            catch { /* best-effort */ }
        }
    }
}
