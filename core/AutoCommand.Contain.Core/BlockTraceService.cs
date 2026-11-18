using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AutoCommand.Contain.Core
{
    /// <summary>One process instance that hit a block, with its identity —
    /// the trace surfaces' answer to "for WHICH process, including any
    /// svchost subprocess". Identity joins by Sysmon ProcessGuid (stable for
    /// the whole boot), falling back to (pid, image) for pre-GUID rows; the
    /// EID 1 create-record supplies the command line / parent / user even
    /// after the process has exited, and its -k/-s tokens resolve a svchost
    /// instance to its service offline.</summary>
    public sealed class BlockTraceInstance
    {
        public string ProcessGuid = "";       // braces stripped; "" on pre-GUID rows
        public int Pid;
        public string Image = "";
        public string Process = "";           // image file name
        public int Attempts;
        public DateTime FirstUtc, LastUtc;
        public string Destinations = "";      // "443/udp · 443/tcp"
        public string CommandLine = "";       // from the archive's EID 1, "" when not found
        public string ParentImage = "";
        public string User = "";
        public string SvchostId = "";         // "-s X · -k Y" decoded offline, "" for non-svchost
        public string IdentitySource = "none"; // live | archive | none
        public string SvchostCorroboration = ""; // what the archive can and cannot prove
    }

    /// <summary>The full provenance of one blocked target, composed in one
    /// pass: the current record, the decision evidence (block-time or
    /// archive-inferred), the lifecycle event list, and the hitting process
    /// instances. Served verbatim to the Blocks tab's Trace window and the
    /// trace_block bridge tool — one composer, two renderers.</summary>
    public sealed class BlockTrace
    {
        public string Kind = "", Key = "";
        public BlockRecord Record;                 // null when the block no longer exists
        public BlockDecision Decision;             // null when nothing could be proven
        public bool DecisionInferred;              // true = joined from the archive AFTER the fact
        public string InferredNote = "";           // the inference's evidence line, when inferred
        public List<AuditEvent> Lifecycle = new();              // oldest-first
        public List<BlockTraceInstance> Instances = new();
        public DateTime? CreatedUtc;               // record's, or the earliest created event
        public DateTime? RemovedUtc;               // the removed event, when gone
        public string Summary = "";

        public string Title => Kind == "ip" ? Key : Path.GetFileName(Key);
    }

    /// <summary>
    /// Trace-back for any blocked target — "when was this blocked, why, and
    /// for which process instance (svchost included)". Pure composition over
    /// artifacts that already exist: the ledger record, the append-only
    /// blocks-events.log (with its "decided" decision lines), the block-hit
    /// feed, and the Sysmon archive (EID 3 attempts, EID 1 create records).
    /// Read-only by contract: the bridge tool calls it freely; the one
    /// write it offers — TryBackfill, appending an "attributed" line once an
    /// inference proved the trigger instance — runs only from user surfaces
    /// (the Blocks tab's Trace window), never from an agent read.
    /// </summary>
    public static class BlockTraceService
    {
        /// <summary>How far back the events-log tail read reaches — the log
        /// grows forever by design, so trace reads a bounded tail.</summary>
        private const int EventTailBytes = 8 * 1024 * 1024;

        /// <summary>How long after the created event an archive attempt may
        /// sit and still count as the trigger (the user saw the row, then
        /// clicked — the attempt preceded the block, never followed it).</summary>
        private static readonly TimeSpan TriggerGrace = TimeSpan.FromMinutes(5);

        // ── compose ─────────────────────────────────────────────────────

        /// <param name="ledger">The ledger to trace (its record set and event
        /// log); null = the app's default store.</param>
        /// <param name="hits">The hit feed rows to join; null = the live
        /// feed's recent window. Callers that already run the feed pass it
        /// here; offline tests pass synthetic rows.</param>
        /// <param name="hitMinutes">Hit look-back window (the feed retains
        /// 24 h — longer asks still return what exists).</param>
        public static BlockTrace Trace(string kind, string key, BlocksLedger ledger = null,
            IReadOnlyList<BlockHitFeedService.BlockHit> hits = null, int hitMinutes = 1440)
        {
            var t = new BlockTrace { Kind = kind, Key = key };

            if (ledger == null)
            {
                BlocksStore.FlushPending();
                t.Record = BlocksStore.Records.FirstOrDefault(r =>
                    r.Kind == kind && string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase));
                FillLifecycle(t, ReadEvents(BlocksStore.EventLogPath));
            }
            else
            {
                ledger.FlushPending();
                t.Record = ledger.Records.FirstOrDefault(r =>
                    r.Kind == kind && string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase));
                FillLifecycle(t, ReadEvents(ledger.EventLogPath));
            }

            if (hits == null)
            {
                try { hits = BlockHitFeedService.Instance.Recent(hitMinutes, 2000); }
                catch { hits = Array.Empty<BlockHitFeedService.BlockHit>(); }
            }
            FillInstances(t, hits);

            // ── decision: captured evidence first, archive inference second ──
            var decided = t.Lifecycle.LastOrDefault(e => e.Action == "decided");
            if (decided != null && BlockDecision.TryParse(decided.Detail, out var d))
                t.Decision = d;
            else if (kind == "ip")
                InferDecision(t);

            t.Summary = Summarize(t);
            return t;
        }

        private static List<AuditEvent> ReadEvents(string path) =>
            AuditTrail.ReadEvents(path, EventTailBytes);

        private static void FillLifecycle(BlockTrace t, List<AuditEvent> all)
        {
            t.Lifecycle = all.Where(e =>
                    string.Equals(e.Kind, t.Kind, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(e.Key, t.Key, StringComparison.OrdinalIgnoreCase))
                .OrderBy(e => e.TimeUtc)
                .ToList();

            var created = t.Lifecycle.FirstOrDefault(e => e.Action is "created" or "imported");
            t.CreatedUtc = t.Record?.CreatedUtc ?? created?.TimeUtc;
            var removed = t.Lifecycle.LastOrDefault(e => e.Action == "removed");
            t.RemovedUtc = removed?.TimeUtc;
        }

        // ── instances: who has been hitting it ──────────────────────────

        private static void FillInstances(BlockTrace t,
            IReadOnlyList<BlockHitFeedService.BlockHit> hits)
        {
            IEnumerable<BlockHitFeedService.BlockHit> mine = hits.Where(h =>
                t.Kind == "ip"
                    ? string.Equals(h.DestIp, t.Key, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(h.Image, t.Key, StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(Path.GetFileName(h.Image ?? ""), Path.GetFileName(t.Key ?? ""),
                          StringComparison.OrdinalIgnoreCase));
            if (t.CreatedUtc.HasValue)
                mine = mine.Where(h => h.TimeUtc >= t.CreatedUtc.Value); // hits BEFORE the block existed are not its evidence

            var groups = mine.GroupBy(h => !string.IsNullOrEmpty(h.ProcessGuid)
                    ? "g:" + h.ProcessGuid.ToLowerInvariant()
                    : "p:" + h.Pid + ":" + (h.Image ?? "").ToLowerInvariant())
                .Select(g => new BlockTraceInstance
                {
                    ProcessGuid = (g.First().ProcessGuid ?? "").Trim('{', '}'),
                    Pid = g.First().Pid,
                    Image = g.First().Image ?? "",
                    Attempts = g.Count(),
                    FirstUtc = g.Min(h => h.TimeUtc),
                    LastUtc = g.Max(h => h.TimeUtc),
                    Destinations = string.Join(" · ", g
                        .GroupBy(h => $"{h.DestPort}/{(h.Protocol ?? "tcp").ToLowerInvariant()}")
                        .Select(pg => pg.Key).OrderBy(x => x)),
                })
                .OrderByDescending(i => i.LastUtc)
                .ToList();

            foreach (var inst in groups)
                ResolveIdentity(inst);
            t.Instances = groups;
        }

        /// <summary>Best-identity join per instance: live SCM resolve while
        /// the PID is alive, otherwise the archive's EID 1 create-record
        /// (command line, parent, user) — and for svchost images, the -k/-s
        /// tokens decoded offline. The archive join works after the process
        /// has exited; the PID alone never could.</summary>
        private static void ResolveIdentity(BlockTraceInstance inst)
        {
            inst.Process = Path.GetFileName(inst.Image);
            bool isSvchost = string.Equals(inst.Process, "svchost.exe", StringComparison.OrdinalIgnoreCase);

            // Live first — a running instance's SCM map is ground truth.
            if (isSvchost && inst.Pid > 0)
            {
                try
                {
                    var id = SvchostIdentityService.Resolve(inst.Pid);
                    if (id != null && (!string.IsNullOrEmpty(id.ServicesCsv) ||
                                       !string.IsNullOrEmpty(id.Group) ||
                                       !string.IsNullOrEmpty(id.DeclaredService)))
                    {
                        inst.SvchostId = DescribeSvchost(id.DeclaredService, id.Group, id.ServicesCsv);
                        inst.SvchostCorroboration = id.Mismatch
                            ? "⚠ live SCM contradicts the command line — masquerade signal"
                            : "live SCM resolve — corroborates the command line ✓";
                        inst.IdentitySource = "live";
                    }
                }
                catch { /* a dead PID between snapshot and resolve — archive below */ }
            }

            // Archive EID 1 — proves image/command line/parent/user for dead
            // processes, and gives non-svchost instances their full context.
            try
            {
                var create = FindCreateEvent(inst);
                if (create != null)
                {
                    Get(create, "CommandLine", v => inst.CommandLine = v);
                    Get(create, "ParentImage", v => inst.ParentImage = v);
                    Get(create, "User", v => inst.User = v);
                    Get(create, "Image", v =>
                    {
                        if (string.IsNullOrEmpty(inst.Image)) inst.Image = v;
                        inst.Process = Path.GetFileName(inst.Image);
                    });
                    if (isSvchost && inst.IdentitySource != "live")
                    {
                        var (group, declared) = DecodeSvchostTokens(inst.CommandLine);
                        if (!string.IsNullOrEmpty(group) || !string.IsNullOrEmpty(declared))
                        {
                            inst.SvchostId = DescribeSvchost(declared, group, "");
                            inst.SvchostCorroboration =
                                "command line from the archive (process exited) — SCM corroboration only possible while it runs";
                            inst.IdentitySource = "archive";
                        }
                    }
                    else if (inst.IdentitySource != "live")
                    {
                        inst.IdentitySource = "archive";
                    }
                }
            }
            catch { /* archive unreadable — identity stays PID+image */ }
        }

        /// <summary>The EID 1 create-record for this instance: GUID match
        /// first (exact, boot-scoped), then (pid + image) for pre-GUID rows.</summary>
        private static ArchiveEvent FindCreateEvent(BlockTraceInstance inst)
        {
            if (!string.IsNullOrEmpty(inst.ProcessGuid))
            {
                var byGuid = SysmonArchiveService.Search(Eid1, inst.ProcessGuid, null, 5);
                var hit = byGuid.FirstOrDefault(e => e.Eid == 1);
                if (hit != null) return hit;
            }
            if (inst.Pid > 0)
            {
                foreach (var e in SysmonArchiveService.SearchCreateEvents(inst.Pid, 10))
                {
                    if (!string.IsNullOrEmpty(inst.Image) &&
                        string.Equals(e.Data.TryGetValue("Image", out var img) ? img : null,
                            inst.Image, StringComparison.OrdinalIgnoreCase))
                        return e;
                }
                return SysmonArchiveService.SearchCreateEvents(inst.Pid, 1)
                    .FirstOrDefault();
            }
            return null;
        }

        private static readonly int? Eid1 = 1;

        private static void Get(ArchiveEvent e, string field, Action<string> set)
        {
            if (e.Data != null && e.Data.TryGetValue(field, out var v) && !string.IsNullOrEmpty(v))
                set(v);
        }

        private static string DescribeSvchost(string declared, string group, string scmCsv)
        {
            string s = string.IsNullOrEmpty(declared) ? "—" : declared;
            string k = string.IsNullOrEmpty(group) ? "—" : group;
            string scm = string.IsNullOrEmpty(scmCsv) ? "unverified" : scmCsv;
            return $"-s {s} · -k {k} · SCM {scm}";
        }

        /// <summary>-k/-s token decode from a svchost command line — the
        /// offline half of SvchostIdentityService (no SCM to corroborate
        /// against, which the trace says explicitly).</summary>
        private static (string Group, string Declared) DecodeSvchostTokens(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return ("", "");
            string Group(string v) => v.Trim().Trim('"');
            var k = Regex.Match(commandLine, @"-k[= ]+""?([^""\s]+)""?", RegexOptions.IgnoreCase);
            var s = Regex.Match(commandLine, @"-s[= ]+""?([^""\s]+)""?", RegexOptions.IgnoreCase);
            return (k.Success ? Group(k.Groups[1].Value) : "",
                    s.Success ? Group(s.Groups[1].Value) : "");
        }

        // ── decision inference: pre-decision blocks, honestly marked ────

        /// <summary>Blocks created before "decided" lines existed (or removed
        /// records whose only story was the event log) get their trigger
        /// instance joined from the archive: the newest EID 3 attempt to this
        /// IP at-or-before the block's creation, within the trigger grace.
        /// ALWAYS marked inferred — it is evidence joined after the fact,
        /// never a snapshot, and it may name a process that merely shared
        /// the IP's traffic while the row showed another.</summary>
        private static void InferDecision(BlockTrace t)
        {
            if (!t.CreatedUtc.HasValue) return;
            try
            {
                var cutoff = t.CreatedUtc.Value.Add(TriggerGrace);
                var attempts = SysmonArchiveService.NewestConnectionPerIp(
                    new[] { t.Key },
                    accept: e => e.TsUtc <= cutoff);
                if (!attempts.TryGetValue(t.Key, out var e3)) return;

                string guid = e3.Data != null && e3.Data.TryGetValue("ProcessGuid", out var g) ? g : "";
                string image = e3.Data != null && e3.Data.TryGetValue("Image", out var i) ? i : "";
                int.TryParse(e3.Data != null && e3.Data.TryGetValue("ProcessId", out var p) ? p : "0",
                    out int pid);

                var inst = new BlockTraceInstance
                {
                    ProcessGuid = (guid ?? "").Trim('{', '}'),
                    Pid = pid,
                    Image = image ?? "",
                    IdentitySource = "archive",
                };
                ResolveIdentity(inst);
                t.Instances.Insert(0, inst);   // the trigger instance leads the list

                t.Decision = new BlockDecision
                {
                    Actor = "inferred (archive join, not captured at block time)",
                    TriggerPid = pid,
                    TriggerStartUtc = null,
                    Image = image ?? "",
                    SvchostId = inst.SvchostId,
                    RowSnapshot = $"newest archived attempt to this IP before the block: " +
                                  $"{e3.TsUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} → " +
                                  $"{(e3.Data != null && e3.Data.TryGetValue("DestinationPort", out var dp) ? dp : "?")}" +
                                  $"/{(e3.Data != null && e3.Data.TryGetValue("Protocol", out var pr) ? pr : "?")}",
                };
                t.DecisionInferred = true;
                t.InferredNote = "This block predates decision capture — the trigger instance was joined from the " +
                                 "Sysmon archive after the fact (newest attempt at-or-before creation). Honest, not exact.";
            }
            catch { /* archive unavailable — the trace stays decision-less, and says so */ }
        }

        /// <summary>Persists a proven inference as ONE "attributed" event line
        /// (dedup-guarded). USER SURFACES ONLY — the bridge's read tools never
        /// call this; writing history from an agent read would break the
        /// read-only contract the MCP surface is built on.</summary>
        public static void TryBackfill(BlockTrace t, BlocksLedger ledger = null)
        {
            if (t?.DecisionInferred != true) return;
            try
            {
                // Dedup against the LOG's current state, not t.Lifecycle — the
                // trace object was composed before any earlier backfill landed,
                // so a second call would pass that stale guard and write again.
                string path = ledger != null ? ledger.EventLogPath : BlocksStore.EventLogPath;
                if (AuditTrail.ReadEvents(path, 512 * 1024).Any(e =>
                        e.Action == "attributed" &&
                        e.Kind.Equals(t.Kind, StringComparison.OrdinalIgnoreCase) &&
                        e.Key.Equals(t.Key, StringComparison.OrdinalIgnoreCase) &&
                        e.Detail.Contains("trace-backfill")))
                    return;

                string detail = $"trace-backfill: trigger instance joined from the archive — " +
                                $"{(t.Decision?.TriggerPid ?? 0)} {(string.IsNullOrEmpty(t.Decision?.Image) ? "" : Path.GetFileName(t.Decision.Image))}";
                if (ledger != null) ledger.AppendEvent("attributed", t.Kind, t.Key, detail, "trace");
                else BlocksStore.AppendEvent("attributed", t.Kind, t.Key, detail, "trace");
            }
            catch { /* history is best-effort */ }
        }

        // ── renderers ───────────────────────────────────────────────────

        /// <summary>Plain-English headline: the one line a returning user
        /// actually wants to read.</summary>
        private static string Summarize(BlockTrace t)
        {
            string when = t.CreatedUtc.HasValue
                ? t.CreatedUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                : "an unknown time";
            string gone = t.RemovedUtc.HasValue
                ? $" — removed {t.RemovedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm}, no longer blocking"
                : "";
            string who = t.Decision == null
                ? "no decision evidence could be proven"
                : t.DecisionInferred
                    ? $"the archive points at PID {t.Decision.TriggerPid} " +
                      $"{(string.IsNullOrEmpty(t.Decision.Image) ? "" : $"({Path.GetFileName(t.Decision.Image)})")} (inferred)"
                    : $"trigger: PID {t.Decision.TriggerPid} " +
                      $"{(string.IsNullOrEmpty(t.Decision.Image) ? "" : $"({Path.GetFileName(t.Decision.Image)})")}";
            int attempts = t.Instances.Sum(i => i.Attempts);
            string hits = t.Instances.Count > 0
                ? $" {t.Instances.Count} process instance(s) hit it {attempts} time(s) in the retained feed window."
                : " No hits in the retained feed window.";
            return $"Blocked {when}{gone}; {who}.{hits}";
        }

        /// <summary>Multi-line report for the Blocks tab's Trace window — the
        /// same compose the bridge JSON serves, in the audit trail's voice.</summary>
        public static string FormatReport(BlockTrace t)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"═══ Trace: {(t.Kind == "ip" ? "IP" : "EXE")} {t.Key} ═══");
            sb.AppendLine();

            sb.AppendLine("── Decision ──");
            if (t.Record != null)
                sb.AppendLine($"State: blocking {(t.Record.Status == "on" ? "ON" : "OFF (paused)")} · " +
                              $"rules live · class at block: {t.Record.ClassAtBlock} · " +
                              $"origin: {t.Record.Origin} · identity: {t.Record.ServiceKey} " +
                              $"via {t.Record.Attrib}");
            else
                sb.AppendLine("State: not in the ledger (removed, or pre-ledger firewall rule)");
            if (t.Decision != null)
            {
                sb.AppendLine(t.Decision.Describe());
                if (t.DecisionInferred) sb.AppendLine("⚠ " + t.InferredNote);
            }
            else
                sb.AppendLine("No decision evidence available (pre-capture block and no archive attempt matched).");
            sb.AppendLine();

            sb.AppendLine("── Lifecycle (blocks-events.log) ──");
            if (t.Lifecycle.Count == 0)
                sb.AppendLine("(no events recorded for this target)");
            else
                foreach (var e in t.Lifecycle)
                    sb.AppendLine($"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {e.Action,-10} {e.Detail}  [{e.Origin}]");
            sb.AppendLine();

            sb.AppendLine("── Process instances that hit it ──");
            if (t.Instances.Count == 0)
                sb.AppendLine("(none in the retained feed window — quiet block, or hits aged out)");
            else
                foreach (var i in t.Instances)
                {
                    sb.AppendLine($"{i.Process}  PID {i.Pid}" +
                                  (string.IsNullOrEmpty(i.ProcessGuid) ? "" : $"  guid {{{i.ProcessGuid}}}"));
                    sb.AppendLine($"   attempts {i.Attempts} · {i.FirstUtc.ToLocalTime():HH:mm:ss} → {i.LastUtc.ToLocalTime():HH:mm:ss} · {i.Destinations}");
                    if (!string.IsNullOrEmpty(i.SvchostId)) sb.AppendLine($"   svchost identity: {i.SvchostId}");
                    if (!string.IsNullOrEmpty(i.SvchostCorroboration)) sb.AppendLine($"   {i.SvchostCorroboration}");
                    if (!string.IsNullOrEmpty(i.CommandLine)) sb.AppendLine($"   command line: {i.CommandLine}");
                    if (!string.IsNullOrEmpty(i.ParentImage)) sb.AppendLine($"   spawned by {Path.GetFileName(i.ParentImage)}");
                    if (!string.IsNullOrEmpty(i.User)) sb.AppendLine($"   user: {i.User}");
                    sb.AppendLine($"   identity source: {i.IdentitySource}");
                    sb.AppendLine();
                }

            sb.AppendLine("── Summary ──");
            sb.AppendLine(t.Summary);
            return sb.ToString();
        }
    }
}
