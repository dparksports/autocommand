using System;
using System.Globalization;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// The decision evidence captured at the moment a block is chosen — the
    /// "who chose this, and what did they see" snapshot the v3 record's
    /// identity fields (ServiceKey/ClassAtBlock) cannot carry. Persisted as
    /// ONE "decided" line in blocks-events.log, adjacent to its "created"
    /// line, so the audit trail stays the single history file:
    ///
    ///   utc|decided|kind|key|pid=…;start=…;image=…;actor=…;svc=…;snap=…|origin
    ///
    /// (six pipe-fields, same shape every other event uses — the structured
    /// fields ride INSIDE the detail segment, ';'-separated k=v pairs).
    /// Everything here is evidence, never a guess: the PID is the monitor
    /// row's PID, the start time is the row's stable process identity
    /// (recycled PIDs join by (pid, start)), and the snapshot is what the
    /// row showed at choice time — the counters that evaporate with the
    /// in-memory monitor state.
    /// </summary>
    public sealed class BlockDecision
    {
        /// <summary>Who chose the block: "user:&lt;surface&gt;" (user:monitor,
        /// user:blocks-tab), "autopilot", or "agent:&lt;client&gt;". The
        /// gate service already records who asked for unblocks; blocks get
        /// the same honesty.</summary>
        public string Actor = "user:monitor";

        /// <summary>The monitor row's PID at block time — 0 when unknown.
        /// Meaningful only together with TriggerStartUtc (PIDs recycle).</summary>
        public int TriggerPid;

        /// <summary>When the trigger process started (UTC), per Sysmon —
        /// the (pid, start) pair is the instance identity the archive join
        /// resolves after the process dies.</summary>
        public DateTime? TriggerStartUtc;

        /// <summary>Full executable path at block time (the v3 record's
        /// ProcessName label is audit-only and not persisted; the path is).</summary>
        public string Image = "";

        /// <summary>svchost instance identity at block time, when the row
        /// was a service host: "-s WpnService · -k netsvcs · SCM WpnService"
        /// (⚠ marks a declared-vs-SCM mismatch). "" for non-svchost rows.</summary>
        public string SvchostId = "";

        /// <summary>What the monitor row showed at choice time: counters,
        /// destination shape, hostname — the "why" evidence.</summary>
        public string RowSnapshot = "";

        // ── wire format ─────────────────────────────────────────────────

        /// <summary>Encodes as the detail segment: ';'-separated k=v pairs.
        /// Values are field-sanitized (';' and '|' stripped) so one value can
        /// never forge another field.</summary>
        public override string ToString()
        {
            static string V(string s) => (s ?? "").Replace(';', ',').Replace('|', '/');
            return $"pid={TriggerPid}" +
                   $";start={(TriggerStartUtc.HasValue ? V(TriggerStartUtc.Value.ToString("O", CultureInfo.InvariantCulture)) : "-")}" +
                   $";image={V(Image)}" +
                   $";actor={V(Actor)}" +
                   (string.IsNullOrEmpty(SvchostId) ? "" : $";svc={V(SvchostId)}") +
                   (string.IsNullOrEmpty(RowSnapshot) ? "" : $";snap={V(RowSnapshot)}");
        }

        /// <summary>Inverse of ToString — parses one "decided" detail segment.
        /// Tolerant of older/simpler encodings: unknown k=v pairs are skipped,
        /// a missing pid/start leaves defaults, and only a corrupt lead pair
        /// (no '=' anywhere) fails.</summary>
        public static bool TryParse(string detail, out BlockDecision d)
        {
            d = new BlockDecision();
            if (string.IsNullOrWhiteSpace(detail)) return false;
            bool any = false;
            foreach (string pair in detail.Split(';'))
            {
                int eq = pair.IndexOf('=');
                if (eq <= 0) continue;
                string k = pair[..eq].Trim();
                string v = pair[(eq + 1)..].Trim();
                switch (k)
                {
                    case "pid": any |= int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out d.TriggerPid); break;
                    case "start":
                        if (v != "-" && DateTime.TryParse(v, CultureInfo.InvariantCulture,
                                DateTimeStyles.RoundtripKind, out var st))
                        {
                            d.TriggerStartUtc = DateTime.SpecifyKind(st, DateTimeKind.Utc);
                            any = true;
                        }
                        break;
                    case "image": d.Image = v; any = true; break;
                    case "actor": d.Actor = v; any = true; break;
                    case "svc": d.SvchostId = v; any = true; break;
                    case "snap": d.RowSnapshot = v; any = true; break;
                }
            }
            return any;
        }

        /// <summary>Plain-English line for the trace surfaces ("Blocked from
        /// the Process Monitor — trigger: 5852 (brave.exe)…").</summary>
        public string Describe()
        {
            string who = string.IsNullOrEmpty(Actor) ? "unknown actor" : Actor.Replace("user:", "user · ");
            string trigger = TriggerPid > 0
                ? $"{TriggerPid}" + (string.IsNullOrEmpty(Image) ? "" : $" ({System.IO.Path.GetFileName(Image)})")
                  + (TriggerStartUtc.HasValue ? $" started {TriggerStartUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm}" : "")
                : "trigger instance not captured";
            string svc = string.IsNullOrEmpty(SvchostId) ? "" : $" · svchost identity: {SvchostId}";
            string snap = string.IsNullOrEmpty(RowSnapshot) ? "" : $"\nRow at choice time: {RowSnapshot}";
            return $"Chosen by {who} — trigger: {trigger}{svc}{snap}";
        }
    }
}
