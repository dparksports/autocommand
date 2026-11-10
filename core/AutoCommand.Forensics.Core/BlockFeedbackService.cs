using System;
using System.Linq;
using System.Text;

namespace AutoCommand.Forensics.Core
{
    /// <summary>
    /// The pre-block context the confirmation dialog shows — the same join
    /// the bridge's investigate_process produces (who is this image, what
    /// shape is its traffic, is it already being blocked), compressed into
    /// a few lines so users decide with the investigation in front of them
    /// instead of a bare path. Archive-backed: budget it on a background
    /// thread (the monitor already does this dance for other joins).
    /// Returns "" when nothing meaningful is known — silence over invention.
    /// </summary>
    public static class BlockFeedbackService
    {
        /// <summary>
        /// Brief for an image name (wildcards not needed here — the monitor
        /// passes a concrete leaf). Optional ip adds the destination line
        /// for remote-IP blocks.
        /// </summary>
        public static string Brief(string processName, string ip = null, int hours = 6)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(processName) && string.IsNullOrWhiteSpace(ip)) return "";
                var inv = ProcessInvestigationService.Investigate(processName, null, hours);
                var sb = new StringBuilder();

                sb.Append("🔎 Pre-block brief — ").Append(string.IsNullOrWhiteSpace(inv.ImageName) ? processName : inv.ImageName)
                  .Append(" (last ").Append(inv.WindowHours).Append(" h)");
                if (!string.IsNullOrWhiteSpace(ip)) sb.Append("\n  destination: ").Append(ip);
                sb.AppendLine();

                string who = inv.Provenance?.Verdict;
                sb.Append("  who: ").Append(string.IsNullOrWhiteSpace(who) ? "no live instance to profile" : who).AppendLine();

                if (inv.Trace != null)
                {
                    sb.Append("  traffic: ").Append(inv.Trace.ConnectsLast24H).Append(" connects (~")
                      .Append(Math.Round(inv.Trace.ConnectsPerHour)).Append("/hr");
                    var top = inv.Trace.Destinations?.FirstOrDefault();
                    if (top != null)
                        sb.Append(" · top: ").Append(top.Ip).Append(":").Append(top.Port)
                          .Append(" [").Append(string.IsNullOrEmpty(top.Classification) ? "unclassified" : top.Classification)
                          .Append("] ×").Append(top.Count);
                    sb.AppendLine();
                }

                if (inv.BlockHitCount > 0)
                    sb.Append("  already blocked: yes — ").Append(inv.BlockHitCount).Append(" attempt(s) dropped in window").AppendLine();

                if (!string.IsNullOrWhiteSpace(inv.VerdictHeadline))
                    sb.Append("  verdict: ").Append(inv.VerdictHeadline).AppendLine();

                sb.Append("  after blocking: attempts drop, bytes stay zero — the row's glyph and\n")
                  .Append("  'Blocked' → Manage all show contained / stale / leak honestly.");
                return sb.ToString();
            }
            catch
            {
                return "";   // the brief is advisory; the block flow must never fail on it
            }
        }
    }
}
