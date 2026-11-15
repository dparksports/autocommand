using System;
using System.Collections.Generic;
using System.Linq;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Pure math behind the Cadence tab — how strongly DiagTrack's hourly
    /// packet cadence relates to the (opt-in) hourly typing-count cadence.
    /// No IO, no state, no UI: every input is an int[24] indexed by hour of
    /// local day, so callers can pass one day or a concatenated multi-day
    /// series. Rank correlation (Spearman) instead of Pearson: CDN batching
    /// and TCP coalescing smear packet counts, and ranks survive that.
    /// </summary>
    public static class CadenceMath
    {
        /// <summary>Spearman rank correlation over the paired hourly series.
        /// Null when either side is constant (nothing to rank) — that is the
        /// honest "not enough signal" answer, never a forced 0.</summary>
        public static double? Spearman(int[] a, int[] b)
        {
            if (a == null || b == null || a.Length != b.Length || a.Length < 4) return null;
            if (a.All(v => v == a[0]) || b.All(v => v == b[0])) return null;

            double[] ra = Ranks(a), rb = Ranks(b);
            int n = a.Length;
            double ma = ra.Average(), mb = rb.Average();
            double num = 0, da = 0, db = 0;
            for (int i = 0; i < n; i++)
            {
                num += (ra[i] - ma) * (rb[i] - mb);
                da += (ra[i] - ma) * (ra[i] - ma);
                db += (rb[i] - mb) * (rb[i] - mb);
            }
            if (da <= 0 || db <= 0) return null;
            return num / Math.Sqrt(da * db);
        }

        /// <summary>Average ranks (1-based), ties split — the standard
        /// Spearman ranking rule.</summary>
        private static double[] Ranks(int[] values)
        {
            var order = Enumerable.Range(0, values.Length)
                .OrderByDescending(i => values[i])   // descending: more = higher rank
                .ToArray();
            var ranks = new double[values.Length];
            int i = 0;
            while (i < order.Length)
            {
                int j = i;
                while (j + 1 < order.Length && values[order[j + 1]] == values[order[i]]) j++;
                double rank = (i + 1 + j + 1) / 2.0;  // average of the tied block
                for (int k = i; k <= j; k++) ranks[order[k]] = rank;
                i = j + 1;
            }
            return ranks;
        }

        /// <summary>Share of DiagTrack packets that landed in hours where
        /// typing was observed ("typing-locked"), 0-100. Null when there are
        /// no packets at all — again, honest "no signal".</summary>
        public static double? TypingLockedPercent(int[] keys, int[] packets)
        {
            if (keys == null || packets == null || keys.Length != packets.Length) return null;
            long total = 0, locked = 0;
            for (int h = 0; h < packets.Length; h++)
            {
                total += packets[h];
                if (keys[h] > 0) locked += packets[h];
            }
            if (total == 0) return null;
            return 100.0 * locked / total;
        }

        /// <summary>The non-technical verdict line for a correlation value.
        /// Bands are fixed and documented in docs/PRIVACY.md so the tab's
        /// wording never drifts with the data.</summary>
        public static string Verdict(double? rho)
        {
            if (rho == null) return "Not enough signal yet — collect more days with typing counted.";
            double v = rho.Value;
            if (v >= 0.5) return "Follows your typing — most telemetry lands while you are at the keyboard.";
            if (v >= 0.2) return "Partially related — a mix of typing-time and machine-timed uploads.";
            return "Machine-timed — unrelated to your typing.";
        }

        /// <summary>Concatenates several day-series into one long series so a
        /// multi-day correlation can be computed from per-day int[24] rows.</summary>
        public static int[] Concat(IEnumerable<int[]> daySeries)
        {
            var outList = new List<int>();
            foreach (var day in daySeries ?? Array.Empty<int[]>())
                if (day != null) outList.AddRange(day);
            return outList.ToArray();
        }
    }
}
