using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Media;

#nullable enable

namespace AutoCommand.Views
{
    /// <summary>One local day's dual series for the strip chart.</summary>
    public sealed class CadenceDayStrip
    {
        public string Label = "";
        public int[] Keys = Array.Empty<int>();
        public int[] Packets = Array.Empty<int>();
        public bool IsToday;
    }

    /// <summary>
    /// The Cadence tab's correlation visual — ONE strip per local day, each
    /// strip drawing that day's 24 hour buckets with BOTH series at once:
    /// a gray bar for typing counts rising from the strip's lower half and
    /// cyan ticks for DiagTrack packets hanging in the upper half. Seven
    /// strips stacked = the whole week in one glance; there is no mode to
    /// switch and nothing hidden, so the two presentations (strip chart and
    /// dual-half matrix) stay continuous. House pattern: a FrameworkElement
    /// hosting a DrawingVisual repainted on demand (no chart library).
    /// </summary>
    public sealed class CadenceChartCanvas : FrameworkElement
    {
        private readonly DrawingVisual _visual = new();
        private string _legend = "";
        private List<CadenceDayStrip> _strips = new();

        public CadenceChartCanvas()
        {
            AddVisualChild(_visual);
        }

        protected override int VisualChildrenCount => 1;
        protected override Visual GetVisualChild(int index) => _visual;

        public void SetStrips(string legend, List<CadenceDayStrip> strips)
        {
            _legend = legend ?? "";
            _strips = strips ?? new List<CadenceDayStrip>();
            Render();
        }

        private Brush Brush(string key, Brush fallback) => TryFindResource(key) as Brush ?? fallback;

        private void Render()
        {
            using var dc = _visual.RenderOpen();
            double w = Math.Max(ActualWidth, 10);
            double h = Math.Max(ActualHeight, 10);

            var surface = Brush("SurfaceBrush", Brushes.DimGray);
            var border = Brush("BorderBrush", Brushes.Gray);
            var textBrush = Brush("MutedTextBrush", Brushes.Gray);
            var primaryBrush = Brush("TextPrimaryBrush", Brushes.White);
            var rowAlt = Brush("RowAltBrush", Brushes.LightGray);
            var keyBrush = new SolidColorBrush(Color.FromArgb(170, 150, 150, 150));
            var packetBrush = Brush("AccentCyanBrush", Brushes.DodgerBlue);
            double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

            dc.DrawRectangle(surface, null, new Rect(0, 0, w, h));

            double left = 46, right = 8, top = 22, bottom = 6;
            if (_strips.Count == 0)
            {
                var none = new FormattedText("no data yet", CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight, new Typeface("Segoe UI"), 12, textBrush, dpi);
                dc.DrawText(none, new Point(10, h / 2));
                return;
            }

            var legendText = new FormattedText(_legend, CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight, new Typeface("Segoe UI"), 10, textBrush, dpi);
            dc.DrawText(legendText, new Point(left, 3));

            double stripH = Math.Max(10, (h - top - bottom) / _strips.Count);

            double maxKeys = 1, maxPackets = 1;
            foreach (var s in _strips)
            {
                foreach (var v in s.Keys) maxKeys = Math.Max(maxKeys, v);
                foreach (var v in s.Packets) maxPackets = Math.Max(maxPackets, v);
            }
            maxKeys *= 1.15;
            maxPackets *= 1.15;

            for (int si = 0; si < _strips.Count; si++)
            {
                var s = _strips[si];
                double y = top + si * stripH;

                // today's strip gets the alternate row wash, like the tables
                if (s.IsToday)
                    dc.DrawRectangle(rowAlt, null, new Rect(left, y, Math.Max(1, w - left - right), stripH));

                var lbl = new FormattedText(
                    s.IsToday ? s.Label + " · today" : s.Label,
                    CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                    new Typeface("Segoe UI"), 9,
                    s.IsToday ? primaryBrush : textBrush, dpi);
                dc.DrawText(lbl, new Point(4, y + stripH / 2 - 6));

                double slot = Math.Max(2, (w - left - right) / 24);
                double barW = Math.Max(2.5, Math.Min(12, slot * 0.5));
                double halfH = Math.Max(3, stripH / 2 - 3);

                for (int i = 0; i < 24; i++)
                {
                    double x = left + i * slot;

                    // typing counts: gray bar rising from the strip's bottom half
                    double kv = i < s.Keys.Length ? s.Keys[i] : 0;
                    double kh = halfH * Math.Min(1.0, kv / maxKeys);
                    if (kh > 0.5)
                        dc.DrawRectangle(keyBrush, null, new Rect(x, y + stripH - 2 - kh, barW, kh));

                    // DiagTrack packets: cyan ticks stacked in the strip's upper half
                    double pk = i < s.Packets.Length ? s.Packets[i] : 0;
                    double tickH = Math.Max(1.8, halfH * 0.12);
                    double px = x + barW + 1;
                    for (int p = 0; p < Math.Min(pk, 12); p++)
                    {
                        double py = y + 2 + halfH - (p + 1) * (tickH + 1);
                        if (py < y + 1) break;
                        dc.DrawRectangle(packetBrush, null, new Rect(px, py, Math.Max(2.5, barW), tickH));
                    }
                }

                // strip separator
                dc.DrawRectangle(border, null, new Rect(left, y, Math.Max(1, w - left - right), 0.6));
            }
        }
    }
}
