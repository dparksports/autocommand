using System;
using System.Windows;
using System.Windows.Media;

#nullable enable

namespace AutoCommand.Views
{
    /// <summary>
    /// The Cadence tab's correlation visual: 24 hour buckets, each showing a
    /// gray typing bar beside accent packet marks, so a non-technical user
    /// can see at a glance whether telemetry lands while they type or while
    /// they are away. House pattern — a FrameworkElement hosting one
    /// DrawingVisual repainted on demand (no chart library in this app).
    /// </summary>
    public sealed class CadenceChartCanvas : FrameworkElement
    {
        private readonly DrawingVisual _visual = new();
        private int[] _keys = Array.Empty<int>();
        private int[] _packets = Array.Empty<int>();
        private string _title = "";

        public CadenceChartCanvas()
        {
            AddVisualChild(_visual);
        }

        protected override int VisualChildrenCount => 1;
        protected override Visual GetVisualChild(int index) => _visual;

        public void SetData(string title, int[] keys, int[] packets)
        {
            _title = title ?? "";
            _keys = keys ?? Array.Empty<int>();
            _packets = packets ?? Array.Empty<int>();
            Render();
        }

        private Brush Brush(string key, Brush fallback)
        {
            var b = TryFindResource(key) as Brush;
            return b ?? fallback;
        }

        private void Render()
        {
            using var dc = _visual.RenderOpen();
            double w = Math.Max(ActualWidth, 10);
            double h = Math.Max(ActualHeight, 10);

            var surface = Brush("SurfaceBrush", Brushes.DimGray);
            var border = Brush("BorderBrush", Brushes.Gray);
            var textBrush = Brush("MutedTextBrush", Brushes.Gray);
            var keyBrush = new SolidColorBrush(Color.FromArgb(160, 150, 150, 150));
            var packetBrush = Brush("AccentCyanBrush", Brushes.DodgerBlue);

            dc.DrawRectangle(surface, null, new Rect(0, 0, w, h));

            int n = Math.Max(_keys.Length, _packets.Length);
            if (n == 0)
            {
                var none = new FormattedText("no data yet", System.Globalization.CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight, new Typeface("Segoe UI"), 12, textBrush,
                    VisualTreeHelper.GetDpi(this).PixelsPerDip);
                dc.DrawText(none, new Point(10, h / 2));
                return;
            }

            double left = 34, right = 8, top = 8, bottom = 18;
            double plotW = Math.Max(w - left - right, 1);
            double plotH = Math.Max(h - top - bottom, 1);
            double slot = plotW / n;
            double barW = Math.Max(3, Math.Min(14, slot * 0.55));

            double maxKeys = 1, maxPackets = 1;
            foreach (var v in _keys) maxKeys = Math.Max(maxKeys, v);
            foreach (var v in _packets) maxPackets = Math.Max(maxPackets, v);
            maxKeys *= 1.15;
            maxPackets *= 1.15;

            dc.DrawRectangle(null, new Pen(border, 0.5), new Rect(left, top, plotW, plotH));

            for (int i = 0; i < n; i++)
            {
                double x = left + i * slot;

                // keys: solid gray bar from the baseline
                double kh = plotH * Math.Min(1.0, _keys.Length > i ? _keys[i] / maxKeys : 0);
                if (kh > 0.5)
                    dc.DrawRectangle(keyBrush, null, new Rect(x + 1, top + plotH - kh, barW, kh));

                // packets: accent marks in the upper half — packets per hour are
                // small (single digits), so each packet draws one tick
                double pk = _packets.Length > i ? _packets[i] : 0;
                double tickH = Math.Max(2.5, plotH * 0.04);
                double px = x + 1 + barW + 1;
                for (int p = 0; p < Math.Min(pk, 20); p++)
                {
                    double py = top + (plotH * 0.55) - p * (tickH + 1.5);
                    if (py < top + 1) break;
                    dc.DrawRectangle(packetBrush, null, new Rect(px, py, Math.Max(3, barW), tickH));
                }

                if (i % 3 == 0 || i == 23)
                {
                    var lbl = new FormattedText($"{i,2}h", System.Globalization.CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight, new Typeface("Segoe UI"), 9, textBrush,
                        VisualTreeHelper.GetDpi(this).PixelsPerDip);
                    dc.DrawText(lbl, new Point(x - 4, top + plotH + 3));
                }
            }

            if (!string.IsNullOrEmpty(_title))
            {
                var t = new FormattedText(_title, System.Globalization.CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight, new Typeface("Segoe UI"), 11, textBrush,
                    VisualTreeHelper.GetDpi(this).PixelsPerDip);
                dc.DrawText(t, new Point(left, top + 2));
            }
        }
    }
}
