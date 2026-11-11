using System;
using System.Windows;
using System.Windows.Media;

namespace AutoCommand.Matrix
{
    /// <summary>
    /// The rain's host surface: two stacked DrawingVisuals — the frozen
    /// ambient backdrop below, the falling rain above — opened and repainted
    /// by MatrixRenderer each frame. Text-rendered by construction: the
    /// visuals' content is WPF-owned glyph geometry, so a render-device loss
    /// (display sleep/wake, session lock, monitor change) is absorbed inside
    /// WPF's composition — nothing here holds a GPU resource, and there is
    /// no lock protocol to violate. The bitmap engine this replaces crashed
    /// three times on exactly that (crash.log 2026-11-08/09/11).
    /// </summary>
    public sealed class MatrixRainCanvas : FrameworkElement
    {
        private readonly DrawingVisual _ambient = new();
        private readonly DrawingVisual _rain = new();
        private double _ppd;      // cached PixelsPerDip once connected

        public MatrixRainCanvas()
        {
            AddVisualChild(_ambient);
            AddVisualChild(_rain);
        }

        protected override int VisualChildrenCount => 2;
        protected override Visual GetVisualChild(int index) => index == 0 ? _ambient : _rain;

        protected override Size ArrangeOverride(Size arrangeSize)
        {
            // Lift cells and bloom halos poke past their grid cells by
            // design; the pane's edge is the hard stop.
            Clip = new RectangleGeometry(new Rect(arrangeSize));
            return base.ArrangeOverride(arrangeSize);
        }

        /// <summary>Open a fresh drawing pass over the backdrop layer (the
        /// old content is replaced wholesale — clearing is implicit).</summary>
        public DrawingContext OpenAmbient() => _ambient.RenderOpen();

        /// <summary>Open a fresh drawing pass over the rain layer.</summary>
        public DrawingContext OpenRain() => _rain.RenderOpen();

        /// <summary>Per-monitor DPI for glyph hinting, cached on first
        /// connection (cosmetic only — layout and sizing are DIP-native and
        /// scale without this).</summary>
        public double PixelsPerDip
        {
            get
            {
                if (_ppd == 0)
                {
                    try { _ppd = VisualTreeHelper.GetDpi(this).PixelsPerDip; }
                    catch { _ppd = 1.0; }   // not connected to a presentation source yet
                }
                return _ppd;
            }
        }
    }
}
