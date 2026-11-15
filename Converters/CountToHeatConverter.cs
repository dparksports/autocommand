using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace AutoCommand.Converters
{
    /// <summary>
    /// int? count → heat brush for the Cadence matrix. The distinction the
    /// tab lives by: <c>null</c> means "not tracked / no signal" (rendered
    /// muted with a — in the cell), while 0 means "tracked and quiet".
    /// Bands are fixed per mode ("keys" vs "packets") so colors never lie:
    /// keys volume is 1-2 orders of magnitude above DiagTrack packets.
    /// </summary>
    public sealed class CountToHeatConverter : IValueConverter
    {
        private static readonly Brush NoData = new SolidColorBrush(Color.FromArgb(60, 128, 128, 128));
        private static readonly Brush Zero = Brushes.Transparent;
        // typing side: amber family — "you"
        private static readonly Brush Low = new SolidColorBrush(Color.FromArgb(70, 240, 163, 10));
        private static readonly Brush Mid = new SolidColorBrush(Color.FromArgb(140, 240, 163, 10));
        private static readonly Brush High = new SolidColorBrush(Color.FromArgb(200, 224, 82, 46));
        // telemetry side: cyan family — "the machine" (hue alone separates
        // the two halves of a cell, no legend-reading required)
        private static readonly Brush PkLow = new SolidColorBrush(Color.FromArgb(70, 59, 130, 246));
        private static readonly Brush PkMid = new SolidColorBrush(Color.FromArgb(140, 59, 130, 246));
        private static readonly Brush PkHigh = new SolidColorBrush(Color.FromArgb(200, 37, 99, 235));

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            int? v = value as int?;
            if (v == null) return NoData;
            if (v.Value == 0) return Zero;

            bool keys = !string.Equals(parameter as string, "packets", StringComparison.Ordinal);
            if (keys)
            {
                if (v.Value >= 250) return High;
                if (v.Value >= 50) return Mid;
                return Low;
            }
            if (v.Value >= 10) return PkHigh;
            if (v.Value >= 4) return PkMid;
            return PkLow;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }
}
