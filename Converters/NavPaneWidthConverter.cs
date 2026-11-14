using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AutoCommand.Converters
{
    /// <summary>
    /// IsPaneCollapsed → the sidebar column's GridLength: the icon rail when
    /// the labels are hidden, the full label pane when shown. The burger
    /// (and the narrow-launch auto-fold) drive the bool — the width simply
    /// follows, so every path that flips the flag reshapes the panel.
    /// One-way on purpose: the width never writes back.
    /// </summary>
    public sealed class NavPaneWidthConverter : IValueConverter
    {
        public double ExpandedWidth { get; set; } = 220;
        public double CollapsedWidth { get; set; } = 56;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
            value is true ? new GridLength(CollapsedWidth) : new GridLength(ExpandedWidth);

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
