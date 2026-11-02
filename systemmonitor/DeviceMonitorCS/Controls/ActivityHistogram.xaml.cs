using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Controls
{
    public partial class ActivityHistogram : UserControl
    {
        public event Action<DateTime, DateTime> TimeRangeSelected;

        private List<TimelineEvent> _allEvents;
        private double _barWidth;
        private int _totalBuckets = 96; // 15-minute intervals (24 * 4)
        private DateTime _dayStart;
        
        public ActivityHistogram()
        {
            InitializeComponent();
        }

        public void LoadData(IEnumerable<TimelineEvent> events, DateTime day)
        {
            _allEvents = events.ToList();
            _dayStart = day.Date; // Normalize to midnight
            DrawChart();
        }

        private void DrawChart()
        {
            ChartCanvas.Children.Clear();
            if (_allEvents == null || !_allEvents.Any()) return;

            double width = ChartCanvas.ActualWidth;
            double height = ChartCanvas.ActualHeight;
            if (width == 0 || height == 0) return;

            // Bucketing
            var buckets = new int[_totalBuckets];
            var errorBuckets = new int[_totalBuckets]; // Red
            var warnBuckets = new int[_totalBuckets]; // Yellow
            
            foreach (var evt in _allEvents)
            {
                var offset = evt.Timestamp - _dayStart;
                if (offset.TotalMinutes < 0) continue; 
                
                int bucketIndex = (int)(offset.TotalMinutes / 15.0);
                if (bucketIndex >= 0 && bucketIndex < _totalBuckets)
                {
                    buckets[bucketIndex]++;
                    
                    // Categorize for color
                    if (IsCritical(evt)) errorBuckets[bucketIndex]++;
                    else if (IsWarning(evt)) warnBuckets[bucketIndex]++;
                }
            }

            int maxCount = buckets.Max();
            if (maxCount == 0) maxCount = 1;

            MaxCountText.Text = $"{maxCount}";

            _barWidth = width / _totalBuckets;

            for (int i = 0; i < _totalBuckets; i++)
            {
                int total = buckets[i];
                if (total == 0) continue;

                int errors = errorBuckets[i];
                int warnings = warnBuckets[i];
                int infos = total - errors - warnings;

                double x = i * _barWidth;
                
                // Stacked Bars (Info bottom, Warn mid, Error top)
                double currentY = height;

                // Info Bar (Cyan)
                if (infos > 0)
                {
                    double h = (infos / (double)maxCount) * height;
                    DrawBar(x, currentY - h, h, Brushes.Cyan, 0.4);
                    currentY -= h;
                }

                // Warn Bar (Yellow)
                if (warnings > 0)
                {
                    double h = (warnings / (double)maxCount) * height;
                    DrawBar(x, currentY - h, h, Brushes.Yellow, 0.6);
                    currentY -= h;
                }

                // Error Bar (Red)
                if (errors > 0)
                {
                    double h = (errors / (double)maxCount) * height;
                    DrawBar(x, currentY - h, h, Brushes.Red, 0.8);
                }
            }
        }

        private void DrawBar(double x, double y, double height, Brush fill, double opacity)
        {
            if (height < 1) height = 1; // Min height visibility

            var rect = new Rectangle
            {
                Width = Math.Max(1, _barWidth - 1), // 1px gap
                Height = height,
                Fill = fill,
                Opacity = opacity,
                IsHitTestVisible = false // Canvas handles clicks
            };

            Canvas.SetLeft(rect, x);
            Canvas.SetTop(rect, y);
            ChartCanvas.Children.Add(rect);
        }

        private bool IsCritical(TimelineEvent evt)
        {
            // Security failures, critical system errors
            if (evt.EventId == 4625) return true; // Login Failed
            if (evt.Category == "Error" || evt.Category.Contains("Fail")) return true;
            if (evt.EventId == 6008) return true; // Unexpected Shutdown
            return false;
        }

        private bool IsWarning(TimelineEvent evt)
        {
             if (evt.Category.Contains("Change") || evt.Category.Contains("Policy")) return true;
             return false;
        }

        private void ChartCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            DrawChart();
        }

        private void ChartCanvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (_barWidth <= 0) return;

            var pos = e.GetPosition(ChartCanvas);
            int bucketIndex = (int)(pos.X / _barWidth);

            if (bucketIndex >= 0 && bucketIndex < _totalBuckets)
            {
                // Calculate time range
                var start = _dayStart.AddMinutes(bucketIndex * 15);
                var end = start.AddMinutes(15);
                
                TimeRangeSelected?.Invoke(start, end);
                TooltipText.Text = $"Filtered: {start:HH:mm} - {end:HH:mm}";
            }
        }
    }
}
