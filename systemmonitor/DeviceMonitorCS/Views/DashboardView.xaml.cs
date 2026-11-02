using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using System.Diagnostics;
using System.Windows.Shapes;
using System.Collections.Generic;
using System.Management;

namespace DeviceMonitorCS.Views
{
    public partial class DashboardView : UserControl
    {
        private DispatcherTimer _timer;
        private PerformanceCounter _cpuCounter;
        private PerformanceCounter _ramCounter;
        private double _totalRamMB;
        public ObservableCollection<TimelineItem> RecentEvents { get; set; } = new ObservableCollection<TimelineItem>();

        public event Action<string> NavigationRequested;

        public DashboardView()
        {
            InitializeComponent();
            TimelineList.ItemsSource = RecentEvents;

            // Sample Data
            RecentEvents.Add(new TimelineItem { Title = "Firewall Rule Updated", Time = DateTime.Now.AddMinutes(-10), Color = "#00F0FF" });
            RecentEvents.Add(new TimelineItem { Title = "Scan Completed", Time = DateTime.Now.AddMinutes(-45), Color = "#00E676" });
            RecentEvents.Add(new TimelineItem { Title = "Device Connected", Time = DateTime.Now.AddHours(-1), Color = "#FFAE00" });
             RecentEvents.Add(new TimelineItem { Title = "Scan Completed", Time = DateTime.Now.AddHours(-2), Color = "#00E676" });
        }

        private async void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // Defer blocking operations to background thread
                await Task.Run(() => 
                {
                    _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                    _ramCounter = new PerformanceCounter("Memory", "Available MBytes");

                    // Get Total RAM via WMI
                    using (var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem"))
                    {
                        foreach (var obj in searcher.Get())
                        {
                            _totalRamMB = Convert.ToDouble(obj["TotalVisibleMemorySize"]) / 1024.0; // KB to MB
                        }
                    }
                });

                _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                _timer.Tick += Timer_Tick;
                _timer.Start();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("PerfCounter Error: " + ex.Message);
            }
        }

        private void StatusShield_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            NavigationRequested?.Invoke("SecureBoots");
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            _timer?.Stop();
        }

        // Graph Data History (Last 60 seconds)
        private readonly int _historyLength = 60;
        private List<double> _cpuHistory = new List<double>();
        private List<double> _ramHistory = new List<double>();

        private void Timer_Tick(object sender, EventArgs e)
        {
            if (_cpuCounter != null)
            {
                float cpu = _cpuCounter.NextValue();
                float ramAvailableMB = _ramCounter.NextValue();
                
                double availableGB = ramAvailableMB / 1024.0;
                if (availableGB < 0) availableGB = 0;

                CpuText.Text = $"{cpu:0}%";
                MemText.Text = $"{availableGB:0.0} GB Available";

                // Scale: CPU max 100, RAM max TotalRamGB
                UpdateGraphSmoothed(_cpuHistory, cpu, CpuPath, 100);
                UpdateGraphSmoothed(_ramHistory, availableGB, MemPath, _totalRamMB / 1024.0); 
            }
        }

        private void UpdateGraphSmoothed(List<double> history, double newValue, System.Windows.Shapes.Path path, double maxY)
        {
            history.Add(newValue);
            if (history.Count > _historyLength) history.RemoveAt(0);

            double width = path.ActualWidth;
            double height = path.ActualHeight;
            if (width == 0 || height == 0) return;

            double xStep = width / (_historyLength - 1);
            
            var geometry = new PathGeometry();
            var figure = new PathFigure();
            
            // Base height adjusted for stroke thickness to prevent sinking
            double baseHeight = height - 1.0; 
            
            // Start Point (at the bottom left if we want a fill)
            figure.StartPoint = new Point(0, baseHeight);
            figure.IsClosed = true;

            if (history.Count < 2) return;

            // First Actual Data Point
            double firstY = baseHeight - ((history[0] / maxY) * baseHeight);
            figure.Segments.Add(new LineSegment(new Point(0, firstY), true));

            for (int i = 1; i < history.Count; i++)
            {
                double x = i * xStep;
                double y = baseHeight - ((history[i] / maxY) * baseHeight);
                if (y < 0) y = 0;
                if (y > baseHeight) y = baseHeight;

                // For smoothing, we use a Bezier segment. 
                double prevX = (i - 1) * xStep;
                double prevY = baseHeight - ((history[i-1] / maxY) * baseHeight);

                figure.Segments.Add(new BezierSegment(
                    new Point(prevX + (xStep / 2), prevY),
                    new Point(x - (xStep / 2), y),
                    new Point(x, y),
                    true
                ));
            }

            // End Point (at the bottom right for fill)
            figure.Segments.Add(new LineSegment(new Point((history.Count - 1) * xStep, baseHeight), true));

            geometry.Figures.Add(figure);
            path.Data = geometry;
        }
    }

    public class TimelineItem
    {
        public string Title { get; set; }
        public DateTime Time { get; set; }
        public string Color { get; set; }
        public string TimeDisplay => Time.ToString("t") + ", " + Time.ToString("M");
        public Brush ColorBrush 
        {
            get 
            {
                try { return (Brush)new BrushConverter().ConvertFromString(Color); }
                catch { return Brushes.Gray; }
            }
        }
    }
}
