using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Controls
{
    public partial class TimelineCanvas : UserControl
    {
        public event Action<TimelineEvent> EventClicked;

        private List<TimelineEvent> _allEvents;
        private double _zoomLevel = 2.0; // Pixels per Minute (Default: 2px/min = 120px/hour)
        private DateTime _dayStart;

        // Visual Encodings
        private readonly SolidColorBrush BrushLogin = new SolidColorBrush(Color.FromRgb(33, 150, 243)); // #2196F3
        private readonly SolidColorBrush BrushUSB = new SolidColorBrush(Color.FromRgb(255, 152, 0));   // #FF9800
        private readonly SolidColorBrush BrushDriver = new SolidColorBrush(Color.FromRgb(156, 39, 176)); // #9C27B0
        private readonly SolidColorBrush BrushSecurity = new SolidColorBrush(Color.FromRgb(244, 67, 54)); // #F44336
        private readonly SolidColorBrush BrushSoftware = new SolidColorBrush(Color.FromRgb(76, 175, 80));  // #4CAF50
        private readonly SolidColorBrush BrushStartup = new SolidColorBrush(Color.FromRgb(255, 235, 59));   // #FFEB3B
        private readonly SolidColorBrush BrushReboot = new SolidColorBrush(Color.FromRgb(33, 33, 33));      // #212121
        private readonly SolidColorBrush BrushDefault = Brushes.Gray;

        public TimelineCanvas()
        {
            InitializeComponent();
            MainScrollViewer.PreviewMouseWheel += MainScrollViewer_PreviewMouseWheel;
        }

        public void LoadEvents(List<TimelineEvent> events)
        {
            _allEvents = events ?? new List<TimelineEvent>();
            // Determine day start (assume single day view for now, or first event)
            if (_allEvents.Any())
            {
                _dayStart = _allEvents.Min(e => e.Timestamp).Date;
            }
            else
            {
                _dayStart = DateTime.Today;
            }

            Draw();
        }

        private void Draw()
        {
            DrawingCanvas.Children.Clear();
            DrawGridLines(); // Draw hours first

            if (_allEvents == null || !_allEvents.Any()) return;

            // Coordinate System
            // X = (Time - DayStart).TotalMinutes * ZoomLevel
            // Canvas Width = 24 * 60 * ZoomLevel

            double dayWidth = 24 * 60 * _zoomLevel;
            DrawingCanvas.Width = Math.Max(ActualWidth, dayWidth + 100);

            // Group by approximate location for clustering (Collision Detection can go here)
            // For now, draw everything to prove visual encoding.
            
            // Lanes Logic: Distribute vertical position to avoid overlap if possible, or use fixed lanes
            // Lane 0: System/Boot (Top) - Y=20
            // Lane 1: Security/Login - Y=60
            // Lane 2: Software/Driver - Y=100
            // Lane 3: Network/Other - Y=140

            foreach (var evt in _allEvents)
            {
                double x = (evt.Timestamp - _dayStart).TotalMinutes * _zoomLevel;
                double y = GetLaneY(evt);
                
                var shape = CreateDetailedShape(evt);
                Canvas.SetLeft(shape, x);
                Canvas.SetTop(shape, y);
                
                DrawingCanvas.Children.Add(shape);
            }
        }

        private void DrawGridLines()
        {
            double dayWidth = 24 * 60 * _zoomLevel;
            DrawingCanvas.Width = Math.Max(ActualWidth, dayWidth + 100);
            
            // Draw Hours
            for (int i = 0; i <= 24; i++)
            {
                double x = i * 60 * _zoomLevel;
                
                // Line
                var line = new Line
                {
                    X1 = x, Y1 = 0,
                    X2 = x, Y2 = DrawingCanvas.Height,
                    Stroke = Brushes.DimGray,
                    StrokeThickness = 1,
                    StrokeDashArray = new DoubleCollection { 2, 4 }
                };
                DrawingCanvas.Children.Add(line);

                // Label
                var label = new TextBlock
                {
                    Text = $"{i:00}:00",
                    Foreground = Brushes.Gray,
                    FontSize = 10
                };
                Canvas.SetLeft(label, x + 5);
                Canvas.SetTop(label, 5);
                DrawingCanvas.Children.Add(label);
            }
        }

        private double GetLaneY(TimelineEvent evt)
        {
            string cat = evt.Category;
            if (evt.EventId == 1074 || evt.EventId >= 6005 && evt.EventId <= 6008) return 50; // Boot/Reboot
            if (cat.Contains("Login") || cat.Contains("User")) return 100;
            if (cat.Contains("Security") || cat.Contains("Firewall")) return 150;
            if (cat.Contains("Install") || cat.Contains("Software")) return 200;
            if (cat.Contains("Driver") || cat.Contains("PnP")) return 250;
            if (cat.Contains("Defender")) return 300;
            return 350; // Other
        }

        private Shape CreateDetailedShape(TimelineEvent evt)
        {
            Shape shape;
            double size = 14; 

            // Shape Logic
            if (evt.EventId == 4625 || evt.Category.Contains("Error")) // Triangle (Critical)
            {
                // Triangle pointing up
                var poly = new Polygon();
                poly.Points = new PointCollection { new Point(0, size), new Point(size/2, 0), new Point(size, size) };
                shape = poly;
            }
            else if (evt.Category.Contains("Login")) // Circle (User Action)
            {
                shape = new Ellipse { Width = size, Height = size };
            }
            else if (evt.Category.Contains("Install") || evt.Category.Contains("System")) // Square (System)
            {
                shape = new Rectangle { Width = size, Height = size };
            }
            else 
            {
                // Diamond
                var poly = new Polygon();
                poly.Points = new PointCollection { new Point(size/2, 0), new Point(size, size/2), new Point(size/2, size), new Point(0, size/2) };
                shape = poly;
            }

            // Color Logic
            shape.Fill = GetColor(evt);
            shape.Stroke = Brushes.White;
            shape.StrokeThickness = 1;
            shape.Cursor = Cursors.Hand;
            shape.Tag = evt;
            shape.ToolTip = $"{evt.Timestamp:HH:mm:ss} - {evt.Category}\n{evt.Description.Substring(0, Math.Min(evt.Description.Length, 100))}...";

            return shape;
        }

        private Brush GetColor(TimelineEvent evt)
        {
            string cat = evt.Category;
            if (cat.Contains("Login")) return BrushLogin;
            if (cat.Contains("USB")) return BrushUSB;
            if (cat.Contains("Driver") || cat.Contains("PnP")) return BrushDriver;
            if (cat.Contains("Security") || cat.Contains("Firewall")) return BrushSecurity;
            if (cat.Contains("Install") || cat.Contains("Software")) return BrushSoftware;
            if (cat.Contains("Start") || cat.Contains("Boot")) return BrushStartup;
            if (cat.Contains("Reboot") || cat.Contains("Shutdown")) return BrushReboot;
            return BrushDefault;
        }

        private void DrawingCanvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (e.OriginalSource is Shape shape && shape.Tag is TimelineEvent evt)
            {
                EventClicked?.Invoke(evt);
            }
        }

        private void MainScrollViewer_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (Keyboard.Modifiers == ModifierKeys.Control)
            {
                // Semantic Zoom
                if (e.Delta > 0) _zoomLevel *= 1.1;
                else _zoomLevel /= 1.1;

                // Clamp
                if (_zoomLevel < 0.5) _zoomLevel = 0.5; // Compact
                if (_zoomLevel > 30) _zoomLevel = 30;   // High detail

                Draw(); // Redraw
                e.Handled = true;
            }
        }
        
        // Manual buttons
        private void ZoomInBtn_Click(object sender, RoutedEventArgs e)
        {
            _zoomLevel *= 1.25;
            Draw();
        }

        private void ZoomOutBtn_Click(object sender, RoutedEventArgs e)
        {
            _zoomLevel /= 1.25;
            Draw();
        }
    }
}
