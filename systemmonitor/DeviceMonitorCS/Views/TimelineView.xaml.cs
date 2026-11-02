using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeviceMonitorCS.Helpers;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class TimelineView : UserControl
    {
        private List<TimelineEvent> _loadedEvents;

        public TimelineView()
        {
            InitializeComponent();
            EventDatePicker.SelectedDate = DateTime.Today;
            MainTimelineCanvas.EventClicked += OnEventClicked;
            
            // Subscribe to filters
            TimelineFilterControl.FiltersChanged += OnFiltersChanged;
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            await LoadEvents();
        }

        private async Task LoadEvents()
        {
            try
            {
                StatusText.Text = "Loading events...";
                LoadingBar.Visibility = Visibility.Visible;
                RefreshBtn.IsEnabled = false;

                DateTime date = EventDatePicker.SelectedDate ?? DateTime.Today;

                _loadedEvents = await EventLogHelper.GetTimelineEventsAsync(date);
                
                ApplyFilters(); // Apply filters initially

                StatusText.Text = $"Loaded {_loadedEvents.Count} events.";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error loading events.";
                MessageBox.Show($"Error: {ex.Message}");
            }
            finally
            {
                LoadingBar.Visibility = Visibility.Collapsed;
                RefreshBtn.IsEnabled = true;
            }
        }
        
        private void OnFiltersChanged()
        {
            ApplyFilters();
        }

        private void ApplyFilters()
        {
            if (_loadedEvents == null) return;

            var selectedCats = TimelineFilterControl.GetSelectedCategories();
            var filtered = _loadedEvents.Where(ev => 
                selectedCats.Any(cat => ev.Category.Contains(cat)) || 
                (selectedCats.Contains("Defender") && ev.Source.Contains("Defender"))
            ).ToList();

            MainTimelineCanvas.LoadEvents(filtered);
            
            // Update Metrics
            MetricTotal.Text = filtered.Count.ToString();
            MetricErrors.Text = filtered.Count(ev => ev.Category.Contains("Error") || ev.EventId == 4625).ToString();
        }

        private void OnEventClicked(TimelineEvent evt)
        {
            // Populate Detail Panel
            DetailPanelContent.Children.Clear();

            // Time & Category
            var header = new TextBlock 
            { 
                Text = $"{evt.Timestamp:HH:mm:ss} - {evt.Category}", 
                FontSize = 16, 
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.Cyan,
                 Margin = new Thickness(0,0,0,10)
            };
            DetailPanelContent.Children.Add(header);

            // Properties
            AddDetailItem("Event ID", evt.EventId.ToString());
            AddDetailItem("Source", evt.Source);
            
            // Separator
             var sep = new Border { Height=1, Background=Brushes.Gray, Margin=new Thickness(0,10,0,10) };
             DetailPanelContent.Children.Add(sep);

            // Description
            var desc = new TextBlock 
            { 
                Text = evt.Description, 
                TextWrapping = TextWrapping.Wrap,
                Foreground = Brushes.LightGray,
                FontSize = 13,
                LineHeight = 20
            };
            DetailPanelContent.Children.Add(desc);
        }

        private void AddDetailItem(string label, string value)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0,2,0,2) };
            sp.Children.Add(new TextBlock { Text = label + ": ", FontWeight = FontWeights.Bold, Foreground = Brushes.Gray, Width = 80 });
            sp.Children.Add(new TextBlock { Text = value, Foreground = Brushes.White });
            DetailPanelContent.Children.Add(sp);
        }
    }
}
