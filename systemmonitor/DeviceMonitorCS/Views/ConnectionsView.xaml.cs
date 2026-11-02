using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class ConnectionsView : UserControl
    {
        private ConnectionMonitor _monitor;
        private DispatcherTimer _timer;

        public ConnectionsView()
        {
            InitializeComponent();
            _monitor = new ConnectionMonitor();

            ActiveGrid.ItemsSource = _monitor.ActiveConnections;
            HistoryGrid.ItemsSource = _monitor.HistoricalConnections;
            MutedGrid.ItemsSource = _monitor.DisplayMutedConnections;

            // Timer
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += (s, e) => { if (AutoRefreshToggle.IsChecked == true) _monitor.RefreshConnections(); };
            _timer.Start();

            // Initial Load
            _monitor.RefreshConnections();

            // Event Handlers
            RefreshBtn.Click += (s, e) => _monitor.RefreshConnections();
            ClearHistoryBtn.Click += (s, e) => { _monitor.ClearHistory(); MessageBox.Show("History cleared."); };
            
            // Context Menus
            MuteActiveCtx.Click += (s, e) => MuteSelected(ActiveGrid);
            MuteHistoryCtx.Click += (s, e) => MuteSelected(HistoryGrid);
            
            CopyActiveIpCtx.Click += (s, e) => CopyIp(ActiveGrid);
            CopyHistoryIpCtx.Click += (s, e) => CopyIp(HistoryGrid);

            UnmuteCtx.Click += (s, e) => UnmuteSelected();
            
            // Double click unmute
            MutedGrid.MouseDoubleClick += (s, e) => UnmuteSelected();
            
            this.Unloaded += (s, e) => { _timer.Stop(); _monitor.SavePersistence(); };
            this.Loaded += (s, e) => { _timer.Start(); };
        }

        private void MuteSelected(DataGrid grid)
        {
            if (grid.SelectedItem is ConnectionItem item)
            {
                var res = MessageBox.Show($"Mute all contributions from {item.RemoteAddress}?", "Confirm Mute", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (res == MessageBoxResult.Yes)
                {
                    _monitor.MuteConnection(item);
                    _monitor.RefreshConnections(); 
                }
            }
        }

        private void UnmuteSelected()
        {
            if (MutedGrid.SelectedItem is ConnectionItem item)
            {
                 _monitor.UnmuteConnection(item.RemoteAddress);
                 _monitor.RefreshConnections();
            }
        }

        private void CopyIp(DataGrid grid)
        {
             if (grid.SelectedItem is ConnectionItem item)
             {
                 Clipboard.SetText(item.RemoteAddress);
             }
        }

        private void AskAi_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as System.Windows.Controls.MenuItem;
            var contextMenu = menuItem.Parent as System.Windows.Controls.ContextMenu;
            // Handle both DataGrid and ListBox
            object selectedItem = null;

            if (contextMenu.PlacementTarget is DataGrid grid) selectedItem = grid.SelectedItem;
            else if (contextMenu.PlacementTarget is ListBox list) selectedItem = list.SelectedItem;

            if (selectedItem != null)
            {
                var window = new AskAiWindow(selectedItem);
                window.Owner = Window.GetWindow(this);
                window.ShowDialog();
            }
        }
    }
}
