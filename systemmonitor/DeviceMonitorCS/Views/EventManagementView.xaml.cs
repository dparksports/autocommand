using System;
using System.Windows;
using System.Windows.Controls;

namespace DeviceMonitorCS.Views
{
    public partial class EventManagementView : UserControl
    {
        public EventManagementView()
        {
            InitializeComponent();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            // Bind to the collections in MainWindow
            if (Application.Current.MainWindow is MainWindow main)
            {
                SecurityGrid.ItemsSource = main.SecurityData;
                DeviceGrid.ItemsSource = main.DeviceData;
            }
        }
    }
}
