using System.Windows.Controls;
using DeviceMonitorCS.Services;

namespace DeviceMonitorCS.Views
{
    public partial class ConsoleOutputView : UserControl
    {
        public ConsoleOutputView()
        {
            InitializeComponent();
            
            // Manual binding for thread safety simple text update or Direct DataContext
            this.DataContext = InspectionService.Instance;
            
            // Bind Text property
            var binding = new System.Windows.Data.Binding("LogText")
            {
                Source = InspectionService.Instance,
                Mode = System.Windows.Data.BindingMode.OneWay
            };
            ConsoleTextBox.SetBinding(TextBox.TextProperty, binding);
        }

        private void ConsoleTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ConsoleTextBox.ScrollToEnd();
        }

        private void ClearBtn_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            InspectionService.Instance.ClearLogs();
        }
    }
}
