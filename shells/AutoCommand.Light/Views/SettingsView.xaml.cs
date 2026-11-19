using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;

namespace AutoCommand.Light.Views
{
    public partial class SettingsView : UserControl
    {
        public SettingsView()
        {
            InitializeComponent();
        }

        private void BuildReport_Click(object sender, RoutedEventArgs e)
        {
            // The Overview view owns the report; navigating there with the
            // forced rebuild keeps exactly one composer in charge.
            (Application.Current.MainWindow as MainWindow)?.NavigateTo("overview");
            (Application.Current.MainWindow as MainWindow)?.OverviewTab.BeginReport();
        }

        private void OpenData_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("explorer.exe", LightServices.Root);
        }
    }
}
