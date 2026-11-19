using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace AutoCommand.Light.Views
{
    public partial class SettingsView : UserControl
    {
        public SettingsView()
        {
            InitializeComponent();
            Loaded += (s, e) => RefreshState();
            LightGate.Changed += () => Dispatcher.BeginInvoke(new Action(RefreshState));
        }

        private void RefreshState()
        {
            if (LightGate.IsOpen)
            {
                GateStateText.Text = "The internet is open for everyone right now — temporary. " +
                    "The gate comes back on its own when the time ends.";
                OpenBtn.Visibility = Visibility.Collapsed;
                CloseBtn.Visibility = Visibility.Visible;
            }
            else
            {
                GateStateText.Text = "The gate is up: your browser talks, everything new asks first. " +
                    "If something ever breaks, you can open everything for ten minutes — it closes itself.";
                OpenBtn.Visibility = Visibility.Visible;
                CloseBtn.Visibility = Visibility.Collapsed;
            }
        }

        private async void OpenBtn_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(Window.GetWindow(this),
                "Open the internet for everyone for 10 minutes?\n\n" +
                "Every block pauses — Light's and the Advanced app's. Nothing is deleted, " +
                "and the gate comes back on its own when the ten minutes end.",
                "Open for everyone", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;
            OpenBtn.IsEnabled = false;
            try
            {
                await LightGate.OpenForEveryoneAsync(TimeSpan.FromMinutes(10));
                RefreshState();
            }
            finally { OpenBtn.IsEnabled = true; }
        }

        private async void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            CloseBtn.IsEnabled = false;
            try
            {
                await LightGate.CloseEveryoneAsync();
                RefreshState();
            }
            finally { CloseBtn.IsEnabled = true; }
        }

        private void OpenData_Click(object sender, RoutedEventArgs e) =>
            Process.Start("explorer.exe", LightServices.Root);
    }
}
