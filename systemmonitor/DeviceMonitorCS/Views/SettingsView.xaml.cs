using System;
using System.Windows.Controls;

namespace DeviceMonitorCS.Views
{
    public partial class SettingsView : UserControl
    {
        public event Action<int> IntervalChanged;
        public event Action ClearLogsRequested;

        public SettingsView()
        {
            InitializeComponent();
            
            // Sync UI with Service
            AnalyticsToggle.IsChecked = Services.AnalyticsService.Instance.IsAnalyticsEnabled;
            ExpertModeToggle.IsChecked = Services.SettingsManager.Instance.IsExpertMode;
            RemediationDebugToggle.IsChecked = Services.SettingsManager.Instance.IsRemediationDebug;
            AppVersionText.Text = "v" + typeof(SettingsView).Assembly.GetName().Version.ToString(3);

            IntervalSlider.ValueChanged += (s, e) =>
            {
                int val = (int)e.NewValue;
                IntervalValueText.Text = $"{val} ms";
                IntervalChanged?.Invoke(val);
            };

            // Status Binding
            UpdateAnalyticsStatus(Services.AnalyticsService.Instance.TelemetryStatus);
            Services.AnalyticsService.Instance.StatusChanged += UpdateAnalyticsStatus;
        }

        private void UpdateAnalyticsStatus(string status)
        {
            Dispatcher.Invoke(() =>
            {
                AnalyticsStatusText.Text = $"Status: {status}";
                
                if (status == "Active") AnalyticsStatusText.Foreground = System.Windows.Media.Brushes.LightGreen;
                else if (status.Contains("Disabled")) AnalyticsStatusText.Foreground = System.Windows.Media.Brushes.Gray;
                else AnalyticsStatusText.Foreground = System.Windows.Media.Brushes.Red;
            });
        }
        
        private void AnalyticsToggle_Changed(object sender, System.Windows.RoutedEventArgs e)
        {
            Services.AnalyticsService.Instance.IsAnalyticsEnabled = AnalyticsToggle.IsChecked == true;
        }

        private void ExpertModeToggle_Changed(object sender, System.Windows.RoutedEventArgs e)
        {
            Services.SettingsManager.Instance.IsExpertMode = ExpertModeToggle.IsChecked == true;
        }

        private void RemediationDebugToggle_Changed(object sender, System.Windows.RoutedEventArgs e)
        {
            Services.SettingsManager.Instance.IsRemediationDebug = RemediationDebugToggle.IsChecked == true;
        }

        public void SetCurrentInterval(int interval)
        {
            IntervalSlider.Value = interval;
            IntervalValueText.Text = $"{interval} ms";
        }

        private void RunWizardBtn_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            var wizard = new SecurityAuditWizardView();
            wizard.ShowDialog();
        }
        private void InstallTaskBtn_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            try
            {
                string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                string taskName = "DeviceMonitorAutoStart";
                string command = $"/create /sc onlogon /tn \"{taskName}\" /tr \"'{exePath}'\" /rl highest /f";

                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = command,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(startInfo))
                {
                    process.WaitForExit();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    if (process.ExitCode == 0)
                    {
                        System.Windows.MessageBox.Show("Successfully installed to Scheduled Tasks!", "Success", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                    }
                    else
                    {
                        System.Windows.MessageBox.Show($"Failed to install task.\nError: {error}\nOutput: {output}", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                 System.Windows.MessageBox.Show($"An error occurred:\n{ex.Message}", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
        }
        private void UninstallTaskBtn_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            try
            {
                string taskName = "DeviceMonitorAutoStart";
                string command = $"/delete /tn \"{taskName}\" /f";

                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = command,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(startInfo))
                {
                    process.WaitForExit();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    if (process.ExitCode == 0)
                    {
                        System.Windows.MessageBox.Show("Successfully uninstalled from Scheduled Tasks.", "Success", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                    }
                    else
                    {
                        // Check if error is 'The specified task name was not found' (common case)
                        if (error.Contains("not found"))
                        {
                             System.Windows.MessageBox.Show("Task was not found. It might already be uninstalled.", "Info", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                        }
                        else
                        {
                             System.Windows.MessageBox.Show($"Failed to uninstall task.\nError: {error}\nOutput: {output}", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                 System.Windows.MessageBox.Show($"An error occurred:\n{ex.Message}", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
        }
        private void ClearLogsBtn_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            var result = System.Windows.MessageBox.Show("Are you sure you want to clear all monitoring logs?", "Confirm Clear", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question);
            if (result == System.Windows.MessageBoxResult.Yes)
            {
                ClearLogsRequested?.Invoke();
            }
        }
    }
}
