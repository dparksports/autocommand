using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DeviceMonitorCS.Views
{
    public partial class TrueShutdownView : UserControl
    {
        public TrueShutdownView()
        {
            InitializeComponent();
            CheckHibernateStatus();
        }

        public void InitializeAndLoad()
        {
            CheckHibernateStatus();
        }

        private void CheckHibernateStatus()
        {
            try
            {
                // We'll check if hiberfil.sys exists or check powercfg status
                // A reliable way is to check the registry or run powercfg /a
                // For simplicity and robustness, let's just run powercfg /a and parse output
                
                string output = RunCommand("powercfg", "/a");
                if (output.ToLower().Contains("hibernation has not been enabled"))
                {
                    UpdateStatus(false);
                }
                else
                {
                    // It might say "Hibernation" is available
                    UpdateStatus(true);
                }
            }
            catch
            {
                HibernateStatusText.Text = "Error Checking Status";
                HibernateStatusText.Foreground = Brushes.Red;
            }
        }

        private void UpdateStatus(bool isEnabled)
        {
            if (isEnabled)
            {
                HibernateStatusText.Text = "ENABLED (Hibernation File Active)";
                HibernateStatusText.Foreground = Brushes.LimeGreen;
                ToggleHibernateBtn.Content = "Disable Hibernation";
            }
            else
            {
                HibernateStatusText.Text = "DISABLED (Space Saved)";
                HibernateStatusText.Foreground = Brushes.Orange;
                ToggleHibernateBtn.Content = "Enable Hibernation";
            }
        }

        private void ToggleHibernateBtn_Click(object sender, RoutedEventArgs e)
        {
            string currentText = ToggleHibernateBtn.Content.ToString();
            string args = "";

            if (currentText.Contains("Disable"))
            {
                args = "/hibernate off";
            }
            else
            {
                args = "/hibernate on";
            }

            try
            {
                RunCommand("powercfg", args);
                // Wait a moment for system to apply
                System.Threading.Thread.Sleep(500);
                CheckHibernateStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to toggle hibernation: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void TrueShutdownBtn_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show("Are you sure you want to perform a True Shutdown?\n\nThis will close all apps and fully shut down the PC (No Fast Startup/Hibernation).", 
                                       "Confirm Shutdown", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            
            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    Process.Start(new ProcessStartInfo("shutdown", "/s /t 0") { CreateNoWindow = true, UseShellExecute = false });
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to shutdown: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string RunCommand(string fileName, string arguments)
        {
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return output;
        }
    }
}
