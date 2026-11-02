using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class PrivacyView : UserControl
    {


        public PrivacyView()
        {
            InitializeComponent();
            Loaded += PrivacyView_Loaded;
        }

        private async void PrivacyView_Loaded(object sender, RoutedEventArgs e)
        {
            await CheckStatusAsync();
        }

        private readonly string[] _vpnServices = { "RasMan", "IKEEXT", "PolicyAgent", "RemoteAccess" };

        private async Task CheckStatusAsync()
        {
             UpdateStatusText("Refreshing status...");

             // Run heavy checks in background
             var results = await Task.Run(() =>
             {
                 return new 
                 {
                     Vpn = CheckVpnStatus(),
                     Wifi = CheckWifiDirectStatus(),
                     Debug = CheckDebugStatus(),
                     Usage = IsUsageDataEnabled()
                 };
             });

             // Update UI on UI thread
             VpnToggle.IsChecked = results.Vpn;
             WifiDirectToggle.IsChecked = results.Wifi;
             DebugToggle.IsChecked = results.Debug;
             UsageDataToggle.IsChecked = results.Usage;

             // Start async check
             CheckTamperProtectionStatus();
             
             UpdateStatusText("Statuses refreshed.");
        }

        private async void CheckTamperProtectionStatus()
        {
            try
            {
                TamperProtectionText.Text = "Checking...";
                TamperProtectionText.Foreground = Brushes.Gray;

                await Task.Run(() =>
                {
                    string script = @"$tp = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -ErrorAction SilentlyContinue).TamperProtection; if ($tp -eq 1 -or $tp -eq 5) { 'ENABLED' } elseif ($tp -eq 0 -or $tp -eq 4) { 'DISABLED' } else { 'UNKNOWN' }";
                    
                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var p = Process.Start(psi))
                    {
                        string raw = p.StandardOutput.ReadToEnd().Trim();
                        p.WaitForExit();

                        string[] lines = raw.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        string result = lines.Length > 0 ? lines[lines.Length - 1].Trim() : "";

                        Dispatcher.Invoke(() =>
                        {
                            if (result == "ENABLED")
                            {
                                TamperProtectionText.Text = "Enabled";
                                TamperProtectionText.Foreground = Brushes.LimeGreen;
                            }
                            else if (result == "DISABLED")
                            {
                                TamperProtectionText.Text = "Disabled";
                                TamperProtectionText.Foreground = Brushes.Red;
                            }
                            else
                            {
                                TamperProtectionText.Text = "Unknown / Managed";
                                TamperProtectionText.Foreground = Brushes.Orange;
                            }
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                TamperProtectionText.Text = "Error";
                Debug.WriteLine($"TP Check Error: {ex.Message}");
            }
        }

        private void UpdateStatusText(string msg)
        {
            StatusDetailsText.Text = msg;
            StatusDetailsText.Foreground = Brushes.Cyan;
        }

        // --- VPN Logic ---
        private bool CheckVpnStatus()
        {
            try
            {
                // Simple logic: if any are running/enabled, it's ON
                foreach (var svcName in _vpnServices)
                {
                    using (var sc = new System.ServiceProcess.ServiceController(svcName))
                    {
                        if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped && sc.StartType != System.ServiceProcess.ServiceStartMode.Disabled)
                            return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private void VpnToggle_Click(object sender, RoutedEventArgs e)
        {
            bool enable = VpnToggle.IsChecked == true;
            try
            {
                string startType = enable ? "manual" : "disabled";
                foreach (var svcName in _vpnServices)
                {
                    RunCommand("sc.exe", $"config \"{svcName}\" start= {startType}");
                    
                    if (!enable)
                    {
                        using (var sc = new System.ServiceProcess.ServiceController(svcName))
                        {
                            if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped) sc.Stop();
                        }
                    }
                }
                UpdateStatusText($"VPN Services {(enable ? "Enabled" : "Disabled")}");
            }
            catch (Exception ex) 
            {
                MessageBox.Show($"Error toggling VPN: {ex.Message}");
                VpnToggle.IsChecked = !enable; // Revert
            }
        }

        // --- WiFi Direct Logic ---
        private bool CheckWifiDirectStatus()
        {
             // Simple fallback assumption: Unchecked by default if we don't have a perfect check
             // or check existence of adapter if previously implemented.
             // MainWindow implementation had this returning false or implementing simple check.
             return false; 
        }

        private void WifiDirectToggle_Click(object sender, RoutedEventArgs e)
        {
             bool enable = WifiDirectToggle.IsChecked == true;
             string cmd = enable ? "Enable-NetAdapter" : "Disable-NetAdapter";
             try
             {
                 RunCommand("powershell.exe", $"-Command \"{cmd} -Name '*Wi-Fi Direct*' -Confirm:$false\"");
                 UpdateStatusText($"WiFi Direct {(enable ? "Enabled" : "Disabled")}");
             }
             catch (Exception ex)
             {
                 MessageBox.Show($"Error: {ex.Message}");
                 WifiDirectToggle.IsChecked = !enable;
             }
        }

        // --- Debug Logic ---
        private bool CheckDebugStatus()
        {
             try
             {
                 var p = Process.Start(new ProcessStartInfo { FileName = "bcdedit.exe", Arguments = "/enum {current}", RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true });
                 string outStr = p.StandardOutput.ReadToEnd();
                 p.WaitForExit();
                 return outStr.Contains("debug                   Yes");
             }
             catch { return false; }
        }

        private void DebugToggle_Click(object sender, RoutedEventArgs e)
        {
             bool enable = DebugToggle.IsChecked == true;
             string state = enable ? "on" : "off";
             try
             {
                 RunCommand("bcdedit.exe", $"/set {{current}} debug {state}");
                 UpdateStatusText($"Kernel Debug {(enable ? "Enabled" : "Disabled")}");
             }
             catch (Exception ex)
             {
                  MessageBox.Show($"Error: {ex.Message}");
                  DebugToggle.IsChecked = !enable;
             }
        }

        // --- Usage Data Logic ---
        private bool IsUsageDataEnabled()
        {
             try
             {
                 var psi = new ProcessStartInfo 
                 { 
                     FileName = "powershell.exe", 
                     Arguments = "-Command \"(Get-ScheduledTask -TaskName 'UsageDataReceiver' -TaskPath '\\Microsoft\\Windows\\Flighting\\FeatureConfig\\').State\"", 
                     RedirectStandardOutput = true, 
                     UseShellExecute = false, 
                     CreateNoWindow = true 
                 };
                 using (var p = Process.Start(psi))
                 {
                     string outStr = p.StandardOutput.ReadToEnd();
                     p.WaitForExit();
                     return !string.IsNullOrWhiteSpace(outStr) && !outStr.Trim().Equals("Disabled", StringComparison.OrdinalIgnoreCase);
                 }
             }
             catch { return false; }
        }

        private void UsageDataToggle_Click(object sender, RoutedEventArgs e)
        {
             bool enable = UsageDataToggle.IsChecked == true;
             string cmd = enable ? "Enable-ScheduledTask" : "Disable-ScheduledTask";
             try
             {
                 RunCommand("powershell.exe", $"-Command \"{cmd} -TaskName 'UsageDataReceiver' -TaskPath '\\Microsoft\\Windows\\Flighting\\FeatureConfig\\'\"");
                 UpdateStatusText($"Usage Data {(enable ? "Enabled" : "Disabled")}");
             }
             catch (Exception ex)
             {
                  MessageBox.Show($"Error: {ex.Message}");
                  UsageDataToggle.IsChecked = !enable;
             }
        }
        
        private void RunCommand(string exe, string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using (var p = new Process { StartInfo = psi })
            {
                p.Start();
                p.WaitForExit();
            }
        }


    }
}
