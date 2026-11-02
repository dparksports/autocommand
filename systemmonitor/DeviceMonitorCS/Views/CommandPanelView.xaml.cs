using System;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeviceMonitorCS.Models;
using DeviceMonitorCS.Services;

namespace DeviceMonitorCS.Views
{
    public partial class CommandPanelView : UserControl
    {
        public ObservableCollection<NetworkAdapterItem> WanMiniports { get; set; } = new ObservableCollection<NetworkAdapterItem>();
        public ObservableCollection<NetworkAdapterItem> WifiDirectDevices { get; set; } = new ObservableCollection<NetworkAdapterItem>();
        public ObservableCollection<NetworkAdapterItem> KdnetDevices { get; set; } = new ObservableCollection<NetworkAdapterItem>();

        public CommandPanelView()
        {
            InitializeComponent();
            WanMiniportGrid.ItemsSource = WanMiniports;
            WifiDirectGrid.ItemsSource = WifiDirectDevices;
            KdnetGrid.ItemsSource = KdnetDevices;
            
            this.Loaded += (s, e) => RefreshData();
        }

        public void InitializeAndLoad()
        {
            RefreshData();
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshData();
            // Brief visual feedback that refresh happened
            var originalBackground = RefreshBtn.Background;
            RefreshBtn.Background = Brushes.Green;
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
            timer.Tick += (s, ev) => { RefreshBtn.Background = originalBackground; timer.Stop(); };
            timer.Start();
        }

        private void RefreshData()
        {
            LoadSstpStatus();
            LoadWanMiniports();
            LoadWifiDirectStatus();
            LoadWifiDirectDevices();
            LoadKdnetStatus();
            LoadKdnetDevices();
        }

        // --- Microsoft VPN Hole (SSTP) ---

        private void LoadSstpStatus()
        {
            try
            {
                using (ServiceController sc = new ServiceController("SstpSvc"))
                {
                    string status = sc.Status.ToString();
                    string startType = GetServiceStartType("SstpSvc");
                    
                    SstpStatusText.Text = $"Status: {status} | Startup: {startType}";

                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        SstpToggleBtn.Content = "Stop & Disable";
                        SstpToggleBtn.Background = new SolidColorBrush(Color.FromRgb(255, 107, 107)); // Red
                    }
                    else
                    {
                        SstpToggleBtn.Content = "Start & Enable";
                        SstpToggleBtn.Background = new SolidColorBrush(Color.FromRgb(0, 122, 204)); // Blue
                    }
                }
            }
            catch (Exception ex)
            {
                SstpStatusText.Text = "Error reading service";
                SstpToggleBtn.IsEnabled = false;
                Debug.WriteLine($"SSTP Error: {ex.Message}");
            }
        }

        private async void SstpToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                using (ServiceController sc = new ServiceController("SstpSvc"))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        // Stop and Disable
                        SecurityEnforcer.IsSstpAllowed = false; // Revoke Whitelist
                        
                        InspectionService.Instance.Log("AGENCY PROTOCOL: REVOKING SSTP AUTHORIZATION.");
                        await InspectionService.Instance.ExecuteCommandAsync("powershell.exe", "-Command \"Set-Service -Name SstpSvc -StartupType Disabled; Stop-Service -Name SstpSvc -Force\"");
                        
                        // Execute Removal
                        DeviceMonitorCS.Helpers.WanMiniportRemover.Execute();

                        // User Feedback for Stop Action
                        MessageBox.Show("Amending security hole... System Secured.", "Security Restored", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        // Enable and Start
                        
                        // Use Custom Dialog with Gemini Integration
                        var dialog = new DeviceMonitorCS.Views.SecurityWarningDialog();
                        dialog.ShowDialog();

                        if (dialog.Result == true)
                        {
                             SecurityEnforcer.IsSstpAllowed = true; // Grant Whitelist
                             InspectionService.Instance.Log("AGENCY PROTOCOL: AUTHORIZING SSTP EXCEPTION (USER OVERRIDE).");
                             
                             await InspectionService.Instance.ExecuteCommandAsync("powershell.exe", "-Command \"Set-Service -Name SstpSvc -StartupType Manual; Start-Service -Name SstpSvc\"");
                        }
                        else
                        {
                            return; // Abort
                        }
                    }
                }
                RefreshData();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error toggling service: {ex.Message}");
            }
        }

        private string GetServiceStartType(string serviceName)
        {
            try
            {
                using (ManagementObject service = new ManagementObject(new ManagementPath($"Win32_Service.Name='{serviceName}'")))
                {
                    return service["StartMode"]?.ToString();
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        private void LoadWanMiniports()
        {
            try
            {
                WanMiniports.Clear();
                // Query for WAN Miniports
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE 'WAN Miniport%'");
                var adapters = searcher.Get();

                foreach (ManagementObject obj in adapters)
                {
                    WanMiniports.Add(new NetworkAdapterItem
                    {
                        Name = obj["Name"]?.ToString(),
                        Description = obj["Description"]?.ToString(),
                        Status = obj["NetConnectionStatus"]?.ToString() ?? "Unknown", // 0=Disconnected, 2=Connected, etc.
                        InterfaceType = obj["AdapterType"]?.ToString(),
                        DeviceID = obj["PNPDeviceID"]?.ToString()
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading WAN Miniports: {ex.Message}");
            }
        }

        private void RunPowerShellCommand(string command, string actionName)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                using (var process = Process.Start(startInfo))
                {
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error executing command: {ex.Message}");
            }
        }

        // --- WiFi Direct Hole ---

        private void LoadWifiDirectStatus()
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show hostednetwork",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    bool isStarted = output.Contains("Status") && output.Contains("Started");
                    bool isAllowed = output.Contains("Mode") && output.Contains("Allow");

                    WifiDirectStatusText.Text = isStarted ? "Status: Started" : (isAllowed ? "Status: Stopped (Allowed)" : "Status: Disallowed");
                    
                    if (isStarted)
                    {
                        WifiDirectToggleBtn.Content = "Stop & Disable";
                        WifiDirectToggleBtn.Background = new SolidColorBrush(Color.FromRgb(255, 107, 107));
                    }
                    else
                    {
                        WifiDirectToggleBtn.Content = "Start & Enable";
                        WifiDirectToggleBtn.Background = new SolidColorBrush(Color.FromRgb(0, 122, 204));
                    }
                }
            }
            catch (Exception ex)
            {
                WifiDirectStatusText.Text = "Error reading status";
                Debug.WriteLine($"WiFi Direct Status Error: {ex.Message}");
            }
        }

        private void LoadWifiDirectDevices()
        {
            try
            {
                WifiDirectDevices.Clear();
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE '%Microsoft Wi-Fi Direct Virtual Adapter%'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    WifiDirectDevices.Add(new NetworkAdapterItem
                    {
                        Name = obj["Name"]?.ToString(),
                        Status = GetNetConnStatusString(obj["NetConnectionStatus"]?.ToString(), obj["ConfigManagerErrorCode"]?.ToString()),
                        DeviceID = obj["PNPDeviceID"]?.ToString()
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading WiFi Direct devices: {ex.Message}");
            }
        }

        private string GetNetConnStatusString(string code, string configErrorCode = null)
        {
            // If ConfigManagerErrorCode is 22, it's disabled.
            if (configErrorCode == "22") return "Disabled";

            if (string.IsNullOrEmpty(code)) return "Stale/Disabled";
            switch (code)
            {
                case "0": return "Disconnected";
                case "1": return "Connecting";
                case "2": return "Connected";
                case "3": return "Disconnecting";
                case "7": return "Media Disconnected";
                case "22": return "Disabled";
                default: return "Ready";
            }
        }

        private void WifiDirectToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string content = WifiDirectToggleBtn.Content.ToString();
                if (content.Contains("Stop"))
                {
                    // Stop, Disallow, Disable, and Uninstall
                    RunPowerShellCommand("netsh wlan stop hostednetwork; netsh wlan set hostednetwork mode=disallow", "Stop Hosted Network");
                    
                    // Disable and Uninstall Virtual Adapter
                    RunPowerShellCommand("Get-PnpDevice -FriendlyName '*Microsoft Wi-Fi Direct Virtual Adapter*' | Disable-PnpDevice -Confirm:$false", "Disable Virtual Adapter");
                    
                    // Native Uninstall
                    DeviceMonitorCS.Helpers.WanMiniportRemover.RemoveWifiDirect();
                }
                else
                {
                    // Allow and Start
                    RunPowerShellCommand("netsh wlan set hostednetwork mode=allow; netsh wlan start hostednetwork", "Start Hosted Network");
                }
                RefreshData();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error toggling WiFi Direct: {ex.Message}");
            }
        }

        private void InspectAgentToggle_Click(object sender, RoutedEventArgs e)
        {
            // Removed: Global Toggle Logic in MainWindow
        }

        private async void UninstallWifiBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Uninstall all WiFi Adapters (including physical)?\nWarning: This may disconnect your internet.", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
            {
                try
                {
                    // Search for WiFi adapters to uninstall
                    InspectionService.Instance.Log("AGENCY PROTOCOL: SCANNING FOR WIFI ADAPTERS...");
                    
                    var searcher = new ManagementObjectSearcher("SELECT PNPDeviceID, Name FROM Win32_NetworkAdapter WHERE AdapterType LIKE '%Wireless%' OR Name LIKE '%Wi-Fi%'");
                    var collection = searcher.Get();
                    
                    if (collection.Count == 0)
                    {
                        InspectionService.Instance.Log("SCAN RESULT: 0 TARGETS IDENTIFIED.");
                        InspectionService.Instance.Log("ACTION: ABORTING.");
                    }
                    else
                    {
                        InspectionService.Instance.Log($"SCAN RESULT: {collection.Count} POTENTIAL TARGET(S).");
                    
                        foreach (ManagementObject obj in collection)
                        {
                            string id = obj["PNPDeviceID"]?.ToString();
                            string name = obj["Name"]?.ToString();

                            if (!string.IsNullOrEmpty(id))
                            {
                                InspectionService.Instance.Log($"TARGET ACQUIRED: {name} ({id})");
                                
                                // Use Global Service
                                await InspectionService.Instance.ExecuteCommandAsync("pnputil.exe", $"/remove-device \"{id}\"");
                            }
                        }
                        RefreshData();
                        MessageBox.Show("WiFi Adapter removal attempt completed.", "Done");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}");
                }
            }
        }

        // --- Microsoft Kernel Debug Network Hole ---

        private void LoadKdnetStatus()
        {
            try
            {
                bool exists = false;
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%Kernel Debug Network%'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    exists = true;
                    break;
                }

                KdnetStatusText.Text = exists ? "Status: Device Exists" : "Status: Peripheral Not Found";
                
                if (exists)
                {
                    KdnetToggleBtn.Content = "Disable & Uninstall";
                    KdnetToggleBtn.Background = new SolidColorBrush(Color.FromRgb(255, 107, 107));
                }
                else
                {
                    KdnetToggleBtn.Content = "Enable (bcdedit)";
                    KdnetToggleBtn.Background = new SolidColorBrush(Color.FromRgb(0, 122, 204));
                }
            }
            catch (Exception ex)
            {
                KdnetStatusText.Text = "Error reading status";
                Debug.WriteLine($"KDNET Status Error: {ex.Message}");
            }
        }

        private void LoadKdnetDevices()
        {
            try
            {
                KdnetDevices.Clear();
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE '%Kernel Debug Network%'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    KdnetDevices.Add(new NetworkAdapterItem
                    {
                        Name = obj["Name"]?.ToString(),
                        Status = GetNetConnStatusString(obj["NetConnectionStatus"]?.ToString(), obj["ConfigManagerErrorCode"]?.ToString()),
                        DeviceID = obj["PNPDeviceID"]?.ToString()
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading KDNET devices: {ex.Message}");
            }
        }

        private void KdnetToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string content = KdnetToggleBtn.Content.ToString();
                if (content.Contains("Disable"))
                {
                    // Disable and Uninstall
                    RunPowerShellCommand("Get-PnpDevice -FriendlyName '*Kernel Debug Network*' | Disable-PnpDevice -Confirm:$false", "Disable KDNET");
                    
                    // Native Uninstall
                    DeviceMonitorCS.Helpers.WanMiniportRemover.RemoveKdnet();
                }
                else
                {
                    // Enable (usually requires bcdedit and reboot, but we'll try to trigger the command)
                    RunPowerShellCommand("bcdedit /set privatedbg yes; bcdedit /debug on", "Enable KDNET via BCD");
                    MessageBox.Show("KDNET enabled via BCD. A reboot may be required to see the adapter.", "Reboot Required", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                
                // Wait a moment for OS to reflect changes
                System.Threading.Thread.Sleep(500);
                RefreshData();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error toggling KDNET: {ex.Message}");
            }
        }
    }
}
