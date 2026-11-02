using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class OverviewView : UserControl
    {
        private ConnectionMonitor _connectionMonitor;
        private DispatcherTimer _refreshTimer;

        public event Action<string> NavigationRequested;

        public OverviewView()
        {
            InitializeComponent();
            _connectionMonitor = new ConnectionMonitor();
            
            // Setup auto-refresh timer (every 30 seconds)
            _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
            _refreshTimer.Tick += async (s, e) => await LoadAllDataAsync();
            
            this.Loaded += async (s, e) => 
            {
                await LoadAllDataAsync();
                _refreshTimer.Start();
            };
            this.Unloaded += (s, e) => _refreshTimer.Stop();
        }

        private void SecurityCard_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            NavigationRequested?.Invoke("SecureBoots");
        }

        /// <summary>
        /// Load all dashboard data asynchronously
        /// </summary>
        public async Task LoadAllDataAsync()
        {
            await Task.WhenAll(
                LoadRunningTasksAsync(),
                LoadActiveConnectionsAsync(),
                LoadDisconnectedDevicesAsync(),
                LoadColdBootsAsync(),
                LoadFirewallRulesAsync(),
                LoadPrivacySettingsAsync()
            );
        }

        #region Running Tasks (Only Running, with friendly descriptions)

        private async Task LoadRunningTasksAsync()
        {
            try
            {
                var tasks = await Task.Run(() =>
                {
                    var list = new List<RunningTaskItem>();
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = "/query /FO CSV /V",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        StandardOutputEncoding = System.Text.Encoding.UTF8
                    };

                    using (var process = Process.Start(startInfo))
                    {
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length > 1)
                        {
                            var headers = ParseCsvLine(lines[0]);
                            int idxTaskName = Array.IndexOf(headers, "TaskName");
                            int idxStatus = Array.IndexOf(headers, "Status");

                            if (idxTaskName == -1) idxTaskName = 0;

                            var addedTasks = new HashSet<string>();

                            for (int i = 1; i < lines.Length && list.Count < 10; i++)
                            {
                                var cols = ParseCsvLine(lines[i]);
                                if (cols.Length < 2) continue;

                                string taskName = GetCol(cols, idxTaskName);
                                if (taskName == headers[idxTaskName]) continue;

                                string tnClean = taskName.Trim('"');
                                if (addedTasks.Contains(tnClean)) continue;

                                string status = GetCol(cols, idxStatus);
                                // Only show RUNNING tasks
                                if (status == "Running")
                                {
                                    addedTasks.Add(tnClean);
                                    // Extract friendly description from task name
                                    string displayName = GetFriendlyTaskName(tnClean);
                                    list.Add(new RunningTaskItem { TaskName = tnClean, Description = displayName });
                                }
                            }
                        }
                    }
                    return list;
                });

                Dispatcher.Invoke(() =>
                {
                    TasksList.ItemsSource = tasks;
                    TasksCountText.Text = $"({tasks.Count})";
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading tasks: {ex.Message}");
            }
        }

        private string GetFriendlyTaskName(string fullTaskName)
        {
            // Extract just the leaf name
            string name = fullTaskName.Contains("\\") 
                ? fullTaskName.Substring(fullTaskName.LastIndexOf('\\') + 1) 
                : fullTaskName;
            
            // Create user-friendly descriptions for common tasks
            if (name.Contains("GoogleUpdate")) return "Google Update Service";
            if (name.Contains("MicrosoftEdgeUpdate")) return "Microsoft Edge Update";
            if (name.Contains("OneDrive")) return "OneDrive Sync";
            if (name.Contains("Defender")) return "Windows Defender Scan";
            if (name.Contains("SynchronizeTime")) return "Time Synchronization";
            if (name.Contains("Backup")) return "Backup Task";
            if (name.Contains("NGEN")) return ".NET Optimization";
            if (name.Contains("ScheduledDefrag")) return "Disk Defragmentation";
            if (name.Contains("SilentCleanup")) return "Disk Cleanup";
            if (name.Contains("Consolidator")) return "Telemetry Consolidation";
            if (name.Contains("DeviceMonitor") || name.Contains("AutoCommand")) return "Auto Command Monitor";
            
            // Remove common prefixes and make it readable
            name = name.Replace("TaskMachine", "")
                       .Replace("Core[", " (")
                       .Replace("]", ")")
                       .Replace("UA[", " Update (");
            
            // Add spaces before capital letters for camelCase names
            if (!name.Contains(" ") && name.Length > 3)
            {
                name = System.Text.RegularExpressions.Regex.Replace(name, "([a-z])([A-Z])", "$1 $2");
            }
            
            return name.Trim();
        }

        private string GetCol(string[] cols, int index) => index >= 0 && index < cols.Length ? cols[index] : "";
        private string[] ParseCsvLine(string line) => line.Split(new[] { "\",\"" }, StringSplitOptions.None).Select(s => s.Trim('"')).ToArray();

        #endregion

        #region Active Connections (Grouped by Process, Established only)

        private async Task LoadActiveConnectionsAsync()
        {
            try
            {
                await Task.Run(() => _connectionMonitor.RefreshConnections());
                
                Dispatcher.Invoke(() =>
                {
                    // Group by process name and count connections
                    var grouped = _connectionMonitor.ActiveConnections
                        .Where(c => c.State == "Established" || c.State == "ESTABLISHED")
                        .GroupBy(c => c.ProcessName ?? "Unknown")
                        .Select(g => new ConnectionGroup { ProcessName = g.Key, ConnectionCount = $"{g.Count()} conn" })
                        .OrderByDescending(g => int.TryParse(g.ConnectionCount.Split(' ')[0], out int n) ? n : 0)
                        .Take(10)
                        .ToList();
                    
                    ConnectionsList.ItemsSource = grouped;
                    ConnectionsCountText.Text = $"({grouped.Count} processes)";
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading connections: {ex.Message}");
            }
        }

        #endregion

        #region Disconnected Devices (Device Management)

        private async Task LoadDisconnectedDevicesAsync()
        {
            try
            {
                var devices = await Task.Run(() =>
                {
                    var list = new List<DisconnectedDevice>();
                    try
                    {
                        // Use PowerShell to get PnP devices like the main view does
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = "-NoProfile -Command \"Get-PnpDevice | Where-Object { $_.Status -ne 'OK' } | Select-Object -First 10 FriendlyName, Status\"",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd();
                            process.WaitForExit();

                            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var line in lines.Skip(2)) // Skip headers
                            {
                                var parts = System.Text.RegularExpressions.Regex.Split(line.Trim(), @"\s{2,}");
                                if (parts.Length >= 2)
                                {
                                    list.Add(new DisconnectedDevice 
                                    { 
                                        FriendlyName = parts[0], 
                                        Status = parts[1] 
                                    });
                                }
                            }
                        }
                    }
                    catch { }
                    return list;
                });

                Dispatcher.Invoke(() =>
                {
                    DevicesList.ItemsSource = devices;
                    DevicesCountText.Text = $"({devices.Count})";
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading devices: {ex.Message}");
            }
        }

        #endregion

        #region Cold Boots (Top 3 only)

        private async Task LoadColdBootsAsync()
        {
            try
            {
                var boots = await Task.Run(() =>
                {
                    var list = new List<BootEvent>();
                    try
                    {
                        // Use ID 12 (Kernel-General) for cold boots and 1074 for shutdowns
                        // We filter to ensure we get distinct events in history
                        var query = new EventLogQuery("System", PathType.LogName, "*[System[(EventID=12 or EventID=1074)]]");
                        query.ReverseDirection = true;
                        
                        using (var log = new EventLogReader(query))
                        {
                            EventRecord record;
                            int count = 0;
                            while ((record = log.ReadEvent()) != null && count < 3)
                            {
                                string status = record.Id == 12 ? "Cold Boot" : "System Shutdown";
                                string timeStr = record.TimeCreated?.ToString("MM/dd HH:mm:ss") ?? "";

                                list.Add(new BootEvent
                                {
                                    BootTime = timeStr,
                                    Status = status,
                                    Uptime = "" 
                                });
                                count++;
                            }
                        }
                    }
                    catch { }
                    return list;
                });

                Dispatcher.Invoke(() =>
                {
                    ShutdownsList.ItemsSource = boots;
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading cold boots: {ex.Message}");
            }
        }

        #endregion

        #region Firewall Rules (Group names, Active/Mixed only)

        private async Task LoadFirewallRulesAsync()
        {
            try
            {
                var rules = await Task.Run(() =>
                {
                    var inbound = new List<string>();
                    var outbound = new List<string>();
                    
                    try
                    {
                        // Get inbound rules. Only take those with a valid Group name, and ensure uniqueness.
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = "-NoProfile -Command \"Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.Group } | Select-Object -ExpandProperty Group -Unique | Select-Object -First 8\"",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd();
                            process.WaitForExit();
                            
                            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                string groupName = line.Trim();
                                if (string.IsNullOrEmpty(groupName)) continue;
                                inbound.Add(groupName.Length > 25 ? groupName.Substring(0, 22) + "..." : groupName);
                            }
                        }

                        // Get outbound rules. Only take those with a valid Group name, and ensure uniqueness.
                        startInfo.Arguments = "-NoProfile -Command \"Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow | Where-Object { $_.Group } | Select-Object -ExpandProperty Group -Unique | Select-Object -First 8\"";
                        
                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd();
                            process.WaitForExit();
                            
                            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                string groupName = line.Trim();
                                if (string.IsNullOrEmpty(groupName)) continue;
                                outbound.Add(groupName.Length > 25 ? groupName.Substring(0, 22) + "..." : groupName);
                            }
                        }
                    }
                    catch { }
                    
                    return (inbound, outbound);
                });

                // Create UI objects on UI thread
                Dispatcher.Invoke(() =>
                {
                    var greenBrush = new SolidColorBrush(Color.FromRgb(78, 201, 176));
                    
                    InboundRulesList.ItemsSource = rules.inbound.Select(name => new FirewallRuleGroup 
                    { 
                        GroupName = name, 
                        StatusColor = greenBrush 
                    }).ToList();
                    
                    OutboundRulesList.ItemsSource = rules.outbound.Select(name => new FirewallRuleGroup 
                    { 
                        GroupName = name, 
                        StatusColor = greenBrush 
                    }).ToList();
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading firewall rules: {ex.Message}");
            }
        } 

        #endregion

        #region Privacy Settings

        private async Task LoadPrivacySettingsAsync()
        {
            try
            {
                var status = await Task.Run(() =>
                {
                    var result = new PrivacySettingsInfo();

                    // 1. VPN Services (Matching PrivacyView check)
                    try
                    {
                        var vpnServices = new[] { "RasMan", "IKEEXT", "PolicyAgent", "RemoteAccess" };
                        bool vpnActive = false;
                        foreach (var svc in vpnServices)
                        {
                            using (var sc = new System.ServiceProcess.ServiceController(svc))
                            {
                                if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped) { vpnActive = true; break; }
                            }
                        }
                        result.VpnActive = vpnActive;
                        result.VpnStatus = vpnActive ? "Active" : "Protected";
                    }
                    catch { result.VpnStatus = "Unknown"; }

                    // 2. WiFi Direct
                    try
                    {
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = "-NoProfile -Command \"Get-NetAdapter | Where-Object { $_.Name -like '*Wi-Fi Direct*' } | Measure-Object | Select-Object -ExpandProperty Count\"",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd().Trim();
                            process.WaitForExit();
                            if (int.TryParse(output, out int count) && count > 0)
                            {
                                result.WifiActive = true;
                                result.WifiStatus = $"{count} Active";
                            }
                            else result.WifiStatus = "Inactive";
                        }
                    }
                    catch { result.WifiStatus = "Unknown"; }

                    // 3. Kernel Debug Mode (Matching PrivacyView check via BCD)
                    try
                    {
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "bcdedit.exe",
                            Arguments = "/enum {current}",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd();
                            process.WaitForExit();
                            result.DebugActive = output.Contains("debug               Yes");
                            result.DebugStatus = result.DebugActive ? "Enabled" : "Disabled";
                        }
                    }
                    catch { result.DebugStatus = "Unknown"; }

                    // 4. Usage Data (Telemetry Task)
                    try
                    {
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "schtasks.exe",
                            Arguments = "/query /TN \"\\Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataReceiver\" /FO CSV",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd();
                            process.WaitForExit();
                            result.UsageActive = output.Contains("Ready") || output.Contains("Running");
                            result.UsageStatus = result.UsageActive ? "Enabled" : "Disabled";
                        }
                    }
                    catch { result.UsageStatus = "Inactive"; }

                    return result;
                });

                Dispatcher.Invoke(() =>
                {
                    UpdatePrivacyIndicator(VpnDot, VpnStatus, status.VpnActive, status.VpnStatus);
                    UpdatePrivacyIndicator(WifiDot, WifiStatus, status.WifiActive, status.WifiStatus);
                    UpdatePrivacyIndicator(DebugDot, DebugStatus, status.DebugActive, status.DebugStatus, isCritical: true);
                    UpdatePrivacyIndicator(UsageDot, UsageStatus, status.UsageActive, status.UsageStatus);
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading privacy settings: {ex.Message}");
            }
        }

        private void UpdatePrivacyIndicator(System.Windows.Shapes.Ellipse dot, TextBlock text, bool active, string statusText, bool isCritical = false)
        {
            if (active)
            {
                // Amber if active (potential risk), Red if critical debug mode is on
                dot.Fill = isCritical ? new SolidColorBrush(Color.FromRgb(255, 107, 107)) : new SolidColorBrush(Color.FromRgb(255, 179, 71));
            }
            else
            {
                dot.Fill = new SolidColorBrush(Color.FromRgb(78, 201, 176)); // Green - safe
            }
            text.Text = statusText;
            text.Foreground = new SolidColorBrush(Color.FromRgb(136, 136, 136));
        }

        #endregion

        #region Status Updates (for external callers)

        public void UpdateLiveStatus(string status, string colorType)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = status;

                Brush targetBrush = (Brush)Application.Current.Resources["NeonGreenBrush"];
                Color targetColor = (Color)Application.Current.Resources["NeonGreen"];

                if (colorType == "Red")
                {
                    targetBrush = (Brush)Application.Current.Resources["NeonRedBrush"];
                    targetColor = (Color)Application.Current.Resources["NeonRed"];
                    NetworkText.Text = "Intervention";
                }
                else if (colorType == "Amber")
                {
                    targetBrush = (Brush)Application.Current.Resources["NeonAmberBrush"];
                    targetColor = (Color)Application.Current.Resources["NeonAmber"];
                    TaskText.Text = "Alert";
                }

                StatusText.Foreground = targetBrush;
                SecurityIcon.Foreground = targetBrush;
                SecurityGlow.Color = targetColor;

                if (colorType == "Red")
                {
                    NetworkIcon.Foreground = targetBrush;
                    NetworkGlow.Color = targetColor;
                    NetworkText.Foreground = targetBrush;
                }

                if (colorType == "Red")
                {
                    NetworkIcon.Foreground = targetBrush;
                    NetworkGlow.Color = targetColor;
                    NetworkText.Foreground = targetBrush;
                }

                // REMOVED: Auto-revert logic. The dashboard should reflect the actual persistent state.
                // Status will remain until explicitly changed by SecurityStatusViewModel or SecurityEnforcer.
            });
        }

        #endregion

        #region Helper Classes

        private class RunningTaskItem
        {
            public string TaskName { get; set; }
            public string Description { get; set; }
        }

        private class ConnectionGroup
        {
            public string ProcessName { get; set; }
            public string ConnectionCount { get; set; }
        }

        private class DisconnectedDevice
        {
            public string FriendlyName { get; set; }
            public string Status { get; set; }
        }

        private class BootEvent
        {
            public string BootTime { get; set; }
            public string Status { get; set; }
            public string Uptime { get; set; }
        }

        private class FirewallRuleGroup
        {
            public string GroupName { get; set; }
            public SolidColorBrush StatusColor { get; set; }
        }

        private class PrivacySettingsInfo
        {
            public bool VpnActive { get; set; }
            public string VpnStatus { get; set; } = "";
            public bool WifiActive { get; set; }
            public string WifiStatus { get; set; } = "";
            public bool DebugActive { get; set; }
            public string DebugStatus { get; set; } = "";
            public bool UsageActive { get; set; }
            public string UsageStatus { get; set; } = "";
        }

        #endregion
    }
}
