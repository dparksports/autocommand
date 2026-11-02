using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Xml.Linq;

namespace DeviceMonitorCS.Views
{
    public partial class DeviceManagementView : UserControl
    {
        public ObservableCollection<PnpDeviceInfo> ConnectedList { get; set; } = new ObservableCollection<PnpDeviceInfo>();
        public ObservableCollection<PnpDeviceInfo> DisconnectedList { get; set; } = new ObservableCollection<PnpDeviceInfo>();

        private bool _isInitialized = false;

        public DeviceManagementView()
        {
            InitializeComponent();
            ConnectedGrid.ItemsSource = ConnectedList;
            DisconnectedGrid.ItemsSource = DisconnectedList;
        }

        public async void InitializeAndLoad()
        {
            if (_isInitialized) return;
            _isInitialized = true;
            await RefreshDataAsync();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            // Handled by MainWindow via InitializeAndLoad
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            await RefreshDataAsync();
        }

        private async Task RefreshDataAsync()
        {
            if (RefreshBtn != null)
            {
                RefreshBtn.IsEnabled = false;
                RefreshBtn.Content = "Refreshing...";
            }
            
            try
            {
                var allDevices = await Task.Run(() => PnpDeviceReader.GetDevices(new[] { "Keyboard", "Mouse", "Monitor" }));
                
                ConnectedList.Clear();
                DisconnectedList.Clear();
                
                var connected = allDevices.Where(d => string.Equals(d.Status, "OK", StringComparison.OrdinalIgnoreCase)).ToList();
                foreach (var d in connected) ConnectedList.Add(d);

                var disconnected = allDevices.Where(d => !string.Equals(d.Status, "OK", StringComparison.OrdinalIgnoreCase)).ToList();
                foreach (var d in disconnected) DisconnectedList.Add(d);
                
                if (ConnectedCountText != null) ConnectedCountText.Text = $"({ConnectedList.Count})";
                if (DisconnectedCountText != null) DisconnectedCountText.Text = $"({DisconnectedList.Count})";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error refreshing devices: {ex.Message}", "Device Management Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (RefreshBtn != null)
                {
                    RefreshBtn.IsEnabled = true;
                    RefreshBtn.Content = "Refresh Devices";
                }
            }
        }
    }

    public class PnpDeviceInfo
    {
        public string Class { get; set; }
        public string Status { get; set; }
        public string FriendlyName { get; set; }
        public string InstanceId { get; set; }
        public DateTime? LastStarted { get; set; }
        public DateTime? LastConfigured { get; set; }
        public string OtherEvents { get; set; }
    }

    public static class PnpDeviceReader
    {
        public static List<PnpDeviceInfo> GetDevices(string[] classes)
        {
            var results = new List<PnpDeviceInfo>();
            try 
            {
                string classList = string.Join(",", classes.Select(c => $"'{c}'"));
                string script = $@"
                    $env:PSModulePath = $env:PSModulePath + ';C:\Windows\System32\WindowsPowerShell\v1.0\Modules';
                    Import-Module PnpDevice -SkipEditionCheck -ErrorAction SilentlyContinue;
                    $devices = Get-PnpDevice -Class {classList} -ErrorAction SilentlyContinue | 
                               Select-Object Class, Status, FriendlyName, InstanceId;
                    if ($devices) {{ $devices | ConvertTo-Json -Compress }} else {{ '[]' }}
                ";

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        using (var doc = JsonDocument.Parse(output))
                        {
                            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                            {
                                results = JsonSerializer.Deserialize<List<PnpDeviceInfo>>(output, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            }
                            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                            {
                                var single = JsonSerializer.Deserialize<PnpDeviceInfo>(output, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                                if (single != null) results.Add(single);
                            }
                        }
                    }
                }
                
                EnrichWithEventLogs(results);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"PnpDeviceReader Error: {ex.Message}");
            }
            return results;
        }

        private static void EnrichWithEventLogs(List<PnpDeviceInfo> devices)
        {
            try
            {
                // Robust Match: Query last 1000 events and index them by InstanceId
                var eventMap = new Dictionary<string, (DateTime? started, DateTime? configured)>(StringComparer.OrdinalIgnoreCase);

                string query = "*[System[(EventID=400 or EventID=410)]]";
                var eventsQuery = new EventLogQuery("Microsoft-Windows-Kernel-PnP/Configuration", PathType.LogName, query)
                {
                    ReverseDirection = true
                };

                using (var reader = new EventLogReader(eventsQuery))
                {
                    int processed = 0;
                    EventRecord ev;
                    while ((ev = reader.ReadEvent()) != null && processed++ < 1000)
                    {
                        try
                        {
                            string xml = ev.ToXml();
                            var x = XElement.Parse(xml);
                            
                            // Find DeviceInstanceID in UserData/EventData
                            string instanceId = x.Descendants().FirstOrDefault(n => n.Name.LocalName == "DeviceInstanceID")?.Value?.Trim();
                            if (string.IsNullOrEmpty(instanceId))
                            {
                                // Fallback: Check for 'InstanceId' or 'DeviceId' in generic Data elements
                                instanceId = x.Descendants().Where(n => n.Name.LocalName == "Data")
                                              .FirstOrDefault(d => (string)d.Attribute("Name") == "DeviceInstanceId" || (string)d.Attribute("Name") == "InstanceId" )?.Value?.Trim();
                            }

                            if (!string.IsNullOrEmpty(instanceId))
                            {
                                if (!eventMap.TryGetValue(instanceId, out var times)) times = (null, null);

                                if (ev.Id == 400 && times.started == null) times.started = ev.TimeCreated;
                                else if (ev.Id == 410 && times.configured == null) times.configured = ev.TimeCreated;

                                eventMap[instanceId] = times;
                            }
                        }
                        catch { }
                        finally { ev.Dispose(); }
                    }
                }

                // Apply to objects
                foreach (var device in devices)
                {
                    if (!string.IsNullOrEmpty(device.InstanceId) && eventMap.TryGetValue(device.InstanceId, out var times))
                    {
                        device.LastStarted = times.started;
                        device.LastConfigured = times.configured;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Event Log Enrichment Error: {ex.Message}");
            }
        }
    }
}
