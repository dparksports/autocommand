using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace DeviceMonitorCS.Views
{
    public partial class ColdBootsView : UserControl
    {
        public ObservableCollection<BootEvent> Boots { get; set; } = new ObservableCollection<BootEvent>();
        
        // Configuration from original script
        static readonly int MaxSecondsDiff = 300; 
        static readonly DateTime StartTime = DateTime.Now.AddDays(-90);

        private bool _isInitialized = false;

        public ColdBootsView()
        {
            InitializeComponent();
            BootsGrid.ItemsSource = Boots;
            CheckHibernateStatus();
            
            // Lazy load - removing direct LoadBoots call in constructor
            // Loaded += async (s, e) => await LoadBoots(); 
        }

        public async void InitializeAndLoad()
        {
            CheckHibernateStatus();
            if (_isInitialized) return;
            _isInitialized = true;
            await LoadBoots();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            await LoadBoots();
            CheckHibernateStatus();
        }

        private async Task LoadBoots()
        {
            Mouse.OverrideCursor = Cursors.Wait;
            Boots.Clear();
            
            try
            {
                await Task.Run(() =>
                {
                    // 1. Query System Log
                    var sysEvents = QueryLog("System", new[] { 12, 6006, 1074 });

                    // 2. Query Security Log
                    List<SimpleEvent> secEvents = new List<SimpleEvent>();
                    try
                    {
                        secEvents = QueryLog("Security", new[] { 4608, 4609 });
                    }
                    catch (EventLogException)
                    {
                        // Access Denied or other error - ignore for now or log
                        // In a real app we might want to show a warning
                        Dispatcher.Invoke(() => 
                        {
                            // Optional: Show warning or just log to console
                        });
                    }

                    // 3. Process Logic
                    var boots = sysEvents
                        .Where(e => e.Id == 12 && e.Provider == "Microsoft-Windows-Kernel-General")
                        .OrderBy(e => e.TimeCreated)
                        .ToList();

                    var all4608s = secEvents
                        .Where(e => e.Id == 4608)
                        .OrderBy(e => e.TimeCreated)
                        .ToList();

                    var allShutdowns = sysEvents.Concat(secEvents)
                        .Where(e => e.Id == 6006 || e.Id == 1074 || e.Id == 4609)
                        .OrderBy(e => e.TimeCreated)
                        .ToList();

                    var resultList = new List<BootEvent>();

                    for (int i = 0; i < boots.Count; i++)
                    {
                        var boot = boots[i];
                        DateTime bootTime = boot.TimeCreated;

                        // --- BINARY SEARCH 4608 ---
                        var matched4608 = FindNearestEvent(bootTime, all4608s);
                        string sec4608Str = "---";

                        if (matched4608 != null)
                        {
                            double diff = (matched4608.TimeCreated - bootTime).TotalSeconds;
                            if (Math.Abs(diff) <= MaxSecondsDiff)
                            {
                                sec4608Str = $"{matched4608.TimeCreated:HH:mm:ss} ({diff:+0;-0}s)";
                            }
                        }

                        DateTime nextBootTime = (i < boots.Count - 1) 
                            ? boots[i + 1].TimeCreated 
                            : DateTime.Now;

                        var shutdown = allShutdowns
                            .Where(e => e.TimeCreated > bootTime && e.TimeCreated < nextBootTime)
                            .LastOrDefault();

                        DateTime endTime;
                        string status;
                        string shutdownStr;

                        if (i < boots.Count - 1)
                        {
                            if (shutdown != null)
                            {
                                endTime = shutdown.TimeCreated;
                                status = "Clean";
                                shutdownStr = endTime.ToString("yyyy-MM-dd HH:mm:ss");
                            }
                            else
                            {
                                endTime = nextBootTime;
                                status = "Dirty/Crash";
                                shutdownStr = endTime.ToString("yyyy-MM-dd HH:mm:ss");
                            }
                        }
                        else
                        {
                            if (shutdown != null)
                            {
                                endTime = shutdown.TimeCreated;
                                status = "Clean (Ended)";
                                shutdownStr = endTime.ToString("yyyy-MM-dd HH:mm:ss");
                            }
                            else
                            {
                                endTime = DateTime.Now;
                                status = "Running";
                                shutdownStr = "---";
                            }
                        }

                        TimeSpan uptime = endTime - bootTime;
                        string uptimeStr = $"{uptime.Days:00}d {uptime.Hours:00}h {uptime.Minutes:00}m";

                        resultList.Add(new BootEvent
                        {
                            BootTime = bootTime,
                            ShutdownTimeStr = shutdownStr,
                            Status = status,
                            UptimeStr = uptimeStr,
                            Kg12Time = bootTime.ToString("HH:mm:ss"),
                            Sec4608Str = sec4608Str
                        });
                    }

                    // Reverse for UI (latest first)
                    resultList.Reverse();

                    Dispatcher.Invoke(() =>
                    {
                        foreach (var item in resultList)
                        {
                            Boots.Add(item);
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading boot history: {ex.Message}");
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        // --- Event Logic Helpers ---

        public class SimpleEvent
        {
            public DateTime TimeCreated { get; set; }
            public int Id { get; set; }
            public string Provider { get; set; }
        }

        public class BootEvent
        {
            public DateTime BootTime { get; set; }
            public string ShutdownTimeStr { get; set; }
            public string Status { get; set; }
            public string UptimeStr { get; set; }
            public string Kg12Time { get; set; }
            public string Sec4608Str { get; set; }
        }

        static List<SimpleEvent> QueryLog(string logName, int[] ids)
        {
            var results = new List<SimpleEvent>();
            
            string idQuery = string.Join(" or ", ids.Select(id => $"EventID={id}"));
            // Properly format timestamp for query
            string timeQuery = $"TimeCreated[@SystemTime>='{StartTime.ToUniversalTime():o}']";
            
            string queryString = $@"
                <QueryList>
                  <Query Id='0' Path='{logName}'>
                    <Select Path='{logName}'>*[System[({idQuery}) and {timeQuery}]]</Select>
                  </Query>
                </QueryList>";

            try 
            {
                var query = new EventLogQuery(logName, PathType.LogName, queryString);
                using (var reader = new EventLogReader(query))
                {
                    EventRecord eventInstance;
                    while ((eventInstance = reader.ReadEvent()) != null)
                    {
                        results.Add(new SimpleEvent
                        {
                            TimeCreated = eventInstance.TimeCreated ?? DateTime.MinValue,
                            Id = eventInstance.Id,
                            Provider = eventInstance.ProviderName
                        });
                    }
                }
            }
            catch (EventLogException)
            {
                throw; 
            }
            catch
            {
                // Silently ignore other errors for robustness
            }

            return results;
        }

        static SimpleEvent FindNearestEvent(DateTime target, List<SimpleEvent> sortedEvents)
        {
            if (sortedEvents == null || sortedEvents.Count == 0) return null;

            int left = 0;
            int right = sortedEvents.Count - 1;

            while (left <= right)
            {
                int mid = left + (right - left) / 2;
                if (sortedEvents[mid].TimeCreated == target) return sortedEvents[mid];
                
                if (sortedEvents[mid].TimeCreated < target)
                    left = mid + 1;
                else
                    right = mid - 1;
            }

            SimpleEvent c1 = (left < sortedEvents.Count) ? sortedEvents[left] : null;
            SimpleEvent c2 = (left - 1 >= 0) ? sortedEvents[left - 1] : null;

            double diff1 = (c1 != null) ? Math.Abs((c1.TimeCreated - target).TotalSeconds) : double.MaxValue;
            double diff2 = (c2 != null) ? Math.Abs((c2.TimeCreated - target).TotalSeconds) : double.MaxValue;

            return (diff1 < diff2) ? c1 : c2;
        }

        // --- Hibernation & Shutdown Logic (Ported) ---

        private void CheckHibernateStatus()
        {
            // Simple check using powercfg /a
            Task.Run(() => 
            {
                var output = RunCommand("powercfg", "/a");
                bool isEnabled = !output.ToLower().Contains("hibernation has not been enabled");
                
                Dispatcher.Invoke(() => 
                {
                    UpdateStatus(isEnabled);
                });
            });
        }

        private void UpdateStatus(bool isEnabled)
        {
             if (isEnabled)
            {
                HibernateStatusText.Text = "ENABLED";
                HibernateStatusText.Foreground = Brushes.LimeGreen;
                ToggleHibernateBtn.Content = "Disable Hibernation";
            }
            else
            {
                HibernateStatusText.Text = "DISABLED";
                HibernateStatusText.Foreground = Brushes.Orange;
                ToggleHibernateBtn.Content = "Enable Hibernation";
            }
        }

        private async void ToggleHibernateBtn_Click(object sender, RoutedEventArgs e)
        {
            string currentText = ToggleHibernateBtn.Content.ToString();
            string args = currentText.Contains("Disable") ? "/hibernate off" : "/hibernate on";

            try
            {
                await Task.Run(() => RunCommand("powercfg", args));
                // Wait a moment
                await Task.Delay(500);
                CheckHibernateStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to toggle hibernation: {ex.Message}");
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
                    MessageBox.Show($"Failed to shutdown: {ex.Message}");
                }
            }
        }

        private string RunCommand(string fileName, string arguments)
        {
            try 
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
            catch 
            {
                return "";
            }
        }
    }
}
