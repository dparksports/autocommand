using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DeviceMonitorCS.Views
{
    public partial class WindowsDefenderView : UserControl
    {
        public ObservableCollection<DefenderEventItem> DefenderEvents { get; set; } = new ObservableCollection<DefenderEventItem>();

        public WindowsDefenderView()
        {
            InitializeComponent();
            EventsGrid.ItemsSource = DefenderEvents; // Explicit binding if XAML context fails
            
            Loaded += (s, e) => 
            {
               RefreshData();
            };
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshData();
        }

        private async void RefreshData()
        {
            CheckTamperProtectionStatus();
            await LoadEventLog();
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
            catch 
            {
                 TamperProtectionText.Text = "Error";
                 TamperProtectionText.Foreground = Brushes.Red;
            }
        }

        private async Task LoadEventLog()
        {
            DefenderEvents.Clear();
            
            await Task.Run(() => 
            {
                try 
                {
                    // Scan: 1000, 1001, 1002, 1005
                    // Threat: 1006, 1116, 1117
                    // Update: 2000, 2002
                    // Critical: 3002, 5001
                    // Config/Tamper: 5007, 5013, 5014, 5015
                    string query = @"*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1005 or EventID=1006 or EventID=1116 or EventID=1117 or EventID=2000 or EventID=2002 or EventID=3002 or EventID=5001 or EventID=5007 or EventID=5013 or EventID=5014 or EventID=5015)]]";
                    
                    var elq = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, query) { ReverseDirection = true };
                    var reader = new EventLogReader(elq);

                    EventRecord eventInstance;
                    while ((eventInstance = reader.ReadEvent()) != null)
                    {
                        string msg = eventInstance.FormatDescription();
                        // Sometimes FormatDescription needs context, fallback to manual parsing if null?
                        // Usually fine for Defender logs.
                        
                        var item = new DefenderEventItem
                        {
                            Time = eventInstance.TimeCreated?.ToString("yyyy-MM-dd HH:mm:ss"),
                            Id = eventInstance.Id,
                            Message = msg
                        };

                        Dispatcher.Invoke(() => DefenderEvents.Add(item));
                        
                        if (DefenderEvents.Count > 200) break; // Limit 200
                    }
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => DefenderEvents.Add(new DefenderEventItem { Message = $"Error reading logs: {ex.Message}" }));
                }
            });
        }
    }

    public class DefenderEventItem
    {
        public string Time { get; set; }
        public int Id { get; set; }
        public string Message { get; set; }
    }
}
