using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;

namespace DeviceMonitorCS.Services
{
    public class InspectionService : INotifyPropertyChanged
    {
        private static InspectionService _instance;
        public static InspectionService Instance => _instance ??= new InspectionService();

        private bool _isInspectModeEnabled;
        public bool IsInspectModeEnabled
        {
            get => _isInspectModeEnabled;
            private set { _isInspectModeEnabled = value; OnPropertyChanged(); OnPropertyChanged(nameof(ConsoleVisibility)); }
        }

        public Visibility ConsoleVisibility => IsInspectModeEnabled ? Visibility.Visible : Visibility.Collapsed;

        private StringBuilder _logBuilder = new StringBuilder();
        public string LogText 
        { 
            get => _logBuilder.ToString(); 
            private set { OnPropertyChanged(); } // Value set trigger not really used, just notification
        }

        public void SetInspectMode(bool enabled)
        {
            IsInspectModeEnabled = enabled;
            if (IsInspectModeEnabled)
            {
                Log("AGENCY PROTOCOL: ACTIVE");
            }
            else
            {
                Log("AGENCY PROTOCOL: STANDBY");
            }
        }

        public void Log(string message)
        {
            // Thread-safe append
            Application.Current.Dispatcher.Invoke(() =>
            {
                _logBuilder.AppendLine(message);
                OnPropertyChanged(nameof(LogText));
            });
        }

        public void ClearLogs()
        {
             _logBuilder.Clear();
             OnPropertyChanged(nameof(LogText));
        }

        public async Task ExecuteCommandAsync(string fileName, string arguments)
        {
            if (IsInspectModeEnabled)
            {
                Log($"\n[EXEC] {fileName} {arguments}");
                Log("------------------------------------------------");

                await Task.Run(() =>
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = fileName,
                            Arguments = arguments,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };

                        using (var p = Process.Start(psi))
                        {
                            if (p != null)
                            {
                                p.OutputDataReceived += (s, e) => { if (e.Data != null) Log(e.Data); };
                                p.ErrorDataReceived += (s, e) => { if (e.Data != null) Log("[STDERR] " + e.Data); };

                                p.BeginOutputReadLine();
                                p.BeginErrorReadLine();
                                p.WaitForExit();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"[ERROR] Execution failed: {ex.Message}");
                    }
                });
                Log("------------------------------------------------\n");
            }
            else
            {
                // Silent Execution
                await Task.Run(() =>
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = fileName,
                            Arguments = arguments,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        using (var p = Process.Start(psi))
                        {
                            p?.WaitForExit();
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Silent Exec Error: {ex.Message}");
                    }
                });
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
