using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows;
using System.Windows.Threading;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using DeviceMonitorCS.Helpers;
using DeviceMonitorCS.Models;
using DeviceMonitorCS.Services;
using System.Collections.Generic;
using System.Windows.Controls;
using System.Windows.Media;

namespace DeviceMonitorCS
{
    public partial class MainWindow : Window
    {
        public ObservableCollection<DeviceEvent> DeviceData { get; set; } = new ObservableCollection<DeviceEvent>();
        public ObservableCollection<SecurityEvent> SecurityData { get; set; } = new ObservableCollection<SecurityEvent>();
        
        // Hybrid Device Monitoring (Native + WMI)
        private string _currentUser;
        
        // Dedup Cache: "EventType|Name|Type" -> Timestamp
        private Dictionary<string, DateTime> _eventDedupCache = new Dictionary<string, DateTime>();
        private bool _isMinimized = false;

        // Called by BOTH Native WndProc and WMI Handler
        private void DispatchDeviceEvent(DeviceEvent newEvent)
        {
            Dispatcher.Invoke(() => 
            {
                // Simple Dedup: Check if same event (Name + Type + Action) occurred in last 2 seconds
                string key = $"{newEvent.EventType}|{newEvent.Name}|{newEvent.Type}";
                
                if (_eventDedupCache.TryGetValue(key, out DateTime lastTime))
                {
                    if ((DateTime.Now - lastTime).TotalSeconds < 2)
                    {
                        Debug.WriteLine($"Duplicate suppressed: {key}");
                        return; // Suppress duplicate
                    }
                }
                
                _eventDedupCache[key] = DateTime.Now;
                
                // Add to UI
                DeviceData.Insert(0, newEvent);
                if (DeviceData.Count > 100) DeviceData.RemoveAt(DeviceData.Count - 1);
                
                // Keep cache clean (remove old entries every 50 events)
                if (_eventDedupCache.Count > 50) _eventDedupCache.Clear();
            });
        }


        
        private SecurityEnforcer _enforcer;
        private PerformanceMonitor _perfMonitor;

        // private FirebaseTelemetryService _telemetryService; // Old
        private AuthenticationService _authService;

        private Dictionary<Type, UserControl> _viewCache = new Dictionary<Type, UserControl>();

        private void NavigateTo<T>() where T : UserControl
        {
            Type viewType = typeof(T);
            UserControl view;

            if (!_viewCache.TryGetValue(viewType, out view))
            {
                // Instantiate View
                view = (UserControl)Activator.CreateInstance(viewType);
                _viewCache[viewType] = view;

                // --- Wiring ---
                if (view is Views.SettingsView sv)
                {
                    sv.SetCurrentInterval(_enforcer.CheckInterval);
                    sv.IntervalChanged += (newInterval) => _enforcer.CheckInterval = newInterval;
                    sv.ClearLogsRequested += () => 
                    {
                        DeviceData.Clear();
                        SecurityData.Clear();
                    };
                }
                
                if (view is Views.DeviceManagementView dmv)
                {
                    // Optionally load data only once or every time?
                    // Original logic loaded every time.
                    // dmv.InitializeAndLoad(); Wiring to be safe to happen on load or similar.
                }
            }

            // Perform View-Specific "On Show" Logic
            if (view is Views.DashboardView dv)
            {
                 // Wire up navigation if not already wired (check for duplicates? event += handles it but need to avoid multiple subs)
                 // Best practice: unsubscribe then subscribe, or just ensure once. 
                 // Simple approach: Always unsub then sub.
                 dv.NavigationRequested -= OnDashboardNavRequested;
                 dv.NavigationRequested += OnDashboardNavRequested;
            }
            if (view is Views.OverviewView ov)
            {
                 _ = ov.LoadAllDataAsync();
            }
            if (view is Views.DeviceManagementView dmView)
            {
                dmView.InitializeAndLoad();
            }
            if (view is Views.FirewallSettingsView fsv)
            {
                fsv.InitializeAndLoad();
            }
            if (view is Views.ColdBootsView cbv)
            {
                cbv.InitializeAndLoad();
            }
            if (view is Views.CommandPanelView cpv)
            {
                cpv.InitializeAndLoad();
            }
            if (view is Views.TrueShutdownView tsv)
            {
                tsv.InitializeAndLoad();
            }

            // Set Content
            MainContentArea.Content = view;

            // Telemetry
            _ = Services.AnalyticsService.Instance.LogEventAsync("screen_view", new Dictionary<string, object>
            {
                { "screen_name", viewType.Name },
                { "screen_class", viewType.Name }
            });
            
            // Handle Side-Effects (like perf timer for PerfView)
            // Perf timer was running globally, checking visibility. 
            // We can simplify or keep it running but checking if Content is PerfView
        }

        private void NavDashboardBtn_Click(object sender, RoutedEventArgs e)
        {
            UpdateSelectedNavTag(NavDashboardBtn);
            NavigateTo<Views.DashboardView>();
        }

        private void NavSecurityBtn_Click(object sender, RoutedEventArgs e)
        {
            UpdateSelectedNavTag(NavSecurityBtn);
            NavigateTo<Views.SecurityMainView>();
        }

        private void NavDiagnosticsBtn_Click(object sender, RoutedEventArgs e)
        {
            UpdateSelectedNavTag(NavDiagnosticsBtn);
            NavigateTo<Views.DiagnosticsMainView>();
        }

        private void SettingsBtn_Click(object sender, RoutedEventArgs e)
        {
            UpdateSelectedNavTag(SettingsBtn);
            NavigateTo<Views.SettingsView>();
        }

        private void InspectAgentSidebarToggle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Primitives.ToggleButton toggle)
            {
                InspectionService.Instance.SetInspectMode(toggle.IsChecked == true);
            }
        }

        private void HamburgerBtn_Click(object sender, RoutedEventArgs e)
        {
            _isMinimized = !_isMinimized;
            
            // Toggle Width
            SidebarPane.Width = _isMinimized ? 80 : 120;
            
            // Toggle Label Visibility
            Visibility labelVis = _isMinimized ? Visibility.Collapsed : Visibility.Visible;
            LabelDashboard.Visibility = labelVis;
            LabelSecurity.Visibility = labelVis;
            LabelDiagnostics.Visibility = labelVis;
            LabelSettings.Visibility = labelVis;
            
            // Toggle Header/Footer extra elements
            SidebarHeader.Visibility = labelVis;

        }

        private void UpdateSelectedNavTag(Button selected)
        {
            NavDashboardBtn.Tag = null;
            NavSecurityBtn.Tag = null;
            NavDiagnosticsBtn.Tag = null;
            SettingsBtn.Tag = null;
            selected.Tag = "Selected";
        }

        private void OnDashboardNavRequested(string destination)
        {
            if (destination == "SecureBoots")
            {
                Dispatcher.Invoke(() => 
                {
                    UpdateSelectedNavTag(NavSecurityBtn);
                    NavigateTo<Views.SecurityMainView>();
                    
                    if (_viewCache.TryGetValue(typeof(Views.SecurityMainView), out var view) && view is Views.SecurityMainView smv)
                    {
                        smv.NavigateSub<Views.SecureBootsView>();
                    }
                });
            }
        }

        public MainWindow()
        {
            InitializeComponent();
            
            _authService = new AuthenticationService();
            // _analyticsService = new AnalyticsService(_authService); // Now Singleton

            // Privacy Consent Check
            // Privacy Consent Check Removed (Moved to App.xaml.cs)
            Loaded += async (s, e) =>
            {
                await Services.AnalyticsService.Instance.LogEventAsync("app_start", new { app_version = "3.12.0" });
            };

            // _telemetryService = new FirebaseTelemetryService();
            // _ = _telemetryService.SendEventAsync("app_start", new Dictionary<string, object> 
            // { 
            //    { "app_version", "3.9.2" }
            // });


            this.AddHandler(Button.ClickEvent, new RoutedEventHandler(Global_ButtonClick));

            // FAST Identity retrieval
            _currentUser = WindowsIdentity.GetCurrent().Name;
            Title = $"Auto Command (Administrator) - User: {_currentUser}";
            
            // Defer heavy initializations to background threads to keep UI instant
            Task.Run(() => 
            {
                Dispatcher.Invoke(() => 
                {
                    StartSecurityMonitoring();
                    
                    _enforcer = new SecurityEnforcer(HandleThreatDetected); // existing
                    _enforcer.StatusChanged += (status, color) => 
                    {
                         Dispatcher.Invoke(() => 
                         {
                             if (_viewCache.TryGetValue(typeof(Views.OverviewView), out var view))
                             {
                                 ((Views.OverviewView)view).UpdateLiveStatus(status, color);
                             }
                             // Update Unified ViewModel
                             ViewModels.SecurityStatusViewModel.Instance.UpdateStatus(status, color);
                         });
                    };
                    
                    _enforcer.ConfigurationDriftDetected += (driftItems) => Dispatcher.Invoke(() => HandleFirewallDrift(driftItems));
                    _enforcer.Start();

                    // --- SECURE BOOT MONITORING ---
                    // --- SECURE BOOT MONITORING ---
                    UefiService.Instance.UefiChanged += (s, args) =>
                    {
                        Dispatcher.Invoke(() =>
                        {
                            string msg = "";
                            if (args.NewDbEntries.Count > 0) msg += $"{args.NewDbEntries.Count} new allowed signature(s) detected.\n";
                            if (args.DbCountDifference != 0) msg += $"Allowed signature list changed ({args.DbCountDifference:+0;-0} entries).\n";
                            if (args.DbxCountDifference != 0) msg += $"Revocation list changed ({args.DbxCountDifference:+0;-0} entries).";

                            // 1. Toast
                            Services.ToastNotificationService.Instance.ShowToast("UEFI Secure Boot Change", msg.Trim());

                            // 2. Global Log
                            SecurityData.Insert(0, new SecurityEvent
                            {
                                Time = DateTime.Now.ToString("HH:mm:ss"),
                                Activity = "UEFI Policy Change",
                                Type = msg.Replace("\n", " "),
                                Account = "System Firmware",
                                Id = 8007
                            });

                            // 3. Dashboard Timeline (if active)
                            if (_viewCache.TryGetValue(typeof(Views.DashboardView), out var dbView))
                            {
                                var dashboard = (Views.DashboardView)dbView;
                                dashboard.RecentEvents.Insert(0, new Views.TimelineItem 
                                { 
                                    Title = "Secure Boot Policy Changed", 
                                    Time = DateTime.Now, 
                                    Color = "#FFAE00" 
                                });
                            }
                        });
                    };
                    
                    // BlackLotus Vulnerability Check (CVE-2022-21894)
                    bool isPatched = UefiService.Instance.IsBlackLotusMitigated();
                    Dispatcher.Invoke(() => {
                        if (isPatched)
                        {
                             SecurityData.Insert(0, new SecurityEvent { 
                                 Time = DateTime.Now.ToString("HH:mm:ss"), 
                                 Activity = "Vulnerability Scan", 
                                 Type = "System is PATCHED against BlackLotus (CVE-2022-21894).", 
                                 Account = "System Firmware", 
                                 Id = 8008 
                            });
                        }
                        else
                        {
                             string warning = "Hash 459458... not found in DBX.\nSystem may be vulnerable to CVE-2022-21894 (BlackLotus/Baton Drop).";
                             
                             SecurityData.Insert(0, new SecurityEvent { 
                                 Time = DateTime.Now.ToString("HH:mm:ss"), 
                                 Activity = "Vulnerability Detected", 
                                 Type = warning.Replace("\n", " "), 
                                 Account = "System Firmware", 
                                 Id = 8009 
                            });

                             Services.ToastNotificationService.Instance.ShowToast("Security Warning: BlackLotus", warning);
                        }
                    });

                    _ = UefiService.Instance.CheckForChangesAsync();
                    // ------------------------------
                    // ------------------------------

                    _perfMonitor = new PerformanceMonitor();
                    var perfTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                    perfTimer.Tick += (s, e) => 
                    {
                        if (MainContentArea.Content is Views.DiagnosticsMainView dmv && dmv.SubContentArea.Content is Views.PerformanceView pv)
                        {
                             pv.UpdateMetrics(_perfMonitor.GetMetrics());
                        }
                    };
                    perfTimer.Start();
                    
                    NavigateTo<Views.DashboardView>();
                });
            });

            // Navigation Wiring
            NavDashboardBtn.Click += NavDashboardBtn_Click;
            NavSecurityBtn.Click += NavSecurityBtn_Click;
            NavDiagnosticsBtn.Click += NavDiagnosticsBtn_Click;
            SettingsBtn.Click += SettingsBtn_Click;
            
            Closed += MainWindow_Closed;
        }

        private void Global_ButtonClick(object sender, RoutedEventArgs e)
        {
            try
            {
                if (e.OriginalSource is Button btn)
                {
                    string btnName = btn.Name;
                    string btnContent = btn.Content?.ToString() ?? "Icon/Image";
                    
                    if (string.IsNullOrEmpty(btnName)) btnName = "UnnamedButton";

                    _ = Services.AnalyticsService.Instance.LogEventAsync("ui_interaction", new Dictionary<string, object>
                    {
                        { "element_type", "button" },
                        { "element_name", btnName },
                        { "element_content", btnContent }
                    });
                }
            }
            catch { }
        }

        // Native Device Notification
        private DeviceGuidManager _guidManager = new DeviceGuidManager();
        
        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            var source = PresentationSource.FromVisual(this) as HwndSource;
            source?.AddHook(WndProc);
            ConnectDeviceWatcher(source?.Handle ?? IntPtr.Zero);
        }

        private void ConnectDeviceWatcher(IntPtr windowHandle)
        {
            try
            {
                foreach (var guid in _guidManager.GetAllGuids())
                {
                    var dbi = new NativeMethods.DEV_BROADCAST_DEVICEINTERFACE();
                    dbi.dbcc_size = Marshal.SizeOf(dbi);
                    dbi.dbcc_devicetype = NativeMethods.DBT_DEVTYP_DEVICEINTERFACE;
                    dbi.dbcc_classguid = guid;

                    IntPtr buffer = Marshal.AllocHGlobal(dbi.dbcc_size);
                    Marshal.StructureToPtr(dbi, buffer, true);

                    IntPtr handle = NativeMethods.RegisterDeviceNotification(windowHandle, buffer, 0);
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Device Watcher Warning: {ex.Message}");
            }
        }
        
        private void RegisterNewGuid(Guid guid)
        {
             try
             {
                var source = PresentationSource.FromVisual(this) as HwndSource;
                if (source == null) return;

                var dbi = new NativeMethods.DEV_BROADCAST_DEVICEINTERFACE();
                dbi.dbcc_size = Marshal.SizeOf(dbi);
                dbi.dbcc_devicetype = NativeMethods.DBT_DEVTYP_DEVICEINTERFACE;
                dbi.dbcc_classguid = guid;

                IntPtr buffer = Marshal.AllocHGlobal(dbi.dbcc_size);
                Marshal.StructureToPtr(dbi, buffer, true);

                NativeMethods.RegisterDeviceNotification(source.Handle, buffer, 0);
                Marshal.FreeHGlobal(buffer);
             }
             catch { }
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == NativeMethods.WM_DEVICECHANGE)
            {
                 int nEventType = wParam.ToInt32();
                 if (nEventType == NativeMethods.DBT_DEVICEARRIVAL || nEventType == NativeMethods.DBT_DEVICEREMOVECOMPLETE)
                 {
                     string action = nEventType == NativeMethods.DBT_DEVICEARRIVAL ? "ADDED" : "REMOVED";
                     
                     var hdr = Marshal.PtrToStructure<NativeMethods.DEV_BROADCAST_HDR>(lParam);
                     if (hdr.dbch_devicetype == NativeMethods.DBT_DEVTYP_DEVICEINTERFACE)
                     {
                         var dev = Marshal.PtrToStructure<NativeMethods.DEV_BROADCAST_DEVICEINTERFACE>(lParam);
                         string name = dev.dbcc_name; // Usually \\?\USB#VID_xxxx...
                         
                         // Clean up name for display
                         name = ParseDeviceName(name);

                         DispatchDeviceEvent(new DeviceEvent
                         {
                             Time = DateTime.Now.ToString("HH:mm:ss"),
                             EventType = action,
                             Name = name,
                             Type = "USB/Device",
                             Initiator = _currentUser
                         });
                    }
                 }
            }
            return IntPtr.Zero;
        }

        private string ParseDeviceName(string dbcc_name)
        {
            // Input format: \\?\USB#VID_1038&PID_12AD#6&25732bb2&0&1#{a5dcbf10-6530-11d2-901f-00c04fb951ed}
            try 
            {
                if (string.IsNullOrEmpty(dbcc_name)) return "Unknown Device";
                var parts = dbcc_name.Split('#');
                if (parts.Length >= 3)
                {
                    return $"{parts[1]} ({parts[2]})";
                }
                return dbcc_name;
            }
            catch { return dbcc_name; }
        }



        private string GetInitiator()
        {
             // Use the fast cached identity instead of blocking WMI
             return _currentUser ?? "Unknown";
        }


        // replacing Timer with EventLogWatcher for proper efficiency
        // Re-implementing StartSecurityMonitoring
        private EventLogWatcher _logWatcher;

        // --- Security Monitoring ---
        private void StartSecurityMonitoring()
        {
             try
             {
                 var query = new EventLogQuery("Security", PathType.LogName, "*[System/EventID > 0]");
                 _logWatcher = new EventLogWatcher(query);
                 _logWatcher.EventRecordWritten += (s, e) => 
                 {
                     if (e.EventRecord != null)
                        Dispatcher.Invoke(() => ProcessSecurityEvent(e.EventRecord));
                 };
                 _logWatcher.Enabled = true;
             }
             catch (Exception ex)
             {
                 SecurityData.Add(new SecurityEvent { Time = "ERR", Activity = ex.Message });
             }
        }

        private void ProcessSecurityEvent(EventRecord evt)
        {
             string source = evt.ProviderName ?? "System";
             string details = "";
             
             // Properties to extract
             string accountName = "";
             string accountDomain = "";
             string logonId = "";
             string securityId = "";
             string privileges = "";
             string logonType = "";
             string processName = "";
             string workstationName = "";
             string ipAddress = "";
             string ipPort = "";
             string restrictedAdminMode = "";
             string remoteCredentialGuard = "";
             string virtualAccount = "";
             string groupName = "";
             string groupDomain = "";
             string groupSecurityId = "";

             try 
             {
                 details = evt.FormatDescription();
                 if (!string.IsNullOrEmpty(details))
                 {
                     // Convert newlines to spaces for uniform regex parsing
                     details = details.Replace("\r", " ").Replace("\n", " ");

                     // Dictionary mapping Regex Pattern -> Ref Variable (conceptually)
                     // Since we can't pass refs easily in a loop with different variables, we'll do it sequentially
                     // but use a helper to extract and remove.
                     
                     // Helper Func: Extract value, assign to var, remove from details
                     // We match "Key: Value" where Value is until the next "Key:" or end of string.
                     // The lookahead checks for " TwoWords:" or " OneWord:" pattern.
                     
                     string Extract(string keyPattern, ref string targetVar)
                     {
                         // Pattern: Key followed by colon, optional space, then convert the capture group
                         // We use a non-greedy match for content (.*?) until valid lookahead
                         var regex = new System.Text.RegularExpressions.Regex(keyPattern + @":\s*(.*?)(?=\s+[A-Za-z][A-Za-z ]+:|$)");
                         var match = regex.Match(details);
                         if (match.Success)
                         {
                             targetVar = match.Groups[1].Value.Trim();
                             details = details.Replace(match.Value, " "); // Replace with space to prevent sticking words together
                             return match.Value;
                         }
                         return null;
                     }

                     // 1. Account Info
                     Extract("Account Name", ref accountName);
                     Extract("Account Domain", ref accountDomain);
                     Extract("Logon ID", ref logonId);
                     Extract("Security ID", ref securityId);
                     
                     // 2. Network / System
                     Extract("Logon Type", ref logonType);
                     Extract("Workstation Name", ref workstationName);
                     Extract("Source Network Address", ref ipAddress);
                     Extract("Source Port", ref ipPort);
                     Extract("Process Name", ref processName);
                     Extract("New Process Name", ref processName); // sometimes "New Process Name"

                     // 3. Extended Info
                     Extract("Restricted Admin Mode", ref restrictedAdminMode);
                     Extract("Remote Credential Guard", ref remoteCredentialGuard);
                     Extract("Virtual Account", ref virtualAccount);

                     // 4. Group Info
                     Extract("Group Name", ref groupName);
                     Extract("Group Domain", ref groupDomain);
                     // If there's a second Security ID (e.g. for Group), extracting 'Security ID' again will pick it up
                     // because the first one was removed from 'details' by the first Extract call.
                     Extract("Security ID", ref groupSecurityId);

                     // 5. Privileges - Specific handling
                     // Privileges often is the last item or long list. 
                     // The generic extraction might fail if it contains keys inside (unlikely for privileges).
                     // But strictly speaking, Privileges might be: "SeTcbPrivilege\nSeChangeNotify..."
                     Extract("Privileges", ref privileges);

                     // Clean up multiple spaces
                     details = System.Text.RegularExpressions.Regex.Replace(details, @"\s+", " ").Trim();
                     if (details.Length > 150) details = details.Substring(0, 147) + "...";
                 }
             }
             catch { details = evt.OpcodeDisplayName ?? "Info"; }

             if (string.IsNullOrEmpty(details)) details = evt.OpcodeDisplayName ?? "Info";

             string activity = evt.TaskDisplayName ?? $"Event {evt.Id}";
             
             SecurityData.Insert(0, new SecurityEvent
             {
                 Time = evt.TimeCreated?.ToString("HH:mm:ss"),
                 Id = evt.Id,
                 Type = details,
                 Activity = activity,
                 Account = source,
                 AccountName = accountName,
                 AccountDomain = accountDomain,
                 LogonId = logonId,
                 SecurityId = securityId,
                 Privileges = privileges,
                 LogonType = logonType,
                 ProcessName = processName,
                 WorkstationName = workstationName,
                 IpAddress = ipAddress,
                 IpPort = ipPort,
                 RestrictedAdminMode = restrictedAdminMode,
                 RemoteCredentialGuard = remoteCredentialGuard,
                 VirtualAccount = virtualAccount,
                 GroupName = groupName,
                 GroupDomain = groupDomain,
                 GroupSecurityId = groupSecurityId,
                 // Set Privilege Flags based on substrings
                 SeAssignPrimaryTokenPrivilege = privileges.Contains("SeAssignPrimaryTokenPrivilege"),
                 SeTcbPrivilege = privileges.Contains("SeTcbPrivilege"),
                 SeSecurityPrivilege = privileges.Contains("SeSecurityPrivilege"),
                 SeTakeOwnershipPrivilege = privileges.Contains("SeTakeOwnershipPrivilege"),
                 SeLoadDriverPrivilege = privileges.Contains("SeLoadDriverPrivilege"),
                 SeBackupPrivilege = privileges.Contains("SeBackupPrivilege"),
                 SeRestorePrivilege = privileges.Contains("SeRestorePrivilege"),
                 SeDebugPrivilege = privileges.Contains("SeDebugPrivilege"),
                 SeAuditPrivilege = privileges.Contains("SeAuditPrivilege"),
                 SeSystemEnvironmentPrivilege = privileges.Contains("SeSystemEnvironmentPrivilege"),
                 SeImpersonatePrivilege = privileges.Contains("SeImpersonatePrivilege")
             });
        }

        private void AskAi_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as System.Windows.Controls.MenuItem;
            var contextMenu = menuItem.Parent as System.Windows.Controls.ContextMenu;
            var grid = contextMenu.PlacementTarget as System.Windows.Controls.DataGrid;

            if (grid != null && grid.SelectedItem != null)
            {
                var window = new AskAiWindow(grid.SelectedItem);
                window.Owner = this;
                window.ShowDialog();
            }
        }


        private async void HandleThreatDetected(string type, string details)
        {
            Dispatcher.Invoke(() => {
                SecurityData.Insert(0, new SecurityEvent { 
                     Time = DateTime.Now.ToString("HH:mm:ss"), 
                     Activity = $"Blocked: {type}", 
                     Type = details, // Details Column
                     Account = "Security Enforcer", // Source Column
                     Id = 999 
                });
            });

            // Get Key
            string apiKey = "";
            try { apiKey = System.IO.File.ReadAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "apikey.txt")).Trim(); } catch {}

            if (!string.IsNullOrEmpty(apiKey)) 
            {
                try
                {
                    var client = new GeminiClient(apiKey);
                    // Use new AnalyzeThreatAsync method for "Active Advisor" persona
                    string explanation = await client.AnalyzeThreatAsync(type, details);
                
                    Dispatcher.Invoke(() => {
                         SecurityData.Insert(0, new SecurityEvent { 
                             Time = DateTime.Now.ToString("HH:mm:ss"), 
                             Activity = "Active Advisor", 
                             Type = explanation, 
                             Account = "Gemini AI", 
                             Id = 999 
                        });
                         
                         // Show Toast instead of intrusive MessageBox
                         Services.ToastNotificationService.Instance.ShowToast("Security Threat Blocked", $"{type}\n{explanation}");
                    });
                }
                catch {}
            }
        }
        
        private bool IsAdministrator()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        // Old NavigateTo removed in favor of Generic Lazy Load version


        private void MinimizeBtn_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

        private void MaximizeBtn_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();

        private void MainWindow_Closed(object sender, EventArgs e)
        {
            _enforcer?.Stop();
            // _logWatcher?.Enabled = false; // if using watcher
            Application.Current.Shutdown();
        }

        private void HandleFirewallDrift(List<string> driftItems)
        {
            if (driftItems == null || driftItems.Count == 0) return;

            string changes = string.Join("\n", driftItems);
            string message = "The following Firewall settings have changed or were modified by Windows:\n\n" +
                             changes +
                             "\n\nDo you want to restore your saved settings?";

            var result = MessageBox.Show(message, "Firewall Configuration Drift Detected", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            
            if (result == MessageBoxResult.Yes)
            {
                _enforcer.ForceApplyFirewallRules();
                MessageBox.Show("Settings restored successfully.", "Restored");
            }
        }
    }
}