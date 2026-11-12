using System;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Controls;
using System.Windows.Threading;
using System.IO;
using AutoCommand.Models;
using AutoCommand.Services;
using AutoCommand.Views;
using AutoCommand.Helpers;

namespace AutoCommand
{
    public partial class MainWindow : Window
    {
        private SecurityEnforcer _enforcer;
        private TrayNotifier _trayNotifier;

        private static string AppVersion =>
            FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "unknown";

        // ── hamburger: sidebar collapse ──────────────────────────────────
        // The burger item at the top of the strip is a fake tab — its
        // selection is intercepted here to toggle IsPaneCollapsed (labels
        // and group headers hide; the strip narrows to its icons) and the
        // previously selected tab is restored. NavPaneLabel/NavGroupLabel
        // styles in MainWindow.xaml bind their Visibility to this property.

        public static readonly DependencyProperty IsPaneCollapsedProperty =
            DependencyProperty.Register(nameof(IsPaneCollapsed), typeof(bool), typeof(MainWindow),
                new PropertyMetadata(false));

        public bool IsPaneCollapsed
        {
            get => (bool)GetValue(IsPaneCollapsedProperty);
            set => SetValue(IsPaneCollapsedProperty, value);
        }

        private object _lastContentItem;
        private bool _reselecting;

        private void MainTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_reselecting) return;
            if (e.AddedItems.Count > 0 && e.AddedItems[0] == NavPaneToggleItem)
            {
                IsPaneCollapsed = !IsPaneCollapsed;
                _reselecting = true;
                MainTabControl.SelectedItem = _lastContentItem ?? ProcessMonitorNavItem;
                _reselecting = false;
            }
            else if (e.AddedItems.Count > 0)
            {
                _lastContentItem = e.AddedItems[0];
            }
        }

        // ── the monitor tab's two panes: the list and the rain ───────────
        // The Matrix rain lives beside the Process Monitor grid (one glance
        // apart, same live table) instead of its own tab. The rail between
        // them folds EITHER pane: ‹ toggles the list, › toggles the rain —
        // a chevron disables when pressing it would empty the tab, so both
        // can never hide at once. A hidden pane costs nothing: the rain's
        // IsVisibleChanged machinery stops its renderer and feed; the list
        // stops rendering while its engines keep feeding the shared table
        // the rain reads. State persists as one word in rain_panel.txt —
        // "both" | "rain" | "grid" (older "collapsed"/"expanded" files
        // migrate), the same %LOCALAPPDATA%\AutoCommand home as the other
        // preference files.

        private string _paneState = "both";
        private double _rainWidth = 110;     // rain pane width in DIP (auto-fit or user-dragged)
        private bool _rainWidthManual;       // the splitter was dragged — auto-fit stands down

        private static string RainPanelPath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "rain_panel.txt");

        private void ListToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            _paneState = _paneState == "rain" ? "both" : "rain";
            ApplyPaneState();
            SavePaneState();
        }

        private void RainToggleBtn_Click(object sender, RoutedEventArgs e)
        {
            _paneState = _paneState == "grid" ? "both" : "grid";
            ApplyPaneState();
            SavePaneState();
        }

        private void ApplyPaneState()
        {
            bool list = _paneState != "rain";
            bool rain = _paneState != "grid";
            ListColumn.Width = new GridLength(1, GridUnitType.Star);
            SvchostTab.Visibility = list ? Visibility.Visible : Visibility.Collapsed;
            RainColumn.Width = rain ? new GridLength(_rainWidth) : new GridLength(0);
            MatrixRainTab.Visibility = rain ? Visibility.Visible : Visibility.Collapsed;
            RainSplitter.IsEnabled = rain;   // dragging must not widen a hidden pane
            // a triangle disables exactly when its press would hide the
            // only visible pane
            ListToggleBtn.IsEnabled = rain;
            RainToggleBtn.IsEnabled = list;
            ListToggleBtn.Opacity = rain ? 1.0 : 0.25;
            RainToggleBtn.Opacity = list ? 1.0 : 0.25;
            ListToggleBtn.ToolTip = rain ? "Hide the process list — rain only" : "Show the process list";
            RainToggleBtn.ToolTip = list ? "Hide the Matrix rain" : "Show the Matrix rain";
        }

        // ── rain pane width: auto-fit vs user-dragged ────────────────────
        // The renderer knows how wide the rain wants to be (alive columns ×
        // cell); the splitter lets the user take over. Dragging sets the
        // manual flag; double-clicking the splitter returns to auto-fit;
        // both persist. Auto-fit changes are DEBOUNCED: the alive count
        // churns as connections start and stop, and every width change
        // re-measures the list's DataGrid — an un-debounced fit spins the
        // UI on a busy desktop.

        private readonly System.Windows.Threading.DispatcherTimer _rainWidthDebounce =
            new(System.Windows.Threading.DispatcherPriority.Background)
            { Interval = TimeSpan.FromSeconds(1) };
        private double _rainWidthPending = double.NaN;

        private void ApplyRainColumnWidth()
        {
            if (_rainWidthManual || _paneState == "grid") return;
            double dip = MatrixRainTab.DesiredWidthDip;
            if (dip <= 0 || Math.Abs(dip - _rainWidth) < 0.5) return;
            if (_rainWidthDebounce.IsEnabled)
            {
                _rainWidthPending = dip;   // settle after the churn quiets down
                return;
            }
            _rainWidth = dip;
            RainColumn.Width = new GridLength(dip);
            _rainWidthDebounce.Start();
        }

        private void RainWidthDebounce_Tick(object sender, EventArgs e)
        {
            _rainWidthDebounce.Stop();
            if (_rainWidthManual || _paneState == "grid" ||
                double.IsNaN(_rainWidthPending) ||
                Math.Abs(_rainWidthPending - _rainWidth) < 0.5) return;
            _rainWidth = _rainWidthPending;
            _rainWidthPending = double.NaN;
            RainColumn.Width = new GridLength(_rainWidth);
            _rainWidthDebounce.Start();   // keep debouncing while it keeps changing
        }

        private void RainSplitter_DragStarted(object sender, System.Windows.Controls.Primitives.DragStartedEventArgs e)
            => _rainWidthManual = true;

        private void RainSplitter_DragCompleted(object sender, System.Windows.Controls.Primitives.DragCompletedEventArgs e)
        {
            if (RainColumn.Width.IsAbsolute) _rainWidth = RainColumn.Width.Value;
            SavePaneState();
        }

        private void RainSplitter_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            _rainWidthManual = false;
            ApplyRainColumnWidth();
            SavePaneState();
        }

        private void SavePaneState()
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(RainPanelPath));
                var width = _rainWidthManual ? $"manual={_rainWidth.ToString("0", System.Globalization.CultureInfo.InvariantCulture)}" : "auto";
                System.IO.File.WriteAllText(RainPanelPath, _paneState + "\n" + width);
            }
            catch { /* read-only profile — the choice lives for this session */ }
        }

        public MainWindow()
        {
            InitializeComponent();

            // persisted pane state applies BEFORE layout so a folded pane
            // never flashes open on launch
            try
            {
                var lines = System.IO.File.Exists(RainPanelPath)
                    ? System.IO.File.ReadAllLines(RainPanelPath)
                    : Array.Empty<string>();
                var saved = lines.Length > 0 ? lines[0].Trim() : "";
                _paneState = saved switch
                {
                    "rain" => "rain",
                    "grid" => "grid",
                    "collapsed" => "grid",   // pre-two-pane file: the rain was hidden
                    _ => "both",
                };
                if (lines.Length > 1 && lines[1].Trim().StartsWith("manual=", System.StringComparison.Ordinal)
                    && double.TryParse(lines[1].Trim().AsSpan(7), System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var w)
                    && w >= 24 && w <= 1200)
                {
                    _rainWidth = w;
                    _rainWidthManual = true;
                }
            }
            catch { _paneState = "both"; }
            MatrixRainTab.ColumnWidthChanged += ApplyRainColumnWidth;
            _rainWidthDebounce.Tick += RainWidthDebounce_Tick;
            ApplyPaneState();

            // ── adaptive placement (small-screen support) ────────────────
            // Restores persisted geometry, or starts MAXIMIZED on screens too
            // small for the designed 1200×750 — the 800×600-class a refresh
            // install shows until GPU drivers land. Runs before the window
            // shows so no oversized frame ever flashes. TrackWorkArea keeps
            // the window on-screen when the resolution changes mid-session.
            WindowPlacement.ApplyStartupPlacement(this);
            WindowPlacement.TrackWorkArea(this);

            // narrow launches start with the sidebar folded to icons — every
            // horizontal pixel goes to content; the burger expands it and
            // the choice sticks for the session. Covers both the 800×600
            // class (maximized) and a restored narrow window on a big screen.
            if (WindowPlacement.SmallScreenStartup ||
                (WindowState == WindowState.Normal && Width < 1000))
                IsPaneCollapsed = true;

            // Live version from the assembly instead of a hardcoded string
            VersionText.Text = $"AutoCommand v{AppVersion}";

            InitializeEnforcer();

            // App-level TCP capture + traffic aggregation: one raw socket
            // shared by the Python Spawns and Traffic Patterns tabs; the
            // aggregator runs whenever either captures and persists its
            // (process → destination → bytes) history across sessions.
            TrafficAggregationService.Shared.Attach(TcpStreamCaptureService.Shared);
            TrafficAggregationService.Shared.Start();
        }

        private void InitializeEnforcer()
        {
            // Initialize system tray notifier first so it's ready for callbacks
            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_icon.ico");
            _trayNotifier = new TrayNotifier(iconPath);
            _trayNotifier.ToastActivated += BringWindowToForeground;

            _enforcer = new SecurityEnforcer(OnThreatDetected);
            _enforcer.StatusChanged += OnEnforcerStatusChanged;
            _enforcer.ConfigurationDriftDetected += OnDriftDetected;

            // Wire the tray toast notification for adapter events
            _enforcer.OnAdapterAlert = (title, message) =>
                Dispatcher.Invoke(() => _trayNotifier.ShowSecurityAlert(title, message));

            _enforcer.Start();
        }

        private void BringWindowToForeground()
        {
            Dispatcher.Invoke(() =>
            {
                if (WindowState == WindowState.Minimized)
                    WindowState = WindowState.Normal;
                Activate();
                Topmost = true;
                Topmost = false;
                Focus();
            });
        }

        private string _currentThreatType;
        private string _currentThreatDetails;

        /// <summary>
        /// Lets tabs surface a finding on the app-level threat status bar
        /// (amber text + Review button) through the same path the Security
        /// Enforcer uses. Currently used by the BITS tab for UPLOAD-type
        /// jobs (ATT&CK T1197 exfiltration vector).
        /// </summary>
        public void RaiseExternalThreat(string type, string details) => OnThreatDetected(type, details);

        /// <summary>
        /// Transmissions tab's encrypted-upload toasts: same Action Center
        /// path as the enforcer's, but activating the toast selects the
        /// Transmissions tab instead of just raising the window.
        /// </summary>
        public void ShowTransmissionsToast(string title, string message)
        {
            // The Transmissions tab was removed from the sidebar (the engine
            // and its toasts remain) — activating the toast lands on the
            // Process Monitor instead of selecting a tab that no longer exists.
            _trayNotifier?.ShowSecurityAlert(title, message, durationMs: 10000, onActivated: () =>
                Dispatcher.Invoke(() => MainTabControl.SelectedItem = ProcessMonitorNavItem));
        }

        // Advanced investigation tabs were removed with the tab strip slimmed
        // down (their views, the Settings toggle and this machinery went with
        // them; the engines and AI tools behind them are unchanged).


        private void OnThreatDetected(string type, string details)
        {
            Dispatcher.Invoke(() =>
            {
                _currentThreatType = type;
                _currentThreatDetails = details;
                ThreatAlertText.Text = $"⚠ {type}: {details}";
                ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31));
                ReviewAlertBtn.Visibility = Visibility.Visible;
            });
        }

        private void ReviewAlertBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_currentThreatType == "Privileged Task")
            {
                string msg = $"{_currentThreatDetails}\n\n" +
                             "This task is running with the highest system privileges. While some third-party updaters (like Edge or Chrome) do this legitimately, malware often uses it for persistence.\n\n" +
                             "Would you like to ignore this task permanently (Whitelist)?\n" +
                             "Click 'No' to keep alerting. To investigate or delete the task, use the Tasks page in Shields Up.";
                
                var result = MessageBox.Show(msg, "Review Threat", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    // Extract task name and whitelist it
                    string taskName = _currentThreatDetails.Replace("High Risk Task detected: ", "").Trim();
                    SecurityEnforcer.WhitelistTask(taskName);
                    ThreatAlertText.Text = "✓ Task added to whitelist.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
            }
            else if (_currentThreatType == "Network Adapter")
            {
                string msg = $"Active Adapter Detected: {_currentThreatDetails}\n\n" +
                             "This adapter might be used for unauthorized tunneling or kernel debugging.\n\n" +
                             "Click 'Yes' to Block & Delete (removes device and service).\n" +
                             "Click 'No' to Whitelist — AutoCommand will STOP checking for and removing this surface. " +
                             "Drift is still detected and recorded, but NOT remediated; re-arm anytime in Settings → Network Adapter Security.\n" +
                             "Click 'Cancel' to ignore for now.";
                             
                var result = MessageBox.Show(msg, "Review Network Adapter", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    _enforcer.MitigateAdapter(_currentThreatDetails);
                    ThreatAlertText.Text = "✓ Adapter mitigated.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
                else if (result == MessageBoxResult.No)
                {
                    if (_currentThreatDetails.Contains("SSTP")) SecurityEnforcer.IsSstpAllowed = true;
                    if (_currentThreatDetails.Contains("Kernel Debug")) SecurityEnforcer.IsKernelDebugAllowed = true;
                    ThreatAlertText.Text = "✓ Adapter whitelisted.";
                    ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F));
                    ReviewAlertBtn.Visibility = Visibility.Collapsed;
                }
            }
            else
            {
                MessageBox.Show($"{_currentThreatType}\n\n{_currentThreatDetails}", "Security Alert", MessageBoxButton.OK, MessageBoxImage.Information);
                ReviewAlertBtn.Visibility = Visibility.Collapsed;
            }
        }


        private void OnEnforcerStatusChanged(string status, string colorType)
        {
            Dispatcher.Invoke(() =>
            {
                EnforcerStatusText.Text = $"Security Enforcer: {status}";
                EnforcerDot.Fill = colorType switch
                {
                    "Red" => new SolidColorBrush(Color.FromRgb(0xE5, 0x53, 0x4B)),
                    "Amber" => new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31)),
                    _ => new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F))
                };
            });
        }

        private void OnDriftDetected(List<string> driftItems)
        {
            Dispatcher.Invoke(() =>
            {
                ThreatAlertText.Text = $"⚠ Firewall drift detected: {driftItems.Count} rule(s) changed";
                ThreatAlertText.Foreground = new SolidColorBrush(Color.FromRgb(0xE5, 0xA6, 0x31));
            });
        }

        // Persist the final placement while the state is still valid — the
        // restore path re-clamps it against whatever screen exists next run.
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            WindowPlacement.SaveState(this);
            base.OnClosing(e);
        }

        protected override void OnClosed(EventArgs e)
        {
            _enforcer?.Stop();
            _trayNotifier?.Dispose();

            // Stop the shared capture FIRST so live flows finalize into the
            // aggregator, then persist that final state. (Content Unloaded
            // events fire after OnClosed, so tab-level Release may follow —
            // Stop is idempotent.)
            TcpStreamCaptureService.Shared.Stop();
            TrafficAggregationService.Shared.Shutdown();
            // Transmissions pipeline drains what the capture flush finalized
            // (up to its 3s budget), then releases its capture reference.
            TransmissionsPipelineService.Shared.Stop();

            TlsKeylogService.CleanupAtExit(); // drop the rotated TLS keylog leftover

            // Layer 3 must never outlive the app: stop restores the system
            // proxy, removes the QUIC block rule and untrusts the CA.
            AutoCommand.Intercept.Core.InterceptProxyService.Shared.StopSession("app exit");
            base.OnClosed(e);
        }

        // ── Emergency internet restore (panic button) ───────────────────────
        //
        // The #1 self-inflicted outage from Process Monitor blocking is blocking
        // svchost/DNS or a Microsoft endpoint. This disables every AutoCommand-
        // created block rule in one click — reversible, nothing deleted.

        private async void RestoreInternetBtn_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "Restore internet access?\n\n" +
                "This DISABLES every firewall block rule AutoCommand created (IP and process\n" +
                "blocks — including legacy ones). Nothing is deleted; re-enable all of them\n" +
                "from Process Monitor → Blocked → Manage all.\n\n" +
                "If this does not restore connectivity, the block came from another tool\n" +
                "or a proxy/VPN — this button only touches AutoCommand rules.",
                "🚑 Restore Internet", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            RestoreInternetBtn.IsEnabled = false;
            try
            {
                var result = await FirewallService.Instance
                    .SetAllBlocksEnabledAsync(false);

                // A stale DNS cache keeps sites dead even after the block is
                // lifted — flush it automatically so recovery is one click.
                // Pinned to System32 and run off the UI thread so a slow
                // ipconfig can never freeze the window (the app runs
                // elevated from a portable folder; a bare "ipconfig" would
                // resolve through the app/CWD first — both user-writable).
                string dnsNote;
                try
                {
                    var flush = await Task.Run(() =>
                    {
                        var psi = new System.Diagnostics.ProcessStartInfo(
                            System.IO.Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.System), "ipconfig.exe"),
                            "/flushdns")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true
                        };
                        using var p = System.Diagnostics.Process.Start(psi);
                        p.StandardOutput.ReadToEnd();
                        return p.WaitForExit(5000) ? p.ExitCode : -1;
                    });
                    dnsNote = flush == 0
                        ? "The DNS cache was flushed automatically — no further steps needed."
                        : $"ipconfig /flushdns did not complete cleanly (exit {flush}); run it manually if sites still fail.";
                }
                catch (Exception ex)
                {
                    dnsNote = $"Could not flush DNS automatically ({ex.Message}); run  ipconfig /flushdns  manually.";
                }

                // Fleet ops bypass SetStatuses by design — log the incident
                // so the Blocks tab's audit digest can answer "when did all
                // my blocks go off, and how far did it reach".
                BlocksStore.LogFleet("fleet-disabled",
                    $"{result.Changed}/{result.Matched} rule(s) disabled", "panic-button");
                await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
                var blocksRefresh = BlocksTab != null ? BlocksTab.RefreshIfLoadedAsync() : Task.CompletedTask;
                var monitorRefresh = Views.SvchostMonitorView.Current != null
                    ? Views.SvchostMonitorView.Current.RefreshBlockStateIfLoadedAsync()
                    : Task.CompletedTask;

                string extra = result.FirstError != null ? $"\nFirst error: {result.FirstError}" : "";
                MessageBox.Show(
                    $"Disabled {result.Changed} of {result.Matched} AutoCommand block rule(s).{extra}\n\n" +
                    $"{dnsNote}\n\n" +
                    "Restore options in Process Monitor → Blocked → Manage all:\n" +
                    "  · 'Restore except Microsoft/Windows' — recommended: brings back your\n" +
                    "    real blocks, leaves the breakage-causing ones (red rows) off\n" +
                    "  · 'Re-enable all' — everything back on",
                    "🚑 Restore Internet", MessageBoxButton.OK, MessageBoxImage.Information);
                await blocksRefresh;
                await monitorRefresh;
            }
            finally { RestoreInternetBtn.IsEnabled = true; }
        }
    }
}

