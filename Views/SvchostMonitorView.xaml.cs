using System;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using AutoCommand.Helpers;
using AutoCommand.Models;
using AutoCommand.Services;

namespace AutoCommand.Views
{
    public partial class SvchostMonitorView : UserControl, IAiAuditable
    {
        private readonly ConcurrentDictionary<string, SvchostMonitorItem> _trackedIps = new();
        private readonly ObservableCollection<SvchostMonitorItem> _uiCollection = new();
        
        private DnsResolutionService _dnsService;
        private SysmonWatcherService _sysmonService;
        private RawSocketSnifferService _snifferService;
        private readonly SysmonInstallerService _installerService = new();
        private bool _isMonitoring = false;
        private DispatcherTimer _saveTimer;
        private DispatcherTimer _lastSeenRefreshTimer;
        // absolute on purpose: a relative path resolves against the CWD,
        // which is System32 under the schtasks launch — user-writable
        // app-data instead, beside the rest of AutoCommand's stores
        private readonly string _csvPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "svchost-watch", "ultimate_autopilot_stats.csv");

        // Firewall blocks created from this monitor live in BlocksStore (v3
        // blocks.txt under %LOCALAPPDATA%\AutoCommand) — service identity is
        // captured at block time because the PID (and with it the identity)
        // dies with the process.

        // Live firewall truth for row marking: which remote IPs / executable
        // paths have block rules (any enabled rule = active, all disabled =
        // paused). Rebuilt from GetBlockedInventoryAsync after every
        // block/unblock, when the Blocked-rules window closes, and once a
        // minute to catch out-of-band changes (agent actions, wf.msc edits).
        private readonly HashSet<string> _activeIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _pausedIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _activeApps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _pausedApps = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _blockNotes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<int, string> _pidPathCache = new();
        private DispatcherTimer _blockStateTimer;
        private bool _blockStateSyncing;
        private bool _blockStateResyncRequested;

        // Non-modal block feedback (message + Undo, auto-hides)
        private DispatcherTimer _toastTimer;
        private string _toastUndoKind;
        private string _toastUndoKey;

        // High-transmitter threshold in bytes, persisted under %LOCALAPPDATA%\AutoCommand
        private long _txThreshold = 1024;
        private static readonly string _txThresholdPath = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "tx_threshold.txt");
        private const string LegacyTxThresholdPath = "tx_threshold.txt";
        private bool _loadingThreshold = true;

        // Scheduled-task attribution for taskhostw rows (who/what/why launched)
        private readonly TaskAttributionService _taskAttribution = new();

        // Traffic Peek windows, one per subject ("Peer into this connection",
        // "Peer into this program", "Track this service") — keys name the
        // scope: "ip:x" · "pid:N" · "svc:name".
        private readonly Dictionary<string, ConnectionPeekWindow> _peekWindows = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>The live monitor instance — the Blocks tab reads current
        /// connections from it for its "last traffic" column.</summary>
        public static SvchostMonitorView Current { get; private set; }

        /// <summary>The shared row table both engines write into — the Rain
        /// tab's MatrixRainFeed aggregates it (read-only by contract) so the
        /// rain is literally the same data the DataGrid shows, with no
        /// second watcher or sniffer.</summary>
        public ConcurrentDictionary<string, SvchostMonitorItem> TrackedTable => _trackedIps;

        /// <summary>Newest live row still talking to this IP, or null — the
        /// Blocks tab's freshest "last traffic" source (beats the archive).</summary>
        public SvchostMonitorItem LiveRowForIp(string ip)
        {
            SvchostMonitorItem best = null;
            foreach (var item in _trackedIps.Values)
            {
                if (!string.Equals(item.RemoteIp, ip, StringComparison.OrdinalIgnoreCase)) continue;
                if (best == null || item.LastSeen > best.LastSeen) best = item;
            }
            return best;
        }

        /// <summary>Newest live row for an executable path, or null.</summary>
        public SvchostMonitorItem LiveRowForPath(string path)
        {
            SvchostMonitorItem best = null;
            foreach (var item in _trackedIps.Values)
            {
                if (!string.Equals(item.ImagePath, path, StringComparison.OrdinalIgnoreCase)) continue;
                if (best == null || item.LastSeen > best.LastSeen) best = item;
            }
            return best;
        }

        public SvchostMonitorView()
        {
            Current = this;
            InitializeComponent();
            SvchostGrid.ItemsSource = _uiCollection;

            // Most-recent-first order that keeps itself current: the LastSeen
            // setter raises PropertyChanged on every packet, and live sorting
            // repositions that row at the top. The Remote IP tiebreaker keeps
            // equal-timestamp rows in a stable order instead of reshuffling.
            // High transmitters sort ahead of everything (the red-pinned
            // heavy talkers), still most-recent-first within their group.
            // (ListCollectionView implements ICollectionViewLiveShaping
            // explicitly, so the shaping members need the interface cast.)
            if (CollectionViewSource.GetDefaultView(_uiCollection) is ICollectionViewLiveShaping liveShaping)
            {
                liveShaping.LiveSortingProperties.Add(nameof(SvchostMonitorItem.IsHighTransmitter));
                liveShaping.LiveSortingProperties.Add(nameof(SvchostMonitorItem.LastSeen));
                liveShaping.IsLiveSorting = true;
                // TX-only filter membership is live too: rows slide in when
                // their grace period lapses with zero Rx, and drop out the
                // moment a reply packet lands.
                liveShaping.LiveFilteringProperties.Add(nameof(SvchostMonitorItem.IsTxOnly));
                liveShaping.IsLiveFiltering = true;
            }
            if (CollectionViewSource.GetDefaultView(_uiCollection) is ListCollectionView view)
            {
                view.SortDescriptions.Add(new SortDescription(
                    nameof(SvchostMonitorItem.IsHighTransmitter), ListSortDirection.Descending));
                view.SortDescriptions.Add(new SortDescription(
                    nameof(SvchostMonitorItem.LastSeen), ListSortDirection.Descending));
                view.SortDescriptions.Add(new SortDescription(
                    nameof(SvchostMonitorItem.RemoteIp), ListSortDirection.Ascending));
            }
        }

        private bool _isInitialized = false;

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            if (_isInitialized) return;
            _isInitialized = true;

            CheckSysmonStatus();

            _dnsService   = DnsResolutionService.Instance;
            _sysmonService = new SysmonWatcherService(_trackedIps, _dnsService);
            _sysmonService.MonitorAllProcesses = true;
            _sysmonService.FilterKnownCloudIps = HideCloudCheck.IsChecked == true;
            _snifferService = new RawSocketSnifferService(_trackedIps);

            _sysmonService.OnError += ShowError;
            _sysmonService.OnNewConnectionTracked += AddToUi;

            _snifferService.OnError += ShowError;

            // Attribution errors are non-fatal (rows just lack task info)
            _taskAttribution.OnError += msg => { };
            _taskAttribution.Start();

            RefreshIgnoredUi();
            LoadBlockedEntries();
            RefreshBlockedUi();
            RefreshConfirmPrefsUi();
            LoadTxThreshold();

            // Mark rows whose IP/process already has firewall rules (includes
            // blocks created outside this monitor — the rules are the truth)
            _ = RefreshBlockStateFromFirewallAsync();
            _blockStateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) };
            _blockStateTimer.Tick += (s, args) => _ = RefreshBlockStateFromFirewallAsync();
            _blockStateTimer.Start();
            // firewall-inventory snapshot read — pause the 60 s poll while
            // this tab is hidden, and trigger an immediate sync when shown
            // again so Blocks-tab / Restore-Internet toggles reflect right away
            RefreshLoop.GateVisibility(this, () => _blockStateTimer, () =>
            {
                if (_isInitialized) _ = RefreshBlockStateFromFirewallAsync();
            });

            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(6.5) };
            _toastTimer.Tick += (s, args) => HideToast();

            // Setup auto-save every 1 hour
            _saveTimer = new DispatcherTimer { Interval = TimeSpan.FromHours(1) };
            _saveTimer.Tick += (s, args) => SaveToCsv();

            // Refresh relative "Last Packet" column + DNS cache chip every 10 seconds
            _lastSeenRefreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
            _lastSeenRefreshTimer.Tick += (s, args) =>
            {
                foreach (var item in _uiCollection)
                    item.RefreshLastSeenDisplay();

                // Rows outlive their processes — label the ones whose PID is
                // gone so a dead connection stops masquerading as a live one.
                MarkExitedProcesses();

                // Re-enqueue any rows still showing raw IPs (handles items loaded from CSV etc.)
                foreach (var item in _uiCollection)
                    _dnsService.EnqueueForResolution(item);

                // Fill in scheduled-task attribution as the event logs catch up
                foreach (var item in _uiCollection)
                    EnrichWithTaskInfo(item);

                // Resolve svchost rows' service identity (which -s service /
                // SCM tenant each instance is) — rows created mid-tick and
                // re-attributed rows land here on the next pass.
                foreach (var item in _uiCollection)
                    EnrichWithSvchostIdentity(item);

                // Stamp WSL context onto the wslservice/vmmem family rows so
                // "wslservice.exe is uploading" reads as "my Linux VM did
                // that" before anyone reaches for the Block button.
                foreach (var item in _uiCollection)
                    EnrichWithWslIdentity(item);

                // Rows whose name never resolved get one archive-backed
                // reveal attempt (one-shot per row — the day-file scan is
                // real disk work, and the archive does not grow backwards)
                foreach (var item in _uiCollection)
                    EnrichWithRevealedName(item);

                DnsCacheChip.Text = $"DNS cache: {_dnsService.CacheCount} entries";
                UpdateHighTxChip();
                UpdateTxOnlyCheckLabel();
            };
            _lastSeenRefreshTimer.Start();

            // Start DNS service before Sysmon so first events can hit the cache
            _dnsService.Start();

            // Auto-start monitor on load
            ToggleMonitorBtn_Click(null, null);
        }

        private void CheckSysmonStatus()
        {
            if (!_installerService.IsSysmonInstalled())
            {
                SetupSysmonBtn.Visibility = Visibility.Visible;
                MonitorStatusText.Text = "Sysmon is not installed — install it from the Sysmon Audit tab. Network tracking will not work.";
            }
            else
            {
                SetupSysmonBtn.Visibility = Visibility.Collapsed;
            }
        }

        private async void SetupSysmonBtn_Click(object sender, RoutedEventArgs e)
        {
            SetupSysmonBtn.IsEnabled = false;

            // Inconsistent state = leftovers of a failed install (stale event
            // manifest registration / stray Sysmon64.exe) that make every
            // install attempt fail. Offer a guided repair instead.
            if (_installerService.DetectInstallState() == SysmonInstallState.Inconsistent)
            {
                await RepairSysmonFlowAsync();
                return;
            }

            MonitorStatusText.Text = "Downloading and configuring Sysmon... please wait.";

            var (installOk, installError) = await _installerService.InstallAndConfigureAsync();
            if (installOk)
            {
                MessageBox.Show("Sysmon has been successfully installed and configured for network tracking.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                CheckSysmonStatus();
                MonitorStatusText.Text = "Sysmon ready. Click 'Start Monitor' to begin tracking.";
            }
            else
            {
                MessageBox.Show($"Failed to install Sysmon.\n\nDetails: {installError}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);

                // Offline path: the download was the failure, so offer the
                // local-copy route (USB-brought exe, IT-provided copy…).
                // Seeding runs the same Microsoft-signature gate as every
                // other source — a local copy is acceptable exactly when it
                // verifies.
                if (installError != null && installError.Contains("could not be downloaded"))
                {
                    var useLocal = MessageBox.Show(
                        "This PC appears to be offline, so Sysmon64.exe could not be downloaded.\n\n" +
                        "Use a local copy now? Pick a Microsoft-signed Sysmon64.exe you brought to this PC " +
                        "(downloaded from live.sysinternals.com on any connected machine, moved here e.g. via USB).",
                        "Offline install", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);

                    if (useLocal == MessageBoxResult.Yes)
                    {
                        var dlg = new Microsoft.Win32.OpenFileDialog
                        {
                            Title = "Choose Sysmon64.exe",
                            Filter = "Sysmon64.exe|Sysmon64.exe|Executables (*.exe)|*.exe",
                        };
                        if (dlg.ShowDialog() == true)
                        {
                            MonitorStatusText.Text = "Verifying and copying the local Sysmon64.exe...";
                            string seedError = _installerService.TrySeedCacheFrom(dlg.FileName);
                            if (seedError == null)
                            {
                                var (retryOk, retryError) = await _installerService.InstallAndConfigureAsync();
                                if (retryOk)
                                {
                                    MessageBox.Show("Sysmon installed from the local copy and configured for network tracking.",
                                        "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                                    CheckSysmonStatus();
                                    MonitorStatusText.Text = "Sysmon ready. Click 'Start Monitor' to begin tracking.";
                                    return;
                                }
                                MessageBox.Show($"Local copy accepted, but the install still failed.\n\nDetails: {retryError}",
                                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else
                            {
                                MessageBox.Show(seedError, "Local copy refused", MessageBoxButton.OK, MessageBoxImage.Warning);
                            }
                        }
                    }
                }

                SetupSysmonBtn.IsEnabled = true;
                MonitorStatusText.Text = "Sysmon is not installed — install it from the Sysmon Audit tab. Network tracking will not work.";
            }
        }

        private async Task RepairSysmonFlowAsync()
        {
            var repair = MessageBox.Show(
                "Sysmon is in an inconsistent install state: leftovers of an earlier failed install " +
                "(a stale event-manifest registration and/or a stray Sysmon64.exe) make every install attempt fail.\n\n" +
                "Repair now? The leftovers will be removed and Sysmon reinstalled. " +
                "If Windows still holds the stale registration, a restart will be offered to finish the repair.",
                "Sysmon repair", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);

            if (repair != MessageBoxResult.Yes)
            {
                SetupSysmonBtn.IsEnabled = true;
                MonitorStatusText.Text = "Sysmon repair cancelled. Network tracking will not work.";
                return;
            }

            MonitorStatusText.Text = "Repairing Sysmon... removing leftovers and reinstalling.";
            var (repairedOk, repairedError, rebootRequired) = await _installerService.RepairAsync();

            if (repairedOk)
            {
                MessageBox.Show("Sysmon repair completed and verified. No restart was needed.", "Repair complete", MessageBoxButton.OK, MessageBoxImage.Information);
                CheckSysmonStatus();
                MonitorStatusText.Text = "Sysmon ready. Click 'Start Monitor' to begin tracking.";
                return;
            }

            if (rebootRequired)
            {
                var restart = MessageBox.Show(
                    "Windows still holds the stale Sysmon registration; it can only be cleared during a restart.\n\n" +
                    "Restart Windows now to finish the repair? Save your work first — the PC will reboot. " +
                    "After the restart AutoCommand will reinstall and verify Sysmon automatically.",
                    "Sysmon repair — restart required", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);

                if (restart == MessageBoxResult.Yes)
                {
                    MonitorStatusText.Text = "Restarting Windows to complete the Sysmon repair...";
                    ProcessRunner.RunDetached("shutdown.exe",
                        "/r /t 10 /c \"AutoCommand: restarting to complete the Sysmon repair\"");
                    return;
                }

                MessageBox.Show("The repair will finish automatically after the next Windows restart: " +
                    "AutoCommand will reinstall and verify Sysmon on startup.", "Repair pending restart",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                MonitorStatusText.Text = "Sysmon repair pending restart. Network tracking will not work until then.";
                return;
            }

            MessageBox.Show($"Sysmon repair failed.\n\nDetails: {repairedError}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            SetupSysmonBtn.IsEnabled = true;
            MonitorStatusText.Text = "Sysmon is not installed. Network tracking will not work.";
        }

        private void Filter_Changed(object sender, RoutedEventArgs e)
        {
            if (_sysmonService != null)
                _sysmonService.FilterKnownCloudIps = HideCloudCheck.IsChecked == true;
        }

        // -----------------------------------------------------------------------
        // TX-only view filter — off by default. When on, only one-way
        // transmitters (sent packets, never a reply) are shown. This is a
        // view lens only: unlike the cloud filter (ingestion-side), turning
        // it off restores the full grid, and rows keep accruing counters
        // either way.
        // -----------------------------------------------------------------------

        private void TxOnlyFilter_Changed(object sender, RoutedEventArgs e)
        {
            // Assigning Filter refreshes the view; with live filtering on
            // IsTxOnly, membership keeps itself current afterwards.
            CollectionViewSource.GetDefaultView(_uiCollection).Filter =
                TxOnlyCheck.IsChecked == true ? TxOnlyPredicate : null;
            UpdateTxOnlyCheckLabel();
        }

        private static bool TxOnlyPredicate(object o) =>
            o is SvchostMonitorItem m && m.IsTxOnly;

        /// <summary>
        /// Keeps the TX-only count in the checkbox label so users can see how
        /// many one-way transmitters are out there before switching the lens
        /// on (same cadence as the High TX chip).
        /// </summary>
        private void UpdateTxOnlyCheckLabel()
        {
            int count = 0;
            foreach (var item in _uiCollection)
                if (item.IsTxOnly) count++;
            TxOnlyCheck.Content = count == 0
                ? "TX-only (no reply)"
                : $"TX-only (no reply): {count}";
        }

        // -----------------------------------------------------------------------
        // High-transmitter threshold (pinned + tinted rows at/above it)
        // -----------------------------------------------------------------------

        private void LoadTxThreshold()
        {
            try
            {
                string pathToRead = File.Exists(_txThresholdPath)
                    ? _txThresholdPath
                    : (File.Exists(LegacyTxThresholdPath) ? LegacyTxThresholdPath : null);
                if (pathToRead != null &&
                    long.TryParse(File.ReadAllText(pathToRead).Trim(), out long bytes) &&
                    bytes >= 0)
                {
                    _txThreshold = bytes;
                    if (pathToRead == LegacyTxThresholdPath)
                    {
                        try
                        {
                            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_txThresholdPath));
                            File.WriteAllText(_txThresholdPath, _txThreshold.ToString());
                        }
                        catch { }
                    }
                }
            }
            catch { /* first run or unreadable file — keep the 1 KB default */ }

            SvchostMonitorItem.TxThresholdBytes = _txThreshold;

            // Reflect the byte value in the number/unit controls
            long unit = _txThreshold >= 1048576 ? 1048576 : _txThreshold >= 1024 ? 1024 : 1;
            TxUnitCombo.SelectionChanged -= TxThreshold_Changed;
            foreach (var item in TxUnitCombo.Items.OfType<ComboBoxItem>())
                if (item.Tag is string tag && long.Parse(tag) == unit) item.IsSelected = true;
            TxUnitCombo.SelectionChanged += TxThreshold_Changed;
            TxThresholdBox.Text = (_txThreshold / unit).ToString();
            UpdateHighTxChip();
            _loadingThreshold = false;
        }

        private void TxThreshold_Changed(object sender, RoutedEventArgs e)
        {
            if (_loadingThreshold) return;

            if (!long.TryParse(TxThresholdBox.Text.Trim(), out long value) || value < 0)
                return; // mid-typing or invalid — keep the last valid threshold

            long unit = 1;
            if (TxUnitCombo.SelectedItem is ComboBoxItem unitItem && unitItem.Tag is string tag)
                long.TryParse(tag, out unit);

            _txThreshold = value * unit;
            SvchostMonitorItem.TxThresholdBytes = _txThreshold;
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_txThresholdPath));
                File.WriteAllText(_txThresholdPath, _txThreshold.ToString());
            }
            catch { /* persistence is best-effort — the live threshold still applies */ }

            // Re-sort immediately: live sorting reacts to per-row changes,
            // not to the shared threshold moving under them
            CollectionViewSource.GetDefaultView(_uiCollection).Refresh();
            UpdateHighTxChip();
        }

        private void UpdateHighTxChip()
        {
            int count = 0;
            foreach (var item in _uiCollection)
                if (item.IsHighTransmitter) count++;
            HighTxCountText.Text = $"High TX: {count} ≥ {FormatThreshold(_txThreshold)}";
        }

        private static string FormatThreshold(long bytes) =>
            bytes >= 1048576 ? $"{bytes / 1048576.0:0.#} MB" :
            bytes >= 1024 ? $"{bytes / 1024.0:0.#} KB" : $"{bytes} B";

        /// <summary>
        /// Labels rows whose process has exited. The PID snapshot is taken on
        /// a background thread (Process.GetProcesses is not free) and applied
        /// on the UI thread; the flag is sticky — only a Sysmon
        /// re-attribution (a new PID on the same remote IP) can clear it.
        /// </summary>
        private async void MarkExitedProcesses()
        {
            try
            {
                var alive = new HashSet<int>();
                await Task.Run(() =>
                {
                    foreach (var p in Process.GetProcesses())
                    {
                        using (p)
                            alive.Add(p.Id);
                    }
                });

                foreach (var item in _uiCollection)
                {
                    if (item.ProcessId <= 0 || item.HasExited) continue; // System/Idle never exits
                    if (!alive.Contains(item.ProcessId))
                    {
                        _pidPathCache.TryRemove(item.ProcessId, out _);
                        item.MarkExited();
                    }
                }
            }
            catch { /* snapshot failed — retried on the next tick */ }
        }

        private void ShowError(string msg)
        {
            Dispatcher.Invoke(() =>
            {
                MessageBox.Show(msg, "Monitor Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                if (_isMonitoring) ToggleMonitorBtn_Click(null, null); // Stop on critical error
            });
        }

        private void AddToUi(SvchostMonitorItem item)
        {
            Dispatcher.Invoke(() =>
            {
                // The event may have raced with the user adding an ignore entry
                if (_sysmonService.IsProcessIgnored(item.ProcessName))
                {
                    _trackedIps.TryRemove(item.RemoteIp, out _);
                    return;
                }
                EnrichWithTaskInfo(item);
                EnrichWithSvchostIdentity(item);
                EnrichWithWslIdentity(item);
                // A blocked IP reappearing as a fresh row shows ⛔ immediately,
                // not only after the next sync pass
                ApplyBlockState(item);
                _uiCollection.Add(item);
            });
        }

        /// <summary>
        /// Stamps scheduled-task attribution (task path + user) onto taskhostw
        /// rows once the event logs have caught up with the launch.
        /// </summary>
        private void EnrichWithTaskInfo(SvchostMonitorItem item)
        {
            if (item.TaskName != null) return;
            var info = _taskAttribution.GetTaskForPid(item.ProcessId, item.ProcessStartedUtc);
            if (info == null || string.IsNullOrEmpty(info.TaskPath)) return;
            item.SetTaskInfo(info.TaskPath, info.UserContext);
        }

        /// <summary>
        /// Stamps WSL context onto the wslservice/vmmem family rows: the
        /// plain-English "your Linux VM made this" note (running distros +
        /// networking mode), and — when the VM is already up — the joined
        /// guest answer ("linux side: node (pid 4312) → 1.1.1.1:80"). Both
        /// probes cache internally and can never start the utility VM, so
        /// the 10-second tick can call this freely; the guest half runs off
        /// the UI thread with the same PID-recycle guard as the svchost
        /// enrichment.
        /// </summary>
        private async void EnrichWithWslIdentity(SvchostMonitorItem item)
        {
            if (!WslIdentityService.IsWslFamilyProcess(item.ProcessName)) return;

            string distros;
            string modeNote;
            bool vmRunning;
            try
            {
                var state = WslIdentityService.GetState();
                distros = state.RunningDistros.Length > 0
                    ? string.Join(", ", state.RunningDistros)
                    : "none running";
                modeNote = state.ModeNote;
                vmRunning = state.VmRunning;
            }
            catch
            {
                item.SetWslIdentity("state unavailable");
                return;
            }

            string baseNote = $"running distros: {distros}" +
                              (string.IsNullOrEmpty(modeNote) ? "" : $" · {modeNote}");
            item.SetWslIdentity(baseNote);

            bool alreadyJoined = item.WslNote != null && item.WslNote.Contains("linux side:");
            if (!vmRunning || alreadyJoined || string.IsNullOrEmpty(item.RemoteIp)) return;

            int pid = item.ProcessId;
            string remoteIp = item.RemoteIp;
            try
            {
                var snapshot = await Task.Run(WslGuestProbe.Probe);
                if (item.ProcessId != pid) return; // re-attributed mid-probe
                var matches = WslGuestProbe.MatchByRemoteIp(snapshot, remoteIp).Take(4).ToList();
                if (matches.Count == 0) return;
                string guest = string.Join("; ", matches.Select(m =>
                {
                    var (ip, port) = WslGuestProbe.SplitEndpoint(m.Socket.Peer);
                    return $"{m.Distro.Distro ?? "default distro"}: " +
                           $"{m.Socket.Process ?? "unknown process"} " +
                           $"(pid {m.Socket.Pid?.ToString() ?? "?"}) → {ip}:{port}";
                }));
                item.SetWslIdentity(baseNote + "\nlinux side: " + guest);
            }
            catch
            {
                // guest join is best-effort — the base note still stands
            }
        }

        /// <summary>
        /// Resolves a svchost row's service identity (SCM-hosted services +
        /// -k/-s command-line tokens) on a background thread and stamps it on
        /// the UI thread. One attempt per row at a time; the 10-second timer
        /// retries rows still unresolved (fresh spawns, re-attributed tenants).
        /// </summary>
        private async void EnrichWithSvchostIdentity(SvchostMonitorItem item)
        {
            if (!item.TryBeginIdentity()) return;
            int pid = item.ProcessId;
            try
            {
                var id = await Task.Run(() => SvchostIdentityService.Resolve(pid));
                // The row may have been re-attributed while the WMI query ran —
                // the identity belongs to the old tenant, not the new one.
                if (item.ProcessId != pid) { item.AbandonIdentity(); return; }
                item.SetSvchostIdentity(id.ServicesCsv, id.ServicesDetail, id.Group, id.DeclaredService,
                                        id.CommandLineVisible, id.Mismatch || id.NoK);
            }
            catch
            {
                item.AbandonIdentity(); // retried on the next timer tick
            }
        }

        private void ToggleMonitorBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!_isMonitoring)
            {
                _sysmonService.Start();
                _snifferService.Start();
                _saveTimer.Start();

                ToggleMonitorBtn.Content = "Stop Monitor";
                MonitorStatusText.Text = "Monitor active: Sysmon event listening and Raw Socket sniffing enabled.";
                _isMonitoring = true;

                // Baseline: connections opened before Start never fire a
                // Sysmon ID 3 (svchost's boot-time WNS channel and other
                // long-lived sockets) — seed rows for everything established
                // right now, then let live events take over. Off the UI
                // thread: it does a PID/path lookup per connection.
                _ = Task.Run(() =>
                {
                    int seeded = _sysmonService.SeedBaseline();
                    Dispatcher.BeginInvoke(() =>
                    {
                        if (_isMonitoring)
                            MonitorStatusText.Text =
                                $"Monitor active: Sysmon events + raw socket sniffing · {seeded} existing connection(s) seeded";
                    });
                });
            }
            else
            {
                _sysmonService.Stop();
                _snifferService.Stop();
                _saveTimer.Stop();
                
                ToggleMonitorBtn.Content = "Start Monitor";
                MonitorStatusText.Text = "Monitor is stopped.";
                _isMonitoring = false;
            }
        }

        // -----------------------------------------------------------------------
        // Process ignore list
        // -----------------------------------------------------------------------

        private void IgnoreProcessBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) IgnoreProcessBtn_Click(sender, e);
        }

        private void IgnoreProcessBtn_Click(object sender, RoutedEventArgs e)
        {
            string procName = IgnoreProcessBox.Text.Trim();
            if (string.IsNullOrEmpty(procName)) return;

            IgnoreProcess(procName);
            IgnoreProcessBox.Clear();
        }

        private void IgnoreRowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is SvchostMonitorItem item && !string.IsNullOrEmpty(item.ProcessName))
                IgnoreProcess(item.ProcessName);
        }

        // ── DNS resolve-state support (tooltips live on the Host column) ──

        private void ResolveNowMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;
            MonitorStatusText.Text = DnsResolutionService.Instance.ResolveNow(item.RemoteIp)
                ? "Urgent re-lookup queued for " + item.RemoteIp +
                  " — the row updates itself when the answer lands."
                : item.RemoteIp + " already resolves — nothing to retry.";
        }

        private void RetryDnsBtn_Click(object sender, RoutedEventArgs e)
        {
            var unresolved = _uiCollection
                .Where(i => !i.IsResolved && !string.IsNullOrEmpty(i.RemoteIp))
                .Select(i => i.RemoteIp)
                .Distinct()
                .ToList();
            DnsResolutionService.Instance.RetryUnresolved(unresolved);
            foreach (var item in _uiCollection.Where(i => !i.IsResolved))
                _dnsService.EnqueueForResolution(item);
            MonitorStatusText.Text = unresolved.Count > 0
                ? "Re-queued " + unresolved.Count + " unresolved lookup(s) — cached 'no answer' results were forgotten; polite pacing applies."
                : "Nothing to retry — every row on this view is resolved.";
        }

        private void RowMenu_Opened(object sender, RoutedEventArgs e)
        {
            var sel = SvchostGrid.SelectedItem as SvchostMonitorItem;

            bool traceable = sel != null && sel.ProcessId > 0;
            TracePidMenuItem.IsEnabled = traceable;
            TracePidMenuItem.Header = traceable
                ? $"🔎 Trace PID {sel.ProcessId} — how was it spawned?"
                : "🔎 Trace: how was this PID spawned?";

            // Peer needs a real remote endpoint to scope the capture to.
            bool peerable = sel != null &&
                System.Net.IPAddress.TryParse(sel.RemoteIp, out _);
            PeerMenuItem.IsEnabled = peerable;
            PeerMenuItem.Header = peerable
                ? $"🔬 Peer into this connection ({sel.RemoteIp})"
                : "🔬 Peer into this connection";

            // Program scope needs a live PID (Sysmon EID 3 does the rest).
            bool programPeekable = sel != null && sel.ProcessId > 0;
            ProgramPeekMenuItem.IsEnabled = programPeekable;
            ProgramPeekMenuItem.Header = programPeekable
                ? $"🔬 Peer into this program (PID {sel.ProcessId})"
                : "🔬 Peer into this program";

            // A service pin is the subject that survives restarts — anchored
            // to the NAME, so it tracks whichever instance pops up next.
            string pinnedService = sel == null ? null : FirstService(sel.HostedServicesCsv);
            TrackServiceMenuItem.IsEnabled = !string.IsNullOrEmpty(pinnedService);
            TrackServiceMenuItem.Header = !string.IsNullOrEmpty(pinnedService)
                ? $"⭐ Track this service ({pinnedService}) — follows restarts"
                : "⭐ Track this service (svchost rows only)";

            ResolveNowMenuItem.IsEnabled = sel != null &&
                System.Net.IPAddress.TryParse(sel.RemoteIp, out _) && !sel.IsResolved;
            ResolveNowMenuItem.Visibility = ResolveNowMenuItem.IsEnabled
                ? Visibility.Visible : Visibility.Collapsed;

            bool revealable = sel != null && sel.ProcessId > 0;
            RevealNameMenuItem.IsEnabled = revealable;
            RevealNameMenuItem.Header = revealable
                ? $"🏷 Reveal real name of PID {sel.ProcessId} (Sysmon record)"
                : "🏷 Reveal real process name (Sysmon record)";

            IgnoreRowMenuItem.Header = sel != null && !string.IsNullOrEmpty(sel.ProcessName)
                ? $"🚫 Ignore process '{sel.ProcessName}'"
                : "🚫 Ignore process (no row selected)";

            // Block items tell the current state: flip to Unblock when a
            // block exists, and explain (disabled) when it is only paused —
            // re-blocking a paused target would silently not block anything.
            bool validIp = sel != null && System.Net.IPAddress.TryParse(sel.RemoteIp, out _);
            if (validIp && sel.IpBlockState == BlockRuleState.Active)
            {
                BlockIpMenuItem.IsEnabled = true;
                BlockIpMenuItem.Header = $"✅ Unblock remote IP {sel.RemoteIp} — traffic resumes";
            }
            else if (validIp && sel.IpBlockState == BlockRuleState.Paused)
            {
                BlockIpMenuItem.IsEnabled = false;
                BlockIpMenuItem.Header = $"⏸ IP block for {sel.RemoteIp} is paused — re-enable from 'Blocked' → Manage all";
            }
            else
            {
                BlockIpMenuItem.IsEnabled = validIp;
                BlockIpMenuItem.Header = validIp
                    ? $"⛔ Block remote IP {sel.RemoteIp} in Firewall"
                    : "⛔ Block Remote IP in Firewall";
            }

            bool blockableProcess = sel != null && sel.ProcessId > 0;
            if (blockableProcess && sel.ProcessBlockState == BlockRuleState.Active)
            {
                BlockProcessMenuItem.IsEnabled = true;
                BlockProcessMenuItem.Header = $"✅ Unblock process '{sel.ProcessName}' — traffic resumes";
            }
            else if (blockableProcess && sel.ProcessBlockState == BlockRuleState.Paused)
            {
                BlockProcessMenuItem.IsEnabled = false;
                BlockProcessMenuItem.Header = "⏸ Process block is paused — re-enable from 'Blocked' → Manage all";
            }
            else
            {
                BlockProcessMenuItem.IsEnabled = blockableProcess;
                BlockProcessMenuItem.Header = blockableProcess && !string.IsNullOrEmpty(sel.ProcessName)
                    ? $"⛔ Block process '{sel.ProcessName}' in Firewall"
                    : "⛔ Block Process in Firewall";
            }

            bool killable = sel != null && sel.ProcessId > 0;
            KillProcessMenuItem.IsEnabled = killable;
            KillProcessMenuItem.Header = killable && !string.IsNullOrEmpty(sel.ProcessName)
                ? $"💀 Kill process '{sel.ProcessName}' (PID {sel.ProcessId})"
                : "💀 Kill process";

            bool hasTask = sel != null && !string.IsNullOrEmpty(sel.TaskName);
            TaskDetailsMenuItem.IsEnabled = hasTask;
            TaskDetailsMenuItem.Header = hasTask
                ? $"📋 Scheduled task '{sel.TaskName}'"
                : "📋 Scheduled task details";
            DisableTaskMenuItem.IsEnabled = hasTask;
        }

        private void IgnoredListBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshIgnoredUi();
            IgnoredListPopup.IsOpen = true;
        }

        private void RemoveIgnoredBtn_Click(object sender, RoutedEventArgs e)
        {
            if (IgnoredListBox.SelectedItem is string name)
            {
                _sysmonService.RemoveIgnoredProcess(name);
                RefreshIgnoredUi();
            }
        }

        /// <summary>
        /// Hides a process name from the list: adds it to the persisted ignore
        /// list, then removes any rows already on screen for it.
        /// </summary>
        private void IgnoreProcess(string procName)
        {
            _sysmonService.AddIgnoredProcess(procName);
            PruneIgnoredRows();
            RefreshIgnoredUi();
        }

        /// <summary>Drops rows whose process is now ignored (list + packet counters).</summary>
        private void PruneIgnoredRows()
        {
            foreach (var item in _uiCollection.Where(i => _sysmonService.IsProcessIgnored(i.ProcessName)).ToList())
            {
                _uiCollection.Remove(item);
                _trackedIps.TryRemove(item.RemoteIp, out _);
            }
        }

        private void RefreshIgnoredUi()
        {
            var ignored = _sysmonService.IgnoredProcesses;
            IgnoredListBtn.Content = $"Ignored: {ignored.Count}";
            IgnoredListBox.ItemsSource = ignored.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        }

        private void SvchostGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            // Right-click selects the row under the cursor so the "Ignore
            // process" menu item knows which process was meant.
            if (e.OriginalSource is DependencyObject source &&
                ItemsControl.ContainerFromElement(SvchostGrid, source) is DataGridRow row)
            {
                row.IsSelected = true;
            }
        }

        private void SvchostGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // Double-clicking a row opens the spawn-chain trace — the same
            // PID inquiry as the context menu's "Trace" item. Clicks on
            // column headers or empty space fall through to nothing.
            if (e.OriginalSource is DependencyObject source &&
                ItemsControl.ContainerFromElement(SvchostGrid, source) is DataGridRow row &&
                row.Item is SvchostMonitorItem item)
            {
                row.IsSelected = true;
                OpenPidTrace(item.ProcessId, item);
            }
        }

        // -----------------------------------------------------------------------
        // PID inquiry — provenance tracing ("how was this spawned?")
        // -----------------------------------------------------------------------

        private void TracePidMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is SvchostMonitorItem item)
                OpenPidTrace(item.ProcessId, item);
        }

        private void WslDiagnosisMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var win = new WslDiagnosisWindow { Owner = Window.GetWindow(this) };
            win.Show();
        }

        // -----------------------------------------------------------------------
        // Traffic Peek — peer into what a connection carries
        // -----------------------------------------------------------------------

        private void PeerMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item ||
                string.IsNullOrEmpty(item.RemoteIp))
                return;

            OpenIpPeekWindow(item.RemoteIp, item.ProcessName, item.ProcessId, item.HostedServicesCsv, item.Hostname);
        }

        private void ProgramPeekMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || item.ProcessId <= 0)
                return;
            OpenProgramPeekWindow(item.ProcessId, item.ImagePath ?? item.ProcessName, item.ProcessName, item.HostedServicesCsv, item.Hostname);
        }

        private void TrackServiceMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;
            string service = FirstService(item.HostedServicesCsv);
            if (string.IsNullOrEmpty(service)) return;
            OpenServicePeekWindow(service, item.ProcessName, item.HostedServicesCsv, item.Hostname);
        }

        /// <summary>The first SCM-resident service name on a svchost row.</summary>
        private static string FirstService(string hostedServicesCsv)
        {
            if (string.IsNullOrWhiteSpace(hostedServicesCsv)) return null;
            foreach (var part in hostedServicesCsv.Split(','))
                if (!string.IsNullOrWhiteSpace(part)) return part.Trim();
            return null;
        }

        // One peek window per subject: a second request focuses the existing
        // window instead of stacking two captures on the same subject. The
        // key names the scope ("ip:x" · "pid:N" · "svc:name").
        private ConnectionPeekWindow OpenOrFocus(string key, Func<ConnectionPeekWindow> create)
        {
            if (_peekWindows.TryGetValue(key, out var existing))
            {
                if (existing != null && existing.IsLoaded)
                {
                    existing.Activate();
                    return existing;
                }
                _peekWindows.Remove(key);
            }
            var win = create();
            win.Closed += (_, _) => _peekWindows.Remove(key);
            _peekWindows[key] = win;
            win.Show();
            return win;
        }

        private ConnectionPeekWindow OpenIpPeekWindow(
            string remoteIp, string processName, int pid, string hostedServices, string hostname) =>
            OpenOrFocus($"ip:{remoteIp}", () => new ConnectionPeekWindow(
                remoteIp, processName, pid, hostedServices, hostname)
            {
                Owner = Window.GetWindow(this)
            });

        /// <summary>
        /// Opens (or focuses) the program-scoped peek for a PID. Public so
        /// Launch-under-watch can point a fresh window at the instance it
        /// just started, from inside any peek window.
        /// </summary>
        public ConnectionPeekWindow OpenProgramPeekWindow(
            int pid, string image, string processName,
            string hostedServices = null, string hostname = null) =>
            OpenOrFocus($"pid:{pid}", () => new ConnectionPeekWindow(
                pid, image, processName, hostedServices, hostname)
            {
                Owner = Window.GetWindow(this)
            });

        /// <summary>
        /// Opens (or focuses) a service-scoped peek. The window follows the
        /// service across restarts: the scope is the service NAME, so every
        /// future svchost instance hosting it is tracked with no user action.
        /// </summary>
        public ConnectionPeekWindow OpenServicePeekWindow(
            string service, string processName, string hostedServices = null, string hostname = null) =>
            OpenOrFocus($"svc:{service}", () => new ConnectionPeekWindow(
                AutoCommand.Engines.Watch.PeekScope.NewServiceScope(service), service, processName, 0,
                hostedServices, hostname)
            {
                Owner = Window.GetWindow(this)
            });

        /// <summary>
        /// Opens the read-only PID inquiry window. Row hints (name, Sysmon
        /// image path, task attribution) travel along so the report stays
        /// meaningful even when the process has already exited.
        /// </summary>
        private void OpenPidTrace(int pid, SvchostMonitorItem item)
        {
            if (pid <= 0)
            {
                MessageBox.Show("The System/Idle process has no spawn chain to trace.",
                    "PID Inquiry", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var win = new ProcessTraceWindow(
                pid,
                item?.ProcessName,
                item?.ImagePath,
                item != null ? _taskAttribution.GetTaskForPid(pid, item.ProcessStartedUtc) : null,
                item?.LastSeen,          // hints are as-of the last traffic sighting (UTC)
                item?.ProcessStartedUtc) // capture-time process start — strongest tenant check
            {
                Owner = Window.GetWindow(this)
            };
            // Trace→row loop: whatever the inquiry establishes about
            // identity flows back onto the row (RevealFromReport below) —
            // until now that finding died with the window.
            win.ReportCollected += report => Dispatcher.Invoke(() => RevealFromReport(item, report));
            win.Show();
        }

        /// <summary>
        /// Writes a PID Inquiry's resolved identity back onto its row.
        /// Skipped when the report describes a different tenant of the PID
        /// than the row anchors (start times disagree by more than the
        /// 5-second capture tolerance) — then the finding belongs to some
        /// other process, not this row.
        /// </summary>
        private void RevealFromReport(SvchostMonitorItem item, ProvenanceReport report)
        {
            if (item == null || report == null || string.IsNullOrEmpty(report.ExePath)) return;
            if (item.ProcessStartedUtc.HasValue && report.Created.HasValue &&
                (report.Created.Value.ToUniversalTime() - item.ProcessStartedUtc.Value).Duration() > TimeSpan.FromSeconds(5))
                return;
            string parent = report.Chain.Count > 1
                ? (report.Chain[1].ExePath ?? report.Chain[1].Name)
                : null;
            item.RevealIdentity(report.ExePath, report.ExePath, parent);
        }

        /// <summary>
        /// Context-menu reveal: recovers the row's true identity from the
        /// Sysmon archive — the same anchored recovery the PID Inquiry
        /// performs — and corrects the row in place. For rows named by a
        /// recycled PID, never named at all, or just to learn the parent.
        /// </summary>
        private async void RevealNameMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || item.ProcessId <= 0) return;

            var records = await Task.Run(() =>
                SysmonArchiveService.SearchCreateEvents(item.ProcessId, 12));
            var rec = PickBestCreateRecord(records, item);
            if (rec == null || !rec.Data.TryGetValue("Image", out string image) || string.IsNullOrEmpty(image))
            {
                ShowToast($"🏷 No Sysmon create-event found for PID {item.ProcessId} — nothing to reveal.\n" +
                          "The live-log attempt may still know more: '🔎 Trace: how was this PID spawned?'.");
                return;
            }

            rec.Data.TryGetValue("ParentImage", out string parent);
            string before = item.ProcessName;
            item.RevealIdentity(image, image, parent);

            string toast = string.Equals(before, item.ProcessName, StringComparison.OrdinalIgnoreCase)
                ? $"🏷 Confirmed '{item.ProcessName}' is the real name (Sysmon record)."
                : $"🏷 Real name revealed: '{item.ProcessName}'" +
                  (string.IsNullOrEmpty(before) ? "." : $" — the row previously showed '{before}'.");
            if (!string.IsNullOrEmpty(parent))
                toast += $"\nSpawned by {System.IO.Path.GetFileName(parent)}.";
            ShowToast(toast);
        }

        /// <summary>
        /// One archive-backed identity attempt for rows whose name never
        /// resolved (process gone before any lookup, event without an
        /// image). One-shot per row via TryBeginNameProbe: the day-file
        /// scan is real disk work, and the archive does not grow
        /// backwards — a miss will stay a miss.
        /// </summary>
        private async void EnrichWithRevealedName(SvchostMonitorItem item)
        {
            if (!item.NeedsNameReveal || !item.TryBeginNameProbe()) return;

            var records = await Task.Run(() =>
                SysmonArchiveService.SearchCreateEvents(item.ProcessId, 12));
            var rec = PickBestCreateRecord(records, item);
            if (rec == null) return;
            if (!rec.Data.TryGetValue("Image", out string image) || string.IsNullOrEmpty(image)) return;
            rec.Data.TryGetValue("ParentImage", out string parent);
            item.RevealIdentity(image, image, parent);
        }

        // -----------------------------------------------------------------------
        // Firewall blocking (remote IP / process)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Builds the v3 block record from everything the monitor row knows
        /// RIGHT NOW — the moment identity is richest. The PID dies later;
        /// the record must not.
        /// </summary>
        private static BlockRecord BuildBlockRecord(SvchostMonitorItem item, string kind, string key)
        {
            string serviceKey = "", display = "";
            string attrib = "none";

            if (item != null && item.IsSvchost)
            {
                // Identity preference: the -s declared single tenant, then the
                // first SCM-resident service, then the -k group, then unknown.
                string csv = item.HostedServicesCsv;
                string declared = item.DeclaredService;
                if (!string.IsNullOrEmpty(declared))
                    serviceKey = declared.ToLowerInvariant();
                else if (!string.IsNullOrEmpty(csv))
                    serviceKey = csv.Split(',')[0].Trim().ToLowerInvariant();
                else if (!string.IsNullOrEmpty(item.SvchostGroup))
                    serviceKey = "svchost:" + item.SvchostGroup.ToLowerInvariant();
                if (serviceKey.Length > 0 && serviceKey != "svchost:unresolved")
                    attrib = "live";
                if (serviceKey.Length == 0) serviceKey = "svchost:unresolved";
            }
            else if (item != null && !string.IsNullOrEmpty(item.ProcessName) &&
                     !item.ProcessName.StartsWith("<", StringComparison.Ordinal))
            {
                serviceKey = System.IO.Path.GetFileNameWithoutExtension(item.ProcessName).ToLowerInvariant();
                attrib = "catalog";
            }

            if (serviceKey.Length > 0)
                display = ServiceCatalog.TryGet(serviceKey, out var c) ? c.DisplayName : "";

            return new BlockRecord
            {
                Kind = kind,
                Key = key,
                ProcessName = item?.ProcessName ?? "",
                CreatedUtc = DateTime.UtcNow,
                ServiceKey = serviceKey,
                SvcDisplayName = display,
                ClassAtBlock = kind == "ip"
                    ? IpClassifier.Classify(key)
                    : BlocksStore.ClassForPath(key),
                Origin = "monitor",
                Attrib = attrib,
                Status = "on",
                StatusUtc = DateTime.UtcNow,
            };
        }

        private async void BlockRemoteIP_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;

            string ip = item.RemoteIp;
            if (!System.Net.IPAddress.TryParse(ip, out _))
            {
                MessageBox.Show($"'{ip}' is not a valid IP address.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // The menu flips to "Unblock" once a block exists — the same
            // item removes it again.
            if (item.IpBlockState == BlockRuleState.Active)
            {
                await ConfirmAndRemoveBlockAsync("ip", ip);
                return;
            }
            if (item.IpBlockState == BlockRuleState.Paused)
            {
                ShowToast($"⏸ The block for {ip} is paused (traffic flows). Re-enable it from 'Blocked' → Manage all.");
                return;
            }

            string msWarning = IpClassifier.WarningText(ip); // "" when not Microsoft infrastructure
            bool msApplies = msWarning.Length > 0;

            // Per-class suppression: the prompt is skipped only when the
            // generic confirm AND (if applicable) the Microsoft-infra warning
            // are both silenced — a silenced generic confirm still shows the
            // dialog when the infra warning itself is not silenced.
            bool confirmSuppressed =
                ConfirmPrefs.IsSuppressed(ConfirmPrefs.ConfirmIp) &&
                (!msApplies || ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnMsInfra));

            if (!confirmSuppressed)
            {
                string warning = msApplies && !ConfirmPrefs.IsSuppressed(ConfirmPrefs.WarnMsInfra)
                    ? msWarning + "\n\n⚠ Think twice: this IP is Microsoft infrastructure."
                    : "";
                string procName = item.ProcessName;
                string footer =
                    "2 rules are created: outbound TCP and UDP — inbound is already covered by the\n" +
                    "firewall's stateful filtering.\n" +
                    "Undo anytime: the Undo button on the toast, right-click this row again,\nor 'Blocked' → Manage all.";
                string initialDetail = $"Contacted by '{procName}'.\n\n⏳ Loading recent 6-hour activity…\n\n" + footer;
                // Stream the archive/provenance brief into the open dialog so
                // clicking "Block Remote IP" opens the window in <16 ms instead
                // of stalling 1–3 s while scanning 6 h of Sysmon archives.
                var briefTask = Task.Run(() =>
                {
                    string brief = AutoCommand.Forensics.Core.BlockFeedbackService.Brief(procName, ip);
                    return $"Contacted by '{procName}'.\n\n" + brief + (brief.Length > 0 ? "\n" : "") + footer;
                });
                // The checkbox silences the highest-severity thing on screen:
                // the infra warning when present, otherwise the plain confirm.
                string key = warning.Length > 0 ? ConfirmPrefs.WarnMsInfra : ConfirmPrefs.ConfirmIp;
                string label = warning.Length > 0
                    ? "Don't warn me about Microsoft-infrastructure IPs — I know what I'm doing"
                    : "Don't ask again before blocking remote IPs";
                if (!ConfirmBlockWithDialog($"Block all outbound traffic to remote IP {ip}?", warning, initialDetail, key, label, briefTask))
                    return;
            }

            try
            {
                string note = BuildProvenance(item, $"→ {ip}", confirmSuppressed);
                var (created, updated) = await FirewallService.Instance.AddIpBlockAsync(ip, note);
                RecordBlockedEntry(item, "ip", ip);
                ApplyOptimisticBlock("ip", ip, note);
                _ = FirewallBaselineManager.AdoptLiveBlockRulesAsync();
                _ = RefreshBlockStateFromFirewallAsync();
                ShowToast(created > 0
                        ? $"⛔ Blocked remote IP {ip} — 2 rules (outbound TCP/UDP).\nProvenance written to the rule description (visible in wf.msc)."
                        : $"Block for {ip} already existed — refreshed its provenance (no duplicate rules).",
                    "ip", ip);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to block remote IP: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void BlockProcess_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;

            if (item.ProcessId == 0)
            {
                MessageBox.Show("Cannot block System/Idle process.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // A process that "ran away" (already exited) is still blockable:
            // the firewall rule matches the exe path and arms for the next
            // run. The only real problems are recovering that path and never
            // mistaking a recycled PID's new tenant for the suspect.
            var target = await ResolveBlockTargetAsync(item);
            string path = target.Path;
            if (string.IsNullOrEmpty(path))
            {
                MessageBox.Show(
                    $"'{item.ProcessName}' (PID {item.ProcessId}) already exited, and its executable path could not be recovered:\n" +
                    "the row carries no Sysmon image path and the 30-day archive holds no create-event for this PID.\n\n" +
                    "Firewall rules match a full path, so there is nothing to arm the block on.\n" +
                    (string.IsNullOrEmpty(item.RemoteIp)
                        ? ""
                        : "You can still act on the infrastructure it used: right-click the row →\n" +
                          $"'⛔ Block Remote IP in Firewall' for {item.RemoteIp}.\n") +
                    "'🔎 Trace: how was this PID spawned?' shows everything recorded about the exited process.",
                    "Process already exited — cannot block", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (item.ProcessBlockState == BlockRuleState.Active)
            {
                await ConfirmAndRemoveBlockAsync("proc", path);
                return;
            }
            if (item.ProcessBlockState == BlockRuleState.Paused)
            {
                ShowToast($"⏸ The block for {path} is paused (traffic flows). Re-enable it from 'Blocked' → Manage all.");
                return;
            }

            string warning = "";
            bool wslWarning = WslIdentityService.IsWslFamilyProcess(item.ProcessName);
            if (wslWarning)
                warning = $"'{item.ProcessName}' belongs to the WSL family: in NAT mode this connection was\n" +
                          "made by a Linux process inside the WSL utility VM. Blocking the PROCESS takes down\n" +
                          "the VM's whole network — every distro, every Linux process. To stop one destination,\n" +
                          "block the remote IP instead (right-click → Block Remote IP).";
            else if (string.Equals(item.ProcessName, "svchost.exe", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(item.ProcessName, "taskhostw.exe", StringComparison.OrdinalIgnoreCase))
                warning = $"'{item.ProcessName}' hosts Windows SERVICES. One instance carries DNS (Dnscache),\n" +
                          "DHCP, diagnostics and more — blocking it is the #1 cause of 'I blocked something\n" +
                          "and lost my internet'. If a specific connection looks bad, block the IP, not this process.";
            else if (path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase))
                warning = $"'{item.ProcessName}' is a Windows component. Blocking it can break shell features,\n" +
                          "widgets, or web content in Start/Settings.";

            // Kernel/critical image guard — refuses the kernel outright (a
            // PID 4 row once produced a literal AC-BLOCK-APP System rule
            // that starved every kernel-mode socket) and escalates the
            // dialog for security-critical images like lsass.
            var guardDecision = BlockGuard.Decide(path, out string guardText);
            if (guardDecision == BlockGuard.Decision.Refuse)
            {
                MessageBox.Show(guardText, "Cannot block — kernel process",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (guardDecision == BlockGuard.Decision.Warn)
                warning = string.IsNullOrEmpty(warning) ? guardText : guardText + "\n\n" + warning;

            bool coreApplies = warning.Length > 0;
            string warnKey = wslWarning ? ConfirmPrefs.WarnWslFamily : ConfirmPrefs.WarnWindowsCore;
            bool confirmSuppressed =
                ConfirmPrefs.IsSuppressed(ConfirmPrefs.ConfirmProcess) &&
                (!coreApplies || ConfirmPrefs.IsSuppressed(warnKey));

            // The ran-away note is information, not a warning class: it rides
            // whichever surface the user sees (the dialog when a prompt is
            // due, otherwise the success toast) rather than adding a fifth
            // suppressible prompt.
            string exitedNote = target.SubjectExited
                ? "⚠ This process has already exited — the block is preventive:\n" +
                  "the rule takes effect on the exe's NEXT run. A copy of the exe at a\n" +
                  "different path is NOT covered." +
                  (target.ReuseNote != null ? $"\n⚠ {target.ReuseNote}." : "") +
                  (target.Source == BlockPathSource.Archive
                      ? "\nPath recovered from the Sysmon archive (create-event for this PID)."
                      : "") + "\n\n"
                : "";

            if (!confirmSuppressed)
            {
                string shownWarning = coreApplies && !ConfirmPrefs.IsSuppressed(warnKey) ? warning : "";
                string procName = item.ProcessName;
                string footer =
                    $"{path}\n\n(1 outbound rule)\n" +
                    "Undo anytime: the Undo button on the toast, right-click the row again,\nor 'Blocked' → Manage all.";
                string initialDetail = exitedNote + "⏳ Loading recent 6-hour activity…\n\n" + footer;
                // Pre-block brief: only run when the dialog is actually shown,
                // and stream asynchronously so the dialog opens immediately.
                var briefTask = Task.Run(() =>
                {
                    string brief = AutoCommand.Forensics.Core.BlockFeedbackService.Brief(procName);
                    return exitedNote + brief + (brief.Length > 0 ? "\n" : "") + footer;
                });
                string key = shownWarning.Length > 0 ? warnKey : ConfirmPrefs.ConfirmProcess;
                string label = shownWarning.Length > 0
                    ? (wslWarning
                        ? "Don't warn me about blocking WSL family processes — I know what I'm doing"
                        : "Don't warn me about blocking Windows service hosts / components — I know what I'm doing")
                    : "Don't ask again before blocking processes";
                if (!ConfirmBlockWithDialog(
                        target.SubjectExited
                            ? "Process already exited — block its executable for next time?"
                            : "Block all outbound network traffic for this process?",
                        shownWarning, initialDetail, key, label, briefTask))
                    return;
            }

            try
            {
                // Ran-away blocks say so in the rule description — auditable
                // in wf.msc that the rule was armed on an exited process and
                // where the path was recovered from.
                string tags = null;
                if (target.SubjectExited)
                {
                    if (target.ReuseNote != null) tags = "exited · pid-reused";
                    else if (target.Source == BlockPathSource.Archive) tags = "exited · path-from-archive";
                    else tags = "exited";
                }
                string note = BuildProvenance(item, $"app: {path}", confirmSuppressed, tags);
                var (created, updated) = await FirewallService.Instance.AddAppBlockAsync(path, note);
                RecordBlockedEntry(item, "proc", path);
                ApplyOptimisticBlock("proc", path, note);
                _ = FirewallBaselineManager.AdoptLiveBlockRulesAsync();
                _ = RefreshBlockStateFromFirewallAsync();
                string toast = created > 0
                    ? $"⛔ Blocked application (1 outbound rule):\n{path}"
                    : $"Block for {System.IO.Path.GetFileName(path)} already existed — provenance refreshed.";
                if (target.SubjectExited)
                    toast += "\nThe process had already exited — the rule arms its next run.";
                ShowToast(toast, "proc", path);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to block process: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Shows the block confirmation window (warning + "don't ask again"
        /// check-off). MessageBox cannot host the checkbox, hence the dialog;
        /// a checked box persists the per-class suppression immediately.
        /// </summary>
        private bool ConfirmBlockWithDialog(string headline, string warning, string detail,
                                            string suppressKey, string suppressLabel,
                                            Task<string> asyncDetailTask = null)
        {
            var win = new BlockConfirmWindow(headline, warning, detail, suppressKey, suppressLabel, asyncDetailTask)
            {
                Owner = Window.GetWindow(this)
            };
            if (win.ShowDialog() != true) return false;
            if (win.Suppress) ConfirmPrefs.Suppress(suppressKey);
            return true;
        }

        /// <summary>Full provenance embedded into the firewall rule Description.</summary>
        private static string BuildProvenance(SvchostMonitorItem item, string what, bool confirmSuppressed = false,
                                              string tags = null)
        {
            string host = "";
            try { host = item.HostnameDisplay is string h && h.Contains("…") == false && h != "resolving…" ? $" host {h}" : ""; } catch { }
            // svchost blocks say which service was actually blocked — the
            // identity survives in wf.msc even after the PID is recycled
            string svc = item.HasServiceIdentity ? $" [{item.IdentityLabel}]" : "";
            // Blocks made under a suppressed prompt say so — auditable later
            // in wf.msc that the standard confirmation was skipped
            return $"[blocked {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC] {item.ProcessName}{svc} PID {item.ProcessId} {what}{host} · " +
                   $"rx {item.RxBytesDisplay} tx {item.TxBytesDisplay}" +
                   $"{(string.IsNullOrEmpty(tags) ? "" : $" · {tags}")}" +
                   $"{(confirmSuppressed ? " · confirm-suppressed" : "")} · AutoCommand Process Monitor";
        }

        private void BlockedListBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshBlockedUi();
            BlockedListPopup.IsOpen = true;
        }

        private void ManageBlockedBtn_Click(object sender, RoutedEventArgs e)
        {
            BlockedListPopup.IsOpen = false;
            var win = new BlockedRulesWindow { Owner = Window.GetWindow(this) };
            // Unblock/re-enable there must be reflected in this grid's glyphs
            win.Closed += (s, args) => _ = RefreshBlockStateFromFirewallAsync();
            win.Show();
        }

        private async void UnblockBtn_Click(object sender, RoutedEventArgs e)
        {
            if (BlockedListBox.SelectedItem is not BlockRecord entry) return;
            await ConfirmAndRemoveBlockAsync(entry.Kind, entry.Key);
        }

        /// <summary>Asks once, then removes the block (rules + monitor record) and toasts the outcome.</summary>
        private async Task ConfirmAndRemoveBlockAsync(string kind, string key)
        {
            // Process blocks are a NAME family (AppBlockCoverageService keeps
            // a blocked exe covered at every path it runs from) — say so, so
            // the removal scope is never a surprise.
            string family = kind == "ip"
                ? ""
                : "\n\nThis lifts every path the executable is blocked from —\n" +
                  "coverage siblings included, or they would re-block it on its next run.";
            if (MessageBox.Show($"Remove the firewall block for\n{key}?\n\nIts rules are deleted and traffic resumes immediately.{family}",
                "Confirm Unblock", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            await RemoveBlockCoreAsync(kind, key);
        }

        /// <summary>Removes the firewall rules and the blocked.txt record; reports via toast.</summary>
        private async Task RemoveBlockCoreAsync(string kind, string key)
        {
            try
            {
                int removed = kind == "ip"
                    ? await FirewallService.Instance.RemoveBlockRulesForIpAsync(key)
                    : await FirewallService.Instance.RemoveBlockRulesForAppAsync(key);

                if (kind == "ip")
                {
                    BlocksStore.Remove(kind, key);
                }
                else
                {
                    // The removal above lifted the whole name family — drop
                    // the exe from the coverage cache (a spawn arriving before
                    // the next 30 s inventory refresh must not re-extend what
                    // this just lifted) and clear every sibling-path record.
                    string exeName = System.IO.Path.GetFileName(key);
                    AppBlockCoverageService.Instance.NotifyUnblocked(exeName);
                    BlocksStore.RemoveForExeName(exeName);
                }
                BlockGateService.Instance.ForgetTarget(kind == "ip" ? "ip" : "proc", key);
                RefreshBlockedUi();
                ApplyOptimisticUnblock(kind, key);
                _ = FirewallBaselineManager.AdoptLiveBlockRulesAsync();
                if (BlocksView.Current != null) _ = BlocksView.Current.RefreshIfLoadedAsync();

                // Verify against the live firewall before claiming success: a
                // surviving rule re-blocks on the next run, and "unblocked but
                // still reported blocked" must never be a silent outcome.
                var inventory = await FirewallService.Instance.GetBlockedInventoryAsync();
                await ApplyBlockedInventoryAsync(inventory);

                int surviving = kind == "ip"
                    ? inventory.Count(t => t.Kind == "ip" &&
                        string.Equals(t.Ip, key, StringComparison.OrdinalIgnoreCase) && t.EnabledRules > 0)
                    : inventory.Count(t => t.Kind == "app" && t.EnabledRules > 0 &&
                        string.Equals(System.IO.Path.GetFileName(t.AppPath ?? ""), System.IO.Path.GetFileName(key),
                                      StringComparison.OrdinalIgnoreCase));

                if (surviving > 0)
                {
                    ShowToast(removed > 0
                        ? $"⚠ {surviving} enabled rule(s) still cover {key} ({removed} removed) — the block persists. Check 'Blocked' → Manage all."
                        : $"⚠ Nothing was removed — {surviving} enabled rule(s) still cover {key}. Check 'Blocked' → Manage all.");
                }
                else
                {
                    ShowToast(removed > 0
                            ? $"✅ Unblocked {key} — {removed} firewall rule(s) removed, traffic resumes."
                            : $"No matching firewall rules found for {key} (already removed?).");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to unblock: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ResetConfirmPrefsBtn_Click(object sender, RoutedEventArgs e)
        {
            ConfirmPrefs.ResetAll();
            RefreshConfirmPrefsUi();
            ShowToast("↩ Confirmation prompts restored — blocks will ask again (each warning class, until re-suppressed).");
        }

        private async void KillProcess_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item) return;

            if (item.ProcessId == 0)
            {
                MessageBox.Show("Cannot kill System/Idle process.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                var proc = Process.GetProcessById(item.ProcessId);

                // PID reuse guard: the row may be stale — the original process
                // exited and Windows recycled the PID to something else.
                // Verify the live identity before pulling the trigger.
                string liveName = string.Empty;
                try { liveName = proc.ProcessName; } catch { }

                string knownName = Path.GetFileNameWithoutExtension(item.ProcessName ?? string.Empty);
                string confirmName = item.ProcessName;
                if (knownName.Length > 0 && !liveName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                {
                    confirmName = liveName;
                    var stale = MessageBox.Show(
                        $"This row is stale: PID {item.ProcessId} now runs '{liveName}', not '{item.ProcessName}'.\n\n" +
                        $"Kill the running process '{liveName}' (PID {item.ProcessId}) anyway?\n" +
                        "This forcefully terminates the application.",
                        "PID reused — confirm kill", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                    if (stale != MessageBoxResult.Yes) return;
                }
                else if (MessageBox.Show(
                    $"Kill process '{confirmName}' (PID {item.ProcessId})?\nThis forcefully terminates the application.",
                    "Confirm Kill", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                {
                    return;
                }

                proc.Kill();
                await Task.Delay(500); // Give it a moment to release ports
            }
            catch (ArgumentException)
            {
                MessageBox.Show($"Process {item.ProcessId} is no longer running (it already exited).",
                    "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to kill process: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void TaskDetails_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || string.IsNullOrEmpty(item.TaskName)) return;

            var (summary, error) = await TaskSchedulerService.Instance.GetTaskSummaryAsync(item.TaskName);

            // What code the task actually executes (COM-handler DLL), when
            // attribution has it — DLL tasks have no command line of their own
            var launch = _taskAttribution.GetTaskForPid(item.ProcessId, item.ProcessStartedUtc);
            if (launch?.HandlerClassId != null)
            {
                string handler = launch.HandlerDllExists == true
                    ? $"Handler DLL: {launch.HandlerDll} (CLSID {launch.HandlerClassId})"
                    : $"Handler CLSID {launch.HandlerClassId} is not registered — the task's DLL is gone (leftover of uninstalled software)";
                summary = string.IsNullOrEmpty(summary) ? handler : $"{handler}\n\n{summary}";
                error = null;
            }

            MessageBox.Show(
                string.IsNullOrEmpty(error)
                    ? summary
                    : $"Could not read task '{item.TaskName}': {error}",
                "Scheduled task", MessageBoxButton.OK,
                string.IsNullOrEmpty(error) ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }

        private async void DisableTask_Click(object sender, RoutedEventArgs e)
        {
            if (SvchostGrid.SelectedItem is not SvchostMonitorItem item || string.IsNullOrEmpty(item.TaskName)) return;

            if (MessageBox.Show(
                $"Disable scheduled task '{item.TaskName}'?\n\n" +
                "The task will not run again until it is re-enabled (Tasks tab, or:\n" +
                $"schtasks /Change /TN \"{item.TaskName}\" /ENABLE).\n\n" +
                "The running instance keeps going — use 'Kill process' to end it now.",
                "Confirm Disable Task", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            try
            {
                await TaskSchedulerService.Instance.SetTaskEnabledAsync(item.TaskName, false);
                MessageBox.Show($"Scheduled task disabled:\n{item.TaskName}", "Task Disabled",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to disable task: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Resolves an executable path for a PID; falls back to WMI when the
        /// process module cannot be read (bitness mismatch) or the process exited.
        /// </summary>
        private static string GetProcessPath(int processId)
        {
            try
            {
                using var proc = Process.GetProcessById(processId);
                string path = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(path)) return path;
            }
            catch { }

            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
                using var results = searcher.Get();
                foreach (System.Management.ManagementObject obj in results)
                {
                    return obj["ExecutablePath"]?.ToString();
                }
            }
            catch { }
            return null;
        }

        // -----------------------------------------------------------------------
        // Block-target resolution — "the suspect ran away" support
        // -----------------------------------------------------------------------

        private enum BlockPathSource { Live, Row, Archive }

        /// <summary>What BlockProcess_Click will arm the firewall rule on.</summary>
        private sealed class BlockTarget
        {
            /// <summary>Full exe path; null when unrecoverable (nothing to arm a rule on).</summary>
            public string Path;
            /// <summary>Where the path came from: live process, the row's Sysmon capture, or the archive.</summary>
            public BlockPathSource Source;
            /// <summary>True when the row's process is known dead (sticky exit flag, or a recycled PID proved it).</summary>
            public bool SubjectExited;
            /// <summary>Non-null when PID reuse was detected (the live tenant contradicts the row).</summary>
            public string ReuseNote;
        }

        /// <summary>
        /// Resolves the executable to block for a row, exited or not. Order:
        /// corroborated live lookup → the row's Sysmon image path → the
        /// 30-day archive's create-event. The live lookup is skipped
        /// entirely for exited rows and name-checked otherwise, so a
        /// recycled PID's new tenant can never end up blocked.
        /// </summary>
        private async Task<BlockTarget> ResolveBlockTargetAsync(SvchostMonitorItem item)
        {
            var t = new BlockTarget();

            if (item.HasExited)
            {
                t.SubjectExited = true;
            }
            else
            {
                string live = GetProcessPath(item.ProcessId);
                if (!string.IsNullOrEmpty(live))
                {
                    // Name cross-check — the kill flow's reuse guard, applied
                    // to blocking: the row can be up to one refresh tick
                    // (10 s) behind reality.
                    string liveName = System.IO.Path.GetFileName(live);
                    if (string.IsNullOrEmpty(item.ProcessName) ||
                        liveName.Equals(item.ProcessName, StringComparison.OrdinalIgnoreCase))
                    {
                        t.Path = live;
                        t.Source = BlockPathSource.Live;
                        return t;
                    }
                    t.SubjectExited = true;
                    t.ReuseNote = $"PID {item.ProcessId} now runs '{liveName}', not '{item.ProcessName}' — " +
                                  "the row's process exited and Windows recycled the number";
                }
                else if (string.IsNullOrEmpty(item.ImagePath))
                {
                    // Live lookup empty and no row path: the process most
                    // likely died between refresh ticks (HasExited lags) —
                    // let the archive decide before declaring it lost.
                    t.SubjectExited = true;
                }
            }

            // The row's identity survives exit — Sysmon captured the image
            // path at row creation exactly so dead rows stay blockable.
            if (!string.IsNullOrEmpty(item.ImagePath))
            {
                t.Path = item.ImagePath;
                t.Source = BlockPathSource.Row;
                return t;
            }

            // Last resort: the archive. A dead process's create-event IS its
            // identity — the same recovery the PID Inquiry performs.
            var records = await Task.Run(() =>
                SysmonArchiveService.SearchCreateEvents(item.ProcessId, 12));
            var best = PickBestCreateRecord(records, item);
            if (best != null && best.Data.TryGetValue("Image", out string image) &&
                !string.IsNullOrEmpty(image))
            {
                t.Path = image;
                t.Source = BlockPathSource.Archive;
            }
            return t;
        }

        /// <summary>
        /// Picks the create-record that belongs to the row's process when the
        /// archive holds several for the same (recycled) PID. Preference:
        /// start-time window ±5 s AND image match &gt; window &gt; image —
        /// ties keep the newest record (the list comes newest-first).
        /// </summary>
        private static ArchiveEvent PickBestCreateRecord(
            List<ArchiveEvent> records, SvchostMonitorItem item)
        {
            if (records == null || records.Count == 0) return null;
            ArchiveEvent best = null;
            int bestScore = -1;
            foreach (var rec in records)
            {
                bool imageMatch = !string.IsNullOrEmpty(item.ProcessName) &&
                                  rec.Data.TryGetValue("Image", out string img) &&
                                  System.IO.Path.GetFileName(img).Equals(item.ProcessName, StringComparison.OrdinalIgnoreCase);
                bool inWindow = item.ProcessStartedUtc.HasValue &&
                                (rec.TsUtc - item.ProcessStartedUtc.Value).Duration() <= TimeSpan.FromSeconds(5);
                int score = inWindow && imageMatch ? 3 : inWindow ? 2 : imageMatch ? 1 : 0;
                if (score > bestScore) { bestScore = score; best = rec; }
            }
            return best;
        }

        // -----------------------------------------------------------------------
        // Blocked-state marking — the firewall rules are the source of truth
        // -----------------------------------------------------------------------

        public Task RefreshBlockStateIfLoadedAsync() =>
            _isInitialized ? RefreshBlockStateFromFirewallAsync() : Task.CompletedTask;

        /// <summary>
        /// Immediately stamps newly blocked target rows on the UI thread (0 ms)
        /// while background firewall inventory reconciliation catches up.
        /// </summary>
        private void ApplyOptimisticBlock(string kind, string key, string note)
        {
            if (string.IsNullOrEmpty(key)) return;
            if (kind == "ip")
            {
                _pausedIps.Remove(key);
                _activeIps.Add(key);
                if (!string.IsNullOrEmpty(note))
                    _blockNotes["ip:" + key] = note;
            }
            else
            {
                string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(key);
                _pausedApps.Remove(key);
                _activeApps.Add(key);
                if (norm.Length > 0)
                {
                    _pausedApps.Remove(norm);
                    _activeApps.Add(norm);
                }
                if (!string.IsNullOrEmpty(note))
                {
                    _blockNotes["app:" + key.ToLowerInvariant()] = note;
                    if (norm.Length > 0)
                        _blockNotes["app:" + norm.ToLowerInvariant()] = note;
                }
            }

            foreach (var row in _uiCollection)
                ApplyBlockState(row);
        }

        /// <summary>
        /// Immediately clears unblocked target rows on the UI thread; the
        /// post-unblock inventory pass verifies no sibling rule survived.
        /// </summary>
        private void ApplyOptimisticUnblock(string kind, string key)
        {
            if (string.IsNullOrEmpty(key)) return;
            if (kind == "ip")
            {
                _activeIps.Remove(key);
                _pausedIps.Remove(key);
                _blockNotes.Remove("ip:" + key);
            }
            else
            {
                string exeName = System.IO.Path.GetFileName(key);
                _activeApps.RemoveWhere(p =>
                    string.Equals(p, key, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(System.IO.Path.GetFileName(p), exeName, StringComparison.OrdinalIgnoreCase));
                _pausedApps.RemoveWhere(p =>
                    string.Equals(p, key, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(System.IO.Path.GetFileName(p), exeName, StringComparison.OrdinalIgnoreCase));
            }

            foreach (var row in _uiCollection)
                ApplyBlockState(row);
        }

        /// <summary>
        /// Rebuilds the blocked-IP / blocked-app sets from the live firewall
        /// inventory (agent- and wf.msc-created blocks included, not just
        /// this monitor's), then re-marks every row. Concurrent triggers
        /// coalesce into one follow-up pass instead of dropping updates.
        /// </summary>
        private async Task RefreshBlockStateFromFirewallAsync()
        {
            if (_blockStateSyncing)
            {
                _blockStateResyncRequested = true;
                return;
            }

            _blockStateSyncing = true;
            try
            {
                do
                {
                    _blockStateResyncRequested = false;
                    var inventory = await FirewallService.Instance.GetBlockedInventoryAsync();
                    await ApplyBlockedInventoryAsync(inventory);
                }
                while (_blockStateResyncRequested);
            }
            finally
            {
                _blockStateSyncing = false;
            }
        }

        private async Task ApplyBlockedInventoryAsync(IList<BlockedTarget> inventory)
        {
            _activeIps.Clear(); _pausedIps.Clear();
            _activeApps.Clear(); _pausedApps.Clear();
            _blockNotes.Clear();

            if (inventory != null)
            {
                foreach (var t in inventory)
                {
                    if (t.Kind == "ip")
                    {
                        if (string.IsNullOrEmpty(t.Ip)) continue;
                        if (t.EnabledRules > 0) _activeIps.Add(t.Ip); else _pausedIps.Add(t.Ip);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(t.AppPath)) continue;
                        string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(t.AppPath);
                        if (t.EnabledRules > 0)
                        {
                            _activeApps.Add(t.AppPath);
                            if (norm.Length > 0) _activeApps.Add(norm);
                        }
                        else
                        {
                            _pausedApps.Add(t.AppPath);
                            if (norm.Length > 0) _pausedApps.Add(norm);
                        }
                        if (!string.IsNullOrEmpty(t.Description) && norm.Length > 0)
                            _blockNotes.TryAdd("app:" + norm.ToLowerInvariant(), t.Description);
                    }
                    if (!string.IsNullOrEmpty(t.Description))
                        _blockNotes[t.Key] = t.Description;
                }
            }

            // Resolve any missing live process paths off the UI thread when app
            // rules exist, so ApplyBlockState never stalls on Process.MainModule.
            if (_activeApps.Count > 0 || _pausedApps.Count > 0)
            {
                var missingPids = new List<int>();
                foreach (var item in _uiCollection)
                {
                    if (string.IsNullOrEmpty(item.ImagePath) && item.ProcessId > 0 &&
                        !item.HasExited && !_pidPathCache.ContainsKey(item.ProcessId))
                    {
                        missingPids.Add(item.ProcessId);
                    }
                }
                if (missingPids.Count > 0)
                {
                    var distinct = missingPids.Distinct().ToArray();
                    await Task.Run(() =>
                    {
                        foreach (int pid in distinct)
                        {
                            _pidPathCache[pid] = LiveProcessPath(pid) ?? "";
                        }
                    });
                }
            }

            await Dispatcher.InvokeAsync(() =>
            {
                foreach (var item in _uiCollection)
                    ApplyBlockState(item);
            });
        }

        /// <summary>Stamps one row's IP / process block state from the cached sets (pure in-memory, 0 I/O).</summary>
        private void ApplyBlockState(SvchostMonitorItem item)
        {
            string ip = item.RemoteIp ?? "";
            var ipState = _activeIps.Contains(ip) ? BlockRuleState.Active
                        : _pausedIps.Contains(ip) ? BlockRuleState.Paused
                        : BlockRuleState.None;
            _blockNotes.TryGetValue("ip:" + ip, out string ipNote);

            var appState = BlockRuleState.None;
            string appNote = null;
            if (_activeApps.Count > 0 || _pausedApps.Count > 0)
            {
                bool hasCachedPid = _pidPathCache.TryGetValue(item.ProcessId, out string cached);
                string appPath = !string.IsNullOrEmpty(item.ImagePath)
                    ? item.ImagePath
                    : cached;

                if (!string.IsNullOrEmpty(appPath))
                {
                    appState = _activeApps.Contains(appPath) ? BlockRuleState.Active
                             : _pausedApps.Contains(appPath) ? BlockRuleState.Paused
                             : BlockRuleState.None;
                    if (appState == BlockRuleState.None && (appPath.Contains("..") || appPath.Contains('%')))
                    {
                        string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(appPath);
                        if (norm.Length > 0)
                        {
                            appState = _activeApps.Contains(norm) ? BlockRuleState.Active
                                     : _pausedApps.Contains(norm) ? BlockRuleState.Paused
                                     : BlockRuleState.None;
                        }
                    }
                    if (!_blockNotes.TryGetValue("app:" + appPath.ToLowerInvariant(), out appNote))
                    {
                        string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(appPath);
                        if (norm.Length > 0)
                            _blockNotes.TryGetValue("app:" + norm.ToLowerInvariant(), out appNote);
                    }
                }
                else if (!hasCachedPid && item.ProcessId > 0 && !item.HasExited)
                {
                    int pid = item.ProcessId;
                    _pidPathCache[pid] = ""; // claim once so concurrent calls don't fan out
                    _ = Task.Run(() => LiveProcessPath(pid)).ContinueWith(t =>
                    {
                        if (t.Status == TaskStatus.RanToCompletion && !string.IsNullOrEmpty(t.Result))
                        {
                            _pidPathCache[pid] = t.Result;
                            Dispatcher.BeginInvoke(new Action(() => ApplyBlockState(item)));
                        }
                    });
                }
            }

            item.SetBlockState(ipState, ipNote, appState, appNote);
        }

        /// <summary>Cheap live module path (no WMI fallback — the periodic sync must stay fast).</summary>
        private static string LiveProcessPath(int pid)
        {
            if (pid <= 0) return null;
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.MainModule?.FileName;
            }
            catch { return null; }
        }

        // -----------------------------------------------------------------------
        // Non-modal block feedback (message + Undo, auto-hides)
        // -----------------------------------------------------------------------

        private void ShowToast(string message, string undoKind = null, string undoKey = null)
        {
            BlockToastText.Text = message;
            _toastUndoKind = undoKind;
            _toastUndoKey = undoKey;
            BlockToastUndoBtn.Visibility = undoKind != null ? Visibility.Visible : Visibility.Collapsed;
            BlockToast.Visibility = Visibility.Visible;
            _toastTimer.Stop();
            _toastTimer.Start();
        }

        private void HideToast()
        {
            _toastTimer.Stop();
            BlockToast.Visibility = Visibility.Collapsed;
            _toastUndoKind = null;
            _toastUndoKey = null;
        }

        private async void BlockToastUndo_Click(object sender, RoutedEventArgs e)
        {
            if (_toastUndoKind == null || _toastUndoKey == null) return;
            string kind = _toastUndoKind, key = _toastUndoKey;
            HideToast();
            await RemoveBlockCoreAsync(kind, key);
        }

        // -----------------------------------------------------------------------
        // Block records — BlocksStore v3 persistence (see BlocksStore.cs)
        // -----------------------------------------------------------------------

        private void RecordBlockedEntry(SvchostMonitorItem item, string kind, string key)
        {
            BlocksStore.AddOrUpdate(BuildBlockRecord(item, kind, key));
            RefreshBlockedUi();
        }

        private void LoadBlockedEntries()
        {
            BlocksStore.Load(); // migrates legacy blocked.txt files once, in place
            RefreshBlockedUi();
        }

        private void RefreshBlockedUi()
        {
            var records = BlocksStore.Records;
            BlockedListBtn.Content = $"Blocked: {records.Count}";
            BlockedListBox.ItemsSource = records
                .OrderBy(b => b.Kind).ThenBy(b => b.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
            RefreshConfirmPrefsUi();
        }

        /// <summary>Keeps the Blocked popup's suppression indicator honest.</summary>
        private void RefreshConfirmPrefsUi()
        {
            int n = ConfirmPrefs.SuppressedCount;
            SuppressedPromptsText.Text = n > 0
                ? $"{n} of 4 confirmation prompt(s) suppressed"
                : "All confirmation prompts active";
        }

        private void SaveCsvBtn_Click(object sender, RoutedEventArgs e)
        {
            SaveToCsv();
            MessageBox.Show($"Data saved to {_csvPath}", "Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void SaveToCsv()
        {
            try
            {
                // rolling, not append-forever: the hourly tick appends the
                // whole live table, so the file grows O(rows × hours) — past
                // ~5 MB rotate once to a single ".1" and start fresh
                Directory.CreateDirectory(Path.GetDirectoryName(_csvPath));
                if (File.Exists(_csvPath) && new FileInfo(_csvPath).Length > 5 * 1024 * 1024)
                {
                    string backup = _csvPath + ".1";
                    if (File.Exists(backup)) File.Delete(backup);
                    File.Move(_csvPath, backup);
                }

                bool writeHeader = !File.Exists(_csvPath);
                using var writer = new StreamWriter(_csvPath, true);

                if (writeHeader)
                {
                    writer.WriteLine("Timestamp,PID,ProcessName,RemoteIP,Host,RxPackets,TxPackets,RxBytes,TxBytes,LastSeen");
                }

                string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                // cap the window: rows not seen for 7 days stopped being
                // signal long ago — never-seen rows (default LastSeen) drop
                // out on the same comparison
                var cutoff = DateTime.UtcNow.AddDays(-7);
                var snap = _trackedIps.Values.Where(i => i.LastSeen >= cutoff).ToList();

                foreach (var item in snap)
                {
                    writer.WriteLine($"{ts},{item.ProcessId},{item.ProcessName},{item.RemoteIp},{item.Hostname},{item.RxPackets},{item.TxPackets},{item.RxBytes},{item.TxBytes},{item.LastSeen:u}");
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => MessageBox.Show($"Failed to save CSV: {ex.Message}"));
            }
        }

        public string GetAuditContext()
        {
            var items = _uiCollection.ToList();
            if (items.Count == 0) return "Process Monitor is currently empty. No active connections tracked.";

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Currently Tracked Processes and Connections:");
            foreach (var item in items)
            {
                sb.AppendLine($"- Process: {item.ProcessName}{(item.HasServiceIdentity ? $" [{item.IdentityLabel}]" : "")} (PID: {item.ProcessId}{(item.HasExited ? ", exited" : "")}) | Remote IP: {item.RemoteIp} ({item.Hostname}) | Packets: {item.TxPackets} sent, {item.RxPackets} received | Last Seen: {item.LastSeen:u}");
            }
            return sb.ToString();
        }
    }
}
