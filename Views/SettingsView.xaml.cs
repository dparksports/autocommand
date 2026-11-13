using System;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using AutoCommand.Services;
using AutoCommand.Engines.Core;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    public partial class SettingsView : UserControl
    {
        private const string TaskName = FreshSetupService.StartupTaskName;

        public SettingsView()
        {
            InitializeComponent();

            // Live version from the assembly instead of a hardcoded string
            // (same source as the status bar)
            VersionValueText.Text =
                FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "unknown";
        }

        private async void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            await CheckStartupTask();

            // Load Auto-Mitigate Adapters preference
            AutoMitigateAdaptersCheck.Checked -= AutoMitigateAdaptersCheck_Checked;
            AutoMitigateAdaptersCheck.Unchecked -= AutoMitigateAdaptersCheck_Unchecked;
            AutoMitigateAdaptersCheck.IsChecked = SecurityEnforcer.AutoMitigateAdapters;
            AutoMitigateAdaptersCheck.Checked += AutoMitigateAdaptersCheck_Checked;
            AutoMitigateAdaptersCheck.Unchecked += AutoMitigateAdaptersCheck_Unchecked;

            // Instrumentation cadences (replaces the old fixed check-rate combo)
            BuildInstrumentRows();

            // Load theme preference (Dark | Light)
            ThemeCombo.SelectionChanged -= ThemeCombo_SelectionChanged;
            foreach (var item in ThemeCombo.Items.OfType<ComboBoxItem>())
            {
                if (item.Tag is string tag && tag == ThemeService.Saved)
                {
                    item.IsSelected = true;
                    break;
                }
            }
            ThemeCombo.SelectionChanged += ThemeCombo_SelectionChanged;

            // Load Matrix animation visibility preference
            var mainWin = Window.GetWindow(this) as MainWindow ?? Application.Current?.MainWindow as MainWindow;
            ShowMatrixRainCheck.Checked -= ShowMatrixRainCheck_Changed;
            ShowMatrixRainCheck.Unchecked -= ShowMatrixRainCheck_Changed;
            ShowMatrixRainCheck.IsChecked = mainWin?.IsMatrixRainEnabled ?? true;
            ShowMatrixRainCheck.Checked += ShowMatrixRainCheck_Changed;
            ShowMatrixRainCheck.Unchecked += ShowMatrixRainCheck_Changed;

            // Protected-surface verdicts (SSTP / kernel debug): render now and
            // stay live on every enforcement sweep while this view is open.
            SecurityEnforcer.VerdictsUpdated -= OnVerdictsUpdated;
            SecurityEnforcer.VerdictsUpdated += OnVerdictsUpdated;
            RefreshSurfaceVerdicts();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.VerdictsUpdated -= OnVerdictsUpdated;
        }

        // ── protected surfaces (SSTP / kernel debug) ─────────────────────

        // Live machine truth from the enforcer sweeps — computed regardless of
        // allow-list state, so a whitelisted surface still shows its drift.
        private void OnVerdictsUpdated() => RefreshSurfaceVerdicts();

        private void RefreshSurfaceVerdicts()
        {
            SurfaceVerdict sstp = null, kdnet = null;
            foreach (var v in SecurityEnforcer.LastVerdicts)
            {
                if (v.Surface == SurfaceAssurance.SstpSurfaceName) sstp = v;
                else if (v.Surface == SurfaceAssurance.KdnetSurfaceName) kdnet = v;
            }

            SstpVerdictText.Text = sstp == null
                ? "SSTP service — first sweep pending…"
                : Describe(sstp);
            SstpVerdictText.Foreground = VerdictBrush(sstp);
            ReArmSstpBtn.Visibility = sstp != null && sstp.Allowed ? Visibility.Visible : Visibility.Collapsed;

            KdnetVerdictText.Text = kdnet == null
                ? "Kernel debug — first sweep pending…"
                : Describe(kdnet);
            KdnetVerdictText.Foreground = VerdictBrush(kdnet);
            ReArmKdnetBtn.Visibility = kdnet != null && kdnet.Allowed ? Visibility.Visible : Visibility.Collapsed;

            var notices = SecurityEnforcer.TamperNotices;
            if (notices.Count > 0)
            {
                AllowListStatusText.Text = "⚠ Allow-list tamper detected — enforcement re-armed. Last: " +
                                           notices[notices.Count - 1];
                AllowListStatusText.Visibility = Visibility.Visible;
            }
            else
            {
                AllowListStatusText.Visibility = Visibility.Collapsed;
            }
        }

        private static string Describe(SurfaceVerdict v)
        {
            string icon = v.Clean ? "✅" : (v.Allowed ? "🟡" : "🔴");
            string mode = v.Allowed ? " — whitelisted (drift recorded, NOT remediated)" : " — enforced";
            return $"{icon} {v.Surface}: {v.Summary}{mode} · verified {v.VerifiedUtc.ToLocalTime():HH:mm:ss}";
        }

        private Brush VerdictBrush(SurfaceVerdict v)
        {
            if (v == null) return (Brush)FindResource("TextSecondaryBrush");
            if (v.Clean) return new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0x6F)); // green
            if (v.Allowed) return new SolidColorBrush(Color.FromRgb(0xE5, 0xA5, 0x0A)); // amber
            return new SolidColorBrush(Color.FromRgb(0xE5, 0x6B, 0x56)); // red — drift while enforced
        }

        private void ReArmSstpBtn_Click(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.ReArm("sstp");
            RefreshSurfaceVerdicts();
        }

        private void ReArmKdnetBtn_Click(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.ReArm("kdnet");
            RefreshSurfaceVerdicts();
        }

        private void ThemeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ThemeCombo.SelectedItem is ComboBoxItem item && item.Tag is string theme)
            {
                ThemeService.ApplyTheme(theme);
            }
        }

        private void ShowMatrixRainCheck_Changed(object sender, RoutedEventArgs e)
        {
            var mainWin = Window.GetWindow(this) as MainWindow ?? Application.Current?.MainWindow as MainWindow;
            mainWin?.SetMatrixRainEnabled(ShowMatrixRainCheck.IsChecked == true);
        }

        // ── instrumentation calibration ──────────────────────────────────

        /// <summary>One row per registered instrument: on/off, calibrated
        /// cadence, live run stats, and the metronome's notes (auto-slow,
        /// last error). Rebuilt on load, on change and on demand.</summary>
        private void BuildInstrumentRows()
        {
            var rows = new List<object>();
            foreach (var s in InstrumentMetronome.Instance.Snapshot())
            {
                var panel = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };

                var head = new StackPanel { Orientation = Orientation.Horizontal };
                var chk = new CheckBox
                {
                    IsChecked = s.Enabled,
                    Tag = s.Spec.Id,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 8, 0),
                    ToolTip = "Run this instrument at all (persisted)",
                };
                chk.Click += InstrumentEnabled_Click;
                head.Children.Add(chk);
                head.Children.Add(new TextBlock
                {
                    Text = s.Spec.Name,
                    FontSize = 12,
                    FontWeight = FontWeights.SemiBold,
                    VerticalAlignment = VerticalAlignment.Center,
                    Foreground = (Brush)FindResource("TextPrimaryBrush"),
                });
                if (s.Spec.Cost == InstrumentCost.Heavy)
                    head.Children.Add(new TextBlock
                    {
                        Text = "  heavy",
                        FontSize = 11,
                        VerticalAlignment = VerticalAlignment.Center,
                        Foreground = (Brush)FindResource("AccentAmberBrush"),
                        ToolTip = "Serialized by the metronome — no two heavy instruments start within a second of each other.",
                    });
                panel.Children.Add(head);

                panel.Children.Add(new TextBlock
                {
                    Text = s.Spec.Description,
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                    Margin = new Thickness(20, 2, 0, 0),
                });

                panel.Children.Add(new TextBlock
                {
                    Text = s.Runs == 0
                        ? "not run yet"
                        : $"last run {(int)s.LastMs} ms · {s.Runs:N0} runs · every {s.Seconds}s" +
                          (s.Paused ? " · paused" : ""),
                    FontSize = 11,
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                    Margin = new Thickness(20, 2, 0, 0),
                });

                if (!string.IsNullOrEmpty(s.Note))
                    panel.Children.Add(new TextBlock
                    {
                        Text = "⚠ " + s.Note,
                        FontSize = 11,
                        TextWrapping = TextWrapping.Wrap,
                        Foreground = (Brush)FindResource("AccentAmberBrush"),
                        Margin = new Thickness(20, 2, 0, 0),
                    });

                var combo = new ComboBox
                {
                    Width = 190,
                    FontSize = 11,
                    Margin = new Thickness(20, 6, 0, 0),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Tag = s.Spec.Id,
                };
                foreach (int secs in InstrumentMetronome.CadenceChoices)
                {
                    if (secs != 0 && (secs < s.Spec.MinSeconds || secs > s.Spec.MaxSeconds)) continue;
                    var item = new ComboBoxItem
                    {
                        Content = secs == 0 ? "Off" : $"Every {secs} second{(secs == 1 ? "" : "s")}",
                        Tag = secs.ToString(),
                    };
                    combo.Items.Add(item);
                    if (s.Enabled ? s.Seconds == secs : secs == 0) item.IsSelected = true;
                }
                combo.SelectionChanged += InstrumentCadence_SelectionChanged;
                panel.Children.Add(combo);

                rows.Add(panel);
            }
            InstrumentsList.ItemsSource = rows;
            BuildDiskStats();
        }

        private void InstrumentEnabled_Click(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox chk && chk.Tag is string id)
                InstrumentMetronome.Instance.SetEnabled(id, chk.IsChecked == true);
        }

        private void InstrumentCadence_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is ComboBox combo && combo.Tag is string id &&
                combo.SelectedItem is ComboBoxItem item &&
                item.Tag is string tag && int.TryParse(tag, out int secs))
            {
                if (secs == 0)
                {
                    InstrumentMetronome.Instance.SetEnabled(id, false);
                }
                else
                {
                    InstrumentMetronome.Instance.SetCadence(id, secs, userSet: true);
                    InstrumentMetronome.Instance.SetEnabled(id, true);
                }
            }
        }

        private void ResetInstrumentsBtn_Click(object sender, RoutedEventArgs e)
        {
            InstrumentMetronome.Instance.ResetDefaults();
            BuildInstrumentRows();
        }

        private void RefreshInstrumentsBtn_Click(object sender, RoutedEventArgs e) => BuildInstrumentRows();

        // ── managed disk writes ─────────────────────────────────────────

        /// <summary>What the managed write buffers actually did: written
        /// totals, currently-pending bytes, and the top sinks by volume —
        /// the self-audit for the whole disk-write story.</summary>
        private void BuildDiskStats()
        {
            var stats = BufferedAppender.Stats();
            long written = stats.Sum(st => st.Item3);
            int pending = stats.Sum(st => st.Item2);
            string top = string.Join("  ·  ", stats
                .Where(st => st.Item3 > 0)
                .OrderByDescending(st => st.Item3)
                .Take(3)
                .Select(st => $"{System.IO.Path.GetFileName(st.Item1)} {st.Item3 / 1024.0:0.#} KB"));
            DiskStatsText.Text =
                $"flushed this session: {written / 1024.0:0.#} KB" +
                (pending > 0 ? $" · buffered now: {pending / 1024.0:0.#} KB" : "") +
                (top.Length > 0 ? "$\n{top}" : "");

            // reflect the persisted thrifty calibration
            bool thrifty = InstrumentMetronome.Instance.CadenceOf("disk-flush") >= 300;
            ThriftyDiskChk.IsChecked = thrifty;
            BufferedAppender.ThresholdBytes = thrifty ? 1024 * 1024 : 256 * 1024;
        }

        private void ThriftyDisk_Changed(object sender, RoutedEventArgs e)
        {
            if (ThriftyDiskChk.IsChecked == true)
            {
                InstrumentMetronome.Instance.SetCadence("disk-flush", 300, userSet: true);
                BufferedAppender.ThresholdBytes = 1024 * 1024;
            }
            else
            {
                InstrumentMetronome.Instance.SetCadence("disk-flush", 30, userSet: true);
                BufferedAppender.ThresholdBytes = 256 * 1024;
            }
            BuildDiskStats();
        }

        private void FlushDiskBtn_Click(object sender, RoutedEventArgs e)
        {
            BufferedAppender.FlushAll();
            AutoCommand.Contain.Core.BlocksStore.FlushPending();
            BuildDiskStats();
        }

        private void AutoMitigateAdaptersCheck_Checked(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.AutoMitigateAdapters = true;
        }

        private void AutoMitigateAdaptersCheck_Unchecked(object sender, RoutedEventArgs e)
        {
            SecurityEnforcer.AutoMitigateAdapters = false;
        }

        private async Task CheckStartupTask()
        {
            bool exists = false;
            await Task.Run(() =>
            {
                try
                {
                    Type tsType = Type.GetTypeFromProgID("Schedule.Service");
                    dynamic ts = Activator.CreateInstance(tsType);
                    ts.Connect();
                    dynamic rootFolder = ts.GetFolder("\\");
                    dynamic task = rootFolder.GetTask(TaskName);
                    exists = task != null;
                }
                catch
                {
                    exists = false;
                }
            });

            // Detach events to avoid infinite loop
            LaunchOnStartupCheck.Checked -= LaunchOnStartupCheck_Checked;
            LaunchOnStartupCheck.Unchecked -= LaunchOnStartupCheck_Unchecked;
            
            LaunchOnStartupCheck.IsChecked = exists;

            LaunchOnStartupCheck.Checked += LaunchOnStartupCheck_Checked;
            LaunchOnStartupCheck.Unchecked += LaunchOnStartupCheck_Unchecked;
        }

        private async void LaunchOnStartupCheck_Checked(object sender, RoutedEventArgs e)
        {
            bool ok = await FreshSetupService.EnableLaunchAtLogon();
            if (!ok)
                MessageBox.Show("Failed to create startup task.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            await CheckStartupTask();
        }

        private async void LaunchOnStartupCheck_Unchecked(object sender, RoutedEventArgs e)
        {
            await FreshSetupService.DisableLaunchAtLogon();
            await CheckStartupTask();
        }

        // -----------------------------------------------------------------------
        // Unblock (Mark-of-the-Web removal) — see Helpers/MotwUnblocker.cs
        // -----------------------------------------------------------------------

        private async void UnblockAppBtn_Click(object sender, RoutedEventArgs e)
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            UnblockAppBtn.IsEnabled = false;
            UnblockStatusText.Text = $"Scanning {dir} …";
            try
            {
                var result = await System.Threading.Tasks.Task.Run(() => MotwUnblocker.UnblockFolder(dir));
                UnblockStatusText.Text = result.Summary;
                if (result.Unblocked > 0)
                    MessageBox.Show(
                        $"Removed the download mark from {result.Unblocked} file(s) in this app's folder.\n\n" +
                        "SmartScreen / Smart App Control will no longer treat them as downloaded\n" +
                        "files — taskbar pins and direct launches work normally now.",
                        "Unblocked", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            finally
            {
                UnblockAppBtn.IsEnabled = true;
            }
        }

        private async void UnblockFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Pick the folder to unblock (e.g. a freshly extracted AutoCommand zip)"
            };
            if (dialog.ShowDialog() != true) return;

            UnblockFolderBtn.IsEnabled = false;
            UnblockStatusText.Text = $"Scanning {dialog.FolderName} …";
            try
            {
                var result = await System.Threading.Tasks.Task.Run(() => MotwUnblocker.UnblockFolder(dialog.FolderName));
                UnblockStatusText.Text = result.Summary;
                if (result.Failures.Count > 0)
                    MessageBox.Show(
                        $"{result.Summary}\n\nFiles in use or in admin-only locations could not be updated —\n" +
                        "close the apps using them, or re-run AutoCommand as Administrator and try again.",
                        "Unblock", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                UnblockFolderBtn.IsEnabled = true;
            }
        }

        // ── Community: the live anonymous count + share ─────────────────────

        private void CommunityGraph_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // The worker serves the graph page at its root; before the
                // endpoint is deployed, fall back to the releases page.
                string url = UsagePingService.GraphPageUrl ?? UsagePingService.ReleasesUrl;
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch { /* browser launch refused — nothing to do */ }
        }

        private void Share_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string url = UsagePingService.GraphPageUrl ?? UsagePingService.ReleasesUrl;
                Clipboard.SetText(url);
                ShareStatusText.Text = "Link copied — every install counts. Thank you!";
                var clear = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
                clear.Tick += (s, _) => { ShareStatusText.Text = ""; clear.Stop(); };
                clear.Start();
            }
            catch { /* clipboard unavailable — nothing to do */ }
        }
    }
}
