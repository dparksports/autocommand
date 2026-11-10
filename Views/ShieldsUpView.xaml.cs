using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ShieldsUp.Core.Services;

namespace AutoCommand.Views;

/// <summary>
/// The Shields Up tab: the standalone app's rituals as a left-side rail —
/// Quick Scan (the whole ritual as one checklist), Doors, Privacy, Junk
/// and Hardening — driven through the vendored ShieldsUp.Core services, the
/// same logic the WinUI shell calls, so the two faces cannot drift. The
/// firewall presets deliberately live in the Firewall tab (they were a
/// duplicate here). Every action confirms first; state rows re-read live
/// system state, never a cached verdict.
/// </summary>
public partial class ShieldsUpView : UserControl
{
    // The app's own green/amber/red accents (same hexes as the theme brushes;
    // resolved here because row models set Foreground in code).
    private static readonly Brush OkBrush = new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99));
    private static readonly Brush WarnBrush = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24));
    private static readonly Brush BadBrush = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));

    private readonly TelemetryRulesService _telemetry = new();
    private ObservableCollection<ScanRow> _scanRows;

    public ShieldsUpView()
    {
        InitializeComponent();
        Loaded += async (_, _) => await OnLoadedAsync();
    }

    private async Task OnLoadedAsync()
    {
        RestoreSubTab();
        RestoreRail();

        // Migration banner: the standalone app's state, offered once.
        if (StandaloneImport.HasLegacyState())
        {
            MigrationText.Text = StandaloneImport.IsStandaloneRunning()
                ? "A standalone Shields Up install left state on this machine, and the standalone app is running right now. Two apps flipping the same switches will fight — close it, then import its state here (edited bloatware list, telemetry revert history, freeze ledger) and delete the Shields Up folder."
                : "A standalone Shields Up install left state on this machine. Import it to keep your edited bloatware list, telemetry revert history and update-freeze ledger — then the Shields Up folder can be deleted.";
            MigrationBanner.Visibility = Visibility.Visible;
        }

        BuildQuickScanRows();
        await Task.WhenAll(
            RefreshDoorsAsync(),
            RefreshStartupAsync(),
            RefreshTelemetryAsync(),
            RefreshBloatwareAsync(),
            RefreshHardeningAsync(),
            QuickScanCheckAsync());
    }

    // ── helpers ─────────────────────────────────────────────────────────

    /// <summary>Every destructive action goes through here. No is the default
    /// button — Enter dismisses safely (same convention as Shields Up's
    /// Quick Scan master confirm).</summary>
    private bool Confirm(string text, string title) =>
        MessageBox.Show(Window.GetWindow(this), text, title,
            MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;

    private void ShowResult(TextBlock target, string message)
    {
        target.Text = message;
        target.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
    }

    // ── migration banner ────────────────────────────────────────────────

    private async void ImportBtn_Click(object sender, RoutedEventArgs e)
    {
        ImportBtn.IsEnabled = false;
        try
        {
            var report = await Task.Run(() => StandaloneImport.Import(ShieldsUp.Core.AppPaths.DataRoot));
            MigrationResultText.Text = report.DidAnything
                ? "Imported: " + string.Join(", ", report.Imported.Concat(report.Merged))
                : "Nothing to import — this machine's state is already in place.";
            MigrationBanner.Visibility = Visibility.Collapsed;
            await Task.WhenAll(RefreshDoorsAsync(), RefreshTelemetryAsync(), RefreshBloatwareAsync(), RefreshHardeningAsync());
        }
        finally
        {
            ImportBtn.IsEnabled = true;
        }
    }

    // ── quick scan ──────────────────────────────────────────────────────

    public sealed class ScanRow : System.ComponentModel.INotifyPropertyChanged
    {
        public string Title { get; init; }
        public string Chip { get; private set; } = "…";
        public Brush ChipBrush { get; private set; } = Brushes.Gray;
        public string Detail { get; private set; } = "not checked yet";

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        public void Set(string chip, Brush brush, string detail)
        {
            Chip = chip; ChipBrush = brush; Detail = detail;
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(string.Empty));
        }
    }

    private void BuildQuickScanRows()
    {
        _scanRows = new ObservableCollection<ScanRow>(
            QuickScanService.Steps.Select(s => new ScanRow { Title = s.Title }));
        QuickScanList.ItemsSource = _scanRows;
    }

    /// <summary>Verify-only pass: runs every step's Verify lambda and colors
    /// the row — the checklist doubles as a status dashboard.</summary>
    private async Task QuickScanCheckAsync()
    {
        var steps = QuickScanService.Steps.ToList();
        for (int i = 0; i < steps.Count; i++)
        {
            var row = _scanRows[i];
            try
            {
                var (ok, detail) = await steps[i].Verify();
                row.Set(ok ? "✓" : "⚠", ok ? OkBrush : WarnBrush, detail);
            }
            catch (Exception ex)
            {
                row.Set("⚠", WarnBrush, "check failed: " + ex.Message);
            }
        }
        SetQuickScanDot();
    }

    private async void QuickScanCheckBtn_Click(object sender, RoutedEventArgs e)
    {
        QuickScanCheckBtn.IsEnabled = false;
        try { await QuickScanCheckAsync(); }
        finally { QuickScanCheckBtn.IsEnabled = true; }
    }

    private async void QuickScanBtn_Click(object sender, RoutedEventArgs e)
    {
        var steps = QuickScanService.Steps.ToList();
        var summary = string.Join("\n", steps.Select(s => "• " + s.Title + " — " + s.Description));
        if (!Confirm("Quick Scan will apply every step that is not already done:\n\n" + summary +
                     "\n\nNothing runs without this confirmation. Continue?",
                     "Run Quick Scan"))
            return;

        QuickScanBtn.IsEnabled = false;
        QuickScanProgress.Visibility = Visibility.Visible;
        try
        {
            var progress = new Progress<string>(s => QuickScanProgress.Text = s);
            for (int i = 0; i < steps.Count; i++)
            {
                var row = _scanRows[i];
                row.Set("…", Brushes.Gray, "running…");
                try
                {
                    var (ok, detail) = await steps[i].Apply(progress);
                    row.Set(ok ? "✓" : "⚠", ok ? OkBrush : WarnBrush, detail);

                    // Trust the verify, not the apply: re-read live state.
                    var (vok, vdetail) = await steps[i].Verify();
                    if (!vok)
                        row.Set("⚠", WarnBrush, detail + " — but re-check says: " + vdetail);
                }
                catch (Exception ex)
                {
                    row.Set("✗", BadBrush, "failed: " + ex.Message);
                }
            }
            QuickScanProgress.Text = "Quick Scan finished. Re-check any row by reopening this tab or pressing Re-check status.";
            SetQuickScanDot();
        }
        finally
        {
            QuickScanBtn.IsEnabled = true;
            // Actions changed the machine — refresh every section's rows.
            await Task.WhenAll(RefreshDoorsAsync(), RefreshTelemetryAsync(), RefreshBloatwareAsync(), RefreshHardeningAsync());
        }
    }

    // ── doors ───────────────────────────────────────────────────────────

    private async Task RefreshDoorsAsync()
    {
        var (sstp, hosted, kdnet, vpn, miniports, wifidirect, llmnr, netbios, mdns) = await Task.Run(() =>
        (
            AttackSurfaceService.GetSstpStatus(),
            AttackSurfaceService.GetHostedNetworkStatus(),
            AttackSurfaceService.IsKernelDebugOn(),
            PrivacyService.GetVpnStatus(),
            AttackSurfaceService.ListWanMiniports(),
            PrivacyService.IsWifiDirectAdapterPresent(),
            NameResolutionDoors.GetLlmnrStatus(),
            NameResolutionDoors.GetNetbiosStatus(),
            NameResolutionDoors.GetMdnsStatus()
        ));

        bool sstpActive = sstp.Active;
        SstpStatusText.Text = sstp.StatusText == "NotFound"
            ? "SSTP service not installed — door closed ✓"
            : $"SstpSvc {sstp.StatusText} · startup: {sstp.StartMode}" + (sstpActive ? " — door open ⚠" : " — off ✓");
        SstpStatusText.Foreground = sstpActive ? WarnBrush : OkBrush;
        SstpToggleBtn.Content = sstpActive ? "Disable + neuter miniports" : "Re-enable service & miniports";

        bool hostedActive = hosted == "Started";
        HostedNetworkStatusText.Text = hosted switch
        {
            "Started" => "hosted network STARTED — ghost hotspot possible ⚠",
            "Not started" => "hosted network allowed but not started ⚠",
            "Not Available" => "hosted network not available ✓",
            _ => "hosted network state unknown"
        };
        HostedNetworkStatusText.Foreground = hostedActive ? WarnBrush : (hosted == "Not Available" ? OkBrush : WarnBrush);

        KdnetStatusText.Text = kdnet
            ? "Kernel Debug ENABLED — low-level memory exposed ⚠"
            : "Kernel debug disabled ✓";
        KdnetStatusText.Foreground = kdnet ? BadBrush : OkBrush;
        KdnetToggleBtn.Content = kdnet ? "Turn debug off" : "Turn debug on";

        var (running, total) = vpn;
        VpnStatusText.Text = running > 0
            ? $"{running} of {total} VPN service(s) running — potential attack surface ⚠"
            : $"All {total} VPN services stopped ✓";
        VpnStatusText.Foreground = running > 0 ? WarnBrush : OkBrush;

        MiniportStatusText.Text = miniports.Count == 0
            ? "no WAN Miniport adapters present ✓"
            : $"{miniports.Count} WAN Miniport adapter(s) present ⚠ — " +
              string.Join(", ", miniports.Take(4).Select(a => a.Name)) + (miniports.Count > 4 ? ", …" : "");
        MiniportStatusText.Foreground = miniports.Count == 0 ? OkBrush : WarnBrush;

        // legacy name-resolution doors (LLMNR · NetBIOS · mDNS)
        LlmnrStatusText.Text = llmnr.Evidence;
        LlmnrStatusText.Foreground = llmnr.Open ? WarnBrush : OkBrush;
        LlmnrToggleBtn.Content = llmnr.Open ? "Disable LLMNR" : "Re-enable LLMNR";

        bool nbClosed = netbios.State == NameResolutionDoors.NbState.Closed;
        NbnsStatusText.Text = netbios.Evidence;
        NbnsStatusText.Foreground = nbClosed ? OkBrush : WarnBrush;
        NbnsToggleBtn.Content = nbClosed ? "Re-enable NetBIOS" : "Disable NetBIOS";

        MdnsStatusText.Text = mdns.Evidence;
        MdnsStatusText.Foreground = mdns.Open ? WarnBrush : OkBrush;
        MdnsToggleBtn.Content = mdns.Open ? "Block mDNS" : "Unblock mDNS";

        // Rail dot: red when kernel debug is on (the one BadBrush row),
        // amber while any door stands open, green when all are closed.
        int openDoors = (sstpActive ? 1 : 0) + (hostedActive ? 1 : 0) + (kdnet ? 1 : 0)
            + (running > 0 ? 1 : 0) + (miniports.Count > 0 ? 1 : 0)
            + (llmnr.Open ? 1 : 0)
            + (netbios.State is NameResolutionDoors.NbState.None or NameResolutionDoors.NbState.Partial ? 1 : 0)
            + (mdns.Open ? 1 : 0);
        // total = every counted row above: remote-access five + the three
        // name-resolution doors
        int totalDoors = 8;
        if (kdnet)
        {
            SetDot(DoorsDot, BadBrush, "Kernel debug on — open Doors");
            SetPill(DoorsPillDot, DoorsPillText, BadBrush, "Kernel debug on — attention");
        }
        else if (openDoors > 0)
        {
            SetDot(DoorsDot, WarnBrush, openDoors + " door(s) open — open Doors");
            SetPill(DoorsPillDot, DoorsPillText, WarnBrush, openDoors + " of " + totalDoors + " open");
        }
        else
        {
            SetDot(DoorsDot, OkBrush, "All doors closed");
            SetPill(DoorsPillDot, DoorsPillText, OkBrush, "All " + totalDoors + " doors closed");
        }

        DoorActionResult.Visibility = Visibility.Collapsed;
    }

    private async void DoorsRefreshBtn_Click(object sender, RoutedEventArgs e)
    {
        DoorsRefreshBtn.IsEnabled = false;
        try { await RefreshDoorsAsync(); }
        finally { DoorsRefreshBtn.IsEnabled = true; }
    }

    private async void SstpToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        bool active = AttackSurfaceService.GetSstpStatus().Active;
        if (active && !Confirm(
                "This will stop the SSTP service and disable all VPN miniport adapters (SSTP, IKEv2, L2TP, PPTP, AgileVPN, NDISWAN).\n\nYou can re-enable them at any time with the same button.",
                "Disable SSTP & miniports"))
            return;

        SstpToggleBtn.IsEnabled = false;
        try
        {
            var failures = await Task.Run(() => active
                ? AttackSurfaceService.DisableSstp()
                : AttackSurfaceService.EnableSstp());
            ShowResult(DoorActionResult, failures is { Count: > 0 }
                ? "Some miniport adapters could not be " + (active ? "disabled" : "re-enabled") + ":\n" + string.Join("\n", failures)
                : active ? "SSTP disabled; miniports neutered (reversible)." : "SSTP service and miniports re-enabled.");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "SSTP toggle failed: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            SstpToggleBtn.IsEnabled = true;
        }
    }

    // ── legacy name-resolution doors (LLMNR · NetBIOS · mDNS) ────────────
    // Same contract as the other doors: confirm on the CLOSING direction
    // (re-open is the safe direction), act on a background thread, report
    // into the shared DoorActionResult line, refresh the board.

    private async void LlmnrToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        bool open = NameResolutionDoors.GetLlmnrStatus().Open;
        if (open && !Confirm(
                "Disable LLMNR (multicast name fallback, UDP 5355)?\n\nDNS misses will fail fast instead of asking every host on the LAN — this also kills the LLMNR-poisoning credential-theft class.\n\nReversible with the same button.",
                "Disable LLMNR"))
            return;
        LlmnrToggleBtn.IsEnabled = false;
        try
        {
            var failures = await Task.Run(() => open ? NameResolutionDoors.DisableLlmnr() : NameResolutionDoors.EnableLlmnr());
            ShowResult(DoorActionResult, failures.Count > 0
                ? "LLMNR toggle failed: " + string.Join("; ", failures)
                : open ? "LLMNR disabled (EnableMulticast=0, snapshotted — reversible)." : "LLMNR re-enabled (previous value restored).");
        }
        catch (Exception ex) { ShowResult(DoorActionResult, "LLMNR toggle failed: " + ex.Message); }
        finally { await RefreshDoorsAsync(); LlmnrToggleBtn.IsEnabled = true; }
    }

    private async void NbnsToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        var before = NameResolutionDoors.GetNetbiosStatus();
        if (before.State != NameResolutionDoors.NbState.Closed && !Confirm(
                "Disable NetBIOS name resolution (UDP 137 broadcasts) on every interface?\n\nLegacy NetBIOS-name SMB stops resolving (DNS and FQDNs keep working). Takes effect on adapter restart or reboot. Per-interface previous values are snapshotted — reversible.",
                "Disable NetBIOS"))
            return;
        NbnsToggleBtn.IsEnabled = false;
        try
        {
            var failures = await Task.Run(() => before.State == NameResolutionDoors.NbState.Closed
                ? NameResolutionDoors.EnableNetbios()
                : NameResolutionDoors.DisableNetbios());
            ShowResult(DoorActionResult, failures.Count > 0
                ? "NetBIOS toggle issues: " + string.Join("; ", failures)
                : before.State == NameResolutionDoors.NbState.Closed
                    ? "NetBIOS re-enabled (per-interface previous values restored)."
                    : "NetBIOS disabled on every interface (applies on adapter restart/reboot — snapshotted, reversible).");
        }
        catch (Exception ex) { ShowResult(DoorActionResult, "NetBIOS toggle failed: " + ex.Message); }
        finally { await RefreshDoorsAsync(); NbnsToggleBtn.IsEnabled = true; }
    }

    private async void MdnsToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        bool open = NameResolutionDoors.GetMdnsStatus().Open;
        if (open && !Confirm(
                "Block outbound mDNS multicast (UDP 5353) at the firewall?\n\n.local device discovery — printers, Chromecast, AirPlay — stops while closed. Windows has no source switch for mDNS, so this door is network-level only (the resolver itself stays on).\n\nReversible with the same button.",
                "Block mDNS"))
            return;
        MdnsToggleBtn.IsEnabled = false;
        try
        {
            var failures = await Task.Run(() => open ? NameResolutionDoors.DisableMdns() : NameResolutionDoors.EnableMdns());
            ShowResult(DoorActionResult, failures.Count > 0
                ? "mDNS toggle failed: " + string.Join("; ", failures)
                : open ? "mDNS multicast blocked (scoped firewall rule — reversible)." : "mDNS unblocked (scoped rule removed).");
        }
        catch (Exception ex) { ShowResult(DoorActionResult, "mDNS toggle failed: " + ex.Message); }
        finally { await RefreshDoorsAsync(); MdnsToggleBtn.IsEnabled = true; }
    }

    // ── Startup & Tasks (the persistence surface) ────────────────────────
    // Logon items (Run keys — snapshotted off by StartupSurfaceService;
    // Startup-folder shortcuts are shown but never touched by us) and
    // scheduled tasks (TaskSchedulerService COM). Third-party entries
    // lead; Windows inbox tasks are counted, not listed.

    private sealed class LogonRow { public string Name, Value, Location; public bool Folder; public bool DisabledByUs; }
    private sealed class TaskRow { public string TaskPath, TaskName, State, Action, User; }

    private Border MakeStartupRow(string title, string evidence, string actionLabel,
        object tag, RoutedEventHandler onClick, bool actionEnabled, string disabledToolTip = null)
    {
        var btn = new Button
        {
            Content = actionLabel,
            Style = (Style)FindResource("QuietBtn"),
            Tag = tag,
            Padding = new Thickness(14, 7, 14, 7),
            Margin = new Thickness(12, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            IsEnabled = actionEnabled,
            ToolTip = actionEnabled ? null : disabledToolTip,
        };
        btn.Click += onClick;
        var border = new Border
        {
            Style = (Style)FindResource("StatusRow"),
            Child = new Grid(),
        };
        var grid = (Grid)border.Child;
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock { Text = title, Style = (Style)FindResource("RowTitle") });
        stack.Children.Add(new TextBlock
        {
            Text = evidence,
            Style = (Style)FindResource("RowEvidence"),
            Margin = new Thickness(0, 2, 0, 0),
        });
        Grid.SetColumn(stack, 0);
        Grid.SetColumn(btn, 1);
        grid.Children.Add(stack);
        grid.Children.Add(btn);
        return border;
    }

    private async Task RefreshStartupAsync()
    {
        try
        {
            var logon = await Task.Run(() => AutoCommand.Helpers.RegistryHelper.GetStartupItems());
            var tasks = await AutoCommand.Forensics.Core.TaskSchedulerService.Instance.LoadTasksAsync();

            StartupLogonPanel.Children.Clear();
            var logonRows = new List<LogonRow>();
            foreach (var item in logon)
            {
                bool folder = ShieldsUp.Core.Services.StartupSurfaceService.KindOfLocation(item.Location)
                    == ShieldsUp.Core.Services.StartupSurfaceService.LogonKind.Folder;
                bool byUs = !folder && ShieldsUp.Core.Services.StartupSurfaceService.HasLogonSnapshot(item.Location, item.Name);
                var row = new LogonRow { Name = item.Name, Value = item.Value, Location = item.Location, Folder = folder, DisabledByUs = byUs };
                logonRows.Add(row);
                StartupLogonPanel.Children.Add(MakeStartupRow(
                    item.Name + (byUs ? "  · disabled by AutoCommand" : folder ? "" : ""),
                    $"{item.Value}\n{item.Location}",
                    folder ? "Manual" : byUs ? "Re-enable" : "Disable",
                    row,
                    StartupLogonToggle_Click,
                    !folder,
                    folder ? "Folder shortcut — remove it in the Startup folder if unwanted; AutoCommand only toggles registry entries." : null));
            }
            if (logonRows.Count == 0)
                StartupLogonPanel.Children.Add(new TextBlock { Text = "Nothing registered to run at logon ✓", Style = (Style)FindResource("RowEvidence"), Margin = new Thickness(8, 4, 0, 4) });

            StartupTaskPanel.Children.Clear();
            var thirdParty = tasks.Where(t => ShieldsUp.Core.Services.StartupSurfaceService.ClassifyTask(t.TaskPath)
                                              == ShieldsUp.Core.Services.StartupSurfaceService.TaskGroup.ThirdParty).ToList();
            foreach (var t in thirdParty.Take(40))
            {
                var row = new TaskRow { TaskPath = t.TaskPath, TaskName = t.TaskName, State = t.State, Action = t.Action, User = t.User };
                StartupTaskPanel.Children.Add(MakeStartupRow(
                    t.TaskName,
                    $"{t.State} · {t.Action}" + (string.IsNullOrWhiteSpace(t.User) ? "" : $" · {t.User}"),
                    t.State == "Disabled" ? "Enable" : "Disable",
                    row,
                    StartupTaskToggle_Click,
                    true));
            }
            if (thirdParty.Count == 0)
                StartupTaskPanel.Children.Add(new TextBlock { Text = "No third-party scheduled tasks ✓", Style = (Style)FindResource("RowEvidence"), Margin = new Thickness(8, 4, 0, 4) });
            else if (thirdParty.Count > 40)
                StartupTaskPanel.Children.Add(new TextBlock { Text = $"… and {thirdParty.Count - 40} more", Style = (Style)FindResource("RowEvidence"), Margin = new Thickness(8, 4, 0, 4) });

            int inbox = tasks.Count - thirdParty.Count;
            StartupInboxText.Text = inbox > 0
                ? $"{inbox} Windows inbox task(s) — maintained by Windows, not listed; each is reviewable from the Process Monitor's task attribution."
                : "";

            int active = logonRows.Count(r => !r.Folder && !r.DisabledByUs) + thirdParty.Count(t => t.State != "Disabled");
            if (active > 0)
            {
                SetDot(StartupDot, WarnBrush, active + " third-party autostart(s) — open Startup");
                SetPill(StartupPillDot, StartupPillText, WarnBrush, active + " third-party autostart(s)");
            }
            else
            {
                SetDot(StartupDot, OkBrush, "Startup reviewed");
                SetPill(StartupPillDot, StartupPillText, OkBrush, "Reviewed");
            }
        }
        catch (Exception ex)
        {
            SetPill(StartupPillDot, StartupPillText, WarnBrush, "status unreadable");
            StartupActionResult.Text = "Startup refresh failed: " + ex.Message;
            StartupActionResult.Visibility = Visibility.Visible;
        }
    }

    private async void StartupRefreshBtn_Click(object sender, RoutedEventArgs e)
    {
        StartupRefreshBtn.IsEnabled = false;
        try { await RefreshStartupAsync(); }
        finally { StartupRefreshBtn.IsEnabled = true; }
    }

    private async void StartupLogonToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: LogonRow row }) return;
        bool disabling = !row.DisabledByUs;
        if (disabling && !Confirm(
                $"Stop '{row.Name}' from running at logon?\n\nIts registry value is snapshotted and removed — restore it any time with the same button.",
                "Disable logon item"))
            return;
        try
        {
            var failures = await Task.Run(() => disabling
                ? ShieldsUp.Core.Services.StartupSurfaceService.DisableRegistryLogon(row.Location, row.Name)
                : ShieldsUp.Core.Services.StartupSurfaceService.EnableRegistryLogon(row.Location, row.Name));
            ShowResult(StartupActionResult, failures.Count > 0
                ? string.Join("; ", failures)
                : disabling ? $"'{row.Name}' disabled at logon (snapshotted — reversible)." : $"'{row.Name}' restored.");
        }
        catch (Exception ex) { ShowResult(StartupActionResult, "Logon toggle failed: " + ex.Message); }
        finally { await RefreshStartupAsync(); }
    }

    private async void StartupTaskToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: TaskRow row }) return;
        bool disabling = row.State != "Disabled";
        if (disabling && !Confirm(
                $"Disable the scheduled task '{row.TaskName}'?\n\nThe task stays registered — its trigger stops firing. Reversible with the same button.",
                "Disable scheduled task"))
            return;
        try
        {
            await AutoCommand.Forensics.Core.TaskSchedulerService.Instance.SetTaskEnabledAsync(row.TaskPath, !disabling);
            ShowResult(StartupActionResult, disabling
                ? $"Task '{row.TaskName}' disabled (reversible)."
                : $"Task '{row.TaskName}' re-enabled.");
        }
        catch (Exception ex) { ShowResult(StartupActionResult, "Task toggle failed: " + ex.Message); }
        finally { await RefreshStartupAsync(); }
    }

    private async void HostedStopBtn_Click(object sender, RoutedEventArgs e)
    {
        HostedStopBtn.IsEnabled = false;
        try
        {
            await Task.Run(AttackSurfaceService.DisallowHostedNetwork);
            ShowResult(DoorActionResult, "Hosted network stopped and disallowed (reversible with netsh mode=allow).");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            HostedStopBtn.IsEnabled = true;
        }
    }

    private async void WifiDirectRemoveBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Remove the Wi-Fi Direct Virtual Adapter(s)? The devices reappear when the driver re-enumerates.",
                "Remove Wi-Fi Direct adapter"))
            return;

        WifiDirectRemoveBtn.IsEnabled = false;
        try
        {
            var results = await Task.Run(AttackSurfaceService.RemoveWifiDirectAdapters);
            ShowResult(DoorActionResult, results.Count > 0
                ? string.Join("\n", results)
                : "No Wi-Fi Direct adapters found.");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            WifiDirectRemoveBtn.IsEnabled = true;
        }
    }

    private async void KdnetToggleBtn_Click(object sender, RoutedEventArgs e)
    {
        bool on = AttackSurfaceService.IsKernelDebugOn();
        if (!on && !Confirm("Enable kernel debugging? This is a security risk.", "Enable kernel debug"))
            return;

        KdnetToggleBtn.IsEnabled = false;
        try
        {
            await Task.Run(() => AttackSurfaceService.SetKernelDebug(!on));
            ShowResult(DoorActionResult, on ? "Kernel debug turned off (takes effect at next boot)." : "Kernel debug turned on.");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            KdnetToggleBtn.IsEnabled = true;
        }
    }

    private async void VpnDisableBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm(
                "Stop and disable the Windows VPN services (RasMan, IKEEXT, PolicyAgent, RemoteAccess)?\n\nAny VPN connection you rely on will drop until you re-enable them.",
                "Disable VPN services"))
            return;

        VpnDisableBtn.IsEnabled = false;
        try
        {
            await Task.Run(PrivacyService.DisableVpnServices);
            ShowResult(DoorActionResult, "VPN services stopped and disabled (reversible with Re-enable).");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "Failed to disable VPN services: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            VpnDisableBtn.IsEnabled = true;
        }
    }

    private async void VpnEnableBtn_Click(object sender, RoutedEventArgs e)
    {
        VpnEnableBtn.IsEnabled = false;
        try
        {
            await Task.Run(PrivacyService.EnableVpnServices);
            ShowResult(DoorActionResult, "VPN services re-enabled.");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "Failed to re-enable VPN services: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            VpnEnableBtn.IsEnabled = true;
        }
    }

    private async void MiniportRemoveBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Remove ALL WAN Miniport adapters? This will disable VPN capabilities until the drivers re-enumerate.",
                "Remove WAN miniports"))
            return;

        MiniportRemoveBtn.IsEnabled = false;
        try
        {
            var results = await Task.Run(AttackSurfaceService.RemoveAllWanMiniports);
            ShowResult(DoorActionResult, results.Count > 0
                ? string.Join("\n", results)
                : "No WAN Miniports found.");
        }
        catch (Exception ex)
        {
            ShowResult(DoorActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshDoorsAsync();
            MiniportRemoveBtn.IsEnabled = true;
        }
    }

    // ── firewall presets: deliberately NOT here ─────────────────────────
    // The named presets are the Firewall tab's own control (profile dropdown
    // there, which pauses the drift enforcer, applies and re-captures the
    // baseline atomically). A duplicate row here meant two doors to the same
    // operation on two different tabs; the tab now says where they live.

    // ── rail status dots ────────────────────────────────────────────────
    // Each rail row carries its section's live state as one dot — the same
    // green/amber/red language as the checklist chips (green = closed/done,
    // amber = open/not yet set, red = needs attention). The refresh methods
    // update their dot after re-reading the machine, so the rail doubles as
    // a checklist visible from every section.

    private static void SetDot(System.Windows.Shapes.Ellipse dot, Brush brush, string tip)
    {
        dot.Fill = brush;
        dot.ToolTip = tip;
    }

    private void SetQuickScanDot()
    {
        int open = _scanRows.Count(r => r.ChipBrush == WarnBrush);
        int failed = _scanRows.Count(r => r.ChipBrush == BadBrush);
        if (failed > 0)
        {
            SetDot(QuickScanDot, BadBrush, failed + " step(s) failed — open Quick Scan");
            SetPill(QuickScanPillDot, QuickScanPillText, BadBrush, failed + " step(s) failed");
        }
        else if (open > 0)
        {
            SetDot(QuickScanDot, WarnBrush, open + " step(s) open — open Quick Scan");
            SetPill(QuickScanPillDot, QuickScanPillText, WarnBrush, open + " step(s) open");
        }
        else
        {
            SetDot(QuickScanDot, OkBrush, "All steps done");
            SetPill(QuickScanPillDot, QuickScanPillText, OkBrush, "All steps done");
        }
    }

    /// <summary>The HIG summary pill under each subtab's large title: the
    /// page's whole verdict in one glance, driven from the same aggregate
    /// the rail dot already computes — dot for the rail, pill for the page.</summary>
    private void SetPill(System.Windows.Shapes.Ellipse dot, TextBlock text,
        System.Windows.Media.Brush brush, string message)
    {
        try
        {
            dot.Fill = brush;
            text.Text = message;
        }
        catch { /* the pill is advisory */ }
    }

    // ── rail collapse ───────────────────────────────────────────────────
    // Mirrors the main window's hamburger (IsPaneCollapsed): the rail
    // narrows to its icons and status dots while labels, header and legend
    // hide (the RailLabel/RailExpand/RailMeta styles bind Visibility to
    // this property). One word persists in shieldsup_rail.txt — the same
    // flat-file pattern as shieldsup_subtab.txt.

    public static readonly DependencyProperty RailCollapsedProperty =
        DependencyProperty.Register(nameof(RailCollapsed), typeof(bool), typeof(ShieldsUpView),
            new PropertyMetadata(false));

    public bool RailCollapsed
    {
        get => (bool)GetValue(RailCollapsedProperty);
        set => SetValue(RailCollapsedProperty, value);
    }

    private static string RailPrefsPath => System.IO.Path.Combine(
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
        "AutoCommand", "shieldsup_rail.txt");

    private void RestoreRail()
    {
        try
        {
            if (System.IO.File.Exists(RailPrefsPath))
                RailCollapsed = System.IO.File.ReadAllText(RailPrefsPath).Trim() == "collapsed";
        }
        catch { /* persistence is best-effort — the rail starts expanded */ }
    }

    private void RailCollapseBtn_Click(object sender, RoutedEventArgs e)
    {
        RailCollapsed = !RailCollapsed;
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(RailPrefsPath));
            System.IO.File.WriteAllText(RailPrefsPath, RailCollapsed ? "collapsed" : "open");
        }
        catch { /* persistence is best-effort */ }
    }

    // ── sub-tabs ────────────────────────────────────────────────────────

    private static readonly string[] SubTabNames = { "quick-scan", "doors", "privacy", "junk", "hardening" };

    private static string SubTabPrefsPath => System.IO.Path.Combine(
        System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
        "AutoCommand", "shieldsup_subtab.txt");

    /// <summary>Restores the last-used sub-tab (same flat-file pattern as
    /// rain_panel.txt); Quick Scan stays the default when unset.</summary>
    private void RestoreSubTab()
    {
        try
        {
            if (!System.IO.File.Exists(SubTabPrefsPath)) return;
            var name = System.IO.File.ReadAllText(SubTabPrefsPath).Trim();
            var idx = System.Array.IndexOf(SubTabNames, name);
            if (idx > 0) SubTabs.SelectedIndex = idx;
        }
        catch { /* persistence is best-effort — default lands on Quick Scan */ }
    }

    /// <summary>Switching sub-tabs re-reads that section's live state — the
    /// same rows the refresh buttons re-read, so opening a tab IS a check.</summary>
    private void SubTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SubTabs.SelectedIndex < 0) return;
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(SubTabPrefsPath));
            System.IO.File.WriteAllText(SubTabPrefsPath, SubTabNames[SubTabs.SelectedIndex]);
        }
        catch { }

        switch (SubTabs.SelectedIndex)
        {
            case 0: _ = QuickScanCheckAsync(); break;
            case 1: _ = RefreshDoorsAsync(); break;
            case 2: _ = RefreshStartupAsync(); break;
            case 3: _ = RefreshTelemetryAsync(); break;
            case 4: _ = RefreshBloatwareAsync(); break;
            case 5: _ = RefreshHardeningAsync(); break;
        }
    }

    // ── telemetry opt-outs ──────────────────────────────────────────────

    public sealed class TelemetryRow
    {
        public string AppName { get; init; }
        public string StateText { get; init; }
        public Brush StateBrush { get; init; }
        public string Evidence { get; init; }
        public Visibility OptOutVis { get; init; }
        public Visibility RevertVis { get; init; }
        public TelemetryRule Rule { get; init; }
    }

    private async Task RefreshTelemetryAsync()
    {
        try
        {
            var statuses = (await _telemetry.EvaluateAllAsync()).ToList();
            TelemetryList.ItemsSource = statuses.Select(s => new TelemetryRow
            {
                AppName = s.Rule.AppName,
                StateText = s.StateText,
                StateBrush = s.State switch
                {
                    TelemetryState.Off => OkBrush,
                    TelemetryState.Ineffective => BadBrush,
                    TelemetryState.On => WarnBrush,
                    _ => Brushes.Gray
                },
                Evidence = s.Evidence,
                OptOutVis = s.State == TelemetryState.Off ? Visibility.Collapsed : Visibility.Visible,
                RevertVis = s.State == TelemetryState.Off ? Visibility.Visible : Visibility.Collapsed,
                Rule = s.Rule
            }).ToList();

            // Rail dot: red when an opt-out was applied but proved
            // ineffective, amber while anyone still reports, green when all
            // vendors are off.
            int stillOn = statuses.Count(s => s.State != TelemetryState.Off);
            int ineffective = statuses.Count(s => s.State == TelemetryState.Ineffective);
            if (ineffective > 0)
            {
                SetDot(PrivacyDot, BadBrush, ineffective + " opt-out(s) ineffective — open Privacy");
                SetPill(PrivacyPillDot, PrivacyPillText, BadBrush, ineffective + " opt-out(s) ineffective");
            }
            else if (stillOn > 0)
            {
                SetDot(PrivacyDot, WarnBrush, stillOn + " vendor(s) still reporting — open Privacy");
                SetPill(PrivacyPillDot, PrivacyPillText, WarnBrush, stillOn + " vendor(s) still on");
            }
            else
            {
                SetDot(PrivacyDot, OkBrush, "All vendors opted out");
                SetPill(PrivacyPillDot, PrivacyPillText, OkBrush, "All vendors opted out");
            }
        }
        catch (Exception ex)
        {
            ShowResult(TelemetryResultText, "Telemetry status check failed: " + ex.Message);
        }
    }

    private async void TelemetryRefreshBtn_Click(object sender, RoutedEventArgs e)
    {
        TelemetryRefreshBtn.IsEnabled = false;
        try { await RefreshTelemetryAsync(); }
        finally { TelemetryRefreshBtn.IsEnabled = true; }
    }

    private async void TelemetryOptOut_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not TelemetryRow row) return;
        if (!Confirm(
                $"Opt out of {row.AppName} telemetry using the vendor's own official switch?\n\nThe previous setting is saved first — Revert puts it back exactly.",
                "Opt out"))
            return;

        SetTelemetryButtonsEnabled(false);
        try
        {
            var (ok, message) = await _telemetry.ApplyOptOutAsync(row.Rule);
            ShowResult(TelemetryResultText, (ok ? "Opted out: " : "Failed: ") + message);
        }
        catch (Exception ex)
        {
            ShowResult(TelemetryResultText, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshTelemetryAsync();
            SetTelemetryButtonsEnabled(true);
        }
    }

    private async void TelemetryRevert_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not TelemetryRow row) return;

        SetTelemetryButtonsEnabled(false);
        try
        {
            var (ok, message) = await _telemetry.RevertAsync(row.Rule);
            ShowResult(TelemetryResultText, (ok ? "Reverted: " : "Failed: ") + message);
        }
        catch (Exception ex)
        {
            ShowResult(TelemetryResultText, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshTelemetryAsync();
            SetTelemetryButtonsEnabled(true);
        }
    }

    private async void TelemetryEnforceAllBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm(
                "Pin the watch domains of every detected-but-not-opted-out vendor in the hosts file (127.0.0.1 backstop)?\n\nThe pins are tagged, removable, and attempts show up in AutoCommand's sinkhole log.",
                "Pin telemetry domains"))
            return;

        TelemetryEnforceAllBtn.IsEnabled = false;
        try
        {
            var statuses = await _telemetry.EvaluateAllAsync();
            int pinned = 0, failed = 0;
            foreach (var s in statuses.Where(s => s.Detected && s.State != TelemetryState.Off))
            {
                var (ok, _) = await _telemetry.ApplyEnforceAsync(s.Rule);
                if (ok) pinned++; else failed++;
            }
            ShowResult(TelemetryResultText, pinned > 0
                ? $"Pinned {pinned} vendor(s)" + (failed > 0 ? $"; {failed} failed (is the app elevated?)" : "") + "."
                : "Nothing to pin — everyone is already opted out.");
        }
        catch (Exception ex)
        {
            ShowResult(TelemetryResultText, "Failed: " + ex.Message);
        }
        finally
        {
            TelemetryEnforceAllBtn.IsEnabled = true;
        }
    }

    private void SetTelemetryButtonsEnabled(bool enabled)
    {
        TelemetryRefreshBtn.IsEnabled = enabled;
        TelemetryEnforceAllBtn.IsEnabled = enabled;
    }

    // ── bloatware ───────────────────────────────────────────────────────

    private List<ShieldsUp.Core.Models.AppPackageItem> _matchedBloat;

    private async Task RefreshBloatwareAsync()
    {
        try
        {
            _matchedBloat = await AppManagerService.Instance.FindBloatwareAsync();
            BloatListText.Text = _matchedBloat.Count == 0
                ? "No bloatware packages installed ✓"
                : $"{_matchedBloat.Count} matched package(s):\n" +
                  string.Join("\n", _matchedBloat.Select(a => "• " + a.Name));
            BloatRemoveBtn.IsEnabled = _matchedBloat.Count > 0;
            if (_matchedBloat.Count > 0)
            {
                SetDot(JunkDot, WarnBrush, _matchedBloat.Count + " matched package(s) — open Junk");
                SetPill(JunkPillDot, JunkPillText, WarnBrush, _matchedBloat.Count + " package(s) matched");
            }
            else
            {
                SetDot(JunkDot, OkBrush, "Nothing to remove");
                SetPill(JunkPillDot, JunkPillText, OkBrush, "Nothing to remove");
            }
        }
        catch (Exception ex)
        {
            BloatListText.Text = "Bloatware scan failed: " + ex.Message;
        }
    }

    private async void BloatRefreshBtn_Click(object sender, RoutedEventArgs e)
    {
        BloatRefreshBtn.IsEnabled = false;
        try { await RefreshBloatwareAsync(); }
        finally { BloatRefreshBtn.IsEnabled = true; }
    }

    private async void BloatRemoveBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_matchedBloat is not { Count: > 0 }) return;
        if (!Confirm(
                "Uninstall these packages?\n\n" + string.Join("\n", _matchedBloat.Select(a => "• " + a.Name)) +
                "\n\nThis cannot be undone — the apps can be reinstalled from their stores, but not restored in place.",
                "Remove bloatware"))
            return;

        BloatRemoveBtn.IsEnabled = false;
        try
        {
            var progress = new Progress<string>();
            var (matched, removed, failed) = await AppManagerService.Instance.RemoveBloatwareAsync(progress);
            ShowResult(BloatResultText, failed.Count == 0
                ? $"Removed {removed}/{matched.Count} package(s)."
                : $"Removed {removed}/{matched.Count}; failed: {string.Join(", ", failed)}");
        }
        catch (Exception ex)
        {
            ShowResult(BloatResultText, "Removal failed: " + ex.Message);
        }
        finally
        {
            await RefreshBloatwareAsync();
            BloatRemoveBtn.IsEnabled = true;
        }
    }

    // ── OS hardening ────────────────────────────────────────────────────

    private async Task RefreshHardeningAsync()
    {
        var (ipv6, lsa, uac, hosts) = await Task.Run(() =>
        (
            HardeningService.IsIpv6Disabled(),
            HardeningService.IsLsaProtected(),
            HardeningService.IsUacStrict(),
            HardeningService.AuditHostsFile()
        ));

        Ipv6StatusText.Text = ipv6 ? "IPv6 disabled globally ✓ (reboot to take effect)" : "IPv6 enabled ⚠";
        Ipv6StatusText.Foreground = ipv6 ? OkBrush : WarnBrush;
        Ipv6Btn.Content = ipv6 ? "Re-enable" : "Disable";

        LsaStatusText.Text = lsa ? "LSA Protection enabled ✓" : "LSA Protection disabled ⚠ — credentials unprotected";
        LsaStatusText.Foreground = lsa ? OkBrush : WarnBrush;
        LsaBtn.Content = lsa ? "Disable" : "Enable";

        UacStatusText.Text = uac ? "UAC at maximum strictness ✓" : "UAC relaxed ⚠";
        UacStatusText.Foreground = uac ? OkBrush : WarnBrush;
        UacBtn.Content = uac ? "Relax" : "Set maximum";

        HostsStatusText.Text = !hosts.Exists
            ? "hosts file missing (default behavior on some systems) ✓"
            : hosts.Suspicious
                ? $"{hosts.ActiveRules} active redirect(s), some non-loopback — potentially hijacked ⚠"
                : hosts.ActiveRules > 0
                    ? $"{hosts.ActiveRules} standard redirect(s) ✓"
                    : "hosts file is clean (default) ✓";
        HostsStatusText.Foreground = hosts.Suspicious ? BadBrush : OkBrush;

        // Rail dot: red on a hijacked hosts file, amber while switches are
        // not yet set, green when everything is in place.
        int unset = (ipv6 ? 0 : 1) + (lsa ? 0 : 1) + (uac ? 0 : 1);
        if (hosts.Suspicious)
        {
            SetDot(HardeningDot, BadBrush, "Hosts file may be hijacked — open Hardening");
            SetPill(HardeningPillDot, HardeningPillText, BadBrush, "Hosts file may be hijacked");
        }
        else if (unset > 0)
        {
            SetDot(HardeningDot, WarnBrush, unset + " switch(es) not set — open Hardening");
            SetPill(HardeningPillDot, HardeningPillText, WarnBrush, unset + " switch(es) not set");
        }
        else
        {
            SetDot(HardeningDot, OkBrush, "All switches set");
            SetPill(HardeningPillDot, HardeningPillText, OkBrush, "All switches set");
        }
    }

    private async void Ipv6Btn_Click(object sender, RoutedEventArgs e)
    {
        bool disabled = HardeningService.IsIpv6Disabled();
        if (!disabled && !Confirm(
                "Disable IPv6 system-wide via registry (DisabledComponents=0xFF)?\n\nNetworks and services that require IPv6 will stop working until it is re-enabled. A reboot is required.",
                "Disable IPv6"))
            return;

        Ipv6Btn.IsEnabled = false;
        try
        {
            await Task.Run(() => HardeningService.SetIpv6Disabled(!disabled));
            ShowResult(HardeningActionResult, disabled
                ? "IPv6 re-enabled. A reboot is required."
                : "IPv6 disabled via registry (0xFF). A reboot is required.");
        }
        catch (Exception ex)
        {
            ShowResult(HardeningActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshHardeningAsync();
            Ipv6Btn.IsEnabled = true;
        }
    }

    private async void LsaBtn_Click(object sender, RoutedEventArgs e)
    {
        bool on = HardeningService.IsLsaProtected();
        if (!on && !Confirm(
                "Enable LSA Protection (RunAsPPL)?\n\nThird-party credential providers or VPN plug-ins that hook LSA may stop working at next boot.",
                "Enable LSA Protection"))
            return;

        LsaBtn.IsEnabled = false;
        try
        {
            await Task.Run(() => HardeningService.SetLsaProtected(!on));
            ShowResult(HardeningActionResult, on
                ? "LSA Protection disabled."
                : "LSA Protection enabled. A reboot is required for this to take effect.");
        }
        catch (Exception ex)
        {
            ShowResult(HardeningActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshHardeningAsync();
            LsaBtn.IsEnabled = true;
        }
    }

    private async void UacBtn_Click(object sender, RoutedEventArgs e)
    {
        bool strict = HardeningService.IsUacStrict();
        if (strict && !Confirm(
                "Relax UAC from maximum strictness? This lowers the system's elevation security.",
                "Relax UAC"))
            return;

        UacBtn.IsEnabled = false;
        try
        {
            await Task.Run(() => HardeningService.SetUacStrict(!strict));
            ShowResult(HardeningActionResult, strict ? "UAC relaxed." : "UAC set to maximum strictness.");
        }
        catch (Exception ex)
        {
            ShowResult(HardeningActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshHardeningAsync();
            UacBtn.IsEnabled = true;
        }
    }

    private async void HostsResetBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm(
                "Reset the hosts file to the Windows default? ALL custom entries will be lost — including any telemetry pins. This cannot be undone.",
                "Reset hosts file"))
            return;

        HostsResetBtn.IsEnabled = false;
        try
        {
            await Task.Run(HardeningService.ResetHostsFile);
            ShowResult(HardeningActionResult, "Hosts file reset to the Windows default.");
        }
        catch (Exception ex)
        {
            ShowResult(HardeningActionResult, "Failed: " + ex.Message);
        }
        finally
        {
            await RefreshHardeningAsync();
            HostsResetBtn.IsEnabled = true;
        }
    }
}
