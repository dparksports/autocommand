using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The live connection grid. Rows wrap the engine's SvchostMonitorItem
    /// (which raises INPC as engines update it) and add the one thing the
    /// Advanced grid never surfaces first: a plain-English "What it is"
    /// chip, recomputed from the pure VerdictChip mapping. Block/unblock
    /// goes straight through Light's engine instance and ledger.
    /// </summary>
    public partial class ConnectionsView : UserControl
    {
        private readonly ObservableCollection<RowVm> _rows = new();
        private RowVm _menuRow;

        public ConnectionsView()
        {
            InitializeComponent();
            RowsGrid.ItemsSource = _rows;
            Loaded += (s, e) =>
            {
                RefreshSysmonChip();
                foreach (var item in LightServices.Tracked.Values) AddRow(item);
            };
        }

        private void RefreshSysmonChip()
        {
            try
            {
                SysmonChip.Text = LightServices.Installer.DetectInstallState() == SysmonInstallState.Installed
                    ? "Sysmon: on — program stories available"
                    : "Sysmon: off — set it up on Overview for program stories";
            }
            catch { SysmonChip.Text = "Sysmon: unknown"; }
        }

        private void AddRow(SvchostMonitorItem item)
        {
            var key = item.RemoteIp;
            if (string.IsNullOrEmpty(key)) return;
            foreach (var existing in _rows)
                if (existing.Item == item) return;
            _rows.Add(new RowVm(item, Dispatcher));
        }

        private sealed class RowVm : INotifyPropertyChanged
        {
            private readonly Dispatcher _dispatcher;
            public readonly SvchostMonitorItem Item;

            public RowVm(SvchostMonitorItem item, Dispatcher dispatcher)
            {
                Item = item;
                _dispatcher = dispatcher;
                // engines mutate the wrapped row off the UI thread; every
                // change re-renders the bound columns and the chip
                ((INotifyPropertyChanged)item).PropertyChanged += (s, e) =>
                    _dispatcher.BeginInvoke(new Action(() =>
                    {
                        Raise(nameof(Glyph));
                        Raise(nameof(Program));
                        Raise(nameof(Website));
                        Raise(nameof(Ip));
                        Raise(nameof(Attempts));
                        Raise(nameof(Out));
                        Raise(nameof(In));
                        RefreshChip();
                    }));
                RefreshChip();
            }

            public string Glyph => Item.StatusGlyph;
            public string Program => Item.ProcessDisplay;
            public string Website => Item.HostnameDisplay;
            public string Ip => Item.RemoteIp;
            public string Attempts => Item.BlockedAttemptsDisplay;
            public string Out => Item.TxBytesDisplay;
            public string In => Item.RxBytesDisplay;
            public string Chip { get; private set; }
            public string ChipDetail { get; private set; }
            public Brush ChipBrush { get; private set; }

            public void RefreshChip()
            {
                var (chip, detail, tone) = VerdictChip.Map(LightServices.ChipFactsOf(Item));
                Chip = chip;
                ChipDetail = detail;
                ChipBrush = tone switch
                {
                    "act" => TryFind("AccentRedBrush"),
                    "watch" => TryFind("AccentAmberBrush"),
                    _ => TryFind("TextPrimaryBrush"),
                };
                Raise(nameof(Chip));
                Raise(nameof(ChipDetail));
                Raise(nameof(ChipBrush));
            }

            private static Brush TryFind(string key) =>
                (Brush)Application.Current.TryFindResource(key) ?? Brushes.Black;

            public event PropertyChangedEventHandler PropertyChanged;
            private void Raise(string name) =>
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        // ── context menu ────────────────────────────────────────────────

        private void RowsGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            _menuRow = RowsGrid.SelectedItem as RowVm;
            if (_menuRow == null) e.Handled = true;
        }

        private async void BlockProgram_Click(object sender, RoutedEventArgs e)
        {
            if (_menuRow == null) return;
            var path = _menuRow.Item.ImagePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                MessageBox.Show(Window.GetWindow(this),
                    "AutoCommand can't yet tell where this program runs from, so a program block " +
                    "would not land anywhere. Try “Block this address” instead, or set up Sysmon on the Overview page.",
                    "Block program", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var (created, _) = await LightServices.Firewall.AddAppBlockAsync(path, LightServices.OwnMarker + " · from Connections");
            LightServices.Ledger.AddOrUpdate(new BlockRecord
            {
                Kind = "proc",
                Key = path,
                ProcessName = _menuRow.Item.ProcessName,
                Origin = "light-connections",
                CreatedUtc = DateTime.UtcNow,
                Status = "on"
            }, "light-connections");
            _menuRow.Item.SetBlockState(BlockRuleState.Active, "your block", BlockRuleState.None, "");
            MessageBox.Show(Window.GetWindow(this),
                $"Blocked “{_menuRow.Item.ProcessName}” ({created} rule(s) now on). " +
                "It stays blocked even if the app moves or updates — and you'll see its attempts on the Blocks page.",
                "Blocked", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async void BlockAddress_Click(object sender, RoutedEventArgs e)
        {
            if (_menuRow == null) return;
            var ip = _menuRow.Item.RemoteIp;
            var (created, _) = await LightServices.Firewall.AddIpBlockAsync(ip, LightServices.OwnMarker + " · from Connections");
            LightServices.Ledger.AddOrUpdate(new BlockRecord
            {
                Kind = "ip",
                Key = ip,
                Origin = "light-connections",
                CreatedUtc = DateTime.UtcNow,
                Status = "on"
            }, "light-connections");
            _menuRow.Item.SetBlockState(BlockRuleState.Active, "your block", BlockRuleState.None, "");
            MessageBox.Show(Window.GetWindow(this),
                $"Blocked the address {ip} ({created} rule(s) now on).",
                "Blocked", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async void Unblock_Click(object sender, RoutedEventArgs e)
        {
            if (_menuRow == null) return;
            var item = _menuRow.Item;
            await LightServices.Firewall.RemoveBlockRulesForIpAsync(item.RemoteIp);
            if (!string.IsNullOrWhiteSpace(item.ImagePath))
                await LightServices.Firewall.RemoveBlockRulesForAppAsync(item.ImagePath);
            LightServices.Ledger.Remove("ip", item.RemoteIp, "light-connections");
            if (!string.IsNullOrWhiteSpace(item.ImagePath))
                LightServices.Ledger.Remove("proc", item.ImagePath, "light-connections");
            item.SetBlockState(BlockRuleState.None, "", BlockRuleState.None, "");
        }

        private void Ignore_Click(object sender, RoutedEventArgs e)
        {
            if (_menuRow == null) return;
            LightServices.IgnoreProcess(_menuRow.Item.ProcessName);
            MessageBox.Show(Window.GetWindow(this),
                $"“{_menuRow.Item.ProcessName}” will stop appearing in this list. " +
                "You can undo that from the Overview page's data folder or the Advanced app.",
                "Ignored", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void CopyAddress_Click(object sender, RoutedEventArgs e)
        {
            if (_menuRow == null) return;
            Clipboard.SetText(_menuRow.Item.RemoteIp ?? "");
        }
    }
}
