using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// Every block the install family has made, from one inventory walk:
    /// Light's own AL-BLOCK rules AND the Advanced app's adopted AC-BLOCK
    /// ones (mutual adoption — either app sees the whole picture). Own
    /// blocks can be removed outright; adopted ones get Pause/Resume, never
    /// delete — that stays the Advanced app's call, from its own Blocks tab.
    /// </summary>
    public partial class BlocksView : UserControl
    {
        private readonly ObservableCollection<BlockRowVm> _rows = new();

        public BlocksView()
        {
            InitializeComponent();
            BlocksGrid.ItemsSource = _rows;
            Loaded += (s, e) => _ = LoadAsync();
        }

        public void RefreshAfterFleetOp() => _ = LoadAsync();

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = LoadAsync();

        private async Task LoadAsync()
        {
            HintText.Text = "Loading…";
            var inv = await LightServices.Firewall.GetBlockedInventoryAsync();

            _rows.Clear();
            foreach (var b in inv)
            {
                bool own = (b.Description ?? "").StartsWith(LightServices.OwnMarker, StringComparison.Ordinal);
                _rows.Add(new BlockRowVm
                {
                    Target = b.Target,
                    Kind = b.Kind,
                    Key = b.Key,
                    Rules = b.Rules,
                    EnabledRules = b.EnabledRules,
                    KindLabel = b.Kind == "ip" ? "address" : "program",
                    StateLabel = b.EnabledRules > 0 ? "on" : "paused",
                    Since = b.Created?.ToLocalTime().ToString("MMM d, HH:mm") ?? "—",
                    Note = b.Rules > b.EnabledRules
                        ? "paused"
                        : (b.Class ?? ""),
                    IsOwn = own,
                    ActionLabel = own ? "Remove" : (b.EnabledRules > 0 ? "Pause" : "Resume"),
                });
            }

            HintText.Text = _rows.Count == 0
                ? "No blocks are on. Right-click a program on the Connections page to block it."
                : $"{_rows.Count} block(s) on record — {_rows.Count(r => r.EnabledRules > 0)} active.";
        }

        private async void RowAction_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.DataContext is not BlockRowVm row) return;
            try
            {
                if (row.IsOwn)
                {
                    int removed = row.Kind == "ip"
                        ? await LightServices.Firewall.RemoveBlockRulesForIpAsync(row.Key)
                        : await LightServices.Firewall.RemoveBlockRulesForAppAsync(row.Key);
                    string ledgerKind = row.Kind == "ip" ? "ip" : "proc";
                    LightServices.Ledger.Remove(ledgerKind, row.Key, "light-blocks");
                    MessageBox.Show(Window.GetWindow(this),
                        $"Removed “{row.Target}” ({removed} rule(s)). Blocking is fully off for it.",
                        "Removed", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    bool enable = row.EnabledRules <= 0;
                    var snap = await LightServices.Firewall.ToggleSingleTargetSnapshotAsync(
                        row.Kind, row.Key, row.Rules, true, enable);
                    // adopted blocks stay the Advanced app's records — no
                    // ledger write here; the rules themselves are the truth
                    if (snap.FirstError != null)
                    {
                        MessageBox.Show(Window.GetWindow(this),
                            $"Could not {(enable ? "resume" : "pause")} “{row.Target}”: {snap.FirstError}",
                            "Blocks", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }
                await LoadAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show(Window.GetWindow(this), ex.Message, "Blocks",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public sealed class BlockRowVm
        {
            public string Target { get; set; }
            public string Kind { get; set; }
            public string Key { get; set; }
            public int Rules { get; set; }
            public int EnabledRules { get; set; }
            public string KindLabel { get; set; }
            public string StateLabel { get; set; }
            public string Since { get; set; }
            public string Note { get; set; }
            public bool IsOwn { get; set; }
            public string ActionLabel { get; set; }
        }
    }
}
