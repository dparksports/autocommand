using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using AutoCommand.Agent.Core;
using AutoCommand.Helpers;
using AutoCommand.Models;

namespace AutoCommand.Views
{
    /// <summary>
    /// The Spawn Watches tab: rule cards on the left, the hit feed on the
    /// right, the selected hit's full EventData below. Everything shown is
    /// what <see cref="SpawnWatchService"/> already collected at ingestion
    /// time — this view only reads, so the 10 s refresh loop is safe to
    /// visibility-gate (accumulation continues while the tab is hidden).
    /// </summary>
    public partial class SpawnWatchesView : UserControl, IAiAuditable
    {
        private sealed class RuleRowVm
        {
            // public PROPERTIES, not fields — WPF bindings resolve CLR
            // properties only; a field silently binds to nothing (the
            // BlockRowVm house pattern exists for exactly this reason)
            public SpawnWatch Watch { get; set; }
            public string MatchDescription { get; set; }
            public string Hits24hText { get; set; }
            public bool IsSelected { get; set; }
        }

        private sealed class HitRowVm
        {
            public string TimeText { get; set; }
            public string Rule { get; set; }
            public string Image { get; set; }
            public string Pid { get; set; }
            public string Parent { get; set; }
            public string Service { get; set; }
            public string CmdText { get; set; }
            public SpawnWatchService.HitRow Raw { get; set; }
        }

        /// <summary>A load pass's result, built off the UI thread.</summary>
        private sealed class Snapshot
        {
            public List<RuleRowVm> Rules { get; set; }
            public int Hits24hTotal { get; set; }
            public List<HitRowVm> Hits { get; set; }
            public DateTime? LastHitUtc { get; set; }
        }

        private const int RefreshSeconds = 10;
        private const int HitWindowHours = 24;
        private const int MaxHitsShown = 500;

        private string _selectedRule = ""; // "" = all rules
        private readonly System.Windows.Threading.DispatcherTimer _timer;

        public SpawnWatchesView()
        {
            InitializeComponent();

            _timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(RefreshSeconds) };
            _timer.Tick += (_, _) => _ = LoadAsync();

            // reading service-side snapshots only — pausing while hidden
            // never pauses collection (RefreshLoop's stated precondition)
            RefreshLoop.GateVisibility(this, () => _timer);
            IsVisibleChanged += (_, _) =>
            {
                if (IsVisible) _ = LoadAsync();
            };
        }

        /// <summary>Structured tab state for AI auditability.</summary>
        public string GetAuditContext()
        {
            var rules = SpawnWatchStore.Load();
            var lines = new List<string> { $"SpawnWatches: {rules.Count} rule(s), {(string.IsNullOrEmpty(_selectedRule) ? "all" : $"'{_selectedRule}'")} selected" };
            foreach (var w in rules)
                lines.Add($"  - {w.Name} [{(w.Enabled ? "enabled" : "disabled")}] process={w.MatchProcess} parent={w.MatchParent} service={w.ServiceKey}");
            foreach (var h in SpawnWatchService.ReadHits(_selectedRule, DateTime.UtcNow.AddHours(-HitWindowHours), 20))
                lines.Add($"  hit {h.TsUtc.ToLocalTime():HH:mm:ss} [{h.Rule}] pid={h.Pid} {Leaf(h.Image)} ← {Leaf(h.Parent)}" +
                          (string.IsNullOrEmpty(h.Service) ? "" : $" ({h.Service})"));
            return string.Join(Environment.NewLine, lines);
        }

        // ── loading ───────────────────────────────────────────────────────

        private async Task LoadAsync()
        {
            var selectedRule = _selectedRule;
            var snapshot = await Task.Run(() => BuildSnapshot(selectedRule));
            if (!Dispatcher.CheckAccess()) // always marshaled via the awaiter's context
                Dispatcher.Invoke(() => Apply(snapshot));
            else
                Apply(snapshot);
        }

        private static Snapshot BuildSnapshot(string selectedRule)
        {
            try
            {
                SpawnWatchStore.EnsureSeeded();
                var rules = SpawnWatchStore.Load();
                var counts = SpawnWatchService.HitCounts(DateTime.UtcNow.AddHours(-HitWindowHours));
                var hits = SpawnWatchService.ReadHits(selectedRule,
                    DateTime.UtcNow.AddHours(-HitWindowHours), MaxHitsShown);

                var s = new Snapshot
                {
                    Rules = rules.Select(w => new RuleRowVm
                    {
                        Watch = w,
                        MatchDescription = DescribeMatch(w),
                        Hits24hText = counts.TryGetValue(w.Name, out var n) ? n.ToString() : "0",
                        IsSelected = string.Equals(selectedRule, w.Name, StringComparison.OrdinalIgnoreCase),
                    }).ToList(),
                    Hits = hits.Select(ToHitRowVm).ToList(),
                    Hits24hTotal = counts.Values.Sum(),
                    LastHitUtc = hits.Count > 0 ? hits[0].TsUtc : null,
                };
                return s;
            }
            catch
            {
                // a failed pass must not take the tab down — an empty
                // snapshot keeps the controls alive
                return new Snapshot { Rules = new List<RuleRowVm>(), Hits = new List<HitRowVm>() };
            }
        }

        private static HitRowVm ToHitRowVm(SpawnWatchService.HitRow h) => new()
        {
            TimeText = h.TsUtc.ToLocalTime().ToString("HH:mm:ss"),
            Rule = h.Rule,
            Image = h.Image,
            Pid = h.Pid,
            Parent = Leaf(h.Parent),
            Service = h.Service,
            CmdText = h.CommandLine?.Length > 120 ? h.CommandLine[..120] + "…" : h.CommandLine,
            Raw = h,
        };

        private static string Leaf(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            int i = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
            return i < 0 ? path : path[(i + 1)..];
        }

        private static string DescribeMatch(SpawnWatch w)
        {
            var parts = new List<string> { "process " + w.MatchProcess };
            parts.Add(string.IsNullOrWhiteSpace(w.MatchParent) ? "parent any" : "parent " + w.MatchParent);
            if (!string.IsNullOrWhiteSpace(w.ServiceKey)) parts.Add("service " + w.ServiceKey);
            if (!string.IsNullOrWhiteSpace(w.CommandLineContains)) parts.Add("cmd~ '" + w.CommandLineContains + "'");
            if (w.MinusAllowlist) parts.Add("minus allowlist");
            return string.Join(" · ", parts);
        }

        private void Apply(Snapshot s)
        {
            RulesList.ItemsSource = s.Rules;
            AllRulesText.Text = _selectedRule.Length == 0 ? "All rules (showing)" : "All rules";
            HitsChipText.Text = $"Hits 24h: {s.Hits24hTotal}";

            var last = s.LastHitUtc != null ? s.LastHitUtc.Value.ToLocalTime().ToString("HH:mm:ss") : "—";
            StatusText.Text = $"{s.Rules.Count} rule(s) · collection runs at ingestion time (continues while hidden) · last hit {last}";
            HitsHeaderText.Text = _selectedRule.Length == 0
                ? "HITS — ALL RULES (LAST 24 H)"
                : $"HITS — '{_selectedRule.ToUpperInvariant()}' (LAST 24 H)";

            // keep the user's selection row when the feed refreshes under it
            var selected = (HitsGrid.SelectedItem as HitRowVm)?.Raw;
            HitsGrid.ItemsSource = s.Hits;
            if (selected != null)
            {
                var again = s.Hits.FirstOrDefault(h => h.Raw == selected);
                if (again != null) HitsGrid.SelectedItem = again;
            }
        }

        // ── rule interactions ─────────────────────────────────────────────

        private void AllRulesRow_Click(object sender, MouseButtonEventArgs e)
        {
            _selectedRule = "";
            _ = LoadAsync();
        }

        private void RuleRow_Click(object sender, MouseButtonEventArgs e)
        {
            if ((e.OriginalSource as FrameworkElement)?.DataContext is not RuleRowVm vm) return;
            _selectedRule = vm.Watch.Name;
            _ = LoadAsync();
        }

        private void RuleEnabled_Changed(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox { Tag: RuleRowVm vm })
            {
                SpawnWatchStore.Save(vm.Watch); // Enabled was mutated by the binding
                _ = LoadAsync();
            }
        }

        private void NewRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            RuleNameBox.Text = "";
            RuleProcessBox.Text = "*";
            RuleParentBox.Text = "";
            RuleServiceBox.Text = "";
            RuleContainsBox.Text = "";
            RuleMinusAllowBox.IsChecked = true;
            RuleEnabledBox.IsChecked = true;
            EditorPanel.Visibility = Visibility.Visible;
            RuleNameBox.Focus();
        }

        private void CancelRuleBtn_Click(object sender, RoutedEventArgs e) =>
            EditorPanel.Visibility = Visibility.Collapsed;

        private void SaveRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            var name = (RuleNameBox.Text ?? "").Trim();
            if (name.Length == 0)
            {
                MessageBox.Show("Give the rule a name — it also becomes the rule's file name.",
                    "Spawn Watches", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                SpawnWatchStore.Save(new SpawnWatch
                {
                    Name = name,
                    MatchProcess = string.IsNullOrWhiteSpace(RuleProcessBox.Text) ? "*" : RuleProcessBox.Text.Trim(),
                    MatchParent = (RuleParentBox.Text ?? "").Trim(),
                    ServiceKey = (RuleServiceBox.Text ?? "").Trim(),
                    CommandLineContains = (RuleContainsBox.Text ?? "").Trim(),
                    MinusAllowlist = RuleMinusAllowBox.IsChecked == true,
                    Enabled = RuleEnabledBox.IsChecked == true,
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Saving the rule failed: {ex.Message}", "Spawn Watches",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            EditorPanel.Visibility = Visibility.Collapsed;
            _selectedRule = name;
            // rules changed — cover what the archive already holds now,
            // don't make the user wait for the next spawn
            Task.Run(() =>
            {
                try { SpawnWatchService.ReplayRecent(); } catch { /* best-effort */ }
            });
            _ = LoadAsync();
        }

        private void DeleteRuleBtn_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not RuleRowVm vm) return;
            var answer = MessageBox.Show($"Delete rule '{vm.Watch.Name}'? Hits already recorded stay on disk.",
                "Spawn Watches", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (answer != MessageBoxResult.Yes) return;
            SpawnWatchStore.Delete(vm.Watch.Name);
            if (string.Equals(_selectedRule, vm.Watch.Name, StringComparison.OrdinalIgnoreCase))
                _selectedRule = "";
            _ = LoadAsync();
        }

        // ── toolbar ───────────────────────────────────────────────────────

        private async void ReplayBtn_Click(object sender, RoutedEventArgs e)
        {
            ReplayBtn.IsEnabled = false;
            ReplayBtn.Content = "⟲ Replaying…";
            try
            {
                var count = await Task.Run(() =>
                {
                    try { return SpawnWatchService.ReplayRecent(); }
                    catch { return 0; }
                });
                MessageBox.Show($"Replay over the last 24 h appended {count} hit(s).",
                    "Spawn Watches", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            finally
            {
                ReplayBtn.IsEnabled = true;
                ReplayBtn.Content = "⟲ Replay 24 h";
                _ = LoadAsync();
            }
        }

        private void OpenFolderBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                SpawnWatchStore.EnsureSeeded();
                var dir = SpawnWatchStore.WatchesDirectory;
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Opening the folder failed: {ex.Message}", "Spawn Watches",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // ── hit detail ────────────────────────────────────────────────────

        private void HitsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (HitsGrid.SelectedItem is not HitRowVm vm || vm.Raw == null)
            {
                DetailHeaderText.Text = "DETAIL — select a hit";
                DetailText.Text = "";
                return;
            }
            var raw = vm.Raw;
            DetailHeaderText.Text = $"DETAIL — {raw.Rule} @ {vm.TimeText}";
            DetailText.Text = string.Join(Environment.NewLine,
                raw.Data.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(kv => $"{kv.Key,-22} {kv.Value}"));
        }
    }
}
