using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The control surface of the whole product: one row per app, one
    /// segmented permission control per row. Groups read like sentences —
    /// Allowed / Asks first / Never / Windows (system) — and a flip lands
    /// on the firewall instantly, with a one-flip-deep undo. The pure
    /// GatePolicy decides grouping; this view only renders.
    /// </summary>
    public partial class AppsView : UserControl
    {
        private sealed record AppRow(
            string Key, string DisplayName, string ImagePath, bool Running,
            AppPermission Permission, bool IsNew, Exemption Exemption,
            string? PreviousAllowUntilUtc, string PreviousSource);

        private (string Key, AppPermission Prev, string PrevSource, DateTime? PrevAllowUntil)? _undo;
        private string _filter = "";

        public AppsView()
        {
            InitializeComponent();
            Loaded += (s, e) => Rebuild();
            LightGate.Changed += () => Dispatcher.BeginInvoke(new Action(Rebuild));
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _filter = SearchBox.Text?.Trim() ?? "";
            Rebuild();
        }

        public void Rebuild()
        {
            var now = DateTime.UtcNow;
            var rows = new List<AppRow>();

            // every permission decision is a row
            foreach (var e in LightGate.Store.Entries)
                rows.Add(new AppRow(e.Key, DisplayName(e), "", false, e.Permission, false,
                    Exemption.None, null, e.Source));

            // every running app is a row, even one the store has never met
            foreach (var g in LightServices.Tracked.Values
                .Where(r => !string.IsNullOrWhiteSpace(r.ProcessName))
                .GroupBy(r => PermissionStore.NormalizeKey(r.ProcessName)))
            {
                var first = g.First();
                var exemption = GatePolicy.ExemptReason(first.ProcessName, first.ImagePath, first.IsSvchost);
                if (exemption != Exemption.None) continue;   // pinned Windows group below
                if (rows.Any(r => r.Key == g.Key)) continue;
                var decision = GatePolicy.Resolve(first.ProcessName, first.ImagePath, first.IsSvchost,
                    LightGate.Store, now);
                rows.Add(new AppRow(g.Key, DisplayNameKey(g.Key), first.ImagePath ?? "", true,
                    decision.Permission, decision.IsNew, Exemption.None, null, ""));
            }

            rows = rows
                .Where(r => _filter.Length == 0 ||
                            r.DisplayName.Contains(_filter, StringComparison.OrdinalIgnoreCase) ||
                            r.Key.Contains(_filter, StringComparison.OrdinalIgnoreCase))
                .OrderBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            GroupsPanel.Children.Clear();
            BuildGroup("Allowed — they talk", rows.Where(r => r.Permission == AppPermission.Always));
            BuildGroup("Asks first — held until you answer", rows.Where(r => r.Permission == AppPermission.Ask));
            BuildGroup("Never — the gate holds them", rows.Where(r => r.Permission == AppPermission.Never));
            BuildWindowsGroup();
        }

        private void BuildGroup(string title, IEnumerable<AppRow> items)
        {
            var list = items.ToList();
            var card = new Border
            {
                Style = (Style)FindResource("CardPanel"),
                Margin = new Thickness(0, 0, 0, 14),
                Padding = new Thickness(16),
            };
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = title + (list.Count == 0 ? "" : $"  ·  {list.Count}"),
                Style = (Style)FindResource("SectionHeader"),
            });

            if (list.Count == 0)
            {
                panel.Children.Add(new TextBlock
                {
                    Text = "None.",
                    Margin = new Thickness(0, 6, 0, 0),
                    FontSize = 13,
                    Foreground = (Brush)FindResource("MutedTextBrush"),
                });
            }

            foreach (var r in list) panel.Children.Add(BuildRow(r));
            card.Child = panel;
            GroupsPanel.Children.Add(card);
        }

        private void BuildWindowsGroup()
        {
            var running = LightServices.Tracked.Values
                .Where(r => GatePolicy.ExemptReason(r.ProcessName, r.ImagePath, r.IsSvchost) != Exemption.None)
                .Select(r => DisplayNameKey(PermissionStore.NormalizeKey(r.ProcessName)))
                .Distinct()
                .OrderBy(n => n)
                .ToList();

            var card = new Border
            {
                Style = (Style)FindResource("CardPanel"),
                Margin = new Thickness(0, 0, 0, 14),
                Padding = new Thickness(16),
                Background = (Brush)FindResource("SurfaceAltBrush"),
            };
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = "Windows (system) — always on",
                Style = (Style)FindResource("SectionHeader"),
            });
            panel.Children.Add(new TextBlock
            {
                Text = "Windows' own essentials keep the PC alive, updated and signed in. " +
                       "They are part of the house, so they are on the list, not behind it.",
                Margin = new Thickness(0, 4, 0, 8),
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = (Brush)FindResource("TextSecondaryBrush"),
            });
            if (running.Count > 0)
                panel.Children.Add(new TextBlock
                {
                    Text = "Seen now: " + string.Join(", ", running),
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = (Brush)FindResource("MutedTextBrush"),
                });
            card.Child = panel;
            GroupsPanel.Children.Add(card);
        }

        private UIElement BuildRow(AppRow r)
        {
            var card = new Border
            {
                Background = (Brush)FindResource("SurfaceBrush"),
                BorderBrush = (Brush)FindResource("BorderBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(9),
                Padding = new Thickness(12, 9, 12, 9),
                Margin = new Thickness(0, 8, 0, 0),
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // face: first letter in a soft circle — the "icon" without assets
            var face = new Border
            {
                Width = 34, Height = 34, CornerRadius = new CornerRadius(17),
                Background = (Brush)FindResource("BadgeBlueBg"),
                Child = new TextBlock
                {
                    Text = string.IsNullOrEmpty(r.DisplayName) ? "?" : r.DisplayName[..1].ToUpperInvariant(),
                    FontWeight = FontWeights.SemiBold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    Foreground = (Brush)FindResource("AccentBlueBrush"),
                },
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0),
            };
            Grid.SetColumn(face, 0);

            var namePanel = new StackPanel();
            var nameLine = new StackPanel { Orientation = Orientation.Horizontal };
            nameLine.Children.Add(new TextBlock
            {
                Text = r.DisplayName,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
            });
            if (r.Running)
                nameLine.Children.Add(new TextBlock
                {
                    Text = "  ·  running",
                    FontSize = 11,
                    Foreground = (Brush)FindResource("AccentGreenBrush"),
                    VerticalAlignment = VerticalAlignment.Center,
                });
            if (r.IsNew)
                nameLine.Children.Add(new TextBlock
                {
                    Text = "  ·  new",
                    FontSize = 11,
                    Foreground = (Brush)FindResource("AccentAmberBrush"),
                    VerticalAlignment = VerticalAlignment.Center,
                });
            namePanel.Children.Add(nameLine);
            if (!string.IsNullOrWhiteSpace(r.ImagePath))
                namePanel.Children.Add(new TextBlock
                {
                    Text = r.ImagePath,
                    FontSize = 11,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Foreground = (Brush)FindResource("MutedTextBrush"),
                });
            Grid.SetColumn(namePanel, 1);

            var seg = new Controls.Segmented
            {
                Options = new[] { "Always", "Ask", "Never" },
                Value = r.Permission switch
                {
                    AppPermission.Always => "Always",
                    AppPermission.Never => "Never",
                    _ => "Ask",
                },
                Width = 210,
                VerticalAlignment = VerticalAlignment.Center,
                Tag = r,
            };
            seg.ValueChanged += (s, e) => OnPermissionFlipped(seg, r);
            Grid.SetColumn(seg, 2);

            grid.Children.Add(face);
            grid.Children.Add(namePanel);
            grid.Children.Add(seg);
            card.Child = grid;
            return card;
        }

        private void OnPermissionFlipped(Controls.Segmented seg, AppRow row)
        {
            var newPermission = seg.Value switch
            {
                "Always" => AppPermission.Always,
                "Never" => AppPermission.Never,
                _ => AppPermission.Ask,
            };
            if (newPermission == row.Permission) return;

            // remember exactly one flip for undo — the last one, in words
            var prev = LightGate.Store.Find(row.Key);
            _undo = (row.Key, row.Permission, prev?.Source ?? "", prev?.AllowUntilUtc);

            LightGate.Decide(row.Key, newPermission, row.DisplayName, row.ImagePath,
                "apps-page");
            ShowUndo(row.DisplayName, row.Permission);
        }

        private void ShowUndo(string name, AppPermission revertedTo)
        {
            UndoText.Text = $"{name} is now " + revertedTo switch
            {
                AppPermission.Always => "allowed. ",
                AppPermission.Never => "never allowed. ",
                _ => "asking first. ",
            } + "Tap undo to go back.";
            UndoBanner.Visibility = Visibility.Visible;
        }

        private void UndoBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_undo is not { } undo) { UndoBanner.Visibility = Visibility.Collapsed; return; }
            var prev = LightGate.Store.Find(undo.Key);
            var path = LightServices.Tracked.Values
                .FirstOrDefault(t => PermissionStore.NormalizeKey(t.ProcessName) == undo.Key)?
                .ImagePath ?? "";
            var allowFor = undo.PrevAllowUntil.HasValue
                ? undo.PrevAllowUntil - DateTime.UtcNow
                : (TimeSpan?)null;
            LightGate.Decide(undo.Key, undo.Prev,
                prev?.DisplayName ?? DisplayNameKey(undo.Key), path, "undo", allowFor);
            _undo = null;
            UndoBanner.Visibility = Visibility.Collapsed;
        }

        private static string DisplayName(PermissionEntry e) =>
            string.IsNullOrWhiteSpace(e.DisplayName)
                ? DisplayNameKey(e.Key)
                : e.DisplayName;

        private static string DisplayNameKey(string key) =>
            Core.GatePolicy.IsBrowser(key)
                ? char.ToUpperInvariant(key[0]) + key[1..] + " (browser)"
                : char.ToUpperInvariant(key[0]) + key[1..];
    }
}
