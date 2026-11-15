// 🧾 Audit tab — the readable surface over the app's append-only event
// trails: blocks-events.log plus the Process Monitor's
// ignored_processes-events.log. Everything else in the app WRITES those
// trails; this tab answers, in one sentence per incident, the only
// questions a returning user actually has: "what happened to my blocks
// while I wasn't looking, and does anything need me?"
//
// Design contract (matches the Blocks digest, not the raw log):
//   · incidents, not lines — AuditTrail collapses bursts into sentences
//   · reassurance first — the status strip answers "am I OK?" before any
//     list appears; red is reserved for un-remediated external changes
//   · defaults match attention span — "Since last visit", not "All"
//   · read-mostly — the only action is a deep link into the Blocks tab;
//     the audit trail itself is never editable from here
using AutoCommand.Contain.Core;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace AutoCommand.Views
{
    public partial class AuditView : UserControl
    {
        /// <summary>One raw ledger row (display shaping only; facts come
        /// straight from the parsed event).</summary>
        private class LedgerRow
        {
            public string Time { get; }
            public string Category { get; }
            public string What { get; }
            public string Target { get; }
            public string By { get; }
            public LedgerRow(AuditEvent e)
            {
                Time = e.TimeUtc.ToLocalTime().ToString("M/d h:mm tt", CultureInfo.CurrentCulture);
                Category = AuditTrail.CategoryOf(e.Action);
                What = e.Action switch
                {
                    "created" => "block added",
                    "removed" => "block removed / expired",
                    "paused" => "paused",
                    "resumed" => "resumed",
                    "fleet-disabled" => "all blocks disabled",
                    "fleet-enabled" => "blocks re-enabled",
                    "consolidated" => "legacy rules consolidated",
                    "rule-toggled" => $"rule switched {e.Detail}",
                    "ignored" => "added to process ignore list",
                    "unignored" => "removed from process ignore list",
                    "ignore-imported" => "already on ignore list (untracked)",
                    _ => e.Action
                };
                Target = e.Kind == "proc" && e.Key.Contains('\\')
                    ? System.IO.Path.GetFileName(e.Key)
                    : (e.Key.Length > 0 ? e.Key : "—");
                By = AuditTrail.ActorFor(e.Origin);
            }
        }

        private readonly ObservableCollection<AuditIncident> _incidents = new();
        private List<AuditIncident> _all = new();
        private List<AuditEvent> _events = new();
        private DateTime _lastSeenUtc = DateTime.MinValue;
        private bool _firstVisit = true;

        public AuditView()
        {
            InitializeComponent();

            TimeCombo.ItemsSource = new[] { "Since last visit", "24 hours", "7 days", "All" };
            TimeCombo.SelectedIndex = 0;
            CatCombo.ItemsSource = new[] { "All changes", "Fleet", "Pauses & manual", "External", "Auto-blocks", "Ignore list" };
            CatCombo.SelectedIndex = 0;

            var view = CollectionViewSource.GetDefaultView(_incidents);
            view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(AuditIncident.DayHeader)));
            IncidentsList.ItemsSource = view;

            IsVisibleChanged += (s, e) => { if (IsVisible) Reload(); };
        }

        // ── load ────────────────────────────────────────────────────────

        private void Reload()
        {
            string logPath = BlocksStore.EventLogPath;
            string marker = AuditTrail.VisitMarkerPath(logPath);
            _lastSeenUtc = AuditTrail.ReadSeenUtc(marker);
            _firstVisit = _lastSeenUtc == DateTime.MinValue;

            _events = AuditTrail.ReadEvents(logPath);
            // The Process Monitor's ignore-list trail uses the same pipe
            // format — merge it in so ignore changes surface here with
            // everything else, not only block events.
            _events.AddRange(AuditTrail.ReadEvents(
                AutoCommand.Engines.Watch.SysmonWatcherService.IgnoredEventsLogPath));
            _events.Sort((a, b) => a.TimeUtc.CompareTo(b.TimeUtc));
            _all = AuditTrail.BuildIncidents(_events);
            _all.Reverse();   // newest day first

            ApplyFilters();
            UpdateStatusStrip();

            // Same semantics as the Blocks digest: having shown the user
            // everything up to the newest event, that becomes the new
            // "seen" point. First visit adopts history silently.
            AuditTrail.MarkSeenUtc(marker,
                _events.Count > 0 ? _events.Max(e => e.TimeUtc) : DateTime.UtcNow);
        }

        private bool InRange(AuditIncident inc) => TimeCombo.SelectedIndex switch
        {
            0 => !_firstVisit && inc.EndUtc > _lastSeenUtc,
            1 => inc.EndUtc > DateTime.UtcNow.AddHours(-24),
            2 => inc.EndUtc > DateTime.UtcNow.AddDays(-7),
            _ => true
        };

        private string SelectedCategory => CatCombo.SelectedIndex switch
        {
            1 => "fleet",
            2 => "pause",
            3 => "external",
            4 => "auto",
            5 => "ignore",
            _ => "all"
        };

        private void ApplyFilters()
        {
            string cat = SelectedCategory;

            _incidents.Clear();
            foreach (var inc in _all.Where(i => i.Category == cat || cat == "all"))
                _incidents.Add(inc);

            var view = CollectionViewSource.GetDefaultView(_incidents);
            view.Filter = o => o is AuditIncident i && InRange(i);
            view.Refresh();

            // The ledger shows the same facts, one row per event, newest
            // first — the same filter decides both so the two views can't
            // disagree about what happened.
            bool InRangeEvent(AuditEvent e) => TimeCombo.SelectedIndex switch
            {
                0 => !_firstVisit && e.TimeUtc > _lastSeenUtc,
                1 => e.TimeUtc > DateTime.UtcNow.AddHours(-24),
                2 => e.TimeUtc > DateTime.UtcNow.AddDays(-7),
                _ => true
            };
            LedgerGrid.ItemsSource = _events
                .Where(InRangeEvent)
                .Where(e => cat == "all" || AuditTrail.CategoryOf(e.Action) == cat)
                .OrderByDescending(e => e.TimeUtc)
                .Select(e => new LedgerRow(e))
                .ToList();

            int shown = _all.Count(i => (i.Category == cat || cat == "all") && InRange(i));
            CountText.Text = $"{shown} incident{(shown == 1 ? "" : "s")}";
            bool empty = shown == 0;
            EmptyText.Visibility = empty && LedgerGrid.Visibility != Visibility.Visible
                ? Visibility.Visible : Visibility.Collapsed;
        }

        private void UpdateStatusStrip()
        {
            var attention = _all.Where(i => i.Severity == "attention" && InRange(i)).ToList();
            int visible = _all.Count(i => InRange(i));

            if (attention.Count > 0)
            {
                StatusStrip.Background = new SolidColorBrush(Color.FromRgb(0x2A, 0x1B, 0x1E));
                StatusStrip.BorderBrush = FindResource("AccentRedBrush") as Brush;
                StatusStrip.BorderThickness = new Thickness(1);
                StatusIcon.Text = "⚠";
                StatusIcon.Foreground = FindResource("AccentRedBrush") as Brush;
                StatusMain.Text = $"{attention.Count} incident{(attention.Count == 1 ? "" : "s")} need your attention.";
                StatusMain.Foreground = FindResource("TextPrimaryBrush") as Brush;
                StatusSub.Text = "Something outside AutoCommand changed block rules and it was not confirmed undone.";
                StatusSub.Foreground = FindResource("AccentRedBrush") as Brush;
            }
            else
            {
                StatusStrip.Background = new SolidColorBrush(Color.FromArgb(0x26, 0x34, 0xD3, 0x99));
                StatusStrip.BorderBrush = new SolidColorBrush(Color.FromArgb(0x40, 0x34, 0xD3, 0x99));
                StatusStrip.BorderThickness = new Thickness(1);
                StatusIcon.Text = "✓";
                StatusIcon.Foreground = FindResource("AccentGreenBrush") as Brush;
                StatusMain.Text = _firstVisit
                    ? "First visit — from now on, every change will appear here."
                    : "Nothing needs your attention.";
                StatusMain.Foreground = FindResource("TextPrimaryBrush") as Brush;
                StatusSub.Text = _firstVisit ? "" :
                    visible == 0 ? "No incidents in this range." :
                    $"{visible} incident{(visible == 1 ? "" : "s")} in this range";
                StatusSub.Foreground = FindResource("TextSecondaryBrush") as Brush;
            }

            StatusWhen.Text = _firstVisit ? "" :
                $"You last looked {_lastSeenUtc.ToLocalTime():ddd h:mm tt}";
            StatusWhen.Foreground = FindResource("TextSecondaryBrush") as Brush;
        }

        // ── controls ────────────────────────────────────────────────────

        private void Filter_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (IncidentsList == null) return;   // ctor-time selections
            ApplyFilters();
            UpdateStatusStrip();
        }

        private void LedgerCheck_Changed(object sender, RoutedEventArgs e)
        {
            if (IncidentsList == null) return;
            bool ledger = LedgerCheck.IsChecked == true;
            LedgerGrid.Visibility = ledger ? Visibility.Visible : Visibility.Collapsed;
            IncidentsList.Visibility = ledger ? Visibility.Collapsed : Visibility.Visible;
            ApplyFilters();   // refresh the empty-state verdict for the active view
        }

        private void ReviewInBlocks_Click(object sender, RoutedEventArgs e)
        {
            var win = Window.GetWindow(this);
            if (win?.FindName("BlocksNavItem") is TabItem tab) tab.IsSelected = true;
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV (*.csv)|*.csv",
                FileName = $"audit-events-{DateTime.Now:yyyyMMdd-HHmm}.csv"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                string cat = SelectedCategory;
                bool InRangeEvent(AuditEvent ev) => TimeCombo.SelectedIndex switch
                {
                    0 => !_firstVisit && ev.TimeUtc > _lastSeenUtc,
                    1 => ev.TimeUtc > DateTime.UtcNow.AddHours(-24),
                    2 => ev.TimeUtc > DateTime.UtcNow.AddDays(-7),
                    _ => true
                };
                var lines = new List<string> { "TimeUtc,Category,Action,Kind,Target,Detail,Actor" };
                foreach (var ev in _events
                    .Where(InRangeEvent)
                    .Where(ev => cat == "all" || AuditTrail.CategoryOf(ev.Action) == cat)
                    .OrderByDescending(ev => ev.TimeUtc))
                {
                    lines.Add($"{ev.TimeUtc:O},{AuditTrail.CategoryOf(ev.Action)},{ev.Action}," +
                              $"{Csv(ev.Kind)},{Csv(ev.Key)},{Csv(ev.Detail)},{Csv(AuditTrail.ActorFor(ev.Origin))}");
                }
                File.WriteAllLines(dlg.FileName, lines);
                StatusWhen.Text = $"Exported {lines.Count - 1} event(s) → {System.IO.Path.GetFileName(dlg.FileName)}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Audit export",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private static string Csv(string s) =>
            (s ?? "").Contains(',') || (s ?? "").Contains('"')
                ? $"\"{(s ?? "").Replace("\"", "'")}\""
                : (s ?? "");
    }
}
