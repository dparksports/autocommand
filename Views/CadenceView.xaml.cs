using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

using AutoCommand.Helpers;

#nullable enable

namespace AutoCommand.Views
{
    /// <summary>
    /// Cadence tab — DiagTrack's hourly transmit cadence beside the (strictly
    /// opt-in) hourly typing counts, 7 local days × 24 hours, with a
    /// plain-language correlation verdict. Two hard rules shape this view:
    /// the typing side shows NOTHING until the user's toggle is on (missing
    /// days render "—" — never zeros implying tracking happened), and the
    /// verdict is only computed over days that were actually tracked.
    /// </summary>
    public partial class CadenceView : UserControl
    {
        private sealed class HourRow
        {
            public string Hour { get; set; } = "";
            public int?[] Keys { get; set; } = new int?[7];
            public int?[] Packets { get; set; } = new int?[7];
            public int?[] Sessions { get; set; } = new int?[7];
        }

        private readonly DispatcherTimer _timer;
        private bool _syncingToggle;
        private List<string> _days = new();

        public CadenceView()
        {
            InitializeComponent();

            IsVisibleChanged += (_, e) =>
            {
                if (e.NewValue is true)
                {
                    Reload();
                    _timer.Start();
                }
                else
                {
                    _timer.Stop();
                }
            };

            _timer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(60),
            };
            _timer.Tick += (_, _) => Reload();

            var diag = Services.DiagTrackPacketsService.Instance;
            diag.Changed += () => Dispatcher.BeginInvoke(() => { if (IsVisible) Reload(); });
            diag.Initialize();
        }

        // ── wiring ───────────────────────────────────────────────────────

        private void ConsentToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (_syncingToggle) return;
            Services.KeyCadenceService.Instance.Enable();
            Reload();
        }

        private void ConsentToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_syncingToggle) return;
            var purge = MessageBox.Show(
                "Stop counting keystrokes?\n\nYes — stop, and also delete the stored hourly counts.\n" +
                "No — stop, but keep the already-collected counts on disk.",
                "Cadence", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
            Services.KeyCadenceService.Instance.Disable(purgeFile: purge);
            Reload();
        }

        private void Mode_Changed(object sender, RoutedEventArgs e)
        {
            if (IsLoaded) Reload();
        }

        private void DayCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsLoaded) Reload();
        }

        // ── data ─────────────────────────────────────────────────────────

        private void Reload()
        {
            try
            {
                var keysService = Services.KeyCadenceService.Instance;
                var diag = Services.DiagTrackPacketsService.Instance;

                _syncingToggle = true;
                try { ConsentToggle.IsChecked = keysService.IsEnabled; }
                finally { _syncingToggle = false; }

                var packets = diag.PacketsPerHour();
                var sessions = diag.SessionsPerHour();
                var covered = diag.ScannedLocalDays();
                Dictionary<string, int[]>? keys = keysService.IsEnabled
                    ? keysService.SnapshotDays()
                    : null;

                _days = Enumerable.Range(0, 7)
                    .Select(i => DateTime.Now.Date.AddDays(-6 + i).ToString("yyyy-MM-dd"))
                    .ToList();

                // refresh the day combo without losing the user's selection
                if (DayCombo.ItemsSource == null ||
                    !DayCombo.Items.Cast<string>().SequenceEqual(_days))
                {
                    var keep = DayCombo.SelectedItem as string;
                    DayCombo.ItemsSource = _days;
                    var pick = (keep != null && _days.Contains(keep)) ? keep : _days.Last();
                    _syncingCombo = true;
                    DayCombo.SelectedItem = pick;
                    _syncingCombo = false;
                }

                BuildMatrix(packets, sessions, covered, keys);
                RenderChart(packets, keys);
                BuildVerdict(packets, covered, keys);

                ScanStatusText.Text = diag.FirstScanComplete
                    ? $"archive scanned ({diag.ScanDaysDone}/{diag.ScanDaysTotal} day files)"
                    : $"scanning archive… {diag.ScanDaysDone}/{diag.ScanDaysTotal} day files";
            }
            catch
            {
                // a tab must never take the app down over a refresh
            }
        }

        private bool _syncingCombo;

        private void BuildMatrix(
            Dictionary<string, int[]> packets,
            Dictionary<string, int[]> sessions,
            HashSet<string> covered,
            Dictionary<string, int[]>? keys)
        {
            bool keysOn = keys != null;
            bool keysMode = KeysRadio.IsChecked == true;

            var rows = new List<HourRow>();
            for (int h = 0; h < 24; h++)
            {
                var row = new HourRow { Hour = $"{h:00}h" };
                for (int d = 0; d < _days.Count; d++)
                {
                    var day = _days[d];

                    row.Packets[d] = packets.TryGetValue(day, out var pa) ? pa[h]
                        : (covered.Contains(day) ? 0 : (int?)null);

                    row.Sessions[d] = sessions.TryGetValue(day, out var sa) ? sa[h]
                        : (covered.Contains(day) ? 0 : (int?)null);

                    // the consent boundary, enforced in the model: without the
                    // toggle the typing side is null ("no data"), never zero
                    row.Keys[d] = keys != null && keys.TryGetValue(day, out var ka) ? ka[h] : (int?)null;
                }
                rows.Add(row);
            }

            CadenceGrid.Columns.Clear();
            CadenceGrid.Columns.Add(new DataGridTextColumn
            {
                Header = "hour",
                Binding = new Binding(nameof(HourRow.Hour)),
                IsReadOnly = true,
                Width = 50,
            });

            string modeParam = keysMode ? "keys" : "packets";
            for (int d = 0; d < _days.Count; d++)
            {
                string path = keysMode ? $"Keys[{d}]" : $"Packets[{d}]";
                var tipBinding = new Binding($"Sessions[{d}]")
                {
                    StringFormat = "{0} session(s) this hour",
                    TargetNullValue = "not scanned",
                };

                var cellStyle = new Style(typeof(DataGridCell));
                cellStyle.Setters.Add(new Setter(
                    DataGridCell.BackgroundProperty,
                    new Binding(path) { Converter = FindResource("Heat") as IValueConverter, ConverterParameter = modeParam }));
                cellStyle.Setters.Add(new Setter(ToolTipService.ToolTipProperty, tipBinding));

                CadenceGrid.Columns.Add(new DataGridTextColumn
                {
                    Header = _days[d].Substring(5),
                    Binding = new Binding(path) { TargetNullValue = "—" },
                    IsReadOnly = true,
                    Width = new DataGridLength(1, DataGridLengthUnitType.Star),
                    CellStyle = cellStyle,
                });
            }

            CadenceGrid.ItemsSource = rows;
        }

        private void RenderChart(Dictionary<string, int[]> packets, Dictionary<string, int[]>? keys)
        {
            var day = DayCombo.SelectedItem as string;
            if (string.IsNullOrEmpty(day)) return;

            bool keysOn = keys != null;
            var k = keys != null && keys.TryGetValue(day, out var ka) ? ka : new int[24];
            var p = packets.TryGetValue(day, out var pa) ? pa : new int[24];
            Chart.SetData($"{day} — gray bar: keys counted · cyan ticks: DiagTrack packets" +
                          (keysOn ? "" : "  (typing counts are OFF — bars stay flat by choice)"), k, p);
        }

        private void BuildVerdict(
            Dictionary<string, int[]> packets,
            HashSet<string> covered,
            Dictionary<string, int[]>? keys)
        {
            if (keys == null)
            {
                VerdictText.Text = "Typing counts are off — enable them above to see whether telemetry follows your typing.";
                TypingLockedText.Text = "";
                return;
            }

            var trackedDays = _days.Where(keys.ContainsKey).ToList();
            if (trackedDays.Count == 0)
            {
                VerdictText.Text = "Counting is on — the first hourly bucket appears after the next minute of typing (and the next flush).";
                TypingLockedText.Text = "";
                return;
            }

            var keysAll = CadenceMath.Concat(trackedDays.Select(d => keys[d]));
            var packetsAll = CadenceMath.Concat(trackedDays.Select(d =>
                packets.TryGetValue(d, out var pa) ? pa : covered.Contains(d) ? new int[24] : new int[24]));

            double? rho = CadenceMath.Spearman(keysAll, packetsAll);
            VerdictText.Text = CadenceMath.Verdict(rho) +
                $"  (ρ = {(rho == null ? "—" : rho.Value.ToString("0.00"))}, {trackedDays.Count} tracked day(s))";

            var chips = trackedDays.Select(d =>
            {
                var pct = CadenceMath.TypingLockedPercent(keys[d], packets.TryGetValue(d, out var pa) ? pa : new int[24]);
                return $"{d.Substring(5)}: " + (pct == null
                    ? "no telemetry packets"
                    : $"{pct.Value:0}% of packets landed in typing hours");
            });
            TypingLockedText.Text = "Typing-locked share of DiagTrack packets — " + string.Join("  ·  ", chips);
        }
    }
}
