using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;

using AutoCommand.Helpers;

#nullable enable

namespace AutoCommand.Views
{
    /// <summary>
    /// Cadence tab — DiagTrack's hourly transmit cadence beside the (strictly
    /// opt-in) hourly typing counts, 7 local days × 24 hours, with a
    /// plain-language correlation verdict. Two presentation rules shape it:
    /// the typing side shows NOTHING until the user's toggle is on (missing
    /// days render "—" — never zeros implying tracking happened), and BOTH
    /// series are always visible together — the matrix renders each day as
    /// adjacent K|P columns and the strip chart draws both per hour — there
    /// is no mode to switch, so the two presentations stay continuous.
    /// </summary>
    public partial class CadenceView : UserControl
    {
        private sealed class HourRow
        {
            public string Hour { get; set; } = "";
            public int?[] Keys { get; set; } = new int?[7];
            public int?[] Packets { get; set; } = new int?[7];
            public int?[] Sessions { get; set; } = new int?[7];
            public string[] Tips { get; set; } = new string[7];
        }

        private readonly DispatcherTimer _timer;
        private bool _syncingToggle;
        private List<string> _days = new();
        private IValueConverter _heat = null!;

        public CadenceView()
        {
            InitializeComponent();
            _heat = (IValueConverter)FindResource("Heat");

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

                BuildMatrix(packets, sessions, covered, keys);
                BuildStrips(packets, keys);
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

        // ── matrix: every day renders BOTH series as adjacent K|P columns ─

        private void BuildMatrix(
            Dictionary<string, int[]> packets,
            Dictionary<string, int[]> sessions,
            HashSet<string> covered,
            Dictionary<string, int[]>? keys)
        {
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

                    row.Tips[d] =
                        $"keys: {(row.Keys[d] == null ? "not tracked" : row.Keys[d].Value.ToString())}" +
                        $" · packets: {(row.Packets[d] == null ? "not scanned" : row.Packets[d].Value.ToString())}" +
                        $" · sessions: {(row.Sessions[d] == null ? "n/a" : row.Sessions[d].Value.ToString())}";
                }
                rows.Add(row);
            }

            CadenceGrid.Columns.Clear();
            CadenceGrid.Columns.Add(new DataGridTextColumn
            {
                Header = "hour",
                Binding = new Binding(nameof(HourRow.Hour)),
                IsReadOnly = true,
                Width = 46,
            });

            var star = new DataGridLength(1, DataGridLengthUnitType.Star);
            for (int d = 0; d < _days.Count; d++)
            {
                var dayShort = _days[d].Substring(5);
                var tip = new Binding($"Tips[{d}]");
                AddCountColumn("K " + dayShort, $"Keys[{d}]", "keys", tip, star);
                AddCountColumn("P " + dayShort, $"Packets[{d}]", "packets", tip, star);
            }

            CadenceGrid.ItemsSource = rows;
        }

        private void AddCountColumn(
            string header, string path, string heatMode, Binding tip, DataGridLength width)
        {
            var cellStyle = new Style(typeof(DataGridCell));
            cellStyle.Setters.Add(new Setter(
                DataGridCell.BackgroundProperty,
                new Binding(path) { Converter = _heat, ConverterParameter = heatMode }));
            cellStyle.Setters.Add(new Setter(ToolTipService.ToolTipProperty, tip));

            CadenceGrid.Columns.Add(new DataGridTextColumn
            {
                Header = header,
                Binding = new Binding(path) { TargetNullValue = "—" },
                IsReadOnly = true,
                Width = width,
                CellStyle = cellStyle,
            });
        }

        // ── strip chart: one strip per day, both series per hour ─────────

        private void BuildStrips(
            Dictionary<string, int[]> packets,
            Dictionary<string, int[]>? keys)
        {
            var strips = _days.Select((day, i) => new CadenceDayStrip
            {
                Label = day.Substring(5),
                Keys = keys != null && keys.TryGetValue(day, out var ka) ? ka : new int[24],
                Packets = packets.TryGetValue(day, out var pa) ? pa : new int[24],
                IsToday = i == _days.Count - 1,
            }).ToList();

            Chart.SetStrips(
                "gray bars = keys counted (opt-in) · cyan ticks = DiagTrack packets · " +
                "one strip per day, newest last · both series always shown",
                strips);
        }

        // ── verdict ──────────────────────────────────────────────────────

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
                packets.TryGetValue(d, out var pa) ? pa : new int[24]));

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
