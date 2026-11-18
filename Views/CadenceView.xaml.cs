using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
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

        public CadenceView()
        {
            InitializeComponent();

            _timer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(60),
            };

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
            _timer.Tick += (_, _) => Reload();

            var diag = Services.DiagTrackPacketsService.Instance;
            diag.Changed += () => Dispatcher.BeginInvoke(() => { if (IsVisible) Reload(); });
            diag.Initialize();
        }

        // ── wiring ───────────────────────────────────────────────────────

        private void RefreshNow_Click(object sender, RoutedEventArgs e)
        {
            // flip the status line immediately, then scan off the UI
            // thread — ScanNow raises Changed, which reloads the view
            // when the pass lands. Re-clicks are harmless: concurrent
            // ScanNow calls collapse into the running one.
            Reload();
            _ = Task.Run(() => Services.DiagTrackPacketsService.Instance.ScanNow());
        }

        /// <summary>The "actual vs reported" cross-check, in-app: Search
        /// re-reads the archive fresh (it flushes the archive's buffers
        /// first, so it sees the freshest lines), and every svchost
        /// EID-3 row is bucketed against what the Exfil scanner counted.
        /// The buckets are honest about what counts alone cannot split:
        /// an unknown guid is another svchost service (bits, dosvc…) or
        /// an unlearned utcsvc instance — either way the matrix stays
        /// conservative, never overclaiming.</summary>
        private void Verify_Click(object sender, RoutedEventArgs e)
        {
            VerifyButton.IsEnabled = false;
            VerifyText.Text = "verifying — streaming the archive for the last 15 minutes…";

            var diag = Services.DiagTrackPacketsService.Instance;
            _ = Task.Run(() =>
            {
                string text;
                try
                {
                    var sinceUtc = DateTime.UtcNow.AddMinutes(-15);
                    var rows = SysmonArchiveService.Search(3, "svchost", sinceUtc, int.MaxValue);

                    int raw = 0, knownGuid = 0;
                    foreach (var e in rows)
                    {
                        // `contains` prefilters on any data value —
                        // ParentImage matches too — so the Image check is
                        // the actual identity test
                        if (!e.Data.TryGetValue("Image", out var img) ||
                            img.IndexOf("svchost", StringComparison.OrdinalIgnoreCase) < 0)
                            continue;
                        raw++;
                        if (e.Data.TryGetValue("ProcessGuid", out var g) && diag.IsKnownDiagGuid(g))
                            knownGuid++;
                    }

                    var attributed = diag.RecentCount(TimeSpan.FromMinutes(15));
                    var unknown = raw - knownGuid;
                    var lagging = knownGuid - attributed;

                    string verdict;
                    if (attributed > knownGuid)
                        verdict = "attributed exceeds the archive read — a rescan raced this check; verify again.";
                    else if (lagging > 0)
                        verdict = $"{lagging} row(s) are countable but not ingested yet — the scanner is behind the archive; click refresh now.";
                    else if (raw == 0)
                        verdict = "no svchost connection rows in this window — nothing to reconcile.";
                    else
                        verdict = "the scanner is in sync — rows outside DiagTrack are other svchost services by guid, and the matrix never overclaims.";

                    text = $"verify last 15 min — archive: {raw} svchost connection row(s) · " +
                           $"attributed to DiagTrack: {attributed} · unknown guid: {unknown}" +
                           Environment.NewLine + verdict;
                }
                catch
                {
                    text = "verify failed — the archive read could not complete; try again.";
                }
                Dispatcher.BeginInvoke(() =>
                {
                    VerifyButton.IsEnabled = true;
                    VerifyText.Text = text;
                });
            });
        }

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
                "Exfil", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
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

                ScanStatusText.Text = BuildScanStatus(diag);
            }
            catch
            {
                // a tab must never take the app down over a refresh
            }
        }

        /// <summary>One line answering "is this pipeline live?": scan
        /// cadence and next pass (so a stale view is diagnosable as "the
        /// instrument is slow or disabled", not "data is missing"), plus
        /// the newest ingested packet time.</summary>
        private static string BuildScanStatus(Services.DiagTrackPacketsService diag)
        {
            if (!diag.FirstScanComplete)
                return $"scanning archive… {diag.ScanDaysDone}/{diag.ScanDaysTotal} day files";

            var newest = diag.NewestEventLocal();
            var newestText = newest == null ? "no packets yet" : "newest packet " + newest.Value.ToString("HH:mm");
            var tail = $"archive scanned ({diag.ScanDaysDone}/{diag.ScanDaysTotal} day files) · {newestText}";

            var st = Services.InstrumentMetronome.Instance.Snapshot()
                .FirstOrDefault(s => s.Spec.Id == "diagtrack-cadence-scan");
            if (st == null) return tail;
            if (!st.Enabled)
                return tail + " · scan DISABLED in Settings → instruments";

            var paused = st.Paused ? " · paused" : "";
            var cadence = st.Seconds >= 60 ? $"{st.Seconds / 60}m" : $"{st.Seconds}s";
            var next = st.NextRunUtc - DateTime.UtcNow;
            var nextText = next.TotalSeconds <= 0 ? "next: now"
                : next.TotalMinutes < 1 ? $"next in {(int)Math.Ceiling(next.TotalSeconds)}s"
                : $"next in {(int)Math.Ceiling(next.TotalMinutes)}m";
            return $"{tail} · scan every {cadence}{paused} · {nextText}";
        }

        // ── matrix: one column per day, each cell split in half ──────────
        // left half = typing counts (amber heat, opt-in), right half =
        // DiagTrack packets (cyan heat) — the day is the whole header, so a
        // non-technical user reads "left me, right the machine" without
        // decoding K/P labels.

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

                    var k = keys != null && keys.TryGetValue(day, out var ka) ? ka[h] : (int?)null;
                    var p = packets.TryGetValue(day, out var pa) ? pa[h]
                        : (covered.Contains(day) ? 0 : (int?)null);
                    var s = sessions.TryGetValue(day, out var sa) ? sa[h]
                        : (covered.Contains(day) ? 0 : (int?)null);

                    // the consent boundary, enforced in the model: without the
                    // toggle the typing side is null ("no data"), never zero
                    row.Keys[d] = k;
                    row.Packets[d] = p;
                    row.Sessions[d] = s;

                    row.Tips[d] =
                        $"keys: {(k == null ? "not tracked" : k.Value.ToString())}" +
                        $" · packets: {(p == null ? "not scanned" : p.Value.ToString())}" +
                        $" · sessions: {(s == null ? "n/a" : s.Value.ToString())}";
                }
                rows.Add(row);
            }

            CadenceGrid.Columns.Clear();

            // hour labels: readable by design — wider column, smaller muted
            // font, so "00h" never clips
            var hourStyle = new Style(typeof(DataGridCell));
            hourStyle.Setters.Add(new Setter(
                System.Windows.Documents.TextElement.FontSizeProperty, 11.0));
            hourStyle.Setters.Add(new Setter(
                System.Windows.Documents.TextElement.ForegroundProperty,
                FindResource("TextSecondaryBrush") as System.Windows.Media.Brush));

            CadenceGrid.Columns.Add(new DataGridTextColumn
            {
                Header = "hour",
                Binding = new Binding(nameof(HourRow.Hour)),
                IsReadOnly = true,
                Width = 54,
                CellStyle = hourStyle,
            });

            var star = new DataGridLength(1, DataGridLengthUnitType.Star);
            // Per-column header style MUST derive from the app's implicit
            // DataGridColumnHeader style (BasedOn): a bare new Style silently
            // replaces it, the day headers fall back to the default silver
            // chrome while inheriting the grid's light TextPrimary foreground,
            // and the labels turn light-on-light - unreadable.
            var headerStyle = new Style(typeof(System.Windows.Controls.Primitives.DataGridColumnHeader))
            {
                BasedOn = (Style)FindResource(typeof(System.Windows.Controls.Primitives.DataGridColumnHeader))
            };
            headerStyle.Setters.Add(new Setter(ToolTipService.ToolTipProperty,
                "left half = your typing counts (opt-in) · right half = DiagTrack packets"));

            for (int d = 0; d < _days.Count; d++)
            {
                CadenceGrid.Columns.Add(new DataGridTemplateColumn
                {
                    Header = _days[d].Substring(5),
                    CellTemplate = BuildDualCellTemplate(d),
                    Width = star,
                    HeaderStyle = headerStyle,
                });
            }

            CadenceGrid.ItemsSource = rows;
        }

        /// <summary>One day column's dual-half cell, built by parsing plain
        /// XAML — the bindings are ordinary markup, the heat converter is
        /// embedded in the template's own resources.</summary>
        private DataTemplate BuildDualCellTemplate(int d)
        {
            string keysPath = "Keys[" + d + "]";
            string packetsPath = "Packets[" + d + "]";
            string tipsPath = "Tips[" + d + "]";

            string xaml =
                "<DataTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'\n" +
                "                xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'\n" +
                "                xmlns:conv='clr-namespace:AutoCommand.Converters;assembly=AutoCommand'>\n" +
                "  <DataTemplate.Resources>\n" +
                "    <conv:CountToHeatConverter x:Key='Heat'/>\n" +
                "  </DataTemplate.Resources>\n" +
                "  <Grid Background='Transparent' ToolTip='{Binding " + tipsPath + "}'>\n" +
                "    <Grid.ColumnDefinitions>\n" +
                "      <ColumnDefinition Width='*'/>\n" +
                "      <ColumnDefinition Width='*'/>\n" +
                "    </Grid.ColumnDefinitions>\n" +
                "    <Border Grid.Column='0' Background='{Binding " + keysPath + ", Converter={StaticResource Heat}, ConverterParameter=keys}'\n" +
                "            BorderBrush='{DynamicResource BorderBrush}' BorderThickness='0,0,0.6,0'>\n" +
                "      <TextBlock Text='{Binding " + keysPath + ", TargetNullValue=—}' FontSize='10'\n" +
                "                 HorizontalAlignment='Center' VerticalAlignment='Center'\n" +
                "                 Foreground='{DynamicResource TextPrimaryBrush}'/>\n" +
                "    </Border>\n" +
                "    <Border Grid.Column='1' Background='{Binding " + packetsPath + ", Converter={StaticResource Heat}, ConverterParameter=packets}'>\n" +
                "      <TextBlock Text='{Binding " + packetsPath + ", TargetNullValue=—}' FontSize='10'\n" +
                "                 HorizontalAlignment='Center' VerticalAlignment='Center'\n" +
                "                 Foreground='{DynamicResource TextPrimaryBrush}'/>\n" +
                "    </Border>\n" +
                "  </Grid>\n" +
                "</DataTemplate>";

            return (DataTemplate)System.Windows.Markup.XamlReader.Parse(xaml);
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
