using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The landing view: the five-minute first report, then a one-click
    /// refresh any time. All facts are gathered off the UI thread and the
    /// sentences are composed by the pure product core — this view only
    /// renders and deep-links. Honesty rule inherited from the composer:
    /// it shows the reassurance only when the facts earned it.
    /// </summary>
    public partial class OverviewView : UserControl
    {
        private static readonly TimeSpan WatchWindow = TimeSpan.FromMinutes(5);
        private static string MarkerPath => System.IO.Path.Combine(LightServices.Root, "firstrun-seen.txt");

        private readonly DispatcherTimer _countdown = new(DispatcherPriority.Background)
        {
            Interval = WatchWindow
        };
        private DateTime _watchStarted = DateTime.UtcNow;

        public OverviewView()
        {
            InitializeComponent();
            _countdown.Tick += (s, e) => { _countdown.Stop(); _ = BuildReportAsync(); };
            Loaded += (s, e) =>
            {
                if (System.IO.File.Exists(MarkerPath))
                {
                    // returning user: straight to a fresh report
                    WatchCard.Visibility = Visibility.Collapsed;
                    _ = BuildReportAsync();
                }
                else
                {
                    _watchStarted = DateTime.UtcNow;
                    _countdown.Start();
                }
            };
        }

        /// <summary>Deep-link entry (nav token "sysmon"/"overview"): jump
        /// straight to a fresh report regardless of the countdown.</summary>
        public void BeginReport() => _ = BuildReportAsync();

        private void ShowNowBtn_Click(object sender, RoutedEventArgs e) => BeginReport();
        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => BeginReport();

        private async Task BuildReportAsync()
        {
            CountdownText.Text = "Building…";
            WatchCard.Visibility = Visibility.Collapsed;

            const int minutes = 5;
            var report = await Task.Run(() =>
            {
                var (windows, apps, unknown, names, _) = LightServices.Categorize();

                var feed = 0;
                try { feed = BlockHitFeedService.Instance.Recent(minutes, 500).Count; } catch { }
                int denies = 0;
                try { denies = FirewallDenyWatchService.Instance.Recent(minutes, 500).Count; } catch { }
                int attempts = Math.Max(feed, denies);

                var inv = LightServices.Firewall.GetBlockedInventoryAsync().Result;
                int active = inv.Count(b => b.EnabledRules > 0);

                bool sysmon = LightServices.Installer.DetectInstallState() == SysmonInstallState.Installed;

                return FirstRunReport.Compose(new LightFindings(
                    minutes, LightServices.Tracked.Count, windows, apps,
                    unknown, names, attempts, active, sysmon));
            });

            HeadlineText.Text = report.Headline;
            HeadlineText.Foreground = report.Tone switch
            {
                LightTone.Good => (System.Windows.Media.Brush)FindResource("AccentGreenBrush"),
                LightTone.Watch => FindResource("AccentAmberBrush") as System.Windows.Media.Brush,
                _ => FindResource("AccentRedBrush") as System.Windows.Media.Brush,
            };

            ReportLinesPanel.Children.Clear();
            foreach (var line in report.Lines)
                ReportLinesPanel.Children.Add(BuildLine(line));

            TipPanel.Visibility = string.IsNullOrEmpty(report.TipText)
                ? Visibility.Collapsed : Visibility.Visible;
            TipText.Text = report.TipText;
            SysmonBtn.Visibility = report.TipTarget == "sysmon" ? Visibility.Visible : Visibility.Collapsed;

            ReportPanel.Visibility = Visibility.Visible;

            try { System.IO.File.WriteAllText(MarkerPath, DateTime.UtcNow.ToString("o")); }
            catch { // read-only profile: the card simply returns next session
            }
        }

        private UIElement BuildLine(LightReportLine line)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            var dot = new System.Windows.Shapes.Ellipse
            {
                Width = 6,
                Height = 6,
                Fill = (System.Windows.Media.Brush)FindResource("TextSecondaryBrush"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };
            panel.Children.Add(dot);

            var text = new TextBlock
            {
                Text = line.Text,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 560,
                VerticalAlignment = VerticalAlignment.Center
            };
            panel.Children.Add(text);

            if (!string.IsNullOrEmpty(line.ActionLabel))
            {
                var btn = new Button
                {
                    Content = line.ActionLabel,
                    Style = (Style)FindResource("QuietButton"),
                    FontSize = 12,
                    Margin = new Thickness(12, 0, 0, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                    Tag = line.ActionTarget
                };
                btn.Click += (s, e) =>
                    (Application.Current.MainWindow as MainWindow)?.NavigateTo((string)((Button)s).Tag);
                panel.Children.Add(btn);
            }
            return panel;
        }

        private async void SysmonBtn_Click(object sender, RoutedEventArgs e)
        {
            SysmonBtn.IsEnabled = false;
            try
            {
                var (ok, message) = await LightServices.Installer.InstallAndConfigureAsync();
                MessageBox.Show(
                    ok
                        ? "Sysmon is set up. From now on AutoCommand can tell you where every program came from."
                        : $"Sysmon could not be set up automatically.\n\n{message}",
                    "Set up Sysmon", MessageBoxButton.OK,
                    ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
                if (ok) await BuildReportAsync();
            }
            finally { SysmonBtn.IsEnabled = true; }
        }
    }
}
