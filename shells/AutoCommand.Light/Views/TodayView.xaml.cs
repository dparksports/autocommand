using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The home screen: one headline, one honest state. Quiet is the
    /// product and gets top billing; stopped attempts are counted and
    /// named, never dramatized. Data comes straight from the gate's
    /// rings — the sentences are composed by the pure TodayStats.
    /// </summary>
    public partial class TodayView : UserControl
    {
        public TodayView()
        {
            InitializeComponent();
            Loaded += (s, e) => Rebuild();
            LightGate.Changed += () => Dispatcher.BeginInvoke(new Action(Rebuild));
            // the histogram bars and headline tint are chosen in code —
            // a theme swap re-resolves them against the new palette
            LightTheme.Changed += () => Dispatcher.BeginInvoke(new Action(Rebuild));
        }

        public void Rebuild() => _ = RebuildAsync();

        private async System.Threading.Tasks.Task RebuildAsync()
        {
            DateText.Text = DateTime.Now.ToString("dddd, MMMM d");

            var attempts = await System.Threading.Tasks.Task.Run(() =>
                LightGate.AttemptsToday().ToList());
            var asks = LightGate.PendingAsks().Count;
            var model = TodayStats.Compose(attempts, asks, DateTime.Now);

            HeadlineText.Text = model.Headline;
            HeadlineText.SetResourceReference(TextBlock.ForegroundProperty, model.Tone switch
            {
                LightTone.Good => "AccentGreenBrush",
                LightTone.Watch => "AccentAmberBrush",
                _ => "AccentRedBrush",
            });
            SublineText.Text = model.Subline;

            if (asks > 0)
            {
                AsksBanner.Visibility = Visibility.Visible;
                AsksText.Text = asks == 1
                    ? "One app tried to reach the internet and is waiting for your answer."
                    : $"{asks} apps tried to reach the internet and are waiting for your answer.";
            }
            else AsksBanner.Visibility = Visibility.Collapsed;

            AttemptsList.Children.Clear();
            AttemptsEmpty.Visibility = model.StoppedAttempts == 0 ? Visibility.Visible : Visibility.Collapsed;
            foreach (var (app, count) in model.TopApps.Take(6))
            {
                var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 5) };
                row.Children.Add(new TextBlock
                {
                    Text = app,
                    FontWeight = FontWeights.SemiBold,
                    VerticalAlignment = VerticalAlignment.Center,
                });
                row.Children.Add(new TextBlock
                {
                    Text = count == 1 ? "1 attempt stopped" : $"{count} attempts stopped",
                    FontSize = 12,
                    Margin = new Thickness(12, 0, 0, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                });
                AttemptsList.Children.Add(row);
            }

            var max = Math.Max(1, model.HourHistogram.Max());
            Hours.ItemsSource = model.HourHistogram.Select((n, hour) =>
            {
                var h = n == 0 ? 3 : 6 + (int)(54.0 * n / max);
                return new
                {
                    Height = (double)h,
                    Brush = (Brush)FindResource(n == 0 ? "GridLineBrush" : "AccentBlueBrush"),
                    Label = n == 0 ? $"{hour}:00 — quiet" : $"{hour}:00 — {n} attempt(s) stopped",
                };
            }).ToList();
        }

        private void ReviewBtn_Click(object sender, RoutedEventArgs e) =>
            (Application.Current.MainWindow as MainWindow)?.NavigateTo("apps");

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => Rebuild();
    }
}
