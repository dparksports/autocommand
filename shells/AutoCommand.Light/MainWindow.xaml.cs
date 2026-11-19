using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace AutoCommand.Light
{
    /// <summary>
    /// The shell around the gatekeeper: four views, the panic action, the
    /// onboarding overlay, and the ask orchestration — one Ask dialog at a
    /// time, each with the 90-second safe default. The tray carries the
    /// same states for the moments nobody is looking at the window.
    /// </summary>
    public partial class MainWindow : Window
    {
        private TrayController? _tray;
        private AskDialog? _openAsk;
        private int _onbStep;

        public MainWindow()
        {
            InitializeComponent();

            try
            {
                VersionText.Text = "AutoCommand Light v" +
                    FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion;
            }
            catch { VersionText.Text = "AutoCommand Light"; }

            // deny toasts surface as the ask language already on Today; the
            // tray keeps the same state machine for window-closed moments
            AutoCommand.Contain.Core.FirewallDenyWatchService.Instance.OnDenyToast =
                (title, message, onActivated) => Dispatcher.BeginInvoke(new Action(() =>
                {
                    MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
                    onActivated?.Invoke();
                }));

            LightGate.Changed += () => Dispatcher.BeginInvoke(new Action(() =>
            {
                RefreshGateStatus();
                PumpAsks();
            }));

            if (!File.Exists(OnboardingMarkerPath))
            {
                Onboarding.Visibility = Visibility.Visible;
                _onbStep = 1;
            }
        }

        private static string OnboardingMarkerPath =>
            Path.Combine(LightServices.Root, "gate-onboarded.txt");

        // ── navigation ──────────────────────────────────────────────────

        public void NavigateTo(string token)
        {
            var item = token switch
            {
                "apps" => (TabItem)AppsNavItem,
                "attempts" => (TabItem)AttemptsNavItem,
                "ask" => (TabItem)HelpNavItem,
                "settings" => (TabItem)SettingsNavItem,
                _ => (TabItem)TodayNavItem,
            };
            MainTabs.SelectedItem = item;
            if (token == "attempts") AttemptsTab.Refresh();
            if (token == "apps") AppsTab.Rebuild();
            if (token == "today") TodayTab.Rebuild();
        }

        // ── onboarding ──────────────────────────────────────────────────

        private void OnbBtn_Click(object sender, RoutedEventArgs e)
        {
            _onbStep++;
            OnbStep1.Visibility = _onbStep == 1 ? Visibility.Visible : Visibility.Collapsed;
            OnbStep2.Visibility = _onbStep == 2 ? Visibility.Visible : Visibility.Collapsed;
            OnbStep3.Visibility = _onbStep == 3 ? Visibility.Visible : Visibility.Collapsed;
            OnbBtn.Content = _onbStep >= 3 ? "Start guarding" : "Next";
            if (_onbStep > 3)
            {
                Onboarding.Visibility = Visibility.Collapsed;
                try { File.WriteAllText(OnboardingMarkerPath, DateTime.UtcNow.ToString("o")); }
                catch { // read-only profile: the hello repeats next session
                }
            }
        }

        // ── the ask queue: one dialog at a time, 90s, silence = Never ───

        private void PumpAsks()
        {
            if (_openAsk != null) return;
            var next = LightGate.PendingAsks().OrderBy(t => t.RaisedUtc).FirstOrDefault();
            if (next == null) return;

            var dialog = new AskDialog(next);
            _openAsk = dialog;
            dialog.Closed += (s, e) =>
            {
                _openAsk = null;
                if (dialog.Answered)
                {
                    LightGate.Decide(dialog.Ticket.Key, dialog.Answer, dialog.Ticket.DisplayName,
                        dialog.Ticket.ImagePath, "ask-dialog",
                        dialog.AllowOnce ? TimeSpan.FromMinutes(10) : null);
                }
                Dispatcher.BeginInvoke(new Action(PumpAsks), DispatcherPriority.Background);
            };
            dialog.Show();
        }

        // ── gate status + tray ──────────────────────────────────────────

        public void RefreshGateStatus()
        {
            var attempts = LightGate.AttemptsToday().Count;
            var asks = LightGate.PendingAsks().Count;

            if (LightGate.IsOpen)
            {
                GateDot.SetResourceReference(System.Windows.Shapes.Ellipse.FillProperty, "AccentAmberBrush");
                GateText.Text = "the internet is open for everyone — the gate returns on its own";
            }
            else if (asks > 0)
            {
                GateDot.SetResourceReference(System.Windows.Shapes.Ellipse.FillProperty, "AccentAmberBrush");
                GateText.Text = asks == 1
                    ? "1 app is waiting for your answer"
                    : $"{asks} apps are waiting for your answer";
            }
            else
            {
                GateDot.SetResourceReference(System.Windows.Shapes.Ellipse.FillProperty, "AccentGreenBrush");
                GateText.Text = "gate is up — only your browser and allowed apps talk";
            }

            // tray: same three states, readable with or without the window
            var state = asks > 0 ? TrayController.TrayState.Asking
                : attempts > 0 ? TrayController.TrayState.Stopped
                : TrayController.TrayState.Quiet;
            var tooltip = state switch
            {
                TrayController.TrayState.Asking => $"{asks} app(s) waiting for your answer",
                TrayController.TrayState.Stopped => $"{attempts} attempt(s) stopped today",
                _ => "quiet — only allowed apps are talking",
            };
            _tray?.Update(tooltip, state);
        }

        // ── panic ───────────────────────────────────────────────────────

        private async void OpenBtn_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(this,
                "Open the internet for everyone for 10 minutes?\n\n" +
                "Every block pauses — Light's and the Advanced app's. Nothing is deleted, " +
                "and the gate comes back on its own when the ten minutes end.",
                "🚑 Open the internet", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;
            OpenBtn.IsEnabled = false;
            try
            {
                await LightGate.OpenForEveryoneAsync(TimeSpan.FromMinutes(10));
                RefreshGateStatus();
            }
            finally { OpenBtn.IsEnabled = true; }
        }

        public void AttachTray(TrayController tray)
        {
            _tray = tray;
            RefreshGateStatus();
        }

        /// <summary>The tray click path: the window may have been closed
        /// to the tray — show it before navigating.</summary>
        public void ShowFromTray()
        {
            if (!IsVisible)
            {
                Show();
                WindowState = WindowState.Normal;
            }
            Activate();
        }
    }
}
