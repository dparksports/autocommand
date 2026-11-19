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
        private readonly List<(string Key, string Display, string Path, System.Windows.Controls.CheckBox Box)> _snap = new();

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

            if (_onbStep == 3)
            {
                // step 3 is the running-apps snapshot: taken now, after a
                // few seconds of watching, so the baseline is real
                ShowSnapshotStep();
                OnbStep1.Visibility = Visibility.Collapsed;
                OnbStep2.Visibility = Visibility.Collapsed;
                OnbStepSnap.Visibility = Visibility.Visible;
                OnbStep3.Visibility = Visibility.Collapsed;
                OnbBtn.Content = _snap.Count > 0 ? "Done — keep asking the rest" : "Start guarding";
                return;
            }

            if (_onbStep == 4)
            {
                // apply the trust the user granted on the snapshot screen
                foreach (var (key, display, path, box) in _snap)
                {
                    if (box.IsChecked == true && !string.IsNullOrWhiteSpace(path))
                        LightGate.Decide(key, Core.AppPermission.Always, display, path, "onboarding");
                }
                _snap.Clear();
            }

            OnbStep1.Visibility = _onbStep == 1 ? Visibility.Visible : Visibility.Collapsed;
            OnbStep2.Visibility = _onbStep == 2 ? Visibility.Visible : Visibility.Collapsed;
            OnbStepSnap.Visibility = _onbStep == 3 ? Visibility.Visible : Visibility.Collapsed;
            OnbStep3.Visibility = _onbStep == 4 ? Visibility.Visible : Visibility.Collapsed;
            OnbBtn.Content = _onbStep >= 4 ? "Start guarding" : "Next";
            if (_onbStep > 4)
            {
                Onboarding.Visibility = Visibility.Collapsed;
                try { File.WriteAllText(OnboardingMarkerPath, DateTime.UtcNow.ToString("o")); }
                catch { // read-only profile: the hello repeats next session
                }
            }
        }

        /// <summary>One screen of bulk triage: everything unknown that was
        /// running when the gate closed, so the tools a person already had
        /// open are never the surprise — one checkmark per trusted app.</summary>
        private void ShowSnapshotStep()
        {
            SnapList.Children.Clear();
            _snap.Clear();

            var seen = new List<(string Key, string Display, string Path)>();
            foreach (var row in LightServices.Tracked.Values)
            {
                var key = Core.PermissionStore.NormalizeKey(row.ProcessName);
                if (key.Length == 0) continue;
                if (Core.GatePolicy.ExemptReason(row.ProcessName, row.ImagePath, row.IsSvchost) != Exemption.None)
                    continue;
                if (Core.GatePolicy.IsBrowser(key)) continue;
                var entry = LightGate.Store.Find(key);
                if (entry is { Permission: Core.AppPermission.Always }) continue;
                var display = entry?.DisplayName ?? (row.ProcessName ?? key);
                if (seen.Any(s => s.Key == key)) continue;
                seen.Add((key, display, row.ImagePath ?? ""));
            }

            SnapEmpty.Visibility = seen.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            foreach (var (key, display, path) in seen.Take(10))
            {
                var box = new CheckBox
                {
                    Content = display,
                    FontSize = 14,
                    Margin = new Thickness(0, 6, 0, 6),
                    Foreground = (System.Windows.Media.Brush)FindResource("TextPrimaryBrush"),
                };
                SnapList.Children.Add(box);
                _snap.Add((key, display, path, box));
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
                else
                {
                    // closed, dismissed, or the countdown ran out: the app
                    // stays HELD as an Ask — no decision was made
                    LightGate.TicketDismissed(dialog.Ticket);
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
