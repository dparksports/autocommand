using System;
using System.Windows;
using System.Windows.Threading;

namespace AutoCommand.Light
{
    /// <summary>
    /// The question, in the platform's permission grammar. Three answers,
    /// none of them tricks: Allow once (10 minutes), Always allow, Never.
    /// Escape, closing, or 90 seconds of silence all mean Never — the
    /// same safe default as the AI gates, because this dialog usually
    /// appears when nobody is sitting at the desk mentally.
    /// </summary>
    public partial class AskDialog : Window
    {
        private readonly DispatcherTimer _countdown = new(DispatcherPriority.Background)
        { Interval = TimeSpan.FromSeconds(1) };
        private int _secondsLeft = Core.AskTicket.TimeoutSeconds;

        /// <summary>The ticket this dialog answers — the caller decides
        /// with it when the dialog closes.</summary>
        public readonly Core.AskTicket Ticket;

        public Core.AppPermission Answer { get; private set; } = Core.AppPermission.Never;
        public bool Answered { get; private set; }

        public AskDialog(Core.AskTicket ticket)
        {
            InitializeComponent();
            Ticket = ticket;

            HeadlineText.Text = $"“{ticket.DisplayName}” wants to reach the internet";
            var path = ticket.ImagePath ?? "";
            var placed = path.Length > 0
                ? "It runs from " + path
                : "AutoCommand could not yet tell where it runs from.";
            DetailText.Text = "The gate held it until you decide. " + placed;

            Owner = Application.Current.MainWindow;
            Owner.Opacity = 0.45;
            Topmost = true;

            if (ticket.UserDriven)
            {
                // the person is driving this app right now — no countdown:
                // the question waits for them, the gate keeps holding
                CountdownText.Text = "Still held — decide whenever you're ready.";
            }
            else
            {
                UpdateCountdown();
                _countdown.Tick += (s, e) =>
                {
                    _secondsLeft--;
                    UpdateCountdown();
                    if (_secondsLeft <= 0) FinishNoDecision();
                };
                _countdown.Start();
            }
        }

        private void UpdateCountdown() =>
            CountdownText.Text = $"No answer keeps it held — decide later in Apps ({_secondsLeft}s)";

        private void OnceBtn_Click(object s, RoutedEventArgs e) =>
            Finish(Core.AppPermission.Always, allowOnce: true);

        private void AlwaysBtn_Click(object s, RoutedEventArgs e) =>
            Finish(Core.AppPermission.Always);

        private void NeverBtn_Click(object s, RoutedEventArgs e) =>
            Finish(Core.AppPermission.Never);

        /// <summary>Countdown ran out (unattended app): the dialog simply
        /// closes. No decision travels anywhere — the app stays HELD as an
        /// Ask and the question moves to the digest. Never is explicit.
        /// (Non-modal window: DialogResult would throw, so no-decision is
        /// just "closed without Answered".)</summary>
        private void FinishNoDecision()
        {
            if (Answered) return;
            _countdown.Stop();
            if (Owner != null) Owner.Opacity = 1.0;
            Close();
        }

        private void Finish(Core.AppPermission answer, bool allowOnce = false)
        {
            if (Answered) return;
            Answered = true;
            Answer = answer;
            AllowOnce = allowOnce;
            _countdown.Stop();
            if (Owner != null) Owner.Opacity = 1.0;
            Close();
        }

        public bool AllowOnce { get; private set; }

        protected override void OnClosed(EventArgs e)
        {
            _countdown.Stop();
            if (Owner != null && !Answered) Owner.Opacity = 1.0;
            base.OnClosed(e);
        }
    }
}
