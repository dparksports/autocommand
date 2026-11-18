using System.Windows;
using AutoCommand.Agent.Core.DirectChat;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>Opt-in prompt for direct chat. Writes the consent answer
    /// into ChatStore's settings.json itself and closes — same
    /// written-by-the-dialog contract as UsagePingConsentDialog, so callers
    /// just re-read the store afterwards. "Not now" leaves consent unset;
    /// the tab's setup card stays until the user returns.</summary>
    public partial class ChatConsentDialog : Window
    {
        public ChatConsentDialog()
        {
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
        }

        private void EnableBtn_Click(object sender, RoutedEventArgs e)
        {
            var settings = ChatStore.Load();
            settings.Consent = true;
            ChatStore.Save(settings);
            DialogResult = true;
        }

        private void NotNowBtn_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    }
}
