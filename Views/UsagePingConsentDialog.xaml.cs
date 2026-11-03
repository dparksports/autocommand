using System.Windows;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Windows.Navigation;
using AutoCommand.Services;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>Opt-in prompt for the anonymous daily count. Writes the answer
    /// to HKCU (Consent = yes|no|ask) itself and closes; "Maybe later" keeps
    /// consent=ask so the offer can reappear (bounded by UsagePingService.MaxAsks).
    /// The community-graph link only appears when the endpoint is deployed.</summary>
    public partial class UsagePingConsentDialog : Window
    {
        public UsagePingConsentDialog()
        {
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
            if (UsagePingService.GraphPageUrl != null)
                GraphLink.Visibility = Visibility.Visible;
        }

        private void YesBtn_Click(object sender, RoutedEventArgs e)
        {
            UsagePingService.SetConsent("yes");
            DialogResult = true;
        }

        private void NoBtn_Click(object sender, RoutedEventArgs e)
        {
            UsagePingService.SetConsent("no");
            DialogResult = true;
        }

        private void LaterBtn_Click(object sender, RoutedEventArgs e)
        {
            // Consent stays "ask"; the Asks counter (already incremented by the
            // caller) bounds how many times this dialog can reappear.
            DialogResult = true;
        }

        private void GraphHyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            try
            {
                var url = UsagePingService.GraphPageUrl ?? UsagePingService.ReleasesUrl;
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch { /* browser launch refused — nothing to do */ }
            e.Handled = true;
        }
    }
}
