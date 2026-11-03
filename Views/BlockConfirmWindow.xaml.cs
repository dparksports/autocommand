using System.Windows;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>
    /// Confirmation for firewall blocks from the Process Monitor. MessageBox
    /// cannot host a checkbox, so this window carries the class-specific
    /// warning plus the "don't ask again" check-off (a ConfirmPrefs key).
    /// Frequent blockers use the checkbox to stop the prompt interrupting
    /// every block; the choice is per warning class — silencing the routine
    /// IP confirm never silences the svchost warning — and reversible from
    /// the Blocked popup's reset button.
    /// </summary>
    public partial class BlockConfirmWindow : Window
    {
        public bool Confirmed { get; private set; }
        public bool Suppress => SuppressCheck.IsChecked == true;

        /// <summary>ConfirmPrefs key the checkbox silences (null → no checkbox shown).</summary>
        public string SuppressKey { get; }

        public BlockConfirmWindow(string headline, string warning, string detail,
                                  string suppressKey, string suppressLabel)
        {
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
            HeadText.Text = headline;
            WarningText.Text = warning;
            WarningBorder.Visibility = string.IsNullOrEmpty(warning) ? Visibility.Collapsed : Visibility.Visible;
            DetailText.Text = detail;
            SuppressKey = suppressKey;
            if (string.IsNullOrEmpty(suppressLabel))
            {
                SuppressCheck.Visibility = Visibility.Collapsed;
            }
            else
            {
                SuppressCheck.Content = suppressLabel;
            }
        }

        private void BlockBtn_Click(object sender, RoutedEventArgs e)
        {
            Confirmed = true;
            DialogResult = true;
        }
    }
}
