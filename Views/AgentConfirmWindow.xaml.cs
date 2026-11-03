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
    /// Tier-3 consent: shown by the AI-access bridge before any mutating tool
    /// runs (the gate pair). The answer travels back
    /// to the assistant as a bare allowed/denied; "always for this session"
    /// grants stay in the bridge's memory and die with the session.
    /// </summary>
    public partial class AgentConfirmWindow : Window
    {
        public bool Allowed { get; private set; }
        public bool AlwaysForTool { get; private set; }

        public AgentConfirmWindow(string tool, string detail)
        {
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
            HeadText.Text = $"An AI assistant asks to run: {tool}";
            DetailText.Text = detail;
            if (tool == "open_gate" || tool == "close_gate")
                AlwaysCheck.Content = "Allow gates for THIS target for the rest of the session — other targets still ask";
            // Non-modal timing: the bridge waits on this dialog for up to 90 s,
            // then answers 'denied (timeout)' on its own.
        }

        private void AllowBtn_Click(object sender, RoutedEventArgs e)
        {
            Allowed = true;
            AlwaysForTool = AlwaysCheck.IsChecked == true;
            DialogResult = true;
        }

        private void DenyBtn_Click(object sender, RoutedEventArgs e)
        {
            Allowed = false;
            DialogResult = false;
        }
    }
}
