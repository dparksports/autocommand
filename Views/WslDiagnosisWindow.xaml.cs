using System.Windows;
using AutoCommand.Contain.Core;
using AutoCommand.Helpers;

namespace AutoCommand.Views;

/// <summary>
/// The "Why is WSL offline?" result window: runs the staged diagnosis
/// (WslDiagnosisService — the same one the diagnose_wsl bridge tool uses,
/// so the AI and the screen can never disagree), renders one plain-English
/// verdict with the stage-by-stage evidence and the next step. Read-only
/// end to end; the probe never starts the utility VM.
/// </summary>
public partial class WslDiagnosisWindow : Window
{
    public WslDiagnosisWindow()
    {
        InitializeComponent();
        WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
        Loaded += async (_, _) => await RunAsync();
    }

    private async void RerunBtn_Click(object sender, RoutedEventArgs e) => await RunAsync();

    private async System.Threading.Tasks.Task RunAsync()
    {
        RerunBtn.IsEnabled = false;
        VerdictText.Text = "Checking — host egress, guest probe, rule model, Hyper-V layer…";
        EvidenceText.Text = "…";
        NextStepText.Visibility = Visibility.Collapsed;
        try
        {
            var progress = new Progress<string>(s => VerdictText.Text = "Checking — " + s);
            var d = await WslDiagnosisService.DiagnoseLiveAsync(progress);

            VerdictText.Text = (d.Healthy ? "✓ " : "⚠ ") + d.Verdict;
            EvidenceText.Text = string.Join("\n", d.Evidence);
            if (d.NextStep != null)
            {
                NextStepText.Text = "Next: " + d.NextStep;
                NextStepText.Visibility = Visibility.Visible;
            }
        }
        catch (Exception ex)
        {
            VerdictText.Text = "The diagnosis could not run: " + ex.Message;
        }
        finally
        {
            RerunBtn.IsEnabled = true;
        }
    }
}
