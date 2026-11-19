using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace AutoCommand.Light
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            try
            {
                VersionText.Text = "AutoCommand Light v" +
                    FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion;
            }
            catch { VersionText.Text = "AutoCommand Light"; }

            // Denial toasts land on the Blocks page, where the rule lives —
            // same contract as Advanced, one level of ceremony lower.
            AutoCommand.Contain.Core.FirewallDenyWatchService.Instance.OnDenyToast =
                (title, message, onActivated) => Dispatcher.BeginInvoke(new Action(() =>
                {
                    MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
                    onActivated?.Invoke();
                }));
        }

        /// <summary>Nav-token deep links from the report and chat lines:
        /// "connections" | "blocks" | "history" | "ask" | "overview".</summary>
        public void NavigateTo(string token)
        {
            var item = token switch
            {
                "connections" => (TabItem)ConnectionsNavItem,
                "blocks" => (TabItem)BlocksNavItem,
                "history" => (TabItem)HistoryNavItem,
                "ask" => (TabItem)AskNavItem,
                "sysmon" => (TabItem)OverviewNavItem,   // the Sysmon card lives on Overview
                _ => (TabItem)OverviewNavItem,
            };
            MainTabs.SelectedItem = item;
            if (token == "sysmon" || token == "overview")
                OverviewTab?.BeginReport();
        }

        // ── Emergency internet restore (the panic button) ───────────────
        // The #1 self-inflicted outage is blocking something load-bearing.
        // This pauses EVERY block this install family made — Light's
        // AL-BLOCK and the Advanced app's adopted AC-BLOCK — reversibly.
        // Nothing is deleted; re-enable from the Blocks page.
        private async void RestoreInternetBtn_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "Restore internet access?\n\n" +
                "This pauses every firewall block this app (and the Advanced app) created. " +
                "Nothing is deleted — turn them back on from the Blocks page.\n\n" +
                "If this does not restore connectivity, the outage came from something else " +
                "(a VPN, a proxy, or another tool).",
                "🚑 Restore Internet", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            RestoreInternetBtn.IsEnabled = false;
            try
            {
                var result = await LightServices.Firewall.SetAllBlocksEnabledSnapshotAsync(false, false, true, null);

                // A stale DNS cache keeps sites dead after the pause —
                // flush it automatically, off the UI thread, pinned to
                // System32 (the app runs elevated from a user-writable
                // folder; a bare "ipconfig" would resolve through CWD).
                string dnsNote;
                try
                {
                    var flush = await System.Threading.Tasks.Task.Run(() =>
                    {
                        var psi = new ProcessStartInfo(
                            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                "ipconfig.exe"),
                            "/flushdns")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true
                        };
                        using var p = Process.Start(psi);
                        p.StandardOutput.ReadToEnd();
                        if (!p.WaitForExit(5000))
                        {
                            try { p.Kill(entireProcessTree: true); } catch { }
                            p.WaitForExit();
                            return -1;
                        }
                        return p.ExitCode;
                    });
                    dnsNote = flush == 0
                        ? "The DNS cache was flushed automatically — no further steps needed."
                        : "The DNS cache could not be flushed automatically; run  ipconfig /flushdns  if sites still fail.";
                }
                catch (Exception ex)
                {
                    dnsNote = $"Could not flush DNS automatically ({ex.Message}).";
                }

                // Fleet ops bypass per-record statuses by design — the
                // incident lands in Light's ledger so History can answer
                // "when did everything go off, and how far did it reach".
                LightServices.Ledger.AppendEvent("fleet-disabled", "-", "-",
                    $"{result.Changed}/{result.Matched} rule(s) paused", "panic-button");

                MessageBox.Show(
                    $"Paused {result.Changed} of {result.Matched} block rule(s)." +
                    (result.FirstError != null ? $"\nFirst error: {result.FirstError}" : "") +
                    $"\n\n{dnsNote}\n\n" +
                    "Turn blocks back on from the Blocks page whenever you like.",
                    "🚑 Restore Internet", MessageBoxButton.OK, MessageBoxImage.Information);

                BlocksTab?.RefreshAfterFleetOp();
                HistoryTab?.Refresh();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not pause the blocks: {ex.Message}",
                    "🚑 Restore Internet", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally { RestoreInternetBtn.IsEnabled = true; }
        }
    }
}
