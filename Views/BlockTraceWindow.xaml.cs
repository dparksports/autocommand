using System;
using System.Windows;
using AutoCommand.Contain.Core;

namespace AutoCommand.Views
{
    /// <summary>
    /// The Blocks tab's trace-back window: "when was this blocked, why, and
    /// for which process instance (svchost included)". One compose via
    /// BlockTraceService — ledger record, decision evidence, lifecycle events,
    /// hitting instances with their archive-joined identities — rendered as
    /// the plain report the audit surfaces speak. This is a USER surface: a
    /// decision the composer had to infer from the archive is persisted here
    /// (TryBackfill's one "attributed" line), which the bridge's read tools
    /// deliberately never do.
    /// </summary>
    public partial class BlockTraceWindow : Window
    {
        private readonly string _kind, _key;
        private readonly BlocksLedger _ledger;   // null = the app's default store

        public BlockTraceWindow(string kind, string key, BlocksLedger ledger = null)
        {
            InitializeComponent();
            _kind = kind;
            _key = key;
            _ledger = ledger;
            Title = $"Block Trace — {(kind == "ip" ? key : System.IO.Path.GetFileName(key))}";
            Loaded += OnLoaded;
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            // The compose scans the Sysmon archive — real disk work; keep the
            // window responsive and the status strip honest while it runs.
            try
            {
                var trace = await System.Threading.Tasks.Task.Run(() =>
                    BlockTraceService.Trace(_kind, _key, _ledger));
                ReportText.Text = BlockTraceService.FormatReport(trace);

                if (trace.DecisionInferred)
                {
                    StatusText.Text = "⚠ Decision inferred from the Sysmon archive — this block predates decision " +
                                     "capture. The inference is persisted once as an 'attributed' line.";
                    await System.Threading.Tasks.Task.Run(() =>
                        BlockTraceService.TryBackfill(trace, _ledger));
                }
                else if (trace.Decision != null)
                    StatusText.Text = "Decision evidence was captured at block time.";
                else
                    StatusText.Text = "No decision evidence could be proven — no captured decision and no archive attempt matched.";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Trace failed: " + ex.Message;
            }
        }
    }
}
