using System;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using AutoCommand.Services;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>
    /// PID Inquiry — "how was this PID spawned?" for any process visible in
    /// the Process Monitor (row context menu) or typed/picked in the PID
    /// dropdown. Renders the ProvenanceReport collected by
    /// ProcessProvenanceService: verdict, identity, verified ancestry chain,
    /// and corroborating records (Sysmon create-events, shell history,
    /// autostart entries, hosted services).
    /// </summary>
    public partial class ProcessTraceWindow : Window
    {
        private readonly int _pid;
        private readonly string _knownName;
        private readonly string _knownImage;
        private readonly TaskLaunchInfo _taskHint;
        private readonly DateTime? _hintSeenUtc;
        private readonly DateTime? _knownCreatedUtc;
        private ProvenanceReport _report;
        private bool _busy;

        /// <summary>
        /// Raised after each successful collection. The Process Monitor
        /// subscribes so a resolved real name flows back onto the row that
        /// opened the inquiry (trace→row loop) instead of dying with the
        /// window.
        /// </summary>
        public event Action<ProvenanceReport> ReportCollected;

        public ProcessTraceWindow(int pid, string knownName, string knownImagePath, TaskLaunchInfo taskHint,
                                  DateTime? hintSeenUtc = null, DateTime? knownCreatedUtc = null)
        {
            _pid = pid;
            _knownName = knownName;
            _knownImage = knownImagePath;
            _taskHint = taskHint;
            _hintSeenUtc = hintSeenUtc;
            _knownCreatedUtc = knownCreatedUtc;
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
            Title = $"PID Inquiry — {pid} {knownName}".TrimEnd();
            Loaded += (_, _) => _ = CollectAsync();
        }

        private async Task CollectAsync()
        {
            if (_busy) return;
            _busy = true;
            try
            {
                StatusText.Text = "Collecting… (WMI snapshot, parent chain, Sysmon events, shell history)";
                var report = await Task.Run(() =>
                    ProcessProvenanceService.Collect(_pid, _knownName, _knownImage, _taskHint,
                        _hintSeenUtc, _knownCreatedUtc));
                _report = report;
                Render(report);
                ReportCollected?.Invoke(report);
                StatusText.Text = $"Collected in {report.Elapsed.TotalSeconds:F1}s · {DateTime.Now:HH:mm:ss} · " +
                                  "collection is read-only";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Collection failed: " + ex.Message;
            }
            finally
            {
                _busy = false;
            }
        }

        private void Render(ProvenanceReport r)
        {
            Title = $"PID Inquiry — {r.Pid} · {Path.GetFileName(r.ExePath ?? r.Name ?? "?")}";

            VerdictKindText.Text = r.Verdict;
            VerdictDetailText.Text = r.VerdictDetail;
            (Color bg, Color fg) = r.Verdict switch
            {
                string v when v.StartsWith("User-launched", StringComparison.Ordinal) => ((Color)ColorConverter.ConvertFromString("#14351F"), (Color)ColorConverter.ConvertFromString("#7ED8A0")),
                string v when v.StartsWith("Scheduled", StringComparison.Ordinal)    => ((Color)ColorConverter.ConvertFromString("#3A2E10"), (Color)ColorConverter.ConvertFromString("#FBBF24")),
                string v when v.StartsWith("Windows service", StringComparison.Ordinal) => ((Color)ColorConverter.ConvertFromString("#1A4A8A"), (Color)ColorConverter.ConvertFromString("#7EB8F7")),
                _ => ((Color)ColorConverter.ConvertFromString("#3A1520"), (Color)ColorConverter.ConvertFromString("#F2A0B4"))
            };
            VerdictBanner.Background = new SolidColorBrush(bg);
            VerdictKindText.Foreground = new SolidColorBrush(fg);
            VerdictDetailText.Foreground = new SolidColorBrush(Color.FromArgb(0xD0, fg.R, fg.G, fg.B));

            IdentName.Text = r.Name ?? "?";
            IdentPid.Text = r.Pid.ToString();
            IdentCreated.Text = r.Created?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
            IdentOwner.Text = r.Owner ?? "unknown";
            IdentSession.Text = r.Session ?? "?";
            IdentMemory.Text = r.Alive ? r.Memory ?? "—" : "— (not running)";
            IdentImage.Text = r.ExePath;
            // svchost (and other SYSTEM) command lines are unreadable to a
            // standard user — say so instead of showing a blank field
            IdentCmd.Text = r.CommandLine ?? (
                IsSvchostReport(r)
                    ? "— hidden (standard users cannot read SYSTEM svchost lines; rerun elevated to corroborate -k/-s)"
                    : null);

            // Plain-English gloss for names that mean nothing on their own
            // ("git-remote-https.exe") — the chain below shows the raw
            // parentage; this line translates it
            IdentGloss.Text = ProcessGlossary.TryDescribe(r.ExePath ?? r.Name, out string gloss)
                ? "ℹ " + gloss
                : null;

            var rows = new List<ChainRowVm>();
            for (int i = 0; i < r.Chain.Count; i++)
            {
                var link = r.Chain[i];
                rows.Add(new ChainRowVm
                {
                    Arrow = i == 0 ? "▸ this process" : "↑ spawned by",
                    Head = $"PID {link.Pid,-7} {link.Name ?? "?"}   started {link.Created?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown"}   {link.Owner ?? ""}",
                    Cmd = link.CommandLine,
                    Note = link.Note,
                    Verified = link.Verified
                });
            }
            ChainList.ItemsSource = rows;

            EvidenceList.ItemsSource = r.Evidence
                .Select(ev => new EvidenceRowVm { Source = ev.Source, Detail = ev.Detail })
                .ToList();

            WarningsText.Text = r.Warnings.Count == 0
                ? null
                : "⚠ " + string.Join("\n⚠ ", r.Warnings);
        }

        /// <summary>True when the report's subject is the svchost service-host image.</summary>
        private static bool IsSvchostReport(ProvenanceReport r) =>
            string.Equals(r.Name, "svchost.exe", StringComparison.OrdinalIgnoreCase) ||
            (r.ExePath?.EndsWith("\\svchost.exe", StringComparison.OrdinalIgnoreCase) ?? false);

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = CollectAsync();

        private void CopyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_report == null) return;
            try
            {
                Clipboard.SetText(ProcessProvenanceService.BuildReportText(_report));
                StatusText.Text = "Report copied to clipboard.";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Copy failed: " + ex.Message;
            }
        }

        /// <summary>Display row for one ancestry hop.</summary>
        private sealed class ChainRowVm
        {
            public string Arrow { get; set; }
            public string Head { get; set; }
            public string Cmd { get; set; }
            public string Note { get; set; }
            public bool Verified { get; set; } = true;
        }

        /// <summary>
        /// Display row for one evidence record. A named class (not an
        /// anonymous type): Run.Text bindings evaluate TwoWay by default and
        /// throw on read-only properties.
        /// </summary>
        private sealed class EvidenceRowVm
        {
            public string Source { get; set; }
            public string Detail { get; set; }
        }
    }
}
