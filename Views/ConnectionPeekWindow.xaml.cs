using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using AutoCommand.Forensics.Core;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>
    /// Traffic Peek — "what does this connection actually carry?", opened
    /// from the Process Monitor row context menu. Three scopes: a remote IP
    /// ("this connection"), a program instance ("this program", PID-anchored
    /// via Sysmon EID 3), or a svchost-hosted service by name ("DiagTrack" —
    /// the only anchor that survives service restarts, so a tracked service
    /// keeps being followed no matter which instance pops up). While open it
    /// holds the shared TCP stream capture (FlowPeekService AddRef/Release),
    /// shows every finalized flow to the subject with the TLS decryptor's
    /// honest verdict, and reads the Windows Update / BITS / Delivery
    /// Optimization event channels for the same time window — the plaintext
    /// answer for services whose TLS can never be decrypted.
    ///
    /// Takes identity values (not the live row) so the window survives the
    /// process exiting — the ProcessTraceWindow pattern.
    /// </summary>
    public partial class ConnectionPeekWindow : Window
    {
        private const int MaxFlowsShown = 200;

        private readonly AutoCommand.Engines.Watch.PeekScope _scope;
        private readonly string _subject;
        private readonly string _processName;
        private readonly string _image;      // program scope: the subject's image path
        private bool _showPythonTrace;
        private readonly int _pid;
        private readonly string _hostedServices;
        private readonly string _hostname;
        private readonly DateTime _openedUtc = DateTime.UtcNow;

        private FlowPeekService _peekService;
        private readonly ObservableCollection<object> _flows = new();   // PeekEntry | InterceptedRow
        private readonly ObservableCollection<ServiceEventLine> _events = new();
        private readonly DispatcherTimer _statusTimer;
        private readonly DispatcherTimer _bannerTimer;
        private DateTime _lastEventRefreshUtc = DateTime.MinValue;
        private bool _busyRefreshingEvents;
        private bool _closed;
        private int _interceptPid;           // > 0 while a session this window started runs
        private bool _sessionStartedHere;

        /// <summary>Peer one remote connection ("this connection").</summary>
        public ConnectionPeekWindow(string remoteIp, string processName, int pid, string hostedServices, string hostname)
            : this(AutoCommand.Engines.Watch.PeekScope.NewRemoteIpScope(remoteIp), remoteIp, processName, pid, hostedServices, hostname)
        {
        }

        /// <summary>Peer one program instance ("this program").</summary>
        public ConnectionPeekWindow(int pid, string image, string processName, string hostedServices, string hostname)
            : this(AutoCommand.Engines.Watch.PeekScope.NewProgramScope(pid, image),
                   string.IsNullOrEmpty(image) ? $"PID {pid}" : System.IO.Path.GetFileName(image),
                   processName, pid, hostedServices, hostname)
        {
            _image = image;
            _showPythonTrace = pid > 0 && IsPythonImage(_image);
            if (_showPythonTrace)
            {
                PythonTraceSection.Visibility = Visibility.Visible;
                PythonTraceBox.Text = "Not instrumented yet — stacks appear once the environment runs the audit hook (🐍 Instrument… button).";
            }
        }

        private static bool IsPythonImage(string image) =>
            !string.IsNullOrEmpty(image) && image.Contains("python", StringComparison.OrdinalIgnoreCase);

        /// <summary>Track one svchost-hosted service by name — survives restarts.</summary>
        public ConnectionPeekWindow(AutoCommand.Engines.Watch.PeekScope scope, string subject,
                                    string processName, int pid, string hostedServices, string hostname)
        {
            _scope = scope;
            _subject = subject;
            _processName = processName;
            _pid = pid;
            _hostedServices = hostedServices;
            _hostname = hostname;
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen

            Title = $"Traffic Peek — {subject}";
            bool programScope = scope.IsProgramScope || scope.IsServiceScope;
            IdentIpLabel.Text = scope.IsServiceScope ? "TRACKED SERVICE" : programScope ? "PROGRAM" : "REMOTE IP";
            IdentIp.Text = subject;
            IdentProcess.Text = BuildProcessLabel();
            IdentServices.Text = string.IsNullOrEmpty(hostedServices) ? "—" : hostedServices;
            IdentHost.Text = string.IsNullOrEmpty(hostname) ? "(not resolved)" : hostname;

            FlowList.ItemsSource = _flows;
            EventList.ItemsSource = _events;
            UpdateKeylogChip();

            _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _statusTimer.Tick += (_, _) => UpdateStatusStrip();

            _bannerTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _bannerTimer.Tick += (_, _) => UpdateInterceptBanner();
            _bannerTimer.Start();

            Loaded += (_, _) => { _statusTimer.Start(); StartPeek(); };
            Closed += (_, _) =>
            {
                _closed = true;
                _statusTimer.Stop();
                _bannerTimer.Stop();
                StopPeek();
                // A scoped peek owns its intercept session: closing the window
                // ends it (restores proxy, removes the QUIC rule, untrusts the
                // CA) — a time-boxed session must never outlive its banner.
                if (_sessionStartedHere && InterceptProxyService.Shared.IsRunning)
                    InterceptProxyService.Shared.StopSession("peek closed");
            };
        }

        private string BuildProcessLabel() =>
            (_processName ?? "svchost.exe") + (_pid > 0 ? $" · PID {_pid}" : string.Empty);

        // ── lifecycle ────────────────────────────────────────────────────

        private void StartPeek()
        {
            _peekService = FlowPeekService.OfScope(_scope);
            _peekService.OnEntry += entry =>
                Dispatcher.BeginInvoke(new Action(() => AddFlow(entry)));
            // Non-fatal by contract (Sysmon absent → no PID attribution);
            // shown as a note, never a stop.
            _peekService.OnError += msg =>
                Dispatcher.BeginInvoke(new Action(() =>
                    SetWarning("attribution: " + msg)));
            _peekService.Start();
            _ = RefreshEventsAsync();
            UpdateStatusStrip();

            if (_showPythonTrace) StartPythonTrace();
        }

        // ── python audit trace (instrumented program scopes) ────────────

        private PyTraceReaderService _pyTraceReader;

        private void StartPythonTrace()
        {
            try
            {
                _pyTraceReader = new PyTraceReaderService();
                _pyTraceReader.OnError += msg =>
                    Dispatcher.BeginInvoke(new Action(() => SetWarning("python trace: " + msg)));
                _pyTraceReader.OnRecord += _ =>
                    Dispatcher.BeginInvoke(new Action(RenderPythonTrace));
                _pyTraceReader.Start(); // loads existing trace-<pid>.jsonl, then tails
                RenderPythonTrace();
            }
            catch (Exception ex)
            {
                SetWarning("python trace unavailable: " + ex.Message);
            }
        }

        private void RenderPythonTrace()
        {
            var records = _pyTraceReader?.GetForPid(_pid) ?? Array.Empty<PyTraceRecord>();
            if (records.Count == 0)
            {
                PythonTraceBox.Text = "No spawn recorded yet for this pid — the section fills when the " +
                                      "instrumented python spawns something (or runs, if the hook just landed).";
                return;
            }
            var sb = new StringBuilder();
            foreach (var record in records)
            {
                sb.Append("── ").Append(record.Header).AppendLine(" ──");
                sb.AppendLine(record.Stack);
                sb.AppendLine();
            }
            PythonTraceBox.Text = sb.ToString().TrimEnd();
        }

        private void InstrumentBtn_Click(object sender, RoutedEventArgs e)
        {
            new PythonInstrumentDialog { Owner = Window.GetWindow(this) }.ShowDialog();
            if (_showPythonTrace)
                RenderPythonTrace(); // instrumentation may have landed while the dialog was open
        }

        private void StopPeek()
        {
            try { _peekService?.Stop(); } catch { /* the capture outliving us is fine */ }
            _peekService = null;
            try { _pyTraceReader?.Stop(); } catch { }
            _pyTraceReader = null;
        }

        // ── flows ────────────────────────────────────────────────────────

        private void AddFlow(PeekEntry entry)
        {
            _flows.Insert(0, entry);
            while (_flows.Count > MaxFlowsShown)
                _flows.RemoveAt(_flows.Count - 1);
            UpdateStatusStrip();

            // The service-activity window is anchored to the earliest flow
            // we saw; refresh at most every 15 s.
            if ((DateTime.UtcNow - _lastEventRefreshUtc).TotalSeconds >= 15)
                _ = RefreshEventsAsync();
        }

        private void FlowList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            switch (FlowList.SelectedItem)
            {
                case PeekEntry entry: RenderDetail(entry); break;
                case InterceptedRow row: RenderIntercepted(row); break;
                default: RenderDetail(null); break;
            }
        }

        private void RenderDetail(PeekEntry entry)
        {
            if (entry == null)
            {
                DetailWire.Text = "No flow selected.";
                DetailTls.Text = DetailSni.Text = DetailApp.Text = string.Empty;
                StatusBanner.Visibility = Visibility.Collapsed;
                PlaintextSection.Visibility = Visibility.Collapsed;
                InterceptBtn.Visibility = Visibility.Collapsed;
                SaveBodiesBtn.Visibility = Visibility.Collapsed;
                return;
            }

            var flow = entry.Flow;
            string flags =
                (flow.FinBoth ? " · FIN both" : "") +
                (flow.Reset ? " · RST" : "") +
                (flow.Truncated ? " · capture truncated" : "");
            DetailWire.Text = $"{entry.RemoteEndpoint}   ←   {entry.LocalEndpoint}   ·   {entry.UpDisplay} up · {entry.DownDisplay} down{flags}";

            string tls = entry.Decrypt.TlsVersion ?? "TLS version unknown";
            if (!string.IsNullOrEmpty(entry.Decrypt.Alpn)) tls += $" · ALPN {entry.Decrypt.Alpn}";
            if (!string.IsNullOrEmpty(entry.Decrypt.CipherSuite)) tls += $" · {entry.Decrypt.CipherSuite}";
            DetailTls.Text = tls;
            DetailSni.Text = "SNI: " + entry.SniDisplay;
            DetailApp.Text = entry.Decrypt.Success
                ? $"plaintext: {entry.Decrypt.ClientAppBytes} B up · {entry.Decrypt.ServerAppBytes} B down"
                : string.Empty;

            // Verbatim decryptor verdict, color-coded: green = decrypted,
            // amber = honest "can't and here's why", red = unexpected.
            StatusBanner.Visibility = Visibility.Visible;
            StatusBannerText.Text = entry.Decrypt.Status ?? "(no status)";
            string status = entry.Status ?? "";
            (string bg, string fg) =
                status.StartsWith("decrypted", StringComparison.Ordinal)      ? ("#14351F", "#7ED8A0") :
                status.StartsWith("encrypted", StringComparison.Ordinal)      ? ("#3A2E10", "#FBBF24") :
                status.StartsWith("not TLS", StringComparison.Ordinal)        ? ("#3A2E10", "#FBBF24") :
                                                                                ("#3A1520", "#F2A0B4");
            StatusBanner.Background = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(bg));
            StatusBannerText.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(fg));

            // On "encrypted (no keys)": tell the user exactly how plaintext
            // becomes possible (launch under watch) and why schannel rows
            // never will — the honest coverage answer, not a gap.
            bool noKeys = status.StartsWith("encrypted", StringComparison.Ordinal);
            CoverageNoteText.Text = noKeys ? TransmissionKeyService.CoverageNote : null;
            CoverageNoteText.Visibility = noKeys ? Visibility.Visible : Visibility.Collapsed;

            // Layer 3: the only path for rows that can never write keys —
            // offered on program/service scopes (they know the PID), never
            // while a session is already active.
            bool interceptable = noKeys && flow.Pid > 0 &&
                                 (_scope.IsProgramScope || _scope.IsServiceScope) &&
                                 !InterceptProxyService.Shared.IsRunning;
            InterceptBtn.Visibility = interceptable ? Visibility.Visible : Visibility.Collapsed;
            InterceptBtn.Tag = flow;

            bool showPlaintext = entry.Decrypt.Success;
            PlaintextSection.Visibility = showPlaintext ? Visibility.Visible : Visibility.Collapsed;
            if (!showPlaintext) return;

            DetailHttp.Text = string.IsNullOrEmpty(entry.Decrypt.HttpSummary)
                ? null
                : "HTTP/session: " + entry.Decrypt.HttpSummary;

            var sb = new StringBuilder();
            var hex = new StringBuilder();
            int written = 0;
            foreach (var rec in entry.Decrypt.Records)
            {
                if (rec == null || !rec.Decrypted || rec.Data == null || rec.Data.Length == 0) continue;
                sb.AppendLine($"── {rec.ContentType} · {(rec.FromClient ? "client → server" : "server → client")} · {rec.Data.Length} B ──");
                AppendPrintable(sb, rec.Data, 32 * 1024 - sb.Length);
                sb.AppendLine();
                if (hex.Length < 8 * 1024) AppendHex(hex, rec.Data, 8 * 1024 - hex.Length);
                written += rec.Data.Length;
                if (written >= 256 * 1024) { sb.AppendLine("… (further records omitted)"); break; }
            }
            PlaintextBox.Text = sb.Length == 0 ? "(no decrypted application data in this capture)" : sb.ToString();
            HexBox.Text = hex.ToString();
        }

        /// <summary>Printable preview: control bytes become '·', the usual
        /// whitespace survives. A plaintext pane is for reading, not dumping.</summary>
        private static void AppendPrintable(StringBuilder sb, byte[] data, int budget)
        {
            int max = Math.Min(data.Length, Math.Max(0, budget));
            for (int i = 0; i < max; i++)
            {
                byte b = data[i];
                char c = b switch
                {
                    (byte)'\r' or (byte)'\n' or (byte)'\t' => (char)b,
                    < 0x20 or >= 0x7F => '·',
                    _ => (char)b
                };
                sb.Append(c);
            }
            if (max < data.Length) sb.Append($"\n… ({data.Length - max} more bytes)");
        }

        private static void AppendHex(StringBuilder sb, byte[] data, int budgetChars)
        {
            const int perLine = 16;
            for (int offset = 0; offset < data.Length && sb.Length < budgetChars; offset += perLine)
            {
                sb.Append($"{offset:X6}  ");
                for (int i = 0; i < perLine; i++)
                {
                    if (offset + i < data.Length) sb.Append($"{data[offset + i]:X2} ");
                    else sb.Append("   ");
                    if (i == 7) sb.Append(' ');
                }
                sb.AppendLine();
            }
        }

        // ── status strip ─────────────────────────────────────────────────

        private void UpdateStatusStrip()
        {
            if (_peekService == null)
            {
                CaptureStatusText.Text = "Capture stopped.";
                return;
            }
            var capture = TcpStreamCaptureService.Shared;
            string attribution = _scope.IsRemoteIpScope
                ? ""
                : " · flows are attributed via Sysmon EID 3 — without Sysmon this peek stays empty";
            CaptureStatusText.Text =
                $"Capture running · {_peekService.EntryCount} peered flow(s) shown · " +
                $"{capture.OutboundPackets} out / {capture.InboundPackets} in packets this session" +
                attribution +
                " · flows appear when a conversation closes (or ~10 s after it goes quiet).";

            // Some NIC/driver combos deliver only outbound packets to a
            // receive-all socket — say so instead of letting a zero reply
            // count read as "the server never answered".
            if (!capture.InboundSeen && capture.OutboundPackets > 0)
                SetWarning("Only outbound packets observed on this NIC — server replies are not being captured " +
                           "(driver limitation). Metadata comes from the outgoing direction only.");
        }

        private void SetWarning(string message)
        {
            CaptureWarnText.Text = "⚠ " + message;
            CaptureWarnText.Visibility = Visibility.Visible;
        }

        // ── layer-3 intercept (program/service scopes) ───────────────────

        /// <summary>One intercepted conversation (from the pipeline's
        /// intercept seam) as the flows list shows it — the same display
        /// surface a PeekEntry carries, over a TransmissionRecord.</summary>
        private sealed class InterceptedRow
        {
            public required TransmissionRecord Record { get; init; }

            public string TimeDisplay => Record.TsUtc.ToLocalTime().ToString("HH:mm:ss");
            public string RemoteEndpoint => Record.ServerEndpoint;
            public string UpDisplay => PeekEntry.FormatBytes(Record.ClientBytes);
            public string DownDisplay => PeekEntry.FormatBytes(Record.ServerBytes);
            public string Status => Record.Status ?? "?";
            public string SniDisplay => string.IsNullOrEmpty(Record.Sni) ? "(no SNI)" : Record.Sni;
            public string ProcessDisplay => Record.ProcessDisplay;
        }

        private void InterceptBtn_Click(object sender, RoutedEventArgs e)
        {
            if (InterceptBtn.Tag is not TcpFlowRecord flow || flow.Pid <= 0) return;

            if (InterceptProxyService.Shared.IsRunning)
            {
                MessageBox.Show("An intercept session is already active. Stop it first (⏹ Stop now in the banner).",
                    "🛡 Intercept", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string image = flow.Image ?? _image ?? $"pid:{flow.Pid}";
            var confirm = MessageBox.Show(
                $"🛡 Intercept this process?\n\nTarget: {System.IO.Path.GetFileName(image)} (PID {flow.Pid})\n" +
                $"Scope: every process running from this exe, not just PID {flow.Pid} — browsers and\n" +
                "multi-instance apps spawn new PIDs constantly, and firewall rules cannot\n" +
                "distinguish PIDs (shared-host images like svchost are the exception: exact PID only).\n\n" +
                "For the next 15 minutes (auto-reverts; fully reversible):\n" +
                "  • A temporary 'AutoCommand Intercept CA' is trusted machine-wide, and removed\n" +
                "    when the session ends.\n" +
                "  • The system proxy (WinHTTP for services, WinINET for apps) points at a local\n" +
                "    loopback proxy on this machine. Other apps' traffic is tunneled through\n" +
                "    untouched — only processes in the scope above are decrypted.\n" +
                "  • The target's QUIC (UDP 443) is blocked so it falls back to TCP/TLS.\n" +
                "  • Decrypted conversations appear in this window as 'decrypted · intercept'.\n\n" +
                "Certificate-pinned apps will fail their connections during the session — recorded\n" +
                "here as 'refused intercept (pinning)'. Stop now restores proxy, firewall rule and\n" +
                "CA immediately if anything misbehaves. Closing this window also stops the session.",
                "🛡 Intercept this process", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            string error = InterceptProxyService.Shared.StartSession(flow.Pid, image);
            if (error != null)
            {
                MessageBox.Show(error, "🛡 Intercept", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _interceptPid = flow.Pid;
            _sessionStartedHere = true;
            InterceptProxyService.Shared.OnStatus += OnInterceptStatus;
            InterceptProxyService.Shared.OnSessionEnded += OnInterceptSessionEnded;
            TransmissionsPipelineService.Shared.OnRecord += OnInterceptRecord;
            UpdateInterceptBanner();
        }

        private void InterceptStopBtn_Click(object sender, RoutedEventArgs e) =>
            InterceptProxyService.Shared.StopSession("stopped by user");

        private void OnInterceptStatus(string message) =>
            Dispatcher.BeginInvoke(new Action(() => SetStatus("🛡 " + message)));

        private void OnInterceptSessionEnded(string reason)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                UpdateInterceptBanner();
                SetStatus($"🛡 Intercept ended ({reason}) — proxy, firewall rule and CA restored.");
            }));
            TransmissionsPipelineService.Shared.OnRecord -= OnInterceptRecord;
            InterceptProxyService.Shared.OnStatus -= OnInterceptStatus;
            InterceptProxyService.Shared.OnSessionEnded -= OnInterceptSessionEnded;
            _sessionStartedHere = false;
        }

        private void OnInterceptRecord(TransmissionRecord record)
        {
            if (record == null || _closed) return;
            // Only the subject's rows belong in this scoped window.
            if (record.Pid != _interceptPid &&
                !string.Equals(record.Image, _image, StringComparison.OrdinalIgnoreCase))
                return;
            Dispatcher.BeginInvoke(new Action(() =>
            {
                _flows.Insert(0, new InterceptedRow { Record = record });
                while (_flows.Count > MaxFlowsShown)
                    _flows.RemoveAt(_flows.Count - 1);
            }));
        }

        private void UpdateInterceptBanner()
        {
            var proxy = InterceptProxyService.Shared;
            if (!proxy.IsRunning)
            {
                InterceptBanner.Visibility = Visibility.Collapsed;
                return;
            }
            TimeSpan left = proxy.EndsAtUtc - DateTime.UtcNow;
            if (left < TimeSpan.Zero) left = TimeSpan.Zero;
            InterceptBannerText.Text =
                $"🛡 INTERCEPT ACTIVE — {proxy.TargetDisplay} · local proxy 127.0.0.1:{proxy.Port} · " +
                $"ends in {(int)left.TotalMinutes:00}:{left:ss} · other apps tunneled untouched · " +
                "decrypted rows tagged 'decrypted · intercept'";
            InterceptBanner.Visibility = Visibility.Visible;
        }

        private void RenderIntercepted(InterceptedRow row)
        {
            var r = row.Record;
            InterceptBtn.Visibility = Visibility.Collapsed;
            CoverageNoteText.Visibility = Visibility.Collapsed;

            DetailWire.Text = $"{r.ServerEndpoint}   ·   {PeekEntry.FormatBytes(r.ClientBytes)} up · {PeekEntry.FormatBytes(r.ServerBytes)} down" +
                              (r.TlsVersion != null ? $"   ·   {r.TlsVersion}{(r.CipherSuite != null ? $" · {r.CipherSuite}" : "")}" : "");
            DetailTls.Text = "intercepted through the local proxy — plaintext below when the session decrypted it";
            DetailSni.Text = "Host: " + (r.Sni ?? "(none)");
            DetailApp.Text = r.Decrypted ? $"messages: {r.MessageCount} · kinds: {r.ContentKinds ?? "—"}" : string.Empty;

            StatusBanner.Visibility = Visibility.Visible;
            StatusBannerText.Text = r.Status ?? "(no status)";
            string status = r.Status ?? "";
            (string bg, string fg) =
                status.StartsWith("decrypted", StringComparison.Ordinal) ? ("#14351F", "#7ED8A0") :
                status.StartsWith("refused", StringComparison.Ordinal)   ? ("#3A2E10", "#FBBF24") :
                                                                           ("#3A1520", "#F2A0B4");
            StatusBanner.Background = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(bg));
            StatusBannerText.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(fg));

            if (!r.Decrypted)
            {
                PlaintextSection.Visibility = Visibility.Collapsed;
                SaveBodiesBtn.Visibility = Visibility.Collapsed;
                return;
            }

            PlaintextSection.Visibility = Visibility.Visible;
            DetailHttp.Text = null;

            // Plaintext comes from this session's live decrypt (the archive
            // is metadata-only since the witness diet — no bodies at rest).
            byte[] request = null, response = null;
            var pipeline = TransmissionsPipelineService.Shared;
            if (pipeline.TryGetBodies(r.Id, out request, out response))
            { /* cache hit */ }

            var sb = new StringBuilder();
            if (request is { Length: > 0 })
            {
                sb.AppendLine($"── REQUEST · {request.Length} B ──");
                AppendPrintable(sb, request, 32 * 1024 - sb.Length);
                sb.AppendLine();
            }
            if (response is { Length: > 0 })
            {
                sb.AppendLine($"── RESPONSE · {response.Length} B ──");
                AppendPrintable(sb, response, 32 * 1024 - sb.Length);
                sb.AppendLine();
            }
            PlaintextBox.Text = sb.Length == 0 ? "(no bodies recorded for this conversation)" : sb.ToString();

            var hex = new StringBuilder();
            if (request is { Length: > 0 }) { hex.AppendLine("── REQUEST ──"); AppendHex(hex, request, 8 * 1024 - hex.Length); }
            if (response is { Length: > 0 }) { hex.AppendLine("── RESPONSE ──"); AppendHex(hex, response, 8 * 1024 - hex.Length); }
            HexBox.Text = hex.ToString();

            SaveBodiesBtn.Visibility = Visibility.Visible;
            SaveBodiesBtn.Tag = (request, response);
        }

        /// <summary>Writes the intercepted request/response to files — the
        /// BITS-preview honesty rule: in memory until the user says so.</summary>
        private void SaveBodiesBtn_Click(object sender, RoutedEventArgs e)
        {
            if (SaveBodiesBtn.Tag is not (byte[] request, byte[] response)) return;
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save intercepted bodies",
                FileName = "intercepted.bin",
                Filter = "Binary (*.bin)|*.bin|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog(this) != true) return;
            try
            {
                string baseName = dialog.FileName;
                if (request is { Length: > 0 }) System.IO.File.WriteAllBytes(System.IO.Path.ChangeExtension(baseName, ".request.bin"), request);
                if (response is { Length: > 0 }) System.IO.File.WriteAllBytes(System.IO.Path.ChangeExtension(baseName, ".response.bin"), response);
                SetStatus($"Saved intercepted bodies next to {System.IO.Path.GetFileName(baseName)}.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Save failed: {ex.Message}", "Traffic Peek", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        /// <summary>Neutral status line (reuses the capture strip without
        /// clobbering its next scheduled refresh).</summary>
        private void SetStatus(string message)
        {
            CaptureWarnText.Text = message;
            CaptureWarnText.Visibility = Visibility.Visible;
        }

        // ── service activity ─────────────────────────────────────────────

        private void RefreshEventsBtn_Click(object sender, RoutedEventArgs e) => _ = RefreshEventsAsync();

        private async Task RefreshEventsAsync()
        {
            if (_busyRefreshingEvents || _closed) return;
            _busyRefreshingEvents = true;
            _lastEventRefreshUtc = DateTime.UtcNow;
            try
            {
                // Window: the earliest captured flow − 2 min → now, or the
                // last 15 minutes while nothing has arrived yet.
                DateTime start = _openedUtc;
                var flowEntries = _flows.OfType<PeekEntry>().ToList();
                if (flowEntries.Count > 0)
                    start = flowEntries.Min(f => f.Flow.StartedUtc == default(DateTime) ? _openedUtc : f.Flow.StartedUtc);
                start = start.ToUniversalTime().AddMinutes(-2);
                var lines = await Task.Run(() => ServiceLogProbe.QueryEvents(start, DateTime.UtcNow));
                if (_closed) return;
                _events.Clear();
                foreach (var line in lines) _events.Add(line);
            }
            catch (Exception ex)
            {
                if (!_closed) SetWarning("Service activity lookup failed: " + ex.Message);
            }
            finally
            {
                _busyRefreshingEvents = false;
            }
        }

        // ── footer actions ───────────────────────────────────────────────

        private void LaunchUnderWatchBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Choose a program to launch under watch",
                Filter = "Programs (*.exe;*.bat;*.cmd)|*.exe;*.bat;*.cmd|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog(this) != true) return;

            string arguments = PromptForArguments(dialog.FileName);
            Process proc = null;
            try
            {
                proc = TransmissionKeyService.LaunchUnderWatch(dialog.FileName, arguments, null);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Launch failed: {ex.Message}", "Launch under watch",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (proc?.Id > 0)
            {
                // The launched instance gets its own program-scoped peek: the
                // subject the user cares about, from its first connection on.
                var name = System.IO.Path.GetFileName(dialog.FileName);
                var monitor = SvchostMonitorView.Current;
                if (monitor != null)
                    monitor.OpenProgramPeekWindow(proc.Id, dialog.FileName, name);
                else
                    new ConnectionPeekWindow(proc.Id, dialog.FileName, name, null, null)
                    {
                        Owner = Window.GetWindow(this)
                    }.Show();
            }
        }

        /// <summary>Arguments prompt — a small code-built modal (the ii
        /// Launch-under-watch pattern): what will be launched, one Consolas
        /// box for the command line, Launch/Cancel. Cancel launches with
        /// empty arguments.</summary>
        private string PromptForArguments(string exePath)
        {
            var input = new System.Windows.Controls.TextBox
            {
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                FontSize = 12,
                Margin = new Thickness(0, 8, 0, 0),
            };
            var buttons = new System.Windows.Controls.StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
            };
            var launch = new Button { Content = "Launch", IsDefault = true, MinWidth = 84, Margin = new Thickness(0, 12, 8, 0) };
            var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 84, Margin = new Thickness(0, 12, 0, 0) };
            var panel = new System.Windows.Controls.StackPanel { Margin = new Thickness(16) };
            panel.Children.Add(new TextBlock
            {
                Text = $"Launching:\n{exePath}\n\nSSLKEYLOGFILE will be set for this program only.",
                TextWrapping = TextWrapping.Wrap,
            });
            panel.Children.Add(input);
            buttons.Children.Add(launch);
            buttons.Children.Add(cancel);
            panel.Children.Add(buttons);
            var win = new Window
            {
                Title = "🚀 Launch under watch",
                Width = 540,
                SizeToContent = SizeToContent.Height,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Content = panel,
            };
            var ok = false;
            launch.Click += (_, _) => { ok = true; win.Close(); };
            input.Focus();
            win.ShowDialog();
            return ok ? input.Text.Trim() : "";
        }

        private void UpdateKeylogChip() =>
            KeylogChip.Content = TlsKeylogService.KeylogEnabled
                ? "🔑 Session-key logging: ON"
                : "🔑 Session-key logging: OFF";

        private void KeylogChip_Click(object sender, RoutedEventArgs e)
        {
            bool enabling = !TlsKeylogService.KeylogEnabled;
            var confirm = MessageBox.Show(
                enabling
                    ? "Re-enable TLS session-key logging?\n\nOnly apps that opt in (instrumented python, SSLKEYLOGFILE-aware browsers) ever write keys there. Windows services never do."
                    : "Disable TLS session-key logging?\n\nThe keylog file is deleted and no future session keys are recorded. Flows captured from now on will report 'keylogging is disabled'.",
                "Traffic Peek", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                if (enabling) TlsKeylogService.EnableKeylogging();
                else TlsKeylogService.DisableKeylogging();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Keylog toggle failed: " + ex.Message, "Traffic Peek",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            UpdateKeylogChip();
        }

        private void CopyBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(BuildReportText());
            }
            catch (Exception ex)
            {
                MessageBox.Show("Copy failed: " + ex.Message, "Traffic Peek",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private string BuildReportText()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"=== TRAFFIC PEEK: {_subject} ===");
            sb.AppendLine($"process: {BuildProcessLabel()}   services: {_hostedServices ?? "—"}   host: {_hostname ?? "(not resolved)"}");
            sb.AppendLine($"window: {_openedUtc:yyyy-MM-dd HH:mm:ss} → {DateTime.Now:HH:mm:ss} (local)");
            sb.AppendLine();
            var entries = _flows.OfType<PeekEntry>().ToList();
            var intercepted = _flows.OfType<InterceptedRow>().ToList();
            sb.AppendLine($"--- FLOWS ({entries.Count}) ---");
            foreach (var f in entries)
            {
                sb.AppendLine($"{f.TimeDisplay}  {f.RemoteEndpoint,-22} {f.UpDisplay,9} ↑ {f.DownDisplay,9} ↓  {f.Status,-24} SNI={f.SniDisplay}  {f.ProcessDisplay}");
                if (!string.IsNullOrEmpty(f.Decrypt?.Status)) sb.AppendLine($"          └ {f.Decrypt.Status}");
            }
            if (intercepted.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine($"--- INTERCEPTED ({intercepted.Count}) ---");
                foreach (var f in intercepted)
                    sb.AppendLine($"{f.TimeDisplay}  {f.RemoteEndpoint,-22} {f.UpDisplay,9} ↑ {f.DownDisplay,9} ↓  {f.Status,-40} SNI={f.SniDisplay}");
            }
            sb.AppendLine();
            sb.AppendLine($"--- SERVICE ACTIVITY ({_events.Count}) ---");
            foreach (var ev in _events)
                sb.AppendLine($"{ev.TimeDisplay}  [{ev.ChannelDisplay} id {ev.EventId}]  {ev.Message}");
            return sb.ToString();
        }
    }
}
