using System;
using AutoCommand.Contain.Core;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoCommand.Intercept.Core;

namespace AutoCommand.Contain.Core
{
    public enum BlockProxyStatus { Stopped, Starting, Listening, PortBusy, Failed }

    /// <summary>
    /// The friendly side of a firewall block. Windows Firewall refuses the
    /// TCP connect in the kernel, so the browser can only show its raw
    /// "internet access is blocked" page — no application can put a sentence
    /// in front of the user at that layer. This service moves the conversation
    /// one layer up, opt-in: while enabled it is the per-user (WinINET)
    /// system proxy on 127.0.0.1:7878, and every request it sees is checked
    /// against AutoCommand's blocked inventory (hostname resolved, addresses
    /// matched against live AC-BLOCK rules via BlockHitFeedService):
    ///
    ///   · blocked plain-HTTP host → the proxy itself answers with a clean
    ///     page: what was blocked, which rule class, when, and how to undo;
    ///   · blocked HTTPS host → CONNECT is answered, TLS terminates with a
    ///     leaf minted from the Intercept CA (the machine-trust decision the
    ///     toggle's consent covers), and the inner request gets the same
    ///     page with a 403. SELECTIVE termination: only blocked hostnames
    ///     are ever decrypted — everything else is a byte-for-byte tunnel;
    ///   · everything else → forwarded upstream untouched. The proxy is
    ///     pass-first, block-second: any internal error degrades to normal
    ///     forwarding (or a plain 502), never to "the internet stopped".
    ///
    /// Fail-safety mirrors the intercept stack: hooks are journaled
    /// (BlockPageProxyHooks) and restored on stop/exit/crash; the listener
    /// restarts itself through transient errors and — if it ever fails
    /// fatally — disables the whole feature itself, because a system proxy
    /// pointing at a dead port is worse than no friendly page at all.
    /// </summary>
    public sealed class BlockPageProxyService
    {
        public static BlockPageProxyService Instance => _instance ??= new BlockPageProxyService();
        private static BlockPageProxyService _instance;

        public const int DefaultPort = 7878;
        private const int HeadLimitBytes = 16 * 1024;
        private static readonly TimeSpan DecisionCacheTtl = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan NegativeResolveCache = TimeSpan.FromMinutes(2);
        private const int MaxFatalAcceptFailures = 5;

        /// <summary>Settable for offline self-tests (house pattern): an
        /// ephemeral port keeps the test off the real feature's port.</summary>
        internal static int PortOverride;

        /// <summary>Decision seam for tests: hostname → (blocked, class).
        /// Null = resolve + blocked-inventory join (the real behavior).</summary>
        internal static Func<string, Task<(bool Blocked, string Class)>> Decision;

        /// <summary>TLS seam for tests: false skips CA install/leaf minting so
        /// plain-HTTP and tunnel paths run without touching the trust store.</summary>
        internal static bool TlsInterceptEnabled = true;

        /// <summary>Hook seam for tests: false keeps StartAsync's hands off
        /// the real WinINET settings entirely (the self-test must never
        /// re-route the host machine's traffic).</summary>
        internal static bool InstallHooks = true;

        /// <summary>Upstream-connect resolver seam for tests: null = System
        /// .Net.Dns. The self-test pins every hostname to loopback so tunnel
        /// tests hit a local HttpListener without touching real DNS.</summary>
        internal static Func<string, Task<IPAddress[]>> UpstreamResolver;

        /// <summary>Audit sink for tests: the lifecycle events go to the
        /// shared blocks ledger (static facade — the real user store), so
        /// the offline self-test redirects them here instead.</summary>
        internal static Action<string> AuditSink;

        private static void Audit(string detail)
        {
            try
            {
                if (AuditSink != null) AuditSink(detail);
                else BlocksStore.AppendEvent("blockproxy", "-", "-", detail, "settings");
            }
            catch { /* ledger writes are best-effort */ }
        }

        private readonly object _gate = new();
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private readonly ConcurrentDictionary<string, (DateTime At, bool Blocked, string Class)> _decisions =
            new(StringComparer.OrdinalIgnoreCase);
        private int _acceptFailures;
        private int _pagesServed;

        public BlockProxyStatus Status { get; private set; } = BlockProxyStatus.Stopped;
        public string StatusDetail { get; private set; }
        public int Port { get; private set; } = DefaultPort;
        public int PagesServed => _pagesServed;
        public event Action StatusChanged;

        /// <summary>Raised when the fail-safe self-disabled the feature (the
        /// listener died fatally) — the app wiring toasts this, because the
        /// user must know their proxy just went away.</summary>
        public event Action<string> AutoDisabled;

        private BlockPageProxyService() { }

        public bool IsRunning => Status is BlockProxyStatus.Listening or BlockProxyStatus.Starting;

        // ── lifecycle ─────────────────────────────────────────────────────

        /// <summary>Installs the WinINET hooks and starts listening. Returns
        /// false (with StatusDetail) when the port is taken or startup failed
        /// — the hooks are never installed unless the listener is live first,
        /// so a busy port degrades to "feature off", never to "no internet".</summary>
        public async Task<bool> StartAsync()
        {
            lock (_gate)
            {
                if (IsRunning) return true;
            }

            Port = PortOverride > 0 ? PortOverride : DefaultPort;
            Status = BlockProxyStatus.Starting;
            StatusDetail = "starting…";
            StatusChanged?.Invoke();

            if (TlsInterceptEnabled)
            {
                try
                {
                    // The CA is created here so the first blocked HTTPS page
                    // does not pay the minting cost mid-request. Trust-store
                    // installation only happens on the real (hooks-on) path —
                    // the self-test runs the same code with a temp CA dir.
                    _ = InterceptCaService.GetOrCreateCa();
                    if (InstallHooks) InterceptCaService.InstallToRoot();
                }
                catch (Exception ex)
                {
                    // HTTPS pages degrade to generic browser errors; plain-HTTP
                    // pages and tunnels keep working, so this is not fatal.
                    StatusDetail = $"CA unavailable ({ex.Message}) — HTTPS block pages will be generic.";
                }
            }

            _cts = new CancellationTokenSource();
            try
            {
                // Tests (hooks off) may bind port 0 — the real port is read
                // back below so the test can address it.
                int listenPort = (!InstallHooks && PortOverride == 0) ? 0 : Port;
                _listener = new TcpListener(IPAddress.Loopback, listenPort);
                _listener.Start(128);
                if (listenPort == 0) Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            }
            catch (SocketException ex)
            {
                _listener = null;
                _cts.Dispose(); _cts = null;
                Status = BlockProxyStatus.PortBusy;
                StatusDetail = $"127.0.0.1:{Port} is already in use ({ex.SocketErrorCode}) — feature stays off.";
                StatusChanged?.Invoke();
                return false;
            }

            // Listener LIVE before the hooks: the window between "proxy
            // installed" and "listening" is where connectivity would die.
            if (InstallHooks)
            {
                try
                {
                    BlockPageProxyHooks.Install(Port);
                }
                catch (Exception ex)
                {
                    await HardStopInternalAsync("hook install failed", disableHooks: false);
                    Status = BlockProxyStatus.Failed;
                    StatusDetail = $"Could not install the per-user proxy: {ex.Message}";
                    StatusChanged?.Invoke();
                    return false;
                }
            }

            Status = BlockProxyStatus.Listening;
            StatusDetail = $"127.0.0.1:{Port} — blocked hostnames get an explanation, everything else forwards.";
            _acceptFailures = 0;
            StatusChanged?.Invoke();
            Audit($"block-page proxy enabled on 127.0.0.1:{Port} (WinINET, block pages + selective TLS termination)");
            _ = Task.Run(() => AcceptLoopAsync(_cts.Token));
            return true;
        }

        public async Task StopAsync(string reason = "toggle off")
        {
            if (Status == BlockProxyStatus.Stopped) return;
            await HardStopInternalAsync(reason, disableHooks: true);
        }

        /// <summary>The one teardown path — listener down FIRST (nothing can
        /// reach a half-dead proxy), then hooks restored, then the CA lifted
        /// unless an intercept session still needs it.</summary>
        private async Task HardStopInternalAsync(string reason, bool disableHooks)
        {
            lock (_gate)
            {
                try { _listener?.Stop(); } catch { }
                _listener = null;
                try { _cts?.Cancel(); } catch { }
                _cts?.Dispose(); _cts = null;
            }
            if (disableHooks)
            {
                if (InstallHooks)
                {
                    try { BlockPageProxyHooks.Undo(); } catch { /* startup repair sweeps stragglers */ }
                }
            }
            if (TlsInterceptEnabled)
            {
                try
                {
                    // The intercept MITM session may legitimately still be
                    // running — its CA stays until its own session ends.
                    if (!InterceptProxyService.Shared.IsRunning)
                    {
                        var removed = InterceptCaService.TryRemoveFromRoot();
                        InterceptCaService.ClearLeafCache();
                        if (removed == InterceptCaService.RootRemoveResult.Failed)
                            StatusDetail = "note: the Intercept CA could not be removed from the trust store — try again or remove it manually (certmgr).";
                    }
                }
                catch { /* best-effort — the thumbprint-pinned removal is retried by the intercept repair */ }
            }
            Status = BlockProxyStatus.Stopped;
            StatusDetail = $"stopped ({reason}).";
            StatusChanged?.Invoke();
            Audit($"block-page proxy disabled ({reason})");
            await Task.CompletedTask;
        }

        /// <summary>App-exit hook: undo the hooks even when Settings never
        /// got a clean toggle-off (MainWindow.OnClosed).</summary>
        public static void ShutdownOnExit()
        {
            try { BlockPageProxyHooks.RecoverAfterCrash(); } catch { }
        }

        // ── accept loop + fail-safe ───────────────────────────────────────

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            var listener = _listener;
            while (!ct.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await listener.AcceptSocketAsync();
                    _acceptFailures = 0;
                }
                catch (ObjectDisposedException) { break; }   // Stop() called
                catch (SocketException)
                {
                    // Transient listener errors restart with a short backoff;
                    // a sustained failure disables the whole feature — a
                    // system proxy pointing at a dead port is the one failure
                    // mode this feature must never survive into.
                    if (++_acceptFailures >= MaxFatalAcceptFailures)
                    {
                        await HardStopInternalAsync("listener failed repeatedly — auto-disabled to protect connectivity", disableHooks: true);
                        AutoDisabled?.Invoke("The block-page proxy stopped itself: its listener kept failing. " +
                                             "Your normal internet settings are restored.");
                        return;
                    }
                    try { await Task.Delay(500, ct); } catch (OperationCanceledException) { break; }
                    continue;
                }
                _ = Task.Run(() => HandleConnectionAsync(client), ct);
            }
        }

        // ── per-connection handling ───────────────────────────────────────

        private async Task HandleConnectionAsync(Socket client)
        {
            try
            {
                using (client)
                {
                    client.ReceiveTimeout = 30_000;
                    client.SendTimeout = 30_000;
                    using var stream = new NetworkStream(client, ownsSocket: false);
                    string head = await ReadHeadAsync(stream);
                    if (head == null) return;

                    string requestLine = head.Split('\n')[0].TrimEnd('\r');
                    if (requestLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                        await HandleConnectAsync(client, stream, requestLine);
                    else if (requestLine.Contains("://"))
                        // absolute-form proxy speech — "GET http://host/path HTTP/1.1"
                        // (the METHOD comes first; the absolute URL never starts
                        // the line, which is exactly the dispatch bug the
                        // self-test caught)
                        await HandlePlainHttpAsync(stream, head, requestLine);
                    // anything else is not explicit-proxy speech — close
                }
            }
            catch { /* one broken client never takes the proxy down */ }
        }

        /// <summary>CONNECT host:port — the only place a hostname is visible
        /// for HTTPS. Blocked: answer the tunnel, terminate TLS with our leaf,
        /// serve the page over 403. Unblocked: connect upstream BEFORE the
        /// 200 goes out (so an unreachable origin surfaces as 502, not as a
        /// tunnel that dies mid-handshake), then pump bytes untouched.</summary>
        private async Task HandleConnectAsync(Socket client, NetworkStream stream, string requestLine)
        {
            string authority = requestLine.Length > 8 ? requestLine[8..].Trim() : "";
            int space = authority.IndexOf(' ');
            if (space > 0) authority = authority[..space];
            string host = authority;
            int port = 443;
            int colon = host.LastIndexOf(':');
            if (host.StartsWith("["))   // [IPv6]:port
            {
                int bracket = host.IndexOf(']');
                if (bracket > 0)
                {
                    if (bracket + 1 < host.Length && host[bracket + 1] == ':'
                        && int.TryParse(host[(bracket + 2)..], out int p6)) port = p6;
                    host = host[1..bracket];
                }
            }
            else if (colon > 0 && int.TryParse(host[(colon + 1)..], out int p)) { port = p; host = host[..colon]; }

            if (IsLoopbackName(host)) return;   // bypass should prevent; belt and braces

            var (blocked, cls) = await DecideAsync(host);

            if (blocked)
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"));
                if (!TlsInterceptEnabled)
                {
                    try { client.Close(); } catch { }
                    return;
                }
                try
                {
                    await ServePageOverTlsAsync(stream, host, cls);
                }
                catch (Exception ex)
                {
                    // pinned clients abort the handshake — same as intercept;
                    // the failure lands in StatusDetail so the Settings row
                    // (and the self-test) can see WHY a page did not serve
                    StatusDetail = $"TLS block page failed for {host}: {ex.Message}";
                    StatusChanged?.Invoke();
                }
                finally
                {
                    try { client.Close(); } catch { }
                }
                return;
            }

            // Unblocked: upstream first, then the 200.
            Socket upstream = null;
            try
            {
                upstream = await ConnectUpstreamAsync(host, port);
            }
            catch { }
            if (upstream == null)
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"));
                return;
            }
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"));
            await PumpBothAsync(stream, new NetworkStream(upstream, ownsSocket: false));
        }

        /// <summary>Plain absolute-form HTTP: blocked hosts get the page
        /// straight from the proxy; everyone else is forwarded with the first
        /// line rewritten to origin form (the same rewrite InterceptProxyService
        /// does) and Connection: close so the raw pump terminates cleanly.</summary>
        private async Task HandlePlainHttpAsync(NetworkStream stream, string head, string requestLine)
        {
            string host = null;
            int port = 80;
            int space1 = requestLine.IndexOf(' ');
            int lastSpace = requestLine.LastIndexOf(' ');
            if (space1 > 0 && lastSpace > space1)
            {
                string rest = requestLine[(space1 + 1)..lastSpace];
                // strip the scheme first — "http://host/path".Split('/') starts
                // with "http:", which is exactly the mis-parse the self-test
                // caught (every plain-HTTP host looked like "http:")
                if (rest.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) rest = rest[7..];
                else if (rest.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) rest = rest[8..];
                string authority = rest.Split('/')[0];
                string path = rest.Length > authority.Length ? rest[authority.Length..] : "/";
                int colon = authority.LastIndexOf(':');
                if (colon > 0 && int.TryParse(authority[(colon + 1)..], out int parsed))
                {
                    host = authority[..colon];
                    port = parsed;
                }
                else host = authority;
                requestLine = $"{requestLine[..space1]} {path} {requestLine[(lastSpace + 1)..]}";
            }
            if (host == null)
            {
                foreach (string line in head.Split('\n'))
                {
                    if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                    {
                        host = line.Substring(5).Trim();
                        int hostColon = host.LastIndexOf(':');
                        if (hostColon > 0 && int.TryParse(host[(hostColon + 1)..], out int hostPort))
                        {
                            port = hostPort;
                            host = host[..hostColon];
                        }
                        break;
                    }
                }
            }
            if (host == null || IsLoopbackName(host)) return;

            var (blocked, cls) = await DecideAsync(host);
            if (blocked)
            {
                await WriteBlockPageAsync(stream, host, cls, statusCode: 403);
                Interlocked.Increment(ref _pagesServed);
                return;
            }

            Socket upstream = null;
            try { upstream = await ConnectUpstreamAsync(host, port); }
            catch { }
            if (upstream == null)
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"));
                return;
            }
            var upstreamStream = new NetworkStream(upstream, ownsSocket: false);
            // origin-form request line + forced close semantics
            var rebuilt = new StringBuilder();
            rebuilt.Append(requestLine).Append("\r\n");
            foreach (string line in head.Split('\n').Skip(1))
            {
                string l = line.TrimEnd('\r');
                if (l.Length == 0) continue;
                if (l.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase)) continue;   // proxy-private headers never travel
                if (l.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase)) continue;
                rebuilt.Append(l).Append("\r\n");
            }
            rebuilt.Append("Connection: close\r\n\r\n");
            await upstreamStream.WriteAsync(Encoding.ASCII.GetBytes(rebuilt.ToString()));
            // The forced upstream Connection: close means the origin's EOF IS
            // the end of the response — close the client side the moment it
            // arrives (waiting for the browser's own close would strand a
            // pump pair for every keep-alive socket the browser pools).
            await PumpBothAsync(stream, upstreamStream, closeOnFirstEnd: true);
        }

        /// <summary>TLS with our minted leaf, then the inner request gets the
        /// 403 + page. Modeled on InterceptProxyService's server-side branch.
        /// The inner head is READ (not parsed) before answering: closing with
        /// unread socket data sends RST, which can kill the page before the
        /// browser loads it.</summary>
        private async Task ServePageOverTlsAsync(NetworkStream stream, string host, string cls)
        {
            var leaf = InterceptCaService.GetOrMintLeaf(host);
            using var tls = new SslStream(stream, leaveInnerStreamOpen: false);
            await tls.AuthenticateAsServerAsync(leaf, clientCertificateRequired: false,
                enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: false);

            _ = await ReadHeadAsync(tls);   // drain the inner request head
            await WriteBlockPageAsync(tls, host, cls, statusCode: 403);
            Interlocked.Increment(ref _pagesServed);
            try { await Task.Delay(200); } catch { }   // let the page leave before teardown
        }

        // ── block decision (cached; fail-open) ────────────────────────────

        private async Task<(bool Blocked, string Class)> DecideAsync(string host)
        {
            if (Decision != null)
            {
                try { return await Decision(host); }
                catch { return (false, null); }   // seam failure must not take browsing down
            }

            if (_decisions.TryGetValue(host, out var hit) && DateTime.UtcNow - hit.At < DecisionCacheTtl)
                return (hit.Blocked, hit.Class);

            BlockHitFeedService.Instance.Start();   // inventory source (idempotent)
            IPAddress[] addresses;
            try
            {
                var work = Dns.GetHostAddressesAsync(host);
                if (await Task.WhenAny(work, Task.Delay(6000)) != work) addresses = null;
                else addresses = work.Result;
            }
            catch { addresses = null; }

            bool blocked = false;
            string cls = null;
            if (addresses != null && addresses.Length > 0)
            {
                foreach (var addr in addresses)
                {
                    var normal = addr.IsIPv4MappedToIPv6 ? addr.MapToIPv4() : addr;
                    var info = BlockHitFeedService.Instance.BlockedIp(normal.ToString());
                    if (info != null)
                    {
                        blocked = true;
                        cls = info.Class ?? "";
                        break;
                    }
                }
            }
            _decisions[host] = (DateTime.UtcNow, blocked, cls ?? "");
            // Failed resolves are cached too (negative): a dead DNS must not
            // turn every request into a 6-second stall. Both caches expire.
            if (addresses == null)
                _decisions[host] = (DateTime.UtcNow - DecisionCacheTtl + NegativeResolveCache, false, "");
            return (blocked, cls);
        }

        private static bool IsLoopbackName(string host)
        {
            if (string.IsNullOrEmpty(host)) return true;
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
            return IPAddress.TryParse(host, out var ip)
                && (IPAddress.Loopback.Equals(ip) || IPAddress.IPv6Loopback.Equals(ip));
        }

        private async Task<Socket> ConnectUpstreamAsync(string host, int port)
        {
            IPAddress[] addresses;
            try
            {
                var work = UpstreamResolver != null ? UpstreamResolver(host) : Dns.GetHostAddressesAsync(host);
                if (await Task.WhenAny(work, Task.Delay(6000)) != work) return null;
                addresses = work.Result;
            }
            catch { return null; }

            foreach (var addr in addresses)
            {
                var normal = addr.IsIPv4MappedToIPv6 ? addr.MapToIPv4() : addr;
                // Loopback upstreams are refused with the REAL resolver —
                // a name resolving to 127.0.0.1 through a proxy is a loop
                // (or a pin) waiting to happen. The test seam pins loopback
                // deliberately, so it may pass.
                if (UpstreamResolver == null &&
                    (IPAddress.Loopback.Equals(normal) || IPAddress.IPv6Loopback.Equals(normal)))
                    continue;
                var socket = new Socket(normal.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(normal, port);
                    return socket;
                }
                catch
                {
                    try { socket.Dispose(); } catch { }
                }
            }
            return null;
        }

        // ── the friendly page ─────────────────────────────────────────────

        internal static string BuildBlockPageHtml(string host, string cls, int statusCode)
        {
            string clsLine = string.IsNullOrEmpty(cls)
                ? ""
                : $"<p class='muted'>Matches: {Escape(cls)} (AutoCommand block list).</p>";
            return $@"<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>Blocked by AutoCommand — {Escape(host)}</title>
<style>
 body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#f6f7f9; color:#1f2430;
        display:flex; align-items:center; justify-content:center; min-height:90vh; margin:0; }}
 .card {{ background:#fff; max-width:640px; padding:40px 48px; border-radius:12px;
         box-shadow:0 6px 24px rgba(20,30,60,.12); }}
 h1 {{ font-size:20px; margin:0 0 12px; }} code {{ background:#eef1f5; padding:2px 6px; border-radius:4px; }}
 .muted {{ color:#5b6472; font-size:13px; }} .why {{ line-height:1.55; }}
 ul {{ line-height:1.7; }} .foot {{ margin-top:24px; font-size:12px; color:#5b6472; }}
</style></head><body><div class='card'>
<h1>This address is blocked by AutoCommand</h1>
<p class='why'>Your Windows Firewall has a rule that refuses every connection to
<code>{Escape(host)}</code>. The site never received your request — the block happened on your own machine.</p>
{clsLine}
<p class='why'>To let this through:</p>
<ul>
 <li>Open <b>AutoCommand</b> → <b>Blocks</b> tab and remove the matching IP block, or</li>
 <li>if this hostname is on your <b>Domain blocks</b> list, remove it there (the DNS sync will retire its rules), or</li>
 <li>use <b>Blocked → Manage all</b> for the full rule list.</li>
</ul>
<p class='foot'>Block-page proxy · served locally by AutoCommand · nothing about this request left your machine.
Status {statusCode}.</p>
</div></body></html>";
        }

        private static string Escape(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");

        private static async Task WriteBlockPageAsync(Stream stream, string host, string cls, int statusCode)
        {
            string body = BuildBlockPageHtml(host, cls, statusCode);
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string head =
                $"HTTP/1.1 {statusCode} Blocked\r\n" +
                "Content-Type: text/html; charset=utf-8\r\n" +
                $"Content-Length: {bodyBytes.Length}\r\n" +
                "Connection: close\r\n" +
                "Cache-Control: no-store\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(head));
            await stream.WriteAsync(bodyBytes);
            await stream.FlushAsync();
        }

        // ── stream helpers ────────────────────────────────────────────────

        /// <summary>Reads one HTTP head (\r\n\r\n-terminated) WITHOUT
        /// consuming past it — byte-at-a-time so nothing that belongs to the
        /// next layer (TLS handshake, request body) is swallowed. Loopback
        /// latency makes this cheap; the cap keeps a hostile client from
        /// allocating.</summary>
        private static async Task<string> ReadHeadAsync(Stream stream)
        {
            var buffer = new MemoryStream();
            var one = new byte[1];
            while (buffer.Length < HeadLimitBytes)
            {
                int n = await stream.ReadAsync(one, 0, 1);
                if (n <= 0) return null;
                buffer.WriteByte(one[0]);
                if (buffer.Length >= 4)
                {
                    long pos = buffer.Position;
                    var bytes = buffer.GetBuffer();
                    int start = (int)pos - 4;
                    if (bytes[start] == (byte)'\r' && bytes[start + 1] == (byte)'\n'
                        && bytes[start + 2] == (byte)'\r' && bytes[start + 3] == (byte)'\n')
                    {
                        return Encoding.ASCII.GetString(bytes, 0, (int)pos);
                    }
                }
            }
            return null;   // oversized head — close
        }

        /// <summary>Relay both directions. closeOnFirstEnd=true (plain HTTP
        /// forwarding): either side's EOF ends the whole relay — the upstream
        /// close IS the response end. False (CONNECT tunnels): both directions
        /// must end, because a keep-alive origin closes and serves the NEXT
        /// request on the same tunnel — closing early would kill browsing.</summary>
        private static async Task PumpBothAsync(NetworkStream a, NetworkStream b, bool closeOnFirstEnd = false)
        {
            var toB = a.CopyToAsync(b);
            var toA = b.CopyToAsync(a);
            if (closeOnFirstEnd)
            {
                var done = await Task.WhenAny(toB, toA);
                try { await done; } catch { /* errors are normal at EOF */ }
                try { a.Dispose(); } catch { }
                try { b.Dispose(); } catch { }
                try { await Task.WhenAll(toB, toA); } catch { }
                return;
            }
            try { await Task.WhenAll(toB, toA); } catch { /* half-close and errors are normal here */ }
            try { a.Flush(); } catch { }
            try { b.Flush(); } catch { }
            try { b.Dispose(); } catch { }
        }
    }
}
