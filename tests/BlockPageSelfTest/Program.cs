// BlockPageSelfTest — the block-awareness layers, offline.
//
// Persistence is redirected to a temp dir (house pattern: the settable
// statics — StoreDirectory, InterceptCaService.DirOverride). The proxy
// section runs the shipped BlockPageProxyService in-process with hooks
// OFF (never touches the machine's real WinINET settings or trust
// store), a pinned decision seam, a loopback-pinned upstream resolver,
// and a raw-socket origin — the full request paths, not mocks of them.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AutoCommand.Contain.Core;
using AutoCommand.Engines.Firewall;
using AutoCommand.Intercept.Core;

int failures = 0;
void Check(bool ok, string name)
{
    Console.WriteLine((ok ? "PASS  " : "FAIL  ") + name);
    if (!ok) failures++;
}

string tempRoot = args.Length > 0
    ? Path.Combine(args[0], "blockpage-selftest-" + Guid.NewGuid().ToString("N")[..8])
    : Path.Combine(Path.GetTempPath(), "blockpage-selftest-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(tempRoot);

// ── S1: the 5157 parser ──────────────────────────────────────────────
{
    string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>5157</EventID><TimeCreated SystemTime="2026-11-16T14:22:31.000Z"/></System>
          <EventData>
            <Data Name="Application">C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe</Data>
            <Data Name="SourceAddress">192.168.6.42</Data>
            <Data Name="SourcePort">52741</Data>
            <Data Name="DestAddress">199.232.210.172</Data>
            <Data Name="DestPort">443</Data>
            <Data Name="Protocol">6</Data>
            <Data Name="FilterRTID">88012</Data>
            <Data Name="LayerName">FWPM_LAYER_ALE_AUTH_CONNECT_V4</Data>
            <Data Name="RemoteUserID">S-1-5-18</Data>
          </EventData>
        </Event>
        """;
    var deny = FirewallDenyWatchService.ParseEventXml(xml);
    Check(deny != null, "S1: 5157 xml parses");
    Check(deny?.Image == @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", "S1: image by name");
    Check(deny?.DestIp == "199.232.210.172" && deny?.DestPort == 443, "S1: destination 4-tuple");
    Check(deny?.Protocol == "TCP", "S1: protocol 6 → TCP");
    Check(deny?.FilterRtId == 88012, "S1: filter id");
    Check(FirewallDenyWatchService.ParseEventXml("<not-xml") == null, "S1: malformed → null");
    Check(FirewallDenyWatchService.ParseEventXml(xml.Replace("DestAddress\">199.232.210.172", "DestAddress\">not-an-ip")) == null,
        "S1: non-IP destination → null");
}

// ── S2: the toast rate limiter ───────────────────────────────────────
{
    var svc = FirewallDenyWatchService.Instance;
    var t0 = DateTime.UtcNow;
    Check(svc.ShouldToast(t0, "brave.exe", "199.232.210.172", TimeSpan.FromMinutes(10)), "S2: first (proc,ip) toasts");
    Check(!svc.ShouldToast(t0.AddSeconds(30), "brave.exe", "199.232.210.172", TimeSpan.FromMinutes(10)),
        "S2: same pair inside window stays quiet");
    Check(svc.ShouldToast(t0.AddSeconds(30), "chrome.exe", "199.232.210.172", TimeSpan.FromMinutes(10)),
        "S2: different process toasts immediately");
    Check(svc.ShouldToast(t0.AddMinutes(11), "brave.exe", "199.232.210.172", TimeSpan.FromMinutes(10)),
        "S2: window expiry re-arms");
    var msg = FirewallDenyWatchService.BuildToastMessage(new FirewallDenyWatchService.DenyEvent
    {
        Image = @"C:\Browsers\brave.exe",
        DestIp = "199.232.210.172",
        DestPort = 443,
        Protocol = "TCP",
        BlockedClass = "Akamai (MS CDN)",
    });
    Check(msg.Contains("brave.exe") && msg.Contains("199.232.210.172:443") && msg.Contains("Akamai (MS CDN)"),
        "S2: toast message names process, endpoint, class");
}

// ── S3: the impact probe (pinned resolver) ───────────────────────────
{
    var table = new Dictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["target.test"] = new[] { IPAddress.Parse("203.0.113.5") },
        ["windowsupdate.com"] = new[] { IPAddress.Parse("203.0.113.5"), IPAddress.Parse("1.2.3.4") },   // shares the target's edge
        ["unknown.test"] = null,                                       // resolver failure
    };
    // every curated service gets its own answer — a real probe resolves all of them
    int counter = 10;
    foreach (var cs in BlockImpactProbe.CriticalServices)
        if (!table.ContainsKey(cs.Domain))
            table[cs.Domain] = new[] { IPAddress.Parse($"140.82.{counter / 250}.{counter++ % 250 + 1}") };
    BlockImpactProbe.Resolver = host => Task.FromResult(table.TryGetValue(host, out var ips) ? ips : null);
    var probe = await BlockImpactProbe.ProbeAsync("target.test");
    Check(probe.Affected.Any(s => s.Domain == "windowsupdate.com"), "S3: shared edge detected");
    Check(probe.Affected.All(s => s.Domain != "github.com"), "S3: unrelated services not flagged");
    Check(probe.WarningLine().Contains("Windows Update"), "S3: warning line tells the story");
    var lone = await BlockImpactProbe.ProbeAsync("github.com");
    // github.com IS a curated service, so it self-matches — assert only
    // that nothing ELSE shares its address
    Check(lone.Affected.All(s => s.Domain == "github.com") && !lone.Incomplete, "S3: clean target unaffected");
    var dead = await BlockImpactProbe.ProbeAsync("unknown.test");
    Check(dead.Incomplete, "S3: resolver failure marks probe incomplete");
    BlockImpactProbe.Resolver = null;
}

// ── S4: the proxy-hook shapes + journal-absent recovery no-op ────────
{
    BlockPageProxyHooks.StoreDirectory = Path.Combine(tempRoot, "hooks");
    Check(BlockPageProxyHooks.ServerShape.IsMatch("127.0.0.1:7878"), "S4: own proxy shape accepted");
    Check(BlockPageProxyHooks.ServerShape.IsMatch("http=10.0.0.1:80;https=10.0.0.1:443"), "S4: per-scheme proxy shape accepted");
    Check(!BlockPageProxyHooks.ServerShape.IsMatch("evil\"--x & format"), "S4: hostile proxy string rejected");
    Check(BlockPageProxyHooks.OverrideShape.IsMatch("127.0.0.1;localhost;<local>"), "S4: bypass shape accepted");
    Check(BlockPageProxyHooks.OwnProxyServerShape(7878).Contains("127") &&
          new Regex(BlockPageProxyHooks.OwnProxyServerShape(7878)).IsMatch("127.0.0.1:7878") &&
          !new Regex(BlockPageProxyHooks.OwnProxyServerShape(7878)).IsMatch("127.0.0.1:7879"),
        "S4: own-shape regex pins the exact port");
    BlockPageProxyHooks.RecoverAfterCrash();   // no journal on disk — must be a silent no-op
    Check(!File.Exists(Path.Combine(BlockPageProxyHooks.StoreDirectory, "blockproxy-active.json")),
        "S4: recovery without journal is a no-op");
}

// ── S5: the domain block sync lifecycle (fake engine seams) ─────────
{
    string dir = Path.Combine(tempRoot, "domain-sync");
    DomainBlockSyncService.StoreDirectory = dir;
    var answers = new Dictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["app.test"] = new[] { IPAddress.Parse("203.0.113.10"), IPAddress.Parse("203.0.113.11") },
        ["shared.test"] = new[] { IPAddress.Parse("203.0.114.5") },
    };
    DomainBlockSyncService.Resolver = host => Task.FromResult(
        answers.TryGetValue(host, out var ips) ? ips : null);
    var addCalls = new List<string>();
    var removeCalls = new List<(string Name, string Marker)>();
    DomainBlockSyncService.AddIpBlock = (ip, desc) =>
    {
        addCalls.Add(ip);
        return Task.FromResult((1, 0, new[]
            { $"AC-BLOCK-IP {ip} (TCP Out)", $"AC-BLOCK-IP {ip} (UDP Out)" }));
    };
    DomainBlockSyncService.RemoveRuleByName = (name, marker) =>
    {
        removeCalls.Add((name, marker));
        return Task.FromResult(1);
    };
    DomainBlockSyncService.Inventory = () => Task.FromResult(new List<BlockedTarget>());

    Check(!DomainBlockSyncService.IsValidDomain("not a host"), "S5: invalid name rejected");
    Check(!DomainBlockSyncService.IsValidDomain("no-dots"), "S5: bare label rejected");
    Check(DomainBlockSyncService.IsValidDomain("app.test"), "S5: hostname accepted");

    await DomainBlockSyncService.Instance.AddAsync("app.test", "blocks-tab");
    Check(addCalls.Count == 2, "S5: both DNS addresses get rule pairs");
    Check(DomainBlockSyncService.Instance.OwnedFor("app.test") == (2, 4), "S5: ownership map tracks 2 IPs · 4 rules");

    // rotation: one address rotates away, one remains
    answers["app.test"] = new[] { IPAddress.Parse("203.0.113.10") };
    removeCalls.Clear();
    await DomainBlockSyncService.Instance.SyncAllAsync();
    Check(removeCalls.Count == 2, "S5: rotated-away IP's rules retired by exact name");
    Check(removeCalls.All(r => r.Marker.Contains("domain block app.test")), "S5: removal requires the ownership marker");
    Check(DomainBlockSyncService.Instance.OwnedFor("app.test") == (1, 2), "S5: map drops the rotated IP");

    // disown: the marker check fails (a manual re-block owns the rule now);
    // the sync rotates to a new edge — old IP is disowned, not deleted
    DomainBlockSyncService.RemoveRuleByName = (_, _) => Task.FromResult(0);
    answers["app.test"] = new[] { IPAddress.Parse("203.0.113.99") };
    await DomainBlockSyncService.Instance.SyncAllAsync();
    Check(DomainBlockSyncService.Instance.OwnedFor("app.test") == (1, 2), "S5: disowned IP leaves the map, new edge owned");
    // the ledger must NOT have deleted the disowned record — the manual block survives
    string blocksFile = Path.Combine(dir, "blocks.txt");
    Check(!File.Exists(blocksFile) || File.ReadAllText(blocksFile).Contains("203.0.113.10"),
        "S5: disowned record kept in the store");

    // removal end-to-end (a recording fake again — the discard fake above
    // answers but never records)
    DomainBlockSyncService.RemoveRuleByName = (name, marker) =>
    {
        removeCalls.Add((name, marker));
        return Task.FromResult(1);
    };
    removeCalls.Clear();
    await DomainBlockSyncService.Instance.RemoveAsync("app.test");
    Check(DomainBlockSyncService.Instance.Count == 0, "S5: domain removed from the list");
    Check(removeCalls.Count == 2, $"S5: RemoveAsync retires the held rule pair (got {removeCalls.Count}: {string.Join(",", removeCalls.Select(r => r.Name))})");
    Check(DomainBlockSyncService.Instance.OwnedFor("app.test") == (0, 0), "S5: map empty after removal");

    // covered-externally: an existing foreign rule adopts instead of creating
    DomainBlockSyncService.Inventory = () => Task.FromResult(new List<BlockedTarget>
    {
        new BlockedTarget { Kind = "ip", Ip = "203.0.114.5", EnabledRules = 2, Rules = 2 },
    });
    addCalls.Clear();
    await DomainBlockSyncService.Instance.AddAsync("shared.test");
    Check(addCalls.Count == 0, "S5: already-blocked IP adopted, not re-created");
    Check(DomainBlockSyncService.Instance.OwnedFor("shared.test") == (0, 0), "S5: adoption holds no ownership");
    await DomainBlockSyncService.Instance.RemoveAsync("shared.test");

    // seams back to null (the service instance is a process-wide singleton)
    DomainBlockSyncService.Resolver = null;
    DomainBlockSyncService.AddIpBlock = null;
    DomainBlockSyncService.RemoveRuleByName = null;
    DomainBlockSyncService.Inventory = null;
}

// ── S5b: TLS key-store environment probe ─────────────────────────────
// Persisting a private key needs a writable CryptoAPI key container.
// Restricted sandboxes (Low-IL agent jobs) deny it while CI runners and
// the elevated app allow it — where the store is denied, the TLS
// server-handshake asserts are skipped (an environment limitation, not a
// code regression). The probe itself is the shipped import path.
bool tlsKeyStoreUsable = true;
{
    InterceptCaService.DirOverride = Path.Combine(tempRoot, "intercept-ca");
    try
    {
        using var scratch = RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=probe", scratch, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var selfSigned = req.CreateSelfSigned(DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddDays(1));
        var pfx = selfSigned.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12);
        using var imported = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfx, (string)null,
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.UserKeySet |
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable |
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet);
    }
    catch (Exception ex)
    {
        tlsKeyStoreUsable = false;
        Console.WriteLine($"      [env] persisted key container unavailable ({ex.GetType().Name}: {ex.Message}) — TLS server-handshake asserts will be skipped");
    }
    finally
    {
        InterceptCaService.ClearLeafCache();
        InterceptCaService.DirOverride = null;
    }
}

// ── S6: the block-page proxy end-to-end (hooks OFF, local origin) ────
{
    BlockPageProxyService.InstallHooks = false;
    BlockPageProxyService.TlsInterceptEnabled = false;
    BlockPageProxyService.PortOverride = 0;   // ephemeral
    BlockPageProxyService.AuditSink = _ => { };
    // S6 predates scoping: pin "all apps" so these requests (made by this
    // non-browser test process) keep reaching the contained paths. The
    // scope-specific behavior is S6b below.
    ProxyScope.ModeOverride = ProxyScope.ModeAllApps;
    BlockPageProxyService.Decision = host =>
        Task.FromResult((host.Equals("blocked.test", StringComparison.OrdinalIgnoreCase),
                         host.Equals("blocked.test", StringComparison.OrdinalIgnoreCase) ? "Test CDN" : ""));
    BlockPageProxyService.UpstreamResolver = _ => Task.FromResult(new[] { IPAddress.Loopback });

    // raw-socket origin: one fixed answer, Connection: close
    var origin = new TcpListener(IPAddress.Loopback, 0);
    origin.Start();
    int originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
    _ = Task.Run(async () =>
    {
        while (true)
        {
            Socket client;
            try { client = await origin.AcceptSocketAsync(); }
            catch { break; }
            _ = Task.Run(() =>
            {
                try
                {
                    var buf = new byte[8192];
                    int total = 0;
                    do { int n = client.Receive(buf); if (n <= 0) break; total += n; }
                    while (total < buf.Length && !Encoding.ASCII.GetString(buf, 0, total).Contains("\r\n\r\n"));
                    byte[] answer = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 11\r\n\r\norigin-body");
                    client.Send(answer);
                }
                catch { }
                finally { try { client.Close(); } catch { } }
            });
        }
    });

    bool started = await BlockPageProxyService.Instance.StartAsync();
    Check(started, "S6: proxy starts (hooks off)");
    int proxyPort = BlockPageProxyService.Instance.Port;
    Check(proxyPort > 0, "S6: ephemeral port bound");

    // a) blocked plain-HTTP → the friendly page
    try
    {
        var req = (HttpWebRequest)WebRequest.Create("http://blocked.test/path");
        req.Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}");
        req.Timeout = 15000;
        string body;
        try
        {
            using var resp = (HttpWebResponse)req.GetResponse();
            body = new StreamReader(resp.GetResponseStream()).ReadToEnd();
        }
        catch (WebException ex)
        {
            using var resp = (HttpWebResponse)ex.Response;
            body = new StreamReader(resp.GetResponseStream()).ReadToEnd();
        }
        Check(body.Contains("This address is blocked by AutoCommand") && body.Contains("blocked.test"),
            $"S6: blocked host gets the friendly page (body[..160]={body[..Math.Min(160, body.Length)]})");
    }
    catch (Exception ex) { Check(false, $"S6: blocked plain-HTTP page ({ex.GetType().Name}: {ex.ToString()} (proxy status: {BlockPageProxyService.Instance.StatusDetail})"); }

    // b) unblocked plain-HTTP → forwarded to the origin untouched.
    // The origin port is in the URL so the proxy's upstream connect lands
    // on the local listener (nothing runs on loopback:80 here).
    try
    {
        var req = (HttpWebRequest)WebRequest.Create($"http://safe.test:{originPort}/data");
        req.Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}");
        req.Timeout = 15000;
        using var resp = (HttpWebResponse)req.GetResponse();
        string body = new StreamReader(resp.GetResponseStream()).ReadToEnd();
        Check(resp.StatusCode == HttpStatusCode.OK && body == "origin-body", "S6: unblocked host forwards to origin");
    }
    catch (Exception ex) { Check(false, $"S6: passthrough ({ex.GetType().Name}: {ex.ToString()} (proxy status: {BlockPageProxyService.Instance.StatusDetail})"); }

    // c) CONNECT tunnel (unblocked): 200 then the origin's answer flows through
    try
    {
        string reply = await TunnelAndRequestAsync(proxyPort, "safe.test", originPort, originPort);
        Check(reply.Contains("HTTP/1.1 200 Connection established") && reply.Contains("origin-body"),
            $"S6: CONNECT tunnel passes through to origin (reply[..120]={reply[..Math.Min(120, reply.Length)]})");
    }
    catch (Exception ex) { Check(false, $"S6: CONNECT tunnel ({ex.GetType().Name}: {ex.ToString()}"); }

    // d) CONNECT blocked (TLS off in this section): 200 then close. No GET is
    // sent — the proxy closes without reading, and sending more bytes first
    // would trigger an RST that could kill the 200 in flight.
    try
    {
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(IPAddress.Loopback, proxyPort);
        await using var net = new NetworkStream(client, ownsSocket: true);
        byte[] connect = Encoding.ASCII.GetBytes("CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n");
        await net.WriteAsync(connect);
        string head = await ReadUntilDoubleCrlfAsync(net);
        Check(head.Contains("HTTP/1.1 200 Connection established"),
            "S6: blocked CONNECT answers tunnel then closes (TLS off)");
    }
    catch (Exception ex) { Check(false, $"S6: blocked CONNECT no-TLS ({ex.GetType().Name}: {ex.ToString()}"); }

    await BlockPageProxyService.Instance.StopAsync("selftest section boundary");

    // e) CONNECT blocked with TLS on: leaf minted from the temp CA → 403 + page
    try
    {
        InterceptCaService.DirOverride = Path.Combine(tempRoot, "intercept-ca");
        _ = InterceptCaService.GetOrCreateCa();
        BlockPageProxyService.TlsInterceptEnabled = true;
        bool started2 = await BlockPageProxyService.Instance.StartAsync();
        Check(started2, "S6: proxy restarts with TLS on");

        string host = "blocked.test";
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(IPAddress.Loopback, BlockPageProxyService.Instance.Port);
        await using var net = new NetworkStream(client, ownsSocket: true);
        byte[] connect = Encoding.ASCII.GetBytes($"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        await net.WriteAsync(connect);
        string head = await ReadUntilDoubleCrlfAsync(net);
        Check(head.Contains("200 Connection established"), "S6: blocked CONNECT answered");

        if (!tlsKeyStoreUsable)
        {
            Console.WriteLine("SKIP  S6: blocked HTTPS page over TLS (restricted key store in this environment)");
        }
        else
        {
            using var tls = new SslStream(net, leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,   // offline: accept our own leaf
            });
            string subject = tls.RemoteCertificate?.Subject ?? "";
            Check(subject.Contains(host), "S6: leaf minted for the blocked host");

            byte[] get = Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            await tls.WriteAsync(get);
            string page = await ReadUntilEndAsync(tls);
            Check(page.Contains("HTTP/1.1 403") && page.Contains("This address is blocked by AutoCommand"),
                $"S6: blocked HTTPS host gets the friendly page over TLS (proxy status: {BlockPageProxyService.Instance.StatusDetail})");
        }
    }
    catch (Exception ex) { Check(false, $"S6: blocked HTTPS page ({ex.GetType().Name}: {ex.ToString()} (proxy status: {BlockPageProxyService.Instance.StatusDetail})"); }
    finally
    {
        await BlockPageProxyService.Instance.StopAsync("selftest end");
        InterceptCaService.ClearLeafCache();
        InterceptCaService.DirOverride = null;
        BlockPageProxyService.TlsInterceptEnabled = true;
        BlockPageProxyService.InstallHooks = true;
        BlockPageProxyService.UpstreamResolver = null;
        BlockPageProxyService.Decision = null;
        ProxyScope.ModeOverride = null;
    }

    try { origin.Stop(); } catch { }
}

// ── S6b: proxy scope — browsers-only routing (hooks off, local origin) ──
// The client here is this test process, so the image seam decides who is
// "calling": each scenario pins one image and asserts what that client gets.
{
    BlockPageProxyService.InstallHooks = false;
    BlockPageProxyService.TlsInterceptEnabled = false;
    BlockPageProxyService.PortOverride = 0;
    BlockPageProxyService.AuditSink = _ => { };
    BlockPageProxyService.Decision = host =>
        Task.FromResult((host.Equals("blocked.test", StringComparison.OrdinalIgnoreCase),
                         host.Equals("blocked.test", StringComparison.OrdinalIgnoreCase) ? "Test CDN" : ""));
    BlockPageProxyService.UpstreamResolver = _ => Task.FromResult(new[] { IPAddress.Loopback });

    ProxyScope.ModeOverride = ProxyScope.ModeBrowsersOnly;
    ProxyScope.IncludeWebView2Override = false;
    ProxyScope.ClientImageResolver = _ => null;   // replaced per scenario

    var origin = new TcpListener(IPAddress.Loopback, 0);
    origin.Start();
    int originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
    _ = Task.Run(async () =>
    {
        while (true)
        {
            Socket client;
            try { client = await origin.AcceptSocketAsync(); }
            catch { break; }
            _ = Task.Run(() =>
            {
                try
                {
                    var buf = new byte[8192];
                    int total = 0;
                    do { int n = client.Receive(buf); if (n <= 0) break; total += n; }
                    while (total < buf.Length && !Encoding.ASCII.GetString(buf, 0, total).Contains("\r\n\r\n"));
                    byte[] answer = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 11\r\n\r\norigin-body");
                    client.Send(answer);
                }
                catch { }
                finally { try { client.Close(); } catch { } }
            });
        }
    });

    bool started = await BlockPageProxyService.Instance.StartAsync();
    Check(started, "S6b: proxy starts (browsers-only scope)");
    int proxyPort = BlockPageProxyService.Instance.Port;
    Check(BlockPageProxyService.Instance.StatusDetail.Contains("browsers only"),
        $"S6b: status line states the scope ({BlockPageProxyService.Instance.StatusDetail})");

    // One proxied plain-HTTP request as a given client image. Blocked host
    // + contained client → friendly page; anything tunneled → origin-body.
    async Task<string> FetchAsync(string pinnedImage, string host, int port)
    {
        ProxyScope.ClientImageResolver = _ => pinnedImage;
        var req = (HttpWebRequest)WebRequest.Create($"http://{host}:{port}/x");
        req.Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}");
        req.Timeout = 15000;
        try
        {
            using var resp = (HttpWebResponse)req.GetResponse();
            return new StreamReader(resp.GetResponseStream()).ReadToEnd();
        }
        catch (WebException ex)
        {
            if (ex.Response == null) throw;
            using var resp = (HttpWebResponse)ex.Response;
            return new StreamReader(resp.GetResponseStream()).ReadToEnd();
        }
    }

    try
    {
        // a) pinned browser + blocked host → the friendly page
        string page = await FetchAsync("chrome.exe", "blocked.test", originPort);
        Check(page.Contains("This address is blocked by AutoCommand"),
            "S6b: browser image still gets the block page");

        // b) pinned non-browser + the SAME blocked host → tunneled to origin
        string body = await FetchAsync("everything.exe", "blocked.test", originPort);
        Check(body == "origin-body",
            $"S6b: non-browser tunnels through a blocked host untouched (got: {body[..Math.Min(60, body.Length)]})");

        // c) lookup miss (null image) → tunnel too — fail-open, never fail-closed
        string miss = await FetchAsync(null, "blocked.test", originPort);
        Check(miss == "origin-body", "S6b: unknown client tunnels (fail-open)");

        // d) WebView2 gated by its own flag, off by default
        string wvOff = await FetchAsync("msedgewebview2.exe", "blocked.test", originPort);
        Check(wvOff == "origin-body", "S6b: WebView2 excluded by default (tunnels)");
        ProxyScope.IncludeWebView2Override = true;
        string wvOn = await FetchAsync("msedgewebview2.exe", "blocked.test", originPort);
        Check(wvOn.Contains("This address is blocked by AutoCommand"),
            "S6b: WebView2 included when the user opts in (block page)");
        ProxyScope.IncludeWebView2Override = false;

        // e) mode "all" restores the every-client behavior
        ProxyScope.ModeOverride = ProxyScope.ModeAllApps;
        string all = await FetchAsync("everything.exe", "blocked.test", originPort);
        Check(all.Contains("This address is blocked by AutoCommand"),
            "S6b: mode all contains every client");
        ProxyScope.ModeOverride = ProxyScope.ModeBrowsersOnly;

        // f) CONNECT tunnel from a non-browser → passes to the origin too
        ProxyScope.ClientImageResolver = _ => "everything.exe";
        string reply = await TunnelAndRequestAsync(proxyPort, "blocked.test", originPort, originPort);
        Check(reply.Contains("200 Connection established") && reply.Contains("origin-body"),
            "S6b: CONNECT tunnel from a non-browser passes through a blocked host");

        // g) scope list logic, pinned away from machine state
        ProxyScope.BrowserListOverride = new[] { "chrome.exe" };
        Check(ProxyScope.ShouldContain(@"C:\Browsers\Chrome\Application\chrome.exe"),
            "S6b: full-path image matched by name");
        Check(!ProxyScope.ShouldContain(@"C:\Windows\System32\cmd.exe"),
            "S6b: non-browser image out of scope");
        Check(!ProxyScope.ShouldContain(null), "S6b: null image out of scope");
        Check(!ProxyScope.ShouldContain("msedgewebview2.exe"), "S6b: WebView2 out by default");
        ProxyScope.IncludeWebView2Override = true;
        Check(ProxyScope.ShouldContain("msedgewebview2.exe"), "S6b: WebView2 in when opted in");
        ProxyScope.IncludeWebView2Override = false;
        ProxyScope.BrowserListOverride = new[] { "chrome.exe", "msedgewebview2.exe" };
        Check(!ProxyScope.ShouldContain("msedgewebview2.exe"),
            "S6b: the WebView2 flag stays authoritative even over a custom list");
        ProxyScope.IncludeWebView2Override = true;
        Check(ProxyScope.ShouldContain("msedgewebview2.exe"),
            "S6b: flag on includes WebView2 over a custom list too");
        ProxyScope.IncludeWebView2Override = false;
        ProxyScope.BrowserListOverride = null;
        ProxyScope.ModeOverride = ProxyScope.ModeAllApps;
        Check(ProxyScope.ShouldContain(@"C:\anything.exe"), "S6b: mode all contains everyone");
        ProxyScope.ModeOverride = ProxyScope.ModeBrowsersOnly;
        Check(ProxyScope.ModeText == "browsers only", "S6b: mode text plain");
    }
    catch (Exception ex)
    {
        Check(false, $"S6b: scope scenarios ({ex.GetType().Name}: {ex.Message}) (proxy status: {BlockPageProxyService.Instance.StatusDetail})");
    }
    finally
    {
        await BlockPageProxyService.Instance.StopAsync("S6b end");
        ProxyScope.ModeOverride = null;
        ProxyScope.IncludeWebView2Override = null;
        ProxyScope.ClientImageResolver = null;
        ProxyScope.BrowserListOverride = null;
        BlockPageProxyService.UpstreamResolver = null;
        BlockPageProxyService.Decision = null;
        try { origin.Stop(); } catch { }
    }
}

// ── S7: standalone leaf handshake (server role) — isolates TLS plumbing ──
if (!tlsKeyStoreUsable)
{
    Console.WriteLine("SKIP  S7: standalone leaf handshake (restricted key store in this environment)");
}
else
{
    InterceptCaService.DirOverride = Path.Combine(tempRoot, "intercept-ca");
    try
    {
        var leaf = InterceptCaService.GetOrMintLeaf("diag.test");
        Check(leaf.HasPrivateKey, "S7: minted leaf carries its private key");

        var lis = new TcpListener(IPAddress.Loopback, 0);
        lis.Start();
        int port = ((IPEndPoint)lis.LocalEndpoint).Port;
        Exception serverError = null;
        var serverTask = Task.Run(async () =>
        {
            try
            {
                using var s = await lis.AcceptSocketAsync();
                using var ns = new NetworkStream(s, ownsSocket: true);
                using var tlsS = new SslStream(ns, leaveInnerStreamOpen: false);
                await tlsS.AuthenticateAsServerAsync(leaf, clientCertificateRequired: false,
                    enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: false);
                await tlsS.WriteAsync(Encoding.ASCII.GetBytes("hello"));
            }
            catch (Exception ex) { serverError = ex; throw; }
            finally { try { lis.Stop(); } catch { } }
        });
        try
        {
            using var c = new TcpClient("127.0.0.1", port);
            using var tlsC = new SslStream(c.GetStream(), leaveInnerStreamOpen: false);
            await tlsC.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "diag.test",
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            });
            var buf = new byte[5];
            int n = await tlsC.ReadAsync(buf, 0, buf.Length);
            Check(n == 5 && Encoding.ASCII.GetString(buf) == "hello", "S6: leaf serves a TLS response");
        }
        catch (Exception ex) { Check(false, $"S6: client handshake failed: {ex.GetType().Name}: {ex.Message}"); }
        try { await serverTask; } catch { }
        Check(serverError == null, $"S6: server handshake clean (server: {serverError})");
    }
    finally
    {
        InterceptCaService.ClearLeafCache();
        InterceptCaService.DirOverride = null;
    }
}

// ── done ─────────────────────────────────────────────────────────────
Console.WriteLine(failures == 0 ? "\nALL PASS" : $"\n{failures} FAILURE(S)");
try { Directory.Delete(tempRoot, recursive: true); } catch { }
return failures == 0 ? 0 : 1;

// ── local helpers ────────────────────────────────────────────────────

static async Task<string> TunnelAndRequestAsync(int proxyPort, string host, int port, int originPort)
{
    using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    await client.ConnectAsync(IPAddress.Loopback, proxyPort);
    await using var net = new NetworkStream(client, ownsSocket: true);
    byte[] connect = Encoding.ASCII.GetBytes($"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    await net.WriteAsync(connect);
    string head = await ReadUntilDoubleCrlfAsync(net);
    if (!head.Contains("200 Connection established")) return head;

    byte[] get = Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    await net.WriteAsync(get);
    try { client.Shutdown(SocketShutdown.Send); } catch { }   // half-close: the relay's client side sees EOF
    return head + "\n" + await ReadUntilEndAsync(net);
}

static async Task<string> ReadUntilDoubleCrlfAsync(Stream stream)
{
    var sb = new StringBuilder();
    var one = new byte[1];
    while (sb.Length < 16384)
    {
        int n = await stream.ReadAsync(one, 0, 1);
        if (n <= 0) break;
        sb.Append((char)one[0]);
        if (sb.Length >= 4 && sb.ToString(sb.Length - 4, 4) == "\r\n\r\n") break;
    }
    return sb.ToString();
}

static async Task<string> ReadUntilEndAsync(Stream stream)
{
    var sb = new StringBuilder();
    var buf = new byte[4096];
    while (true)
    {
        int n = await stream.ReadAsync(buf, 0, buf.Length);
        if (n <= 0) break;
        sb.Append(Encoding.ASCII.GetString(buf, 0, n));
        if (sb.Length > 256 * 1024) break;
    }
    return sb.ToString();
}
