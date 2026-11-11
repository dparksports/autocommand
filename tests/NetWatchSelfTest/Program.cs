// NetWatch self-test — TcpConnectionTable (dual-family kernel enumeration,
// incl. a LIVE held [::1] connection) + SysmonArchiveService (watermark
// dedupe, day-file rotation, search, prune, corrupt-line tolerance) +
// FlowPeek (Traffic Peek: synthetic-packet capture → TLS-metadata-only
// honesty, remote-IP scoping, pid tagging, refcount lifecycle). Archive and
// keylog persistence run against temp dirs; nothing touches the real
// %LOCALAPPDATA% archive, keylog or the live Sysmon channel.
using System;
using AutoCommand.NetWatch.Core;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// ─────────────────────────────────────────────────────────────────────
// 1. TcpConnectionTable — destination classification, both families
// ─────────────────────────────────────────────────────────────────────
var localOrNonRoutable = new Dictionary<string, bool>
{
    ["127.0.0.1"] = true, ["127.5.5.5"] = true,
    ["192.168.1.5"] = true, ["10.0.0.1"] = true,
    ["172.16.0.1"] = true, ["172.31.9.9"] = true,
    ["172.32.0.1"] = false, ["8.8.8.8"] = false, ["1.1.1.1"] = false,
    ["224.0.0.1"] = true, ["239.255.255.255"] = true, ["255.255.255.255"] = true,
    ["::1"] = true, ["fe80::1"] = true, ["fd00::1"] = true, ["fc00::1"] = true,
    ["ff02::1"] = true, ["2600::1"] = false, ["2620:fe::fe"] = false,
    [""] = true,
};
foreach (var (ip, expected) in localOrNonRoutable)
    Check($"IsLocalOrNonRoutable({ip}) == {expected}",
        TcpConnectionTable.IsLocalOrNonRoutable(ip) == expected);
Check("IsLocalOrNonRoutable(null) == true", TcpConnectionTable.IsLocalOrNonRoutable(null));

// ─────────────────────────────────────────────────────────────────────
// 2. TcpConnectionTable — LIVE dual-family enumeration with a held
//    IPv6 loopback connection (the exact gap shipped in v2026.10.17.1:
//    AF_INET never returned it; the dual-family table must)
// ─────────────────────────────────────────────────────────────────────
using var v6Listener = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
v6Listener.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
v6Listener.Listen(1);
int listenPort = ((IPEndPoint)v6Listener.LocalEndPoint).Port;
using var accepted = new ManualResetEventSlim(false);
var v6Server = new Thread(() =>
{
    using var s = v6Listener.Accept();
    accepted.Set();
    Thread.Sleep(8000); // hold it open while the assertions run
});
v6Server.Start();

using var v6Client = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
v6Client.Connect(new IPEndPoint(IPAddress.IPv6Loopback, listenPort));

var rows = TcpConnectionTable.GetEstablished();
var v6rows = rows.Where(r => r.IsIpv6).ToList();
var v4rows = rows.Where(r => !r.IsIpv6).ToList();

Check("held [::1] connection is visible", v6rows.Any(r => r.RemoteIp == "::1"),
    $"{v6rows.Count} v6 rows: {string.Join(", ", v6rows.Select(r => r.RemoteEndPoint))}");
Check("v6 endpoints are bracketed", v6rows.All(r => r.RemoteEndPoint.StartsWith("[")),
    v6rows.FirstOrDefault()?.RemoteEndPoint ?? "(none)");
Check("v4 endpoints are not bracketed", v4rows.All(r => !r.RemoteEndPoint.StartsWith("[")),
    v4rows.FirstOrDefault()?.RemoteEndPoint ?? "(none)");
Check("every RemoteIp parses as an address", rows.All(r => IPAddress.TryParse(r.RemoteIp, out _)),
    rows.FirstOrDefault(r => !IPAddress.TryParse(r.RemoteIp, out _))?.RemoteIp ?? "");
Check("every port in range", rows.All(r => r.RemotePort > 0 && r.RemotePort <= 65535),
    rows.FirstOrDefault(r => r.RemotePort is <= 0 or > 65535)?.RemotePort.ToString() ?? "");
Check("pids are non-negative", rows.All(r => r.Pid >= 0));

v6Client.Close();

// ─────────────────────────────────────────────────────────────────────
// 3. SysmonArchiveService — offline, temp-dir persistence
// ─────────────────────────────────────────────────────────────────────
string tempRoot = Path.Combine(Path.GetTempPath(), "netwatch-selftest-" + Guid.NewGuid().ToString("N")[..8]);
SysmonArchiveService.ArchiveDirectory = tempRoot;

var day1 = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
var day2 = new DateTime(2026, 1, 2, 10, 0, 0, DateTimeKind.Utc);

var e1 = new ArchiveEvent { TsUtc = day1, Eid = 1, RecordId = 101, Data = new() { ["ProcessId"] = "111", ["Image"] = @"C:\temp\alpha.exe", ["CommandLine"] = "alpha --one" } };
var e2 = new ArchiveEvent { TsUtc = day1.AddHours(1), Eid = 3, RecordId = 102, Data = new() { ["ProcessId"] = "111", ["DestinationIp"] = "8.8.8.8", ["Image"] = @"C:\temp\alpha.exe" } };
var e3 = new ArchiveEvent { TsUtc = day1.AddHours(2), Eid = 1, RecordId = 103, Data = new() { ["ProcessId"] = "222", ["Image"] = @"C:\temp\beta.exe", ["CommandLine"] = "beta --two" } };
var e4 = new ArchiveEvent { TsUtc = day2, Eid = 1, RecordId = 104, Data = new() { ["ProcessId"] = "111", ["Image"] = @"C:\temp\alpha.exe", ["CommandLine"] = "alpha --again" } };
var e5 = new ArchiveEvent { TsUtc = day2.AddMinutes(5), Eid = 1, RecordId = 105, Data = new() { ["ProcessId"] = "333", ["Image"] = @"C:\temp\gamma.exe" } };

foreach (var e in new[] { e1, e2, e3, e4, e5 }) SysmonArchiveService.Append(e);
AutoCommand.Engines.Core.BufferedAppender.FlushAll();  // managed buffers: drain before file-level assertions

Check("day files rotate by date",
    File.Exists(Path.Combine(tempRoot, "sysmon-archive-2026-01-01.jsonl")) &&
    File.Exists(Path.Combine(tempRoot, "sysmon-archive-2026-01-02.jsonl")));
var (days, total) = SysmonArchiveService.StatusSummary();
Check("status summary counts", days == 2 && total == 5, $"days={days} events={total}");

// watermark dedupe: same event again, and an older one — neither appended
// managed write buffers: assertions below read the day files directly,
// so drain the archive's buffers once the write phase is done
AutoCommand.Engines.Core.BufferedAppender.FlushAll();
Check("duplicate append is dropped", !SysmonArchiveService.Append(e5));
Check("older-than-watermark append is dropped", !SysmonArchiveService.Append(e1));
var (_, totalAfterDupes) = SysmonArchiveService.StatusSummary();
Check("dedupe kept the count at 5", totalAfterDupes == 5, totalAfterDupes.ToString());

// exact-tie boundary: same ts as watermark, higher record id — appended
var e6 = new ArchiveEvent { TsUtc = day2.AddMinutes(5), Eid = 3, RecordId = 106, Data = new() { ["ProcessId"] = "333", ["DestinationIp"] = "1.1.1.1" } };
Check("same-ts-higher-rid append is accepted", SysmonArchiveService.Append(e6));

// search: newest-first, filters, cap
var all = SysmonArchiveService.Search(null, null, null, 100);
Check("search returns everything newest-first",
    all.Count == 6 && all[0].RecordId == 106 && all[^1].RecordId == 101,
    $"{all.Count} rows, first rid={all.FirstOrDefault()?.RecordId}");
Check("search eid filter", SysmonArchiveService.Search(3, null, null, 100).Count == 2);
Check("search contains matches data values",
    SysmonArchiveService.Search(null, "beta", null, 100).Count == 1 &&
    SysmonArchiveService.Search(null, "beta", null, 100)[0].Data["ProcessId"] == "222");
Check("search since cutoff",
    SysmonArchiveService.Search(null, null, day2, 100).Count == 3);
Check("search max cap", SysmonArchiveService.Search(null, null, null, 2).Count == 2);

// create-event lookup by pid — streamed, newest first, cap honored
var created111 = SysmonArchiveService.SearchCreateEvents(111, 5);
Check("SearchCreateEvents filters pid 111",
    created111.Count == 2 && created111.All(e => e.Data["ProcessId"] == "111"),
    $"count={created111.Count}");
Check("SearchCreateEvents newest first", created111[0].RecordId == 104);

// corrupt-line tolerance: garbage lines must not break the reader
File.AppendAllText(Path.Combine(tempRoot, "sysmon-archive-2026-01-02.jsonl"),
    "{not json at all" + Environment.NewLine);
Check("corrupt lines are skipped",
    SysmonArchiveService.Search(null, null, null, 100).Count == 6);

// prune: everything here predates today → all day files go
int pruned = SysmonArchiveService.Prune(30);
var (daysAfter, eventsAfter) = SysmonArchiveService.StatusSummary();
Check("prune removes expired day files", pruned == 2 && daysAfter == 0 && eventsAfter == 0,
    $"pruned={pruned} days={daysAfter} events={eventsAfter}");
Check("state.json survives prune as the only file",
    Directory.GetFiles(tempRoot).Length == 1 &&
    Directory.GetFiles(tempRoot)[0].EndsWith("state.json"));

try { Directory.Delete(tempRoot, true); } catch { }

// ─────────────────────────────────────────────────────────────────────
// 4. DnsResolutionService — the resolve-state surface (this process's
//    instance has empty caches, so every state below is deterministic;
//    no network, the worker is never started)
// ─────────────────────────────────────────────────────────────────────
var dns = DnsResolutionService.Instance;
Check("local address state explains itself",
      dns.DescribeResolveState("192.168.1.5")?.Contains("local or non-routable") == true,
      dns.DescribeResolveState("192.168.1.5"));
Check("non-IP state is null", dns.DescribeResolveState("not-an-ip") == null);
Check("unresolved routable address reports queued-on-next-pass",
      dns.DescribeResolveState("203.0.113.7")?.Contains("not resolved yet") == true,
      dns.DescribeResolveState("203.0.113.7"));
Check("ResolveNow refuses addresses nothing can answer", !dns.ResolveNow("10.0.0.1"));
Check("ResolveNow queues an urgent lookup", dns.ResolveNow("203.0.113.7"));
Check("queued address reports resolving",
      dns.DescribeResolveState("203.0.113.7")?.StartsWith("resolving") == true,
      dns.DescribeResolveState("203.0.113.7"));
Check("RetryUnresolved re-queues the given address", dns.RetryUnresolved(new[] { "203.0.113.7" }) == 1);

// ─────────────────────────────────────────────────────────────────────
// 5. Idle reconciliation — candidate collection + batch pick (no
//    network; the worker is never started, so queued items just sit)
// ─────────────────────────────────────────────────────────────────────
dns.SeedFromSysmon("203.0.113.9", "203.0.113.9");   // raw-IP placeholder → candidate
dns.SeedFromSysmon("198.51.100.4", "example.test"); // real name → NOT a candidate
Check("UnresolvedIps lists placeholders only",
      dns.UnresolvedIps.Contains("203.0.113.9") && !dns.UnresolvedIps.Contains("198.51.100.4"),
      string.Join(",", dns.UnresolvedIps));
Check("idle pass refuses while traffic is busy",
      dns.RunIdlePassForTest(() => TimeSpan.FromSeconds(10)) == 0);
int took = dns.RunIdlePassForTest(() => TimeSpan.FromMinutes(10));
Check("idle pass queues the candidate when idle", took == 1, took.ToString());
Check("queued-by-idle address reports resolving",
      dns.DescribeResolveState("203.0.113.9")?.StartsWith("resolving") == true,
      dns.DescribeResolveState("203.0.113.9"));
dns.SeedFromSysmon("203.0.113.8", "203.0.113.8");   // second placeholder
Check("idle batch honors the batch size (all candidates fit)",
      dns.RunIdlePassForTest(() => TimeSpan.FromMinutes(10)) == 1);

// ─────────────────────────────────────────────────────────────────────
// 6. FlowPeek — the Traffic Peek engine, offline: synthetic IPv4/TCP
//    packets fed straight into the shared capture's self-test seam. The
//    peered IP is a TEST-NET address (never routed) so real machine
//    traffic can never pollute the assertions; the keylog lives in a
//    temp DataRoot, so the decryptor's "no keys" honesty is deterministic.
// ─────────────────────────────────────────────────────────────────────
string peerRoot = Path.Combine(Path.GetTempPath(), "netwatch-peer-" + Guid.NewGuid().ToString("N")[..8]);
AutoCommand.Engines.Watch.WatchConfig.Configure(new AutoCommand.Engines.Core.AppIdentity(
    "NetWatchSelfTest", peerRoot, "TEST-IP ", "TEST-APP ",
    Microsoft.FSharp.Collections.ListModule.OfSeq(Array.Empty<string>()), 47821, "netwatch-selftest"));

const string PeerIp = "198.51.100.10"; // TEST-NET-2 — never routed, never real traffic
var peek = AutoCommand.Engines.Watch.FlowPeekService.ForIp(PeerIp);
var collected = new List<AutoCommand.Engines.Watch.PeekEntry>();
var peekNotes = new List<string>();
object entryGate = new object();
peek.OnEntry += e => { lock (entryGate) collected.Add(e); };
peek.OnError += m => { lock (entryGate) peekNotes.Add(m); };

peek.Start();
Check("peek start arms the shared capture", AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IsRunning);
Check("peek shortens the idle sweep to 10 s",
      AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IdleTimeout == TimeSpan.FromSeconds(10));
Check("peek registers as the active peer", AutoCommand.Engines.Watch.FlowPeekService.ActiveCount == 1);

// Flow A — TLS ClientHello to the peered IP:443, closed by RST (the
// reassembler finalizes a reset flow immediately — no sweep wait).
byte[] hello = BuildClientHello("fe3cr.delivery.mp.microsoft.com");
var cap = AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared;
Feed(cap, Tcp4("192.0.2.10", 51234, PeerIp, 443, 1, 0x18, hello));
Feed(cap, Tcp4("192.0.2.10", 51234, PeerIp, 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));

// Flow B — plain HTTP to the same IP (the peek keeps non-TLS flows on
// purpose; the honest verdict is the point).
byte[] req = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: fe3cr.delivery.mp.microsoft.com\r\n\r\n");
Feed(cap, Tcp4("192.0.2.10", 51236, PeerIp, 80, 1, 0x18, req));
Feed(cap, Tcp4("192.0.2.10", 51236, PeerIp, 80, 1 + (uint)req.Length, 0x04, Array.Empty<byte>()));

// Flow C — a different remote IP entirely: must never appear.
byte[] noise = Encoding.ASCII.GetBytes("GET /elsewhere HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n");
Feed(cap, Tcp4("192.0.2.10", 51238, "203.0.113.7", 80, 1, 0x18, noise));
Feed(cap, Tcp4("192.0.2.10", 51238, "203.0.113.7", 80, 1 + (uint)noise.Length, 0x04, Array.Empty<byte>()));

Check("peered flows arrive and the foreign IP stays out", WaitForEntries(collected, entryGate, 2, 15000),
      $"collected={collected.Count} notes={string.Join(" | ", peekNotes.Take(2))}");
Check("exactly the two peered flows arrived", collected.Count == 2, collected.Count.ToString());

var tlsEntry = collected.FirstOrDefault(e => e.Status == "encrypted (no keys)");
Check("TLS flow reports honestly 'encrypted (no keys)'", tlsEntry != null,
      string.Join(", ", collected.Select(e => e.Status)));
Check("SNI extracted from the ClientHello without keys",
      tlsEntry != null && tlsEntry.Decrypt.Sni == "fe3cr.delivery.mp.microsoft.com",
      tlsEntry?.Decrypt.Sni ?? "(none)");
Check("no-keys status names the real reason (not instrumented)",
      tlsEntry != null && (tlsEntry.Decrypt.Status?.Contains("Not instrumented") ?? false),
      tlsEntry?.Decrypt.Status);
Check("client bytes preserved through reassembly",
      tlsEntry != null && tlsEntry.Flow.ClientBytes == hello.Length && tlsEntry.Decrypt.ClientAppBytes == 0,
      tlsEntry != null ? $"{tlsEntry.Flow.ClientBytes} wire / {tlsEntry.Decrypt.ClientAppBytes} app" : "");
Check("remote endpoint scoped to the peered IP",
      tlsEntry != null && tlsEntry.RemoteEndpoint == PeerIp + ":443",
      tlsEntry?.RemoteEndpoint);
Check("plain flow reported as 'not TLS'", collected.Any(e => e.Status == "not TLS"),
      string.Join(", ", collected.Select(e => e.Status)));

// Flow D — PID attribution: the seam the Sysmon EID 3 watcher drives,
// exercised directly (TagFlow is first-writer-wins).
Feed(cap, Tcp4("192.0.2.10", 51240, PeerIp, 443, 1, 0x18, hello));
Check("TagFlow tags the live flow",
      cap.TagFlow("192.0.2.10", 51240, PeerIp, 443, 4242, @"C:\Windows\System32\svchost.exe"));
Feed(cap, Tcp4("192.0.2.10", 51240, PeerIp, 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));
Check("tagged pid/image ride the peek entry", WaitForEntries(collected, entryGate, 3, 15000) &&
      collected[^1].ProcessDisplay.Contains("svchost.exe") && collected[^1].ProcessDisplay.Contains("4242"),
      collected[^1].ProcessDisplay);

// Service-activity probe: must never throw, and stays inside its budget —
// on CI the channels are absent (empty result); on a dev box it reads real events.
var probe = AutoCommand.Engines.Watch.ServiceLogProbe.QueryEvents(
    DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow);
Check("service event probe is bounded and quiet", probe.Count <= 60, probe.Count.ToString());

peek.Stop();
Check("peek stop releases the capture",
      !AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IsRunning &&
      AutoCommand.Engines.Watch.FlowPeekService.ActiveCount == 0);
Check("idle sweep restored to the 60 s default",
      AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IdleTimeout == TimeSpan.FromSeconds(60));

// A window close/reopen cycle must re-arm cleanly (one peek per IP, reused).
var peek2 = AutoCommand.Engines.Watch.FlowPeekService.ForIp(PeerIp);
peek2.Start();
bool reArmed = AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IsRunning;
peek2.Stop();
Check("close/reopen re-arms and re-releases the capture", reArmed &&
      !AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IsRunning);

// ─────────────────────────────────────────────────────────────────────
// 6b. Program + service scopes — the subject-scoped siblings: a pinned
//     program matches its tagged PID (with an image fallback for normal
//     images), a pinned svchost-hosted service survives restarts because
//     the match is the PID's hosted-services answer, and shared hosts
//     are never image-matched.
// ─────────────────────────────────────────────────────────────────────
var progPeek = AutoCommand.Engines.Watch.FlowPeekService.ForProgram(4242, @"C:\Program Files\MyApp\myapp.exe");
var progCollected = new List<AutoCommand.Engines.Watch.PeekEntry>();
progPeek.OnEntry += e => { lock (entryGate) progCollected.Add(e); };
progPeek.Start();

// PID match: a flow tagged 4242 belongs to the program scope
Feed(cap, Tcp4("192.0.2.10", 51242, "203.0.113.9", 443, 1, 0x18, hello));
cap.TagFlow("192.0.2.10", 51242, "203.0.113.9", 443, 4242, @"C:\Program Files\MyApp\myapp.exe");
Feed(cap, Tcp4("192.0.2.10", 51242, "203.0.113.9", 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));

// Different pid, same (non-shared) image — the restart-under-a-new-pid case
Feed(cap, Tcp4("192.0.2.10", 51244, "203.0.113.9", 443, 1, 0x18, hello));
cap.TagFlow("192.0.2.10", 51244, "203.0.113.9", 443, 5001, @"C:\Program Files\MyApp\myapp.exe");
Feed(cap, Tcp4("192.0.2.10", 51244, "203.0.113.9", 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));

Check("program scope: pid match + image fallback arrive", WaitForEntries(progCollected, entryGate, 2, 15000),
      progCollected.Count.ToString());

// Shared-host guard: a program scope on svchost must match ONLY its exact
// pid — a sibling svchost tenant's flow (pid 8888) is never image-matched.
var svchostPeek = AutoCommand.Engines.Watch.FlowPeekService.ForProgram(777, @"C:\Windows\System32\svchost.exe");
var sharedCollected = new List<AutoCommand.Engines.Watch.PeekEntry>();
svchostPeek.OnEntry += e => { lock (entryGate) sharedCollected.Add(e); };
svchostPeek.Start();
Feed(cap, Tcp4("192.0.2.10", 51246, "203.0.113.9", 443, 1, 0x18, hello));
cap.TagFlow("192.0.2.10", 51246, "203.0.113.9", 443, 8888, @"C:\Windows\System32\svchost.exe");
Feed(cap, Tcp4("192.0.2.10", 51246, "203.0.113.9", 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));
Check("shared-host guard: svchost scope matches only its exact pid",
      WaitForEntries(progCollected, entryGate, 2, 1000) && sharedCollected.Count == 0,
      sharedCollected.Count.ToString());

// Service scope: "DiagTrack" pinned — attribution via the PID's hosted
// services (overridden here so the test never touches real SCM state).
AutoCommand.Engines.Watch.ServiceDirectory.Override(5999, new[] { "DiagTrack" });
AutoCommand.Engines.Watch.ServiceDirectory.Override(6000, new[] { "DoSvc" });
var diagPeek = AutoCommand.Engines.Watch.FlowPeekService.ForService("DiagTrack");
var diagCollected = new List<AutoCommand.Engines.Watch.PeekEntry>();
diagPeek.OnEntry += e => { lock (entryGate) diagCollected.Add(e); };
diagPeek.Start();

Feed(cap, Tcp4("192.0.2.10", 51248, "203.0.113.9", 443, 1, 0x18, hello));
cap.TagFlow("192.0.2.10", 51248, "203.0.113.9", 443, 5999, @"C:\Windows\System32\svchost.exe");
Feed(cap, Tcp4("192.0.2.10", 51248, "203.0.113.9", 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));

// A sibling tenant hosting a different service must stay out.
Feed(cap, Tcp4("192.0.2.10", 51250, "203.0.113.9", 443, 1, 0x18, hello));
cap.TagFlow("192.0.2.10", 51250, "203.0.113.9", 443, 6000, @"C:\Windows\System32\svchost.exe");
Feed(cap, Tcp4("192.0.2.10", 51250, "203.0.113.9", 443, 1 + (uint)hello.Length, 0x04, Array.Empty<byte>()));

Check("service scope: pinned service follows its instance, sibling stays out",
      WaitForEntries(diagCollected, entryGate, 1, 15000) && diagCollected.Count == 1,
      diagCollected.Count.ToString());

progPeek.Stop();
svchostPeek.Stop();
diagPeek.Stop();
Check("scoped peeks all release the capture",
      !AutoCommand.Engines.Watch.TcpStreamCaptureService.Shared.IsRunning &&
      AutoCommand.Engines.Watch.FlowPeekService.ActiveCount == 0,
      AutoCommand.Engines.Watch.FlowPeekService.ActiveCount.ToString());

try { Directory.Delete(peerRoot, true); } catch { }

// ── synthetic packet builders for section 6 ──────────────────────────

/// <summary>Feeds one synthetic packet through the capture's self-test seam.</summary>
static void Feed(AutoCommand.Engines.Watch.TcpStreamCaptureService capture, byte[] packet)
    => capture.ProcessIpPacket(packet, packet.Length);

static byte[] Tcp4(string srcIp, int srcPort, string dstIp, int dstPort, uint seq, byte flags, byte[] payload)
{
    int total = 20 + 20 + payload.Length;
    var buf = new byte[total];
    buf[0] = 0x45; // IPv4, IHL 20
    buf[2] = (byte)(total >> 8);
    buf[3] = (byte)(total & 0xFF);
    buf[8] = 64;   // TTL (unchecked by the reassembler)
    buf[9] = 6;    // TCP
    IPAddress.Parse(srcIp).GetAddressBytes().CopyTo(buf, 12);
    IPAddress.Parse(dstIp).GetAddressBytes().CopyTo(buf, 16);
    int t = 20;
    buf[t] = (byte)(srcPort >> 8);
    buf[t + 1] = (byte)(srcPort & 0xFF);
    buf[t + 2] = (byte)(dstPort >> 8);
    buf[t + 3] = (byte)(dstPort & 0xFF);
    buf[t + 4] = (byte)(seq >> 24);
    buf[t + 5] = (byte)((seq >> 16) & 0xFF);
    buf[t + 6] = (byte)((seq >> 8) & 0xFF);
    buf[t + 7] = (byte)(seq & 0xFF);
    buf[t + 12] = 0x50; // data offset 5 (20-byte header)
    buf[t + 13] = flags;
    payload.CopyTo(buf, t + 20);
    return buf;
}

/// <summary>A minimal RFC-8446-style ClientHello with one SNI entry and one
/// offered TLS 1.3 suite — exactly what the decryptor's metadata path reads.</summary>
static byte[] BuildClientHello(string sni)
{
    byte[] name = Encoding.ASCII.GetBytes(sni);
    int listLen = 3 + name.Length;          // type(1) + len(2) + name
    int extDataLen = 2 + listLen;           // server_name_list len(2) + list
    int extLen = 4 + extDataLen;            // type(2) + ext len(2) + data
    int bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen;
    int hsLen = 4 + bodyLen;

    var b = new List<byte>
    {
        0x16, 0x03, 0x01, (byte)(hsLen >> 8), (byte)(hsLen & 0xFF),   // handshake record
        0x01, 0x00, (byte)(bodyLen >> 8), (byte)(bodyLen & 0xFF),     // ClientHello
        0x03, 0x03,                                                   // client_version TLS 1.2
    };
    var random = new byte[32];
    Random.Shared.NextBytes(random);
    b.AddRange(random);                                               // client random
    b.Add(0x00);                                                      // session_id: empty
    b.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 });                // one suite: TLS_AES_128_GCM_SHA256
    b.AddRange(new byte[] { 0x01, 0x00 });                            // compression: null
    b.Add((byte)(extLen >> 8));
    b.Add((byte)(extLen & 0xFF));                                     // extensions length
    b.AddRange(new byte[] { 0x00, 0x00, (byte)(extDataLen >> 8), (byte)(extDataLen & 0xFF) }); // server_name
    b.Add((byte)(listLen >> 8));
    b.Add((byte)(listLen & 0xFF));
    b.Add(0x00);                                                      // host_name
    b.Add((byte)(name.Length >> 8));
    b.Add((byte)(name.Length & 0xFF));
    b.AddRange(name);
    return b.ToArray();
}

static bool WaitForEntries(List<AutoCommand.Engines.Watch.PeekEntry> collected, object gate, int count, int timeoutMs)
{
    var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
    while (DateTime.UtcNow < deadline)
    {
        lock (gate)
            if (collected.Count >= count) return true;
        Thread.Sleep(50);
    }
    lock (gate) return collected.Count >= count;
}

Console.WriteLine(failures == 0 ? "\nALL CHECKS PASSED" : $"\n{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;
