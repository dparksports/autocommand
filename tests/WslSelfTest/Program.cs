using AutoCommand.Contain.Core;
using AutoCommand.Services;

// WslSelfTest — the WSL traffic-visibility engines, offline:
//   1. the family matcher (wslservice/vmmem/… — the rows users panic about)
//   2. the wsl.exe list decoders (UTF-16 artifacts, notice/header lines)
//   3. the .wslconfig networking-mode parser
//   4. the ss -tnp guest-socket parser (columns, users:((…)) shapes)
//   5. the endpoint splitter and the host→guest join
//   6. every verdict branch of the staged WSL diagnosis (synthetic inputs)
//   7. the guest-probe exit-code classifier (0 / 124 / did-not-run)
// Nothing here spawns wsl.exe, touches WMI, or opens a socket.

int failed = 0;
void Check(string name, bool pass, string detail = null)
{
    Console.WriteLine((pass ? "PASS  " : "FAIL  ") + name +
                      (pass || string.IsNullOrEmpty(detail) ? "" : $" — {detail}"));
    if (!pass) failed++;
}

// ── 1. family matcher ───────────────────────────────────────────────────

Check("1a wslservice.exe is family", WslIdentityService.IsWslFamilyProcess("wslservice.exe"));
Check("1b vmmem is family (old image name)", WslIdentityService.IsWslFamilyProcess("vmmem"));
Check("1c vmmemWSL is family (new image name)", WslIdentityService.IsWslFamilyProcess("vmmemWSL"));
Check("1d wslrelay + wslhost + wslg + wsl are family",
      WslIdentityService.IsWslFamilyProcess("wslrelay.exe") &&
      WslIdentityService.IsWslFamilyProcess("wslhost") &&
      WslIdentityService.IsWslFamilyProcess("wslg.exe") &&
      WslIdentityService.IsWslFamilyProcess("wsl"));
Check("1e wslservice without extension is family", WslIdentityService.IsWslFamilyProcess("wslservice"));
Check("1f near-miss name is NOT family", !WslIdentityService.IsWslFamilyProcess("wslservicehelper.exe"));
Check("1g near-miss and everyday processes are NOT family",
      !WslIdentityService.IsWslFamilyProcess("wslserviceui2.exe") &&
      !WslIdentityService.IsWslFamilyProcess("chrome.exe") &&
      !WslIdentityService.IsWslFamilyProcess("svchost.exe"));
Check("1h null/empty is NOT family",
      !WslIdentityService.IsWslFamilyProcess(null) && !WslIdentityService.IsWslFamilyProcess(""));

// ── 2. wsl.exe list decoders ────────────────────────────────────────────

var running = WslIdentityService.ParseRunningDistros("Ubuntu-22.04\ndocker-desktop\n");
Check("2a running list parses one distro per line",
      running.Length == 2 && running[0] == "Ubuntu-22.04" && running[1] == "docker-desktop",
      "got: " + string.Join(",", running));

var withNotice = WslIdentityService.ParseRunningDistros(
    "Windows Subsystem for Linux has no running distributions.\r\n");
Check("2b the official no-running notice parses to none", withNotice.Length == 0);

Check("2c empty/null lists parse to none",
      WslIdentityService.ParseRunningDistros("").Length == 0 &&
      WslIdentityService.ParseRunningDistros(null).Length == 0);

Check("2d stray verbose header is skipped",
      WslIdentityService.ParseRunningDistros("NAME STATE VERSION\nUbuntu-22.04 Running 2").Length == 1);

Check("2e UTF-16 decode artifacts (BOM + nulls) are stripped",
      WslIdentityService.DecodeWslOutput("\uFEFFU\0b\0u\0n\0t\0u\0\r\n\0") == "Ubuntu\n");

var verbose = WslIdentityService.ParseDistroList(
    "  NAME            STATE           VERSION\n  Ubuntu-22.04    Running         2\n  Debian          Stopped         2\n");
Check("2f verbose list parses name/state/version",
      verbose.Length == 2 && verbose[0].Name == "Ubuntu-22.04" && verbose[0].State == "Running" &&
      verbose[0].Version == "2" && verbose[1].Name == "Debian" && verbose[1].State == "Stopped",
      "got: " + string.Join(" | ", verbose.Select(v => $"{v.Name}/{v.State}/{v.Version}")));

// ── 3. .wslconfig mode parser ───────────────────────────────────────────

Check("3a absent body → nat default", WslIdentityService.ParseNetworkingMode(null) == "nat");
Check("3b empty body → nat default", WslIdentityService.ParseNetworkingMode("") == "nat");
Check("3c mirrored honored",
      WslIdentityService.ParseNetworkingMode("[wsl2]\nnetworkingMode=mirrored\n") == "mirrored");
Check("3d comments and sections tolerated",
      WslIdentityService.ParseNetworkingMode("# my config\n; note\n[wsl2]\nnetworkingMode = Mirrored\nmemory=8GB\n") == "mirrored");
Check("3e other values pass through lowercased",
      WslIdentityService.ParseNetworkingMode("networkingMode=NAT") == "nat");
Check("3f missing key → nat default",
      WslIdentityService.ParseNetworkingMode("[wsl2]\nmemory=8GB\n") == "nat");

// ── 4. ss -tnp guest-socket parser ──────────────────────────────────────

const string ssFixture =
    "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n" +
    "tcp   ESTAB  0      0      172.20.64.9:45232  1.1.1.1:80        users:((\"node\",pid=4312,fd=31))\n" +
    "tcp   ESTAB  0      0      172.20.64.9:22     52.1.2.3:443\n" +
    "tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:((\"sshd\",pid=99,fd=3))\n" +
    "tcp   ESTAB  0      0      172.20.64.9:45300  104.16.1.1:443    users:((\"curl\",pid=770,fd=12),(\"curl-helper\",pid=771,fd=4))\n";

// the State-first shape plain `ss -tnp` emits on most distros
const string ssFixtureStateFirst =
    "State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process\n" +
    "ESTAB   0       0       172.20.64.9:45232    1.1.1.1:80        users:((\"node\",pid=4312,fd=31))\n" +
    "ESTAB   0       0       172.20.64.9:22       52.1.2.3:443\n" +
    "LISTEN  0       128     0.0.0.0:22           0.0.0.0:*\n";

var sockets = WslGuestProbe.ParseSsOutput(ssFixture);
Check("4a Netid-first shape: header/LISTEN skipped, ESTAB kept",
      sockets.Length == 3, $"got {sockets.Length}");

var socketsStateFirst = WslGuestProbe.ParseSsOutput(ssFixtureStateFirst);
Check("4a2 State-first shape parses identically",
      socketsStateFirst.Length == 2 && socketsStateFirst[0].Peer == "1.1.1.1:80" &&
      socketsStateFirst[0].Process == "node",
      $"got {socketsStateFirst.Length}");
Check("4b process name + pid extracted",
      sockets[0].Process == "node" && sockets[0].Pid == 4312,
      $"got {sockets[0].Process}/{sockets[0].Pid}");
Check("4c no-process socket parses with null identity",
      sockets[1].Process == null && sockets[1].Pid == null);
Check("4d multi-entry users:(…) takes the first process",
      sockets[2].Process == "curl" && sockets[2].Pid == 770,
      $"got {sockets[2].Process}/{sockets[2].Pid}");
Check("4e peer endpoints preserved verbatim",
      sockets[0].Peer == "1.1.1.1:80" && sockets[2].Peer == "104.16.1.1:443");

var bare = WslGuestProbe.ParseSsProcess("users:((\"nginx\",pid=99,fd=8))");
Check("4f users token parser (single entry)", bare.Process == "nginx" && bare.Pid == 99);
var junk = WslGuestProbe.ParseSsProcess("users:((garbage");
Check("4g malformed users token → (null, null), never throws", junk.Process == null && junk.Pid == null);

// ── 5. endpoint split + the join ────────────────────────────────────────

Check("5a v4 endpoint splits", WslGuestProbe.SplitEndpoint("1.1.1.1:80") is { Ip: "1.1.1.1", Port: "80" });
Check("5b v6 endpoint splits inside brackets",
      WslGuestProbe.SplitEndpoint("[2606:4700:4700::1111]:443") is { Ip: "2606:4700:4700::1111", Port: "443" });
Check("5c portless endpoint survives", WslGuestProbe.SplitEndpoint("0.0.0.0:*").Ip == "0.0.0.0");

var snapshot = new WslGuestProbe.GuestSnapshot(true, new[]
{
    new WslGuestProbe.DistroSnapshot("Ubuntu-22.04", true, new[]
    {
        new WslGuestProbe.GuestSocket("ESTAB", "172.20.64.9:45232", "1.1.1.1:80", "node", 4312),
        new WslGuestProbe.GuestSocket("ESTAB", "172.20.64.9:45300", "104.16.1.1:443", "curl", 770),
    }, null),
    new WslGuestProbe.DistroSnapshot("docker-desktop", true, new[]
    {
        new WslGuestProbe.GuestSocket("ESTAB", "172.20.64.9:46000", "1.1.1.1:80", "docker-proxy", 120),
    }, null),
}, DateTime.UtcNow);

var joined = WslGuestProbe.MatchByRemoteIp(snapshot, "1.1.1.1").ToList();
Check("5d the join matches every distro's socket for one remote",
      joined.Count == 2 && joined.Any(j => j.Socket.Process == "node") &&
      joined.Any(j => j.Socket.Process == "docker-proxy"),
      $"got {joined.Count}");
Check("5e a remote with no guest sockets matches none",
      WslGuestProbe.MatchByRemoteIp(snapshot, "8.8.8.8").Count() == 0);
Check("5f the join is a no-op when the VM is not running",
      WslGuestProbe.MatchByRemoteIp(WslGuestProbe.GuestSnapshot.NotRunning, "1.1.1.1").Count() == 0);

// ── 6. the staged diagnosis — every verdict branch ──────────────────────

WslDiagnosisService.WslDiagnosisInputs Inputs(
    bool? host = true, bool? guest = null, string guestErr = null,
    bool? gw = null, string gwErr = null,
    List<string> disabled = null, string hvOutbound = "NotConfigured", string hvErr = null,
    bool installed = true, bool vm = true) => new(
    installed, vm, vm ? new[] { "Ubuntu-22.04" } : Array.Empty<string>(), vm ? "nat" : null,
    host, host == false ? "refused" : null,
    guest, guestErr, gw, gwErr,
    1149, disabled == null ? 1149 : 1149 - disabled.Count, disabled ?? new List<string>(),
    hvOutbound, hvOutbound != null, hvErr);

var d = WslDiagnosisService.Diagnose(Inputs(installed: false));
Check("6a not installed → honest nothing-to-diagnose",
      d.Healthy && d.Verdict.Contains("isn't installed"));

d = WslDiagnosisService.Diagnose(Inputs(vm: false));
Check("6b VM not running → start-one-and-rerun, never a launch",
      d.Healthy && d.Verdict.Contains("No WSL distro is running"));

d = WslDiagnosisService.Diagnose(Inputs(host: false));
Check("6c host down → machine-wide verdict, not WSL-specific",
      !d.Healthy && d.Verdict.Contains("machine-wide"));

d = WslDiagnosisService.Diagnose(Inputs(guest: true));
Check("6d healthy guest → healthy verdict, blame stays inside the distro when it persists",
      d.Healthy && d.Verdict.Contains("healthy right now") && d.Verdict.Contains("resolv.conf"));

d = WslDiagnosisService.Diagnose(Inputs(guest: null, guestErr: "exit 127: bash not found"));
Check("6e skipped probe → no network verdict is claimed",
      !d.Healthy && d.Verdict.Contains("could not run") && d.Verdict.Contains("bash"));

d = WslDiagnosisService.Diagnose(Inputs(guest: false, disabled: new List<string>
{
    "[Outbound] vmswitch-allow (group=Hyper-V)", "[Inbound] wsl-mirror (group=WSL)",
}));
Check("6f disabled family rules → in-the-rule-model verdict naming the count",
      !d.Healthy && d.Verdict.Contains("2 WSL/Hyper-V-family firewall rules are DISABLED") &&
      d.Evidence.Any(e => e.Contains("OFF · [Outbound] vmswitch-allow")),
      "verdict: " + d.Verdict);

d = WslDiagnosisService.Diagnose(Inputs(guest: false, hvOutbound: "Block"));
Check("6g Hyper-V layer blocking → verdict names WSL's own layer",
      !d.Healthy && d.Verdict.Contains("Hyper-V firewall") && d.Verdict.Contains("Block"));

d = WslDiagnosisService.Diagnose(Inputs(guest: false, gw: false));
Check("6h gateway unreachable → vSwitch/HNS verdict",
      !d.Healthy && d.Verdict.Contains("NAT gateway") &&
      d.NextStep != null && d.NextStep.Contains("wsl --shutdown"),
      "verdict: " + d.Verdict + " | next: " + d.NextStep);

var below = WslDiagnosisService.Diagnose(Inputs(guest: false, gw: true));
Check("6i everything says allow yet guest drops → below-the-rule-model verdict",
      !below.Healthy && below.Verdict.Contains("BELOW the rule model") &&
      below.NextStep.Contains("wsl-egress-elevated-diag") && below.Verdict.Contains("not an AutoCommand block"),
      "verdict: " + below.Verdict);

var inconclusiveGw = WslDiagnosisService.Diagnose(Inputs(guest: false, gw: null,
    gwErr: "timeout to 172.18.112.1:53 — expected when nothing listens"));
Check("6j inconclusive gateway leg still reaches the below-rule-model verdict",
      !inconclusiveGw.Healthy && inconclusiveGw.Verdict.Contains("BELOW the rule model") &&
      inconclusiveGw.Evidence.Any(e => e.Contains("expected when nothing listens")),
      "verdict: " + inconclusiveGw.Verdict + " | evidence: " + string.Join(" // ", inconclusiveGw.Evidence));

// ── 7. the guest-probe exit-code classifier ─────────────────────────────

Check("7a exit 0 = connected", WslDiagnosisService.ClassifyGuestProbe(0, "") is { Ok: true });
Check("7b exit 124 = dropped",
      WslDiagnosisService.ClassifyGuestProbe(124, "") is { Ok: false, Error: not null });
var skipped = WslDiagnosisService.ClassifyGuestProbe(127, "/bin/bash: not found");
Check("7c did-not-run exits classify as inconclusive (never a verdict)",
      skipped.Ok == null && skipped.Error.Contains("127"));
Check("7d 0-byte probe output with odd exit stays inconclusive",
      WslDiagnosisService.ClassifyGuestProbe(1, "").Ok == null);

Console.WriteLine(failed == 0
    ? "ALL WSL SELF-TESTS PASSED"
    : $"{failed} WSL SELF-TEST(S) FAILED");
return failed == 0 ? 0 : 1;
