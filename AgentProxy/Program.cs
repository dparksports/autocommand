// AutoCommand.AgentProxy — the process an MCP client spawns for the
// "autocommand" server entry. Deliberately tiny and privilege-free:
//
//   • reads %LOCALAPPDATA%\AutoCommand\agent\session.json — written only
//     while the user's AI session is active in the running (elevated) app
//   • forwards each stdin JSON-RPC line to 127.0.0.1:<port> with the
//     session bearer token, writes the response to stdout
//   • with no session active, completes the MCP handshake anyway and
//     answers every tool call with setup guidance, so the client connects
//     cleanly at any time and self-describes
//
// The session token never appears in any config file — the MCP
// registration is just "spawn this exe".
//
// Startup note: this exe is published self-contained (single file, runtime
// bundled) precisely so a client that exports its own DOTNET_ROOT — desktop
// MCP clients bundling an older .NET do — cannot break the spawn. A
// framework-dependent build dies in the apphost before any code here runs.

using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

// offline tools/list surface: minimal descriptors (real schemas arrive from
// the app once a session is active — that list is authoritative)
const string OfflineToolsJson = """
[
  { "name": "get_monitor_rows", "description": "Live established-connection snapshot with process attribution and svchost identity (needs an active AutoCommand AI session)." },
  { "name": "get_svchost_identity", "description": "SCM services + -k/-s identity of one svchost instance (needs an active session)." },
  { "name": "run_pid_inquiry", "description": "Full PID provenance report (needs an active session)." },
  { "name": "tail_sysmon", "description": "Recent Sysmon/Operational events (needs an active session)." },
  { "name": "list_watches", "description": "Spawn watch rules with match definitions and 24h hit counts (needs an active session)." },
  { "name": "tail_watches", "description": "Recent spawn-watch hits: rule, image, PID, parent image, parent service, command line (needs an active session)." },
  { "name": "classify_ip", "description": "Destination-range classification, block-warning text and blocked-list status (needs an active session)." },
  { "name": "lookup_ip", "description": "Resolve one IP: hostname, range classification, org/geo with its cache state (ip-api throttled + RDAP fallback), blocked-list status; force=true re-asks urgently (needs an active session)." },
  { "name": "list_blocks", "description": "Inventory of every AutoCommand firewall block with recent hit counts (needs an active session)." },
  { "name": "open_gate", "description": "Temporarily stop blocking ONE specific blocked IP/process for 1/10/30/60 minutes (user-confirmed; auto-restores; dry_run previews) (needs an active session)." },
  { "name": "close_gate", "description": "Close an open block gate early - blocking returns ON now (needs an active session)." },
  { "name": "list_gates", "description": "Open block gates with remaining minutes, requester and reason (needs an active session)." },
  { "name": "list_recent_block_hits", "description": "Live process-attributed feed of connects hitting firewall blocks — the 'who is being blocked' view (needs an active session)." },
  { "name": "verify_block_containment", "description": "Prove blocked processes are silent, not just trying: block attempts joined against live sockets and archived transmissions since block creation (needs an active session)." },
  { "name": "audit_block_duplicates", "description": "Read-only duplicate audit of the block rules: per target, rules that exactly duplicate another (blocking unchanged, but clutter and skewed counts); the Rules tab's 'Clean duplicates' retires them (needs an active session)." },
  { "name": "check_host", "description": "'Why can't I reach this site?' — resolve, check blocked-list membership per address, plain-English verdict (needs an active session)." },
  { "name": "investigate_process", "description": "The whole 'why is this transmitting?' playbook for one PID in a single call — provenance, traffic profile, block-hit check, plain-English verdict (needs an active session)." },
  { "name": "diagnose_site", "description": "The Site Doctor pipeline for one hostname: fingerprint, dependency-block pass, live probes, verdict (needs an active session)." },
  { "name": "get_shieldsup_status", "description": "The Shields Up status board: doors (SSTP, Wi-Fi Direct, kernel debug, VPN services, LLMNR/NetBIOS/mDNS, hotpatch monitoring), hardening switches, hosts audit, per-vendor telemetry opt-out state (needs an active session)." },
  { "name": "get_startup_status", "description": "The Startup & Tasks surface: logon items (Run keys + Startup folders) and scheduled tasks — third-party listed, Windows inbox counted (needs an active session)." },
  { "name": "close_shieldsup_door", "description": "Close ONE door Windows leaves open - sstp, hostednetwork, vpnservices, kdnet, wifidirect, llmnr, netbios, mdns or hotpatch (user-confirmed, reversible; no enable path over the bridge) (needs an active session)." },
  { "name": "opt_out_telemetry", "description": "Flip one vendor's own official telemetry opt-out switch, or revert=true to restore the saved previous value (user-confirmed) (needs an active session)." },
  { "name": "apply_shieldsup_preset", "description": "Apply a named firewall preset (strict_public/home_trusted/gaming_media/office/shield_up) with the baseline re-captured atomically (user-confirmed) (needs an active session)." },
  { "name": "get_wsl_status", "description": "WSL network state: installed, VM running, distros, NAT/mirrored mode, and - when the VM is already up - the Linux-side socket table joined to host WSL-family connections; never starts the VM (needs an active session)." },
  { "name": "diagnose_wsl", "description": "The staged 'Why is WSL offline?' check: host vs guest probes, rule-model scan, Hyper-V layer, one plain-English verdict; read-only, never starts the VM (needs an active session)." }
]
""";

// ── MCP protocol surface ────────────────────────────────────────────────
// Protocol versions this proxy AND the app's bridge actually implement:
// initialize / notifications/*, ping, tools/list, tools/call (resources/*
// and prompts/* are honestly refused with -32601 in both halves). Echo the
// client's version when it is one of these; otherwise answer with the
// newest supported one. Blindy echoing whatever arrived used to make us
// claim protocols (e.g. "1999-01-01") we never spoke.
string[] SupportedProtocols = { "2024-11-05", "2025-03-26", "2025-06-18" };
string Negotiate(string requested) =>
    !string.IsNullOrEmpty(requested) && Array.IndexOf(SupportedProtocols, requested) >= 0
        ? requested
        : SupportedProtocols[^1];

// same identity online and offline, so the client's UI does not relabel the
// server when a session flips: version comes from this exe's file version,
// which release.ps1 keeps in lockstep with the app's
string ServerVersion()
{
    try { return FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "?"; }
    catch { return "?"; }
}

// ── activity trail ──────────────────────────────────────────────────────
// Proxy lifetimes belong in the same audit trail as sessions and tool
// calls. Never to stdout — stdout is JSON-RPC and nothing else.
// AC_AGENT_DIR overrides the agent directory for offline self-tests.
string AgentDir = Environment.GetEnvironmentVariable("AC_AGENT_DIR") is string d && d.Length > 0
    ? d
    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                   "AutoCommand", "agent");
string ClientName = ""; // from initialize clientInfo, when the client sends one
void LogProxy(string what, string detail)
{
    try
    {
        Directory.CreateDirectory(AgentDir);
        var line = new JsonObject
        {
            ["t"] = DateTime.Now.ToString("o"),
            ["kind"] = "proxy",
            ["what"] = what,
            ["client"] = ClientName,
        };
        if (!string.IsNullOrEmpty(detail)) line["detail"] = detail;
        File.AppendAllText(Path.Combine(AgentDir, "activity.jsonl"), line.ToJsonString() + "\n");
    }
    catch { /* best-effort audit trail */ }
}

var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
// MCP-over-stdio is UTF-8 by spec; without pinning, an attached console
// decodes stdin with the OEM code page and non-ASCII tool arguments (paths,
// hostnames, reason strings) get mangled before they are forwarded.
try { Console.InputEncoding = Encoding.UTF8; } catch { /* detached stdin keeps default */ }
var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

(int Port, string Token, long Pid, string Exe)? ReadSession()
{
    try
    {
        string path = Path.Combine(AgentDir, "session.json");
        var o = JsonNode.Parse(File.ReadAllText(path)) as JsonObject;
        return (o["port"].GetValue<int>(), o["token"].GetValue<string>(),
                (long?)o["pid"] ?? 0, o["exe"]?.GetValue<string>() ?? "");
    }
    catch { return null; }
}

async Task<string> ForwardAsync(int port, string token, string body, JsonNode id)
{
    try
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{port}/");
        req.Content = new StringContent(body, Encoding.UTF8, "application/json");
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        req.Headers.Accept.ParseAdd("application/json");
        req.Headers.Accept.ParseAdd("text/event-stream");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(110));
        using var resp = await http.SendAsync(req, cts.Token);
        if (resp.StatusCode == System.Net.HttpStatusCode.Accepted) return null; // notification accepted
        return await resp.Content.ReadAsStringAsync();
    }
    catch (Exception ex)
    {
        // -32603 internal error: the session disappearing is a transport
        // failure on our side, not an MCP lifecycle state — -32002 used to
        // tell well-behaved clients we were never initialized, which is a
        // lie (they DID initialize; the app just went away). The error must
        // echo the request id — a null id here made strict clients drop
        // the response entirely.
        return Error(id, -32603,
            "The AutoCommand AI session ended (app closed or session stopped). " +
            "Start AutoCommand → Settings → AI access → Start session, then retry. (" + ex.Message + ")");
    }
}

static string Result(JsonNode id, JsonObject result) =>
    new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["result"] = result }.ToJsonString();

static string Error(JsonNode id, int code, string message) =>
    new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
    }.ToJsonString();

static bool HasResult(string response)
{
    try { return (JsonNode.Parse(response ?? "") as JsonObject)?["result"] != null; }
    catch { return false; }
}

static bool IsNotInitialized(string response)
{
    try { return (int?)((JsonNode.Parse(response ?? "") as JsonObject)?["error"]?["code"]) == -32002; }
    catch { return false; }
}

// ── upstream lifecycle resync ───────────────────────────────────────────
// The app bridge enforces its own initialize-before-request rule per app
// process lifetime, but the client's initialize is consumed exactly once —
// possibly hours before the app restarts or the user restarts the AI
// session. After that the bridge is fresh, every forwarded request dies
// with -32002 forever, and the client never knows (its pipe to this proxy
// never broke). So track WHICH bridge instance was initialized upstream
// ("pid:port:token" from session.json) and replay the client's handshake
// whenever it changes — plus one reactive retry if the bridge reset without
// session.json changing.
JsonNode clientHello = null;   // params of the client's initialize, for faithful replay
string upstreamKey = null;     // bridge instance the handshake was last sent to
long reinitCounter = 0;

// wake-on-knock (opt-in): with no session and the preference on, a knock may
// OPEN AutoCommand for the user - window up, Be My Guest tab in front. A
// knock can never start a session: activation happens only in that tab. The
// app's manifest requires administrator, so ShellExecute surfaces ONE UAC
// approval (the user is present - they just asked their assistant to look at
// the PC). A cooldown stops retry storms, and an already-running app is
// never spawned over (its session being off is a user decision, not a
// launch). AC_APP_EXE overrides the app path for offline self-tests.
DateTime lastKnockUtc = DateTime.MinValue;
TimeSpan KnockCooldown = TimeSpan.FromMinutes(5);

// True when the session's pid is still the process the app named when it
// wrote session.json. With "exe" in the file (app builds since this field
// exists) an EXACT full-path match is required — layout-proof and stronger
// than any same-directory guess. Legacy files (no exe) fall back to the
// name guard alone. The directory heuristic this replaces assumed the app
// sits one level above the proxy's folder; auto-registration deploys the
// proxy to tools\v<version>\ while the app runs from an extracted zip
// anywhere, so it rejected the GENUINE app and every tool call answered
// as offline (field report 2026-11-11). The session token remains the
// channel's real authentication either way.
static bool PidAlive(long pid, string expectedExe)
{
    if (pid <= 0) return false;
    try
    {
        // QueryFullProcessImageName (not Process.MainModule) so this works
        // while the app runs elevated and the proxy does not
        string sessionExe = QueryProcessImagePath((int)pid);
        if (sessionExe.Length == 0) return false;   // gone, or unidentifiable
        if (!string.IsNullOrEmpty(expectedExe))
        {
            if (string.Equals(sessionExe, expectedExe, StringComparison.OrdinalIgnoreCase))
                return true;
            // Launched through a directory junction, symlink, subst drive, or
            // 8.3 alias: compare final Win32 canonical targets on mismatch.
            string canonSession = CanonicalizePath(sessionExe);
            string canonExpected = CanonicalizePath(expectedExe);
            return canonSession.Length > 0 &&
                   string.Equals(canonSession, canonExpected, StringComparison.OrdinalIgnoreCase);
        }
        return Path.GetFileName(sessionExe).StartsWith("AutoCommand", StringComparison.OrdinalIgnoreCase);
    }
    catch { return false; }
}

static bool IsLocalDrivePath(string path) =>
    !string.IsNullOrEmpty(path) &&
    path.Length >= 3 &&
    char.IsLetter(path[0]) &&
    path[1] == ':' &&
    (path[2] == '\\' || path[2] == '/') &&
    path.IndexOfAny(Path.GetInvalidPathChars()) < 0 &&
    Path.IsPathFullyQualified(path);

static string CanonicalizePath(string path)
{
    if (string.IsNullOrEmpty(path)) return "";
    const uint FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    IntPtr h = CreateFileW(path, 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
    if (h == IntPtr.Zero || h == new IntPtr(-1))
    {
        try { return Path.GetFullPath(path); } catch { return path; }
    }
    try
    {
        var sb = new System.Text.StringBuilder(1024);
        uint len = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
        if (len == 0 || len >= sb.Capacity) return path;
        string resolved = sb.ToString();
        if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + resolved.Substring(8);
        if (resolved.StartsWith(@"\\?\", StringComparison.Ordinal))
            return resolved.Substring(4);
        return resolved;
    }
    finally { CloseHandle(h); }
}

static string TryResolveRecordedAppExe(string recorded)
{
    if (!IsLocalDrivePath(recorded)) return "";
    if (!string.Equals(Path.GetFileName(recorded), "AutoCommand.exe", StringComparison.OrdinalIgnoreCase))
        return "";
    if (!File.Exists(recorded)) return "";
    string canonical = CanonicalizePath(Path.GetFullPath(recorded));
    if (!IsLocalDrivePath(canonical)) return "";
    if (!string.Equals(Path.GetFileName(canonical), "AutoCommand.exe", StringComparison.OrdinalIgnoreCase))
        return "";
    if (!File.Exists(canonical)) return "";
    try
    {
        string orig = (FileVersionInfo.GetVersionInfo(canonical).OriginalFilename ?? "").Trim();
        if (!string.Equals(orig, "AutoCommand.dll", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(orig, "AutoCommand.exe", StringComparison.OrdinalIgnoreCase))
            return "";
    }
    catch { return ""; }
    return canonical;
}

static string QueryProcessImagePath(int pid)
{
    // PROCESS_QUERY_LIMITED_INFORMATION: readable across elevation boundaries
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (h == IntPtr.Zero) return "";
    try
    {
        var sb = new System.Text.StringBuilder(1024);
        uint size = (uint)sb.Capacity;
        return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : "";
    }
    finally { CloseHandle(h); }
}

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
static extern bool QueryFullProcessImageName(IntPtr process, uint flags, System.Text.StringBuilder exeName, ref uint size);

[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
static extern uint GetFinalPathNameByHandleW(IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

[System.Runtime.InteropServices.DllImport("kernel32.dll")]
static extern bool CloseHandle(IntPtr handle);

static bool InteractiveAppRunning()
{
    // AC_SIMULATE_APP_RUNNING is a self-test override for the running-app
    // probe (test boxes usually have a live interactive instance).
    if (Environment.GetEnvironmentVariable("AC_SIMULATE_APP_RUNNING") is string sim &&
        sim == "0") return false;
    var procs = Process.GetProcessesByName("AutoCommand");
    try { return procs.Length > 0; }
    finally { foreach (var p in procs) p.Dispose(); }
}

string AppExePath()
{
    // Resolution order, most-trusted first:
    //   1. AC_APP_EXE — offline self-tests
    //   2. agent\app_path.txt — written by the app at every startup; the
    //      only source that knows where the real exe lives when the app
    //      runs from an extracted zip far from this deployed proxy. Must
    //      resolve to a local AutoCommand.exe with AutoCommand PE metadata
    //      so user-writable app_path.txt cannot spoof UAC onto foreign exes.
    //   3. walk up from this proxy's own folder — the release zip keeps
    //      AutoCommand.exe at the root above tools\AgentProxy
    //   4. the legacy flat guess — proxy directly under <install>\tools\
    //
    // AgentProxy builds with <Nullable>disable</Nullable>, so the null
    // handling here is explicit rather than annotation-based
    string overridePath = Environment.GetEnvironmentVariable("AC_APP_EXE");
    if (!string.IsNullOrEmpty(overridePath)) return overridePath;
    try
    {
        string recorded = File.ReadAllText(Path.Combine(AgentDir, "app_path.txt")).Trim();
        string verified = TryResolveRecordedAppExe(recorded);
        if (verified.Length > 0) return verified;
        if (recorded.Length > 0)
            LogProxy("wake", "ignored untrusted or missing path in app_path.txt");
    }
    catch { /* not written yet — pre-update app */ }
    try
    {
        string dir = Path.GetDirectoryName(Environment.ProcessPath);
        for (int up = 0; up < 4 && !string.IsNullOrEmpty(dir); up++)
        {
            string candidate = Path.Combine(dir, "AutoCommand.exe");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        return Path.Combine(Path.GetDirectoryName(
            Path.GetDirectoryName(Environment.ProcessPath) ?? "") ?? "", "AutoCommand.exe");
    }
    catch { return ""; }
}

bool WakePrefOn()
{
    try { return File.ReadAllText(Path.Combine(AgentDir, "wake_pref.txt")).Trim() == "on"; }
    catch { return false; }
}

async Task<(int Port, string Token, long Pid, string Exe)?> TryWakeAsync()
{
    if (!WakePrefOn()) return null;
    if (DateTime.UtcNow - lastKnockUtc < KnockCooldown) return null;
    if (InteractiveAppRunning())
    {
        // Running app with its session off is a user decision — never spawn
        // a second instance over it; the offline guidance covers this case.
        return null;
    }

    string exe = AppExePath();
    if (exe.Length == 0 || !File.Exists(exe))
    {
        LogProxy("wake", "app exe not found next to proxy — install layout changed?");
        lastKnockUtc = DateTime.UtcNow;
        return null;
    }

    lastKnockUtc = DateTime.UtcNow;
    try
    {
        Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
LogProxy("wake", "app launch requested - the user starts the session in the Be My Guest tab");
    }
    catch (Exception ex)
    {
        LogProxy("wake", "launch failed: " + ex.Message);
        return null;
    }

    return null;
}

string SessionKey((int Port, string Token, long Pid, string Exe) s) => $"{s.Pid}:{s.Port}:{s.Token}";

// Why a present session.json still counts as offline — the log must say
// which of two very different states fired. "its app pid is gone" was also
// logged while the pid was alive and only the identity check failed, the
// exact red herring that hid the 2026-11-11 layout bug for a day.
string StaleDetail((int Port, string Token, long Pid, string Exe) s)
{
    string path = "";
    try { path = QueryProcessImagePath((int)s.Pid); } catch { }
    if (path.Length == 0)
        return $"session.json pid {s.Pid} is gone — treating as offline";
    string expected = s.Exe.Length > 0 ? s.Exe : "(legacy session file, no exe recorded)";
    return $"session.json pid {s.Pid} is alive (\"{path}\") but is not the session's app " +
           $"(\"{expected}\") — treating as offline";
}

async Task<bool> EnsureUpstreamInitializedAsync((int Port, string Token, long Pid, string Exe) s)
{
    string key = SessionKey(s);
    if (upstreamKey == key) return false;
    var init = new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = $"proxy-reinit-{++reinitCounter}",
        ["method"] = "initialize",
        ["params"] = clientHello?.DeepClone() ?? new JsonObject(),
    };
    string response = await ForwardAsync(s.Port, s.Token, init.ToJsonString(), init["id"]);
    if (HasResult(response))
    {
        upstreamKey = key;
        LogProxy("reinit", $"app bridge pid {s.Pid} — initialize replayed upstream");
        return true;
    }
    return false;   // bridge unreachable — ForwardAsync already returned guidance
}

// Two offline states, two different asks. Conflating them ("not running or
// its AI session is off") sent a user hunting for an app that was running
// fine with a live session — true-ish for both states, actionable for
// neither.
string OfflineGuidance()
{
    if (ReadSession() == null)
        return "No AutoCommand AI session is active right now.\n" +
            "Ask the user to open AutoCommand > Be My Guest tab > Start session, then retry.\n" +
            "(To stop being asked: tick 'Start the session automatically' and/or " +
            "'let my AI assistant open it for me' - both on the Be My Guest tab.)";
    return "AutoCommand is no longer running - it ended without stopping its AI session.\n" +
        "Ask the user to start AutoCommand again (and start the session in the Be My Guest " +
        "tab if they want tools to answer), then retry.";
}

string AnswerOffline(JsonObject rpc)
{
    JsonNode id = rpc["id"];
    if (id == null) return null; // notification — nothing to answer
    string method = rpc["method"]?.GetValue<string>() ?? "";
    var @params = rpc["params"] as JsonObject;

    switch (method)
    {
        case "initialize":
            string requested = @params?["protocolVersion"]?.GetValue<string>();
            return Result(id, new JsonObject
            {
                ["protocolVersion"] = Negotiate(requested),
                ["capabilities"] = new JsonObject { ["tools"] = new JsonObject { ["listChanged"] = false } },
                // identity matches the app bridge's online answer (name,
                // title, version) so the client UI never sees it change
                ["serverInfo"] = new JsonObject
                {
                    ["name"] = "autocommand",
                    ["title"] = "AutoCommand (agent bridge)",
                    ["version"] = ServerVersion(),
                },
                ["instructions"] = "Bridge to the locally running AutoCommand app. No AI session is currently " +
                    "active — every tool call answers with setup guidance until the user starts one " +
                    "(AutoCommand > Be My Guest tab > Start session).",
            });
        case "ping":
            return Result(id, new JsonObject());
        case "tools/list":
            return Result(id, new JsonObject
            {
                ["tools"] = JsonNode.Parse(OfflineToolsJson),
                ["_note"] = "inactive session — full schemas arrive from the app once a session starts",
            });
        case "tools/call":
            string name = @params?["name"]?.GetValue<string>() ?? "";
            return Result(id, new JsonObject
            {
                ["content"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["type"] = "text",
                        ["text"] = OfflineGuidance(),
                    },
                },
                ["isError"] = true,
            });
        default:
            return Error(id, -32601, $"Unknown method: {method} (no active AutoCommand session)");
    }
}

// ── orphan guard ────────────────────────────────────────────────────────
// stdin EOF is the normal shutdown: the client closes its write end, and a
// crashed client's handles are reaped by Windows so EOF still arrives. The
// rare leak case (the pipe handle inherited into a long-lived bystander)
// would strand this proxy forever — so also watch the parent PID and exit
// when it is gone. GetProcessById can be fooled by PID reuse in theory; the
// 5-second poll plus EOF make that irrelevant in practice.
(int ParentPid, string ParentName) FindParent()
{
    try
    {
        var self = Process.GetCurrentProcess().Id;
        var entries = Native.SnapshotProcesses();
        var mine = entries.FirstOrDefault(e => e.Pid == self);
        if (mine == null) return (0, "?");
        var parent = entries.FirstOrDefault(e => e.Pid == mine.ParentPid);
        return ((int)mine.ParentPid, parent?.Name ?? "?" + mine.ParentPid);
    }
    catch { return (0, "?"); }
}
var (parentPid, parentName) = FindParent();
if (parentPid != 0)
{
    int watched = parentPid;
    _ = Task.Run(async () =>
    {
        while (true)
        {
            await Task.Delay(5000);
            try { Process.GetProcessById(watched).Dispose(); }
            catch { LogProxy("stop", $"parent {parentName} ({watched}) is gone"); Environment.Exit(0); }
        }
    });
}
LogProxy("start", $"spawned by {parentName} ({parentPid}), proxy v{ServerVersion()}");

// ── main loop ───────────────────────────────────────────────────────────
// The session file is re-read on every incoming message: the client spawns
// this proxy at ITS startup, possibly long before the user presses "Start
// AI session" — when that flip happens mid-connection, calls must start
// working immediately, and the client should re-list tools.
bool clientInitialized = false; // MCP lifecycle: no requests before initialize
bool wasOnline = false;
bool staleSessionLogged = false;
try
{
    string line;
    while ((line = Console.ReadLine()) != null)
    {
        line = line.Trim();
        if (line.Length == 0) continue;

        JsonObject rpc = null;
        try { rpc = JsonNode.Parse(line) as JsonObject; } catch { }

        if (rpc == null)
        {
            stdout.WriteLine(Error(null, -32700, "Parse error"));
            continue;
        }

        string method = rpc["method"]?.GetValue<string>() ?? "";
        bool isRequest = rpc["id"] != null;

        // lifecycle: requests other than initialize/ping before the
        // handshake completed are refused (-32002); notifications are
        // simply ignored (there is nobody to answer). Mirrored in the app
        // bridge so both halves enforce the same rule.
        if (isRequest && !clientInitialized && method != "initialize" && method != "ping")
        {
            stdout.WriteLine(Error(rpc["id"], -32002, "Server not initialized — send initialize first."));
            continue;
        }
        if (method == "initialize")
        {
            clientInitialized = true;
            clientHello = (rpc["params"] as JsonObject)?.DeepClone();
            ClientName = (rpc["params"]?["clientInfo"] as JsonObject)?["name"]?.GetValue<string>() ?? "";
            if (ClientName.Length > 0) LogProxy("client", ClientName);
        }

        var session = ReadSession();
        // a session file whose pid is dead (app crashed without cleanup), or
        // whose pid is alive but is not the exe that wrote the file, is
        // offline — forwarding into it just times out
        bool online = session != null && PidAlive(session.Value.Pid, session.Value.Exe);
        if (session != null && !online && !staleSessionLogged)
        {
            staleSessionLogged = true;
            LogProxy("stale", StaleDetail(session.Value));
        }

        // wake-on-knock: no live session + a real post-handshake request +
        // the user's opt-in → launch the headless app and wait for its session
        if (!online && clientInitialized && isRequest && method != "initialize" && method != "ping")
        {
            var woke = await TryWakeAsync();
            if (woke != null)
            {
                session = woke;
                online = true;
            }
        }

        bool flipped = online != wasOnline;
        wasOnline = online;

        // Bridge instance changed since the last handshake reached it (app
        // restart, AI session restart): replay the client's initialize
        // BEFORE forwarding, or the bridge would refuse the request.
        bool reinitialized = false;
        if (online && clientInitialized && isRequest && method != "initialize" && method != "ping")
            reinitialized = await EnsureUpstreamInitializedAsync(session.Value);

        string response;
        if (online)
        {
            response = await ForwardAsync(session.Value.Port, session.Value.Token, line, rpc["id"]);

            // The client's own initialize IS the upstream handshake — book
            // it, so the first regular request doesn't replay a redundant one.
            if (isRequest && method == "initialize" && HasResult(response))
                upstreamKey = SessionKey(session.Value);

            // Bridge reset without session.json changing (defensive): its
            // -32002 is replayable exactly like an identity change.
            if (isRequest && method != "initialize" && IsNotInitialized(response))
            {
                upstreamKey = null;
                reinitialized |= await EnsureUpstreamInitializedAsync(session.Value);
                response = await ForwardAsync(session.Value.Port, session.Value.Token, line, rpc["id"]);
            }
        }
        else
            response = AnswerOffline(rpc);

        if (isRequest && !string.IsNullOrEmpty(response))
            stdout.WriteLine(response);

        // the session flipped while this proxy was connected, or the bridge
        // was re-initialized after a restart: in both cases the client's
        // cached tool list is stale (a new app build can add tools). Tell it
        // only AFTER the response to the in-flight message (usually
        // initialize) has been written, and only if the client finished
        // initializing — a notification racing the initialize response
        // confuses strict clients.
        if ((flipped || reinitialized) && clientInitialized)
            stdout.WriteLine(new JsonObject
            {
                ["jsonrpc"] = "2.0",
                ["method"] = "notifications/tools/list_changed",
                ["params"] = new JsonObject(),
            }.ToJsonString());
    }
    LogProxy("stop", "stdin closed (client exited)");
}
catch (Exception ex) { LogProxy("stop", "crashed: " + ex.Message); }
// stdin closed — the MCP client is gone

// ── native: Toolhelp32 process snapshot (parent lookup) ─────────────────
static class Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll")] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll")] private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll")] private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    public sealed record Entry(uint Pid, uint ParentPid, string Name);

    public static List<Entry> SnapshotProcesses()
    {
        const uint TH32CS_SNAPPROCESS = 2;
        var result = new List<Entry>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero) return result;
        try
        {
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref e))
                do
                {
                    result.Add(new Entry(e.th32ProcessID, e.th32ParentProcessID, e.szExeFile));
                } while (Process32NextW(snap, ref e));
        }
        finally { CloseHandle(snap); }
        return result;
    }
}
