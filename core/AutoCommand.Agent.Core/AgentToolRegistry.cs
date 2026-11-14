using System.Collections.Generic;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using AutoCommand.Services;
using AutoCommand.Models;
using ShieldsUp.Core.Services;
using SvchostAnalyzer.Core;

namespace AutoCommand.Agent.Core
{
    /// <summary>
    /// The MCP tool surface the AI-access bridge exposes. Read-only tools
    /// wrap services the running (elevated) app already trusts — the AI gets
    /// answers, never credentials and never raw UAC prompts. Mutating tools
    /// exist only when the user enabled them for the session, and every call
    /// passes through the bridge's confirmation dialog before executing.
    ///
    /// Handlers run on a background thread; they must not touch UI state.
    /// Anything that needs elevation fails with a plain-language note when
    /// the session happens to run non-elevated — degrade, never guess.
    /// </summary>
    public static class AgentToolRegistry
    {
        public sealed record Tool(
            string Name,
            string Description,
            JsonObject Schema,
            bool Mutating,
            Func<JsonObject, string> Handler,
            Func<JsonObject, string> ConfirmDetail = null);

        // ── registry access ───────────────────────────────────────────────

        /// <summary>Every registered tool's name — the single source the
        /// AgentProxy offline stub list is checked against (ProxyInstallSelfTest
        /// fails the build if the stub list drifts from this).</summary>
        public static IReadOnlyList<string> ToolNames =>
            Tools.Select(t => t.Name).ToList();

        // ── app-provided seam (same inversion as IAgentInteraction) ──────
        // The firewall baseline manager lives in the app assembly (the
        // enforcer and the Firewall tab both own it there), so the bridge
        // cannot call it directly. The app installs this seam at startup;
        // the offline self-tests install nothing and the preset tool
        // degrades to apply-only with an honest note.
        public sealed record ShieldsUpBaselineSeam(
            Action<int> PauseMinutes,
            Func<Task<(int Count, DateTime CapturedAt)>> CaptureAsync);
        public static ShieldsUpBaselineSeam ShieldsUpBaseline { get; set; }

        private static readonly List<Tool> Tools = new()
        {
            new Tool(
                "get_monitor_rows",
                "Live snapshot of every established outbound TCP connection on the machine (IPv4 and IPv6), " +
                "attributed to its process — svchost instances decoded to their hosted service " +
                "(SCM ground truth + -k/-s command-line tokens) and each destination classified " +
                "(Microsoft/Azure, Akamai, Gcore, unclassified). Same view as AutoCommand's Process Monitor.",
                Schema(),
                false,
                a => ToJson(BuildMonitorSnapshot())),
            new Tool(
                "get_svchost_identity",
                "Identify one svchost.exe instance: the services the SCM says it hosts (ground truth), " +
                "its command-line -k group and -s service claim, and whether the claim corroborates. " +
                "A mismatch is a masquerade signal.",
                Schema(("pid", "Process ID of the svchost.exe instance", true)),
                false,
                a => GetSvchostIdentity(a)),

            new Tool(
                "run_pid_inquiry",
                "Full provenance trace of a PID: verdict, identity, verified spawn chain, hosted services, " +
                "Sysmon corroboration — the same report AutoCommand's PID Inquiry window renders. " +
                "Needs the elevated app for SYSTEM process command lines; degrades gracefully otherwise.",
                Schema(("pid", "Process ID to trace", true)),
                false,
                a => RunPidInquiry(a)),

            new Tool(
                "tail_sysmon",
                "Recent events from the Sysmon/Operational log (process creates, network connections, " +
                "process terminates). Needs the elevated app; returns a clear note when unreadable. " +
                "With archive=true: reads the app's Sysmon archive instead — every event backfilled or " +
                "watched since the archive began (default 30 days), including events that already " +
                "wrapped out of the rolling live channel.",
                Schema(("minutes", "Look this many minutes back (default 30)", false),
                       ("eid", "Filter to one Sysmon event ID (e.g. 1=process create, 3=network)", false),
                       ("contains", "Only events whose description contains this text (case-insensitive)", false),
                       ("max", "Maximum events to return (default 50, cap 500)", false),
                       ("archive", "true = query the app's Sysmon archive instead of the live log", false)),
                false,
                a => TailSysmon(a)),

            new Tool(
                "list_watches",
                "List the user's Spawn Watches — name-based prefilters evaluated at Sysmon " +
                "INGESTION time (the moment a process is archived, not after the fact): image " +
                "and parent-image wildcards, parent svchost -s service scoping, command-line " +
                "substring, allowlist subtraction — each with its 24 h hit count. Rules are JSON " +
                "files in the watches directory; editing or dropping a file takes effect on the " +
                "next pass, no restart. Read-only.",
                Schema(),
                false,
                a => ListWatches(a)),

            new Tool(
                "tail_watches",
                "Recent spawn-watch hits: processes caught by the user's Spawn Watch rules at " +
                "Sysmon ingestion time, each with its rule, image, PID, parent image, parent " +
                "svchost service and command line. This answers 'what did svchost (or anything) " +
                "spawn' for classes the user prefiltered — no chasing after spawn. Read-only.",
                Schema(("rule", "Only hits for this rule name (default: all rules)", false),
                       ("minutes", "Look this many minutes back (default 1440 = 24 h)", false),
                       ("max", "Maximum hits to return (default 100, cap 500)", false)),
                false,
                a => TailWatches(a)),

            new Tool(
                "trace_analyze",
                "Run AutoCommand's svchost trace analyzer. With seconds>0: capture live traffic for that " +
                "long, then analyze (parentage, identity corroboration, destinations, beacon regularity, " +
                "upload dominance). With seconds=0: analyze the most recent saved capture file instead.",
                Schema(("seconds", "Live capture length in seconds (default 0 = analyze latest capture file, cap 120)", false),
                       ("path", "Explicit .jsonl capture path to analyze instead", false)),
                false,
                a => TraceAnalyze(a)),

            new Tool(
                "classify_ip",
                "Classify a destination IP against session-verified ranges (Microsoft/Azure, Akamai, Gcore), " +
                "return the same block-warning text the app shows before blocking, AND report whether the IP " +
                "is currently on AutoCommand's explicit blocked list (rule count, since when) — the part the " +
                "range classifier alone cannot see.",
                Schema(("ip", "IPv4 address to classify", true)),
                false,
                a => ClassifyIp(a)),

            new Tool(
                "lookup_ip",
                "Resolve one IP the way AutoCommand's rows do: hostname (or none), range classification, " +
                "org/geo label with its cache state (fresh / negative-cached with a retry time / throttled " +
                "with a retry estimate / local-by-design) — ip-api throttled at the free tier, with an " +
                "RDAP registry fallback — plus blocked-list status. force=true marks the lookup " +
                "user-initiated: it skips the inter-call spacing for this one lookup (cooldowns still " +
                "apply) and re-asks even a negative-cached answer; the fresh answer lands in the cache " +
                "for every row. Read-only.",
                Schema(("ip", "IPv4 address to resolve", true),
                       ("force", "true = user-initiated urgent lookup", false)),
                false,
                a => LookupIp(a)),

            new Tool(
                "get_transmissions",
                "Recent recorded TLS transmissions (the Transmissions tab's archive): per conversation — process, " +
                "pid, destination, SNI hostname, RDAP provider, wire and decrypted byte counts, status " +
                "(decrypted / encrypted-no-keys), SHA-256 and whether full bodies are on disk. METADATA ONLY: " +
                "bodies contain credentials and are never returned over the bridge; read them in the app.",
                Schema(("max", "Maximum rows to return (default 50, cap 200)", false),
                       ("pid", "Only rows for this process ID", false),
                       ("contains", "Only rows whose process/SNI/IP/provider/status contains this text", false),
                       ("minutes", "Look this many minutes back (default 1440 = 24h)", false)),
                false,
                a => GetTransmissions(a)),

            new Tool(
                "list_blocks",
                "Inventory of every AutoCommand firewall block (the Blocks tab's data): per target — kind, " +
                "owner class, enabled/total rules, created time and recent hit counts from the live " +
                "Sysmon-joined feed. This is the authoritative 'is it blocked' source: classify_ip's range " +
                "answer alone cannot see explicit blocked-list entries.",
                Schema(("minutes", "Hit-count lookback window in minutes (default 60)", false)),
                false,
                a => ListBlocks(a)),

            new Tool(
                "list_gates",
                "Open block gates — temporary unblocks agents requested and the user approved. Per row: " +
                "target, remaining minutes, who asked and why. Check this BEFORE requesting a gate " +
                "(a gate may already be open for your target) and close yours with close_gate when done.",
                Schema(),
                false,
                _ =>
                {
                    var rows = new JsonArray();
                    foreach (var g in BlockGateService.Instance.Open)
                        rows.Add(new JsonObject
                        {
                            ["target"] = g.Display,
                            ["kind"] = g.Kind,
                            ["remaining_minutes"] = Math.Round(g.RemainingMinutes, 1),
                            ["closes_at"] = g.ExpiresUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
                            ["client"] = g.Client,
                            ["reason"] = g.Reason,
                        });
                    return ToJson(new JsonObject { ["type"] = "open_gates", ["gates"] = rows.Count, ["rows"] = rows });
                }),

            new Tool(
                "list_recent_block_hits",
                "Processes recently caught hitting AutoCommand firewall blocks, LIVE: Sysmon EID 3 connect " +
                "attempts joined against the blocked-target inventory — process, pid, blocked destination, " +
                "first/last seen, attempt count. Windows Firewall blocks silently (connect fails with " +
                "access-denied, nothing is logged by default), so this join — not pfirewall.log — is the " +
                "real-time 'who is being blocked' feed, and the fastest way to explain a " +
                "'This site can't be reached' error.",
                Schema(("minutes", "Look-back window (default 60, cap 1440)", false),
                       ("contains", "Only rows whose process or destination contains this text (case-insensitive)", false),
                       ("max", "Maximum aggregated rows (default 50, cap 200)", false)),
                false,
                a => ListRecentBlockHits(a)),

            new Tool(
                "verify_block_containment",
                "Prove blocked processes are actually silent, not just still trying: Sysmon-attributed block " +
                "attempts (EID 3 logs the attempt, never the outcome) joined against the live kernel socket " +
                "table and the TLS-transmissions archive since each block was created. Per process instance: " +
                "contained (the kernel is dropping everything), stale-flow (a socket that predates the block " +
                "may still be alive — firewall rules never sever established flows), or leak (socket or " +
                "archived bytes after the block — escalate). Enabled blocks with no attempts in the window " +
                "are listed as quiet. Read-only; for sub-threshold, UDP or DNS traffic compose with " +
                "trace_analyze.",
                Schema(("minutes", "Attempt look-back window (default 60, cap 1440)", false),
                       ("contains", "Only instances whose process or destination contains this text (case-insensitive)", false)),
                false,
                a => VerifyBlockContainment(a)),

            new Tool(
                "audit_block_duplicates",
                "Read-only duplicate audit of AutoCommand's block rules: per target, how many rules are " +
                "exact duplicates of another (same rule name — and for process rules, the same image " +
                "path). Duplicates are inert residue of concurrent blocking (blocking is unchanged) but " +
                "clutter wf.msc, skew inventory counts and re-appear on every reconcile; the Rules tab's " +
                "'Clean duplicates' retires them. One executable name covered at several paths is " +
                "intentional coverage and is NOT reported here.",
                Schema(),
                false,
                _ => AuditBlockDuplicates()),

            new Tool(
                "check_host",
                "'Why can't I reach this site?' in one call: resolve a hostname, then per address — range " +
                "classification, whether it is on AutoCommand's blocked list (with rule count and since " +
                "when), and recent blocked-connect attempts against it — ending in a plain-English verdict. " +
                "Accounts for DNS rotation: blocks are per-IP, so a blocked front-end can make a site fail " +
                "intermittently while other Google/Microsoft/CDN pages still work.",
                Schema(("host", "Hostname to check (e.g. accounts.google.com)", true),
                       ("minutes", "Recent-hit lookback (default 120)", false)),
                false,
                a => CheckHost(a)),

            new Tool(
                "diagnose_site",
                "Run the Site Doctor pipeline for one hostname — the 'why is this site slow / broken / failing " +
                "to sign in' question: passive fingerprint from the recorded-transmissions archive, a " +
                "dependency-block pass (were the page's other hosts — captcha, assets, APIs — silently blocked " +
                "during this browser's recorded visits? blocked connects carry no hostname, so only the " +
                "block-hit join can see them), then a capped live probe run (~10-25 quick operations, every one " +
                "listed in the result) — DNS rotation sampling, per-edge TCP plus two TLS hello shapes, " +
                "control-host comparison — and the plain-English verdict with evidence. Read-only; nothing is " +
                "blocked, killed or changed. Takes roughly 30 seconds.",
                Schema(("host", "Hostname to diagnose (e.g. chat.z.ai)", true),
                       ("minutes", "Archive lookback window in minutes (default 1440)", false)),
                false,
                a => DiagnoseSite(a)),

            new Tool(
                "get_phonehome_cards",
                "The Phone Home tab's curated cards: one per well-known Windows talker (DiagTrack, " +
                "CryptSvc, Delivery Optimization…) — the authored plain-English story, measured " +
                "connects/hr over the last 24 h against the authored normal band, top destinations " +
                "with classification, beacon regularity and identity corroboration. Read-only.",
                Schema(),
                false,
                a => GetPhoneHomeCards()),

            new Tool(
                "list_trace_projects",
                "The Traces tab's user-defined tracing projects (JSON files under " +
                "%LOCALAPPDATA%\\AutoCommand\\traces\\projects): name, process/service match and " +
                "notes for each. Read-only.",
                Schema(),
                false,
                a => ListTraceProjects()),

            new Tool(
                "get_trace_project",
                "One trace project's definition plus its measured snapshot (frequency, destinations, " +
                "volume, beacon regularity, identity) — the same card the Traces tab renders. Read-only.",
                Schema(("name", "Project name exactly as listed", true)),
                false,
                a => GetTraceProject(a)),

            new Tool(
                "run_trace",
                "Ad-hoc trace without saving a project: measure any process (wildcards ok, e.g. " +
                "'chrome*') or one svchost service key over the last N hours (default 24, cap 24) — " +
                "the same metrics the Traces tab cards show. Read-only; nothing is captured, blocked " +
                "or changed.",
                Schema(("process", "Image name to watch ('*' wildcards)", false),
                       ("service", "svchost SCM service key instead of a process name", false),
                       ("hours", "Lookback hours (default 24, max 24)", false)),
                false,
                a => RunTrace(a)),

            new Tool(
                "investigate_process",
                "Composite read-only investigation of one process in a single call — the whole " +
                "'why is this transmitting?' playbook: PID provenance (who launched it, PID-recycle " +
                "guard), traffic profile over the lookback window (frequency, destinations with " +
                "classification, beacon regularity, recorded TLS volume, live connections), AutoCommand " +
                "block-hit check, and a synthesized verdict ('internal-only', 'outbound attempts none " +
                "completed', 'actively blocked', 'quiet') plus a plain-text report. Needs a PID for the " +
                "provenance half; a name alone still gets the full traffic picture. Hours default 6 " +
                "(cap 24) — larger windows scan more archive and take longer.",
                Schema(("process", "Image name to investigate ('*' wildcards); used when pid is absent", false),
                       ("pid", "Process ID to investigate instead — enables the provenance half", false),
                       ("hours", "Lookback hours (default 6, max 24)", false)),
                false,
                a => InvestigateProcess(a)),

            new Tool(
                "get_shieldsup_status",
                "The Shields Up tab's status board, read-only: every door Windows leaves open (SSTP VPN service " +
                "and miniports, Wi-Fi Direct hosted network, kernel debug, the four Windows VPN services, WAN " +
                "miniports, and the legacy name-resolution doors llmnr/netbios/mdns with their live 24h " +
                "chatter counts — dropped UDP 137/5355/5353 attempts), the OS-hardening switches (IPv6, LSA " +
                "Protection, UAC strictness), the hosts-file audit, Defender Tamper Protection, and per-vendor " +
                "telemetry opt-out state with rule ids. Everything is re-read live — never a cached verdict.",
                Schema(),
                false,
                a => GetShieldsUpStatus()),

            new Tool(
                "get_startup_status",
                "The Startup & Tasks surface, read-only: logon items (Run keys + Startup folders, with " +
                "disabled-by-AutoCommand flags) and scheduled tasks — third-party entries listed individually " +
                "(path, state, action, user), Windows inbox tasks as a count. Classification is location-based " +
                "and says so; no signature claims. Mutating stays in the app's Shields Up tab.",
                Schema(),
                false,
                a => GetStartupStatus()),

            new Tool(
                "get_wsl_status",
                "WSL (Windows Subsystem for Linux) network state, read-only: whether WSL is installed and the " +
                "utility VM is running, the running distros, the networking mode (NAT vs mirrored) with its " +
                "source, and — when the VM is already up — the Linux-side socket table (ss -tnp) joined " +
                "against the host's WSL-family connections, so 'wslservice.exe is talking to X' becomes " +
                "'<distro>'s <process> is talking to X'. NEVER starts the utility VM: when it is not running " +
                "the guest half says so instead of launching it. Pairs with get_monitor_rows (WSL rows carry " +
                "a wsl object) and diagnose_wsl for the no-internet case.",
                Schema(),
                false,
                a => GetWslStatus()),

            new Tool(
                "diagnose_wsl",
                "Run the staged 'Why is WSL offline?' diagnosis — the pipeline from the 2026-10-30 field " +
                "report, read-only end to end: host egress probe, guest probe from inside the running " +
                "distro (bash /dev/tcp, exit 0 vs 124), the guest's NAT-gateway leg, the full firewall " +
                "rule-model scan for WSL/Hyper-V-family rules, and the Hyper-V firewall layer — ending in " +
                "one plain-English verdict: healthy, machine-wide outage, disabled family rules, Hyper-V " +
                "layer blocking, or a drop below the rule model (WFP, needs the elevated attribution " +
                "script). Never starts the utility VM; takes ~15 seconds.",
                Schema(),
                false,
                a => DiagnoseWsl()),

            // ── mutating: only present when the session allows, each call confirmed ──

            new Tool(
                "open_gate",
                "Temporarily stop blocking ONE specific blocked IP or process image (all instances of that " +
                "exe — firewall rules cannot distinguish PIDs). The user confirms the exact target in " +
                "AutoCommand. The gate AUTO-CLOSES: blocking returns ON after the duration you choose, so " +
                "pick the SHORTEST window your task needs (allowed: 1, 10, 30, 60 minutes). dry_run=true " +
                "resolves the target and previews without asking the user — do that first when unsure. " +
                "Ambiguous names return the candidates instead of acting; be specific. close_gate ends a " +
                "gate early; list_gates shows what is open.",
                Schema(("target", "One blocked target: an IP address, a process image name, or a full exe path", true),
                       ("minutes", "Gate window: 1, 10, 30 or 60 — pick the shortest your task needs", true),
                       ("reason", "Why — shown to the user in the confirmation", false),
                       ("dry_run", "true = resolve and preview only, no confirmation, no change", false)),
                true,
                a => OpenGate(a),
                a => OpenGateConfirmText(a)),

            new Tool(
                "close_gate",
                "Close an open block gate early: blocking returns ON for that target immediately. " +
                "Call this the moment your work is done — every minute a gate stays open is a minute " +
                "its target is unblocked. Asks the user for every call.",
                Schema(("target", "The gated IP / process name / exe path (as reported by list_gates)", true)),
                true,
                a => CloseGate(a),
                a => $"Close the block gate early - return blocking ON for {a["target"]} now?"),

            new Tool(
                "close_shieldsup_door",
                "Close ONE of the doors Windows leaves open (Shields Up tab): sstp (stop the SSTP VPN " +
                "service + disable its miniport adapters), hostednetwork (stop + disallow the Wi-Fi Direct " +
                "ghost hotspot), vpnservices (stop + disable RasMan/IKEEXT/PolicyAgent/RemoteAccess — any " +
                "VPN connection drops), kdnet (turn kernel debug off), wifidirect (disable the Wi-Fi " +
                "Direct virtual adapters), the legacy name-resolution doors: llmnr (EnableMulticast=0 — " +
                "kills the LLMNR-poisoning credential-theft class), netbios (NetbiosOptions=2 per interface " +
                "— stops UDP 137 broadcasts), mdns (firewall-scoped block of UDP 5353 multicast — network-" +
                "level only, .local device discovery stops while closed), or hotpatch (disable the " +
                "\\Microsoft\\Windows\\Hotpatch\\Monitoring boot task — its SYSTEM-run hpatchmonTask.cmd " +
                "readiness phone-home stops; updates still install normally). All reversible. There is " +
                "deliberately NO enable path over the bridge — re-opening a door is a human decision made " +
                "in the tab. Asks the user for every call.",
                Schema(("door", "One of: sstp | hostednetwork | vpnservices | kdnet | wifidirect | llmnr | netbios | mdns | hotpatch", true),
                       ("reason", "Why — shown to the user in the confirmation", false)),
                true,
                a => CloseShieldsUpDoor(a),
                a => CloseShieldsUpDoorConfirm(a)),

            new Tool(
                "opt_out_telemetry",
                "Flip one vendor's OWN official opt-out switch (Shields Up tab's vendor table: dotnet CLI, " +
                "PowerShell 7, VS Code, Windows diagnostic data, Edge, Chrome, ultralytics, Windows search " +
                "features). The previous setting is saved first, the flip is verified by re-reading, and " +
                "revert=true restores the previous value exactly. Rules marked switch_kind=feature disable a " +
                "network-fetching FEATURE at its source — honest effect: 'reduced', not network-stopped; only " +
                "verify_block_containment proves zero bytes. Rules with a traffic_process return a connects/hr " +
                "baseline at flip time for the before/after check. Asks the user for every call.",
                Schema(("rule_id", "Rule id from get_shieldsup_status (e.g. 'vscode-telemetry')", true),
                       ("revert", "true = restore the previous setting instead of opting out", false)),
                true,
                a => OptOutTelemetry(a),
                a => OptOutTelemetryConfirm(a)),

            new Tool(
                "apply_shieldsup_preset",
                "Apply one named firewall preset (the Firewall tab's profile control): strict_public (kill sharing/discovery/" +
                "remote desktop), home_trusted, gaming_media, office or shield_up (disable every grouped " +
                "rule, re-enable only mDNS, Core Networking and the WSL/Hyper-V VM-infrastructure groups). " +
                "The firewall baseline is re-captured atomically with the apply, so Auto-Mitigate protects " +
                "the preset's intent instead of fighting it. Asks the user for every call.",
                Schema(("preset", "One of: strict_public | home_trusted | gaming_media | office | shield_up", true),
                       ("reason", "Why — shown to the user in the confirmation", false)),
                true,
                a => ApplyShieldsUpPreset(a),
                a => ApplyShieldsUpPresetConfirm(a)),

        };

        public static string[] Names(bool includeMutating) =>
            Tools.Where(t => includeMutating || !t.Mutating).Select(t => t.Name).ToArray();

        public static Tool Find(string name, bool includeMutating) =>
            Tools.FirstOrDefault(t => t.Name == name && (includeMutating || !t.Mutating));

        public static JsonArray Descriptors(bool includeMutating)
        {
            var arr = new JsonArray();
            foreach (var t in Tools.Where(t => includeMutating || !t.Mutating))
                arr.Add(new JsonObject
                {
                    ["name"] = t.Name,
                    ["description"] = t.Description,
                    ["inputSchema"] = t.Schema.DeepClone(),
                });
            return arr;
        }

        // ── read tool handlers ────────────────────────────────────────────

        // Last snapshot's live (pid → name, start time) pairs, so the next
        // snapshot can flag a PID whose name changed instead of silently
        // attaching the new holder's name — the PID-reuse trap.
        private static readonly object _lastSeenLock = new();
        private static Dictionary<int, (string Name, DateTime? StartedUtc)> _lastSeen = new();

        public static JsonObject BuildMonitorSnapshot()
        {
            // Kernel table FIRST, name snapshot second — the join must never
            // name a PID from data older than the connection table, or a PID
            // reused in between gets the previous owner's name attached.
            // GetExtendedTcpTable returns the whole table at one kernel
            // instant: no child process, no parse, microseconds of skew.
            var connections = TcpConnectionTable.GetEstablished();

            var procs = new Dictionary<int, (string Name, DateTime? StartedUtc)>();
            try
            {
                // CreationDate rides along because a bare PID is not an
                // identity — (pid, start time) is, the same rule the PID
                // Inquiry enforces against PID recycling.
                using var s = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, CreationDate FROM Win32_Process");
                foreach (ManagementObject o in s.Get())
                {
                    DateTime? started = null;
                    try
                    {
                        if (o["CreationDate"] is string dmtf && dmtf.Length > 0)
                            started = ManagementDateTimeConverter.ToDateTime(dmtf).ToUniversalTime();
                    }
                    catch { /* some system rows have no readable date — the name still joins */ }
                    procs[Convert.ToInt32(o["ProcessId"])] = (o["Name"]?.ToString() ?? "?", started);
                }
            }
            catch { /* WMI failed — rows carry PID only */ }

            var seenNow = new Dictionary<int, (string, DateTime?)>();
            var rows = new JsonArray();
            foreach (var c in connections)
            {
                string name; DateTime? started; string attribution;
                if (procs.TryGetValue(c.Pid, out var live))
                {
                    name = live.Name; started = live.StartedUtc; attribution = "live";
                    seenNow[c.Pid] = (live.Name, live.StartedUtc);
                }
                else
                {
                    // The owner exited between the two snapshots. Never
                    // attach a possibly-reused name: recover the identity
                    // Sysmon recorded at create time, else say it exited.
                    string recovered = TryRecoverNameFromSysmon(c.Pid);
                    if (recovered != null)
                    {
                        name = recovered; attribution = "recovered-from-sysmon";
                    }
                    else
                    {
                        name = "(exited during snapshot)"; attribution = "exited";
                    }
                    started = null;
                }

                var row = new JsonObject
                {
                    ["local"] = c.LocalEndPoint,
                    ["remote"] = c.RemoteEndPoint,
                    ["pid"] = c.Pid,
                    ["process"] = name,
                    ["classification"] = SvchostTraceClassifier.Classify(c.RemoteIp),
                    ["attribution"] = attribution,
                };
                if (started != null)
                    row["process_started_utc"] = started.Value.ToString("yyyy-MM-dd HH:mm:ss");

                lock (_lastSeenLock)
                {
                    if (_lastSeen.TryGetValue(c.Pid, out var prev) &&
                        !string.Equals(prev.Name, name, StringComparison.OrdinalIgnoreCase))
                        row["pid_reused_since_last_snapshot"] = true;
                }

                if (name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    var id = SvchostIdentityService.Resolve(c.Pid);
                    row["svchost"] = new JsonObject
                    {
                        ["services"] = id.ServicesCsv,
                        ["k"] = id.Group,
                        ["s"] = id.DeclaredService,
                        ["cmdline_visible"] = id.CommandLineVisible,
                        ["mismatch"] = id.Mismatch,
                    };
                }

                // WSL family rows: the connection belongs to the Linux VM, so
                // say so — and warn that a process block here takes down every
                // distro. State rides the cached probe; never starts the VM.
                if (WslIdentityService.IsWslFamilyProcess(name))
                {
                    var st = WslIdentityService.GetState();
                    row["wsl"] = new JsonObject
                    {
                        ["egress"] = "WSL2 utility VM — a Linux process made this connection; " +
                                     "host-side attribution stops at the VM boundary",
                        ["vm_running"] = st.VmRunning,
                        ["running_distros"] = new JsonArray(st.RunningDistros.Select(d => (JsonNode)d).ToArray()),
                        ["networking_mode"] = st.NetworkingMode,
                        ["block_warning"] = "blocking this PROCESS blocks every distro's whole network — " +
                                            "block the destination IP instead for anything narrower",
                    };
                }
                rows.Add(row);
            }
            lock (_lastSeenLock) { _lastSeen = seenNow; }

            // open block gates ride the snapshot: offline agents reading the
            // feed alone see which targets are temporarily unblocked
            var gates = new JsonArray();
            foreach (var g in BlockGateService.Instance.Open)
                gates.Add(new JsonObject
                {
                    ["target"] = g.Display,
                    ["remaining_minutes"] = Math.Round(g.RemainingMinutes, 1),
                    ["closes_at"] = g.ExpiresUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
                    ["client"] = g.Client,
                });

            return new JsonObject
            {
                ["type"] = "monitor_snapshot",
                ["rows"] = rows,
                ["row_count"] = rows.Count,
                ["open_gates"] = gates,
            };
        }

        /// <summary>
        /// The image name Sysmon recorded when this PID was created, from the
        /// most recent matching create event in the last hour. The event
        /// carries the image itself, so PID reuse cannot misattribute — this
        /// is ground truth, not a lookup against the live process table.
        /// Null when Sysmon is absent, unreadable (non-elevated session), or
        /// has no recent event for the PID. Only consulted for rows whose
        /// owner already exited.
        /// </summary>
        private static string TryRecoverNameFromSysmon(int pid)
        {
            try
            {
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName,
                    $"*[System[EventID=1 and TimeCreated[timediff(@SystemTime) <= 3600000]] " +
                    $"and EventData[Data[@Name='ProcessId']='{pid}']]");
                string best = null;
                DateTime bestTime = DateTime.MinValue;
                using var reader = new EventLogReader(query);
                for (var ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
                using (ev)
                {
                    if (ev.TimeCreated is { } t && t > bestTime)
                    {
                        // EID 1 property layout: 0 RuleName, 1 UtcTime,
                        // 2 ProcessGuid, 3 ProcessId, 4 Image, …
                        var props = ev.Properties;
                        if (props.Count > 4 && props[4].Value is string img && img.Length > 0)
                        {
                            bestTime = t;
                            best = Path.GetFileName(img);
                        }
                    }
                }
                return best;
            }
            catch { return null; } // not installed / unreadable non-elevated — degrade, never guess
        }


        private static string GetSvchostIdentity(JsonObject a)
        {
            int pid = a["pid"]?.GetValue<int>() ?? 0;
            string name;
            try
            {
                using var proc = Process.GetProcessById(pid);
                name = proc.ProcessName;
            }
            catch { return $"PID {pid} is not running."; }
            if (!name.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                return $"PID {pid} is '{name}', not svchost.exe.";

            var id = SvchostIdentityService.Resolve(pid);
            return ToJson(new JsonObject
            {
                ["pid"] = pid,
                ["scm_services"] = id.ServicesCsv.Length > 0 ? id.ServicesCsv : "(none — strongest masquerade red flag)",
                ["services_detail"] = id.ServicesDetail,
                ["k_group"] = id.Group,
                ["s_declared"] = id.DeclaredService,
                ["command_line_visible"] = id.CommandLineVisible,
                ["mismatch"] = id.Mismatch,
                ["readable_line_without_k"] = id.NoK,
                ["verdict"] = id.Mismatch || id.NoK
                    ? "SUSPICIOUS — self-declared identity contradicts the SCM"
                    : id.CommandLineVisible ? "corroborated" : "no command line readable — rerun the app elevated to corroborate",
            });
        }

        private static string RunPidInquiry(JsonObject a)
        {
            int pid = a["pid"]?.GetValue<int>() ?? 0;
            var report = ProcessProvenanceService.Collect(pid);
            return ProcessProvenanceService.BuildReportText(report);
        }

        private static string TailSysmon(JsonObject a)
        {
            int minutes = a["minutes"]?.GetValue<int>() ?? 30;
            minutes = Math.Clamp(minutes, 1, 24 * 60);
            int? eid = a["eid"] is JsonNode e ? e.GetValue<int>() : null;
            string contains = a["contains"]?.GetValue<string>();
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 50, 1, 500);
            bool archive = a["archive"] is JsonNode ab && ab.GetValue<bool>();

            if (archive)
            {
                var events = SysmonArchiveService.Search(eid, contains, DateTime.UtcNow.AddMinutes(-minutes), max);
                if (events.Count == 0)
                    return $"No matching events in the Sysmon archive (last {minutes} min). " +
                           "The archive fills at every elevated app start (backfill) and while the app runs.";
                var sb2 = new StringBuilder();
                foreach (var ev in events)
                {
                    string stamp = ev.TsUtc.ToLocalTime().ToString("HH:mm:ss");
                    string pid = ev.Data.GetValueOrDefault("ProcessId", "");
                    string img = ev.Data.GetValueOrDefault("Image", "");
                    string cmd = ev.Data.GetValueOrDefault("CommandLine", "");
                    string line = $"{stamp}  EID {ev.Eid}  PID {pid}  {img}" +
                                  (cmd.Length > 0 ? $" | {cmd}" : "");
                    if (line.Length > 400) line = line[..400] + "…";
                    sb2.AppendLine(line);
                }
                return sb2.ToString();
            }

            try
            {
                var since = DateTime.UtcNow.AddMinutes(-minutes);
                var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational",
                    PathType.LogName, "*[System[TimeCreated[@SystemTime >= '" + since.ToString("yyyy-MM-ddTHH:mm:ss.000Z") + "']]]");
                using var reader = new EventLogReader(query);
                var sb = new StringBuilder();
                int shown = 0, scanned = 0;
                for (var ev = reader.ReadEvent(); ev != null && shown < max; ev = reader.ReadEvent())
                using (ev)
                {
                    scanned++;
                    if (eid.HasValue && ev.Id != eid.Value) continue;
                    string desc;
                    try { desc = ev.FormatDescription() ?? ""; } catch { desc = ""; }
                    if (!string.IsNullOrEmpty(contains) &&
                        !desc.Contains(contains, StringComparison.OrdinalIgnoreCase)) continue;
                    int pid = -1;
                    try { pid = Convert.ToInt32(ev.Properties[3]?.Value); } catch { }
                    string stamp = ev.TimeCreated?.ToLocalTime().ToString("HH:mm:ss") ?? "??";
                    string line = stamp + $"  EID {ev.Id}  PID {pid}  " +
                                  desc.Replace("\r\n", " | ").Replace("\n", " | ").TrimEnd();
                    if (line.Length > 400) line = line[..400] + "…";
                    sb.AppendLine(line);
                    shown++;
                }
                if (shown == 0)
                    return $"No matching Sysmon events in the last {minutes} min (scanned {scanned}). " +
                           "Zero scanned usually means the log is empty or Sysmon config dropped this event class.";
                return sb.ToString();
            }
            catch (UnauthorizedAccessException)
            {
                return "The Sysmon log is not readable from this session — the running AutoCommand instance " +
                       "is not elevated. Restart AutoCommand as Administrator and start a new AI session.";
            }
            catch (Exception ex)
            {
                return "Sysmon log read failed: " + ex.Message;
            }
        }

        private static string ListWatches(JsonObject a)
        {
            var rules = SpawnWatchStore.Load();
            if (rules.Count == 0)
                return "No spawn watches defined yet. Drop a " +
                       "rule JSON into " + SpawnWatchStore.WatchesDirectory + " (files are the interface).";
            var counts = SpawnWatchService.HitCounts(DateTime.UtcNow.AddHours(-24));
            var sb = new StringBuilder();
            sb.AppendLine($"{rules.Count} spawn watch rule(s) in {SpawnWatchStore.WatchesDirectory}:");
            foreach (var w in rules)
            {
                counts.TryGetValue(w.Name, out var hits);
                sb.AppendLine($"- {w.Name} [{(w.Enabled ? "enabled" : "disabled")}] — " +
                              DescribeWatch(w) + $" — {hits} hit(s)/24h" +
                              (string.IsNullOrWhiteSpace(w.Notes) ? "" : $" — {w.Notes}"));
            }
            return sb.ToString();
        }

        private static string DescribeWatch(SpawnWatch w)
        {
            var parts = new List<string>
            {
                "process " + (string.IsNullOrWhiteSpace(w.MatchProcess) ? "(none)" : w.MatchProcess),
            };
            parts.Add(string.IsNullOrWhiteSpace(w.MatchParent) ? "parent any" : "parent " + w.MatchParent);
            parts.Add(string.IsNullOrWhiteSpace(w.ServiceKey) ? "service any" : "service " + w.ServiceKey);
            if (!string.IsNullOrWhiteSpace(w.CommandLineContains))
                parts.Add("cmd contains '" + w.CommandLineContains + "'");
            if (w.MinusAllowlist) parts.Add("minus allowlist");
            return string.Join(", ", parts);
        }

        private static string TailWatches(JsonObject a)
        {
            string rule = a["rule"]?.GetValue<string>();
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 1440, 1, 24 * 60);
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 100, 1, 500);

            var hits = SpawnWatchService.ReadHits(rule, DateTime.UtcNow.AddMinutes(-minutes), max);
            if (hits.Count == 0)
                return $"No spawn-watch hits for {(string.IsNullOrEmpty(rule) ? "any rule" : $"'{rule}'")} " +
                       $"in the last {minutes} min. Hits land as rules match events at ingestion time — " +
                       "check list_watches for the defined rules.";
            var sb = new StringBuilder();
            foreach (var h in hits)
            {
                string stamp = h.TsUtc.ToLocalTime().ToString("HH:mm:ss");
                var line = $"{stamp}  [{h.Rule}]  PID {h.Pid}  {h.Image}" +
                           $"  ← {h.Parent}" +
                           (string.IsNullOrEmpty(h.Service) ? "" : $" ({h.Service})") +
                           (string.IsNullOrEmpty(h.CommandLine) ? "" : $" | {h.CommandLine}");
                if (line.Length > 400) line = line[..400] + "…";
                sb.AppendLine(line);
            }
            return sb.ToString();
        }

        private static string TraceAnalyze(JsonObject a)
        {
            int seconds = a["seconds"]?.GetValue<int>() ?? 0;
            string path = a["path"]?.GetValue<string>();

            try
            {
                if (seconds <= 0)
                {
                    string file = path;
                    if (string.IsNullOrEmpty(file))
                    {
                        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                               "AutoCommand", "captures");
                        file = Directory.Exists(dir)
                            ? Directory.GetFiles(dir, "*.jsonl").OrderByDescending(File.GetLastWriteTime).FirstOrDefault()
                            : null;
                    }
                    if (file == null || !File.Exists(file))
                        return "No capture file to analyze (none passed, none in the captures folder). " +
                               "Call again with seconds>0 to capture live.";
                    var result = TraceAnalyzer.Analyze(new[] { file });
                    return $"analyzed: {Path.GetFileName(file)}\n\n{result.Report}";
                }

                seconds = Math.Min(seconds, 120);
                string temp = Path.Combine(Path.GetTempPath(), $"agent-trace-{DateTime.Now:yyyyMMdd-HHmmss}.jsonl");
                using (var engine = new CaptureEngine(new CaptureOptions
                {
                    OutFile = temp,
                    PollMs = 1000,
                    Duration = TimeSpan.FromSeconds(seconds),
                }))
                {
                    var done = new ManualResetEventSlim(false);
                    engine.Completed += _ => done.Set();
                    engine.Start();
                    done.Wait(TimeSpan.FromSeconds(seconds + 10));
                }
                var analysis = TraceAnalyzer.Analyze(new[] { temp });
                try { File.Delete(temp); } catch { }
                return $"live capture {seconds}s (exit {analysis.Flags} flag(s)):\n\n{analysis.Report}";
            }
            catch (InvalidOperationException ex)
            {
                return "Capture could not start (another capture is likely running in the app): " + ex.Message;
            }
            catch (Exception ex)
            {
                return "trace_analyze failed: " + ex.Message;
            }
        }

        private static string LookupIp(JsonObject a)
        {
            string ip = a["ip"]?.GetValue<string>() ?? "";
            if (!System.Net.IPAddress.TryParse(ip, out _))
                return ToJson(new JsonObject { ["error"] = "'" + ip + "' is not an IP address" });

            bool force = a["force"] is JsonNode fb && fb.GetValue<bool>();
            var dns = DnsResolutionService.Instance;
            if (force) dns.ResolveNow(ip);   // urgent re-ask; the fresh answer lands in the shared cache

            EnsureFeedStarted();
            var blocked = BlockHitFeedService.Instance.BlockedIp(ip);
            var o = new JsonObject
            {
                ["ip"] = ip,
                ["hostname_or_org"] = dns.GetCachedHostname(ip),
                ["classification"] = IpClassifier.Classify(ip),
                ["microsoft_infra"] = IpClassifier.IsMicrosoftInfra(ip),
                ["resolve_state"] = dns.DescribeResolveState(ip),
                ["lookup"] = force ? "user-initiated (force)" : "cache / refresh pass",
                ["blocked"] = blocked != null,
            };
            if (blocked != null)
                o["blocked_rules"] = $"{blocked.EnabledRules}/{blocked.Rules} enabled";
            if (force)
                o["note"] = "Urgent re-lookup queued — call again in a few seconds for the fresh answer " +
                            "(it lands in the cache and every monitor row's tooltip).";
            return ToJson(o);
        }

        private static string ClassifyIp(JsonObject a)
        {
            string ip = a["ip"]?.GetValue<string>() ?? "";
            EnsureFeedStarted();
            var blocked = BlockHitFeedService.Instance.BlockedIp(ip);
            var o = new JsonObject
            {
                ["ip"] = ip,
                ["classification"] = IpClassifier.Classify(ip),
                ["microsoft_infra"] = IpClassifier.IsMicrosoftInfra(ip),
                ["block_warning"] = IpClassifier.WarningText(ip),
                ["blocked"] = blocked != null,
            };
            if (blocked != null)
            {
                o["blocked_rules"] = $"{blocked.EnabledRules}/{blocked.Rules} enabled";
                o["blocked_class"] = blocked.Class;
                o["blocked_since"] = blocked.Created?.ToString("yyyy-MM-dd HH:mm") ?? "unknown (legacy rule)";
                o["note"] = "On AutoCommand's blocked list — the AC-BLOCK firewall rules drop connects " +
                            "silently at the kernel (instant access-denied). See list_recent_block_hits " +
                            "for which processes are hitting it and check_host for the site-level picture.";
            }
            return ToJson(o);
        }

        /// <summary>Start() is idempotent — every blocked-list reader ensures the feed lives.</summary>
        private static void EnsureFeedStarted()
        {
            try { BlockHitFeedService.Instance.Start(); } catch { }
        }

        private static string AuditBlockDuplicates()
        {
            var inv = FirewallService.Instance.GetBlockedInventoryAsync().GetAwaiter().GetResult();
            var rows = new JsonArray();
            int flagged = 0, totalDups = 0;
            foreach (var t in inv)
            {
                if (t.DuplicateRules <= 0) continue;
                flagged++;
                totalDups += t.DuplicateRules;
                rows.Add(new JsonObject
                {
                    ["kind"] = t.Kind,
                    ["target"] = t.Target,
                    ["path"] = t.Kind == "app" ? t.AppPath : null,
                    ["ip"] = t.Kind == "ip" ? t.Ip : null,
                    ["rules"] = t.Rules,
                    ["duplicates"] = t.DuplicateRules,
                });
            }
            return ToJson(new JsonObject
            {
                ["type"] = "block_duplicates",
                ["targets_with_duplicates"] = flagged,
                ["duplicate_rules"] = totalDups,
                ["verdict"] = totalDups == 0
                    ? "clean — every target carries exactly its intended rule shapes"
                    : $"residue found — {totalDups} duplicate rule(s) on {flagged} target(s); retire via the Rules tab's 'Clean duplicates'",
                ["rows"] = rows,
            });
        }

        private static string ListBlocks(JsonObject a)
        {
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 60, 1, 24 * 60);
            EnsureFeedStarted();
            var inv = FirewallService.Instance.GetBlockedInventoryAsync().GetAwaiter().GetResult();
            var feedHits = BlockHitFeedService.Instance.FeedHitsByIp(minutes);

            var arr = new JsonArray();
            foreach (var t in inv)
            {
                var gate = BlockGateService.Instance.Find(
                    t.Kind == "ip" ? "ip" : "proc",
                    t.Kind == "ip" ? t.Ip : t.AppPath);
                int h = t.Kind == "ip" && feedHits.TryGetValue(t.Ip, out int c) ? c : 0;
                string note = string.IsNullOrEmpty(t.Description) ? "" :
                    (t.Description.Length > 160 ? t.Description[..160] + "…" : t.Description);
                if (t.StaleRules > 0)
                    note = $"STALE ({t.StaleRules} rule path gone — {t.CoverageNote})" +
                           (note.Length > 0 ? " · " + note : "");
                arr.Add(new JsonObject
                {
                    ["target"] = t.Target,
                    ["kind"] = t.Kind,
                    ["class"] = t.Class,
                    ["rules"] = $"{t.EnabledRules}/{t.Rules} enabled",
                    ["stale_rules"] = t.StaleRules,
                    ["created"] = t.Created?.ToString("yyyy-MM-dd HH:mm") ?? "legacy",
                    [$"hits_{minutes}m"] = h,
                    ["gate_minutes_remaining"] = gate != null ? Math.Round(gate.RemainingMinutes, 1) : null,
                    ["note"] = note,
                });
            }
            var feed = BlockHitFeedService.Instance;
            return ToJson(new JsonObject
            {
                ["type"] = "blocked_inventory",
                ["targets"] = arr.Count,
                ["rows"] = arr,
                ["feed_inventory_refreshed_utc"] = feed.LastRefreshUtc == default ? null : feed.LastRefreshUtc.ToString("yyyy-MM-dd HH:mm:ss"),
            });
        }

        private static string ListRecentBlockHits(JsonObject a)
        {
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 60, 1, 1440);
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 50, 1, 200);
            string contains = a["contains"]?.GetValue<string>();
            EnsureFeedStarted();
            var feed = BlockHitFeedService.Instance;

            var aggs = feed.Aggregates(minutes, 200);
            if (!string.IsNullOrEmpty(contains))
                aggs = aggs.Where(x =>
                    (x.Process?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (x.Image?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (x.DestIp?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();

            if (aggs.Count == 0)
                return $"No blocked-connect hits in the last {minutes} min. The feed joins live Sysmon EID 3 " +
                       "attempts against the blocked inventory — it needs Sysmon installed and sees attempts " +
                       "from service start onward (history persists across restarts). " +
                       (feed.WatcherError != null ? $"Feed note: {feed.WatcherError}" :
                        "If you are chasing a 'site can't be reached' error, also try check_host.");

            var arr = new JsonArray();
            foreach (var x in aggs.Take(max))
            {
                // shared fields carry block-hits.jsonl's exact names
                // (Image, Pid, DestIp, DestPort, MatchKind); aggregate-only
                // extras (Process label, Attempts, FirstUtc, LastUtc) are
                // additive
                arr.Add(new JsonObject
                {
                    ["LastUtc"] = x.LastUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["Image"] = x.Image,
                    ["Pid"] = x.Pid,
                    ["DestIp"] = x.DestIp,
                    ["DestPort"] = x.DestPort,
                    ["MatchKind"] = x.MatchKind,   // ip = destination IP block, app = process block
                    ["Process"] = x.Process,
                    ["Attempts"] = x.Count,
                    ["FirstUtc"] = x.FirstUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                });
            }
            return ToJson(new JsonObject
            {
                ["type"] = "block_hits",
                ["window_minutes"] = minutes,
                ["rows"] = arr,
                ["row_count"] = arr.Count,
                ["inventory_refreshed_utc"] = feed.LastRefreshUtc == default ? null : feed.LastRefreshUtc.ToString("yyyy-MM-dd HH:mm:ss"),
            });
        }

        /// <summary>
        /// The containment proof — one call instead of a list_blocks ×
        /// get_monitor_rows × get_transmissions choreography with timestamp
        /// math the caller would have to get right. BlockContainmentVerifier
        /// holds the join; BlockContainmentReader gathers the live inputs,
        /// shared with the Blocks tab's containment column so the two views
        /// cannot disagree.
        /// </summary>
        private static string VerifyBlockContainment(JsonObject a)
        {
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 60, 1, 1440);
            string contains = a["contains"]?.GetValue<string>();

            // The same gatherer the Blocks tab's containment column uses —
            // screen and AI share one join, so they can never disagree.
            var snap = BlockContainmentReader.Take(minutes);
            var feed = BlockHitFeedService.Instance;
            var inv = snap.Inventory;

            var instances = snap.Instances;
            if (!string.IsNullOrEmpty(contains))
                instances = instances.Where(i =>
                    (i.Process?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (i.Image?.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    i.BlockedIps.Any(ip => ip.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();

            // Quiet roll-up: enabled blocks nothing is hitting — the rule
            // lives in the verifier (QuietTargets) so every consumer of the
            // containment join agrees on what "quiet" means.
            var quiet = new JsonArray();
            foreach (var t in BlockContainmentVerifier.QuietTargets(inv, instances))
            {
                quiet.Add(new JsonObject
                {
                    ["target"] = t.Target,
                    ["kind"] = t.Kind,
                    ["rules"] = $"{t.EnabledRules}/{t.Rules} enabled",
                    ["created"] = t.Created?.ToString("yyyy-MM-dd HH:mm") ?? "legacy",
                    ["state"] = "quiet",
                });
            }

            var arr = new JsonArray();
            foreach (var i in instances)
            {
                arr.Add(new JsonObject
                {
                    ["verdict"] = i.Verdict,
                    ["process"] = i.Process,
                    ["pid"] = i.Pid,
                    ["image"] = i.Image,
                    ["blocked_kind"] = i.AppBlocked ? "app" : "ip",
                    ["attempts"] = i.Attempts,
                    ["blocked_destinations"] = new JsonArray(i.BlockedIps.Select(ip => (JsonNode)ip).ToArray()),
                    ["first_utc"] = i.FirstUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["last_utc"] = i.LastUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["block_created_utc"] = i.T0.ToString("yyyy-MM-dd HH:mm:ss") +
                        (i.T0Approximate ? " (approximate — legacy rule, no provenance)" : ""),
                    ["live_sockets_to_blocked"] = new JsonArray(i.SocketEvidence.Select(e => (JsonNode)e).ToArray()),
                    ["flows_since_block"] = i.FlowsSinceT0,
                    ["bytes_since_block"] = i.BytesSinceT0,
                    ["pid_reused"] = i.PidReused,
                    ["note"] = i.Note,
                });
            }

            if (arr.Count == 0 && quiet.Count == 0)
                return $"Nothing to verify: no blocked-connect hits in the last {minutes} min and no enabled " +
                       "blocks in the inventory. " +
                       (feed.WatcherError != null ? $"Feed note: {feed.WatcherError}." :
                           "If a site is failing, try check_host; to see who is being blocked, list_recent_block_hits.");

            return ToJson(new JsonObject
            {
                ["type"] = "block_containment",
                ["window_minutes"] = minutes,
                ["instances"] = arr,
                ["quiet_targets"] = quiet,
                ["summary"] = new JsonObject
                {
                    ["leak"] = instances.Count(i => i.Verdict == BlockContainmentVerifier.Leak),
                    ["stale_flow"] = instances.Count(i => i.Verdict == BlockContainmentVerifier.StaleFlow),
                    ["contained"] = instances.Count(i => i.Verdict == BlockContainmentVerifier.Contained),
                    ["quiet_targets"] = quiet.Count,
                },
                ["caveats"] = "EID 3 records attempts, never outcomes; the archive only holds TLS flows over " +
                              "10 KB that decrypted or pushed upstream — absence is strong evidence, not " +
                              "wire-level proof. Sub-threshold, UDP and DNS traffic need trace_analyze. " +
                              "Sockets carry no creation time: 'predates the block' means the owning process " +
                              "started before the rule was created — the honest bound the kernel table gives.",
                ["inventory_refreshed_utc"] = feed.LastRefreshUtc == default ? null : feed.LastRefreshUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                ["feed_note"] = string.IsNullOrEmpty(snap.Note) ? null : snap.Note,
            });
        }

        /// <summary>
        /// Site-level blocked triage: resolve → per-IP verdict → plain English.
        /// The error users actually see ("This site can't be reached") is Chrome's
        /// rendering of an instantly-denied connect — so the verdict keys off
        /// blocked-list membership, not range classification.
        /// </summary>
        private static string CheckHost(JsonObject a)
        {
            string host = a["host"]?.GetValue<string>() ?? "";
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 120, 1, 1440);
            if (string.IsNullOrWhiteSpace(host))
                return "check_host: 'host' is required.";
            host = host.Trim();
            try { if (host.Contains("://")) host = new Uri(host).Host; }   // tolerate pasted URLs
            catch { /* not URL-shaped — treat as a bare hostname */ }

            EnsureFeedStarted();
            var feed = BlockHitFeedService.Instance;

            System.Net.IPAddress[] addrs;
            try { addrs = System.Net.Dns.GetHostAddresses(host); }
            catch (Exception ex)
            {
                return ToJson(new JsonObject
                {
                    ["host"] = host,
                    ["verdict"] = $"DNS resolution failed ({ex.Message}) — the hostname itself is unreachable " +
                                  "before any firewall decision. Not an AutoCommand block.",
                });
            }

            var recent = feed.Recent(minutes, 2000)
                .Where(h => h.MatchKind == "ip")
                .GroupBy(h => h.DestIp)
                .ToDictionary(g => g.Key, g => g.Count());

            var rows = new JsonArray();
            var blockedAddrs = new List<string>();
            foreach (var addr in addrs)
            {
                string ip = addr.ToString();
                var b = feed.BlockedIp(ip);
                recent.TryGetValue(ip, out int hits);
                if (b != null) blockedAddrs.Add(ip);
                rows.Add(new JsonObject
                {
                    ["ip"] = ip,
                    ["classification"] = IpClassifier.Classify(ip),
                    ["blocked"] = b != null,
                    ["blocked_since"] = b?.Created?.ToString("yyyy-MM-dd HH:mm"),
                    [$"blocked_attempts_{minutes}m"] = hits,
                });
            }

            string verdict;
            if (blockedAddrs.Count > 0)
                verdict = $"{host} resolves to {addrs.Length} address(es); {blockedAddrs.Count} are on " +
                          "AutoCommand's blocked list. Connects to those fail INSTANTLY with access-denied " +
                          "(kernel-level firewall block), which browsers show as 'This site can't be reached'. " +
                          "Because blocks are per-IP and this host rotates addresses, the site may work from " +
                          "other networks or fail intermittently. Open a temporary gate via open_gate, or manage the block in the Blocks tab.";
            else if (rows.Any(r => ((JsonNode)r!["blocked_attempts_" + minutes + "m"]).GetValue<int>() > 0))
                verdict = "No currently-resolved address is blocked, but blocked-connect attempts were seen " +
                          "recently — DNS rotation likely served a blocked address earlier. List the feed with " +
                          "list_recent_block_hits and intersect with this host's address pool.";
            else
                verdict = $"No AutoCommand block matches any of {host}'s {addrs.Length} resolved address(es) " +
                          $"and no blocked-connect attempts were seen in the last {minutes} min — if the site " +
                          "still fails, the cause is upstream (network, DNS filtering on the router, or the " +
                          "remote end), not a local block rule.";

            return ToJson(new JsonObject
            {
                ["type"] = "check_host",
                ["host"] = host,
                ["rows"] = rows,
                ["verdict"] = verdict,
            });
        }

        /// <summary>Read-only archive query — metadata only by design; the
        /// decrypted bodies stay on disk for the user to view in the tab.</summary>
        private static string GetTransmissions(JsonObject a)
        {
            int max = Math.Clamp(a["max"]?.GetValue<int>() ?? 50, 1, 200);
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 1440, 1, 60 * 24 * 30);
            int? pid = a["pid"] is JsonNode p ? p.GetValue<int>() : null;
            string contains = a["contains"]?.GetValue<string>();

            var rows = TransmissionsArchiveService.Read(max, pid, contains, DateTime.UtcNow.AddMinutes(-minutes));
            if (rows.Count == 0)
                return $"No archived transmissions matching the filter (last {minutes} min). " +
                       "Rows appear when the Transmissions tab has watched a TLS flow that decrypted " +
                       "or pushed more than 10 KB upstream.";

            var arr = new JsonArray();
            foreach (var r in rows)
            {
                arr.Add(new JsonObject
                {
                    ["ts_utc"] = r.TsUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["pid"] = r.Pid,
                    ["process"] = r.ProcessDisplay,
                    ["destination"] = r.ServerEndpoint,
                    ["sni"] = r.Sni,
                    ["provider"] = r.ProviderAndCountry,
                    ["tls"] = r.TlsVersion,
                    ["status"] = r.Status,
                    ["client_bytes"] = r.ClientBytes,
                    ["server_bytes"] = r.ServerBytes,
                    ["client_app_bytes"] = r.ClientAppBytes,
                    ["server_app_bytes"] = r.ServerAppBytes,
                    ["big_upload"] = r.BigUpload,
                    ["has_content_on_disk"] = r.HasContent,
                    ["sha256"] = r.Sha256,
                    ["message_count"] = r.MessageCount,
                    ["content_kinds"] = r.ContentKinds,
                });
            }
            return ToJson(new JsonObject { ["type"] = "transmissions", ["rows"] = arr, ["row_count"] = arr.Count });
        }

        /// <summary>
        /// diagnose_site: the tab's whole pipeline over the bridge — same
        /// engines, same caps, same honest verdicts. The bridge handler runs
        /// on a background thread; DNS sampling is tightened to 3s so the
        /// whole call lands around 30 seconds.
        /// </summary>
        private static string DiagnoseSite(JsonObject a)
        {
            string host = a["host"]?.GetValue<string>()?.Trim().TrimEnd('.');
            if (string.IsNullOrEmpty(host)) return "Missing 'host' — the hostname to diagnose.";
            int minutes = Math.Clamp(a["minutes"]?.GetValue<int>() ?? 1440, 1, 60 * 24 * 30);

            var rows = RowAdapter.ToRows(TransmissionsArchiveService.Read(4000, null, null, DateTime.UtcNow.AddMinutes(-minutes)));
            var siteRows = rows.Where(r => string.Equals(r.Sni, host, StringComparison.OrdinalIgnoreCase)).ToList();
            var all = SiteFingerprintService.AllFingerprints(rows);
            var fingerprint = SiteFingerprintService.Fingerprint(
                siteRows, SiteFingerprintService.BaselineEdgeCount(all));

            var controls = SiteFingerprintService.TopHosts(rows, 10)
                .Where(h => !string.Equals(h, host, StringComparison.OrdinalIgnoreCase))
                .Take(SiteProbeService.MaxControlHosts)
                .ToList();
            if (controls.Count == 0) controls = new List<string> { "example.com" };

            SiteProbeReport report;
            try
            {
                report = SiteProbeService.Shared.RunAsync(
                    host,
                    fingerprint.Edges.Select(e => e.Ip),
                    controls,
                    progress: null,
                    CancellationToken.None,
                    dnsSampleInterval: TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
            }
            catch (ArgumentException ex) { return ex.Message; }

            // Dependency pass — same engine as the tab: were any of the
            // page's other hosts silently blocked during this browser's
            // recorded visits? Blocked connects carry no hostname, so only
            // this join can see them. Degrades to null, never throws.
            Report dep = null;
            try
            {
                BlockHitFeedService.Instance.Start();
                dep = DependencyBlockService.AnalyzeLiveAsync(host, minutes, null, System.Threading.CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch { dep = null; }

            var verdict = SiteVerdictService.Decide(fingerprint, report, dep);

            var edgeArr = new JsonArray();
            foreach (var e in report.Edges)
                edgeArr.Add(new JsonObject
                {
                    ["ip"] = e.Ip,
                    ["tcp_ms"] = e.TcpConnectMs,
                    ["tcp_error"] = e.TcpError,
                    ["tls_default_ms"] = e.TlsDefaultMs,
                    ["tls_default_version"] = e.TlsDefaultVersion,
                    ["tls_default_error"] = e.TlsDefaultError,
                    ["tls_plain_ms"] = e.TlsPlainMs,
                    ["tls_plain_version"] = e.TlsPlainVersion,
                    ["tls_plain_error"] = e.TlsPlainError,
                });

            var controlArr = new JsonArray();
            foreach (var c in report.Controls)
                controlArr.Add(new JsonObject
                {
                    ["host"] = c.Host,
                    ["tcp_ms"] = c.TcpConnectMs,
                    ["tls_ms"] = c.TlsMs,
                    ["error"] = c.Error,
                });

            var evidenceArr = new JsonArray();
            foreach (var line in verdict.Evidence) evidenceArr.Add(line);

            var signalArr = new JsonArray();
            foreach (var s in fingerprint.Signals) signalArr.Add(s);

            var opsArr = new JsonArray();
            foreach (var op in report.Operations.Take(60))
                opsArr.Add($"[{op.Kind}] {op.Detail}");

            var ipArr = new JsonArray();
            foreach (var ip in report.Dns.DistinctIps) ipArr.Add(ip);

            var root = new JsonObject
            {
                ["type"] = "site_diagnosis",
                ["host"] = host,
                ["verdict"] = new JsonObject
                {
                    ["kind"] = verdict.Kind.ToString(),
                    ["headline"] = verdict.Headline,
                    ["next_step"] = verdict.NextStep,
                    ["evidence"] = evidenceArr,
                },
                ["fingerprint"] = new JsonObject
                {
                    ["conversations"] = fingerprint.Conversations,
                    ["distinct_edges"] = fingerprint.Edges.Count,
                    ["burst_windows"] = fingerprint.BurstWindows,
                    ["window_local"] = fingerprint.SpanDisplay,
                    ["signals"] = signalArr,
                },
                ["probes"] = new JsonObject
                {
                    ["dns_samples"] = report.Dns.Samples.Count,
                    ["dns_distinct_ips"] = ipArr,
                    ["dns_rotated"] = report.Dns.AnswerRotated,
                    ["edges"] = edgeArr,
                    ["controls"] = controlArr,
                },
                ["operations"] = opsArr,
            };

            if (dep != null && (dep.InWindow.Count > 0 || dep.Nearby.Count > 0 || dep.Rotations.Count > 0))
            {
                var depArr = new JsonArray();
                foreach (var h in dep.InWindow.Concat(dep.Nearby))
                {
                    var served = new JsonArray();
                    foreach (var sh in h.ServedHosts) served.Add(sh);
                    depArr.Add(new JsonObject
                    {
                        ["ip"] = h.Ip,
                        ["process"] = h.Process,
                        ["attempts"] = h.Attempts,
                        ["first_utc"] = h.FirstUtc,
                        ["last_utc"] = h.LastUtc,
                        ["in_visit_window"] = dep.InWindow.Contains(h),
                        ["served_hosts"] = served,
                        ["blocked_since"] = h.BlockedSince,
                        ["block_class"] = h.BlockClass,
                    });
                }
                var rotArr = new JsonArray();
                foreach (var f in dep.Rotations)
                    rotArr.Add(new JsonObject
                    {
                        ["host"] = f.Host,
                        ["blocked_addresses"] = f.BlockedAddresses,
                        ["total_addresses"] = f.TotalAddresses,
                    });
                root["dependency_blocks"] = new JsonObject
                {
                    ["hits"] = depArr,
                    ["rotation"] = rotArr,
                    ["visit_times_utc"] = dep.VisitTimesUtc.Count,
                };
            }

            return ToJson(root);
        }

        // ── mutating handlers (already user-confirmed when reached) ───────

        // ── block gates: time-boxed unblocks the user confirmed ──────────

        private sealed record GateResolution(bool Ok, string Kind, string Key, string Display,
            int Rules, List<string> Candidates, string Error);

        /// <summary>Resolve ONE gate target from the live block inventory.
        /// IPs match exactly; process targets match a full path exactly or
        /// an image name — ambiguity returns candidates instead of acting
        /// ("specific" is the contract, enforced).</summary>
        private static GateResolution ResolveGateTarget(string target)
        {
            target = (target ?? "").Trim();
            if (target.Length == 0)
                return new GateResolution(false, null, null, null, 0, null, "target is empty");

            var inv = FirewallService.Instance.GetBlockedInventoryAsync().GetAwaiter().GetResult();
            if (System.Net.IPAddress.TryParse(target, out var ip))
            {
                var m = inv.Where(t => t.Kind == "ip" &&
                                       string.Equals(t.Ip, ip.ToString(), StringComparison.OrdinalIgnoreCase)).ToList();
                if (m.Count == 0)
                    return new GateResolution(false, null, null, null, 0, null,
                        target + " is not on the blocked list - nothing to gate. See list_blocks.");
                return new GateResolution(true, "ip", m[0].Ip, m[0].Ip, m[0].Rules, null, null);
            }

            var apps = inv.Where(t => t.Kind == "app" && !string.IsNullOrEmpty(t.AppPath)).ToList();
            var exact = apps.Where(t => string.Equals(t.AppPath, target, StringComparison.OrdinalIgnoreCase)).ToList();
            var byName = apps.Where(t => string.Equals(System.IO.Path.GetFileName(t.AppPath), target,
                                                       StringComparison.OrdinalIgnoreCase)).ToList();
            var chosen = exact.Count > 0 ? exact : byName;
            if (chosen.Count == 0)
                return new GateResolution(false, null, null, null, 0, null,
                    "No blocked process matches '" + target + "'. Call list_blocks to see targets; " +
                    "use the full path when several share a name.");
            if (chosen.Count > 1)
                return new GateResolution(false, null, null, null, 0,
                    chosen.Take(8).Select(t => t.AppPath).ToList(),
                    "'" + target + "' matches " + chosen.Count + " blocked processes - be specific (full path).");
            return new GateResolution(true, "proc", chosen[0].AppPath, chosen[0].Target, chosen[0].Rules, null, null);
        }

        private static bool TryMinutes(JsonObject a, out int minutes, out string error)
        {
            minutes = 0;
            error = null;
            if (!int.TryParse(a["minutes"]?.ToString(), out minutes) ||
                !BlockGateService.AllowedMinutes.Contains(minutes))
            {
                error = "minutes must be one of [" + string.Join(", ", BlockGateService.AllowedMinutes) +
                        "] - pick the SHORTEST window your task needs; the gate closes itself.";
                return false;
            }
            return true;
        }

        private static string OpenGate(JsonObject a)
        {
            var target = a["target"]?.GetValue<string>();
            if (!TryMinutes(a, out int minutes, out string mErr))
                return ToJson(new JsonObject { ["error"] = mErr });
            string reason = a["reason"]?.GetValue<string>();
            bool dryRun = string.Equals(a["dry_run"]?.ToString(), "true", StringComparison.OrdinalIgnoreCase);

            var r = ResolveGateTarget(target);
            if (!r.Ok)
                return ToJson(new JsonObject { ["error"] = r.Error, ["candidates"] = ToJsonArray(r.Candidates) });

            var existing = BlockGateService.Instance.Find(r.Kind, r.Key);
            if (dryRun)
                return ToJson(new JsonObject
                {
                    ["target"] = r.Display,
                    ["kind"] = r.Kind,
                    ["rules_currently_enabled"] = r.Rules,
                    ["minutes"] = minutes,
                    ["would_close_at"] = DateTime.UtcNow.AddMinutes(minutes).ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
                    ["gate_open_now"] = existing != null,
                    ["remaining_minutes"] = existing != null ? Math.Round(existing.RemainingMinutes, 1) : null,
                    ["note"] = "No change made. A real call asks the user to confirm this exact target.",
                });

            // post-confirmation: persist the gate FIRST, then stop blocking
            var gate = BlockGateService.Instance.OpenGate(r.Kind, r.Key, r.Display, minutes, "mcp", reason);
            var targets = new[] { (r.Kind, r.Key) };
            var (matched, changed, firstError) = FirewallService.Instance.SetTargetsEnabledWithErrorAsync(targets, false).GetAwaiter().GetResult();
            if (matched == 0 || (changed == 0 && !string.IsNullOrEmpty(firstError)))
            {
                BlockGateService.Instance.ForgetTarget(r.Kind, r.Key);
                return ToJson(new JsonObject
                {
                    ["error"] = "Failed to disable firewall rules for '" + r.Display + "'" +
                                (!string.IsNullOrEmpty(firstError) ? ": " + firstError : " (no matching rules found)."),
                });
            }
            BlocksStore.SetStatuses(targets, "off", "mcp");
            BlockGateService.Instance.NotifyGateOpened(gate, "mcp");
            try { AgentBridgeService.Instance.LogActivity(
                "gate", "opened", $"{r.Display} for {minutes} min" +
                (string.IsNullOrEmpty(reason) ? "" : $" — {reason}")); } catch { }
            return ToJson(new JsonObject
            {
                ["gate_open"] = true,
                ["target"] = r.Display,
                ["minutes"] = minutes,
                ["closes_at"] = gate.ExpiresUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
                ["rules_disabled"] = changed + "/" + matched,
                ["note"] = "Traffic resumes now; blocking returns ON automatically at closes_at " +
                           "(or app exit). Call close_gate the moment your work is done.",
            });
        }

        private static string OpenGateConfirmText(JsonObject a)
        {
            if (!TryMinutes(a, out int minutes, out string mErr))
                return "GATE REQUEST - invalid as asked.\n" + mErr;
            var r = ResolveGateTarget(a["target"]?.GetValue<string>());
            if (!r.Ok)
                return "GATE REQUEST - cannot be fulfilled as asked:\n" + r.Error;
            var existing = BlockGateService.Instance.Find(r.Kind, r.Key);
            string reason = a["reason"]?.GetValue<string>();
            return "Open a " + minutes + "-minute block gate?\n\n" +
                   "Target: " + r.Display + "  (" + r.Kind + ", " + r.Rules + " rule(s) - blocking OFF for this target only)\n" +
                   (existing != null
                       ? "A gate is already open (" + Math.Round(existing.RemainingMinutes) + " min left) - this EXTENDS it.\n"
                       : "") +
                   "Auto-close: blocking returns ON at " +
                   DateTime.UtcNow.AddMinutes(minutes).ToLocalTime().ToString("HH:mm") + " (or when the app exits).\n" +
                   (string.IsNullOrEmpty(reason) ? "" : "Reason given: " + reason + "\n") +
                   "\nTraffic resumes immediately. Nothing is deleted; the gate closes itself.";
        }

        private static string CloseGate(JsonObject a)
        {
            var r = ResolveGateTarget(a["target"]?.GetValue<string>());
            if (!r.Ok)
                return ToJson(new JsonObject { ["error"] = r.Error, ["candidates"] = ToJsonArray(r.Candidates) });
            var existing = BlockGateService.Instance.Find(r.Kind, r.Key);
            if (existing == null)
                return ToJson(new JsonObject
                {
                    ["gate_open"] = false,
                    ["note"] = "No gate is open for that target - blocking was already restored (or never gated).",
                });
            BlockGateService.Instance.CloseAsync(r.Kind, r.Key, "mcp").GetAwaiter().GetResult();
            if (BlockGateService.Instance.Find(r.Kind, r.Key) != null)
            {
                return ToJson(new JsonObject
                {
                    ["gate_open"] = true,
                    ["target"] = r.Display,
                    ["error"] = "Failed to re-enable firewall rules after 3 attempts; gate stays queued for automatic retry.",
                });
            }
            try { AgentBridgeService.Instance.LogActivity(
                "gate", "closed (by agent)", $"{r.Display} — blocking restored"); } catch { }
            return ToJson(new JsonObject
            {
                ["gate_open"] = false,
                ["target"] = r.Display,
                ["note"] = "Gate closed early - blocking is back ON for this target.",
            });
        }

        private static JsonArray ToJsonArray(List<string> items)
        {
            if (items == null) return null;
            var arr = new JsonArray();
            foreach (var i in items) arr.Add(i);
            return arr;
        }


        // ── schema / description helpers ──────────────────────────────────

        private static JsonObject Schema(params (string Name, string Desc, bool Required)[] props)
        {
            var properties = new JsonObject();
            var required = new JsonArray();
            foreach (var (name, desc, req) in props)
            {
                bool isInt = name is "pid" or "minutes" or "eid" or "max" or "seconds" or "hours";
                bool isBool = name is "archive";
                properties[name] = new JsonObject
                {
                    ["type"] = isBool ? "boolean" : isInt ? "integer" : "string",
                    ["description"] = desc,
                };
                if (req) required.Add(name);
            }
            return new JsonObject
            {
                ["type"] = "object",
                ["properties"] = properties,
                ["required"] = required,
            };
        }

        // ── Phone Home / Traces (read-only, backed by TraceMetricsService) ─

        private static string GetPhoneHomeCards()
        {
            var arr = new JsonArray();
            foreach (var key in ServiceCatalog.CuratedPhoneHomeKeys)
            {
                try
                {
                    var snap = TraceMetricsService.Compute(TraceMetricsService.Match.ForService(key));
                    var card = SnapshotJson(snap);
                    ServiceCatalog.TryGet(key, out var info);
                    card.Insert(0, "service", key);
                    if (info != null)
                    {
                        card["display_name"] = info.DisplayName;
                        card["story"] = info.PhoneHomeStory ?? info.Description;
                        card["impact_if_blocked"] = info.Impact.ToString();
                        card["normal_max_per_hour"] = info.NormalMaxPerHour;
                    }
                    arr.Add(card);
                }
                catch (Exception ex)
                {
                    arr.Add(new JsonObject { ["service"] = key, ["error"] = ex.Message });
                }
            }
            return ToJson(new JsonObject { ["cards"] = arr });
        }

        private static string ListTraceProjects()
        {
            var arr = new JsonArray();
            foreach (var p in TraceProjectStore.Load())
                arr.Add(new JsonObject
                {
                    ["name"] = p.Name,
                    ["match_process"] = p.MatchProcess,
                    ["service_key"] = p.ServiceKey,
                    ["notes"] = p.Notes,
                });
            return ToJson(new JsonObject
            {
                ["projects"] = arr,
                ["directory"] = TraceProjectStore.ProjectsDirectory,
            });
        }

        private static string GetTraceProject(JsonObject a)
        {
            string name = a["name"]?.GetValue<string>() ?? "";
            var project = TraceProjectStore.Load()
                .FirstOrDefault(p => p.Name.Equals(name, System.StringComparison.OrdinalIgnoreCase));
            if (project == null)
                return $"No trace project named '{name}' — call list_trace_projects for the exact names.";

            var match = string.IsNullOrWhiteSpace(project.ServiceKey)
                ? TraceMetricsService.Match.ForProcess(project.MatchProcess)
                : TraceMetricsService.Match.ForService(project.ServiceKey);
            var snap = TraceMetricsService.Compute(match);
            var o = SnapshotJson(snap);
            o.Insert(0, "name", project.Name);
            o["match_process"] = project.MatchProcess;
            o["service_key"] = project.ServiceKey;
            o["notes"] = project.Notes;
            return ToJson(o);
        }

        private static string RunTrace(JsonObject a)
        {
            string process = a["process"]?.GetValue<string>();
            string service = a["service"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(process) && string.IsNullOrWhiteSpace(service))
                return "Give either process (image name, wildcards ok) or service (svchost SCM service key).";
            int hours = 24;
            if (a["hours"] != null)
            {
                try { hours = Math.Clamp(a["hours"].GetValue<int>(), 1, 24); } catch { }
            }
            var match = string.IsNullOrWhiteSpace(service)
                ? TraceMetricsService.Match.ForProcess(process)
                : TraceMetricsService.Match.ForService(service);
            var snap = TraceMetricsService.Compute(match, hours);
            var o = SnapshotJson(snap);
            o.Insert(0, "match", match.Describe());
            o["window_hours"] = hours;
            return ToJson(o);
        }

        private static string InvestigateProcess(JsonObject a)
        {
            string process = a["process"]?.GetValue<string>();
            int? pid = null;
            if (a["pid"] != null) { try { pid = a["pid"].GetValue<int>(); } catch { } }
            if (pid == null && string.IsNullOrWhiteSpace(process))
                return "Give either process (image name, wildcards ok) or pid — a pid adds the " +
                       "provenance half, a name alone still gets the traffic picture.";
            int hours = 6;
            if (a["hours"] != null)
            {
                try { hours = Math.Clamp(a["hours"].GetValue<int>(), 1, 24); }
                catch { try { hours = Math.Clamp(int.Parse(a["hours"].GetValue<string>()), 1, 24); } catch { } }
            }
            try
            {
                var inv = ProcessInvestigationService.Investigate(process, pid, hours);
                var o = InvestigationJson(inv);
                o["report_text"] = ProcessInvestigationService.BuildReportText(inv);
                return ToJson(o);
            }
            catch (Exception ex) { return $"Investigation failed: {ex.Message}"; }
        }

        private static JsonObject InvestigationJson(ProcessInvestigationService.Investigation inv)
        {
            var o = new JsonObject
            {
                ["type"] = "process_investigation",
                ["subject"] = inv.Requested,
                ["pid"] = inv.RequestedPid,
                ["image"] = inv.ImageName,
                ["window_hours"] = inv.WindowHours,
                ["verdict"] = new JsonObject
                {
                    ["kind"] = inv.Kind.ToString(),
                    ["headline"] = inv.VerdictHeadline,
                    ["detail"] = inv.VerdictDetail,
                },
            };

            if (inv.Provenance != null)
            {
                var p = inv.Provenance;
                o["provenance"] = new JsonObject
                {
                    ["pid"] = p.Pid,
                    ["alive"] = p.Alive,
                    ["name"] = p.Name,
                    ["image"] = p.ExePath,
                    ["owner"] = p.Owner,
                    ["started"] = p.Created?.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["command_line"] = p.CommandLine,
                    ["verdict"] = p.Verdict,
                    ["verdict_detail"] = p.VerdictDetail,
                    ["recycled"] = p.Recycled,
                    ["current_owner"] = p.CurrentOwnerSummary,
                    ["warnings"] = new JsonArray(p.Warnings.Select(w => (JsonNode)w).ToArray()),
                };
            }

            if (inv.Trace != null)
            {
                var t = inv.Trace;
                var dests = new JsonArray();
                foreach (var d in t.Destinations)
                    dests.Add(new JsonObject
                    {
                        ["ip"] = d.Ip, ["port"] = d.Port, ["connects"] = d.Count,
                        ["classification"] = d.Classification,
                    });
                o["traffic"] = new JsonObject
                {
                    ["connects_per_hour"] = t.ConnectsPerHour,
                    ["connects_in_window"] = t.ConnectsLast24H,
                    ["connects_last_1h"] = t.ConnectsLast1H,
                    ["spawns_in_window"] = t.SpawnsLast24H,
                    ["live_connections"] = t.LiveConnectionCount,
                    ["destinations"] = dests,
                    ["beacon"] = t.BeaconVerdict == null ? null : t.BeaconVerdict + " — " + t.BeaconDetail,
                    ["tls_tx_bytes"] = t.BytesAttributable ? t.TxBytes24H : null,
                    ["tls_rx_bytes"] = t.BytesAttributable ? t.RxBytes24H : null,
                    ["archive_note"] = t.ArchiveNote,
                };
            }

            var hits = new JsonArray();
            foreach (var h in inv.BlockHits.Take(10))
                hits.Add(new JsonObject
                {
                    ["process"] = h.Process, ["dest"] = $"{h.DestIp}:{h.DestPort}",
                    ["count"] = h.Count, ["match_kind"] = h.MatchKind,
                    ["last_utc"] = h.LastUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                });
            o["block_hits"] = new JsonObject
            {
                ["count_in_window"] = inv.BlockHitCount,
                ["aggregates"] = hits,
            };

            var ev = new JsonArray(inv.Evidence.Select(e => (JsonNode)e).ToArray());
            o["evidence"] = ev;
            return o;
        }

        private static JsonObject SnapshotJson(TraceMetricsService.Snapshot snap)
        {
            var dests = new JsonArray();
            foreach (var d in snap.Destinations)
                dests.Add(new JsonObject
                {
                    ["ip"] = d.Ip, ["port"] = d.Port, ["connects"] = d.Count,
                    ["classification"] = d.Classification,
                });
            var live = new JsonArray();
            foreach (var c in snap.Live)
                live.Add(new JsonObject
                {
                    ["pid"] = c.Pid, ["remote"] = c.Remote, ["classification"] = c.Classification,
                });
            return new JsonObject
            {
                ["connects_per_hour"] = snap.ConnectsPerHour,
                ["connects_24h"] = snap.ConnectsLast24H,
                ["connects_last_1h"] = snap.ConnectsLast1H,
                ["spawns_24h"] = snap.SpawnsLast24H,
                ["live_connections"] = snap.LiveConnectionCount,
                ["destinations"] = dests,
                ["live"] = live,
                ["beacon"] = snap.BeaconVerdict == null ? null
                    : snap.BeaconVerdict + " — " + snap.BeaconDetail,
                ["tls_tx_bytes_24h"] = snap.BytesAttributable ? snap.TxBytes24H : null,
                ["tls_rx_bytes_24h"] = snap.BytesAttributable ? snap.RxBytes24H : null,
                ["identity"] = snap.IdentityNote,
                ["verdict"] = snap.VerdictText,
                ["note"] = snap.ArchiveNote,
            };
        }

        // ── shields-up tools (vendored ShieldsUp.Core) ────────────────────

        private static string GetShieldsUpStatus()
        {
            var o = new JsonObject { ["type"] = "shieldsup_status" };

            try
            {
                var sstp = AttackSurfaceService.GetSstpStatus();
                o["sstp"] = new JsonObject
                {
                    ["active"] = sstp.Active,
                    ["service_state"] = sstp.StatusText,
                    ["start_mode"] = sstp.StartMode,
                };
            }
            catch (Exception ex) { o["sstp"] = Err(ex); }

            try
            {
                string hosted = AttackSurfaceService.GetHostedNetworkStatus();
                o["wifi_direct_hosted_network"] = hosted;
                o["wifi_direct_adapter_present"] = PrivacyService.IsWifiDirectAdapterPresent();
            }
            catch (Exception ex) { o["wifi_direct_hosted_network"] = Err(ex); }

            // legacy name-resolution doors — config + live chatter in one
            // place: the same per-port attempt counts that diagnosed the
            // PID 4 NetBIOS broadcasts
            try
            {
                var chatter = NameResolutionChatter();
                var llmnr = NameResolutionDoors.GetLlmnrStatus();
                o["llmnr"] = new JsonObject
                {
                    ["open"] = llmnr.Open,
                    ["evidence"] = llmnr.Evidence,
                    ["chatter_24h"] = chatter.GetValueOrDefault(5355, 0),
                };
            }
            catch (Exception ex) { o["llmnr"] = Err(ex); }
            try
            {
                var chatter = NameResolutionChatter();
                var nb = NameResolutionDoors.GetNetbiosStatus();
                o["netbios"] = new JsonObject
                {
                    ["state"] = nb.State.ToString().ToLowerInvariant(),
                    ["interfaces_disabled"] = nb.Disabled,
                    ["interfaces_total"] = nb.Total,
                    ["evidence"] = nb.Evidence,
                    ["chatter_24h"] = chatter.GetValueOrDefault(137, 0),
                };
            }
            catch (Exception ex) { o["netbios"] = Err(ex); }
            try
            {
                var chatter = NameResolutionChatter();
                var mdns = NameResolutionDoors.GetMdnsStatus();
                o["mdns"] = new JsonObject
                {
                    ["open"] = mdns.Open,
                    ["evidence"] = mdns.Evidence,
                    ["chatter_24h"] = chatter.GetValueOrDefault(5353, 0),
                };
            }
            catch (Exception ex) { o["mdns"] = Err(ex); }

            try { o["kernel_debug_on"] = AttackSurfaceService.IsKernelDebugOn(); }
            catch (Exception ex) { o["kernel_debug_on"] = Err(ex); }

            try
            {
                var (running, total) = PrivacyService.GetVpnStatus();
                o["vpn_services"] = new JsonObject
                {
                    ["running"] = running,
                    ["total"] = total,
                    ["names"] = new JsonArray(PrivacyService.VpnServices.Select(s => (JsonNode)s).ToArray()),
                };
            }
            catch (Exception ex) { o["vpn_services"] = Err(ex); }

            try { o["wan_miniports_present"] = AttackSurfaceService.ListWanMiniports().Count; }
            catch (Exception ex) { o["wan_miniports_present"] = Err(ex); }

            // hotpatch monitoring boot task — present=false means the build
            // has no hotpatching at all (a closed door by absence, reported
            // honestly instead of folding into "disabled")
            try
            {
                var hotpatch = AttackSurfaceService.GetHotpatchStatus();
                o["hotpatch_monitoring"] = new JsonObject
                {
                    ["present"] = hotpatch.Present,
                    ["enabled"] = hotpatch.Enabled,
                };
            }
            catch (Exception ex) { o["hotpatch_monitoring"] = Err(ex); }

            try
            {
                o["tamper_protection_on"] = PrivacyService.IsTamperProtectionOn();
                o["ipv6_disabled"] = HardeningService.IsIpv6Disabled();
                o["lsa_protected"] = HardeningService.IsLsaProtected();
                o["uac_strict"] = HardeningService.IsUacStrict();
            }
            catch (Exception ex) { o["hardening"] = Err(ex); }

            try
            {
                var hosts = HardeningService.AuditHostsFile();
                o["hosts_file"] = new JsonObject
                {
                    ["exists"] = hosts.Exists,
                    ["active_rules"] = hosts.ActiveRules,
                    ["suspicious_non_loopback"] = hosts.Suspicious,
                };
            }
            catch (Exception ex) { o["hosts_file"] = Err(ex); }

            try
            {
                var rows = new JsonArray();
                foreach (var s in _telemetryStatuses())
                    rows.Add(new JsonObject
                    {
                        ["rule_id"] = s.Rule.Id,
                        ["vendor"] = s.Rule.AppName,
                        ["state"] = s.StateText,
                        ["evidence"] = s.Evidence,
                    });
                o["telemetry_rules"] = rows;
                o["telemetry_note"] = "pass rule_id to opt_out_telemetry (revert=true to restore the saved previous " +
                                  "setting). switch_kind=feature rules turn the fetching off at the source — " +
                                  "expect 'reduced', not network-stopped; only verify_block_containment proves " +
                                  "zero bytes.";
            }
            catch (Exception ex) { o["telemetry_rules"] = Err(ex); }

            return ToJson(o);

            static JsonObject Err(Exception ex) => new() { ["error"] = ex.Message };
        }

        /// <summary>The Startup &amp; Tasks surface for the bridge: logon
        /// items and scheduled tasks, read-only. Registry reads are local
        /// (Agent.Core must not lean on the WPF app's helpers).</summary>
        private static string GetStartupStatus()
        {
            var o = new JsonObject { ["type"] = "startup_status" };
            try
            {
                var logon = new JsonArray();
                foreach (var (hive, label) in new[]
                {
                    (Microsoft.Win32.Registry.CurrentUser, "HKCU Run"),
                    (Microsoft.Win32.Registry.LocalMachine, "HKLM Run"),
                })
                {
                    using var key = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                    if (key == null) continue;
                    foreach (var name in key.GetValueNames())
                        logon.Add(new JsonObject
                        {
                            ["name"] = name,
                            ["location"] = label,
                            ["command"] = key.GetValue(name)?.ToString() ?? "",
                            ["disabled_by_autocommand"] = ShieldsUp.Core.Services.StartupSurfaceService.HasLogonSnapshot(label, name),
                        });
                }
                o["logon_items"] = logon;
            }
            catch (Exception ex) { o["logon_items"] = new JsonObject { ["error"] = ex.Message }; }

            try
            {
                var tasks = AutoCommand.Forensics.Core.TaskSchedulerService.Instance.LoadTasksAsync().GetAwaiter().GetResult();
                var thirdParty = new JsonArray();
                int inbox = 0;
                foreach (var t in tasks)
                {
                    if (ShieldsUp.Core.Services.StartupSurfaceService.ClassifyTask(t.TaskPath) == ShieldsUp.Core.Services.StartupSurfaceService.TaskGroup.Inbox)
                    { inbox++; continue; }
                    thirdParty.Add(new JsonObject
                    {
                        ["name"] = t.TaskName,
                        ["path"] = t.TaskPath,
                        ["state"] = t.State,
                        ["action"] = t.Action,
                        ["user"] = t.User,
                    });
                }
                o["third_party_tasks"] = thirdParty;
                o["windows_inbox_task_count"] = inbox;
                o["note"] = "Classification is location-based (\\Microsoft\\Windows\\ = inbox; everything else " +
                            "third-party) — no signature claims. Mutating (disable/re-enable) stays in the app's Shields Up tab.";
            }
            catch (Exception ex) { o["third_party_tasks"] = new JsonObject { ["error"] = ex.Message }; }

            return ToJson(o);
        }

        /// <summary>Legacy-name-resolution chatter: dropped-attempt counts by
        /// port (137 NBNS, 5355 LLMNR, 5353 mDNS) over 24 h, from the live
        /// block-hit feed. Attempts, never bytes — the honest currency.</summary>
        private static Dictionary<int, int> NameResolutionChatter()
        {
            var counts = new Dictionary<int, int>();
            try
            {
                foreach (var a in AutoCommand.Contain.Core.BlockHitFeedService.Instance.Aggregates(24 * 60, 300))
                {
                    if (a.DestPort is 137 or 5355 or 5353)
                        counts[a.DestPort] = counts.GetValueOrDefault(a.DestPort, 0) + a.Count;
                }
            }
            catch { /* feed not running → zero chatter is the honest answer */ }
            return counts;
        }

        private static List<TelemetryRuleStatus> _telemetryStatuses() =>
            new TelemetryRulesService().EvaluateAllAsync().GetAwaiter().GetResult();

        private static string CloseShieldsUpDoor(JsonObject a)
        {
            string door = a["door"]?.GetValue<string>()?.Trim().ToLowerInvariant() ?? "";
            try
            {
                switch (door)
                {
                    case "sstp":
                        var failures = AttackSurfaceService.DisableSstp();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = failures is not { Count: > 0 },
                            ["result"] = failures is { Count: > 0 }
                                ? "service stopped+disabled; some miniports failed: " + string.Join(", ", failures)
                                : "SSTP service stopped+disabled; miniport adapters disabled (reversible in the tab).",
                        });
                    case "hostednetwork":
                        AttackSurfaceService.DisallowHostedNetwork();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = true,
                            ["result"] = "hosted network stopped and disallowed (reversible: netsh mode=allow).",
                        });
                    case "vpnservices":
                        PrivacyService.DisableVpnServices();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = true,
                            ["result"] = "RasMan/IKEEXT/PolicyAgent/RemoteAccess stopped+disabled (reversible in the tab).",
                        });
                    case "kdnet":
                        AttackSurfaceService.SetKernelDebug(false);
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = true,
                            ["result"] = "kernel debug turned off (effective at next boot).",
                        });
                    case "wifidirect":
                        int acted = PrivacyService.SetWifiDirectAdaptersEnabled(false);
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = acted > 0,
                            ["result"] = $"{acted} Wi-Fi Direct adapter(s) disabled (reversible in the tab).",
                        });
                    case "llmnr":
                        var llmnrFails = NameResolutionDoors.DisableLlmnr();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = llmnrFails.Count == 0,
                            ["result"] = llmnrFails.Count == 0
                                ? "EnableMulticast=0 written (snapshotted; reversible in the tab). DNS misses now fail fast instead of asking the LAN."
                                : string.Join("; ", llmnrFails),
                        });
                    case "netbios":
                        var nbFails = NameResolutionDoors.DisableNetbios();
                        var nbAfter = NameResolutionDoors.GetNetbiosStatus();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = nbFails.Count == 0 && nbAfter.State == NameResolutionDoors.NbState.Closed,
                            ["result"] = $"NetbiosOptions=2 on {nbAfter.Disabled}/{nbAfter.Total} interface(s)" +
                                (nbFails.Count > 0 ? " — failures: " + string.Join("; ", nbFails) : "") +
                                ". Applies on adapter restart/reboot; per-interface snapshot saved (reversible in the tab).",
                        });
                    case "mdns":
                        var mdnsFails = NameResolutionDoors.DisableMdns();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = mdnsFails.Count == 0,
                            ["result"] = mdnsFails.Count == 0
                                ? "Outbound mDNS multicast (UDP 5353 → 224.0.0.251/ff02::fb) blocked at the firewall — network-level; the resolver itself stays on. Printer/Chromecast/AirPlay discovery stops while closed (reversible in the tab)."
                                : string.Join("; ", mdnsFails),
                        });
                    case "hotpatch":
                        var hpBefore = AttackSurfaceService.GetHotpatchStatus();
                        if (!hpBefore.Present)
                            return ToJson(new JsonObject
                            {
                                ["door"] = door,
                                ["closed"] = true,
                                ["result"] = "Hotpatch monitoring task is not registered on this build — door closed by absence, nothing to do.",
                            });
                        var hpFails = AttackSurfaceService.DisableHotpatchMonitoring();
                        return ToJson(new JsonObject
                        {
                            ["door"] = door,
                            ["closed"] = hpFails.Count == 0,
                            ["result"] = hpFails.Count == 0
                                ? "Task disabled — hpatchmonTask.cmd no longer runs as SYSTEM at boot to report hotpatch readiness. Updates (hotpatches included) still install normally. Servicing can re-enable the task, so the tab re-checks it live (reversible in the tab)."
                                : string.Join("; ", hpFails),
                        });
                    default:
                        return $"Unknown door '{door}'. Valid doors: sstp, hostednetwork, vpnservices, kdnet, wifidirect, llmnr, netbios, mdns, hotpatch.";
                }
            }
            catch (Exception ex)
            {
                return $"Closing '{door}' failed: {ex.Message}";
            }
        }

        private static string CloseShieldsUpDoorConfirm(JsonObject a)
        {
            string door = a["door"]?.GetValue<string>()?.Trim().ToLowerInvariant() ?? "";
            string reason = a["reason"]?.GetValue<string>();
            return (door switch
            {
                "sstp" => "Stop the SSTP VPN service and disable its miniport adapters (reversible)?",
                "hostednetwork" => "Stop and disallow the Wi-Fi Direct hosted network (reversible)?",
                "vpnservices" => "Stop and disable RasMan, IKEEXT, PolicyAgent and RemoteAccess — any VPN connection drops (reversible)?",
                "kdnet" => "Turn kernel debugging OFF (effective next boot)?",
                "wifidirect" => "Disable the Wi-Fi Direct virtual adapters (reversible)?",
                "llmnr" => "Disable LLMNR (multicast name fallback, UDP 5355)? DNS misses will fail fast instead of asking the LAN; kills the LLMNR-poisoning credential-theft class. Reversible.",
                "netbios" => "Disable NetBIOS name resolution (UDP 137 broadcasts) on every interface? Applies on adapter restart/reboot. Legacy NetBIOS-name SMB stops resolving. Reversible.",
                "mdns" => "Block outbound mDNS multicast (UDP 5353) at the firewall? .local device discovery (printers, Chromecast, AirPlay) stops while closed. Network-level only — no source switch exists. Reversible.",
                "hotpatch" => "Disable the Windows Hotpatch monitoring scheduled task (\\Microsoft\\Windows\\Hotpatch\\Monitoring)? Its boot-time hpatchmonTask.cmd readiness check (run as SYSTEM) stops phoning home; updates still install normally. Reversible.",
                _ => $"Close door '{door}'?",
            }) + (string.IsNullOrEmpty(reason) ? "" : $"\n\nReason: {reason}");
        }

        private static string OptOutTelemetry(JsonObject a)
        {
            string ruleId = a["rule_id"]?.GetValue<string>()?.Trim() ?? "";
            bool revert = a["revert"] is JsonNode rb && rb.GetValue<bool>();

            try
            {
                var status = _telemetryStatuses().FirstOrDefault(s =>
                    string.Equals(s.Rule.Id, ruleId, StringComparison.OrdinalIgnoreCase));
                if (status == null)
                {
                    var ids = _telemetryStatuses().Select(s => s.Rule.Id).ToList();
                    return "Unknown rule_id '" + ruleId + "'. Known ids: " + string.Join(", ", ids);
                }

                var svc = new TelemetryRulesService();
                var (ok, message) = revert ? svc.RevertAsync(status.Rule).GetAwaiter().GetResult()
                                           : svc.ApplyOptOutAsync(status.Rule).GetAwaiter().GetResult();
                var result = new JsonObject
                {
                    ["rule_id"] = ruleId,
                    ["action"] = revert ? "revert" : "opt_out",
                    ["success"] = ok,
                    ["message"] = message,
                    ["switch_kind"] = status.Rule.IsFeatureToggle ? "feature" : "telemetry",
                };
                // Verify-after-opt-out: measure the affected talker's rate at
                // flip time so the follow-up ("did it actually slow down?")
                // has its baseline. Honest by construction — this is the
                // BEFORE number; the switch lands when the feature's host
                // restarts, and the note says exactly that.
                if (ok && !revert && !string.IsNullOrEmpty(status.Rule.TrafficProcess))
                {
                    try
                    {
                        var snap = TraceMetricsService.Compute(
                            TraceMetricsService.Match.ForProcess(status.Rule.TrafficProcess));
                        result["traffic_check"] = new JsonObject
                        {
                            ["process"] = status.Rule.TrafficProcess,
                            ["connects_last_1h"] = snap.ConnectsLast1H,
                            ["connects_per_hour_24h_basis"] = snap.ConnectsPerHour,
                            ["note"] =
                                "Baseline measured at flip time — the BEFORE number. The switch takes effect " +
                                "when the feature's host restarts (SearchHost respawns on its own; sign out/in " +
                                "is certain). Re-check with get_phonehome_cards or run_trace afterwards: the " +
                                "rate should fall toward the functional-traffic floor, not to zero. " +
                                "'Reduced at the source' — only a firewall block proves zero bytes " +
                                "(verify_block_containment).",
                        };
                    }
                    catch { /* measurement is best-effort; the opt-out result stands on its own */ }
                }
                return ToJson(result);
            }
            catch (Exception ex)
            {
                return $"Telemetry {(revert ? "revert" : "opt-out")} failed: {ex.Message}";
            }
        }

        private static string OptOutTelemetryConfirm(JsonObject a)
        {
            string ruleId = a["rule_id"]?.GetValue<string>() ?? "";
            bool revert = a["revert"] is JsonNode rb && rb.GetValue<bool>();
            return revert
                ? $"Restore the previously-saved setting for telemetry rule '{ruleId}'?"
                : $"Apply '{ruleId}' via the vendor's own official switch? Feature rules turn the fetching off " +
                  $"at the source ('reduced', not network-stopped); the previous setting is saved first.";
        }

        private static string ApplyShieldsUpPreset(JsonObject a)
        {
            string preset = a["preset"]?.GetValue<string>()?.Trim().ToLowerInvariant() ?? "";
            var type = preset switch
            {
                "strict_public" => AutoCommand.Contain.Core.FirewallProfileService.ProfileType.BlockSharingDiscoveryRemoteDesktop,
                "home_trusted" => AutoCommand.Contain.Core.FirewallProfileService.ProfileType.AllowSharingDiscovery,
                "gaming_media" => AutoCommand.Contain.Core.FirewallProfileService.ProfileType.AllowDiscoveryCast,
                "office" => AutoCommand.Contain.Core.FirewallProfileService.ProfileType.AllowSharingDiscoveryRemoteDesktop,
                "shield_up" => AutoCommand.Contain.Core.FirewallProfileService.ProfileType.ShieldsUpMdns,
                _ => (AutoCommand.Contain.Core.FirewallProfileService.ProfileType?)null,
            };
            if (type == null)
                return "Unknown preset '" + preset + "'. Valid presets: strict_public, home_trusted, gaming_media, office, shield_up.";

            try
            {
                // Atomic apply — the same order the tab uses: pause the drift
                // enforcer while the preset churns rules, apply, re-capture.
                // The baseline manager itself lives in the app assembly; the
                // app installs the seam at startup. Headless without the seam:
                // apply anyway, say honestly what was skipped.
                var seam = ShieldsUpBaseline;
                seam?.PauseMinutes(2);
                var result = AutoCommand.Contain.Core.FirewallProfileService.Instance
                    .ApplyProfile(type.Value).GetAwaiter().GetResult();

                string baselineNote;
                if (seam != null)
                {
                    var (count, at) = seam.CaptureAsync().GetAwaiter().GetResult();
                    baselineNote = $"baseline re-captured ({count} rules, {at.ToLocalTime():HH:mm})";
                }
                else
                {
                    baselineNote = "baseline NOT re-captured (no app seam in this session) — press Re-baseline " +
                                   "in the Firewall tab so Auto-Mitigate adopts the preset's intent";
                }

                return ToJson(new JsonObject
                {
                    ["preset"] = preset,
                    ["changed"] = result.TotalChanged,
                    ["failed"] = result.TotalFailed,
                    ["notes"] = result.Notes,
                    ["baseline"] = baselineNote,
                });
            }
            catch (Exception ex)
            {
                return $"Preset '{preset}' failed: {ex.Message}";
            }
        }

        private static string ApplyShieldsUpPresetConfirm(JsonObject a)
        {
            string preset = a["preset"]?.GetValue<string>() ?? "";
            string reason = a["reason"]?.GetValue<string>();
            return $"Apply the '{preset}' firewall preset? This changes many Windows firewall rule states at once; " +
                   "the baseline is re-captured as part of the same operation. " +
                   (string.IsNullOrEmpty(reason) ? "" : $"\n\nReason: {reason}");
        }

        // ── wsl tools (NetWatch.Core's WslIdentityService) ────────────────

        private static string GetWslStatus()
        {
            WslIdentityService.WslState st;
            try { st = WslIdentityService.GetState(); }
            catch (Exception ex) { return "WSL state probe failed: " + ex.Message; }

            var o = new JsonObject
            {
                ["type"] = "wsl_status",
                ["installed"] = st.Installed,
                ["vm_running"] = st.VmRunning,
                ["running_distros"] = new JsonArray(st.RunningDistros.Select(d => (JsonNode)d).ToArray()),
                ["networking_mode"] = st.NetworkingMode,
                ["mode_note"] = st.ModeNote,
                ["note"] = "WSL-family rows in get_monitor_rows (wslservice/vmmem/wslrelay) carry a 'wsl' " +
                           "object; in NAT mode host-side process attribution stops at the VM boundary — " +
                           "this tool never starts the utility VM.",
            };
            if (st.Error != null) o["probe_error"] = st.Error;

            if (!st.Installed) o["verdict"] = "WSL is not installed on this machine.";
            else if (!st.VmRunning) o["verdict"] =
                "WSL is installed but the utility VM is not running — start a distro yourself to see live " +
                "traffic; this probe deliberately never launches it.";
            else
            {
                // Guest half: ss -tnp per running distro, joined to the host's
                // WSL-family connections by destination (NAT preserves it).
                try
                {
                    var snap = WslGuestProbe.Probe();
                    var hostWsl = GetHostWslConnections();

                    var distrosArr = new JsonArray();
                    foreach (var d in snap.Distros)
                    {
                        var distro = new JsonObject
                        {
                            ["distro"] = d.Distro ?? "(default)",
                            ["ok"] = d.Ok,
                            ["sockets"] = d.Sockets.Length,
                        };
                        if (d.Error != null) distro["error"] = d.Error;

                        var matches = new JsonArray();
                        foreach (var h in hostWsl.Take(50))
                        {
                            var guests = WslGuestProbe.MatchByRemoteIp(snap, WslGuestProbe.SplitEndpoint(h.Remote).Ip)
                                .Take(5).ToList();
                            if (guests.Count == 0) continue;
                            var gArr = new JsonArray();
                            foreach (var (_, g) in guests)
                                gArr.Add(new JsonObject
                                {
                                    ["process"] = g.Process,
                                    ["pid"] = g.Pid,
                                    ["state"] = g.State,
                                    ["peer"] = g.Peer,
                                    ["local"] = g.Local,
                                });
                            matches.Add(new JsonObject
                            {
                                ["host_remote"] = h.Remote,
                                ["host_process"] = h.Process,
                                ["host_pid"] = h.Pid,
                                ["linux_side"] = gArr,
                            });
                        }
                        distro["joined_host_connections"] = matches;
                        distrosArr.Add(distro);
                    }

                    o["guest"] = new JsonObject
                    {
                        ["probed_utc"] = snap.ProbedUtc.ToString("yyyy-MM-dd HH:mm:ss") + "Z",
                        ["distros"] = distrosArr,
                        ["method"] = "ss -tnp per running distro, joined to host WSL-family connections by " +
                                     "remote endpoint (NAT preserves the destination)",
                    };

                    // WSL's own firewall layer: profiles + the Hyper-V rule set
                    // (the Windows-native way to filter WSL traffic per-VM).
                    var hv = WslDiagnosisService.ReadHyperVDetails();
                    var hvObj = new JsonObject();
                    if (hv.Error != null)
                        hvObj["note"] = $"Hyper-V firewall layer unreadable: {hv.Error} (pre-22H2 Windows lacks it)";
                    if (hv.Profiles.Count > 0)
                    {
                        var profArr = new JsonArray();
                        foreach (var p in hv.Profiles)
                            profArr.Add(new JsonObject
                            {
                                ["profile"] = p.Name,
                                ["default_inbound"] = p.DefaultInbound,
                                ["default_outbound"] = p.DefaultOutbound,
                                ["allow_host_policy_merge"] = p.AllowHostPolicyMerge,
                            });
                        hvObj["profiles"] = profArr;
                    }
                    if (hv.Rules.Count > 0)
                    {
                        hvObj["rules_total"] = hv.Rules.Count;
                        hvObj["rules_enabled"] = hv.Rules.Count(r => r.Enabled);
                        var ruleArr = new JsonArray();
                        foreach (var r in hv.Rules.Take(30))
                            ruleArr.Add(new JsonObject
                            {
                                ["name"] = r.Name,
                                ["direction"] = r.Direction,
                                ["action"] = r.Action,
                                ["enabled"] = r.Enabled,
                            });
                        hvObj["rules_sample"] = ruleArr;
                        hvObj["rules_note"] = "per-VM filtering lives here (New-NetFirewallHyperVRule) — " +
                                              "granular WSL containment goes on this layer, not the process layer";
                    }
                    if (hvObj.Count > 0) o["hyperv_firewall"] = hvObj;

                    o["verdict"] = $"WSL VM is up ({st.RunningDistros.Length} distro(s)); the guest socket " +
                                   "table above maps host-side WSL connections to their Linux processes.";
                }
                catch (Exception ex)
                {
                    o["guest_error"] = ex.Message;
                }
            }
            return ToJson(o);
        }

        /// <summary>The staged WSL diagnosis over the bridge — the same
        /// engine the UI's 'Why is WSL offline?' entry runs, so both faces
        /// answer identically.</summary>
        private static string DiagnoseWsl()
        {
            try
            {
                var d = WslDiagnosisService.DiagnoseLiveAsync().GetAwaiter().GetResult();
                return ToJson(new JsonObject
                {
                    ["type"] = "wsl_diagnosis",
                    ["healthy"] = d.Healthy,
                    ["verdict"] = d.Verdict,
                    ["next_step"] = d.NextStep,
                    ["evidence"] = new JsonArray(d.Evidence.Select(e => (JsonNode)e).ToArray()),
                });
            }
            catch (Exception ex)
            {
                return "WSL diagnosis failed: " + ex.Message;
            }
        }

        /// <summary>Host-side established connections owned by the WSL
        /// family (wslservice/vmmem/wslrelay/…) — the rows a guest join can
        /// explain. Capped by the caller.</summary>
        private static List<(string Remote, int Pid, string Process)> GetHostWslConnections()
        {
            var procs = new Dictionary<int, string>();
            try
            {
                using var s = new ManagementObjectSearcher("SELECT ProcessId, Name FROM Win32_Process");
                foreach (ManagementObject o in s.Get())
                    procs[Convert.ToInt32(o["ProcessId"])] = o["Name"]?.ToString() ?? "?";
            }
            catch { }

            var list = new List<(string Remote, int Pid, string Process)>();
            foreach (var c in TcpConnectionTable.GetEstablished())
                if (procs.TryGetValue(c.Pid, out var name) &&
                    WslIdentityService.IsWslFamilyProcess(name))
                    list.Add((c.RemoteEndPoint, c.Pid, name));
            return list;
        }

        private static string ToJson(JsonObject o) => o.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = false });
    }
}
