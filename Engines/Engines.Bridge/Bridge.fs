// F# port of Core\Services\AgentBridgeService.cs (AutoScope.Services →
// AutoCommand.Engines.Bridge). Faithful by contract: same trust model, same
// wire bytes (HTTP/1.1 subset, JSON-RPC shapes, status codes and reason
// phrases), same session-file JSON shape (the deployed
// AutoScope.AgentProxy.exe reads {port, token, pid} from it). The app
// values the C# hardcoded — port base 47921, %LOCALAPPDATA%\AutoScope,
// "autoscope", "AutoScope" — now come from the AppIdentity the host
// constructs; the tool surface is injected through IAgentTools instead of
// the static AgentToolRegistry.
namespace AutoCommand.Engines.Bridge

open System
open System.Collections.Generic
open System.Diagnostics
open System.IO
open System.Net
open System.Net.Sockets
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Text
open System.Text.Encodings.Web
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading
open System.Threading.Tasks
open AutoCommand.Engines.Core

/// <summary>
/// The AI-access bridge: a loopback-only MCP endpoint hosted INSIDE the
/// running (elevated) app process.
///
/// Trust model — the app is the broker:
///   • The user starts a session from Settings → "AI access" (or the app
///     is launched with --agent-headless). Starting writes
///     &lt;identity.DataRoot&gt;\agent\session.json {port, token, pid, exe, mutatingAllowed}.
///     The port is portBase + the first free offset when several
///     instances run - clients must read the file, never hardcode a
///     port; a sibling instance's bridge will reject this token.
///   • An MCP client spawns the proxy exe with --agent-stdio (headless,
///     inherits the caller's non-elevated token — no UAC), which reads the
///     session file and forwards JSON-RPC to the listener below.
///   • Every call must carry the session bearer token (constant-time
///     compare) and a 127.0.0.1 Host header (DNS-rebinding guard).
///   • Read-only tools answer immediately; mutating tools need the
///     session toggle AND a per-action confirmation dialog on the UI.
///   • Stopping the session (or exiting the app) deletes the session
///     file and kills the listener — revocation is instant.
///
/// Raw TcpListener instead of HttpListener: http.sys URL reservations
/// need admin or netsh setup; a hand-rolled HTTP/1.1 subset (POST-only,
/// one request per connection) has no ACL surface at all.
/// </summary>
type AgentBridgeService (identity: AppIdentity, tools: IAgentTools,
                         [<Optional; DefaultParameterValue(-1)>] portBaseOverride: int) as this =

    // F# port: interfaces/classes do not admit the null literal in F#, so
    // the C#'s `= null` initializers are Unchecked.defaultof here; C# code
    // still reads and assigns plain null.
    static let mutable ui: IAgentBridgeUI = Unchecked.defaultof<IAgentBridgeUI>

    // Protocol versions this bridge actually implements — must match the
    // proxy's set (see AgentProxy\Program.cs): initialize/notifications/*,
    // ping, tools/list, tools/call; resources/* and prompts/* answer -32601.
    static let SupportedProtocols = [| "2024-11-05"; "2025-03-26"; "2025-06-18" |]

    // F# port: the C# hardcoded PortBase = 47921; the port base lives on
    // AppIdentity.BridgePortBase. portBaseOverride exists so tests can
    // bind a non-production range (pass -1 to use the identity's base).
    let portBase = if portBaseOverride >= 0 then portBaseOverride else identity.BridgePortBase

    // F# port: %LOCALAPPDATA%\AutoScope\agent → identity.DataRoot\agent.
    let agentDir = Path.Combine(identity.DataRoot, "agent")
    let sessionPath = Path.Combine(agentDir, "session.json")
    let activityPath = Path.Combine(agentDir, "activity.jsonl")
    let feedPath = Path.Combine(agentDir, "feed.jsonl")

    let mutable listener: TcpListener = null
    let mutable cts: CancellationTokenSource = null
    let mutable token = ""
    let mutable port = 0
    let mutable mutatingAllowed = false
    let mutable clientInitialized = false
    let mutable clientName = ""
    let mutable connectedCalls = 0
    let sessionToolsLock = obj ()
    let sessionAllowedTools = HashSet<string>(StringComparer.Ordinal)

    // event Action<string> Activity — same delegate shape the C# field-like
    // event exposed, so C# `bridge.Activity += s => ...` compiles unchanged.
    let activity = DelegateEvent<Action<string>>()

    /// <summary>Installed by the app at startup; without it the bridge
    /// still serves read-only tools but cannot confirm mutating ones
    /// (same behavior as headless sessions).</summary>
    static member Ui
        with get () = ui
        and set (value) = ui <- value

    /// <summary>F# port: the C# exposed a parameterless `Instance`
    /// singleton; the engine needs the app's identity and tool provider,
    /// so the host assigns Shared once at startup
    /// (AgentBridgeService.Shared = new AgentBridgeService(...)).</summary>
    static member val Shared: AgentBridgeService = Unchecked.defaultof<AgentBridgeService> with get, set

    // F# port: const → plain static members ([<Literal>] is not valid on
    // members); same values readable from C#.
    static member PortRange = 20
    static member MaxBodyBytes = 4 * 1024 * 1024
    static member ConfirmTimeoutMs = 90_000

    // Every JSON-RPC body this bridge writes goes through one encoder:
    // relaxed escaping keeps tool payloads embedded as content.text readable
    // (" and newline, not \u0022 and \u000a). Valid JSON either way — but
    // hand-rolled clients kept double-decoding around the escaped form
    // (field report), so the wire now carries the conventional form.
    static member private JsonOpts = JsonSerializerOptions(Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping)

    member _.AgentDir = agentDir
    member _.ClientName = clientName
    member _.ConnectedCalls = connectedCalls
    member _.IsRunning = not (isNull listener)
    member _.Port = port
    member _.AllowMutating = mutatingAllowed

    /// <summary>Fires on bridge state changes (session started/stopped,
    /// tool calls) for UI status.</summary>
    [<CLIEvent>]
    member _.Activity = activity.Publish

    // ── session lifecycle ─────────────────────────────────────────────

    member _.Start (allowMutating: bool) : bool * string =
        if this.IsRunning then
            (false, "AI access session is already running.")
        else
            token <- Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            mutatingAllowed <- allowMutating
            lock sessionToolsLock (fun () -> sessionAllowedTools.Clear())
            clientName <- ""
            clientInitialized <- false // a new session is a new MCP lifecycle
            connectedCalls <- 0

            let mutable bound: TcpListener = null
            let mutable boundPort = 0
            let mutable p = portBase
            let mutable trying = true
            while trying && p < portBase + AgentBridgeService.PortRange do
                try
                    let l = new TcpListener(IPAddress.Loopback, p)
                    l.Start()
                    bound <- l
                    boundPort <- p
                    trying <- false
                with _ -> p <- p + 1 // port taken — try the next
            // F# port: the C#'s `if (listener == null)` guard can never see
            // the last failed attempt (the ctor succeeds before Start()
            // throws), so a fully-blocked range would have written
            // session.json with port 0 — the port tracks success instead.
            if isNull bound then
                (false, $"No free port in {portBase}–{portBase + AgentBridgeService.PortRange - 1}.")
            else
                listener <- bound
                port <- boundPort
                cts <- new CancellationTokenSource()
                Task.Run(fun () -> this.AcceptLoop(bound, cts.Token)) |> ignore

                Directory.CreateDirectory(agentDir) |> ignore
                let session = JsonObject()
                session["port"] <- JsonValue.Create(port)
                session["token"] <- JsonValue.Create(token)
                session["pid"] <- JsonValue.Create(Process.GetCurrentProcess().Id)
                // The app's own exe path — the proxy's only layout-independent
                // proof of session identity. Its old "the app sits one level
                // above my folder" guess broke on the deployed
                // tools\v<version>\ layout (field report 2026-11-11: live
                // session, every tool call answered as offline).
                let exePath = Environment.ProcessPath
                if not (isNull exePath) then session["exe"] <- JsonValue.Create(exePath)
                session["startedUtc"] <- JsonValue.Create(DateTime.UtcNow.ToString("o"))
                session["mutatingAllowed"] <- JsonValue.Create(allowMutating)
                // no tool list here: it went stale the moment a build added a
                // tool mid-session - tools/list over the wire is authoritative
                File.WriteAllText(sessionPath, session.ToJsonString(JsonSerializerOptions(WriteIndented = true)))

                let snap = JsonObject()
                snap["type"] <- JsonValue.Create("session_started")
                snap["port"] <- JsonValue.Create(port)
                snap["mutatingAllowed"] <- JsonValue.Create(allowMutating)
                this.AppendFeed(snap)
                let mutText = if allowMutating then "on (each action asks)" else "off"
                this.LogActivity("session", "started", $"loopback port {port}, mutating {mutText}")
                activity.Trigger([| box "session started" |])
                (true, $"Listening on 127.0.0.1:{port}.")

    member _.Stop () =
        if this.IsRunning then
            if not (isNull cts) then (try cts.Cancel() with _ -> ())
            if not (isNull listener) then (try listener.Stop() with _ -> ())
            listener <- null
            if not (isNull cts) then cts.Dispose()
            cts <- null
            // Delete OUR session file only. Sibling AutoCommand instances
            // share agent\, and the file describes whichever session started
            // LAST — one instance exiting must not revoke the other's live
            // session (field report: the new build's autostarted session
            // lost its file when the old build's exit path ran Stop, leaving
            // a live mutating bridge no client could authenticate to).
            (try
                if File.Exists(sessionPath) && this.SessionFileBelongsToThisProcess() then
                    File.Delete(sessionPath)
             with _ -> ())
            this.LogActivity("session", "stopped", "")
            activity.Trigger([| box "session stopped" |])

    /// <summary>True when session.json carries THIS process's pid — the only
    /// file Stop may delete. A sibling's file (its pid) belongs to the other
    /// live session. An unreadable or pid-less file counts as ours so a
    /// stopping session still cleans up after itself.</summary>
    member private _.SessionFileBelongsToThisProcess () : bool =
        try
            match JsonNode.Parse(File.ReadAllText(sessionPath)) with
            | :? JsonObject as o ->
                match o["pid"] with
                | null -> true
                | p -> try p.GetValue<int>() = Process.GetCurrentProcess().Id with _ -> true
            | _ -> true
        with _ -> true

    /// <summary>True when a live session file matches a running bridge
    /// (crash-cleanup helper for the stdio bridge).</summary>
    member _.ReadSession () : int * string =
        // F# port: static in the C# (fixed path); the engine derives the
        // path from the identity, so this is an instance member.
        let node =
            match JsonNode.Parse(File.ReadAllText(sessionPath)) with
            | :? JsonObject as o -> o
            | _ -> null
        let portValue =
            if isNull node || isNull node["port"] then 0 else node["port"].GetValue<int>()
        let tokenValue =
            if isNull node || isNull node["token"] then "" else node["token"].GetValue<string>()
        (portValue, tokenValue)

    member _.SessionFileExists = File.Exists(sessionPath)

    /// <summary>Last N activity lines (newest first) for the Settings
    /// card. F# port: static in the C#; instance here (identity-derived
    /// path).</summary>
    member _.RecentActivity ([<Optional; DefaultParameterValue(30)>] count: int) : ResizeArray<string> =
        let lines = ResizeArray<string>()
        try
            if File.Exists(activityPath) then
                for line in File.ReadLines(activityPath) |> Seq.rev |> Seq.truncate count do
                    lines.Add(line)
        with _ -> ()
        lines

    // ── accept + minimal HTTP/1.1 ─────────────────────────────────────

    member private _.AcceptLoop (listener: TcpListener, ct: CancellationToken) : Task =
        task {
            let mutable running = true
            while running && not ct.IsCancellationRequested do
                try
                    let! client = listener.AcceptTcpClientAsync(ct).AsTask()
                    Task.Run(fun () -> this.HandleClient(client, ct)) |> ignore
                with _ -> running <- false // listener stopped
        } :> Task

    member private _.HandleClient (client: TcpClient, ct: CancellationToken) : Task =
        task {
            // hoisted so the last-resort handler below can still answer
            let mutable stream: NetworkStream = null
            try
                use __ = client
                client.ReceiveTimeout <- 120_000
                stream <- client.GetStream()

                let! head = AgentBridgeService.ReadUntilAsync(stream, "\r\n\r\n", 64 * 1024)
                if isNull head then
                    ()
                else
                    let lines = head.Split("\r\n")
                    let requestLine = lines.[0].Split(' ')
                    let method = if requestLine.Length > 0 then requestLine.[0] else ""
                    let headers = Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    for i = 1 to lines.Length - 1 do
                        let c = lines.[i].IndexOf(':')
                        if c > 0 then
                            headers.[lines.[i].Substring(0, c).Trim()] <- lines.[i].Substring(c + 1).Trim()

                    if method <> "POST" then
                        // JSON-RPC error body like every other rejection, so
                        // a misdirected client sees one dialect everywhere
                        do! AgentBridgeService.DrainBody(stream, headers)
                        do! AgentBridgeService.WriteJsonResponse(stream,
                            (if method = "GET" then 405 else 400),
                            AgentBridgeService.RpcError(null, -32001,
                                "POST only (MCP streamable HTTP, stateless)"))
                    else
                        let hostOk =
                            match headers.TryGetValue("Host") with
                            | true, host ->
                                host.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase) ||
                                host.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase)
                            | _ -> false
                        if not hostOk then
                            do! AgentBridgeService.DrainBody(stream, headers)
                            do! AgentBridgeService.WriteJsonResponse(stream, 403, AgentBridgeService.RpcError(null, -32001, "Forbidden: the bridge is loopback only"))
                        else
                            let authOk =
                                match headers.TryGetValue("Authorization") with
                                | true, auth -> this.TokenMatches(auth)
                                | _ -> false
                            if not authOk then
                                do! AgentBridgeService.DrainBody(stream, headers)
                                do! AgentBridgeService.WriteJsonResponse(stream, 401, AgentBridgeService.RpcError(null, -32001, "Unauthorized: bad or missing session token. Tokens change on every session restart - re-read session.json in the AutoCommand agent folder (no file = no active session: start one from the app's AI access settings)"))
                            else
                                let contentLength =
                                    match headers.TryGetValue("Content-Length") with
                                    | true, cl -> (match Int32.TryParse(cl) with true, n -> Some n | _ -> None)
                                    | _ -> None
                                let chunked =
                                    match headers.TryGetValue("Transfer-Encoding") with
                                    | true, te -> te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0
                                    | _ -> false
                                if chunked || contentLength.IsNone then
                                    // A bodyless parse below used to throw into
                                    // the catch-all and close the socket with
                                    // NO response — clients read that as the
                                    // flaky "empty body" (field report). State
                                    // the requirement instead.
                                    do! AgentBridgeService.WriteJsonResponse(stream, 411,
                                        AgentBridgeService.RpcError(null, -32002, "Content-Length required (the bridge does not read chunked bodies)"))
                                elif contentLength.Value > AgentBridgeService.MaxBodyBytes then
                                    do! AgentBridgeService.DrainBody(stream, headers)
                                    do! AgentBridgeService.WriteJsonResponse(stream, 413, AgentBridgeService.RpcError(null, -32002, "Payload too large"))
                                else
                                    match headers.TryGetValue("Expect") with
                                    | true, expect when expect.Contains("100-continue") ->
                                        do! AgentBridgeService.WriteRaw(stream, "HTTP/1.1 100 Continue\r\n\r\n")
                                    | _ -> ()

                                    let bodyTask =
                                        if contentLength.Value = 0 then Task.FromResult("")
                                        else AgentBridgeService.ReadExactAsync(stream, contentLength.Value)
                                    let! body = bodyTask

                                    // invalid JSON must ANSWER (-32700), not die
                                    // in the catch-all: the old split closed
                                    // the socket bare on parse throws
                                    let parsed =
                                        try Some(JsonNode.Parse(body))
                                        with _ -> None
                                    match parsed with
                                    | Some (:? JsonObject as rpc) ->
                                        let rpcId =
                                            if isNull rpc["id"] then null else rpc["id"].ToJsonString()
                                        let! jsonResponse =
                                            this.DispatchAsync(rpc,
                                                (match headers.TryGetValue("User-Agent") with
                                                 | true, ua -> ua | _ -> ""))
                                        if isNull rpcId || isNull jsonResponse then
                                            do! AgentBridgeService.WriteRaw(stream,
                                                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                        else
                                            do! AgentBridgeService.WriteResponse(stream, 200,
                                                JsonNode.Parse(jsonResponse) :?> JsonObject)
                                    | _ ->
                                        do! AgentBridgeService.WriteJsonResponse(stream, 400,
                                            AgentBridgeService.RpcError(null, -32700, "Parse error"))
            with _ ->
                // last resort: answer SOMETHING — a bare close reads as an
                // empty response on the client (the flaky-empty class).
                // Best-effort only; a vanished client swallows this too.
                let _ =
                    if not (isNull stream) then
                        try
                            AgentBridgeService.WriteJsonResponse(stream, 500,
                                AgentBridgeService.RpcError(null, -32603, "Internal error (connection closing)"))
                                .GetAwaiter().GetResult()
                        with _ -> ()
                ()
        } :> Task

    member private _.TokenMatches (authHeader: string) : bool =
        if isNull authHeader || token.Length = 0 then false
        else
            let prefix = "Bearer "
            if not (authHeader.StartsWith(prefix, StringComparison.Ordinal)) then false
            else
                let given = Encoding.UTF8.GetBytes(authHeader.Substring(prefix.Length))
                let expected = Encoding.UTF8.GetBytes(token)
                given.Length = expected.Length && CryptographicOperations.FixedTimeEquals(given, expected)

    // ── MCP dispatch ──────────────────────────────────────────────────

    static member private NegotiateProtocol (requested: string) =
        if not (String.IsNullOrEmpty requested) && Array.IndexOf(SupportedProtocols, requested) >= 0
        then requested
        else SupportedProtocols.[SupportedProtocols.Length - 1]

    member internal _.DispatchAsync (rpc: JsonObject, userAgent: string) : Task<string> =
        task {
            let method =
                let m = rpc["method"]
                if isNull m then "" else m.GetValue<string>()
            let prm =
                match box rpc["params"] with
                | :? JsonObject as o -> o
                | _ -> null
            let isNotification = isNull rpc["id"]

            // MCP lifecycle: requests before initialize are refused (-32002).
            // ping stays answerable (clients probe with it), notifications
            // are dropped — there is nobody to answer. Mirrored in the proxy
            // so both halves enforce the same rule.
            if not isNotification && not clientInitialized && method <> "initialize" && method <> "ping" then
                return AgentBridgeService.RpcError(rpc["id"], -32002, "Server not initialized — send initialize first.")
            else
                try
                    match method with
                    | "initialize" ->
                        let requested =
                            if isNull prm then null
                            else
                                let pv = prm["protocolVersion"]
                                if isNull pv then null else pv.GetValue<string>()
                        let clientInfo =
                            match (if isNull prm then null else prm["clientInfo"]) with
                            | :? JsonObject as o -> o
                            | _ -> null
                        let initName =
                            if isNull clientInfo then null
                            else
                                let n = clientInfo["name"]
                                if isNull n then null else n.GetValue<string>()
                        clientName <-
                            if not (String.IsNullOrEmpty initName) then initName
                            elif not (String.IsNullOrEmpty userAgent) then userAgent
                            else "unknown"
                        clientInitialized <- true
                        this.LogActivity("client", "connected", clientName)
                        activity.Trigger([| box $"client connected: {clientName}" |])
                        let negotiated = AgentBridgeService.NegotiateProtocol(requested)
                        if negotiated <> requested then
                            let reqText = if isNull requested then "(none)" else requested
                            this.LogActivity("client", "protocol", $"requested {reqText} — answered {negotiated}")
                        let result = JsonObject()
                        result["protocolVersion"] <- JsonValue.Create(negotiated)
                        let caps = JsonObject()
                        let toolsCap = JsonObject()
                        toolsCap["listChanged"] <- JsonValue.Create(false)
                        caps["tools"] <- toolsCap
                        result["capabilities"] <- caps
                        let serverInfo = JsonObject()
                        serverInfo["name"] <- JsonValue.Create(identity.McpId)
                        // same title offline and online so the client UI
                        // never relabels the server when a session flips
                        serverInfo["title"] <- JsonValue.Create(identity.Name + " (agent bridge)")
                        let exePath =
                            match Environment.ProcessPath with
                            | null -> identity.Name + ".exe"
                            | path -> path
                        serverInfo["version"] <- JsonValue.Create(
                            (match FileVersionInfo.GetVersionInfo(exePath).ProductVersion with
                             | null -> "?" | v -> v))
                        result["serverInfo"] <- serverInfo
                        // The mutating surface is GENERATED from the injected
                        // registry, not hand-maintained: this sentence once
                        // said "the only mutating tools are open_gate/
                        // close_gate" while the registry had already grown
                        // to five. A model's picture of what can change the
                        // machine must match the actual tool list.
                        let mutators =
                            tools.Names(true)
                            |> Seq.filter (fun n ->
                                match tools.Find(n, true) with
                                | t when not (isNull (box t)) -> t.Mutating
                                | _ -> false)
                            |> Seq.toList
                        let mutatingText =
                            if mutators.IsEmpty then
                                "This session exposes read-only tools only."
                            else
                                "Mutating tools ("
                                + String.concat ", " mutators
                                + ") each ask the user for confirmation in the app UI on "
                                + "every single call; everything else is read-only."
                        result["instructions"] <- JsonValue.Create(
                            "Read-only security telemetry from the locally running " + identity.Name + " app " +
                            "(process monitor, svchost identity, PID provenance, Sysmon tail, trace analysis). " +
                            mutatingText)
                        return AgentBridgeService.RpcResult(rpc["id"], result)

                    | "notifications/initialized"
                    | "notifications/cancelled" ->
                        return null

                    | "ping" ->
                        return AgentBridgeService.RpcResult(rpc["id"], JsonObject())

                    | "tools/list" ->
                        let result = JsonObject()
                        result["tools"] <- JsonNode.Parse(tools.ListTools(mutatingAllowed))
                        return AgentBridgeService.RpcResult(rpc["id"], result)

                    | "tools/call" ->
                        let name =
                            if isNull prm then ""
                            else
                                let n = prm["name"]
                                if isNull n then "" else n.GetValue<string>()
                        let args =
                            match (if isNull prm then null else prm["arguments"]) with
                            | :? JsonObject as o -> o
                            | _ -> JsonObject()
                        connectedCalls <- connectedCalls + 1
                        let! (content, isError) = this.CallToolAsync(name, args)
                        let outcomeText = if isError then "error" else "ok"
                        this.LogActivity("tool", name, AgentBridgeService.SummarizeArgs(args), outcomeText)
                        activity.Trigger([| box $"tool {name} → {outcomeText}" |])
                        let result = JsonObject()
                        let contentObj = JsonObject()
                        contentObj["type"] <- JsonValue.Create("text")
                        contentObj["text"] <- JsonValue.Create(content)
                        let contentArr = JsonArray()
                        contentArr.Add(contentObj)
                        result["content"] <- contentArr
                        result["isError"] <- JsonValue.Create(isError)
                        // structuredContent (MCP 2025-06-18): when the text
                        // payload is itself JSON, hand it to capable clients
                        // as a parsed object - no double-decode
                        if not isError then
                            try
                                match JsonNode.Parse(content) with
                                | :? JsonObject as structured -> result["structuredContent"] <- structured
                                | _ -> ()
                            with _ -> ()
                        return AgentBridgeService.RpcResult(rpc["id"], result)

                    | _ ->
                        if isNotification then return null
                        else return AgentBridgeService.RpcError(rpc["id"], -32601, $"Unknown method: {method}")
                with ex ->
                    if isNotification then return null
                    else
                        let result = JsonObject()
                        let contentObj = JsonObject()
                        contentObj["type"] <- JsonValue.Create("text")
                        contentObj["text"] <- JsonValue.Create("tool failed: " + ex.Message)
                        let contentArr = JsonArray()
                        contentArr.Add(contentObj)
                        result["content"] <- contentArr
                        result["isError"] <- JsonValue.Create(true)
                        return AgentBridgeService.RpcResult(rpc["id"], result)
        }

    member private _.CallToolAsync (name: string, args: JsonObject) : Task<string * bool> =
        task {
            // find WITHOUT the mutating filter so a policy-disabled tool is
            // distinguishable from a typo (bug report: both used to read the
            // same "unknown tool" message)
            let tool = tools.Find(name, true)
            if isNull (box tool) then
                return ($"Unknown tool '{name}'. Call tools/list for this session's tool set.", true)
            elif tool.Mutating && not mutatingAllowed then
                return ($"Tool '{name}' exists, but this session runs WITHOUT mutating tools — " +
                        "headless/background sessions have no UI to confirm actions with. Start a session " +
                        "from the running app's AI access settings and retry there.", true)
            else
                // dry_run=true is the documented "resolve and preview only"
                // contract for every mutating tool that offers it: no
                // confirmation, no change, and no UI needs to exist at all.
                // Checked BEFORE the confirmation branch — the field bug
                // where dry_run crashed identically to a real call was this
                // ordering (the UI pre-check ran first, off the UI thread).
                let dryRunOnly =
                    match args["dry_run"] with
                    | null -> false
                    | v -> v.ToString().Trim().Equals("true", StringComparison.OrdinalIgnoreCase)

                if tool.Mutating && not dryRunOnly && not (this.SessionGranted(AgentBridgeService.GrantKey(name, args))) then
                    let allowed, note = this.RequestConfirmation(name, AgentBridgeService.GrantKey(name, args), tool.ConfirmDetail(args.ToJsonString()))
                    if not allowed then
                        return ($"User denied '{name}'" + (if note.Length > 0 then $" — {note}" else "") + ".", true)
                    else
                        let! output = Task.Run(fun () -> tool.Invoke(args.ToJsonString()))
                        return (output, false)
                else
                    let! output = Task.Run(fun () -> tool.Invoke(args.ToJsonString()))
                    return (output, false)
        }

    member private _.SessionGranted (grantKey: string) =
        lock sessionToolsLock (fun () -> sessionAllowedTools.Contains(grantKey))

    /// <summary>What a "for this session" grant actually covers. Gate tools
    /// grant PER TARGET AND PER DURATION — the confirmation dialog quotes
    /// the exact gate length ("Open a 1-minute block gate?"), so a grant
    /// must never silently cover a longer one for the same target. Other
    /// mutating tools grant per-target when their args carry an obvious
    /// target (ip / pid / task_path — AutoScope's block_ip, unblock_ip,
    /// kill_process, disable_task run on this shared engine — plus the
    /// ShieldsUp tools' door / rule_id / preset shapes): "always allow
    /// kill_process" must never widen to every process for the rest of the
    /// session, and "always close the sstp door" must never cover the VPN
    /// doors. Tools with no target-shaped argument fall back to
    /// per-tool.</summary>
    static member private GrantKey (toolName: string, args: JsonObject) : string =
        if toolName = "open_gate" || toolName = "close_gate" then
            let target =
                match args["target"] with
                | null -> ""
                | t -> "|" + t.ToString().Trim().ToLowerInvariant()

            let minutes =
                match args["minutes"] with
                | null -> ""
                | m -> "|" + m.ToString().Trim()

            toolName + target + minutes
        else
            // per-target when the tool's scope is a specific object
            let scoped =
                [ "ip"; "pid"; "task_path"; "door"; "rule_id"; "preset" ]
                |> List.tryPick (fun k ->
                    match args[k] with
                    | null -> None
                    | v -> Some (v.ToString().Trim().ToLowerInvariant()))
            match scoped with
            | Some t -> toolName + "|" + t
            | None -> toolName

    // ── per-action confirmation (Tier 3) ──────────────────────────────

    /// <summary>
    /// Asks the user at the app's UI. Runs on the dispatcher; returns
    /// after the user answers or the timeout elapses (deny). "Always for
    /// this session" grants are remembered per tool until Stop() - and for
    /// the gate tools, per target (other targets keep asking).
    /// </summary>
    member _.RequestConfirmation (toolName: string, grantKey: string, detail: string) : bool * string =
        if not mutatingAllowed then (false, "mutating tools are disabled for this session")
        else
            let uiInstance = AgentBridgeService.Ui
            // A UI hook that THROWS here (the original bug: reading a
            // VerifyThread() WPF property from this RPC thread) reports
            // "no UI" — the tool returns a clean, actionable denial instead
            // of surfacing raw WPF exception text to the client.
            let uiReady =
                try
                    not (isNull (box uiInstance)) && uiInstance.IsUiAvailable
                with _ -> false
            if not uiReady then
                (false, "headless session has no UI to confirm with — restart the session from "
                        + identity.Name + " Settings to allow mutating tools")
            else
                let tcs = TaskCompletionSource<bool * bool * string>(TaskCreationOptions.RunContinuationsAsynchronously)
                uiInstance.BeginInvokeOnUI(Action(fun () ->
                    // F# port: the C# passed an `async` lambda where Action
                    // accepted it (async void) — a task{} started eagerly is
                    // the same fire-and-forget, with continuations posted
                    // back to the UI context by the await.
                    let dialog =
                        task {
                            try
                                let! (allowed, always) = uiInstance.ShowConfirmAsync(toolName, detail)
                                tcs.TrySetResult((allowed, always,
                                    (if allowed then "allowed by user" else "denied by user"))) |> ignore
                            with ex ->
                                tcs.TrySetResult((false, false, "confirm dialog failed: " + ex.Message)) |> ignore
                        }
                    ignore dialog))

                let completed =
                    Task.WhenAny(tcs.Task, Task.Delay(AgentBridgeService.ConfirmTimeoutMs))
                        .GetAwaiter().GetResult()
                if completed <> (tcs.Task :> Task) then
                    (false, $"no answer in {AgentBridgeService.ConfirmTimeoutMs / 1000}s")
                else
                    let allowed, always, note = tcs.Task.Result
                    if allowed && always then
                        lock sessionToolsLock (fun () -> sessionAllowedTools.Add(grantKey) |> ignore)
                        this.LogActivity("session", "grant",
                            $"{grantKey} allowed for the rest of the session" +
                            (if grantKey <> toolName then " (this target only)" else ""))
                    (allowed, note)

    // ── activity log + feed (Phase 1) ─────────────────────────────────

    member _.LogActivity (kind: string, what: string, detail: string,
                                  [<Optional; DefaultParameterValue(null: string)>] outcome: string) =
        try
            Directory.CreateDirectory(agentDir) |> ignore
            let line = JsonObject()
            line["t"] <- JsonValue.Create(DateTime.Now.ToString("o"))
            line["kind"] <- JsonValue.Create(kind)
            line["what"] <- JsonValue.Create(what)
            line["client"] <- JsonValue.Create(if isNull clientName then "" else clientName)
            if not (String.IsNullOrEmpty detail) then line["detail"] <- JsonValue.Create(detail)
            if not (isNull outcome) then line["outcome"] <- JsonValue.Create(outcome)
            BufferedAppender.Append(activityPath, line.ToJsonString())
        with _ -> () // best-effort audit trail

    member private _.AppendFeed (snapshot: JsonObject) =
        try
            Directory.CreateDirectory(agentDir) |> ignore
            snapshot["t"] <- JsonValue.Create(DateTime.Now.ToString("o"))
            BufferedAppender.Append(feedPath, snapshot.ToJsonString())
        with _ -> () // best-effort feed

    // (A periodic full-snapshot feed loop once lived here, present but
    // unreferenced in the C# original and never wired into Start. Removed
    // in the 2026-11 dead-code pass: feed.jsonl carries the session-start
    // snapshot written at Start(), and live state comes from
    // IAgentTools/BuildMonitorSnapshot on demand.)

    // ── plumbing ──────────────────────────────────────────────────────

    static member private ReadUntilAsync (stream: NetworkStream, terminator: string, maxBytes: int) : Task<string> =
        task {
            let buffer = Array.zeroCreate<byte> 1
            let sb = StringBuilder()
            let raw = new MemoryStream()
            let mutable finished = false
            let mutable result: string = null
            while not finished do
                let s = sb.ToString()
                if s.EndsWith(terminator, StringComparison.Ordinal) || raw.Length >= maxBytes then
                    finished <- true
                    result <- s
                else
                    let! n = stream.ReadAsync(buffer, 0, 1)
                    if n = 0 then
                        finished <- true
                        result <- (if sb.Length = 0 then null else sb.ToString())
                    else
                        raw.WriteByte(buffer.[0])
                        sb.Append(char buffer.[0]) |> ignore
            return result
        }

    static member private ReadExactAsync (stream: NetworkStream, count: int) : Task<string> =
        task {
            let buffer = Array.zeroCreate<byte> count
            let mutable read = 0
            let mutable reading = true
            while reading && read < count do
                let! n = stream.ReadAsync(buffer, read, count - read)
                if n = 0 then reading <- false else read <- read + n
            return Encoding.UTF8.GetString(buffer, 0, read)
        }

    /// <summary>Reads and discards the announced request body before an
    /// early rejection. Disposing a socket with UNREAD bytes in the receive
    /// buffer makes Windows send RST instead of FIN — a client that reads
    /// its response lazily then loses the bytes we just wrote (the flaky
    /// "response vanished" class). Best-effort: lying Content-Length or a
    /// vanished client gives up quietly.</summary>
    static member private DrainBody (stream: NetworkStream, headers: Dictionary<string, string>) : Task =
        task {
            let announced =
                match headers.TryGetValue("Content-Length") with
                | true, cl -> (match Int32.TryParse(cl) with true, n when n > 0 && n <= AgentBridgeService.MaxBodyBytes -> Some n | _ -> None)
                | _ -> None
            match announced with
            | None -> ()
            | Some total ->
                let buffer = Array.zeroCreate<byte> 8192
                let mutable read = 0
                let mutable draining = true
                while draining && read < total do
                    try
                        let! n = stream.ReadAsync(buffer, 0, Math.Min(buffer.Length, total - read))
                        if n = 0 then draining <- false else read <- read + n
                    with _ -> draining <- false
        } :> Task

    static member private WriteRaw (stream: NetworkStream, text: string) : Task =
        task {
            let bytes = Encoding.ASCII.GetBytes(text)
            do! stream.WriteAsync(bytes, 0, bytes.Length)
            do! stream.FlushAsync()
        } :> Task

    static member private WriteResponse (stream: NetworkStream, status: int, body: JsonObject) : Task =
        // re-serialization point for every 200: the relaxed encoder decides
        // here how tool JSON embedded as content.text is escaped
        AgentBridgeService.WriteJsonResponse(stream, status,
            (if isNull body then "" else body.ToJsonString(AgentBridgeService.JsonOpts)))

    static member private WriteJsonResponse (stream: NetworkStream, status: int, json: string) : Task =
        task {
            let payload = Encoding.UTF8.GetBytes(if isNull json then "" else json)
            let reason =
                match status with
                | 200 -> "OK" | 202 -> "Accepted" | 400 -> "Bad Request" | 401 -> "Unauthorized"
                | 403 -> "Forbidden" | 405 -> "Method Not Allowed" | 411 -> "Length Required"
                | 413 -> "Payload Too Large" | 500 -> "Internal Server Error"
                | _ -> "Error"
            let head = $"HTTP/1.1 {status} {reason}\r\n" +
                       "Content-Type: application/json\r\n" +
                       $"Content-Length: {payload.Length}\r\n" +
                       "Connection: close\r\n\r\n"
            do! AgentBridgeService.WriteRaw(stream, head)
            if payload.Length > 0 then do! stream.WriteAsync(payload, 0, payload.Length)
            do! stream.FlushAsync()
        } :> Task

    static member private RpcResult (id: JsonNode, result: JsonObject) : string =
        let o = JsonObject()
        o["jsonrpc"] <- JsonValue.Create("2.0")
        o["id"] <- (if isNull id then null else id.DeepClone())
        o["result"] <- result
        o.ToJsonString(AgentBridgeService.JsonOpts)

    static member private RpcError (id: JsonNode, code: int, message: string) : string =
        let o = JsonObject()
        o["jsonrpc"] <- JsonValue.Create("2.0")
        o["id"] <- (if isNull id then null else id.DeepClone())
        let err = JsonObject()
        err["code"] <- JsonValue.Create(code)
        err["message"] <- JsonValue.Create(message)
        o["error"] <- err
        o.ToJsonString(AgentBridgeService.JsonOpts)

    static member private SummarizeArgs (args: JsonObject) =
        try args.ToJsonString()
        with _ -> ""
