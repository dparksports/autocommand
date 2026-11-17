// Traffic Peek engine: the Process Monitor's "Peer into this connection"
// action. While one peek window is open, a FlowPeekService holds the
// shared TcpStreamCaptureService via AddRef/Release (it runs for nobody
// else today), filters every finalized TCP flow to the peered subject,
// runs it through the TLS decryptor, and hands the result to the view.
//
// A subject is one of three scopes:
//   RemoteIpScope  — one remote IP ("this connection")
//   ProgramScope   — one program instance, matched by the PID Sysmon EID 3
//                    attributes (never image-matched for shared hosts)
//   ServiceScope   — a svchost-hosted service name (DiagTrack, CryptSvc…),
//                    matched by resolving each connecting PID's hosted
//                    services — the pin survives service restarts, where
//                    a PID-anchored scope would go stale
//
// Honesty rules (same vocabulary the Transmissions pipeline uses):
//   • TLS metadata (SNI/ALPN/cipher) is always extracted from the
//     ClientHello — keys or no keys.
//   • Plaintext appears only when session keys exist in the keylog.
//     schannel services (wuauserv, bits, DoSvc …) never log keys, so
//     their rows stay metadata-only and say exactly why.
//   • Nothing is persisted: PersistFlows stays off, entries are
//     fire-and-forget events. The capture lives exactly as long as the
//     window that asked for it.
//
// PID attribution rides Sysmon EID 3 via this service's own
// SysmonConnectWatcherService feeding TagFlow — first-writer-wins, so a
// future pipeline doing the same is harmless.

namespace AutoCommand.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.Diagnostics.Eventing.Reader
open System.Globalization
open System.Management
open System.Text
open System.Threading

/// <summary>
/// What one Traffic Peek watches: a remote IP ("this connection"), one
/// program instance ("this program", PID-anchored via Sysmon EID 3), or
/// one svchost-hosted service by NAME ("DiagTrack") — the only anchor
/// that survives service restarts, so a pinned service keeps being
/// tracked no matter which instance pops up.
/// </summary>
type PeekScope =
    | RemoteIpScope of ip: string
    | ProgramScope of pid: int * image: string
    | ServiceScope of service: string

/// PID → hosted-services resolution for ServiceScope, cached per PID with
/// a short TTL: a svchost instance's service set never changes while it
/// lives, but PIDs get recycled — a stale answer would attribute a new
/// tenant's traffic to the pinned service. One WMI roundtrip per PID per
/// TTL window; steady state is a dictionary lookup.
module internal ServiceDirectory =
    let private Ttl = TimeSpan.FromSeconds 30.0
    let private cache = ConcurrentDictionary<int, string[] * DateTime>()
    let private gate = obj ()

    let private Fresh(pid: int) : string[] =
        lock gate (fun () ->
            let now = DateTime.UtcNow
            match cache.TryGetValue pid with
            | true, (s, seen) when now - seen < Ttl -> s
            | _ ->
                let found =
                    try
                        use searcher = new ManagementObjectSearcher(
                            $"SELECT Name FROM Win32_Service WHERE ProcessId = {pid}")
                        Array.ofList [ for o in searcher.Get() -> o["Name"].ToString() ]
                    with _ -> [||]
                cache[pid] <- (found, now)
                found)

    let HostsService(pid: int, service: string) : bool =
        if pid <= 0 || String.IsNullOrWhiteSpace service then false
        else
            let services = Fresh pid
            services |> Array.exists (fun s -> String.Equals(s, service, StringComparison.OrdinalIgnoreCase))

    /// Drop a dead PID's entry (called on exit events; cheap enough to skip).
    let Forget(pid: int) = cache.TryRemove pid |> ignore

    /// Self-test seam: pin a fake pid → services answer without WMI.
    let internal Override(pid: int, services: string[]) =
        cache[pid] <- (services, DateTime.UtcNow)

/// Short status for the flows list — the pipeline's vocabulary, with
/// "not TLS" for flows that carried no handshake at all.
module private PeekStatus =
    let Short(decrypt: TlsDecryptResult) : string =
        let mutable s =
            if decrypt.Success then "decrypted"
            elif decrypt.Status <> null && decrypt.Status.Contains("No TLS handshake") then "not TLS"
            elif decrypt.Status <> null && (decrypt.Status.Contains("no TLS secrets") ||
                                            decrypt.Status.Contains("Not instrumented") ||
                                            decrypt.Status.Contains("keylogging is disabled")) then "encrypted (no keys)"
            elif decrypt.Status <> null && decrypt.Status.Contains("Unsupported cipher") then "unsupported cipher"
            else "undecryptable"
        if decrypt.Truncated && not (s.Contains "truncated") then s <- s + " · truncated"
        s

/// <summary>
/// Scope matching shared by the flow filter and the TagFlow filter. Shared
/// hosts (svchost, taskhostw…) host many processes at once, so they are
/// NEVER image-matched — a program scope on svchost.exe matches only its
/// exact PID, and a service scope resolves the PID's hosted services
/// instead (the ii InterceptProxyService guard, carried over).
/// </summary>
module private Peek =
    let SharedHostImages =
        HashSet<string>(
            [| "svchost.exe"; "taskhostw.exe"; "runtimebroker.exe"; "dllhost.exe"
               "explorer.exe"; "conhost.exe"; "csrss.exe" |],
            StringComparer.OrdinalIgnoreCase)

    let Display(scope: PeekScope) : string =
        match scope with
        | RemoteIpScope ip -> $"ip {ip}"
        | ProgramScope (pid, image) ->
            let name = if String.IsNullOrEmpty image then "?" else IO.Path.GetFileName image
            $"{name} (PID {pid})"
        | ServiceScope service -> $"service {service}"

    let MatchesConnect(scope: PeekScope, evt: SysmonConnectEvent) : bool =
        match scope with
        | RemoteIpScope ip ->
            String.Equals(evt.DestIp, ip, StringComparison.OrdinalIgnoreCase)
            || String.Equals(evt.SourceIp, ip, StringComparison.OrdinalIgnoreCase)
        | ProgramScope (pid, image) ->
            if pid > 0 && evt.Pid = pid then true
            elif String.IsNullOrEmpty image then false
            else
                let name = IO.Path.GetFileName image
                not (SharedHostImages.Contains name)
                && String.Equals(evt.Image, image, StringComparison.OrdinalIgnoreCase)
        | ServiceScope service -> ServiceDirectory.HostsService(evt.Pid, service)

    let MatchesFlow(scope: PeekScope, flow: TcpFlowRecord) : bool =
        match scope with
        | RemoteIpScope ip ->
            let prefix = ip + ":"
            (flow.ServerEndpoint <> null && flow.ServerEndpoint.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            || (flow.ClientEndpoint <> null && flow.ClientEndpoint.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        | ProgramScope (pid, image) ->
            if pid > 0 && flow.Pid = pid then true
            elif String.IsNullOrEmpty image || flow.Pid = 0 then false
            else
                let name = IO.Path.GetFileName image
                not (SharedHostImages.Contains name)
                && String.Equals(flow.Image, image, StringComparison.OrdinalIgnoreCase)
        | ServiceScope service -> ServiceDirectory.HostsService(flow.Pid, service)

/// <summary>
/// One peered conversation: the finalized TCP flow plus the decryptor's
/// honest verdict. Carries its own display strings so the view binds
/// directly (the TransmissionRecord pattern — engine types own their
/// row presentation).
/// </summary>
type PeekEntry(flow: TcpFlowRecord, decrypt: TlsDecryptResult, scope: PeekScope) =

    // Which side of the conversation is the peered endpoint, decided once.
    // IP scope picks whichever endpoint carries the peered IP; program and
    // service scopes have no endpoint anchor — display server as remote.
    let serverIsPeer =
        match scope with
        | RemoteIpScope ip -> flow.ServerEndpoint <> null && flow.ServerEndpoint.StartsWith(ip + ":", StringComparison.OrdinalIgnoreCase)
        | ProgramScope _ | ServiceScope _ -> true
    let clientIsPeer =
        match scope with
        | RemoteIpScope ip -> flow.ClientEndpoint <> null && flow.ClientEndpoint.StartsWith(ip + ":", StringComparison.OrdinalIgnoreCase)
        | ProgramScope _ | ServiceScope _ -> false

    member _.Status: string = PeekStatus.Short decrypt

    member _.Flow: TcpFlowRecord = flow
    member _.Decrypt: TlsDecryptResult = decrypt

    /// The peered endpoint of this flow ("ip:port"), whichever side it was.
    member _.RemoteEndpoint: string =
        if serverIsPeer then flow.ServerEndpoint
        elif clientIsPeer then flow.ClientEndpoint
        else flow.ServerEndpoint

    member _.LocalEndpoint: string =
        if serverIsPeer then flow.ClientEndpoint else flow.ServerEndpoint

    member _.TimeDisplay =
        let t = if flow.EndedUtc = DateTime() then DateTime.UtcNow else flow.EndedUtc
        t.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture)

    member _.UpDisplay = PeekEntry.FormatBytes flow.ClientBytes
    member _.DownDisplay = PeekEntry.FormatBytes flow.ServerBytes

    member _.SniDisplay =
        if String.IsNullOrEmpty decrypt.Sni then "(no SNI)" else decrypt.Sni

    member _.ProcessDisplay =
        if flow.Pid > 0 then
            let image = if String.IsNullOrEmpty flow.Image then "?" else IO.Path.GetFileName flow.Image
            $"{image} · pid {flow.Pid}"
        else "unattributed"

    static member FormatBytes(bytes: int64) : string =
        if bytes >= (1L <<< 20) then $"{float bytes / float (1L <<< 20):F1} MB"
        elif bytes >= (1L <<< 10) then $"{float bytes / float (1L <<< 10):F1} KB"
        else $"{bytes} B"

/// <summary>
/// One service-activity line for the peek window's log pane, read from
/// the Windows Update / BITS / Delivery Optimization operational
/// channels — the plaintext "what did this service actually do" that TLS
/// metadata cannot show.
/// </summary>
type ServiceEventLine() =
    member val TimeUtc = DateTime() with get, set
    member val Channel = null with get, set
    member val EventId = 0 with get, set
    member val Message = null with get, set

    member this.ChannelDisplay =
        if String.IsNullOrEmpty this.Channel then "?"
        else
            // "Microsoft-Windows-WindowsUpdateClient/Operational" → "WindowsUpdateClient"
            let head = this.Channel.Split('/').[0]
            let lastDot = head.LastIndexOf('.')
            if lastDot >= 0 && lastDot < head.Length - 1 then head.Substring(lastDot + 1) else head

    member this.TimeDisplay = this.TimeUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture)

/// <summary>
/// Reads the service-operational event channels for a time window.
/// Missing channels (Delivery Optimization is absent on some SKUs) and
/// unreadable providers never fail the probe — they just contribute
/// nothing. Read-only; no channel is created or written.
/// </summary>
module ServiceLogProbe =

    let Channels =
        [| "Microsoft-Windows-WindowsUpdateClient/Operational"
           "Microsoft-Windows-Bits-Client/Operational"
           "Microsoft-Windows-DeliveryOptimization/Operational" |]

    let MaxPerChannel = 50
    let MaxTotal = 60

    let private JoinProperties(er: EventRecord) : string =
        try
            let sb = StringBuilder()
            for p in er.Properties do
                if not (String.IsNullOrWhiteSpace (p.Value |> string)) then
                    if sb.Length > 0 then sb.Append(" | ") |> ignore
                    sb.Append(string p.Value) |> ignore
            if sb.Length = 0 then "<no description>" else sb.ToString()
        with _ -> "<no description>"

    /// FormatDescription throws when the provider metadata is unavailable
    /// (classic for forwarded/DO events) — fall back to the raw properties.
    let private FormatSafe(er: EventRecord) : string =
        try
            let s = er.FormatDescription()
            if String.IsNullOrWhiteSpace s then JoinProperties er else s
        with _ -> JoinProperties er

    /// Events between the window bounds (UTC), newest first, at most
    /// <see cref="MaxTotal"/>. The window is expressed "ms ago" through
    /// timediff — the one time filter event-log XPath accepts reliably
    /// across locales.
    let QueryEvents(windowStartUtc: DateTime, windowEndUtc: DateTime) : ResizeArray<ServiceEventLine> =
        let now = DateTime.UtcNow
        // events cannot be in the future; clamp the end so the timediff
        // window covers the whole requested range
        let endUtc = min windowEndUtc now
        let msAgo = max 0L (int64 (now - windowStartUtc).TotalMilliseconds) + 1000L
        let xpath = $"*[System[TimeCreated[timediff(@SystemTime) <= {msAgo}]]]"

        let all = ResizeArray<ServiceEventLine>()
        for channel in Channels do
            try
                let query = EventLogQuery(channel, PathType.LogName, xpath)
                use reader = new EventLogReader(query)
                let perChannel = ResizeArray<ServiceEventLine>()
                let mutable er = reader.ReadEvent()
                while not (isNull er) && perChannel.Count < MaxPerChannel do
                    try
                        let line = ServiceEventLine(
                            TimeUtc = (if er.TimeCreated.HasValue then er.TimeCreated.Value.ToUniversalTime() else now),
                            Channel = channel,
                            EventId = er.Id,
                            Message = FormatSafe er)
                        if line.TimeUtc >= windowStartUtc && line.TimeUtc <= endUtc.AddSeconds 2.0 then
                            perChannel.Add line
                    with _ -> ()
                    (try er.Dispose() with _ -> ())
                    er <- reader.ReadEvent()
                all.AddRange perChannel
            with
            | :? EventLogNotFoundException -> () // channel absent on this SKU — fine
            | _ -> ()                            // any other channel failure — fine

        // newest first, merged across channels
        let sorted = all |> Seq.sortByDescending (fun l -> l.TimeUtc) |> Seq.truncate MaxTotal
        ResizeArray sorted

/// <summary>
/// The peer service behind one Traffic Peek window. Start() takes a
/// refcount on the shared capture, shortens its idle sweep so quiet
/// conversations surface within seconds, tags matching Sysmon EID 3
/// connects with pid/image, and decrypts every finalized flow that
/// belongs to the scope (remote IP / program instance / hosted service)
/// on a private worker thread. Stop() undoes all of it; a window closing
/// must always pair the two.
/// </summary>
type FlowPeekService private (scope: PeekScope) as this =

    let capture = TcpStreamCaptureService.Shared
    let keylog = TlsKeylogService()
    let mutable connectWatcher: SysmonConnectWatcherService = Unchecked.defaultof<_>
    let mutable worker: Thread = null
    let mutable cts: CancellationTokenSource = null
    // Recreated per Start: CompleteAdding is permanent (the pipeline's lesson).
    let mutable queue = new BlockingCollection<TcpFlowRecord>(boundedCapacity = 64)
    let mutable running = 0
    let mutable entries = 0L

    let onEntry = DelegateEvent<Action<PeekEntry>>()
    let onError = DelegateEvent<Action<string>>()

    // Stable delegate so Stop() removes exactly what Start() added.
    let onFlowFinalizedHandler = Action<TcpFlowRecord>(fun flow -> this.OnFlowFinalized flow)

    // Peek windows can overlap; only the first shortens the sweep and the
    // last departure restores it. The original timeout is captured AT the
    // 0→1 transition, not at construction: a second peek constructed while
    // the first had already shortened the capture used to save the
    // SHORTENED value as "original", and when it was the last to stop the
    // shared capture stayed at the 10 s sweep for the whole session.
    static let mutable activePeeks = 0
    // Overwritten at every 0→1 transition before any restore can read it.
    static let mutable savedIdleTimeout = Unchecked.defaultof<TimeSpan>

    // C#-friendly construction — no DU syntax leaks into the views/tests.
    static member ForIp(ip: string) = FlowPeekService(RemoteIpScope ip)
    static member ForProgram(pid: int, image: string) = FlowPeekService(ProgramScope(pid, image))
    static member ForService(service: string) = FlowPeekService(ServiceScope service)
    static member OfScope(scope: PeekScope) = FlowPeekService scope

    /// How many peeks hold the capture right now (self-test seam).
    static member ActiveCount = activePeeks

    member _.ScopeDisplay: string = Peek.Display scope

    member _.IsRunning = Volatile.Read(&running) = 1

    /// Finalized, peered flows processed so far.
    member _.EntryCount = Interlocked.Read(&entries)

    [<CLIEvent>]
    member _.OnEntry = onEntry.Publish

    [<CLIEvent>]
    member _.OnError = onError.Publish

    member _.Start() =
        if Interlocked.Exchange(&running, 1) = 1 then ()
        else
            queue <- new BlockingCollection<TcpFlowRecord>(boundedCapacity = 64)
            cts <- new CancellationTokenSource()

            // Respect the opt-out: never recreate a keylog file the user
            // disabled (the flag file is the contract).
            if TlsKeylogService.KeylogEnabled then
                try TlsKeylogService.EnsureHygiene() with _ -> ()

            if Interlocked.Increment(&activePeeks) = 1 then
                savedIdleTimeout <- capture.IdleTimeout
                capture.IdleTimeout <- TimeSpan.FromSeconds 10.0

            connectWatcher <- new SysmonConnectWatcherService()
            connectWatcher.add_OnError(Action<string>(fun e -> onError.Trigger [| box e |]))
            connectWatcher.add_OnConnect(Action<SysmonConnectEvent>(fun evt -> this.OnConnect evt))
            connectWatcher.Start() // raises OnError (not fatal) when Sysmon is absent

            capture.add_OnFlowFinalized onFlowFinalizedHandler
            capture.AddRef() // balanced by Stop() — the capture runs while the peek does

            worker <- new Thread(ThreadStart(fun () -> this.ProcessQueue()),
                                 IsBackground = true, Name = "FlowPeek")
            worker.Start()

    member _.Stop() =
        if Interlocked.Exchange(&running, 0) = 0 then ()
        else
            capture.remove_OnFlowFinalized onFlowFinalizedHandler
            (if not (isNull (box connectWatcher)) then connectWatcher.Stop())
            connectWatcher <- Unchecked.defaultof<_>
            capture.Release()

            if Interlocked.Decrement(&activePeeks) = 0 then
                capture.IdleTimeout <- savedIdleTimeout

            queue.CompleteAdding()
            (try (if not (isNull worker) then worker.Join(TimeSpan.FromSeconds 3.0) |> ignore) with _ -> ())
            (if not (isNull cts) then cts.Cancel())

    member private _.OnConnect(evt: SysmonConnectEvent) =
        if not evt.IsTcp then ()
        elif not (Peek.MatchesConnect(scope, evt)) then ()
        else capture.TagFlow(evt.SourceIp, evt.SourcePort, evt.DestIp, evt.DestPort, evt.Pid, evt.Image) |> ignore

    member private _.OnFlowFinalized(flow: TcpFlowRecord) =
        // Raised on capture threads — filter cheap, enqueue or drop, never block.
        if not (Peek.MatchesFlow(scope, flow)) then ()
        elif not (queue.TryAdd flow) then () // queue full: decryption outpaced — drop silently
        else Interlocked.Increment(&entries) |> ignore

    member private _.ProcessQueue() =
        try
            for flow in queue.GetConsumingEnumerable cts.Token do
                try this.Process flow
                with _ -> () // one flow's failure never stops the peek
        with
        | :? OperationCanceledException -> ()
        | _ -> () // shutdown race

    member private this.Process(flow: TcpFlowRecord) =
        keylog.Refresh()
        let result = TlsDecryptor.Decrypt(flow, keylog)
        onEntry.Trigger [| box (PeekEntry(flow, result, scope)) |]
