// F# port of Core\NetWatch\DnsResolutionService.cs + DnsResolutionService.Geo.cs
// (namespace AutoCommand.NetWatch.Core) — now the FULL autocommand-ii engine,
// not the pre-geo autoscope port: the /24 prefix geo cache with adaptive
// backoff, the RDAP registry fallback (Engines.Watch/Rdap.fs), the
// resolve-state visibility (DescribeResolveState), the user-initiated
// ResolveNow / RetryUnresolved, and the idle reconciler that drains
// unresolved addresses when the machine's traffic goes quiet.
// Behavioral faithfulness is the contract: same TTLs, same throttle and
// backoff, same queue caps, same persisted JSON shapes (short keys
// "h"/"t"/"i" and "L"/"T"/"N"), same public member names.
//
// F# port notes (deviations, none behavioral beyond the cache location):
//   • C# cached beside the exe / in ProgramData; engines take every path
//     from the identity, so the three cache files live under
//     WatchConfig.Identity.DataRoot. Same file names, same JSON.
//   • The C# private nested classes (CacheEntry, GeoCacheEntry,
//     AdHocResolve, the persist DTOs) are file-private top-level types —
//     F# cannot nest type declarations inside a class; the JSON DTOs are
//     public in the DnsJsonDto module (private DTO properties would
//     compile non-public and System.Text.Json would silently write {}).
//   • The C# private struct GeoResult {Kind, Label} is a private DU
//     (GeoOutcome) — same three answers, exhaustive by construction.
//   • C# caches rdap/geo per INSTANCE via the singleton; the F# port
//     constructs RdapService.Instance the same way.

namespace AutoCommand.Engines.Watch

open System
open System.Collections.Concurrent
open System.Collections.Generic
open System.IO
open System.Net
open System.Net.Http
open System.Text.Json
open System.Threading
open System.Threading.Channels
open System.Threading.Tasks
open System.Runtime.InteropServices
open AutoCommand.Engines.Core

// -----------------------------------------------------------------------
// Inner types (F# port: C# nested them inside the class)
// -----------------------------------------------------------------------

/// <summary>Reverse-cache row: ip → (hostname, resolved-at).</summary>
type private CacheEntry(hostname: string, resolvedAt: DateTime) =

    member _.Hostname: string = hostname
    member _.ResolvedAt: DateTime = resolvedAt
    member _.IsStale(ttl: TimeSpan) : bool = (DateTime.UtcNow - resolvedAt) > ttl

module DnsJsonDto =

    /// <summary>Used only for JSON serialization (short keys to keep files small).</summary>
    type PersistedEntry() =
        member val H: string = null with get, set // hostname
        member val T = DateTime() with get, set // resolved-at (UTC)

    type PersistedForwardEntry() =
        member val I: string[] = null with get, set // resolved IPs (empty = negative entry)
        member val T = DateTime() with get, set // resolved-at (UTC)

    type PersistedGeoEntry() =
        member val L: string = null with get, set // label ("" for negative entries)
        member val T = DateTime() with get, set // resolved-at (UTC)
        member val N = false with get, set // negative?

type private ForwardCacheEntry(ips: string[], resolvedAt: DateTime, ttl: TimeSpan) =
    let expiresAt = resolvedAt + ttl

    member _.Ips: string[] = ips
    member _.ResolvedAt: DateTime = resolvedAt
    member _.IsStale: bool = DateTime.UtcNow >= expiresAt

/// <summary>One org·country answer for a whole /24 block (or one IPv6 address).</summary>
type private GeoCacheEntry(label: string, resolvedAt: DateTime, negative: bool) =

    member _.Label: string = label
    member _.ResolvedAt: DateTime = resolvedAt
    /// <summary>definitive no-data — shorter TTL</summary>
    member _.Negative: bool = negative
    member _.IsStale(ttl: TimeSpan) : bool = (DateTime.UtcNow - resolvedAt) > ttl

/// <summary>
/// The geo pipeline's three answers (was the C# private struct GeoResult
/// with Kind/Label): a label, a definitive no-data, or a transient
/// failure that must cache nothing.
/// </summary>
type private GeoOutcome =
    | GeoOk of label: string
    | GeoNoData
    | GeoRetryLater

/// <summary>An urgent lookup queued by ResolveNow/RetryUnresolved/the idle
/// reconciler — carries no row to update; only the network answer and the
/// cache write matter.</summary>
type private AdHocResolve(remoteIp: string) =
    member val Hostname: string = remoteIp with get, set
    interface IResolvableHost with
        member this.RemoteIp: string = remoteIp
        member this.Hostname with get () = this.Hostname and set (v) = this.Hostname <- v

/// <summary>
/// Resolves IP → hostname in the background, with a persistent JSON cache,
/// rate-limited queues, live row updates via INotifyPropertyChanged — and,
/// when reverse DNS has nothing, the org engine: locally classified ranges
/// first, then the /24 prefix cache, then RDAP over HTTPS (IANA-bootstrap
/// routed, its own cache and pacing). The old ip-api.com step — the one
/// cleartext-HTTP egress in the app, broadcasting every unclassified
/// destination IP to the network path — is gone; RDAP-only attribution
/// keeps org·country labels flowing with no plaintext sender anywhere.
/// </summary>
type DnsResolutionService() as this =

    // ── constants ─────────────────────────────────────────────────────
    static let dnsCacheTtl = TimeSpan.FromHours 24.
    static let geoCacheTtl = TimeSpan.FromDays 14.
    static let geoNegativeTtl = TimeSpan.FromHours 24.
    static let forwardCacheTtl = TimeSpan.FromMinutes 60.
    static let forwardNegativeTtl = TimeSpan.FromMinutes 10.
    static let saveInterval = TimeSpan.FromSeconds 60.

    // ── fields ────────────────────────────────────────────────────────
    let cache = ConcurrentDictionary<string, CacheEntry>()
    let forwardCache = ConcurrentDictionary<string, ForwardCacheEntry>()
    let forwardGate = new SemaphoreSlim(1, 1)

    // Queue of items waiting for resolution; bounded to avoid runaway growth
    let queue =
        Channel.CreateBounded<IResolvableHost>(
            BoundedChannelOptions(512, FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true)
        )

    let cts = new CancellationTokenSource()
    let mutable workerTask: Task = null
    let mutable saveTimer: Timer = null
    let mutable started = 0

    // "a.b.c.0/24" (IPv4; full address for IPv6) → (org·code, resolvedAt, negative)
    let geoCache = ConcurrentDictionary<string, GeoCacheEntry>()

    /// <summary>Addresses queued for background resolution — the honest
    /// "resolving" state for DescribeResolveState (a Channel cannot be
    /// peeked without consuming).</summary>
    let pendingIps = ConcurrentDictionary<string, byte>()

    // idle reconciliation state
    let idleAttempts = ConcurrentDictionary<string, int>()
    let mutable idleStarted = 0
    let mutable idleFor: Func<TimeSpan> = null

    static let instance = new DnsResolutionService()

    do
        this.LoadCacheFromDisk()
        this.LoadForwardCacheFromDisk()
        this.LoadGeoCacheFromDisk()

    // idle reconciliation: drains unresolved addresses when the machine's
    // traffic is quiet (no new Sysmon events)
    static member internal IdleThreshold = TimeSpan.FromMinutes 5.
    static member internal IdleTick = TimeSpan.FromMinutes 1.
    static member internal IdleBatchSize = 8
    static member internal IdleBatchCooldown = TimeSpan.FromMinutes 2.
    static member internal IdleMaxAttemptsPerIp = 5

    static member private CacheFilePath =
        Path.Combine(WatchConfig.Identity.DataRoot, "dns_cache.json")

    static member private ForwardCacheFilePath =
        Path.Combine(WatchConfig.Identity.DataRoot, "dns_forward_cache.json")

    static member private GeoCacheFilePath =
        Path.Combine(WatchConfig.Identity.DataRoot, "geo_prefix_cache.json")

    // ── public API ────────────────────────────────────────────────────

    static member Instance: DnsResolutionService = instance

    /// <summary>
    /// Starts the background resolution worker. Idempotent — every consumer
    /// (Svchost monitor, Traffic Patterns, BITS) may call it on the shared
    /// instance; only the first spawns the single reader.
    /// </summary>
    member _.Start() : unit =
        if Interlocked.Exchange(&started, 1) = 0 then
            workerTask <- Task.Run(fun () -> this.WorkerLoopAsync cts.Token)

            saveTimer <-
                new Timer(
                    (fun _ ->
                        this.SaveCacheToDisk()
                        this.SaveGeoCacheToDisk()),
                    null,
                    saveInterval,
                    saveInterval
                )

    /// <summary>Returns the cached hostname for <c>ip</c> synchronously, or null if not yet resolved.</summary>
    member _.GetCachedHostname(ip: string) : string =
        let mutable entry = Unchecked.defaultof<CacheEntry>

        match cache.TryGetValue(ip, &entry) with
        | true when not (entry.IsStale dnsCacheTtl) -> entry.Hostname
        | _ -> null

    /// <summary>
    /// Resolves <c>item</c>.RemoteIp → Hostname asynchronously. If a fresh
    /// cache entry exists, the item is updated immediately on the calling
    /// thread; otherwise it is queued for background resolution and the
    /// DataGrid row will update itself via INotifyPropertyChanged.
    /// </summary>
    member _.EnqueueForResolution(item: IResolvableHost) : unit =
        if not (isNull (box item)) && not (String.IsNullOrEmpty item.RemoteIp) then
            if DnsResolutionService.IsUnresolvedHostname item.Hostname then
                let mutable entry = Unchecked.defaultof<CacheEntry>

                match cache.TryGetValue(item.RemoteIp, &entry) with
                | true when not (entry.IsStale dnsCacheTtl) -> item.Hostname <- entry.Hostname
                | _ ->
                    // drops silently if full
                    if queue.Writer.TryWrite item then pendingIps.[item.RemoteIp] <- 1uy

    /// <summary>Pre-seeds the cache with a Sysmon-provided hostname (already resolved at event time).</summary>
    member _.SeedFromSysmon(ip: string, hostname: string) : unit =
        if
            not (String.IsNullOrEmpty ip)
            && not (String.IsNullOrEmpty hostname)
            && hostname <> "-"
        then
            cache.[ip] <- CacheEntry(hostname, DateTime.UtcNow)

    // ── resolve-state visibility + user-initiated retries ─────────────

    /// <summary>
    /// User-initiated immediate retry for one address ("Resolve now" on a
    /// row): forget this prefix's cached answer (a negative one would
    /// otherwise suppress the re-ask for 24 h), reset the provider
    /// backoff, and queue a fresh lookup whose API call skips the
    /// inter-request spacing (cooldowns still apply). Returns false when
    /// nothing needed doing — the address already resolves.
    /// </summary>
    member _.ResolveNow(ip: string) : bool =
        if String.IsNullOrEmpty ip || not (fst (IPAddress.TryParse ip)) then false
        elif not (DnsResolutionService.IsGloballyRoutable ip) then false // nothing to ask anyone
        else
            let localCls = IpClassification.classify ip

            if localCls <> "Unclassified" && localCls <> "IPv6/other" then
                false
            else
                geoCache.TryRemove(DnsResolutionService.GeoPrefixKey ip) |> ignore

                let cachedHostname = this.GetCachedHostname ip
                let effective = if isNull (box cachedHostname) then ip else cachedHostname

                if not (DnsResolutionService.IsUnresolvedHostname effective) then
                    false
                else
                    pendingIps.[ip] <- 1uy
                    queue.Writer.TryWrite(AdHocResolve ip) |> ignore
                    true

    /// <summary>
    /// The "Retry unresolved" bulk action: forget every negative geo
    /// answer (definitive only as of when it was asked) and every raw-IP
    /// placeholder in the hostname cache (those placeholders are what
    /// stops EnqueueForResolution from re-queuing), and re-queue the given
    /// addresses — or every pending one when the caller passes none. RDAP's
    /// own pacing applies throughout: the point is a fresh, polite re-ask.
    /// Returns the number re-queued.
    /// </summary>
    member _.RetryUnresolved([<Optional; DefaultParameterValue(null: IEnumerable<string>)>] ips: IEnumerable<string>) : int =
        for kv in geoCache do
            if kv.Value.Negative then geoCache.TryRemove(kv.Key) |> ignore

        for kv in cache do
            if DnsResolutionService.IsUnresolvedHostname kv.Value.Hostname then cache.TryRemove(kv.Key) |> ignore

        let mutable queuedCount = 0

        let source =
            if isNull (box ips) then
                pendingIps.Keys |> Seq.map (fun k -> k) |> Array.ofSeq :> IEnumerable<string>
            else
                ips

        for ip in source do
            if not (String.IsNullOrEmpty ip) && fst (IPAddress.TryParse ip) then
                pendingIps.[ip] <- 1uy
                queue.Writer.TryWrite(AdHocResolve ip) |> ignore
                queuedCount <- queuedCount + 1

        queuedCount

    /// <summary>
    /// Why an address shows no hostname yet — the tooltip text the monitor
    /// rows carry instead of a blank. Null only for a string that is not
    /// an IP.
    /// </summary>
    member _.DescribeResolveState(ip: string) : string =
        if String.IsNullOrEmpty ip || not (fst (IPAddress.TryParse ip)) then null
        elif not (DnsResolutionService.IsGloballyRoutable ip) then
            "local or non-routable address — no hostname/org lookup exists for it"
        else
            let local = IpClassification.classify ip

            if local <> "Unclassified" && local <> "IPv6/other" then
                "classified locally as " + local + " — no lookup needed"
            else
                let mutable entry = Unchecked.defaultof<CacheEntry>

                let resolvedLine =
                    match cache.TryGetValue(ip, &entry) with
                    | true when
                        not (entry.IsStale dnsCacheTtl)
                        && not (DnsResolutionService.IsUnresolvedHostname entry.Hostname)
                        ->
                        Some("resolved " + entry.ResolvedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm"))
                    | _ -> None

                match resolvedLine with
                | Some line -> line
                | None ->
                    let mutable pending = 0uy

                    if pendingIps.TryGetValue(ip, &pending) then
                        "resolving — queued (" + string pendingIps.Count + " waiting)"
                    else
                        let mutable geo = Unchecked.defaultof<GeoCacheEntry>
                        let prefix = DnsResolutionService.GeoPrefixKey ip

                        let geoLine =
                            match geoCache.TryGetValue(prefix, &geo) with
                            | true when geo.Negative ->
                                Some(
                                    "no owner data for this /24 — negative-cached, retries after "
                                    + geo.ResolvedAt.Add(geoNegativeTtl).ToLocalTime().ToString("HH:mm")
                                    + " (or use Resolve now)"
                                )
                            | true when not (geo.IsStale geoCacheTtl) -> Some "resolved from the /24 prefix cache"
                            | _ -> None

                        match geoLine with
                        | Some line -> line
                        | None -> "not resolved yet — queued on the next refresh pass"

    // ── idle reconciliation ───────────────────────────────────────────

    /// <summary>
    /// Every address whose cached answer is a placeholder (no real
    /// hostname yet), oldest attempts first — the idle reconciler's work
    /// queue. The hostname cache already persists these placeholders, so
    /// the set survives restarts.
    /// </summary>
    member _.UnresolvedIps: IReadOnlyList<string> =
        cache
        |> Seq.filter (fun kv -> DnsResolutionService.IsUnresolvedHostname kv.Value.Hostname)
        |> Seq.sortBy (fun kv -> kv.Value.ResolvedAt)
        |> Seq.map (fun kv -> kv.Key)
        |> ResizeArray
        :> IReadOnlyList<string>

    /// <summary>
    /// Starts the idle reconciler: whenever <paramref name="idleFor"/>
    /// reports the machine quiet past IdleThreshold (the app wires this to
    /// the Sysmon watcher's quiet period), drain the unresolved set in
    /// small batches through the normal paced pipeline — never the urgent
    /// path; normal spacing and backoff throughout. Idempotent.
    /// </summary>
    member _.StartIdleReconciliation(idleForArg: Func<TimeSpan>) : unit =
        if Interlocked.Exchange(&idleStarted, 1) = 0 then
            if not (isNull (box idleForArg)) then idleFor <- idleForArg
            Task.Run(fun () -> this.IdleLoopAsync cts.Token) |> ignore

    member private _.IdleLoopAsync(ct: CancellationToken) : Task =
        task {
            let mutable keepGoing = not ct.IsCancellationRequested

            while keepGoing do
                try
                    do! Task.Delay(DnsResolutionService.IdleTick, ct)
                with :? OperationCanceledException -> keepGoing <- false

                if keepGoing then
                    try
                        let idleForNow = if isNull (box idleFor) then TimeSpan.FromDays 365. else idleFor.Invoke()

                        if idleForNow < DnsResolutionService.IdleThreshold then ()
                        elif this.TakeIdleBatch() = 0 then ()
                        else
                            // still idle? wait out the cooldown before the next batch —
                            // a busy machine cancels the wait and the loop re-checks
                            do! Task.Delay(DnsResolutionService.IdleBatchCooldown, ct)
                    with
                    | :? OperationCanceledException -> keepGoing <- false
                    | _ -> () // an idle pass is opportunistic — never fatal
        }

    /// <summary>One idle episode: hand a batch of oldest unresolved
    /// addresses to the normal paced pipeline. Fresh negative answers are
    /// skipped (they were a definitive "no" less than a day ago) and
    /// addresses past the per-session attempt cap are left until their
    /// cache entries age out naturally. Returns the batch size.</summary>
    member private _.TakeIdleBatch() : int =
        let mutable queuedCount = 0

        for ip in this.UnresolvedIps do
            if queuedCount < DnsResolutionService.IdleBatchSize then
                let mutable tries = 0
                let hadTries = idleAttempts.TryGetValue(ip, &tries)

                if hadTries && tries >= DnsResolutionService.IdleMaxAttemptsPerIp then
                    ()
                else
                    let mutable geo = Unchecked.defaultof<GeoCacheEntry>

                    let freshNegative =
                        geoCache.TryGetValue(DnsResolutionService.GeoPrefixKey ip, &geo)
                        && geo.Negative
                        && not (geo.IsStale geoNegativeTtl)

                    if freshNegative then
                        ()
                    else
                        idleAttempts.[ip] <- tries + 1
                        cache.TryRemove(ip) |> ignore // placeholder out — the pipeline must re-ask
                        pendingIps.[ip] <- 1uy
                        queue.Writer.TryWrite(AdHocResolve ip) |> ignore
                        queuedCount <- queuedCount + 1

        queuedCount

    /// <summary>Test seam: one idle episode with an injected idle reading,
    /// bypassing the loop's timer. Internal for NetWatchSelfTest.</summary>
    member internal _.RunIdlePassForTest(idleFor: Func<TimeSpan>) : int =
        let idleForNow = if isNull (box idleFor) then TimeSpan.FromDays 365. else idleFor.Invoke()

        if idleForNow >= DnsResolutionService.IdleThreshold then this.TakeIdleBatch() else 0

    member _.Dispose() : unit =
        if Interlocked.Exchange(&started, 2) <> 2 then
            cts.Cancel()
            queue.Writer.TryComplete() |> ignore
            (if not (isNull (box workerTask)) then workerTask.Wait(TimeSpan.FromSeconds 3.) |> ignore)
            (if not (isNull (box saveTimer)) then saveTimer.Dispose())

            saveTimer <- null
            this.SaveCacheToDisk()
            this.SaveForwardCacheToDisk()
            this.SaveGeoCacheToDisk()
            cts.Dispose()

    interface IDisposable with
        member this.Dispose() = this.Dispose()

    // ── forward resolution (hostname → IPs) — the BITS tab ────────────

    member _.ResolveForwardAsync(host: string) : Task<string[]> =
        task {
            if String.IsNullOrEmpty host || fst (IPAddress.TryParse host) then
                return [| host |]
            else
                let mutable cached = Unchecked.defaultof<ForwardCacheEntry>

                match forwardCache.TryGetValue(host, &cached) with
                | true when not cached.IsStale -> return cached.Ips
                | _ ->
                    do! forwardGate.WaitAsync()

                    try
                        let mutable second = Unchecked.defaultof<ForwardCacheEntry>

                        match forwardCache.TryGetValue(host, &second) with
                        | true when not second.IsStale -> return second.Ips // resolved while waiting on the gate
                        | _ ->
                            let mutable ips: string[] = [||]

                            try
                                let! entry = Dns.GetHostEntryAsync host

                                ips <-
                                    entry.AddressList
                                    |> Array.filter (fun a ->
                                        a.AddressFamily = Sockets.AddressFamily.InterNetwork
                                        || a.AddressFamily = Sockets.AddressFamily.InterNetworkV6)
                                    |> Array.map (fun a -> a.ToString())
                                    |> Array.distinct
                                    |> Array.truncate 6
                            with _ -> () // NXDOMAIN / no resolver answer — negative cache below

                            forwardCache.[host] <-
                                ForwardCacheEntry(
                                    ips,
                                    DateTime.UtcNow,
                                    (if ips.Length = 0 then forwardNegativeTtl else forwardCacheTtl)
                                )

                            if forwardCache.Count % 10 = 0 then this.SaveForwardCacheToDisk ()

                            return ips
                    finally
                        forwardGate.Release() |> ignore
        }

    member private _.LoadForwardCacheFromDisk() : unit =
        try
            if File.Exists DnsResolutionService.ForwardCacheFilePath then
                let dict =
                    JsonSerializer.Deserialize<Dictionary<string, DnsJsonDto.PersistedForwardEntry>>(
                        File.ReadAllText DnsResolutionService.ForwardCacheFilePath
                    )

                if not (isNull (box dict)) then
                    for kv in dict do
                        let ips = (if isNull (box kv.Value.I) then [||] else kv.Value.I)

                        let entry =
                            ForwardCacheEntry(
                                ips,
                                kv.Value.T,
                                (if isNull (box kv.Value.I) || Array.isEmpty kv.Value.I then
                                     forwardNegativeTtl
                                 else forwardCacheTtl)
                            )

                        if not entry.IsStale then forwardCache.[kv.Key] <- entry
        with _ -> () // corrupt or missing file — start fresh

    member private _.SaveForwardCacheToDisk() : unit =
        try
            let dict = Dictionary<string, DnsJsonDto.PersistedForwardEntry>(forwardCache.Count)

            for kv in forwardCache do
                dict.[kv.Key] <- DnsJsonDto.PersistedForwardEntry(I = kv.Value.Ips, T = kv.Value.ResolvedAt)

            DnsResolutionService.AtomicWriteJson(
                DnsResolutionService.ForwardCacheFilePath,
                JsonSerializer.Serialize(dict, JsonSerializerOptions(WriteIndented = false))
            )
        with _ -> () // disk full, permissions — silently skip

    // ── background worker — processes one item at a time ──────────────

    member private _.WorkerLoopAsync(ct: CancellationToken) : Task =
        task {
            // F# port: C#'s `await foreach` + break/continue written as a
            // manual enumerator loop — F# has no break.
            let mutable keepGoing = true
            let reader = queue.Reader.ReadAllAsync(ct).GetAsyncEnumerator ct

            try
                while keepGoing do
                    let! moved = reader.MoveNextAsync().AsTask()

                    if not moved then keepGoing <- false
                    else
                        let item = reader.Current

                        if ct.IsCancellationRequested then keepGoing <- false
                        elif not (DnsResolutionService.IsUnresolvedHostname item.Hostname) then
                            () // resolved by another path
                        else
                            try
                                let! hostname = this.ResolveAsync(item.RemoteIp, ct)
                                // triggers INotifyPropertyChanged → DataGrid refresh
                                item.Hostname <- hostname
                                pendingIps.TryRemove(item.RemoteIp) |> ignore
                            with
                            | :? OperationCanceledException -> keepGoing <- false
                            | _ -> () // silently skip failed items
            finally
                reader.DisposeAsync().AsTask().GetAwaiter().GetResult()

            this.SaveCacheToDisk ()
        }

    // ── resolution pipeline: reverse DNS → geo-IP fallback ────────────

    member private _.ResolveAsync(ip: string, ct: CancellationToken) : Task<string> =
        task {
            // 1. Return fresh cache hit
            let mutable cached = Unchecked.defaultof<CacheEntry>

            if
                cache.TryGetValue(ip, &cached)
                && not (cached.IsStale dnsCacheTtl)
            then
                return cached.Hostname
            else
                // 2. Reverse DNS
                let! dnsAnswer = DnsResolutionService.ReversesDnsAsync ip
                let mutable resolved = dnsAnswer

                // 3. If DNS only gave us the raw IP, try geo-IP (local
                //    ranges and prefix cache first; the API only for
                //    genuinely new blocks)
                let mutable transient = false

                if resolved = ip || DnsResolutionService.IsUnresolvedHostname resolved then
                    let! geo = this.GeoIpLookupAsync(ip, ct)

                    match geo with
                    | GeoOk label when not (String.IsNullOrEmpty label) -> resolved <- label
                    | GeoRetryLater ->
                        // Rate limit / transport failure: no API answer
                        // existed, so caching the raw IP would poison this
                        // address for 24h. Leave it unresolved — the
                        // monitor's re-enqueue tick (or a later session)
                        // retries once the backoff window clears.
                        transient <- true
                    | _ ->
                        // Negative (definitive no-data) falls through and
                        // caches the raw IP as before: the prefix cache
                        // already stops API trips.
                        ()

                if transient then
                    return ip
                else
                    // 4. Store in cache (even failed lookups, so we don't retry immediately)
                    cache.[ip] <- CacheEntry(resolved, DateTime.UtcNow)

                    // 5. Periodically persist to disk (every 20 resolutions; a
                    //    60s timer is the other checkpoint)
                    if cache.Count % 20 = 0 then this.SaveCacheToDisk ()

                    return resolved
        }

    static member private ReversesDnsAsync(ip: string) : Task<string> =
        task {
            try
                let! entry = Dns.GetHostEntryAsync ip
                return if String.IsNullOrEmpty entry.HostName then ip else entry.HostName
            with _ ->
                return ip // DNS NXDOMAIN or timeout
        }

    /// <summary>
    /// Geo/owner label for an IP, cheapest source first:
    ///   1. locally classified ranges (IpClassification) — no network at all;
    ///   2. non-routable addresses (RFC1918, loopback, link-local…) — no
    ///      answer exists, so no trip either;
    ///   3. the /24-prefix cache — one answer serves a whole rotating
    ///      fleet block for two weeks;
    ///   4. RDAP over HTTPS (IANA-bootstrap routed; the engine keeps its
    ///      own cache, pacing and negative state).
    /// Transient failures (timeout, throttle) return RetryLater and cache
    /// NOTHING — a wrong "unresolved" answer must not outlive the outage.
    /// </summary>
    member private _.GeoIpLookupAsync(ip: string, ct: CancellationToken) : Task<GeoOutcome> =
        task {
            // 1–2. Local answers cost nothing and are always in stock.
            if not (DnsResolutionService.IsGloballyRoutable ip) then
                return GeoNoData
            else
                let local = IpClassification.classify ip

                if local <> "Unclassified" && local <> "IPv6/other" then
                    return GeoOk local
                else
                    // 3. Prefix cache (positive and negative both stop API trips)
                    let prefix = DnsResolutionService.GeoPrefixKey ip
                    let mutable cachedGeo = Unchecked.defaultof<GeoCacheEntry>

                    let cacheAnswer =
                        match geoCache.TryGetValue(prefix, &cachedGeo) with
                        | true ->
                            let ttl = if cachedGeo.Negative then geoNegativeTtl else geoCacheTtl

                            if not (cachedGeo.IsStale ttl) then
                                Some(if cachedGeo.Negative then GeoNoData else GeoOk cachedGeo.Label)
                            else None
                        | _ -> None

                    match cacheAnswer with
                    | Some answer -> return answer
                    | None ->
                        // 4. RDAP over HTTPS — the only external attribution
                        //    source (see the type header: the cleartext
                        //    ip-api.com step is gone). The RDAP engine keeps
                        //    its own cache, pacing and negative state; here
                        //    we only translate its answer into the prefix
                        //    cache so the whole /24 stops asking.
                        try
                            let! entry = RdapService.Instance.LookupAsync ip

                            if
                                isNull (box entry)
                                || entry.IsNegative
                                || String.IsNullOrEmpty entry.Org
                            then
                                // Definitive no-data — negative prefix entry,
                                // re-asked only after the negative TTL.
                                geoCache.[prefix] <- GeoCacheEntry("", DateTime.UtcNow, true)
                                return GeoNoData
                            else
                                let mutable org = entry.Org

                                if
                                    org.Length > 3
                                    && org.[0] = 'A'
                                    && org.[1] = 'S'
                                then
                                    let space = org.IndexOf ' '

                                    if space > 0 then org <- org[(space + 1) ..]

                                if String.IsNullOrEmpty org then
                                    geoCache.[prefix] <- GeoCacheEntry("", DateTime.UtcNow, true)
                                    return GeoNoData
                                else
                                    let label =
                                        if String.IsNullOrEmpty entry.Country then org
                                        else $"{org} · {entry.Country}"

                                    geoCache.[prefix] <- GeoCacheEntry(label, DateTime.UtcNow, false)
                                    return GeoOk(label + " · RDAP")
                        with
                        | :? OperationCanceledException ->
                            return! Task.FromException<GeoOutcome>(OperationCanceledException ct)
                        | _ ->
                            // Timeout / throttle — transient: cache nothing, the
                            // monitor's re-enqueue tick retries later.
                            return GeoRetryLater
        }

    /// <summary>/24 network for IPv4 ("a.b.c.0/24"); IPv6 keeps its full address as key.</summary>
    static member internal GeoPrefixKey(ip: string) : string =
        match IPAddress.TryParse ip with
        | true, a when a.AddressFamily = Sockets.AddressFamily.InterNetwork ->
            let b = a.GetAddressBytes()
            $"{b.[0]}.{b.[1]}.{b.[2]}.0/24"
        | _ -> ip

    /// <summary>False for addresses that can never have a geo answer — never spend an API call on them.</summary>
    static member internal IsGloballyRoutable(ip: string) : bool =
        match IPAddress.TryParse ip with
        | true, a when a.AddressFamily = Sockets.AddressFamily.InterNetwork ->
            let b = a.GetAddressBytes()

            not (
                b.[0] = 0uy
                || b.[0] = 10uy
                || b.[0] = 127uy
                || b.[0] >= 224uy // this-net, private, loopback, multicast+
                || (b.[0] = 172uy && b.[1] >= 16uy && b.[1] <= 31uy) // RFC1918
                || (b.[0] = 192uy && b.[1] = 168uy) // RFC1918
                || (b.[0] = 169uy && b.[1] = 254uy) // link-local
                || (b.[0] = 100uy && b.[1] >= 64uy && b.[1] <= 127uy) // CGNAT
            )
        | _ -> true // IPv6 etc. — don't gate here

    // ── geo prefix cache persistence (same pattern, its own file) ─────

    member private _.LoadGeoCacheFromDisk() : unit =
        try
            if File.Exists DnsResolutionService.GeoCacheFilePath then
                let dict =
                    JsonSerializer.Deserialize<Dictionary<string, DnsJsonDto.PersistedGeoEntry>>(
                        File.ReadAllText DnsResolutionService.GeoCacheFilePath
                    )

                if not (isNull (box dict)) then
                    for kv in dict do
                        let entry = GeoCacheEntry((if isNull (box kv.Value.L) then "" else kv.Value.L), kv.Value.T, kv.Value.N)

                        if not (entry.IsStale(if entry.Negative then geoNegativeTtl else geoCacheTtl)) then
                            geoCache.[kv.Key] <- entry
        with _ -> () // corrupt or missing file — start fresh

    member private _.SaveGeoCacheToDisk() : unit =
        try
            let dict = Dictionary<string, DnsJsonDto.PersistedGeoEntry>(geoCache.Count)

            for kv in geoCache do
                dict.[kv.Key] <- DnsJsonDto.PersistedGeoEntry(L = kv.Value.Label, T = kv.Value.ResolvedAt, N = kv.Value.Negative)

            DnsResolutionService.AtomicWriteJson(
                DnsResolutionService.GeoCacheFilePath,
                JsonSerializer.Serialize(dict, JsonSerializerOptions(WriteIndented = false))
            )
        with _ -> () // best effort

    // ── disk persistence  (simple JSON: { "ip": { "h": "host", "t": "utc" } }) ──

    member private _.LoadCacheFromDisk() : unit =
        try
            if File.Exists DnsResolutionService.CacheFilePath then
                let json = File.ReadAllText DnsResolutionService.CacheFilePath

                let dict =
                    JsonSerializer.Deserialize<Dictionary<string, DnsJsonDto.PersistedEntry>>(json)

                if not (isNull (box dict)) then
                    for kv in dict do
                        let entry = CacheEntry(kv.Value.H, kv.Value.T)

                        // Only load entries that are still within TTL
                        if not (entry.IsStale dnsCacheTtl) then cache.[kv.Key] <- entry
        with _ -> () // corrupt or missing file — start fresh

    member private _.SaveCacheToDisk() : unit =
        try
            let dict = Dictionary<string, DnsJsonDto.PersistedEntry>(cache.Count)

            for kv in cache do
                dict.[kv.Key] <- DnsJsonDto.PersistedEntry(H = kv.Value.Hostname, T = kv.Value.ResolvedAt)

            DnsResolutionService.AtomicWriteJson(
                DnsResolutionService.CacheFilePath,
                JsonSerializer.Serialize(dict, JsonSerializerOptions(WriteIndented = false))
            )
        with _ -> () // disk full, permissions, etc. — silently skip

    /// <summary>Write-via-temp-then-replace: a crash mid-save can never truncate the cache.</summary>
    static member private AtomicWriteJson(path: string, json: string) : unit =
        let tmp = path + ".tmp"
        File.WriteAllText(tmp, json)

        if File.Exists path then File.Replace(tmp, path, null)
        else File.Move(tmp, path)

    // ── helpers ───────────────────────────────────────────────────────

    /// <summary>True when the hostname value is effectively unresolved (raw IP or empty).</summary>
    static member IsUnresolvedHostname(hostname: string) : bool =
        if String.IsNullOrEmpty hostname then true
        elif hostname = "Unknown" || hostname = "-" then true
        else
            // Looks like a raw IPv4 address
            fst (IPAddress.TryParse hostname)

    member _.CacheCount: int = cache.Count
