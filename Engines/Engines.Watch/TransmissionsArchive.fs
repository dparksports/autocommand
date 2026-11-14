// F# port of Core\Models\TransmissionRecord.cs and
// Core\Services\TransmissionsArchiveService.cs (namespaces
// AutoScope.Models / AutoScope.Services) for the Engines library.
//
// WITNESS-GRADE (v2026.11.13.3): the archive records METADATA ONLY —
// endpoints, SNI, TLS handshake facts, wire byte counts, Sysmon-attributed
// identity — as the containment proof's third witness (bytes to a blocked
// destination since the block was created). No decryption, no plaintext
// bodies, no DPAPI body blobs: FlowPeek/ConnectionPeek decrypt live on
// their own behalf, and nothing at rest here is plaintext traffic.
//
// F# port notes (deviations forced by F#/C# interop, none behavioral):
//   • TransmissionRecord stays a mutable class implementing
//     INotifyPropertyChanged with the same property names.
//   • Optional parameters use [<Optional; DefaultParameterValue>], not
//     F# `?` optionals (Read(4000, null, null, sinceUtc) call shapes).
//   • The archive root defaults to WatchConfig.Identity.DataRoot
//     \transmissions; the settable ArchiveDirectory self-test seam stays.
//     Pre-diet archives keep parsing: old rows carry body-count keys the
//     reader tolerates, and the bodies\ directory they reference is simply
//     orphaned (pruned by age with the day files).

// FS3211 fires on [<Optional; DefaultParameterValue(null)>] below, but the
// emitted metadata is exactly what C# needs (same pattern as Probe.fs —
// verified there by reflection and by ported call shapes compiling).
#nowarn "3211"

namespace AutoCommand.Engines.Watch

open System
open System.Collections.Generic
open System.ComponentModel
open System.IO
open System.Runtime.InteropServices
open System.Text.Json

// ── record model (C# Core\Models\TransmissionRecord.cs) ───────────

/// <summary>
/// One finalized outbound TLS conversation as the Transmissions tab sees
/// it: the decrypted view when session keys existed, the honest status
/// ("encrypted — no keys", "not TLS") when they did not. The wire facts
/// (endpoints, sizes, pid via Sysmon EID 3) are always present; the
/// content lives in the archive's body files, referenced by Id.
/// </summary>
type TransmissionRecord() =

    let propertyChanged = Event<PropertyChangedEventHandler, PropertyChangedEventArgs>()
    let mutable provider = "Unclassified"

    member val Id = Guid.NewGuid().ToString("N") with get, set
    member val TsUtc = DateTime() with get, set

    member val Pid = 0 with get, set
    member val Image: string = null with get, set
    member this.ProcessDisplay =
        if String.IsNullOrEmpty this.Image then
            (if this.Pid > 0 then $"pid {this.Pid}" else "unattributed")
        else Path.GetFileName this.Image

    member val RemoteIp: string = null with get, set
    member val RemotePort = 0 with get, set
    member this.ServerEndpoint = $"{this.RemoteIp}:{this.RemotePort}"
    member val LocalEndpoint: string = null with get, set

    member val Sni: string = null with get, set
    member this.HostDisplay = if String.IsNullOrEmpty this.Sni then "(no SNI)" else this.Sni

    member val TlsVersion: string = null with get, set
    member val Alpn: string = null with get, set
    member val CipherSuite: string = null with get, set

    /// <summary>RDAP netname/org when known, else the static range
    /// classification, else "Unclassified". Late-bound: RDAP answers
    /// asynchronously and the grid row updates in place.</summary>
    member this.Provider
        with get () = provider
        and set value =
            if this.SetField(&provider, value, "Provider") then
                this.OnPropertyChanged "ProviderAndCountry"
    member val ProviderCountry: string = null with get, set
    member this.ProviderAndCountry =
        if String.IsNullOrEmpty this.ProviderCountry then this.Provider
        else $"{this.Provider} ({this.ProviderCountry})"

    member val ClientBytes = 0L with get, set       // wire, reassembled
    member val ServerBytes = 0L with get, set
    member val ClientAppBytes = 0L with get, set    // decrypted plaintext
    member val ServerAppBytes = 0L with get, set

    /// <summary>"decrypted" · "encrypted (no keys)" · "not TLS" ·
    /// "no handshake" · "unsupported cipher" · "undecryptable", with an
    /// optional " · truncated" suffix when the capture dropped bytes.
    /// Intercept-sourced rows use "decrypted · intercept …" variants.</summary>
    member val Status: string = null with get, set
    member this.Decrypted =
        this.Status <> null &&
        (this.Status = "decrypted" || this.Status.StartsWith("decrypted", StringComparison.Ordinal))

    /// <summary>The user-facing threshold this tab exists for: an upload
    /// larger than 10 KB deserves a row even when no keys existed.</summary>
    member this.BigUpload = this.ClientBytes > 10L * 1024L
    member this.BigUploadVisibility = if this.BigUpload then "Visible" else "Collapsed"

    member val HasContent = false with get, set
    member val Sha256: string = null with get, set
    member val MessageCount = 0 with get, set
    member val ContentKinds: string = null with get, set

    member val ArchiveDay: string = null with get, set

    // ── display helpers ──────────────────────────────────────────────

    member this.TimeDisplay = if this.TsUtc = DateTime() then "" else this.TsUtc.ToLocalTime().ToString("MM-dd HH:mm:ss")
    member this.UpDisplay = TransmissionRecord.FormatBytes this.ClientBytes
    member this.DownDisplay = TransmissionRecord.FormatBytes this.ServerBytes
    member this.AppBytesDisplay =
        if this.Decrypted then
            $"{TransmissionRecord.FormatBytes this.ClientAppBytes} / {TransmissionRecord.FormatBytes this.ServerAppBytes}"
        else "—"

    static member private FormatBytes(bytes: int64) =
        if bytes < 1024L then $"{bytes}B"
        elif bytes < 1048576L then $"{float bytes / 1024.0:F1}KB"
        else $"{float bytes / 1048576.0:F1}MB"

    [<CLIEvent>]
    member _.PropertyChanged = propertyChanged.Publish

    interface INotifyPropertyChanged with
        [<CLIEvent>]
        member _.PropertyChanged = propertyChanged.Publish

    member private this.OnPropertyChanged(name: string) =
        propertyChanged.Trigger(this, PropertyChangedEventArgs(name))

    // F# port: the C# SetField<T>(ref field, ...) is spelled with a
    // concrete byref<string> — F# does not permit byref<'T> in generic
    // members, and Provider is the only property with change tracking.
    member private this.SetField(backing: byref<string>, value: string, name: string) =
        if EqualityComparer<string>.Default.Equals(backing, value) then false
        else
            backing <- value
            this.OnPropertyChanged name
            true

// ── archive service (C# Core\Services\TransmissionsArchiveService.cs) ──

/// <summary>
/// On-disk store behind the containment proof's third witness, mirroring
/// the Sysmon archive's shape: one readable, greppable JSONL index file
/// per day under DataRoot\transmissions. METADATA ONLY — endpoints, SNI,
/// TLS handshake facts, wire byte counts, provider attribution. No bodies,
/// no decryption, no plaintext traffic at rest (pre-diet archives keep
/// parsing; their orphaned bodies\ folder prunes by age with the day
/// files).
///
/// Retention: day files prune after DefaultRetainDays. Everything stays
/// local; the containment reader (BlockContainmentReader) is the consumer.
/// </summary>
[<AbstractClass; Sealed>]
type TransmissionsArchiveService private () =

    static let gate = obj()
    static let mutable lastPruneUtc = DateTime.MinValue

    static member DefaultRetainDays = 30

    /// <summary>Archive root; settable for offline self-tests (house pattern).
    /// Defaults to DataRoot\transmissions.</summary>
    static member val ArchiveDirectory =
        Path.Combine(WatchConfig.Identity.DataRoot, "transmissions") with get, set

    static member DayFilePath(utc: DateTime) =
        Path.Combine(TransmissionsArchiveService.ArchiveDirectory, "transmissions-" + utc.ToString("yyyy-MM-dd") + ".jsonl")

    // ── append ────────────────────────────────────────────────────────

    /// <summary>Writes one metadata row. Returns true when written.</summary>
    static member Append(record: TransmissionRecord) : bool =
        if isNull (box record) then false
        else
        try
            lock gate (fun () ->
                Directory.CreateDirectory TransmissionsArchiveService.ArchiveDirectory |> ignore

                record.ArchiveDay <- record.TsUtc.ToString("yyyy-MM-dd")

                // Same keys the reader has always parsed (body-count keys are
                // simply absent from new rows — Read tolerates their absence).
                let fields = Dictionary<string, obj>()
                let add (key: string) (value: obj) = fields[key] <- value
                add "id" record.Id
                add "ts" (record.TsUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
                add "pid" record.Pid
                add "image" record.Image
                add "remote" record.ServerEndpoint
                add "local" record.LocalEndpoint
                add "sni" record.Sni
                add "tls" record.TlsVersion
                add "alpn" record.Alpn
                add "cipher" record.CipherSuite
                add "provider" record.Provider
                add "provider_country" record.ProviderCountry
                add "client_bytes" record.ClientBytes
                add "server_bytes" record.ServerBytes
                add "status" record.Status
                let line = JsonSerializer.Serialize fields
                File.AppendAllText(TransmissionsArchiveService.DayFilePath record.TsUtc, line + Environment.NewLine)

                TransmissionsArchiveService.MaybePrune()
                true)
        with _ ->
            false // archive is best-effort

    // ── retention ─────────────────────────────────────────────────────

    /// <summary>Runs at most hourly: day-file age prune. Public for
    /// self-tests.</summary>
    static member Prune([<Optional; DefaultParameterValue(30)>] retainDays: int) =
        try
            if not (Directory.Exists TransmissionsArchiveService.ArchiveDirectory) then ()
            else
            let cutoff = DateTime.UtcNow.Date.AddDays(float -retainDays)
            for file in Directory.GetFiles(TransmissionsArchiveService.ArchiveDirectory, "transmissions-*.jsonl") do
                let stem = Path.GetFileName(file).Substring("transmissions-".Length).Replace(".jsonl", "")
                match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
                | true, day when day < cutoff ->
                    try File.Delete file with _ -> () // locked — next prune
                | _ -> ()

            // Pre-diet bodies\ directories (legacy plaintext/DPAPI blobs)
            // age out with the day files.
            let legacyBodies = Path.Combine(TransmissionsArchiveService.ArchiveDirectory, "bodies")
            if Directory.Exists legacyBodies then
                for dir in Directory.GetDirectories(legacyBodies, "*") do
                    let stem = Path.GetFileName(dir)
                    match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
                    | true, day when day < cutoff -> try Directory.Delete(dir, true) with _ -> ()
                    | _ -> ()
        with _ -> () // retention is opportunistic

    static member private MaybePrune() =
        if (DateTime.UtcNow - lastPruneUtc).TotalMinutes < 60.0 then ()
        else
            lastPruneUtc <- DateTime.UtcNow
            TransmissionsArchiveService.Prune()

    static member private ParseDay(dir: string) : DateTime option =
        let stem = Path.GetFileName dir
        match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
        | true, day -> Some day
        | _ -> None

    static member private DirSize(dir: string) : int64 =
        try
            Directory.GetFiles(dir, "*", SearchOption.AllDirectories)
            |> Seq.sumBy (fun f -> (FileInfo f).Length)
        with _ -> 0L

    // ── queries ───────────────────────────────────────────────────────

    /// <summary>Newest-first read of archived rows. Filters are applied
    /// in-memory per line; `contains` matches any field.</summary>
    static member Read(
        [<Optional; DefaultParameterValue(200)>] max: int,
        [<Optional; DefaultParameterValue(null)>] pid: Nullable<int>,
        [<Optional; DefaultParameterValue(null)>] contains: string,
        [<Optional; DefaultParameterValue(null)>] sinceUtc: Nullable<DateTime>) : ResizeArray<TransmissionRecord> =
        let hits = ResizeArray<TransmissionRecord>()
        try
            if not (Directory.Exists TransmissionsArchiveService.ArchiveDirectory) then ()
            else
            // F# port: C# OrderByDescending(f => f, StringComparer.Ordinal) —
            // ordinal string compare, descending, via sortWith.
            let files =
                Directory.GetFiles(TransmissionsArchiveService.ArchiveDirectory, "transmissions-*.jsonl")
                |> Array.sortWith (fun a b -> String.CompareOrdinal(b, a))
                |> Array.toList

            for file in files do
                if hits.Count >= max then ()
                else
                let stem = Path.GetFileName(file).Substring("transmissions-".Length).Replace(".jsonl", "")
                let skipByDay =
                    sinceUtc.HasValue &&
                    (match DateTime.TryParseExact(stem, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None) with
                     | true, day -> day < sinceUtc.Value.Date
                     | _ -> false)
                if skipByDay then ()
                else
                let lines = File.ReadAllLines file
                let mutable li = lines.Length - 1
                while li >= 0 && hits.Count < max do
                    let line = lines[li]
                    li <- li - 1
                    if line.Length = 0 then ()
                    else
                    try
                        use doc = JsonDocument.Parse line
                        let root = doc.RootElement
                        let rowPid =
                            match root.TryGetProperty("pid") with
                            | true, p -> p.GetInt32()
                            | _ -> 0
                        if pid.HasValue && rowPid <> pid.Value then ()
                        else
                        let record =
                            TransmissionRecord(
                                Id = TransmissionsArchiveService.GetString(root, "id"),
                                TsUtc = DateTime.Parse(TransmissionsArchiveService.GetString(root, "ts"),
                                                        System.Globalization.CultureInfo.InvariantCulture,
                                                        System.Globalization.DateTimeStyles.AssumeUniversal).ToUniversalTime(),
                                Pid = rowPid,
                                Image = TransmissionsArchiveService.GetString(root, "image"),
                                RemoteIp = TransmissionsArchiveService.RemoteIpOf(TransmissionsArchiveService.GetString(root, "remote")),
                                RemotePort = TransmissionsArchiveService.RemotePortOf(TransmissionsArchiveService.GetString(root, "remote")),
                                LocalEndpoint = TransmissionsArchiveService.GetString(root, "local"),
                                Sni = TransmissionsArchiveService.GetString(root, "sni"),
                                TlsVersion = TransmissionsArchiveService.GetString(root, "tls"),
                                Alpn = TransmissionsArchiveService.GetString(root, "alpn"),
                                CipherSuite = TransmissionsArchiveService.GetString(root, "cipher"),
                                Provider = (match TransmissionsArchiveService.GetString(root, "provider") with
                                            | null -> "Unclassified"
                                            | v -> v),
                                ProviderCountry = TransmissionsArchiveService.GetString(root, "provider_country"),
                                ClientBytes = TransmissionsArchiveService.GetLong(root, "client_bytes"),
                                ServerBytes = TransmissionsArchiveService.GetLong(root, "server_bytes"),
                                ClientAppBytes = TransmissionsArchiveService.GetLong(root, "client_app_bytes"),
                                ServerAppBytes = TransmissionsArchiveService.GetLong(root, "server_app_bytes"),
                                Status = TransmissionsArchiveService.GetString(root, "status"),
                                HasContent = (match root.TryGetProperty("has_content") with
                                              | true, hc -> hc.GetBoolean()
                                              | _ -> false),
                                Sha256 = TransmissionsArchiveService.GetString(root, "sha256"),
                                MessageCount = int (TransmissionsArchiveService.GetLong(root, "message_count")),
                                ContentKinds = TransmissionsArchiveService.GetString(root, "content_kinds"),
                                ArchiveDay = stem)

                        if not (String.IsNullOrEmpty contains) then
                            let haystack = $"{record.Image} {record.Sni} {record.RemoteIp} {record.Provider} {record.Status}"
                            if not (haystack.Contains(contains, StringComparison.OrdinalIgnoreCase)) then ()
                            else hits.Add record
                        else hits.Add record
                    with _ -> () // truncated/corrupt line — skip, keep the file
        with _ -> () // unreadable archive — partial result, never a throw
        hits

    /// <summary>(day files, bytes on disk) for the tab's status line.</summary>
    static member StatusSummary() : struct (int * int64) =
        try
            if not (Directory.Exists TransmissionsArchiveService.ArchiveDirectory) then struct (0, 0L)
            else
            let days =
                Directory.GetFiles(TransmissionsArchiveService.ArchiveDirectory, "transmissions-*.jsonl").Length
            let bytes = TransmissionsArchiveService.DirSize TransmissionsArchiveService.ArchiveDirectory
            struct (days, bytes)
        with _ -> struct (0, 0L)

    static member private GetString(root: JsonElement, prop: string) : string =
        match root.TryGetProperty(prop) with
        | true, v when v.ValueKind = JsonValueKind.String -> v.GetString()
        | _ -> null

    static member private GetLong(root: JsonElement, prop: string) : int64 =
        match root.TryGetProperty(prop) with
        | true, v when v.ValueKind = JsonValueKind.Number ->
            match v.TryGetInt64() with
            | true, n -> n
            | _ -> 0L
        | _ -> 0L

    static member private RemoteIpOf(endpoint: string) : string =
        if endpoint <> null && endpoint.LastIndexOf(':') > 0 then endpoint[..endpoint.LastIndexOf(':') - 1]
        else endpoint

    static member private RemotePortOf(endpoint: string) : int =
        if endpoint <> null && endpoint.LastIndexOf(':') > 0 then
            match Int32.TryParse(endpoint[endpoint.LastIndexOf(':') + 1..]) with
            | true, port -> port
            | _ -> 0
        else 0
