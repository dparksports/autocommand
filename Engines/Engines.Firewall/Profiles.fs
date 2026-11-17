namespace AutoCommand.Engines.Firewall

open System
open System.Collections.Generic
open System.Reflection
open System.Threading.Tasks

/// <summary>
/// COM late-binding helpers for INetFwPolicy2 — F# has no C# `dynamic`, so
/// IDispatch property reads/writes go through Type.InvokeMember (the
/// pre-dynamic interop route; same IDispatch dispatch under the hood).
/// F# port: private per-file copy so this file stays independent of whatever
/// shared COM module Com.fs / Service.fs end up exposing.
/// </summary>
module private ProfileCom =

    let getProp (o: obj) (name: string) : obj =
        o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, [||])

    let private setProp (o: obj) (name: string) (value: obj) : unit =
        o.GetType().InvokeMember(name, BindingFlags.SetProperty, null, o, [| value |])
        |> ignore

    let create () : obj =
        let t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
        Activator.CreateInstance(t)

    /// The Rules collection is a plain COM enumerable (INetFwRules).
    let rules (policy: obj) : obj seq =
        Seq.cast<obj> (getProp policy "Rules" :?> System.Collections.IEnumerable)

    /// rule.Grouping ?? "" — null or non-string variants come back as "".
    let groupingOrEmpty (rule: obj) : string =
        match getProp rule "Grouping" with
        | :? string as s -> s
        | _ -> ""

    let isEnabled (rule: obj) : bool = getProp rule "Enabled" :?> bool

    let setEnabled (rule: obj) (value: bool) : unit = setProp rule "Enabled" value

/// <summary>
/// The canonical Shield Up whitelist. The 2026-10-30 field report (§3) caught
/// a mass-disable with only mDNS + Core Networking surviving, which silently
/// took WSL2/Hyper-V VM egress down with it — forwarded VM traffic dies below
/// the per-app rule model, with no attribution anywhere in the UI. VM
/// infrastructure groups stay ON so a lockdown never kills virtual machines.
/// Both C# copies (Contain.Core facade, vendored Shields Up core) delegate
/// their Shield Up preset here rather than carry their own table; the pure
/// predicate is public so HardenSelfTest can pin it without touching COM.
/// </summary>
module ShieldsUpWhitelist =

    /// Friendly display names to keep enabled.
    let Display = [| "mDNS"; "Core Networking" |]

    /// Raw-group tokens (resource-string groups like icsvc.dll,-700 and the
    /// WSL ms-resource package group never resolve to a friendly name) —
    /// matched case-insensitively against the raw grouping and the display name.
    let RawTokens =
        [|
            "icsvc"                 // Hyper-V Host Compute Service (Virtual Machine rules)
            "SubsystemForLinux"     // WSL store-package group (ms-resource://...SubsystemForLinux...)
            "Hyper-V"
            "Virtual Machine"
            "VirtualMachine"
            "WSL"
            "HNS"                   // Host Network Service (vSwitch/NAT plumbing)
            "wslservice"
            "vmcompute"
        |]

    let isWhitelisted (display: string) (rawGroup: string) : bool =
        (Display
        |> Array.exists (fun wl ->
            String.Equals(display, wl, StringComparison.OrdinalIgnoreCase)
            || String.Equals(rawGroup, wl, StringComparison.OrdinalIgnoreCase)))
        || (RawTokens
        |> Array.exists (fun token ->
            rawGroup.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0
            || display.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0))

/// <summary>
/// Firewall profile presets using COM API.
/// Ported from DeviceMonitorCS — now uses FirewallService instead of PowerShell.
/// F# port: values mirror Core/Services/FirewallProfileService.cs exactly.
/// </summary>
type ProfileType =
    | Custom = 0
    | BlockSharingDiscoveryRemoteDesktop = 1
    | AllowSharingDiscovery = 2
    | AllowDiscoveryCast = 3
    | ShieldsUpMdns = 4
    | AllowSharingDiscoveryRemoteDesktop = 5
    | ShieldsUp = 6

/// <summary>
/// Aggregated outcome of applying a firewall profile, for UI progress/summary reporting.
/// </summary>
type ProfileApplyResult() =
    member val ProfileName: string = Unchecked.defaultof<string> with get, set
    member val Groups: ResizeArray<GroupToggleResult> = ResizeArray<GroupToggleResult>() with get
    member val TotalMatched: int = 0 with get, set
    member val TotalChanged: int = 0 with get, set
    member val TotalFailed: int = 0 with get, set
    member val FirstError: string = Unchecked.defaultof<string> with get, set
    member val Notes: string = Unchecked.defaultof<string> with get, set

/// <summary>
/// Firewall profile presets using COM API.
/// Ported from DeviceMonitorCS — now uses FirewallService instead of PowerShell.
/// F# port: the C# FirewallService.Instance singleton is replaced by the
/// injected fw instance (no statics in the engine).
/// </summary>
type ProfilePresets(fw: FirewallService) =

    let report (progress: IProgress<string>) (msg: string) =
        match progress with
        | null -> ()
        | p -> p.Report(msg)

    // Locale-independent group matching. COM's INetFwRule.Grouping returns
    // the RAW indirect string ("@FirewallAPI.dll,-32752") verbatim on every
    // OS language; the display name resolves through the OS UI language.
    // Matching the English display name only — the old behavior — silently
    // toggled nothing on localized Windows while the preset reported
    // success. Candidates are tried in order until one matches, so a token
    // drift on some future build falls back to the display name instead of
    // breaking. Tokens verified live against Windows 10/11 resource IDs.
    static let WellKnownGroups =
        dict [
            "File and Printer Sharing", ("File and Printer Sharing", [ "@FirewallAPI.dll,-28502" ])
            "Network Discovery", ("Network Discovery", [ "@FirewallAPI.dll,-32752" ])
            "Remote Desktop", ("Remote Desktop", [ "@FirewallAPI.dll,-28752" ])
            "Cast to Device functionality", ("Cast to Device functionality", [ "@FirewallAPI.dll,-36001" ])
        ]

    let toggle (acc: ProfileApplyResult) (progress: IProgress<string>) (group: string) (enable: bool) : Task<unit> =
        task {
            let display, rawTokens =
                match WellKnownGroups.TryGetValue group with
                | true, (d, tokens) -> (d, tokens)
                | _ -> (group, [])

            report progress (if enable then $"Enabling group '{display}'…" else $"Disabling group '{display}'…")

            // Try the raw token(s) first, then the display name; stop at the
            // first candidate that actually matched rules (running further
            // candidates would re-toggle the same rules — Matched>0 but no
            // additional Changed).
            let mutable chosen: GroupToggleResult option = None
            let mutable idx = 0
            let candidates = rawTokens @ [ display ]
            while idx < candidates.Length do
                let! r = fw.ToggleGroupAsync(candidates.[idx], enable)
                if r.Matched > 0 || not (isNull r.FirstError) then
                    chosen <- Some r
                    idx <- candidates.Length // stop
                else
                    idx <- idx + 1

            match chosen with
            | Some r ->
                acc.Groups.Add(r)
                acc.TotalMatched <- acc.TotalMatched + r.Matched
                acc.TotalChanged <- acc.TotalChanged + r.Changed
                acc.TotalFailed <- acc.TotalFailed + r.Failed
                if not (isNull r.FirstError) && isNull acc.FirstError then acc.FirstError <- r.FirstError
            | None -> () // nothing anywhere matched — result carries the zero totals
        }

    let applyShieldsUpMdns () : Task<GroupToggleResult> =
        // Disable ALL rules, then re-enable whitelisted groups
        Task.Run(fun () ->
            let result = GroupToggleResult()
            result.GroupName <- "Shields Up + mDNS (block all)"
            try
                let fwPolicy = ProfileCom.create ()
                let mutable disabledCount = 0
                let mutable whitelistEnabled = 0

                // Pass 1: Disable everything with a group
                for rule in ProfileCom.rules fwPolicy do
                    try
                        let group = ProfileCom.groupingOrEmpty rule
                        if not (String.IsNullOrEmpty group) then
                            let wasEnabled = ProfileCom.isEnabled rule
                            ProfileCom.setEnabled rule false
                            result.Matched <- result.Matched + 1
                            if wasEnabled then
                                result.Changed <- result.Changed + 1
                                disabledCount <- disabledCount + 1
                    with ex ->
                        result.Failed <- result.Failed + 1
                        if isNull result.FirstError then result.FirstError <- ex.Message

                // Pass 2: Re-enable whitelisted groups (see the
                // ShieldsUpWhitelist module above for why the whitelist is
                // wider than mDNS + Core Networking).
                let mutable vmSpared = false
                for rule in ProfileCom.rules fwPolicy do
                    try
                        let group = ProfileCom.groupingOrEmpty rule
                        if not (String.IsNullOrEmpty group) then
                            let display = FirewallService.ResolveGroupName group
                            if ShieldsUpWhitelist.isWhitelisted display group then
                                if not (
                                    String.Equals(display, "mDNS", StringComparison.OrdinalIgnoreCase)
                                    || String.Equals(display, "Core Networking", StringComparison.OrdinalIgnoreCase)) then
                                    vmSpared <- true
                                let wasEnabled = ProfileCom.isEnabled rule
                                ProfileCom.setEnabled rule true
                                result.Matched <- result.Matched + 1
                                whitelistEnabled <- whitelistEnabled + 1
                                if not wasEnabled then result.Changed <- result.Changed + 1
                    with ex ->
                        result.Failed <- result.Failed + 1
                        if isNull result.FirstError then result.FirstError <- ex.Message

                let sparedText = if vmSpared then " (VM networking spared)" else ""
                result.Notes <-
                    $"{disabledCount} grouped rule(s) disabled, {whitelistEnabled} whitelist rule(s) re-enabled{sparedText}"
            with ex ->
                result.FailedCompletely <- true
                result.FirstError <- ex.Message
            result)

    member _.ApplyProfile(profile: ProfileType, progress: IProgress<string>) : Task<ProfileApplyResult> =
        task {
            let result = ProfileApplyResult()
            result.ProfileName <- profile.ToString()
            match profile with
            | ProfileType.BlockSharingDiscoveryRemoteDesktop ->
                do! toggle result progress "File and Printer Sharing" false
                do! toggle result progress "Network Discovery" false
                do! toggle result progress "Remote Desktop" false
            | ProfileType.AllowSharingDiscovery ->
                do! toggle result progress "File and Printer Sharing" true
                do! toggle result progress "Network Discovery" true
            | ProfileType.AllowDiscoveryCast ->
                do! toggle result progress "Network Discovery" true
                do! toggle result progress "Cast to Device functionality" true
            | ProfileType.ShieldsUpMdns ->
                report progress "Shields Up + mDNS: disabling all grouped rules…"
                let! shield = applyShieldsUpMdns ()
                result.Groups.Add(shield)
                result.TotalMatched <- result.TotalMatched + shield.Matched
                result.TotalChanged <- result.TotalChanged + shield.Changed
                result.TotalFailed <- result.TotalFailed + shield.Failed
                if not (isNull shield.FirstError) && isNull result.FirstError then result.FirstError <- shield.FirstError
                result.Notes <- shield.Notes
            | ProfileType.AllowSharingDiscoveryRemoteDesktop ->
                do! toggle result progress "File and Printer Sharing" true
                do! toggle result progress "Network Discovery" true
                do! toggle result progress "Remote Desktop" true
            | ProfileType.ShieldsUp ->
                report progress "Shields Up: restoring Windows defaults…"
                // F# port: C# used FirewallService.Instance — replaced by the injected fw
                let! lockdown = fw.ResetToDefaultsAndLockdownAsync(progress)
                result.Groups.Add(lockdown)
                result.TotalMatched <- result.TotalMatched + lockdown.Matched
                result.TotalChanged <- result.TotalChanged + lockdown.Changed
                result.TotalFailed <- result.TotalFailed + lockdown.Failed
                if not (isNull lockdown.FirstError) && isNull result.FirstError then
                    result.FirstError <- lockdown.FirstError
                result.Notes <- lockdown.Notes
            | _ -> () // Custom: nothing to apply
            return result
        }

    /// F# port: overload for C# callers using the original optional
    /// `progress = null` argument.
    member this.ApplyProfile(profile: ProfileType) : Task<ProfileApplyResult> =
        this.ApplyProfile(profile, Unchecked.defaultof<IProgress<string>>)
