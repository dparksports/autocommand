namespace AutoCommand.Engines.Firewall

open System
open System.Collections.Generic
open System.ComponentModel
open System.Diagnostics
open System.IO
open System.Linq
open System.Net
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading.Tasks
open AutoCommand.Engines.Core

/// <summary>
/// Outcome of a group-wide enable/disable so callers can show what actually
/// happened.
/// F# port: was the nested FirewallService.GroupToggleResult — top-level
/// here; fields became properties.
/// </summary>
type GroupToggleResult() =
    member val GroupName: string = null with get, set
    member val Matched: int = 0 with get, set
    member val Changed: int = 0 with get, set
    member val Failed: int = 0 with get, set
    member val FirstError: string = null with get, set
    member val FailedCompletely: bool = false with get, set
    /// free-form summary FirewallProfileService appends for the UI
    /// (autocommand-ii member the autoscope port predates)
    member val Notes: string = null with get, set

/// <summary>
/// One blocked target (IP or app) in the block-rule inventory.
/// F# port: was the nested FirewallService.BlockedTarget — top-level here;
/// public fields became properties; DateTime? stays Nullable&lt;DateTime&gt;.
/// </summary>
type BlockedTarget() =
    member val Target: string = null with get, set // IP or exe name for display
    member val Kind: string = null with get, set // "ip" | "app"
    member val Key: string = null with get, set // grouping key (ip or lowercased full path)
    member val AppPath: string = null with get, set
    member val Ip: string = null with get, set
    member val Rules: int = 0 with get, set
    member val EnabledRules: int = 0 with get, set
    member val Description: string = "" with get, set
    /// Microsoft/Azure, Akamai, Gcore, Windows component, Application, Unclassified
    member val Class: string = null with get, set
    /// parsed from v2 description; null for legacy rules
    member val Created: Nullable<DateTime> = Nullable<DateTime>() with get, set
    /// rules whose image path no longer exists on disk (inert after an app
    /// update/move) — autocommand-ii members the autoscope port predates
    member val StaleRules: int = 0 with get, set
    /// rules that are exact duplicates of another rule on this target (same
    /// rule name — and for app rules, the same ApplicationName): inert residue
    /// of pre-fix concurrent blocking, retired by the one-click cleanup
    member val DuplicateRules: int = 0 with get, set
    /// why coverage is incomplete (stale path, sibling gap, …)
    member val CoverageNote: string = null with get, set

/// <summary>Fleet-wide toggle outcome (panic button / restore).</summary>
type FleetToggleResult() =
    member val Matched: int = 0 with get, set
    member val Changed: int = 0 with get, set
    member val SkippedRisky: int = 0 with get, set
    member val FirstError: string = null with get, set

/// <summary>
/// Single-pass toggle outcome: rule match/flip counts plus the live inventory
/// and per-rule Enabled states captured in the same COM walk (or just the
/// probed rules when an O(1) direct-lookup fast path handled the toggle).
/// Eliminates the 3 redundant post-toggle firewall enumerations.
/// </summary>
[<AllowNullLiteral>]
type TargetToggleSnapshot() =
    member val Matched: int = 0 with get, set
    member val Changed: int = 0 with get, set
    member val SkippedRisky: int = 0 with get, set
    member val FirstError: string = null with get, set
    member val UsedFastPath: bool = false with get, set
    member val IsFullSnapshot: bool = false with get, set
    member val Inventory: ResizeArray<BlockedTarget> = null with get, set
    member val RuleStates: ResizeArray<struct (string * bool)> = ResizeArray<struct (string * bool)>() with get

/// <summary>Recent DROP hit from pfirewall.log, aggregated per destination.</summary>
type FirewallLogHit() =
    member val Count: int = 0 with get, set
    member val FirstSeen: DateTime = DateTime() with get, set
    member val LastSeen: DateTime = DateTime() with get, set
    member val Processes: HashSet<string> = HashSet<string>(StringComparer.OrdinalIgnoreCase) with get

/// <summary>
/// One firewall rule for the rules view.
/// F# port of the C# FirewallRuleItem (renamed): INotifyPropertyChanged is
/// kept because the rules DataGrid binds EnabledDisplay/Enabled with
/// classic {Binding} and the view code-behind mutates rule.Enabled in place
/// expecting the row to refresh. No UI/Brush property existed on the C#
/// model, so nothing was dropped.
/// </summary>
type RuleInfo() =

    let propertyChanged =
        Event<PropertyChangedEventHandler, PropertyChangedEventArgs>()

    let mutable enabled = false

    member val Name: string = null with get, set
    member val DisplayName: string = null with get, set
    member val DisplayGroup: string = null with get, set
    member val Direction: string = null with get, set
    member val Action: string = null with get, set
    member val Profile: string = null with get, set
    member val Program: string = null with get, set
    member val Protocol: string = null with get, set
    member val LocalPort: string = null with get, set
    member val RemotePort: string = null with get, set
    member val RemoteAddress: string = null with get, set

    member this.Enabled
        with get () = enabled
        and set value =
            if enabled <> value then
                enabled <- value
                propertyChanged.Trigger(this, PropertyChangedEventArgs("Enabled"))
                propertyChanged.Trigger(this, PropertyChangedEventArgs("EnabledDisplay"))

    member this.EnabledDisplay = if this.Enabled then "Yes" else "No"

    [<CLIEvent>]
    member this.PropertyChanged = propertyChanged.Publish

    interface INotifyPropertyChanged with
        [<CLIEvent>]
        member this.PropertyChanged = propertyChanged.Publish

/// <summary>
/// Native Windows Firewall management via INetFwPolicy2 COM.
/// Replaces all PowerShell Get-NetFirewallRule / Set-NetFirewallRule calls.
/// F# port: strong-typed COM (Com.fs) instead of C# `dynamic` COM — no COM
/// reference DLL needed either way.
/// F# port: the C# static singleton (FirewallService.Instance) is gone —
/// the service takes the app's FirewallNaming record so the same engine
/// serves any app's block-rule naming; no rule prefix or app name lives in
/// this file.
/// </summary>
type FirewallService(naming: FirewallNaming, policyFactory: Func<INetFwPolicy2>, ruleFactory: Func<INetFwRule>) =

    // C# cached these as constants (NewIpPrefix "AS-BLOCK-IP " etc.); every
    // prefix now routes through the injected naming record instead.

    static let groupNameCache = Dictionary<string, string>(StringComparer.Ordinal)

    // App-block adds are check-then-act over the process-global policy store
    // (dedupe by path, then add). Concurrent adds — a burst of Sysmon EID 1
    // events for the same exe, each firing EnsureCoveredAsync fire-and-forget
    // — can all pass the "no rule for this path" check before any of them
    // lands a rule, piling up identical duplicates (observed live: six copies
    // of one bash.exe rule created in the same minute). Serializing the add
    // body makes the dedupe check authoritative.
    static let appAddGate = new System.Threading.SemaphoreSlim(1, 1)

    let getPolicy () : INetFwPolicy2 =
        if isNull policyFactory then Com.getPolicy2 ()
        else policyFactory.Invoke()

    let makeRule () : INetFwRule =
        if isNull ruleFactory then Com.newRule ()
        else ruleFactory.Invoke()

    // Authoritative in-memory index of own block rule names, seeded whenever a
    // full-collection walk (inventory or snapshot toggle) completes cleanly.
    // Inside Windows FirewallAPI.dll, INetFwRules.Item(name) has no name index
    // and scans 100% of the BFE policy store (~2,000+ rules) on every miss;
    // consulting ownRuleNames skips Rules.Item completely for brand-new IP and
    // process blocks while probing COM normally (and self-healing) on hits or
    // before the index is seeded.
    let ownRulesGate = obj ()
    let ownRuleNames = HashSet<string>(StringComparer.OrdinalIgnoreCase)
    let mutable ownRuleIndexSeeded = false

    let replaceOwnRuleIndex (names: seq<string>) =
        lock ownRulesGate (fun () ->
            ownRuleNames.Clear()
            for n in names do
                if not (String.IsNullOrEmpty n) then
                    ownRuleNames.Add(n) |> ignore
            ownRuleIndexSeeded <- true)

    let invalidateOwnRuleIndex () =
        lock ownRulesGate (fun () ->
            ownRuleNames.Clear()
            ownRuleIndexSeeded <- false)

    let recordOwnRuleAdded (name: string) =
        if not (String.IsNullOrEmpty name) then
            lock ownRulesGate (fun () ->
                if ownRuleIndexSeeded then
                    ownRuleNames.Add(name) |> ignore)

    let recordOwnRuleRemoved (name: string) =
        if not (String.IsNullOrEmpty name) then
            lock ownRulesGate (fun () ->
                if ownRuleIndexSeeded then
                    ownRuleNames.Remove(name) |> ignore)

    static let writeAndVerifyEnabled (r: INetFwRule) (ruleLabel: string) (desired: bool) : struct (bool * bool * string) =
        r.Enabled <- desired
        let actual = r.Enabled
        if actual = desired then
            struct (actual, true, null)
        else
            let label = if String.IsNullOrEmpty ruleLabel then "(unnamed rule)" else ruleLabel
            struct (actual, false, $"{label}: firewall kept Enabled={actual} after requesting {desired}")

    // ── naming-driven helpers ────────────────────────────────────────

    static let startsWith (prefix: string) (s: string) =
        s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)

    static let startsWithAny (prefixes: string list) (s: string) =
        List.exists (fun p -> startsWith p s) prefixes

    static let isIpName (naming: FirewallNaming) (name: string) =
        startsWith naming.OwnIpPrefix name || startsWithAny naming.LegacyIpPrefixes name

    static let isAppName (naming: FirewallNaming) (name: string) =
        startsWith naming.OwnAppPrefix name || startsWithAny naming.LegacyAppPrefixes name

    // F# port: C# branched on explicit per-family prefixes (NewIpPrefix /
    // ImportedIpPrefix / LegacyIpPrefix[0]). FirewallNaming carries the
    // adopted set as one flat list, so adopted rules branch on content: an
    // app block always sets ApplicationName, an IP block never does. Same
    // outcome for every rule that can actually exist.
    static let isIpRule (naming: FirewallNaming) (name: string) (rule: INetFwRule) =
        if isIpName naming name then true
        elif isAppName naming name then false
        else String.IsNullOrEmpty rule.ApplicationName

    new(naming: FirewallNaming, policyFactory: Func<INetFwPolicy2>) =
        FirewallService(naming, policyFactory, null)

    new(naming: FirewallNaming) =
        FirewallService(naming, null, null)

    /// <summary>
    /// COM's INetFwRule.Grouping returns indirect resource strings (e.g.
    /// "@FirewallAPI.dll,-32752"), not the localized display names
    /// ("Network Discovery") that the profile presets use.
    /// </summary>
    static member ResolveGroupName(grouping: string) : string =
        if String.IsNullOrEmpty grouping || grouping.[0] <> '@' then
            grouping
        else
            lock
                groupNameCache
                (fun () ->
                    match groupNameCache.TryGetValue grouping with
                    | true, cached -> cached
                    | _ ->
                        let mutable resolved = grouping
                        let sb = StringBuilder(512)

                        if
                            Shlwapi.SHLoadIndirectString(grouping, sb, sb.Capacity, IntPtr.Zero) = 0
                            && sb.Length > 0
                        then
                            resolved <- sb.ToString()

                        groupNameCache.[grouping] <- resolved
                        resolved)

    /// <summary>
    /// Case-insensitive group match against both the raw Grouping string
    /// and its resolved display name.
    /// </summary>
    static member private GroupMatches(ruleGrouping: string, targetName: string) : bool =
        if String.IsNullOrEmpty ruleGrouping || String.IsNullOrEmpty targetName then
            false
        elif String.Equals(ruleGrouping, targetName, StringComparison.OrdinalIgnoreCase) then
            true
        else
            String.Equals(
                FirewallService.ResolveGroupName ruleGrouping,
                targetName,
                StringComparison.OrdinalIgnoreCase
            )

    /// <summary>
    /// Load all firewall rules for a given direction using COM API.
    /// direction: 1 = Inbound, 2 = Outbound
    /// </summary>
    member _.LoadRulesAsync(direction: int) : Task<ResizeArray<RuleInfo>> =
        Task.Run(fun () ->
            let results = ResizeArray<RuleInfo>()

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let ruleDir = int r.Direction

                        if ruleDir = direction then
                            let name =
                                match r.Name with
                                | null -> ""
                                | n -> n

                            let grouping =
                                match FirewallService.ResolveGroupName r.Grouping with
                                | null -> ""
                                | g -> g

                            results.Add(
                                RuleInfo(
                                    Name = name,
                                    DisplayName = name,
                                    DisplayGroup = (if String.IsNullOrEmpty grouping then "(Ungrouped)" else grouping),
                                    Direction = (if direction = 1 then "Inbound" else "Outbound"),
                                    Enabled = r.Enabled,
                                    Action = (if int r.Action = 1 then "Allow" else "Block"),
                                    Profile = FirewallService.DecodeProfile r.Profiles,
                                    Program = (match r.ApplicationName with null -> "" | a -> a),
                                    Protocol = FirewallService.DecodeProtocol r.Protocol,
                                    LocalPort = (match r.LocalPorts with null -> "" | l -> l),
                                    RemotePort = (match r.RemotePorts with null -> "" | p -> p),
                                    RemoteAddress = (match r.RemoteAddresses with null -> "" | a -> a)
                                )
                            )
                    with _ ->
                        () // Skip rules that can't be read
            with ex ->
                Debug.WriteLine($"FirewallService.LoadRules Error: {ex.Message}")

            results)

    /// <summary>
    /// Toggle a single rule's enabled state via COM.
    /// </summary>
    member _.ToggleRuleAsync(ruleName: string, enabled: bool) : Task =
        Task.Run(
            Action(fun () ->
                try
                    let fwPolicy = getPolicy ()

                    for r in Com.enumRules fwPolicy.Rules do
                        try
                            if String.Equals(r.Name, ruleName, StringComparison.OrdinalIgnoreCase) then
                                r.Enabled <- enabled
                        with _ -> ()
                with ex ->
                    Debug.WriteLine($"FirewallService.ToggleRule Error: {ex.Message}")
            )
        )

    /// <summary>
    /// Toggle all rules in a group. Matches the raw Grouping string and its
    /// resolved display name.
    /// </summary>
    member _.ToggleGroupAsync(groupName: string, enabled: bool) : Task<GroupToggleResult> =
        Task.Run(fun () ->
            let result = GroupToggleResult(GroupName = groupName)

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    let mutable ruleGroup = Unchecked.defaultof<string>
                    let mutable wasEnabled = false
                    let mutable readable = true

                    try
                        ruleGroup <- (match r.Grouping with null -> "" | g -> g)
                        wasEnabled <- r.Enabled
                    with _ ->
                        readable <- false // Rule unreadable — skip as before

                    if readable then
                        let matches =
                            (String.IsNullOrEmpty ruleGroup && groupName = "(Ungrouped)")
                            || FirewallService.GroupMatches(ruleGroup, groupName)

                        if matches then
                            result.Matched <- result.Matched + 1

                            try
                                if wasEnabled <> enabled then
                                    r.Enabled <- enabled
                                    result.Changed <- result.Changed + 1
                            with ex ->
                                result.Failed <- result.Failed + 1

                                if isNull result.FirstError then
                                    result.FirstError <- ex.Message
            with ex ->
                result.FailedCompletely <- true
                result.FirstError <- ex.Message

            result
        )

    /// <summary>
    /// Captures every firewall rule as JSON before a lockdown resets them.
    /// RestoreLocalFirewallDefaults deletes every non-default rule on the
    /// machine — other security software's, VPNs, Docker/WSL, the user's
    /// own — and nothing can undo the COM call; the snapshot under
    /// %PROGRAMDATA%\AutoCommand\firewall-snapshots at least keeps the
    /// destruction reversible by hand. Best-effort: a failed snapshot is
    /// reported through the returned null but never blocks the lockdown
    /// the user explicitly confirmed.
    /// </summary>
    member private _.ExportPreLockdownSnapshot(fwPolicy: INetFwPolicy2) : string =
        try
            let root =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "AutoCommand",
                    "firewall-snapshots"
                )

            Directory.CreateDirectory(root) |> ignore

            let path =
                Path.Combine(root, "lockdown-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".json")

            let rules = JsonArray()
            let mutable unreadable = 0

            for r in Com.enumRules fwPolicy.Rules do
                try
                    let o = JsonObject()

                    let put (name: string) (value: string) =
                        o[name] <- (match value with null -> null | v -> JsonValue.Create(v))

                    put "name" r.Name
                    put "description" r.Description
                    put "applicationName" r.ApplicationName
                    put "serviceName" r.ServiceName
                    o["protocol"] <- JsonValue.Create(r.Protocol)
                    put "localPorts" r.LocalPorts
                    put "remotePorts" r.RemotePorts
                    put "localAddresses" r.LocalAddresses
                    put "remoteAddresses" r.RemoteAddresses
                    put "icmpTypesAndCodes" r.IcmpTypesAndCodes
                    put "direction" (r.Direction.ToString())
                    put "interfaceTypes" r.InterfaceTypes
                    o["enabled"] <- JsonValue.Create(r.Enabled)
                    put "grouping" r.Grouping
                    o["profiles"] <- JsonValue.Create(r.Profiles)
                    o["edgeTraversal"] <- JsonValue.Create(r.EdgeTraversal)
                    put "action" (r.Action.ToString())
                    rules.Add(o)
                with _ ->
                    unreadable <- unreadable + 1

            let doc = JsonObject()
            doc["capturedUtc"] <- JsonValue.Create(DateTime.UtcNow.ToString("o"))
            doc["ruleCount"] <- JsonValue.Create(rules.Count)
            doc["unreadableRules"] <- JsonValue.Create(unreadable)
            doc["rules"] <- rules
            File.WriteAllText(path, doc.ToJsonString(JsonSerializerOptions(WriteIndented = true)))
            path
        with _ ->
            null

    /// <summary>
    /// Restores firewall rules from a snapshot written by
    /// ExportPreLockdownSnapshot before a ResetToDefaultsAndLockdown.
    /// For each snapshot rule: when a rule with that name exists, its
    /// Enabled state is set to the photographed value; when it does not
    /// (the reset deleted every non-default rule), the rule is recreated
    /// with every photographed field. Default rules the lockdown disabled
    /// but did not delete are re-enabled by the same name match. Rules
    /// created after the snapshot are left untouched — this restores the
    /// photographed state, it does not enforce it.
    /// </summary>
    member _.RestoreFromSnapshotAsync(path: string, progress: IProgress<string>) : Task<GroupToggleResult> =
        Task.Run(fun () ->
            let result = GroupToggleResult(GroupName = "Restore from snapshot")

            try
                let doc =
                    match JsonNode.Parse(File.ReadAllText(path)) with
                    | :? JsonObject as o -> o
                    | _ -> null

                if isNull (box doc) || isNull (box doc["rules"]) then
                    result.FailedCompletely <- true
                    result.FirstError <- "not a rule snapshot file"
                else
                    let fwPolicy = getPolicy ()

                    // Rules that survived the lockdown (Windows defaults are
                    // disabled, not deleted) — matched by name below.
                    let existing = Dictionary<string, INetFwRule>(StringComparer.OrdinalIgnoreCase)

                    for r in Com.enumRules fwPolicy.Rules do
                        try
                            existing[r.Name] <- r
                        with _ -> ()

                    let parseDirection (s: string) =
                        try
                            System.Enum.Parse(typeof<FwRuleDirection>, s) :?> FwRuleDirection
                        with _ ->
                            FwRuleDirection.Out

                    let parseAction (s: string) =
                        try
                            System.Enum.Parse(typeof<FwAction>, s) :?> FwAction
                        with _ ->
                            FwAction.Block

                    for ruleNode in (doc["rules"] :?> JsonArray) do
                        match ruleNode with
                        | :? JsonObject as o ->
                            let get (name: string) =
                                match o[name] with
                                | null -> ""
                                | v -> v.GetValue<string>()

                            let ruleName = get "name"

                            if not (String.IsNullOrEmpty ruleName) then
                                try
                                    let enabled =
                                        match o["enabled"] with
                                        | null -> true
                                        | v -> v.GetValue<bool>()

                                    match existing.TryGetValue(ruleName) with
                                    | true, live ->
                                        // Survived the lockdown as a default
                                        // rule — restore its photographed
                                        // enable state, nothing else.
                                        live.Enabled <- enabled
                                        result.Matched <- result.Matched + 1
                                        result.Changed <- result.Changed + 1
                                    | _ ->
                                        // The reset deleted it — recreate
                                        // from the photographed fields.
                                        let rule = makeRule ()
                                        rule.Name <- ruleName
                                        rule.Description <- get "description"
                                        rule.ApplicationName <- get "applicationName"
                                        rule.ServiceName <- get "serviceName"

                                        (match o["protocol"] with
                                         | null -> ()
                                         | v -> rule.Protocol <- v.GetValue<int>())

                                        rule.LocalPorts <- get "localPorts"
                                        rule.RemotePorts <- get "remotePorts"
                                        rule.LocalAddresses <- get "localAddresses"
                                        rule.RemoteAddresses <- get "remoteAddresses"
                                        rule.IcmpTypesAndCodes <- get "icmpTypesAndCodes"
                                        rule.Direction <- parseDirection (get "direction")
                                        rule.InterfaceTypes <- (match get "interfaceTypes" with "" -> "All" | v -> v)
                                        rule.Enabled <- enabled
                                        rule.Grouping <- get "grouping"

                                        (match o["profiles"] with
                                         | null -> ()
                                         | v -> rule.Profiles <- v.GetValue<int>())

                                        rule.EdgeTraversal <-
                                            (match o["edgeTraversal"] with
                                             | null -> false
                                             | v -> v.GetValue<bool>())

                                        rule.Action <- parseAction (get "action")
                                        fwPolicy.Rules.Add(rule)
                                        result.Matched <- result.Matched + 1
                                        result.Changed <- result.Changed + 1
                                with ex ->
                                    result.Failed <- result.Failed + 1

                                    if isNull result.FirstError then
                                        result.FirstError <- $"{ruleName}: {ex.Message}"
                        | _ -> ()

                    invalidateOwnRuleIndex ()

                    if not (isNull progress) then
                        progress.Report($"Snapshot restore: {result.Changed} applied, {result.Failed} failed")
            with ex ->
                invalidateOwnRuleIndex ()
                result.FailedCompletely <- true
                result.FirstError <- ex.Message

            result
        )

    /// <summary>
    /// DELETES every rule this app ever created (current v2 prefixes, the
    /// legacy pre-v2 names, and the intercept QUIC blocks) — the removal
    /// counterpart of SetAllBlocksEnabledAsync(false), for uninstall-day.
    /// Rules created by Windows or other software are never matched.
    /// </summary>
    member _.RemoveAllOwnRulesAsync() : Task<int> =
        Task.Run(
            Func<int>(fun () ->
                try
                    let fwPolicy = getPolicy ()
                    let rules = fwPolicy.Rules

                    let ownPrefixes =
                        [ naming.OwnIpPrefix
                          naming.OwnAppPrefix
                          yield! naming.LegacyIpPrefixes
                          yield! naming.LegacyAppPrefixes
                          // Intercept session QUIC blocks (pid-suffixed) —
                          // engine-side literal; Intercept.Core is not
                          // referenced here by design.
                          "AutoCommand Intercept QUIC block" ]

                    let mine =
                        seq {
                            for r in Com.enumRules rules do
                                try
                                    let n = r.Name

                                    if not (isNull n)
                                       && List.exists (fun p -> n.StartsWith(p, StringComparison.OrdinalIgnoreCase)) ownPrefixes then
                                        yield n
                                with _ -> ()
                        }
                        |> Seq.toList

                    for name in mine do
                        try
                            rules.Remove(name)
                            recordOwnRuleRemoved name
                        with _ -> ()

                    invalidateOwnRuleIndex ()
                    mine.Length
                with _ ->
                    invalidateOwnRuleIndex ()
                    0
            )
        )

    /// <summary>
    /// Reset the firewall to the Windows default rule set (the COM
    /// equivalent of `netsh advfirewall reset`), then disable every
    /// remaining rule so both all inbound and all outbound traffic is
    /// blocked. Non-default rules — including the app's own v2 blocks — do
    /// not survive the reset; everything deleted is snapshotted first (see
    /// ExportPreLockdownSnapshot).
    /// </summary>
    member this.ResetToDefaultsAndLockdownAsync(progress: IProgress<string>) : Task<GroupToggleResult> =
        Task.Run(fun () ->
            let result = GroupToggleResult(GroupName = "Lockdown (reset to defaults)")

            try
                let fwPolicy = getPolicy ()

                let mutable beforeCount = 0

                try
                    beforeCount <- fwPolicy.Rules.Count
                with _ -> ()

                let snapshotPath = this.ExportPreLockdownSnapshot(fwPolicy)

                if not (isNull progress) then
                    if not (String.IsNullOrEmpty snapshotPath) then
                        progress.Report("Pre-lockdown rule snapshot saved: " + snapshotPath)

                    progress.Report("Restoring Windows default firewall rules…")

                fwPolicy.RestoreLocalFirewallDefaults()
                invalidateOwnRuleIndex ()

                let mutable afterCount = 0

                try
                    afterCount <- fwPolicy.Rules.Count
                with _ -> ()

                let removed = max 0 (beforeCount - afterCount)

                if not (isNull progress) then
                    progress.Report("Defaults restored — disabling every inbound and outbound rule…")

                let mutable disabledCount = 0

                for r in Com.enumRules fwPolicy.Rules do
                    let mutable wasEnabled = false
                    let mutable readable = true

                    try
                        wasEnabled <- r.Enabled
                    with _ ->
                        readable <- false // Rule unreadable — skip as before

                    if readable then
                        result.Matched <- result.Matched + 1

                        try
                            if wasEnabled then
                                r.Enabled <- false
                                result.Changed <- result.Changed + 1
                                disabledCount <- disabledCount + 1
                        with ex ->
                            result.Failed <- result.Failed + 1

                            if isNull result.FirstError then
                                result.FirstError <- ex.Message

                result.Notes <-
                    $"Windows default rule set restored ({removed} non-default rule(s) removed); "
                    + $"{disabledCount} rule(s) disabled — all inbound and outbound traffic is now blocked."
            with ex ->
                result.FailedCompletely <- true
                result.FirstError <- ex.Message

            result
        )

    /// <summary>F# port: overload for the C# optional progress = null.</summary>
    member this.ResetToDefaultsAndLockdownAsync() : Task<GroupToggleResult> =
        this.ResetToDefaultsAndLockdownAsync(Unchecked.defaultof<IProgress<string>>)

    /// <summary>
    /// Get summary counts.
    /// F# port: the C# 4-tuple (TotalInbound, EnabledInbound, TotalOutbound,
    /// EnabledOutbound) returns as ValueTuple — element names are not
    /// carried into C#; deconstruct with `var (a, b, c, d) = await …`.
    /// </summary>
    member _.GetSummaryAsync() : Task<struct (int * int * int * int)> =
        Task.Run(fun () ->
            let mutable totalIn = 0
            let mutable enabledIn = 0
            let mutable totalOut = 0
            let mutable enabledOut = 0

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        let dir = int r.Direction
                        let en = r.Enabled

                        if dir = 1 then
                            totalIn <- totalIn + 1
                            if en then enabledIn <- enabledIn + 1
                        else
                            totalOut <- totalOut + 1
                            if en then enabledOut <- enabledOut + 1
                    with _ -> ()
            with _ -> ()

            struct (totalIn, enabledIn, totalOut, enabledOut)
        )

    /// <summary>
    /// Check if specific rules match their expected config state (for drift
    /// detection). Returns list of drifted rule names.
    /// </summary>
    member _.CheckDriftAsync(overrides: Dictionary<string, string>) : Task<ResizeArray<string>> =
        Task.Run(fun () ->
            let drifted = ResizeArray<string>()

            if isNull (box overrides) || overrides.Count = 0 then
                drifted
            else
                try
                    let fwPolicy = getPolicy ()

                    for r in Com.enumRules fwPolicy.Rules do
                        try
                            let name = r.Name
                            let mutable expected = Unchecked.defaultof<string>

                            if overrides.TryGetValue(name, &expected) then
                                let actual = r.Enabled
                                let expectedBool = expected = "True"

                                if actual <> expectedBool then
                                    let actualText = if actual then "True" else "False"

                                    drifted.Add($"{name} (Expected: {expected}, Actual: {actualText})")
                        with _ -> ()
                with _ -> ()

                drifted
        )

    /// <summary>
    /// Pure prefix matcher: true when <c>ruleName</c> starts with any of the
    /// candidate prefixes (case-insensitive). Public and COM-free so
    /// ContainSelfTest can pin multi-prefix IP unblock matching.
    /// </summary>
    static member MatchesAnyNamePrefix(prefixes: seq<string>, ruleName: string) : bool =
        not (String.IsNullOrEmpty ruleName)
        && not (isNull prefixes)
        && (prefixes
            |> Seq.exists (fun p ->
                not (String.IsNullOrEmpty p)
                && ruleName.StartsWith(p, StringComparison.OrdinalIgnoreCase)))

    /// <summary>
    /// Removes the block rules previously created for a remote IP by
    /// AddBlockRuleForIpAsync (matched on the legacy "IP Block - &lt;ip&gt;"
    /// name prefixes) plus the v2 and adopted families in a single COM pass.
    /// Returns how many rules were removed.
    /// </summary>
    member this.RemoveBlockRulesForIpAsync(remoteIp: string) : Task<int> =
        Task.Run(fun () ->
            let prefixes =
                (naming.LegacyIpPrefixes @ [ naming.OwnIpPrefix ] @ naming.AdoptedPrefixes)
                |> List.map (fun prefix -> $"{prefix}{remoteIp} (")

            this.RemoveRulesByNamePrefixes(prefixes)
        )

    /// <summary>
    /// Pure matcher: does an app-family block rule cover this unblock target.
    /// Exact path, path-normalized equality (MainModule hands out '..'-bearing
    /// strings and the rule stores whatever it was given; device-path forms
    /// fall back to the raw compare), or — the load-bearing leg — the same
    /// exe leaf NAME: AppBlockCoverageService keeps a name-blocked exe
    /// blocked wherever it runs from, so a surviving sibling-path rule
    /// (versioned folder, second install root) keeps the whole name in the
    /// blocked set and re-extends it to the unblocked path on the exe's next
    /// run. Unblocking one path must lift the family. Public and COM-free so
    /// ContainSelfTest can pin the semantics.
    /// </summary>
    static member MatchesAppTarget(naming: FirewallNaming, ruleName: string, ruleApp: string, targetPath: string) : bool =
        let inFamily =
            (not (isNull ruleName))
            && (startsWithAny naming.LegacyAppPrefixes ruleName
                || startsWith naming.OwnAppPrefix ruleName
                || List.exists (fun p -> startsWith p ruleName) naming.AdoptedPrefixes)

        if not inFamily then false
        elif String.Equals(ruleApp, targetPath, StringComparison.OrdinalIgnoreCase) then true
        else
            let norm (p: string) =
                if String.IsNullOrWhiteSpace p then p
                else try Path.GetFullPath(p) with _ -> p

            let leaf (p: string) =
                if String.IsNullOrEmpty p then ""
                else try Path.GetFileName(p) with _ -> p

            String.Equals(norm ruleApp, norm targetPath, StringComparison.OrdinalIgnoreCase)
            || String.Equals(leaf ruleApp, leaf targetPath, StringComparison.OrdinalIgnoreCase)

    /// <summary>
    /// Pure duplicate accounting: given one identity string per rule (IP
    /// rules: the full rule name — app rules: rule name + ApplicationName),
    /// returns how many are redundant (all but the first of each case-insensitive
    /// identity). This is the number the inventory badge and the cleanup button
    /// show, and exactly the count the cleanup retires — nothing else. A target's
    /// distinct shapes (TCP+UDP, the paths of a name family) never count.
    /// </summary>
    static member CountRedundantDuplicates(identities: string seq) : int =
        if isNull identities then
            0
        else
            let counts = Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            for id in identities do
                if not (isNull id) then
                    let mutable n = 0
                    counts.TryGetValue(id, &n) |> ignore
                    counts.[id] <- n + 1

            let mutable redundant = 0
            for KeyValue(_, n) in counts do
                if n > 1 then redundant <- redundant + (n - 1)
            redundant

    /// <summary>
    /// Removes the block rules for an application across its whole NAME
    /// family — every rule whose exe leaf name matches the target, not just
    /// the rules whose ApplicationName equals it. The coverage service
    /// deliberately keeps a name-blocked exe blocked at every path it runs
    /// from, so removing one path's rules while a sibling survives leaves
    /// the exe blocked and the sibling re-extends to the unblocked path on
    /// the next run ("unblock doesn't stick"). Returns the removal count.
    /// </summary>
    member _.RemoveBlockRulesForAppAsync(appPath: string) : Task<int> =
        Task.Run(fun () ->
            let mutable removed = 0

            try
                let fwPolicy = getPolicy ()
                let rules = fwPolicy.Rules
                let names = ResizeArray<string>()

                for r in Com.enumRules rules do
                    try
                        let name =
                            match r.Name with
                            | null -> ""
                            | n -> n

                        let app =
                            match r.ApplicationName with
                            | null -> ""
                            | a -> a

                        if FirewallService.MatchesAppTarget(naming, name, app, appPath) then
                            names.Add(name)
                    with _ -> ()

                for name in names do
                    try
                        rules.Remove(name) |> ignore
                        recordOwnRuleRemoved name
                        removed <- removed + 1
                    with _ -> ()
            with ex ->
                raise (Exception($"Failed to remove firewall rules: {ex.Message}", ex))

            removed
        )

    member private _.RemoveRulesByNamePrefixes(namePrefixes: string list) : int =
        if namePrefixes.IsEmpty then
            0
        else
            let mutable removed = 0

            try
                let fwPolicy = getPolicy ()
                let rules = fwPolicy.Rules
                // Collect matches across all prefixes in one pass — removing while enumerating COM is unreliable
                let names = ResizeArray<string>()

                for r in Com.enumRules rules do
                    try
                        let name =
                            match r.Name with
                            | null -> ""
                            | n -> n

                        if FirewallService.MatchesAnyNamePrefix(namePrefixes, name) then
                            names.Add(name)
                    with _ -> ()

                for name in names do
                    try
                        rules.Remove(name) |> ignore
                        recordOwnRuleRemoved name
                        removed <- removed + 1
                    with _ -> ()
            with ex ->
                raise (Exception($"Failed to remove firewall rules: {ex.Message}", ex))

            removed

    /// <summary>
    /// One-click duplicate cleanup: retires every rule that is an exact
    /// duplicate of another rule on its target (same rule name — and for app
    /// rules the same ApplicationName). Distinct shapes (TCP+UDP per IP, the
    /// paths of a name family) are never touched, a target can never lose its
    /// last rule, and the keeper per identity is the first enabled rule, else
    /// the first — its description (the provenance) survives. Removal is
    /// rename-then-remove: INetFwRules.Remove matches by name and duplicates
    /// SHARE the keeper's name, so each retiring rule is first renamed to a
    /// unique quarantine name (blocking is untouched — a renamed block rule
    /// still blocks) and only then removed by that unique name, so the
    /// by-name delete can never take the keeper with it. Excess legacy+v2
    /// mixes without exact duplicates are NOT touched here — that is the
    /// legacy consolidation's job. Returns (identities cleaned, rules
    /// retired, first error).
    /// </summary>
    member _.RemoveDuplicateBlockRulesAsync() : Task<struct (int * int * string)> =
        Task.Run(fun () ->
            appAddGate.Wait()
            try
                try
                    let fwPolicy = getPolicy ()
                    let groups = Dictionary<string, ResizeArray<INetFwRule>>(StringComparer.OrdinalIgnoreCase)

                    for r in Com.enumRules fwPolicy.Rules do
                        try
                            let (ours, name) = FirewallService.IsOurBlock(naming, r)

                            if ours then
                                let app =
                                    match r.ApplicationName with
                                    | null -> ""
                                    | a -> a

                                let identity =
                                    if isIpRule naming name r then name
                                    else name + "|" + app

                                let mutable list = Unchecked.defaultof<ResizeArray<INetFwRule>>
                                if not (groups.TryGetValue(identity, &list)) then
                                    list <- ResizeArray<INetFwRule>()
                                    groups.[identity] <- list
                                list.Add(r)
                        with _ -> ()

                    let stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")
                    let mutable cleaned = 0
                    let mutable retired = 0
                    let mutable firstError = null

                    for KeyValue(identity, rules) in groups do
                        if rules.Count > 1 then
                            cleaned <- cleaned + 1
                            let keeper =
                                rules
                                |> Seq.tryFind (fun r -> (try r.Enabled with _ -> false))
                                |> Option.defaultValue rules.[0]

                            let mutable i = 0
                            for r in rules do
                                if not (Object.ReferenceEquals(r, keeper)) then
                                    i <- i + 1
                                    try
                                        let quarantine = $"{identity.Split('|').[0]} · dedup-{stamp}-{i}"
                                        r.Name <- quarantine
                                        fwPolicy.Rules.Remove(quarantine) |> ignore
                                        retired <- retired + 1
                                    with ex ->
                                        if isNull firstError then firstError <- ex.Message

                    struct (cleaned, retired, firstError)
                with ex ->
                    raise (Exception($"Failed to remove duplicate block rules: {ex.Message}", ex))
            finally
                appAddGate.Release() |> ignore
        )

    // ── managed block fleet ──────────────────────────────────────────
    //
    // v2 block rules are FEWER and SELF-DESCRIBING:
    //   IP:  2 rules (outbound TCP + UDP) — inbound blocks are redundant on
    //        a client; unsolicited inbound is already dropped by the
    //        firewall's stateful defaults.
    //   APP: 1 outbound rule.
    // Names are deterministic ("<own-ip-prefix><ip> (TCP Out)") which makes
    // creation idempotent and lets wf.msc users sort/filter by the app's
    // block prefix. The Description field carries full provenance (process,
    // PID, host, byte counts, UTC time) — that's the audit trail visible in
    // wf.msc.

    /// <summary>
    /// Shared parser: extracts the IP from a v2, adopted or legacy IP-block
    /// rule name. ("<own-ip-prefix>1.2.3.4 (TCP Out)" /
    /// "&lt;legacy ip prefix&gt;1.2.3.4 (…)" / suffix-less rules).
    /// Public and COM-free so ContainSelfTest can pin inventory ↔ toggle parity.
    /// </summary>
    static member ParseIpTarget(naming: FirewallNaming, name: string) : string =
        if String.IsNullOrEmpty name then
            ""
        else
            let prefix =
                if startsWith naming.OwnIpPrefix name then
                    naming.OwnIpPrefix
                else
                    match List.tryFind (fun p -> startsWith p name) naming.AdoptedPrefixes with
                    | Some p -> p
                    | None ->
                        match List.tryFind (fun p -> startsWith p name) naming.LegacyIpPrefixes with
                        | Some p -> p
                        | None -> ""

            let rest =
                if prefix.Length <= name.Length then name.Substring(prefix.Length)
                else name

            let cut = rest.IndexOf('(')
            let beforeParen = if cut >= 0 then rest.Substring(0, cut) else rest
            let dedupCut = beforeParen.IndexOf(" · ", StringComparison.Ordinal)
            let raw = if dedupCut >= 0 then beforeParen.Substring(0, dedupCut) else beforeParen
            raw.Trim()

    static member NormalizeAppPath(p: string) : string =
        if String.IsNullOrWhiteSpace p then
            ""
        else
            let trimmed = p.Trim()
            let expanded =
                try Environment.ExpandEnvironmentVariables(trimmed)
                with _ -> trimmed
            let full =
                try
                    if expanded.Contains(":\\") || expanded.Contains(":/") || expanded.StartsWith("\\\\") then
                        Path.GetFullPath(expanded)
                    else
                        expanded
                with _ -> expanded
            full.TrimEnd('\\', '/')

    /// <summary>
    /// Pure target matcher shared by SetTargetsEnabledAsync and ContainSelfTest.
    /// Guarantees every target surfaced by GetBlockedInventoryAsync can be
    /// toggled OFF and back ON regardless of suffix, casing, environment
    /// variables (%SystemRoot%), or '..' path segments.
    /// </summary>
    static member MatchesToggleTarget
        (naming: FirewallNaming, ruleName: string, isIp: bool, ruleApp: string, targetKind: string, targetKey: string)
        : bool =
        let key = if isNull targetKey then "" else targetKey.Trim()
        if key.Length = 0 then
            false
        elif String.Equals(targetKind, "ip", StringComparison.OrdinalIgnoreCase) then
            isIp
            && String.Equals(FirewallService.ParseIpTarget(naming, ruleName), key, StringComparison.OrdinalIgnoreCase)
        else
            if isIp then
                false
            else
                let effective = if not (String.IsNullOrEmpty ruleApp) then ruleApp else (if isNull ruleName then "" else ruleName)
                effective.Length > 0
                && (String.Equals(effective, key, StringComparison.OrdinalIgnoreCase)
                    || String.Equals(
                        FirewallService.NormalizeAppPath(effective),
                        FirewallService.NormalizeAppPath(key),
                        StringComparison.OrdinalIgnoreCase))

    /// <summary>
    /// A rule is "risky" when its target is Microsoft/CDN infrastructure or
    /// a Windows component — re-enabling those is what re-breaks internet,
    /// updates or notifications after a panic restore.
    /// </summary>
    static member private IsRiskyRule(naming: FirewallNaming, name: string, rule: INetFwRule) : bool =
        try
            if isIpRule naming name rule then
                IpClassification.isMicrosoftInfra (FirewallService.ParseIpTarget(naming, name))
            else
                let app =
                    match rule.ApplicationName with
                    | null -> ""
                    | a -> a

                app.Length > 0
                && app.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)
        with _ ->
            false

    /// <summary>
    /// O(1) rule lookup via <c>INetFwRules.Item(name)</c>, returning <c>null</c>
    /// when absent (HNetCfg.FwPolicy2 throws FileNotFoundException /
    /// HRESULT 0x80070002 on a miss) and falling back to a short-circuiting
    /// <c>Seq.tryFind</c> only on unexpected COM provider errors. Public so
    /// ContainSelfTest can verify zero-enumeration fast paths offline.
    /// </summary>
    static member FindRuleInCollection(rules: INetFwRules, name: string) : INetFwRule =
        if isNull rules || String.IsNullOrEmpty name then
            null
        else
            try
                rules.Item(name)
            with
            | :? FileNotFoundException -> null
            | :? DirectoryNotFoundException -> null
            | :? ArgumentException -> null
            | :? Runtime.InteropServices.COMException as cex when
                cex.HResult = int 0x80070002u
                || cex.HResult = int 0x80070003u
                || cex.HResult = int 0x80070057u
                || cex.HResult = int 0x80070490u
                || cex.HResult = int 0x8002802Bu ->
                null
            | _ ->
                Com.enumRules rules
                |> Seq.tryFind (fun r ->
                    try
                        not (isNull r) && r.Name = name
                    with _ -> false)
                |> Option.defaultValue null

    static member private FindRule(fwPolicy: INetFwPolicy2, name: string) : INetFwRule =
        if isNull fwPolicy then null
        else FirewallService.FindRuleInCollection(fwPolicy.Rules, name)

    /// <summary>
    /// Consults the seeded in-memory own-rule index before touching COM:
    /// when seeded and <paramref name="name"/> is absent, returns <c>null</c>
    /// in O(1) memory without triggering Windows Firewall's unindexed
    /// <c>INetFwRules.Item(name)</c> full-store scan (~2,000+ rules). When
    /// present in the index (or before the index is seeded), delegates to
    /// <c>FindRuleInCollection</c> and self-heals if the rule was deleted
    /// externally (e.g. wf.msc).
    /// </summary>
    member private _.FindOwnRule(rules: INetFwRules, name: string) : INetFwRule =
        if isNull rules || String.IsNullOrEmpty name then
            null
        else
            let known =
                lock ownRulesGate (fun () ->
                    if ownRuleIndexSeeded then ValueSome(ownRuleNames.Contains(name))
                    else ValueNone)

            match known with
            | ValueSome false -> null
            | _ ->
                let found = FirewallService.FindRuleInCollection(rules, name)
                if isNull found && known = ValueSome true then
                    lock ownRulesGate (fun () -> ownRuleNames.Remove(name) |> ignore)
                found

    static member private IsOurBlock(naming: FirewallNaming, rule: INetFwRule) : bool * string =
        try
            let name =
                match rule.Name with
                | null -> ""
                | n -> n

            if int rule.Action <> 0 then
                false, name // Block only
            else
                (startsWith naming.OwnIpPrefix name
                 || startsWith naming.OwnAppPrefix name
                 || List.exists (fun p -> startsWith p name) naming.AdoptedPrefixes
                 || startsWithAny naming.LegacyIpPrefixes name
                 || startsWithAny naming.LegacyAppPrefixes name),
                name
        with _ ->
            false, null

    member private this.AddIpBlockCore(ip: string, description: string) : struct (int * int * string[]) =
        try
            let mutable created = 0
            let mutable updated = 0
            let fwPolicy = getPolicy ()
            let rules = fwPolicy.Rules
            let appliedNames = ResizeArray<string>(2)

            for (proto, suffix) in [ (FwProtocol.Tcp, "TCP Out"); (FwProtocol.Udp, "UDP Out") ] do
                let name = $"{naming.OwnIpPrefix}{ip} ({suffix})"
                let existing = this.FindOwnRule(rules, name)

                if not (isNull existing) then
                    let actualName =
                        try
                            match existing.Name with
                            | null | "" -> name
                            | n -> n
                        with _ -> name

                    try
                        existing.Description <- description
                        if not existing.Enabled then existing.Enabled <- true
                        updated <- updated + 1
                    with _ -> ()

                    recordOwnRuleAdded actualName
                    appliedNames.Add(actualName)
                else
                    let rule = makeRule ()
                    rule.Action <- FwAction.Block
                    rule.Direction <- FwRuleDirection.Out
                    rule.Enabled <- true
                    rule.InterfaceTypes <- "All"
                    rule.Name <- name
                    rule.RemoteAddresses <- ip
                    rule.Protocol <- int proto
                    rule.Description <- description
                    rules.Add(rule)
                    created <- created + 1
                    recordOwnRuleAdded name
                    appliedNames.Add(name)

            struct (created, updated, appliedNames.ToArray())
        with ex ->
            raise (Exception($"Failed to add IP block: {ex.Message}", ex))

    /// <summary>
    /// Add a 2-rule (outbound TCP+UDP) idempotent IP block with full
    /// provenance, returning the exact rule names created or refreshed so
    /// callers can adopt them into FirewallBaselineManager in O(1) without
    /// scanning the firewall collection.
    /// </summary>
    member this.AddIpBlockWithRulesAsync(ip: string, description: string) : Task<struct (int * int * string[])> =
        Task.Run(fun () -> this.AddIpBlockCore(ip, description))

    /// <summary>
    /// Add a 2-rule (outbound TCP+UDP) idempotent IP block with full
    /// provenance. F# port: returns ValueTuple — deconstruct, element names
    /// are not carried into C#.
    /// </summary>
    member this.AddIpBlockAsync(ip: string, description: string) : Task<struct (int * int)> =
        Task.Run(fun () ->
            let struct (created, updated, _) = this.AddIpBlockCore(ip, description)
            struct (created, updated))

    // ── app-block path coverage (autocommand-ii v2 scheme) ───────────

    /// <summary>The rule name a blocked exe gets at its first (primary) path.</summary>
    member _.PrimaryAppRuleName(exeName: string) : string =
        $"{naming.OwnAppPrefix}{exeName} (Out)"

    /// <summary>Sibling-rule name for an additional path of an already-name-blocked exe.</summary>
    member this.SuffixedAppRuleName(exeName: string, appPath: string) : string =
        $"{this.PrimaryAppRuleName(exeName)} · {FirewallService.PathHash8(appPath)}"

    static member private PathHash8(appPath: string) : string =
        use sha = System.Security.Cryptography.SHA256.Create()
        let path = (if isNull appPath then "" else appPath).TrimEnd('\\').ToUpperInvariant()
        let hash = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(path))
        BitConverter.ToString(hash, 0, 4).Replace("-", "").ToLowerInvariant()

    /// <summary>
    /// Every v2 app-block rule covering one exe name — the primary rule plus
    /// all " · &lt;hash&gt;" siblings — regardless of which path each points at.
    /// </summary>
    static member private GetAppRulesForExe(naming: FirewallNaming, rules: INetFwRules, exeName: string) : ResizeArray<string * string * bool> =
        let result = ResizeArray<string * string * bool>()

        for r in Com.enumRules rules do
            try
                let name = (if isNull r.Name then "" else r.Name)

                if name.StartsWith(naming.OwnAppPrefix, StringComparison.OrdinalIgnoreCase) then
                    let app = (if isNull r.ApplicationName then "" else r.ApplicationName)

                    if String.Equals(Path.GetFileName(app), exeName, StringComparison.OrdinalIgnoreCase) then
                        result.Add((name, app, r.Enabled))
            with _ -> ()

        result

    member private this.AddAppBlockCore(appPath: string, description: string) : struct (int * int * string) =
        // Serialized: the dedupe check below is check-then-act over the
        // process-global policy store, and concurrent callers (a burst of
        // Sysmon EID 1 coverage extensions for the same exe) all pass it
        // before any rule lands — six identical bash.exe rules were observed
        // live. Holding appAddGate across the body makes the check
        // authoritative.
        appAddGate.Wait()
        try
            try
                let exe = Path.GetFileName(if isNull appPath then "" else appPath)

                if exe.Length = 0 then
                    raise (ArgumentException("App block needs a path with a file name.", "appPath"))

                let fwPolicy = getPolicy ()
                let rules = fwPolicy.Rules
                let normTarget = FirewallService.NormalizeAppPath(appPath)
                let primary = $"{naming.OwnAppPrefix}{exe} (Out)"
                let suffixed = $"{primary} · {FirewallService.PathHash8(appPath)}"

                let matchesTargetPath (r: INetFwRule) =
                    not (isNull r)
                    && (try
                            let app = if isNull r.ApplicationName then "" else r.ApplicationName
                            String.Equals(FirewallService.NormalizeAppPath(app), normTarget, StringComparison.OrdinalIgnoreCase)
                        with _ -> false)

                let updateExisting (existing: INetFwRule) (ruleName: string) =
                    let actualName =
                        try
                            match existing.Name with
                            | null | "" -> ruleName
                            | n -> n
                        with _ -> ruleName

                    let mutable updated = 0
                    try
                        existing.Description <- description
                        if not existing.Enabled then existing.Enabled <- true
                        updated <- 1
                    with _ -> ()

                    recordOwnRuleAdded actualName
                    struct (0, updated, actualName)

                // Fast O(1) probes via FindOwnRule: when the own-rule index is
                // seeded, brand-new app blocks skip COM Rules.Item completely
                // (0 full-store scans); suffixed is probed lazily only when
                // primary did not already match normTarget.
                let primaryRule = this.FindOwnRule(rules, primary)

                if matchesTargetPath primaryRule then
                    updateExisting primaryRule primary
                else
                    let suffixedRule = this.FindOwnRule(rules, suffixed)

                    if matchesTargetPath suffixedRule then
                        updateExisting suffixedRule suffixed
                    elif isNull primaryRule && isNull suffixedRule then
                        let rule = makeRule ()
                        rule.Action <- FwAction.Block
                        rule.Direction <- FwRuleDirection.Out
                        rule.Enabled <- true
                        rule.InterfaceTypes <- "All"
                        rule.Name <- primary
                        rule.ApplicationName <- appPath
                        rule.Description <- description
                        rules.Add(rule)
                        recordOwnRuleAdded primary
                        struct (1, 0, primary)
                    else
                        // Primary or hash-sibling already exists for another path
                        // spelling of this exe: scan once to check whether any
                        // '..'-bearing or env-var sibling already covers normTarget.
                        let mine = FirewallService.GetAppRulesForExe(naming, rules, exe)

                        let samePath =
                            mine
                            |> Seq.tryFind (fun (_, app, _) ->
                                String.Equals(FirewallService.NormalizeAppPath(app), normTarget, StringComparison.OrdinalIgnoreCase))

                        match samePath with
                        | Some(sameName, _, _) ->
                            let existing = FirewallService.FindRuleInCollection(rules, sameName)
                            if not (isNull existing) then updateExisting existing sameName
                            else struct (0, 0, null)
                        | None ->
                            let name = if isNull primaryRule then primary else suffixed
                            let candidateExisting = if name = primary then primaryRule else suffixedRule

                            // Path-hash sibling collision means the same path under
                            // different casing — refresh & ensure enabled in place.
                            if not (isNull candidateExisting) then
                                updateExisting candidateExisting name
                            else
                                let rule = makeRule ()
                                rule.Action <- FwAction.Block
                                rule.Direction <- FwRuleDirection.Out
                                rule.Enabled <- true
                                rule.InterfaceTypes <- "All"
                                rule.Name <- name
                                rule.ApplicationName <- appPath
                                rule.Description <- description
                                rules.Add(rule)
                                recordOwnRuleAdded name
                                struct (1, 0, name)
            with ex ->
                raise (Exception($"Failed to add app block: {ex.Message}", ex))
        finally
            appAddGate.Release() |> ignore

    /// <summary>
    /// Adds a 1-rule (outbound) app block, idempotent BY PATH, not just by
    /// name. The firewall enforces the exact ApplicationName, so "already
    /// blocked" is only true when THIS path is already covered — the same
    /// exe running from a new location (versioned folder after an update,
    /// second install root) gets a sibling rule so the name stays blocked
    /// everywhere it lives.
    /// F# port: returns ValueTuple — deconstruct, element names are not
    /// carried into C#.
    /// </summary>
    member this.AddAppBlockAsync(appPath: string, description: string) : Task<struct (int * int)> =
        Task.Run(fun () ->
            let struct (created, updated, _) = this.AddAppBlockCore(appPath, description)
            struct (created, updated))

    /// <summary>
    /// AddAppBlockAsync plus the name of the rule actually created or
    /// refreshed — the audit trail callers like AppBlockCoverageService
    /// persist needs the real rule name, primary or " · hash" sibling.
    /// </summary>
    member this.AddAppBlockWithPathAsync(appPath: string, description: string) : Task<struct (int * int * string)> =
        Task.Run(fun () -> this.AddAppBlockCore(appPath, description))

    /// <summary>
    /// Removes sibling app-block rules whose image path no longer exists on
    /// disk, never the last live rule of a target. Best-effort: the next
    /// pass retries whatever this one could not remove.
    /// </summary>
    member _.RetireDeadAppBlockRulesAsync() : Task<struct (int * int)> =
        Task.Run(fun () ->
            let mutable targets = 0
            let mutable retired = 0

            try
                let fwPolicy = getPolicy ()
                let rules = fwPolicy.Rules
                // Single COM pass: classify (ruleName, isDead) while enumerating
                // instead of re-enumerating fwPolicy.Rules once per blocked exe.
                let byExe = Dictionary<string, ResizeArray<string * bool>>(StringComparer.OrdinalIgnoreCase)

                for r in Com.enumRules rules do
                    try
                        let name = (if isNull r.Name then "" else r.Name)

                        if name.StartsWith(naming.OwnAppPrefix, StringComparison.OrdinalIgnoreCase) then
                            let app = (if isNull r.ApplicationName then "" else r.ApplicationName)

                            if app.Length > 0 then
                                let exe = Path.GetFileName(app)
                                let isDead = not (File.Exists(app))
                                let mutable list = Unchecked.defaultof<ResizeArray<string * bool>>

                                if not (byExe.TryGetValue(exe, &list)) then
                                    list <- ResizeArray<string * bool>()
                                    byExe.[exe] <- list

                                list.Add((name, isDead))
                    with _ -> ()

                for KeyValue(_, entries) in byExe do
                    targets <- targets + 1
                    let mutable hasLive = false
                    let dead = ResizeArray<string>()

                    for (name, isDead) in entries do
                        if isDead then dead.Add(name)
                        else hasLive <- true

                    if hasLive then // never the last rule of a target
                        for name in dead do
                            try
                                rules.Remove(name)
                                recordOwnRuleRemoved name
                                retired <- retired + 1
                            with _ -> ()
            with _ ->
                (* sweep is best-effort; the next pass retries *) ()

            struct (targets, retired))

    /// <summary>
    /// Emergency internet restore / re-enable. With skipRisky=true, rules
    /// targeting Microsoft/CDN infrastructure or Windows components are
    /// left in their current state — that's the "restore everything except
    /// the problematic ones" path after a panic disable.
    /// F# port: renamed from SetAllAutoScopeBlocksEnabledAsync — the C#
    /// name carried an app name; call sites switch to
    /// SetAllBlocksEnabledAsync.
    /// </summary>
    static member private AccumulateInventoryRule
        (
            naming: FirewallNaming,
            byKey: Dictionary<string, BlockedTarget>,
            identitiesByTarget: Dictionary<string, ResizeArray<string>>,
            pathExistsCache: Dictionary<string, bool>,
            r: INetFwRule,
            name: string,
            enabled: bool
        ) =
        try
            let desc =
                match r.Description with
                | null -> ""
                | d -> d

            let app =
                match r.ApplicationName with
                | null -> ""
                | a -> a

            let mutable t = Unchecked.defaultof<BlockedTarget>
            let ruleIsIp = isIpRule naming name r

            if ruleIsIp then
                let ip = FirewallService.ParseIpTarget(naming, name)
                let key = "ip:" + ip

                if not (byKey.TryGetValue(key, &t)) then
                    t <-
                        BlockedTarget(
                            Kind = "ip",
                            Key = key,
                            Ip = ip,
                            Target = ip,
                            Class = IpClassification.classify ip
                        )

                    byKey.[key] <- t
            else
                let path = if not (String.IsNullOrEmpty app) then app else name
                let key = "app:" + path.ToLowerInvariant()

                if not (byKey.TryGetValue(key, &t)) then
                    t <-
                        BlockedTarget(
                            Kind = "app",
                            Key = key,
                            AppPath = path,
                            Target = Path.GetFileName(path),
                            Class =
                                (if FirewallService.IsWindowsComponent path then
                                     "Windows component ⚠"
                                 else
                                     "Application")
                        )

                    byKey.[key] <- t

                if app.Length > 0 then
                    let mutable exists = false
                    if not (pathExistsCache.TryGetValue(app, &exists)) then
                        exists <- File.Exists(app)
                        pathExistsCache.[app] <- exists

                    if not exists then
                        t.StaleRules <- t.StaleRules + 1

                        if String.IsNullOrEmpty t.CoverageNote then
                            t.CoverageNote <-
                                "program path no longer exists on disk — rule is inert "
                                + "(app updated or moved); AppBlockCoverageService re-points or retires it"

            let identity = if ruleIsIp then name else name + "|" + app

            let mutable seen = Unchecked.defaultof<ResizeArray<string>>
            if not (identitiesByTarget.TryGetValue(t.Key, &seen)) then
                seen <- ResizeArray<string>()
                identitiesByTarget.[t.Key] <- seen
            seen.Add(identity)

            t.Rules <- t.Rules + 1
            if enabled then t.EnabledRules <- t.EnabledRules + 1
            if String.IsNullOrEmpty t.Description then t.Description <- desc
            if not t.Created.HasValue then t.Created <- FirewallService.ParseBlockedTime desc
        with _ -> ()

    static member private FinalizeInventory
        (
            byKey: Dictionary<string, BlockedTarget>,
            identitiesByTarget: Dictionary<string, ResizeArray<string>>
        ) : ResizeArray<BlockedTarget> =
        for KeyValue(key, seen) in identitiesByTarget do
            let mutable t = Unchecked.defaultof<BlockedTarget>
            if byKey.TryGetValue(key, &t) then
                t.DuplicateRules <- FirewallService.CountRedundantDuplicates seen

        byKey
            .Values.OrderByDescending(fun (t: BlockedTarget) -> t.Class)
            .ThenBy(fun t -> t.Target)
            .ToList()

    /// <summary>
    /// O(1) direct-lookup fast path for single-target toggles when the caller
    /// knows the target's exact rule count and that it has zero duplicates.
    /// Probes only deterministic v2 rule names via <c>INetFwRules.Item(name)</c>
    /// (zero linear COM enumerations). Returns <c>null</c> without mutating any
    /// rule if the exact expected rules are not all resolved so callers can
    /// seamlessly fall back to the single-pass full scan.
    /// </summary>
    static member TryToggleSingleTargetInCollection
        (
            naming: FirewallNaming,
            rules: INetFwRules,
            targetKind: string,
            targetKey: string,
            expectedRules: int,
            enabled: bool
        ) : TargetToggleSnapshot =
        let key = if isNull targetKey then "" else targetKey.Trim()

        if isNull rules || key.Length = 0 || expectedRules <= 0 then
            null
        else
            let resolved = ResizeArray<string * INetFwRule>()
            let isIp = String.Equals(targetKind, "ip", StringComparison.OrdinalIgnoreCase)

            if isIp then
                if expectedRules = 2 then
                    for suffix in [ "TCP Out"; "UDP Out" ] do
                        let rName = $"{naming.OwnIpPrefix}{key} ({suffix})"
                        let r = FirewallService.FindRuleInCollection(rules, rName)
                        if not (isNull r) && (try int r.Action = 0 with _ -> false) then
                            resolved.Add((rName, r))
            else if expectedRules = 1 then
                let exe = try Path.GetFileName(key) with _ -> ""
                if exe.Length > 0 then
                    let primary = $"{naming.OwnAppPrefix}{exe} (Out)"
                    let suffixed = $"{primary} · {FirewallService.PathHash8(key)}"

                    let matchesAppCandidate (rName: string) (r: INetFwRule) =
                        not (isNull r)
                        && (try
                                int r.Action = 0
                                && FirewallService.MatchesToggleTarget(
                                    naming,
                                    rName,
                                    false,
                                    (match r.ApplicationName with null -> "" | a -> a),
                                    "proc",
                                    key
                                )
                            with _ -> false)

                    let pRule = FirewallService.FindRuleInCollection(rules, primary)
                    if matchesAppCandidate primary pRule then
                        resolved.Add((primary, pRule))
                    else
                        let sRule = FirewallService.FindRuleInCollection(rules, suffixed)
                        if matchesAppCandidate suffixed sRule then
                            resolved.Add((suffixed, sRule))

            if resolved.Count <> expectedRules then
                null
            else
                let snap = TargetToggleSnapshot(UsedFastPath = true, IsFullSnapshot = false)

                for (rName, r) in resolved do
                    snap.Matched <- snap.Matched + 1
                    let actualName =
                        try
                            match r.Name with
                            | null | "" -> rName
                            | n -> n
                        with _ -> rName

                    let mutable effectiveEnabled = false

                    try
                        let was = r.Enabled
                        effectiveEnabled <- was

                        if was <> enabled then
                            let struct (actual, changed, verifyErr) = writeAndVerifyEnabled r actualName enabled
                            effectiveEnabled <- actual
                            if changed then
                                snap.Changed <- snap.Changed + 1
                            elif isNull snap.FirstError && not (isNull verifyErr) then
                                snap.FirstError <- verifyErr
                    with ex ->
                        if isNull snap.FirstError then
                            snap.FirstError <- $"{actualName}: {ex.Message}"

                    snap.RuleStates.Add(struct (actualName, effectiveEnabled))

                snap

    member this.SetAllBlocksEnabledSnapshotAsync
        (enabled: bool, skipRisky: bool, captureInventory: bool, progress: IProgress<struct (int * int)>)
        : Task<TargetToggleSnapshot> =
        Task.Run(fun () ->
            let snap = TargetToggleSnapshot(IsFullSnapshot = true)
            let byKey =
                if captureInventory then Dictionary<string, BlockedTarget>(StringComparer.OrdinalIgnoreCase)
                else null
            let identitiesByTarget =
                if captureInventory then Dictionary<string, ResizeArray<string>>(StringComparer.OrdinalIgnoreCase)
                else null
            let pathExistsCache =
                if captureInventory then Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                else null

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    let (ours, name) = FirewallService.IsOurBlock(naming, r)

                    if ours then
                        let mutable effectiveEnabled = false

                        try
                            let was = r.Enabled
                            effectiveEnabled <- was

                            if skipRisky && enabled && FirewallService.IsRiskyRule(naming, name, r) then
                                snap.SkippedRisky <- snap.SkippedRisky + 1
                            else
                                snap.Matched <- snap.Matched + 1

                                try
                                    if was <> enabled then
                                        let struct (actual, changed, verifyErr) = writeAndVerifyEnabled r name enabled
                                        effectiveEnabled <- actual
                                        if changed then
                                            snap.Changed <- snap.Changed + 1

                                            if not (isNull progress) && (snap.Changed % 16 = 0) then
                                                progress.Report(struct (snap.Changed, snap.Matched))
                                        elif isNull snap.FirstError && not (isNull verifyErr) then
                                            snap.FirstError <- verifyErr
                                with ex ->
                                    if isNull snap.FirstError then snap.FirstError <- $"{name}: {ex.Message}"
                        with ex ->
                            if isNull snap.FirstError then snap.FirstError <- ex.Message

                        if not (String.IsNullOrEmpty name) then
                            snap.RuleStates.Add(struct (name, effectiveEnabled))

                        if captureInventory then
                            FirewallService.AccumulateInventoryRule(
                                naming, byKey, identitiesByTarget, pathExistsCache, r, name, effectiveEnabled
                            )

                replaceOwnRuleIndex (snap.RuleStates |> Seq.map (fun (struct (n, _)) -> n))

                if captureInventory then
                    snap.Inventory <- FirewallService.FinalizeInventory(byKey, identitiesByTarget)

                if not (isNull progress) then
                    progress.Report(struct (snap.Changed, snap.Matched))
            with ex ->
                snap.IsFullSnapshot <- false
                if isNull snap.FirstError then snap.FirstError <- ex.Message

            snap
        )

    member this.SetAllBlocksEnabledAsync(enabled: bool, skipRisky: bool) : Task<FleetToggleResult> =
        task {
            let! snap = this.SetAllBlocksEnabledSnapshotAsync(enabled, skipRisky, false, null)
            return
                FleetToggleResult(
                    Matched = snap.Matched,
                    Changed = snap.Changed,
                    SkippedRisky = snap.SkippedRisky,
                    FirstError = snap.FirstError
                )
        }

    /// <summary>F# port: overload for the C# default skipRisky = false.</summary>
    member this.SetAllBlocksEnabledAsync(enabled: bool) : Task<FleetToggleResult> =
        this.SetAllBlocksEnabledAsync(enabled, false)

    /// <summary>
    /// Single-pass per-target/bulk toggle that optionally builds the post-toggle
    /// inventory and captures all own-block rule states in the same COM walk,
    /// eliminating redundant post-toggle firewall enumerations.
    /// </summary>
    member _.SetTargetsEnabledSnapshotAsync
        (
            targets: IEnumerable<struct (string * string)>,
            enabled: bool,
            captureInventory: bool,
            progress: IProgress<struct (int * int)>
        ) : Task<TargetToggleSnapshot> =
        Task.Run(fun () ->
            let snap = TargetToggleSnapshot()
            let byKey =
                if captureInventory then Dictionary<string, BlockedTarget>(StringComparer.OrdinalIgnoreCase)
                else null
            let identitiesByTarget =
                if captureInventory then Dictionary<string, ResizeArray<string>>(StringComparer.OrdinalIgnoreCase)
                else null
            let pathExistsCache =
                if captureInventory then Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                else null

            try
                let list =
                    if isNull (box targets) then
                        []
                    else
                        targets
                        |> Seq.map (fun (struct (kind, key)) ->
                            (if isNull kind then "" else kind),
                            (if isNull key then "" else key.Trim()))
                        |> Seq.filter (fun (_, key) -> key.Length > 0)
                        |> List.ofSeq

                if not list.IsEmpty then
                    let ipTargets =
                        HashSet<string>(
                            list
                            |> Seq.filter (fun (kind, _) -> String.Equals(kind, "ip", StringComparison.OrdinalIgnoreCase))
                            |> Seq.map snd,
                            StringComparer.OrdinalIgnoreCase
                        )

                    let appRawTargets =
                        HashSet<string>(
                            list
                            |> Seq.filter (fun (kind, _) -> not (String.Equals(kind, "ip", StringComparison.OrdinalIgnoreCase)))
                            |> Seq.map snd,
                            StringComparer.OrdinalIgnoreCase
                        )

                    let appNormTargets =
                        HashSet<string>(
                            appRawTargets
                            |> Seq.map FirewallService.NormalizeAppPath
                            |> Seq.filter (fun p -> p.Length > 0),
                            StringComparer.OrdinalIgnoreCase
                        )

                    let fwPolicy = getPolicy ()
                    snap.IsFullSnapshot <- true

                    for r in Com.enumRules fwPolicy.Rules do
                        let (ours, name) = FirewallService.IsOurBlock(naming, r)

                        if ours then
                            let mutable hit = false

                            try
                                if isIpRule naming name r then
                                    if ipTargets.Count > 0 then
                                        let ip = FirewallService.ParseIpTarget(naming, name)
                                        hit <- ip.Length > 0 && ipTargets.Contains(ip)
                                else if appRawTargets.Count > 0 then
                                    let app =
                                        match r.ApplicationName with
                                        | null -> ""
                                        | a -> a

                                    let effective = if not (String.IsNullOrEmpty app) then app else name

                                    hit <-
                                        effective.Length > 0
                                        && (appRawTargets.Contains(effective)
                                            || appNormTargets.Contains(FirewallService.NormalizeAppPath(effective)))
                            with _ -> ()

                            let mutable effectiveEnabled = false
                            let mutable was = false
                            try
                                was <- r.Enabled
                                effectiveEnabled <- was
                            with _ -> ()

                            if hit then
                                snap.Matched <- snap.Matched + 1

                                try
                                    if was <> enabled then
                                        let struct (actual, changed, verifyErr) = writeAndVerifyEnabled r name enabled
                                        effectiveEnabled <- actual
                                        if changed then
                                            snap.Changed <- snap.Changed + 1

                                            if not (isNull progress) && (snap.Changed % 16 = 0) then
                                                progress.Report(struct (snap.Changed, snap.Matched))
                                        elif isNull snap.FirstError && not (isNull verifyErr) then
                                            snap.FirstError <- verifyErr
                                with ex ->
                                    Debug.WriteLine($"FirewallService.SetTargetsEnabled rule '{name}' failed: {ex.Message}")

                                    if isNull snap.FirstError then
                                        snap.FirstError <- $"{name}: {ex.Message}"

                            if not (String.IsNullOrEmpty name) then
                                snap.RuleStates.Add(struct (name, effectiveEnabled))

                            if captureInventory then
                                FirewallService.AccumulateInventoryRule(
                                    naming, byKey, identitiesByTarget, pathExistsCache, r, name, effectiveEnabled
                                )

                    replaceOwnRuleIndex (snap.RuleStates |> Seq.map (fun (struct (n, _)) -> n))

                    if captureInventory then
                        snap.Inventory <- FirewallService.FinalizeInventory(byKey, identitiesByTarget)

                    if not (isNull progress) then
                        progress.Report(struct (snap.Changed, snap.Matched))
            with ex ->
                snap.IsFullSnapshot <- false
                Debug.WriteLine($"FirewallService.SetTargetsEnabled policy failed: {ex.Message}")

                if isNull snap.FirstError then
                    snap.FirstError <- ex.Message

            snap
        )

    /// <summary>
    /// Single-target toggle with O(1) direct Item(name) fast path when eligible,
    /// falling back automatically to the single-pass snapshot walk for legacy or
    /// multi-rule/duplicate targets.
    /// </summary>
    member this.ToggleSingleTargetSnapshotAsync
        (
            targetKind: string,
            targetKey: string,
            expectedRules: int,
            allowFastPath: bool,
            enabled: bool
        ) : Task<TargetToggleSnapshot> =
        Task.Run(fun () ->
            let mutable fast: TargetToggleSnapshot = null

            if allowFastPath && expectedRules > 0 then
                try
                    let fwPolicy = getPolicy ()
                    fast <-
                        FirewallService.TryToggleSingleTargetInCollection(
                            naming, fwPolicy.Rules, targetKind, targetKey, expectedRules, enabled
                        )
                with _ ->
                    fast <- null

            if not (isNull fast) then
                fast
            else
                this
                    .SetTargetsEnabledSnapshotAsync([| struct (targetKind, targetKey) |], enabled, true, null)
                    .GetAwaiter()
                    .GetResult()
        )

    /// <summary>
    /// Per-target (and per-group, via a list) enable/disable — the toggle
    /// behind the Blocks tab, returning (matched, changed, firstError) so UI
    /// surfaces can distinguish zero-match / COM failures from a clean apply.
    /// Matching uses ParseIpTarget + NormalizeAppPath so every rule surfaced
    /// by GetBlockedInventoryAsync can be disabled and re-enabled symmetrically.
    /// </summary>
    member this.SetTargetsEnabledWithErrorAsync
        (targets: IEnumerable<struct (string * string)>, enabled: bool)
        : Task<struct (int * int * string)> =
        task {
            let! snap = this.SetTargetsEnabledSnapshotAsync(targets, enabled, false, null)
            return struct (snap.Matched, snap.Changed, snap.FirstError)
        }

    /// <summary>
    /// Per-target (and per-group, via a list) enable/disable — returns
    /// (rules matched, rules actually flipped) as ValueTuple.
    /// </summary>
    member this.SetTargetsEnabledAsync
        (targets: IEnumerable<struct (string * string)>, enabled: bool)
        : Task<struct (int * int)> =
        task {
            let! struct (matched, changed, _) = this.SetTargetsEnabledWithErrorAsync(targets, enabled)
            return struct (matched, changed)
        }

    /// <summary>Inventory of all managed block rules, grouped per target, classified.</summary>
    member _.GetBlockedInventoryAsync() : Task<ResizeArray<BlockedTarget>> =
        Task.Run(fun () ->
            let byKey = Dictionary<string, BlockedTarget>(StringComparer.OrdinalIgnoreCase)
            let identitiesByTarget = Dictionary<string, ResizeArray<string>>(StringComparer.OrdinalIgnoreCase)
            let pathExistsCache = Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)

            try
                let fwPolicy = getPolicy ()
                let seenOwnNames = ResizeArray<string>()

                for r in Com.enumRules fwPolicy.Rules do
                    let (ours, name) = FirewallService.IsOurBlock(naming, r)

                    if ours then
                        if not (String.IsNullOrEmpty name) then
                            seenOwnNames.Add(name)

                        let mutable enabled = false
                        try enabled <- r.Enabled with _ -> ()
                        FirewallService.AccumulateInventoryRule(
                            naming, byKey, identitiesByTarget, pathExistsCache, r, name, enabled
                        )

                replaceOwnRuleIndex seenOwnNames
            with _ -> ()

            FirewallService.FinalizeInventory(byKey, identitiesByTarget)
        )

    /// <summary>
    /// One-click cleanup of ALL legacy-name blocks: IP sets (4 rules) shrink
    /// to the v2 2-rule scheme, app blocks (2 rules) shrink to the v2 single
    /// outbound rule. Lossless — descriptions and Enabled state carry over
    /// with a migration marker, protection unchanged (inbound was covered by
    /// stateful filtering). Safe to run repeatedly; exits fast when nothing
    /// legacy remains. F# port: ValueTuple return; the migration marker text
    /// no longer carries an app name.
    /// </summary>
    member this.ConsolidateLegacyIpBlocksAsync() : Task<struct (int * int * int)> =
        Task.Run(fun () ->
            let mutable targets = 0
            let mutable removed = 0
            let mutable migrated = 0

            try
                let fwPolicy = getPolicy ()
                let rules = fwPolicy.Rules
                let legacy = ResizeArray<string * INetFwRule * string>()
                let legacyApps = ResizeArray<string * INetFwRule * string>()

                // Single COM enumeration collects both legacy IP and legacy app rules
                for r in Com.enumRules rules do
                    try
                        if int r.Action = 0 then
                            let name =
                                match r.Name with
                                | null -> ""
                                | n -> n

                            if startsWithAny naming.LegacyIpPrefixes name then
                                legacy.Add((name, r, FirewallService.ParseIpTarget(naming, name)))
                            elif startsWithAny naming.LegacyAppPrefixes name then
                                let app =
                                    match r.ApplicationName with
                                    | null -> ""
                                    | a -> a

                                if app.Length > 0 then
                                    legacyApps.Add((name, r, app))
                    with _ -> ()

                // F# port: group keys lowercased — Seq.groupBy has no
                // comparer overload; C# grouped apps OrdinalIgnoreCase.
                for ipGroup in legacy |> Seq.groupBy (fun (_, _, ip) -> ip.ToLowerInvariant()) do
                    targets <- targets + 1

                    for (name, rule, ip) in snd ipGroup do
                        if name.Contains("Inbound") then
                            try
                                rules.Remove(name) |> ignore
                                recordOwnRuleRemoved name
                                removed <- removed + 1
                            with _ -> ()
                        else
                            // rewrite under v2 name: copy-create-remove (COM rename is unreliable)
                            try
                                let proto = if name.Contains("UDP") then "UDP" else "TCP"
                                let newName = $"{naming.OwnIpPrefix}{ip} ({proto} Out)"
                                let wasEnabled = try rule.Enabled with _ -> true

                                if isNull (this.FindOwnRule(rules, newName)) then
                                    let nr = makeRule ()
                                    nr.Action <- FwAction.Block
                                    nr.Direction <- FwRuleDirection.Out
                                    nr.Enabled <- wasEnabled
                                    nr.InterfaceTypes <- "All"
                                    nr.Name <- newName
                                    nr.RemoteAddresses <- ip
                                    nr.Protocol <- (if name.Contains("UDP") then int FwProtocol.Udp else int FwProtocol.Tcp)

                                    nr.Description <-
                                        (match rule.Description with
                                         | null -> ""
                                         | d -> d)
                                        + " [migrated from legacy rule]"

                                    rules.Add(nr)
                                    recordOwnRuleAdded newName

                                rules.Remove(name) |> ignore
                                recordOwnRuleRemoved name
                                migrated <- migrated + 1
                            with _ -> ()

                // ── legacy app blocks: 2 rules → 1 outbound v2 rule ──
                for appGroup in legacyApps |> Seq.groupBy (fun (_, _, app) -> app.ToLowerInvariant()) do
                    targets <- targets + 1

                    for (name, rule, app) in snd appGroup do
                        if name.Contains("Inbound") then
                            try
                                rules.Remove(name) |> ignore
                                recordOwnRuleRemoved name
                                removed <- removed + 1
                            with _ -> ()
                        else
                            try
                                let newName = $"{naming.OwnAppPrefix}{Path.GetFileName(app)} (Out)"
                                let wasEnabled = try rule.Enabled with _ -> true

                                if isNull (this.FindOwnRule(rules, newName)) then
                                    let nr = makeRule ()
                                    nr.Action <- FwAction.Block
                                    nr.Direction <- FwRuleDirection.Out
                                    nr.Enabled <- wasEnabled
                                    nr.InterfaceTypes <- "All"
                                    nr.Name <- newName
                                    nr.ApplicationName <- app

                                    nr.Description <-
                                        (match rule.Description with
                                         | null -> ""
                                         | d -> d)
                                        + " [migrated from legacy rule]"

                                    rules.Add(nr)
                                    recordOwnRuleAdded newName

                                rules.Remove(name) |> ignore
                                recordOwnRuleRemoved name
                                migrated <- migrated + 1
                            with _ -> ()
            with _ -> ()

            struct (targets, removed, migrated)
        )

    /// <summary>Count of legacy-name block rules still in the firewall (0 after migration).</summary>
    member _.CountLegacyBlocksAsync() : Task<int> =
        Task.Run(fun () ->
            let mutable count = 0

            try
                let fwPolicy = getPolicy ()

                for r in Com.enumRules fwPolicy.Rules do
                    try
                        if int r.Action = 0 then
                            let name =
                                match r.Name with
                                | null -> ""
                                | n -> n

                            if startsWithAny naming.LegacyIpPrefixes name
                               || startsWithAny naming.LegacyAppPrefixes name then
                                count <- count + 1
                    with _ -> ()
            with _ -> ()

            count
        )

    /// <summary>
    /// Recent DROP hits from the firewall log, per destination IP with
    /// first/last seen and the process paths the log carries. Empty when
    /// drop-logging is off (the default) — the process-attributed live
    /// source is the block-hit feed.
    /// pfirewall.log format: date time DROP proto src sport DST dport size
    /// … info PATH — the trailing token group starting at a "X:\" marker is
    /// the program.
    /// </summary>
    static member GetRecentLogHits(minutes: int) : Dictionary<string, FirewallLogHit> =
        let hits = Dictionary<string, FirewallLogHit>(StringComparer.OrdinalIgnoreCase)

        try
            let log = Environment.SystemDirectory + @"\LogFiles\Firewall\pfirewall.log"

            if File.Exists log then
                let cutoff = DateTime.Now.AddMinutes(float -minutes)

                for line in File.ReadLines(log) do
                    // 2026-10-10  14:22:31  DROP  TCP  src  port  dst  port ...
                    if line.Contains("DROP") then
                        let parts = line.Split([| ' ' |], StringSplitOptions.RemoveEmptyEntries)

                        if parts.Length >= 8 then
                            let mutable ts = DateTime()

                            let mutable dst = Unchecked.defaultof<IPAddress>

                            if
                                DateTime.TryParse(parts.[0] + " " + parts.[1], &ts)
                                && ts >= cutoff
                                && IPAddress.TryParse(parts.[6], &dst)
                            then
                                let h =
                                    match hits.TryGetValue(parts.[6]) with
                                    | true, existing -> existing
                                    | false, _ ->
                                        let n = FirewallLogHit(FirstSeen = ts, LastSeen = ts)
                                        hits.[parts.[6]] <- n
                                        n

                                h.Count <- h.Count + 1

                                if ts < h.FirstSeen then h.FirstSeen <- ts

                                if ts > h.LastSeen then h.LastSeen <- ts

                                for i = 8 to parts.Length - 1 do
                                    if parts.[i].Length > 3 && parts.[i].[1] = ':' && parts.[i].[2] = '\\' then
                                        h.Processes.Add(String.Join(' ', parts |> Seq.skip i)) |> ignore
        with _ -> ()

        hits

    static member FirewallDropLoggingOn() : bool =
        // INetFwPolicy2's per-profile logging settings are parameterized COM
        // properties; detection reads the registry keys netsh/wf.msc write —
        // the documented, stable route (the C# dynamic binder could not
        // dispatch them either).
        let registryOn =
            try
                let mutable on = false
                let mutable key = Unchecked.defaultof<Microsoft.Win32.RegistryKey>

                for profileName in [| "DomainProfile"; "StandardProfile"; "PublicProfile" |] do
                    if not on then
                        key <-
                            Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\"
                                + profileName
                                + @"\Logging"
                            )

                        if not (isNull key) then
                            match key.GetValue("LogDroppedPackets") with
                            | :? int as v when v = 1 -> on <- true
                            | _ -> ()

                        if not (isNull key) then key.Dispose()
                on
            with _ ->
                false

        if registryOn then
            true
        else
            // A leftover file from a past enabled period is NOT evidence logging is
            // on — treating it as such hides the enable button while no rows accrue.
            try
                let log = Environment.SystemDirectory + @"\LogFiles\Firewall\pfirewall.log"

                File.Exists log
                && File.GetLastWriteTime(log) > DateTime.Now.AddDays(-1.0)
            with _ ->
                false

    /// <summary>
    /// One-shot at startup: turn on "log dropped packets" so the firewall
    /// log feed works out of the box. Runs at most once EVER — a marker file
    /// is written either way, so a user who later disables logging is
    /// respected.
    /// F# port: C# wrote the marker under a per-app folder — app names are
    /// not allowed in the engine, so a neutral "FirewallEngine" folder is
    /// used; a host app wanting its own once-semantics should check/write
    /// its own marker instead.
    /// </summary>
    static member EnsureDropLoggingOnce() : unit =
        try
            let marker =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "FirewallEngine",
                    "drop-log-autoenabled.marker"
                )

            if not (File.Exists marker) then
                let err = if FirewallService.FirewallDropLoggingOn () then null else FirewallService.SetDropLogging true

                Directory.CreateDirectory(Path.GetDirectoryName(marker)) |> ignore

                let suffix = if isNull err then "" else $" (netsh failed: {err})"
                let stamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm")

                File.WriteAllText(marker, $"{stamp} ensured{suffix}")
        with _ -> ()

    /// <summary>
    /// Enable/disable "log dropped packets" on all profiles via the
    /// documented netsh CLI (needs the app's elevated context). Returns null
    /// on success, otherwise the netsh output/error.
    /// </summary>
    static member SetDropLogging(enable: bool) : string =
        try
            let verb = if enable then "enable" else "disable"

            // netsh is pinned to System32: the app runs elevated from a
            // portable folder, so a bare name would resolve through the app
            // directory / CWD first (both user-writable).
            let netshPath =
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe")

            let psi = ProcessStartInfo(netshPath, $"advfirewall set allprofiles logging droppedconnections {verb}")

            psi.CreateNoWindow <- true
            psi.UseShellExecute <- false
            psi.RedirectStandardOutput <- true
            psi.RedirectStandardError <- true

            use p = Process.Start(psi)

            let output = (p.StandardOutput.ReadToEnd() + " " + p.StandardError.ReadToEnd()).Trim()

            p.WaitForExit(10000) |> ignore

            if p.ExitCode = 0 then null else $"netsh exit {p.ExitCode}: {output}"
        with ex ->
            ex.Message

    static member private ParseBlockedTime(desc: string) : Nullable<DateTime> =
        // v2 descriptions embed "[blocked 2026-10-10 14:22 UTC]"
        let i = match desc with null -> -1 | d -> d.IndexOf("[blocked ")

        if i < 0 then
            Nullable<DateTime>()
        else
            let s = desc.Substring(i + 9)
            let j = s.IndexOf(']')

            if j > 0 then
                match
                    DateTime.TryParseExact(
                        s.Substring(0, j).Replace(" UTC", ""),
                        "yyyy-MM-dd HH:mm",
                        null,
                        Globalization.DateTimeStyles.AssumeUniversal
                    )
                with
                | true, t -> Nullable(t.ToLocalTime())
                | _ -> Nullable<DateTime>()
            else
                Nullable<DateTime>()

    static member private IsWindowsComponent(path: string) : bool =
        not (String.IsNullOrEmpty path)
        && path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)

    static member private DecodeProfile(profiles: int) : string =
        let parts = ResizeArray<string>()
        if (profiles &&& 1) <> 0 then parts.Add("Domain")
        if (profiles &&& 2) <> 0 then parts.Add("Private")
        if (profiles &&& 4) <> 0 then parts.Add("Public")
        if parts.Count > 0 then String.Join(", ", parts) else "All"

    static member private DecodeProtocol(protocol: int) : string =
        match protocol with
        | 6 -> "TCP"
        | 17 -> "UDP"
        | 1 -> "ICMPv4"
        | 58 -> "ICMPv6"
        | 256 -> "Any"
        | _ -> string protocol
