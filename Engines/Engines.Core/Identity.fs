namespace AutoCommand.Engines.Core

/// <summary>Everything an engine needs to know about the app hosting it.
/// Engines are app-agnostic: the same code serves AutoCommand, AutoScope or
/// Shields Up, each constructing its own identity. No engine may embed an
/// app name, rule prefix, data path or port anywhere else.</summary>
type AppIdentity =
    { /// e.g. "AutoScope" — display and logging
      Name: string
      /// data root, e.g. %LOCALAPPDATA%\AutoScope
      DataRoot: string
      /// rule-name prefixes this app CREATES (e.g. "AS-BLOCK-IP ")
      OwnIpRulePrefix: string
      OwnAppRulePrefix: string
      /// rule-name prefixes created by other installs that this app ADOPTS
      /// (manages in place, never renames) — e.g. AutoCommand's AC-BLOCK
      AdoptedRulePrefixes: string list
      /// loopback MCP bridge port scan base
      BridgePortBase: int
      /// MCP server id written into client configs
      McpId: string }

/// <summary>
/// The user-visible brand of the host app, for the handful of strings the
/// engines themselves author (verdict next-steps, the keylog flag-file
/// text, the provenance report footer, the RDAP User-Agent). Set once at
/// startup — WatchConfig.Configure does it from the identity's Name — and
/// read-only everywhere else. Neutral default so engines stay honest when
/// no host configured them (self-tests).
/// </summary>
module Branding =
    let mutable private displayName = "the app"
    let Configure(name: string) : unit =
        if not (System.String.IsNullOrWhiteSpace name) then displayName <- name
    let DisplayName: string = displayName

module Identity =
    /// AutoCommand III's identity: the autocommand-ii values (port base
    /// 47821, %LOCALAPPDATA%\AutoCommand, AC-BLOCK rule names, the
    /// 'autocommand' MCP id). Adopts AutoCommand Light's AL-BLOCK rules in
    /// place (mutual adoption — either app's panic button restores both
    /// apps' blocks; Light never creates service-scoped rules, so there is
    /// no AL-BLOCK-SVC prefix to adopt).
    let autocommand () =
        { Name = "AutoCommand"
          DataRoot = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "AutoCommand")
          OwnIpRulePrefix = "AC-BLOCK-IP "
          OwnAppRulePrefix = "AC-BLOCK-APP "
          AdoptedRulePrefixes = [ "AL-BLOCK-IP "; "AL-BLOCK-APP " ]
          BridgePortBase = 47821
          McpId = "autocommand" }

    let autoscope () =
        { Name = "AutoScope"
          DataRoot = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "AutoScope")
          OwnIpRulePrefix = "AS-BLOCK-IP "
          OwnAppRulePrefix = "AS-BLOCK-APP "
          AdoptedRulePrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP " ]
          BridgePortBase = 47921
          McpId = "autoscope" }

    /// AutoCommand Light's identity: the novice-facing sibling shell (see
    /// shells\AutoCommand.Light). Own data root and AL-BLOCK rule prefixes;
    /// adopts AutoCommand's AC-BLOCK rules in place so Light's panic button
    /// and Blocks list cover the full install. No MCP bridge of its own —
    /// the bridge port base stays only because every identity carries one
    /// (engines' invariant); Light never starts a listener on it.
    let light () =
        { Name = "AutoCommand Light"
          DataRoot = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "AutoCommandLight")
          OwnIpRulePrefix = "AL-BLOCK-IP "
          OwnAppRulePrefix = "AL-BLOCK-APP "
          AdoptedRulePrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP "; "AC-BLOCK-SVC " ]
          BridgePortBase = 47721
          McpId = "autocommand-light" }
