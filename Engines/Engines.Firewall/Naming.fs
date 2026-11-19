namespace AutoCommand.Engines.Firewall

/// <summary>
/// Every rule-name prefix and description string the firewall engine knows,
/// injected by the host app — the engine itself is app-agnostic and never
/// embeds an app name. "Own" prefixes are what this app CREATES; "Adopted"
/// are other installs' rules it manages in place without renaming;
/// "Legacy" are this app's own historical naming schemes (consolidation
/// targets, still honored for matching).
/// </summary>
type FirewallNaming =
    { OwnIpPrefix: string
      OwnAppPrefix: string
      /// service-scoped blocks: one rule per svchost-hosted service, scoped
      /// by INetFwRule.ServiceName — covers every destination the service
      /// ever contacts, present or future
      OwnSvcPrefix: string
      AdoptedPrefixes: string list
      LegacyIpPrefixes: string list
      LegacyAppPrefixes: string list
      /// rule Description marker for user-created blocks (provenance is
      /// appended after it)
      UserBlockDescription: string }

module Naming =
    /// AutoCommand III's policy: creates AC-BLOCK (autocommand-ii's v2
    /// scheme), adopts AutoCommand Light's AL-BLOCK in place (mutual —
    /// either app's panic button restores both installs' blocks), still
    /// honors its own pre-v2 legacy names.
    let autocommand () =
        { OwnIpPrefix = "AC-BLOCK-IP "
          OwnAppPrefix = "AC-BLOCK-APP "
          OwnSvcPrefix = "AC-BLOCK-SVC "
          AdoptedPrefixes = [ "AL-BLOCK-IP "; "AL-BLOCK-APP " ]
          LegacyIpPrefixes = [ "AutoCommand IP Block - " ]
          LegacyAppPrefixes = [ "AutoCommand Process Block - " ]
          UserBlockDescription = "AutoCommand User Block" }

    /// AutoScope's policy: creates AS-BLOCK, adopts AutoCommand's AC-BLOCK
    /// and AutoTrack's AT-BLOCK in place (mutual adoption — any of the three
    /// apps' panic buttons restores everything), still honors its own
    /// pre-v3 legacy names.
    let autoscope () =
        { OwnIpPrefix = "AS-BLOCK-IP "
          OwnAppPrefix = "AS-BLOCK-APP "
          OwnSvcPrefix = "AS-BLOCK-SVC "
          AdoptedPrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP "; "AT-BLOCK-IP "; "AT-BLOCK-APP " ]
          LegacyIpPrefixes = [ "AutoScope IP Block - " ]
          LegacyAppPrefixes = [ "AutoScope Process Block - " ]
          UserBlockDescription = "AutoScope User Block" }

    /// AutoCommand Light's policy: creates AL-BLOCK (ip and app only —
    /// Light never service-scopes), adopts AutoCommand's AC-BLOCK family
    /// in place so Light's panic button and Blocks list cover the whole
    /// install. No legacy names: Light is new naming, first generation.
    let light () =
        { OwnIpPrefix = "AL-BLOCK-IP "
          OwnAppPrefix = "AL-BLOCK-APP "
          OwnSvcPrefix = "AL-BLOCK-SVC "
          AdoptedPrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP "; "AC-BLOCK-SVC " ]
          LegacyIpPrefixes = []
          LegacyAppPrefixes = []
          UserBlockDescription = "AutoCommand Light User Block" }
