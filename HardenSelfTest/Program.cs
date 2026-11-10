using System.Text.Json;
using AutoCommand.Engines.Firewall;
using ShieldsUp.Core;
using ShieldsUp.Core.Helpers;
using ShieldsUp.Core.Services;

// HardenSelfTest — the Shields Up tab's engine, offline:
//   1. the AppPaths data-root seam (Configure before anything constructs)
//   2. FirewallConfigManager reload-merge-write (the shared firewall_config.json)
//   3. StandaloneImport copy/merge/idempotency rules
//   4. Quick Scan step shape (no ShieldsUp-branded steps rode along)
//   5. the engine's Shield Up whitelist predicate (the WSL/Hyper-V widening)
//   6. the telemetry vendor rule table shape
// Everything runs against a temp data root; no service, COM or bcdedit call.

int failed = 0;
void Check(string name, bool pass, string detail = null)
{
    Console.WriteLine((pass ? "PASS  " : "FAIL  ") + name +
                      (pass || string.IsNullOrEmpty(detail) ? "" : $" — {detail}"));
    if (!pass) failed++;
}

string tempRoot = Path.Combine(Path.GetTempPath(), "autocommand-harden-selftest-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(tempRoot);

try
{
    // ── 1. the AppPaths seam ────────────────────────────────────────────
    AppPaths.Configure(tempRoot);
    Check("1a data root follows Configure", AppPaths.DataRoot == tempRoot,
          $"got {AppPaths.DataRoot}");
    Check("1b per-file paths live under the configured root",
          AppPaths.TelemetryStatePath.StartsWith(tempRoot, StringComparison.Ordinal) &&
          AppPaths.FirewallConfigPath.StartsWith(tempRoot, StringComparison.Ordinal) &&
          AppPaths.BloatwareConfigPath.StartsWith(tempRoot, StringComparison.Ordinal));

    // ── 2. FirewallConfigManager: reload-merge-write on a shared file ───
    // The vendored core and the host's own manager both write
    // firewall_config.json; a blind in-memory save used to clobber the
    // other writer's entries. SetOverride must reload-merge-write.
    var writerA = new FirewallConfigManager();
    writerA.SetOverride("Rule X", false);
    var writerB = new FirewallConfigManager();
    writerB.SetOverride("Rule Y", true);

    var onDisk = JsonSerializer.Deserialize<Dictionary<string, string>>(
        File.ReadAllText(AppPaths.FirewallConfigPath));
    Check("2a both writers' overrides survive in the shared file",
          onDisk != null && onDisk.ContainsKey("Rule X") && onDisk.ContainsKey("Rule Y"),
          onDisk == null ? "file missing" : "keys: " + string.Join(",", onDisk.Keys));

    var fresh = new FirewallConfigManager();
    Check("2b a fresh manager reads the merged state",
          fresh.GetOverride("Rule X") == "False" && fresh.GetOverride("Rule Y") == "True");

    // ── 3. StandaloneImport: copy-if-absent, host-wins merge, idempotent ─
    string legacy = Path.Combine(tempRoot, "legacy-shieldsup");
    Directory.CreateDirectory(legacy);
    File.WriteAllText(Path.Combine(legacy, "telemetry_state.json"),
                      """[{"RuleId":"dotnet-cli-telemetry","PreviousValue":true}]""");
    File.WriteAllText(Path.Combine(legacy, "firewall_config.json"),
                      """{"Legacy Rule":"False","Rule X":"True"}""");

    string hostRoot = Path.Combine(tempRoot, "host");
    Directory.CreateDirectory(hostRoot);
    File.WriteAllText(Path.Combine(hostRoot, "firewall_config.json"),
                      """{"Rule X":"False"}""");

    var report = StandaloneImport.Import(hostRoot, legacy);
    Check("3a a file the host lacks is copied",
          File.Exists(Path.Combine(hostRoot, "telemetry_state.json")),
          "imported: " + string.Join(",", report.Imported));

    var mergedCfg = JsonSerializer.Deserialize<Dictionary<string, string>>(
        File.ReadAllText(Path.Combine(hostRoot, "firewall_config.json")));
    Check("3b the host's own rule intent is never overwritten",
          mergedCfg != null && mergedCfg.TryGetValue("Rule X", out var vx) && vx == "False",
          mergedCfg == null ? "file missing" : "Rule X=" + mergedCfg.GetValueOrDefault("Rule X"));
    Check("3c a rule the host lacks is merged in",
          mergedCfg != null && mergedCfg.ContainsKey("Legacy Rule"));
    Check("3d the report names the merge", report.Merged.Any(m => m.StartsWith("firewall_config")));

    var report2 = StandaloneImport.Import(hostRoot, legacy);
    Check("3e re-import is a no-op", !report2.DidAnything,
          "imported: " + string.Join(",", report2.Imported) + "; merged: " + string.Join(",", report2.Merged));

    // ── 4. Quick Scan step shape ─────────────────────────────────────────
    var steps = QuickScanService.Steps;
    Check("4a the checklist carries its steps", steps.Count >= 5, $"got {steps.Count}");
    Check("4b step ids are unique",
          steps.Select(s => s.Id).Distinct().Count() == steps.Count);
    Check("4c every step has an Apply and a Verify",
          steps.All(s => s.Apply != null && s.Verify != null));
    Check("4d the standalone app's logon-task step did not ride along",
          !steps.Any(s => s.Id == "startup"),
          "inside AutoCommand the host owns its own autostart decisions");

    // ── 5. the engine's Shield Up whitelist (the WSL/Hyper-V widening) ──
    Check("5a mDNS stays whitelisted",
          ShieldsUpWhitelist.isWhitelisted("mDNS", "mDNS"));
    Check("5b Core Networking stays whitelisted",
          ShieldsUpWhitelist.isWhitelisted("Core Networking", "@FirewallAPI.dll,-35102"));
    Check("5c Hyper-V VM rules (icsvc) survive the lockdown",
          ShieldsUpWhitelist.isWhitelisted("", "icsvc.dll,-700"));
    Check("5d the WSL store-package group survives the lockdown",
          ShieldsUpWhitelist.isWhitelisted("Some Display",
              "ms-resource://Microsoft.SubsystemForLinux/..."));
    Check("5e HNS / vSwitch plumbing survives the lockdown",
          ShieldsUpWhitelist.isWhitelisted("Hyper-V Host Network Service", "HNS"));
    Check("5f wslservice survives the lockdown",
          ShieldsUpWhitelist.isWhitelisted("", "wslservice.exe"));
    Check("5g sharing groups are still fair game",
          !ShieldsUpWhitelist.isWhitelisted("File and Printer Sharing",
              "@FirewallAPI.dll,-28502"));
    Check("5h remote desktop is still fair game",
          !ShieldsUpWhitelist.isWhitelisted("Remote Desktop", "RemoteDesktop"));
    Check("5i an empty group is never whitelisted",
          !ShieldsUpWhitelist.isWhitelisted("", ""));

    // ── 6. the telemetry vendor rule table ───────────────────────────────
    var rules = new TelemetryRulesService().Rules;
    Check("6a vendor rules are present (file or seed fallback)",
          rules.Count >= 5, $"got {rules.Count}");
    Check("6b rule ids are unique",
          rules.Select(r => r.Id).Distinct().Count() == rules.Count);
    Check("6c every rule carries a state probe and an opt-out",
          rules.All(r => r.StateProbe != null && r.OptOut != null));
    Check("6d every rule carries a plain-language vendor name",
          rules.All(r => !string.IsNullOrWhiteSpace(r.AppName)));
    Check("6e Windows-search feature rules shipped (the SearchHost talker)",
          new[] { "win-search-bing-suggestions", "win-search-cloud-content", "win-search-web-results" }
              .All(id => rules.Any(r => r.Id == id)),
          $"got: {string.Join(", ", rules.Select(r => r.Id))}");
    Check("6f every registry opt-out/probe stays inside the write allow-list",
          rules.Where(r => r.OptOut?.Type == "registry" || r.StateProbe?.Type == "registry")
               .All(r => TelemetryRulesService.IsRegistryWriteAllowed(r.OptOut.RegKey) &&
                         TelemetryRulesService.IsRegistryWriteAllowed(r.StateProbe.RegKey)));
    Check("6g feature rules never pose as telemetry — category says feature, talker named",
          rules.Where(r => r.IsFeatureToggle)
               .All(r => r.Category?.IndexOf("feature", StringComparison.OrdinalIgnoreCase) >= 0 &&
                         !string.IsNullOrWhiteSpace(r.TrafficProcess)));
    Check("6h feature state text says 'at the source', never a stop claim",
          new TelemetryRuleStatus { Rule = rules.First(r => r.IsFeatureToggle), State = TelemetryState.Off }
              .StateText == "Off at the source" &&
          new TelemetryRuleStatus { Rule = rules.First(r => r.IsFeatureToggle), State = TelemetryState.On }
              .StateText == "Feature on — still fetching");
    Check("6i telemetry rules keep the classic wording (null SwitchKind = telemetry)",
          new TelemetryRuleStatus { Rule = rules.First(r => !r.IsFeatureToggle), State = TelemetryState.Off }
              .StateText == "Opted out");

    // ── 7. legacy name-resolution doors — pure state machine ────────────
    Check("7a netbios: no interfaces is Unknown, never Closed",
          NameResolutionDoors.ComputeNetbiosState(0, 0) == NameResolutionDoors.NbState.Unknown);
    Check("7b netbios: all interfaces disabled is Closed",
          NameResolutionDoors.ComputeNetbiosState(3, 3) == NameResolutionDoors.NbState.Closed);
    Check("7c netbios: some interfaces disabled is Partial",
          NameResolutionDoors.ComputeNetbiosState(3, 1) == NameResolutionDoors.NbState.Partial);
    Check("7d netbios: none disabled is the Open state",
          NameResolutionDoors.ComputeNetbiosState(2, 0) == NameResolutionDoors.NbState.None);
    Check("7e llmnr: absent policy means OPEN (Windows default)",
          NameResolutionDoors.LlmnrOpenFromValue(null) && NameResolutionDoors.LlmnrOpenFromValue(1));
    Check("7f llmnr: EnableMulticast=0 is the only closed value",
          !NameResolutionDoors.LlmnrOpenFromValue(0));
    Check("7g mdns: door closed only when a scoped rule exists",
          !NameResolutionDoors.MdnsClosedFromRuleCount(0) && NameResolutionDoors.MdnsClosedFromRuleCount(1));
}
catch (Exception ex)
{
    Console.WriteLine("FAIL  harness error — " + ex);
    failed++;
}
finally
{
    try { Directory.Delete(tempRoot, recursive: true); } catch { }
}

Console.WriteLine(failed == 0
    ? "ALL HARDEN SELF-TESTS PASSED"
    : $"{failed} HARDEN SELF-TEST(S) FAILED");
return failed == 0 ? 0 : 1;
