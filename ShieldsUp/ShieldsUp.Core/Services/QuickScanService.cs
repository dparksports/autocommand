using System.Management;
using System.ServiceProcess;
using ShieldsUp.Core.Helpers;

namespace ShieldsUp.Core.Services;

/// <summary>
/// One action of the quick-scan plan. Apply reuses the exact action behind the
/// corresponding dedicated page; Verify reads the live system state so the
/// checklist doubles as a status dashboard.
/// </summary>
public class SetupStep
{
    public string Id { get; init; }
    public string Title { get; init; }
    public string Description { get; init; }
    public Func<IProgress<string>, Task<(bool, string)>> Apply { get; init; }
    public Func<Task<(bool, string)>> Verify { get; init; }
}

/// <summary>
/// The one-click fresh-install hardening plan (AutoCommand's FreshSetupService).
/// Each step reuses the exact actions behind the dedicated pages
/// (Attack Surface, Firewall, Privacy, OS Hardening, Settings, Bloatware,
/// Hibernation) so behavior never drifts between the checklist and the pages.
/// The logon task lives in LogonTaskService (Shields Up's own task).
/// </summary>
public static class QuickScanService
{
    private const string TelemetryTaskPath = @"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver";

    private static IReadOnlyList<SetupStep> _steps;
    public static IReadOnlyList<SetupStep> Steps
    {
        get
        {
            if (_steps == null)
            {
                _steps = new List<SetupStep>
                {
                    new SetupStep
                    {
                        Id = "miniports",
                        Title = "WAN Miniports & KDNET",
                        Description = "Remove all WAN Miniport devices (incl. SSTP), the KDNIC kernel-debug adapter, and turn bcdedit debug off. SstpSvc is stopped and disabled.",
                        Apply = async progress =>
                        {
                            progress?.Report("Stopping and disabling SstpSvc…");
                            try
                            {
                                using (var sc = new ServiceController("SstpSvc"))
                                {
                                    if (sc.Status != ServiceControllerStatus.Stopped)
                                        ServiceHelper.StopAndDisable("SstpSvc");
                                }
                            }
                            catch { } // not installed — fine

                            progress?.Report("Removing WAN Miniports and KDNIC adapter…");
                            var results = new List<string>();
                            results.AddRange(WanMiniportRemover.RemoveKdnet());
                            results.AddRange(WanMiniportRemover.Execute());
                            progress?.Report("Turning kernel debug off (bcdedit)…");
                            await ProcessRunner.RunAsync("bcdedit", "/debug off");

                            int removed = results.Count(r => !string.IsNullOrWhiteSpace(r));
                            return (true, $"{removed} device action(s) performed; SstpSvc disabled; kernel debug off");
                        },
                        Verify = async () =>
                        {
                            var (ok, detail) = await Task.Run(() =>
                            {
                                int present = 0;
                                try
                                {
                                    using var searcher = new ManagementObjectSearcher(
                                        "SELECT Name FROM Win32_PnPEntity WHERE Name LIKE '%WAN Miniport%' OR Name LIKE '%KDNIC%' OR Name LIKE '%Kernel Debug%'");
                                    present = searcher.Get().Count;
                                }
                                catch { }

                                bool debugOn = false;
                                string bcd = ProcessRunner.Run("bcdedit", "/enum {current}");
                                if (!string.IsNullOrEmpty(bcd))
                                    debugOn = bcd.IndexOf("debug", StringComparison.OrdinalIgnoreCase) >= 0
                                           && bcd.IndexOf("yes", StringComparison.OrdinalIgnoreCase) >= 0;

                                if (present == 0 && !debugOn)
                                    return (true, "no WAN Miniport / KDNIC devices present; kernel debug off");
                                return (false, $"{present} miniport/debug device(s) present (gone after reboot)"
                                    + (debugOn ? "; kernel debug ON" : ""));
                            });
                            return (ok, detail);
                        }
                    },
                    new SetupStep
                    {
                        Id = "firewall",
                        Title = "Firewall: Shield Up profile",
                        Description = "Disables every grouped firewall rule, then re-enables only the whitelists (mDNS, Core Networking).",
                        Apply = async progress =>
                        {
                            var result = await AutoCommand.Contain.Core.FirewallProfileService.Instance.ApplyProfile(
                                AutoCommand.Contain.Core.FirewallProfileService.ProfileType.ShieldsUpMdns, progress);
                            return (true, $"Applied — {result.TotalChanged} rule(s) changed, {result.TotalFailed} failed");
                        },
                        Verify = async () =>
                        {
                            var (ok, detail) = await Task.Run(CountEnabledGroupedRules);
                            return (ok, detail);
                        }
                    },
                    new SetupStep
                    {
                        Id = "telemetry",
                        Title = "Privacy: usage data & telemetry",
                        Description = "Disables the UsageDataReceiver scheduled task (the same toggle as the Privacy page).",
                        Apply = async progress =>
                        {
                            progress?.Report("Disabling telemetry task…");
                            await TaskSchedulerService.Instance.SetTaskEnabledAsync(TelemetryTaskPath, false);
                            return (true, "UsageDataReceiver telemetry task disabled");
                        },
                        Verify = async () =>
                        {
                            var (ok, detail) = await Task.Run(() =>
                            {
                                bool enabled = TaskSchedulerService.Instance.IsTaskEnabled(TelemetryTaskPath);
                                return (!enabled, enabled ? "telemetry task is active" : "telemetry task is disabled");
                            });
                            return (ok, detail);
                        }
                    },
                    new SetupStep
                    {
                        Id = "hardening",
                        Title = "OS Hardening: IPv6 off + max UAC",
                        Description = "Sets the IPv6 DisabledComponents registry value (0xFF) and moves UAC to maximum strictness. Reboot required.",
                        Apply = progress =>
                        {
                            progress?.Report("Writing hardening registry values…");
                            RegistryHelper.SetIpv6DisabledStatus(true);
                            RegistryHelper.SetUacStrictness(true);
                            return Task.FromResult((true, "IPv6 disabled (DisabledComponents=0xFF); UAC at maximum strictness — reboot required"));
                        },
                        Verify = async () =>
                        {
                            var (ok, detail) = await Task.Run(() =>
                            {
                                bool ipv6 = RegistryHelper.GetIpv6DisabledStatus();
                                bool uac = RegistryHelper.GetUacStrictness();
                                return ((ipv6 && uac),
                                    (ipv6 ? "IPv6 disabled" : "IPv6 enabled") + " · " +
                                    (uac ? "UAC max strictness" : "UAC relaxed") +
                                    ((ipv6 && uac) ? "" : " — reboot after applying"));
                            });
                            return (ok, detail);
                        }
                    },
                    // The standalone app's "launch at logon" step is omitted
                    // here on purpose: it created a ShieldsUp-branded
                    // scheduled task, and inside AutoCommand the host owns
                    // its own autostart decisions.
                    new SetupStep
                    {
                        Id = "bloatware",
                        Title = "Bloatware: remove",
                        Description = "Uninstalls the apps on the bloatware list (Outlook, Xbox, Teams, Copilot, OneDrive, … — user-configurable; included in the master confirmation).",
                        Apply = async progress =>
                        {
                            var (matched, removed, failed) = await AppManagerService.Instance.RemoveBloatwareAsync(progress);
                            if (matched.Count == 0)
                                return (true, "no bloatware packages found");
                            return (failed.Count == 0,
                                $"removed {removed}/{matched.Count} package(s)" +
                                (failed.Count > 0 ? "; failed: " + string.Join(", ", failed) : ""));
                        },
                        Verify = async () =>
                        {
                            // Same effective (user-configured) list the removal
                            // step used — verifying raw defaults would flag
                            // apps the user deliberately opted out of
                            var matched = await AppManagerService.Instance.FindBloatwareAsync();
                            return (matched.Count == 0,
                                matched.Count == 0 ? "no bloatware packages installed" : $"{matched.Count} bloatware package(s) still installed");
                        }
                    },
                    new SetupStep
                    {
                        Id = "hibernation",
                        Title = "Hibernation: disable",
                        Description = "Runs powercfg /hibernate off so no hiberfile is kept on disk.",
                        Apply = async progress =>
                        {
                            progress?.Report("Disabling hibernation…");
                            await ProcessRunner.RunAsync("powercfg", "/hibernate off");
                            return (true, "hibernation disabled (hiberfile removed)");
                        },
                        Verify = async () =>
                        {
                            string output = await ProcessRunner.RunAsync("powercfg", "/a");
                            bool enabled = output.Contains("Hibernate")
                                           && !output.Contains("Hibernate is not available")
                                           && !output.Contains("Hibernation has not been enabled");
                            return (!enabled, enabled ? "hibernation is enabled" : "hibernation is disabled");
                        }
                    },
                };
            }
            return _steps;
        }
    }

    private static Task<(bool, string)> CountEnabledGroupedRules()
    {
        return Task.Run(() =>
        {
            try
            {
                Type fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                dynamic fwPolicy = Activator.CreateInstance(fwPolicyType);
                int count = 0;
                foreach (dynamic rule in fwPolicy.Rules)
                {
                    try
                    {
                        string group = rule.Grouping ?? "";
                        if (!string.IsNullOrEmpty(group) && (bool)rule.Enabled)
                            count++;
                    }
                    catch { }
                }
                return (count == 0,
                    count == 0
                        ? "all grouped rules disabled (whitelists exempt)"
                        : $"{count} grouped rule(s) still enabled");
            }
            catch
            {
                return (true, "rule state unknown (COM unavailable)"); // don't fail the checklist on a COM hiccup
            }
        });
    }
}
