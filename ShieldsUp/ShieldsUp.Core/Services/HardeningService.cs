using ShieldsUp.Core.Helpers;

namespace ShieldsUp.Core.Services;

/// <summary>
/// OS-hardening checks and registry toggles, extracted from Shields Up's
/// WinUI HardeningPage: global IPv6, LSA Protection, UAC strictness and the
/// hosts-file audit. All reversible except the hosts reset, which discards
/// custom entries — the caller confirms first and says so.
/// </summary>
public static class HardeningService
{
    public const string HostsFilePath = @"C:\Windows\System32\drivers\etc\hosts";

    // ── IPv6 ──

    public static bool IsIpv6Disabled() => RegistryHelper.GetIpv6DisabledStatus();

    public static void SetIpv6Disabled(bool disabled) => RegistryHelper.SetIpv6DisabledStatus(disabled);

    // ── LSA Protection (RunAsPPL) ──

    public static bool IsLsaProtected() => RegistryHelper.GetLsaProtectionStatus();

    public static void SetLsaProtected(bool on) => RegistryHelper.SetLsaProtectionStatus(on);

    // ── UAC strictness ──

    public static bool IsUacStrict() => RegistryHelper.GetUacStrictness();

    public static void SetUacStrict(bool strict) => RegistryHelper.SetUacStrictness(strict);

    // ── Hosts file ──

    public sealed record HostsAudit(bool Exists, int ActiveRules, bool Suspicious, string Content);

    /// <summary>Read-only audit: counts active redirect lines and flags any
    /// that do not point at loopback (the shape of a hijack).</summary>
    public static HostsAudit AuditHostsFile()
    {
        try
        {
            if (!File.Exists(HostsFilePath))
                return new HostsAudit(false, 0, false, "");

            string content = File.ReadAllText(HostsFilePath);
            int activeRules = 0;
            bool suspicious = false;
            foreach (var line in File.ReadAllLines(HostsFilePath))
            {
                var t = line.Trim();
                if (string.IsNullOrWhiteSpace(t) || t.StartsWith("#")) continue;
                activeRules++;
                // 0.0.0.0 counts as loopback-equivalent: both this app and
                // AutoCommand's Black Hole pin telemetry domains to 0.0.0.0
                // (comment markers above those lines are skipped already, but
                // the pin lines themselves are not), and treating that shape
                // as "the shape of a hijack" flagged the app's own blocks.
                if (!t.Contains("localhost") && !t.Contains("127.0.0.1") && !t.Contains("::1") && !t.Contains("0.0.0.0"))
                    suspicious = true;
            }
            return new HostsAudit(true, activeRules, suspicious, content);
        }
        catch
        {
            return new HostsAudit(false, 0, false, "");
        }
    }

    /// <summary>IRREVERSIBLE: overwrites the hosts file with the Windows
    /// default. All custom entries — pins included — are lost. The caller
    /// confirms and must mean it.</summary>
    public static void ResetHostsFile()
    {
        string defaultContent = @"# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# 127.0.0.1       localhost
# ::1             localhost
";
        File.WriteAllText(HostsFilePath, defaultContent);
    }
}
