using System.Management;
using System.ServiceProcess;
using ShieldsUp.Core.Helpers;
using ShieldsUp.Core.Models;

namespace ShieldsUp.Core.Services;

/// <summary>
/// The "doors Windows leaves open" checks and closing actions, extracted
/// from Shields Up's WinUI AttackSurfacePage so any face (WinUI shell, WPF
/// tab, self-test) drives the same logic. Pure state reads and system
/// actions — no UI types, no confirmations: the caller confirms first,
/// then calls.
/// </summary>
public static class AttackSurfaceService
{
    public const string SstpServiceName = "SstpSvc";

    public sealed record SstpStatus(bool Active, string StatusText, string StartMode);

    // ── SSTP / VPN miniports ──

    public static SstpStatus GetSstpStatus()
    {
        try
        {
            using var sc = new ServiceController(SstpServiceName);
            string status = sc.Status.ToString();
            string startMode = ServiceHelper.GetStartMode(SstpServiceName);
            bool active = sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;
            return new SstpStatus(active, status, startMode);
        }
        catch
        {
            return new SstpStatus(false, "NotFound", "");
        }
    }

    /// <summary>Stop + disable SstpSvc and disable the SSTP-family VPN miniport
    /// adapters (SSTP, IKEv2, L2TP, PPTP, AgileVPN, NDISWAN). Disabling — not
    /// removing — keeps this reversible. Returns the adapters that could not
    /// be disabled (empty = clean).</summary>
    public static List<string> DisableSstp()
    {
        ServiceHelper.StopAndDisable(SstpServiceName);
        return WanMiniportRemover.SetSstpMiniportsEnabled(false);
    }

    /// <summary>Re-enable the SSTP-family miniports, then enable + start SstpSvc.
    /// Returns the adapters that could not be re-enabled (empty = clean).</summary>
    public static List<string> EnableSstp()
    {
        var failures = WanMiniportRemover.SetSstpMiniportsEnabled(true);
        ServiceHelper.EnableAndStart(SstpServiceName);
        return failures;
    }

    // ── Wi-Fi Direct ghost hotspot ──

    public static string GetHostedNetworkStatus()
    {
        string output = ProcessRunner.Run("netsh", "wlan show hostednetwork");
        if (output.Contains("Not available")) return "Not Available";
        if (output.Contains("Not started")) return "Not Started";
        if (output.Contains("Started")) return "Started";
        return "Unknown";
    }

    /// <summary>Stop the hosted network and disallow it, so the ghost hotspot
    /// cannot be spun back up behind the firewall.</summary>
    public static void DisallowHostedNetwork()
    {
        ProcessRunner.Run("netsh", "wlan stop hostednetwork");
        ProcessRunner.Run("netsh", "wlan set hostednetwork mode=disallow");
    }

    public static void AllowHostedNetwork()
    {
        ProcessRunner.Run("netsh", "wlan set hostednetwork mode=allow");
    }

    // ── Kernel debug (KDNET) ──

    public static bool IsKernelDebugOn()
    {
        string output = ProcessRunner.Run("bcdedit", "/enum {current}");
        // Anchored on the value name: the old substring test
        // ("contains 'debug' and 'Yes'") matched `recoveryenabled Yes` plus
        // `debug No`/`hypervisordebug Off` — a permanent false positive.
        if (string.IsNullOrEmpty(output)) return false;
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.Trim();
            if (!line.StartsWith("debug", StringComparison.OrdinalIgnoreCase))
                continue;
            string value = line["debug".Length..].Trim();
            if (value.StartsWith("yes", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("true", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("on", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>Turning debug ON is the risky direction — the caller confirms
    /// before asking for it.</summary>
    public static void SetKernelDebug(bool on)
    {
        ProcessRunner.Run("bcdedit", on ? "/debug on" : "/debug off");
    }

    // ── Adapter inventory ──

    public static List<NetworkAdapterItem> ListWanMiniports() =>
        ListAdapters("Name LIKE '%WAN Miniport%'");

    public static List<NetworkAdapterItem> ListWifiDirectAdapters() =>
        ListAdapters("Name LIKE '%Wi-Fi Direct%' OR Name LIKE '%Microsoft Wi-Fi Direct Virtual Adapter%'");

    public static List<NetworkAdapterItem> ListKdnetAdapters() =>
        ListAdapters("Name LIKE '%Kernel Debug%' OR Name LIKE '%KDNIC%'");

    private static List<NetworkAdapterItem> ListAdapters(string where)
    {
        var adapters = new List<NetworkAdapterItem>();
        try
        {
            var searcher = new ManagementObjectSearcher(
                $"SELECT Name, NetConnectionStatus FROM Win32_NetworkAdapter WHERE {where}");
            foreach (ManagementObject obj in searcher.Get())
            {
                adapters.Add(new NetworkAdapterItem
                {
                    Name = obj["Name"]?.ToString() ?? "",
                    Status = DecodeNetStatus(obj["NetConnectionStatus"])
                });
            }
        }
        catch { }
        return adapters;
    }

    // ── Removals (DIF_REMOVE — reversible only by driver re-enumeration) ──

    public static List<string> RemoveWifiDirectAdapters() => WanMiniportRemover.RemoveWifiDirect();

    public static List<string> RemoveAllWanMiniports() => WanMiniportRemover.Execute();

    public static string DecodeNetStatus(object status)
    {
        if (status == null) return "N/A";
        return ((int)(ushort)status) switch
        {
            0 => "Disconnected",
            1 => "Connecting",
            2 => "Connected",
            3 => "Disconnecting",
            4 => "Hardware not present",
            5 => "Hardware disabled",
            6 => "Hardware malfunction",
            7 => "Media disconnected",
            _ => status.ToString()
        };
    }
}
