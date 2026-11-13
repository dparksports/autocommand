using System.Management;
using System.ServiceProcess;
using ShieldsUp.Core.Helpers;

namespace ShieldsUp.Core.Services;

/// <summary>
/// Privacy-surface checks and actions, extracted from Shields Up's WinUI
/// PrivacyPage: the Windows VPN service family, Wi-Fi Direct adapters,
/// the UsageDataReceiver telemetry task and Defender Tamper Protection.
/// No UI types, no confirmations — the caller confirms first, then calls.
/// </summary>
public static class PrivacyService
{
    public static readonly string[] VpnServices = { "RasMan", "IKEEXT", "PolicyAgent", "RemoteAccess" };

    public const string UsageDataTaskPath = @"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver";

    // ── VPN services ──

    public static (int Running, int Total) GetVpnStatus()
    {
        int running = 0;
        foreach (var svcName in VpnServices)
        {
            try
            {
                using var sc = new ServiceController(svcName);
                if (sc.Status == ServiceControllerStatus.Running) running++;
            }
            catch { } // not installed — counts as stopped
        }
        return (running, VpnServices.Length);
    }

    /// <summary>Stop + disable the whole VPN service family. Any VPN connection
    /// the user relies on drops until re-enable — the caller confirms first.</summary>
    public static void DisableVpnServices()
    {
        foreach (var svc in VpnServices)
            ServiceHelper.StopAndDisable(svc);
    }

    public static void EnableVpnServices()
    {
        foreach (var svc in VpnServices)
            ServiceHelper.EnableAndStart(svc);
    }

    // ── Wi-Fi Direct adapters ──

    public static bool IsWifiDirectAdapterPresent()
    {
        try
        {
            var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE '%Wi-Fi Direct%'");
            return searcher.Get().Count > 0;
        }
        catch { return false; }
    }

    /// <summary>Enable/disable every Wi-Fi Direct virtual adapter by PNP id via
    /// pnputil (reversible — the devices stay installed). Returns how many
    /// devices were acted on.</summary>
    public static int SetWifiDirectAdaptersEnabled(bool enabled)
    {
        int acted = 0;
        try
        {
            var searcher = new ManagementObjectSearcher(
                "SELECT PNPDeviceID FROM Win32_NetworkAdapter WHERE Name LIKE '%Wi-Fi Direct%'");
            foreach (ManagementObject obj in searcher.Get())
            {
                string deviceId = obj["PNPDeviceID"]?.ToString();
                if (!string.IsNullOrEmpty(deviceId))
                {
                    ProcessRunner.Run("pnputil.exe", $"/{(enabled ? "enable" : "disable")}-device \"{deviceId}\"");
                    acted++;
                }
            }
        }
        catch { }
        return acted;
    }

    // ── Usage data / telemetry task ──

    public static bool IsUsageDataTaskEnabled() =>
        TaskSchedulerService.Instance.IsTaskEnabled(UsageDataTaskPath);

    public static System.Threading.Tasks.Task SetUsageDataTaskEnabledAsync(bool enabled) =>
        TaskSchedulerService.Instance.SetTaskEnabledAsync(UsageDataTaskPath, enabled);

    // ── Defender Tamper Protection (read-only; enable happens in Windows Security) ──

    public static bool IsTamperProtectionOn()
    {
        try
        {
            // WMI, not registry: the registry value is protected
            var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT IsTamperProtected FROM MSFT_MpComputerStatus");
            foreach (ManagementObject obj in searcher.Get())
            {
                if (obj["IsTamperProtected"] != null && (bool)obj["IsTamperProtected"])
                    return true;
            }
        }
        catch { }
        return false;
    }
}
