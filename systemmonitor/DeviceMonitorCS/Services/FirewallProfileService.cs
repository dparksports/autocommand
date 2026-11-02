using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace DeviceMonitorCS.Services
{
    public class FirewallProfileService
    {
        private static FirewallProfileService _instance;
        public static FirewallProfileService Instance => _instance ?? (_instance = new FirewallProfileService());

        public enum ProfileType
        {
            Custom,
            StrictPublic,
            HomeTrusted,
            GamingMedia,
            ShieldUp
        }

        public async Task ApplyProfile(ProfileType profile)
        {
            switch (profile)
            {
                case ProfileType.StrictPublic:
                    await DisableGroup("File and Printer Sharing");
                    await DisableGroup("Network Discovery");
                    await DisableGroup("Remote Desktop");
                    break;
                case ProfileType.HomeTrusted:
                    await EnableGroup("File and Printer Sharing");
                    await EnableGroup("Network Discovery");
                    break;
                case ProfileType.GamingMedia:
                    await EnableGroup("Network Discovery");
                    await EnableGroup("Cast to Device");
                    break;
                case ProfileType.ShieldUp:
                    await ApplyShieldUp();
                    break;
            }
        }

        private async Task ApplyShieldUp()
        {
            // Block ALL groups except whitelisted ones
            // OPTIMIZED: Use Bulk Pipeline operations instead of iterating thousands of rules in a loop
            // This prevents the 30-60s execution time that freezes/hangs the system
            string script = @"
$ErrorActionPreference = 'SilentlyContinue';
# 1. Bulk Disable ALL rules with a DisplayGroup
Get-NetFirewallRule | Where-Object { $_.DisplayGroup -ne $null } | Set-NetFirewallRule -Enabled False;

# 2. Re-enable Whitelisted Groups
Get-NetFirewallRule -DisplayGroup 'mDNS' | Set-NetFirewallRule -Enabled True;
Get-NetFirewallRule -DisplayGroup 'Core Networking' | Set-NetFirewallRule -Enabled True;
";
            await RunPowershellAsync(script);
        }

        private async Task EnableGroup(string group)
        {
            await RunPowershellAsync($"Set-NetFirewallRule -DisplayGroup '{group}' -Enabled True");
        }

        private async Task DisableGroup(string group)
        {
            await RunPowershellAsync($"Set-NetFirewallRule -DisplayGroup '{group}' -Enabled False");
        }

        public Task<string> RunPowershellPublicAsync(string script)
        {
            return Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-Command \"{script}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };
                    var p = Process.Start(psi);
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    return output;
                }
                catch { return ""; }
            });
        }

        private Task<string> RunPowershellAsync(string script) => RunPowershellPublicAsync(script);
    }
}
