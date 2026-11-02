using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Windows;
using System.Collections.Generic;

namespace DeviceMonitorCS
{
    public class SecurityEnforcer
    {
        private bool _isRunning;
        private readonly Action<string, string> _onThreatDetected; // type, details
        public event Action<string, string> StatusChanged; // status, colorType (Green, Red, Amber)

        public SecurityEnforcer(Action<string, string> onThreatDetected)
        {
            _onThreatDetected = onThreatDetected;
        }

        private static volatile bool _isSstpAllowed = false;
        public static bool IsSstpAllowed 
        { 
            get => _isSstpAllowed; 
            set => _isSstpAllowed = value; 
        }

        public void Start()
        {
            if (_isRunning) return;
            _isRunning = true;
            Task.Run(RunLoop);
        }

        public void Stop()
        {
            _isRunning = false;
        }

        public int CheckInterval { get; set; } = 2000;

        private int _loopCount = 0;

        public event Action<List<string>> ConfigurationDriftDetected;

        private async Task RunLoop()
        {
            while (_isRunning)
            {
                try
                {
                    CheckHostedNetwork();
                    CheckWanMiniports();
                    CheckPrivilegedTasks();
                    
                    if (_loopCount % 15 == 0) // Every 30 seconds (approx)
                    {
                         await MonitorFirewallDrift();
                    }
                    _loopCount++;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Enforcer Error: {ex.Message}");
                }

                await Task.Delay(CheckInterval); 
            }
        }

        public void ForceApplyFirewallRules()
        {
            try
            {
                var overrides = DeviceMonitorCS.Helpers.FirewallConfigManager.Instance.RuleOverrides;
                if (overrides.Count == 0) return;

                var toEnable = overrides.Where(x => x.Value == "True").Select(x => x.Key).ToList();
                var toDisable = overrides.Where(x => x.Value == "False").Select(x => x.Key).ToList();

                if (toEnable.Count > 0)
                {
                    string names = string.Join("','", toEnable);
                    RunCommand("powershell", $"-Command \"Set-NetFirewallRule -Name '{names}' -Enabled True -ErrorAction SilentlyContinue\"");
                }

                if (toDisable.Count > 0)
                {
                    string names = string.Join("','", toDisable);
                    RunCommand("powershell", $"-Command \"Set-NetFirewallRule -Name '{names}' -Enabled False -ErrorAction SilentlyContinue\"");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Firewall Enforcer Error: {ex.Message}");
            }
        }

        private async Task MonitorFirewallDrift()
        {
            try
            {
                var overrides = DeviceMonitorCS.Helpers.FirewallConfigManager.Instance.RuleOverrides;
                if (overrides.Count == 0) return;

                var driftItems = new List<string>();

                // Build a script to check status efficiently
                var checkScript = "$drift = @(); ";
                
                foreach (var kvp in overrides)
                {
                    string expected = kvp.Value; // "True" or "False"
                    string desc = expected == "True" ? "Should be Enabled" : "Should be Disabled";
                    
                    // Robust check: Get rule, normalize Enabled state to "True"/"False", compare with expected
                    checkScript += $"$r = Get-NetFirewallRule -Name '{kvp.Key}' -ErrorAction SilentlyContinue; ";
                    checkScript += $"if ($r) {{ ";
                    checkScript += $"  $actual = if ($r.Enabled -eq 1 -or $r.Enabled -eq 'True') {{ 'True' }} else {{ 'False' }}; ";
                    checkScript += $"  if ($actual -ne '{expected}') {{ $drift += '{kvp.Key} ({desc})' }}; ";
                    checkScript += $"}}; ";
                }
                
                checkScript += "$drift";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{checkScript}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                await Task.Run(() =>
                {
                    using (var p = Process.Start(psi))
                    {
                        if (p != null)
                        {
                            string output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit();
                            
                            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            if (lines.Length > 0)
                            {
                                driftItems.AddRange(lines);
                            }
                        }
                    }
                });

                if (driftItems.Count > 0)
                {
                    ConfigurationDriftDetected?.Invoke(driftItems);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Drift Check Error: {ex.Message}");
            }
        }

        private void CheckHostedNetwork()
        {
            // Check if Hosted Network is active
            // We can check via WMI or netsh. Netsh is reliable for "Started" status.
            // Using WMI Win32_NetworkAdapter where Name like 'Microsoft Hosted Network Virtual Adapter'
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE '%Hosted Network Virtual Adapter%' AND NetConnectionStatus = 2");
                if (searcher.Get().Count > 0)
                {
                    // It is connected/active. KILL IT.
                    RunCommand("netsh", "wlan stop hostednetwork");
                    RunCommand("netsh", "wlan set hostednetwork mode=disallow");
                    
                    _onThreatDetected?.Invoke("Hosted Network", "Active Hosted Network detected and disabled.");
                    StatusChanged?.Invoke("Threat Blocked: Hosted Network", "Red");
                }
            }
            catch {}
        }

        private void CheckWanMiniports()
        {
            // Check for WAN Miniport (SSTP) presence
            // User requirement: If it shows up, Stop Svc -> Disable Svc -> Disable Adapter -> Uninstall Adapter -> Alert.
            try
            {
                // We check if the adapter exists at all.
                bool exists = false;
                try 
                {
                    var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE '%WAN Miniport (SSTP)%'");
                    if (searcher.Get().Count > 0) exists = true;
                }
                catch {}

                if (exists)
                {
                    // Check Whitelist
                    if (IsSstpAllowed)
                    {
                        Services.InspectionService.Instance.Log("AGENCY PROTOCOL: SSTP DETECTED (USER WHITELISTED). TAKEDOWN BYPASSED.");
                        // Allow it to run
                        return;
                    }

                    Debug.WriteLine("SecurityEnforcer: WAN Miniport (SSTP) detected. Initiating takedown...");
                    Services.InspectionService.Instance.Log("AGENCY PROTOCOL: UNAUTHORIZED SSTP DEVICE DETECTED.");
                    Services.InspectionService.Instance.Log("ACTION: INITIATING IMMEDIATE TAKEDOWN.");

                    // 1. Stop SstpSvc
                    RunCommand("powershell", "Stop-Service -Name SstpSvc -Force -ErrorAction SilentlyContinue");

                    // 2. Disable SstpSvc
                    RunCommand("powershell", "Set-Service -Name SstpSvc -StartupType Disabled -ErrorAction SilentlyContinue");

                    // 3. Disable Adapter (Robust)
                    RunCommand("powershell", "Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like '*WAN Miniport (SSTP)*' } | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue");

                    // 4. Uninstall Adapter (Robust Lookup)
                    string deviceId = null;
                    
                    // Strategy 1: Win32_NetworkAdapter
                    try
                    {
                        var searcher = new ManagementObjectSearcher("SELECT PNPDeviceID FROM Win32_NetworkAdapter WHERE Name LIKE '%WAN Miniport (SSTP)%'");
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            deviceId = obj["PNPDeviceID"]?.ToString();
                            if (!string.IsNullOrEmpty(deviceId)) break;
                        }
                    }
                    catch { }

                    // Strategy 2: Win32_PnPEntity
                    if (string.IsNullOrEmpty(deviceId))
                    {
                        try
                        {
                            var searcher = new ManagementObjectSearcher("SELECT DeviceID FROM Win32_PnPEntity WHERE Name LIKE '%WAN Miniport%SSTP%'");
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                deviceId = obj["DeviceID"]?.ToString();
                                if (!string.IsNullOrEmpty(deviceId)) break;
                            }
                        }
                        catch { }
                    }

                    // Strategy 3: PowerShell Fallback
                    if (string.IsNullOrEmpty(deviceId))
                    {
                         try
                         {
                             var ps = new ProcessStartInfo
                             {
                                 FileName = "powershell.exe",
                                 Arguments = "-Command \"Get-PnpDevice -FriendlyName '*WAN Miniport (SSTP)*' | Select-Object -ExpandProperty InstanceId\"",
                                 RedirectStandardOutput = true,
                                 UseShellExecute = false,
                                 CreateNoWindow = true
                             };
                             using (var p = Process.Start(ps))
                             {
                                 string output = p.StandardOutput.ReadToEnd();
                                 p.WaitForExit();
                                 if (!string.IsNullOrWhiteSpace(output))
                                 {
                                     deviceId = output.Trim().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                                 }
                             }
                         }
                         catch {}
                    }

                    if (!string.IsNullOrEmpty(deviceId))
                    {
                         RunCommand("pnputil.exe", $"/remove-device \"{deviceId}\"");
                         Debug.WriteLine($"SecurityEnforcer: Removed device {deviceId}");
                    }

                    // 5. Alert & Explain (Only if we actually took action)
                    _onThreatDetected?.Invoke("WAN Miniport (SSTP)", "Active SSTP Adapter detected. Service stopped, disabled, and device uninstalled.");
                    StatusChanged?.Invoke("Threat Blocked: SSTP", "Red");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"CheckWanMiniports Error: {ex.Message}");
            }
        }

        private void CheckPrivilegedTasks()
        {
            // Scan for tasks running with highest privileges
            // We use schtasks /query /v /fo csv and parse for "Highest Availability" or "System"
            // Start simple: just simple check for now.
            // WARNING: Parsing CSV output of schtasks is brittle locally. 
            // We will rely on a separate helper or simplified logic for the MVP.
            // For now, let's just look for tasks we KNOW are bad or just report 'High Risk' count.
            // Actually, let's run the command and just look for lines containing "Highest"
            
            try
            {
                 var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/query /v /fo csv",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                
                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    
                    var lines = output.Split('\n');
                    foreach(var line in lines)
                    {
                         if(line.Contains("Highest Available") && !line.Contains("Microsoft")) // Filter out MS tasks initially to reduce noise
                         {
                             // Found a non-MS high privilege task.
                             var parts = line.Split(',');
                             if(parts.Length > 1) {
                                  string taskName = parts[0].Trim('"');
                                  // Auto-Disable logic would go here:
                                  // RunCommand("schtasks", $"/Change /TN \"{taskName}\" /DISABLE");
                                  _onThreatDetected?.Invoke("Privileged Task", $"High Risk Task detected: {taskName}");
                                  StatusChanged?.Invoke("Warning: Privileged Task", "Amber");
                             }
                         }
                    }
                }
            }
            catch {}
        }

        private void RunCommand(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi)?.WaitForExit();
            }
            catch { }
        }
    }
}
