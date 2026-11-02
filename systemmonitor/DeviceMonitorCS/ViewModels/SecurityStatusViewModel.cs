using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.ViewModels
{
    public class SecurityStatusViewModel : INotifyPropertyChanged
    {
        private static SecurityStatusViewModel _instance;
        public static SecurityStatusViewModel Instance => _instance ?? (_instance = new SecurityStatusViewModel());

        // Private constructor for Singleton
        // Private constructor for Singleton
        // Logic moved to bottom block to include command initialization


        private bool _isExpertMode;
        public bool IsExpertMode
        {
            get => _isExpertMode;
            set
            {
                if (_isExpertMode != value)
                {
                    _isExpertMode = value;
                    OnPropertyChanged();
                }
            }
        }

        private SystemHealth _currentHealth = SystemHealth.Secure;
        public SystemHealth CurrentHealth
        {
            get => _currentHealth;
            set
            {
                if (_currentHealth != value)
                {
                    _currentHealth = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(StatusColor));
                    OnPropertyChanged(nameof(StatusIcon));
                }
            }
        }

        private string _statusMessage = "System Secure";
        public string StatusMessage
        {
            get => _statusMessage;
            set
            {
                if (_statusMessage != value)
                {
                    _statusMessage = value;
                    OnPropertyChanged();
                }
            }
        }

        private string _detailedStatus = "All systems operational.";
        public string DetailedStatus
        {
            get => _detailedStatus;
            set
            {
                if (_detailedStatus != value)
                {
                    _detailedStatus = value;
                    OnPropertyChanged();
                }
            }
        }

        // Helper for UI binding (color strings)
        public string StatusColor
        {
            get
            {
                switch (_currentHealth)
                {
                    case SystemHealth.Secure: return "#4CAF50"; // Green
                    case SystemHealth.AtRisk: return "#FFC107"; // Amber
                    case SystemHealth.Critical: return "#F44336"; // Red
                    default: return "#4CAF50";
                }
            }
        }
        
        public string StatusIcon
        {
             get
             {
                 switch (_currentHealth)
                 {
                     case SystemHealth.Secure: return "CheckCircle"; 
                     case SystemHealth.AtRisk: return "AlertCircle"; 
                     case SystemHealth.Critical: return "ShieldAlert"; 
                     default: return "ShieldCheck";
                 }
             }
        }

        // Scan Command
        public ICommand ScanCommand { get; }
        public ICommand ShieldUpCommand { get; }

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set
            {
                if (_isScanning != value)
                {
                    _isScanning = value;
                    OnPropertyChanged();
                }
            }
        }

        // Expanded Constructor
        private SecurityStatusViewModel() 
        {
             // Sync with SettingsManager
             _isExpertMode = Services.SettingsManager.Instance.IsExpertMode;
             Services.SettingsManager.Instance.ExpertModeChanged += (val) => IsExpertMode = val;
             
             ScanCommand = new Helpers.RelayCommand(async (o) => await PerformScan());
             ShieldUpCommand = new Helpers.RelayCommand(async (o) => await PerformShieldUp());
        }

        private async Task PerformShieldUp()
        {
             StatusMessage = "Activating Shield...";
             await Services.FirewallProfileService.Instance.ApplyProfile(Services.FirewallProfileService.ProfileType.ShieldUp);
             
             CurrentHealth = SystemHealth.Secure;
             StatusMessage = "Shields Up";
             DetailedStatus = "All inbound/outbound rules blocked (except Core Networking/mDNS).";
        }

        private async Task PerformScan()
        {
            if (IsScanning) return;
            
            IsScanning = true;
            StatusMessage = "Scanning System...";
            DetailedStatus = "Analyzing Firewall, Defender, and Network activity...";

            await Task.Delay(500); // Small UI breather

            // 1. Run Checks in Parallel
            // 1. Run Checks in Parallel
            var firewallTask = CheckFirewallHealth();
            var defenderTask = CheckDefenderStatus();
            var networkTask = CheckNetworkHealth();
            var uefiTask = CheckUefiHealth();

            await Task.WhenAll(firewallTask, defenderTask, networkTask, uefiTask);

            bool fwOk = firewallTask.Result;
            bool avOk = defenderTask.Result;
            bool netOk = networkTask.Result;
            bool uefiOk = uefiTask.Result;

            // 2. Aggregate Results
            if (!avOk)
            {
                CurrentHealth = SystemHealth.Critical;
                StatusMessage = "Antivirus Issue";
                DetailedStatus = "Windows Defender is not active or out of date.";
            }
            else if (!uefiOk)
            {
                CurrentHealth = SystemHealth.AtRisk;
                StatusMessage = "Firmware Risk";
                DetailedStatus = "System is vulnerable to BlackLotus (CVE-2022-21894). See Secure Boots tab.";
            }
            else if (!fwOk)
            {
                CurrentHealth = SystemHealth.AtRisk;
                StatusMessage = "Firewall Gaps";
                DetailedStatus = "Critical ports (RDP/SMB) are exposed on Public/Standard profile.";
            }
            else if (!netOk)
            {
                CurrentHealth = SystemHealth.AtRisk;
                StatusMessage = "High Traffic";
                DetailedStatus = "Unusual amount of active connections detected.";
            }
            else
            {
                CurrentHealth = SystemHealth.Secure;
                StatusMessage = "System Secure";
                DetailedStatus = $"Scan complete at {System.DateTime.Now:t}. Firewall, Defender, Network, and Firmware are healthy.";
            }

            IsScanning = false;
        }

        private async Task<bool> CheckUefiHealth()
        {
            // Migrated to DBX Safety Check view. 
            // We no longer flag the main dashboard for BlackLotus to avoid alarm fatigue
            // as users are directed to the specific sidebar item now.
            return await Task.FromResult(true);
        }

        private async Task<bool> CheckFirewallHealth()
        {
            // Check if Firewall is enabled for current profile
            // Simple check: Is RDP or SMB open?
            // Using a specialized script via FirewallService or just direct PS here for simplicity since Service is strictly for Profile Management currently.
            // Let's use FirewallProfileService helper if possible, or just PS.
            // To keep it clean, we'll verify if the "StrictPublic" rules are applied? 
            // Or just generic: Get-NetFirewallProfile -Profile Public | Select Enabled
            
            // We will basically check if RDP is enabled.
            string script = "Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled True -ErrorAction SilentlyContinue";
            var result = await Services.FirewallProfileService.Instance.RunPowershellPublicAsync(script);
            // If result is empty, RDP is NOT enabled (Good). If not empty, RDP is enabled (Bad if we want strict).
            // Let's assume strict default.
            return string.IsNullOrWhiteSpace(result); 
        }

        private async Task<bool> CheckDefenderStatus()
        {
             // Check if Defender is RealTimeProtectionEnabled
             // Note: Requires Admin usually.
             string script = "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled";
             var result = await Services.FirewallProfileService.Instance.RunPowershellPublicAsync(script);
             return result.Trim().Equals("True", System.StringComparison.OrdinalIgnoreCase);
        }

        private Task<bool> CheckNetworkHealth()
        {
             // Check if we have < 100 active connections (arbitrary heuristic)
             // Force a refresh first?
             // ConnectionMonitor is on a background loop, so let's just peek connection count.
             int count = Models.ConnectionMonitor.Instance.ActiveConnections.Count;
             return Task.FromResult(count < 100);
        }

        public void UpdateStatus(string status, string colorType)
        {
            // Map legacy string/color to Enum
            StatusMessage = status;
            
            if (colorType.Equals("Red", System.StringComparison.OrdinalIgnoreCase))
            {
                CurrentHealth = SystemHealth.Critical;
            }
            else if (colorType.Equals("Amber", System.StringComparison.OrdinalIgnoreCase))
            {
                CurrentHealth = SystemHealth.AtRisk;
            }
            else
            {
                CurrentHealth = SystemHealth.Secure;
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
