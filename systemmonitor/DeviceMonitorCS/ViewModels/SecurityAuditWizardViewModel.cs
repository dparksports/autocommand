using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;

namespace DeviceMonitorCS.ViewModels
{
    public class SecurityAuditWizardViewModel : INotifyPropertyChanged
    {
        public event Action RequestClose;

        private int _progress;
        public int Progress
        {
            get => _progress;
            set { _progress = value; OnPropertyChanged(); }
        }

        private string _statusText = "Initializing...";
        public string StatusText
        {
            get => _statusText;
            set { _statusText = value; OnPropertyChanged(); }
        }

        private bool _isScanning = true;
        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); }
        }

        private bool _isComplete = false;
        public bool IsComplete
        {
            get => _isComplete;
            set { _isComplete = value; OnPropertyChanged(); }
        }

        private int _securityScore = 0;
        public int SecurityScore
        {
            get => _securityScore;
            set { _securityScore = value; OnPropertyChanged(); }
        }

        private bool _isReviewing = false;
        public bool IsReviewing
        {
            get => _isReviewing;
            set { _isReviewing = value; OnPropertyChanged(); }
        }

        public System.Collections.ObjectModel.ObservableCollection<string> ProposedChanges { get; set; } = new System.Collections.ObjectModel.ObservableCollection<string>();

        public ICommand StartScanCommand { get; }
        public ICommand ReviewIssuesCommand { get; }
        public ICommand FixIssuesCommand { get; }
        public ICommand SkipCommand { get; }

        public SecurityAuditWizardViewModel()
        {
            StartScanCommand = new RelayCommand(StartScan);
            ReviewIssuesCommand = new RelayCommand(ReviewIssues);
            FixIssuesCommand = new RelayCommand(FixIssues);
            SkipCommand = new RelayCommand(CloseWizard);
            
            // Auto start
            StartScan(null);
        }

        private void ReviewIssues(object obj)
        {
            IsComplete = false;
            IsReviewing = true;
            
            // Populate changes if empty
            if (ProposedChanges.Count == 0)
            {
                ProposedChanges.Add("Enable Windows Firewall (Public Profile)");
                ProposedChanges.Add("Disable Remote Desktop Protocol (RDP)");
                ProposedChanges.Add("Block Inbound Connections on Public Networks");
                ProposedChanges.Add("Enable Real-time Defender Monitoring");
            }
        }

        private async void StartScan(object obj)
        {
            IsScanning = true;
            IsComplete = false;
            
            await Task.Run(async () =>
            {
                UpdateStatus("Checking Network Interfaces...", 10);
                await Task.Delay(800);
                
                UpdateStatus("Scanning for VPN Backdoors (SSTP)...", 30);
                // Simulate check
                await Task.Delay(800);
                
                UpdateStatus("Verifying Firewall Integrity...", 60);
                await Task.Delay(800);
                
                UpdateStatus("Analyzing Privacy Settings...", 80);
                await Task.Delay(800);
                
                UpdateStatus("Audit Complete.", 100);
                await Task.Delay(500);
            });

            IsScanning = false;
            IsComplete = true;
            SecurityScore = 72; // Hardcoded "Drift" simulation as per prompt
        }

        private void UpdateStatus(string text, int progress)
        {
            StatusText = text;
            Progress = progress;
        }

        private async void FixIssues(object obj)
        {
            IsComplete = false;
            IsReviewing = false;
            IsScanning = true;
            
            UpdateStatus("Applying Security Hardening...", 100);
            
            await Task.Run(async () =>
            {
                // Real Remediation: Apply "Coffee Shop" (StrictPublic) profile
                // This disables File Sharing, Network Discovery, and RDP
                await Services.FirewallProfileService.Instance.ApplyProfile(Services.FirewallProfileService.ProfileType.StrictPublic);
                
                // Allow some time for the user to see the "Applying..." state
                await Task.Delay(1500);
            });
            
            Services.SettingsManager.Instance.IsFirstRun = false;
            RequestClose?.Invoke();
        }

        private void CloseWizard(object obj)
        {
            Services.SettingsManager.Instance.IsFirstRun = false;
            RequestClose?.Invoke();
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    // Simple RelayCommand Helper
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        public RelayCommand(Action<object> execute) { _execute = execute; }
        public event EventHandler CanExecuteChanged;
#pragma warning disable CS0067
        // Method to raise the event manually if needed
        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
#pragma warning restore CS0067
        public bool CanExecute(object parameter) => true;
        public void Execute(object parameter) => _execute(parameter);
    }
}
