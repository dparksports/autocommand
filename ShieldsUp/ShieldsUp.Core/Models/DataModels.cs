namespace ShieldsUp.Core.Models
{
    public class NetworkAdapterItem
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Status { get; set; }
        public string MacAddress { get; set; }
        public string InterfaceType { get; set; }
        public string DeviceID { get; set; }
    }

    public class StartupItem
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Location { get; set; }
        public string TargetPath { get; set; }
    }

    public class AppPackageItem
    {
        public string Name { get; set; }

        /// <summary>Exact Appx package name (e.g. Microsoft.Todos) — identity used
        /// for user-added custom bloatware entries, unlike the display Name.</summary>
        public string PackageName { get; set; }
        public string FullName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string InstallLocation { get; set; }
        public string SignatureStatus { get; set; }
        public string SignerCertificate { get; set; }
        public bool IsSystem { get; set; }
    }

    // FirewallRuleItem now lives in the shared engine: the app-wide using
    // alias maps it to AutoCommand.Engines.Firewall.RuleInfo, which carries
    // the same fields and the same INotifyPropertyChanged enable-toggle
    // behavior this local copy implemented.
}
