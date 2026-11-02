using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Linq;

namespace DeviceMonitorCS.Helpers
{
    public class FirewallConfigManager
    {
        private static FirewallConfigManager _instance;
        public static FirewallConfigManager Instance => _instance ??= new FirewallConfigManager();

        private string _configPath;
        
        // Key: Rule Name (InstanceID ideally, unlikely to change). Value: "True" (Enabled) or "False" (Disabled)
        public Dictionary<string, string> RuleOverrides { get; set; } = new Dictionary<string, string>();

        public FirewallConfigManager()
        {
            _configPath = Path.Combine(@"C:\ProgramData\Auto-Command", "firewall_config.json");
            Load();
        }

        public void Load()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    string json = File.ReadAllText(_configPath);
                    var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (data != null)
                    {
                        RuleOverrides = data;
                    }
                }
            }
            catch { }
        }

        public void Save()
        {
            try
            {
                var dir = Path.GetDirectoryName(_configPath);
                if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

                string json = JsonSerializer.Serialize(RuleOverrides, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_configPath, json);
            }
            catch { }
        }

        public void SetOverride(string ruleName, string enabledState)
        {
            // Normalize state to "True"/"False"
            string state = (enabledState == "Yes" || enabledState == "True" || enabledState == "1") ? "True" : "False";
            
            if (RuleOverrides.ContainsKey(ruleName))
            {
                RuleOverrides[ruleName] = state;
            }
            else
            {
                RuleOverrides.Add(ruleName, state);
            }
            Save();
        }

        public string GetOverride(string ruleName)
        {
            if (RuleOverrides.TryGetValue(ruleName, out string val)) return val;
            return null;
        }
    }
}
