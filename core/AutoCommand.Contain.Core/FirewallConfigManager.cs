using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using AutoCommand.Helpers;
using AutoCommand.NetWatch.Core;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// Persists firewall rule override state to JSON with reload-merge-write
    /// semantics and live singleton coherence across the host app and vendored
    /// Shields Up surfaces.
    /// </summary>
    public class FirewallConfigManager
    {
        public static string DefaultConfigPath { get; set; } =
            Path.Combine(ProgramDataGuard.Root, "firewall_config.json");

        private static FirewallConfigManager _instance;
        public static FirewallConfigManager Instance => _instance ??= new FirewallConfigManager();

        private readonly string _explicitPath;
        private string ConfigPath => _explicitPath ?? DefaultConfigPath;

        public Dictionary<string, string> RuleOverrides { get; set; } = new Dictionary<string, string>();

        public FirewallConfigManager(string configPath = null)
        {
            _explicitPath = configPath;
            Load();
        }

        public void Load()
        {
            try
            {
                string path = ConfigPath;
                if (File.Exists(path))
                {
                    string json = File.ReadAllText(path);
                    var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    RuleOverrides = data ?? new Dictionary<string, string>();
                }
                else
                {
                    RuleOverrides = new Dictionary<string, string>();
                }
            }
            catch { }
        }

        public void Save()
        {
            try
            {
                string path = ConfigPath;
                var dir = Path.GetDirectoryName(path);
                if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string json = JsonSerializer.Serialize(RuleOverrides, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch { }
        }

        public void SetOverride(string ruleName, bool enabled)
        {
            // Reload-merge-write so independent instances never clobber rules
            // written since their last load, and synchronize Instance in memory
            // when sharing the default path so SecurityEnforcer sees updates immediately.
            Load();
            string state = enabled ? "True" : "False";
            RuleOverrides[ruleName] = state;
            Save();

            if (_instance != null && !ReferenceEquals(this, _instance) &&
                string.Equals(ConfigPath, _instance.ConfigPath, StringComparison.OrdinalIgnoreCase))
            {
                _instance.RuleOverrides[ruleName] = state;
            }
        }

        public string GetOverride(string ruleName)
        {
            return RuleOverrides.TryGetValue(ruleName, out string val) ? val : null;
        }
    }
}
