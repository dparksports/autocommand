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
    /// Shields Up surfaces. All state access is serialized: SecurityEnforcer's
    /// drift pass iterates RuleOverrides on a background thread while
    /// SetOverride mutates it — the unlocked shape used to enumerate a
    /// dictionary mid-write and silently skip a drift check on the rare throw.
    /// </summary>
    public class FirewallConfigManager
    {
        public static string DefaultConfigPath { get; set; } =
            Path.Combine(ProgramDataGuard.Root, "firewall_config.json");

        private static FirewallConfigManager _instance;
        public static FirewallConfigManager Instance => _instance ??= new FirewallConfigManager();

        private readonly string _explicitPath;
        private string ConfigPath => _explicitPath ?? DefaultConfigPath;

        private readonly object _gate = new object();

        private Dictionary<string, string> _overrides = new Dictionary<string, string>();

        /// <summary>A snapshot copy — callers iterate this, so the live
        /// dictionary can be mutated under the lock without racing.</summary>
        public Dictionary<string, string> RuleOverrides
        {
            get { lock (_gate) return new Dictionary<string, string>(_overrides, StringComparer.Ordinal); }
            set { lock (_gate) _overrides = value ?? new Dictionary<string, string>(); }
        }

        public FirewallConfigManager(string configPath = null)
        {
            _explicitPath = configPath;
            Load();
        }

        public void Load()
        {
            lock (_gate)
            {
                try
                {
                    string path = ConfigPath;
                    if (File.Exists(path))
                    {
                        string json = File.ReadAllText(path);
                        var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                        _overrides = data ?? new Dictionary<string, string>();
                    }
                    else
                    {
                        _overrides = new Dictionary<string, string>();
                    }
                }
                catch
                {
                    // Corrupt (torn write) used to silently reset to empty —
                    // every rule override vanished and the drift enforcer
                    // stopped enforcing the user's fixed states. Keep a
                    // sidecar so the loss is diagnosable, and keep the
                    // previous in-memory state instead of clearing it.
                    try
                    {
                        string path = ConfigPath;
                        if (File.Exists(path))
                            File.Copy(path, path + ".corrupt", overwrite: true);
                    }
                    catch { }
                }
            }
        }

        public void Save()
        {
            lock (_gate)
            {
                try
                {
                    string path = ConfigPath;
                    var dir = Path.GetDirectoryName(path);
                    if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    string json = JsonSerializer.Serialize(_overrides, new JsonSerializerOptions { WriteIndented = true });
                    // Atomic replace: a crash mid-WriteAllText left a truncated
                    // config that the next Load treated as "no overrides".
                    string tmp = path + ".tmp";
                    File.WriteAllText(tmp, json);
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else File.Move(tmp, path);
                }
                catch
                {
                    try
                    {
                        string tmp = ConfigPath + ".tmp";
                        if (File.Exists(tmp)) File.Delete(tmp);
                    }
                    catch { }
                }
            }
        }

        public void SetOverride(string ruleName, bool enabled)
        {
            // Reload-merge-write so independent instances never clobber rules
            // written since their last load, and synchronize Instance in memory
            // when sharing the default path so SecurityEnforcer sees updates immediately.
            Load();
            string state = enabled ? "True" : "False";
            lock (_gate)
            {
                _overrides[ruleName] = state;
            }
            Save();

            if (_instance != null && !ReferenceEquals(this, _instance) &&
                string.Equals(ConfigPath, _instance.ConfigPath, StringComparison.OrdinalIgnoreCase))
            {
                lock (_instance._gate)
                {
                    _instance._overrides[ruleName] = state;
                }
            }
        }

        public string GetOverride(string ruleName)
        {
            lock (_gate)
                return _overrides.TryGetValue(ruleName, out string val) ? val : null;
        }
    }
}
