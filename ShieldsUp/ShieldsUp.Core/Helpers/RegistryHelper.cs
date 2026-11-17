using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using ShieldsUp.Core.Models;

namespace ShieldsUp.Core.Helpers
{
    public static class RegistryHelper
    {
        // ── LSA & UAC Hardening ──

        // Snapshot-and-restore, the house pattern (NameResolutionDoors):
        // the FIRST write records the exact previous value — including
        // "absent" — under ProgramData, and undo restores THAT instead of a
        // stock default. A user whose pre-hardening ConsentPromptBehaviorAdmin
        // was 1 (or 0) permanently loses the exact setting otherwise.
        private static string SnapshotPath => Path.Combine(AppPaths.DataRoot, "registry_undo.json");

        private sealed class RegistrySnapshot
        {
            public string Key { get; set; }
            public string Name { get; set; }
            public string Value { get; set; }      // null = was absent
            public string Kind { get; set; }       // RegistryValueKind name; DWord default
        }

        private static void SnapshotValue(string keyPath, string valueName, RegistryKey rootKey, string subKey)
        {
            try
            {
                var list = new List<RegistrySnapshot>();
                if (File.Exists(SnapshotPath))
                {
                    try
                    {
                        if (System.Text.Json.JsonSerializer.Deserialize<List<RegistrySnapshot>>(
                                File.ReadAllText(SnapshotPath)) is List<RegistrySnapshot> existing)
                            list = existing;
                    }
                    catch { /* unreadable snapshot starts fresh */ }
                }

                // keep the OLDEST observation — a re-apply must not overwrite
                // the true original with the applied value
                if (list.Exists(s =>
                        string.Equals(s.Key, keyPath, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(s.Name, valueName, StringComparison.OrdinalIgnoreCase)))
                    return;

                string value = null;
                string kind = null;
                using (var key = rootKey.OpenSubKey(subKey))
                {
                    if (key != null)
                    {
                        object raw = key.GetValue(valueName);
                        if (raw != null)
                        {
                            value = raw.ToString();
                            try { kind = key.GetValueKind(valueName).ToString(); } catch { }
                        }
                    }
                }

                list.Add(new RegistrySnapshot { Key = keyPath, Name = valueName, Value = value, Kind = kind });
                AppPaths.EnsureDataRoot();
                File.WriteAllText(SnapshotPath,
                    System.Text.Json.JsonSerializer.Serialize(list,
                        new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* snapshot is best-effort — never block the hardening */ }
        }

        private static void ApplyValue(string keyPath, string valueName, object value)
        {
            SnapshotValue(keyPath, valueName,
                keyPath.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) ? Registry.LocalMachine : Registry.CurrentUser,
                keyPath.Substring(keyPath.IndexOf('\\') + 1));
            Registry.SetValue(keyPath, valueName, value, RegistryValueKind.DWord);
        }

        /// <summary>Restores the snapshotted original values (or deletes
        /// values that were absent before). Missing snapshot → nothing done:
        /// the hardening stays, undo is honest about having no record.</summary>
        public static (int Restored, string Message) UndoHardeningValues()
        {
            try
            {
                if (!File.Exists(SnapshotPath)) return (0, "no undo snapshot exists — nothing to restore");
                var list = System.Text.Json.JsonSerializer.Deserialize<List<RegistrySnapshot>>(
                    File.ReadAllText(SnapshotPath));
                if (list == null || list.Count == 0) return (0, "no undo snapshot exists — nothing to restore");

                int restored = 0;
                foreach (var s in list)
                {
                    try
                    {
                        var (hive, subKey) = s.Key.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)
                            ? (Registry.LocalMachine, s.Key.Substring(s.Key.IndexOf('\\') + 1))
                            : (Registry.CurrentUser, s.Key.Substring(s.Key.IndexOf('\\') + 1));
                        using var key = hive.CreateSubKey(subKey);
                        if (key == null) continue;
                        if (s.Value == null)
                        {
                            key.DeleteValue(s.Name, throwOnMissingValue: false);
                        }
                        else
                        {
                            var kind = Enum.TryParse<RegistryValueKind>(s.Kind, out var k) && k != RegistryValueKind.Unknown
                                ? k : RegistryValueKind.DWord;
                            object value = kind == RegistryValueKind.DWord
                                ? (object)(int.TryParse(s.Value, out int n) ? n : 0)
                                : s.Value;
                            key.SetValue(s.Name, value, kind);
                        }
                        restored++;
                    }
                    catch { /* one key failing never blocks the rest */ }
                }
                File.Delete(SnapshotPath);
                return (restored, $"restored {restored} of {list.Count} value(s) to their pre-hardening state");
            }
            catch (Exception ex)
            {
                return (0, "restore failed: " + ex.Message);
            }
        }

        public static bool GetLsaProtectionStatus()
        {
            try
            {
                object value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0);
                return value != null && Convert.ToInt32(value) == 1;
            }
            catch { return false; }
        }

        public static void SetLsaProtectionStatus(bool enable)
        {
            ApplyValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", enable ? 1 : 0);
        }

        public static bool GetUacStrictness()
        {
            try
            {
                object lua = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0);
                object consent = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 0);

                return (lua != null && Convert.ToInt32(lua) == 1) &&
                       (consent != null && Convert.ToInt32(consent) == 2);
            }
            catch { return false; }
        }

        public static void SetUacStrictness(bool strict)
        {
            string system = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            ApplyValue(system, "EnableLUA", 1);
            ApplyValue(system, "ConsentPromptBehaviorAdmin", strict ? 2 : 5);
        }

        // ── IPv6 Hardening ──
        public static bool GetIpv6DisabledStatus()
        {
            try
            {
                object value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", 0);
                // 0xFF (255) means disabled all IPv6 components
                return value != null && Convert.ToInt32(value) == 255;
            }
            catch { return false; }
        }

        public static void SetIpv6DisabledStatus(bool disable)
        {
            // 0xFF to disable, 0 to re-enable default behavior
            ApplyValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", disable ? 0xFF : 0x00);
        }

        // ── Startup Persistence ──

        public static List<StartupItem> GetStartupItems()
        {
            var items = new List<StartupItem>();

            // 1. HKCU Run
            GetRegistryStartupItems(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", items);
            // 2. HKLM Run
            GetRegistryStartupItems(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", items);
            
            // 3. Current User Startup Folder
            GetFolderStartupItems(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup", items);
            // 4. Common Startup Folder
            GetFolderStartupItems(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Common Startup", items);

            return items;
        }

        private static void GetRegistryStartupItems(RegistryKey rootKey, string subKeyPath, string locationName, List<StartupItem> items)
        {
            try
            {
                using (RegistryKey key = rootKey.OpenSubKey(subKeyPath))
                {
                    if (key != null)
                    {
                        foreach (string valueName in key.GetValueNames())
                        {
                            object value = key.GetValue(valueName);
                            items.Add(new StartupItem
                            {
                                Name = valueName,
                                Value = value?.ToString() ?? "",
                                Location = locationName,
                                TargetPath = subKeyPath
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private static void GetFolderStartupItems(string folderPath, string locationName, List<StartupItem> items)
        {
            try
            {
                if (Directory.Exists(folderPath))
                {
                    foreach (string file in Directory.GetFiles(folderPath))
                    {
                        items.Add(new StartupItem
                        {
                            Name = Path.GetFileName(file),
                            Value = file,
                            Location = locationName,
                            TargetPath = folderPath
                        });
                    }
                }
            }
            catch { }
        }

        public static void DeleteStartupItem(StartupItem item)
        {
            try
            {
                if (item.Location.Contains("Run"))
                {
                    RegistryKey root = item.Location.StartsWith("HKLM") ? Registry.LocalMachine : Registry.CurrentUser;
                    using (RegistryKey key = root.OpenSubKey(item.TargetPath, writable: true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue(item.Name, throwOnMissingValue: false);
                        }
                    }
                }
                else if (item.Location.Contains("Startup"))
                {
                    if (File.Exists(item.Value))
                    {
                        File.Delete(item.Value);
                    }
                }
            }
            catch { }
        }
    }
}
