using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AutoCommand.Models;
using System.Text.Json;

namespace AutoCommand.Agent.Core
{
    /// <summary>
    /// Persistence for spawn watches: one JSON file per rule under
    /// %LOCALAPPDATA%\AutoCommand\watches; allowlist.txt sits beside them.
    /// Files are the interface — hand-edits and dropped-in files are picked
    /// up on the next Load (loads are never cached, so there is nothing to
    /// invalidate), and a rule definition is exactly the text of its file
    /// (that's the "share" story: copy the file, paste it on another machine).
    ///
    /// Two faces, the BlocksLedger pattern: <see cref="SpawnWatchLibrary"/>
    /// is the instance core (constructor-injected directory — a test can own
    /// one outright, no ordering traps), and the static
    /// <see cref="SpawnWatchStore"/> facade forwards to one default
    /// instance so existing call sites compile untouched.
    /// </summary>
    public sealed class SpawnWatchLibrary
    {
        private readonly string _watchesDirectory;
        private readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        public SpawnWatchLibrary() : this(null) { }

        /// <summary>Injected directory (null = the default machine location).</summary>
        public SpawnWatchLibrary(string watchesDirectory)
        {
            _watchesDirectory = watchesDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AutoCommand", "watches");
        }

        public string WatchesDirectory => _watchesDirectory;

        public List<SpawnWatch> Load()
        {
            var result = new List<SpawnWatch>();
            try
            {
                if (!Directory.Exists(_watchesDirectory)) return result;
                foreach (var file in Directory.GetFiles(_watchesDirectory, "*.json")
                             .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    try
                    {
                        var w = JsonSerializer.Deserialize<SpawnWatch>(
                            File.ReadAllText(file), JsonOpts);
                        if (w != null && !string.IsNullOrWhiteSpace(w.Name)) result.Add(w);
                    }
                    catch { /* one unreadable file must not take the tab down */ }
                }
            }
            catch { /* unreadable dir — empty list is honest */ }
            return result;
        }

        /// <summary>allowlist.txt contents: one wildcard image pattern per
        /// line, '#' comments allowed, blank lines ignored. Missing file is
        /// an empty allowlist — subtraction simply does nothing.</summary>
        public List<string> LoadAllowlist()
        {
            var patterns = new List<string>();
            try
            {
                var path = Path.Combine(_watchesDirectory, "allowlist.txt");
                if (!File.Exists(path)) return patterns;
                foreach (var raw in File.ReadAllLines(path))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    patterns.Add(line);
                }
            }
            catch { /* unreadable allowlist degrades to "nothing subtracted" */ }
            return patterns;
        }

        private string PathFor(string name) =>
            Path.Combine(_watchesDirectory, SafeFileName(name) + ".json");

        /// <summary>File-system-safe stem for a rule name (letters,
        /// digits, space, dash, underscore; everything else becomes '-').</summary>
        public string SafeFileName(string name)
        {
            var chars = (name ?? "watch").Trim().Select(c =>
                char.IsLetterOrDigit(c) || c == ' ' || c == '-' || c == '_' ? c : '-');
            var stem = new string(chars.ToArray()).Trim();
            return stem.Length == 0 ? "watch" : stem;
        }

        public void Save(SpawnWatch watch)
        {
            Directory.CreateDirectory(_watchesDirectory);
            File.WriteAllText(PathFor(watch.Name),
                JsonSerializer.Serialize(watch, JsonOpts));
        }

        public bool Delete(string name)
        {
            var path = PathFor(name);
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }

        /// <summary>Newest file-write stamp across the rules — the cheap
        /// change signal the service polls, so hand-dropped and hand-edited
        /// rule files take effect without a restart.</summary>
        public DateTime? NewestRuleStampUtc()
        {
            try
            {
                if (!Directory.Exists(_watchesDirectory)) return null;
                DateTime? newest = null;
                foreach (var f in Directory.GetFiles(_watchesDirectory, "*.json"))
                {
                    var t = File.GetLastWriteTimeUtc(f);
                    if (newest == null || t > newest.Value) newest = t;
                }
                return newest;
            }
            catch { return null; }
        }

        /// <summary>Creates the watches directory with one starter rule and
        /// a starter allowlist the first time anything touches the store,
        /// so the tab never greets with an empty list.</summary>
        public void EnsureSeeded()
        {
            try
            {
                Directory.CreateDirectory(_watchesDirectory);
                var hasRules = Directory.GetFiles(_watchesDirectory, "*.json").Length > 0;
                if (hasRules) return;

                Save(new SpawnWatch
                {
                    Name = "svchost children",
                    MatchProcess = "*",
                    MatchParent = "svchost.exe",
                    MinusAllowlist = true,
                    Notes = "Starter watch: every process a service host spawns, minus the " +
                            "known helpers listed in allowlist.txt. Widen or narrow it freely — " +
                            "for one service only, set the service key (e.g. usosvc).",
                });

                var allowlistPath = Path.Combine(_watchesDirectory, "allowlist.txt");
                if (!File.Exists(allowlistPath))
                {
                    File.WriteAllText(allowlistPath, string.Join(Environment.NewLine,
                        "# Spawn Watches allowlist — one wildcard image pattern per line.",
                        "# Rules with 'minus allowlist' never count these as hits.",
                        "# Hand-edit freely; the change is picked up on the next pass.",
                        "svchost.exe",
                        "taskhostw.exe",
                        "dllhost.exe",
                        "RuntimeBroker.exe",
                        "consent.exe",
                        "ctfmon.exe",
                        "audiodg.exe",
                        "smartscreen.exe",
                        "sihost.exe",
                        "SearchHost.exe",
                        "StartMenuExperienceHost.exe",
                        "ShellExperienceHost.exe",
                        "ApplicationFrameHost.exe",
                        "SecurityHealthHost.exe",
                        "WerFault.exe",
                        "wermgr.exe",
                        "unsecapp.exe",
                        "WmiPrvSE.exe",
                        "dxgiadaptercache.exe",
                        "AggregatorHost.exe") + Environment.NewLine);
                }
            }
            catch { /* seeding is cosmetic — never fatal */ }
        }
    }

    /// <summary>
    /// Static facade over one default <see cref="SpawnWatchLibrary"/> —
    /// every existing call site (agent bridge tools) compiles untouched.
    /// Tests construct a SpawnWatchLibrary outright
    /// instead of reaching into the facade.
    /// </summary>
    public static class SpawnWatchStore
    {
        private static readonly SpawnWatchLibrary Default = new();

        public static string WatchesDirectory => Default.WatchesDirectory;

        public static List<SpawnWatch> Load() => Default.Load();

        public static List<string> LoadAllowlist() => Default.LoadAllowlist();

        public static string SafeFileName(string name) => Default.SafeFileName(name);

        public static void Save(SpawnWatch watch) => Default.Save(watch);

        public static bool Delete(string name) => Default.Delete(name);

        public static DateTime? NewestRuleStampUtc() => Default.NewestRuleStampUtc();

        public static void EnsureSeeded() => Default.EnsureSeeded();
    }
}
