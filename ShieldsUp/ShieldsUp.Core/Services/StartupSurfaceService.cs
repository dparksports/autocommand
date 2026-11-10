using System.Text.Json;
using System.Text.Json.Nodes;

namespace ShieldsUp.Core.Services;

/// <summary>
/// The startup/persistence surface behind the "Startup &amp; Tasks" section:
/// logon items (Run keys, Startup folders) and scheduled tasks, each with a
/// reversible off switch. Classification is pure and self-tested; registry
/// toggles snapshot the exact previous value into startup-state.json before
/// removing it (restore is exact — or an honest refusal when no snapshot
/// exists). Scheduled-task toggling is the caller's job (TaskSchedulerService
/// in the host); this service stays free of app-layer dependencies.
///
/// Verdict vocabulary is location-based and says so: "\Microsoft\Windows\…"
/// tasks are "Windows inbox"; anything else (root, vendor folders) is
/// "third-party" — the review-worthy set. No signature claims.
/// </summary>
public static class StartupSurfaceService
{
    public enum TaskGroup { Inbox, ThirdParty }

    /// <summary>Pure: task path → review group (self-tested).</summary>
    public static TaskGroup ClassifyTask(string taskPath) =>
        (taskPath ?? "").Replace('/', '\\').StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase)
            ? TaskGroup.Inbox
            : TaskGroup.ThirdParty;

    public enum LogonKind { Registry, Folder }

    /// <summary>Pure: the location label → how its items toggle
    /// (registry values are snapshotted off; folder shortcuts are not
    /// touched by us — self-tested).</summary>
    public static LogonKind KindOfLocation(string location) =>
        (location ?? "").Contains("Startup", StringComparison.OrdinalIgnoreCase)
            ? LogonKind.Folder
            : LogonKind.Registry;

    // ── registry logon toggles (snapshot → remove / restore) ────────────

    private static string StatePath => Path.Combine(AppPaths.DataRoot, "startup-state.json");

    private static JsonObject LoadState()
    {
        try
        {
            if (File.Exists(StatePath))
                return JsonNode.Parse(File.ReadAllText(StatePath)) as JsonObject ?? new JsonObject();
        }
        catch { /* unreadable state = honest refusal at restore time */ }
        return new JsonObject();
    }

    private static void SaveState(JsonObject state)
    {
        Directory.CreateDirectory(AppPaths.DataRoot);
        File.WriteAllText(StatePath, state.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private static (Microsoft.Win32.RegistryKey Hive, string Path) HiveOf(string location)
    {
        if ((location ?? "").StartsWith("HKCU", StringComparison.OrdinalIgnoreCase))
            return (Microsoft.Win32.Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run");
        return (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run");
    }

    /// <summary>True when a snapshot exists for this logon item (i.e. we
    /// disabled it and can restore it exactly).</summary>
    public static bool HasLogonSnapshot(string location, string name)
    {
        var state = LoadState();
        return state["logon"]?[location]?[name] is JsonObject;
    }

    /// <summary>Snapshots the value, then removes it. Empty list = clean.</summary>
    public static List<string> DisableRegistryLogon(string location, string name)
    {
        var failures = new List<string>();
        try
        {
            var (hive, path) = HiveOf(location);
            using (var key = hive.OpenSubKey(path, writable: true))
            {
                if (key?.GetValue(name) is not string value) { failures.Add($"no '{name}' in {location}"); return failures; }
                var state = LoadState();
                var logon = state["logon"] as JsonObject ?? new JsonObject();
                state.Remove("logon");
                logon[location] ??= new JsonObject();
                logon[location][name] = new JsonObject { ["value"] = value, ["path"] = path, ["disabledUtc"] = DateTime.UtcNow.ToString("o") };
                state["logon"] = logon;
                SaveState(state);
                key.DeleteValue(name);
            }
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    /// <summary>Restores the snapshotted value exactly; refuses honestly
    /// when no snapshot exists.</summary>
    public static List<string> EnableRegistryLogon(string location, string name)
    {
        var failures = new List<string>();
        try
        {
            var state = LoadState();
            var snap = state["logon"]?[location]?[name] as JsonObject;
            if (snap == null) { failures.Add("no snapshot — this item was not disabled by AutoCommand"); return failures; }
            var (hive, _) = HiveOf(location);
            using (var key = hive.CreateSubKey(snap["path"]?.GetValue<string>() ?? @"Software\Microsoft\Windows\CurrentVersion\Run"))
                key.SetValue(name, snap["value"]?.GetValue<string>() ?? "", Microsoft.Win32.RegistryValueKind.String);
            (state["logon"]?[location] as JsonObject)?.Remove(name);
            SaveState(state);
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }
}
