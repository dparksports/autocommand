using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace AutoCommand.Light.Core;

/// <summary>The one attribute every app has: Always / Ask / Never.
/// The vocabulary is deliberately the OS-permission grammar people
/// already know from their phones. Ask is the default for anything new:
/// the gate blocks first and offers the question.</summary>
public enum AppPermission
{
    Ask = 0,
    Always = 1,
    Never = 2,
}

/// <summary>One row of the user's permission decisions, persisted as
/// readable JSON in Light's data folder. Keyed by image base name
/// (lowercase, no extension) — the same face the UI shows.</summary>
public sealed record PermissionEntry(
    string Key,
    AppPermission Permission,
    string DisplayName,
    DateTime DecidedUtc,
    /// <summary>"Always" with a deadline is Allow-once: the gate re-blocks
    /// when this passes. Null = a standing decision.</summary>
    DateTime? AllowUntilUtc = null,
    /// <summary>How the decision was made: "ask-dialog", "apps-page",
    /// "undo", "seed". The history deserves the actor.</summary>
    string Source = "")
{
    /// <summary>Allow-once that has run out is no longer an allow — the
    /// caller turns it back into an Ask. Pure time logic, no clocks here:
    /// the shell passes now in.</summary>
    public bool IsExpiredAllow(DateTime nowUtc) =>
        Permission == AppPermission.Always && AllowUntilUtc.HasValue && nowUtc >= AllowUntilUtc.Value;
}

/// <summary>The store: the whole permission world, serializable. The shell
/// owns the file; this type owns the shape and the seeding.</summary>
public sealed class PermissionStore
{
    public List<PermissionEntry> Entries { get; set; } = new();

    private static readonly HashSet<string> BrowserSeeds = new(StringComparer.OrdinalIgnoreCase)
        { "msedge", "chrome", "firefox", "brave", "opera", "vivaldi" };

    /// <summary>Browsers are the product's founding promise: the user's
    /// browser talks. Seeded Always, shown as normal rows the user can
    /// still change (user control beats our defaults).</summary>
    public static PermissionStore Seeded(DateTime nowUtc) => new()
    {
        Entries = BrowserSeeds
            .Select(n => new PermissionEntry(n.ToLowerInvariant(), AppPermission.Always,
                Cap(n) + " (browser)", nowUtc, null, "seed"))
            .ToList()
    };

    public PermissionEntry? Find(string imageBaseName)
    {
        var key = NormalizeKey(imageBaseName);
        return Entries.FirstOrDefault(e => e.Key == key);
    }

    public void Upsert(PermissionEntry entry)
    {
        var existing = Find(entry.Key);
        if (existing != null) Entries.Remove(existing);
        Entries.Add(entry);
    }

    public bool Remove(string imageBaseName)
    {
        var existing = Find(imageBaseName);
        return existing != null && Entries.Remove(existing);
    }

    public string ToJson() => JsonSerializer.Serialize(this, JsonOpts);

    public static PermissionStore FromJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new PermissionStore();
        try { return JsonSerializer.Deserialize<PermissionStore>(json, JsonOpts) ?? new PermissionStore(); }
        catch { return new PermissionStore(); }   // a corrupt file is an empty world, not a crash
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    public static string NormalizeKey(string imageBaseName)
    {
        var name = (imageBaseName ?? "").Trim();
        var slash = name.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) name = name[(slash + 1)..];
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        return name.ToLowerInvariant();
    }

    private static string Cap(string s) =>
        string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];
}

/// <summary>The exemption classes — the honest fine print of "nobody
/// transmits except you". Windows' own essentials keep the machine alive
/// and are named as a pinned group in the UI, never silently.</summary>
public enum Exemption
{
    None = 0,
    WindowsEssential,   // svchost family, system-dir images, curated set
}

/// <summary>
/// The gatekeeper's decision, pure: given what the shell knows about a
/// program, should the gate hold it, and as what? No clocks, no I/O, no
/// guessing. Priority is the design's spine:
///   Windows essential > the user's stored decision > Ask (the default).
/// </summary>
public static class GatePolicy
{
    /// <summary>Images Light never gates. Small and curated on purpose:
    /// everything not listed but living under \Windows\ is exempt by
    /// directory, and svchost-hosted services are exempt by family.</summary>
    private static readonly HashSet<string> CuratedEssentials =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "msmpeng", "nissrv", "securityhealthservice", "smartscreen",
            "wudfhost", "dwm", "explorer", "winlogon", "csrss", "smss",
            "services", "lsass", "fontdrvhost", "conhost", "runtimebroker",
            "searchapp", "taskhostw",
        };

    public static bool IsBrowser(string imageBaseName) =>
        PermissionStore.NormalizeKey(imageBaseName) is { Length: > 0 } key &&
        key is "msedge" or "chrome" or "firefox" or "brave" or "opera" or "vivaldi";

    public static Exemption ExemptReason(string processName, string imagePath, bool isSvchost)
    {
        if (isSvchost) return Exemption.WindowsEssential;
        var key = PermissionStore.NormalizeKey(processName);
        if (CuratedEssentials.Contains(key)) return Exemption.WindowsEssential;
        var path = imagePath ?? "";
        if (path.Length > 0 &&
            path.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase))
            return Exemption.WindowsEssential;
        return Exemption.None;
    }

    public sealed record Decision(
        bool ShouldGate,
        AppPermission Permission,
        Exemption Exemption,
        /// <summary>True when the store had nothing to say — this program
        /// is new to the gate and the user should be asked.</summary>
        bool IsNew)
    {
        public static readonly Decision Exempt = new(false, AppPermission.Ask, Exemption.WindowsEssential, false);
    }

    public static Decision Resolve(
        string processName, string imagePath, bool isSvchost,
        PermissionStore store, DateTime nowUtc)
    {
        if (ExemptReason(processName, imagePath, isSvchost) != Exemption.None)
            return Decision.Exempt;

        var entry = store.Find(processName);
        if (entry == null)
        {
            // A browser seed that somehow never persisted is still a browser:
            // the founding promise does not depend on store state.
            if (IsBrowser(processName))
                return new Decision(false, AppPermission.Always, Exemption.None, true);
            return new Decision(true, AppPermission.Ask, Exemption.None, true);
        }

        if (entry.IsExpiredAllow(nowUtc))
            return new Decision(true, AppPermission.Ask, Exemption.None, false);

        return new Decision(
            entry.Permission != AppPermission.Always,
            entry.Permission,
            Exemption.None,
            false);
    }
}

/// <summary>A pending question for the user. The gate raises one ticket
/// per unknown app; the dialog shows a countdown for unattended apps.
/// The semantics changed with the gatekeeper's first incident: expiry no
/// longer decides Never — it dismisses the dialog and the app stays
/// HELD (Ask). Never is an explicit tap, always. Silence keeps the
/// person's tools safe; it never condemns them.</summary>
public sealed record AskTicket(
    string Key,
    string DisplayName,
    string ImagePath,
    DateTime RaisedUtc,
    DateTime DeadlineUtc,
    /// <summary>The person is driving this app right now (foreground,
    /// visible window, or launched from their terminal/IDE). User-driven
    /// tickets do not auto-dismiss on the countdown at all.</summary>
    bool UserDriven = false)
{
    public const int TimeoutSeconds = 90;
    public bool Expired(DateTime nowUtc) => nowUtc >= DeadlineUtc;
}

/// <summary>
/// The "person is driving" signal — the interactive-use courtesy that
/// keeps the gate from ever breaking a tool the user is working through.
/// An app is user-driven when it is foreground, has a visible top-level
/// window, or was launched from the user's shell/IDE family (a CLI like
/// an agent terminal is exactly the case that must never be silently
/// condemned). Pure classification; the shell measures the window facts.
/// </summary>
public static class InteractiveUse
{
    /// <summary>Shells and workbenches: parents in this family mean the
    /// app was launched by the user's own hands, not by a service.</summary>
    public static readonly HashSet<string> ShellParents =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "windowsterminal", "wt", "conhost", "cmd", "powershell", "pwsh",
            "code", "idea", "rider", "pycharm", "devenv", "sublime_text",
            "notepad", "explorer",
        };

    public static bool IsUserDriven(
        string key,
        string? foregroundBase,
        IEnumerable<string> visibleWindowBases,
        string? parentImage)
    {
        var k = PermissionStore.NormalizeKey(key);
        if (k.Length == 0) return false;
        if (!string.IsNullOrWhiteSpace(foregroundBase) &&
            PermissionStore.NormalizeKey(foregroundBase) == k) return true;
        foreach (var v in visibleWindowBases ?? Array.Empty<string>())
            if (PermissionStore.NormalizeKey(v) == k) return true;
        var parent = PermissionStore.NormalizeKey(parentImage ?? "");
        return ShellParents.Contains(parent);
    }
}

/// <summary>One stopped attempt, as the shell measures it: an app reached
/// for the internet and the gate held it.</summary>
public sealed record AttemptFact(string AppKey, string AppDisplayName, DateTime TimeUtc, string Destination);

/// <summary>
/// Today's composition — the Screen-Time-meets-Safari-privacy-report
/// surface. Two honest states and nothing else: a quiet day (celebrated,
/// because quiet is the product) or attempts stopped (counted, named,
/// never alarmist). The gate may only claim what the facts counted.
/// </summary>
public static class TodayStats
{
    public sealed record Model(
        string Headline,
        string Subline,
        LightTone Tone,
        int StoppedAttempts,
        int StoppedApps,
        int PendingAsks,
        IReadOnlyList<(string App, int Count)> TopApps,
        IReadOnlyList<int> HourHistogram)   // 24 buckets, local day
    {
        public bool IsQuiet => StoppedAttempts == 0 && PendingAsks == 0;
    }

    public static Model Compose(
        IReadOnlyList<AttemptFact> attempts,
        int pendingAsks,
        DateTime nowLocal)
    {
        ArgumentNullException.ThrowIfNull(attempts);

        var byApp = attempts
            .GroupBy(a => a.AppKey)
            .Select(g => (App: g.First().AppDisplayName, Count: g.Count()))
            .OrderByDescending(x => x.Count)
            .ToList();

        var histogram = new int[24];
        foreach (var a in attempts)
        {
            var local = a.TimeUtc.ToLocalTime();
            if (local.Date == nowLocal.Date) histogram[local.Hour]++;
        }

        var apps = attempts.Select(a => a.AppKey).Distinct().Count();
        string headline, subline;
        LightTone tone;

        if (attempts.Count == 0 && pendingAsks == 0)
        {
            headline = "A quiet day.";
            subline = "Nothing tried to reach the internet except what you allowed.";
            tone = LightTone.Good;
        }
        else if (attempts.Count == 0)
        {
            headline = pendingAsks == 1 ? "One app is waiting for your answer." : $"{pendingAsks} apps are waiting for your answer.";
            subline = "They tried to reach the internet and the gate held them until you decide.";
            tone = LightTone.Watch;
        }
        else
        {
            headline = attempts.Count == 1
                ? "1 attempt was stopped today."
                : $"{attempts.Count} attempts were stopped today.";
            subline = apps == 1
                ? "One app kept trying. Your answer holds."
                : $"From {apps} apps. Your answers hold.";
            tone = pendingAsks > 0 ? LightTone.Watch : LightTone.Act;
        }

        return new Model(headline, subline, tone, attempts.Count, apps, pendingAsks,
            byApp, histogram);
    }
}
