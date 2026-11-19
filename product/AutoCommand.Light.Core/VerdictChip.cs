using System;
using System.Collections.Generic;

namespace AutoCommand.Light.Core;

/// <summary>The facts a connection row carries, distilled for the chip.
/// Mirrors what the shell reads off an SvchostMonitorItem — but as a plain
/// record, so this layer never touches the engine types.</summary>
public sealed record ChipFacts(
    string ProcessName,
    bool IsSvchost,
    string HostedServicesCsv,
    bool IdentitySuspicious,
    bool IsWslFamily,
    string WslNote,
    bool HasExited,
    DateTime? FirstSeenUtc,
    bool IpBlocked,
    bool ProcessBlocked,
    string ImagePath = "")
{
    /// <summary>Browsers Light recognizes by image name (lowercase, no
    /// extension) — same family the block-page proxy scopes by default.</summary>
    public static readonly HashSet<string> BrowserNames = new(StringComparer.OrdinalIgnoreCase)
        { "msedge", "chrome", "firefox", "brave", "opera", "vivaldi" };
}

/// <summary>
/// The one human-readable verdict per connection row — the "what IS this?"
/// answer that lives in the first columns of the Light grid. Pure mapping:
/// priority is blocked → suspicious → svchost → WSL → browser → known
/// Windows piece → honestly Unknown. The chip never speculates: whatever
/// it cannot prove, it says.
/// </summary>
public static class VerdictChip
{
    /// <summary>Windows pieces a novice might otherwise Google. Short on
    /// purpose — anything not listed stays honestly "Unknown".</summary>
    private static readonly Dictionary<string, string> WindowsPieces =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["explorer"] = "Windows desktop",
            ["dwm"] = "Windows graphics",
            ["winlogon"] = "Windows sign-in",
            ["smss"] = "Windows core",
            ["csrss"] = "Windows core",
            ["services"] = "Windows services",
            ["lsass"] = "Windows sign-in security",
            ["taskhostw"] = "Windows task host",
            ["runtimebroker"] = "Windows app permissions",
            ["fontdrvhost"] = "Windows fonts",
            ["conhost"] = "Windows console",
            ["searchapp"] = "Windows search",
            ["smartscreen"] = "Windows security",
            ["wuauserv"] = "Windows Update",
        };

    /// <summary>(ChipText, Detail, Tone) — Tone: "ok" | "watch" | "act".</summary>
    public static (string Chip, string Detail, string Tone) Map(ChipFacts f)
    {
        ArgumentNullException.ThrowIfNull(f);

        // 1. blocked outranks everything — that is the safety-relevant fact
        if (f.IpBlocked || f.ProcessBlocked)
            return ("Blocked", "Your block rule is stopping this program's traffic.", "act");

        // 2. a svchost identity that contradicts the service manager is the
        //    masquerade signal — surface it before the friendly labels
        if (f.IdentitySuspicious)
            return ("Check this", "This program claims a Windows service identity that does not check out.", "watch");

        // 3. svchost with a resolved service → name the service
        if (f.IsSvchost)
        {
            var label = FirstServiceLabel(f.HostedServicesCsv);
            return (string.IsNullOrEmpty(label) ? "Windows services" : label,
                    "Part of Windows — it hosts services inside one shared program.",
                    "ok");
        }

        // 4. WSL family — "your Linux did that", which is the whole answer
        if (f.IsWslFamily)
            return (string.IsNullOrWhiteSpace(f.WslNote) ? "Your Linux (WSL)" : f.WslNote,
                    "A connection from your Windows Linux subsystem.", "ok");

        // 5. browsers, by image name
        var name = ImageBaseName(f.ProcessName);
        if (ChipFacts.BrowserNames.Contains(name))
            return ("Your browser", $"This is {Capitalize(name)} doing what you asked it to.", "ok");

        // 6. curated Windows pieces
        if (WindowsPieces.TryGetValue(name, out var piece))
            return (piece, "A known part of Windows.", "ok");

        // 7. anything else: honest unknown, with the first-seen date
        //    (invariant format on purpose — the app's voice is English, and
        //    a date that renders differently per user locale would make the
        //    chip text unstable)
        var seen = f.FirstSeenUtc?.ToLocalTime();
        string suffix = seen.HasValue
            ? $"Unknown · first seen {seen?.ToString("MMM d", System.Globalization.CultureInfo.InvariantCulture)}"
            : "Unknown";
        string detail = f.HasExited
            ? "This program has already exited."
            : "Not yet identified — right-click it to learn more or block it.";
        return (suffix, detail, "watch");
    }

    /// <summary>One broad category per row — the report's "parts of Windows
    /// / installed apps / unknown" tally. Orthogonal to block state: a
    /// blocked row still counts in its own category. "app" means we know
    /// where it runs from (a real installed program) even if we do not know
    /// the vendor; "unknown" means we cannot even place the file yet.</summary>
    public static string Category(ChipFacts f)
    {
        ArgumentNullException.ThrowIfNull(f);
        if (f.IsSvchost) return "windows";
        var name = ImageBaseName(f.ProcessName);
        if (ChipFacts.BrowserNames.Contains(name)) return "browser";
        if (f.IsWslFamily) return "wsl";
        if (WindowsPieces.ContainsKey(name)) return "windows";
        var path = f.ImagePath ?? "";
        if (path.Length == 0) return "unknown";
        return path.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase) ? "windows" : "app";
    }

    private static string FirstServiceLabel(string hostedServicesCsv)
    {
        if (string.IsNullOrWhiteSpace(hostedServicesCsv)) return "";
        var first = hostedServicesCsv.Split(',')[0].Trim();
        if (first.Length == 0) return "";
        // Friendly names live in the app-side ServiceCatalog; the chip keeps
        // the raw service name, shortened — still plain enough ("wuauserv"
        // beats "svchost.exe" for a novice who can search it).
        return first.Length > 24 ? first[..24] + "…" : first;
    }

    private static string ImageBaseName(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return "";
        var baseName = processName;
        var slash = baseName.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) baseName = baseName[(slash + 1)..];
        if (baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            baseName = baseName[..^4];
        return baseName;
    }

    private static string Capitalize(string s) =>
        string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
