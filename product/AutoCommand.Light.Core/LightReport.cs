using System;
using System.Collections.Generic;

namespace AutoCommand.Light.Core;

/// <summary>How worried the reader should be. Three tones, one honest rule:
/// the composer may only lower worry (Good), it may never hide it.</summary>
public enum LightTone
{
    Good,
    Watch,
    Act,
}

/// <summary>One plain-English line of the report. ActionTarget is a nav
/// token the shell maps to a view ("connections" | "blocks" | "history" |
/// "sysmon" | "ask"); empty means the line is not clickable.</summary>
public sealed record LightReportLine(string Text, string ActionLabel = "", string ActionTarget = "");

/// <summary>Everything the composer needs, already measured by the shell.
/// The composer never invents a count it was not handed — that is the
/// whole honesty contract of the Light report.</summary>
public sealed record LightFindings(
    int WatchMinutes,
    int ProgramsConnected,
    int WindowsPrograms,
    int KnownApps,
    int UnknownCount,
    IReadOnlyList<string> UnknownNames,
    int BlockedAttempts,
    int ActiveBlocks,
    bool SysmonInstalled)
{
    /// <summary>Names shown in sentences, capped so the report stays one
    /// breath long; the rest live behind the Connections link.</summary>
    public const int MaxNamesShown = 3;
}

/// <summary>The composed report: a headline, clickable lines, and one tip.</summary>
public sealed record LightReport(
    string Headline,
    LightTone Tone,
    IReadOnlyList<LightReportLine> Lines,
    string TipText = "",
    string TipTarget = "");

/// <summary>
/// The first-run / "what's happening now" report — the Light shell's
/// landing moment. Pure composition over measured facts: no clocks, no
/// I/O, no guessing. Every sentence is written so a non-technical reader
/// knows, in one pass, whether they need to do anything (they usually
/// don't — that reassurance is the product).
/// </summary>
public static class FirstRunReport
{
    public static LightReport Compose(LightFindings f)
    {
        ArgumentNullException.ThrowIfNull(f);
        if (f.WatchMinutes <= 0) throw new ArgumentOutOfRangeException(nameof(f.WatchMinutes));
        ArgumentNullException.ThrowIfNull(f.UnknownNames);

        var lines = new List<LightReportLine>();

        // ── headline: the one thing they read ───────────────────────────
        string headline;
        LightTone tone;
        if (f.UnknownCount == 0 && f.BlockedAttempts == 0)
        {
            headline = "Nothing looks dangerous.";
            tone = LightTone.Good;
        }
        else if (f.UnknownCount > 0)
        {
            headline = f.UnknownCount == 1
                ? "All quiet — 1 unknown program worth a look."
                : $"All quiet — {f.UnknownCount} unknown programs worth a look.";
            tone = LightTone.Watch;
        }
        else
        {
            headline = "Your blocks are doing their job.";
            tone = LightTone.Good;
        }

        // ── the summary sentence ────────────────────────────────────────
        lines.Add(new LightReportLine(
            $"In the last {f.WatchMinutes} minutes: {f.ProgramsConnected} " +
            (f.ProgramsConnected == 1 ? "program connected" : "programs connected") +
            $" — {f.WindowsPrograms} part" + (f.WindowsPrograms == 1 ? "" : "s") +
            $" of Windows, {f.KnownApps} installed app" + (f.KnownApps == 1 ? "" : "s") +
            $", {f.UnknownCount} unknown."));

        // ── unknowns, named ─────────────────────────────────────────────
        if (f.UnknownCount > 0)
        {
            var shown = new List<string>();
            foreach (var n in f.UnknownNames)
            {
                if (shown.Count >= LightFindings.MaxNamesShown) break;
                if (!string.IsNullOrWhiteSpace(n)) shown.Add(n.Trim());
            }
            string names = shown.Count > 0
                ? " like " + string.Join(", ", shown) + (shown.Count < f.UnknownCount ? " and more" : "")
                : "";
            lines.Add(new LightReportLine(
                $"Unknown means AutoCommand cannot yet tell what it is or where it came from{names}. " +
                "Most turn out to be normal apps updating themselves.",
                "See them", "connections"));
        }

        // ── blocked attempts: the leash working ─────────────────────────
        if (f.BlockedAttempts > 0)
        {
            lines.Add(new LightReportLine(
                f.BlockedAttempts == 1
                    ? "1 blocked program tried to reach the internet — and was stopped."
                    : $"Blocked programs tried to reach the internet {f.BlockedAttempts} times — every attempt was stopped.",
                "See the blocks", "blocks"));
        }

        // ── reassurance when nothing is blocked at all ──────────────────
        if (f.ActiveBlocks == 0 && f.BlockedAttempts == 0)
        {
            lines.Add(new LightReportLine(
                "No blocks are on right now. When you block something, this page says so."));
        }

        // ── the one tip: Sysmon, the backstory engine ───────────────────
        string tip = "";
        string tipTarget = "";
        if (!f.SysmonInstalled)
        {
            tip = "Tip: one click on “Set up Sysmon” lets AutoCommand learn where every program came from.";
            tipTarget = "sysmon";
        }

        return new LightReport(headline, tone, lines, tip, tipTarget);
    }
}
