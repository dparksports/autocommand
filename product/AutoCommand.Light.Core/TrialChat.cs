using System;
using System.Collections.Generic;

namespace AutoCommand.Light.Core;

/// <summary>The measured facts the guided chat may speak about. Everything
/// is optional-or-counted on purpose: when the shell does not know a fact
/// it passes "not tracked", and the router must say so rather than invent.
/// No API key, no network, no model — these answers are composed from the
/// machine's own records, which is exactly what makes them trustworthy.</summary>
public sealed record LightChatFacts(
    int ProgramsConnected,
    int UnknownCount,
    IReadOnlyList<string> UnknownNames,
    int ActiveBlocks,
    IReadOnlyList<string> BlockSummaries,
    int DeniedAttemptsLast10Min,
    int? TelemetrySendsLast24h,
    IReadOnlyList<string> RecentHistoryLines)
{
    public static LightChatFacts Empty { get; } = new(
        0, 0, Array.Empty<string>(), 0, Array.Empty<string>(), 0, null, Array.Empty<string>());
}

/// <summary>
/// Tier-0 of the Light chat: a local intent router that answers a small,
/// honest set of questions about THIS PC from THIS PC's records. Design
/// rules: at most three sentences plus one suggestion; never invent a
/// number; when a question falls outside the facts, say so and list what
/// it CAN answer. The full model-backed conversation is deliberately an
/// Advanced-app feature — this router's honesty is the Light app's voice.
/// </summary>
public static class TrialChatRouter
{
    public const string Suggestions =
        "Try: “What is this program?” · “What are you blocking?” · “My internet broke” · “Is my PC sending data?”";

    public static string Answer(string question, LightChatFacts facts)
    {
        var f = facts ?? LightChatFacts.Empty;
        var q = (question ?? "").ToLowerInvariant();

        if (LooksLikeConnectivityPanic(q)) return ConnectivityAnswer(f);
        if (LooksLikeWhatIsThis(q)) return WhatIsThisAnswer(f);
        if (LooksLikeWhatAreYouBlocking(q)) return BlockingAnswer(f);
        if (LooksLikeTelemetry(q)) return TelemetryAnswer(f);
        if (LooksLikeGreeting(q)) return HelloAnswer();
        return FallbackAnswer();
    }

    // ── intents ─────────────────────────────────────────────────────────

    private static bool LooksLikeConnectivityPanic(string q) =>
        ContainsAny(q, "broken", "internet", "offline", "not working", "no internet", "cant connect", "can't connect", "won't load", "wont load");

    private static bool LooksLikeWhatIsThis(string q) =>
        ContainsAny(q, "what is", "who is", "what's", "this program", "unknown", "mystery", "svchost", "taskhost");

    private static bool LooksLikeWhatAreYouBlocking(string q) =>
        ContainsAny(q, "block", "blocking", "blocked", "rules");

    private static bool LooksLikeTelemetry(string q) =>
        ContainsAny(q, "telemetry", "sending", "spy", "phone home", "my data", "tracking", "privacy");

    private static bool LooksLikeGreeting(string q) =>
        q.Trim().Length < 12 || ContainsAny(q, "hello", "hi", "hey", "help", "what can you");

    // ── answers ─────────────────────────────────────────────────────────

    private static string ConnectivityAnswer(LightChatFacts f)
    {
        if (f.ActiveBlocks > 0 || f.DeniedAttemptsLast10Min > 0)
        {
            var blocksNote = f.ActiveBlocks > 0
                ? $"{f.ActiveBlocks} block" + (f.ActiveBlocks == 1 ? " is" : "s are") + " on right now"
                : "a block was recently active";
            return $"{Capitalize(blocksNote)}. A block is the most common self-inflicted outage — " +
                   "the 🚑 Restore Internet button (bottom bar) pauses every block in one click, deletes nothing, " +
                   "and is always safe to press. If that does not fix it, the outage came from something else — a VPN, a proxy, or another tool.";
        }
        return "No AutoCommand blocks are on right now, so this app is not what stopped your internet. " +
               "Check VPNs, proxies, or your router — those are the usual culprits. " +
               "The 🚑 button in the bottom bar stays available if a block ever turns out to be the cause.";
    }

    private static string WhatIsThisAnswer(LightChatFacts f)
    {
        if (f.UnknownCount == 0)
            return f.ProgramsConnected == 0
                ? "Nothing is connecting right now, so there is nothing to identify yet. " +
                  "Give it a minute — new connections appear here as they happen."
                : $"Every one of the {f.ProgramsConnected} program" + (f.ProgramsConnected == 1 ? "" : "s") +
                  " connecting right now is identified — Windows parts, your apps, your browser. " +
                  "The Connections page shows each one with a plain-English label.";
        var shown = new List<string>();
        foreach (var n in f.UnknownNames)
        {
            if (shown.Count >= LightFindings.MaxNamesShown) break;
            if (!string.IsNullOrWhiteSpace(n)) shown.Add(n.Trim());
        }
        var names = shown.Count > 0 ? " (" + string.Join(", ", shown) + (shown.Count < f.UnknownCount ? ", and more" : "") + ")" : "";
        return $"{f.UnknownCount} connecting program" + (f.UnknownCount == 1 ? " is" : "s are") +
               $" not yet identified{names}. That usually means an app updating itself — not trouble. " +
               "The Connections page shows each one, and right-click offers the story and the block button.";
    }

    private static string BlockingAnswer(LightChatFacts f)
    {
        if (f.ActiveBlocks == 0)
            return "No blocks are on right now. When you block a program or an address, it appears on the Blocks page " +
                   "with its full story and a one-click undo.";
        var lines = new List<string> { $"{f.ActiveBlocks} block" + (f.ActiveBlocks == 1 ? " is" : "s are") + " on right now." };
        foreach (var b in f.BlockSummaries)
        {
            if (lines.Count >= 4) break;
            lines.Add("  · " + b);
        }
        lines.Add("The Blocks page has every one of them, each with a one-click undo.");
        return string.Join("\n", lines);
    }

    private static string TelemetryAnswer(LightChatFacts f)
    {
        if (f.TelemetrySendsLast24h is not int sends)
            return "That count lives in the Advanced app's “Data sent home” page, which watches Windows' telemetry " +
                   "service over a full week. Light keeps an eye on blocked attempts instead — right now there is " +
                   $"{(f.DeniedAttemptsLast10Min == 0 ? "nothing being stopped" : $"{f.DeniedAttemptsLast10Min} attempt(s) being stopped in the last 10 minutes")}.";
        return sends == 0
            ? "Windows' telemetry service has not sent anything in the last 24 hours, as far as your records show."
            : $"Windows' telemetry service sent data {sends} time" + (sends == 1 ? "" : "s") +
              " in the last 24 hours. Only counts — never contents — and the records stay on this PC.";
    }

    private static string HelloAnswer() =>
        "I answer small, factual questions about this PC's connections and blocks — computed right here, " +
        "no account and no internet. " + Suggestions;

    private static string FallbackAnswer() =>
        "That question is outside what I can prove from this PC's records, so I would be guessing — and guessing is not what this app does. " +
        Suggestions;

    // ── helpers ─────────────────────────────────────────────────────────

    private static bool ContainsAny(string q, params string[] needles)
    {
        foreach (var n in needles)
            if (q.Contains(n, StringComparison.Ordinal))
                return true;
        return false;
    }

    private static string Capitalize(string s) =>
        string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
