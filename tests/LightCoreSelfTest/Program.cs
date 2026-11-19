using AutoCommand.Light.Core;

// ── Light product-core self-test ────────────────────────────────────────
// Offline, synthetic, fast — the same discipline as every other suite.
// Three layers under test:
//   1. FirstRunReport  — the honesty contract: counts come from facts,
//      unknowns are surfaced (never hidden), reassurance only when earned.
//   2. VerdictChip     — priority order (blocked > suspicious > svchost >
//      WSL > browser > known-Windows > honest Unknown).
//   3. TrialChatRouter — intents answer from the facts; outside the
//      facts it says so instead of guessing.
// Plus the engines' Naming.light() policy: AL-BLOCK builders parse and
// match, and AutoCommand's naming adopts AL-BLOCK in place (mutual panic).
// ────────────────────────────────────────────────────────────────────────

int passed = 0, failed = 0;

void Check(string name, bool ok, string detail = "")
{
    if (ok) { passed++; Console.WriteLine($"PASS  {name}"); }
    else { failed++; Console.WriteLine($"FAIL  {name}  {detail}"); }
}

// ── 1. the report composer ──────────────────────────────────────────────
{
    var clean = FirstRunReport.Compose(new LightFindings(
        WatchMinutes: 5, ProgramsConnected: 14, WindowsPrograms: 9, KnownApps: 5,
        UnknownCount: 0, UnknownNames: Array.Empty<string>(),
        BlockedAttempts: 0, ActiveBlocks: 0, SysmonInstalled: true));

    Check("report: clean run says so in the headline",
          clean.Headline == "Nothing looks dangerous." && clean.Tone == LightTone.Good);
    Check("report: clean run reassures that no blocks are on",
          clean.Lines.Any(l => l.Text.Contains("No blocks are on right now")));
    Check("report: clean run does not promise a Sysmon tip it cannot give",
          string.IsNullOrEmpty(clean.TipText));

    var unknowns = FirstRunReport.Compose(new LightFindings(
        5, 14, 9, 3, UnknownCount: 2,
        UnknownNames: new[] { "backup-helper.exe", "fun-tool.exe" },
        BlockedAttempts: 0, ActiveBlocks: 0, SysmonInstalled: false));

    Check("report: unknowns surface in the headline (never hidden)",
          unknowns.Headline.Contains("2 unknown") && unknowns.Tone == LightTone.Watch);
    Check("report: unknown names are shown so the reader can act",
          unknowns.Lines.Any(l => l.Text.Contains("backup-helper.exe") && l.Text.Contains("fun-tool.exe")));
    Check("report: unknown line links to Connections",
          unknowns.Lines.Any(l => l.ActionLabel == "See them" && l.ActionTarget == "connections"));
    Check("report: missing Sysmon produces exactly the one-click tip",
          unknowns.TipText.Contains("Set up Sysmon") && unknowns.TipTarget == "sysmon");

    var working = FirstRunReport.Compose(new LightFindings(
        5, 12, 10, 2, 0, Array.Empty<string>(), BlockedAttempts: 137, ActiveBlocks: 3, SysmonInstalled: true));

    Check("report: blocked attempts are counted exactly as measured",
          working.Lines.Any(l => l.Text.Contains("137") && l.Text.Contains("stopped")));
    Check("report: blocks working is Good, not alarmist",
          working.Headline == "Your blocks are doing their job." && working.Tone == LightTone.Good);
    Check("report: blocked line links to Blocks",
          working.Lines.Any(l => l.ActionLabel == "See the blocks" && l.ActionTarget == "blocks"));

    // name cap: five unknowns, only three named inline, count stays honest
    var many = FirstRunReport.Compose(new LightFindings(
        5, 20, 12, 3, 5,
        new[] { "a.exe", "b.exe", "c.exe", "d.exe", "e.exe" },
        0, 0, true));
    var manyLine = many.Lines.First(l => l.Text.Contains("Unknown means"));
    Check("report: name cap holds and the overflow says “and more”",
          manyLine.Text.Contains("c.exe") && !manyLine.Text.Contains("d.exe") && manyLine.Text.Contains("and more"));

    Check("report: composer refuses a nonsense watch window",
          Throws<ArgumentOutOfRangeException>(() => FirstRunReport.Compose(
              new LightFindings(0, 0, 0, 0, 0, Array.Empty<string>(), 0, 0, true))));
}

// ── 2. the verdict chip ─────────────────────────────────────────────────
{
    var blocked = VerdictChip.Map(new ChipFacts(
        "svchost", IsSvchost: true, HostedServicesCsv: "wuauserv", IdentitySuspicious: false,
        IsWslFamily: false, WslNote: "", HasExited: false, FirstSeenUtc: null,
        IpBlocked: true, ProcessBlocked: false));
    Check("chip: blocked outranks every friendly label",
          blocked.Chip == "Blocked" && blocked.Tone == "act");

    var suspicious = VerdictChip.Map(new ChipFacts(
        "svchost", IsSvchost: true, HostedServicesCsv: "wuauserv", IdentitySuspicious: true,
        IsWslFamily: false, WslNote: "", HasExited: false, FirstSeenUtc: null,
        IpBlocked: false, ProcessBlocked: false));
    Check("chip: suspicious identity beats the friendly service label",
          suspicious.Chip == "Check this" && suspicious.Tone == "watch");

    var svchost = VerdictChip.Map(new ChipFacts(
        "svchost", IsSvchost: true, HostedServicesCsv: "wuauserv,bits", IdentitySuspicious: false,
        IsWslFamily: false, WslNote: "", HasExited: false, FirstSeenUtc: null,
        IpBlocked: false, ProcessBlocked: false));
    Check("chip: svchost names its first hosted service",
          svchost.Chip == "wuauserv" && svchost.Tone == "ok");

    var svchostQuiet = VerdictChip.Map(new ChipFacts(
        "svchost", IsSvchost: true, HostedServicesCsv: "", IdentitySuspicious: false,
        IsWslFamily: false, WslNote: "", HasExited: false, FirstSeenUtc: null,
        IpBlocked: false, ProcessBlocked: false));
    Check("chip: svchost without identity stays honestly generic",
          svchostQuiet.Chip == "Windows services");

    var wsl = VerdictChip.Map(new ChipFacts(
        "python", IsSvchost: false, HostedServicesCsv: "", IdentitySuspicious: false,
        IsWslFamily: true, WslNote: "your Linux VM did that", HasExited: false,
        FirstSeenUtc: null, IpBlocked: false, ProcessBlocked: false));
    Check("chip: WSL rows answer “your Linux”", wsl.Chip == "your Linux VM did that");

    var browser = VerdictChip.Map(new ChipFacts(
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", IsSvchost: false,
        HostedServicesCsv: "", IdentitySuspicious: false, IsWslFamily: false, WslNote: "",
        HasExited: false, FirstSeenUtc: null, IpBlocked: false, ProcessBlocked: false));
    Check("chip: browser recognized by full image path", browser.Chip == "Your browser");

    var piece = VerdictChip.Map(new ChipFacts(
        "RuntimeBroker.exe", IsSvchost: false, HostedServicesCsv: "", IdentitySuspicious: false,
        IsWslFamily: false, WslNote: "", HasExited: false, FirstSeenUtc: null,
        IpBlocked: false, ProcessBlocked: false));
    Check("chip: curated Windows pieces translate", piece.Chip == "Windows app permissions");

    var seen = new DateTime(2026, 11, 15, 0, 0, 0, DateTimeKind.Utc);
    var unknown = VerdictChip.Map(new ChipFacts(
        "backup-helper", IsSvchost: false, HostedServicesCsv: "", IdentitySuspicious: false,
        IsWslFamily: false, WslNote: "", HasExited: false, FirstSeenUtc: seen,
        IpBlocked: false, ProcessBlocked: false));
    var expectedDay = seen.ToLocalTime().ToString("MMM d", System.Globalization.CultureInfo.InvariantCulture);
    Check("chip: unknown carries the first-seen date (formatted invariantly, local day)",
          unknown.Chip.Contains("Unknown") && unknown.Chip.Contains(expectedDay) && unknown.Tone == "watch");

    // categories: the report's honest tally — Windows parts, placed apps, unknowns
    Check("chip: svchost counts as Windows",
          VerdictChip.Category(new ChipFacts("svchost", true, "", false, false, "", false, null, false, false)) == "windows");
    Check("chip: an exe placed outside Windows\\ counts as an installed app even when unnamed",
          VerdictChip.Category(new ChipFacts("whatever", false, "", false, false, "", false, null, false, false,
              @"C:\Program Files\Vendor\tool.exe")) == "app");
    Check("chip: an unnamed process under Windows\\ still counts as Windows",
          VerdictChip.Category(new ChipFacts("unknownthing", false, "", false, false, "", false, null, false, false,
              @"C:\Windows\System32\something.dll")) == "windows");
    Check("chip: no path and no name match is honestly unknown",
          VerdictChip.Category(new ChipFacts("backup-helper", false, "", false, false, "", false, null, false, false)) == "unknown");
}

// ── 3. the guided chat router ───────────────────────────────────────────
{
    var facts = new LightChatFacts(
        ProgramsConnected: 14, UnknownCount: 1, UnknownNames: new[] { "fun-tool.exe" },
        ActiveBlocks: 2,
        BlockSummaries: new[] { "fun-tool.exe (program, since today)", "93.184.216.34 (address)" },
        DeniedAttemptsLast10Min: 4, TelemetrySendsLast24h: null,
        RecentHistoryLines: Array.Empty<string>());

    var panic = TrialChatRouter.Answer("my internet is broken", facts);
    Check("chat: connectivity panic names the block count and the panic button",
          panic.Contains("2 blocks") && panic.Contains("Restore Internet"));

    var calm = TrialChatRouter.Answer("why is my internet not working",
                                      LightChatFacts.Empty with { ActiveBlocks = 0, DeniedAttemptsLast10Min = 0 });
    Check("chat: no blocks on → honestly points away from this app",
          calm.Contains("No AutoCommand blocks are on") && calm.Contains("VPN"));

    var whatIs = TrialChatRouter.Answer("what is this program?", facts);
    Check("chat: what-is-this names the unknown programs",
          whatIs.Contains("fun-tool.exe") && whatIs.Contains("not yet identified"));

    var allKnown = TrialChatRouter.Answer("what is that program?",
                                          LightChatFacts.Empty with { ProgramsConnected = 6, UnknownCount = 0 });
    Check("chat: no unknowns → says everything is identified",
          allKnown.Contains("identified"));

    var blocking = TrialChatRouter.Answer("what are you blocking?", facts);
    Check("chat: blocking question lists the real blocks",
          blocking.Contains("2 blocks") && blocking.Contains("fun-tool.exe") && blocking.Contains("one-click undo"));

    var telemetry = TrialChatRouter.Answer("is my pc sending telemetry data?", facts);
    Check("chat: untracked telemetry → admits it and points to Advanced",
          telemetry.Contains("Advanced") && telemetry.Contains("blocked attempts"));

    var telemetryKnown = TrialChatRouter.Answer("is something spying on me?",
                                                LightChatFacts.Empty with { TelemetrySendsLast24h = 7 });
    Check("chat: tracked telemetry → the exact count, counts-only framing",
          telemetryKnown.Contains("7 times") && telemetryKnown.Contains("never contents"));

    var gibberish = TrialChatRouter.Answer("write me a haiku about cats", LightChatFacts.Empty);
    Check("chat: outside the facts → refuses to guess and lists what it can do",
          gibberish.Contains("guessing") && gibberish.Contains("Try:"));

    var hello = TrialChatRouter.Answer("hello?", LightChatFacts.Empty);
    Check("chat: greeting introduces the no-key, no-internet nature",
          hello.Contains("no account") && hello.Contains("no internet"));
}

// ── 4. the AL-BLOCK naming policy (engines) ─────────────────────────────
{
    var ln = AutoCommand.Engines.Firewall.Naming.light();
    Check("naming: light owns AL-BLOCK prefixes",
          ln.OwnIpPrefix == "AL-BLOCK-IP " && ln.OwnAppPrefix == "AL-BLOCK-APP " && ln.OwnSvcPrefix == "AL-BLOCK-SVC ");
    Check("naming: light adopts the AC-BLOCK family in place",
          ln.AdoptedPrefixes.Contains("AC-BLOCK-IP ") && ln.AdoptedPrefixes.Contains("AC-BLOCK-APP ") &&
          ln.AdoptedPrefixes.Contains("AC-BLOCK-SVC "));
    Check("naming: light is first generation — no legacy names",
          ln.LegacyIpPrefixes.Length == 0 && ln.LegacyAppPrefixes.Length == 0);

    var parsed = AutoCommand.Engines.Firewall.FirewallService.ParseIpTarget(
        ln, "AL-BLOCK-IP 1.2.3.4 (TCP Out)");
    Check("naming: AL-BLOCK-IP rule parses as an ip target", parsed == "1.2.3.4");

    var appMatch = AutoCommand.Engines.Firewall.FirewallService.MatchesAppTarget(
        ln, "AL-BLOCK-APP fun.exe (Out)", @"C:\Tools\fun.exe", @"C:\Tools\fun.exe");
    Check("naming: AL-BLOCK-APP rule matches its image", appMatch);

    var ac = AutoCommand.Engines.Firewall.Naming.autocommand();
    Check("naming: AutoCommand adopts AL-BLOCK in place (mutual panic)",
          ac.AdoptedPrefixes.Contains("AL-BLOCK-IP ") && ac.AdoptedPrefixes.Contains("AL-BLOCK-APP "));
    Check("naming: AutoCommand's own scheme is untouched",
          ac.OwnIpPrefix == "AC-BLOCK-IP " && ac.LegacyIpPrefixes.Contains("AutoCommand IP Block - "));

    var id = AutoCommand.Engines.Core.Identity.light();
    Check("identity: light points at its own data root and prefix set",
          id.DataRoot.EndsWith("AutoCommandLight") && id.OwnIpRulePrefix == "AL-BLOCK-IP " &&
          id.AdoptedRulePrefixes.Contains("AC-BLOCK-SVC "));
}

// ── summary ─────────────────────────────────────────────────────────────
Console.WriteLine($"light-core: {passed} passed, {failed} failed");
if (failed > 0)
{
    Console.WriteLine("LIGHT CORE SELF-TEST FAILED");
    Environment.Exit(1);
}
Console.WriteLine("ALL LIGHT CORE SELF-TESTS PASSED");

static bool Throws<T>(Action a) where T : Exception
{
    try { a(); return false; }
    catch (T) { return true; }
    catch { return false; }
}
