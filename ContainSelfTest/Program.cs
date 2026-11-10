// Contain self-test — the blocking/safety path, offline:
//   1. BlocksStore — round-trip persistence against a temp dir: add/upsert/
//      pause/remove, event log, provenance parsing, grouping keys.
//   2. FirewallService — the v2 rule-name builders (the strings the whole
//      block/undo/coverage machinery joins on).
//   3. BlockContainmentVerifier — the verify_block_containment join: every
//      verdict (contained / stale-flow / leak) plus the identity guards
//      (pid reuse, archive image match, loopback) from synthetic rows.
// Nothing touches the real %LOCALAPPDATA% store, the hosts file, netsh, or
// Defender; those halves are exercised by the app itself.
using System;
using AutoCommand.Contain.Core;
using AutoCommand.NetWatch.Core;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// ─────────────────────────────────────────────────────────────────────
// 1. BlocksStore — the undo ledger every block surface writes through
// ─────────────────────────────────────────────────────────────────────
string storeDir = Path.Combine(Path.GetTempPath(), "contain-selftest-" + Guid.NewGuid().ToString("N"));
try
{
    // DI pilot payoff: the ledger's storage location is constructor-
    // injected — no global static to redirect, no "set DataDirectory
    // BEFORE first use" ordering trap. This test owns its ledger outright.
    var store = new BlocksLedger(storeDir);
    store.Load();
    Check("empty store starts empty", store.Records.Count == 0);

    store.AddOrUpdate(new BlockRecord
    {
        Kind = "ip", Key = "1.2.3.4", ProcessName = "chrome.exe",
        ClassAtBlock = "Application", Origin = "blocks-tab",
    }, origin: "selftest");
    store.AddOrUpdate(new BlockRecord
    {
        Kind = "ip", Key = "5.6.7.8", ProcessName = "svchost.exe",
        ServiceKey = "diagtrack", SvcDisplayName = "Connected User Experiences and Telemetry",
        ClassAtBlock = "Microsoft", Origin = "monitor",
    }, origin: "selftest");
    store.AddOrUpdate(new BlockRecord
    {
        Kind = "proc", Key = @"c:\tools\upd.exe", ProcessName = "upd.exe",
        ClassAtBlock = "Application", Origin = "blocks-tab",
    }, origin: "selftest");
    Check("three adds → three records", store.Records.Count == 3,
          $"count={store.Records.Count}");

    // upsert: same kind+key refreshes in place, never duplicates
    store.AddOrUpdate(new BlockRecord
    {
        Kind = "ip", Key = "1.2.3.4", ProcessName = "chrome.exe",
        ClassAtBlock = "Akamai (MS CDN)", Origin = "repair",
    }, origin: "selftest");
    Check("re-block same key upserts (still 3)", store.Records.Count == 3);
    Check("upsert refreshed the classifier snapshot",
          store.Records.First(r => r.Key == "1.2.3.4").ClassAtBlock == "Akamai (MS CDN)");

    // pause semantics: rules off, record kept
    store.SetStatus("ip", "5.6.7.8", "off", origin: "selftest");
    Check("pause keeps the record with Status=off",
          store.Records.First(r => r.Key == "5.6.7.8").Status == "off");

    // persistence round-trip: a fresh process state reloads from disk
    store.Load();
    Check("reload from disk keeps 3 records", store.Records.Count == 3,
          $"count={store.Records.Count}");
    Check("reload keeps the pause", store.Records.First(r => r.Key == "5.6.7.8").Status == "off");
    Check("store file exists", File.Exists(store.StorePath), store.StorePath);

    // the event ledger the Blocks tab shows
    Check("event log recorded adds", File.Exists(store.EventLogPath) &&
          File.ReadAllLines(store.EventLogPath).Count(l => l.Contains("1.2.3.4")) >= 2);

    // remove
    store.Remove("proc", @"c:\tools\upd.exe", origin: "selftest");
    Check("remove drops the record", store.Records.Count == 2 &&
          store.Records.All(r => r.Kind != "proc"));

    // provenance parser: what block rules carry in their description
    Check("provenance: svchost label parses to service key",
          store.TryParseServiceFromDescription(
              "[blocked 2026-10-25 10:00 UTC] svchost.exe [Connected User Experiences and Telemetry]",
              out string svcKey, out string svcDisplay) &&
          svcKey == "connected user experiences and telemetry",
          $"key='{svcKey}'");
    Check("provenance: '+2 more' collapses to the primary service",
          store.TryParseServiceFromDescription(
              "[blocked x] svchost.exe [DiagTrack+2 more]", out string k2, out _) &&
          k2 == "diagtrack", $"key='{k2}'");
    Check("provenance: non-svchost process rejected",
          !store.TryParseServiceFromDescription("[blocked x] chrome.exe [Whatever]", out _, out _));
    Check("provenance: 'no service' rejected",
          !store.TryParseServiceFromDescription("[blocked x] svchost.exe [no service]", out _, out _));
    Check("provenance: garbage rejected",
          !store.TryParseServiceFromDescription("plain description", out _, out _));

    // grouping: the Blocks tab groups rows by service identity
    Check("group key: ip rows group by service key",
          store.ServiceGroupKey(store.Records.First(r => r.Key == "5.6.7.8")) == "diagtrack");
}
finally
{
    try { Directory.Delete(storeDir, true); } catch { }
}

// ─────────────────────────────────────────────────────────────────────
// 2. FirewallService — the v2 rule-name builders every surface joins on
// ─────────────────────────────────────────────────────────────────────
Check("ip rule prefix is the v2 shape", FirewallService.NewIpPrefix == "AC-BLOCK-IP ");
Check("app rule prefix is the v2 shape", FirewallService.NewAppPrefix == "AC-BLOCK-APP ");
Check("primary app rule name shape",
      FirewallService.PrimaryAppRuleName("upd.exe") == "AC-BLOCK-APP upd.exe (Out)",
      FirewallService.PrimaryAppRuleName("upd.exe"));

string s1 = FirewallService.SuffixedAppRuleName("upd.exe", @"C:\Tools\upd.exe");
string s2 = FirewallService.SuffixedAppRuleName("upd.exe", @"C:\Tools\upd.exe");
string s3 = FirewallService.SuffixedAppRuleName("upd.exe", @"C:\Tools\v2\upd.exe");
Check("sibling rule name extends the primary", s1.StartsWith("AC-BLOCK-APP upd.exe (Out) · ", StringComparison.Ordinal), s1);
Check("sibling suffix is 8 lowercase hex chars",
      System.Text.RegularExpressions.Regex.IsMatch(s1.Substring(s1.LastIndexOf('·') + 1).Trim(), "^[0-9a-f]{8}$"), s1);
Check("same path → same sibling name", s1 == s2);
Check("different path → different sibling name", s1 != s3);

// ─────────────────────────────────────────────────────────────────────
// 3. BlockContainmentVerifier — the containment join behind the
//    verify_block_containment bridge tool. All rows synthetic; the live
//    halves (feed, kernel table, WMI, archive) are exercised by the app.
// ─────────────────────────────────────────────────────────────────────
DateTime cNow = new(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);
DateTime cT0 = new(2026, 10, 27, 10, 0, 0, DateTimeKind.Utc);

BlockHitFeedService.HitAggregate CAgg(string image, int pid, string ip, int count,
    DateTime first, DateTime last, string kind = "ip") =>
    new() { Image = image, Process = Path.GetFileName(image), Pid = pid,
            DestIp = ip, DestPort = 443, MatchKind = kind,
            Count = count, FirstUtc = first, LastUtc = last };

var cInv = new List<BlockedTarget>
{
    new() { Target = "1.2.3.4", Kind = "ip", Ip = "1.2.3.4", Rules = 1, EnabledRules = 1, Created = cT0 },
    new() { Target = "5.6.7.8", Kind = "ip", Ip = "5.6.7.8", Rules = 1, EnabledRules = 1, Created = cT0 },
    new() { Target = "upd.exe", Kind = "app", AppPath = @"C:\Tools\upd.exe", Rules = 1, EnabledRules = 1, Created = cT0 },
    new() { Target = "9.9.9.9", Kind = "ip", Ip = "9.9.9.9", Rules = 1, EnabledRules = 1, Created = null },
};

var cV1 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\chrome.exe", 100, "1.2.3.4", 5, cT0.AddMinutes(5), cNow.AddMinutes(-2)) },
    cInv, new(), new());
Check("containment: attempts only → contained",
      cV1.Count == 1 && cV1[0].Verdict == BlockContainmentVerifier.Contained && cV1[0].Attempts == 5,
      cV1.Count == 1 ? cV1[0].Verdict : $"count={cV1.Count}");
Check("containment: t0 from rule provenance", cV1[0].T0 == cT0 && !cV1[0].T0Approximate);

var cV2 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\upd.exe", 200, "8.8.8.8", 3, cNow.AddMinutes(-90), cNow.AddMinutes(-10), kind: "app") },
    cInv,
    new() { new BlockContainmentVerifier.LiveSocket { Pid = 200, RemoteIp = "8.8.8.8", RemotePort = 443,
             ProcessName = "upd.exe", ProcessStartedUtc = cT0.AddHours(-1) } },
    new());
Check("containment: socket owner predates block → stale-flow",
      cV2[0].Verdict == BlockContainmentVerifier.StaleFlow, cV2[0].Verdict);

var cV3 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\upd.exe", 300, "8.8.8.8", 2, cNow.AddMinutes(-30), cNow.AddMinutes(-5), kind: "app") },
    cInv,
    new() { new BlockContainmentVerifier.LiveSocket { Pid = 300, RemoteIp = "8.8.8.8", RemotePort = 443,
             ProcessName = "upd.exe", ProcessStartedUtc = cT0.AddHours(1) } },
    new());
Check("containment: socket owner started after block → leak",
      cV3[0].Verdict == BlockContainmentVerifier.Leak, cV3[0].Verdict);

var cV4 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\b.exe", 400, "5.6.7.8", 4, cT0.AddMinutes(1), cNow.AddMinutes(-1)) },
    cInv, new(),
    new() { new TransmissionRecord { Pid = 400, Image = @"C:\Tools\b.exe",
             RemoteIp = "5.6.7.8", TsUtc = cT0.AddMinutes(30), ClientBytes = 5_000, ServerBytes = 1_000 } });
Check("containment: archived bytes to blocked IP after t0 → leak",
      cV4[0].Verdict == BlockContainmentVerifier.Leak && cV4[0].BytesSinceT0 == 6_000,
      $"{cV4[0].Verdict} bytes={cV4[0].BytesSinceT0}");

var cV5 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\b.exe", 410, "5.6.7.8", 4, cT0.AddMinutes(1), cNow.AddMinutes(-1)) },
    cInv, new(),
    new() { new TransmissionRecord { Pid = 410, Image = @"C:\Tools\b.exe",
             RemoteIp = "203.0.113.9", TsUtc = cT0.AddMinutes(30), ClientBytes = 9_000, ServerBytes = 0 } });
Check("containment: ip-block, bytes to unblocked IP stay allowed",
      cV5[0].Verdict == BlockContainmentVerifier.Contained, cV5[0].Verdict);

var cV6 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\b.exe", 420, "9.9.9.9", 2, cNow.AddMinutes(-45), cNow.AddMinutes(-3)) },
    cInv, new(), new());
Check("containment: legacy block → t0 approximate from first hit",
      cV6[0].T0 == cNow.AddMinutes(-45) && cV6[0].T0Approximate, cV6[0].T0.ToString("O"));

var cV7 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\upd.exe", 500, "8.8.8.8", 2, cNow.AddMinutes(-60), cNow.AddMinutes(-30), kind: "app") },
    cInv,
    new() { new BlockContainmentVerifier.LiveSocket { Pid = 500, RemoteIp = "8.8.8.8", RemotePort = 443,
             ProcessName = "upd.exe", ProcessStartedUtc = cNow.AddMinutes(-1) } },
    new());
Check("containment: reused-pid socket flagged, never accused",
      cV7[0].PidReused && cV7[0].Verdict == BlockContainmentVerifier.Contained,
      $"{cV7[0].Verdict} reused={cV7[0].PidReused}");

var cV8 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\upd.exe", 600, "8.8.8.8", 2, cT0.AddMinutes(5), cNow.AddMinutes(-5), kind: "app") },
    cInv, new(),
    new() { new TransmissionRecord { Pid = 600, Image = @"C:\Tools\other.exe",
             RemoteIp = "8.8.8.8", TsUtc = cT0.AddMinutes(30), ClientBytes = 9_999, ServerBytes = 0 } });
Check("containment: archive join requires image match",
      cV8[0].Verdict == BlockContainmentVerifier.Contained, cV8[0].Verdict);

var cV9 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\upd.exe", 700, "8.8.8.8", 2, cT0.AddMinutes(5), cNow.AddMinutes(-5), kind: "app") },
    cInv,
    new() { new BlockContainmentVerifier.LiveSocket { Pid = 700, RemoteIp = "127.0.0.1", RemotePort = 9050,
             ProcessName = "upd.exe", ProcessStartedUtc = cT0.AddHours(-2) } },
    new());
Check("containment: loopback socket is not exfiltration",
      cV9[0].Verdict == BlockContainmentVerifier.Contained, cV9[0].Verdict);

var cV10 = BlockContainmentVerifier.Evaluate(
    new() { CAgg(@"C:\Tools\a.exe", 800, "1.2.3.4", 99, cT0, cNow),
            CAgg(@"C:\Tools\upd.exe", 300, "8.8.8.8", 2, cNow.AddMinutes(-30), cNow.AddMinutes(-5), kind: "app") },
    cInv,
    new() { new BlockContainmentVerifier.LiveSocket { Pid = 300, RemoteIp = "8.8.8.8", RemotePort = 443,
             ProcessName = "upd.exe", ProcessStartedUtc = cT0.AddHours(1) } },
    new());
Check("containment: leak sorts before contained regardless of attempts",
      cV10.Count == 2 && cV10[0].Verdict == BlockContainmentVerifier.Leak && cV10[0].Pid == 300,
      cV10.Count == 2 ? $"{cV10[0].Verdict} pid={cV10[0].Pid}" : $"count={cV10.Count}");

var cApp = cInv[2];
Check("app match: exact path (case-insensitive)",
      BlockContainmentVerifier.IsAppBlockMatch(cApp, @"c:\tools\UPD.exe"));
Check("app match: sibling path by exe name",
      BlockContainmentVerifier.IsAppBlockMatch(cApp, @"C:\Tools\v2\upd.exe"));
Check("app match: different exe never matches",
      !BlockContainmentVerifier.IsAppBlockMatch(cApp, @"C:\Tools\upd2.exe"));

// WorstForTarget — the Blocks tab's per-row roll-up
var cInsts = new List<BlockContainmentVerifier.Instance>
{
    new() { Image = @"C:\Tools\chrome.exe", Pid = 100, Verdict = BlockContainmentVerifier.Contained,
            BlockedIps = new() { "1.2.3.4" } },
    new() { Image = @"C:\Tools\upd.exe", Pid = 200, Verdict = BlockContainmentVerifier.Leak,
            BlockedIps = new() { "1.2.3.4" } },
    new() { Image = @"C:\Tools\upd.exe", Pid = 210, Verdict = BlockContainmentVerifier.StaleFlow,
            BlockedIps = new() { "5.6.7.8" } },
};
var cW1 = BlockContainmentVerifier.WorstForTarget(cInsts, "ip", "1.2.3.4");
Check("roll-up: leak outranks contained for the same IP",
      cW1 != null && cW1.Verdict == BlockContainmentVerifier.Leak && cW1.Pid == 200,
      cW1?.Verdict ?? "null");
var cW2 = BlockContainmentVerifier.WorstForTarget(cInsts, "proc", @"C:\Tools\v2\upd.exe");
Check("roll-up: app target matches sibling path by basename",
      cW2 != null && cW2.Verdict == BlockContainmentVerifier.Leak, cW2?.Verdict ?? "null");
Check("roll-up: untouched target is quiet (null)",
      BlockContainmentVerifier.WorstForTarget(cInsts, "ip", "9.9.9.9") == null);

// QuietTargets — the engine-owned quiet roll-up (the rule the bridge tool
// applies; disabled rules are never listed because there is nothing to verify)
var qInv = new List<BlockedTarget>
{
    new() { Target = "5.6.7.8", Kind = "ip", Ip = "5.6.7.8", Rules = 2, EnabledRules = 2 },
    new() { Target = "9.9.9.9", Kind = "ip", Ip = "9.9.9.9", Rules = 2, EnabledRules = 2 },
    new() { Target = @"C:\Tools\upd.exe", Kind = "app", AppPath = @"C:\Tools\upd.exe", Rules = 1, EnabledRules = 1 },
    new() { Target = "7.7.7.7", Kind = "ip", Ip = "7.7.7.7", Rules = 2, EnabledRules = 0 }, // paused
};
var quietTargets = BlockContainmentVerifier.QuietTargets(qInv, cInsts);
Check("quiet: hit ip is not quiet", quietTargets.All(t => t.Ip != "5.6.7.8"));
Check("quiet: app-blocked image (sibling path) is not quiet",
      quietTargets.All(t => !BlockContainmentVerifier.IsAppBlockMatch(t, @"C:\Tools\v2\upd.exe")));
Check("quiet: untouched enabled ip is quiet; paused rule never listed",
      quietTargets.Any(t => t.Ip == "9.9.9.9") && quietTargets.All(t => t.Ip != "7.7.7.7"));

// ─────────────────────────────────────────────────────────────────────
// 4. AuditTrail — the Audit tab's grouping + language. Synthetic lines
//    only (the same format AppendEvent writes); nothing opens the real
//    %LOCALAPPDATA% event log.
// ─────────────────────────────────────────────────────────────────────
var auditT0 = DateTime.UtcNow;
string AuditLine(int sec, string action, string kind, string key, string detail, string origin) =>
    $"{auditT0.AddSeconds(sec):O}|{action}|{kind}|{key}|{detail}|{origin}";

var auditLines = new List<string>
{
    "garbage line with no pipes",
    AuditLine(0,  "created", "ip",   "1.2.3.4",    "wuauserv/Microsoft/Azure",        "monitor"),
    AuditLine(2,  "created", "ip",   "5.6.7.8",    "cryptsvc/Akamai (MS CDN)",        "monitor"),
    AuditLine(4,  "created", "proc", @"C:\P\m.exe","msmpeng/Windows Defender",         "monitor"),
    AuditLine(600,"created", "ip",   "9.9.9.9",    "netprofm/Unclassified",           "monitor"),  // 10 min later: new incident
    AuditLine(610,"paused",  "-",    "-",          "162 target(s) via restore-guide", "restore-guide"),
    AuditLine(700,"resumed", "-",    "-",          "23 target(s) via blocks-tab",     "blocks-tab"),
    AuditLine(800,"fleet-disabled", "-", "-",      "490/500 rule(s) disabled",        "panic-button"),
    AuditLine(900,"fleet-enabled",  "-", "-",      "565/565 rule(s) re-enabled",      "manage-all"),
    AuditLine(950,"rule-toggled","-", "AC-BLOCK-APP bash.exe (Out)", "disabled",     "firewall-tab"),
    AuditLine(960,"external-modified","app","bash.exe","disabled by wf.msc; restored","os-audit"),
    AuditLine(970,"removed", "ip",   "142.251.210.131","cryptsvc/after 03d 13h 38m",  "monitor"),
};

int auditParsed = auditLines.Count(l => AuditTrail.ParseLine(l) != null);
Check("audit: parse skips garbage, keeps all 11", auditParsed == 11, $"{auditParsed}");

var incidents = AuditTrail.BuildIncidents(
    auditLines.Select(AuditTrail.ParseLine).Where(e => e != null));

// grouping: [burst of 3] [burst of 1] [paused] [resumed] [fleet] [fleet] [toggled] [external] [removed]
Check("audit: 9 incidents from 11 events", incidents.Count == 9, $"{incidents.Count}");
var burst = incidents[0];
Check("audit: monitor burst collapses with per-kind counts",
      burst.Count == 3 && burst.KindCounts["ip"] == 2 && burst.KindCounts["proc"] == 1,
      $"count={burst.Count}");
Check("audit: burst sentence says addresses and programs",
      burst.Sentence.Contains("2 addresses") && burst.Sentence.Contains("1 program"),
      burst.Sentence);
Check("audit: burst meta carries the owning service key", burst.Meta.Contains("wuauserv"), burst.Meta);

var pause = incidents.First(i => i.EventsAction == "paused");
Check("audit: bulk pause counts targets from the detail line",
      pause.Count == 162 && pause.Sentence.Contains("162"), pause.Sentence);
Check("audit: restore-guide pause names the actor, not 'You'",
      pause.Sentence.StartsWith("The restore guide"), pause.Sentence);

var panic = incidents.First(i => i.EventsAction == "fleet-disabled");
Check("audit: panic stands alone and says who pressed it",
      panic.Category == "fleet" && panic.Severity == "resolved" &&
      panic.Sentence.Contains("panic button"), panic.Sentence);
var reen = incidents.First(i => i.EventsAction == "fleet-enabled");
Check("audit: re-enable-all is its own incident", reen.Count == 1 && !ReferenceEquals(reen, panic));

var toggle = incidents.First(i => i.EventsAction == "rule-toggled");
Check("audit: manual rule toggle reads as a sentence",
      toggle.Category == "pause" && toggle.Sentence.Contains("bash.exe") &&
      toggle.Sentence.Contains("OFF"), toggle.Sentence);

var ext = incidents.First(i => i.EventsAction == "external-modified");
Check("audit: external change restored is 'resolved', not 'attention'",
      ext.Category == "external" && ext.Severity == "resolved", ext.Severity);
Check("audit: unrestored external change would be 'attention'",
      AuditTrail.SeverityOf("external-modified", "disabled by netsh") == "attention");

var gone = incidents.First(i => i.EventsAction == "removed");
Check("audit: expiry sentence names the target",
      gone.Sentence.Contains("142.251.210.131"), gone.Sentence);

// update-mode sessions narrate as fleet incidents with the actor the
// Audit tab shows ("you · Windows Update")
var uo = AuditTrail.ParseLine($"{auditT0.AddSeconds(2000):O}|update-opened|-|-|78 target(s) lifted, hard stop 22:00|update-mode");
var ur = AuditTrail.ParseLine($"{auditT0.AddSeconds(2010):O}|update-restored|-|-|78/78 target(s) restored · verified on|update-mode");
Check("audit: update events parse", uo != null && ur != null);
var uInc = AuditTrail.BuildIncidents(new[] { uo, ur }.Where(e => e != null));
Check("audit: update session collapses to one fleet incident, resolved",
      uInc.Count == 1 && uInc[0].Category == "fleet" && uInc[0].Severity == "resolved",
      $"{uInc.Count} incident(s)");
Check("audit: update sentences read as a session",
      uInc[0].Sentence.Contains("updated Windows") && uInc[0].Sentence.Contains("78") &&
      uInc[0].Sentence.Contains("restored"),
      uInc[0].Sentence);
Check("audit: update actor names the tab, not a mystery",
      AuditTrail.ActorFor("update-mode") == "you · Windows Update",
      AuditTrail.ActorFor("update-mode"));

Check("audit: every incident has a day header", incidents.All(i => i.DayHeader.Length > 0));
string auditMarker = Path.Combine(Path.GetTempPath(), "audit-seen-" + Guid.NewGuid().ToString("N"));
try
{
    Check("audit: unseen marker reads MinValue", AuditTrail.ReadSeenUtc(auditMarker) == DateTime.MinValue);
    AuditTrail.MarkSeenUtc(auditMarker, auditT0);
    Check("audit: marker round-trips UTC", AuditTrail.ReadSeenUtc(auditMarker) == auditT0);
}
finally { try { File.Delete(auditMarker); } catch { } }

// ─────────────────────────────────────────────────────────────────────
// 7. MatchesAppTarget — the unblock family semantics. AppBlockCoverage-
//    Service keeps a name-blocked exe blocked at every path it runs from,
//    so a single-path unblock that leaves a sibling rule resurrects the
//    block on the exe's next run (observed live 2026-10-30: bash.exe
//    unblocked at 20:17, re-extended by the Git\bin sibling at 20:20, six
//    duplicate rules from unserialized concurrent adds).
// ─────────────────────────────────────────────────────────────────────
var acNaming = AutoCommand.Engines.Firewall.Naming.autocommand();
bool M(string ruleName, string ruleApp, string target) =>
    AutoCommand.Engines.Firewall.FirewallService.MatchesAppTarget(acNaming, ruleName, ruleApp, target);

Check("match: exact path covered", M("AC-BLOCK-APP bash.exe (Out)", @"C:\Program Files\Git\usr\bin\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: case-insensitive path", M("AC-BLOCK-APP bash.exe (Out)", @"C:\Program Files\Git\USR\bin\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: '..' path normalizes to the same image",
      M("AC-BLOCK-APP bash.exe (Out)", @"C:\Program Files\Git\usr\lib\..\bin\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: sibling path — same exe NAME, different dir (the resurrection leg)",
      M("AC-BLOCK-APP bash.exe (Out) · 63746dcd", @"C:\Program Files\Git\bin\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: legacy family prefix honored",
      M("AutoCommand Process Block - bash.exe (Outbound Block)", @"C:\old\path\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: different exe name is NOT the family",
      !M("AC-BLOCK-APP sh.exe (Out)", @"C:\Program Files\Git\usr\bin\sh.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: non-family rule name never matches",
      !M("Google Update (Out)", @"C:\Program Files\Git\usr\bin\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: family rule with empty ApplicationName never matches a path",
      !M("AC-BLOCK-APP bash.exe (Out)", "", @"C:\Program Files\Git\usr\bin\bash.exe"));
Check("match: device-path form falls back to leaf-name family match",
      M("AC-BLOCK-APP bash.exe (Out)", @"\Device\HarddiskVolume3\Program Files\Git\usr\bin\bash.exe", @"C:\Program Files\Git\usr\bin\bash.exe"));

// The store-side half of family unblock: sibling-path records must go with
// the exact-key one, or the Blocked list keeps showing the exe.
var famDir = Path.Combine(Path.GetTempPath(), "contain-selftest-" + Guid.NewGuid().ToString("N"));
try
{
    var fam = new BlocksLedger(famDir);
    fam.AddOrUpdate(new BlockRecord { Kind = "proc", Key = @"C:\Program Files\Git\usr\bin\bash.exe", Origin = "monitor" });
    fam.AddOrUpdate(new BlockRecord { Kind = "proc", Key = @"C:\Program Files\Git\bin\bash.exe", Origin = "reconcile" });
    fam.AddOrUpdate(new BlockRecord { Kind = "proc", Key = @"C:\Windows\System32\smartscreen.exe", Origin = "monitor" });
    fam.AddOrUpdate(new BlockRecord { Kind = "ip", Key = "142.251.214.99", Origin = "monitor" });
    int removedRecs = fam.RemoveForExeName("bash.exe");
    Check("store: family remove drops every path record of the exe",
          removedRecs == 2 && fam.Records.Count == 2 &&
          fam.Records.Any(r => r.Key == @"C:\Windows\System32\smartscreen.exe") &&
          fam.Records.Any(r => r.IsIp), $"gone={removedRecs}, left={fam.Records.Count}");
    Check("store: family remove logs one family event",
          File.ReadAllText(fam.EventLogPath).Contains("family · 2 record(s)"));
    Check("store: family remove of an unknown exe is a no-op", fam.RemoveForExeName("nope.exe") == 0);
}
finally { try { Directory.Delete(famDir, true); } catch { } }

// ─────────────────────────────────────────────────────────────────────
// 8. CountRedundantDuplicates — the quota-aware duplicate definition.
//    Distinct shapes (TCP+UDP per IP, the paths of a name family) never
//    count; only exact identity repeats do.
// ─────────────────────────────────────────────────────────────────────
int D(params string[] ids) => AutoCommand.Engines.Firewall.FirewallService.CountRedundantDuplicates(ids);

Check("dup: v2 quota shape (TCP+UDP) is not a duplicate",
      D("AC-BLOCK-IP 1.2.3.4 (TCP Out)", "AC-BLOCK-IP 1.2.3.4 (UDP Out)") == 0);
Check("dup: same name twice counts one redundant",
      D("AC-BLOCK-APP bash.exe (Out)", "AC-BLOCK-APP bash.exe (Out)") == 1);
Check("dup: six race-era copies count five redundant",
      D(Enumerable.Repeat("AC-BLOCK-APP bash.exe (Out)", 6).ToArray()) == 5);
Check("dup: app identity includes the path — family paths are not dups",
      D("AC-BLOCK-APP x.exe (Out)|C:\\a\\x.exe", "AC-BLOCK-APP x.exe (Out)|C:\\b\\x.exe") == 0);
Check("dup: same name + same path is one redundant",
      D("AC-BLOCK-APP x.exe (Out)|C:\\a\\x.exe", "AC-BLOCK-APP x.exe (Out)|C:\\a\\x.exe") == 1);
Check("dup: mixed identities sum per-identity redundants",
      D("n", "n", "m", "m", "m") == 3);
Check("dup: empty input is clean", D(Array.Empty<string>()) == 0);

// ─────────────────────────────────────────────────────────────────────
// 9. AppBlockCoverageService.EnumerateDiskCopies — the proactive disk
//    sweep's pure half: which on-disk copies of a name-blocked exe
//    deserve a sibling rule before anything spawns. Real firewall
//    untouched; roots injected so everything stays inside a temp tree
//    ("upd.exe" is not in the known-multi-root map).
// ─────────────────────────────────────────────────────────────────────
string sweepDir = Path.Combine(Path.GetTempPath(), "contain-selftest-" + Guid.NewGuid().ToString("N"));
try
{
    // versioned layout: Application\157.0.4341.42 covered, 158.0.9999.1 not yet
    string appRoot = Path.Combine(sweepDir, "Application");
    string v157 = Path.Combine(appRoot, "157.0.4341.42");
    string v158 = Path.Combine(appRoot, "158.0.9999.1");
    Directory.CreateDirectory(v157);
    Directory.CreateDirectory(v158);
    File.WriteAllText(Path.Combine(v157, "upd.exe"), "x");
    File.WriteAllText(Path.Combine(v158, "upd.exe"), "x");

    // a second install root: a flat copy plus a one-level (versioned) copy
    string altRoot = Path.Combine(sweepDir, "AltRoot");
    Directory.CreateDirectory(Path.Combine(altRoot, "embedded"));
    File.WriteAllText(Path.Combine(altRoot, "upd.exe"), "x");
    File.WriteAllText(Path.Combine(altRoot, "embedded", "upd.exe"), "x");

    string covered = Path.Combine(v157, "upd.exe");
    var copies = AppBlockCoverageService.EnumerateDiskCopies("upd.exe", new[] { covered }, new[] { altRoot });
    Check("sweep: next version folder found before it ever runs",
          copies.Contains(Path.Combine(v158, "upd.exe")), string.Join("; ", copies));
    Check("sweep: second-root direct copy found",
          copies.Contains(Path.Combine(altRoot, "upd.exe")));
    Check("sweep: second-root one-level copy found",
          copies.Contains(Path.Combine(altRoot, "embedded", "upd.exe")));
    Check("sweep: already-covered path not re-proposed", !copies.Contains(covered));

    // a non-version anchor must never fan out to sibling folders
    string toolsDir = Path.Combine(sweepDir, "Tools");
    Directory.CreateDirectory(toolsDir);
    File.WriteAllText(Path.Combine(toolsDir, "upd.exe"), "x");
    var nonVersion = AppBlockCoverageService.EnumerateDiskCopies(
        "upd.exe", new[] { Path.Combine(toolsDir, "upd.exe") }, Array.Empty<string>());
    Check("sweep: non-version anchor scans nothing drive-wide", nonVersion.Count == 0,
          string.Join("; ", nonVersion));
}
finally { try { Directory.Delete(sweepDir, true); } catch { } }

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL CONTAIN SELF-TESTS PASSED" : $"{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;
