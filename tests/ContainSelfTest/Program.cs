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

// ─────────────────────────────────────────────────────────────────────
// 10. BlockGuard — the kernel/critical image gate. Born from a live
//     AC-BLOCK-APP System rule (program literally "System"); pure leaf
//     matching, both bare names and full paths.
// ─────────────────────────────────────────────────────────────────────
BlockGuard.Decision G(string subject, out string guardText) => BlockGuard.Decide(subject, out guardText);

Check("guard: bare 'System' is refused (the PID 4 incident)",
      G("System", out var t1) == BlockGuard.Decision.Refuse && t1.Contains("kernel"), t1?.Split('\n')[0]);
Check("guard: 'system' case-insensitive",
      G("system", out _) == BlockGuard.Decision.Refuse);
Check("guard: 'Idle' and 'Registry' refused too",
      G("Idle", out _) == BlockGuard.Decision.Refuse && G("registry", out _) == BlockGuard.Decision.Refuse);
Check("guard: lsass warned, never silently allowed",
      G(@"C:\Windows\System32\lsass.exe", out var t2) == BlockGuard.Decision.Warn && t2.Contains("domain"));
Check("guard: ordinary process allowed with no text",
      G(@"C:\Tools\upd.exe", out var t3) == BlockGuard.Decision.Allow && string.IsNullOrEmpty(t3));
Check("guard: empty subject allowed (nothing to mistake)",
      G("", out _) == BlockGuard.Decision.Allow);

// ─────────────────────────────────────────────────────────────────────
// 11. FirewallService toggle-target parity — every IP and app rule shape
//     that GetBlockedInventoryAsync surfaces must match when turning
//     blocking OFF and back ON (ParseIpTarget / NormalizeAppPath /
//     MatchesToggleTarget, offline and COM-free).
// ─────────────────────────────────────────────────────────────────────
{
    var toggleAcNaming = AutoCommand.Engines.Firewall.Naming.autocommand();
    var toggleAsNaming = AutoCommand.Engines.Firewall.Naming.autoscope();

    Check("toggle-ip: v2 TCP rule parses and matches exact IP",
          AutoCommand.Engines.Firewall.FirewallService.ParseIpTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.4 (TCP Out)") == "1.2.3.4" &&
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.4 (TCP Out)", true, "", "ip", "1.2.3.4"));
    Check("toggle-ip: legacy outbound rule parses and matches",
          AutoCommand.Engines.Firewall.FirewallService.ParseIpTarget(toggleAcNaming, "AutoCommand IP Block - 1.2.3.4 (TCP Outbound Block)") == "1.2.3.4" &&
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(toggleAcNaming, "AutoCommand IP Block - 1.2.3.4 (TCP Outbound Block)", true, "", "ip", "1.2.3.4"));
    Check("toggle-ip: suffix-less IP rule (no trailing '(') matches",
          AutoCommand.Engines.Firewall.FirewallService.ParseIpTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.4") == "1.2.3.4" &&
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.4", true, "", "ip", "1.2.3.4"));
    Check("toggle-ip: dedup-quarantined suffix strips cleanly",
          AutoCommand.Engines.Firewall.FirewallService.ParseIpTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.4 · dedup-20261111-1") == "1.2.3.4");
    Check("toggle-ip: adopted prefix under autoscope naming matches",
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(toggleAsNaming, "AT-BLOCK-IP 9.8.7.6", true, "", "ip", "9.8.7.6"));
    Check("toggle-ip: prefix collision 1.2.3.4 vs 1.2.3.40 rejected",
          !AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.40 (TCP Out)", true, "", "ip", "1.2.3.4"));
    Check("toggle-ip: kind mismatch (proc target against IP rule) rejected",
          !AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(toggleAcNaming, "AC-BLOCK-IP 1.2.3.4 (TCP Out)", true, "", "proc", "1.2.3.4"));

    string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
    string svchostExpanded = Path.Combine(sysRoot, "System32", "svchost.exe");
    Check("toggle-app: %SystemRoot% rule matches expanded C:\\Windows target",
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(
              toggleAcNaming, "AC-BLOCK-APP svchost.exe (Out)", false, @"%SystemRoot%\System32\svchost.exe", "proc", svchostExpanded));
    Check("toggle-app: '..' path segments normalize to same target",
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(
              toggleAcNaming, "AC-BLOCK-APP app.exe (Out)", false, @"C:\Program Files\Vendor\Sub\..\app.exe", "proc", @"c:\program files\vendor\app.exe"));
    Check("toggle-app: empty ApplicationName falls back to rule name",
          AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(
              toggleAcNaming, "AC-BLOCK-APP orphan.exe (Out)", false, "", "proc", "AC-BLOCK-APP orphan.exe (Out)"));
    Check("toggle-app: unrelated executable rejected",
          !AutoCommand.Engines.Firewall.FirewallService.MatchesToggleTarget(
              toggleAcNaming, "AC-BLOCK-APP a.exe (Out)", false, @"C:\Tools\a.exe", "proc", @"C:\Tools\b.exe"));
}

// ─────────────────────────────────────────────────────────────────────
// 12. O(1) rule lookup & single-pass multi-prefix matching — ensures
//     AddIpBlock / AddAppBlock never enumerate the full COM rules table
//     on hits or misses, and fallback enumeration short-circuits.
// ─────────────────────────────────────────────────────────────────────
{
    var r1 = new FakeFwRule { Name = "AC-BLOCK-IP 1.2.3.4 (TCP Out)" };
    var r2 = new FakeFwRule { Name = "AC-BLOCK-IP 1.2.3.4 (UDP Out)" };
    var r3 = new FakeFwRule { Name = "Trailing Rule" };

    var directHit = new FakeFwRules(new[] { r1, r2, r3 }, mode: "normal");
    var found = AutoCommand.Engines.Firewall.FirewallService.FindRuleInCollection(
        directHit, "AC-BLOCK-IP 1.2.3.4 (UDP Out)");
    Check("find-rule: INetFwRules.Item hit returns rule with zero enumerations",
          ReferenceEquals(found, r2) && directHit.Enumerations == 0 && directHit.ElementsYielded == 0,
          $"enums={directHit.Enumerations}");

    var fileNotFoundMiss = new FakeFwRules(new[] { r1, r2 }, mode: "fnf");
    var missed1 = AutoCommand.Engines.Firewall.FirewallService.FindRuleInCollection(
        fileNotFoundMiss, "AC-BLOCK-IP 9.9.9.9 (TCP Out)");
    Check("find-rule: FileNotFoundException miss returns null with zero enumerations",
          missed1 == null && fileNotFoundMiss.Enumerations == 0,
          $"enums={fileNotFoundMiss.Enumerations}");

    var comNotFoundMiss = new FakeFwRules(new[] { r1, r2 }, mode: "com-fnf");
    var missed2 = AutoCommand.Engines.Firewall.FirewallService.FindRuleInCollection(
        comNotFoundMiss, "AC-BLOCK-IP 9.9.9.9 (TCP Out)");
    Check("find-rule: HRESULT 0x80070002 miss returns null with zero enumerations",
          missed2 == null && comNotFoundMiss.Enumerations == 0,
          $"enums={comNotFoundMiss.Enumerations}");

    var fallback = new FakeFwRules(new[] { r1, r2, r3 }, mode: "com-other");
    var fbFound = AutoCommand.Engines.Firewall.FirewallService.FindRuleInCollection(
        fallback, "AC-BLOCK-IP 1.2.3.4 (TCP Out)");
    Check("find-rule: unexpected COM error falls back to short-circuiting Seq.tryFind",
          ReferenceEquals(fbFound, r1) && fallback.Enumerations == 1 && fallback.ElementsYielded == 1,
          $"enums={fallback.Enumerations}, yielded={fallback.ElementsYielded}");

    // Multi-prefix IP unblock matcher (Own + Legacy + Adopted in one pass)
    var ipPrefixes = new[]
    {
        "AutoCommand IP Block - 1.2.3.4 (",
        "AC-BLOCK-IP 1.2.3.4 (",
        "AT-BLOCK-IP 1.2.3.4 ("
    };
    Check("prefix-match: matches v2, legacy and adopted prefixes in one set",
          AutoCommand.Engines.Firewall.FirewallService.MatchesAnyNamePrefix(ipPrefixes, "AC-BLOCK-IP 1.2.3.4 (TCP Out)") &&
          AutoCommand.Engines.Firewall.FirewallService.MatchesAnyNamePrefix(ipPrefixes, "AutoCommand IP Block - 1.2.3.4 (UDP Outbound Block)") &&
          AutoCommand.Engines.Firewall.FirewallService.MatchesAnyNamePrefix(ipPrefixes, "at-block-ip 1.2.3.4 (TCP Out)"));
    Check("prefix-match: rejects prefix-colliding IP 1.2.3.40",
          !AutoCommand.Engines.Firewall.FirewallService.MatchesAnyNamePrefix(ipPrefixes, "AC-BLOCK-IP 1.2.3.40 (TCP Out)"));

    // Case-insensitive duplicate accounting
    Check("dup: case-insensitive app path identity counts as redundant duplicate",
          D("AC-BLOCK-APP x.exe (Out)|C:\\Tools\\x.exe", "ac-block-app x.exe (out)|c:\\tools\\x.exe") == 1);
}

// ── 13. BlockHitFeedService case-insensitive IPv6 aggregation ─────────────
{
    var now = DateTime.UtcNow;
    var feed = new BlockHitFeedService(new[]
    {
        new BlockHitFeedService.BlockHit
        {
            TimeUtc = now.AddMinutes(-2),
            Image = @"C:\App\Tool.exe",
            Pid = 4242,
            DestIp = "2606:4700::ABCD",
            DestPort = 443,
            Protocol = "tcp",
            MatchKind = "ip"
        },
        new BlockHitFeedService.BlockHit
        {
            TimeUtc = now.AddMinutes(-1),
            Image = @"c:\app\tool.exe",
            Pid = 4242,
            DestIp = "2606:4700::abcd",
            DestPort = 443,
            Protocol = "tcp",
            MatchKind = "ip"
        }
    });
    var byIp = feed.FeedHitsByIp(60);
    Check("hit-feed: mixed-case IPv6 DestIp merges into one key",
          byIp.Count == 1 && byIp.TryGetValue("2606:4700::AbCd", out int hits) && hits == 2,
          $"keys={byIp.Count}");
    var aggs = feed.Aggregates(60);
    Check("hit-feed: mixed-case image/IPv6 aggregates into single rollup",
          aggs.Count == 1 && aggs[0].Count == 2,
          $"aggs={aggs.Count}");
}

// ── 14. O(1) single-target fast-path toggle, no-op write skip & Win32 owner ─
{
    var naming = AutoCommand.Engines.Firewall.Naming.autocommand();
    var ipTcp = new FakeFwRule { Name = "AC-BLOCK-IP 203.0.113.7 (TCP Out)", Enabled = false, Action = AutoCommand.Engines.Firewall.FwAction.Block };
    var ipUdp = new FakeFwRule { Name = "AC-BLOCK-IP 203.0.113.7 (UDP Out)", Enabled = false, Action = AutoCommand.Engines.Firewall.FwAction.Block };
    var appPath = @"C:\Vendor\Agent\Helper.exe";
    var appPrimary = new FakeFwRule
    {
        Name = "AC-BLOCK-APP Helper.exe (Out)",
        ApplicationName = appPath,
        Enabled = false,
        Action = AutoCommand.Engines.Firewall.FwAction.Block
    };
    var otherAppPath = @"D:\Alt\Agent\Helper.exe";
    var appSuffixed = new FakeFwRule
    {
        Name = FirewallService.SuffixedAppRuleName("Helper.exe", otherAppPath),
        ApplicationName = otherAppPath,
        Enabled = false,
        Action = AutoCommand.Engines.Firewall.FwAction.Block
    };

    var coll = new FakeFwRules(new[] { ipTcp, ipUdp, appPrimary, appSuffixed }, mode: "direct");

    // 2-rule v2 IP target toggles via O(1) Item(name) with zero enumerations
    var ipSnap = AutoCommand.Engines.Firewall.FirewallService.TryToggleSingleTargetInCollection(
        naming, coll, "ip", "203.0.113.7", 2, true);
    Check("fast-toggle: v2 2-rule IP enables in O(1) with zero enumerations",
          ipSnap != null && ipSnap.UsedFastPath && !ipSnap.IsFullSnapshot &&
          ipSnap.Matched == 2 && ipSnap.Changed == 2 && coll.Enumerations == 0 &&
          ipTcp.Enabled && ipUdp.Enabled && ipSnap.RuleStates.Count == 2,
          $"enums={coll.Enumerations}, changed={ipSnap?.Changed}");

    // Re-applying same state skips redundant BFE Enabled property writes
    ipTcp.EnabledSetterCount = 0;
    ipUdp.EnabledSetterCount = 0;
    var noopSnap = AutoCommand.Engines.Firewall.FirewallService.TryToggleSingleTargetInCollection(
        naming, coll, "ip", "203.0.113.7", 2, true);
    Check("fast-toggle: already-enabled rules skip redundant COM Enabled writes",
          noopSnap != null && noopSnap.Matched == 2 && noopSnap.Changed == 0 &&
          ipTcp.EnabledSetterCount == 0 && ipUdp.EnabledSetterCount == 0 && coll.Enumerations == 0,
          $"writes={ipTcp.EnabledSetterCount + ipUdp.EnabledSetterCount}");

    // Suffixed app rule resolves when primary belongs to a sibling path
    var appSnap = AutoCommand.Engines.Firewall.FirewallService.TryToggleSingleTargetInCollection(
        naming, coll, "proc", otherAppPath, 1, true);
    Check("fast-toggle: suffixed sibling app rule toggles without touching primary path",
          appSnap != null && appSnap.UsedFastPath && appSnap.Changed == 1 &&
          appSuffixed.Enabled && !appPrimary.Enabled && coll.Enumerations == 0,
          $"enums={coll.Enumerations}");

    // Incomplete rule match returns null with zero mutations so caller falls back safely
    var partialTcp = new FakeFwRule { Name = "AC-BLOCK-IP 198.51.100.9 (TCP Out)", Enabled = false, Action = AutoCommand.Engines.Firewall.FwAction.Block };
    partialTcp.EnabledSetterCount = 0;
    var partialColl = new FakeFwRules(new[] { partialTcp }, mode: "direct");
    var missSnap = AutoCommand.Engines.Firewall.FirewallService.TryToggleSingleTargetInCollection(
        naming, partialColl, "ip", "198.51.100.9", 2, true);
    Check("fast-toggle: partial rule set returns null without mutating matched half",
          missSnap == null && !partialTcp.Enabled && partialTcp.EnabledSetterCount == 0);

    // Win32 PROCESS_QUERY_LIMITED_INFORMATION socket owner lookup (<10 ms, zero WMI)
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var (procName, startedUtc) = BlockContainmentReader.QueryProcessOwner(Environment.ProcessId);
    sw.Stop();
    Check("win32-owner: QueryProcessOwner resolves current PID name & UTC start time without WMI",
          !string.IsNullOrEmpty(procName) && procName != "?" &&
          procName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
          startedUtc.HasValue && startedUtc.Value <= DateTime.UtcNow.AddMinutes(1) &&
          startedUtc.Value > DateTime.UtcNow.AddDays(-7),
          $"name={procName}, started={startedUtc}, ms={sw.ElapsedMilliseconds}");
}

// ---------------------------------------------------------------------------
// 15. Consolidated FirewallConfigManager coherence & ServiceHelper NRE guard
// ---------------------------------------------------------------------------
Console.WriteLine();
Console.WriteLine("== 15. Consolidated FirewallConfigManager & ServiceHelper ==");
{
    var tempDir = Path.Combine(Path.GetTempPath(), "ac-contain-tier3-" + Guid.NewGuid().ToString("N")[..8]);
    Directory.CreateDirectory(tempDir);
    var prevDefault = FirewallConfigManager.DefaultConfigPath;
    try
    {
        string sharedCfg = Path.Combine(tempDir, "firewall_config.json");
        FirewallConfigManager.DefaultConfigPath = sharedCfg;
        FirewallConfigManager.Instance.Load();

        var writerA = new FirewallConfigManager();
        writerA.SetOverride("Rule Alpha", false);
        var writerB = new FirewallConfigManager();
        writerB.SetOverride("Rule Beta", true);

        Check("fw-config: singleton Instance.RuleOverrides reflects non-singleton SetOverride immediately",
              FirewallConfigManager.Instance.GetOverride("Rule Alpha") == "False" &&
              FirewallConfigManager.Instance.GetOverride("Rule Beta") == "True");

        // Explicit isolated path does not pollute singleton Instance
        string isolatedCfg = Path.Combine(tempDir, "other_config.json");
        var isolated = new FirewallConfigManager(isolatedCfg);
        isolated.SetOverride("Rule Isolated", true);
        Check("fw-config: explicit configPath stays isolated from default Instance",
              FirewallConfigManager.Instance.GetOverride("Rule Isolated") == null);

        // ServiceHelper null-safe start-type resolution (prevents NRE when no backup record exists)
        Check("svc-helper: null recorded start type resolves safely to SERVICE_DEMAND_START",
              ServiceHelper.ResolveRestoreStartType(null) == ServiceHelper.SERVICE_DEMAND_START &&
              ServiceHelper.ResolveRestoreStartType("Manual") == ServiceHelper.SERVICE_DEMAND_START &&
              ServiceHelper.ResolveRestoreStartType("Auto") == ServiceHelper.SERVICE_AUTO_START &&
              ServiceHelper.ResolveRestoreStartType("auto") == ServiceHelper.SERVICE_AUTO_START);

        // Legacy ShieldsUp backup fallback + primary ProgramData precedence
        string legacyBackup = Path.Combine(tempDir, "legacy_backup.txt");
        string primaryBackup = Path.Combine(tempDir, "primary_backup.txt");
        File.WriteAllLines(legacyBackup, new[] { "RasMan=Auto", "IKEEXT=Manual" });
        File.WriteAllLines(primaryBackup, new[] { "IKEEXT=Auto" });
        var mergedMap = ServiceHelper.ReadBackupMapFromPaths(primaryBackup, legacyBackup);
        Check("svc-helper: legacy backup seeds missing keys while primary backup wins",
              mergedMap.TryGetValue("RasMan", out var ras) && ras == "Auto" &&
              mergedMap.TryGetValue("IKEEXT", out var ike) && ike == "Auto");
    }
    finally
    {
        FirewallConfigManager.DefaultConfigPath = prevDefault;
        FirewallConfigManager.Instance.Load();
        try { Directory.Delete(tempDir, recursive: true); } catch { }
    }
}

// ---------------------------------------------------------------------------
// 16. Restore-blocking read-back verification, COM VariantBool ABI & baseline sync
// ---------------------------------------------------------------------------
Console.WriteLine();
Console.WriteLine("== 16. Restore-blocking read-back, COM VariantBool ABI & baseline sync ==");
{
    // 16a. Pin explicit [MarshalAs(UnmanagedType.VariantBool)] on ComImport interfaces
    var fwAsm = typeof(AutoCommand.Engines.Firewall.Com).Assembly;
    foreach (string ifaceName in new[] { "AutoCommand.Engines.Firewall.NetFwRuleX", "AutoCommand.Engines.Firewall.NetFwRuleLegacy" })
    {
        var t = fwAsm.GetType(ifaceName, throwOnError: true, ignoreCase: false);
        var getEn = t.GetMethod("get_Enabled");
        var putEn = t.GetMethod("put_Enabled");
        var retAttr = getEn?.ReturnParameter?.GetCustomAttributes(typeof(System.Runtime.InteropServices.MarshalAsAttribute), false)
            .Cast<System.Runtime.InteropServices.MarshalAsAttribute>().FirstOrDefault();
        var valAttr = putEn?.GetParameters().FirstOrDefault()?.GetCustomAttributes(typeof(System.Runtime.InteropServices.MarshalAsAttribute), false)
            .Cast<System.Runtime.InteropServices.MarshalAsAttribute>().FirstOrDefault();
        Check($"com-abi: {t.Name} get_Enabled/put_Enabled carry VariantBool marshaling",
              retAttr?.Value == System.Runtime.InteropServices.UnmanagedType.VariantBool &&
              valAttr?.Value == System.Runtime.InteropServices.UnmanagedType.VariantBool);
    }

    var naming = AutoCommand.Engines.Firewall.Naming.autocommand();

    // 16b. Fast-path read-back verification when firewall silently refuses Enabled flip
    var lockedTcp = new FakeFwRule
    {
        Name = "AC-BLOCK-IP 203.0.113.99 (TCP Out)",
        Enabled = false,
        RefuseEnableWrites = true,
        Action = AutoCommand.Engines.Firewall.FwAction.Block
    };
    var lockedUdp = new FakeFwRule
    {
        Name = "AC-BLOCK-IP 203.0.113.99 (UDP Out)",
        Enabled = false,
        RefuseEnableWrites = true,
        Action = AutoCommand.Engines.Firewall.FwAction.Block
    };
    var lockedColl = new FakeFwRules(new[] { lockedTcp, lockedUdp }, mode: "direct");
    var lockedFast = AutoCommand.Engines.Firewall.FirewallService.TryToggleSingleTargetInCollection(
        naming, lockedColl, "ip", "203.0.113.99", 2, true);
    Check("restore-verify: fast path detects silent BFE non-persistence (Changed=0, FirstError set, RuleStates=false)",
          lockedFast != null && lockedFast.Matched == 2 && lockedFast.Changed == 0 &&
          !string.IsNullOrEmpty(lockedFast.FirstError) &&
          lockedFast.RuleStates.All(rs => !rs.Item2));

    // 16c. SetTargetsEnabledSnapshotAsync & SetAllBlocksEnabledSnapshotAsync never report
    // optimistic EnabledRules>0 in Inventory when firewall kept rules disabled
    var fakePolicy = new FakeFwPolicy2(lockedColl);
    var svc = new AutoCommand.Engines.Firewall.FirewallService(naming, () => fakePolicy);
    var lockedBulk = await svc.SetTargetsEnabledSnapshotAsync(
        new[] { ("ip", "203.0.113.99") }, true, true, null);
    Check("restore-verify: bulk snapshot Inventory keeps EnabledRules=0 when BFE refuses enable",
          lockedBulk.Matched == 2 && lockedBulk.Changed == 0 &&
          !string.IsNullOrEmpty(lockedBulk.FirstError) &&
          lockedBulk.Inventory != null && lockedBulk.Inventory.Count == 1 &&
          lockedBulk.Inventory[0].EnabledRules == 0);

    var lockedFleet = await svc.SetAllBlocksEnabledSnapshotAsync(true, false, true, null);
    Check("restore-verify: fleet snapshot Inventory keeps EnabledRules=0 when BFE refuses enable",
          lockedFleet.Matched == 2 && lockedFleet.Changed == 0 &&
          !string.IsNullOrEmpty(lockedFleet.FirstError) &&
          lockedFleet.Inventory != null && lockedFleet.Inventory[0].EnabledRules == 0);

    // Unlock and confirm restore flips both rules and updates Inventory EnabledRules=2
    lockedTcp.RefuseEnableWrites = false;
    lockedUdp.RefuseEnableWrites = false;
    var okBulk = await svc.SetTargetsEnabledSnapshotAsync(
        new[] { ("ip", "203.0.113.99") }, true, true, null);
    Check("restore-verify: unlocked bulk restore flips both rules and Inventory EnabledRules=2",
          okBulk.Matched == 2 && okBulk.Changed == 2 && string.IsNullOrEmpty(okBulk.FirstError) &&
          okBulk.Inventory != null && okBulk.Inventory[0].EnabledRules == 2 &&
          lockedTcp.Enabled && lockedUdp.Enabled);

    // 16d. Case-preserving rule name capture on fast path + re-block re-enables paused rules
    var mixedApp = new FakeFwRule
    {
        Name = "AC-BLOCK-APP Upd.exe (Out)",
        ApplicationName = @"C:\Tools\Upd.exe",
        Enabled = false,
        Action = AutoCommand.Engines.Firewall.FwAction.Block
    };
    var mixedColl = new FakeFwRules(new[] { lockedTcp, lockedUdp, mixedApp }, mode: "direct");
    var mixedFast = AutoCommand.Engines.Firewall.FirewallService.TryToggleSingleTargetInCollection(
        naming, mixedColl, "proc", @"c:\tools\upd.exe", 1, true);
    Check("restore-verify: fast path resolves lowercase store key and records actual COM r.Name casing",
          mixedFast != null && mixedFast.Changed == 1 && mixedApp.Enabled &&
          mixedFast.RuleStates.Count == 1 &&
          mixedFast.RuleStates[0].Item1 == "AC-BLOCK-APP Upd.exe (Out)" &&
          mixedFast.RuleStates[0].Item2);

    // Re-blocking an existing paused rule via AddIpBlockAsync / AddAppBlockAsync re-enables it
    lockedTcp.Enabled = false;
    lockedUdp.Enabled = false;
    mixedApp.Enabled = false;
    var mixedSvc = new AutoCommand.Engines.Firewall.FirewallService(naming, () => new FakeFwPolicy2(mixedColl));
    var (_, ipUpdated) = await mixedSvc.AddIpBlockAsync("203.0.113.99", "[blocked] refresh");
    var (_, appUpdated) = await mixedSvc.AddAppBlockAsync(@"C:\Tools\Upd.exe", "[blocked] refresh");
    Check("reblock-paused: AddIpBlockAsync and AddAppBlockAsync re-enable existing paused rules",
          ipUpdated == 2 && appUpdated == 1 && lockedTcp.Enabled && lockedUdp.Enabled && mixedApp.Enabled);

    // 16e. FirewallBaselineLogic case-insensitive JSON map normalization, adoption & drift check
    var rawJsonMap = new System.Collections.Generic.Dictionary<string, bool>(StringComparer.Ordinal)
    {
        ["AC-BLOCK-APP Upd.exe (Out)"] = false,
        ["Core Networking - DNS (UDP-Out)"] = true
    };
    var baselineRules = FirewallBaselineLogic.CreateRulesMap(rawJsonMap);
    bool baselineDirty = FirewallBaselineLogic.ApplyOwnBlockStates(
        baselineRules,
        new[] { ("AC-BLOCK-APP upd.exe (Out)", true) },
        isFullSnapshot: false);
    var drift = FirewallBaselineLogic.EvaluateDrift(
        baselineRules,
        new[]
        {
            ("AC-BLOCK-APP Upd.exe (Out)", true, ""),
            ("Core Networking - DNS (UDP-Out)", true, "@FirewallAPI.dll,-25000")
        });
    Check("baseline-sync: mixed-case fast-path adoption updates existing entry in place with zero false ReEnabled drift",
          baselineDirty && baselineRules.Count == 2 &&
          baselineRules.TryGetValue("AC-BLOCK-APP Upd.exe (Out)", out bool adoptedState) && adoptedState &&
          drift.ReEnabled.Count == 0 && drift.UnexpectedlyDisabled.Count == 0 && drift.SneakedIn.Count == 0);

    // Full snapshot prunes retired own-block rules while keeping non-AutoCommand baseline entries intact
    bool pruneDirty = FirewallBaselineLogic.ApplyOwnBlockStates(
        baselineRules,
        Array.Empty<(string Name, bool Enabled)>(),
        isFullSnapshot: true);
    Check("baseline-sync: full snapshot prunes deleted own-block rules without touching Windows rules",
          pruneDirty && baselineRules.Count == 1 && baselineRules.ContainsKey("Core Networking - DNS (UDP-Out)"));
}

// ---------------------------------------------------------------------------
// 17. Zero-scan new-block fast path (seeded own-rule index + COM miss HResults)
// ---------------------------------------------------------------------------
Console.WriteLine();
Console.WriteLine("== 17. Zero-scan new-block fast path ==");
{
    var naming = AutoCommand.Engines.Firewall.Naming.autocommand();

    // 17a. TYPE_E_ELEMENTNOTFOUND (0x8002802B) & ERROR_NOT_FOUND (0x80070490) return null with 0 enumerations
    var elemMissColl = new FakeFwRules(new[] { new FakeFwRule { Name = "Other" } }, mode: "com-elem-nf");
    var elemMiss = AutoCommand.Engines.Firewall.FirewallService.FindRuleInCollection(elemMissColl, "AC-BLOCK-IP 198.51.100.1 (TCP Out)");
    Check("find-rule: TYPE_E_ELEMENTNOTFOUND (0x8002802B) returns null with 0 COM enumerations",
          elemMiss == null && elemMissColl.Enumerations == 0);

    // 17b. Seeded own-rule index skips Rules.Item completely on brand-new IP and process blocks
    var seededColl = new FakeFwRules(
        new[]
        {
            new FakeFwRule
            {
                Name = "AC-BLOCK-IP 203.0.113.10 (TCP Out)",
                Enabled = true,
                Action = AutoCommand.Engines.Firewall.FwAction.Block
            }
        },
        mode: "direct");
    var fastSvc = new AutoCommand.Engines.Firewall.FirewallService(
        naming,
        () => new FakeFwPolicy2(seededColl),
        () => new FakeFwRule());

    var initInv = await fastSvc.GetBlockedInventoryAsync();
    Check("new-block-fast: initial inventory seeds own-rule index in 1 enumeration",
          initInv.Count == 1 && seededColl.Enumerations == 1);

    int lookupsBeforeNewIp = seededColl.ItemLookups;
    int enumsBeforeNewIp = seededColl.Enumerations;
    var (ipCreated, ipUpdated, ipNames) = await fastSvc.AddIpBlockWithRulesAsync("198.51.100.77", "[blocked] new ip");
    Check("new-block-fast: brand-new IP block skips Rules.Item (0 ItemLookups, 0 Enumerations) and returns 2 rule names",
          ipCreated == 2 && ipUpdated == 0 &&
          seededColl.ItemLookups == lookupsBeforeNewIp &&
          seededColl.Enumerations == enumsBeforeNewIp &&
          ipNames != null && ipNames.Length == 2 &&
          ipNames.Contains("AC-BLOCK-IP 198.51.100.77 (TCP Out)") &&
          ipNames.Contains("AC-BLOCK-IP 198.51.100.77 (UDP Out)"));

    int lookupsBeforeNewApp = seededColl.ItemLookups;
    int enumsBeforeNewApp = seededColl.Enumerations;
    var (appCreated, appUpdated, appRuleName) = await fastSvc.AddAppBlockWithPathAsync(@"C:\Tools\BrandNew.exe", "[blocked] new app");
    Check("new-block-fast: brand-new process block skips Rules.Item (0 ItemLookups, 0 Enumerations) and returns primary rule name",
          appCreated == 1 && appUpdated == 0 &&
          seededColl.ItemLookups == lookupsBeforeNewApp &&
          seededColl.Enumerations == enumsBeforeNewApp &&
          appRuleName == "AC-BLOCK-APP BrandNew.exe (Out)");

    // 17c. Immediate re-block hits O(1) Item(name) and updates in place with zero duplicate rules
    int countBeforeReblock = seededColl.Count;
    var (reIpCreated, reIpUpdated, _) = await fastSvc.AddIpBlockWithRulesAsync("198.51.100.77", "[blocked] refresh ip");
    var (reAppCreated, reAppUpdated, _) = await fastSvc.AddAppBlockWithPathAsync(@"C:\Tools\BrandNew.exe", "[blocked] refresh app");
    Check("new-block-fast: immediate re-block updates existing rules in place with 0 duplicates and 0 enumerations",
          reIpCreated == 0 && reIpUpdated == 2 &&
          reAppCreated == 0 && reAppUpdated == 1 &&
          seededColl.Count == countBeforeReblock &&
          seededColl.Enumerations == enumsBeforeNewApp);

    // 17d. External deletion (wf.msc) self-heals ownRuleNames and recreates missing rule cleanly
    seededColl.Remove("AC-BLOCK-APP BrandNew.exe (Out)");
    var (healedCreated, healedUpdated, healedName) = await fastSvc.AddAppBlockWithPathAsync(@"C:\Tools\BrandNew.exe", "[blocked] recreated");
    Check("new-block-fast: externally deleted rule self-heals index and recreates rule cleanly",
          healedCreated == 1 && healedUpdated == 0 &&
          healedName == "AC-BLOCK-APP BrandNew.exe (Out)" &&
          seededColl.Count == countBeforeReblock);
}

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL CONTAIN SELF-TESTS PASSED" : $"{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;

internal sealed class FakeFwRule : AutoCommand.Engines.Firewall.INetFwRule
{
    private bool _enabled = true;
    public bool RefuseEnableWrites { get; set; }
    public int EnabledSetterCount { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string ApplicationName { get; set; } = "";
    public string ServiceName { get; set; } = "";
    public int Protocol { get; set; }
    public string LocalPorts { get; set; } = "";
    public string RemotePorts { get; set; } = "";
    public string LocalAddresses { get; set; } = "";
    public string RemoteAddresses { get; set; } = "";
    public string IcmpTypesAndCodes { get; set; } = "";
    public string InterfaceTypes { get; set; } = "All";
    public bool Enabled
    {
        get => _enabled;
        set
        {
            EnabledSetterCount++;
            if (!RefuseEnableWrites) _enabled = value;
        }
    }
    public string Grouping { get; set; } = "";
    public int Profiles { get; set; }
    public bool EdgeTraversal { get; set; }
    public AutoCommand.Engines.Firewall.FwRuleDirection Direction { get; set; }
    public AutoCommand.Engines.Firewall.FwAction Action { get; set; }
}

internal sealed class FakeFwPolicy2 : AutoCommand.Engines.Firewall.INetFwPolicy2
{
    private readonly AutoCommand.Engines.Firewall.INetFwRules _rules;
    public FakeFwPolicy2(AutoCommand.Engines.Firewall.INetFwRules rules) => _rules = rules;
    public int CurrentProfileTypes => 0x7FF;
    public AutoCommand.Engines.Firewall.INetFwRules Rules => _rules;
    public void RestoreLocalFirewallDefaults() { }
}

internal sealed class FakeFwRules : AutoCommand.Engines.Firewall.INetFwRules
{
    private readonly System.Collections.Generic.List<AutoCommand.Engines.Firewall.INetFwRule> _rules;
    private readonly string _mode;
    public int Enumerations { get; private set; }
    public int ElementsYielded { get; private set; }
    public int ItemLookups { get; private set; }

    public FakeFwRules(System.Collections.Generic.IReadOnlyList<AutoCommand.Engines.Firewall.INetFwRule> rules, string mode)
    {
        _rules = new System.Collections.Generic.List<AutoCommand.Engines.Firewall.INetFwRule>(rules);
        _mode = mode;
    }

    public int Count => _rules.Count;
    public void Add(AutoCommand.Engines.Firewall.INetFwRule rule)
    {
        if (rule != null) _rules.Add(rule);
    }
    public void Remove(string name)
    {
        _rules.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    public AutoCommand.Engines.Firewall.INetFwRule this[string name]
    {
        get
        {
            ItemLookups++;
            return _mode switch
            {
                "fnf" => throw new FileNotFoundException(),
                "com-fnf" => throw new System.Runtime.InteropServices.COMException("Not found", unchecked((int)0x80070002)),
                "com-elem-nf" => throw new System.Runtime.InteropServices.COMException("Element not found", unchecked((int)0x8002802B)),
                "com-other" => throw new System.Runtime.InteropServices.COMException("Provider quirk", unchecked((int)0x80004005)),
                _ => _rules.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))
                     ?? throw new FileNotFoundException()
            };
        }
    }

    public System.Collections.IEnumerator GetEnumerator()
    {
        Enumerations++;
        return Enumerate().GetEnumerator();
    }

    private System.Collections.Generic.IEnumerable<AutoCommand.Engines.Firewall.INetFwRule> Enumerate()
    {
        foreach (var r in _rules)
        {
            ElementsYielded++;
            yield return r;
        }
    }
}
