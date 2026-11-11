// WatchSelfTest — Spawn Watches pipeline, offline.
//
// Persistence is redirected to a temp dir (house pattern: the settable
// statics — SpawnWatchService.WatchesDirectory,
// SysmonArchiveService.ArchiveDirectory). Rules live in a temp
// SpawnWatchLibrary; the matcher is driven directly; the end-to-end
// section drives the REAL SysmonArchiveService.Append so the Appended
// hook, the consumer, the hits index and the replay dedupe are all the
// shipped code paths.

using AutoCommand.Agent.Core;
using AutoCommand.Models;

int failures = 0;
void Check(bool ok, string name)
{
    Console.WriteLine((ok ? "PASS  " : "FAIL  ") + name);
    if (!ok) failures++;
}

// Optional arg 1: root dir for the redirected persistence — for hosts
// whose %TEMP% is restricted. Default stays the house temp-dir pattern.
string tempRoot = args.Length > 0
    ? Path.Combine(args[0], "watch-selftest-" + Guid.NewGuid().ToString("N")[..8])
    : Path.Combine(Path.GetTempPath(), "watch-selftest-" + Guid.NewGuid().ToString("N")[..8]);
string watchesDir = Path.Combine(tempRoot, "watches");
string archiveDir = Path.Combine(tempRoot, "sysmon-archive");
SpawnWatchService.WatchesDirectory = watchesDir;
SysmonArchiveService.ArchiveDirectory = archiveDir;

try
{
    // ── wildcard matcher ─────────────────────────────────────────────
    Check(SpawnWatchService.WildcardMatches("svchost.exe", @"C:\Windows\System32\svchost.exe"),
          "wildcard: leaf-name match against full path");
    Check(SpawnWatchService.WildcardMatches("*.exe", @"C:\x\whatever.exe"),
          "wildcard: *.exe matches any exe");
    Check(SpawnWatchService.WildcardMatches(@"c:\windows\*\svchost.exe", @"C:\Windows\System32\svchost.exe"),
          "wildcard: mid-path star matches the full path");
    Check(SpawnWatchService.WildcardMatches("updater*", @"C:\Users\honey\AppData\Local\Google\GoogleUpdater\157.0\updater.exe"),
          "wildcard: prefix star matches leaf");
    Check(!SpawnWatchService.WildcardMatches("notepad.exe", @"C:\Windows\System32\svchost.exe"),
          "wildcard: different name does not match");
    Check(!SpawnWatchService.WildcardMatches("", @"C:\x\a.exe"),
          "wildcard: empty pattern never matches");

    // ── parent svchost -s service extraction ─────────────────────────
    Check(SpawnWatchService.ServiceKeyFromParentCommandLine(
              @"C:\Windows\system32\svchost.exe -k netsvcs -p -s usosvc") == "usosvc",
          "service key: -s token extracted");
    Check(SpawnWatchService.ServiceKeyFromParentCommandLine(
              @"C:\Windows\system32\svchost.exe -k netsvcs -p") == null,
          "service key: no -s token → null");
    Check(SpawnWatchService.ServiceKeyFromParentCommandLine("") == null,
          "service key: empty command line → null");

    // ── rule store (library seam — files are the interface) ─────────
    Directory.CreateDirectory(watchesDir);
    var lib = new SpawnWatchLibrary(watchesDir);
    Check(lib.SafeFileName("a/b:c*d").All(c => char.IsLetterOrDigit(c) || c == ' ' || c == '-' || c == '_'),
          "store: safe file name sanitizes separators");
    File.WriteAllText(Path.Combine(watchesDir, "allowlist.txt"),
        "# Spawn Watches allowlist\n\nTaskHostW.exe\r\ndllhost.exe\n");
    var allow = lib.LoadAllowlist();
    Check(allow.Count == 2 && allow[0] == "TaskHostW.exe",
          "store: allowlist skips comments and blanks, trims");

    var ruleA = new SpawnWatch
    {
        Name = "svc-children",
        MatchProcess = "*",
        MatchParent = "svchost.exe",
        MinusAllowlist = true,
    };
    lib.Save(ruleA);
    Check(lib.Load().Count == 1 && lib.Load()[0].Name == "svc-children",
          "store: save/load round-trip");

    // ── matching ─────────────────────────────────────────────────────
    ArchiveEvent Ev(int eid, string image, string parent, string parentCmd, string cmd, long rid) => new()
    {
        Eid = eid,
        RecordId = rid,
        TsUtc = DateTime.UtcNow.AddMinutes(-30).AddSeconds(rid),
        Data = new Dictionary<string, string>
        {
            ["Image"] = image,
            ["ParentImage"] = parent,
            ["ParentCommandLine"] = parentCmd,
            ["CommandLine"] = cmd,
            ["ProcessId"] = rid.ToString(),
        },
    };

    var svcCmd = @"C:\Windows\system32\svchost.exe -k netsvcs -p -s usosvc";

    Check(SpawnWatchService.MatchesAny(new List<SpawnWatch> { ruleA }, allow,
              Ev(1, @"C:\Windows\System32\whatever.exe", @"C:\Windows\system32\svchost.exe", svcCmd, "", 1),
              out var matched) && matched[0].Name == "svc-children",
          "match: any child of svchost matches the starter rule");
    Check(!SpawnWatchService.MatchesAny(new List<SpawnWatch> { ruleA }, allow,
              Ev(3, "anything", @"C:\Windows\system32\svchost.exe", svcCmd, "", 2),
              out _),
          "match: EID 3 (network) is never a spawn hit");
    Check(!SpawnWatchService.MatchesAny(new List<SpawnWatch> { ruleA }, allow,
              Ev(1, @"C:\Windows\System32\taskhostw.exe", @"C:\Windows\system32\svchost.exe", svcCmd, "", 3),
              out _),
          "match: minus-allowlist subtracts taskhostw.exe");

    var scoped = new SpawnWatch { Name = "usosvc only", MatchProcess = "*", MatchParent = "svchost.exe", ServiceKey = "usosvc" };
    Check(SpawnWatchService.MatchesAny(new List<SpawnWatch> { scoped }, null,
              Ev(1, @"C:\x\a.exe", @"C:\Windows\system32\svchost.exe", svcCmd, "", 4),
              out _),
          "match: service key scoping matches the right svchost");
    Check(!SpawnWatchService.MatchesAny(new List<SpawnWatch> { scoped }, null,
              Ev(1, @"C:\x\a.exe", @"C:\Windows\system32\svchost.exe",
                 @"C:\Windows\system32\svchost.exe -k netsvcs -p -s bits", "", 5),
              out _),
          "match: service key scoping rejects other services");

    var contains = new SpawnWatch { Name = "contains", MatchProcess = "*", CommandLineContains = "-install" };
    Check(SpawnWatchService.MatchesAny(new List<SpawnWatch> { contains }, null,
              Ev(1, @"C:\x\setup.exe", @"C:\x\parent.exe", "", @"C:\x\setup.exe -install -quiet", 6),
              out _),
          "match: command-line substring");
    Check(!SpawnWatchService.MatchesAny(new List<SpawnWatch> { contains }, null,
              Ev(1, @"C:\x\setup.exe", @"C:\x\parent.exe", "", @"C:\x\setup.exe -quiet", 7),
              out _),
          "match: command-line substring rejects non-matching cmd");

    var disabled = new SpawnWatch { Name = "off", MatchProcess = "*", Enabled = false };
    Check(!SpawnWatchService.MatchesAny(new List<SpawnWatch> { disabled }, null,
              Ev(1, @"C:\x\a.exe", @"C:\x\p.exe", "", "", 8),
              out _),
          "match: disabled rules never match");

    // ── end-to-end: real Append → hook → consumer → hits index ───────
    SpawnWatchService.Start();
    await Task.Delay(400); // let the startup replay no-op out on the empty rules set

    var appender = new Func<string, long, long>((imageLeaf, rid) =>
    {
        var ev = Ev(1, @"C:\Windows\System32\" + imageLeaf,
                    @"C:\Windows\system32\svchost.exe", svcCmd, "", rid);
        // the watermark demands strictly newer events; bump the stamp per event
        ev.TsUtc = DateTime.UtcNow;
        return SysmonArchiveService.Append(ev) ? rid : -1;
    });

    long ridA = appender("mystery101.exe", 101);
    Check(ridA == 101, "append: event accepted by the archive");

    // poll until the consumer lands the hit (bounded, never flaky)
    async Task<bool> AwaitHitAsync(string rule, long rid, int timeoutMs = 15000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (SpawnWatchService.ReadHits(null, null, 5000).Any(h =>
                    h.Rule == rule && h.RecordId == rid)) return true;
            await Task.Delay(250);
        }
        return false;
    }

    Check(await AwaitHitAsync("svc-children", 101),
          "pipeline: real Append surfaced a hit through the hook + consumer");

    var rows = SpawnWatchService.ReadHits("svc-children", null, 10);
    var row = rows.FirstOrDefault(h => h.RecordId == 101);
    Check(row != null && row.Image.EndsWith("mystery101.exe") &&
          row.Parent.EndsWith("svchost.exe") && row.Service == "usosvc" && row.Pid == "101",
          "read: hit row carries image, parent, service and pid");

    // replay dedupe: everything already indexed → zero new hits
    Check(SpawnWatchService.ReplayRecent() == 0,
          "replay: already-indexed pairs are skipped");

    // a rule created AFTER the fact covers the archive it was too late for
    File.WriteAllText(Path.Combine(watchesDir, "neverseen.json"),
        "{\"name\":\"neverseen\",\"matchProcess\":\"*neverseen*\",\"matchParent\":\"svchost.exe\",\"enabled\":true,\"createdUtc\":\"" +
        DateTime.UtcNow.ToString("o") + "\"}");
    long ridB = appender("neverseen102.exe", 102);
    Check(ridB == 102, "append: second event accepted");
    Check(await AwaitHitAsync("neverseen", 102),
          "pipeline: dropped-in rule file is picked up live");
    Check(await AwaitHitAsync("svc-children", 102),
          "pipeline: existing rule also matched the same spawn");

    // now a spawn that only a FUTURE rule will want: append first, let the
    // consumer index it under the CURRENT rules, create the rule second —
    // then replay must retroactively index exactly the new rule's pair
    long ridC = appender("mystery103.exe", 103);
    Check(ridC == 103, "append: third event accepted");
    Check(await AwaitHitAsync("svc-children", 103),
          "pipeline: consumer indexed the new spawn under current rules");
    File.WriteAllText(Path.Combine(watchesDir, "latecatch.json"),
        "{\"name\":\"latecatch\",\"matchProcess\":\"*mystery103*\",\"matchParent\":\"svchost.exe\",\"enabled\":true,\"createdUtc\":\"" +
        DateTime.UtcNow.ToString("o") + "\"}");
    var replayed = SpawnWatchService.ReplayRecent();
    Check(replayed == 1, $"replay: retro rule indexed the past spawn exactly once (got {replayed})");
    Check(SpawnWatchService.ReplayRecent() == 0, "replay: second replay adds nothing");
    Check(await AwaitHitAsync("latecatch", 103),
          "read: retro hit visible via ReadHits");
}
catch (Exception ex)
{
    Console.WriteLine("FAIL  harness exception: " + ex);
    failures++;
}
finally
{
    try { Directory.Delete(tempRoot, true); } catch { }
}

Console.WriteLine(failures == 0 ? "\nALL CHECKS PASSED" : $"\n{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;
