using AutoCommand.Contain.Core;

// AllowListSelfTest - the tamper-evident allow-list ledger + the surface
// verdict evaluators, offline:
//   1. secure default: absent file enforces (false)
//   2. seeding: a pre-ledger preference file is adopted and pinned
//   3. commit/load round-trip for both keys (sstp, kdnet)
//   4. tamper via rewrite: "True" written by something else -> reverted + reported
//   5. tamper via delete: committed file vanishes -> enforcement re-armed
//   6. garbage file content -> unreadable, secure default
//   7. drift notes never invalidate the pinned hash
//   8. the Tampered event fires on detection
//   9. roots are isolated (a second Configure sees no history)
//  10. SurfaceAssurance.EvaluateSstp / EvaluateKdnet over synthetic states
// Everything runs against a temp root; no service, SetupAPI or bcdedit call.

int failed = 0;
void Check(string name, bool pass, string detail = null)
{
    Console.WriteLine((pass ? "PASS  " : "FAIL  ") + name +
                      (pass || string.IsNullOrEmpty(detail) ? "" : $" -- {detail}"));
    if (!pass) failed++;
}

// Temp root lives under the test's own bin output, not %TEMP%: the
// self-test is sometimes run from restricted hosts where the dotnet child
// cannot create directories in the user temp (build output always works).
string tempRoot = Path.Combine(AppContext.BaseDirectory, "selftest-root-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(tempRoot);
AllowListLedger.Configure(tempRoot);
AllowListLedger.HardenRoot = false; // the ACL path would lock this non-elevated test out of its own root

string prefSstp = Path.Combine(tempRoot, "allowed_sstp.txt");
string prefKdnet = Path.Combine(tempRoot, "allowed_kerneldebug.txt");
string ledgerPath = Path.Combine(tempRoot, "allowlist-ledger.log");

try
{
    // -- 1. secure default ------------------------------------------------
    var absent = AllowListLedger.Load("sstp", prefSstp);
    Check("1  absent file -> enforce (false), status Absent",
          absent.Value == false && absent.Status == AllowListLoadStatus.Absent,
          $"got {absent.Status}/{absent.Value}");

    // -- 2. seeding a pre-ledger file --------------------------------------
    File.WriteAllText(prefSstp, "True"); // exactly the legacy format
    var seeded = AllowListLedger.Load("sstp", prefSstp);
    Check("2a pre-ledger 'True' adopted, status Seeded",
          seeded.Value == true && seeded.Status == AllowListLoadStatus.Seeded,
          $"got {seeded.Status}/{seeded.Value}");
    Check("2b seed pinned the file hash in the ledger", File.Exists(ledgerPath));

    // -- 3. commit/load round-trip ------------------------------------------
    AllowListLedger.Commit("sstp", prefSstp, false);
    var trustedOff = AllowListLedger.Load("sstp", prefSstp);
    Check("3a commit(False)/load -> Trusted False",
          trustedOff.Value == false && trustedOff.Status == AllowListLoadStatus.Trusted,
          $"got {trustedOff.Status}/{trustedOff.Value}");

    AllowListLedger.Commit("sstp", prefSstp, true);
    var trustedOn = AllowListLedger.Load("sstp", prefSstp);
    Check("3b commit(True)/load -> Trusted True",
          trustedOn.Value == true && trustedOn.Status == AllowListLoadStatus.Trusted,
          $"got {trustedOn.Status}/{trustedOn.Value}");

    // keys are independent: kdnet has no history while sstp is committed
    var kdAbsent = AllowListLedger.Load("kdnet", prefKdnet);
    Check("3c kdnet key independent of sstp key",
          kdAbsent.Status == AllowListLoadStatus.Absent);

    // -- 4. tamper via rewrite ----------------------------------------------
    int reportsBefore = AllowListLedger.TamperReports.Count;
    bool eventFired = false;
    AllowListLedger.Tampered += (key, detail) => eventFired = true;

    File.WriteAllText(prefSstp, "True\r\n"); // same meaning, different bytes: hash mismatch
    var tampered = AllowListLedger.Load("sstp", prefSstp);
    Check("4a externally rewritten allow-list fails secure (False)",
          tampered.Value == false && tampered.Status == AllowListLoadStatus.Tampered,
          $"got {tampered.Status}/{tampered.Value}");
    Check("4b tamper report recorded", AllowListLedger.TamperReports.Count > reportsBefore);
    Check("4c Tampered event fired", eventFired);

    // after tamper, a fresh in-app commit restores trust
    AllowListLedger.Commit("sstp", prefSstp, true);
    var repaired = AllowListLedger.Load("sstp", prefSstp);
    Check("4d in-app commit after tamper restores Trusted True",
          repaired.Value == true && repaired.Status == AllowListLoadStatus.Trusted,
          $"got {repaired.Status}/{repaired.Value}");

    // -- 5. tamper via delete ------------------------------------------------
    AllowListLedger.Commit("kdnet", prefKdnet, true);
    File.Delete(prefKdnet);
    var deleted = AllowListLedger.Load("kdnet", prefKdnet);
    Check("5  committed allow-list deleted -> fails secure",
          deleted.Value == false && deleted.Status == AllowListLoadStatus.Tampered,
          $"got {deleted.Status}/{deleted.Value}");

    // -- 6. garbage content ---------------------------------------------------
    File.WriteAllText(prefSstp, "yes please");
    var garbage = AllowListLedger.Load("sstp", prefSstp);
    Check("6  garbage content -> unreadable, enforce (false)",
          garbage.Value == false && garbage.Status == AllowListLoadStatus.Unreadable,
          $"got {garbage.Status}/{garbage.Value}");

    // -- 7. drift notes keep the hash trustable --------------------------------
    AllowListLedger.Commit("sstp", prefSstp, true);
    AllowListLedger.NoteDrift("sstp", "service running (whitelisted)");
    var afterDrift = AllowListLedger.Load("sstp", prefSstp);
    Check("7  drift note does not invalidate the pin",
          afterDrift.Value == true && afterDrift.Status == AllowListLoadStatus.Trusted,
          $"got {afterDrift.Status}/{afterDrift.Value}");

    // -- 8. covered by 4c; ledger history shape --------------------------------
    string ledger = File.ReadAllText(ledgerPath);
    Check("8  ledger carries value, tamper and drift lines",
          ledger.Contains("|sstp|value|") && ledger.Contains("|sstp|tamper|") && ledger.Contains("|sstp|drift|"));

    // -- 9. root isolation ------------------------------------------------------
    string tempRoot2 = tempRoot + "-2";
    Directory.CreateDirectory(tempRoot2);
    AllowListLedger.Configure(tempRoot2);
    var isolated = AllowListLedger.Load("sstp", Path.Combine(tempRoot2, "allowed_sstp.txt"));
    Check("9  a fresh root sees no history (Absent)",
          isolated.Status == AllowListLoadStatus.Absent);
    AllowListLedger.Configure(tempRoot); // back to the primary root

    // -- 10. SurfaceAssurance evaluators (synthetic states) ---------------------
    var clean = SurfaceAssurance.EvaluateSstp(new SurfaceState
    {
        SstpServiceInstalled = true, SstpServiceRunning = false, SstpStartValue = 4, SstpMiniportsPresent = false,
    }, allowed: false);
    Check("10a SSTP desired state -> Clean",
          clean.Clean && !clean.Allowed && clean.Summary.Contains("Disabled"), clean.Summary);

    var running = SurfaceAssurance.EvaluateSstp(new SurfaceState
    {
        SstpServiceInstalled = true, SstpServiceRunning = true, SstpStartValue = 4, SstpMiniportsPresent = false,
    }, allowed: false);
    Check("10b SSTP running -> not clean, names the drift",
          !running.Clean && running.Summary.Contains("service running"), running.Summary);

    var autoStart = SurfaceAssurance.EvaluateSstp(new SurfaceState
    {
        SstpServiceInstalled = true, SstpServiceRunning = false, SstpStartValue = 3, SstpMiniportsPresent = false,
    }, allowed: false);
    Check("10c SSTP Start=3 -> not clean, names Start value",
          !autoStart.Clean && autoStart.Summary.Contains("Start=3"), autoStart.Summary);

    var miniports = SurfaceAssurance.EvaluateSstp(new SurfaceState
    {
        SstpServiceInstalled = true, SstpServiceRunning = false, SstpStartValue = 4, SstpMiniportsPresent = true,
    }, allowed: true);
    Check("10d SSTP miniports present on a whitelisted surface -> not clean, Allowed=true",
          !miniports.Clean && miniports.Allowed && miniports.Summary.Contains("miniports"), miniports.Summary);

    var unreadable = SurfaceAssurance.EvaluateSstp(new SurfaceState
    {
        SstpServiceInstalled = true, SstpServiceRunning = false, SstpStartValue = -1, SstpMiniportsPresent = false,
    }, allowed: false);
    Check("10e unreadable Start value -> treated as NOT clean",
          !unreadable.Clean && unreadable.Summary.Contains("unreadable"), unreadable.Summary);

    var notInstalled = SurfaceAssurance.EvaluateSstp(new SurfaceState
    {
        SstpServiceInstalled = false,
    }, allowed: false);
    Check("10f SSTP not installed -> Clean (nothing to attack)",
          notInstalled.Clean, notInstalled.Summary);

    var kdClean = SurfaceAssurance.EvaluateKdnet(new SurfaceState { }, allowed: false);
    Check("10g KDNET off + no KDNIC -> Clean",
          kdClean.Clean && kdClean.Summary.Contains("off"), kdClean.Summary);

    var kdBoth = SurfaceAssurance.EvaluateKdnet(new SurfaceState { BcdDebugOn = true, KdnicActive = true }, allowed: true);
    Check("10h KDNET on + KDNIC active, whitelisted -> not clean, Allowed=true",
          !kdBoth.Clean && kdBoth.Allowed, kdBoth.Summary);

    var kdNic = SurfaceAssurance.EvaluateKdnet(new SurfaceState { BcdDebugOn = false, KdnicActive = true }, allowed: false);
    Check("10i KDNIC adapter alone -> not clean, names the adapter",
          !kdNic.Clean && kdNic.Summary.Contains("KDNIC"), kdNic.Summary);
}
finally
{
    AllowListLedger.Configure(Path.GetTempPath()); // park the root away from the temp tree we delete
    try { Directory.Delete(tempRoot, recursive: true); } catch { }
}

Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
return failed == 0 ? 0 : 1;
