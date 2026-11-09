// StartupHealthSelfTest - offline checks for the two rules behind the
// 2026-11-08 incident:
//
//   1. ScheduledTaskGuard: a logon task created by `schtasks /create` with no
//      explicit limit inherits Task Scheduler's PT72H default and is
//      terminated three days after the logon that started it. Existence alone
//      must therefore never be reported as healthy.
//   2. LivenessService: a clean exit DELETES heartbeat.json, so a beat left on
//      disk whose pid is gone is an abrupt end by construction. The classifier
//      and the round-trip are both pinned here.
//
// Everything synthetic: a temp directory, an injected liveness probe and an
// injected attribution probe. No task is registered, no live log is read.

using System;
using System.IO;
using AutoCommand.Agent.Core;
using ShieldsUp.Core.Services;

int failures = 0;

void Check(string name, bool ok, string detail = null)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(string.IsNullOrEmpty(detail) ? "" : "  [" + detail + "]")}");
    if (!ok) failures++;
}

Console.WriteLine("== 1. ScheduledTaskGuard.Classify ==");

// The exact shape of the task that killed the app on 2026-11-08.
var poisoned = ScheduledTaskGuard.Classify(true, "PT72H", false, false);
Check("1a PT72H is unhealthy", !poisoned.Healthy);
Check("1b PT72H detail names the limit", poisoned.Detail.Contains("PT72H"), poisoned.Detail);

var good = ScheduledTaskGuard.Classify(true, "PT0S", false, false);
Check("1c PT0S + battery allowed is healthy", good.Healthy);

Check("1d PT0M counts as unlimited", ScheduledTaskGuard.IsUnlimited("PT0M"));
Check("1e PT72H is not unlimited", !ScheduledTaskGuard.IsUnlimited("PT72H"));
Check("1f null limit is not unlimited", !ScheduledTaskGuard.IsUnlimited(null));

var noBattery = ScheduledTaskGuard.Classify(true, "PT0S", true, false);
Check("1g never-start-on-battery is unhealthy", !noBattery.Healthy);

var stopsOnBattery = ScheduledTaskGuard.Classify(true, "PT0S", false, true);
Check("1h stop-on-battery is unhealthy", !stopsOnBattery.Healthy);

var absent = ScheduledTaskGuard.Classify(false, null, false, false);
Check("1i missing task is not healthy", !absent.Exists && !absent.Healthy);

Console.WriteLine();
Console.WriteLine("== 2. LivenessService.ClassifyCause ==");

Check("2a clean stop wins over a live pid",
    LivenessService.ClassifyCause(true, true, true) == LivenessService.Clean);
Check("2b live pid means no death to report",
    LivenessService.ClassifyCause(false, true, false) == LivenessService.StillRunning);
Check("2c dead pid + Scheduler 329 is attributed",
    LivenessService.ClassifyCause(false, false, true) == LivenessService.TaskTimeLimit);
Check("2d dead pid with no record stays unexplained",
    LivenessService.ClassifyCause(false, false, false) == LivenessService.Abrupt);

Console.WriteLine();
Console.WriteLine("== 3. death record round-trip (temp dir, synthetic beat) ==");

string root = Path.Combine(AppContext.BaseDirectory, "startuphealth-" + Guid.NewGuid().ToString("N").Substring(0, 8));
Directory.CreateDirectory(root);

try
{
    string beatPath = Path.Combine(root, "heartbeat.json");
    var dead = new LivenessBeat(999999, DateTime.Now.AddHours(-2), DateTime.Now.AddHours(-1));
    File.WriteAllText(beatPath, System.Text.Json.JsonSerializer.Serialize(dead));

    var recorded = LivenessService.DetectAndRecordPreviousDeath(
        root,
        _ => false,
        _ => "Task Scheduler terminated \"\\AutoCommandStartupTask\" instance {x} due to exceeding the time allocated for execution.");

    Check("3a leftover beat with a dead pid is reported", recorded != null);
    Check("3b cause is attributed to the Scheduler", recorded?.Cause == LivenessService.TaskTimeLimit, recorded?.Cause);
    Check("3c uptime is derived from the beat", recorded != null && Math.Abs(recorded.UptimeSeconds - 3600) < 5,
        recorded?.UptimeSeconds.ToString("F0"));

    string deaths = Path.Combine(root, "deaths.jsonl");
    Check("3d one line appended to deaths.jsonl", File.Exists(deaths) && File.ReadAllLines(deaths).Length == 1);

    Check("3e the notice is plain English",
        LivenessService.Notice(recorded).Contains("three-day"), LivenessService.Notice(recorded));

    Check("3f a live pid is not a death",
        LivenessService.DetectAndRecordPreviousDeath(root, _ => true, _ => null) == null);

    // Clean-exit inversion: StopHeartbeat deletes the beat, so the next start
    // has nothing to report.
    LivenessService.StartHeartbeat(root, TimeSpan.FromMinutes(10));
    Check("3g heartbeat file exists after start", File.Exists(beatPath));
    LivenessService.StopHeartbeat();
    Check("3h clean exit removes the beat", !File.Exists(beatPath));
    Check("3i no death recorded after a clean exit",
        LivenessService.DetectAndRecordPreviousDeath(root, _ => false, _ => null) == null);
}
finally
{
    try { LivenessService.StopHeartbeat(); } catch { }
    try { Directory.Delete(root, true); } catch { }
}

Console.WriteLine();
Console.WriteLine(failures == 0 ? "ALL CHECKS PASSED" : $"{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;
