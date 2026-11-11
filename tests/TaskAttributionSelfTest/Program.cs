using AutoCommand.Models;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;

// Replays the last hours of Sysmon + Task Scheduler history through the same
// Backfill the Taskhostw Spawns tab runs on open, and prints each spawn with
// its stitched attribution: task path, trigger reason, return code, verdict,
// and the known-task explanation when the catalog has one.
//
// Non-elevated runs cannot read the Sysmon log (its channel ACL is
// admin-only), so rows come back empty and the scheduler-only replay below
// carries the verification instead — EID 129 attributes by PID without any
// Sysmon record, which is exactly the guid-less case the rewrite fixed.

var svc = new TaskAttributionService();
var rows = svc.Backfill(TimeSpan.FromHours(8));
Console.WriteLine($"backfill: {rows.Count} taskhostw spawn row(s) in the last 8 h " +
                  $"({(rows.Count == 0 ? "Sysmon log not readable non-elevated — expected outside the app" : "ok")})");

foreach (var r in rows)
{
    var info = svc.GetTaskForPid(r.Pid);
    string cmd = (r.CommandLine ?? "").Trim();
    if (cmd.Length > 68) cmd = cmd[..68] + "…";
    Console.WriteLine($"  {r.TimeUtc.ToLocalTime():HH:mm:ss} pid {r.Pid,-6} {cmd}");
    Console.WriteLine(Detail(svc, info));
}

int processed = svc.BackfillSchedulerOnly(TimeSpan.FromHours(8));
var launches = svc.GetRecentLaunches(25);
Console.WriteLine();
Console.WriteLine($"scheduler-only replay: {processed} record(s) → {launches.Count} attributed launch(es)");
foreach (var info in launches)
{
    Console.WriteLine($"  {(info.StartedAt ?? info.FirstSeenUtc).ToLocalTime():HH:mm:ss} pid {info.ProcessId,-6} {info.TaskPath}");
    Console.WriteLine(Detail(svc, info));
}

static string Detail(TaskAttributionService svc, TaskLaunchInfo info)
{
    if (info == null) return "     (no attribution)";
    var known = KnownTaskCatalog.Lookup(info.TaskPath);
    return $"     task={info.TaskPath} trigger={info.TriggerReason ?? "-"} " +
           $"rc={info.ReturnCode?.ToString() ?? "-"} dur={info.DurationSeconds?.ToString("0.##") ?? "-"}s " +
           $"verdict={info.Verdict ?? "-"}" + Environment.NewLine +
           $"     handler={(info.HandlerDll ?? "-")}{(string.IsNullOrEmpty(info.HandlerDllVersion) ? "" : $" ({info.HandlerDllVersion})")}" +
           (known == null ? "" : Environment.NewLine + $"     known: {known.Title} — {known.Explanation}");
}
