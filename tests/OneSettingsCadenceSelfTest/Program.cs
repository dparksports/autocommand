using System.Xml;
using AutoCommand.OneSettingsCadence;

// Offline self-test for the OneSettingsCadence CLI's pure logic. Every check
// prints PASS/FAIL with evidence; exit code 0 only when everything passed.
//
// Covered: interval parser (all three input forms + rejects + round-trip),
// the Triggers XML transform (Duration removal when interval >= duration,
// Duration kept when shorter, RandomDelay insertion when absent, Repetition
// creation when absent, WNF removal and --keep-wnf), drift detection
// (including PT24H-vs-P1D normalization), and range warnings.
// Not covered (needs the live task / elevation): COM reads, registration,
// rollback, watchdog — those are exercised by status/preview/preview against
// the real task, read-only.

int pass = 0, fail = 0;
void Check(string name, bool ok, string evidence = "")
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(evidence.Length > 0 ? $" — {evidence}" : "")}");
    if (ok) pass++; else fail++;
}

// --- interval parser: accepted forms --------------------------------------
foreach (var (text, expected) in new[]
{
    ("24", TimeSpan.FromHours(24)),      // plain hours
    ("24h", TimeSpan.FromHours(24)),     // trailing h
    ("0.5", TimeSpan.FromMinutes(30)),   // fractional hours
    ("06:00:00", TimeSpan.FromHours(6)), // clock HH:MM:SS
    ("6:00", TimeSpan.FromHours(6)),     // clock HH:MM
    ("1:30:00", TimeSpan.FromHours(1.5)),
    ("PT24H", TimeSpan.FromHours(24)),   // ISO 8601
    ("P1DT12H", TimeSpan.FromHours(36)),
    ("PT30M", TimeSpan.FromMinutes(30)),
    ("P2D", TimeSpan.FromDays(2)),
})
{
    bool ok = IntervalParser.TryParse(text, out TimeSpan got, out string err);
    Check($"parse '{text}' -> {expected}", ok && got == expected, ok ? IntervalParser.ToTaskForm(got) : err);
}

// --- interval parser: rejects ---------------------------------------------
foreach (string bad in new[] { "abc", "-5", "0", "1:99", "PT", "banana:x", "  " })
{
    bool rejected = !IntervalParser.TryParse(bad, out _, out _);
    Check($"parse '{bad}' rejected", rejected);
}

// --- round-trip: every TimeSpan formats and re-parses to itself -----------
bool roundTripOk = true;
foreach (TimeSpan t in new[] { TimeSpan.FromHours(24), TimeSpan.FromHours(6.5), TimeSpan.FromMinutes(90), TimeSpan.FromDays(3.25) })
{
    string form = IntervalParser.ToTaskForm(t);
    if (XmlConvert.ToTimeSpan(form) != t) { roundTripOk = false; Console.WriteLine($"      round-trip broke: {t} -> {form}"); }
}
Check("ToTaskForm round-trips every interval", roundTripOk);

// --- range warnings ---------------------------------------------------------
Check("warning below 6h", IntervalParser.RangeWarning(TimeSpan.FromHours(3)) != null);
Check("no warning at 6h", IntervalParser.RangeWarning(TimeSpan.FromHours(6)) == null);
Check("no warning at 72h", IntervalParser.RangeWarning(TimeSpan.FromHours(72)) == null);
Check("warning above 72h", IntervalParser.RangeWarning(TimeSpan.FromHours(100)) != null);

// --- transform: the stock XML of this machine (Duration absent) ------------
string stockXml = """
    <?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers>
        <TimeTrigger>
          <StartBoundary>2026-10-14T19:01:20-07:00</StartBoundary>
          <Repetition>
            <Interval>PT3H36M</Interval>
          </Repetition>
          <RandomDelay>PT1H</RandomDelay>
        </TimeTrigger>
        <WnfStateChangeTrigger>
          <StateName>7538BCA33A019502</StateName>
        </WnfStateChangeTrigger>
        <WnfStateChangeTrigger>
          <StateName>7574BCA33A019502</StateName>
        </WnfStateChangeTrigger>
        <WnfStateChangeTrigger>
          <StateName>75B8BCA33A019502</StateName>
        </WnfStateChangeTrigger>
      </Triggers>
    </Task>
    """;

var t1 = CadenceEngine.Transform(stockXml, TimeSpan.FromHours(24), keepWnf: false);
var parsed1 = CadenceEngine.ParseLiveXml(t1.ModifiedXml);
Check("stock -> 24h: interval applied", parsed1.Interval == TimeSpan.FromHours(24), IntervalParser.ToTaskForm(parsed1.Interval.Value));
Check("stock -> 24h: random delay zeroed", parsed1.RandomDelay == TimeSpan.Zero);
Check("stock -> 24h: WNF triggers removed", parsed1.WnfStateNames.Count == 0, $"{t1.RemovedWnfNames.Count} removed");
Check("stock -> 24h: StartBoundary untouched",
      t1.ModifiedXml.Contains("2026-10-14T19:01:20-07:00"));

var t2 = CadenceEngine.Transform(stockXml, TimeSpan.FromHours(48), keepWnf: true);
var parsed2 = CadenceEngine.ParseLiveXml(t2.ModifiedXml);
Check("--keep-wnf keeps the WNF triggers", parsed2.WnfStateNames.Count == 3);

// --- transform: Duration present, interval >= duration -> dropped ----------
string withDuration = stockXml.Replace("<Interval>PT3H36M</Interval>",
    "<Interval>PT3H36M</Interval><Duration>P1D</Duration><StopAtDurationEnd>false</StopAtDurationEnd>");
var t3 = CadenceEngine.Transform(withDuration, TimeSpan.FromHours(24), keepWnf: false);
var parsed3 = CadenceEngine.ParseLiveXml(t3.ModifiedXml);
Check("Duration dropped when interval >= duration (24h vs P1D)", parsed3.Duration == null && t3.DurationRemoved,
      t3.Notes.FirstOrDefault() ?? "(no note)");

// --- transform: Duration present, interval < duration -> kept --------------
var t4 = CadenceEngine.Transform(withDuration, TimeSpan.FromHours(12), keepWnf: false);
var parsed4 = CadenceEngine.ParseLiveXml(t4.ModifiedXml);
Check("Duration kept when interval < duration (12h vs P1D)", parsed4.Duration == TimeSpan.FromDays(1) && !t4.DurationRemoved);

// --- transform: RandomDelay absent -> inserted as PT0S ---------------------
string noDelay = stockXml.Replace("<RandomDelay>PT1H</RandomDelay>", "");
var t5 = CadenceEngine.Transform(noDelay, TimeSpan.FromHours(24), keepWnf: false);
Check("RandomDelay inserted when absent", t5.ModifiedXml.Contains("<RandomDelay>PT0S</RandomDelay>"));

// --- transform: Repetition absent -> created --------------------------------
string noRepetition = stockXml.Replace("<Repetition>\n            <Interval>PT3H36M</Interval>\n          </Repetition>", "");
noRepetition = noRepetition.Replace("<Repetition>" + Environment.NewLine + "            <Interval>PT3H36M</Interval>" + Environment.NewLine + "          </Repetition>", "");
var parsedPre = CadenceEngine.ParseLiveXml(noRepetition);
if (parsedPre.Interval != null)
{
    // whitespace variation between the fixture and the replace — fall back to a
    // regex-free manual strip so this case still gets exercised
    int start = noRepetition.IndexOf("<Repetition>");
    int end = noRepetition.IndexOf("</Repetition>") + "</Repetition>".Length;
    noRepetition = noRepetition.Remove(start, end - start);
}
var t6 = CadenceEngine.Transform(noRepetition, TimeSpan.FromHours(24), keepWnf: false);
var parsed6 = CadenceEngine.ParseLiveXml(t6.ModifiedXml);
Check("Repetition created when absent", parsed6.Interval == TimeSpan.FromHours(24));

// --- drift detection ---------------------------------------------------------
var desired = TimeSpan.FromHours(24);
var liveOk = new CadenceEngine.LiveState { Interval = TimeSpan.FromDays(1), RandomDelay = TimeSpan.Zero, WnfStateNames = new() };
Check("no drift when live P1D == desired PT24H (scheduler normalization)",
      CadenceEngine.FindMismatches(liveOk, desired, keepWnf: false, expectedWnfWhenKept: 0).Count == 0);

var liveDrifted = new CadenceEngine.LiveState { Interval = TimeSpan.FromHours(3.6), RandomDelay = TimeSpan.FromHours(1), WnfStateNames = new() { "A" } };
var problems = CadenceEngine.FindMismatches(liveDrifted, desired, keepWnf: false, expectedWnfWhenKept: 0);
Check("drift reported for interval + delay + WNF", problems.Count == 3, string.Join("; ", problems));

var liveKeepWnf = new CadenceEngine.LiveState { Interval = desired, RandomDelay = TimeSpan.Zero, WnfStateNames = new() { "A", "B" } };
Check("keep-wnf accepts the original WNF count",
      CadenceEngine.FindMismatches(liveKeepWnf, desired, keepWnf: true, expectedWnfWhenKept: 2).Count == 0);


// --- run-history field parsing: a REAL captured event triple ---------------
// (the event namespace is exact-match; a typo'd URI parsed nothing for every
// record once — this pins it)
string ev100 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>100</EventID><TimeCreated SystemTime='2026-10-15T02:42:15.7320996Z'/></System><EventData Name='TaskStartEvent'><Data Name='TaskName'>\Microsoft\Windows\Flighting\OneSettings\RefreshCache</Data><Data Name='UserContext'>NT AUTHORITY\SYSTEM</Data><Data Name='InstanceId'>{95d24c30-3a57-481e-b82d-318e657c78df}</Data></EventData></Event>""";
string ev201 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>201</EventID><TimeCreated SystemTime='2026-10-15T02:42:16.6670000Z'/></System><EventData Name='ActionCompletionEvent'><Data Name='TaskName'>\Microsoft\Windows\Flighting\OneSettings\RefreshCache</Data><Data Name='ActionName'>Task Scheduler service started Task Engine process</Data><Data Name='TaskInstanceId'>{95d24c30-3a57-481e-b82d-318e657c78df}</Data><Data Name='ResultCode'>0</Data></EventData></Event>""";

var f100 = RunHistory.ParseFields(ev100);
Check("ParseFields reads EID-100 EventData (namespace exact)", f100 != null && f100["TaskName"] == @"\Microsoft\Windows\Flighting\OneSettings\RefreshCache",
      f100 == null ? "EventData not found — namespace mismatch" : f100["TaskName"]);
var f201 = RunHistory.ParseFields(ev201);
Check("ParseFields reads EID-201 ResultCode", f201 != null && f201["ResultCode"] == "0");
var fBad = RunHistory.ParseFields(ev100.Replace("/win/2004", "/2004"));
Check("ParseFields returns null on a foreign namespace", fBad == null);

// compliance bucketing on synthetic runs
var runs = new List<RunHistory.TaskRun>
{
    new() { TimeUtc = DateTime.UtcNow.AddHours(-1),  Trigger = "timer (schedule)" },
    new() { TimeUtc = DateTime.UtcNow.AddHours(-25), Trigger = "timer (schedule)" },
    new() { TimeUtc = DateTime.UtcNow.AddHours(-30), Trigger = "event / WNF" },
    new() { TimeUtc = DateTime.UtcNow.AddHours(-40), Trigger = "manual / API" },
};
var comp = RunHistory.Compute(runs, TimeSpan.FromHours(24), cadenceIsSaved: true, days: 7);
Check("compliance buckets timer/event/manual", comp.TimerRuns == 2 && comp.EventRuns == 1 && comp.ManualRuns == 1 && comp.TotalRuns == 4,
      $"timer={comp.TimerRuns} event={comp.EventRuns} manual={comp.ManualRuns}");
Check("compliance expects ~7 timer runs/week at 24h", Math.Abs(comp.ExpectedTimerRuns - 7) < 0.2, comp.ExpectedTimerRuns.ToString());
Check("compliance verdict says holding", comp.Verdict.Contains("holding"), comp.Verdict);
var compWnf = RunHistory.Compute(runs, TimeSpan.FromHours(24), cadenceIsSaved: true, days: 7, wnfTriggersPresent: true);
Check("verdict blames WNF triggers when they are installed", compWnf.Verdict.Contains("WNF"), compWnf.Verdict);
var heavyRuns = Enumerable.Range(0, 12).Select(k => new RunHistory.TaskRun
    { TimeUtc = DateTime.UtcNow.AddHours(-k * 6), Trigger = "timer (schedule)" }).ToList();var compRev = RunHistory.Compute(heavyRuns, TimeSpan.FromHours(24), cadenceIsSaved: true, days: 7);
Check("verdict blames servicing when WNF triggers are gone", compRev.Verdict.Contains("servicing"), compRev.Verdict);
var compRevWnf = RunHistory.Compute(heavyRuns, TimeSpan.FromHours(24), cadenceIsSaved: true, days: 7, wnfTriggersPresent: true);
Check("same excess with WNF triggers installed blames them", compRevWnf.Verdict.Contains("WNF"), compRevWnf.Verdict);

// (the external-start correlation section left with ExternalStartMonitor —
// the 2026.10.30 dead-module sweep removed the feature as instantiated
// nowhere; these checks exercised only that removed type)

Console.WriteLine();
Console.WriteLine($"{pass} passed, {fail} failed");
return fail == 0 ? 0 : 1;
