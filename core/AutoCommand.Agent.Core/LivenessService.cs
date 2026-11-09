using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text.Json;
using System.Threading;

namespace AutoCommand.Agent.Core;

/// <summary>One liveness stamp, rewritten every 30 s while the app runs.</summary>
public sealed record LivenessBeat(int Pid, DateTime StartedUtc, DateTime BeatUtc);

/// <summary>One recorded end of an AutoCommand instance.</summary>
public sealed record LivenessDeath(
    DateTime DetectedUtc,
    int Pid,
    DateTime StartedUtc,
    DateTime LastBeatUtc,
    double UptimeSeconds,
    string Cause,
    string Detail);

/// <summary>
/// Tells the user — in a sentence — why the app was not running.
///
/// <para>Implementation note that matters: the beat file is deleted by a
/// clean exit and left behind by every other kind of ending. That inversion
/// is deliberate. A "clean = true" flag written on exit cannot be trusted —
/// exit is exactly the path that does not run when a process is terminated,
/// and it is also the path a crash truncates. A file that must be removed to
/// mean "fine" fails safe: an unreadable, truncated or stale beat all read as
/// "ended abruptly", never as "ended cleanly".</para>
///
/// <para>Nothing here needs elevation. The one privileged fact we want — the
/// Scheduler's own reason — is optional: when the channel is readable the
/// death is attributed (<see cref="TaskTimeLimit"/>), when it is not the
/// record still says when the app was last alive, which is the part a user
/// can act on.</para>
/// </summary>
public static class LivenessService
{
    public const string Clean = "clean";
    public const string StillRunning = "still-running";
    public const string TaskTimeLimit = "task-time-limit";
    public const string Abrupt = "abrupt";

    private static readonly object Gate = new();
    private static Timer _timer;
    private static string _beatPath;
    private static DateTime _startedUtc;

    /// <summary>
    /// Pure cause table: clean beats everything, a live pid means there is no
    /// death to report, and a Scheduler termination record turns an otherwise
    /// unexplained disappearance into a named one.
    /// </summary>
    public static string ClassifyCause(bool cleanStop, bool pidAlive, bool taskTerminationRecorded)
    {
        if (cleanStop) return Clean;
        if (pidAlive) return StillRunning;
        return taskTerminationRecorded ? TaskTimeLimit : Abrupt;
    }

    /// <summary>The sentence a non-technical user reads. No hex, no event ids.</summary>
    public static string Notice(LivenessDeath death)
    {
        if (death == null) return string.Empty;

        var when = death.LastBeatUtc.ToLocalTime().ToString("h:mm tt 'on' MMM d");

        if (string.Equals(death.Cause, TaskTimeLimit, StringComparison.Ordinal))
        {
            return $"AutoCommand was stopped by Windows at {when} because my own startup entry had a " +
                   "three-day time limit. That was my bug, not a problem with your PC. The limit is " +
                   "removed now, so it should not happen again.";
        }

        return $"AutoCommand stopped unexpectedly at {when} and started again just now. " +
               "Nothing you configured was lost.";
    }

    /// <summary>
    /// Reads the previous instance's beat and, when its pid is gone, records
    /// one line in deaths.jsonl. Returns null when there is nothing to report
    /// (no beat, a clean exit, or another instance still running).
    ///
    /// <paramref name="terminationProbe"/> receives the beat window start and
    /// returns the Scheduler's own message, or null when the channel is
    /// unreadable — attribution is a bonus, not a requirement.
    /// </summary>
    public static LivenessDeath DetectAndRecordPreviousDeath(
        string agentDirectory,
        Func<int, bool> pidAlive,
        Func<DateTime, string> terminationProbe)
    {
        try
        {
            if (string.IsNullOrEmpty(agentDirectory)) return null;

            string path = Path.Combine(agentDirectory, "heartbeat.json");
            if (!File.Exists(path)) return null;   // clean exit deletes it — nothing to report

            LivenessBeat beat;
            try { beat = JsonSerializer.Deserialize<LivenessBeat>(File.ReadAllText(path)); }
            catch { beat = null; }

            if (beat == null || beat.Pid <= 0) return null;
            if (beat.Pid == Environment.ProcessId) return null;

            bool alive = pidAlive != null && pidAlive(beat.Pid);

            string probe = null;
            if (!alive && terminationProbe != null)
            {
                try { probe = terminationProbe(beat.BeatUtc.AddSeconds(-5)); } catch { probe = null; }
            }

            string cause = ClassifyCause(false, alive, !string.IsNullOrEmpty(probe));
            if (string.Equals(cause, StillRunning, StringComparison.Ordinal)) return null;

            var death = new LivenessDeath(
                DateTime.Now,
                beat.Pid,
                beat.StartedUtc,
                beat.BeatUtc,
                Math.Max(0, (beat.BeatUtc - beat.StartedUtc).TotalSeconds),
                cause,
                probe ?? string.Empty);

            AppendDeath(agentDirectory, death);
            return death;
        }
        catch
        {
            return null;   // liveness bookkeeping must never be able to break startup
        }
    }

    /// <summary>
    /// Starts the beat. Returns false without writing when another live
    /// instance already owns the file — two instances must not overwrite each
    /// other's beat, or the survivor would later look like a corpse.
    /// </summary>
    public static bool StartHeartbeat(string agentDirectory, TimeSpan? interval = null)
    {
        try
        {
            if (string.IsNullOrEmpty(agentDirectory)) return false;
            Directory.CreateDirectory(agentDirectory);

            string path = Path.Combine(agentDirectory, "heartbeat.json");
            if (File.Exists(path))
            {
                try
                {
                    var other = JsonSerializer.Deserialize<LivenessBeat>(File.ReadAllText(path));
                    if (other != null && other.Pid != Environment.ProcessId && IsAlive(other.Pid)) return false;
                }
                catch { /* truncated beat = our predecessor's corpse; take it over */ }
            }

            lock (Gate)
            {
                _beatPath = path;
                _startedUtc = DateTime.Now;
                WriteBeat();

                var period = interval ?? TimeSpan.FromSeconds(30);
                _timer?.Dispose();
                _timer = new Timer(_ => WriteBeat(), null, period, period);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Clean-exit marker: stop beating and remove the file.</summary>
    public static void StopHeartbeat()
    {
        try { _timer?.Dispose(); } catch { /* timer already gone */ }
        _timer = null;

        try
        {
            if (!string.IsNullOrEmpty(_beatPath) && File.Exists(_beatPath)) File.Delete(_beatPath);
        }
        catch { /* a leftover beat costs one false report, never a crash */ }

        _beatPath = null;
    }

    public static bool IsAlive(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch { return false; }
    }

    private static void WriteBeat()
    {
        try
        {
            string path = _beatPath;
            if (string.IsNullOrEmpty(path)) return;

            var beat = new LivenessBeat(Environment.ProcessId, _startedUtc, DateTime.Now);
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(beat));
            File.Move(tmp, path, overwrite: true);   // atomic on NTFS: never a half-written beat
        }
        catch { /* the next tick will try again */ }
    }

    private static void AppendDeath(string agentDirectory, LivenessDeath death)
    {
        try
        {
            Directory.CreateDirectory(agentDirectory);
            File.AppendAllText(
                Path.Combine(agentDirectory, "deaths.jsonl"),
                JsonSerializer.Serialize(death) + Environment.NewLine);
        }
        catch { /* the report is best-effort; the app still starts */ }
    }
}

/// <summary>
/// The Scheduler's own account of why a task instance stopped. Event 329 is
/// "terminated due to exceeding the time allocated for execution" — the exact
/// record the 2026-11-08 incident produced at 20:05:22, nine seconds before
/// the device-setup screen appeared.
/// </summary>
public static class TaskSchedulerProbe
{
    public const int TimeLimitTerminationEventId = 329;

    /// <summary>
    /// The newest 329 whose message names <paramref name="taskName"/> at or
    /// after <paramref name="sinceLocal"/>, or null. Reads newest-first and
    /// stops as soon as the window is passed.
    /// </summary>
    public static string RecentTimeLimitTermination(string taskName, DateTime sinceLocal)
    {
        if (string.IsNullOrEmpty(taskName)) return null;

        try
        {
            var query = new EventLogQuery(
                "Microsoft-Windows-TaskScheduler/Operational",
                PathType.LogName,
                $"*[System[(EventID={TimeLimitTerminationEventId})]]")
            { ReverseDirection = true };

            using var reader = new EventLogReader(query);

            for (int i = 0; i < 300; i++)
            {
                using var record = reader.ReadEvent();
                if (record == null) break;

                var at = record.TimeCreated?.ToLocalTime() ?? DateTime.MinValue;
                if (at < sinceLocal) break;

                var message = record.FormatDescription();
                if (!string.IsNullOrEmpty(message) &&
                    message.IndexOf(taskName, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return message;
                }
            }
        }
        catch
        {
            // Channel unreadable (not elevated, or Task Scheduler history off).
            // Attribution is a bonus; the death is still recorded without it.
        }

        return null;
    }
}
