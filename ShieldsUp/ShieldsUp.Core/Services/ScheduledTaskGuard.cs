using System;

namespace ShieldsUp.Core.Services;

/// <summary>
/// Keeps a logon task doing what the user asked it to do.
///
/// <para><c>schtasks /create</c> with no explicit limit writes no
/// &lt;ExecutionTimeLimit&gt; element, and Task Scheduler then applies its own
/// default of PT72H. A tool registered that way is terminated by the
/// Scheduler exactly three days after the logon that started it — silently,
/// with no crash artifact, and the logon trigger does not fire again until
/// the next sign-in. The same defaults also refuse to start the task on
/// battery and stop it the moment a laptop unplugs. Both are wrong for an
/// always-on watcher, and neither is visible anywhere in the app that
/// created the task.</para>
///
/// <para>Field incident behind this type: \AutoCommandStartupTask was
/// registered on 2026-11-03 with the schtasks defaults and terminated at
/// 2026-11-08 20:05:22 — exactly PT72H after the 11-05 20:05:05 boot — with
/// Task Scheduler event 329, "terminated due to exceeding the time allocated
/// for execution". The app had been watching for three days and then simply
/// stopped existing, which for a visibility tool is the worst failure mode
/// available: silence that looks identical to "nothing to report".</para>
///
/// <para>This type reads the *registered* task back (the definition on disk
/// may already be poisoned even when the code that created it has been
/// fixed) and repairs the three settings that matter. Existence checks alone
/// are not enough: the old code reported a 72-hour task as healthy forever.</para>
/// </summary>
public static class ScheduledTaskGuard
{
    /// <summary>Task Scheduler's spelling of "no time limit".</summary>
    public const string Unlimited = "PT0S";

    /// <summary>What one registered task's settings say about its longevity.</summary>
    public sealed record Health(
        bool Exists,
        string ExecutionTimeLimit,
        bool DisallowStartIfOnBatteries,
        bool StopIfGoingOnBatteries,
        bool Healthy,
        string Detail);

    public static bool IsUnlimited(string executionTimeLimit)
    {
        var v = (executionTimeLimit ?? string.Empty).Trim();
        return v.Equals(Unlimited, StringComparison.OrdinalIgnoreCase)
            || v.Equals("PT0M", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Pure judgement over the three settings that decide whether a long-lived
    /// task survives. Kept free of COM so the self-test can pin the matrix.
    /// </summary>
    public static Health Classify(
        bool exists,
        string executionTimeLimit,
        bool disallowStartIfOnBatteries,
        bool stopIfGoingOnBatteries)
    {
        var limit = string.IsNullOrWhiteSpace(executionTimeLimit) ? "(none)" : executionTimeLimit.Trim();

        if (!exists)
        {
            return new Health(false, limit, disallowStartIfOnBatteries, stopIfGoingOnBatteries, false,
                "no logon task is registered");
        }

        var unlimited = IsUnlimited(limit);
        var healthy = unlimited && !disallowStartIfOnBatteries && !stopIfGoingOnBatteries;

        string detail;
        if (!unlimited)
        {
            detail = $"Windows stops this task after {limit} — the Task Scheduler default is PT72H (three days)";
        }
        else if (disallowStartIfOnBatteries)
        {
            detail = "the task will not start while the machine is on battery";
        }
        else if (stopIfGoingOnBatteries)
        {
            detail = "the task stops the moment the machine drops to battery";
        }
        else
        {
            detail = "unlimited, starts on battery";
        }

        return new Health(true, limit, disallowStartIfOnBatteries, stopIfGoingOnBatteries, healthy, detail);
    }

    /// <summary>
    /// Reads the registered task. Never throws — an unreadable task is
    /// reported as unhealthy with the reason, because a silent exception here
    /// is how the 72-hour task stayed invisible.
    /// </summary>
    public static Health Inspect(string taskName)
    {
        try
        {
            dynamic ts = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
            ts.Connect();
            dynamic root = ts.GetFolder("\\");
            dynamic task = root.GetTask(taskName);
            dynamic settings = task.Definition.Settings;

            return Classify(
                true,
                (string)settings.ExecutionTimeLimit,
                (bool)settings.DisallowStartIfOnBatteries,
                (bool)settings.StopIfGoingOnBatteries);
        }
        catch (Exception ex)
        {
            return new Health(false, "(unreadable)", false, false, false,
                "task not registered or not readable: " + ex.Message);
        }
    }

    /// <summary>
    /// Rewrites the three settings in place and re-registers the task with its
    /// own principal (the user, HighestAvailable) — the same identity
    /// <c>schtasks /rl highest</c> wrote, so no new privilege is granted and no
    /// credential is needed: TASK_LOGON_INTERACTIVE_TOKEN reuses the token the
    /// scheduler already holds for this user.
    /// </summary>
    public static Health Repair(string taskName)
    {
        try
        {
            dynamic ts = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
            ts.Connect();
            dynamic root = ts.GetFolder("\\");
            dynamic task = root.GetTask(taskName);
            dynamic definition = task.Definition;

            definition.Settings.ExecutionTimeLimit = Unlimited;
            definition.Settings.DisallowStartIfOnBatteries = false;
            definition.Settings.StopIfGoingOnBatteries = false;

            // 6 = TASK_CREATE_OR_UPDATE, 3 = TASK_LOGON_INTERACTIVE_TOKEN.
            // Null credentials keep the principal already in the definition.
            root.RegisterTaskDefinition(taskName, definition, 6, null, null, 3);

            return Inspect(taskName);
        }
        catch (Exception ex)
        {
            return new Health(true, "(repair failed)", false, false, false, "repair failed: " + ex.Message);
        }
    }

    /// <summary>
    /// Repairs only when the task exists and is unhealthy. Returns the state
    /// after the attempt; <see cref="Health.Exists"/> false means there was
    /// nothing registered to fix (a user who never enabled launch-at-logon).
    /// Calling this at every startup is the point: an upgraded build must
    /// cure the task an older build left behind, without asking the user to
    /// find a toggle they never knew about.
    /// </summary>
    public static Health EnsureUnlimited(string taskName)
    {
        var before = Inspect(taskName);
        if (!before.Exists || before.Healthy)
        {
            return before;
        }

        return Repair(taskName);
    }
}
