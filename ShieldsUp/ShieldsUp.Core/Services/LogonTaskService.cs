namespace ShieldsUp.Core.Services;

/// <summary>
///  Shields Up's own launch-at-logon scheduled task, running with highest
/// privileges so the elevated app starts without a second UAC prompt.
/// Extracted from AutoCommand's FreshSetupService so Settings stays
/// self-contained (no firewall/bloatware orchestrator in tow).
/// </summary>
public static class LogonTaskService
{
    public const string TaskName = "ShieldsUpStartupTask";

    /// <summary>Creates the highest-privilege logon task.</summary>
    public static Task<bool> EnableAsync()
    {
        return Task.Run(() =>
        {
            try
            {
                string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                var r = Helpers.ProcessRunner.RunWithDetails("schtasks",
                    $"/create /tn \"{TaskName}\" /tr \"\\\"{exePath}\\\"\" /sc onlogon /rl highest /f");
                if (r.ExitCode != 0) return false;

                // Same trap as AutoCommand's own task: schtasks omits
                // <ExecutionTimeLimit>, Task Scheduler supplies PT72H, and the
                // task is terminated three days after logon. Repair before
                // reporting success.
                return ScheduledTaskGuard.Repair(TaskName).Healthy;
            }
            catch
            {
                return false;
            }
        });
    }

    /// <summary>Removes the logon task.</summary>
    public static Task<bool> DisableAsync()
    {
        return Task.Run(() =>
        {
            try
            {
                Helpers.ProcessRunner.RunWithDetails("schtasks", $"/delete /tn \"{TaskName}\" /f");
                return true;
            }
            catch
            {
                return false;
            }
        });
    }

    /// <summary>Checks the task's existence via Task Scheduler COM (no schtasks text parsing).</summary>
    public static Task<bool> ExistsAsync()
    {
        return Task.Run(() =>
        {
            try
            {
                Type tsType = Type.GetTypeFromProgID("Schedule.Service");
                dynamic ts = Activator.CreateInstance(tsType);
                ts.Connect();
                dynamic rootFolder = ts.GetFolder("\\");
                dynamic task = rootFolder.GetTask(TaskName);
                bool exists = task != null;
                return exists;
            }
            catch
            {
                return false;
            }
        });
    }
}
