using System;
using System.Threading.Tasks;
using AutoCommand.NetWatch.Core;

namespace AutoCommand.Services
{
    /// <summary>
    /// Manages AutoCommand's highest-privilege logon scheduled task, including
    /// automatic normalization of Task Scheduler's default 72-hour execution limit
    /// and laptop battery-stop flags via <see cref="ShieldsUp.Core.Services.ScheduledTaskGuard"/>.
    /// </summary>
    public static class FreshSetupService
    {
        public const string StartupTaskName = "AutoCommandStartupTask";

        /// <summary>Creates the highest-privilege logon task (same as the Settings toggle).</summary>
        public static Task<bool> EnableLaunchAtLogon()
        {
            return Task.Run(() =>
            {
                try
                {
                    string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                    var r = ProcessRunner.RunWithDetails("schtasks",
                        $"/create /tn \"{StartupTaskName}\" /tr \"\\\"{exePath}\\\"\" /sc onlogon /rl highest /f");
                    if (r.ExitCode != 0) return false;

                    // schtasks writes no <ExecutionTimeLimit>, and Task Scheduler
                    // then applies its own PT72H default: the app is terminated
                    // three days after the logon that started it (field report
                    // 2026-11-08, event 329). Normalise immediately so a task is
                    // never born with that fuse, and so the battery defaults stop
                    // killing the watch on every laptop.
                    return ShieldsUp.Core.Services.ScheduledTaskGuard.Repair(StartupTaskName).Healthy;
                }
                catch
                {
                    return false;
                }
            });
        }

        /// <summary>
        /// The registered logon task as Windows actually holds it — not what
        /// the code intended. Trusting existence alone is how a 72-hour task
        /// stayed invisible: it exists, and it kills the app every three days.
        /// </summary>
        public static ShieldsUp.Core.Services.ScheduledTaskGuard.Health InspectStartupTask()
            => ShieldsUp.Core.Services.ScheduledTaskGuard.Inspect(StartupTaskName);

        /// <summary>
        /// Repairs a poisoned logon task in place. Called on every startup so a
        /// build that ships the fix also cures the task an older build left
        /// behind — the affected user never opened Settings and never will.
        /// </summary>
        public static ShieldsUp.Core.Services.ScheduledTaskGuard.Health EnsureStartupTaskHealthy()
            => ShieldsUp.Core.Services.ScheduledTaskGuard.EnsureUnlimited(StartupTaskName);

        /// <summary>Removes the logon task (same as the Settings toggle).</summary>
        public static Task<bool> DisableLaunchAtLogon()
        {
            return Task.Run(() =>
            {
                try
                {
                    ProcessRunner.RunWithDetails("schtasks", $"/delete /tn \"{StartupTaskName}\" /f");
                    return true;
                }
                catch
                {
                    return false;
                }
            });
        }
    }
}
