using System;
using AutoCommand.NetWatch.Core;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace AutoCommand.NetWatch.Core
{
    /// <summary>
    /// Shared utility for running native executables (netsh, powercfg, bcdedit, etc.)
    /// No PowerShell dependency — calls executables directly.
    /// </summary>
    public static class ProcessRunner
    {
        // Inbox tools are pinned to System32: this app ships as a portable
        // folder and runs elevated, so a bare name would otherwise be resolved
        // through the app directory and current directory (both user-writable)
        // before System32 — a planted netsh.exe/bcdedit.exe next to the app
        // would execute with admin rights. Names that already carry a path
        // component are used as-is; unknown names fall back to the legacy
        // PATH search so custom tools keep working.
        private static string ResolveTool(string fileName)
        {
            if (string.IsNullOrEmpty(fileName) || fileName.IndexOfAny(new[] { '/', '\\' }) >= 0)
                return fileName;
            try
            {
                string pinned = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), fileName);
                return File.Exists(pinned) ? pinned : fileName;
            }
            catch
            {
                return fileName;
            }
        }

        // No legitimate caller of this class runs a child longer than a
        // couple of seconds (netsh/bcdedit/wsl listings/schtasks/icacls);
        // a hard ceiling keeps a hung child from hanging the app forever.
        private const int ExitTimeoutMs = 120_000;

        public static string Run(string fileName, string arguments)
        {
            return Run(fileName, arguments, null);
        }

        /// <summary>
        /// Run with an explicit output encoding. Required for Sysinternals tools
        /// (sigcheck etc.), which emit UTF-16LE on redirected stdout — reading them
        /// with the default codepage yields interleaved-null mojibake.
        /// </summary>
        public static string Run(string fileName, string arguments, Encoding outputEncoding)
        {
            fileName = ResolveTool(fileName);
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            if (outputEncoding != null)
                proc.StartInfo.StandardOutputEncoding = outputEncoding;
            proc.Start();
            // Drain stderr concurrently: reading stdout to EOF first deadlocks
            // against a child that fills its stderr pipe (wsl.exe and
            // Sysinternals tools do).
            var stderrTask = proc.StandardError.ReadToEndAsync();
            string output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(ExitTimeoutMs))
            {
                try { proc.Kill(); } catch { }
                proc.WaitForExit();
            }
            return StripNullChars(output);
        }

        public static (string Output, string Error, int ExitCode) RunWithDetails(string fileName, string arguments)
        {
            fileName = ResolveTool(fileName);
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            // Drain stderr concurrently (see Run above).
            var stderrTask = proc.StandardError.ReadToEndAsync();
            string output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(ExitTimeoutMs))
            {
                try { proc.Kill(); } catch { }
                proc.WaitForExit();
            }
            string error = stderrTask.Result;
            return (StripNullChars(output), StripNullChars(error), proc.ExitCode);
        }

        public static Task<string> RunAsync(string fileName, string arguments)
        {
            return Task.Run(() => Run(fileName, arguments));
        }

        public static Task<string> RunAsync(string fileName, string arguments, Encoding outputEncoding)
        {
            return Task.Run(() => Run(fileName, arguments, outputEncoding));
        }

        public static Task<(string Output, string Error, int ExitCode)> RunWithDetailsAsync(string fileName, string arguments)
        {
            return Task.Run(() => RunWithDetails(fileName, arguments));
        }

        /// <summary>
        /// Fire-and-forget execution. Returns immediately.
        /// </summary>
        public static void RunDetached(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = ResolveTool(fileName),
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi)?.Dispose();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ProcessRunner.RunDetached Error: {ex.Message}");
            }
        }

        private static string StripNullChars(string value)
        {
            return string.IsNullOrEmpty(value) || value.IndexOf('\0') < 0
                ? value
                : value.Replace("\0", "");
        }
    }
}
