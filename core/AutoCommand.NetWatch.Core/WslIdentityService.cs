using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using AutoCommand.NetWatch.Core;

namespace AutoCommand.Services
{
    /// <summary>
    /// Host-side WSL identity: recognizes the WSL process family (the rows
    /// users panic about — "wslservice.exe is uploading!") and answers the
    /// state questions behind the monitor-row decode and get_wsl_status.
    ///
    /// Everything here is a query that CANNOT start the utility VM: process
    /// scans and `wsl --list …` (a listing, not a launch). The guest probes
    /// that would start the VM live behind an explicit VmRunning check.
    ///
    /// wsl.exe emits its list output as UTF-16LE (the historic contract, no
    /// flag needed); DecodeWslOutput handles that plus the newer UTF-8
    /// shapes so a decode never depends on the console codepage.
    /// </summary>
    public static class WslIdentityService
    {
        /// <summary>Process images whose connections belong to the WSL
        /// utility VM or its plumbing — compared WITHOUT the .exe suffix.
        /// vmmem is the pre-1.3 VM image name, vmmemWSL the newer one.</summary>
        private static readonly string[] FamilyNames =
        {
            "wslservice", "wslrelay", "wslhost", "wslg", "wsl", "vmmem", "vmmemwsl",
        };

        public static bool IsWslFamilyProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            string name = processName;
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                name = name[..^4];
            foreach (var f in FamilyNames)
                if (string.Equals(name, f, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        public sealed record WslState(
            bool Installed,
            bool VmRunning,
            string[] RunningDistros,
            string NetworkingMode,
            string ModeNote,
            string Error)
        {
            public static readonly WslState Unknown =
                new(false, false, Array.Empty<string>(), null, null, null);
        }

        private static readonly object _stateLock = new();
        private static WslState _cached;
        private static DateTime _cachedAtUtc = DateTime.MinValue;
        private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Current WSL state (installed / VM running / distros / networking
        /// mode), cached ~60s so the monitor's 10-second enrichment tick
        /// never spawns wsl.exe per pass. Never starts the VM.
        /// </summary>
        public static WslState GetState()
        {
            lock (_stateLock)
            {
                if (_cached != null && DateTime.UtcNow - _cachedAtUtc < CacheLifetime)
                    return _cached;
                _cached = ProbeState();
                _cachedAtUtc = DateTime.UtcNow;
                return _cached;
            }
        }

        private static WslState ProbeState()
        {
            bool vmRunning = IsVmProcessRunning();
            string error = null;
            string[] distros = Array.Empty<string>();
            bool installed = true;

            try
            {
                var (output, exit) = RunWslList("--list --running", Encoding.Unicode);
                if (exit != 0 && string.IsNullOrWhiteSpace(DecodeWslOutput(output)))
                {
                    // wsl.exe errored — one retry with the default encoding
                    // covers newer builds that emit UTF-8 instead of UTF-16.
                    var retry = RunWslList("--list --running", null);
                    distros = ParseRunningDistros(DecodeWslOutput(retry.Output));
                    if (retry.ExitCode != 0 && distros.Length == 0)
                        installed = false;
                }
                else
                {
                    distros = ParseRunningDistros(DecodeWslOutput(output));
                }
            }
            catch (Exception ex)
            {
                installed = false; // Win32Exception: wsl.exe not on PATH
                error = ex.Message;
            }

            var (mode, modeNote) = ReadNetworkingMode();
            return new WslState(installed, vmRunning, distros, mode, modeNote, error);
        }

        private static bool IsVmProcessRunning()
        {
            foreach (var name in new[] { "vmmemWSL", "vmmem" })
            {
                try { if (Process.GetProcessesByName(name).Length > 0) return true; }
                catch { }
            }
            return false;
        }

        /// <summary>
        /// Runs a wsl.exe LIST command with an explicit output encoding
        /// (wsl.exe emits UTF-16LE for list output; null = console default)
        /// and returns the decoded stdout + exit code. Read-only listings
        /// only — this helper must never be pointed at a guest launch.
        /// </summary>
        private static (string Output, int ExitCode) RunWslList(string arguments, Encoding outputEncoding)
        {
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    // Pinned to System32 (user-writable app/CWD resolve first
                    // otherwise; this app runs elevated).
                    FileName = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"),
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            if (outputEncoding != null)
                proc.StartInfo.StandardOutputEncoding = outputEncoding;
            proc.Start();
            // Drain stderr concurrently (see WslGuestProbe.RunWsl).
            var stderrTask = proc.StandardError.ReadToEndAsync();
            string output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(120_000))
            {
                try { proc.Kill(); } catch { }
                proc.WaitForExit();
            }
            _ = stderrTask.Result;
            return (output, proc.ExitCode);
        }

        /// <summary>Strip the UTF-16 decode artifacts (BOM, stray nulls) the
        /// runner's default-encoding fallback can leave behind.</summary>
        public static string DecodeWslOutput(string output)
        {
            if (string.IsNullOrEmpty(output)) return output ?? "";
            return output.TrimStart('\uFEFF').Replace("\0", "").Replace("\r\n", "\n");
        }

        /// <summary>`wsl --list --running` body: one distro name per line, no
        /// header. Empty (or the "no running distributions" notice) = none.</summary>
        public static string[] ParseRunningDistros(string output)
        {
            if (string.IsNullOrWhiteSpace(output)) return Array.Empty<string>();
            var result = new System.Collections.Generic.List<string>();
            foreach (var raw in output.Replace("\r\n", "\n").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                if (line.StartsWith("Windows Subsystem for Linux", StringComparison.OrdinalIgnoreCase))
                    continue; // the official "no running distributions" notice
                if (line.StartsWith("NAME ", StringComparison.OrdinalIgnoreCase))
                    continue; // verbose header strayed in
                result.Add(line);
            }
            return result.ToArray();
        }

        /// <summary>`wsl --list --verbose` rows: "  NAME STATE VERSION".
        /// Returns (name, state, version) per distro, header skipped.</summary>
        public static (string Name, string State, string Version)[] ParseDistroList(string output)
        {
            var result = new System.Collections.Generic.List<(string, string, string)>();
            if (string.IsNullOrWhiteSpace(output)) return result.ToArray();
            foreach (var raw in output.Replace("\r\n", "\n").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("NAME ", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3)
                    result.Add((parts[0], parts[1], parts[2]));
            }
            return result.ToArray();
        }

        // ── networking mode (.wslconfig) ─────────────────────────────────

        /// <summary>Parses the networkingMode= line out of a .wslconfig body.
        /// null/absent → "nat" (the documented default); comments (#/;) and
        /// sections ([wsl2]) tolerated.</summary>
        public static string ParseNetworkingMode(string wslConfigContent)
        {
            if (string.IsNullOrWhiteSpace(wslConfigContent)) return "nat";
            foreach (var raw in wslConfigContent.Replace("\r\n", "\n").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";") || line.StartsWith("["))
                    continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                if (!line[..eq].Trim().Equals("networkingMode", StringComparison.OrdinalIgnoreCase))
                    continue;
                var value = line[(eq + 1)..].Trim();
                return value.Length > 0 ? value.ToLowerInvariant() : "nat";
            }
            return "nat";
        }

        /// <summary>Reads the networking mode from the current profile's
        /// .wslconfig. AutoCommand usually runs elevated as the same user,
        /// but if the launcher's profile differs the note says so — the mode
        /// claim is then best-effort, never a verdict.</summary>
        public static (string Mode, string Note) ReadNetworkingMode()
        {
            try
            {
                string path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wslconfig");
                if (!File.Exists(path))
                    return ("nat", "no .wslconfig found — default NAT mode");
                var mode = ParseNetworkingMode(File.ReadAllText(path));
                return (mode, mode == "nat" ? ".wslconfig: nat" : $".wslconfig: {mode} mode");
            }
            catch
            {
                return (null, "networking mode unknown (.wslconfig unreadable)");
            }
        }
    }
}
