using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;

namespace AutoCommand.Services
{
    /// <summary>
    /// The guest half of WSL traffic visibility: the Linux-side socket table
    /// (ss -tnp) per running distro, joined to the host's WSL-family
    /// connections by destination endpoint (NAT preserves it, so the guest's
    /// peer IS the host row's remote).
    ///
    /// Guarded never to start the utility VM: Probe() checks the vmmem
    /// process first and returns a not-running snapshot instead of launching
    /// anything. Results cache ~30s so the monitor's enrichment tick and the
    /// bridge share one probe.
    /// </summary>
    public static class WslGuestProbe
    {
        public sealed record GuestSocket(string State, string Local, string Peer, string Process, int? Pid);

        public sealed record DistroSnapshot(string Distro, bool Ok, GuestSocket[] Sockets, string Error);

        public sealed record GuestSnapshot(bool VmRunning, DistroSnapshot[] Distros, DateTime ProbedUtc)
        {
            public static readonly GuestSnapshot NotRunning =
                new(false, Array.Empty<DistroSnapshot>(), DateTime.MinValue);

            public IEnumerable<GuestSocket> AllSockets =>
                Distros.SelectMany(d => d.Sockets);
        }

        private static readonly object _lock = new();
        private static GuestSnapshot _cached;
        private static DateTime _cachedAtUtc = DateTime.MinValue;
        private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(30);

        public static GuestSnapshot Probe()
        {
            lock (_lock)
            {
                if (_cached != null && DateTime.UtcNow - _cachedAtUtc < CacheLifetime)
                    return _cached;
                _cached = ProbeNow();
                _cachedAtUtc = DateTime.UtcNow;
                return _cached;
            }
        }

        private static GuestSnapshot ProbeNow()
        {
            // The guard that matters: a bare `wsl -e …` would START the VM.
            foreach (var name in new[] { "vmmemWSL", "vmmem" })
            {
                try { if (Process.GetProcessesByName(name).Length > 0) return ProbeDistros(); }
                catch { }
            }
            return GuestSnapshot.NotRunning;
        }

        private static GuestSnapshot ProbeDistros()
        {
            // Probe each RUNNING distro (default distro alone would miss
            // docker-desktop etc.); a distro name from --list --running is
            // trusted enough to pass through -d with quoting.
            string[] distros;
            try
            {
                var (output, _) = RunWsl("--list --running");
                distros = WslIdentityService.ParseRunningDistros(DecodeOutput(output, 0));
                if (distros.Length == 0) distros = new[] { (string)null }; // VM up, list unreadable — try default
            }
            catch
            {
                distros = new[] { (string)null };
            }

            var snapshots = new List<DistroSnapshot>();
            foreach (var d in distros.Distinct())
                snapshots.Add(ProbeDistro(d));

            return new GuestSnapshot(true, snapshots.ToArray(), DateTime.UtcNow);
        }

        private static DistroSnapshot ProbeDistro(string distro)
        {
            try
            {
                var (output, exit) = RunWsl(distro == null ? "-e ss -tnp" : $"-d \"{distro}\" -e ss -tnp");
                var text = DecodeOutput(output, exit);
                if (exit != 0 && !text.Contains("ESTAB"))
                    return new DistroSnapshot(distro, false, Array.Empty<GuestSocket>(),
                        exit == 127 ? "ss not available in this distro" : $"ss -tnp failed (exit {exit})");
                return new DistroSnapshot(distro, true, ParseSsOutput(text), null);
            }
            catch (Exception ex)
            {
                return new DistroSnapshot(distro, false, Array.Empty<GuestSocket>(), ex.Message);
            }
        }

        /// <summary>Raw wsl.exe output decode: trims a UTF-16 BOM artifact and
        /// stray nulls whichever encoding the pipe produced.</summary>
        public static string DecodeOutput(string output, int exitCode)
        {
            if (string.IsNullOrEmpty(output)) return output ?? "";
            return output.TrimStart('\uFEFF').Replace("\0", "").Replace("\r\n", "\n");
        }

        /// <summary>
        /// Parses `ss -tnp` output (established TCP with the owning process).
        /// Two real shapes exist: State-first ("ESTAB 0 0 local peer users:…")
        /// and Netid-first ("tcp ESTAB 0 0 local peer users:…", seen when both
        /// families are printed). Both are handled; headers and
        /// non-established lines are skipped.
        /// </summary>
        public static GuestSocket[] ParseSsOutput(string output)
        {
            var sockets = new List<GuestSocket>();
            if (string.IsNullOrWhiteSpace(output)) return sockets.ToArray();

            foreach (var raw in output.Replace("\r\n", "\n").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                var cols = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (cols.Length < 5) continue;

                int stateIdx;
                if (cols[0].Equals("ESTAB", StringComparison.OrdinalIgnoreCase))
                    stateIdx = 0;                                   // State Recv-Q Send-Q Local Peer [Process]
                else if (cols[0].Equals("State", StringComparison.OrdinalIgnoreCase) ||
                         cols[0].Equals("Netid", StringComparison.OrdinalIgnoreCase))
                    continue;                                       // header (either shape)
                else if (cols[0].StartsWith("tcp", StringComparison.OrdinalIgnoreCase) ||
                         cols[0].StartsWith("udp", StringComparison.OrdinalIgnoreCase) ||
                         cols[0].StartsWith("raw", StringComparison.OrdinalIgnoreCase))
                    stateIdx = 1;                                   // Netid State Recv-Q Send-Q Local Peer [Process]
                else
                    continue;                                       // unknown shape — skip, never guess

                if (!cols[stateIdx].Equals("ESTAB", StringComparison.OrdinalIgnoreCase)) continue;
                int local = stateIdx + 3, peer = stateIdx + 4;
                if (cols.Length <= peer) continue;

                string process = null;
                int? pid = null;
                if (cols.Length > peer + 1)
                {
                    var token = cols[peer + 1];
                    if (token.StartsWith("users:") || token.StartsWith("("))
                    {
                        if (!token.StartsWith("users:")) token = "users:" + token;
                        (process, pid) = ParseSsProcess(token);
                    }
                }

                sockets.Add(new GuestSocket(cols[stateIdx], cols[local], cols[peer], process, pid));
            }
            return sockets.ToArray();
        }

        /// <summary>First (name,pid) out of users:(("node",pid=4312,fd=31),(("nginx",pid=99,fd=8)).</summary>
        public static (string Process, int? Pid) ParseSsProcess(string usersToken)
        {
            try
            {
                int open = usersToken.IndexOf("((\"", StringComparison.Ordinal);
                if (open < 0) return (null, null);
                var body = usersToken[(open + 2)..];
                var first = body.Split(',').Select(p => p.Trim('"', ' ', '('));
                string name = null;
                int? pid = null;
                foreach (var part in first)
                {
                    if (name == null && !part.Contains('='))
                        name = part;
                    else if (part.StartsWith("pid=", StringComparison.OrdinalIgnoreCase) &&
                             int.TryParse(part[4..].TrimEnd(')'), NumberStyles.Integer, CultureInfo.InvariantCulture, out var p))
                        pid = p;
                    if (name != null && pid != null) break;
                }
                return (name, pid);
            }
            catch
            {
                return (null, null);
            }
        }

        /// <summary>Splits "1.1.1.1:80" / "[::1]:443" into (ip, port).</summary>
        public static (string Ip, string Port) SplitEndpoint(string endpoint)
        {
            if (string.IsNullOrEmpty(endpoint)) return (null, null);
            if (endpoint.StartsWith("["))
            {
                int close = endpoint.IndexOf(']');
                if (close > 0)
                {
                    var ip = endpoint[1..close];
                    var port = close + 1 < endpoint.Length && endpoint[close + 1] == ':' ? endpoint[(close + 2)..] : null;
                    return (ip, port);
                }
            }
            int colon = endpoint.LastIndexOf(':');
            return colon > 0 ? (endpoint[..colon], endpoint[(colon + 1)..]) : (endpoint, null);
        }

        /// <summary>
        /// The join: guest sockets whose peer IP equals a host connection's
        /// remote IP. NAT preserves the destination, so this is the honest
        /// key — multiple guest sockets can legitimately match one host row
        /// (same destination from several Linux processes).
        /// </summary>
        public static IEnumerable<(DistroSnapshot Distro, GuestSocket Socket)> MatchByRemoteIp(
            GuestSnapshot snapshot, string remoteIp)
        {
            if (snapshot == null || string.IsNullOrEmpty(remoteIp) || !snapshot.VmRunning)
                yield break;
            foreach (var d in snapshot.Distros)
                foreach (var s in d.Sockets)
                    if (string.Equals(SplitEndpoint(s.Peer).Ip, remoteIp, StringComparison.OrdinalIgnoreCase))
                        yield return (d, s);
        }

        private static (string Output, int ExitCode) RunWsl(string arguments)
        {
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    // Pinned to System32: the app runs elevated from a
                    // portable folder, so an unqualified "wsl.exe" would
                    // resolve through the app/CWD first (user-writable).
                    FileName = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"),
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            proc.Start();
            // Drain stderr concurrently — wsl.exe can write enough to it to
            // deadlock a sequential read.
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
    }
}
