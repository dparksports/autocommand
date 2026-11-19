using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoCommand.Engines.Watch;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// BITS job guard — the containment layer that does not trust the
    /// socket's identity.
    ///
    /// Why it exists: BITS performs its transfers under the JOB OWNER's
    /// token (documented BITS behavior — the job owner's credentials are
    /// used for network access), not under the NT SERVICE\BITS per-service
    /// identity. The service-scoped firewall rule (AC-BLOCK-SVC bits (Out),
    /// INetFwRule.ServiceName = "bits") therefore never matches BITS
    /// traffic: the connection presents as whoever queued the job, the
    /// ServiceName condition misses, and the rule blocks nothing. Three
    /// layers that DO hold:
    ///
    ///   L1 — catch the spawn: a dedicated svchost instance (`-k netsvcs
    ///        -p -s BITS`) is the only place BITS ever runs. The Sysmon
    ///        archive's Appended hook (the same seam SpawnWatch uses)
    ///        flags the spawn and hands us PID + ProcessGuid.
    ///
    ///   L2 — guard the job queue: every BITS transfer IS a job, and the
    ///        job carries its destination URL before the first connect.
    ///        Enumerating IBackgroundCopyManager and canceling foreign
    ///        jobs (IBackgroundCopyJob::Cancel) stops transfers that no
    ///        prior-IP block could have known about — the decision is on
    ///        the job's URL at queue time, not on remembered addresses.
    ///
    ///   L3 — the socket belt: any TCP flow the known BITS PID still
    ///        holds toward a non-allowlisted remote is torn down with
    ///        SetTcpEntry (MIB_TCP_STATE_DELETE_TCB). Not preventive for
    ///        the first packet, but starving: BITS backs off exponentially
    ///        and the instance never gets a conversation through.
    ///
    /// Everything lands in blocks-events.log under origin "job-guard" so
    /// the Blocks tab, trace_block and the instance rows tell the same
    /// story the packets did. Policy file (re-read per sweep, house
    /// pattern): %LOCALAPPDATA%\AutoCommand\bits_guard_pref.txt with
    ///   off     — watch nothing, do nothing
    ///   audit   — log jobs and flows, cancel/kill nothing
    ///   enforce — cancel/kill unless every remote classifies Microsoft
    ///   strict  — cancel/kill everything
    /// Default: enforce (matches the app's posture — the monitor actor
    /// already auto-blocks Unclassified BITS destinations per-IP; this is
    /// that decision moved to where it can actually bite).
    /// </summary>
    public static class BitsJobGuardService
    {
        // ── policy ────────────────────────────────────────────────────────

        private static string PolicyFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "bits_guard_pref.txt");

        /// <summary>Re-read per sweep — a hand edit takes effect without a
        /// restart (same contract as the spawn-watch rule files). Unknown
        /// or missing content means enforce.</summary>
        private static string ReadPolicy()
        {
            try
            {
                if (!File.Exists(PolicyFilePath)) return "enforce";
                var value = File.ReadAllText(PolicyFilePath).Trim().ToLowerInvariant();
                return value is "off" or "audit" or "enforce" or "strict" ? value : "enforce";
            }
            catch { return "enforce"; }
        }

        // ── tracked instances (L1) ────────────────────────────────────────

        private sealed class BitsInstance
        {
            public int Pid;
            public string ProcessGuid;
            public string CommandLine;
            public DateTime SpawnedUtc;
            public int AliveMisses; // consecutive liveness misses before we let go
        }

        private static readonly ConcurrentDictionary<string, BitsInstance> _instances = new();
        private static readonly ConcurrentQueue<ArchiveEvent> _queue = new();
        private static readonly object _gate = new();
        private static bool _started;

        /// <summary>Recent guard activity for tabs/tools — bounded ring.</summary>
        private static readonly ConcurrentQueue<string> _activity = new();
        private static void Note(string line)
        {
            _activity.Enqueue($"{DateTime.UtcNow:HH:mm:ss} {line}");
            while (_activity.Count > 40) _activity.TryDequeue(out _);
        }
        public static List<string> RecentActivity() => _activity.ToList();
        public static int TrackedInstanceCount => _instances.Count;

        // ── lifecycle ─────────────────────────────────────────────────────

        /// <summary>Subscribes to the archive's Appended hook and starts the
        /// sweep. Idempotent; call AFTER Backfill like SpawnWatchService
        /// starts, so no backfilled history replays as spawns.</summary>
        public static void Start()
        {
            lock (_gate)
            {
                if (_started) return;
                _started = true;
                SysmonArchiveService.Appended += OnAppended;
                _ = Task.Run(SweepLoop);
                Note("guard started");
            }
        }

        /// <summary>The hook handler. Runs while the archive lock is HELD —
        /// enqueue and return, nothing else (SpawnWatch's contract).</summary>
        private static void OnAppended(object sender, ArchiveEvent e)
        {
            if (e == null || e.Eid != 1) return;
            _queue.Enqueue(e);
        }

        private static async Task SweepLoop()
        {
            while (true)
            {
                try { Sweep(); }
                catch { /* one bad sweep never stops the guard */ }
                await Task.Delay(2000).ConfigureAwait(false);
            }
        }

        // ── the sweep ─────────────────────────────────────────────────────

        private static void Sweep()
        {
            // Drain the spawn queue (enqueue-only handler; matching here).
            while (_queue.TryDequeue(out var e)) TrackSpawn(e);

            var policy = ReadPolicy();
            if (policy == "off") { _instances.Clear(); return; }

            PruneDeadInstances();
            if (_instances.IsEmpty) return;

            // L2 — the job queue: destinations visible before any connect.
            SweepJobs(policy);

            // L3 — the socket belt: starve whatever flows the PID holds.
            if (policy != "audit")
                foreach (var pid in _instances.Values.Select(i => i.Pid).Distinct().ToList())
                    KillForeignFlows(pid, policy);
        }

        private static void TrackSpawn(ArchiveEvent e)
        {
            // Dedicated BITS instance: the `-s BITS` svchost. A masquerade
            // that CLAIMS BITS on its command line is exactly what we want
            // guarded too, so the -s token alone is enough here.
            string image = Get(e, "Image");
            string commandLine = Get(e, "CommandLine");
            if (string.IsNullOrEmpty(image) ||
                !image.EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase)) return;
            if (string.IsNullOrEmpty(commandLine)) return;

            int sIdx = commandLine.IndexOf("-s", StringComparison.Ordinal);
            if (sIdx < 0 || sIdx + 2 >= commandLine.Length) return;
            var serviceClaim = commandLine[(sIdx + 2)..].TrimStart().Split(' ')[0].Trim('"');
            if (!serviceClaim.Equals("bits", StringComparison.OrdinalIgnoreCase)) return;

            string guid = Get(e, "ProcessGuid");
            string pidText = Get(e, "ProcessId");
            if (!int.TryParse(pidText, out var pid) || pid <= 0) return;

            _instances[guid ?? $"pid-{pid}"] = new BitsInstance
            {
                Pid = pid,
                ProcessGuid = guid,
                CommandLine = commandLine,
                SpawnedUtc = DateTime.UtcNow,
            };

            BlocksStore.AppendEvent("job-guard", "svc", "bits",
                $"spawn pid={pid} guid={guid ?? "?"} policy={ReadPolicy()} claim=-s {serviceClaim}",
                "job-guard");
            Note($"spawn pid {pid} tracked ({_instances.Count} live)");
        }

        private static string Get(ArchiveEvent e, string field) =>
            e.Data != null && e.Data.TryGetValue(field, out var v) ? v : null;

        private static void PruneDeadInstances()
        {
            foreach (var kv in _instances)
            {
                bool alive;
                try { alive = Process.GetProcessById(kv.Value.Pid) != null; }
                catch { alive = false; } // exited — GetProcessById throws

                if (alive) { kv.Value.AliveMisses = 0; continue; }

                kv.Value.AliveMisses++;
                // two consecutive misses: gone for good (one miss guards
                // against a transient enumeration hiccup)
                if (kv.Value.AliveMisses >= 2)
                {
                    _instances.TryRemove(kv.Key, out _);
                    BlocksStore.AppendEvent("job-guard", "svc", "bits",
                        $"instance exited pid={kv.Value.Pid} guid={kv.Value.ProcessGuid ?? "?"}", "job-guard");
                    Note($"pid {kv.Value.Pid} exited — guard released");
                }
            }
        }

        // ── L2: the job queue ─────────────────────────────────────────────

        private sealed class JobSighting
        {
            public string Name;
            public string Owner;
            public string State;
            public List<string> RemoteHosts = new();
        }

        private static void SweepJobs(string policy)
        {
            List<JobSighting> jobs;
            try { jobs = EnumerateJobs(); }
            catch (Exception ex)
            {
                // BITS COM can legitimately refuse (service stopped, RPC
                // hiccup) — the L3 belt still runs on the PID
                Note($"job enumeration unavailable: {ex.Message}");
                return;
            }
            if (jobs.Count == 0) return;

            int canceled = 0;

            foreach (var job in jobs)
            {
                // Policy decision — on the job's own URL, not remembered IPs.
                bool foreign = policy == "strict"
                    || job.RemoteHosts.Count == 0 // no URL readable: safe side is foreign
                    || job.RemoteHosts.Any(h => !IsAllowedHost(h));

                if (!foreign)
                {
                    if (policy == "audit")
                        Note($"allowed job '{job.Name}' remotes={Describe(job.RemoteHosts)}");
                    continue;
                }

                if (policy == "audit")
                {
                    Note($"foreign job present (audit): '{job.Name}' remotes={Describe(job.RemoteHosts)}");
                    continue;
                }

                if (TryCancelJob(job))
                {
                    canceled++;
                    Note($"canceled job '{job.Name}' owner={job.Owner ?? "?"} " +
                         $"state={job.State} remotes={Describe(job.RemoteHosts)} policy={policy}");
                    BlocksStore.AppendEvent("job-guard", "svc", "bits",
                        $"canceled job '{Sanitize(job.Name)}' owner={job.Owner ?? "?"} " +
                        $"state={job.State} remotes={Sanitize(Describe(job.RemoteHosts))} policy={policy}",
                        "job-guard");
                }
            }

            if (canceled > 0)
                Note($"canceled {canceled} foreign job(s) under policy={policy}");
        }

        private static string Describe(List<string> hosts) =>
            hosts.Count == 0 ? "(none readable)" : string.Join(", ", hosts);

        private static string Sanitize(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            var sb = new StringBuilder(s);
            for (int i = 0; i < sb.Length; i++)
                if (sb[i] == '|' || sb[i] == '\r' || sb[i] == '\n') sb[i] = ' ';
            return sb.ToString();
        }

        // Host allowlist: range classification first (Microsoft/Azure covers
        // Windows Update's edge fleet), plus the handful of hostname suffixes
        // the range classifier cannot see for itself.
        private static readonly string[] AllowedHostSuffixes =
        {
            "windowsupdate.com", "microsoft.com", "windows.com",
            "azureedge.net", "msn.com", "bing.com",
        };

        private static readonly ConcurrentDictionary<string, bool> _hostVerdicts = new();

        private static bool IsAllowedHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            var lower = host.Trim().ToLowerInvariant().TrimEnd('.');
            return _hostVerdicts.GetOrAdd(lower, static h =>
            {
                foreach (var suffix in AllowedHostSuffixes)
                    if (h == suffix || h.EndsWith("." + suffix, StringComparison.Ordinal))
                        return true;
                try
                {
                    var addresses = Dns.GetHostAddresses(h);
                    foreach (var address in addresses)
                        if (IpClassifier.Classify(address.ToString()) == "Microsoft/Azure")
                            return true;
                }
                catch { /* unresolvable = foreign */ }
                return false;
            });
        }

        // ── L3: the socket belt ───────────────────────────────────────────

        private static void KillForeignFlows(int pid, string policy)
        {
            try
            {
                int killed = 0;
                var remotes = new HashSet<string>(StringComparer.Ordinal);
                foreach (var row in ReadOwnedTcpRows(pid))
                {
                    if (policy != "strict" && IsAllowedHost(row.remoteIp)) continue;
                    if (SetTcpEntryKill(row.row)) { killed++; remotes.Add(row.remoteIp); }
                }
                if (killed > 0)
                {
                    // Aggregated trail line — a kill storm must not flood the log
                    BlocksStore.AppendEvent("job-guard", "svc", "bits",
                        $"killed {killed} flow(s) pid={pid} remotes={string.Join(",", remotes)} policy={policy}",
                        "job-guard");
                    Note($"killed {killed} flow(s) owned by pid {pid}");
                }
            }
            catch { /* the belt is best-effort; L2 already canceled the jobs */ }
        }

        // ── BITS COM interop (vtable order is the contract) ──────────────

        private static readonly Guid ClsidBackgroundCopyManager =
            new("4991d60b-34b4-4e9a-96f0-f18abfd9e122"); // CLSID_BackgroundCopyManager

        /// <summary>Runtime coclass activation (GetTypeFromCLSID → QI) —
        /// avoids the compile-time coclass cast, which the modern
        /// compilers no longer accept for hand-declared interfaces.</summary>
        private static IBackgroundCopyManager CreateManager() =>
            (IBackgroundCopyManager)Activator.CreateInstance(
                Type.GetTypeFromCLSID(ClsidBackgroundCopyManager));

        [ComImport]
        [Guid("5CE34C0D-0DC9-4C1F-8CBF-1C4082B7C9B3")] // IID_IBackgroundCopyManager
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IBackgroundCopyManager
        {
            void CreateJob(
                [MarshalAs(UnmanagedType.LPWStr)] string displayName,
                int type, out Guid jobId,
                [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyJob job);
            void GetJob(ref Guid jobId,
                [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyJob job);
            void GetErrorDescription(int hresult, uint languageId,
                [MarshalAs(UnmanagedType.LPWStr)] out string error);
            void EnumJobs(uint flags,
                [MarshalAs(UnmanagedType.Interface)] out IEnumBackgroundCopyJobs jobs);
        }

        /// <summary>IBackgroundCopyJob, vtable slots 1-13 in IDL order.
        /// Only EnumFiles(3), Cancel(6), GetId(8), GetDisplayName(9),
        /// GetState(12) and GetOwner(13) are called; the rest are declared
        /// so the slots line up. Never reorder.</summary>
        [ComImport]
        [Guid("37668D37-507E-4160-9316-EA71C4C94975")] // IID_IBackgroundCopyJob
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IBackgroundCopyJob
        {
            void AddFileSet(IntPtr fileInfo, uint count);            // 1 — unused
            void AddFile([MarshalAs(UnmanagedType.LPWStr)] string remoteUrl,
                [MarshalAs(UnmanagedType.LPWStr)] string localName);  // 2 — unused
            void EnumFiles(
                [MarshalAs(UnmanagedType.Interface)] out IEnumBackgroundCopyFiles files); // 3
            void Suspend();                                          // 4 — unused
            void Resume();                                           // 5 — unused
            void Cancel();                                           // 6
            void Complete();                                         // 7 — unused
            void GetId(out Guid id);                                 // 8
            [return: MarshalAs(UnmanagedType.LPWStr)] string GetDisplayName(); // 9
            [return: MarshalAs(UnmanagedType.LPWStr)] string GetDescription(); // 10
            void GetPriority(out int priority);                      // 11 — unused
            void GetState(out int state);                            // 12
            [return: MarshalAs(UnmanagedType.LPWStr)] string GetOwner();       // 13
        }

        [ComImport]
        [Guid("CA51E59D-7EF6-46C5-B3EB-66E44BAF9E93")] // IID_IEnumBackgroundCopyJobs
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IEnumBackgroundCopyJobs
        {
            void Next(uint celt,
                [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyJob job,
                out uint fetched);
            void Skip(uint celt);
            void Reset();
            void Clone(
                [MarshalAs(UnmanagedType.Interface)] out IEnumBackgroundCopyJobs clone);
        }

        /// <summary>File enumeration: the remote URL of each file in the
        /// job. If these IIDs QI-fail on a given stack, the policy decides
        /// on display name alone — the safe side is foreign.</summary>
        [ComImport]
        [Guid("CA51E599-7EF6-46C5-B3EB-66E44BAF9E93")] // IID_IEnumBackgroundCopyFiles
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IEnumBackgroundCopyFiles
        {
            void Next(uint celt,
                [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyFile file,
                out uint fetched);
            void Skip(uint celt);
            void Reset();
            void Clone(
                [MarshalAs(UnmanagedType.Interface)] out IEnumBackgroundCopyFiles clone);
        }

        [ComImport]
        [Guid("481A6195-0A0D-4863-99DC-B959AFA2B66C")] // IID_IBackgroundCopyFile
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IBackgroundCopyFile
        {
            void GetRemoteName([MarshalAs(UnmanagedType.LPWStr)] out string name); // 1
            void GetLocalName([MarshalAs(UnmanagedType.LPWStr)] out string name);  // 2
        }

        private static List<JobSighting> EnumerateJobs()
        {
            var result = new List<JobSighting>();
            var manager = CreateManager();
            manager.EnumJobs(0, out var jobs);

            while (true)
            {
                jobs.Next(1, out var job, out var fetched);
                if (fetched == 0) break;

                var sighting = new JobSighting();
                try { sighting.Name = job.GetDisplayName(); } catch { sighting.Name = "?"; }
                try { sighting.Owner = job.GetOwner(); } catch { sighting.Owner = "?"; }
                try
                {
                    job.GetState(out var state);
                    sighting.State = state switch
                    {
                        0 => "queued", 1 => "connecting", 2 => "transferring",
                        3 => "suspended", 4 => "error", 5 => "transient-error",
                        6 => "transferred", 7 => "acknowledged", 8 => "canceled",
                        _ => $"state{state}",
                    };
                }
                catch { sighting.State = "?"; }
                if (sighting.State is "acknowledged" or "canceled") continue;

                try
                {
                    job.EnumFiles(out var files);
                    for (int i = 0; i < 64; i++) // BITS jobs are small; cap anyway
                    {
                        files.Next(1, out var file, out var fetchedFile);
                        if (fetchedFile == 0) break;
                        try
                        {
                            file.GetRemoteName(out var remote);
                            if (!string.IsNullOrEmpty(remote))
                            {
                                var host = ExtractHost(remote);
                                if (!string.IsNullOrEmpty(host)) sighting.RemoteHosts.Add(host);
                            }
                        }
                        catch { /* one unreadable file never stops the job walk */ }
                    }
                }
                catch
                {
                    // QI/marshal failure on the file interfaces: decide on
                    // display name alone — the safe side is foreign
                }

                result.Add(sighting);
            }
            return result;
        }

        private static string ExtractHost(string url)
        {
            var start = url.IndexOf("://", StringComparison.Ordinal);
            if (start >= 0) start += 3; else start = 0;
            var end = start;
            while (end < url.Length && url[end] != '/' && url[end] != ':' && url[end] != '?') end++;
            return url[start..end];
        }

        private static bool TryCancelJob(JobSighting job)
        {
            try
            {
                var manager = CreateManager();
                manager.EnumJobs(0, out var jobs);
                while (true)
                {
                    jobs.Next(1, out var comJob, out var fetched);
                    if (fetched == 0) return false;
                    string name;
                    try { name = comJob.GetDisplayName(); } catch { name = null; }
                    if (name != job.Name) continue;
                    try { comJob.Cancel(); return true; }
                    catch { return false; }
                }
            }
            catch { return false; }
        }

        // ── the kernel TCP table ──────────────────────────────────────────

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int MIB_TCP_STATE_DELETE_TCB = 12;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
            public uint OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW
        {
            public uint State;
            public uint LocalAddr;
            public uint LocalPort;
            public uint RemoteAddr;
            public uint RemotePort;
        }

        [DllImport("Ws2_32.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int dwSize, bool bOrder, int family,
            int tableClass, int reserved);

        [DllImport("IpHlpApi.dll", SetLastError = true)]
        private static extern uint SetTcpEntry(ref MIB_TCPROW row);

        /// <summary>Rows owned by the PID, with the remote in dotted form.
        /// Port/addr fields stay raw (network byte order) — SetTcpEntry
        /// wants them exactly as the table reported.</summary>
        private static List<(string remoteIp, MIB_TCPROW row)> ReadOwnedTcpRows(int pid)
        {
            var result = new List<(string, MIB_TCPROW)>();
            int size = 0;
            // first call with a null buffer returns the needed size
            _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return result;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var err = GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (err != 0) return result;

                // MIB_TCPTABLE_OWNER_PID: DWORD dwNumEntries, then rows
                uint count = (uint)Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                var rowPtr = IntPtr.Add(buffer, sizeof(uint));

                for (uint i = 0; i < count; i++, rowPtr = IntPtr.Add(rowPtr, rowSize))
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    if (row.OwningPid != (uint)pid) continue;

                    // network byte order → dotted
                    var addrBytes = BitConverter.GetBytes(row.RemoteAddr);
                    var remoteIp = new IPAddress(addrBytes).ToString();

                    result.Add((remoteIp, new MIB_TCPROW
                    {
                        State = row.State,
                        LocalAddr = row.LocalAddr,
                        LocalPort = row.LocalPort,
                        RemoteAddr = row.RemoteAddr,
                        RemotePort = row.RemotePort,
                    }));
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return result;
        }

        private static bool SetTcpEntryKill(MIB_TCPROW row)
        {
            row.State = MIB_TCP_STATE_DELETE_TCB;
            return SetTcpEntry(ref row) == 0; // NO_ERROR
        }
    }
}
