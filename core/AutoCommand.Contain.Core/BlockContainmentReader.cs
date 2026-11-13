using AutoCommand.NetWatch.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using AutoCommand.Engines.Firewall;
using AutoCommand.Engines.Watch;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// Gathers the four live inputs the containment join needs and runs
    /// BlockContainmentVerifier. The single gatherer both consumers share —
    /// the verify_block_containment bridge tool and the Blocks tab's
    /// containment column — so the screen and the AI can never disagree
    /// about whether a block is holding.
    ///
    /// Kernel sockets first, owner identity second: the monitor snapshot's
    /// ordering rule, so a pid reused in between cannot attach the previous
    /// owner's start time to a live socket row. Every input degrades —
    /// unreadable process handles join by pid with unknown start times, an
    /// unreadable archive means an empty flow list — and the verdicts carry
    /// what they were based on.
    /// </summary>
    public static class BlockContainmentReader
    {
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(
            IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr hProcess,
            out long lpCreationTime,
            out long lpExitTime,
            out long lpKernelTime,
            out long lpUserTime);

        private static readonly object _archiveCacheGate = new object();
        private static (string newestFile, long writeTicks, long length, long sinceDayTicks) _archiveStamp;
        private static List<TransmissionRecord> _cachedFlows;

        public sealed class Snapshot
        {
            public DateTime TakenUtc;
            public List<BlockHitFeedService.HitAggregate> Hits;
            public List<BlockedTarget> Inventory;
            public List<BlockContainmentVerifier.Instance> Instances;
            public string Note = "";   // feed/inventory errors, surfaced by both consumers
        }

        /// <summary>
        /// Resolves executable leaf name and UTC start time for a single PID
        /// via PROCESS_QUERY_LIMITED_INFORMATION (&lt;0.05 ms per PID vs ~400 ms
        /// for a full Win32_Process WMI table scan).
        /// </summary>
        internal static (string Name, DateTime? StartedUtc) QueryProcessOwner(int pid)
        {
            if (pid <= 0) return ("System Idle Process", null);
            if (pid == 4) return ("System", null);

            string name = null;
            DateTime? started = null;
            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (hProc != IntPtr.Zero)
            {
                try
                {
                    var sb = new StringBuilder(1024);
                    uint cap = (uint)sb.Capacity;
                    if (QueryFullProcessImageNameW(hProc, 0, sb, ref cap) && cap > 0)
                        name = Path.GetFileName(sb.ToString(0, (int)cap));

                    if (GetProcessTimes(hProc, out long createFt, out _, out _, out _) && createFt > 0)
                        started = DateTime.FromFileTimeUtc(createFt);
                }
                catch { }
                finally { CloseHandle(hProc); }
            }

            if (string.IsNullOrEmpty(name))
            {
                try
                {
                    using var p = Process.GetProcessById(pid);
                    string pn = p.ProcessName;
                    if (!string.IsNullOrEmpty(pn))
                        name = pn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? pn : pn + ".exe";
                }
                catch { }
            }

            return (string.IsNullOrEmpty(name) ? "?" : name, started);
        }

        private static List<TransmissionRecord> ReadFlowsCached(DateTime sinceUtc)
        {
            try
            {
                string dir = TransmissionsArchiveService.ArchiveDirectory;
                if (!Directory.Exists(dir)) return new List<TransmissionRecord>();

                string newest = null;
                foreach (string f in Directory.EnumerateFiles(dir, "transmissions-*.jsonl"))
                {
                    if (newest == null || string.CompareOrdinal(f, newest) > 0)
                        newest = f;
                }
                if (newest == null) return new List<TransmissionRecord>();

                var fi = new FileInfo(newest);
                var stamp = (newest, fi.LastWriteTimeUtc.Ticks, fi.Length, sinceUtc.Date.Ticks);
                lock (_archiveCacheGate)
                {
                    if (_cachedFlows != null && _archiveStamp.Equals(stamp))
                        return _cachedFlows;
                }

                var fresh = TransmissionsArchiveService.Read(200, null, null, sinceUtc);
                lock (_archiveCacheGate)
                {
                    _archiveStamp = stamp;
                    _cachedFlows = fresh;
                }
                return fresh;
            }
            catch
            {
                return TransmissionsArchiveService.Read(200, null, null, sinceUtc);
            }
        }

        /// <summary>
        /// Gathers the four live inputs and runs the join. Callers that already
        /// hold a fresh firewall inventory (e.g. BlocksView) can pass it via
        /// <paramref name="preloadedInventory"/> to avoid a duplicate COM scan.
        /// </summary>
        public static Snapshot Take(int minutes = 60, List<BlockedTarget> preloadedInventory = null)
        {
            if (System.Threading.SynchronizationContext.Current != null)
                throw new InvalidOperationException(
                    "BlockContainmentReader.Take blocks and must not run on a UI thread — " +
                    "call it via Task.Run from UI code.");

            var snap = new Snapshot { TakenUtc = DateTime.UtcNow };

            // Idempotent — every containment reader keeps the feed alive,
            // the same contract the bridge's EnsureFeedStarted follows.
            BlockHitFeedService.Instance.Start();

            snap.Inventory = preloadedInventory
                ?? FirewallService.Instance.GetBlockedInventoryAsync().GetAwaiter().GetResult();
            snap.Hits = BlockHitFeedService.Instance.Aggregates(minutes, 200);

            var conns = TcpConnectionTable.GetEstablished();
            var owners = new Dictionary<int, (string Name, DateTime? StartedUtc)>();
            foreach (var c in conns)
            {
                if (!owners.ContainsKey(c.Pid))
                    owners[c.Pid] = QueryProcessOwner(c.Pid);
            }

            var sockets = conns.Select(c =>
            {
                owners.TryGetValue(c.Pid, out var owner);
                return new BlockContainmentVerifier.LiveSocket
                {
                    Pid = c.Pid,
                    RemoteIp = c.RemoteIp,
                    RemotePort = c.RemotePort,
                    ProcessName = owner.Name,
                    ProcessStartedUtc = owner.StartedUtc,
                };
            }).ToList();

            // Archive read bounded by the oldest block provenance; the
            // verifier applies the per-instance t0 on top of this.
            DateTime since = snap.Inventory.Where(t => t.Created.HasValue).Select(t => t.Created.Value)
                                  .DefaultIfEmpty(DateTime.UtcNow.AddMinutes(-minutes)).Min();
            var flows = ReadFlowsCached(since);

            snap.Instances = BlockContainmentVerifier.Evaluate(snap.Hits, snap.Inventory, sockets, flows);

            var feed = BlockHitFeedService.Instance;
            if (feed.WatcherError != null) snap.Note = $"Feed note: {feed.WatcherError}";
            else if (feed.LastInventoryError != null) snap.Note = $"Inventory note: {feed.LastInventoryError}";
            return snap;
        }
    }
}
