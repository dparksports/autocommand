using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace AutoCommand.Intercept.Core
{
    /// <summary>
    /// App-startup repair sweep for layer-3 leftovers (2026-11 review): a
    /// crash in the wrong instant could leave (a) the intercept CA trusted
    /// in the machine Root store with no journal to undo it, or (b) the
    /// machine/user proxy pointing at a dead loopback port.
    /// RecoverAfterCrash covers the journaled cases at the same call site;
    /// this sweep catches the unjournaled stragglers. Both fire ONLY when no
    /// session is live and the journal is absent — a live session OWNS that
    /// trust and that proxy, and must never see them removed under it.
    /// Best-effort and visible: the caller surfaces every repair it makes.
    /// </summary>
    public static class InterceptStartupRepair
    {
        private static readonly Regex LoopbackProxyPattern =
            new(@"^127\.0\.0\.1:(\d+)$", RegexOptions.Compiled);

        /// <summary>Human-readable lines describing what was repaired
        /// (empty = nothing to do).</summary>
        public static List<string> RepairIfNeeded()
        {
            var repairs = new List<string>();
            try
            {
                if (InterceptProxyService.Shared.IsRunning) return repairs;
                if (File.Exists(InterceptSystemHooks.JournalPathForRepair)) return repairs;

                repairs.AddRange(RemoveStrandedCa());
                repairs.AddRange(RestoreDeadLoopbackProxy());
            }
            catch { /* repair is best-effort; never block startup */ }
            return repairs;
        }

        // ── stranded machine trust ────────────────────────────────────────

        private static IEnumerable<string> RemoveStrandedCa()
        {
            var repaired = new List<string>();

            // (a) the CA this install persists (DPAPI-wrapped pfx), matched by
            //     thumbprint — no CA is created by asking
            string persisted = InterceptCaService.TryGetPersistedThumbprint();
            if (persisted != null && InterceptCaService.RemoveFromRoot(persisted))
                repaired.Add("Removed the AutoCommand intercept CA still trusted machine-wide from a previous session.");

            // (b) any cert with our exact subject — older installs whose pfx
            //     is already gone left Root entries RemoveFromRoot could not
            //     find by thumbprint alone. Exact-subject match only; never a
            //     blanket store cleanup.
            try
            {
                var thumbprints = new List<string>();
                using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    foreach (var cert in store.Certificates.Find(
                                 X509FindType.FindBySubjectName, SubjectLeaf(), validOnly: false))
                        thumbprints.Add(cert.Thumbprint);
                }
                foreach (string tp in thumbprints)
                    if (InterceptCaService.RemoveFromRoot(tp))
                        repaired.Add("Removed a leftover AutoCommand intercept CA (older install) from machine trust.");
            }
            catch { /* store unreadable — next startup retries */ }

            return repaired;
        }

        // "CN=AutoCommand Intercept CA,O=AutoCommand" → the CN's leaf value
        // for FindBySubjectName (which matches the CN component).
        private static string SubjectLeaf()
        {
            string subject = InterceptCaService.CaSubjectForRepair;
            int start = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) + 3;
            int comma = subject.IndexOf(',', start);
            return comma < 0 ? subject[start..] : subject[start..comma];
        }

        // ── dead loopback proxy ───────────────────────────────────────────

        private static IEnumerable<string> RestoreDeadLoopbackProxy()
        {
            // WinHTTP (services). Only the exact shape our hooks install —
            // "127.0.0.1:<port>" — with nothing listening behind it; a real
            // local proxy tool (often also loopback) is left alone when its
            // port answers.
            string server = InterceptSystemHooks.InspectWinHttpProxy();
            foreach (string repair in DeadLoopback(server, "services (WinHTTP)"))
            {
                InterceptSystemHooks.ResetWinHttpProxyForRepair();
                yield return repair;
            }

            // WinINET (per-user apps).
            var (_, wininetServer) = InterceptSystemHooks.InspectWininetProxy();
            foreach (string repair in DeadLoopback(wininetServer, "user apps (WinINET)"))
            {
                InterceptSystemHooks.ClearWininetProxyForRepair();
                yield return repair;
            }
        }

        private static IEnumerable<string> DeadLoopback(string server, string scope)
        {
            if (string.IsNullOrWhiteSpace(server)) yield break;
            var m = LoopbackProxyPattern.Match(server.Trim());
            if (!m.Success) yield break;
            if (!int.TryParse(m.Groups[1].Value, out int port) || port <= 0 || port > 65535) yield break;
            if (HasListener(port)) yield break;
            yield return $"Reset a system proxy pointing at the dead loopback port 127.0.0.1:{port} " +
                         $"({scope}) — left behind by an intercept session that ended in a crash.";
        }

        private static bool HasListener(int port)
        {
            try
            {
                using var c = new TcpClient();
                var ar = c.BeginConnect(IPAddress.Loopback, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(300)) return false;
                c.EndConnect(ar);
                return true;
            }
            catch { return false; }
        }
    }
}
