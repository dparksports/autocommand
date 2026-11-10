using System;
using System.Collections.Generic;
using System.IO;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// The block-time go/no-go for images that must never get a firewall
    /// app-rule — born from a live incident: an AC-BLOCK-APP System rule
    /// (program literally "System") starved every kernel-mode socket and
    /// only looked harmless because nothing needed SMB or a VPN driver that
    /// day. Decide() is pure and offline-testable; the monitor calls it
    /// before the confirmation dialog so a refuse never reaches the
    /// firewall at all.
    /// </summary>
    public static class BlockGuard
    {
        /// <summary>
        /// Kernel/root images. These have no real executable path — a rule
        /// lands on the literal string and matches kernel traffic wholesale:
        /// SMB client (mrxsmb20), http.sys, WSK sockets of VPN/EDR drivers.
        /// Refuse, and point at the protocol-level fix instead.
        /// </summary>
        public static readonly HashSet<string> KernelImages = new(StringComparer.OrdinalIgnoreCase)
            { "system", "system.exe", "idle", "idle.exe", "registry", "registry.exe" };

        /// <summary>
        /// Security-critical user-mode images. Blockable in principle, but
        /// the confirmation must say what stops working — lsass is domain
        /// auth/Kerberos, winlogon/wininit/csrss/smss are logon plumbing.
        /// </summary>
        public static readonly HashSet<string> CriticalImages = new(StringComparer.OrdinalIgnoreCase)
            { "lsass.exe", "winlogon.exe", "wininit.exe", "csrss.exe", "smss.exe", "fontdrvhost.exe" };

        public enum Decision { Allow, Warn, Refuse }

        /// <summary>
        /// Leaf-name check (path or bare name both work). Refuse for kernel
        /// images, Warn for critical ones, Allow otherwise. Never throws.
        /// </summary>
        public static Decision Decide(string processNameOrPath, out string text)
        {
            string subject = (processNameOrPath ?? "").Trim();
            string leaf = Path.GetFileName(subject);
            if (leaf.Length == 0) leaf = subject;   // bare "System" has no directory part

            if (KernelImages.Contains(leaf))
            {
                text = "'" + leaf + "' is the Windows kernel process — the root every chain ends at.\n\n" +
                       "A firewall rule for it matches EVERY kernel-mode socket: SMB file shares,\n" +
                       "http.sys, and the WSK sockets of VPN/EDR drivers fail unpredictably, later,\n" +
                       "with nothing pointing back here.\n\n" +
                       "The traffic you saw is a kernel component (NetBIOS name broadcasts, SMB,\n" +
                       "RPC) — disable the responsible protocol instead:\n" +
                       "  NetBIOS over TCP/IP off per adapter (kills UDP 137 broadcasts), or\n" +
                       "  block the specific remote IP for this row.";
                return Decision.Refuse;
            }

            if (CriticalImages.Contains(leaf))
            {
                text = "'" + leaf + "' is security-critical Windows plumbing:\n" +
                       "lsass = domain login/Kerberos; winlogon/wininit/csrss/smss = logon chain.\n" +
                       "Blocking its network can break sign-in and domain auth the same way —\n" +
                       "make sure you know why this process is talking before you block it.";
                return Decision.Warn;
            }

            text = null;
            return Decision.Allow;
        }
    }
}
