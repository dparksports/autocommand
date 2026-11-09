using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Owns the shared %ProgramData%\AutoCommand root. The elevated app reads
    /// security-relevant desired state from files here (firewall baseline and
    /// config, bloatware list), so the root must not be writable by standard
    /// users: a freshly created ProgramData folder inherits an
    /// "Authenticated Users: Modify" ACE, which would let any non-elevated
    /// process rewrite the baseline the 60-second drift enforcer then
    /// enforces on its behalf. Mirrors the allow-list ledger's hardening, but
    /// with inheritable rules so files created later inside the root are
    /// covered too. One-shot and best-effort — failures never block callers;
    /// the app runs elevated and keeps write access either way.
    /// </summary>
    public static class ProgramDataGuard
    {
        private static string _root;
        private static bool _hardenAttempted;

        /// <summary>ProgramData root, created and ACL-hardened on first access.</summary>
        public static string Root
        {
            get
            {
                EnsureHardened();
                return _root;
            }
        }

        private static void EnsureHardened()
        {
            if (_root == null)
                _root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AutoCommand");

            if (_hardenAttempted) return;
            _hardenAttempted = true;
            try
            {
                Directory.CreateDirectory(_root);

                var info = new DirectoryInfo(_root);
                var security = info.GetAccessControl();

                // Drop the inherited Users-write ACE. The replacement rules
                // are inheritable, so the hardening covers files that already
                // exist under the root (their inherited ACEs mirror the new
                // parent set) as well as future ones — not just the folder.
                security.SetAccessRuleProtection(true, false);
                var sidAdmins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var sidSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var sidUsers = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    sidAdmins, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(
                    sidSystem, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(
                    sidUsers, FileSystemRights.ReadAndExecute,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                info.SetAccessControl(security);
            }
            catch
            {
                // Non-elevated context or odd filesystem — enforcement paths
                // still read what's there; worst case the folder keeps its
                // inherited ACLs until the next elevated launch.
            }
        }
    }
}
