using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AutoCommand.Helpers
{
    /// <summary>
    /// Owns the shared %ProgramData%\AutoCommand root, created and ACL-hardened
    /// (Administrators + SYSTEM FullControl, Users ReadAndExecute) on first access.
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
