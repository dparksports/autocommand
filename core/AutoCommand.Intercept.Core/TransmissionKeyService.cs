using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AutoCommand.Intercept.Core
{
    /// <summary>
    /// Key acquisition for the Traffic Peek: getting apps that honor the
    /// de-facto SSLKEYLOGFILE convention to write their TLS session secrets
    /// where the F# TlsKeylogService already tails them (pytrace\
    /// sslkeys.log, current-user-only ACL, rotated at 5 MB).
    ///
    /// Two mechanisms, both strictly local:
    ///   - Launch under watch: starts one chosen program with the variable
    ///     set in its environment only — the precise instrument when the
    ///     user wants one program observed without changing anything
    ///     global. The peek window opened for that instance then decrypts
    ///     its flows as they finalize.
    ///   - System-wide capture: writes SSLKEYLOGFILE into the user's
    ///     environment (HKCU\Environment) and broadcasts the change so
    ///     freshly launched apps inherit it. Chromium/Electron, curl, wget,
    ///     git, OpenSSL- and Python-based tools pick it up. Schannel-based
    ///     system components ignore the variable — those flows stay
    ///     "encrypted (no keys)" in the peek, which is the honest coverage
    ///     answer, not a gap to paper over.
    /// </summary>
    public static class TransmissionKeyService
    {
        private const string EnvVarName = "SSLKEYLOGFILE";
        private const string EnvKey = "Environment";

        public static string KeylogTarget => TlsKeylogService.KeylogPath;

        // ── system-wide toggle ────────────────────────────────────────────

        /// <summary>True when the user environment currently points
        /// SSLKEYLOGFILE at AutoCommand's keylog.</summary>
        public static bool IsSystemKeylogEnabled()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(EnvKey, writable: false);
                var value = key?.GetValue(EnvVarName) as string;
                return string.Equals(value, KeylogTarget, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>Sets SSLKEYLOGFILE in the user environment and notifies
        /// running processes that the environment changed (newly launched
        /// apps inherit it; nothing running is touched).</summary>
        public static void EnableSystemKeylog()
        {
            TlsKeylogService.EnsureHygiene(); // the target must exist with its ACL before children append
            using var key = Registry.CurrentUser.CreateSubKey(EnvKey);
            key.SetValue(EnvVarName, KeylogTarget);
            BroadcastEnvironmentChange();
        }

        /// <summary>Removes SSLKEYLOGFILE from the user environment. The
        /// key file itself is wiped too: without the variable no new app
        /// writes keys, and stale secrets should not linger either.</summary>
        public static void DisableSystemKeylog()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(EnvKey, writable: true))
            {
                key?.DeleteValue(EnvVarName, throwOnMissingValue: false);
            }
            BroadcastEnvironmentChange();
            try { TlsKeylogService.DisableKeylogging(); } catch { /* flag wipe is best-effort */ }
            TlsKeylogService.EnableKeylogging(); // recreate the empty ACL'd file + clear the hook's no-keylog flag
        }

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessageTimeout(
            IntPtr hWnd, uint msg, UIntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

        private const uint WM_SETTINGCHANGE = 0x001A;
        private const uint SMTO_ABORTIFHUNG = 0x0002;
        private static readonly IntPtr HWND_BROADCAST = (IntPtr)0xFFFF;

        /// <summary>
        /// Explorer (and other long-running parents) build a child's
        /// environment from their own copy of the registry values; without
        /// this broadcast a toggle appears to "not work" until logoff.
        /// </summary>
        private static void BroadcastEnvironmentChange()
        {
            try
            {
                SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, UIntPtr.Zero,
                    "Environment", SMTO_ABORTIFHUNG, 1000, out _);
            }
            catch { /* best-effort notification */ }
        }

        // ── launch under watch ────────────────────────────────────────────

        // ── de-elevated launch (advapi32) ───────────────────────────────
        // AutoCommand runs requireAdministrator, and users casually pick
        // BROWSERS to watch — inheriting the admin token would make every
        // renderer exploit admin-owned and quietly erode the UAC boundary
        // the OS tries to keep. The child is therefore launched with a
        // LUA-filtered copy of this process's own token (the standard UAC
        // de-elevation CreateRestrictedToken(LUA_TOKEN) performs: admin
        // group filtered, medium integrity) — the ONLY thing the child
        // needs from this process is the SSLKEYLOGFILE variable, and that
        // travels in an explicit environment block.

        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint LUA_TOKEN = 0x4;            // CreateRestrictedToken: UAC-style filtered token
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x400;
        private static readonly int SecurityImpersonation = 2;
        private static readonly int TokenPrimary = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess,
            IntPtr tokenAttributes, int impersonationLevel, int tokenType, out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateRestrictedToken(IntPtr existingToken, uint flags,
            int disableSidCount, IntPtr sidsToDisable, int deletePrivilegeCount, IntPtr privilegesToDelete,
            int restrictSidCount, IntPtr sidsToRestrict, out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags,
            string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment,
            string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        /// <summary>
        /// Starts a program with SSLKEYLOGFILE pointing at AutoCommand's
        /// keylog (its own environment only), launched DE-ELEVATED (medium
        /// integrity, admin group filtered) even though this app runs
        /// elevated — a casually-picked browser must never inherit admin.
        /// Returns the Process, or null when the child exited before its
        /// handle could be resolved (nothing left to watch).
        /// </summary>
        public static Process LaunchUnderWatch(string exePath, string arguments, string workingDirectory)
        {
            if (string.IsNullOrWhiteSpace(exePath))
                throw new ArgumentException("No program selected.");

            TlsKeylogService.EnsureHygiene();
            TlsKeylogService.EnableKeylogging(); // clears any stale no-keylog flag

            // Explicit environment block: everything this process has, with
            // SSLKEYLOGFILE pointed at the keylog. Built as a "K=V\0" string
            // (double-null termination comes from the marshaler's final \0).
            var vars = new System.Collections.Hashtable(Environment.GetEnvironmentVariables());
            vars[EnvVarName] = KeylogTarget;
            var block = new System.Text.StringBuilder();
            foreach (System.Collections.DictionaryEntry e in vars)
                block.Append(e.Key).Append('=').Append(e.Value).Append('\0');
            block.Append('\0');
            string envBlock = block.ToString();

            IntPtr ownToken = IntPtr.Zero, primaryDup = IntPtr.Zero, luaToken = IntPtr.Zero;
            IntPtr envPtr = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                        out ownToken))
                    throw new InvalidOperationException("OpenProcessToken failed");

                if (!DuplicateTokenEx(ownToken, 0x02000000 /* MAXIMUM_ALLOWED */, IntPtr.Zero,
                        SecurityImpersonation, TokenPrimary, out primaryDup))
                    throw new InvalidOperationException("DuplicateTokenEx failed");

                if (!CreateRestrictedToken(primaryDup, LUA_TOKEN,
                        0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out luaToken))
                    throw new InvalidOperationException($"CreateRestrictedToken failed (error {Marshal.GetLastWin32Error()})");

                var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
                string commandLine = string.IsNullOrEmpty(arguments) ? exePath : $"\"{exePath}\" {arguments}";
                string dir = string.IsNullOrEmpty(workingDirectory)
                    ? System.IO.Path.GetDirectoryName(exePath)
                    : workingDirectory;
                envPtr = Marshal.StringToHGlobalUni(envBlock);

                if (!CreateProcessWithTokenW(luaToken, 0, null, commandLine,
                        CREATE_UNICODE_ENVIRONMENT, envPtr, dir,
                        ref si, out PROCESS_INFORMATION pi))
                    throw new InvalidOperationException($"CreateProcessWithTokenW failed (error {Marshal.GetLastWin32Error()})");

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                try { return Process.GetProcessById(pi.dwProcessId); }
                catch { return null; } // exited instantly — no peek to open
            }
            finally
            {
                if (envPtr != IntPtr.Zero) Marshal.FreeHGlobal(envPtr);
                if (ownToken != IntPtr.Zero) CloseHandle(ownToken);
                if (primaryDup != IntPtr.Zero) CloseHandle(primaryDup);
                if (luaToken != IntPtr.Zero) CloseHandle(luaToken);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>Programs known to honor SSLKEYLOGFILE, for the launch
        /// dialog's hint text and the peek's coverage note.</summary>
        public static string CoverageNote =>
            "Apps that honor SSLKEYLOGFILE (Chromium/Electron browsers and apps, curl, git, " +
            "wget, OpenSSL- and Python-based tools) write TLS session keys when the variable " +
            "is set at launch. Windows system components using Schannel ignore it — their " +
            "flows stay 'encrypted (no keys)' with full metadata. Certificate-pinned apps " +
            "keep working; their keys decrypt their traffic here the same way.";
    }
}
