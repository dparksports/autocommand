using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace DeviceMonitorCS.Helpers
{
    public static class PrivilegeHelper
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        public static bool EnablePrivilege(string privilegeName)
        {
            try
            {
                IntPtr htok = IntPtr.Zero;
                if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok))
                    return false;

                try
                {
                    TokPriv1Luid tp;
                    tp.Count = 1;
                    tp.Luid = 0;
                    tp.Attr = SE_PRIVILEGE_ENABLED;

                    if (!LookupPrivilegeValue(null, privilegeName, ref tp.Luid))
                        return false;

                    if (!AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                        return false;
                }
                finally
                {
                    CloseHandle(htok);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
