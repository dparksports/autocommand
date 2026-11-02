
$code = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class DebugEnum
{
    private static readonly Guid NetworkClassGuid = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
    private const int DIGCF_PRESENT = 0x00000002;
    private const int DIGCF_PROFILE = 0x00000008;

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, int Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet, uint MemberIndex, ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData, StringBuilder DeviceInstanceId, int DeviceInstanceIdSize, out int RequiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    public static void ListDevices()
    {
        Guid guid = NetworkClassGuid;
        IntPtr hDevInfo = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero, 0);

        if (hDevInfo == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get device info set. Error: " + Marshal.GetLastWin32Error());
            return;
        }

        try
        {
            SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA();
            devInfo.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

            uint index = 0;
            while (SetupDiEnumDeviceInfo(hDevInfo, index, ref devInfo))
            {
                int requiredSize;
                SetupDiGetDeviceInstanceId(hDevInfo, ref devInfo, null, 0, out requiredSize);
                StringBuilder sb = new StringBuilder(requiredSize);
                SetupDiGetDeviceInstanceId(hDevInfo, ref devInfo, sb, requiredSize, out requiredSize);

                string id = sb.ToString().ToUpper();
                Console.WriteLine("Index " + index + ": " + id);

                if (id.Contains("MINIPORT") || id.Contains("WAN"))
                {
                     Console.WriteLine("   -> MATCHES WAN/MINIPORT");
                }
                
                index++;
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }
    }
}
"@

Add-Type -TypeDefinition $code
[DebugEnum]::ListDevices()
