using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

namespace DeviceMonitorCS.Helpers
{
    public static class WanMiniportRemover
    {
        // GUID for Network Adapters: {4d36e972-e325-11ce-bfc1-08002be10318}
        private static readonly Guid NetworkClassGuid = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");

        private const int DIGCF_PRESENT = 0x00000002;
        private const int DIGCF_PROFILE = 0x00000008;
        
        private const int DIF_REMOVE = 0x00000005;

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
        private static extern bool SetupDiCallClassInstaller(int InstallFunction, IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        public static List<string> Execute()
        {
            return ExecuteInternal(null);
        }

        public static List<string> RemoveWifiDirect()
        {
            return ExecuteInternal("MS_VWIFI"); // MicroSoft Virtual WIFI
        }

        public static List<string> RemoveKdnet()
        {
            return ExecuteInternal("KDNIC"); // Microsoft Kernel Debug Network Adapter (ROOT\KDNIC\0000)
        }

        private static List<string> ExecuteInternal(string specificPattern = null)
        {
            var results = new List<string>();
            Guid guid = NetworkClassGuid; // Local copy for ref
            
            // Flags = 0 to include "Phantom" devices
            IntPtr hDevInfo = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero, 0); 

            if (hDevInfo == IntPtr.Zero)
            {
                results.Add("Failed to get device information set.");
                return results;
            }

            try
            {
                SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA();
                devInfo.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                uint index = 0;
                while (SetupDiEnumDeviceInfo(hDevInfo, index, ref devInfo))
                {
                    bool removed = false;
                    string instanceId = GetDeviceInstanceId(hDevInfo, devInfo);
                    
                    bool match = false;
                    if (specificPattern != null)
                    {
                        match = instanceId != null && instanceId.Contains(specificPattern);
                    }
                    else
                    {
                        match = IsWanMiniport(instanceId);
                    }

                    if (match)
                    {
                        try
                        {
                            if (SetupDiCallClassInstaller(DIF_REMOVE, hDevInfo, ref devInfo))
                            {
                                results.Add($"Removed: {instanceId}");
                                removed = true;
                            }
                            else
                            {
                                results.Add($"Failed to remove: {instanceId} (Error: {Marshal.GetLastWin32Error()})");
                            }
                        }
                        catch (Exception ex)
                        {
                            results.Add($"Exception removing {instanceId}: {ex.Message}");
                        }
                    }

                    if (!removed)
                    {
                        index++;
                    }
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(hDevInfo);
            }
            
            return results;
        }

        private static string GetDeviceInstanceId(IntPtr hDevInfo, SP_DEVINFO_DATA devInfo)
        {
            int requiredSize;
            SetupDiGetDeviceInstanceId(hDevInfo, ref devInfo, null, 0, out requiredSize);

            StringBuilder sb = new StringBuilder(requiredSize);
            SetupDiGetDeviceInstanceId(hDevInfo, ref devInfo, sb, requiredSize, out requiredSize);
            return sb.ToString().ToUpper();
        }

        private static bool IsWanMiniport(string instanceId)
        {
            if (string.IsNullOrEmpty(instanceId)) return false;
            
            return instanceId.Contains("MS_L2TPMINIPORT") ||
                   instanceId.Contains("MS_PPTPMINIPORT") ||
                   instanceId.Contains("MS_SSTPMINIPORT") ||
                   instanceId.Contains("MS_IKEV2MINIPORT") ||
                   instanceId.Contains("MS_AGILEVPNMINIPORT") || // IKEv2 (Modern)
                   instanceId.Contains("MS_NDISWANIP") || 
                   instanceId.Contains("MS_NDISWANIPV6") ||
                   instanceId.Contains("MS_PPPOEMINIPORT") ||
                   instanceId.Contains("MS_NDISWANBH") || // Network Monitor
                   instanceId.Contains("MS_VWIFI") || // WiFi Direct Virtual Adapter
                   instanceId.Contains("KDNIC"); // Microsoft Kernel Debug Network Adapter
        }
    }
}
