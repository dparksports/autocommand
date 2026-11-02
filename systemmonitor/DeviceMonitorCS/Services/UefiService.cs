#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DeviceMonitorCS.Services
{
    public class UefiEntry
    {
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
        public string ValidFrom { get; set; } = string.Empty;
        public string Expires { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string GuidType { get; set; } = string.Empty;
        public string RawData { get; set; } = string.Empty; // For search/tally
        public bool IsNew { get; set; } // Added for highlighting
    }

    public class DbxEntry
    {
        public string Hash { get; set; } = string.Empty;
        public string GuidType { get; set; } = string.Empty;
    }

    public class UefiService
    {
        // Singleton Instance
        private static UefiService? _instance;
        public static UefiService Instance => _instance ??= new UefiService();

        private const string SnapshotFileName = "uefi_snapshot.json";
        
        public event EventHandler<UefiChangeEventArgs>? UefiChanged;

        public class UefiChangeEventArgs : EventArgs
        {
            public List<UefiEntry> NewDbEntries { get; set; } = new();
            public int DbxCountDifference { get; set; }
            public int DbCountDifference { get; set; }
        }

        private class UefiSnapshot
        {
            public List<string> DbThumbprints { get; set; } = new();
            public int DbxCount { get; set; }
        }

        public async System.Threading.Tasks.Task CheckForChangesAsync()
        {
            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    // 1. Get Current State
                    var currentDb = GetDbEntries();
                    var currentDbx = GetDbxInfo();
                    int currentDbxCount = currentDbx.Count;

                    // 2. Load Snapshot
                    var snapshotPath = System.IO.Path.Combine("C:\\ProgramData\\Auto-Command", SnapshotFileName);
                    UefiSnapshot snapshot;

                    if (System.IO.File.Exists(snapshotPath))
                    {
                        var json = System.IO.File.ReadAllText(snapshotPath);
                        snapshot = System.Text.Json.JsonSerializer.Deserialize<UefiSnapshot>(json) ?? new UefiSnapshot();
                    }
                    else
                    {
                        // First run, just save current state and return
                        SaveSnapshot(snapshotPath, currentDb, currentDbxCount);
                        return;
                    }

                    // 3. Compare
                    var newEntries = new List<UefiEntry>();
                    foreach (var entry in currentDb)
                    {
                        if (!snapshot.DbThumbprints.Contains(entry.Thumbprint))
                        {
                            entry.IsNew = true;
                            newEntries.Add(entry);
                        }
                    }

                    int dbxDiff = currentDbxCount - snapshot.DbxCount;
                    int dbDiff = currentDb.Count - snapshot.DbThumbprints.Count;

                    // 4. Notify if changes
                    if (newEntries.Count > 0 || dbxDiff != 0 || dbDiff != 0)
                    {
                        UefiChanged?.Invoke(this, new UefiChangeEventArgs 
                        { 
                            NewDbEntries = newEntries, 
                            DbxCountDifference = dbxDiff,
                            DbCountDifference = dbDiff
                        });

                        // Save new state AFTER notification (so if app crashes/UI fails, we retry next time)
                        SaveSnapshot(snapshotPath, currentDb, currentDbxCount);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error checking UEFI changes: {ex.Message}");
                }
            });
        }

        private void SaveSnapshot(string path, List<UefiEntry> db, int dbxCount)
        {
            var dir = System.IO.Path.GetDirectoryName(path);
            if (dir != null && !System.IO.Directory.Exists(dir)) System.IO.Directory.CreateDirectory(dir);

            var snapshot = new UefiSnapshot
            {
                DbThumbprints = db.Select(e => e.Thumbprint).ToList(),
                DbxCount = dbxCount
            };
            var json = System.Text.Json.JsonSerializer.Serialize(snapshot);
            System.IO.File.WriteAllText(path, json);
        }

        // CVE-2022-21894 "BlackLotus" / "Baton Drop" Vulnerable Bootloader Hash
        // Microsoft-signed Windows Boot Manager (bootmgfw.efi)
        public const string BLACKLOTUS_HASH = "4594588E40707C2A7156372D627C28266922332617300C7E283226343202652A";

        public bool IsBlackLotusMitigated()
        {
            // We need to check if the DBX contains the specific hash
             var dbxInfo = GetDbxInfo();
             // Check if any entry matches the hash
             return dbxInfo.Entries.Any(e => e.Hash.Equals(BLACKLOTUS_HASH, StringComparison.OrdinalIgnoreCase));
        }

        private static readonly Guid EFI_GLOBAL_VARIABLE = new Guid("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        private static readonly Guid EFI_IMAGE_SECURITY_DATABASE = new Guid("d719b2cb-3d3a-4596-a3bc-dad00e67656f");
        private static readonly Guid EFI_CERT_X509_GUID = new Guid("a5c059a1-94e4-4138-87ab-5a5cd152628f");
        private static readonly Guid EFI_CERT_X509_GUID_ALT = new Guid("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
        private static readonly Guid EFI_CERT_SHA256_GUID = new Guid("c1c41626-504c-4092-aca9-41f936934328");

        public bool CheckPrivileges()
        {
            return PrivilegeManager.EnablePrivilege("SeSystemEnvironmentPrivilege");
        }

        public List<UefiEntry> GetDbEntries()
        {
            var entries = new List<UefiEntry>();
            if (!CheckPrivileges()) return entries;

            byte[]? data = GetUefiVariableEx("db", EFI_IMAGE_SECURITY_DATABASE.ToString("B"), out _);
            if (data == null) return entries;

            return ParseSignatureList(data);
        }

        public (int Count, List<DbxEntry> Entries) GetDbxInfo()
        {
            var entries = new List<DbxEntry>();
            if (!CheckPrivileges()) return (0, entries);

            byte[]? data = GetUefiVariableEx("dbx", EFI_IMAGE_SECURITY_DATABASE.ToString("B"), out _);
            if (data == null) return (0, entries);

            return ParseDbx(data);
        }

        private List<UefiEntry> ParseSignatureList(byte[] data)
        {
            var results = new List<UefiEntry>();
            int offset = 0;

            try
            {
                while (offset < data.Length)
                {
                    if (offset + 28 > data.Length) break;

                    byte[] guidBytes = new byte[16];
                    Array.Copy(data, offset, guidBytes, 0, 16);
                    Guid typeGuid = new Guid(guidBytes);

                    int listSize = BitConverter.ToInt32(data, offset + 16);
                    int headerSize = BitConverter.ToInt32(data, offset + 20);
                    int signatureSize = BitConverter.ToInt32(data, offset + 24);

                    int currentSigOffset = offset + 28 + headerSize;
                    int endOfList = offset + listSize;

                    while (currentSigOffset < endOfList)
                    {
                        if (currentSigOffset + 16 > data.Length) break;

                        int payloadSize = signatureSize - 16;
                        if (payloadSize > 0 && currentSigOffset + 16 + payloadSize <= data.Length)
                        {
                            byte[] payload = new byte[payloadSize];
                            Array.Copy(data, currentSigOffset + 16, payload, 0, payloadSize);

                            if (typeGuid == EFI_CERT_X509_GUID || typeGuid == EFI_CERT_X509_GUID_ALT)
                            {
                                try
                                {
#pragma warning disable SYSLIB0057
                                    var cert = new X509Certificate2(payload);
#pragma warning restore SYSLIB0057
                                    results.Add(new UefiEntry
                                    {
                                        Subject = cert.Subject,
                                        Issuer = cert.Issuer,
                                        SerialNumber = cert.SerialNumber,
                                        Algorithm = cert.SignatureAlgorithm.FriendlyName ?? "Unknown",
                                        ValidFrom = cert.NotBefore.ToShortDateString(),
                                        Expires = cert.NotAfter.ToShortDateString(),
                                        Thumbprint = cert.Thumbprint,
                                        GuidType = typeGuid.ToString()
                                    });
                                }
                                catch { }
                            }
                        }
                        currentSigOffset += signatureSize;
                    }
                    offset += listSize;
                }
            }
            catch { }
            return results;
        }

        private (int, List<DbxEntry>) ParseDbx(byte[] data)
        {
            var entries = new List<DbxEntry>();
            int count = 0;
            int offset = 0;

            try
            {
                while (offset < data.Length)
                {
                    if (offset + 28 > data.Length) break;
                    byte[] guidBytes = new byte[16];
                    Array.Copy(data, offset, guidBytes, 0, 16);
                    Guid typeGuid = new Guid(guidBytes);

                    int listSize = BitConverter.ToInt32(data, offset + 16);
                    int headerSize = BitConverter.ToInt32(data, offset + 20);
                    int signatureSize = BitConverter.ToInt32(data, offset + 24);
                    int currentSigOffset = offset + 28 + headerSize;
                    int endOfList = offset + listSize;

                    if (signatureSize > 0)
                    {
                       // Standard calculation for count
                       int payloadArea = endOfList - currentSigOffset;
                       if (payloadArea > 0) count += payloadArea / signatureSize;

                       // Extract hashes for search
                       while(currentSigOffset < endOfList)
                       {
                            int payloadSize = signatureSize - 16;
                            if (payloadSize > 0 && currentSigOffset + 16 + payloadSize <= data.Length)
                            {
                                byte[] payload = new byte[payloadSize];
                                Array.Copy(data, currentSigOffset + 16, payload, 0, payloadSize);
                                entries.Add(new DbxEntry 
                                { 
                                    Hash = BitConverter.ToString(payload).Replace("-", ""),
                                    GuidType = typeGuid.ToString()
                                });
                            }
                            currentSigOffset += signatureSize;
                       }
                    }
                    offset += listSize;
                }
            }
            catch { }
            return (count, entries);
        }

        private byte[]? GetUefiVariableEx(string name, string guid, out uint attributes)
        {
            attributes = 0;
            uint size = 2048; // Start bigger
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                int result = UefiNativeMethods.GetFirmwareEnvironmentVariableEx(name, guid, buffer, size, out attributes);
                if (result == 0 && Marshal.GetLastWin32Error() == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buffer);
                    size = 131072; // Bump to 128KB for large DBX
                    buffer = Marshal.AllocHGlobal((int)size);
                    result = UefiNativeMethods.GetFirmwareEnvironmentVariableEx(name, guid, buffer, size, out attributes);
                }
                if (result > 0)
                {
                    byte[] data = new byte[result];
                    Marshal.Copy(buffer, data, 0, result);
                    return data;
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return null;
        }
    }

    public static class PrivilegeManager
    {
        public static bool EnablePrivilege(string? privilegeName)
        {
            if (privilegeName == null) return false;
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!UefiNativeMethods.OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out tokenHandle)) return false;
                UefiNativeMethods.TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Attributes = 0x00000002;
                if (!UefiNativeMethods.LookupPrivilegeValue(null, privilegeName, out tp.Luid)) return false;
                if (!UefiNativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() == 0;
            }
            finally { if (tokenHandle != IntPtr.Zero) UefiNativeMethods.CloseHandle(tokenHandle); }
        }
    }

    static class UefiNativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetFirmwareEnvironmentVariableEx(string lpName, string lpGuid, IntPtr pBuffer, uint nSize, out uint pdwAttributes);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
        
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }
    }
}

