using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecureBootParser
{
    class Program
    {
        // The standard UEFI Global Variable GUID: {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
        static readonly string EfiGlobalGuid = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

        // Signature Type GUIDs
        static readonly Guid CertX509Guid = new Guid("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
        static readonly Guid Sha256Guid   = new Guid("c1c41626-504c-4b56-1e95-7985013b35bd");

        static void Main(string[] args)
        {
            Console.WriteLine("Acquiring SeSystemEnvironmentPrivilege...");
            if (!PrivilegeManager.EnablePrivilege("SeSystemEnvironmentPrivilege"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FAILED: Run as Administrator.");
                return;
            }

            ParseVariable("db", "Allowed Database");
            ParseVariable("dbx", "Forbidden Database");
            ParseVariable("KEK", "Key Exchange Keys");

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nDone. Press any key to exit.");
            Console.ReadKey();
        }

        static void ParseVariable(string varName, string description)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n==========================================");
            Console.WriteLine($" PARSING: {varName} ({description})");
            Console.WriteLine($"==========================================");
            Console.ResetColor();

            byte[] blob = GetUefiVariable(varName, EfiGlobalGuid);

            if (blob == null || blob.Length == 0)
            {
                Console.WriteLine("  [Empty or Not Found]");
                return;
            }

            using (var stream = new MemoryStream(blob))
            using (var reader = new BinaryReader(stream))
            {
                while (stream.Position < stream.Length)
                {
                    // --- READ LIST HEADER (28 Bytes) ---
                    // EFI_SIGNATURE_LIST structure
                    if (stream.Position + 28 > stream.Length) break;

                    byte[] typeGuidBytes = reader.ReadBytes(16);
                    Guid typeGuid = new Guid(typeGuidBytes);
                    
                    int listSize = reader.ReadInt32();
                    int headerSize = reader.ReadInt32(); // Usually 0
                    int entrySize = reader.ReadInt32();

                    // Identify Type
                    string typeName = "Unknown";
                    if (typeGuid == CertX509Guid) typeName = "X.509 Certificate";
                    else if (typeGuid == Sha256Guid) typeName = "SHA-256 Hash";

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"\n>>> LIST TYPE: {typeName}");
                    Console.ResetColor();
                    Console.WriteLine($"    Size: {listSize} bytes | Entry Size: {entrySize}");

                    // Calculate bounds for this specific list
                    // The list starts at the *beginning* of the header we just read.
                    // So the end of this list is: (CurrentPosition - 28) + ListSize
                    long listStartPos = stream.Position - 28; 
                    long listEndPos = listStartPos + listSize;

                    // Skip any extra header data if headerSize > 0
                    if (headerSize > 0) reader.ReadBytes(headerSize);

                    // --- READ ENTRIES ---
                    while (stream.Position + entrySize <= listEndPos)
                    {
                        // EFI_SIGNATURE_DATA structure
                        // 1. Owner GUID (16 bytes)
                        byte[] ownerBytes = reader.ReadBytes(16);
                        Guid ownerGuid = new Guid(ownerBytes);

                        // 2. Data
                        int dataLen = entrySize - 16;
                        byte[] data = reader.ReadBytes(dataLen);

                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine("    --------------------------------------------------");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"    [Owner]: {ownerGuid}");

                        if (typeGuid == CertX509Guid)
                        {
                            try
                            {
                                var cert = new X509Certificate2(data);
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Write("    Subject:    "); Console.WriteLine(cert.Subject);
                                Console.ResetColor();
                                Console.WriteLine($"    Issuer:     {cert.Issuer}");
                                Console.WriteLine($"    Valid To:   {cert.NotAfter.ToShortDateString()}");
                                Console.WriteLine($"    Thumbprint: {cert.Thumbprint}");
                            }
                            catch
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("    [!] Malformed Certificate Data");
                            }
                        }
                        else if (typeGuid == Sha256Guid)
                        {
                            string hash = BitConverter.ToString(data).Replace("-", "");
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write("    Hash:       "); Console.WriteLine(hash);
                        }
                        else
                        {
                            Console.WriteLine($"    [Raw Data]: {data.Length} bytes");
                        }
                    }

                    // Ensure we align perfectly to the start of the next list
                    stream.Position = listEndPos;
                }
            }
        }

        static byte[] GetUefiVariable(string name, string guid)
        {
            // First call to get size (returns 0 and sets error if buffer is null, but gives us size)
            // Note: GetFirmwareEnvironmentVariable is tricky with size detection. 
            // A common strategy is to allocate a reasonably large buffer or retry.
            // Here we'll try a resize loop for robustness.
            
            uint size = 4096; // Start with 4KB
            IntPtr buffer = Marshal.AllocHGlobal((int)size);

            try
            {
                int result = NativeMethods.GetFirmwareEnvironmentVariable(name, guid, buffer, size);
                if (result == 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 122) // ERROR_INSUFFICIENT_BUFFER (though API usually returns just 0)
                    {
                        // In reality, this API often fails hard if buffer is too small without telling required size.
                        // We will try a larger buffer if it fails.
                    }
                    else if (error == 203) // ERROR_ENVVAR_NOT_FOUND
                    {
                        return null; 
                    }
                }
                else
                {
                    byte[] data = new byte[result];
                    Marshal.Copy(buffer, data, 0, result);
                    return data;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            // Retry with massive buffer (64KB) if first attempt failed
            size = 65536; 
            buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                int result = NativeMethods.GetFirmwareEnvironmentVariable(name, guid, buffer, size);
                if (result == 0) return null;

                byte[] data = new byte[result];
                Marshal.Copy(buffer, data, 0, result);
                return data;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    // --- P/INVOKE & PRIVILEGES ---

    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetFirmwareEnvironmentVariable(
            string lpName,
            string lpGuid,
            IntPtr pBuffer,
            uint nSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, 
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public long Luid;
            public uint Attributes;
        }
    }

    public static class PrivilegeManager
    {
        public static bool EnablePrivilege(string privilegeName)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(Process.GetCurrentProcess().Handle, 
                    NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY, out tokenHandle))
                    return false;

                NativeMethods.TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;

                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out tp.Luid))
                    return false;

                if (!NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    return false;

                return Marshal.GetLastWin32Error() == 0; // ERROR_SUCCESS
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero) 
                    // CloseHandle not strictly needed for pseudo-handle but good practice if it were real
                    {}; 
            }
        }
    }
}