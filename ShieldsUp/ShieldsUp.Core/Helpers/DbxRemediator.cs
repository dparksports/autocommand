using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace ShieldsUp.Core.Helpers
{
    /// <summary>
    /// DBX update download and installation.
    /// Ported from DeviceMonitorCS.
    /// </summary>
    public static class DbxRemediator
    {
        public const string DbxUrl = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/amd64/DBXUpdate.bin";
        private const string DbxFileName = "DBXUpdate.bin";

        public static string GetInstallCommand(string path)
        {
            // -ErrorAction Stop + $? propagation: a REJECTED Set-SecureBootUEFI
            // is a non-terminating cmdlet error that still exits 0 — without
            // this the page reported "applied successfully" for a rejected write.
            return $"Set-SecureBootUEFI -Name dbx -ContentFilePath '{path}' -ErrorAction Stop; " +
                   "if (-not $?) { exit 1 }";
        }

        public static async Task<(string Path, string Checksum, string Error)> DownloadUpdateAsync()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), DbxFileName);
            try
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("User-Agent", "ShieldsUp/1.0");
                    var data = await client.GetByteArrayAsync(DbxUrl);
                    await File.WriteAllBytesAsync(tempPath, data);

                    using (var sha256 = System.Security.Cryptography.SHA256.Create())
                    {
                        var hash = sha256.ComputeHash(data);
                        return (tempPath, BitConverter.ToString(hash).Replace("-", ""), null);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Download Failed: {ex.Message}");
                return (string.Empty, string.Empty, ex.Message);
            }
        }

        public static async Task<(bool Success, string Error)> InstallUpdateAsync(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                return (false, "File not found");

            try
            {
                // Apply via PowerShell is unavoidable for Set-SecureBootUEFI (no native C# API for this)
                // This is the ONLY place we use PowerShell — it's a firmware-level UEFI command
                var psCommand = GetInstallCommand(path);
                var psi = new ProcessStartInfo
                {
                    // Pinned to System32 — the host app runs elevated from a
                    // portable folder, so an unqualified "powershell" would
                    // resolve through the app/CWD first (both user-writable).
                    FileName = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "powershell.exe"),
                    Arguments = $"-Command \"{psCommand}\"",
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var process = Process.Start(psi);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    if (process.ExitCode == 0) return (true, null);
                    return (false, $"PowerShell exited with code {process.ExitCode}. Firmware may have rejected the update.");
                }
                return (false, "Failed to start process.");
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }
    }
}

