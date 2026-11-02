using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace DeviceMonitorCS.Helpers
{
    public static class DbxRemediator
    {
        // Official UEFI DBX Update (x64) - Hosted by Microsoft on GitHub
        // Using raw link ensures direct access to the binary file from the official repo.
        public const string DbxUrl = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/amd64/DBXUpdate.bin";
        private const string DbxFileName = "DBXUpdate.bin";

        public static string GetInstallCommand(string path)
        {
            return $"Set-SecureBootUEFI -Name dbx -ContentFilePath '{path}'";
        }

        public static async Task<(string Path, string Checksum, string Error)> DownloadUpdateAsync()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), DbxFileName);
            try
            {
                using (var client = new HttpClient())
                {
                    // Add User-Agent to avoid being blocked by some servers
                    client.DefaultRequestHeaders.Add("User-Agent", "DeviceMonitorCS/1.0");
                    
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
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return (false, "File not found");

            try
            {
                // 2. Apply via PowerShell (Set-SecureBootUEFI)
                var psCommand = GetInstallCommand(path);

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"{psCommand}\"",
                    // Verb = "runas", // REMOVED: App is already elevated via manifest
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var process = Process.Start(psi);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    if (process.ExitCode == 0)
                    {
                        return (true, null);
                    }
                    else
                    {
                        return (false, $"PowerShell process exited with code {process.ExitCode}. This usually means the firmware rejected the update or the command failed.");
                    }
                }
                return (false, "Failed to start PowerShell process.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Installation Failed: {ex.Message}");
                return (false, ex.Message);
            }
        }
    }
}
