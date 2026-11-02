using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Text.Json; // Native .NET Core/5+ JSON but we might need Newtonsoft if older. Assuming .NET Core/5+ based on project.

namespace DeviceMonitorCS.Views
{
    public partial class DbxSafetyView : UserControl
    {
        private const string BaselinePath = @"C:\ProgramData\Auto-Command\efi_baseline.json";
        private const string DbxUpdatePath = @"C:\Users\k2\Downloads\DBXUpdate.bin";
        private const string SigcheckUrl = "https://live.sysinternals.com/sigcheck64.exe";
        private readonly string _sigcheckPath;

        public DbxSafetyView()
        {
            InitializeComponent();
            _sigcheckPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sigcheck64.exe");
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            // Verify integrity immediately when view loads
            VerifySigcheckIntegrity();
        }

        private async void RunCheckBtn_Click(object sender, RoutedEventArgs e)
        {
            LoadingOverlay.Visibility = Visibility.Visible;
            StatusText.Text = "Starting Safety Check...";
            SafetyBadge.Visibility = Visibility.Collapsed;
            BaselineStatusText.Text = "Baseline: Checking...";

            try
            {
                await Task.Run(async () =>
                {
                    // 1. Pre-flight: Admin Check
                    // (Assuming app runs as Admin, but good to handle errors gracefully)

                    // 2. Ensure Sigcheck
                    await EnsureSigcheckAsync();
                    UpdateStatus("Mounting EFI partition...");

                    // 3. Mount EFI
                    bool mounted = MountEfi(true);
                    if (!mounted) throw new Exception("Failed to mount EFI partition (Z:). Ensure Admin rights.");

                    try
                    {
                        // 4. EFI Inspection & Baseline
                        UpdateStatus("Inspecting EFI Baseline...");
                        var scanResult = CheckEfiBaseline();
                        var efiResults = scanResult.FileResults;
                        
                        // 5. Analyze Bootloader
                        UpdateStatus("Analyzing Bootloader Signature...");
                        var bootloaderInfo = AnalyzeBootloader("Z:\\EFI\\Microsoft\\Boot\\bootmgfw.efi");

                        // 6. DBX Check
                        UpdateStatus("Verifying against DBX Revocation List...");
                        var dbxResult = CheckDbxSafety(bootloaderInfo);

                        // Update UI
                        Dispatcher.Invoke(() =>
                        {
                            // Bind Bootloader Info
                            BootloaderGrid.ItemsSource = bootloaderInfo.Select(k => new { Key = k.Key, Value = k.Value });

                            // Bind EFI Files
                            EfiFilesGrid.ItemsSource = efiResults;

                            // Show Baseline Status
                            bool integrityAlerts = efiResults.Any(r => r.Status == "NEW" || r.Status == "MOD" || r.Status == "DEL");
                            bool kernelLocks = efiResults.Any(r => r.Status == "LOCK");
                            bool scanErrors = efiResults.Any(r => r.Status == "DENY" || r.Status == "ERR");

                            // Dynamic Legend Visibility
                            bool showHash = efiResults.Any(r => r.Path.Contains("[Hash"));
                            bool showSize = efiResults.Any(r => r.Path.Contains("[Size"));
                            bool showTime = efiResults.Any(r => r.Path.Contains("[Timestamp"));
                            
                            LegendHash.Visibility = showHash ? Visibility.Visible : Visibility.Collapsed;
                            LegendSize.Visibility = showSize ? Visibility.Visible : Visibility.Collapsed;
                            LegendTime.Visibility = showTime ? Visibility.Visible : Visibility.Collapsed;
                            LegendLock.Visibility = kernelLocks ? Visibility.Visible : Visibility.Collapsed;

                            // Show Parent Legend if ANY exist
                            bool anyLegend = showHash || showSize || showTime || (kernelLocks && integrityAlerts); 
                            
                            // Debug Override
                            bool forceRemediation = Services.SettingsManager.Instance.IsRemediationDebug;

                            if (integrityAlerts || forceRemediation)
                            {
                                AlertLegend.Visibility = integrityAlerts ? Visibility.Visible : Visibility.Collapsed; // Legend still only if alerts
                                RemediationPanel.Visibility = Visibility.Visible;
                                // Force show Lock legend if concurrent with alerts for context
                                if (kernelLocks && integrityAlerts) LegendLock.Visibility = Visibility.Visible; 

                                if (forceRemediation && !integrityAlerts)
                                {
                                     // Add a visual cue that it is forced
                                     StatusText.Text += " (Debug Mode)";
                                }
                            }
                            else
                            {
                                AlertLegend.Visibility = Visibility.Collapsed;
                                RemediationPanel.Visibility = Visibility.Collapsed;
                            }

                            if (scanResult.IsNewBaseline)
                            {
                                BaselineStatusText.Text = "Baseline: Created (Initial Scan)";
                                BaselineStatusText.Foreground = Brushes.LimeGreen;
                                AlertLegend.Visibility = Visibility.Collapsed;
                                RemediationPanel.Visibility = Visibility.Collapsed;
                            }
                            else if (integrityAlerts)
                            {
                                BaselineStatusText.Text = "Baseline: INTEGRITY ALERT";
                                BaselineStatusText.Foreground = Brushes.Red;
                            }
                            else if (scanErrors)
                            {
                                BaselineStatusText.Text = "Baseline: Error (Check permissions)";
                                BaselineStatusText.Foreground = Brushes.Orange;
                            }
                            else if (kernelLocks)
                            {
                                BaselineStatusText.Text = "Verified: Kernel Locks Active";
                                BaselineStatusText.Foreground = Brushes.LimeGreen;
                            }
                            else
                            {
                                BaselineStatusText.Text = "Baseline: Integrity Verified";
                                BaselineStatusText.Foreground = Brushes.LimeGreen;
                            }

                            // Show DBX Badge
                            SafetyBadge.Visibility = Visibility.Visible;
                            SafetyBadgeText.Text = dbxResult.IsSafe ? "SAFE" : "DANGER";
                            SafetyBadgeText.Foreground = dbxResult.IsSafe ? Brushes.LimeGreen : Brushes.Red;
                            SafetyBadge.Background = dbxResult.IsSafe 
                                ? new SolidColorBrush(Color.FromArgb(0x22, 0x00, 0xFF, 0x00)) 
                                : new SolidColorBrush(Color.FromArgb(0x22, 0xFF, 0x00, 0x00));

                            StatusText.Text = dbxResult.Message;
                            StatusText.Foreground = dbxResult.IsSafe ? Brushes.White : Brushes.Red;
                        });

                    }
                    finally
                    {
                        // 7. Cleanup
                        MountEfi(false);
                    }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Safety Check Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusText.Text = "Check Failed.";
            }
            finally
            {
                LoadingOverlay.Visibility = Visibility.Collapsed;
            }
        }

        private async void RepairBootBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("This action will forcefully reinstall the official Microsoft Windows Bootloader from your system store (C:\\Windows) to the EFI Partition (Z:\\).\n\nThis will OVERWRITE any existing bootloader, including bootkits or Grub.\n\nAre you sure you want to proceed?", 
                "Confirm Boot Repair", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }

            LoadingOverlay.Visibility = Visibility.Visible;
            StatusText.Text = "Repairing Bootloader...";

            try
            {
                await Task.Run(() =>
                {
                   // 1. Mount
                   if (!MountEfi(true)) throw new Exception("Failed to mount EFI partition.");

                   try 
                   {
                       // 2. Run bcdboot
                       var psi = new ProcessStartInfo
                       {
                           FileName = "bcdboot.exe",
                           Arguments = @"C:\Windows /s Z: /f UEFI", // Reinstall to Z:
                           UseShellExecute = false,
                           CreateNoWindow = true,
                           RedirectStandardOutput = true
                       };
                       using (var p = Process.Start(psi))
                       {
                           p.WaitForExit();
                           if (p.ExitCode != 0) throw new Exception($"bcdboot failed. Exit Code: {p.ExitCode}");
                       }
                   }
                   finally
                   {
                       MountEfi(false);
                   }
                });

                MessageBox.Show("Bootloader Repair Successful.\n\nThe system integrity will now be re-scanned.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                // Auto Re-run check
                RunCheckBtn_Click(null, null);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Repair Failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LoadingOverlay.Visibility = Visibility.Collapsed;
            }
        }

        private void RecoveryBootBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo("ms-settings:recovery") { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                 MessageBox.Show($"Failed to open Settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateStatus(string msg)
        {
            Dispatcher.Invoke(() => StatusText.Text = msg);
        }

        private bool MountEfi(bool mount)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "mountvol.exe",
                    Arguments = mount ? "Z: /S" : "Z: /D",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                var p = Process.Start(psi);
                p.WaitForExit();
                
                // Allow a moment for FS to stable mount/unmount. 
                // Increased to 1.5s to rule out race conditions.
                System.Threading.Thread.Sleep(1500); 
                
                return mount ? Directory.Exists("Z:\\") : !Directory.Exists("Z:\\");
            }
            catch
            {
                return false;
            }
        }

        private async Task EnsureSigcheckAsync()
        {
            if (!File.Exists(_sigcheckPath))
            {
                UpdateStatus("Downloading Sigcheck...");
                using (var client = new System.Net.Http.HttpClient())
                {
                    var bytes = await client.GetByteArrayAsync(SigcheckUrl);
                    File.WriteAllBytes(_sigcheckPath, bytes);
                }
            }
        }

        private void VerifySigcheckIntegrity()
        {
            try
            {
                string expectedHash = "5D9E06BA65BB4D365E98FBB468F44FA8926F05984BF1A77EC7B1DF19C43DC5EF"; // v2.90
                
                if (File.Exists(_sigcheckPath))
                {
                    long size = new FileInfo(_sigcheckPath).Length;
                    SigcheckSizeDisplay.Text = $"{size:N0} bytes";

                    using (var sha = SHA256.Create())
                    using (var stream = File.OpenRead(_sigcheckPath))
                    {
                        var hashBytes = sha.ComputeHash(stream);
                        string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();
                        SigcheckHashDisplay.Text = hash;

                        if (hash == expectedHash)
                        {
                            SigcheckIntegrityStatus.Text = "(VERIFIED)";
                            SigcheckIntegrityStatus.Foreground = Brushes.LimeGreen;
                        }
                        else
                        {
                            SigcheckIntegrityStatus.Text = "(MISMATCH - TAMPERED)";
                            SigcheckIntegrityStatus.Foreground = Brushes.Red;
                        }
                    }
                }
                else
                {
                    SigcheckIntegrityStatus.Text = "(MISSING)";
                    SigcheckIntegrityStatus.Foreground = Brushes.Red;
                }
            }
            catch (Exception ex)
            {
                SigcheckIntegrityStatus.Text = $"(ERROR: {ex.Message})";
                SigcheckIntegrityStatus.Foreground = Brushes.Red;
            }
        }

        private void OpenLogBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sigcheck_debug.log");
                if (File.Exists(logPath))
                {
                    Process.Start(new ProcessStartInfo(logPath) { UseShellExecute = true });
                }
                else
                {
                    MessageBox.Show("Log file not found.", "Debug Log", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open log: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private Dictionary<string, string> AnalyzeBootloader(string path)
        {
            var info = new Dictionary<string, string>();
            
            // DEBUG: Check if Sigcheck exists
            if (!File.Exists(_sigcheckPath))
            {
                info["DEBUG_ERROR"] = $"Sigcheck MISSING at: {_sigcheckPath}";
                return info;
            }

            if (!File.Exists(path))
            {
                info["Status"] = "File Not Found";
                return info;
            }

            var psi = new ProcessStartInfo
            {
                FileName = _sigcheckPath,
                Arguments = $"-accepteula -a -h \"{path}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd();
                string err = p.StandardError.ReadToEnd();
                p.WaitForExit();

                // SANITIZE
                output = output.Replace("\0", "");
                err = err.Replace("\0", "");

                // LOGGING (Kept per user request)
                try 
                { 
                    string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sigcheck_debug.log");
                    File.WriteAllText(logPath, $"Sigcheck Path: {_sigcheckPath}\r\nSigcheck Size: {(File.Exists(_sigcheckPath) ? new FileInfo(_sigcheckPath).Length : -1)}\r\n\r\nSTDOUT:\r\n{output}\r\n\r\nSTDERR:\r\n{err}"); 
                } 
                catch { }

                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                     // Relaxed Regex
                     var match = Regex.Match(line, @"^\s*([^:]+)\s*:\s*(.*)$");
                     if (match.Success)
                     {
                         string key = match.Groups[1].Value.Trim();
                         string val = match.Groups[2].Value.Trim();

                         // Filter essential keys
                         if (key.Contains("Publisher") || key.Contains("Verified") || key.Contains("date") || 
                             key.Contains("Product") || key.Contains("Version") || 
                             key.Contains("SHA256") || key.Contains("PE256") || key.Contains("MD5"))
                         {
                             info[key] = val;
                         }
                     }
                }
                
                if (info.Count < 3)
                {
                     string rawLimited = output.Length > 200 ? output.Substring(0, 200) + "..." : output;
                     info["DEBUG_ERROR"] = $"Sigcheck Parse Failed. Keys: {info.Count}. see sigcheck_debug.log.\nRaw: {rawLimited}";
                }
            }
            return info;
        }

        public class BaselineEntry
        {
            public string Hash { get; set; } // "LOCKED" if inaccessible
            public long Size { get; set; }
            public DateTime LastWrite { get; set; }
            public FileAttributes Attributes { get; set; }
        }

        public class ScanResult
        {
            public List<EfiFileResult> FileResults { get; set; }
            public bool IsNewBaseline { get; set; }
        }

        private ScanResult CheckEfiBaseline()
        {
            var results = new List<EfiFileResult>();
            var currentSnapshot = new Dictionary<string, BaselineEntry>();

            // Ensure Dir
            string baselineDir = Path.GetDirectoryName(BaselinePath);
            if (!Directory.Exists(baselineDir)) Directory.CreateDirectory(baselineDir);

            // Scan using robust traversal
            try
            {
                if (Directory.Exists("Z:\\EFI"))
                {
                    ScanDirectory("Z:\\EFI", currentSnapshot, results);
                }
                else if (Directory.Exists("Z:\\"))
                {
                     ScanDirectory("Z:\\", currentSnapshot, results);
                }
                else
                {
                    results.Add(new EfiFileResult { Status = "ERROR", Path = "EFI Mount (Z:) not found. Verify Admin privileges.", StatusColor = Brushes.Orange });
                }
            }
            catch (Exception ex)
            {
                results.Add(new EfiFileResult { Status = "ERROR", Path = "Mount Access Error: " + ex.Message, StatusColor = Brushes.Orange });
            }

            // Load Baseline
            Dictionary<string, BaselineEntry> baseline = new Dictionary<string, BaselineEntry>();
            bool baselineExists = File.Exists(BaselinePath);
            bool isNew = !baselineExists;
            
            if (baselineExists)
            {
                try 
                {
                    string json = File.ReadAllText(BaselinePath);
                    // Try new format first
                    baseline = JsonSerializer.Deserialize<Dictionary<string, BaselineEntry>>(json);
                }
                catch 
                { 
                    // Failed? Might be legacy string-string dictionary
                    try
                    {
                        string json = File.ReadAllText(BaselinePath);
                        var legacy = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                        // Convert to new format (Hash only, no metadata known yet)
                        baseline = legacy.ToDictionary(k => k.Key, v => new BaselineEntry { Hash = v.Value, Size = -1 });
                    }
                    catch
                    {
                        results.Add(new EfiFileResult { Status = "WARN", Path = "Corrupt baseline, resetting.", StatusColor = Brushes.Yellow });
                        baseline = new Dictionary<string, BaselineEntry>();
                        baselineExists = false;
                        isNew = true;
                    }
                }
            }
            else
            {
                results.Add(new EfiFileResult { Status = "INFO", Path = "Creating new baseline...", StatusColor = Brushes.Gray });
            }

            // Compare
            bool drift = false;
            if (baseline == null) baseline = new Dictionary<string, BaselineEntry>();

            foreach (var kvp in currentSnapshot)
            {
                if (!baselineExists) continue; 

                if (!baseline.ContainsKey(kvp.Key))
                {
                    results.Add(new EfiFileResult { Status = "NEW", Path = kvp.Key, StatusColor = Brushes.Yellow });
                    drift = true;
                }
                else 
                {
                    var baseEntry = baseline[kvp.Key];
                    var currEntry = kvp.Value;

                    // Comparison Logic
                    bool changed = false;
                    List<string> changes = new List<string>();

                    // 1. Hash Check (if available)
                    if (baseEntry.Hash != "LOCKED" && currEntry.Hash != "LOCKED" && baseEntry.Hash != currEntry.Hash)
                    {
                         changed = true;
                         changes.Add("Hash Mismatch");
                    }
                    // 2. Fallback: If Locked, check Metadata
                    else if (baseEntry.Hash == "LOCKED" || currEntry.Hash == "LOCKED")
                    {
                        if (baseEntry.Hash != currEntry.Hash) 
                        {
                            // State change (Locked <-> Unlocked)
                            changed = true;
                            changes.Add($"Lock State Changed ({baseEntry.Hash} -> {currEntry.Hash})");
                        }
                        
                        // Metadata Check (Size/Time)
                        if (baseEntry.Size != -1 && baseEntry.Size != currEntry.Size)
                        {
                            changed = true;
                            changes.Add($"Size {baseEntry.Size}->{currEntry.Size}");
                        }
                        
                        if (baseEntry.Size != -1 && Math.Abs((baseEntry.LastWrite - currEntry.LastWrite).TotalSeconds) > 2)
                        {
                            changed = true;
                            changes.Add("Timestamp");
                        }
                    }

                    if (changed)
                    {
                        string reason = string.Join(", ", changes);
                        results.Add(new EfiFileResult { Status = "MOD", Path = $"{kvp.Key} [{reason}]", StatusColor = Brushes.Red });
                        drift = true;
                    }
                }
            }

            // 2. Check Deleted
            if (baselineExists)
            {
                foreach (var key in baseline.Keys)
                {
                    if (!currentSnapshot.ContainsKey(key))
                    {
                        results.Add(new EfiFileResult { Status = "DEL", Path = key, StatusColor = Brushes.Gray });
                        drift = true;
                    }
                }
            }

            if (!drift && baselineExists)
            {
                 results.Add(new EfiFileResult { Status = "OK", Path = "System Integrity Verified", StatusColor = Brushes.LimeGreen });
            }
            else
            {
                // Update Baseline (Auto-Accept)
                try
                {
                    string newJson = JsonSerializer.Serialize(currentSnapshot);
                    File.WriteAllText(BaselinePath, newJson);
                    if (baselineExists) results.Add(new EfiFileResult { Status = "INFO", Path = "Baseline updated.", StatusColor = Brushes.Gray });
                }
                catch (Exception ex)
                {
                    results.Add(new EfiFileResult { Status = "ERR", Path = "Failed to save baseline: " + ex.Message, StatusColor = Brushes.Red });
                }
            }

            return new ScanResult { FileResults = results, IsNewBaseline = isNew };
        }

        private void ScanDirectory(string dir, Dictionary<string, BaselineEntry> snapshot, List<EfiFileResult> results)
        {
            try
            {
                var dirInfo = new DirectoryInfo(dir);
                
                // Process Files
                foreach (var fileInfo in dirInfo.GetFiles())
                {
                    try
                    {
                        string fullPath = fileInfo.FullName;
                        string relPath = fullPath.Substring(3); // Remove Z:\ (Assuming Z: root)

                        var entry = new BaselineEntry
                        {
                            Size = fileInfo.Length,
                            LastWrite = fileInfo.LastWriteTimeUtc,
                            Attributes = fileInfo.Attributes,
                            Hash = "LOCKED" 
                        };

                        try
                        {
                            // Try to Hash
                            using (var sha = SHA256.Create())
                            using (var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            {
                                var hashBytes = sha.ComputeHash(stream);
                                entry.Hash = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();
                            }
                        }
                        catch
                        {
                            // Kept as LOCKED. 
                            // Add visualization for locked files so user knows we saw it.
                            results.Add(new EfiFileResult { Status = "LOCK", Path = $"{fileInfo.Name} (Verified Metadata)", StatusColor = Brushes.Orange });
                        }

                        snapshot[relPath] = entry;
                    }
                    catch (Exception ex)
                    {
                        results.Add(new EfiFileResult { Status = "ERR", Path = $"File Error: {ex.Message}", StatusColor = Brushes.Red });
                    }
                }

                // Recurse Directories
                foreach (var subDir in dirInfo.GetDirectories())
                {
                    ScanDirectory(subDir.FullName, snapshot, results);
                }
            }
            catch (UnauthorizedAccessException)
            {
                results.Add(new EfiFileResult { Status = "DENY", Path = $"Access Denied: {dir}", StatusColor = Brushes.Red });
            }
            catch (Exception ex) 
            {
                results.Add(new EfiFileResult { Status = "ERR", Path = $"Error reading {dir}: {ex.Message}", StatusColor = Brushes.Red });
            }
        }

        private (bool IsSafe, string Message) CheckDbxSafety(Dictionary<string, string> info)
        {
            if (!File.Exists(DbxUpdatePath))
            {
                 Dispatcher.Invoke(() => 
                 {
                     DbxStatusSource.Text = "Not Found (Integrity Check Only)";
                     DbxStatusSource.Foreground = Brushes.Orange;
                     DbxStatusDate.Text = "-";
                     DbxStatusCount.Text = "-";
                 });
                 return (true, "DBXUpdate.bin not found. Integrity check only.");
            }

            // Show Date & Count
            try
            {
                DateTime lastWrite = File.GetLastWriteTime(DbxUpdatePath);
                int entryCount = CountDbxEntries(DbxUpdatePath);
                
                Dispatcher.Invoke(() => 
                {
                    DbxStatusSource.Text = Helpers.DbxRemediator.DbxUrl;
                    DbxStatusSource.Foreground = Brushes.LightSkyBlue; // Highlight URL
                    DbxStatusDate.Text = $"{lastWrite:g}";
                    DbxStatusCount.Text = $"{entryCount} signatures reviewed";
                });
            }
            catch { }

            if (info.ContainsKey("DEBUG_ERROR"))
            {
                return (false, info["DEBUG_ERROR"]);
            }

            string peHash = info.ContainsKey("PE256") ? info["PE256"] : null;
            string fileHash = info.ContainsKey("SHA256") ? info["SHA256"] : null;

            if (peHash == null && fileHash == null) return (false, "Could not determine bootloader hashes.");

            try 
            {
                byte[] dbxBytes = File.ReadAllBytes(DbxUpdatePath);
                string dbxHex = BitConverter.ToString(dbxBytes).Replace("-", "").ToUpperInvariant();

                if (peHash != null && dbxHex.Contains(peHash))
                {
                    return (false, "DANGER: Bootloader PE Hash found in Revocations!");
                }
                if (fileHash != null && dbxHex.Contains(fileHash))
                {
                    return (false, "DANGER: Bootloader File Hash found in Revocations!");
                }

                return (true, "Safe: No revocations found for this bootloader.");
            }
            catch (Exception ex)
            {
                return (false, $"Error reading DBX: {ex.Message}");
            }
        }

        private int CountDbxEntries(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                // DBXUpdate.bin is likely EFI_VARIABLE_AUTHENTICATION_2
                // [EFI_TIME (16)] + [WIN_CERTIFICATE (Length at +0)] + [Payload]
                
                if (data.Length < 20) return 0; // Too small

                // Read Auth Info Length (at offset 16)
                int authLength = BitConverter.ToInt32(data, 16);
                int payloadOffset = 16 + authLength;

                if (payloadOffset >= data.Length) 
                {
                     // Maybe it's raw? Try offset 0.
                     payloadOffset = 0;
                }

                int count = 0;
                int offset = payloadOffset;

                while (offset < data.Length)
                {
                    if (offset + 28 > data.Length) break;
                    
                    // EFI_SIGNATURE_LIST header
                    // Guid (16) + ListSize (4) + HeaderSize (4) + SignatureSize (4)
                    int listSize = BitConverter.ToInt32(data, offset + 16);
                    int headerSize = BitConverter.ToInt32(data, offset + 20);
                    int signatureSize = BitConverter.ToInt32(data, offset + 24);

                    int currentSigOffset = offset + 28 + headerSize;
                    int endOfList = offset + listSize;

                    if (signatureSize > 0)
                    {
                        // Calculate payload area for signatures
                        int payloadArea = endOfList - currentSigOffset;
                        if (payloadArea > 0)
                        {
                            count += payloadArea / signatureSize;
                        }
                    }
                    
                    // Advance
                    if (listSize <= 0) break; // Safety
                    offset += listSize;
                }
                return count;
            }
            catch 
            {
                return -1; // Error
            }
        }

        public class EfiFileResult
        {
            public string Status { get; set; }
            public string Path { get; set; }
            public Brush StatusColor { get; set; }
        }
    }
}
