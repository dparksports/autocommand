using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management;
using System.Windows;
using System.Windows.Controls;
using DeviceMonitorCS.Models;

using DeviceMonitorCS.Helpers;

namespace DeviceMonitorCS.Views
{
    public partial class FirmwareSettingsView : UserControl
    {
        public ObservableCollection<FirmwareTableItem> FirmwareTables { get; set; } = new ObservableCollection<FirmwareTableItem>();
        public ObservableCollection<BcdEntry> BcdEntries { get; set; } = new ObservableCollection<BcdEntry>();

        public FirmwareSettingsView()
        {
            InitializeComponent();
            FirmwareGrid.ItemsSource = FirmwareTables;
            BcdGrid.ItemsSource = BcdEntries;
            Loaded += FirmwareSettingsView_Loaded;
        }

        private void FirmwareSettingsView_Loaded(object sender, RoutedEventArgs e)
        {
            if (FirmwareTables.Count == 0) LoadFirmwareTables();
            if (BcdEntries.Count == 0) LoadBcdInfo();
        }

        private void LoadFirmwareTables()
        {
            FirmwareTables.Clear();
            
            // Try to enable privilege for UEFI access
            PrivilegeHelper.EnablePrivilege("SeSystemEnvironmentPrivilege");

            try
            {
                // WMI fallback or primary? The user has issues with WMI. Let's use P/Invoke primary.
                // Standard signatures: 'ACPI', 'FIRM', 'RSMB'
                
                // 1. ACPI
                LoadTablesForProvider("ACPI", 0x41435049); // 'ABCD' -> 0x44434241 (Little Endian) -> 'ACPI' is 0x49504341?
                // Actually simpler: BitConverter can tell us. 'A' is 0x41. 'ACPI' -> 'I' is MSB? No.
                // Using 0x41435049 is correct for String->Int conversion if big endian or just treating as FourCC?
                // Actually the API expects a DWORD. 'ACPI' is 0x49504341 in memory if LE.
                // But most examples use 0x41435049 (Big Endian) representation? No, let's use the FourCC helper below.
                    
                // 2. RSMB (Raw SMBIOS)
                LoadTablesForProvider("RSMB", 0x52534D42);

                // 3. FIRM (Firmware)
                LoadTablesForProvider("FIRM", 0x4649524D);

                // If completely empty, try WMI as last resort?
                // No, user said WMI failed.
                
                if (FirmwareTables.Count == 0)
                {
                     FirmwareTables.Add(new FirmwareTableItem { Name = "Info", TableID = "-", Length = "No tables found via Native API" });
                }
            }
            catch (Exception ex)
            {
                FirmwareTables.Add(new FirmwareTableItem { Name = "Error", TableID = "-", Length = ex.Message });
            }
        }

        private void LoadTablesForProvider(string providerName, uint providerSig)
        {
            try
            {
                // Get buffer size
                uint requiredSize = NativeMethods.EnumSystemFirmwareTables(providerSig, IntPtr.Zero, 0);
                if (requiredSize == 0) return; // None found or error

                IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)requiredSize);
                try
                {
                    uint result = NativeMethods.EnumSystemFirmwareTables(providerSig, buffer, requiredSize);
                    if (result > 0)
                    {
                         int count = (int)result / 4; // Each ID is 4 bytes
                         var idList = new System.Collections.Generic.List<string>();

                         for (int i = 0; i < count; i++)
                         {
                             byte[] idBytes = new byte[4];
                             System.Runtime.InteropServices.Marshal.Copy(IntPtr.Add(buffer, i*4), idBytes, 0, 4);
                             string tableIdStr = System.Text.Encoding.ASCII.GetString(idBytes);
                             idList.Add(tableIdStr);
                         }

                         // Deduplicate
                         var groups = idList.GroupBy(x => x).ToList();

                         foreach (var group in groups)
                         {
                             string tableIdStr = group.Key;
                             int instanceCount = group.Count();
                             
                             // Get content length for the first instance
                             byte[] idBytes = System.Text.Encoding.ASCII.GetBytes(tableIdStr);
                             uint tableIdInt = BitConverter.ToUInt32(idBytes, 0);
                             uint len = NativeMethods.GetSystemFirmwareTable(providerSig, tableIdInt, IntPtr.Zero, 0);

                             string desc = GetTableDescription(tableIdStr);
                             if (instanceCount > 1)
                             {
                                 desc += $" ({instanceCount} instances)";
                             }

                             FirmwareTables.Add(new FirmwareTableItem
                             {
                                 Name = providerName,
                                 TableID = tableIdStr,
                                 Length = len.ToString(),
                                 Description = desc
                             });
                         }
                    }
                }
                finally
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
                }
            }
            catch { }
        }
        
        private string GetTableDescription(string id)
        {
            if (string.IsNullOrEmpty(id)) return "";
            
            // Common ACPI Signatures
            switch (id.ToUpper())
            {
                case "ACPI": return "ACPI Entry Point";
                case "FACP": return "Fixed ACPI Description Table (FADT)";
                case "APIC": return "Multiple APIC Description Table (MADT)";
                case "MCFG": return "PCI Express Memory Mapped Configuration Space";
                case "HPET": return "High Precision Event Timer Table";
                case "SSDT": return "Secondary System Description Table";
                case "DSDT": return "Differentiated System Description Table";
                case "ECDT": return "Embedded Controller Boot Resources Table";
                case "UEFI": return "UEFI ACPI Data Table";
                case "BGRT": return "Boot Graphics Resource Table";
                case "XSDT": return "Extended System Description Table";
                case "RSDT": return "Root System Description Table";
                case "FPDT": return "Firmware Performance Data Table";
                case "MSDM": return "Microsoft Data Management Table (License Key)";
                case "SLIC": return "Software Licensing Description Table (OEM Activation)";
                case "TPM2": return "Trusted Platform Module 2 Table";
                case "DBGP": return "Debug Port Table";
                case "DBG2": return "Debug Port Table 2";
                case "LPIT": return "Low Power Idle Table";
                case "WSMT": return "Windows Security Mitigations Table";
                case "BERT": return "Boot Error Record Table";
                case "HEST": return "Hardware Error Source Table";
                case "ERST": return "Error Record Serialization Table";
                case "EINJ": return "Error Injection Table";
                case "SRAT": return "System Resource Affinity Table";
                case "SLIT": return "System Locality Information Table";
                case "IVRS": return "I/O Virtualization Reporting Structure";
                case "WDAT": return "Watchdog Action Table";
                case "TCPA": return "Trusted Computing Platform Alliance Table";
                case "WAET": return "Windows ACPI Emulated Devices Table";
                case "DRTM": return "Dynamic Root of Trust for Measurement Table";
                case "WPBT": return "Windows Platform Binary Table";
                case "FACS": return "Firmware ACPI Control Structure";
                case "BOOT": return "Simple Boot Flag Table";
                case "CRAT": return "Component Resource Attribute Table";
                case "ASF!": return "Alert Standard Format Table";
                case "NFIT": return "NVDIMM Firmware Interface Table";
                case "PMTT": return "Platform Memory Topology Table";
                case "PPTT": return "Processor Properties Topology Table";
                case "SDEV": return "Secure Devices Table";
                default: return "Unknown / Vendor Specific";
            }
        }

        private void ViewContent_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as MenuItem;
            var contextMenu = menuItem.Parent as ContextMenu;
            var grid = contextMenu.PlacementTarget as DataGrid;

            if (grid != null && grid.SelectedItem is FirmwareTableItem item)
            {
                try
                {
                    // Reconstruct Provider Signature
                    uint providerSig = 0;
                    if (item.Name == "ACPI") providerSig = 0x41435049; // 'ACPI'
                    else if (item.Name == "RSMB") providerSig = 0x52534D42; // 'RSMB'
                    else if (item.Name == "FIRM") providerSig = 0x4649524D; // 'FIRM'
                    else 
                    {
                        MessageBox.Show("Unknown provider signature for " + item.Name);
                        return;
                    }

                    // Reconstruct Table ID Signature
                    // TableID is string, e.g. "FACP". We need it as uint (Little Endian usually for this API?)
                    // The API expects the integer value. 
                    // e.g. 'ACPI' -> 0x41435049 (Big Endian logic in visual) BUT
                    // Let's rely on BitConverter.
                    // If string is "FACP", bytes are 0x46, 0x41, 0x43, 0x50.
                    // ToUInt32 will make it 0x50434146 (Little Endian).
                    // The NativeMethods.Enum... returned it as bytes, we converted to string.
                    // Now we convert back.
                    byte[] idBytes = System.Text.Encoding.ASCII.GetBytes(item.TableID);
                    if (idBytes.Length != 4)
                    {
                        // Some tables might have different lengths or be purely numeric if not ACPI?
                        // For this viewer, we assume standard 4-char IDs.
                        // If parsing failed earlier or ID is weird, we might fail here.
                    }
                    uint tableIdInt = BitConverter.ToUInt32(idBytes, 0);

                    // Get Size
                    uint size = NativeMethods.GetSystemFirmwareTable(providerSig, tableIdInt, IntPtr.Zero, 0);
                    if (size == 0)
                    {
                        MessageBox.Show("Failed to get table size or table not found.");
                        return;
                    }

                    // Get Content
                    IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)size);
                    try
                    {
                        if (NativeMethods.GetSystemFirmwareTable(providerSig, tableIdInt, buffer, size) == size)
                        {
                            byte[] data = new byte[size];
                            System.Runtime.InteropServices.Marshal.Copy(buffer, data, 0, (int)size);

                            string dump = FormatHexDump(data);
                            string headerInfo = ParseAcpiHeader(data);
                            
                            string fullContent = $"Table: {item.TableID} ({item.Description})\nProvider: {item.Name}\nSize: {size} bytes\n\n{headerInfo}\n\n=== Hex Dump ===\n{dump}";

                            var win = new FirmwareDetailWindow($"Table Content: {item.TableID}", fullContent);
                            win.Owner = Window.GetWindow(this);
                            win.Show();
                        }
                        else
                        {
                            MessageBox.Show("Failed to retrieve table content.");
                        }
                    }
                    finally
                    {
                        System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: " + ex.Message);
                }
            }
        }

        private string ParseAcpiHeader(byte[] data)
        {
            if (data.Length < 36) return "Data too short for ACPI Header.";

            try
            {
                string sig = System.Text.Encoding.ASCII.GetString(data, 0, 4);
                uint len = BitConverter.ToUInt32(data, 4);
                byte rev = data[8];
                byte checksum = data[9];
                string oemId = System.Text.Encoding.ASCII.GetString(data, 10, 6);
                string oemTableId = System.Text.Encoding.ASCII.GetString(data, 16, 8);
                uint oemRev = BitConverter.ToUInt32(data, 24);
                string creatorId = System.Text.Encoding.ASCII.GetString(data, 28, 4);
                uint creatorRev = BitConverter.ToUInt32(data, 32);

                return $"=== ACPI Header ===\nSignature: {sig}\nLength: {len}\nRevision: {rev}\nChecksum: 0x{checksum:X2}\nOEM ID: {oemId}\nOEM Table ID: {oemTableId}\nOEM Revision: {oemRev:X8}\nCreator ID: {creatorId}\nCreator Revision: {creatorRev:X8}";
            }
            catch
            {
                return "Error parsing ACPI Header.";
            }
        }

        private string FormatHexDump(byte[] data)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < data.Length; i += 16)
            {
                sb.Append($"{i:X8}  ");

                // Hex
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < data.Length)
                        sb.Append($"{data[i + j]:X2} ");
                    else
                        sb.Append("   ");
                }

                sb.Append(" ");

                // ASCII
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < data.Length)
                    {
                        byte b = data[i + j];
                        if (b >= 32 && b <= 126)
                            sb.Append((char)b);
                        else
                            sb.Append(".");
                    }
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        private static class NativeMethods
        {
            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint EnumSystemFirmwareTables(uint FirmwareTableProviderSignature, IntPtr pFirmwareTableEnumBuffer, uint BufferSize);

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, IntPtr pFirmwareTableBuffer, uint BufferSize);
        }
        
        private void AskAi_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as MenuItem;
            var contextMenu = menuItem.Parent as ContextMenu;
            var grid = contextMenu.PlacementTarget as DataGrid;

            if (grid != null && grid.SelectedItem != null)
            {
                var window = new AskAiWindow(grid.SelectedItem);
                window.Owner = Window.GetWindow(this);
                window.ShowDialog();
            }
        }

        private void ViewDetails_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as MenuItem;
            var contextMenu = menuItem.Parent as ContextMenu;
            var grid = contextMenu.PlacementTarget as DataGrid;

            if (grid != null && grid.SelectedItem is BcdEntry entry)
            {
                string details = $"Type: {entry.Type}\nIdentifier: {entry.Identifier}\nDescription: {entry.Description}\nDevice: {entry.Device}\nPath: {entry.Path}\n\nAdditional Settings:\n{entry.AdditionalSettings}";
                MessageBox.Show(details, "BCD Entry Details", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async void LoadBcdInfo()
        {
            try
            {
                // Clear existing
                BcdEntries.Clear();

                // Run bcdedit
                string output = await System.Threading.Tasks.Task.Run(() =>
                {
                    try 
                    {
                        ProcessStartInfo psi = new ProcessStartInfo("bcdedit", "/enum all");
                        psi.RedirectStandardOutput = true;
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        // psi.StandardOutputEncoding = System.Text.Encoding.GetEncoding(437); // CP437 causes error if provider not registered

                        using (Process p = Process.Start(psi))
                        {
                            string result = p.StandardOutput.ReadToEnd();
                            p.WaitForExit();
                            return result;
                        }
                    }
                    catch (Exception ex)
                    {
                        return "Error running bcdedit: " + ex.Message;
                    }
                });

                // Parse Output
                ParseBcdOutput(output);
            }
            catch (Exception ex)
            {
                BcdEntries.Add(new BcdEntry { Type = "Error", Description = ex.Message });
            }
        }

        private void ParseBcdOutput(string rawOutput)
        {
            if (string.IsNullOrWhiteSpace(rawOutput) || rawOutput.StartsWith("Error"))
            {
                 BcdEntries.Add(new BcdEntry { Type = "Error", Description = rawOutput });
                 return;
            }

            var lines = rawOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            string currentType = "";
            BcdEntry currentEntry = null;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].TrimEnd(); // Keep leading spaces for potential multi-line values, but we mainly care about structure
                
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Check for Section Header (Text followed by separator line)
                if (i + 1 < lines.Length && lines[i + 1].Trim().StartsWith("---"))
                {
                    currentType = line.Trim();
                    i++; // Skip separator
                    continue;
                }

                // Check for Key-Value pair
                // Format: "identifier              {current}"
                // We'll split by first whitespace run
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 1)
                {
                    string key = parts[0].ToLower();
                    
                    // If parsing a new identifier, it's a new entry
                    if (key == "identifier")
                    {
                         if (currentEntry != null)
                         {
                             BcdEntries.Add(currentEntry);
                         }
                         currentEntry = new BcdEntry { Type = currentType };
                    }
                    
                    if (currentEntry != null && parts.Length >= 2)
                    {
                         // Join the rest as value in case value has spaces
                         // But simple split remove empty entries destroys spaces in value if any?
                         // Better: Find first space index
                         int spaceIndex = line.IndexOfAny(new[] { ' ', '\t' });
                         if (spaceIndex > 0)
                         {
                             string val = line.Substring(spaceIndex).Trim();

                             switch (key)
                             {
                                 case "identifier": currentEntry.Identifier = val; break;
                                 case "description": currentEntry.Description = val; break;
                                 case "device": currentEntry.Device = val; break;
                                 case "path": currentEntry.Path = val; break;
                                 default: 
                                     if (string.IsNullOrEmpty(currentEntry.AdditionalSettings))
                                         currentEntry.AdditionalSettings = $"{key}: {val}";
                                     else
                                         currentEntry.AdditionalSettings += $", {key}: {val}";
                                     break;
                             }
                         }
                    }
                }
            }
            
            // Add last entry
            if (currentEntry != null)
            {
                BcdEntries.Add(currentEntry);
            }
        }
    }
}
