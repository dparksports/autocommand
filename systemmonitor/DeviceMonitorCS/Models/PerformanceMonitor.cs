using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Collections.Generic;

namespace DeviceMonitorCS.Models
{

    public class DiskMetric
    {
        public string Name { get; set; }
        public float ReadSpeed { get; set; } // KB/s
        public float WriteSpeed { get; set; } // KB/s
    }

    public class PerformanceMetrics
    {
        public float CpuUsage { get; set; }
        public float AvailableRam { get; set; } // GB
        public float TotalRam { get; set; } // GB
        public float RamUsagePercent { get; set; }
        public float NetworkSend { get; set; } // KB/s
        public float NetworkReceive { get; set; } // KB/s
        public List<GpuMetric> GpuMetrics { get; set; } = new List<GpuMetric>();
        public List<DiskMetric> DiskMetrics { get; set; } = new List<DiskMetric>();
    }

    public class GpuMetric
    {
        public string Name { get; set; }
        public float Utilization { get; set; }
        public float MemoryUsage { get; set; } // Dedicated VRAM used in MB
        public float TotalMemory { get; set; } // Dedicated VRAM total in MB
    }

    public class PerformanceMonitor
    {
        private PerformanceCounter _cpuCounter;
        private PerformanceCounter _ramCounter;
        private List<PerformanceCounter> _netSendCounters = new List<PerformanceCounter>();
        private List<PerformanceCounter> _netRecvCounters = new List<PerformanceCounter>();
        
        // Disk Counters
        private List<PerformanceCounter> _diskReadCounters = new List<PerformanceCounter>();
        private List<PerformanceCounter> _diskWriteCounters = new List<PerformanceCounter>();

        private float _totalRamGb = 0;
        public bool IsInitialized { get; private set; }

        public PerformanceMonitor()
        {
            // Start async initialization so we don't block the UI thread
            Task.Run(() => 
            {
                InitializeCounters();
                _totalRamGb = GetTotalRam();
                IsInitialized = true;
            });
        }

        private void InitializeCounters()
        {
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _ramCounter = new PerformanceCounter("Memory", "Available MBytes");

                // Network - Sum of all interfaces
                var netCat = new PerformanceCounterCategory("Network Interface");
                var netInstances = netCat.GetInstanceNames();
                foreach (var instance in netInstances)
                {
                    _netSendCounters.Add(new PerformanceCounter("Network Interface", "Bytes Sent/sec", instance));
                    _netRecvCounters.Add(new PerformanceCounter("Network Interface", "Bytes Received/sec", instance));
                }

                // Disks
                var diskCat = new PerformanceCounterCategory("PhysicalDisk");
                var diskInstances = diskCat.GetInstanceNames();
                foreach (var instance in diskInstances)
                {
                    if (instance == "_Total") continue;
                    _diskReadCounters.Add(new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", instance));
                    _diskWriteCounters.Add(new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", instance));
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error init counters: {ex.Message}");
            }
        }

        public PerformanceMetrics GetMetrics()
        {
            var m = new PerformanceMetrics();
            if (!IsInitialized) return m; // Return empty metrics until ready
            
            try
            {
                m.CpuUsage = _cpuCounter?.NextValue() ?? 0;
                float availableMb = _ramCounter?.NextValue() ?? 0;
                m.AvailableRam = availableMb / 1024f;
                m.TotalRam = _totalRamGb;
                if (_totalRamGb > 0)
                {
                    m.RamUsagePercent = ((_totalRamGb * 1024 - availableMb) / (_totalRamGb * 1024)) * 100;
                }

                // Network
                float totalSend = 0;
                float totalRecv = 0;
                foreach (var c in _netSendCounters) { try { totalSend += c.NextValue(); } catch {} }
                foreach (var c in _netRecvCounters) { try { totalRecv += c.NextValue(); } catch {} }

                m.NetworkSend = totalSend / 1024f; // KB/s
                m.NetworkReceive = totalRecv / 1024f; // KB/s

                // GPU
                m.GpuMetrics = GetGpuMetrics();

                // Disk
                foreach (var rc in _diskReadCounters)
                {
                    // Find corresponding write counter
                    var wc = _diskWriteCounters.FirstOrDefault(c => c.InstanceName == rc.InstanceName);
                    float read = 0;
                    float write = 0;
                    try { read = rc.NextValue(); } catch {}
                    try { if (wc != null) write = wc.NextValue(); } catch {}

                    m.DiskMetrics.Add(new DiskMetric
                    {
                        Name = rc.InstanceName,
                        ReadSpeed = read / 1024f,
                        WriteSpeed = write / 1024f
                    });
                }
            }
            catch {}

            return m;
        }

        private float GetTotalRam()
        {
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    ulong b = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                    return b / (1024f * 1024f * 1024f); 
                }
            }
            catch {}
            return 8; // Default fallback
        }

        private List<GpuMetric> GetGpuMetrics()
        {
            var metrics = new List<GpuMetric>();
            
            // 1. Try to get NVIDIA stats specifically (High Fidelity)
            var nvidiaMetrics = GetNvidiaMetrics();
            if (nvidiaMetrics.Count > 0)
            {
                metrics.AddRange(nvidiaMetrics);
            }

            // 2. Get WMI stats (Fallback & Other GPUs like AMD/Intel)
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT Name, AdapterRAM FROM Win32_VideoController");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string name = obj["Name"]?.ToString();
                    if (string.IsNullOrEmpty(name)) continue;

                    // If we already have this GPU from Nvidia-SMI, skip WMI (WMI has 4GB limit)
                    if (nvidiaMetrics.Any(n => name.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0 && n.Name.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        continue;
                    }

                    // AdapterRAM returns bytes.
                    float vram = 0;
                    try { vram = Convert.ToUInt64(obj["AdapterRAM"]) / (1024f * 1024f); } catch {} // MB
                    
                    if (vram > 0) // Filter out basic display drivers usually
                    {
                        metrics.Add(new GpuMetric 
                        { 
                            Name = name, 
                            TotalMemory = vram,
                            Utilization = 0, // WMI cannot provide this
                            MemoryUsage = 0
                        });
                    }
                }
            }
            catch {}

            return metrics;
        }

        private List<GpuMetric> GetNvidiaMetrics()
        {
            var list = new List<GpuMetric>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "nvidia-smi",
                    Arguments = "--query-gpu=name,memory.total,memory.used,utilization.gpu --format=csv,noheader,nounits",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();

                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(',');
                        if (parts.Length >= 4)
                        {
                            // Output format: Name, Total, Used, Util
                            // Example: NVIDIA GeForce RTX 3080, 10240, 102, 0
                            string name = parts[0].Trim();
                            float.TryParse(parts[1].Trim(), out float total);
                            float.TryParse(parts[2].Trim(), out float used);
                            float.TryParse(parts[3].Trim(), out float util);

                            list.Add(new GpuMetric
                            {
                                Name = name,
                                TotalMemory = total,
                                MemoryUsage = used,
                                Utilization = util
                            });
                        }
                    }
                }
            }
            catch 
            {
                // nvidia-smi not found or failed
            }
            return list;
        }
    }
}
