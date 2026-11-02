using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;

namespace DeviceMonitorCS.Models
{
    public class ConnectionItem : System.ComponentModel.INotifyPropertyChanged
    {
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));

        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public string RemoteAddress { get; set; }
        private string _state;
        public string State { get { return _state; } set { _state = value; OnPropertyChanged(nameof(State)); } }
        public string ProcessName { get; set; }
        public int Pid { get; set; }
        private string _whoIs = "Resolving...";
        public string WhoIs { get { return _whoIs; } set { _whoIs = value; OnPropertyChanged(nameof(WhoIs)); } }
        public DateTime StartTime { get; set; }
        private DateTime _lastSeen;
        public DateTime LastSeen { get { return _lastSeen; } set { _lastSeen = value; OnPropertyChanged(nameof(LastSeen)); OnPropertyChanged(nameof(Duration)); } }
        public string Duration => (LastSeen - StartTime).ToString(@"hh\:mm\:ss");
        public string DataTransferred { get; set; } = "-"; 
    }

    public class ConnectionMonitor
    {
        public ObservableCollection<ConnectionItem> ActiveConnections { get; set; } = new ObservableCollection<ConnectionItem>();
        public ObservableCollection<ConnectionItem> HistoricalConnections { get; set; } = new ObservableCollection<ConnectionItem>();
        public ObservableCollection<string> MutedConnections { get; set; } = new ObservableCollection<string>();
        // UI Display
        public ObservableCollection<ConnectionItem> DisplayMutedConnections { get; set; } = new ObservableCollection<ConnectionItem>();

        private static ConnectionMonitor _instance;
        public static ConnectionMonitor Instance => _instance ?? (_instance = new ConnectionMonitor());

        private const string BaseDataDir = @"C:\ProgramData\Auto-Command";
        private readonly string _historyFile = Path.Combine(BaseDataDir, "connection_history.json");
        private readonly string _mutedFile = Path.Combine(BaseDataDir, "muted_connections.json");
        private readonly string _ipCacheFile = Path.Combine(BaseDataDir, "ip_cache.json");

        // Cache for Process Names and WhoIs to avoid spamming
        private ConcurrentDictionary<int, string> _processCache = new ConcurrentDictionary<int, string>();
        private ConcurrentDictionary<string, string> _whoIsCache = new ConcurrentDictionary<string, string>();
        
        // Throttling
        private ConcurrentQueue<string> _lookupQueue = new ConcurrentQueue<string>();
        private HashSet<string> _queuedIps = new HashSet<string>();
        private Task _processingTask;
        private readonly object _queueLock = new object();

        public ConnectionMonitor()
        {
            LoadPersistence();
            _processingTask = Task.Run(ProcessLookups);
        }

        public void SavePersistence()
        {
            try
            {
                if (!Directory.Exists(BaseDataDir)) Directory.CreateDirectory(BaseDataDir);

                var historyData = JsonSerializer.Serialize(HistoricalConnections);
                File.WriteAllText(_historyFile, historyData);

                var mutedData = JsonSerializer.Serialize(MutedConnections);
                File.WriteAllText(_mutedFile, mutedData);
                
                var ipData = JsonSerializer.Serialize(_whoIsCache);
                File.WriteAllText(_ipCacheFile, ipData);
            }
            catch (Exception ex) 
            {
                Debug.WriteLine($"Failed to save persistence: {ex.Message}");
            }
        }

        private void LoadPersistence()
        {
            try
            {
                if (File.Exists(_historyFile))
                {
                    var invalidJson = File.ReadAllText(_historyFile);
                    var list = JsonSerializer.Deserialize<List<ConnectionItem>>(invalidJson);
                    if (list != null)
                    {
                        foreach (var item in list) HistoricalConnections.Add(item);
                    }
                }

                if (File.Exists(_mutedFile))
                {
                    var list = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(_mutedFile));
                    if (list != null)
                    {
                        foreach (var item in list) MutedConnections.Add(item);
                    }
                }

                if (File.Exists(_ipCacheFile))
                {
                    var cache = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_ipCacheFile));
                    if (cache != null)
                    {
                        _whoIsCache = new ConcurrentDictionary<string, string>(cache);
                    }
                }
            }
            catch { }
        }

        public void MuteConnection(ConnectionItem item)
        {
            string key = $"{item.RemoteAddress}"; // Mute by IP
            if (!MutedConnections.Contains(key))
            {
                MutedConnections.Add(key);
                SavePersistence();
            }
        }

        public void UnmuteConnection(string ip)
        {
            if (MutedConnections.Contains(ip))
            {
                MutedConnections.Remove(ip);
                SavePersistence();
            }
        }

        public void ClearHistory()
        {
            HistoricalConnections.Clear();
            SavePersistence();
        }

        public void RefreshConnections()
        {
            var currentSnapshot = new List<ConnectionItem>();
            currentSnapshot.AddRange(GetTcpConnections());
            currentSnapshot.AddRange(GetUdpConnections());

            // Merge with Active
            // We need to keep StartTime for existing connections
            // Remove those not in snapshot
            
            var snapshotKeys = new HashSet<string>(currentSnapshot.Select(Key));

            // Remove dead
            var toRemove = ActiveConnections.Where(c => !snapshotKeys.Contains(Key(c))).ToList();
            foreach (var item in toRemove)
            {
                ActiveConnections.Remove(item);
                // Move to History if not muted
                if (!IsMuted(item))
                {
                    // Avoid duplicates in history? User wants log.
                    // Let's add if not recently added? Or just add.
                    // Ideally we update the "LastSeen" of the history item if it exists?
                    // "Historical connections" usually means "closed connections".
                    item.State = "Closed";
                    HistoricalConnections.Insert(0, item);
                    if (HistoricalConnections.Count > 1000) HistoricalConnections.RemoveAt(HistoricalConnections.Count - 1);
                }
            }

            // Add/Update
            foreach (var item in currentSnapshot)
            {
                if (IsMuted(item)) continue;

                var existing = ActiveConnections.FirstOrDefault(c => Key(c) == Key(item));
                if (existing != null)
                {
                    existing.LastSeen = DateTime.Now;
                    existing.State = item.State;
                }
                else
                {
                    item.StartTime = DateTime.Now;
                    item.LastSeen = DateTime.Now;
                    ResolveWhoIs(item); // Async resolution
                    ActiveConnections.Add(item);
                }
            }

            // --- Muted Connections Display Logic ---
            var mutedActive = currentSnapshot.Where(IsMuted).ToList();
            var activeMutedIps = new HashSet<string>(mutedActive.Select(c => c.RemoteAddress));
            
            // Inactive rules
            var inactiveRules = MutedConnections.Where(ip => !activeMutedIps.Contains(ip)).ToList();

            var newDisplayList = new List<ConnectionItem>();
            foreach (var item in mutedActive)
            {
                ResolveWhoIs(item); 
                newDisplayList.Add(item);
            }
            foreach (var ruleIp in inactiveRules)
            {
                 newDisplayList.Add(new ConnectionItem 
                 { 
                     RemoteAddress = ruleIp, 
                     ProcessName = "Rule (Inactive)", 
                     State = "Muted", 
                     WhoIs = _whoIsCache.ContainsKey(ruleIp) ? _whoIsCache[ruleIp] : "Unknown",
                     Protocol = "-",
                     LocalAddress = "-",
                     StartTime = DateTime.MinValue,
                     LastSeen = DateTime.MinValue
                 });
            }

            DisplayMutedConnections.Clear();
            foreach(var item in newDisplayList) DisplayMutedConnections.Add(item);
            
            SavePersistence(); // Maybe too frequent? Save on close instead?
        }

        private bool IsMuted(ConnectionItem item)
        {
            return MutedConnections.Contains(item.RemoteAddress);
        }

        private string Key(ConnectionItem c) => $"{c.Protocol}:{c.LocalAddress}->{c.RemoteAddress}:{c.Pid}";

        private static readonly HttpClient _httpClient = new HttpClient();

        private void ResolveWhoIs(ConnectionItem item)
        {
            if (IsLocalIp(item.RemoteAddress))
            {
                item.WhoIs = "Local/LAN";
                return;
            }

            if (_whoIsCache.TryGetValue(item.RemoteAddress, out string val))
            {
                item.WhoIs = val;
                return;
            }

            item.WhoIs = "Resolving...";
            
            lock (_queueLock)
            {
                if (!_queuedIps.Contains(item.RemoteAddress))
                {
                    _queuedIps.Add(item.RemoteAddress);
                    _lookupQueue.Enqueue(item.RemoteAddress);
                }
            }
        }

        private async Task ProcessLookups()
        {
            while (true)
            {
                if (_lookupQueue.TryDequeue(out string ip))
                {
                    try
                    {
                        string result = await GetIpInfoAsync(ip);
                        if (string.IsNullOrEmpty(result))
                        {
                            try
                            {
                                var entry = Dns.GetHostEntry(ip);
                                result = entry.HostName;
                            }
                            catch { result = "Unknown"; }
                        }
                        
                        _whoIsCache[ip] = result;

                        // Update Active Items
                        // Needs Dispatcher? No, binding should handle it if INPC is correct, but collection access is thread-safe?
                        // ObservableCollection is not thread-safe. We should use Dispatcher if we modify the list, but we are modifying items IN the list.
                        // Modifying properties of items in OC from bg thread is usually fine if UI dispatches change.
                        // But finding the item needs lock or copy.
                        
                        UpdateItemsWithIp(ip, result);
                    }
                    catch { }

                    lock (_queueLock) { _queuedIps.Remove(ip); }
                    
                    // Throttle 3s
                    await Task.Delay(3000);
                }
                else
                {
                    await Task.Delay(500);
                }
            }
        }

        private void UpdateItemsWithIp(string ip, string val)
        {
             // Simple iteration - might race but acceptable for display update
             foreach(var c in ActiveConnections.ToList()) 
             {
                 if (c.RemoteAddress == ip) c.WhoIs = val;
             }
             foreach(var c in HistoricalConnections.ToList())
             {
                 if (c.RemoteAddress == ip) c.WhoIs = val;
             }
        }

        private async Task<string> GetIpInfoAsync(string ip)
        {
            try
            {
                // Unauthenticated rate limits apply (approx 50k/month free)
                string json = await _httpClient.GetStringAsync($"https://ipinfo.io/{ip}/json");
                using (JsonDocument doc = JsonDocument.Parse(json))
                {
                    JsonElement root = doc.RootElement;
                    string org = root.TryGetProperty("org", out var o) ? o.GetString() : "";
                    string city = root.TryGetProperty("city", out var c) ? c.GetString() : "";
                    string country = root.TryGetProperty("country", out var cn) ? cn.GetString() : "";
                    string hostname = root.TryGetProperty("hostname", out var h) ? h.GetString() : "";

                    // Format: "AS15169 Google LLC" or "Comcast Cable"
                    if (!string.IsNullOrEmpty(org))
                    {
                        // Clean up AS number if present "AS1234 Name" -> "Name" if desired, but AS is useful
                        return $"{org} ({country})"; 
                    }
                    if (!string.IsNullOrEmpty(hostname) && hostname != ip) return hostname;
                    
                    return "";
                }
            }
            catch 
            {
                return "";
            }
        }

        private bool IsLocalIp(string ip)
        {
             return ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::" || ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172.16.");
        }

        private IEnumerable<ConnectionItem> GetTcpConnections()
        {
            var buffer = IntPtr.Zero;
            int size = 0;
            // Get size
            uint result = IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, true, IpHlpApi.AF_INET, IpHlpApi.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            
            buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = IpHlpApi.GetExtendedTcpTable(buffer, ref size, true, IpHlpApi.AF_INET, IpHlpApi.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                if (result != 0) return Enumerable.Empty<ConnectionItem>();

                var table = Marshal.PtrToStructure<IpHlpApi.MIB_TCPTABLE_OWNER_PID>(buffer);
                int rowSize = Marshal.SizeOf<IpHlpApi.MIB_TCPROW_OWNER_PID>();
                IntPtr currentRow = buffer + Marshal.SizeOf<uint>(); // skip dwNumEntries

                var list = new List<ConnectionItem>();
                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    var row = Marshal.PtrToStructure<IpHlpApi.MIB_TCPROW_OWNER_PID>(currentRow);
                    
                    string local = IPToString(row.localAddr) + ":" + PortToString(row.localPort);
                    string remote = IPToString(row.remoteAddr); 
                    // Remote Port? Struct has it.
                    
                    list.Add(new ConnectionItem
                    {
                        Protocol = "TCP",
                        LocalAddress = local,
                        RemoteAddress = remote,
                        State = ((TcpState)row.state).ToString(),
                        ProcessName = GetProcessName((int)row.owningPid),
                        Pid = (int)row.owningPid
                    });

                    currentRow += rowSize;
                }
                return list;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private IEnumerable<ConnectionItem> GetUdpConnections()
        {
             var buffer = IntPtr.Zero;
            int size = 0;
            // Get size
            uint result = IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, true, IpHlpApi.AF_INET, IpHlpApi.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            
            buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = IpHlpApi.GetExtendedUdpTable(buffer, ref size, true, IpHlpApi.AF_INET, IpHlpApi.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
                if (result != 0) return Enumerable.Empty<ConnectionItem>();

                var table = Marshal.PtrToStructure<IpHlpApi.MIB_UDPTABLE_OWNER_PID>(buffer);
                int rowSize = Marshal.SizeOf<IpHlpApi.MIB_UDPROW_OWNER_PID>();
                IntPtr currentRow = buffer + Marshal.SizeOf<uint>(); 

                var list = new List<ConnectionItem>();
                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    var row = Marshal.PtrToStructure<IpHlpApi.MIB_UDPROW_OWNER_PID>(currentRow);
                    
                    string local = IPToString(row.localAddr) + ":" + PortToString(row.localPort);
                    
                    list.Add(new ConnectionItem
                    {
                        Protocol = "UDP",
                        LocalAddress = local,
                        RemoteAddress = "-", // UDP is connectionless
                        State = "Listening",
                        ProcessName = GetProcessName((int)row.owningPid),
                        Pid = (int)row.owningPid
                    });

                    currentRow += rowSize;
                }
                return list;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private string IPToString(uint ip)
        {
            return new IPAddress(BitConverter.GetBytes(ip)).ToString();
        }

        private string PortToString(byte[] port)
        {
            // Port is network byte order (Big Endian)?
            // Actually API returns it in network byte order usually
            if (BitConverter.IsLittleEndian)
                return ((port[0] << 8) | port[1]).ToString();
            else
                return ((port[1] << 8) | port[0]).ToString();
        }

        private string GetProcessName(int pid)
        {
            if (pid == 0) return "System Idle";
            if (pid == 4) return "System";

            if (_processCache.TryGetValue(pid, out string name)) return name;

            try
            {
                var p = Process.GetProcessById(pid);
                name = p.ProcessName;
                _processCache[pid] = name;
                return name;
            }
            catch 
            {
                return $"PID {pid}";
            }
        }
    }
}
