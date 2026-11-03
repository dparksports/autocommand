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
        // The TCP row always carried the remote port; the grid never rendered
        // it ("Remote Port? Struct has it."). Kept separate from
        // RemoteAddress, which must stay a BARE IP — WhoIs, DNS, clipboard
        // and the TCP mute key all consume it as one.
        public string RemotePort { get; set; } = "-";
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

        // Mute identity. TCP rows mute by remote IP — the historical contract
        // (WhoIs, clipboard, and the View's Unmute(item.RemoteAddress) all
        // key on the bare IP). UDP rows have NO remote ("-" for every one of
        // them — one mute used to mute every UDP row at once); they mute by
        // their local endpoint instead.
        public string MuteKey(ConnectionItem item) =>
            item.Protocol == "UDP" ? "udp:" + item.LocalAddress : item.RemoteAddress;

        public void MuteConnection(ConnectionItem item)
        {
            string key = MuteKey(item);
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
            // pid→name pairs go stale the moment a pid is reused by a
            // different image (the cache never expired before) — re-resolve
            // once per refresh cycle, the same cadence Task Manager uses.
            _processCache.Clear();

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
                // Move to History if not muted. TCP connections close; a UDP
                // endpoint UNBINDS — "Closed" fabricated a connection
                // lifecycle that connectionless sockets never had.
                if (!IsMuted(item))
                {
                    item.State = item.Protocol == "UDP" ? "Unbound" : "Closed";
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
            var activeMutedKeys = new HashSet<string>(mutedActive.Select(MuteKey));

            // Inactive rules (keyed the same way they were muted)
            var inactiveRules = MutedConnections.Where(key => !activeMutedKeys.Contains(key)).ToList();

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

            SavePersistence();
        }

        private bool IsMuted(ConnectionItem item)
        {
            return MutedConnections.Contains(MuteKey(item));
        }

        private string Key(ConnectionItem c) => $"{c.Protocol}:{c.LocalAddress}->{c.RemoteAddress}:{c.Pid}";

        private static readonly HttpClient _httpClient = new HttpClient();

        private void ResolveWhoIs(ConnectionItem item)
        {
            // Rows with no remote (UDP endpoints) must not enter the lookup
            // pipeline — "-" used to be queued like an IP, junk-caching a
            // literal dash and burning a lookup slot on it.
            if (string.IsNullOrEmpty(item.RemoteAddress) || item.RemoteAddress == "-")
            {
                item.WhoIs = item.Protocol == "UDP" ? "UDP (bound, no remote)" : "-";
                return;
            }

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

                        // Item properties raise INPC from this background
                        // thread — safe for the bound grid; the collection
                        // itself is never mutated here.
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
            if (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip == "::") return true;
            if (ip.StartsWith("192.168.") || ip.StartsWith("10.")) return true;
            if (ip.StartsWith("172."))
            {
                // RFC1918 is 172.16.0.0/12 — second octet 16..31. The old
                // "172.16."-prefix check misclassified 172.17–172.31 as
                // non-local, so those LAN rows hit the WhoIs pipeline.
                var second = ip.Substring(4).Split('.')[0];
                if (int.TryParse(second, out int octet) && octet >= 16 && octet <= 31) return true;
            }
            return false;
        }

        private IEnumerable<ConnectionItem> GetTcpConnections()
        {
            var list = new List<ConnectionItem>();
            list.AddRange(GetTcpTable(IpHlpApi.AF_INET));
            list.AddRange(GetTcpTable(IpHlpApi.AF_INET6));
            return list;
        }

        private IEnumerable<ConnectionItem> GetUdpConnections()
        {
            var list = new List<ConnectionItem>();
            list.AddRange(GetUdpTable(IpHlpApi.AF_INET));
            list.AddRange(GetUdpTable(IpHlpApi.AF_INET6));
            return list;
        }

        private const uint ErrorInsufficientBuffer = 122;

        // One syscall pair per family with the race closed: the sizing probe
        // must answer ERROR_INSUFFICIENT_BUFFER (its result was previously
        // ignored), and if the table GROWS between sizing and fill the fill
        // returns 122 too — retry once with the new size instead of the old
        // code's silent EMPTY snapshot ("no connections" was a lie the race
        // could produce at any moment).
        private IEnumerable<ConnectionItem> GetTcpTable(int family)
        {
            bool v6 = family == IpHlpApi.AF_INET6;
            int size = 0;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                if (IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, false, family,
                        IpHlpApi.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL) != ErrorInsufficientBuffer)
                    return Enumerable.Empty<ConnectionItem>();

                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint result = IpHlpApi.GetExtendedTcpTable(buffer, ref size, false, family,
                        IpHlpApi.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                    if (result == ErrorInsufficientBuffer) continue; // grew — resize and retry
                    if (result != 0) return Enumerable.Empty<ConnectionItem>();

                    int count = Marshal.ReadInt32(buffer);
                    int rowSize = v6
                        ? Marshal.SizeOf<IpHlpApi.MIB_TCP6ROW_OWNER_PID>()
                        : Marshal.SizeOf<IpHlpApi.MIB_TCPROW_OWNER_PID>();
                    IntPtr currentRow = buffer + sizeof(uint); // skip dwNumEntries

                    var list = new List<ConnectionItem>();
                    for (int i = 0; i < count; i++)
                    {
                        if (v6)
                        {
                            var row = Marshal.PtrToStructure<IpHlpApi.MIB_TCP6ROW_OWNER_PID>(currentRow);
                            var localIp = IP6ToString(row.localAddr, row.localScopeId);
                            var remoteIp = IP6ToString(row.remoteAddr, row.remoteScopeId);
                            list.Add(new ConnectionItem
                            {
                                Protocol = "TCP",
                                LocalAddress = $"[{localIp}]:{PortToString(row.localPort)}",
                                RemoteAddress = remoteIp, // bare IP: WhoIs/DNS/clipboard contract
                                RemotePort = PortToString(row.remotePort),
                                State = ((TcpState)row.state).ToString(),
                                ProcessName = GetProcessName((int)row.owningPid),
                                Pid = (int)row.owningPid
                            });
                        }
                        else
                        {
                            var row = Marshal.PtrToStructure<IpHlpApi.MIB_TCPROW_OWNER_PID>(currentRow);
                            list.Add(new ConnectionItem
                            {
                                Protocol = "TCP",
                                LocalAddress = IPToString(row.localAddr) + ":" + PortToString(row.localPort),
                                RemoteAddress = IPToString(row.remoteAddr), // bare IP: WhoIs/DNS/clipboard contract
                                RemotePort = PortToString(row.remotePort),
                                State = ((TcpState)row.state).ToString(),
                                ProcessName = GetProcessName((int)row.owningPid),
                                Pid = (int)row.owningPid
                            });
                        }
                        currentRow += rowSize;
                    }
                    return list;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return Enumerable.Empty<ConnectionItem>();
        }

        private IEnumerable<ConnectionItem> GetUdpTable(int family)
        {
            bool v6 = family == IpHlpApi.AF_INET6;
            int size = 0;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                if (IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, false, family,
                        IpHlpApi.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID) != ErrorInsufficientBuffer)
                    return Enumerable.Empty<ConnectionItem>();

                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint result = IpHlpApi.GetExtendedUdpTable(buffer, ref size, false, family,
                        IpHlpApi.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
                    if (result == ErrorInsufficientBuffer) continue; // grew — resize and retry
                    if (result != 0) return Enumerable.Empty<ConnectionItem>();

                    int count = Marshal.ReadInt32(buffer);
                    int rowSize = v6
                        ? Marshal.SizeOf<IpHlpApi.MIB_UDP6ROW_OWNER_PID>()
                        : Marshal.SizeOf<IpHlpApi.MIB_UDPROW_OWNER_PID>();
                    IntPtr currentRow = buffer + sizeof(uint); // skip dwNumEntries

                    var list = new List<ConnectionItem>();
                    for (int i = 0; i < count; i++)
                    {
                        if (v6)
                        {
                            var row = Marshal.PtrToStructure<IpHlpApi.MIB_UDP6ROW_OWNER_PID>(currentRow);
                            var localIp = IP6ToString(row.localAddr, row.localScopeId);
                            list.Add(new ConnectionItem
                            {
                                Protocol = "UDP",
                                LocalAddress = $"[{localIp}]:{PortToString(row.localPort)}",
                                RemoteAddress = "-", // the owner-pid UDP row HAS no remote — connectionless
                                State = "Bound",     // a UDP endpoint is bound; "Listening" is a TCP concept
                                ProcessName = GetProcessName((int)row.owningPid),
                                Pid = (int)row.owningPid
                            });
                        }
                        else
                        {
                            var row = Marshal.PtrToStructure<IpHlpApi.MIB_UDPROW_OWNER_PID>(currentRow);
                            list.Add(new ConnectionItem
                            {
                                Protocol = "UDP",
                                LocalAddress = IPToString(row.localAddr) + ":" + PortToString(row.localPort),
                                RemoteAddress = "-", // the owner-pid UDP row HAS no remote — connectionless
                                State = "Bound",     // a UDP endpoint is bound; "Listening" is a TCP concept
                                ProcessName = GetProcessName((int)row.owningPid),
                                Pid = (int)row.owningPid
                            });
                        }
                        currentRow += rowSize;
                    }
                    return list;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            return Enumerable.Empty<ConnectionItem>();
        }

        private string IP6ToString(byte[] addr, uint scopeId)
        {
            var ip = scopeId == 0 ? new IPAddress(addr) : new IPAddress(addr, scopeId);
            return ip.ToString();
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

        /// <summary>Read-only diagnostic: is this key in the WhoIs cache?
        /// (Canary tests assert "-" never lands here.)</summary>
        public bool WhoIsCached(string ip) => _whoIsCache.ContainsKey(ip);
    }
}
