using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace BootAnalyzer
{
    public class Program
    {
        // Configuration
        static readonly int MaxSecondsDiff = 300; 
        static readonly DateTime StartTime = DateTime.Now.AddDays(-90);

        public class SimpleEvent
        {
            public DateTime TimeCreated { get; set; }
            public int Id { get; set; }
            // Fix CS8618: Make nullable to allow nulls
            public string? Provider { get; set; } 
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("1. Querying Event Logs (This may take a moment)...");

            var sysEvents = QueryLog("System", new[] { 12, 6006, 1074 });

            List<SimpleEvent> secEvents = new List<SimpleEvent>();
            try
            {
                secEvents = QueryLog("Security", new[] { 4608, 4609 });
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("   [!] ERROR: Access Denied to Security Log. Please Run as Administrator.");
                Console.ResetColor();
            }
            // Catch generic Exception if EventLogException isn't found during runtime for some reason
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"   [!] ERROR reading Security Log: {ex.Message}");
                Console.ResetColor();
            }

            // ... (Rest of logical filtering remains the same) ...

            // Master Boot List: Kernel-General ID 12
            var boots = sysEvents
                .Where(e => e.Id == 12 && e.Provider == "Microsoft-Windows-Kernel-General")
                .OrderBy(e => e.TimeCreated)
                .ToList();

            // Searchable 4608 List
            var all4608s = secEvents
                .Where(e => e.Id == 4608)
                .OrderBy(e => e.TimeCreated)
                .ToList();

            // All Shutdowns
            var allShutdowns = sysEvents.Concat(secEvents)
                .Where(e => e.Id == 6006 || e.Id == 1074 || e.Id == 4609)
                .OrderBy(e => e.TimeCreated)
                .ToList();

            Console.WriteLine($"   Stats: {boots.Count} Boots | {all4608s.Count} 4608 Events | {allShutdowns.Count} Shutdowns");
            Console.WriteLine(new string('-', 110));
            Console.WriteLine("{0,-22} {1,-22} {2,-15} {3,-18} {4,-10} {5,-15}", 
                "BootTime", "ShutdownTime", "Status", "Uptime", "KG12", "Sec4608");
            Console.WriteLine(new string('-', 110));

            for (int i = 0; i < boots.Count; i++)
            {
                var boot = boots[i];
                DateTime bootTime = boot.TimeCreated;

                // --- BINARY SEARCH ---
                var matched4608 = FindNearestEvent(bootTime, all4608s);
                string sec4608Str = "---";

                if (matched4608 != null)
                {
                    double diff = (matched4608.TimeCreated - bootTime).TotalSeconds;
                    if (Math.Abs(diff) <= MaxSecondsDiff)
                    {
                        sec4608Str = $"{matched4608.TimeCreated:HH:mm:ss} ({diff:+0;-0}s)";
                    }
                }

                DateTime nextBootTime = (i < boots.Count - 1) 
                    ? boots[i + 1].TimeCreated 
                    : DateTime.Now;

                var shutdown = allShutdowns
                    .Where(e => e.TimeCreated > bootTime && e.TimeCreated < nextBootTime)
                    .LastOrDefault();

                DateTime endTime;
                string status;
                string shutdownStr;

                if (i < boots.Count - 1)
                {
                    if (shutdown != null)
                    {
                        endTime = shutdown.TimeCreated;
                        status = "Clean";
                        shutdownStr = endTime.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                    else
                    {
                        endTime = nextBootTime;
                        status = "Dirty/Crash";
                        shutdownStr = endTime.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                }
                else
                {
                    if (shutdown != null)
                    {
                        endTime = shutdown.TimeCreated;
                        status = "Clean (Ended)";
                        shutdownStr = endTime.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                    else
                    {
                        endTime = DateTime.Now;
                        status = "Running";
                        shutdownStr = "---";
                    }
                }

                TimeSpan uptime = endTime - bootTime;
                string uptimeStr = $"{uptime.Days:00}d {uptime.Hours:00}h {uptime.Minutes:00}m";

                Console.WriteLine("{0,-22} {1,-22} {2,-15} {3,-18} {4,-10} {5,-15}",
                    bootTime.ToString("yyyy-MM-dd HH:mm:ss"),
                    shutdownStr,
                    status,
                    uptimeStr,
                    bootTime.ToString("HH:mm:ss"),
                    sec4608Str
                );
            }
            
            Console.WriteLine(new string('-', 110));
        }

        static List<SimpleEvent> QueryLog(string logName, int[] ids)
        {
            var results = new List<SimpleEvent>();
            
            string idQuery = string.Join(" or ", ids.Select(id => $"EventID={id}"));
            string timeQuery = $"TimeCreated[@SystemTime>='{StartTime.ToUniversalTime():o}']";
            
            string queryString = $@"
                <QueryList>
                  <Query Id='0' Path='{logName}'>
                    <Select Path='{logName}'>*[System[({idQuery}) and {timeQuery}]]</Select>
                  </Query>
                </QueryList>";

            // PathType requires System.Diagnostics.Eventing.Reader
            var query = new EventLogQuery(logName, PathType.LogName, queryString);
            
            try 
            {
                using (var reader = new EventLogReader(query))
                {
                    EventRecord? eventInstance; // Fix CS8600: Allow null return
                    while ((eventInstance = reader.ReadEvent()) != null)
                    {
                        results.Add(new SimpleEvent
                        {
                            TimeCreated = eventInstance.TimeCreated ?? DateTime.MinValue,
                            Id = eventInstance.Id,
                            Provider = eventInstance.ProviderName
                        });
                    }
                }
            }
            catch
            {
                // Fix CA2200: Use 'throw' to preserve stack trace, or handle silently
                throw; 
            }

            return results;
        }

        // Fix CS8603: Return type allows null (SimpleEvent?)
        static SimpleEvent? FindNearestEvent(DateTime target, List<SimpleEvent> sortedEvents)
        {
            if (sortedEvents == null || sortedEvents.Count == 0) return null;

            int left = 0;
            int right = sortedEvents.Count - 1;

            while (left <= right)
            {
                int mid = left + (right - left) / 2;
                if (sortedEvents[mid].TimeCreated == target) return sortedEvents[mid];
                
                if (sortedEvents[mid].TimeCreated < target)
                    left = mid + 1;
                else
                    right = mid - 1;
            }

            // Fix CS8600: Explicitly nullable checks
            SimpleEvent? c1 = (left < sortedEvents.Count) ? sortedEvents[left] : null;
            SimpleEvent? c2 = (left - 1 >= 0) ? sortedEvents[left - 1] : null;

            double diff1 = (c1 != null) ? Math.Abs((c1.TimeCreated - target).TotalSeconds) : double.MaxValue;
            double diff2 = (c2 != null) ? Math.Abs((c2.TimeCreated - target).TotalSeconds) : double.MaxValue;

            return (diff1 < diff2) ? c1 : c2;
        }
    }
}