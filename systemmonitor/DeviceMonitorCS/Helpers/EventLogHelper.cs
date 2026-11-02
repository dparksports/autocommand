using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Helpers
{
    public static class EventLogHelper
    {
        public static async Task<List<TimelineEvent>> GetTimelineEventsAsync(DateTime? dateFilter = null)
        {
            return await Task.Run(() =>
            {
                var events = new List<TimelineEvent>();

                // Time filter - MUST ESCAPE XML CHARACTERS (<, >)
                string timeQuery = "";
                if (dateFilter.HasValue)
                {
                    var start = dateFilter.Value.Date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
                    var end = dateFilter.Value.Date.AddDays(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
                    // Use &gt;= and &lt; for XML compatibility
                    timeQuery = $" and TimeCreated[@SystemTime &gt;= '{start}' and @SystemTime &lt; '{end}']";
                }

                // 1. Security Log Queries
                string securityQuery = $@"
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>
      *[System[
        (
         (EventID &gt;= 4624 and EventID &lt;= 4634) or 
         EventID=4800 or EventID=4801 or EventID=4778 or EventID=4779 or
         (EventID &gt;= 4720 and EventID &lt;= 4739) or 
         EventID=4719 or EventID=1102 or
         (EventID &gt;= 4946 and EventID &lt;= 4960) or
         (EventID &gt;= 4698 and EventID &lt;= 4702)
        )
        {timeQuery}
      ]]
    </Select>
  </Query>
</QueryList>";

                // 2. System Log Queries
                string systemQuery = $@"
<QueryList>
  <Query Id='0' Path='System'>
    <Select Path='System'>
      *[System[
        (
          EventID=1074 or EventID=6005 or EventID=6006 or EventID=6008 or
          (Provider[@Name='Microsoft-Windows-Kernel-PnP'] and (EventID=20001 or EventID=20002 or EventID=20003))
        )
        {timeQuery}
      ]]
    </Select>
  </Query>
</QueryList>";

                // 3. Application Log Queries
                string appQuery = $@"
<QueryList>
  <Query Id='0' Path='Application'>
    <Select Path='Application'>
      *[System[
        (Provider[@Name='MsiInstaller'] and (EventID=11707 or EventID=11724))
        {timeQuery}
      ]]
    </Select>
  </Query>
</QueryList>";

                // 4. Windows Defender
                string defenderQuery = $@"
<QueryList>
  <Query Id='0' Path='Microsoft-Windows-Windows Defender/Operational'>
    <Select Path='Microsoft-Windows-Windows Defender/Operational'>
      *[System[EventID &gt;= 0 {timeQuery}]]
    </Select>
  </Query>
</QueryList>";

                // Execute Queries
                events.AddRange(QueryLog(securityQuery, "Security"));
                events.AddRange(QueryLog(systemQuery, "System"));
                events.AddRange(QueryLog(appQuery, "Application"));
                
                try {
                    events.AddRange(QueryLog(defenderQuery, "Windows Defender/Operational")); 
                } catch {}

                return events.OrderByDescending(e => e.Timestamp).ToList();
            });
        }

        private static List<TimelineEvent> QueryLog(string queryXml, string logName)
        {
            var results = new List<TimelineEvent>();
            try
            {
                // Must specify the log name (path) in constructor if we want to be safe, 
                // though PathType.LogName with implicit XML path usually works. 
                // Using the passed logName as fallback path.
                var queryObj = new EventLogQuery(logName, PathType.LogName, queryXml);
                queryObj.Session = System.Diagnostics.Eventing.Reader.EventLogSession.GlobalSession;

                using (var reader = new EventLogReader(queryObj))
                {
                    EventRecord eventInstance;
                    while ((eventInstance = reader.ReadEvent()) != null)
                    {
                        using (eventInstance)
                        {
                            try
                            {
                                var evt = new TimelineEvent
                                {
                                    Timestamp = eventInstance.TimeCreated ?? DateTime.MinValue,
                                    EventId = eventInstance.Id,
                                    Source = string.IsNullOrEmpty(eventInstance.ProviderName) ? logName : eventInstance.ProviderName,
                                    Description = FormatDescription(eventInstance),
                                    Category = CategorizeEvent(eventInstance.Id, eventInstance.ProviderName, eventInstance.LogName)
                                };
                                results.Add(evt);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (EventLogException ex)
            {
                // Surface syntax errors or permission errors
                System.Diagnostics.Debug.WriteLine($"Error querying {logName}: {ex.Message}");
                results.Add(new TimelineEvent { 
                    Timestamp = DateTime.Now, 
                    Category = "Error", 
                    Source = logName, 
                    Description = $"Error reading log: {ex.Message}" 
                });
            }
            catch (Exception ex)
            {
                 System.Diagnostics.Debug.WriteLine($"General Error {logName}: {ex.Message}");
            }
            return results;
        }

        private static string FormatDescription(EventRecord e)
        {
            try
            {
                // Sometimes FormatDescription() is slow or throws.
                string desc = e.FormatDescription();
                if (!string.IsNullOrWhiteSpace(desc)) return desc;
            }
            catch {}
            
            // Fallback: concatenate properties
            if (e.Properties != null && e.Properties.Count > 0)
            {
                return string.Join(" ", e.Properties.Select(p => p.Value?.ToString()));
            }
            return "(No description available)";
        }

        private static string CategorizeEvent(int id, string provider, string log)
        {
            if (log == "Security")
            {
                if (id == 4624) return "Login (Success)";
                if (id == 4625) return "Login (Failed)";
                if (id == 4634 || id == 4647) return "Logout";
                if (id == 4800) return "Workstation Locked";
                if (id == 4801) return "Workstation Unlocked";
                if (id == 4778 || id == 4779) return "RDP Session";
                if (id >= 4720 && id <= 4732) return "User Account Change";
                if (id >= 4946 && id <= 4960) return "Firewall Rule Change";
                if (id == 4698 || id == 4699 || id == 4700) return "Scheduled Task";
                if (id == 4719 || id == 4739 || id == 1102) return "Security Policy Change";
            }
            
            if (log == "System")
            {
               if (id == 1074) return "Shutdown/Restart Initiated";
               if (id == 6005) return "Event Log Started (Boot)";
               if (id == 6006) return "Event Log Stopped (Shutdown)";
               if (id == 6008) return "Unexpected Shutdown";
               if (provider.Contains("Kernel-PnP")) return "Driver/Device Install";
            }

            if (log == "Application")
            {
                if (provider == "MsiInstaller")
                {
                    if (id == 11707) return "Software Install (Success)";
                    if (id == 11724) return "Software Uninstall (Success)";
                    return "Software Change";
                }
            }
            
            if (log.Contains("Defender")) return "System Integrity (Defender)";

            return "Other";
        }
    }
}
