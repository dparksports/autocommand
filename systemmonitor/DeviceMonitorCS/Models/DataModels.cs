using System;

namespace DeviceMonitorCS.Models
{
    public class DeviceEvent
    {
        public string Time { get; set; }
        public string EventType { get; set; }
        public string Name { get; set; }
        public string Type { get; set; }
        public string Initiator { get; set; }
    }

    public class SecurityEvent
    {
        public string Time { get; set; }
        public int? Id { get; set; } // Nullable because sometimes we might want to put "-"
        public string Type { get; set; }
        public string Activity { get; set; }
        public string Account { get; set; }
        public string AccountName { get; set; }
        public string AccountDomain { get; set; }
        public string LogonId { get; set; }
        public string SecurityId { get; set; }
        public string Privileges { get; set; }
        public string LogonType { get; set; }
        public string ProcessName { get; set; }
        public string WorkstationName { get; set; }
        public string IpAddress { get; set; }
        public string IpPort { get; set; }
        public string RestrictedAdminMode { get; set; }
        public string RemoteCredentialGuard { get; set; }
        public string VirtualAccount { get; set; }
        public string GroupName { get; set; }
        public string GroupDomain { get; set; }
        public string GroupSecurityId { get; set; }

        // Privilege Flags
        public bool SeAssignPrimaryTokenPrivilege { get; set; }
        public bool SeTcbPrivilege { get; set; }
        public bool SeSecurityPrivilege { get; set; }
        public bool SeTakeOwnershipPrivilege { get; set; }
        public bool SeLoadDriverPrivilege { get; set; }
        public bool SeBackupPrivilege { get; set; }
        public bool SeRestorePrivilege { get; set; }
        public bool SeDebugPrivilege { get; set; }
        public bool SeAuditPrivilege { get; set; }
        public bool SeSystemEnvironmentPrivilege { get; set; }
        public bool SeImpersonatePrivilege { get; set; }
    }

    public class ScheduledTaskItem
    {
        public string TaskName { get; set; }
        public string TaskPath { get; set; }
        public string State { get; set; }
        public string Action { get; set; }
        public string User { get; set; }
    }

    public class NetworkAdapterItem
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Status { get; set; }
        public string MacAddress { get; set; }
        public string InterfaceType { get; set; }
        public string DeviceID { get; set; }
    }

    public class FirmwareTableItem
    {
        public string Name { get; set; }
        public string TableID { get; set; }
        public string Length { get; set; }
        public string Description { get; set; }
    }

    public class BcdEntry
    {
        public string Type { get; set; }
        public string Identifier { get; set; }
        public string Description { get; set; }
        public string Device { get; set; }
        public string Path { get; set; }
        public string AdditionalSettings { get; set; }
    }

    public class TimelineEvent
    {
        public DateTime Timestamp { get; set; }
        public string Category { get; set; }
        public int EventId { get; set; }
        public string Source { get; set; }
        public string Description { get; set; }
    }
}
