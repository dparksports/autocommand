namespace AutoCommand.Models
{
    /// <summary>
    /// One row of the scheduled-tasks list, shared across Forensics,
    /// Shields Up, and Agent tools via Contain.Core.
    /// </summary>
    public class ScheduledTaskItem
    {
        public string TaskName { get; set; }
        public string TaskPath { get; set; }
        public string State { get; set; }
        public string Action { get; set; }
        public string User { get; set; }
    }
}
