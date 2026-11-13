using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using AutoCommand.Models;

namespace AutoCommand.Forensics.Core
{
    /// <summary>
    /// Native Task Scheduler management via COM (taskschd.dll).
    /// Replaces schtasks.exe calls and PowerShell Enable/Disable-ScheduledTask.
    /// Hosted in Contain.Core so both Forensics.Core and ShieldsUp.Core share
    /// a single implementation.
    /// </summary>
    public class TaskSchedulerService
    {
        private static TaskSchedulerService _instance;
        public static TaskSchedulerService Instance => _instance ??= new TaskSchedulerService();

        private dynamic GetService()
        {
            Type tsType = Type.GetTypeFromProgID("Schedule.Service");
            if (tsType == null)
                throw new InvalidOperationException("Task Scheduler COM component not available.");
            dynamic ts = Activator.CreateInstance(tsType);
            ts.Connect();
            return ts;
        }

        /// <summary>
        /// Load all scheduled tasks recursively via COM.
        /// </summary>
        public Task<List<ScheduledTaskItem>> LoadTasksAsync()
        {
            return Task.Run(() =>
            {
                var results = new List<ScheduledTaskItem>();
                try
                {
                    dynamic ts = GetService();
                    dynamic rootFolder = ts.GetFolder("\\");
                    EnumerateFolder(rootFolder, results);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"TaskSchedulerService.LoadTasks Error: {ex.Message}");
                }
                return results;
            });
        }

        private void EnumerateFolder(dynamic folder, List<ScheduledTaskItem> results)
        {
            try
            {
                // Get tasks (1 = include hidden)
                dynamic tasks = folder.GetTasks(1);
                foreach (dynamic task in tasks)
                {
                    try
                    {
                        string fullPath = (string)task.Path;
                        string name = task.Name;
                        string folderPath = "\\";

                        int lastSlash = fullPath.LastIndexOf('\\');
                        if (lastSlash > 0)
                        {
                            folderPath = fullPath.Substring(0, lastSlash);
                            // Trailing slash: \Microsoft\WindowsCE is a DIFFERENT
                            // folder and must not be treated as the Windows folder
                            if (folderPath.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase))
                            {
                                folderPath = folderPath.Substring(@"\Microsoft\Windows\".Length);
                                if (folderPath.StartsWith("\\")) folderPath = folderPath.Substring(1);
                                if (string.IsNullOrEmpty(folderPath)) folderPath = "Windows System";
                            }
                        }
                        else if (lastSlash == 0)
                        {
                            folderPath = "\\";
                        }

                        string actionStr = "";
                        try
                        {
                            dynamic def = task.Definition;
                            dynamic actions = def.Actions;
                            if (actions.Count > 0)
                            {
                                dynamic firstAction = actions.Item(1); // 1-based index
                                actionStr = firstAction.Path ?? "";
                            }
                        }
                        catch { }

                        string user = "";
                        try
                        {
                            user = task.Definition.Principal.UserId ?? "";
                        }
                        catch { }

                        int stateInt = (int)task.State;
                        string state = stateInt switch
                        {
                            0 => "Unknown",
                            1 => "Disabled",
                            2 => "Queued",
                            3 => "Ready",
                            4 => "Running",
                            _ => "Unknown"
                        };

                        results.Add(new ScheduledTaskItem
                        {
                            TaskName = name,
                            TaskPath = folderPath,
                            State = state,
                            Action = actionStr,
                            User = user
                        });
                    }
                    catch { }
                }

                dynamic subFolders = folder.GetFolders(0);
                foreach (dynamic sub in subFolders)
                {
                    EnumerateFolder(sub, results);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"EnumerateFolder Error: {ex.Message}");
            }
        }

        public Task SetTaskEnabledAsync(string taskPath, bool enabled)
        {
            return Task.Run(() =>
            {
                try
                {
                    dynamic ts = GetService();
                    dynamic rootFolder = ts.GetFolder("\\");
                    dynamic task = rootFolder.GetTask(taskPath);
                    task.Enabled = enabled;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"SetTaskEnabled Error: {ex.Message}");
                    throw;
                }
            });
        }

        public Task RunTaskAsync(string taskPath)
        {
            return Task.Run(() =>
            {
                try
                {
                    dynamic ts = GetService();
                    dynamic rootFolder = ts.GetFolder("\\");
                    dynamic task = rootFolder.GetTask(taskPath);
                    task.Run(null);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"RunTask Error: {ex.Message}");
                    throw;
                }
            });
        }

        public Task StopTaskAsync(string taskPath)
        {
            return Task.Run(() =>
            {
                try
                {
                    dynamic ts = GetService();
                    dynamic rootFolder = ts.GetFolder("\\");
                    dynamic task = rootFolder.GetTask(taskPath);
                    task.Stop(0);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"StopTask Error: {ex.Message}");
                    throw;
                }
            });
        }

        public Task DeleteTaskAsync(string taskPath)
        {
            return Task.Run(() =>
            {
                try
                {
                    dynamic ts = GetService();
                    int lastSlash = taskPath.LastIndexOf('\\');
                    string folderPath = lastSlash > 0 ? taskPath.Substring(0, lastSlash) : "\\";
                    string taskName = taskPath.Substring(lastSlash + 1);

                    dynamic folder = ts.GetFolder(folderPath);
                    folder.DeleteTask(taskName, 0);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"DeleteTask Error: {ex.Message}");
                    throw;
                }
            });
        }

        public bool IsTaskEnabled(string taskPath)
        {
            try
            {
                dynamic ts = GetService();
                dynamic rootFolder = ts.GetFolder("\\");
                dynamic task = rootFolder.GetTask(taskPath);
                return (int)task.State != 1; // 1 = Disabled
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Task state as display text ("Disabled", "Ready", "Running", ...),
        /// or null when the task is not registered.
        /// </summary>
        public string GetTaskStateText(string taskPath)
        {
            try
            {
                dynamic ts = GetService();
                dynamic rootFolder = ts.GetFolder("\\");
                dynamic task = rootFolder.GetTask(taskPath);
                return (int)task.State switch
                {
                    1 => "Disabled",
                    2 => "Queued",
                    3 => "Ready",
                    4 => "Running",
                    _ => "Unknown"
                };
            }
            catch
            {
                return null;
            }
        }

        public Task<(string Summary, string Error)> GetTaskSummaryAsync(string taskPath)
        {
            return Task.Run<(string, string)>(() =>
            {
                try
                {
                    dynamic ts = GetService();
                    dynamic rootFolder = ts.GetFolder("\\");
                    dynamic task = rootFolder.GetTask(taskPath);

                    var sb = new StringBuilder();
                    sb.AppendLine($"Task:     {taskPath}");
                    int stateInt = (int)task.State;
                    sb.AppendLine($"State:    " + stateInt switch
                    {
                        1 => "Disabled",
                        2 => "Queued",
                        3 => "Ready",
                        4 => "Running",
                        _ => "Unknown"
                    });
                    try { sb.AppendLine($"Last run: {task.LastRunTime:yyyy-MM-dd HH:mm:ss}"); } catch { }
                    try { sb.AppendLine($"Next run: {task.NextRunTime:yyyy-MM-dd HH:mm:ss}"); } catch { }

                    var xml = XDocument.Parse((string)task.Xml);
                    var ns = xml.Root?.Name.Namespace ?? XNamespace.None;

                    var principal = xml.Root?.Element(ns + "Principals")?.Element(ns + "Principal");
                    if (principal != null)
                    {
                        string uid = principal.Element(ns + "UserId")?.Value ?? principal.Element(ns + "GroupId")?.Value;
                        if (!string.IsNullOrEmpty(uid)) sb.AppendLine($"Runs as:  {uid}");
                    }

                    var registration = xml.Root?.Element(ns + "RegistrationInfo");
                    string author = registration?.Element(ns + "Author")?.Value ?? registration?.Element(ns + "URI")?.Value;
                    if (!string.IsNullOrEmpty(author)) sb.AppendLine($"Author:   {author}");
                    string description = registration?.Element(ns + "Description")?.Value;
                    if (!string.IsNullOrEmpty(description)) sb.AppendLine($"Description: {description}");

                    foreach (var action in xml.Root?.Element(ns + "Actions")?.Elements(ns + "Exec") ?? Enumerable.Empty<XElement>())
                    {
                        string cmd = action.Element(ns + "Command")?.Value;
                        string args = action.Element(ns + "Arguments")?.Value;
                        if (!string.IsNullOrEmpty(cmd))
                            sb.AppendLine($"Action:   {cmd}{(string.IsNullOrEmpty(args) ? "" : " " + args)}");
                    }
                    foreach (var action in xml.Root?.Element(ns + "Actions")?.Elements(ns + "ComHandler") ?? Enumerable.Empty<XElement>())
                    {
                        string clsid = action.Element(ns + "ClassId")?.Value;
                        if (!string.IsNullOrEmpty(clsid)) sb.AppendLine($"COM handler: {clsid}");
                    }

                    foreach (var trigger in xml.Root?.Element(ns + "Triggers")?.Elements() ?? Enumerable.Empty<XElement>())
                    {
                        string startBoundary = trigger.Element(ns + "StartBoundary")?.Value;
                        bool triggerDisabled = trigger.Element(ns + "Enabled")?.Value == "false";
                        sb.AppendLine($"Trigger:  {trigger.Name.LocalName}" +
                                      (string.IsNullOrEmpty(startBoundary) ? "" : $" from {startBoundary}") +
                                      (triggerDisabled ? " (disabled)" : ""));
                    }

                    return (sb.ToString(), null);
                }
                catch (Exception ex)
                {
                    return (null, ex.Message);
                }
            });
        }
    }
}
