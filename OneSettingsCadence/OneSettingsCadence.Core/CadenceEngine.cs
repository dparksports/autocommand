using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace AutoCommand.OneSettingsCadence
{
    /// <summary>
    /// Engine behind the OneSettingsCadence CLI: reads and re-registers the
    /// Windows inbox task \Microsoft\Windows\Flighting\OneSettings\RefreshCache
    /// (OneSettings remote-config fetch, stock ~PT3H20M repetition + PT1H
    /// random delay + WNF state-change triggers) over the Task Scheduler COM
    /// interface — never schtasks.exe (TECHNICAL_NOTES design rule 1).
    ///
    /// The transform touches the Triggers block only: the TimeTrigger's
    /// repetition interval becomes the user's choice, its RandomDelay becomes
    /// PT0S, and the WnfStateChangeTrigger elements are removed unless the
    /// caller opts out. Everything else — principal (S-1-5-18), actions,
    /// settings, SecurityDescriptor — is preserved byte-for-byte from the
    /// live XML, and a timestamped copy of that XML is written under
    /// %ProgramData%\AutoCommand\onesettings-cadence\backups before any write.
    /// </summary>
    public class CadenceEngine
    {
        public const string TaskPath = @"\Microsoft\Windows\Flighting\OneSettings\RefreshCache";
        public const string TaskFolder = @"\Microsoft\Windows\Flighting\OneSettings";
        public const string TaskName = "RefreshCache";
        public const string WatchdogPath = @"\AutoCommand\OneSettingsCadenceWatchdog";

        private static readonly Encoding NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        public static string StateDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AutoCommand", "onesettings-cadence");
        public static string BackupDir => Path.Combine(StateDir, "backups");
        public static string StateFile => Path.Combine(StateDir, "state.json");
        public static string AuditFile => Path.Combine(StateDir, "audit.jsonl");

        // -----------------------------------------------------------------------
        // COM plumbing (same dynamic Schedule.Service pattern as the app's
        // Services/TaskSchedulerService.cs)
        // -----------------------------------------------------------------------

        private static dynamic Connect()
        {
            Type tsType = Type.GetTypeFromProgID("Schedule.Service");
            if (tsType == null)
                throw new InvalidOperationException("Task Scheduler COM component not available.");
            dynamic ts = Activator.CreateInstance(tsType);
            ts.Connect();
            return ts;
        }

        // -----------------------------------------------------------------------
        // Live-state reading (no elevation required — the task's security
        // descriptor grants Authenticated Users read)
        // -----------------------------------------------------------------------

        /// <summary>Everything the status report shows, parsed from the live task.</summary>
        public sealed class LiveState
        {
            public string Xml;
            public TimeSpan? Interval;          // TimeTrigger repetition interval
            public TimeSpan? RandomDelay;       // PT0S when the element is absent
            public TimeSpan? Duration;          // null = indefinite repetition
            public List<string> WnfStateNames = new();
            public DateTime? LastRun;
            public DateTime? NextRun;
            public int? LastResult;
            public string TaskState;            // Ready / Running / Disabled / ...
            public string PrincipalUserId;
        }

        public LiveState ReadLive()
        {
            dynamic ts = Connect();
            dynamic folder = ts.GetFolder(TaskFolder);
            dynamic task;
            try { task = folder.GetTask(TaskName); }
            catch (COMException ex) when ((uint)ex.ErrorCode == 0x80070002) // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
            {
                throw new InvalidOperationException(
                    $"task {TaskPath} does not exist on this machine — nothing to do (an OS upgrade may have renamed or removed it)");
            }

            var live = ParseLiveXml((string)task.Xml);

            int stateInt = (int)task.State;
            live.TaskState = stateInt switch
            {
                1 => "Disabled", 2 => "Queued", 3 => "Ready", 4 => "Running", _ => "Unknown"
            };
            try { live.LastRun = ToDateTime(task.LastRunTime); } catch { /* unset on some installs */ }
            try { live.NextRun = ToDateTime(task.NextRunTime); } catch { /* e.g. no upcoming run */ }
            try { live.LastResult = (int)task.LastTaskResult; } catch { }
            return live;
        }

        private static DateTime? ToDateTime(dynamic value)
        {
            // Task Scheduler returns 1899-12-30 00:00 for "never"
            if (value is DateTime dt && dt.Year > 1900) return dt;
            return null;
        }

        /// <summary>Parses the trigger facts out of a task XML string.</summary>
        public static LiveState ParseLiveXml(string xml)
        {
            XDocument doc;
            try { doc = XDocument.Parse(xml); }
            catch (XmlException ex) { throw new InvalidOperationException($"task XML is not parseable: {ex.Message}"); }

            var live = new LiveState { Xml = xml };
            XElement triggers = doc.Root?.Element(Ns + "Triggers");
            XElement root = doc.Root;
            if (triggers == null) throw new InvalidOperationException("task XML has no Triggers block — unexpected definition, refusing to touch it");

            XElement time = triggers.Element(Ns + "TimeTrigger");
            if (time != null)
            {
                XElement rep = time.Element(Ns + "Repetition");
                XElement interval = rep?.Element(Ns + "Interval");
                if (interval != null)
                    live.Interval = XmlConvert.ToTimeSpan(interval.Value);
                XElement duration = rep?.Element(Ns + "Duration");
                if (duration != null && !string.IsNullOrWhiteSpace(duration.Value))
                    live.Duration = XmlConvert.ToTimeSpan(duration.Value);
                XElement randomDelay = time.Element(Ns + "RandomDelay");
                if (randomDelay != null && !string.IsNullOrWhiteSpace(randomDelay.Value))
                    live.RandomDelay = XmlConvert.ToTimeSpan(randomDelay.Value);
            }

            // WNF state-change triggers: <WnfStateChangeTrigger> since Win10 1809;
            // defensively also match EventTriggers whose subscription names WNF
            foreach (XElement t in triggers.Elements())
            {
                if (t.Name.LocalName == "WnfStateChangeTrigger")
                    live.WnfStateNames.Add(t.Element(Ns + "StateName")?.Value ?? "(unnamed)");
                else if (t.Name.LocalName == "EventTrigger" &&
                         (t.Element(Ns + "Subscription")?.Value ?? "").IndexOf("WNF", StringComparison.OrdinalIgnoreCase) >= 0)
                    live.WnfStateNames.Add("(event-form WNF trigger)");
            }

            live.PrincipalUserId = root?.Element(Ns + "Principals")?.Element(Ns + "Principal")
                                         ?.Element(Ns + "UserId")?.Value;
            return live;
        }

        // -----------------------------------------------------------------------
        // The transform (pure — the same code path behind preview and set)
        // -----------------------------------------------------------------------

        public sealed class TransformResult
        {
            public string ModifiedXml;
            public TimeSpan? OldInterval, NewInterval;
            public TimeSpan? OldRandomDelay;          // null = was absent
            public List<string> RemovedWnfNames = new();
            public bool DurationRemoved;
            public List<string> Notes = new();
        }

        /// <summary>
        /// Builds the modified task XML from the live one. Repetition interval
        /// set, RandomDelay forced to PT0S, WNF triggers removed unless
        /// keepWnf. If a repetition Duration exists and the new interval is >=
        /// it, the Duration is dropped (indefinite repetition) — an interval
        /// longer than the window would make the pattern re-arm exactly on the
        /// boundary and the cadence would not hold.
        /// </summary>
        public static TransformResult Transform(string originalXml, TimeSpan interval, bool keepWnf)
        {
            XDocument doc = XDocument.Parse(originalXml);
            XElement triggers = doc.Root?.Element(Ns + "Triggers")
                ?? throw new InvalidOperationException("task XML has no Triggers block — unexpected definition, refusing to touch it");

            var result = new TransformResult
            {
                NewInterval = interval,
            };

            XElement time = triggers.Element(Ns + "TimeTrigger")
                ?? throw new InvalidOperationException("task XML has no TimeTrigger — unexpected definition, refusing to touch it");

            XElement rep = time.Element(Ns + "Repetition");
            if (rep == null)
            {
                rep = new XElement(Ns + "Repetition");
                time.AddFirst(rep); // schema order: StartBoundary, Repetition, RandomDelay
            }

            XElement intervalEl = rep.Element(Ns + "Interval");
            if (intervalEl == null) { intervalEl = new XElement(Ns + "Interval"); rep.Add(intervalEl); }
            result.OldInterval = intervalEl.Value.Length == 0 ? null : XmlConvert.ToTimeSpan(intervalEl.Value);
            intervalEl.Value = XmlConvert.ToString(interval);

            XElement durationEl = rep.Element(Ns + "Duration");
            if (durationEl != null && !string.IsNullOrWhiteSpace(durationEl.Value))
            {
                TimeSpan duration = XmlConvert.ToTimeSpan(durationEl.Value);
                if (interval >= duration)
                {
                    durationEl.Remove();
                    result.DurationRemoved = true;
                    result.Notes.Add($"Repetition duration {durationEl.Value} removed: the new interval {XmlConvert.ToString(interval)} is >= the window, which would re-arm on the boundary instead of holding the cadence (absent Duration = repeat indefinitely)");
                }
            }

            XElement delayEl = time.Element(Ns + "RandomDelay");
            if (delayEl == null)
            {
                delayEl = new XElement(Ns + "RandomDelay") { Value = "PT0S" };
                rep.AddAfterSelf(delayEl);
            }
            else
            {
                result.OldRandomDelay = delayEl.Value.Length == 0 ? null : XmlConvert.ToTimeSpan(delayEl.Value);
                delayEl.Value = "PT0S";
            }

            if (!keepWnf)
            {
                foreach (XElement t in triggers.Elements().ToList())
                {
                    bool isWnf = t.Name.LocalName == "WnfStateChangeTrigger"
                              || (t.Name.LocalName == "EventTrigger" &&
                                  (t.Element(Ns + "Subscription")?.Value ?? "").IndexOf("WNF", StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!isWnf) continue;
                    result.RemovedWnfNames.Add(t.Element(Ns + "StateName")?.Value ?? t.Name.LocalName);
                    t.Remove();
                }
            }

            result.ModifiedXml = Serialize(doc);
            return result;
        }

        private static string Serialize(XDocument doc)
        {
            string body = doc.Root?.ToString(SaveOptions.None) ?? "";
            return doc.Declaration == null ? body : doc.Declaration + "\n" + body;
        }

        // -----------------------------------------------------------------------
        // Registration (writes — elevated callers only)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Re-registers the task from an XML string. The principal is taken
        /// from the XML (untouched by the transform); the RegisterTask
        /// credentials are derived from it so the registration matches the
        /// original exactly: this inbox task runs as a service account, which
        /// is the only shape this tool will re-register.
        /// </summary>
        public void RegisterXml(string xml)
        {
            var principal = XDocument.Parse(xml).Root?.Element(Ns + "Principals")?.Element(Ns + "Principal")
                                ?.Element(Ns + "UserId")?.Value
                            ?? throw new InvalidOperationException("task XML carries no Principal UserId — refusing to register");

            // TASK_LOGON_SERVICE_ACCOUNT (2): userId must be exactly one of
            // the three service-account names; map the SIDs the inbox task uses
            (string account, int logonType) = principal.Trim().ToUpperInvariant() switch
            {
                "S-1-5-18" or "SYSTEM" or "NT AUTHORITY\\SYSTEM" => ("SYSTEM", 2),
                "S-1-5-19" or "LOCAL SERVICE" or "NT AUTHORITY\\LOCAL SERVICE" => ("LOCAL SERVICE", 2),
                "S-1-5-20" or "NETWORK SERVICE" or "NT AUTHORITY\\NETWORK SERVICE" => ("NETWORK SERVICE", 2),
                _ => throw new InvalidOperationException(
                    $"task principal is '{principal}', not a service account — this tool only re-registers the stock SYSTEM task; restore manually if this is unexpected"),
            };

            dynamic ts = Connect();
            dynamic folder = ts.GetFolder(TaskFolder);
            folder.RegisterTask(TaskName, xml, 6 /* TASK_CREATE_OR_UPDATE */, account, null, logonType, null);
        }

        /// <summary>
        /// True when the live task matches the intended state: repetition
        /// interval equal, effective random delay zero, WNF trigger count as
        /// expected. TimeSpans are compared by value so PT24H == P1D-style
        /// normalization by the scheduler does not cause false drift.
        /// </summary>
        public static List<string> FindMismatches(LiveState live, TimeSpan? desiredInterval,
                                                  bool keepWnf, int expectedWnfWhenKept)
        {
            var problems = new List<string>();
            if (desiredInterval.HasValue)
            {
                if (live.Interval == null) problems.Add("live task has no repetition interval");
                else if (live.Interval.Value != desiredInterval.Value)
                    problems.Add($"live interval {IntervalParser.ToTaskForm(live.Interval.Value)} != desired {IntervalParser.ToTaskForm(desiredInterval.Value)}");
            }
            if (live.RandomDelay is { } delay && delay != TimeSpan.Zero)
                problems.Add($"random delay is {IntervalParser.ToTaskForm(delay)}, expected PT0S");
            if (!keepWnf && live.WnfStateNames.Count > 0)
                problems.Add($"{live.WnfStateNames.Count} WNF trigger(s) still present: {string.Join(", ", live.WnfStateNames)}");
            if (keepWnf && live.WnfStateNames.Count != expectedWnfWhenKept)
                problems.Add($"WNF trigger count changed: {live.WnfStateNames.Count} live vs {expectedWnfWhenKept} expected");
            return problems;
        }

        // -----------------------------------------------------------------------
        // Backups
        // -----------------------------------------------------------------------

        /// <summary>
        /// Writes the current XML to a timestamped file under
        /// %ProgramData%\AutoCommand\onesettings-cadence\backups (UTF-16 with
        /// BOM, matching the XML declaration schtasks itself emits), then
        /// verifies the round-trip parses and matches the source document.
        /// </summary>
        public string WriteBackup(string xml)
        {
            Directory.CreateDirectory(BackupDir);
            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string file = Path.Combine(BackupDir, $"RefreshCache-{stamp}.xml");
            for (int i = 2; File.Exists(file); i++)
                file = Path.Combine(BackupDir, $"RefreshCache-{stamp}-{i}.xml");

            File.WriteAllText(file, xml, Encoding.Unicode);

            string readBack = File.ReadAllText(file); // BOM detection restores the string
            if (XDocument.Parse(readBack).ToString() != XDocument.Parse(xml).ToString())
                throw new InvalidOperationException($"backup verification failed for {Path.GetFileName(file)} — aborting before any change");
            return file;
        }

        public sealed class BackupInfo
        {
            public string File;
            public DateTime Written;
            public long Size;
        }

        public static List<BackupInfo> ListBackups()
        {
            if (!Directory.Exists(BackupDir)) return new List<BackupInfo>();
            return Directory.GetFiles(BackupDir, "RefreshCache-*.xml")
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.Name, StringComparer.OrdinalIgnoreCase)
                .Select(f => new BackupInfo { File = f.FullName, Written = f.LastWriteTime, Size = f.Length })
                .ToList();
        }

        /// <summary>Resolves a --backup argument (bare name or full path) to an existing file.</summary>
        public static string ResolveBackup(string name)
        {
            string candidate = Path.IsPathRooted(name) ? name : Path.Combine(BackupDir, name);
            if (File.Exists(candidate)) return candidate;
            throw new InvalidOperationException(
                $"backup '{name}' not found ({BackupDir} holds {ListBackups().Count} backups)");
        }

        // -----------------------------------------------------------------------
        // Saved desired cadence + audit trail (plain inspectable files, per
        // the app's no-hidden-state rule)
        // -----------------------------------------------------------------------

        public sealed class DesiredState
        {
            public string DesiredInterval { get; set; }      // PT24H form
            public DateTime SetAtUtc { get; set; }
            public bool KeepWnf { get; set; }
            public bool Watchdog { get; set; }
            public int OriginalWnfCount { get; set; }
            public string SetBy { get; set; }
            public string ExePath { get; set; }
            public DateTime? LastEnforcedUtc { get; set; }
        }

        public static DesiredState LoadState() =>
            File.Exists(StateFile)
                ? JsonSerializer.Deserialize<DesiredState>(File.ReadAllText(StateFile))
                : null;

        public static void SaveState(DesiredState s)
        {
            Directory.CreateDirectory(StateDir);
            File.WriteAllText(StateFile, JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }), NoBom);
        }

        public static void ClearState()
        {
            if (File.Exists(StateFile)) File.Delete(StateFile);
        }

        public sealed class AuditRecord
        {
            public DateTime TimeUtc { get; set; }
            public string Action { get; set; }        // set / restore / enforce / rollback / watchdog-remove
            public string Task { get; set; }
            public TriggerFacts Old { get; set; }
            public TriggerFacts New { get; set; }
            public string Backup { get; set; }
            public bool Watchdog { get; set; }
            public string Result { get; set; }
            public string User { get; set; }
        }

        public sealed class TriggerFacts
        {
            public string Interval { get; set; }
            public string RandomDelay { get; set; }
            public int WnfCount { get; set; }
        }

        /// <summary>Appends one line to audit.jsonl — every change, what/when/old->new/backup.</summary>
        public static void Audit(string action, LiveState old, LiveState @new, string backup,
                                 bool watchdog, string result)
        {
            try
            {
                Directory.CreateDirectory(StateDir);
                var record = new AuditRecord
                {
                    TimeUtc = DateTime.UtcNow,
                    Action = action,
                    Task = TaskPath,
                    Old = Facts(old),
                    New = Facts(@new),
                    Backup = backup,
                    Watchdog = watchdog,
                    Result = result,
                    User = System.Security.Principal.WindowsIdentity.GetCurrent().Name,
                };
                File.AppendAllText(AuditFile, JsonSerializer.Serialize(record) + Environment.NewLine, NoBom);
            }
            catch (IOException)
            {
                // disk full/locked — the operation itself already happened; the
                // audit line is lost, not the change. Say so on stderr.
                Console.Error.WriteLine($"WARNING: could not append to audit trail {AuditFile}");
            }
        }

        private static TriggerFacts Facts(LiveState s) => s == null ? null : new TriggerFacts
        {
            Interval = s.Interval == null ? null : IntervalParser.ToTaskForm(s.Interval.Value),
            RandomDelay = s.RandomDelay == null ? null : IntervalParser.ToTaskForm(s.RandomDelay.Value),
            WnfCount = s.WnfStateNames.Count,
        };

        // -----------------------------------------------------------------------
        // Watchdog — SYSTEM task that re-applies the saved cadence daily and
        // at logon (Windows servicing rewrites inbox task definitions; this
        // machine's StartBoundary was rewritten by the OS the very day this
        // tool was written)
        // -----------------------------------------------------------------------

        public bool WatchdogInstalled()
        {
            try
            {
                dynamic ts = Connect();
                dynamic folder = ts.GetFolder(@"\AutoCommand");
                folder.GetTask("OneSettingsCadenceWatchdog");
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// Installs/updates the watchdog. The action is parameterized because
        /// the two faces need different launchers: the CLI points it at
        /// itself ("enforce --quiet"), the app at AutoCommand.exe
        /// ("onesettings-enforce" — handled headlessly in App.OnStartup so the
        /// GUI never appears at 03:30).
        /// </summary>
        public void InstallWatchdog(string exePath, string arguments)
        {
            EnsureElevatedLocationForSystemTask(exePath);
            string xml =
                $"""
                <?xml version="1.0" encoding="UTF-16"?>
                <Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                  <RegistrationInfo>
                    <Description>AutoCommand - re-applies the saved OneSettings RefreshCache cadence daily and at logon (Windows servicing can revert inbox task definitions). Managed by OneSettingsCadence.exe; removed automatically by 'OneSettingsCadence restore'.</Description>
                    <URI>\AutoCommand\OneSettingsCadenceWatchdog</URI>
                  </RegistrationInfo>
                  <Principals>
                    <Principal id="LocalSystem">
                      <UserId>S-1-5-18</UserId>
                    </Principal>
                  </Principals>
                  <Settings>
                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                    <StartWhenAvailable>true</StartWhenAvailable>
                  </Settings>
                  <Triggers>
                    <CalendarTrigger>
                      <StartBoundary>{DateTime.Now:yyyy-MM-dd}T03:30:00</StartBoundary>
                      <ScheduleByDay>
                        <DaysInterval>1</DaysInterval>
                      </ScheduleByDay>
                    </CalendarTrigger>
                    <LogonTrigger>
                      <Enabled>true</Enabled>
                    </LogonTrigger>
                  </Triggers>
                  <Actions Context="LocalSystem">
                    <Exec>
                      <Command>{exePath}</Command>
                      <Arguments>{arguments}</Arguments>
                    </Exec>
                  </Actions>
                </Task>
                """;

            dynamic ts = Connect();
            dynamic root = ts.GetFolder("\\");
            dynamic folder;
            try { folder = root.GetFolder("AutoCommand"); }
            catch (COMException ex) when ((uint)ex.ErrorCode == 0x80070002)
            {
                folder = root.CreateFolder("AutoCommand", null); // ERROR_FILE_NOT_FOUND = folder absent
            }
            folder.RegisterTask("OneSettingsCadenceWatchdog", xml, 6 /* TASK_CREATE_OR_UPDATE */,
                                "SYSTEM", null, 2 /* TASK_LOGON_SERVICE_ACCOUNT */, null);
        }

        /// <summary>
        /// The watchdog runs as SYSTEM (S-1-5-18) daily and at logon — the
        /// strongest persistence this repo creates, so the binary it points
        /// at must not live somewhere a standard-user process can replace
        /// (Downloads, Desktop, any user profile path). An exe under a
        /// user-writable root means "replace the exe, own SYSTEM": refuse
        /// and tell the user to move the install (Program Files, ProgramData
        /// with admin ACLs, or %SystemRoot%) and retry.
        /// </summary>
        private static void EnsureElevatedLocationForSystemTask(string exePath)
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                throw new InvalidOperationException(
                    $"Watchdog target '{exePath}' does not exist; nothing registered.");

            string full = Path.GetFullPath(exePath);

            string[] protectedRoots =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            };

            bool inProtectedRoot = protectedRoots
                .Where(r => !string.IsNullOrEmpty(r))
                .Any(r => full.StartsWith(
                    r.TrimEnd('\\') + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase));

            if (!inProtectedRoot)
                throw new InvalidOperationException(
                    $"Refusing to register a SYSTEM task for '{full}': the location is user-writable, " +
                    "so replacing that file would mean SYSTEM execution of attacker code. " +
                    "Move the install under Program Files (or another admin-writable location) and retry.");
        }

        public void RemoveWatchdog()
        {
            try
            {
                dynamic ts = Connect();
                dynamic folder = ts.GetFolder(@"\AutoCommand");
                folder.DeleteTask("OneSettingsCadenceWatchdog", 0);
            }
            catch (COMException ex) when ((uint)ex.ErrorCode == 0x80070002)
            {
                // already gone — the outcome restore wants
            }
        }

        // -----------------------------------------------------------------------
        // Orchestration — the single backup → transform → register → verify →
        // rollback flow shared by the CLI's set/restore/enforce and the app's
        // OneSettings tab. One implementation so both faces cannot drift.
        // -----------------------------------------------------------------------

        /// <summary>Outcome of Apply — what happened, for either face to print.</summary>
        public sealed class ApplyResult
        {
            public bool Ok;                    // applied and verified live
            public string BackupFile;          // timestamped XML written first
            public LiveState Before, After;
            public TimeSpan Interval;
            public bool KeepWnf;
            public List<string> Notes = new(); // transform notes (e.g. duration dropped)
            public List<string> Problems = new(); // verification failures (when !Ok)
            public bool RolledBack;            // a failure was undone from the backup
            public bool RollbackFailed;        // rollback did not land — manual attention
            public string FatalError;          // exception before/at registration
            public bool WatchdogInstalled;     // actual state after the request
        }

        /// <summary>
        /// Applies a cadence: snapshot → transform → register → verify, rolling
        /// back from the snapshot on any failure. Watchdog handling: true =
        /// install/update, false = remove, null = leave as installed.
        /// Caller must be elevated (CLI self-elevates; the app manifest already
        /// demands administrator).
        /// </summary>
        public ApplyResult Apply(TimeSpan interval, bool keepWnf, bool? watchdog,
                                 string watchdogExe, string watchdogArgs)
        {
            var r = new ApplyResult { Interval = interval, KeepWnf = keepWnf };
            LiveState before = null;
            string backup = null;
            try
            {
                before = ReadLive();
                r.Before = before;
                backup = WriteBackup(before.Xml);
                r.BackupFile = backup;

                var t = Transform(before.Xml, interval, keepWnf);
                r.Notes.AddRange(t.Notes);
                RegisterXml(t.ModifiedXml);

                r.After = ReadLive();
                r.Problems = FindMismatches(r.After, interval, keepWnf, before.WnfStateNames.Count);
                if (r.Problems.Count > 0)
                {
                    (bool ok, LiveState rolled, Exception ex) = RollbackFromBackup(before, backup, watchdog == true,
                        "rolled back after failed verification: " + string.Join("; ", r.Problems));
                    r.RolledBack = ok;
                    r.RollbackFailed = !ok;
                    r.After = rolled ?? r.After;
                    return r;
                }
            }
            catch (Exception ex)
            {
                r.FatalError = ex.Message;
                // any failure after the backup rolls back from it — re-registering
                // the backup is idempotent even if the modified XML never landed
                if (backup != null && before != null)
                {
                    (bool ok, LiveState rolled, _) = RollbackFromBackup(before, backup, watchdog == true,
                        "rolled back after failure: " + ex.Message);
                    r.RolledBack = ok;
                    r.RollbackFailed = !ok;
                    r.After = rolled ?? r.After;
                }
                return r;
            }

            // watchdog lifecycle: install/update/remove as requested; failures
            // are surfaced, not fatal — the cadence itself is already verified
            try
            {
                if (watchdog == true)
                {
                    InstallWatchdog(watchdogExe, watchdogArgs);
                    r.WatchdogInstalled = true;
                }
                else if (watchdog == false && WatchdogInstalled())
                {
                    RemoveWatchdog();
                    r.WatchdogInstalled = false;
                }
                else
                {
                    r.WatchdogInstalled = WatchdogInstalled();
                }
            }
            catch (Exception ex)
            {
                r.Notes.Add("watchdog request failed: " + ex.Message);
                r.WatchdogInstalled = WatchdogInstalled();
            }

            SaveState(new DesiredState
            {
                DesiredInterval = IntervalParser.ToTaskForm(interval),
                SetAtUtc = DateTime.UtcNow,
                KeepWnf = keepWnf,
                Watchdog = r.WatchdogInstalled,
                OriginalWnfCount = before.WnfStateNames.Count,
                SetBy = System.Security.Principal.WindowsIdentity.GetCurrent().Name,
                ExePath = watchdogExe,
            });
            Audit("set", before, r.After, Path.GetFileName(backup), r.WatchdogInstalled, "applied+verified");
            r.Ok = true;
            return r;
        }

        /// <summary>Outcome of RestoreFrom.</summary>
        public sealed class RestoreResult
        {
            public bool Ok;
            public string BackupFile;          // the backup restored from
            public string SafetyBackupFile;    // snapshot of what was live, taken first
            public LiveState Before, After;
            public List<string> Problems = new();
            public bool HadWatchdog;
            public bool RolledBack;
            public bool RollbackFailed;
            public string FatalError;
        }

        /// <summary>
        /// Re-registers a backup (newest when file is null), verifies, and on
        /// success clears the saved cadence and removes the watchdog (it would
        /// re-apply the old cadence and fight the restore).
        /// Caller must be elevated.
        /// </summary>
        public RestoreResult RestoreFrom(string file)
        {
            var r = new RestoreResult();
            var backups = ListBackups();
            if (backups.Count == 0)
                throw new InvalidOperationException($"no backups under {BackupDir} — nothing to restore");
            r.BackupFile = file != null ? ResolveBackup(file) : backups[0].File;

            LiveState before = null;
            string safety = null;
            try
            {
                before = ReadLive();
                r.Before = before;
                string restoreXml = File.ReadAllText(r.BackupFile);
                var expected = ParseLiveXml(restoreXml);

                // same discipline as Apply: snapshot what is live now so a
                // failed restore can put it back
                safety = WriteBackup(before.Xml);
                r.SafetyBackupFile = safety;

                RegisterXml(restoreXml);
                r.After = ReadLive();

                r.Problems = FindMismatches(r.After, expected.Interval,
                                            expected.WnfStateNames.Count > 0, expected.WnfStateNames.Count);
                if ((r.After.RandomDelay ?? TimeSpan.Zero) != (expected.RandomDelay ?? TimeSpan.Zero))
                    r.Problems.Add($"random delay {(r.After.RandomDelay is { } rd ? IntervalParser.ToTaskForm(rd) : "none")} != backup's {(expected.RandomDelay is { } re ? IntervalParser.ToTaskForm(re) : "none")}");
                if (r.Problems.Count > 0)
                {
                    (bool ok, LiveState rolled, _) = RollbackFromBackup(before, safety, false,
                        "rolled back after failed restore: " + string.Join("; ", r.Problems));
                    r.RolledBack = ok;
                    r.RollbackFailed = !ok;
                    r.After = rolled ?? r.After;
                    return r;
                }
            }
            catch (Exception ex)
            {
                r.FatalError = ex.Message;
                if (safety != null && before != null)
                {
                    (bool ok, LiveState rolled, _) = RollbackFromBackup(before, safety, false,
                        "rolled back after restore failure: " + ex.Message);
                    r.RolledBack = ok;
                    r.RollbackFailed = !ok;
                    r.After = rolled ?? r.After;
                }
                return r;
            }

            r.HadWatchdog = WatchdogInstalled();
            RemoveWatchdog();
            ClearState();
            Audit("restore", before, r.After, Path.GetFileName(r.BackupFile), false, "restored+verified");
            r.Ok = true;
            return r;
        }

        /// <summary>
        /// The watchdog's verb: re-applies the saved cadence only when the live
        /// task drifted. No backups pile up — the stock snapshot from Apply
        /// remains the escape hatch, and Enforce never changes the desired
        /// state, only restores it.
        /// Caller must be elevated.
        /// </summary>
        public sealed class EnforceResult
        {
            public bool HadState;              // false = nothing to enforce (normal after restore)
            public bool DriftFound;
            public bool Applied;               // drift found AND re-apply verified
            public List<string> Problems = new();
            public string FatalError;
            public LiveState Before, After;
        }

        public EnforceResult Enforce()
        {
            var r = new EnforceResult();
            var state = LoadState();
            if (state == null) return r;
            r.HadState = true;

            try
            {
                r.Before = ReadLive();
                var desired = XmlConvert.ToTimeSpan(state.DesiredInterval);
                r.Problems = FindMismatches(r.Before, desired, state.KeepWnf, state.OriginalWnfCount);
                if (r.Problems.Count == 0)
                {
                    state.LastEnforcedUtc = DateTime.UtcNow;
                    SaveState(state);
                    return r;
                }

                r.DriftFound = true;
                var t = Transform(r.Before.Xml, desired, state.KeepWnf);
                RegisterXml(t.ModifiedXml);
                r.After = ReadLive();
                var still = FindMismatches(r.After, desired, state.KeepWnf, state.OriginalWnfCount);
                if (still.Count > 0)
                {
                    // no rollback here: the watchdog runs unattended daily —
                    // leave the task as-is (the stock backup from Apply remains
                    // the escape hatch) and record the failure for status
                    Audit("enforce", r.Before, r.After, null, WatchdogInstalled(), "FAILED: " + string.Join("; ", still));
                    r.Problems = still;
                    return r;
                }
                state.LastEnforcedUtc = DateTime.UtcNow;
                SaveState(state);
                Audit("enforce", r.Before, r.After, null, WatchdogInstalled(), "re-applied+verified");
                r.Applied = true;
                return r;
            }
            catch (Exception ex)
            {
                r.FatalError = ex.Message;
                try { Audit("enforce", r.Before, r.After, null, WatchdogInstalled(), "FAILED: " + ex.Message); }
                catch { /* the audit failure must not mask the original error */ }
                return r;
            }
        }

        /// <summary>
        /// Shared rollback: re-register a backup, verify the live trigger facts
        /// match the pre-change state, audit either way. Returns whether the
        /// rollback landed and the rolled-back live state for the report.
        /// </summary>
        private (bool Ok, LiveState Rolled, Exception Error) RollbackFromBackup(
            LiveState before, string backup, bool watchdog, string reason)
        {
            try
            {
                RegisterXml(File.ReadAllText(backup));
                LiveState rolled = ReadLive();
                bool ok = rolled.Interval == before.Interval
                          && (rolled.RandomDelay ?? TimeSpan.Zero) == (before.RandomDelay ?? TimeSpan.Zero)
                          && rolled.WnfStateNames.Count == before.WnfStateNames.Count;
                Audit("rollback", before, rolled, Path.GetFileName(backup), watchdog,
                    ok ? reason : "ROLLBACK FAILED after: " + reason);
                return (ok, rolled, null);
            }
            catch (Exception ex)
            {
                Audit("rollback", before, null, Path.GetFileName(backup), watchdog, "ROLLBACK FAILED: " + ex.Message);
                return (false, null, ex);
            }
        }
    }
}
