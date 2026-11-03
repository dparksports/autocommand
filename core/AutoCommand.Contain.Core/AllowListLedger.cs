using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace AutoCommand.Contain.Core
{
    /// <summary>Outcome of reading an allow-list preference back from disk.</summary>
    public enum AllowListLoadStatus
    {
        /// <summary>No preference file and no ledger history — enforce (secure default).</summary>
        Absent,
        /// <summary>Preference file existed with no ledger history (first run after the
        /// ledger shipped) — adopted as-is and seeded into the ledger.</summary>
        Seeded,
        /// <summary>File content matches the hash the app last committed — trusted.</summary>
        Trusted,
        /// <summary>File changed or vanished outside the app's confirmed flow — value
        /// forced back to the secure default (false = enforce) and the event recorded.</summary>
        Tampered,
        /// <summary>File or ledger unreadable/garbage — secure default applied.</summary>
        Unreadable,
    }

    public sealed class AllowListLoadResult
    {
        public bool Value;
        public AllowListLoadStatus Status;
        public string Detail;
    }

    /// <summary>
    /// Tamper-evident persistence for the security allow-lists (SSTP, kernel debug).
    ///
    /// The allow-list files themselves ("allowed_sstp.txt", "allowed_kerneldebug.txt")
    /// stay plain one-line files next to the exe — but every change the app itself
    /// makes is pinned in an append-only ledger under %PROGRAMDATA%\AutoCommand
    /// (admin-only write ACL, best-effort): each line records the SHA-256 of the
    /// preference file at the moment the app wrote it. On every load the file's
    /// current hash is checked against the ledger's last commit; a mismatch means
    /// something outside the app flipped the preference, and the value fails secure
    /// (false = enforce) rather than trusting the write.
    ///
    /// This closes the silent back door: any process can still write "True" into the
    /// file, but the write is detected, reverted and reported instead of silently
    /// disabling enforcement. Absent/unreadable/garbage files also fail secure.
    /// </summary>
    public static class AllowListLedger
    {
        private static string _root;

        /// <summary>Point the ledger at a different root. Tests call this before
        /// anything constructs; the app never does (default = %PROGRAMDATA%\AutoCommand).</summary>
        public static void Configure(string root)
        {
            if (!string.IsNullOrEmpty(root)) _root = root;
        }

        private static string Root => _root ?? (_root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AutoCommand"));

        /// <summary>Apply the admin-only write ACL to the ledger root. On by
        /// default (the app runs elevated, so it keeps write access while
        /// standard-user processes lose theirs). Tests turn this off — a
        /// non-elevated test process would otherwise lock itself out of its
        /// own temp root after the first write, which proves the ACL works
        /// but makes every subsequent step fail.</summary>
        public static bool HardenRoot { get; set; } = true;

        private static bool _hardenAttempted;

        private static string LedgerPath => Path.Combine(Root, "allowlist-ledger.log");

        private static readonly object _gate = new object();
        private static readonly List<string> _tamperReports = new List<string>();

        /// <summary>Human-readable tamper/drift reports from this session (newest last).</summary>
        public static IReadOnlyList<string> TamperReports
        {
            get { lock (_gate) return _tamperReports.ToArray(); }
        }

        /// <summary>Fired whenever a tamper is detected (key, detail).</summary>
        public static event Action<string, string> Tampered;

        // ── Load ──────────────────────────────────────────────────────────────

        /// <summary>Reads an allow-list preference with tamper verification. Never
        /// throws; every failure path returns the secure default (false = enforce).</summary>
        public static AllowListLoadResult Load(string key, string prefPath)
        {
            var result = new AllowListLoadResult { Value = false, Status = AllowListLoadStatus.Absent };

            try
            {
                string fileValue = null;
                byte[] fileBytes = null;
                if (File.Exists(prefPath))
                {
                    fileBytes = File.ReadAllBytes(prefPath);
                    fileValue = ParsePref(Encoding.UTF8.GetString(fileBytes));
                    if (fileValue == null)
                    {
                        result.Status = AllowListLoadStatus.Unreadable;
                        result.Detail = "preference file content is not True/False — enforcement stays on";
                        Record(key, "unreadable", "pref content not True/False");
                        return result;
                    }
                }

                string committedValue = null, committedHash = null;
                foreach (var entry in ReadLedger(key))
                {
                    if (entry.Kind == "value")
                    {
                        // payload = "<True|False> <64-hex hash>"
                        int sp = entry.Payload.LastIndexOf(' ');
                        if (sp > 0 && entry.Payload.Length - sp - 1 == 64)
                        {
                            committedValue = entry.Payload.Substring(0, sp);
                            committedHash = entry.Payload.Substring(sp + 1);
                        }
                    }
                }

                if (committedHash == null)
                {
                    if (fileBytes == null) return result; // Absent, secure default

                    // First run after the ledger shipped: adopt what the user's own
                    // machine already had, and pin it so every future edit is checked.
                    Record(key, "value", fileValue + " " + Hash(fileBytes));
                    result.Value = fileValue == "True";
                    result.Status = AllowListLoadStatus.Seeded;
                    result.Detail = "seeded from pre-ledger preference file";
                    return result;
                }

                if (fileBytes == null)
                {
                    // A committed preference vanished — treat as tampering: fail secure.
                    result.Status = AllowListLoadStatus.Tampered;
                    result.Detail = "allow-list file disappeared after it was committed — enforcement re-armed";
                    Record(key, "tamper", "file deleted");
                    Report(key, result.Detail);
                    return result;
                }

                string actual = Hash(fileBytes);
                if (actual != committedHash)
                {
                    result.Status = AllowListLoadStatus.Tampered;
                    result.Detail = "allow-list file was modified outside the app (committed '"
                                    + committedValue + "', found '" + fileValue + "') — enforcement re-armed";
                    Record(key, "tamper", "hash mismatch (committed " + committedHash.Substring(0, 12)
                                          + ", found " + actual.Substring(0, 12) + ")");
                    Report(key, result.Detail);
                    return result;
                }

                result.Value = fileValue == "True";
                result.Status = AllowListLoadStatus.Trusted;
                return result;
            }
            catch (Exception ex)
            {
                result.Status = AllowListLoadStatus.Unreadable;
                result.Detail = "ledger/preference read failed: " + ex.Message + " — enforcement stays on";
                return result;
            }
        }

        // ── Commit ────────────────────────────────────────────────────────────

        /// <summary>Writes the preference file and pins its hash in the ledger.
        /// Returns false (best-effort, like the flat-file writers it replaces) on
        /// any failure; the file may still have been written unpinned.</summary>
        public static bool Commit(string key, string prefPath, bool value)
        {
            try
            {
                string text = value ? "True" : "False";
                EnsureRoot();
                File.WriteAllText(prefPath, text); // exactly the legacy format
                byte[] bytes = File.ReadAllBytes(prefPath);
                Record(key, "value", text + " " + Hash(bytes));
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Appends a drift observation for a key without touching the
        /// pinned file hash (drift while allow-listed is recorded, never remediated).</summary>
        public static void NoteDrift(string key, string summary)
        {
            try { Record(key, "drift", summary ?? ""); } catch { }
        }

        // ── Internals ─────────────────────────────────────────────────────────

        private static string ParsePref(string raw)
        {
            if (raw == null) return null;
            string t = raw.Trim();
            return (t == "True" || t == "False") ? t : null;
        }

        private static string Hash(byte[] bytes)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var sb = new StringBuilder(64);
                foreach (byte b in sha.ComputeHash(bytes))
                    sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        private sealed class LedgerEntry
        {
            public string Kind;   // "value" | "tamper" | "drift" | "unreadable"
            public string Payload;
        }

        /// <summary>All ledger entries for one key, oldest first. A "value" payload
        /// is "&lt;True|False&gt; &lt;64-hex-char hash&gt;". Malformed lines are skipped.</summary>
        private static List<LedgerEntry> ReadLedger(string key)
        {
            var entries = new List<LedgerEntry>();
            if (!File.Exists(LedgerPath)) return entries;
            string[] lines = File.ReadAllLines(LedgerPath);
            foreach (string line in lines)
            {
                // utc|key|kind|payload — payload may itself contain '|'
                int p1 = line.IndexOf('|'); if (p1 < 0) continue;
                int p2 = line.IndexOf('|', p1 + 1); if (p2 < 0) continue;
                int p3 = line.IndexOf('|', p2 + 1); if (p3 < 0) continue;
                if (line.Substring(p1 + 1, p2 - p1 - 1) != key) continue;
                entries.Add(new LedgerEntry
                {
                    Kind = line.Substring(p2 + 1, p3 - p2 - 1),
                    Payload = line.Substring(p3 + 1),
                });
            }
            return entries;
        }

        private static void Record(string key, string kind, string payload)
        {
            lock (_gate)
            {
                EnsureRoot();
                string line = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
                              + "|" + key + "|" + kind + "|" + payload;
                File.AppendAllText(LedgerPath, line + Environment.NewLine, Encoding.UTF8);
            }
        }

        private static void Report(string key, string detail)
        {
            lock (_gate)
            {
                _tamperReports.Add(key + ": " + detail);
                if (_tamperReports.Count > 100) _tamperReports.RemoveRange(0, _tamperReports.Count - 100);
            }
            Tampered?.Invoke(key, detail);
        }

        private static void EnsureRoot()
        {
            Directory.CreateDirectory(Root);
            if (!HardenRoot || _hardenAttempted) return;
            _hardenAttempted = true;
            TryHarden(Root);
        }

        /// <summary>Best-effort admin-only write ACL on the ledger directory. The app
        /// runs elevated (requireAdministrator), so it keeps write access; standard
        /// user processes (where most tampering originates) lose theirs. Never fails
        /// the caller — the hash pin detects tampering even where the ACL cannot.</summary>
        private static void TryHarden(string dir)
        {
            try
            {
                var info = new DirectoryInfo(dir);
                var security = info.GetAccessControl();

                security.SetAccessRuleProtection(true, false); // drop inherited Users-write
                var sidAdmins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var sidSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var sidUsers = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                security.AddAccessRule(new FileSystemAccessRule(sidAdmins, FileSystemRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(sidSystem, FileSystemRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(sidUsers, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
                info.SetAccessControl(security);
            }
            catch
            {
                // Non-elevated context or odd filesystem — the hash pin still detects edits.
            }
        }
    }
}
