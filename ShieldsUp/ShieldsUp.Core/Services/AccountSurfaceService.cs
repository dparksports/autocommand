using System.Management;
using System.Text.Json.Nodes;
using ShieldsUp.Core.Helpers;

namespace ShieldsUp.Core.Services;

public sealed record AccountInfo(string Name, string Sid, bool Enabled, bool IsAdmin);
public sealed record ProfileInfo(string Sid, string Path, bool Loaded, DateTime? LastUseTime);

/// <summary>Kind: bootstrap_leftover_account | orphaned_profile | account_without_profile.
/// Severity: attention (admin-member or orphaned) | info.
/// Title/Glyph/ShowPrune are computed view properties for the OS Hardening card.</summary>
public sealed record Finding(string Kind, string Severity, string AccountName, string Sid, string Detail)
{
    public string Title => string.IsNullOrEmpty(AccountName)
        ? (Kind == "orphaned_profile" ? "orphaned profile" : Kind)
        : AccountName;
    public string Glyph => Severity == "attention" ? "⚠" : "ℹ";
    public bool ShowPrune => Kind != "account_without_profile"; // informational rows have nothing to prune
}

public sealed record AccountsStatus(
    IReadOnlyList<Finding> Findings, int AccountsInspected, int ProfilesInspected,
    IReadOnlyList<string> Failures);

/// <summary>
/// The local-accounts audit: disabled Windows setup/bootstrap accounts (the
/// "defaultuser0" class OOBE leaves behind), orphaned user profiles (a
/// ProfileList entry whose account no longer exists) and accounts without a
/// profile. One board (Shields Up → OS Hardening), one prune action each.
///
/// Deleting a profile is NOT reversible — the snapshot before deletion exists
/// only so the report can say exactly what was removed. The guard refuses
/// everything that is not a genuine leftover: enabled accounts, the current
/// user, built-in accounts (RID 500/501/503/504), the service SIDs
/// (S-1-5-18/19/20), and any loaded profile. Pure state computers live here
/// so the self-test can verify the guard matrix without touching a live
/// system; the caller confirms first, then calls (same contract as
/// AttackSurfaceService).
/// </summary>
public static class AccountSurfaceService
{
    private const string BootstrapPrefix = "defaultuser";

    // ── pure state computers (self-tested; no WMI, no registry) ─────────

    /// <summary>defaultuser0 / defaultuser1 / defaultuser100000 — the name
    /// pattern Windows Setup's OOBE bootstrap account always uses.</summary>
    public static bool IsBootstrapAccountName(string name)
    {
        if (string.IsNullOrEmpty(name) ||
            !name.StartsWith(BootstrapPrefix, StringComparison.OrdinalIgnoreCase))
            return false;
        var rest = name[BootstrapPrefix.Length..];
        return rest.Length > 0 && rest.All(char.IsDigit);
    }

    /// <summary>Never-prunable SIDs: the built-in accounts (Administrator 500,
    /// Guest 501, DefaultAccount 503, WDAGUtilityAccount 504) and the local
    /// service SIDs. EndsWith is safe because these RIDs are only special on
    /// the final subauthority.</summary>
    public static bool IsBuiltInOrServiceSid(string sid)
    {
        if (string.IsNullOrEmpty(sid)) return true; // unknown → treat as protected
        if (sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") return true;
        return sid.EndsWith("-500") || sid.EndsWith("-501")
            || sid.EndsWith("-503") || sid.EndsWith("-504");
    }

    /// <summary>Lowercase machine-SID prefix ("S-1-5-21-a-b-c") derived from
    /// any local account SID — profiles outside this prefix are not machine-
    /// local accounts (service SIDs, domain users) and are never findings.</summary>
    public static string MachineSidPrefix(IEnumerable<string> localAccountSids)
    {
        foreach (var sid in localAccountSids)
        {
            if (sid is null || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) continue;
            var idx = sid.LastIndexOf('-');
            if (idx > "S-1-5-21-".Length) return sid[..idx];
        }
        return null;
    }

    public static bool IsLocalMachineSid(string sid, string machinePrefix) =>
        !string.IsNullOrEmpty(machinePrefix)
        && !string.IsNullOrEmpty(sid)
        && sid.StartsWith(machinePrefix + "-", StringComparison.Ordinal);

    /// <summary>The OOBE bootstrap leftover. Disabled + defaultuser pattern is
    /// the classic leftover; an admin-member one is the interesting case (a
    /// dormant privileged account), an enabled one is outright unusual.</summary>
    public static Finding ClassifyAccount(AccountInfo a)
    {
        if (a is null || !IsBootstrapAccountName(a.Name)) return null;
        var severity = (!a.Enabled && !a.IsAdmin) ? "info" : "attention";
        var state = a.Enabled ? "ENABLED" : "disabled";
        var role = a.IsAdmin ? ", member of Administrators" : "";
        return new Finding("bootstrap_leftover_account", severity, a.Name, a.Sid,
            $"setup/bootstrap account '{a.Name}' is {state}{role} — left behind by Windows setup");
    }

    /// <summary>A registered profile whose local account no longer exists.</summary>
    public static Finding ClassifyProfile(ProfileInfo p, ISet<string> accountSids, string machinePrefix)
    {
        if (p is null || !IsLocalMachineSid(p.Sid, machinePrefix)) return null;
        if (accountSids is not null && accountSids.Contains(p.Sid)) return null;
        return new Finding("orphaned_profile", "attention", null, p.Sid,
            $"profile folder '{p.Path}' is registered but its local account no longer exists");
    }

    /// <summary>A non-built-in account that has no registered profile (info —
    /// usually an account that was created but never logged into).</summary>
    public static Finding ClassifyAccountWithoutProfile(AccountInfo a, ISet<string> profileSids)
    {
        if (a is null || IsBuiltInOrServiceSid(a.Sid)) return null;
        if (profileSids is not null && profileSids.Contains(a.Sid)) return null;
        return new Finding("account_without_profile", "info", a.Name, a.Sid,
            $"account '{a.Name}' has no registered profile (created but never logged into?)");
    }

    /// <summary>The hard never-touch guard. Refuses enabled accounts, loaded
    /// profiles, the current user, built-ins and service SIDs, and anything on
    /// the caller-supplied extra list.</summary>
    public static bool MayPrune(string sid, bool accountEnabled, bool profileLoaded,
        string currentUserSid, ISet<string> extraProtectedSids = null)
    {
        if (string.IsNullOrEmpty(sid)) return false;
        if (accountEnabled || profileLoaded) return false;
        if (IsBuiltInOrServiceSid(sid)) return false;
        if (currentUserSid is not null && string.Equals(sid, currentUserSid, StringComparison.OrdinalIgnoreCase))
            return false;
        if (extraProtectedSids is not null && extraProtectedSids.Contains(sid)) return false;
        return true;
    }

    // ── live reads ──────────────────────────────────────────────────────

    public static AccountsStatus GetAccountsStatus()
    {
        var failures = new List<string>();
        var findings = new List<Finding>();

        var accounts = new List<AccountInfo>();
        var profiles = new List<ProfileInfo>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = True");
            foreach (var o in searcher.Get())
            {
                var name = o["Name"]?.ToString();
                var sid = o["SID"]?.ToString();
                if (string.IsNullOrEmpty(sid)) continue;
                accounts.Add(new AccountInfo(name, sid, !BoolOf(o["Disabled"]), IsAdmin(name, failures)));
            }
        }
        catch (Exception ex)
        {
            failures.Add("account enumeration failed: " + ex.Message);
        }

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT SID, ProfilePath, Loaded, LastUseTime, LocalProfile FROM Win32_UserProfile");
            foreach (var o in searcher.Get())
            {
                var sid = o["SID"]?.ToString();
                if (string.IsNullOrEmpty(sid)) continue;
                profiles.Add(new ProfileInfo(
                    sid,
                    o["ProfilePath"]?.ToString(),
                    BoolOf(o["Loaded"]),
                    TryToDateTime(o["LastUseTime"])));
            }
        }
        catch (Exception ex)
        {
            failures.Add("profile enumeration failed: " + ex.Message);
        }

        var machinePrefix = MachineSidPrefix(accounts.Select(a => a.Sid));
        var accountSids = accounts.Select(a => a.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var profileSids = profiles.Select(p => p.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var a in accounts)
        {
            var f = ClassifyAccount(a);
            if (f is not null) findings.Add(f);
            f = ClassifyAccountWithoutProfile(a, profileSids);
            if (f is not null) findings.Add(f);
        }
        foreach (var p in profiles)
        {
            var f = ClassifyProfile(p, accountSids, machinePrefix);
            if (f is not null) findings.Add(f);
        }

        return new AccountsStatus(findings, accounts.Count, profiles.Count, failures);
    }

    // ── the prune action (caller confirms first, then calls) ────────────

    /// <summary>Delete one leftover: its registered profile (if any) and its
    /// account (if any). Refuses everything the guard rejects — empty return
    /// list means the prune verified clean.</summary>
    public static List<string> PruneLeftover(string sid)
    {
        var failures = new List<string>();
        sid = sid?.Trim();
        if (string.IsNullOrEmpty(sid))
        {
            failures.Add("no SID given");
            return failures;
        }

        // Format gate BEFORE any WQL use: the SID is interpolated into WQL
        // strings below, and this is the elevated delete-everything primitive.
        // A well-formed Windows SID contains only "S-1-" and digits/dashes, so
        // anything else — quotes, comments, an injected OR clause — is refused
        // here rather than shaped into a query.
        if (!System.Text.RegularExpressions.Regex.IsMatch(sid, @"^S-1-\d+(-\d+){1,15}$"))
        {
            failures.Add($"'{sid}' is not a well-formed Windows SID — refusing");
            return failures;
        }

        string currentUserSid = null;
        try { currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value; }
        catch { }

        // live re-read of exactly this target
        string accountName = null;
        bool accountEnabled = false;
        bool accountExists = false;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = True AND SID = '{sid}'");
            foreach (var o in searcher.Get())
            {
                // Trust the ROW's own SID, not just the query filter — the
                // guard below must never validate one string and delete
                // another row.
                if (!string.Equals(o["SID"]?.ToString(), sid, StringComparison.OrdinalIgnoreCase)) continue;
                accountExists = true;
                accountName = o["Name"]?.ToString();
                accountEnabled = !BoolOf(o["Disabled"]);
            }
        }
        catch (Exception ex)
        {
            failures.Add("account re-read failed: " + ex.Message);
            return failures;
        }

        string profilePath = null;
        bool profileLoaded = false;
        bool profileExists = false;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT SID, ProfilePath, Loaded FROM Win32_UserProfile WHERE SID = '{sid}'");
            foreach (var o in searcher.Get())
            {
                profileExists = true;
                profilePath = o["ProfilePath"]?.ToString();
                profileLoaded = BoolOf(o["Loaded"]);
            }
        }
        catch (Exception ex)
        {
            failures.Add("profile re-read failed: " + ex.Message);
            return failures;
        }

        if (!accountExists && !profileExists)
        {
            failures.Add($"nothing to prune: no account and no profile for {sid}");
            return failures;
        }

        // the guard — refuse anything that is not a genuine leftover
        if (accountExists)
        {
            if (accountEnabled) { failures.Add($"account '{accountName}' is ENABLED — refusing"); return failures; }
            if (!IsBootstrapAccountName(accountName))
            {
                failures.Add($"account '{accountName}' is not a bootstrap-pattern (defaultuser*) account — refusing");
                return failures;
            }
        }
        if (profileLoaded) { failures.Add($"profile for {sid} is loaded (in use) — refusing"); return failures; }
        if (IsBuiltInOrServiceSid(sid)) { failures.Add($"{sid} is a built-in/service SID — refusing"); return failures; }
        if (!MayPrune(sid, accountEnabled, profileLoaded, currentUserSid))
        {
            failures.Add($"guard refused {sid} (current user or protected)");
            return failures;
        }
        // The account name goes into a `net user "…" /delete` command line:
        // a name carrying quotes or control characters is refused before it
        // can shape that command.
        if (accountName != null && (accountName.Contains('"') || accountName.Any(char.IsControl)))
        {
            failures.Add($"account name '{accountName}' contains characters that are never valid — refusing");
            return failures;
        }

        // snapshot before deleting (reporting only — deletion is not reversible)
        try
        {
            AppPaths.EnsureDataRoot();
            var arr = new JsonArray();
            var statePath = AppPaths.AccountsStatePath;
            if (File.Exists(statePath))
            {
                if (JsonNode.Parse(File.ReadAllText(statePath)) is JsonArray existing)
                    arr = existing;
            }
            arr.Add(new JsonObject
            {
                ["sid"] = sid,
                ["account"] = accountName,
                ["profile_path"] = profilePath,
                ["pruned_at"] = DateTime.UtcNow.ToString("o"),
            });
            File.WriteAllText(statePath, arr.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            failures.Add("snapshot failed (nothing deleted): " + ex.Message);
            return failures;
        }

        // delete the profile first (files + ProfileList entry), then the account
        if (profileExists)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT SID FROM Win32_UserProfile WHERE SID = '{sid}'");
                foreach (var o in searcher.Get().Cast<ManagementObject>())
                {
                    // Same row-trust rule: delete only a row whose own SID is
                    // exactly the validated target.
                    if (!string.Equals(o["SID"]?.ToString(), sid, StringComparison.OrdinalIgnoreCase)) continue;
                    o.Delete();
                }
            }
            catch (Exception ex)
            {
                failures.Add("profile deletion failed: " + ex.Message);
            }
        }

        if (accountExists)
        {
            try
            {
                var output = ProcessRunner.RunAsync("net", $"user \"{accountName}\" /delete").GetAwaiter().GetResult();
                if (output is not null && output.IndexOf("successfully", StringComparison.OrdinalIgnoreCase) < 0
                    && output.IndexOf("command completed", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    failures.Add("net user reported: " + output.Trim());
                }
            }
            catch (Exception ex)
            {
                failures.Add("account deletion failed: " + ex.Message);
            }
        }

        // verify by re-read
        bool stillAccount = AccountExistsNow(sid);
        bool stillProfileKey = ProfileListKeyExists(sid);
        bool stillFolder = profilePath is not null && Directory.Exists(profilePath);
        if (stillAccount) failures.Add("account still exists after delete");
        if (stillProfileKey) failures.Add("ProfileList registry entry still exists after delete");
        if (stillFolder) failures.Add("profile folder still exists after delete");

        AppLogger.Log("accounts", failures.Count == 0
            ? $"pruned {(accountName ?? "orphaned profile")} ({sid}); verified clean"
            : $"prune of {sid} finished with failures: {string.Join("; ", failures)}");
        return failures;
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private static bool BoolOf(object v) =>
        v is true || (v?.ToString()?.Equals("True", StringComparison.OrdinalIgnoreCase) ?? false);

    private static DateTime? TryToDateTime(object v)
    {
        var s = v?.ToString();
        if (string.IsNullOrEmpty(s)) return null;
        try { return ManagementDateTimeConverter.ToDateTime(s); }
        catch { return null; }
    }

    private static bool IsAdmin(string accountName, List<string> failures)
    {
        if (string.IsNullOrEmpty(accountName)) return false;
        try
        {
            var output = ProcessRunner.RunAsync("net", "localgroup Administrators").GetAwaiter().GetResult();
            if (string.IsNullOrEmpty(output)) return false;
            foreach (var raw in output.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('-') || line.StartsWith("Alias ") ||
                    line.StartsWith("Comment") || line.StartsWith("Members") ||
                    line.IndexOf("command completed", StringComparison.OrdinalIgnoreCase) >= 0)
                    continue;
                if (string.Equals(line, accountName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            if (failures.Count == 0 || !failures[^1].StartsWith("admin-group check failed"))
                failures.Add("admin-group check failed: " + ex.Message);
            return false;
        }
    }

    private static bool AccountExistsNow(string sid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT SID FROM Win32_UserAccount WHERE LocalAccount = True AND SID = '{sid}'");
            return searcher.Get().Count > 0;
        }
        catch { return true; } // cannot verify → report as still-present (honest)
    }

    private static bool ProfileListKeyExists(string sid)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
            return key is not null;
        }
        catch { return true; }
    }
}
