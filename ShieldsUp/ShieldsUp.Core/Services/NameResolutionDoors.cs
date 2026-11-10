using System.Text.Json;
using System.Text.Json.Nodes;
using ShieldsUp.Core.Helpers;

namespace ShieldsUp.Core.Services;

/// <summary>
/// The legacy name-resolution doors: LLMNR (UDP 5355), NetBIOS over TCP/IP
/// (UDP 137-139) and mDNS (UDP 5353). Windows enables all three by default;
/// each is a broadcast/multicast fallback that interrogates every host on
/// the segment, and LLMNR/NBNS poisoning is a classic credential-theft
/// attack. One board (Shields Up → Doors), one toggle each, reversible.
///
/// Honesty notes baked into the evidence strings: the NetBIOS toggle is
/// per-interface and applies on adapter restart/reboot; mDNS has NO source
/// switch on Windows (the Dnscache resolver always listens), so that door
/// is network-level — a scoped outbound firewall rule — and says so.
/// </summary>
public static class NameResolutionDoors
{
    // ── shared shape ─────────────────────────────────────────────────────

    public enum NbState { None = 0, Partial, Closed, Unknown }

    public sealed record LlmnrStatus(bool Open, string Evidence);
    public sealed record NetbiosStatus(NbState State, int Total, int Disabled, string Evidence);
    public sealed record MdnsStatus(bool Open, string Evidence);

    /// <summary>Pure: interface counts → door state (self-tested).</summary>
    public static NbState ComputeNetbiosState(int total, int disabled) =>
        total <= 0 ? NbState.Unknown
        : disabled == total ? NbState.Closed
        : disabled > 0 ? NbState.Partial
        : NbState.None;

    /// <summary>Pure: the EnableMulticast policy value → open? (self-tested).
    /// Absent means Windows default = LLMNR on.</summary>
    public static bool LlmnrOpenFromValue(int? enableMulticast) => enableMulticast != 0;

    /// <summary>Pure: enabled scoped-rule count → door closed? (self-tested)</summary>
    public static bool MdnsClosedFromRuleCount(int enabledRules) => enabledRules > 0;

    // ── LLMNR ────────────────────────────────────────────────────────────

    private const string LlmnrKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNS Client";

    public static LlmnrStatus GetLlmnrStatus()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LlmnrKey);
            int? v = null;
            if (key?.GetValue("EnableMulticast") is int i) v = i;
            bool open = LlmnrOpenFromValue(v);
            return new LlmnrStatus(open,
                $"EnableMulticast = {(v?.ToString() ?? "not set (default: on)")} — LLMNR {(open ? "open ⚠" : "off ✓")}");
        }
        catch (Exception ex)
        {
            return new LlmnrStatus(true, "status unreadable: " + ex.Message);
        }
    }

    /// <summary>Sets EnableMulticast=0 (snapshot first). Empty list = clean.</summary>
    public static List<string> DisableLlmnr()
    {
        var failures = new List<string>();
        try
        {
            string prev = "absent";
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LlmnrKey))
            {
                if (key?.GetValue("EnableMulticast") is int i) prev = i.ToString();
            }
            SaveSnapshot(s => s["llmnr"] = JsonValue.Create(prev));
            using var w = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(LlmnrKey);
            w.SetValue("EnableMulticast", 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    public static List<string> EnableLlmnr()
    {
        var failures = new List<string>();
        try
        {
            var snap = LoadSnapshot();
            string prev = snap?["llmnr"]?.GetValue<string>();
            using var w = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(LlmnrKey);
            if (prev == null || prev == "absent") w.DeleteValue("EnableMulticast", throwOnMissingValue: false);
            else w.SetValue("EnableMulticast", int.Parse(prev), Microsoft.Win32.RegistryValueKind.DWord);
            ClearSnapshot(s => s.Remove("llmnr"));
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    // ── NetBIOS over TCP/IP (per-interface) ──────────────────────────────

    private const string NbRoot = @"SYSTEM\CurrentControlSet\Services\Netbt\Parameters\Interfaces";

    public static NetbiosStatus GetNetbiosStatus()
    {
        try
        {
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(NbRoot);
            var guids = root?.GetSubKeyNames()
                .Where(n => n.StartsWith("Tcpip_", StringComparison.OrdinalIgnoreCase))
                .ToList() ?? new List<string>();
            int disabled = 0;
            foreach (var g in guids)
                using (var k = root!.OpenSubKey(g))
                    if (k?.GetValue("NetbiosOptions") is int i && i == 2) disabled++;
            var state = ComputeNetbiosState(guids.Count, disabled);
            string note = state switch
            {
                NbState.Closed => "NetBIOS name resolution off on every interface ✓ (applies after adapter restart/reboot)",
                NbState.Partial => $"PARTIAL — NetbiosOptions=2 on {disabled} of {guids.Count} interfaces ⚠",
                NbState.None => $"open on all {guids.Count} interface(s) ⚠ (UDP 137 broadcasts)",
                _ => "no NetBT interfaces found",
            };
            return new NetbiosStatus(state, guids.Count, disabled, note);
        }
        catch (Exception ex)
        {
            return new NetbiosStatus(NbState.Unknown, 0, 0, "status unreadable: " + ex.Message);
        }
    }

    /// <summary>Sets NetbiosOptions=2 on every Tcpip_ interface (per-GUID
    /// snapshot first — 0/1/2/absent restored exactly on re-open).</summary>
    public static List<string> DisableNetbios()
    {
        var failures = new List<string>();
        try
        {
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(NbRoot);
            var guids = root?.GetSubKeyNames()
                .Where(n => n.StartsWith("Tcpip_", StringComparison.OrdinalIgnoreCase))
                .ToList() ?? new List<string>();
            SaveSnapshot(snap =>
            {
                var nb = new JsonObject();
                foreach (var g in guids)
                {
                    string prev = "absent";
                    using (var k = root!.OpenSubKey(g))
                        if (k?.GetValue("NetbiosOptions") is int i) prev = i.ToString();
                    nb[g] = JsonValue.Create(prev);
                }
                snap["netbios"] = nb;
            });
            foreach (var g in guids)
            {
                try
                {
                    using var k = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(NbRoot + @"\" + g);
                    k.SetValue("NetbiosOptions", 2, Microsoft.Win32.RegistryValueKind.DWord);
                }
                catch (Exception ex) { failures.Add($"{g}: {ex.Message}"); }
            }
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    public static List<string> EnableNetbios()
    {
        var failures = new List<string>();
        try
        {
            var snap = LoadSnapshot();
            var nb = snap?["netbios"] as JsonObject;
            if (nb == null)
                return new List<string> { "no snapshot — no previous per-interface values to restore" };
            foreach (var (guid, prevNode) in nb)
            {
                string prev = prevNode?.GetValue<string>() ?? "absent";
                try
                {
                    using var k = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(NbRoot + @"\" + guid);
                    if (prev == "absent") k.DeleteValue("NetbiosOptions", throwOnMissingValue: false);
                    else k.SetValue("NetbiosOptions", int.Parse(prev), Microsoft.Win32.RegistryValueKind.DWord);
                }
                catch (Exception ex) { failures.Add($"{guid}: {ex.Message}"); }
            }
            ClearSnapshot(s => s.Remove("netbios"));
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    // ── mDNS (network-level — no source switch exists) ───────────────────

    public const string MdnsRuleGroup = "AC-BLOCK-MDNS";
    private const string MdnsRuleName = "AC-BLOCK-MDNS mDNS multicast (Out)";

    public static MdnsStatus GetMdnsStatus()
    {
        try
        {
            int enabled = CountMdnsRules();
            bool open = !MdnsClosedFromRuleCount(enabled);
            return new MdnsStatus(open, open
                ? "no scoped block — mDNS multicast (UDP 5353) flows ⚠"
                : "outbound mDNS multicast blocked at the firewall ✓ (network-level — the Dnscache resolver itself stays on)");
        }
        catch (Exception ex)
        {
            return new MdnsStatus(true, "status unreadable: " + ex.Message);
        }
    }

    /// <summary>Creates the scoped outbound block (224.0.0.251 / ff02::fb,
    /// UDP 5353) under its own group — the clean revert unit. Printer /
    /// Chromecast / AirPlay discovery stops while closed.</summary>
    public static List<string> DisableMdns()
    {
        var failures = new List<string>();
        try
        {
            if (CountMdnsRules() > 0) return failures;   // idempotent
            string ps = $"New-NetFirewallRule -DisplayName '{MdnsRuleName}' -Group '{MdnsRuleGroup}' " +
                        "-Direction Outbound -Action Block -Protocol UDP -RemoteAddress 224.0.0.251,ff02::fb | Out-Null";
            ProcessRunner.Run("powershell", $"-NoProfile -Command \"{ps}\"");
            if (CountMdnsRules() == 0) failures.Add("rule did not land — check elevation");
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    public static List<string> EnableMdns()
    {
        var failures = new List<string>();
        try
        {
            ProcessRunner.Run("powershell",
                $"-NoProfile -Command \"Remove-NetFirewallRule -Group '{MdnsRuleGroup}' -ErrorAction SilentlyContinue\"");
        }
        catch (Exception ex) { failures.Add(ex.Message); }
        return failures;
    }

    private static int CountMdnsRules()
    {
        string outText = ProcessRunner.Run("powershell",
            $"-NoProfile -Command \"(Get-NetFirewallRule -Group '{MdnsRuleGroup}' -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.Enabled -eq 'True' } | Measure-Object).Count\"");
        return int.TryParse(outText?.Trim(), out int n) ? n : 0;
    }

    // ── snapshot persistence (house JSON pattern) ────────────────────────

    private static string StatePath => Path.Combine(AppPaths.DataRoot, "name-resolution-doors.json");

    private static void SaveSnapshot(Action<JsonObject> mutate)
    {
        Directory.CreateDirectory(AppPaths.DataRoot);
        var snap = LoadSnapshot() ?? new JsonObject();
        mutate(snap);
        File.WriteAllText(StatePath, snap.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private static void ClearSnapshot(Action<JsonObject> mutate)
    {
        var snap = LoadSnapshot();
        if (snap == null) return;
        mutate(snap);
        File.WriteAllText(StatePath, snap.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private static JsonObject? LoadSnapshot()
    {
        try
        {
            if (File.Exists(StatePath))
                return JsonNode.Parse(File.ReadAllText(StatePath)) as JsonObject;
        }
        catch { /* unreadable snapshot = honest failure at re-open time */ }
        return null;
    }
}
