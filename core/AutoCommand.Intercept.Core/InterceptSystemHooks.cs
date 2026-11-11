using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AutoCommand.Intercept.Core
{
    /// <summary>
    /// The driverless system hooks an intercept session installs, and their
    /// exact undo:
    ///
    ///   - WinHTTP proxy (netsh) — how Windows SERVICES (svchost, BITS,
    ///     Delivery Optimization, telemetry hosts) are routed into the local
    ///     proxy with zero drivers. Works on 26H2 regardless of HVCI or
    ///     Smart App Control, unlike the WinDivert transparent-redirect
    ///     route the open-source tools take.
    ///   - WinINET per-user proxy (registry + refresh broadcast) — user-side
    ///     apps, same effect.
    ///   - One outbound UDP/443 block rule per target program — QUIC cannot
    ///     be MITM'd by an HTTP proxy; the block makes QUIC-using clients
    ///     fall back to TCP/TLS for the session's duration. Standard WFP
    ///     rule via netsh, no driver.
    ///
    /// Every change is journaled to session-active.json BEFORE it is made
    /// and the journal deleted after a clean stop, so a crash never leaves
    /// the machine proxied: RecoverAfterCrash() runs at every app start and
    /// undoes whatever the journal still describes.
    ///
    /// The journal is replay input for ELEVATED netsh/registry calls, so
    /// its strings are never trusted: every restore validates its undo
    /// value against the exact shape this class itself captured (defense
    /// in depth behind the CA dir's admin-only ACL — a forged journal in
    /// a user-writable location must degrade to the conservative action,
    /// never shape an elevated command line; arguments also travel via
    /// ArgumentList, so quoting is the runtime's job, not string surgery).
    /// </summary>
    public static class InterceptSystemHooks
    {
        public const string FirewallRulePrefix = "AutoCommand Intercept QUIC block";

        private static string JournalPath => Path.Combine(InterceptCaService.Dir, "session-active.json");

        internal sealed class Journal
        {
            public string WinHttpProxyBefore { get; set; }   // null = direct (netsh reset proxy restores this)
            public string WinHttpBypassBefore { get; set; }  // null = no bypass list; restored alongside the proxy
            public int? WininetEnableBefore { get; set; }
            public string WininetServerBefore { get; set; }
            public string CaThumbprint { get; set; }
            public int ProxyPort { get; set; }
            public string[] FirewallRules { get; set; } = Array.Empty<string>();
        }

        // ── journal ───────────────────────────────────────────────────────

        private static void WriteJournal(Journal journal)
        {
            Directory.CreateDirectory(InterceptCaService.Dir);
            File.WriteAllText(JournalPath, System.Text.Json.JsonSerializer.Serialize(journal,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }

        private static Journal ReadJournal()
        {
            try
            {
                if (File.Exists(JournalPath))
                    return System.Text.Json.JsonSerializer.Deserialize<Journal>(File.ReadAllText(JournalPath));
            }
            catch { /* unreadable journal — best-effort recovery below still runs */ }
            return null;
        }

        /// <summary>Test seam: the self-test round-trips the journal through
        /// a temp dir via the CA dir override; this exposes the file path.</summary>
        internal static string JournalPathForTest => JournalPath;

        // ── WinHTTP (services) ────────────────────────────────────────────

        private static string RunNetsh(params string[] arguments)
        {
            // Pinned to System32: the app runs elevated from a portable
            // folder, and an unqualified "netsh" would resolve through the
            // app directory / CWD first (both user-writable). Arguments
            // travel via ArgumentList — each element is ONE process
            // argument, quoted by the runtime — so no caller-side string
            // can ever break out into extra netsh tokens.
            var psi = new ProcessStartInfo(
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe"))
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (string argument in arguments)
                psi.ArgumentList.Add(argument);
            using var process = Process.Start(psi);
            // Drain stderr concurrently — netsh never writes much, but a
            // blocked pipe must not be able to wedge the read.
            var stderrTask = process.StandardError.ReadToEndAsync();
            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(10000))
            {
                try { process.Kill(); } catch { }
                process.WaitForExit();
            }
            _ = stderrTask.Result;
            return output;
        }

        // ── journal-input validation ─────────────────────────────────────
        // The journal's undo strings are replayed by the elevated app, so
        // they are validated at the sink against the exact shapes this
        // class itself captures. Anything else degrades to the
        // conservative action (reset / skip) instead of being applied.

        private static readonly Regex RuleNameShape = new(
            @"^AutoCommand Intercept QUIC block \(\d{1,10}\)$", RegexOptions.Compiled);
        private static readonly Regex WinHttpProxyShape = new(
            @"^[A-Za-z0-9.\-]+:\d{1,5}$", RegexOptions.Compiled);
        // WinINET ProxyServer values ("host:port", "socks=host:port",
        // "http=h1:p1;https=h2:p2") and WinHTTP bypass lists ("<local>",
        // "foo;bar", wildcards) — a conservative charset with no quoting,
        // newline or shell-relevant characters in it.
        private static readonly Regex ProxyServerShape = new(
            @"^[A-Za-z0-9.:\-;=]{1,256}$", RegexOptions.Compiled);
        private static readonly Regex BypassShape = new(
            @"^[A-Za-z0-9.\-;=<>*, ]{1,1024}$", RegexOptions.Compiled);

        private static bool IsPortInRange(string hostPort)
        {
            int colon = hostPort.LastIndexOf(':');
            return colon > 0 && int.TryParse(hostPort[(colon + 1)..], out int port) && port is > 0 and <= 65535;
        }

        /// <summary>The proxy line and bypass list netsh reports, plus
        /// whether a proxy is set at all.</summary>
        private static (string Proxy, bool IsDirect, string Bypass) CurrentWinHttpProxy()
        {
            string show = RunNetsh("winhttp", "show", "proxy");
            string proxy = null;
            string bypass = null;
            foreach (var line in show.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("Proxy Server(s)", StringComparison.OrdinalIgnoreCase))
                {
                    string value = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim();
                    if (value.Length > 0 && !value.Equals("direct", StringComparison.OrdinalIgnoreCase) &&
                        !value.Contains("directly accessing", StringComparison.OrdinalIgnoreCase))
                        proxy = value;
                }
                else if (trimmed.StartsWith("Bypass List", StringComparison.OrdinalIgnoreCase))
                {
                    string value = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim();
                    if (value.Length > 0)
                        bypass = value;
                }
            }
            return (proxy, proxy == null, bypass);
        }

        /// <summary>Snapshot of the WinHTTP state to restore afterwards:
        /// the proxy line (null = direct) AND the bypass list — a user with
        /// a custom bypass must not lose it to every intercept session.</summary>
        internal static (string Proxy, string Bypass) CaptureWinHttpProxy()
        {
            var (before, wasDirect, bypass) = CurrentWinHttpProxy();
            return (wasDirect ? null : before, bypass);
        }

        private static void ApplyWinHttpProxy(int port) =>
            RunNetsh("winhttp", "set", "proxy", $"127.0.0.1:{port}", "<local>");

        internal static void RestoreWinHttpProxy(string before, string bypass)
        {
            if (before == null || !WinHttpProxyShape.IsMatch(before) || !IsPortInRange(before))
            {
                // null = was direct; a value that no longer has the shape
                // this class captures came from a tampered journal — reset
                // is the conservative undo either way.
                RunNetsh("winhttp", "reset", "proxy");
                return;
            }
            if (bypass != null && BypassShape.IsMatch(bypass))
                RunNetsh("winhttp", "set", "proxy", before, bypass);
            else
                RunNetsh("winhttp", "set", "proxy", before);
        }

        // ── WinINET (user apps) ───────────────────────────────────────────

        private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
        private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        private const int INTERNET_OPTION_REFRESH = 37;

        internal static (int? EnableBefore, string ServerBefore) InstallWininetProxy(int port)
        {
            var (enableBefore, serverBefore) = CaptureWininetProxy();
            ApplyWininetProxy(port);
            return (enableBefore, serverBefore);
        }

        /// <summary>Snapshot of the per-user WinINET proxy values, before
        /// anything changes.</summary>
        internal static (int? EnableBefore, string ServerBefore) CaptureWininetProxy()
        {
            int? enableBefore = null;
            string serverBefore = null;
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false))
            {
                if (key != null)
                {
                    if (key.GetValue("ProxyEnable") is int enable) enableBefore = enable;
                    serverBefore = key.GetValue("ProxyServer") as string;
                }
            }
            return (enableBefore, serverBefore);
        }

        private static void ApplyWininetProxy(int port)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key != null)
                {
                    key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
                }
            }
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }

        internal static void RestoreWininetProxy(int? enableBefore, string serverBefore)
        {
            // A ProxyServer that no longer matches the shapes this class
            // captures came from a tampered journal — restoring it is never
            // attempted; the value is cleared instead.
            string server = serverBefore != null && ProxyServerShape.IsMatch(serverBefore)
                ? serverBefore
                : null;
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key != null)
                {
                    if (enableBefore.HasValue)
                        key.SetValue("ProxyEnable", enableBefore.Value, RegistryValueKind.DWord);
                    else
                        key.DeleteValue("ProxyEnable", throwOnMissingValue: false);

                    if (server != null)
                        key.SetValue("ProxyServer", server, RegistryValueKind.String);
                    else
                        key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                }
            }
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }

        // ── QUIC block rule ───────────────────────────────────────────────

        internal static string AddQuicBlock(string image, int pid)
        {
            string rule = $"{FirewallRulePrefix} ({pid})";
            RunNetsh("advfirewall", "firewall", "add", "rule",
                $"name={rule}", "dir=out", "action=block",
                $"program={image}", "protocol=UDP", "remoteport=443");
            return rule;
        }

        internal static void RemoveRule(string ruleName)
        {
            // Only our own deterministic rule names are ever deletable from
            // journal data — the shape check is what keeps a forged journal
            // from deleting rules it should not even name (name=all is the
            // documented netsh delete-everything wildcard).
            if (string.IsNullOrEmpty(ruleName) || !RuleNameShape.IsMatch(ruleName))
                return;
            RunNetsh("advfirewall", "firewall", "delete", "rule", $"name={ruleName}");
        }

        // ── inspection seams for the startup repair sweep ─────────────────

        /// <summary>The current WinHTTP proxy server line (null = direct),
        /// read-only.</summary>
        internal static string InspectWinHttpProxy() => CaptureWinHttpProxy().Proxy;

        internal static void ResetWinHttpProxyForRepair() => RunNetsh("winhttp reset proxy");

        /// <summary>Current per-user WinINET proxy values, read-only.</summary>
        internal static (int? EnableBefore, string ServerBefore) InspectWininetProxy()
        {
            int? enable = null;
            string server = null;
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false))
            {
                if (key != null)
                {
                    if (key.GetValue("ProxyEnable") is int e) enable = e;
                    server = key.GetValue("ProxyServer") as string;
                }
            }
            return (enable, server);
        }

        /// <summary>Clears the per-user proxy (used only by the repair sweep
        /// for a dead loopback value we installed) and broadcasts the refresh
        /// so running apps pick the change up.</summary>
        internal static void ClearWininetProxyForRepair()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key != null)
                {
                    key.DeleteValue("ProxyEnable", throwOnMissingValue: false);
                    key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                }
            }
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }

        /// <summary>The journal path the repair sweep checks (absent journal +
        /// no live session = nothing owns today's trust/proxy state).</summary>
        internal static string JournalPathForRepair => JournalPath;

        // ── session open/close + crash recovery ───────────────────────────

        /// <summary>
        /// Installs all three hooks under the journal-ahead contract: the
        /// journal is on disk BEFORE the first system mutation (the crash
        /// guarantee this class is named for). The QUIC rule name is
        /// deterministic, so it is journaled before the rule exists (deleting
        /// a not-yet-created rule is a no-op), and each proxy's "before"
        /// values are journaled in the gap between reading and overwriting
        /// them — at every instant the journal describes everything changed
        /// so far. Returns the journal the caller keeps for StopSession.
        /// </summary>
        internal static Journal InstallAll(int port, int pid, string image, string caThumbprint)
        {
            string rule = $"{FirewallRulePrefix} ({pid})";
            var journal = new Journal
            {
                ProxyPort = port,
                CaThumbprint = caThumbprint,
                FirewallRules = new[] { rule },
            };
            WriteJournal(journal);

            var (wininetEnable, wininetServer) = CaptureWininetProxy();
            journal.WininetEnableBefore = wininetEnable;
            journal.WininetServerBefore = wininetServer;
            WriteJournal(journal);
            ApplyWininetProxy(port);

            var (winHttpProxy, winHttpBypass) = CaptureWinHttpProxy();
            journal.WinHttpProxyBefore = winHttpProxy;
            journal.WinHttpBypassBefore = winHttpBypass;
            WriteJournal(journal);
            ApplyWinHttpProxy(port);

            AddQuicBlock(image, pid); // installs the rule name journaled above
            return journal;
        }

        /// <summary>
        /// Removes Ca-only or all journaled state. removeCa=false is for a
        /// StopSession that lost a race with a new session using the same CA:
        /// the proxies/rules being torn down are the OLD session's, but the
        /// CA under the new session must stay trusted.
        /// The journal may only be deleted once the CA is confirmed out of
        /// the Root store (or was never installed / not ours to remove);
        /// otherwise it stays on disk so the next app start's
        /// RecoverAfterCrash retries instead of silently stranding a
        /// machine-trusted CA.
        /// </summary>
        internal static void UndoAll(Journal journal, bool removeCa = true)
        {
            if (journal == null) return;
            foreach (var rule in journal.FirewallRules ?? Array.Empty<string>())
                RemoveRule(rule);
            RestoreWinHttpProxy(journal.WinHttpProxyBefore, journal.WinHttpBypassBefore);
            RestoreWininetProxy(journal.WininetEnableBefore, journal.WininetServerBefore);

            bool caClean = true;
            if (removeCa && !string.IsNullOrEmpty(journal.CaThumbprint))
                caClean = InterceptCaService.RemoveFromRoot(journal.CaThumbprint);

            if (caClean)
                try { File.Delete(JournalPath); } catch { }
        }

        /// <summary>
        /// App-start safety net: a crash mid-session leaves the journal on
        /// disk — undo everything it describes. No journal, no action. An
        /// UNREADABLE journal is left in place, never guessed at: a partial
        /// write means the hooks may be live with the journal as their only
        /// undo record, so deleting it could strand the machine proxied.
        /// </summary>
        public static void RecoverAfterCrash()
        {
            var journal = ReadJournal();
            if (journal != null)
                UndoAll(journal);
        }
    }
}
