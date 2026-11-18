using System;
using AutoCommand.Contain.Core;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// The system hooks the block-page proxy installs, and their exact undo —
    /// the WinINET-only, journal-ahead twin of InterceptSystemHooks (that
    /// class also drives WinHTTP for services and a QUIC rule; this feature
    /// is deliberately scoped to the per-user proxy so Windows services are
    /// never routed through a loopback listener):
    ///
    ///   · WinINET per-user proxy (HKCU Internet Settings): ProxyEnable=1,
    ///     ProxyServer=127.0.0.1:&lt;port&gt;, ProxyOverride bypassing loopback
    ///     and local names — user-side apps (browsers) route through the
    ///     block-page proxy; services untouched.
    ///   · The refresh broadcast (InternetSetOption) so running apps pick the
    ///     change up without a re-login.
    ///
    /// Every change is journaled to blockproxy-active.json BEFORE it is made
    /// (atomic tmp+rename, capture sentinels distinguishing "never captured"
    /// from "was absent"), and the journal is deleted after a clean stop — so
    /// a crash never leaves the machine proxied: RecoverAfterCrash() undoes
    /// whatever the journal still describes at every app start, and
    /// RepairIfNeeded() sweeps the unjournaled straggler the intercept repair
    /// cannot know about (registry pointing at THIS feature's port with
    /// nothing listening behind it).
    ///
    /// The journal is replay input for registry restores, so its strings are
    /// never trusted: every restore validates its undo value against the
    /// exact shapes this class itself captures — a forged journal in a
    /// user-writable location degrades to clearing the value, never to
    /// writing attacker-chosen proxy settings.
    /// </summary>
    public static class BlockPageProxyHooks
    {
        private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        private const int InternetOptionSettingsChanged = 39;
        private const int InternetOptionRefresh = 37;

        /// <summary>Conservative charset mirrors of the shapes InterceptSystemHooks
        /// captures — no quoting, newline or shell-relevant characters.</summary>
        internal static readonly Regex ServerShape = new(@"^[A-Za-z0-9.:\-;=]{1,256}$", RegexOptions.Compiled);
        internal static readonly Regex OverrideShape = new(@"^[A-Za-z0-9.\-;=<>*, ]{0,1024}$", RegexOptions.Compiled);

        /// <summary>Exactly what a healthy install of this feature looks like —
        /// the repair sweep only ever clears a ProxyServer matching it.</summary>
        internal static string OwnProxyServerShape(int port) => $@"^127\.0\.0\.1:{port}$";

        internal sealed class Journal
        {
            public int? ProxyEnableBefore { get; set; }      // null = never captured
            public bool ProxyEnableCaptured { get; set; }
            public string ProxyServerBefore { get; set; }    // null + captured = value was absent
            public bool ProxyServerCaptured { get; set; }
            public string ProxyOverrideBefore { get; set; }
            public bool ProxyOverrideCaptured { get; set; }
            public int Port { get; set; }
        }

        /// <summary>Persistence root; settable for offline self-tests (house
        /// pattern) — the journal is the only file this class touches.</summary>
        public static string StoreDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private static string JournalPath => Path.Combine(StoreDirectory, "blockproxy-active.json");

        // ── journal ───────────────────────────────────────────────────────

        private static void WriteJournal(Journal journal)
        {
            Directory.CreateDirectory(StoreDirectory);
            // Atomic replace — the journal is the ONLY undo record for live
            // hooks (the same torn-write lesson InterceptSystemHooks records).
            string tmp = JournalPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(journal, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, JournalPath, overwrite: true);
        }

        private static Journal ReadJournal()
        {
            try
            {
                if (File.Exists(JournalPath))
                    return JsonSerializer.Deserialize<Journal>(File.ReadAllText(JournalPath));
            }
            catch { /* unreadable journal — best-effort recovery below still runs */ }
            return null;
        }

        internal static string JournalPathForTest => JournalPath;

        // ── install / undo ────────────────────────────────────────────────

        /// <summary>The per-user proxy as it stands RIGHT NOW — what Install
        /// would replace and Undo restores. The consent dialog reads this to
        /// warn when a real (non-loopback) proxy is about to be replaced:
        /// while the block-page proxy is on, that proxy's routing is not in
        /// effect for the apps it served.</summary>
        public static (bool Enabled, string Server) CurrentUserProxy()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
                bool enabled = ((int?)key?.GetValue("ProxyEnable") ?? 0) == 1;
                string server = key?.GetValue("ProxyServer") as string;
                return (enabled, server);
            }
            catch { return (false, null); }   // unreadable settings = nothing to warn about
        }

        /// <summary>Captures the current per-user proxy, journals it, then
        /// points WinINET at the loopback proxy. The journal write happens
        /// BEFORE the first registry mutation (journal-ahead contract).</summary>
        public static void Install(int port)
        {
            var journal = new Journal { Port = port };
            WriteJournal(journal);   // journal exists before any change

            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey))
            {
                if (key != null)
                {
                    journal.ProxyEnableCaptured = true;
                    journal.ProxyEnableBefore = (int?)key.GetValue("ProxyEnable");
                    journal.ProxyServerCaptured = true;
                    journal.ProxyServerBefore = key.GetValue("ProxyServer") as string;
                    journal.ProxyOverrideCaptured = true;
                    journal.ProxyOverrideBefore = key.GetValue("ProxyOverride") as string;
                }
            }
            WriteJournal(journal);

            using (var key = Registry.CurrentUser.CreateSubKey(InternetSettingsKey))
            {
                key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
                key.SetValue("ProxyOverride", "127.0.0.1;localhost;<local>", RegistryValueKind.String);
            }
            BroadcastProxyChanged();
        }

        /// <summary>Restores exactly what was captured (shape-validated), then
        /// deletes the journal. Safe to call with no live journal — a no-op.</summary>
        public static void Undo()
        {
            var journal = ReadJournal();
            if (journal == null) return;
            Undo(journal);
        }

        private static void Undo(Journal journal)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true))
            {
                if (key != null)
                {
                    if (journal.ProxyEnableCaptured)
                    {
                        if (journal.ProxyEnableBefore.HasValue)
                            key.SetValue("ProxyEnable", journal.ProxyEnableBefore.Value, RegistryValueKind.DWord);
                        else
                            key.DeleteValue("ProxyEnable", throwOnMissingValue: false);
                    }

                    if (journal.ProxyServerCaptured)
                    {
                        // A ProxyServer that no longer matches the capture
                        // shape came from a tampered journal — restoring it is
                        // never attempted; the value is cleared instead.
                        string server = journal.ProxyServerBefore != null && ServerShape.IsMatch(journal.ProxyServerBefore)
                            ? journal.ProxyServerBefore
                            : null;
                        if (server != null)
                            key.SetValue("ProxyServer", server, RegistryValueKind.String);
                        else
                            key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                    }

                    if (journal.ProxyOverrideCaptured)
                    {
                        string bypass = journal.ProxyOverrideBefore != null && OverrideShape.IsMatch(journal.ProxyOverrideBefore)
                            ? journal.ProxyOverrideBefore
                            : null;
                        if (bypass != null)
                            key.SetValue("ProxyOverride", bypass, RegistryValueKind.String);
                        else
                            key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
                    }
                }
            }
            BroadcastProxyChanged();
            try { File.Delete(JournalPath); } catch { /* a stuck journal is re-swept at next start */ }
        }

        /// <summary>Crash recovery: undo whatever the journal still describes.
        /// Runs at every app start, before anything else mutates proxy state.</summary>
        public static void RecoverAfterCrash()
        {
            var journal = ReadJournal();
            if (journal == null) return;
            Undo(journal);
        }

        // ── unjournaled straggler sweep ───────────────────────────────────

        /// <summary>
        /// Covers the gap a journal cannot: proxy settings pointing at this
        /// feature's port with NO journal present (a hand-edit, or an undo
        /// that ran while the registry write failed). Only a value that
        /// exactly matches this feature's own loopback:port shape is cleared —
        /// a real local proxy tool the user configured is left alone, and a
        /// port probe decides whether the setting is live. Returns
        /// human-readable repair lines (empty = nothing to do).
        /// </summary>
        public static List<string> RepairIfNeeded(int port)
        {
            var repairs = new List<string>();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
                if (key == null) return repairs;
                string server = key.GetValue("ProxyServer") as string;
                if (server == null || !Regex.IsMatch(server, OwnProxyServerShape(port))) return repairs;

                int enable = (int?)key.GetValue("ProxyEnable") ?? 0;
                bool listening = IsPortListening(port);

                if (listening)
                {
                    // Something serves the port right now. If the block-page
                    // proxy is the thing (the only writer of this exact
                    // shape), the journal will exist too — RestoreJournalless
                    // is only reached when it does not, i.e. a crashed run
                    // whose undo already deleted the journal but whose
                    // registry write half-survived, or an external edit.
                    if (File.Exists(JournalPath)) return repairs;   // RecoverAfterCrash owns it
                    // A live listener this run knows nothing about: leave it.
                    return repairs;
                }

                if (enable == 1)
                {
                    key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                    repairs.Add($"cleared a dead per-user proxy (pointed at {server} with nothing listening)");
                }
                key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                if (repairs.Count == 0)
                    repairs.Add($"removed a stale proxy override value ({server})");
                BroadcastProxyChanged();
            }
            catch { /* repair is best-effort; never block startup */ }
            return repairs;
        }

        private static bool IsPortListening(int port)
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var work = client.ConnectAsync("127.0.0.1", port);
                return work.Wait(300) && client.Connected;
            }
            catch { return false; }
        }

        // ── the refresh broadcast ─────────────────────────────────────────

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        private static void BroadcastProxyChanged()
        {
            try
            {
                InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
                InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
            }
            catch { /* best-effort — apps re-read settings on their own timers */ }
        }
    }
}
