using System;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;

namespace AutoCommand.Services
{
    /// <summary>
    /// Opt-in usage count — the only thing AutoCommand ever sends.
    /// Counts unique installs so the project can show real usage numbers;
    /// there is no other telemetry of any kind.
    ///
    /// Consent model: OFF by default. A one-time dialog (max 3 offers) asks
    /// the user to opt in; "no" is permanent and respected immediately.
    /// State lives in HKCU\Software\AutoCommand\UsagePing (Consent = ask|yes|no,
    /// LastSentDay, Asks, InstallId, ConsentRev) — readable registry policy,
    /// same as every other app setting.
    ///
    /// Payload — the whole thing, nothing else, ever:
    ///   { "a": "autocommand",
    ///     "v": build date, compact (e.g. 261015),
    ///     "o": Windows build,
    ///     "i": random install id }
    /// The id is invented by this app on this machine (a fresh Guid) — it is
    /// NOT derived from the hardware, the Windows account, or the IP address,
    /// and it is never sent or stored alongside anything identifying. Deleting
    /// the registry key withdraws consent AND erases the id; a later opt-in
    /// invents a brand-new id that cannot be linked to the old one. The server
    /// dedupes by this id — one row per unique install, one row per install
    /// per active day — so re-launches, re-unzips, and even a wiped registry
    /// within a day cannot inflate the count. Country is derived at the
    /// network edge and no IP address is ever stored (see telemetry/ in the
    /// repository for the spec, the worker code, and the schema).
    ///
    /// ConsentRev marks which payload shape the user agreed to; "yes" answers
    /// given under an older shape are re-asked once, permanent "no" answers
    /// are never re-asked.
    ///
    /// Endpoint stays empty until the receiver is deployed (telemetry/server);
    /// while empty this whole service is inert — no dialog, no network.
    /// </summary>
    public static class UsagePingService
    {
        // Receiver deployed 2026-10-15 (worker + D1; deploy/hardening notes in
        // telemetry/server/DEPLOY.md, spec in telemetry/USAGE_PING_SPEC.md).
        private const string Endpoint = "https://autocommand-usage-ping.dpark-sports.workers.dev/v1/ping";
        private const string AppName = "autocommand";
        private const int MaxAsks = 3;

        /// <summary>Payload-shape revision the current dialog text describes.
        /// Rev 1: no id at all. Rev 2: adds the random install id ("i"). Bump
        /// whenever the payload or its description changes — stale "yes"
        /// answers are re-asked once; stale "no" answers stay final.</summary>
        private const int CurrentConsentRev = 2;

        private const string RegKey = @"Software\AutoCommand\UsagePing";

        /// <summary>Root of the public community graph page (served by the same
        /// worker — daily actives, countries, download + share links). Null while
        /// Endpoint is unset, so callers fall back to the releases page.</summary>
        public static string GraphPageUrl
        {
            get
            {
                if (string.IsNullOrWhiteSpace(Endpoint) || !Endpoint.StartsWith("https://")) return null;
                int cut = Endpoint.IndexOf('/', "https://".Length);
                return cut < 0 ? Endpoint : Endpoint.Substring(0, cut);
            }
        }

        /// <summary>Stable public download link — what the Share button copies
        /// when the graph page isn't deployed yet.</summary>
        public const string ReleasesUrl = "https://github.com/dparksports/autocommand/releases/latest";

        /// <summary>Startup entry point — call once from App.OnStartup (UI thread).</summary>
        public static async Task RunStartupFlowAsync()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(Endpoint) || !Endpoint.StartsWith("https://"))
                    return; // not configured → fully inert, including the consent dialog

                string consent = ReadString("Consent", "ask");

                // Re-ask once when the payload shape changed after a "yes"
                // (informed consent): rev 2 discloses the random install id.
                // A permanent "no" is never converted back into a question —
                // only the rev marker moves so this check stays cheap.
                if (ReadInt("ConsentRev", 1) < CurrentConsentRev)
                {
                    if (consent == "yes") { WriteString("Consent", "ask"); consent = "ask"; }
                    if (consent == "ask") WriteInt("Asks", 0);
                    WriteInt("ConsentRev", CurrentConsentRev);
                }

                if (consent == "yes")
                {
                    _ = SendDailyPingAsync(); // fire-and-forget; never blocks startup
                    return;
                }

                if (consent == "ask" && ReadInt("Asks", 0) < MaxAsks)
                {
                    // Let the main window settle first so the dialog isn't the
                    // first thing a user sees.
                    await Task.Delay(4000);
                    if (Application.Current?.MainWindow == null) return;

                    WriteInt("Asks", ReadInt("Asks", 0) + 1);
                    var answer = new Views.UsagePingConsentDialog
                    {
                        Owner = Application.Current.MainWindow
                    }.ShowDialog() == true
                        ? ReadString("Consent", "ask")   // dialog wrote the answer itself
                        : "no";

                    if (answer == "yes")
                        _ = SendDailyPingAsync();
                }
            }
            catch { /* never let counting break the app */ }
        }

        /// <summary>Writes the consent answer (yes|no|ask) together with the
        /// payload revision the user saw in the dialog. Public for the consent
        /// dialog and a future Settings toggle.</summary>
        public static void SetConsent(string value)
        {
            if (value != "yes" && value != "no" && value != "ask") return;
            WriteString("Consent", value);
            WriteInt("ConsentRev", CurrentConsentRev);
        }

        /// <summary>Sends today's ping unless one was already sent (UTC day).
        /// The daily gate is client-side (LastSentDay); the server additionally
        /// dedupes per install id per day, so even a wiped registry cannot
        /// double-count a day. The id itself is random and unlinkable —
        /// see the class comment for exactly what that means.</summary>
        public static async Task SendDailyPingAsync()
        {
            try
            {
                string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
                if (ReadString("LastSentDay", "") == today) return;

                var payload = JsonSerializer.Serialize(new
                {
                    a = AppName,
                    v = CompactBuildDate(),
                    o = Environment.OSVersion.Version.ToString(),
                    i = GetOrCreateInstallId()
                });

                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                using var response = await client.PostAsync(Endpoint, content);
                if (response.IsSuccessStatusCode)
                    WriteString("LastSentDay", today);
                // On failure: no state change — retried on a later launch, never spammed.
            }
            catch { /* offline / DNS blocked / endpoint down — silently fine */ }
        }

        /// <summary>The count tracks builds by day, so the ping sends the
        /// version's date in compact form (2026.10.15[.2] → 261015) rather than
        /// the full app version — same-day revisions fold to the same day, by
        /// design. Anything unparseable passes through unchanged.</summary>
        private static string CompactBuildDate()
        {
            string v = Assembly.GetEntryAssembly()?
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion ?? "unknown";
            var m = System.Text.RegularExpressions.Regex.Match(v, @"^(\d{4})\.(\d{2})\.(\d{2})");
            return m.Success
                ? m.Groups[1].Value.Substring(2) + m.Groups[2].Value + m.Groups[3].Value
                : v;
        }

        /// <summary>Random, locally-invented install id (32 hex chars) — the
        /// "i" field. Created on first send, stored in the same registry key.
        /// Deliberately NOT derived from hardware, the Windows account, the
        /// install folder, or the IP address, and never paired with anything
        /// identifying, so the server can count unique installs without ever
        /// learning who an install belongs to. Deleting the registry key
        /// erases it; a re-consent invents a fresh id with no link to the old.</summary>
        private static string GetOrCreateInstallId()
        {
            string id = ReadString("InstallId", "");
            if (!System.Text.RegularExpressions.Regex.IsMatch(id ?? "", "^[0-9a-f]{32}$"))
            {
                id = Guid.NewGuid().ToString("N");
                WriteString("InstallId", id);
            }
            return id;
        }

        // ── HKCU persistence (same store and style as ThemeService) ──

        private static Microsoft.Win32.RegistryKey OpenKey(bool writable = true)
        {
            using var root = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\AutoCommand", writable);
            return root?.CreateSubKey("UsagePing", writable: writable);
        }

        private static string ReadString(string name, string fallback)
        {
            try { using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegKey);
                  return (string)k?.GetValue(name) ?? fallback; }
            catch { return fallback; }
        }

        private static int ReadInt(string name, int fallback)
        {
            return int.TryParse(ReadString(name, null), out var v) ? v : fallback;
        }

        private static void WriteString(string name, string value)
        {
            try { using var k = OpenKey(); k?.SetValue(name, value); } catch { }
        }

        private static void WriteInt(string name, int value) => WriteString(name, value.ToString());
    }
}
