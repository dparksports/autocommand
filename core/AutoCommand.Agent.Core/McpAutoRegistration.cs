using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AutoCommand.Engines.Bridge;

namespace AutoCommand.Agent.Core
{
    /// <summary>
    /// One consent, then zero-touch MCP registration (Be My Guest tab).
    ///
    /// Modes, persisted beside session.json in agent\auto-register.json:
    ///   "ask"  (no file / unreadable) — offer the consent dialog when a
    ///          session starts and unregistered clients exist
    ///   "auto" — consented once: register detected clients now, and the
    ///          startup self-heal re-points registrations whose proxy moved
    ///          or died (mode is the ONLY trigger — nothing ever writes a
    ///          client config without it or an explicit button click)
    ///   "off"  — never ask again (the dialog's Cancel)
    ///
    /// Notification contract for the self-heal (the "is the user aware?"
    /// design): a SUCCESSFUL repair is never a modal — it gets the status
    /// line on the Be My Guest tab (StatusLine) and a timestamped JSONL
    /// event per pass (agent\registration-events.jsonl, house persistence
    /// pattern) recording every client touched, old → new path and outcome
    /// — the durable "what was done". A FAILED repair stays on-screen:
    /// Failures() feeds the tab's warning line, and the manual Refresh
    /// path remains the exit. Nothing is ever swallowed silently.
    /// </summary>
    public static class McpAutoRegistration
    {
        // ── consent ──────────────────────────────────────────────────────

        private static string AgentDir => AgentBridgeService.AgentDir;
        private static string ModePath => Path.Combine(AgentDir, "auto-register.json");
        private static string EventsPath => Path.Combine(AgentDir, "registration-events.jsonl");

        public static string GetMode()
        {
            try
            {
                if (File.Exists(ModePath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(ModePath));
                    if (doc.RootElement.TryGetProperty("mode", out var m))
                    {
                        var v = m.GetString();
                        if (v == "auto" || v == "off") return v;
                    }
                }
            }
            catch { /* unreadable consent file = ask again */ }
            return "ask";
        }

        public static void SetMode(string mode)
        {
            try
            {
                Directory.CreateDirectory(AgentDir);
                File.WriteAllText(ModePath, JsonSerializer.Serialize(new { mode }));
            }
            catch { /* consent persistence is best-effort; the session works regardless */ }
        }

        // ── population + bulk register ───────────────────────────────────

        /// <summary>Detected clients with no 'autocommand' entry yet — the
        /// population the consent dialog offers to wire up.</summary>
        public static List<McpClientRegistration> UnregisteredDetectedClients()
        {
            var list = new List<McpClientRegistration>();
            foreach (var c in McpClientCatalog.Catalog)
            {
                try { if (McpClientCatalog.IsDetected(c) && !McpClientCatalog.IsRegistered(c)) list.Add(c); }
                catch { /* one unreadable config never blocks the rest */ }
            }
            return list;
        }

        /// <summary>The zero-touch path after consent: resolve → preflight →
        /// register every detected client. Same preflight rule as a manual
        /// Register click — never point a config at an unproven proxy.</summary>
        public static (List<RegistrationOutcome> Outcomes, string Error) RegisterAllDetected()
        {
            var (proxy, installNote) = McpClientCatalog.ResolveAndInstallProxy();
            if (proxy == null) return (null, installNote);
            var (preOk, preMsg) = McpClientCatalog.PreflightProxy(proxy);
            if (!preOk) return (null, preMsg);
            return (McpClientCatalog.RegisterDetectedClients(proxy), null);
        }

        // ── startup self-heal + its notifications ────────────────────────

        /// <summary>One repair pass: what was stale, what was fixed, what
        /// refused — everything the status line and the JSONL event carry.</summary>
        public sealed class RepairReport
        {
            public DateTime AtUtc { get; set; }
            public int StaleFound { get; set; }
            public int Repaired { get; set; }
            public List<string> RepairedClients { get; set; } = new();
            public List<string> FailedClients { get; set; } = new();   // "DisplayName: reason"
            public string ProxyPath { get; set; }
        }

        private static readonly object _gate = new();
        private static RepairReport _lastReport;

        /// <summary>The newest repair outcome (this run, else re-read from the
        /// events file) — null when no repair ever ran.</summary>
        public static RepairReport LastRepair
        {
            get { lock (_gate) { return _lastReport ??= LoadLastEvent(); } }
        }

        /// <summary>
        /// App-startup self-heal (mode=auto only): re-point registrations
        /// whose proxy moved or died at the stable junction path. Runs the
        /// same resolve → preflight → Register discipline as every manual
        /// click, records the JSONL event, caches the report for the tab.
        /// Returns the report (null when mode != auto or nothing to do).
        /// </summary>
        public static RepairReport RunStartupRepair()
        {
            if (GetMode() != "auto") return null;
            try
            {
                var (proxy, _) = McpClientCatalog.ResolveAndInstallProxy();
                if (proxy == null) return RecordNoRepair(null);
                var stale = McpClientCatalog.FindStaleRegistrations(proxy);
                if (stale.Count == 0) return RecordNoRepair(proxy);

                var report = new RepairReport { AtUtc = DateTime.UtcNow, StaleFound = stale.Count, ProxyPath = proxy };
                var (preOk, preMsg) = McpClientCatalog.PreflightProxy(proxy);
                if (!preOk)
                {
                    report.FailedClients.AddRange(stale.Select(s =>
                        s.Client.DisplayName + ": proxy preflight failed — " + preMsg.Split('\n')[0]));
                    return Record(report);
                }
                foreach (var s in stale)
                {
                    var (ok, msg) = McpClientCatalog.Register(s.Client, proxy);
                    if (ok) { report.Repaired++; report.RepairedClients.Add(s.Client.DisplayName); }
                    else report.FailedClients.Add(s.Client.DisplayName + ": " + (msg ?? "").Split('\n')[0]);
                }
                return Record(report);
            }
            catch (Exception ex)
            {
                return Record(new RepairReport
                {
                    AtUtc = DateTime.UtcNow,
                    FailedClients = { "self-heal error: " + ex.Message },
                });
            }
        }

        private static RepairReport RecordNoRepair(string proxy) =>
            Record(new RepairReport { AtUtc = DateTime.UtcNow, ProxyPath = proxy });

        private static RepairReport Record(RepairReport report)
        {
            lock (_gate) _lastReport = report;
            try
            {
                Directory.CreateDirectory(AgentDir);
                File.AppendAllText(EventsPath, JsonSerializer.Serialize(report) + Environment.NewLine);
            }
            catch { /* the events file is best-effort; the in-memory report still feeds the tab */ }
            return report;
        }

        private static RepairReport LoadLastEvent()
        {
            try
            {
                if (!File.Exists(EventsPath)) return null;
                var last = File.ReadLines(EventsPath).LastOrDefault(l => !string.IsNullOrWhiteSpace(l));
                return last == null ? null : JsonSerializer.Deserialize<RepairReport>(last);
            }
            catch { return null; }
        }

        /// <summary>
        /// The Be My Guest status line (refreshed by the tab's 2s timer):
        /// the quiet "kept current" note after a successful repair, the
        /// LOUD refusal line when one failed, null when there is nothing
        /// to say. Success never interrupts; failure never disappears.
        /// </summary>
        public static string StatusLine()
        {
            var r = LastRepair;
            if (r == null) return null;
            string when = r.AtUtc.ToLocalTime().ToString("HH:mm");
            if (r.FailedClients.Count > 0)
                return "⚠ Auto-repair could not refresh " + r.FailedClients.Count +
                       " registration(s) at " + when + " — " + string.Join("; ", r.FailedClients) +
                       ". Use the Refresh button above.";
            if (r.Repaired > 0)
                return "Auto-repair kept " + r.Repaired + " assistant registration" +
                       (r.Repaired == 1 ? "" : "s") + " current with this install (" + when + ")." +
                       " Details: " + EventsPath;
            return null; // nothing stale, nothing done — silence
        }
    }
}
