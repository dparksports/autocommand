using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutoCommand.Contain.Core
{
    /// <summary>One service entry of the release's included list. The
    /// identity is the portable kind — a Windows service name means the
    /// same thing on every machine, unlike the ledger's IP and exe-path
    /// keys. Since is the seed version that introduced the entry: it is
    /// the tombstone. The version gate never re-applies an entry at or
    /// below the version a store already processed, so a user who
    /// released a seeded block keeps it released — even when a later
    /// release still carries the same entry.</summary>
    public sealed record SeedServiceEntry(string ServiceKey, string DisplayName, int Since);

    /// <summary>One domain entry of the included list, before it lands in
    /// the domain store (where DomainBlockSyncService keeps its IP rules
    /// current across CDN rotation).</summary>
    public sealed record SeedDomainEntry(string Domain, string Note, int Since);

    /// <summary>What one import pass did. Version is the seed version the
    /// store now counts as processed — held back when a service block
    /// failed, so the next launch retries exactly the unapplied tail.</summary>
    public sealed record SeedApplyResult(int DomainsApplied, int ServicesApplied, int ServicesFailed, int Version);

    /// <summary>
    /// The included list: each release ships the curated portable
    /// projection of the block collection — the identities that mean the
    /// same thing on every machine (domain names, Windows service
    /// names). The raw ledger does not travel: IP keys rotate under CDNs
    /// (DomainBlockSyncService exists precisely for that) and proc keys
    /// are absolute paths.
    ///
    /// Import rules, in priority order:
    ///   · gap-fill only — an identity the user already has a decision
    ///     for (any origin, any state) is never touched; the user's
    ///     decision outranks the ship.
    ///   · additive only — the import never removes anything. Releasing
    ///     a seeded block is the user's call and stays made.
    ///   · the version gate — each entry carries the seed version that
    ///     introduced it (its Since); a store that processed version N
    ///     never re-processes entries with Since ≤ N. State lives in
    ///     seed-state.json next to the stores. This is why removals
    ///     survive updates without tombstone files.
    ///   · never break startup — every failure is counted, not thrown.
    ///     A failed service block holds the version back so the next
    ///     launch retries it; domain gap-fill makes that retry's domain
    ///     half a no-op.
    ///
    /// Service blocks go straight to the engine — one idempotent
    /// service-scoped rule each (AC-BLOCK-SVC naming) — and are skipped
    /// when any rule already exists, so a paused block stays paused and
    /// a user's own block is never re-described or re-enabled. Domain
    /// blocks land through DomainBlockSyncService.ImportSeedDomains and
    /// the domain sync pass then materializes and maintains their IP
    /// rules. The ledger rows for seeded service blocks are re-derived
    /// from the live rules by the reconcile pass on the next session
    /// (svc rows are session-derived — see BlocksView's inventory
    /// adoption), with the rule description carrying the provenance.
    /// </summary>
    public static class SeedImporter
    {
        private const string DomainsResource = "AutoCommand.Assets.SeedDomains.jsonl";
        private const string ServicesResource = "AutoCommand.Assets.SeedServices.txt";
        private const string StateFileName = "seed-state.json";

        // ── test seams (null = the real half; house pattern) ─────────────
        internal static Func<string> DomainsContent;
        internal static Func<string> ServicesContent;
        internal static Func<string> StateDirectory;
        internal static Func<string, Task<int>> ServiceBlockState;
        internal static Func<string, string, Task<string>> AddServiceBlock;
        internal static Func<Task> SyncKick;

        /// <summary>Read the two embedded seed files and apply whatever
        /// the version gate admits. Never throws and never blocks
        /// startup: callers run it fire-and-forget.</summary>
        public static async Task<SeedApplyResult> ApplyIncludedListAsync()
        {
            int priorVersion = ReadStateVersion();
            try
            {
                var domains = ParseDomains(
                    DomainsContent?.Invoke() ?? EmbeddedContent(DomainsResource));
                var services = ParseServices(
                    ServicesContent?.Invoke() ?? EmbeddedContent(ServicesResource));

                int seedVersion = 0;
                foreach (var d in domains) seedVersion = Math.Max(seedVersion, d.Since);
                foreach (var s in services) seedVersion = Math.Max(seedVersion, s.Since);

                // The common path after the first launch of a release:
                // this store already processed everything the files carry.
                if (seedVersion <= priorVersion)
                    return new SeedApplyResult(0, 0, 0, priorVersion);

                int domainsApplied = 0, servicesApplied = 0, servicesFailed = 0;

                var freshDomains = domains.Where(d => d.Since > priorVersion).ToList();
                if (freshDomains.Count > 0)
                    domainsApplied = DomainBlockSyncService.Instance.ImportSeedDomains(
                        freshDomains.Select(d => (d.Domain, d.Note)));

                foreach (var e in services.Where(s => s.Since > priorVersion))
                {
                    try
                    {
                        int state = ServiceBlockState != null
                            ? await ServiceBlockState(e.ServiceKey)
                            : await FirewallService.Instance.GetServiceBlockStateAsync(e.ServiceKey);
                        if (state != 0) continue;   // a rule exists — user's block or paused seed: hands off

                        string description = $"AutoCommand Included List — {e.DisplayName} (seed v{e.Since})";
                        if (AddServiceBlock != null) await AddServiceBlock(e.ServiceKey, description);
                        else await FirewallService.Instance.AddServiceBlockAsync(e.ServiceKey, description);
                        servicesApplied++;
                    }
                    catch { servicesFailed++; }   // counted, not thrown — the header explains why
                }

                // A failed service block keeps the old version so the next
                // launch retries exactly the unapplied tail.
                int appliedVersion = servicesFailed == 0 ? seedVersion : priorVersion;
                WriteStateVersion(appliedVersion);

                if (domainsApplied > 0)
                {
                    var kick = SyncKick ?? (() => DomainBlockSyncService.Instance.SyncAllAsync());
                    _ = Task.Run(async () => { try { await kick(); } catch { /* the cadence retries */ } });
                }

                return new SeedApplyResult(domainsApplied, servicesApplied, servicesFailed, appliedVersion);
            }
            catch
            {
                // A packaging bug or an unreadable disk must never break
                // startup; the next launch re-runs the whole gated pass.
                return new SeedApplyResult(0, 0, 0, priorVersion);
            }
        }

        // ── parsing (internal for the self-test's shipped-file check) ────

        internal static List<SeedDomainEntry> ParseDomains(string content)
        {
            var list = new List<SeedDomainEntry>();
            if (string.IsNullOrWhiteSpace(content)) return list;
            foreach (string raw in content.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                try
                {
                    // case-insensitive on purpose: a human curates this file,
                    // camelCase or PascalCase keys both parse (STJ is
                    // case-sensitive by default — the silent-skip trap)
                    var d = JsonSerializer.Deserialize<SeedDomainLine>(line,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (d == null || !DomainBlockSyncService.IsValidDomain(d.Domain)) continue;
                    list.Add(new SeedDomainEntry(
                        d.Domain.Trim().TrimEnd('.').ToLowerInvariant(),
                        d.Note ?? "",
                        Math.Max(1, d.Since)));
                }
                catch { }   // one bad line never kills the batch
            }
            return list;
        }

        internal static List<SeedServiceEntry> ParseServices(string content)
        {
            var list = new List<SeedServiceEntry>();
            if (string.IsNullOrWhiteSpace(content)) return list;
            foreach (string raw in content.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] p = line.Split('|');
                if (p.Length < 3) continue;
                string key = p[0].Trim().ToLowerInvariant();
                if (key.Length == 0) continue;
                if (!int.TryParse(p[2].Trim(), out int since) || since < 1) continue;
                list.Add(new SeedServiceEntry(key, p[1].Trim(), since));
            }
            return list;
        }

        internal static string EmbeddedContent(string resourceName)
        {
            var assembly = typeof(SeedImporter).Assembly;
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
                throw new InvalidOperationException($"Embedded resource {resourceName} not found.");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        private sealed record SeedDomainLine(string Domain, string Note, int Since);

        // ── the version gate: seed-state.json, next to the stores ────────

        private static string StatePath => Path.Combine(
            StateDirectory?.Invoke() ?? BlocksLedger.DefaultDirectory, StateFileName);

        private static int ReadStateVersion()
        {
            try
            {
                if (!File.Exists(StatePath)) return 0;
                return JsonSerializer.Deserialize<SeedState>(File.ReadAllText(StatePath))?.Version ?? 0;
            }
            catch { return 0; }   // unreadable state = the seed re-applies; gap-fill makes that safe
        }

        private static void WriteStateVersion(int version)
        {
            try
            {
                string dir = Path.GetDirectoryName(StatePath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(StatePath, JsonSerializer.Serialize(
                    new SeedState { Version = version, AppliedUtc = DateTime.UtcNow }));
            }
            catch { }   // a failed state write re-runs the pass next launch; gap-fill makes it safe
        }

        private sealed class SeedState
        {
            public int Version { get; set; }
            public DateTime AppliedUtc { get; set; }
        }
    }
}
