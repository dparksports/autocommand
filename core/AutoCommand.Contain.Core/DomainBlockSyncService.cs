using System;
using AutoCommand.Contain.Core;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// Domain blocks that survive the internet's plumbing. Windows Firewall
    /// rules address IPs, and today's services live on CDNs whose answer sets
    /// rotate by the minute — the exact failure this service exists for: an
    /// ISO download host resolving to 199.232.x.x edges that a pinned-IP
    /// blocklist caught yesterday and missed today. The fix is to let the
    /// user think in domains and keep the IP rules current behind the scenes:
    ///
    ///   · the user maintains a plain list of blocked domains (managed in the
    ///     Blocks tab's Domain blocks window);
    ///   · a sync pass (metronome instrument `domain-dns-sync`, plus once at
    ///     startup) fresh-resolves every domain and reconciles the live
    ///     AC-BLOCK-IP rules: new addresses get 2-rule blocks with a
    ///     sync-marker provenance; addresses that rotated away get their
    ///     sync-created rules retired;
    ///   · retirement goes through the engine's marker-checked
    ///     RemoveOwnRuleByNameAsync — an IP the user ALSO blocked by hand
    ///     (the engine's idempotency key is the rule name, so both writes
    ///     land on the same rule) is never deleted by a rotation: the
    ///     marker check disowns it and the manual block survives;
    ///   · an IP that is already blocked before the sync ever reaches it is
    ///     adopted as covered, not owned — the sync creates no rule and has
    ///     nothing to retire later, so the original block's provenance stays.
    ///
    /// Every create/remove is a BlocksStore ledger event under origin
    /// `domain-sync`, so the Audit tab tells the whole story of why an IP
    /// rule exists and which domain put it there.
    /// </summary>
    public sealed class DomainBlockSyncService
    {
        public static DomainBlockSyncService Instance => _instance ??= new DomainBlockSyncService();
        private static DomainBlockSyncService _instance;

        private static readonly TimeSpan InventoryTtl = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan NegativeCache = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan FirstSyncDelay = TimeSpan.FromSeconds(20);

        /// <summary>One user-maintained domain block.</summary>
        public sealed class DomainBlock
        {
            public string Domain { get; set; }
            public DateTime AddedUtc { get; set; }
            public string Origin { get; set; }   // "blocks-tab" | "mcp" | "repair" | …
            public string Note { get; set; }
        }

        /// <summary>The provenance marker written into every rule description
        /// this service creates, and the ownership proof its removals require
        /// (stable across refreshes — the [blocked … UTC] prefix is not).</summary>
        internal static string MarkerFor(string domain) =>
            $"domain block {domain} · AutoCommand DomainBlockSync";

        private readonly object _gate = new();
        // The blocks ledger, constructor-injected with this service's
        // (settable) StoreDirectory — the DI-pilot instance form, not the
        // static facade: a self-test that overrides StoreDirectory must
        // never touch the real user store. Lazy because StoreDirectory is
        // settable until first use. In the app both land on the same
        // %LOCALAPPDATA%\AutoCommand files, so records converge; each
        // instance Load()s before Save(), and the only overlap risk is a
        // millisecond-scale read-modify-write race on the snapshot file
        // between this cadence and a user action — the append-only event
        // ledger never loses lines.
        private BlocksLedger _ledger;
        private BlocksLedger Ledger => _ledger ??= new BlocksLedger(StoreDirectory);
        private readonly List<DomainBlock> _blocks = new();
        // domain → (ip → exact rule names this service created and owns)
        private readonly Dictionary<string, Dictionary<string, string[]>> _owned =
            new(StringComparer.OrdinalIgnoreCase);
        // domain → IPs currently covered by SOMEONE ELSE's rule (adopted, never retired by us)
        private readonly Dictionary<string, HashSet<string>> _coveredExternally =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTime> _lastResolveFailure =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, Task> _inFlight = new(StringComparer.OrdinalIgnoreCase);
        private DateTime _inventoryAtUtc = DateTime.MinValue;
        private List<BlockedTarget> _inventory;
        private bool _running, _dirty, _mapDirty;

        /// <summary>Settable for offline self-tests (house pattern).</summary>
        public static string StoreDirectory { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand");

        private static string BlocksStorePath => Path.Combine(StoreDirectory, "domain-blocks.jsonl");
        private static string MapStorePath => Path.Combine(StoreDirectory, "domain-ip-map.json");

        // ── engine seams (null = the real firewall engine; tests inject) ──
        internal static Func<string, Task<IPAddress[]>> Resolver;
        internal static Func<string, string, Task<(int Created, int Updated, string[] RuleNames)>> AddIpBlock;
        internal static Func<string, string, Task<int>> RemoveRuleByName;
        /// <summary>Blocked-inventory seam: the real channel is live firewall
        /// COM — the offline self-test pins it synthetic.</summary>
        internal static Func<Task<List<BlockedTarget>>> Inventory;

        /// <summary>Raised after create/remove passes so the app wiring can
        /// adopt new rule names into the firewall baseline and refresh views
        /// (Contain.Core must not reach into app helpers directly).</summary>
        public event Action<string[]> RulesCreated;
        public event Action BlocksChanged;

        public int Count { get { lock (_gate) return _blocks.Count; } }

        private DomainBlockSyncService() { }

        /// <summary>Idempotent. Loads both stores and kicks one background
        /// sync — the startup reconcile that catches rotations while the app
        /// was closed (the gates-reconcile pattern).</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_running) return;
                _running = true;
            }
            Load();
            _ = Task.Run(async () =>
            {
                await Task.Delay(FirstSyncDelay);   // let startup's DNS landscape settle
                await SyncAllAsync();
            });
        }

        // ── the user-facing list ──────────────────────────────────────────

        public List<DomainBlock> All()
        {
            lock (_gate) return _blocks.Select(b => new DomainBlock
            {
                Domain = b.Domain,
                AddedUtc = b.AddedUtc,
                Origin = b.Origin,
                Note = b.Note,
            }).ToList();
        }

        /// <summary>The rules this service currently owns per domain, for UI
        /// display ("3 IPs · 6 rules held").</summary>
        public (int Ips, int Rules) OwnedFor(string domain)
        {
            lock (_gate)
            {
                if (!_owned.TryGetValue(domain, out var ips)) return (0, 0);
                return (ips.Count, ips.Values.Sum(r => r?.Length ?? 0));
            }
        }

        public static bool IsValidDomain(string candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate)) return false;
            string d = candidate.Trim().TrimEnd('.');
            if (d.Length == 0 || d.Length > 253 || !d.Contains('.')) return false;
            return Uri.CheckHostName(d) == UriHostNameType.Dns;
        }

        /// <summary>Add (idempotent on exact normalized name) and sync it
        /// immediately so the user sees rules materialize within seconds.
        /// Returns false when the name is not a valid DNS hostname.</summary>
        public async Task<bool> AddAsync(string domain, string origin = "blocks-tab", string note = null)
        {
            if (!IsValidDomain(domain)) return false;
            string d = domain.Trim().TrimEnd('.').ToLowerInvariant();

            bool added;
            lock (_gate)
            {
                if (_blocks.Any(b => b.Domain.Equals(d, StringComparison.OrdinalIgnoreCase))) return true;
                _blocks.Add(new DomainBlock { Domain = d, AddedUtc = DateTime.UtcNow, Origin = origin, Note = note });
                added = true;
                _dirty = true;
            }
            if (added)
            {
                SaveIfDirty();
                Ledger.AppendEvent("created", "domain", d, $"domain block added ({origin})", origin);
            }
            await SyncOneAsync(d);
            BlocksChanged?.Invoke();
            return true;
        }

        /// <summary>Remove a domain block and retire every rule it created
        /// (marker-checked — see the engine member). Manual blocks on the
        /// same IPs are never touched.</summary>
        public async Task<bool> RemoveAsync(string domain, string origin = "blocks-tab")
        {
            string d = (domain ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            Dictionary<string, string[]> owned;
            lock (_gate)
            {
                var block = _blocks.FirstOrDefault(b => b.Domain.Equals(d, StringComparison.OrdinalIgnoreCase));
                if (block == null) return false;
                _blocks.Remove(block);
                _owned.TryGetValue(d, out owned);
                _owned.Remove(d);
                _coveredExternally.Remove(d);
                _dirty = true; _mapDirty = true;
            }

            int retired = 0;
            if (owned != null)
            {
                foreach (var (ip, ruleNames) in owned)
                {
                    foreach (string name in ruleNames ?? Array.Empty<string>())
                    {
                        try
                        {
                            int removed = await RemoveEngineAsync(name, MarkerFor(d));
                            if (removed > 0)
                            {
                                retired += removed;
                                Ledger.AppendEvent("removed", "ip", ip,
                                    $"domain block {d} removed · rule {name}", origin);
                            }
                        }
                        catch { /* next rule; the next sync retries strays */ }
                    }
                    if (retired > 0) Ledger.Remove("ip", ip, origin);
                }
            }
            SaveIfDirty();
            Ledger.AppendEvent("removed", "domain", d, $"domain block removed · {retired} rule(s) retired", origin);
            if (retired > 0) RulesCreated?.Invoke(Array.Empty<string>());   // baseline re-read signal
            BlocksChanged?.Invoke();
            return true;
        }

        // ── the sync pass ─────────────────────────────────────────────────

        /// <summary>The metronome callback: reconcile every domain. Per-domain
        /// in-flight guards collapse overlapping ticks; one domain's failure
        /// never stops the others.</summary>
        public async Task SyncAllAsync()
        {
            string[] domains;
            lock (_gate) domains = _blocks.Select(b => b.Domain).ToArray();
            if (domains.Length == 0) return;

            var passes = domains.Select(d => (Task)_inFlight.GetOrAdd(
                d, _ => Task.Run(() => SyncOneGuardedAsync(d)))).ToList();
            await Task.WhenAll(passes);
            BlocksChanged?.Invoke();
        }

        private async Task SyncOneGuardedAsync(string domain)
        {
            try { await SyncOneAsync(domain); }
            catch { /* this pass failed; the next cadence retries */ }
            finally { _inFlight.TryRemove(domain, out _); }
        }

        /// <summary>Reconcile one domain's IP rules against its current DNS
        /// answers. Add side: create what is missing (unless already covered
        /// by a foreign rule — adopted, not owned). Remove side: retire owned
        /// rules for IPs no longer answering; disown silently when the marker
        /// check finds a manual rule in the name's place.</summary>
        internal async Task SyncOneAsync(string domain)
        {
            // Negative-cached failures keep an NXDOMAIN domain from hammering
            // resolvers every tick; a fresh answer clears it.
            if (_lastResolveFailure.TryGetValue(domain, out var failedAt)
                && DateTime.UtcNow - failedAt < NegativeCache)
                return;

            var desired = await ResolveAsync(domain);
            if (desired == null)
            {
                _lastResolveFailure[domain] = DateTime.UtcNow;
                return;
            }
            _lastResolveFailure.TryRemove(domain, out _);

            var inventory = await GetInventoryCachedAsync();
            List<string[]> adoptedRules = new();

            lock (_gate)
            {
                if (!_blocks.Any(b => b.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)))
                    return;   // removed while we were resolving — do not resurrect
            }

            // desired IP set, normalized (the resolver can hand back IPv6
            // forms for A-record questions and vice versa)
            var wanted = desired
                .Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
                .Select(a => a.ToString())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            Dictionary<string, string[]> ownedSnapshot;
            HashSet<string> externalSnapshot;
            lock (_gate)
            {
                if (_owned.TryGetValue(domain, out var live))
                    ownedSnapshot = new Dictionary<string, string[]>(live, StringComparer.OrdinalIgnoreCase);
                else
                    ownedSnapshot = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                _coveredExternally.TryGetValue(domain, out externalSnapshot);
                externalSnapshot ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            // ── add side ─────────────────────────────────────────────────
            foreach (string ip in wanted)
            {
                if (ownedSnapshot.ContainsKey(ip) || externalSnapshot.Contains(ip)) continue;

                // Already blocked by someone else's rule? Adopt as covered —
                // creating our own would share the rule name (the engine's
                // idempotency key) and overwrite that rule's provenance.
                var existing = inventory?.FirstOrDefault(t =>
                    t.Kind == "ip" && t.Ip.Equals(ip, StringComparison.OrdinalIgnoreCase));
                if (existing != null && existing.EnabledRules > 0)
                {
                    lock (_gate)
                    {
                        if (_coveredExternally.TryGetValue(domain, out var set)) set.Add(ip);
                    }
                    Ledger.AppendEvent("adopted", "ip", ip,
                        $"domain block {domain} covered by existing rule", "domain-sync");
                    continue;
                }

                try
                {
                    string desc = $"[blocked {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC] {MarkerFor(domain)} — " +
                                  $"DNS-sync kept current for blocked domain {domain}";
                    var (created, updated, ruleNames) = await AddEngineAsync(ip, desc);
                    if (ruleNames == null || ruleNames.Length == 0) continue;

                    bool fresh = created > 0;
                    lock (_gate)
                    {
                        if (_owned.TryGetValue(domain, out var ips)) ips[ip] = ruleNames;
                        else _owned[domain] = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                        {
                            [ip] = ruleNames,
                        };
                        _mapDirty = true;
                    }
                    adoptedRules.Add(ruleNames);

                    var record = new BlockRecord
                    {
                        Kind = "ip",
                        Key = ip,
                        ProcessName = "",
                        CreatedUtc = DateTime.UtcNow,
                        ServiceKey = "",
                        SvcDisplayName = "",
                        ClassAtBlock = IpClassifier.Classify(ip),
                        Origin = "domain-sync",
                        Attrib = "none",
                        Status = "on",
                        StatusUtc = DateTime.UtcNow,
                    };
                    Ledger.AddOrUpdate(record, "domain-sync");
                    Ledger.AppendEvent("created", "ip", ip,
                        $"{(fresh ? "created" : "refreshed")} for domain block {domain}", "domain-sync");
                }
                catch { /* this IP's rules failed; the next pass retries it */ }
            }

            // ── remove side ──────────────────────────────────────────────
            string marker = MarkerFor(domain);
            foreach (var (ip, ruleNames) in ownedSnapshot)
            {
                if (wanted.Contains(ip)) continue;
                bool allGone = true;
                int retiredForIp = 0;
                foreach (string name in ruleNames ?? Array.Empty<string>())
                {
                    try
                    {
                        int removed = await RemoveEngineAsync(name, marker);
                        if (removed > 0)
                        {
                            retiredForIp += removed;
                            Ledger.AppendEvent("removed", "ip", ip,
                                $"IP rotated out of {domain} · rule {name} retired", "domain-sync");
                        }
                        else
                        {
                            // marker gone = a manual re-block owns the rule now:
                            // it stays, we just stop tracking it
                            allGone = false;
                            Ledger.AppendEvent("disowned", "ip", ip,
                                $"rule {name} no longer domain-sync's — manual block preserved", "domain-sync");
                        }
                    }
                    catch { allGone = false; /* retry next pass */ }
                }
                lock (_gate)
                {
                    if (_owned.TryGetValue(domain, out var ips)) ips.Remove(ip);
                    _mapDirty = true;
                }
                if (allGone && retiredForIp > 0) Ledger.Remove("ip", ip, "domain-sync");
            }

            SaveIfDirty();
            if (adoptedRules.Count > 0)
                RulesCreated?.Invoke(adoptedRules.SelectMany(r => r).ToArray());
        }

        private async Task<IPAddress[]> ResolveAsync(string domain)
        {
            try
            {
                var resolve = Resolver ?? (d => Dns.GetHostAddressesAsync(d));
                var work = resolve(domain);
                var done = await Task.WhenAny(work, Task.Delay(TimeSpan.FromSeconds(6)));
                if (done != work) return null;
                var ips = work.Result;
                return ips != null && ips.Length > 0 ? ips : null;
            }
            catch { return null; }   // NXDOMAIN / resolver down — negative cache above
        }

        private async Task<List<BlockedTarget>> GetInventoryCachedAsync()
        {
            lock (_gate)
            {
                // the cache exists for the real engine's COM cost — a test
                // seam changes answers between calls, so it bypasses the TTL
                if (Inventory == null && _inventory != null && DateTime.UtcNow - _inventoryAtUtc < InventoryTtl)
                    return _inventory;
            }
            try
            {
                List<BlockedTarget> fresh = Inventory != null
                    ? await Inventory()
                    : (await FirewallService.Instance.GetBlockedInventoryAsync()).ToList();
                lock (_gate)
                {
                    _inventory = fresh;
                    _inventoryAtUtc = DateTime.UtcNow;
                }
                return fresh;
            }
            catch { return null; }   // inventory unavailable → treat as no foreign coverage
        }

        private static async Task<(int, int, string[])> AddEngineAsync(string ip, string description)
        {
            if (AddIpBlock != null) return await AddIpBlock(ip, description);
            var (created, updated, ruleNames) =
                await FirewallService.Instance.AddIpBlockWithRulesAsync(ip, description);
            return (created, updated, ruleNames);
        }

        private static async Task<int> RemoveEngineAsync(string ruleName, string marker)
        {
            if (RemoveRuleByName != null) return await RemoveRuleByName(ruleName, marker);
            return await FirewallService.Instance.RemoveOwnRuleByNameAsync(ruleName, marker);
        }

        // ── persistence (house JSONL/JSON patterns, atomic rewrites) ─────

        public List<string> OwnedRuleNamesForTests()
        {
            lock (_gate) return _owned.Values.SelectMany(d => d.Values.SelectMany(r => r ?? Array.Empty<string>())).ToList();
        }

        private void Load()
        {
            try
            {
                if (File.Exists(BlocksStorePath))
                {
                    lock (_gate)
                    {
                        foreach (string line in File.ReadLines(BlocksStorePath))
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            var b = JsonSerializer.Deserialize<DomainBlock>(line);
                            if (!string.IsNullOrEmpty(b?.Domain)) _blocks.Add(b);
                        }
                    }
                }
                if (File.Exists(MapStorePath))
                {
                    var map = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string[]>>>(
                        File.ReadAllText(MapStorePath));
                    lock (_gate)
                    {
                        foreach (var (domain, ips) in map ?? new())
                        {
                            if (ips == null) continue;
                            _owned[domain] = new Dictionary<string, string[]>(ips, StringComparer.OrdinalIgnoreCase);
                        }
                    }
                }
            }
            catch { /* unreadable stores start fresh; rules live in the firewall anyway */ }
        }

        private void SaveIfDirty()
        {
            List<DomainBlock> blocks;
            Dictionary<string, Dictionary<string, string[]>> map;
            bool wasDirty, wasMapDirty;
            lock (_gate)
            {
                if (!_dirty && !_mapDirty) return;
                blocks = _blocks.ToList();
                map = _owned.ToDictionary(
                    d => d.Key,
                    d => new Dictionary<string, string[]>(d.Value, StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase);
                wasDirty = _dirty; wasMapDirty = _mapDirty;
                _dirty = false; _mapDirty = false;
            }
            try
            {
                Directory.CreateDirectory(StoreDirectory);
                if (wasDirty)
                {
                    string tmp = BlocksStorePath + ".tmp";
                    using (var w = new StreamWriter(tmp))
                        foreach (var b in blocks) w.WriteLine(JsonSerializer.Serialize(b));
                    File.Delete(BlocksStorePath);
                    File.Move(tmp, BlocksStorePath);
                }
                if (wasMapDirty)
                {
                    string tmpMap = MapStorePath + ".tmp";
                    File.WriteAllText(tmpMap, JsonSerializer.Serialize(map));
                    File.Delete(MapStorePath);
                    File.Move(tmpMap, MapStorePath);
                }
            }
            catch { /* offline disk is survivable — state stays in memory */ }
        }
    }
}
