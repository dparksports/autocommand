using System;
using AutoCommand.Contain.Core;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace AutoCommand.Contain.Core
{
    /// <summary>
    /// The "think twice" probe for IP and domain blocks. Blocking an IP or a
    /// domain name on today's internet rarely stops exactly one thing: CDN
    /// edges are shared, and a hostname you have never seen may sit on the
    /// same addresses. This service answers the user-facing question BEFORE
    /// the block lands — the same moment the confirm dialog does — by
    /// forward-checking a curated list of connectivity-critical services
    /// (Windows Update, the NCSI connectivity check, sign-in, dev hosts)
    /// against the addresses the target resolves to, plus a best-effort
    /// reverse-DNS. The result feeds the confirm-dialog warning line and the
    /// provenance suffix, the same slot IpClassifier.WarningText occupies for
    /// Microsoft infrastructure.
    ///
    /// Never a verdict: a shared edge is a warning, not a prohibition. DNS
    /// answers are cached 10 minutes so confirm dialogs stay fast, and every
    /// lookup failure degrades to "probe incomplete" instead of blocking the
    /// flow. The resolver is injectable so the offline self-test can pin
    /// answers without a network.
    /// </summary>
    public sealed class BlockImpactProbe
    {
        /// <summary>One curated always-critical hostname, with the plain
        /// sentence shown when a block would take it down with the target.</summary>
        public sealed class CriticalService
        {
            public string Domain { get; }
            public string Story { get; }
            public CriticalService(string domain, string story) { Domain = domain; Story = story; }
        }

        /// <summary>Windows' own connectivity-critical names plus the
        /// highest-traffic user-facing ones. Add entries as co-block reports
        /// come in — each needs a story a user can act on.</summary>
        public static readonly IReadOnlyList<CriticalService> CriticalServices = new[]
        {
            new CriticalService("www.msftconnecttest.com", "Windows' network-connectivity check — the internet icon would show “no internet”"),
            new CriticalService("windowsupdate.com", "Windows Update"),
            new CriticalService("update.microsoft.com", "Windows Update"),
            new CriticalService("download.windowsupdate.com", "Windows Update downloads"),
            new CriticalService("ctldl.windowsupdate.com", "Defender definition updates"),
            new CriticalService("login.live.com", "Microsoft sign-in"),
            new CriticalService("login.microsoftonline.com", "Microsoft/Office sign-in"),
            new CriticalService("settings-win.data.microsoft.com", "Windows diagnostic-data endpoint"),
            new CriticalService("www.microsoft.com", "Microsoft sites"),
            new CriticalService("www.google.com", "Google search"),
            new CriticalService("fonts.googleapis.com", "Web fonts many sites embed"),
            new CriticalService("fonts.gstatic.com", "Web fonts many sites embed"),
            new CriticalService("github.com", "GitHub"),
            new CriticalService("api.github.com", "GitHub API"),
            new CriticalService("raw.githubusercontent.com", "GitHub raw content"),
            new CriticalService("registry.npmjs.org", "npm package registry"),
            new CriticalService("pypi.org", "Python package index"),
            new CriticalService("cdn.jsdelivr.net", "jsDelivr CDN — many sites' scripts"),
        };

        private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan PerLookupTimeout = TimeSpan.FromSeconds(5);
        private const int MaxParallel = 8;

        /// <summary>Injectable resolver (house test seam): hostname → its
        /// current addresses. Null = System.Net.Dns.</summary>
        public static Func<string, Task<IPAddress[]>> Resolver { get; set; }

        private static readonly object CacheGate = new();
        private static readonly Dictionary<string, (DateTime At, IPAddress[] Ips)> Cache =
            new(StringComparer.OrdinalIgnoreCase);

        private static async Task<IPAddress[]> ResolveAsync(string host)
        {
            lock (CacheGate)
                if (Cache.TryGetValue(host, out var hit) && DateTime.UtcNow - hit.At < CacheTtl)
                    return hit.Ips;

            IPAddress[] ips;
            try
            {
                var resolve = Resolver ?? (h => Dns.GetHostAddressesAsync(h));
                var work = resolve(host);
                if (work == await Task.WhenAny(work, Task.Delay(PerLookupTimeout)))
                    ips = work.Result ?? Array.Empty<IPAddress>();
                else
                    ips = null;   // timed out — probe degrades, never hangs the dialog
            }
            catch { ips = null; }   // NXDOMAIN / no network — same degradation

            lock (CacheGate)
                Cache[host] = (DateTime.UtcNow, ips);   // failures cached too (negative caching)
            return ips;
        }

        /// <summary>One probe outcome. Affected lists the curated services
        /// sharing the target's addresses; Incomplete is true when DNS
        /// answers were missing, so absence of a warning is weak.</summary>
        public sealed class ImpactResult
        {
            public List<CriticalService> Affected { get; } = new();
            public string PtrHostname { get; set; }
            public bool Incomplete { get; set; }

            /// <summary>The warning line for the confirm dialog — empty when
            /// nothing known is affected.</summary>
            public string WarningLine()
            {
                if (Affected.Count == 0) return "";
                var names = string.Join(", ", Affected.Select(s => s.Story).Distinct().Take(4));
                var more = Affected.Count > 4 ? " …" : "";
                return $"⚠ Shared infrastructure: these addresses also serve {names}{more}. " +
                       "Blocking will take those down too.";
            }
        }

        /// <summary>
        /// Probe an IP or hostname the user is about to block. For an IP:
        /// reverse-DNS + every critical service resolving to it. For a
        /// hostname: its current addresses are checked against every critical
        /// service's addresses (the CDN co-block question), plus the same
        /// forward-check of the hostname itself. Never throws.
        /// </summary>
        public static async Task<ImpactResult> ProbeAsync(string target)
        {
            var result = new ImpactResult();
            if (string.IsNullOrWhiteSpace(target)) return result;
            target = target.Trim().TrimEnd('.');

            bool isIp = IPAddress.TryParse(target, out IPAddress parsedIp);

            // Reverse DNS is decoration, never load-bearing.
            if (isIp)
            {
                try
                {
                    var ptr = await Task.WhenAny(Dns.GetHostEntryAsync(parsedIp), Task.Delay(PerLookupTimeout));
                    if (ptr is Task<IPHostEntry> ok && ok.Status == TaskStatus.RanToCompletion)
                        result.PtrHostname = ok.Result?.HostName;
                }
                catch { /* PTR often empty for CDN edges */ }
            }

            // The load-bearing leg: which curated services share these addresses.
            IPAddress[] targetIps;
            if (isIp) targetIps = new[] { parsedIp };
            else
            {
                targetIps = await ResolveAsync(target);
                if (targetIps == null) result.Incomplete = true;
            }

            if (targetIps != null && targetIps.Length > 0)
            {
                var targetSet = new HashSet<string>(
                    targetIps.Select(a => NormalizeIp(a)), StringComparer.Ordinal);

                using var gate = new SemaphoreSlim(MaxParallel);
                var lookups = CriticalServices.Select(async cs =>
                {
                    await gate.WaitAsync();
                    try
                    {
                        var ips = await ResolveAsync(cs.Domain);
                        return (cs, ips);
                    }
                    finally { gate.Release(); }
                }).ToList();

                var answers = await Task.WhenAll(lookups);
                foreach (var (cs, ips) in answers)
                {
                    if (ips == null) { result.Incomplete = true; continue; }
                    if (ips.Any(a => targetSet.Contains(NormalizeIp(a))))
                        result.Affected.Add(cs);
                }
            }
            else result.Incomplete = true;

            return result;
        }

        /// <summary>Address-family-aware normalization so an IPv4-mapped IPv6
        /// answer and its plain form compare equal.</summary>
        private static string NormalizeIp(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            return address.ToString();
        }
    }
}
