using AutoCommand.Contain.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AutoCommand.Agent.Core
{
    /// <summary>One open gate: blocking is temporarily OFF for a single
    /// blocked target, auto-restored at ExpiresUtc.</summary>
    public sealed class BlockGate
    {
        public string Kind { get; set; }          // BlockRecord kind: "ip" | "proc"
        public string Key { get; set; }           // the record key: IP or exe path
        public string Display { get; set; }       // what confirm dialogs and lists show
        public int Minutes { get; set; }
        public DateTime OpenedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public string Client { get; set; } = "mcp";
        public string Reason { get; set; } = "";
        public double RemainingMinutes => Math.Max(0, (ExpiresUtc - DateTime.UtcNow).TotalMinutes);
    }

    /// <summary>
    /// Time-boxed unblocks ("gates") for agent-initiated requests. A gate
    /// turns blocking OFF for ONE specific target the user confirmed, then
    /// turns it back ON automatically when the window ends — the agent picks
    /// the duration from the fixed menu (1/10/30/60 minutes), the human
    /// approves the specific target, and the door closes itself even if the
    /// agent, its client, or the whole conversation is gone.
    ///
    /// Safety properties:
    ///   • gates.json is written SYNCHRONOUSLY before blocking turns off —
    ///     a lost gate record would mean protection stays down, so this is
    ///     the one store that does not ride the managed write buffers;
    ///   • a gate record is removed only AFTER its blocks are confirmed
    ///     back ON — a failed re-arm (firewall COM hiccup) keeps the
    ///     expired record so the tick retries instead of silently leaving
    ///     a door open with no record of it;
    ///   • app exit closes every open gate (a dead app never leaves a door
    ///     open); startup closes anything that expired while it was down;
    ///   • one gate per target — re-opening extends from now (after a fresh
    ///     confirmation), never stacks;
    ///   • every transition lands in blocks-events.log (origins: mcp,
    ///     gate-expiry, gate-exit) so the Blocks tab shows who/why.
    /// </summary>
    public sealed class BlockGateService
    {
        public static readonly BlockGateService Instance = new();
        private BlockGateService() { }

        public static readonly int[] AllowedMinutes = { 1, 10, 30, 60 };

        private readonly object _lock = new();
        private List<BlockGate> _gates = new();
        private bool _loaded;

        /// <summary>Fires when a gate closes (origin: "mcp" | "gate-expiry"
        /// | "gate-exit") — the bridge logs it; the UI can toast it.</summary>
        public event Action<BlockGate, string> GateClosed;

        private static string StorePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "gates.json");

        public IReadOnlyList<BlockGate> Open
        {
            get { LoadOnce(); lock (_lock) return _gates.ToList(); }
        }

        public BlockGate Find(string kind, string key)
        {
            LoadOnce();
            lock (_lock) return _gates.FirstOrDefault(g =>
                g.Kind == kind && g.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Open (or extend) a gate. Persisted synchronously BEFORE
        /// the caller turns blocking off; the caller does the firewall work
        /// so the confirm dialog and the disable stay one user decision.</summary>
        public BlockGate OpenGate(string kind, string key, string display, int minutes, string client, string reason)
        {
            LoadOnce();
            var g = new BlockGate
            {
                Kind = kind,
                Key = key,
                Display = display,
                Minutes = minutes,
                OpenedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(minutes),
                Client = string.IsNullOrEmpty(client) ? "mcp" : client,
                Reason = reason ?? "",
            };
            lock (_lock)
            {
                _gates.RemoveAll(x =>
                    x.Kind == kind && x.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
                _gates.Add(g);
                SaveLocked();
            }
            return g;
        }

        /// <summary>Close a gate and turn blocking back ON. Idempotent —
        /// closing an unknown gate is a no-op (already safe). The gate
        /// record is only removed AFTER the firewall re-enable succeeds: a
        /// failed re-arm keeps the (expired) record in the store so the
        /// watch tick and the next startup retry it — a lost record would
        /// mean protection stays down with nothing saying otherwise.</summary>
        public async Task CloseAsync(string kind, string key, string origin)
        {
            LoadOnce();
            BlockGate g;
            lock (_lock)
            {
                g = _gates.FirstOrDefault(x =>
                    x.Kind == kind && x.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (g == null) return;
            }

            if (!await RestoreBlockingAsync(g, origin))
            {
                // Re-arm failed after retries — keep the gate and push its
                // expiry 30s out so the watch tick retries shortly (and
                // ReconcileOnStartupAsync picks it up after a restart).
                lock (_lock)
                {
                    g.ExpiresUtc = DateTime.UtcNow.AddSeconds(30);
                    SaveLocked();
                }
                return;
            }

            lock (_lock)
            {
                _gates.Remove(g);
                SaveLocked();
            }
        }

        /// <summary>The gate-watch instrument's tick: close everything past
        /// its window.</summary>
        public async Task CloseExpiredAsync()
        {
            LoadOnce();
            List<BlockGate> due;
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                due = _gates.Where(g => g.ExpiresUtc <= now).ToList();
            }
            foreach (var g in due)
                await CloseAsync(g.Kind, g.Key, "gate-expiry");
        }

        /// <summary>App exit / shutdown sweep — every gate closes, blocking
        /// returns ON. Run before the metronome stops.</summary>
        public async Task CloseAllAsync(string origin)
        {
            LoadOnce();
            List<BlockGate> all;
            lock (_lock) all = _gates.ToList();
            foreach (var g in all)
                await CloseAsync(g.Kind, g.Key, origin);
        }

        /// <summary>Startup re-arm: a gate whose window ended while the app
        /// was down closes immediately; the rest resume counting.</summary>
        public Task ReconcileOnStartupAsync() => CloseExpiredAsync();

        /// <summary>Turns blocking back ON for one gate's target, retrying
        /// transient firewall-COM failures. True when the target is
        /// confirmed re-armed; false means the gate record must STAY so the
        /// tick/startup retry path keeps trying.</summary>
        private async Task<bool> RestoreBlockingAsync(BlockGate g, string origin)
        {
            var targets = new[] { (g.Kind, g.Key) };
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    await FirewallService.Instance.SetTargetsEnabledAsync(targets, true);
                    BlocksStore.SetStatuses(targets, "on", origin);
                    try { GateClosed?.Invoke(g, origin); } catch { }
                    return true;
                }
                catch
                {
                    // Firewall COM hiccups are usually momentary — three
                    // attempts with a small gap before the caller falls back
                    // to the keep-the-gate-and-retry path.
                    if (attempt >= 3) return false;
                    await Task.Delay(300 * attempt);
                }
            }
        }

        private void LoadOnce()
        {
            lock (_lock)
            {
                if (_loaded) return;
                _loaded = true;
                try
                {
                    if (File.Exists(StorePath))
                        _gates = JsonSerializer.Deserialize<List<BlockGate>>(
                            File.ReadAllText(StorePath)) ?? new List<BlockGate>();
                }
                catch { _gates = new List<BlockGate>(); }
            }
        }

        // synchronous on purpose — see the class doc
        private void SaveLocked()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(StorePath));
                File.WriteAllText(StorePath,
                    JsonSerializer.Serialize(_gates, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* best-effort: an unsaved gate still closes via expiry
                    while the app runs; the app-exit sweep is the backstop */ }
        }
    }
}
