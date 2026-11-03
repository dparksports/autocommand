using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Collections.Generic;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Services;
using AutoCommand.Sitedoctor.Core;

namespace AutoCommand
{
    /// <summary>
    /// Background security enforcement loop.
    /// Ported from DeviceMonitorCS — all PowerShell replaced with native APIs.
    /// Adapter detection is event-driven via AdapterEventWatcher (zero polling overhead),
    /// backed by a state-reconciliation sweep that re-asserts the desired SSTP service
    /// and kernel-debug state so anything re-enabled silently is neutralized again.
    /// </summary>
    public class SecurityEnforcer
    {
        private bool _isRunning;
        private readonly Action<string, string> _onThreatDetected;
        public event Action<string, string> StatusChanged;

        /// <summary>Optional extra callback to trigger system-level notifications (e.g. tray balloon).</summary>
        public Action<string, string> OnAdapterAlert;

        private Helpers.AdapterEventWatcher _adapterWatcher;

        public SecurityEnforcer(Action<string, string> onThreatDetected)
        {
            _onThreatDetected = onThreatDetected;
            Active = this;
        }

        // The one live enforcer instance (MainWindow constructs a single one);
        // lets the static Settings re-arm path trigger an immediate re-verify.
        public static SecurityEnforcer Active { get; private set; }

        // Allow-list persistence goes through AllowListLedger (Contain core): the
        // plain files keep their legacy format, but every app-side change is
        // hash-pinned in %PROGRAMDATA%\AutoCommand\allowlist-ledger.log and every
        // load is checked against that pin — a "True" written by anything else
        // fails secure (enforcement re-arms, tamper reported) instead of silently
        // disarming the sweep.
        public const string SstpPrefPath = "allowed_sstp.txt";
        public const string KdnetPrefPath = "allowed_kerneldebug.txt";

        private static volatile bool _isSstpAllowed = false;
        public static bool IsSstpAllowed
        {
            get => _isSstpAllowed;
            set
            {
                _isSstpAllowed = value;
                try { AllowListLedger.Commit("sstp", SstpPrefPath, value); } catch { }
            }
        }

        private static volatile bool _isKernelDebugAllowed = false;
        public static bool IsKernelDebugAllowed
        {
            get => _isKernelDebugAllowed;
            set
            {
                _isKernelDebugAllowed = value;
                try { AllowListLedger.Commit("kdnet", KdnetPrefPath, value); } catch { }
            }
        }

        // ── Surface verdicts: live machine truth, computed every sweep ────────
        // Detected regardless of allow state — the allow flag gates remediation,
        // never observation. Settings renders these directly.
        private static readonly object _verdictGate = new object();
        private static readonly List<SurfaceVerdict> _verdicts = new List<SurfaceVerdict>();
        public static event Action VerdictsUpdated;

        public static IReadOnlyList<SurfaceVerdict> LastVerdicts
        {
            get { lock (_verdictGate) return _verdicts.ToArray(); }
        }

        // Fires VerdictsUpdated only when a verdict's content actually changes —
        // the sweep runs every few seconds and the render is not free.
        private static readonly Dictionary<string, string> _verdictSignatures = new Dictionary<string, string>();

        private static void UpdateVerdict(SurfaceVerdict verdict)
        {
            string sig = verdict.Clean + "|" + verdict.Allowed + "|" + verdict.Summary;
            bool changed;
            lock (_verdictGate)
            {
                int idx = _verdicts.FindIndex(v => v.Surface == verdict.Surface);
                if (idx >= 0) _verdicts[idx] = verdict; else _verdicts.Add(verdict);
                string prev;
                if (!_verdictSignatures.TryGetValue(verdict.Surface, out prev) || prev != sig)
                {
                    _verdictSignatures[verdict.Surface] = sig;
                    changed = true;
                }
                else changed = false;
            }
            if (changed) VerdictsUpdated?.Invoke();
        }

        /// <summary>Re-arms a whitelisted surface ("sstp" | "kdnet") — enforcement
        /// resumes and the surface is re-verified immediately.</summary>
        public static void ReArm(string surface)
        {
            if (surface == "sstp") IsSstpAllowed = false;
            else if (surface == "kdnet") IsKernelDebugAllowed = false;
            Active?.VerifyNow(surface);
        }

        /// <summary>Immediate verification + (if armed) remediation sweep for one
        /// surface, outside the metronome cadence.</summary>
        public void VerifyNow(string surface)
        {
            if (surface == "sstp") EnforceSstpService();
            else if (surface == "kdnet") EnforceKernelDebug();
        }

        // AutoMitigateAdapters: cached in-memory; persisted to disk via setter only.
        private static volatile bool _autoMitigateAdapters = false;
        public static bool AutoMitigateAdapters
        {
            get => _autoMitigateAdapters;
            set
            {
                _autoMitigateAdapters = value;
                try { System.IO.File.WriteAllText("auto_mitigate_adapters.txt", value.ToString()); } catch { }
            }
        }

        // Tamper notices produced while loading the allow-lists (files rewritten
        // or deleted outside the app); surfaced as alerts once Start() runs and
        // the alert callbacks are wired.
        private static readonly List<string> _tamperNotices = new List<string>();

        // Load all persisted preferences from disk — called once at Start().
        private static void LoadPersistedPreferences()
        {
            try
            {
                var sstp = AllowListLedger.Load("sstp", SstpPrefPath);
                _isSstpAllowed = sstp.Value;
                if (sstp.Status == AllowListLoadStatus.Tampered)
                    _tamperNotices.Add("SSTP allow-list: " + sstp.Detail);

                var kdnet = AllowListLedger.Load("kdnet", KdnetPrefPath);
                _isKernelDebugAllowed = kdnet.Value;
                if (kdnet.Status == AllowListLoadStatus.Tampered)
                    _tamperNotices.Add("Kernel-debug allow-list: " + kdnet.Detail);

                if (System.IO.File.Exists("auto_mitigate_adapters.txt"))
                    _autoMitigateAdapters = System.IO.File.ReadAllText("auto_mitigate_adapters.txt").Trim() == "True";
            }
            catch { }
        }

        /// <summary>Allow-list tamper notices from load time (empty when clean).</summary>
        public static IReadOnlyList<string> TamperNotices => _tamperNotices.ToArray();

        private static HashSet<string> _whitelistedTasks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public static void WhitelistTask(string taskName)
        {
            lock (_whitelistedTasks)
            {
                _whitelistedTasks.Add(taskName);
            }
        }

        public void Start()
        {
            if (_isRunning) return;
            LoadPersistedPreferences();
            _isRunning = true;

            // Tampered allow-lists were reverted to enforce-on at load; say so
            // loudly now that the alert callbacks are wired (MainWindow wires
            // them before Start). This is the "a True appeared in my pref file
            // and I did not write it" moment — never silent.
            foreach (string notice in _tamperNotices)
            {
                _onThreatDetected?.Invoke("Allow-list Tamper", notice);
                StatusChanged?.Invoke("Tamper: Allow-list Reverted", "Red");
                OnAdapterAlert?.Invoke("🔴 AutoCommand re-armed a tampered allow-list", notice);
            }

            // Start the event-driven adapter watcher (replaces 2s WMI polling)
            _adapterWatcher = new Helpers.AdapterEventWatcher();
            _adapterWatcher.AdapterAppeared += OnAdapterAppeared;
            _adapterWatcher.Start();

            // The fast-check loop now rides the Instrument Metronome: its
            // cadence is user-calibratable in Settings, phase-spread against
            // the other periodic instruments, and self-slowing if a run
            // takes too long on this machine.
            InstrumentMetronome.Instance.Register(new InstrumentSpec
            {
                Id = "security-enforcer",
                Name = "Security enforcement (fast checks)",
                Description = "SSTP service state, hosted network and adapter checks. Heavier scans " +
                              "(kernel debug, hosts file, privileged tasks, firewall drift) ride along " +
                              "at fixed 30-60s cadences inside this instrument.",
                Cost = InstrumentCost.Heavy,
                DefaultSeconds = LegacyIntervalSeconds(),
                MinSeconds = 1,
                MaxSeconds = 60,
                Callback = EnforceOnceAsync,
            });
            InstrumentMetronome.Instance.SetEnabled("security-enforcer", true);
            InstrumentMetronome.Instance.Start();
        }

        public void Stop()
        {
            _isRunning = false;
            _adapterWatcher?.Dispose();
            _adapterWatcher = null;
            InstrumentMetronome.Instance.SetEnabled("security-enforcer", false);
        }

        /// <summary>One metronome tick: the old RunLoop body without its
        /// sleep. Heavy scans keep their own fixed elapsed-time cadences.</summary>
        private async Task EnforceOnceAsync()
        {
            if (!_isRunning) return;
            try
            {
                // Fast checks — every tick, at the user-selected rate
                // (cheap: one service-controller read, one registry read, one WMI query)
                CheckHostedNetwork();
                EnforceSstpService();

                // Heavier scans — fixed cadences regardless of tick rate
                var now = DateTime.UtcNow;
                if ((now - _lastKdnetCheckUtc).TotalSeconds >= HeavyScanKdnetSeconds)
                {
                    _lastKdnetCheckUtc = now;
                    EnforceKernelDebug();
                }
                if ((now - _lastHostsCheckUtc).TotalSeconds >= HeavyScanHostsSeconds)
                {
                    _lastHostsCheckUtc = now;
                    CheckHostsFile();
                }
                if ((now - _lastPrivTasksCheckUtc).TotalSeconds >= HeavyScanPrivTasksSeconds)
                {
                    _lastPrivTasksCheckUtc = now;
                    CheckPrivilegedTasks();
                }
                if ((now - _lastFirewallDriftCheckUtc).TotalSeconds >= HeavyScanFirewallDriftSeconds)
                {
                    _lastFirewallDriftCheckUtc = now;
                    await MonitorFirewallDrift();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Enforcer Error: {ex.Message}");
            }
        }

        /// <summary>One-time migration of the old check_interval.txt knob —
        /// its value becomes the user's calibrated cadence for the enforcer
        /// instrument in cadence_settings.json.</summary>
        private static int LegacyIntervalSeconds()
        {
            try
            {
                if (System.IO.File.Exists("check_interval.txt") &&
                    int.TryParse(System.IO.File.ReadAllText("check_interval.txt").Trim(), out int saved))
                {
                    int[] allowed = { 60, 30, 10, 6, 5, 3, 1 };
                    return allowed.Contains(saved) ? saved : 5;
                }
            }
            catch { /* default below */ }
            return 5;
        }

        // User-selected tick rate for the fast checks — now the metronome
        // instrument's calibration (Settings ▸ Instrumentation). Kept as an
        // API bridge for older callers; heavy scans keep fixed 30s/60s
        // cadences regardless of this value.
        public static int CheckIntervalSeconds
        {
            get => InstrumentMetronome.Instance.CadenceOf("security-enforcer") is int s && s > 0 ? s : 5;
            set => InstrumentMetronome.Instance.SetCadence("security-enforcer", value, userSet: true);
        }

        // Fixed cadences for heavier scans (seconds) — independent of the tick rate
        private const int HeavyScanKdnetSeconds = 30;
        private const int HeavyScanHostsSeconds = 30;
        private const int HeavyScanPrivTasksSeconds = 60;
        private const int HeavyScanFirewallDriftSeconds = 60;

        private DateTime _lastHostsCheckUtc = DateTime.MinValue;
        private DateTime _lastPrivTasksCheckUtc = DateTime.MinValue;
        private DateTime _lastFirewallDriftCheckUtc = DateTime.MinValue;
        private DateTime _lastKdnetCheckUtc = DateTime.MinValue;

        // Debounce so drift alerts don't spam every tick while the user decides
        private static readonly TimeSpan DriftAlertDebounce = TimeSpan.FromSeconds(60);
        private DateTime _lastSstpDriftAlertUtc = DateTime.MinValue;
        private DateTime _lastKdnetDriftAlertUtc = DateTime.MinValue;
        private DateTime _lastFirewallDriftAlertUtc = DateTime.MinValue;

        // Transition dedup for whitelisted-surface drift notes (one ledger line
        // and one amber status per clean→drift flip, not one per tick)
        private bool _sstpDriftRecorded;
        private bool _kdnetDriftRecorded;

        public event Action<List<string>> ConfigurationDriftDetected;

        public void ForceApplyFirewallRules()
        {
            try
            {
                var overrides = Helpers.FirewallConfigManager.Instance.RuleOverrides;
                if (overrides.Count == 0) return;

                // Use COM API to apply overrides
                Type fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                dynamic fwPolicy = Activator.CreateInstance(fwPolicyType);
                foreach (dynamic rule in fwPolicy.Rules)
                {
                    try
                    {
                        string name = (string)rule.Name;
                        if (overrides.TryGetValue(name, out string expected))
                        {
                            rule.Enabled = expected == "True";
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Firewall Enforcer Error: {ex.Message}");
            }
        }

        private async Task MonitorFirewallDrift()
        {
            try
            {
                // While paused the user is (or was) editing rules by hand — adopt, don't fight
                if (Helpers.FirewallBaselineManager.PausedUntilUtc > DateTime.UtcNow)
                    return;

                var overrides = Helpers.FirewallConfigManager.Instance.RuleOverrides;
                if (overrides.Count > 0)
                {
                    var driftItems = await FirewallService.Instance.CheckDriftAsync(overrides);
                    if (driftItems.Count > 0)
                    {
                        ConfigurationDriftDetected?.Invoke(driftItems);
                    }
                }

                // Whole-firewall baseline drift — detects rules re-enabled after a
                // reboot or Windows Update, and new rules sneaking in. Restores the
                // baseline when Auto-Mitigate is on; otherwise alerts (debounced).
                if (Helpers.FirewallBaselineManager.HasBaseline)
                {
                    var drift = await Helpers.FirewallBaselineManager.GetDriftAsync();
                    int problems = drift.ReEnabled.Count + drift.SneakedIn.Count + drift.UnexpectedlyDisabled.Count;
                    if (problems > 0 && DateTime.UtcNow - _lastFirewallDriftAlertUtc >= DriftAlertDebounce)
                    {
                        _lastFirewallDriftAlertUtc = DateTime.UtcNow;

                        if (AutoMitigateAdapters)
                        {
                            int fixedCount = 0;
                            if (drift.ReEnabled.Count > 0)
                                fixedCount += await Helpers.FirewallBaselineManager.ReDisableAsync(drift.ReEnabled);
                            if (drift.UnexpectedlyDisabled.Count > 0)
                                fixedCount += await Helpers.FirewallBaselineManager.RestoreEnableAsync(drift.UnexpectedlyDisabled);

                            // New rules: grouped ones violate the applied profile's end
                            // state (e.g. Shields Up) — block those; ungrouped ones are
                            // reported for review instead of being touched.
                            var groupedSneaks = drift.SneakedIn
                                .Where(s => !string.IsNullOrEmpty(s.Item2))
                                .Select(s => s.Item1).ToList();
                            if (groupedSneaks.Count > 0)
                                fixedCount += await Helpers.FirewallBaselineManager.ReDisableAsync(groupedSneaks);

                            _onThreatDetected?.Invoke("Firewall Drift",
                                $"{problems} drifted rule(s) detected; {fixedCount} restored to baseline.");
                            StatusChanged?.Invoke("Threat Blocked: Firewall Drift", "Red");
                            OnAdapterAlert?.Invoke("🟢 AutoCommand fixed firewall drift",
                                $"{drift.ReEnabled.Count} disabled rule(s) had been re-enabled, {drift.SneakedIn.Count} new rule(s) appeared — baseline restored.");
                        }
                        else
                        {
                            _onThreatDetected?.Invoke("Firewall Drift",
                                $"{drift.ReEnabled.Count} rule(s) re-enabled, {drift.SneakedIn.Count} new, {drift.UnexpectedlyDisabled.Count} disabled — review in the Firewall tab.");
                            StatusChanged?.Invoke("Warning: Firewall Drift", "Amber");
                            OnAdapterAlert?.Invoke("⚠ Firewall drift detected",
                                "Rules differ from your saved baseline. Review them in the Firewall tab.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Drift Check Error: {ex.Message}");
            }
        }

        private void CheckHostedNetwork()
        {
            try
            {
                var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkAdapter WHERE Name LIKE '%Hosted Network Virtual Adapter%' AND NetConnectionStatus = 2");
                if (searcher.Get().Count > 0)
                {
                    // Kill it using netsh directly (not PowerShell)
                    ProcessRunner.RunDetached("netsh", "wlan stop hostednetwork");
                    ProcessRunner.RunDetached("netsh", "wlan set hostednetwork mode=disallow");

                    _onThreatDetected?.Invoke("Hosted Network", "Active Hosted Network detected and disabled.");
                    StatusChanged?.Invoke("Threat Blocked: Hosted Network", "Red");
                }
            }
            catch { }
        }

        // ── State reconciliation sweep ────────────────────────────────────────
        // The adapter event watcher only fires when a device is created or flips to
        // working state. Re-enables that bypass device events — SstpSvc simply being
        // started again, or kernel debug flipped back on in the BCD — are caught here
        // by verifying the desired state every tick and neutralizing any drift.

        /// <summary>
        /// Reconciles the SSTP attack surface every tick. The surface is probed and
        /// the verdict updated EVEN when allow-listed — detection is never gated by
        /// the preference; the allow flag only skips the stop/disable remediation,
        /// and allowed drift is recorded to the ledger instead. Unless allow-listed,
        /// SstpSvc must be stopped AND disabled (Start=4): Windows Update and RAS
        /// reconfiguration can re-enable both silently, so the state is re-asserted.
        /// </summary>
        private void EnforceSstpService()
        {
            var state = ProbeSstp();
            var verdict = SurfaceAssurance.EvaluateSstp(state, IsSstpAllowed);
            UpdateVerdict(verdict);

            if (IsSstpAllowed)
            {
                // Whitelisted: record drift in the ledger (once per clean→drift
                // transition), alert amber, never remediate.
                if (!verdict.Clean && !_sstpDriftRecorded)
                {
                    _sstpDriftRecorded = true;
                    AllowListLedger.NoteDrift("sstp", verdict.Summary);
                    _onThreatDetected?.Invoke("SSTP Service",
                        $"Drift on a whitelisted surface (recorded, NOT remediated): {verdict.Summary}");
                    StatusChanged?.Invoke("Drift (whitelisted): SSTP Service", "Amber");
                }
                else if (verdict.Clean)
                {
                    _sstpDriftRecorded = false;
                }
                return;
            }

            try
            {
                if (!state.SstpServiceInstalled) return; // nothing to enforce
                if (state.SstpStartValue == -1) return; // registry unreadable — skip this tick
                bool serviceDrift = state.SstpServiceRunning || state.SstpStartValue != 4;
                if (!serviceDrift) return; // service at desired state; miniport presence only informs the verdict

                if (AutoMitigateAdapters)
                {
                    Helpers.ServiceHelper.StopAndDisable("SstpSvc");
                    Helpers.WanMiniportRemover.SetSstpMiniportsEnabled(false);

                    if (DateTime.UtcNow - _lastSstpDriftAlertUtc >= DriftAlertDebounce)
                    {
                        _lastSstpDriftAlertUtc = DateTime.UtcNow;
                        _onThreatDetected?.Invoke("SSTP Service",
                            $"SstpSvc was re-enabled ({(state.SstpServiceRunning ? "service running" : "startup type restored")}) and has been stopped and disabled again.");
                        StatusChanged?.Invoke("Threat Blocked: SSTP Service", "Red");
                        OnAdapterAlert?.Invoke("🔴 AutoCommand blocked: SSTP service",
                            "SstpSvc was re-enabled and has been stopped and disabled again.");
                    }
                }
                else if (DateTime.UtcNow - _lastSstpDriftAlertUtc >= DriftAlertDebounce)
                {
                    _lastSstpDriftAlertUtc = DateTime.UtcNow;
                    // "WAN Miniport (SSTP)" keeps the existing Review flow working:
                    // Block & Delete stops/disables the service, No whitelists SSTP.
                    _onThreatDetected?.Invoke("Network Adapter", "WAN Miniport (SSTP)");
                    StatusChanged?.Invoke("Threat Detected: SSTP Service", "Amber");
                    OnAdapterAlert?.Invoke("⚠ Security Alert: SSTP Service Re-enabled",
                        "SstpSvc is no longer disabled. Click to review and block it.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"EnforceSstpService Error: {ex.Message}");
            }
        }

        /// <summary>Live SSTP surface probe: service presence/status, registry Start
        /// value, and a no-touch enumeration of the SSTP-family WAN miniports.</summary>
        private static SurfaceState ProbeSstp()
        {
            var state = new SurfaceState();
            try
            {
                using (var sc = new ServiceController("SstpSvc"))
                {
                    state.SstpServiceInstalled = true;
                    state.SstpServiceRunning = sc.Status == ServiceControllerStatus.Running
                                            || sc.Status == ServiceControllerStatus.StartPending;
                }
            }
            catch
            {
                state.SstpServiceInstalled = false; // service not installed
            }

            state.SstpStartValue = GetServiceStartValue("SstpSvc");

            try
            {
                var listed = Helpers.WanMiniportRemover.ListSstpMiniports();
                state.SstpMiniportsPresent =
                    listed.Count > 0 && !listed[0].StartsWith("Failed", StringComparison.Ordinal);
            }
            catch
            {
                state.SstpMiniportsPresent = false; // enumeration failed — evaluator still says what it knows
            }

            return state;
        }

        /// <summary>
        /// Reconciles the KDNET attack surface every ~30s. Probed and judged even
        /// when allow-listed (the verdict updates); remediation — debug off in the
        /// BCD, KDNIC removal — only when NOT allow-listed. Allowed drift is
        /// recorded to the ledger, never remediated.
        /// </summary>
        private void EnforceKernelDebug()
        {
            try
            {
                bool debugOn = false;
                string bcdOutput = ProcessRunner.Run("bcdedit", "/enum {current}");
                if (!string.IsNullOrEmpty(bcdOutput))
                {
                    debugOn = bcdOutput.IndexOf("debug", StringComparison.OrdinalIgnoreCase) >= 0
                           && bcdOutput.IndexOf("yes", StringComparison.OrdinalIgnoreCase) >= 0;
                }

                bool kdnicActive = IsKdnicAdapterActive();

                var verdict = SurfaceAssurance.EvaluateKdnet(
                    new SurfaceState { BcdDebugOn = debugOn, KdnicActive = kdnicActive },
                    IsKernelDebugAllowed);
                UpdateVerdict(verdict);

                if (IsKernelDebugAllowed)
                {
                    if (!verdict.Clean && !_kdnetDriftRecorded)
                    {
                        _kdnetDriftRecorded = true;
                        AllowListLedger.NoteDrift("kdnet", verdict.Summary);
                        _onThreatDetected?.Invoke("Kernel Debug",
                            $"Drift on a whitelisted surface (recorded, NOT remediated): {verdict.Summary}");
                        StatusChanged?.Invoke("Drift (whitelisted): Kernel Debug", "Amber");
                    }
                    else if (verdict.Clean)
                    {
                        _kdnetDriftRecorded = false;
                    }
                    return;
                }

                if (verdict.Clean) return; // desired state

                if (AutoMitigateAdapters)
                {
                    if (debugOn)
                        ProcessRunner.RunDetached("bcdedit", "/debug off");
                    if (kdnicActive)
                        Helpers.WanMiniportRemover.RemoveKdnet();

                    if (DateTime.UtcNow - _lastKdnetDriftAlertUtc >= DriftAlertDebounce)
                    {
                        _lastKdnetDriftAlertUtc = DateTime.UtcNow;
                        _onThreatDetected?.Invoke("Kernel Debug", debugOn
                            ? "Kernel debugging was re-enabled in the boot configuration and has been turned off again."
                            : "An active Kernel Debug adapter was detected and removed.");
                        StatusChanged?.Invoke("Threat Blocked: Kernel Debug", "Red");
                        OnAdapterAlert?.Invoke("🔴 AutoCommand blocked: Kernel Debug",
                            debugOn
                                ? "Kernel debugging (bcdedit) was re-enabled and turned off again."
                                : "An active Kernel Debug (KDNIC) adapter was detected and removed.");
                    }
                }
                else if (DateTime.UtcNow - _lastKdnetDriftAlertUtc >= DriftAlertDebounce)
                {
                    _lastKdnetDriftAlertUtc = DateTime.UtcNow;
                    _onThreatDetected?.Invoke("Network Adapter", "Kernel Debug Network Adapter");
                    StatusChanged?.Invoke("Threat Detected: Kernel Debug", "Amber");
                    OnAdapterAlert?.Invoke("⚠ Security Alert: Kernel Debug Detected",
                        debugOn
                            ? "Kernel debugging is enabled in the boot configuration. Click to review."
                            : "An active Kernel Debug (KDNIC) adapter is present. Click to review.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"EnforceKernelDebug Error: {ex.Message}");
            }
        }

        private static bool IsKdnicAdapterActive()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT Name, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE Name LIKE '%Kernel Debug%' OR Name LIKE '%KDNIC%'"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var raw = obj["ConfigManagerErrorCode"];
                        int err = raw == null ? 0 : Convert.ToInt32(raw);
                        if (err == 0) return true; // present and working
                    }
                }
            }
            catch { }
            return false;
        }

        private static int GetServiceStartValue(string serviceName)
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName))
                {
                    if (key == null) return -1; // service key missing — not installed
                    var raw = key.GetValue("Start");
                    return raw == null ? -1 : Convert.ToInt32(raw);
                }
            }
            catch
            {
                return -1;
            }
        }

        /// <summary>
        /// Called by AdapterEventWatcher when a monitored adapter appears.
        /// This fires once per adapter appearance — no spam, no polling cost.
        /// </summary>
        private void OnAdapterAppeared(string adapterName)
        {
            bool isSstp        = adapterName.IndexOf("SSTP", StringComparison.OrdinalIgnoreCase) >= 0;
            bool isKernelDebug = adapterName.IndexOf("Kernel Debug", StringComparison.OrdinalIgnoreCase) >= 0
                              || adapterName.IndexOf("KDNIC",       StringComparison.OrdinalIgnoreCase) >= 0;

            if (isSstp && IsSstpAllowed) return;
            if (isKernelDebug && IsKernelDebugAllowed) return;

            string threatType    = isSstp ? "WAN Miniport (SSTP)" : "Kernel Debug Adapter";
            string displayName   = isSstp ? "WAN Miniport (SSTP)" : "Kernel Debug Network Adapter";
            string statusColor   = "Amber";

            if (AutoMitigateAdapters)
            {
                MitigateAdapter(displayName);
                _onThreatDetected?.Invoke(threatType, $"Active adapter detected and auto-mitigated: {adapterName}");
                StatusChanged?.Invoke($"Threat Blocked: {threatType}", "Red");
                // Also fire the tray notification for auto-mitigated events
                OnAdapterAlert?.Invoke(
                    $"🔴 AutoCommand blocked: {threatType}",
                    $"The {adapterName} adapter was detected and automatically removed.");
            }
            else
            {
                _onThreatDetected?.Invoke("Network Adapter", displayName);
                StatusChanged?.Invoke($"Threat Detected: {threatType}", statusColor);
                // Fire the tray balloon notification so user sees it even if app is minimized
                OnAdapterAlert?.Invoke(
                    $"⚠ Security Alert: {threatType} Detected",
                    $"The {adapterName} adapter has become active. Click to review and block it.");
            }
        }

        /// <summary>
        /// Mitigates an adapter by its friendly name using SetupAPI (native, no pnputil shell).
        /// For SSTP, also stops and disables the SstpSvc service.
        /// </summary>
        public void MitigateAdapter(string adapterFriendlyName)
        {
            Task.Run(() =>
            {
                try
                {
                    bool isSstp = adapterFriendlyName.IndexOf("SSTP", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isKdnic = adapterFriendlyName.IndexOf("Kernel Debug", StringComparison.OrdinalIgnoreCase) >= 0
                                || adapterFriendlyName.IndexOf("KDNIC", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (isSstp)
                    {
                        // Stop the RAS/SSTP service first
                        Helpers.ServiceHelper.StopAndDisable("SstpSvc");
                        // Use native SetupAPI via WanMiniportRemover (more reliable than pnputil)
                        var results = Helpers.WanMiniportRemover.RemoveSstpMiniports();
                        foreach (var r in results)
                            Debug.WriteLine($"MitigateAdapter (SSTP): {r}");
                    }
                    else if (isKdnic)
                    {
                        var results = Helpers.WanMiniportRemover.RemoveKdnet();
                        foreach (var r in results)
                            Debug.WriteLine($"MitigateAdapter (KDNET): {r}");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"MitigateAdapter Error: {ex.Message}");
                }
            });
        }

        private void CheckPrivilegedTasks()
        {
            try
            {
                // Use TaskScheduler COM to check for non-MS high privilege tasks
                Type tsType = Type.GetTypeFromProgID("Schedule.Service");
                dynamic ts = Activator.CreateInstance(tsType);
                ts.Connect();
                dynamic rootFolder = ts.GetFolder("\\");
                CheckTasksInFolder(rootFolder);
            }
            catch { }
        }

        private void CheckTasksInFolder(dynamic folder)
        {
            try
            {
                dynamic tasks = folder.GetTasks(1);
                foreach (dynamic task in tasks)
                {
                    try
                    {
                        string path = (string)task.Path;
                        // Skip Microsoft tasks to reduce noise
                        if (path.Contains("\\Microsoft\\")) continue;

                        dynamic def = task.Definition;
                        dynamic principal = def.Principal;
                        int runLevel = (int)principal.RunLevel;

                        // RunLevel 1 = TASK_RUNLEVEL_HIGHEST
                        if (runLevel == 1)
                        {
                            string name = task.Name;
                            bool isWhitelisted = false;
                            lock (_whitelistedTasks)
                            {
                                if (_whitelistedTasks.Contains(name)) isWhitelisted = true;
                            }

                            if (!isWhitelisted)
                            {
                                _onThreatDetected?.Invoke("Privileged Task", $"High Risk Task detected: {name}");
                                StatusChanged?.Invoke("Warning: Privileged Task", "Amber");
                            }
                        }
                    }
                    catch { }
                }

                dynamic subFolders = folder.GetFolders(0);
                foreach (dynamic sub in subFolders)
                {
                    try
                    {
                        string subPath = sub.Path;
                        if (subPath.Contains("\\Microsoft\\")) continue;
                        CheckTasksInFolder(sub);
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void CheckHostsFile()
        {
            try
            {
                string hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
                if (!System.IO.File.Exists(hostsPath)) return;

                var lines = System.IO.File.ReadAllLines(hostsPath);
                foreach (var line in lines)
                {
                    var t = line.Trim();
                    if (string.IsNullOrWhiteSpace(t) || t.StartsWith("#")) continue;

                    if (!t.Contains("localhost") && !t.Contains("127.0.0.1") && !t.Contains("::1"))
                    {
                        _onThreatDetected?.Invoke("Hosts File Modification", $"Suspicious redirect found: {t}");
                        StatusChanged?.Invoke("Warning: Hosts Modified", "Amber");
                        return; // Found a bad one, alert and return
                    }
                }
            }
            catch { }
        }
    }
}

