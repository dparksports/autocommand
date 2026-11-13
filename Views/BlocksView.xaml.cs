using System;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using AutoCommand.Services;

namespace AutoCommand.Views
{
    // ── view-models ───────────────────────────────────────────────────────

    public sealed class BlockRowVm : System.ComponentModel.INotifyPropertyChanged
    {
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        private void Notify(string name) =>
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));

        private bool _rulesEnabled;
        private int _enabledCount;
        private string _pausedShort;
        private string _pausedInfoToolTip;
        private bool _isSelected;
        private bool _canSelect;
        private string _lastTraffic = "…";
        private string _lastTrafficToolTip = "Resolving from live monitor and Sysmon archive…";
        private Brush _lastTrafficBrush;
        private string _containmentVerdict = "…";
        private string _containment = "…";
        private string _containmentToolTip = "Computing the containment join…";
        private Brush _containmentBrush;

        public BlockRecord Record { get; set; }
        public bool HasRules { get; set; }
        public bool RulesEnabled // any enabled rule → on
        {
            get => _rulesEnabled;
            set
            {
                if (_rulesEnabled == value) return;
                _rulesEnabled = value;
                Notify(nameof(RulesEnabled));
                Notify(nameof(HasDisabledRules));
                Notify(nameof(StatusGlyph));
                Notify(nameof(StatusToolTip));
                Notify(nameof(SelectionToolTip));
                Notify(nameof(RowActionLabel));
            }
        }
        public bool RulesStale { get; set; }  // rule(s) point at a path that no longer exists on disk
        public int RulesCount { get; set; }  // rules the firewall holds for this target
        public int DuplicateRules { get; set; } // exact duplicate rules on disk (0 => eligible for O(1) fast path)
        public int EnabledCount // how many of them are enabled (partial when 0 < n < RulesCount)
        {
            get => _enabledCount;
            set
            {
                if (_enabledCount == value) return;
                _enabledCount = value;
                Notify(nameof(EnabledCount));
                Notify(nameof(HasDisabledRules));
                Notify(nameof(StatusGlyph));
                Notify(nameof(StatusToolTip));
                Notify(nameof(SelectionToolTip));
                Notify(nameof(RowActionLabel));
            }
        }
        public bool HasDisabledRules => HasRules && EnabledCount < RulesCount;
        public string StatusGlyph => !HasRules ? "⚠" : RulesStale ? "🕳" : !RulesEnabled ? "⏸"
            : EnabledCount < RulesCount ? "◐" : "⛔";
        public string StatusToolTip => !HasRules
            ? "No firewall rules found for this target (removed elsewhere, or created by an older tool)"
            : RulesStale
            ? "Stale — the rule's program path no longer exists (app updated or moved). It cannot block anything until coverage is re-pointed; AppBlockCoverageService extends it when the process reappears and retires the dead rule."
            : RulesEnabled
            ? (EnabledCount < RulesCount
                ? $"Partial — only {EnabledCount} of {RulesCount} rule(s) are enabled; the disabled ones let traffic through"
                : $"Blocking ON — all {RulesCount} rule(s) enabled; outbound traffic to this target is dropped")
            : $"Blocking OFF — {RulesCount} rule(s) exist but are disabled; traffic flows"
                + (PausedShort != null ? $"\n⏸ {PausedShort}" : "");

        /// <summary>Why blocking is off, at a glance: "3d · Blocks tab".
        /// Null when no pause event/history is known.</summary>
        public string PausedShort
        {
            get => _pausedShort;
            set { if (_pausedShort != value) { _pausedShort = value; Notify(nameof(PausedShort)); Notify(nameof(StatusToolTip)); } }
        }
        public string PausedInfoToolTip
        {
            get => _pausedInfoToolTip;
            set { if (_pausedInfoToolTip != value) { _pausedInfoToolTip = value; Notify(nameof(PausedInfoToolTip)); } }
        }

        public string Target => Record.IsIp ? Record.Key
            : System.IO.Path.GetFileName(Record.Key);
        public string TargetToolTip  => Record.Key;

        // ── restore basket (blocking-OFF or partial rows) ──
        public bool IsSelected
        {
            get => _isSelected;
            set { if (_isSelected != value) { _isSelected = value; Notify(nameof(IsSelected)); } }
        }
        public bool CanSelect // rows with disabled rules — nothing to restore otherwise
        {
            get => _canSelect;
            set { if (_canSelect != value) { _canSelect = value; Notify(nameof(CanSelect)); } }
        }
        public string SelectionKey  => Record.Kind + ":" + Record.Key;
        public string SelectionToolTip => RulesEnabled && HasDisabledRules
            ? "Add to the restore basket — some rules are OFF for this target"
            : "Add to the restore basket — blocking is OFF for this target";

        /// <summary>The service that made the blocked connection — the row's
        /// own answer to "which network service did I block?", independent of
        /// its category header.</summary>
        public string ServiceDisplay
        {
            get
            {
                string key = BlocksStore.ServiceGroupKey(Record);
                if (key == "svchost:unresolved") return "…attributing";
                return ServiceCatalog.DisplayNameFor(key, Record.SvcDisplayName) switch
                {
                    "Unattributed" => "…attributing",
                    var n => n,
                };
            }
        }
        public string ServiceToolTip
        {
            get
            {
                string key = BlocksStore.ServiceGroupKey(Record);
                if (ServiceCatalog.TryGet(key, out var c)) return c.Description;
                return key == "svchost:unresolved"
                    ? "Service identity not yet recovered — the Sysmon/SCM attribution pass fills this in."
                    : $"Service/exe identity: {key} (recovered via {Record.Attrib})";
            }
        }
        public string ClassDisplay  => Record.IsIp ? Record.ClassAtBlock : Record.ClassAtBlock;
        public Brush ClassBrush { get; set; }
        public string ClassToolTip => Record.IsIp
            ? $"Ownership classification captured at block time:\n{Record.ClassAtBlock}"
            : $"Target type: {Record.ClassAtBlock}";

        public string CreatedDisplay  => Record.CreatedUtc.ToLocalTime().ToString("MMM d HH:mm");
        public string CreatedToolTip => $"Blocked {Record.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss local}\n" +
            $"({DateTime.UtcNow - Record.CreatedUtc:dd\\d\\ hh\\h\\ mm\\m} ago) · origin: {Record.Origin}\n" +
            $"identity: {(Record.Attrib == "none" ? "unresolved" : Record.Attrib)}";

        public string LastTraffic
        {
            get => _lastTraffic;
            set { if (_lastTraffic != value) { _lastTraffic = value; Notify(nameof(LastTraffic)); } }
        }
        public string LastTrafficToolTip
        {
            get => _lastTrafficToolTip;
            set { if (_lastTrafficToolTip != value) { _lastTrafficToolTip = value; Notify(nameof(LastTrafficToolTip)); } }
        }
        public Brush LastTrafficBrush
        {
            get => _lastTrafficBrush;
            set { if (!ReferenceEquals(_lastTrafficBrush, value)) { _lastTrafficBrush = value; Notify(nameof(LastTrafficBrush)); } }
        }
        /// <summary>Newest attempt time (live or archived) — the Restore
        /// guide's ranking signal; null when no traffic was ever found.</summary>
        public DateTime? LastTrafficUtc { get; set; }

        /// <summary>Containment proof — the raw verdict the category summary
        /// counts ("leak" | "stale-flow" | "contained" | "quiet" | "paused"
        /// | "—" when there is nothing to contain).</summary>
        public string ContainmentVerdict
        {
            get => _containmentVerdict;
            set { if (_containmentVerdict != value) { _containmentVerdict = value; Notify(nameof(ContainmentVerdict)); } }
        }
        public string Containment
        {
            get => _containment;
            set { if (_containment != value) { _containment = value; Notify(nameof(Containment)); } }
        }
        public string ContainmentToolTip
        {
            get => _containmentToolTip;
            set { if (_containmentToolTip != value) { _containmentToolTip = value; Notify(nameof(ContainmentToolTip)); } }
        }
        public Brush ContainmentBrush
        {
            get => _containmentBrush;
            set { if (!ReferenceEquals(_containmentBrush, value)) { _containmentBrush = value; Notify(nameof(ContainmentBrush)); } }
        }

        public string RowActionLabel => HasDisabledRules || !RulesEnabled ? "Restore blocking" : "Stop blocking";
    }

    public sealed class BlockGroupVm
    {
        public string ServiceKey { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public ServiceImpact Impact { get; set; }
        public string Summary { get; set; }  // "6 blocks · 4 Akamai · 2 Azure · ⚠ 1 LEAKING"

        /// <summary>Every row of the category, unfiltered — the truth counts
        /// and bulk actions scope over.</summary>
        public List<BlockRowVm> AllRows { get; set; } = new();

        public int ActiveCount { get; set; }  // rules present and enabled (blocking ON)
        public int PausedCount { get; set; }  // rules present, all disabled (blocking OFF)
        public int NoRulesCount { get; set; }  // no rules on disk at all

        public string StateText => $"{ActiveCount} on · {PausedCount} off"
            + (NoRulesCount > 0 ? $" · {NoRulesCount} no-rules" : "");
        public string StateToolTip => "Green = blocking ON (traffic dropped), amber = blocking OFF (rules disabled, traffic flows)"
            + (NoRulesCount > 0 ? $"\n{NoRulesCount} target(s) have no firewall rules on disk — nothing to toggle." : "");

        // Star-widths for the proportional state bar; "0*" collapses a segment.
        public string ActiveStar  => ActiveCount > 0 ? $"{ActiveCount}*" : "0*";
        public string PausedStar  => PausedCount > 0 ? $"{PausedCount}*" : "0*";
    }

    /// <summary>One row of the master (category) list. Key null = the pinned
    /// "All blocks" pseudo-category.</summary>
    public sealed class MasterItemVm
    {
        public string Key { get; set; }
        public bool IsAll { get; set; }
        public string Title { get; set; }
        public string Badge { get; set; }  // 🔴 / 🟠, empty for normal impact
        public bool HasBadge { get; set; }
        public string BadgeTip { get; set; }
        public bool HasCheck { get; set; }  // false for "All" — the command bar owns select-all
        public bool? Checked { get; set; }
        public string OnStar { get; set; }
        public string OffStar { get; set; }
        public string StateText { get; set; }
        public BlockGroupVm Group { get; set; }  // null for "All"
        public override string ToString() => Title;
    }

    // ── the tab ───────────────────────────────────────────────────────────

    public partial class BlocksView : UserControl
    {
        private enum BlockFilter { All, Active, Paused, Partial, HighImpact, Unattributed, MsInfra }

        /// <summary>User-chosen row order for the detail pane. Default is
        /// the shipped order (IPs first, then apps, each by key) — every
        /// other value is a column header the user clicked.</summary>
        private enum BlockSortColumn { Default, Target, Service, Class, Created, LastTraffic, Containment, Status }

        private sealed class FilterChip
        {
            public readonly BlockFilter Mode;
            private readonly string _label;
            public FilterChip(BlockFilter mode, string label) { Mode = mode; _label = label; }
            public override string ToString() => _label;
        }

        private bool _loading;
        private System.Threading.Tasks.TaskCompletionSource<bool> _queuedReloadTcs;
        private List<AutoCommand.Engines.Firewall.BlockedTarget> _pendingPreloadedInventory;
        private int _reloadGeneration;
        public static BlocksView Current { get; private set; }
        // written from inside Task.Run (the archive pass below) while the UI
        // thread reads after awaits — a plain Dictionary corrupts under that;
        // concurrent covers indexer-set / TryGetValue / TryRemove
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime utc, string source)?> _trafficCache =
            new(StringComparer.OrdinalIgnoreCase);

        // Restore-guide state: the symptom the user picked and its matched
        // ACTIVE rows, ranked by freshest attempt.
        private ServiceSymptom _restoreSymptom;
        private List<BlockRowVm> _restoreMatches = new();

        // One automatic attribution repair & one legacy-rule consolidation per session.
        private bool _autoRepairStarted;
        private bool _autoConsolidateStarted;

        // State ribbon / master-detail / basket
        private BlockFilter _filter = BlockFilter.All;
        private bool _buildingFilter;
        private bool _buildingMaster;
        private string _selectedKey;               // null = "All blocks"
        private string _searchText = "";
        private List<BlockRowVm> _allRows = new();
        private List<BlockGroupVm> _allGroups = new();
        private BlockGroupVm _detailGroup;         // null while "All blocks" is selected
        private readonly HashSet<string> _selectedKeys = new(StringComparer.OrdinalIgnoreCase);
        private bool _syncingSelection;

        // Column sort: which header the user clicked and which way it
        // points. Default preserves the shipped IP-first order everywhere;
        // the choice survives restarts (blocks-sort.txt beside the store).
        private BlockSortColumn _sortColumn = BlockSortColumn.Default;
        private bool _sortDescending;
        private Dictionary<BlockSortColumn, (Button btn, string label)> _sortHeaders;

        // Post-action undo
        private DispatcherTimer _toastTimer;
        private List<(string kind, string key, bool wasEnabled)> _undoSnapshot;

        public BlocksView()
        {
            Current = this;
            InitializeComponent();
            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(12) };
            _toastTimer.Tick += (s, a) => HideToast();
            _sortHeaders = new Dictionary<BlockSortColumn, (Button, string)>
            {
                [BlockSortColumn.Status]      = (HdrStatus, "⛔"),
                [BlockSortColumn.Target]      = (HdrTarget, "Target"),
                [BlockSortColumn.Service]     = (HdrService, "Service"),
                [BlockSortColumn.Class]       = (HdrClass, "Class"),
                [BlockSortColumn.Created]     = (HdrCreated, "Created"),
                [BlockSortColumn.LastTraffic] = (HdrTraffic, "Last attempt"),
                [BlockSortColumn.Containment] = (HdrContainment, "Containment"),
            };
            LoadSortPref();
            UpdateSortHeaderGlyphs();
            IsVisibleChanged += (s, e) => { if (IsVisible) { _ = ReloadAsync(); MaybeShowAuditDigest(); } };
            Loaded += (s, e) => _ = ReloadAsync();
        }

        public System.Threading.Tasks.Task RefreshIfLoadedAsync(
            List<AutoCommand.Engines.Firewall.BlockedTarget> preloadedInventory = null) =>
            IsLoaded ? ReloadAsync(preloadedInventory) : System.Threading.Tasks.Task.CompletedTask;

        private async System.Threading.Tasks.Task ReloadAsync(
            List<AutoCommand.Engines.Firewall.BlockedTarget> preloadedInventory = null)
        {
            if (preloadedInventory != null)
                _pendingPreloadedInventory = preloadedInventory;

            if (_loading)
            {
                _queuedReloadTcs ??= new System.Threading.Tasks.TaskCompletionSource<bool>(
                    System.Threading.Tasks.TaskCreationOptions.RunContinuationsAsynchronously);
                await _queuedReloadTcs.Task;
                return;
            }

            _loading = true;
            try
            {
                while (true)
                {
                    var currentBatch = _queuedReloadTcs;
                    _queuedReloadTcs = null;
                    var preloaded = _pendingPreloadedInventory;
                    _pendingPreloadedInventory = null;
                    try
                    {
                        await ReloadCoreAsync(preloaded);
                        currentBatch?.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        currentBatch?.TrySetResult(false);
                        StatusText.Text = "load failed";
                        MessageBox.Show($"Failed to load blocks: {ex.Message}", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                    if (_queuedReloadTcs == null) break;
                }
            }
            finally { _loading = false; }
        }

        private async System.Threading.Tasks.Task ReloadCoreAsync(
            List<AutoCommand.Engines.Firewall.BlockedTarget> preloadedInventory = null)
        {
            int reloadGen = ++_reloadGeneration;
            if (preloadedInventory == null)
                StatusText.Text = "loading…";
            BlocksStore.Load();

            // Phase 1 — Firewall truth + store reconcile + immediate UI render.
            // When a toggle/fleet call already captured the post-toggle inventory,
            // we reuse it directly with zero COM scans.
            var inventory = preloadedInventory ?? await FirewallService.Instance.GetBlockedInventoryAsync();
            var byKey = new Dictionary<string, AutoCommand.Engines.Firewall.BlockedTarget>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var item in inventory)
            {
                byKey[item.Key] = item;
                if (item.Kind == "app" && !string.IsNullOrEmpty(item.AppPath))
                {
                    string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(item.AppPath);
                    if (norm.Length > 0)
                        byKey.TryAdd("app:" + norm.ToLowerInvariant(), item);
                }
            }

            // Records the firewall knows about but the store doesn't
            // (rules from an older version, or pre-v3 blocks) become
            // store records so the tab is complete.
            var records = BlocksStore.Records.ToList();
            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in records)
            {
                known.Add((r.IsIp ? "ip:" : "app:") + (r.Key ?? "").Trim().ToLowerInvariant());
                if (!r.IsIp && !string.IsNullOrEmpty(r.Key))
                {
                    string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(r.Key);
                    if (norm.Length > 0)
                        known.Add("app:" + norm.ToLowerInvariant());
                }
            }
            foreach (var t in inventory)
            {
                if (known.Contains(t.Key)) continue;
                if (t.Kind == "app" && !string.IsNullOrEmpty(t.AppPath))
                {
                    string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(t.AppPath);
                    if (norm.Length > 0 && known.Contains("app:" + norm.ToLowerInvariant())) continue;
                }
                var r = new BlockRecord
                {
                    Kind = t.Kind == "ip" ? "ip" : "proc",
                    Key = t.Kind == "ip" ? t.Ip : t.AppPath,
                    ProcessName = System.IO.Path.GetFileName(t.AppPath ?? ""),
                    CreatedUtc = t.Created ?? DateTime.UtcNow,
                    StatusUtc = t.Created ?? DateTime.UtcNow,
                    ClassAtBlock = t.Kind == "ip" ? IpClassifier.Classify(t.Ip) : BlocksStore.ClassForPath(t.AppPath ?? ""),
                    Origin = "reconcile",
                    Attrib = "none",
                };
                if (BlocksStore.TryParseServiceFromDescription(t.Description, out string sk, out string dn))
                {
                    r.ServiceKey = sk;
                    r.SvcDisplayName = dn;
                    r.Attrib = "rule-desc";
                }
                else if (r.Kind == "proc" && !string.IsNullOrEmpty(r.Key))
                {
                    r.ServiceKey = System.IO.Path.GetFileNameWithoutExtension(r.Key).ToLowerInvariant();
                    r.SvcDisplayName = ServiceCatalog.DisplayNameFor(r.ServiceKey, null);
                    r.Attrib = "catalog";
                }
                if (!string.IsNullOrEmpty(r.Key)) BlocksStore.AddOrUpdate(r, "reconcile");
            }
            if (records.Count == 0 || BlocksStore.Records.Count != records.Count) records = BlocksStore.Records.ToList();

            var pauseHist = await System.Threading.Tasks.Task.Run(LoadPauseHistory);
            var mutedBrush = (Brush)FindResource("MutedTextBrush");
            bool needsArchiveLookup = false;
            bool needsContainmentJoin = false;

            var vms = new List<BlockRowVm>(records.Count);
            foreach (var r in records)
            {
                string invKey = (r.IsIp ? "ip:" : "app:") + (r.Key ?? "").Trim().ToLowerInvariant();
                if (!byKey.TryGetValue(invKey, out var t) && !r.IsIp && !string.IsNullOrEmpty(r.Key))
                {
                    string norm = AutoCommand.Engines.Firewall.FirewallService.NormalizeAppPath(r.Key);
                    if (norm.Length > 0)
                        byKey.TryGetValue("app:" + norm.ToLowerInvariant(), out t);
                }
                int rules = t?.Rules ?? 0;
                int enabled = t?.EnabledRules ?? 0;
                var vm = new BlockRowVm
                {
                    Record = r,
                    HasRules = rules > 0,
                    RulesEnabled = enabled > 0,
                    RulesCount = rules,
                    DuplicateRules = t?.DuplicateRules ?? 0,
                    EnabledCount = enabled,
                    RulesStale = (t?.StaleRules ?? 0) > 0,
                    ClassBrush = BrushForClass(r),
                    LastTrafficBrush = mutedBrush,
                    ContainmentBrush = mutedBrush,
                };
                vm.CanSelect = vm.HasDisabledRules;
                var gate = AutoCommand.Agent.Core.BlockGateService.Instance.Find(r.Kind, r.Key);
                if (gate != null)
                {
                    vm.PausedShort = $"gate {gate.RemainingMinutes:0}m · {gate.Client}";
                    vm.PausedInfoToolTip =
                        $"Block gate opened {gate.OpenedUtc.ToLocalTime():HH:mm} by {gate.Client}" +
                        (string.IsNullOrEmpty(gate.Reason) ? "" : $" — {gate.Reason}") +
                        $"\nBlocking returns ON automatically at {gate.ExpiresUtc.ToLocalTime():HH:mm}.";
                }
                if (vm.CanSelect)
                {
                    string hk = r.Kind + ":" + r.Key;
                    if (pauseHist.TryGetValue(hk, out var h))
                    {
                        vm.PausedShort = $"{ShortAge(DateTime.UtcNow - h.utc)} · {FriendlyOrigin(h.origin)}";
                        vm.PausedInfoToolTip =
                            $"Blocking turned off at {h.utc.ToLocalTime():yyyy-MM-dd HH:mm:ss local} via {FriendlyOrigin(h.origin)}\n" +
                            "Restore in one step: the '⏸ blocking OFF' chip lenses the list to exactly these, then 'Turn blocking back ON'.";
                    }
                    else if (r.Status == "off")
                    {
                        vm.PausedShort = $"{ShortAge(DateTime.UtcNow - r.StatusUtc)}";
                        vm.PausedInfoToolTip = $"Blocking turned off at {r.StatusUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss local}";
                    }
                }

                // Populate live or already-cached traffic synchronously so rows
                // don't flicker on refreshes.
                var live = r.IsIp
                    ? SvchostMonitorView.Current?.LiveRowForIp(r.Key)
                    : SvchostMonitorView.Current?.LiveRowForPath(r.Key);
                if (live != null)
                {
                    vm.LastTraffic = $"live · {live.LastSeenDisplay}";
                    vm.LastTrafficToolTip = $"Currently tracked by the Process Monitor.\n" +
                        $"rx {live.RxBytesDisplay} · tx {live.TxBytesDisplay} · last packet {live.LastSeenDisplay}";
                    vm.LastTrafficUtc = live.LastSeen;
                }
                else if (_trafficCache.TryGetValue(r.Kind + r.Key, out var cachedHit))
                {
                    ApplyArchiveTraffic(vm, cachedHit);
                }
                else
                {
                    needsArchiveLookup = true;
                }

                // Deterministic containment states render immediately in Phase 1.
                if (!vm.HasRules)
                {
                    SetContainment(vm, "—", "—", "MutedTextBrush",
                        "No firewall rules exist for this target — nothing to contain.");
                }
                else if (!vm.RulesEnabled)
                {
                    SetContainment(vm, "paused",
                        vm.PausedShort != null ? "⏸ " + vm.PausedShort : "off",
                        "MutedTextBrush",
                        (vm.PausedInfoToolTip != null ? vm.PausedInfoToolTip + "\n\n" : "") +
                        "Blocking is OFF — traffic flows by design, so containment is moot.");
                }
                else
                {
                    needsContainmentJoin = true;
                }

                vms.Add(vm);
            }

            Render(vms);

            string unrecSuffix = BlocksStore.Unrecognized.Count > 0
                ? $" · {BlocksStore.Unrecognized.Count} unrecognized line(s) preserved in blocks.txt" : "";
            if (!needsArchiveLookup && !needsContainmentJoin)
            {
                StatusText.Text = $"synced {DateTime.Now:HH:mm:ss}{unrecSuffix}";
            }
            else
            {
                StatusText.Text = $"synced {DateTime.Now:HH:mm:ss} · verifying containment…";
                _ = EnrichRowsAsync(vms, inventory, reloadGen);
            }

            // Auto-consolidate legacy 4-rule IP / 2-rule app blocks once per
            // session in the background so future toggles halve their BFE writes
            // and become eligible for the O(1) direct-lookup fast path.
            if (!_autoConsolidateStarted && inventory.Any(t => t.Kind == "ip" && t.Rules > 2))
            {
                _autoConsolidateStarted = true;
                _ = System.Threading.Tasks.Task.Run(async () =>
                {
                    try
                    {
                        var (targets, removedIn, migratedOut) =
                            await FirewallService.Instance.ConsolidateLegacyIpBlocksAsync();
                        if (migratedOut > 0 || removedIn > 0)
                        {
                            BlocksStore.LogFleet("consolidated",
                                $"{targets} target(s): {removedIn} inbound deleted, {migratedOut} migrated to v2 naming",
                                "auto-consolidate");
                            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
                            await Dispatcher.InvokeAsync(() => ReloadAsync()).Task.Unwrap();
                        }
                    }
                    catch { }
                });
            }

            // Auto-repair: once per session, when rows are still unattributed,
            // run the Sysmon/SCM pass in the background and re-render.
            int unresolved = vms.Count(v => BlocksStore.ServiceGroupKey(v.Record) == "svchost:unresolved");
            if (unresolved > 0 && !_autoRepairStarted)
            {
                _autoRepairStarted = true;
                StatusText.Text = $"attributing {unresolved} block(s) from the Sysmon archive…";
                _ = System.Threading.Tasks.Task.Run(async () =>
                {
                    try
                    {
                        var progress = new Progress<string>(m =>
                            Dispatcher.Invoke(() => StatusText.Text = m));
                        await BlockAttributionService.RepairAllAsync(progress);
                    }
                    finally
                    {
                        await Dispatcher.InvokeAsync(() => ReloadAsync()).Task.Unwrap();
                    }
                });
            }
        }

        /// <summary>
        /// Phase 2 — Resolves uncached Sysmon archive traffic and runs the
        /// containment join off the UI thread, reusing Phase 1's inventory so
        /// zero extra firewall COM enumerations occur, then updates rows in-place
        /// via INotifyPropertyChanged without resetting scroll or selection.
        /// </summary>
        private async System.Threading.Tasks.Task EnrichRowsAsync(
            List<BlockRowVm> vms,
            List<AutoCommand.Engines.Firewall.BlockedTarget> preloadedInventory,
            int reloadGen)
        {
            Dictionary<string, (DateTime utc, string source)?> newlyResolvedTraffic = null;
            BlockContainmentReader.Snapshot containmentSnap = null;
            bool containmentFailed = false;

            await System.Threading.Tasks.Task.Run(() =>
            {
                var unseenIps = vms.Where(v => v.Record.IsIp &&
                        v.LastTraffic == "…" &&
                        !_trafficCache.ContainsKey(v.Record.Kind + v.Record.Key))
                    .Select(v => v.Record.Key).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                var unseenImages = vms.Where(v => !v.Record.IsIp &&
                        v.LastTraffic == "…" &&
                        !_trafficCache.ContainsKey(v.Record.Kind + v.Record.Key))
                    .Select(v => v.Record.Key).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                if (unseenIps.Count > 0 || unseenImages.Count > 0)
                {
                    newlyResolvedTraffic = new Dictionary<string, (DateTime utc, string source)?>(StringComparer.OrdinalIgnoreCase);
                    var ipIndex = unseenIps.Count > 0
                        ? SysmonArchiveService.NewestConnectionPerIp(unseenIps)
                        : new Dictionary<string, AutoCommand.Engines.Watch.ArchiveEvent>(StringComparer.OrdinalIgnoreCase);
                    var imageIndex = unseenImages.Count > 0
                        ? SysmonArchiveService.NewestConnectionPerImage(unseenImages)
                        : new Dictionary<string, AutoCommand.Engines.Watch.ArchiveEvent>(StringComparer.OrdinalIgnoreCase);

                    foreach (var vm in vms)
                    {
                        string cacheKey = vm.Record.Kind + vm.Record.Key;
                        if (_trafficCache.ContainsKey(cacheKey)) continue;
                        var net = vm.Record.IsIp
                            ? (ipIndex.TryGetValue(vm.Record.Key, out var e1) ? e1 : null)
                            : (imageIndex.TryGetValue(vm.Record.Key, out var e2) ? e2 : null);
                        (DateTime utc, string source)? hit = net != null ? (net.TsUtc, "Sysmon archive") : null;
                        _trafficCache[cacheKey] = hit;
                        newlyResolvedTraffic[cacheKey] = hit;
                    }
                }

                if (vms.Any(v => v.HasRules && v.RulesEnabled))
                {
                    try
                    {
                        containmentSnap = BlockContainmentReader.Take(60, preloadedInventory);
                    }
                    catch
                    {
                        containmentFailed = true;
                    }
                }
            });

            if (reloadGen != _reloadGeneration) return;

            if (newlyResolvedTraffic != null)
            {
                foreach (var vm in vms)
                {
                    if (vm.LastTraffic != "…") continue;
                    if (_trafficCache.TryGetValue(vm.Record.Kind + vm.Record.Key, out var hit))
                        ApplyArchiveTraffic(vm, hit);
                    else
                        vm.LastTraffic = "—";
                }
            }

            int leaks = 0;
            if (containmentFailed)
            {
                foreach (var vm in vms.Where(v => v.HasRules && v.RulesEnabled))
                    SetContainment(vm, "—", "—", "MutedTextBrush",
                        "Containment join unavailable this refresh (feed or archive unreadable).");
            }
            else if (containmentSnap != null)
            {
                foreach (var vm in vms)
                {
                    if (!vm.HasRules || !vm.RulesEnabled) continue;
                    var worst = BlockContainmentVerifier.WorstForTarget(
                        containmentSnap.Instances, vm.Record.Kind, vm.Record.Key);
                    if (worst == null)
                    {
                        SetContainment(vm, "quiet", "quiet", "MutedTextBrush",
                            "No blocked-connect attempts in the last hour — nothing is even trying " +
                            "this target. The block may be dead weight (CDN edges rotate).");
                        continue;
                    }

                    string approx = worst.T0Approximate ? "\n(block time approximate — legacy rule without provenance)" : "";
                    string reused = worst.PidReused
                        ? $"\nA live socket under pid {worst.Pid} belonged to a newer process (pid reuse) — not attributed here." : "";
                    if (worst.Verdict == BlockContainmentVerifier.Leak)
                    {
                        leaks++;
                        string ev = worst.SocketEvidence.Count > 0
                            ? $"{worst.SocketEvidence.Count} live socket(s) to blocked target(s): {string.Join(", ", worst.SocketEvidence.Take(3))}"
                            : $"{worst.FlowsSinceT0} archived flow(s), {worst.BytesSinceT0:N0} bytes since the block was created";
                        SetContainment(vm, "leak", "🔴 LEAK", "AccentRedBrush",
                            $"{worst.Process} (pid {worst.Pid}): {ev}.\n" +
                            "Something established AFTER the block was created — the rule is not holding. " +
                            $"Escalate: transport-level hard block, or remove/restart the process.{approx}{reused}");
                    }
                    else if (worst.Verdict == BlockContainmentVerifier.StaleFlow)
                    {
                        SetContainment(vm, "stale-flow", "🟠 stale flow", "AccentAmberBrush",
                            $"{worst.Process} (pid {worst.Pid}) predates the block; socket(s): " +
                            $"{string.Join(", ", worst.SocketEvidence.Take(3))}.\n" +
                            "Firewall rules never sever flows that were already established — this socket " +
                            $"may still be alive. Sever it (restart the process) to be sure.{worst.Note}{approx}{reused}");
                    }
                    else
                    {
                        SetContainment(vm, "contained", "contained", "AccentGreenBrush",
                            $"{worst.Process} (pid {worst.Pid}): {worst.Attempts} attempt(s) in the last hour, " +
                            "all dropped at the kernel. No live socket to a blocked target, no archived " +
                            $"bytes since the block was created.{approx}{reused}");
                    }
                }
            }

            // Refresh group summary strings & header leak counter without rebuilding
            // DetailRows unless sorted by one of the async columns.
            foreach (var g in _allGroups)
            {
                var classes = g.AllRows.GroupBy(v => v.Record.ClassAtBlock ?? "?")
                    .OrderByDescending(x => x.Count())
                    .Select(x => $"{x.Count()} {x.Key}");
                int gLeak = g.AllRows.Count(v => v.ContainmentVerdict == BlockContainmentVerifier.Leak);
                int gStale = g.AllRows.Count(v => v.ContainmentVerdict == BlockContainmentVerifier.StaleFlow);
                int gContained = g.AllRows.Count(v => v.ContainmentVerdict == BlockContainmentVerifier.Contained);
                g.Summary = $"{g.AllRows.Count} block{(g.AllRows.Count == 1 ? "" : "s")} · {string.Join(" · ", classes)}" +
                    (gLeak > 0 ? $" · ⚠ {gLeak} LEAKING" :
                     gStale > 0 ? $" · {gStale} stale flow" :
                     gContained > 0 ? $" · {gContained} contained" : "");
            }
            if (_detailGroup == null)
            {
                int on = _allRows.Count(r => r.RulesEnabled);
                int off = _allRows.Count(r => r.HasRules && !r.RulesEnabled);
                DetailSummaryText.Text =
                    $"{_allRows.Count} blocks · {_allGroups.Count} categories · {on} blocking ON · {off} blocking OFF" +
                    (leaks > 0 ? $" · ⚠ {leaks} LEAKING" : "");
            }
            else
            {
                DetailSummaryText.Text = $"{_detailGroup.Summary} · {_detailGroup.StateText}";
            }

            if (_sortColumn is BlockSortColumn.LastTraffic or BlockSortColumn.Containment)
                RenderDetail();

            StatusText.Text = $"synced {DateTime.Now:HH:mm:ss}" +
                (leaks > 0 ? $" · ⚠ {leaks} target(s) LEAKING — see containment column" : "") +
                (BlocksStore.Unrecognized.Count > 0
                    ? $" · {BlocksStore.Unrecognized.Count} unrecognized line(s) preserved in blocks.txt" : "");
        }

        /// <summary>Newest "paused" event per kind:key from the audit log's
        /// tail — pause provenance without parsing the whole history.</summary>
        private Dictionary<string, (DateTime utc, string origin)> LoadPauseHistory()
        {
            var result = new Dictionary<string, (DateTime, string)>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(BlocksStore.EventLogPath)) return result;
                using var fs = new FileStream(BlocksStore.EventLogPath, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                int tail = (int)Math.Min(fs.Length, 256 * 1024);
                fs.Seek(-tail, SeekOrigin.End);
                using var sr = new StreamReader(fs);
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    // utc|action|kind|key|detail|origin
                    var p = line.Split('|');
                    if (p.Length < 6 || p[1] != "paused") continue;
                    if (!DateTime.TryParse(p[0], null,
                            System.Globalization.DateTimeStyles.RoundtripKind, out var utc)) continue;
                    result[p[2] + ":" + p[3]] = (utc.ToUniversalTime(), p[5]);
                }
            }
            catch { /* history is best-effort */ }
            return result;
        }

        private static string FriendlyOrigin(string origin) => origin switch
        {
            "restore-guide" => "Restore guide",
            "blocks-tab" => "Blocks tab",
            "monitor" => "Process monitor",
            "migration" => "import",
            "repair" => "attribution repair",
            "undo" => "undo",
            "mcp" => "MCP",
            "gate-expiry" => "gate auto-close",
            "gate-exit" => "gate exit",
            "" or null => "unknown surface",
            _ => origin,
        };

        private void ApplyArchiveTraffic(BlockRowVm vm, (DateTime utc, string source)? hit)
        {
            if (hit == null)
            {
                vm.LastTraffic = "no traffic found";
                vm.LastTrafficToolTip = "No connection attempt found in the live monitor or the Sysmon archive window.";
                return;
            }
            var age = DateTime.UtcNow - hit.Value.utc;
            vm.LastTrafficUtc = hit.Value.utc;
            vm.LastTraffic = $"{ShortAge(age)} ago · attempt ({hit.Value.source})";
            vm.LastTrafficToolTip = $"Last connection attempt: {hit.Value.utc.ToLocalTime():yyyy-MM-dd HH:mm:ss local}\n" +
                "Sysmon records attempts even when the firewall drops them —\n" +
                "'no traffic found' means this block may be dead weight (CDN edges rotate).";
        }

        private void SetContainment(BlockRowVm vm, string verdict, string text, string brushKey, string toolTip)
        {
            vm.ContainmentVerdict = verdict;
            vm.Containment = text;
            vm.ContainmentToolTip = toolTip;
            vm.ContainmentBrush = (Brush)FindResource(brushKey);
        }

        private static string ShortAge(TimeSpan age) => age.TotalDays >= 1
            ? $"{(int)age.TotalDays}d"
            : age.TotalHours >= 1 ? $"{(int)age.TotalHours}h" : $"{(int)age.TotalMinutes}m";

        private Brush BrushForClass(BlockRecord r)
        {
            string c = r.ClassAtBlock ?? "";
            if (c.Contains("Defender")) return (Brush)FindResource("AccentRedBrush");
            if (c.Contains("Windows component")) return (Brush)FindResource("AccentRedBrush");
            if (c.Contains("Microsoft/Azure")) return (Brush)FindResource("AccentBlueBrush");
            if (c.Contains("Akamai") || c.Contains("Gcore")) return (Brush)FindResource("AccentAmberBrush");
            return (Brush)FindResource("MutedTextBrush");
        }

        private void Render(List<BlockRowVm> vms)
        {
            _allRows = vms;
            var groups = vms.GroupBy(v => BlocksStore.ServiceGroupKey(v.Record))
                .Select(g =>
                {
                    string key = g.Key;
                    ServiceCatalog.TryGet(key, out var info);
                    // MS-infra IP categories inherit at least Medium impact even
                    // when the service itself is unknown.
                    var impact = info?.Impact ?? ServiceImpact.Normal;
                    if (impact < ServiceImpact.Medium && g.Any(v =>
                        v.Record.ClassAtBlock is string c &&
                        (c.Contains("Microsoft/Azure") || c.Contains("Akamai") || c.Contains("Gcore"))))
                        impact = ServiceImpact.Medium;

                    var classes = g.GroupBy(v => v.Record.ClassAtBlock ?? "?")
                        .OrderByDescending(x => x.Count())
                        .Select(x => $"{x.Count()} {x.Key}");
                    int gLeak = g.Count(v => v.ContainmentVerdict == BlockContainmentVerifier.Leak);
                    int gStale = g.Count(v => v.ContainmentVerdict == BlockContainmentVerifier.StaleFlow);
                    int gContained = g.Count(v => v.ContainmentVerdict == BlockContainmentVerifier.Contained);

                    var ordered = g.OrderBy(v => v.Record.IsIp ? 0 : 1)
                        .ThenBy(v => v.Record.Key).ToList();
                    return new BlockGroupVm
                    {
                        ServiceKey = key,
                        DisplayName = ServiceCatalog.DisplayNameFor(key,
                            g.FirstOrDefault()?.Record.SvcDisplayName),
                        Description = info?.Description ??
                            "No catalog description for this service — it is grouped by its Windows service/exe identity. " +
                            "Repair attribution may recover more detail.",
                        Impact = impact,
                        Summary = $"{g.Count()} block{(g.Count() == 1 ? "" : "s")} · {string.Join(" · ", classes)}" +
                            (gLeak > 0 ? $" · ⚠ {gLeak} LEAKING" :
                             gStale > 0 ? $" · {gStale} stale flow" :
                             gContained > 0 ? $" · {gContained} contained" : ""),
                        AllRows = ordered,
                        ActiveCount = ordered.Count(v => v.RulesEnabled),
                        PausedCount = ordered.Count(v => v.HasRules && !v.RulesEnabled),
                        NoRulesCount = ordered.Count(v => !v.HasRules),
                    };
                })
                .OrderByDescending(g => (int)g.Impact)
                .ThenByDescending(g => g.AllRows.Count)
                .ToList();
            _allGroups = groups;

            // ── state ribbon + command bar ──
            int active = vms.Count(v => v.RulesEnabled);
            int pausedN = vms.Count(v => v.HasRules && !v.RulesEnabled);
            int partial = vms.Count(v => v.HasRules && v.EnabledCount > 0 && v.EnabledCount < v.RulesCount);
            int restorableN = vms.Count(v => v.HasDisabledRules);
            int high = groups.Where(g => g.Impact == ServiceImpact.High).Sum(g => g.AllRows.Count);
            int msInfra = vms.Count(v => v.Record.ClassAtBlock is string c &&
                (c.Contains("Microsoft/Azure") || c.Contains("Akamai") || c.Contains("Gcore")));
            int unattr = vms.Count(v => BlocksStore.ServiceGroupKey(v.Record) == "svchost:unresolved");

            BuildFilterChips(vms.Count, groups.Count, active, pausedN, partial, high, msInfra, unattr);

            ResumePausedBtn.Content = pausedN > 0 && partial > 0
                ? $"Turn blocking back ON ({pausedN} off · {partial} partial)"
                : pausedN == 0 && partial > 0
                    ? $"Turn blocking back ON ({partial} partial)"
                    : $"Turn blocking back ON ({pausedN} off)";
            ResumePausedBtn.IsEnabled = restorableN > 0;
            PauseActiveBtn.Content = $"Turn blocking OFF ({active} on)";
            PauseActiveBtn.IsEnabled = active > 0;
            SelectAllPausedChk.Visibility = restorableN > 0 ? Visibility.Visible : Visibility.Collapsed;

            // basket survives reloads only for still-off rows
            var offKeys = new HashSet<string>(
                vms.Where(v => v.CanSelect).Select(v => v.SelectionKey),
                StringComparer.OrdinalIgnoreCase);
            _selectedKeys.IntersectWith(offKeys);
            foreach (var v in vms) v.IsSelected = _selectedKeys.Contains(v.SelectionKey);

            RebuildMaster();
            RenderDetail();
            UpdateSelectionUi();

            RebuildRestorePanel(vms, high, active);
        }

        // ── state ribbon (lenses) ──────────────────────────────────────────

        private void BuildFilterChips(int total, int groupsCount, int active, int paused,
            int partial, int high, int msInfra, int unattr)
        {
            _buildingFilter = true;
            var chips = new List<FilterChip>
            {
                new(BlockFilter.All, $"{total} blocks · {groupsCount} categories"),
                new(BlockFilter.Active, $"⛔ {active} blocking ON"),
                new(BlockFilter.Paused, $"⏸ {paused} blocking OFF"),
            };
            if (partial > 0) chips.Add(new(BlockFilter.Partial, $"◐ {partial} partial"));
            if (high > 0) chips.Add(new(BlockFilter.HighImpact, $"🔴 {high} high-impact"));
            if (msInfra > 0) chips.Add(new(BlockFilter.MsInfra, $"⚠ {msInfra} on Microsoft infra"));
            if (unattr > 0) chips.Add(new(BlockFilter.Unattributed, $"❓ {unattr} unattributed"));
            FilterList.ItemsSource = chips;
            int sel = chips.FindIndex(c => c.Mode == _filter);
            if (sel < 0) { _filter = BlockFilter.All; sel = 0; }
            FilterList.SelectedIndex = sel;
            _buildingFilter = false;
        }

        private void FilterList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_buildingFilter) return;
            if (FilterList.SelectedItem is FilterChip chip) _filter = chip.Mode;
            RebuildMaster();
            RenderDetail();
        }

        private bool RowMatches(BlockRowVm r) => _filter switch
        {
            BlockFilter.Active => r.RulesEnabled,
            BlockFilter.Paused => r.HasRules && !r.RulesEnabled,
            BlockFilter.Partial => r.HasRules && r.EnabledCount > 0 && r.EnabledCount < r.RulesCount,
            BlockFilter.Unattributed => BlocksStore.ServiceGroupKey(r.Record) == "svchost:unresolved",
            BlockFilter.MsInfra => r.Record.ClassAtBlock is string c &&
                (c.Contains("Microsoft/Azure") || c.Contains("Akamai") || c.Contains("Gcore")),
            _ => true,   // All and HighImpact (HighImpact lenses categories, not rows)
        };

        // ── master list (the categories) ───────────────────────────────────

        private void RebuildMaster()
        {
            _buildingMaster = true;
            string q = (_searchText ?? "").Trim();

            var items = new List<MasterItemVm> { BuildAllItem() };
            foreach (var g in _allGroups)
            {
                if (_filter == BlockFilter.HighImpact && g.Impact != ServiceImpact.High) continue;
                if (_filter != BlockFilter.All && _filter != BlockFilter.HighImpact &&
                    !g.AllRows.Any(RowMatches)) continue;
                if (q.Length > 0 && !CategoryMatches(g, q)) continue;
                items.Add(BuildGroupItem(g));
            }

            MasterList.ItemsSource = items;
            int sel = _selectedKey == null ? 0
                : items.FindIndex(i => string.Equals(i.Key, _selectedKey, StringComparison.OrdinalIgnoreCase));
            if (sel < 0) sel = 0;
            MasterList.SelectedIndex = sel;
            _selectedKey = items[sel].IsAll ? null : items[sel].Key;
            _buildingMaster = false;
        }

        private MasterItemVm BuildAllItem()
        {
            int on = _allRows.Count(r => r.RulesEnabled);
            int off = _allRows.Count(r => r.HasRules && !r.RulesEnabled);
            return new MasterItemVm
            {
                Key = null,
                IsAll = true,
                Title = "All blocks",
                HasCheck = false,
                HasBadge = false,
                OnStar = on > 0 ? $"{on}*" : "0*",
                OffStar = off > 0 ? $"{off}*" : "0*",
                StateText = $"{on} on · {off} off",
            };
        }

        private MasterItemVm BuildGroupItem(BlockGroupVm g)
        {
            var off = g.AllRows.Where(r => r.CanSelect).ToList();
            bool? check = off.Count == 0 ? false
                : off.All(r => _selectedKeys.Contains(r.SelectionKey)) ? true
                : off.Any(r => _selectedKeys.Contains(r.SelectionKey)) ? null
                : false;
            bool high = g.Impact == ServiceImpact.High;
            bool med = g.Impact == ServiceImpact.Medium;
            return new MasterItemVm
            {
                Key = g.ServiceKey,
                Title = g.DisplayName,
                Badge = high ? "🔴" : med ? "🟠" : "",
                HasBadge = high || med,
                BadgeTip = high
                    ? "High impact — blocking this breaks Windows security features, sign-in or updates"
                    : "Medium impact — blocking this degrades Windows features",
                HasCheck = true,
                Checked = check,
                OnStar = g.ActiveStar,
                OffStar = g.PausedStar,
                StateText = $"{g.ActiveCount} on · {g.PausedCount} off",
                Group = g,
            };
        }

        /// <summary>Search matches a category by name or by any of its
        /// targets (IP/exe/service display).</summary>
        private static bool CategoryMatches(BlockGroupVm g, string q)
        {
            if (g.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)) return true;
            if (g.ServiceKey?.Contains(q, StringComparison.OrdinalIgnoreCase) == true) return true;
            return g.AllRows.Any(r =>
                r.Target.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.Record.Key.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                r.ServiceDisplay.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        private void MasterList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_buildingMaster) return;
            var item = MasterList.SelectedItem as MasterItemVm;
            _selectedKey = item is { IsAll: true } ? null : item?.Key;
            RenderDetail();
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _searchText = SearchBox.Text;
            RebuildMaster();
            RenderDetail();
        }

        private void MasterCheck_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not CheckBox chk || chk.Tag is not BlockGroupVm g) return;
            bool on = chk.IsChecked == true;
            foreach (var r in g.AllRows.Where(r => r.CanSelect))
            {
                r.IsSelected = on;
                if (on) _selectedKeys.Add(r.SelectionKey);
                else _selectedKeys.Remove(r.SelectionKey);
            }
            UpdateSelectionUi();
        }

        // ── detail pane ────────────────────────────────────────────────────

        private void RenderDetail()
        {
            var g = _allGroups.FirstOrDefault(x =>
                string.Equals(x.ServiceKey, _selectedKey, StringComparison.OrdinalIgnoreCase));
            bool all = g == null;
            _detailGroup = all ? null : g;

            DetailBadge.Visibility = Visibility.Collapsed;
            if (all)
            {
                _selectedKey = null;
                int on = _allRows.Count(r => r.RulesEnabled);
                int off = _allRows.Count(r => r.HasRules && !r.RulesEnabled);
                int leaks = _allRows.Count(r => r.ContainmentVerdict == BlockContainmentVerifier.Leak);
                DetailTitleText.Text = "All blocks";
                DetailSummaryText.Text =
                    $"{_allRows.Count} blocks · {_allGroups.Count} categories · {on} blocking ON · {off} blocking OFF" +
                    (leaks > 0 ? $" · ⚠ {leaks} LEAKING" : "");
                DetailDescText.Text = LensDescription();
                DetailRestoreBtn.Visibility = Visibility.Collapsed;
                DetailStopBtn.Visibility = Visibility.Collapsed;
            }
            else
            {
                if (g.Impact >= ServiceImpact.Medium)
                {
                    DetailBadge.Text = g.Impact == ServiceImpact.High ? "🔴" : "🟠";
                    DetailBadge.Visibility = Visibility.Visible;
                }
                DetailTitleText.Text = g.DisplayName;
                DetailSummaryText.Text = $"{g.Summary} · {g.StateText}";
                DetailDescText.Text = g.Description;
                int gRestorable = g.AllRows.Count(v => v.HasDisabledRules);
                int gPartial = gRestorable - g.PausedCount;
                DetailRestoreBtn.Content = g.PausedCount > 0 && gPartial > 0
                    ? $"Restore blocking ({g.PausedCount} off · {gPartial} partial)"
                    : g.PausedCount == 0 && gPartial > 0
                        ? $"Restore blocking ({gPartial} partial)"
                        : $"Restore blocking ({g.PausedCount} off)";
                DetailRestoreBtn.Visibility = gRestorable > 0 ? Visibility.Visible : Visibility.Collapsed;
                DetailStopBtn.Content = $"Stop blocking ({g.ActiveCount} on)";
                DetailStopBtn.Visibility = g.ActiveCount > 0 ? Visibility.Visible : Visibility.Collapsed;
            }

            IEnumerable<BlockRowVm> rows = all ? OrderAllRows() : g.AllRows;
            rows = rows.Where(RowMatches);
            if (!string.IsNullOrWhiteSpace(_searchText))
            {
                string q = _searchText.Trim();
                rows = rows.Where(r =>
                    r.Target.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    r.Record.Key.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                    r.ServiceDisplay.Contains(q, StringComparison.OrdinalIgnoreCase));
            }
            DetailRows.ItemsSource = ApplyUserSort(rows.ToList());
        }

        /// <summary>Every row, in category order — the "All blocks" detail
        /// keeps the master list's grouping visually via the Service
        /// column's order (until the user picks a column sort, which
        /// reorders globally; ties keep this order via stable sort).</summary>
        private List<BlockRowVm> OrderAllRows()
        {
            var order = new Dictionary<BlockRowVm, int>();
            int i = 0;
            foreach (var g in _allGroups)
                foreach (var r in g.AllRows) order[r] = i++;
            return _allRows
                .OrderBy(r => order.TryGetValue(r, out var idx) ? idx : int.MaxValue)
                .ToList();
        }

        // ── column sort (user-chosen row order) ────────────────────────────

        /// <summary>The user's column sort, applied where rows reach the UI
        /// (after lens and search filtering, which compose freely under it).
        /// Keys are typed per column — IPs numerically, times chronologically,
        /// containment by severity — so "4.209.x" no longer sorts before
        /// "10.x", and "no traffic found" sinks to the bottom in both
        /// directions. Default keeps the caller's shipped order.</summary>
        private List<BlockRowVm> ApplyUserSort(List<BlockRowVm> rows)
        {
            switch (_sortColumn)
            {
                case BlockSortColumn.Target:
                    return _sortDescending
                        ? rows.OrderByDescending(TargetSortKey)
                              .ThenByDescending(v => v.Target, StringComparer.OrdinalIgnoreCase).ToList()
                        : rows.OrderBy(TargetSortKey)
                              .ThenBy(v => v.Target, StringComparer.OrdinalIgnoreCase).ToList();
                case BlockSortColumn.Service:
                    return _sortDescending
                        ? rows.OrderByDescending(v => v.ServiceDisplay, StringComparer.OrdinalIgnoreCase).ToList()
                        : rows.OrderBy(v => v.ServiceDisplay, StringComparer.OrdinalIgnoreCase).ToList();
                case BlockSortColumn.Class:
                    return _sortDescending
                        ? rows.OrderByDescending(v => v.Record.ClassAtBlock ?? "", StringComparer.OrdinalIgnoreCase).ToList()
                        : rows.OrderBy(v => v.Record.ClassAtBlock ?? "", StringComparer.OrdinalIgnoreCase).ToList();
                case BlockSortColumn.Created:
                    return _sortDescending
                        ? rows.OrderByDescending(v => v.Record.CreatedUtc).ToList()
                        : rows.OrderBy(v => v.Record.CreatedUtc).ToList();
                case BlockSortColumn.LastTraffic:   // nulls sink, both ways
                    return _sortDescending
                        ? rows.OrderBy(v => v.LastTrafficUtc == null ? 1 : 0)
                              .ThenByDescending(v => v.LastTrafficUtc ?? DateTime.MinValue).ToList()
                        : rows.OrderBy(v => v.LastTrafficUtc == null ? 1 : 0)
                              .ThenBy(v => v.LastTrafficUtc ?? DateTime.MinValue).ToList();
                case BlockSortColumn.Containment:
                    return _sortDescending
                        ? rows.OrderByDescending(ContainmentSortRank).ToList()
                        : rows.OrderBy(ContainmentSortRank).ToList();
                case BlockSortColumn.Status:
                    return _sortDescending
                        ? rows.OrderByDescending(StatusSortRank).ToList()
                        : rows.OrderBy(StatusSortRank).ToList();
                default:
                    return rows;
            }
        }

        /// <summary>IPs sort by address value (10.x.x.x before 4.x.x.x — the
        /// string sort had them backwards), apps after all IPs by name. IPv6
        /// and anything unparseable keep string order at the IP tier's end.</summary>
        private static (int tier, uint ip) TargetSortKey(BlockRowVm v)
        {
            if (!v.Record.IsIp) return (1, 0);
            try
            {
                byte[] b = System.Net.IPAddress.Parse(v.Record.Key).GetAddressBytes();
                return b.Length == 4 ? (0, (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3])) : (0, uint.MaxValue);
            }
            catch { return (0, uint.MaxValue); }
        }

        /// <summary>Severity order for the containment column: leak worst,
        /// then stale flow, contained, quiet; paused / no-rules / unknown
        /// ("…", "—") sink last.</summary>
        private static int ContainmentSortRank(BlockRowVm v) => v.ContainmentVerdict switch
        {
            BlockContainmentVerifier.Leak => 0,
            BlockContainmentVerifier.StaleFlow => 1,
            BlockContainmentVerifier.Contained => 2,
            "quiet" => 3,
            _ => 4,
        };

        /// <summary>Blocking-state order for the status column: ON, partial,
        /// OFF, stale, no rules at all.</summary>
        private static int StatusSortRank(BlockRowVm v) => !v.HasRules ? 4
            : v.RulesStale ? 3
            : !v.RulesEnabled ? 2
            : v.EnabledCount < v.RulesCount ? 1 : 0;

        private void SortHeader_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not string name ||
                !Enum.TryParse(name, ignoreCase: true, out BlockSortColumn col) ||
                col == BlockSortColumn.Default)
                return;

            if (col == _sortColumn)
            {
                // natural → reversed → back to the shipped default
                if (_sortDescending) { _sortColumn = BlockSortColumn.Default; _sortDescending = false; }
                else _sortDescending = true;
            }
            else
            {
                _sortColumn = col;
                _sortDescending = NaturalDirection(col);
            }
            UpdateSortHeaderGlyphs();
            SaveSortPref();
            RenderDetail();
        }

        /// <summary>The direction a first click means: dates and severity
        /// read backwards (newest / worst first), names read forwards.</summary>
        private static bool NaturalDirection(BlockSortColumn col) => col switch
        {
            BlockSortColumn.Created or BlockSortColumn.LastTraffic or BlockSortColumn.Containment => true,
            _ => false,
        };

        /// <summary>Header labels carry ▲/▼ on the active column; the 20px
        /// status header signals by brightening alone (no room for an
        /// arrow). Default order = no glyphs anywhere.</summary>
        private void UpdateSortHeaderGlyphs()
        {
            foreach (var (col, (btn, label)) in _sortHeaders)
            {
                bool active = col == _sortColumn;
                bool arrow = active && col != BlockSortColumn.Status;
                btn.Content = !arrow ? label : label + (_sortDescending ? " ▼" : " ▲");
                btn.Style = (Style)FindResource(active ? "SortHeaderBtnActive" : "SortHeaderBtn");
            }
        }

        // The sort choice persists as one line beside the store ("traffic
        // desc"), the same best-effort marker convention as audit-seen.txt;
        // unreadable or absent falls back to the shipped order.
        private string SortPrefPath => Path.Combine(
            Path.GetDirectoryName(BlocksStore.EventLogPath) ?? ".", "blocks-sort.txt");

        private void LoadSortPref()
        {
            try
            {
                if (!File.Exists(SortPrefPath)) return;
                string[] parts = File.ReadAllText(SortPrefPath).Trim().Split(' ');
                if (parts.Length == 0 ||
                    !Enum.TryParse(parts[0], ignoreCase: true, out BlockSortColumn col) ||
                    col == BlockSortColumn.Default) return;
                _sortColumn = col;
                _sortDescending = parts.Length > 1 && parts[1].Equals("desc", StringComparison.OrdinalIgnoreCase);
            }
            catch { /* unreadable pref = default order */ }
        }

        private void SaveSortPref()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SortPrefPath) ?? ".");
                File.WriteAllText(SortPrefPath, _sortColumn == BlockSortColumn.Default
                    ? "default"
                    : _sortColumn.ToString().ToLowerInvariant() + (_sortDescending ? " desc" : ""));
            }
            catch { /* best-effort */ }
        }

        private string LensDescription() => _filter switch
        {
            BlockFilter.Active => "Lens: only blocks whose rules are enabled — blocking ON. Click a chip again to clear the lens.",
            BlockFilter.Paused => "Lens: only blocks whose rules are disabled — blocking OFF. These are the inactive rules; 'Turn blocking back ON' restores them all (with a preview).",
            BlockFilter.Partial => "Lens: only partially-covered targets — some of their rules are on, some off.",
            BlockFilter.HighImpact => "Lens: only categories Windows depends on (security features, sign-in, updates).",
            BlockFilter.Unattributed => "Lens: blocks whose service identity is still unresolved — 'Repair attribution' may recover it.",
            BlockFilter.MsInfra => "Lens: blocks on Microsoft/Azure, Akamai or Gcore infrastructure.",
            _ => "Every firewall block this app created. Pick a category on the right for its detail; the search box finds categories and targets.",
        };

        // ── basket (restore selection) ─────────────────────────────────────

        private void RowSelect_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not CheckBox chk || chk.Tag is not BlockRowVm vm) return;
            vm.IsSelected = chk.IsChecked == true;
            if (vm.IsSelected) _selectedKeys.Add(vm.SelectionKey);
            else _selectedKeys.Remove(vm.SelectionKey);
            UpdateSelectionUi();
        }

        private void SelectAllPaused_Changed(object sender, RoutedEventArgs e)
        {
            if (_syncingSelection) return;
            bool on = SelectAllPausedChk.IsChecked == true;
            _selectedKeys.Clear();
            foreach (var r in _allRows.Where(r => r.CanSelect))
            {
                r.IsSelected = on;
                if (on) _selectedKeys.Add(r.SelectionKey);
            }
            RebuildMaster();
            RenderDetail();
            UpdateSelectionUi();
        }

        private void UpdateSelectionUi()
        {
            var sel = _allRows.Where(r => r.IsSelected).ToList();
            ResumeSelectedBtn.Visibility = sel.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (sel.Count > 0)
                ResumeSelectedBtn.Content =
                    $"Restore blocking — selected ({sel.Count} target(s) · {sel.Sum(r => r.RulesCount)} rules)";

            int offTotal = _allRows.Count(r => r.CanSelect);
            _syncingSelection = true;
            SelectAllPausedChk.IsChecked = sel.Count == 0 ? false
                : sel.Count >= offTotal ? true : null;
            _syncingSelection = false;
        }

        // ── bulk actions: preview → apply → undo ───────────────────────────

        private static ServiceImpact GroupImpactFor(BlockRecord r)
        {
            string key = BlocksStore.ServiceGroupKey(r);
            ServiceCatalog.TryGet(key, out var info);
            var impact = info?.Impact ?? ServiceImpact.Normal;
            if (impact < ServiceImpact.Medium && r.ClassAtBlock is string c &&
                (c.Contains("Microsoft/Azure") || c.Contains("Akamai") || c.Contains("Gcore")))
                impact = ServiceImpact.Medium;
            return impact;
        }

        /// <summary>
        /// Optimistically flips row &amp; ribbon state on the UI thread (&lt;16 ms)
        /// before the firewall COM transaction runs so buttons, badges, and row
        /// glyphs respond instantaneously.
        /// </summary>
        private void ApplyOptimisticToggle(IReadOnlyList<BlockRowVm> rows, bool enable, string statusMessage)
        {
            if (rows == null || rows.Count == 0) return;
            foreach (var vm in rows)
            {
                if (!vm.HasRules) continue;
                vm.RulesEnabled = enable;
                vm.EnabledCount = enable ? vm.RulesCount : 0;
                vm.CanSelect = !enable;
                if (enable)
                {
                    vm.IsSelected = false;
                    _selectedKeys.Remove(vm.SelectionKey);
                    vm.PausedShort = null;
                    vm.PausedInfoToolTip = null;
                    SetContainment(vm, "…", "…", "MutedTextBrush", "Verifying containment…");
                }
                else
                {
                    vm.PausedShort = "just now · Blocks tab";
                    vm.PausedInfoToolTip = "Blocking turned off just now via Blocks tab.";
                    SetContainment(vm, "paused", "⏸ just now · Blocks tab", "MutedTextBrush",
                        "Blocking is OFF — traffic flows by design, so containment is moot.");
                }
            }
            Render(_allRows);
            if (!string.IsNullOrEmpty(statusMessage))
                StatusText.Text = statusMessage;
        }

        /// <summary>The one path every bulk blocking change takes: build the
        /// grouped preview, let the user scope it (all / except high-impact),
        /// apply, record one audit event, and offer undo on the toast.</summary>
        private async System.Threading.Tasks.Task BulkToggleAsync(List<BlockRowVm> scope, bool enable, string scopeLabel)
        {
            if (scope == null || scope.Count == 0) return;

            var previewGroups = scope.GroupBy(v => BlocksStore.ServiceGroupKey(v.Record))
                .Select(g =>
                {
                    var impact = GroupImpactFor(g.First().Record);
                    return new BulkGroupLine
                    {
                        Glyph = impact switch
                        {
                            ServiceImpact.High => "🔴",
                            ServiceImpact.Medium => "🟠",
                            _ => "⚪",
                        },
                        DisplayName = ServiceCatalog.DisplayNameFor(g.Key, g.First().Record.SvcDisplayName),
                        Targets = g.Count(),
                        Rules = g.Sum(v => v.RulesCount),
                        HighImpact = impact == ServiceImpact.High,
                        Warning = impact == ServiceImpact.High
                            ? (enable
                                ? "re-enables blocking on a service Windows depends on — security features, sign-in or updates may stop working again"
                                : "lifts blocking on a service Windows depends on — its traffic (updates, sign-in, security checks) flows again")
                            : "",
                    };
                })
                .ToList();

            string verb = enable ? "Restore blocking" : "Stop blocking";
            var win = new BlockBulkPreviewWindow(verb, enable, previewGroups);
            if (Window.GetWindow(this) is { IsLoaded: true } owner) win.Owner = owner;
            if (win.ShowDialog() != true) return;

            var final = win.ExcludeHighImpact
                ? scope.Where(v => GroupImpactFor(v.Record) != ServiceImpact.High).ToList()
                : scope;
            if (final.Count == 0) return;

            // before-state snapshot powers the undo (capture BEFORE optimistic mutation)
            var snapshot = final.Select(v => (v.Record.Kind, v.Record.Key, enable ? !v.HasDisabledRules : v.RulesEnabled)).ToList();
            var targets = final.Select(v => (v.Record.Kind, v.Record.Key)).ToList();
            int estRules = final.Sum(v => v.RulesCount);

            ApplyOptimisticToggle(final, enable,
                $"{verb} — updating {estRules} firewall rule(s) across {final.Count} target(s)…");

            var progress = new Progress<(int Changed, int Matched)>(p =>
                StatusText.Text = $"{verb} — {p.Changed} firewall rule(s) updated ({p.Matched} matched)…");

            var snap = await FirewallService.Instance.SetTargetsEnabledSnapshotAsync(targets, enable, true, progress);
            if (snap.Matched == 0 || (snap.Changed == 0 && !string.IsNullOrEmpty(snap.FirstError)))
            {
                string detail = !string.IsNullOrEmpty(snap.FirstError)
                    ? $" — {snap.FirstError}"
                    : " — no matching firewall rules found on disk";
                ShowBulkToast($"{verb} did not change any rules ({snap.Changed}/{snap.Matched}){detail}", null);
                await ReloadAsync(snap.Inventory);
                return;
            }

            BlocksStore.SetStatuses(targets, enable ? "on" : "off", "blocks-tab");
            await Helpers.FirewallBaselineManager.ApplyToggleSnapshotAsync(snap);
            NotifyMonitorIfVisible();

            string errSuffix = !string.IsNullOrEmpty(snap.FirstError) ? $" · warning: {snap.FirstError}" : "";
            ShowBulkToast((enable
                ? $"Blocking restored — {final.Count} target(s) ON again ({snap.Changed}/{snap.Matched} rules) · {scopeLabel}"
                : $"Blocking stopped — {final.Count} target(s) OFF, traffic flows ({snap.Changed}/{snap.Matched} rules) · {scopeLabel}") + errSuffix,
                snapshot);
            await ReloadAsync(snap.Inventory);
        }

        private static void NotifyMonitorIfVisible()
        {
            if (SvchostMonitorView.Current is { IsVisible: true } mon)
                _ = mon.RefreshBlockStateIfLoadedAsync();
        }

        private async void ResumePausedBtn_Click(object sender, RoutedEventArgs e)
        {
            var scope = _allRows.Where(r => r.CanSelect).ToList();
            await BulkToggleAsync(scope, true, "all OFF blocks");
        }

        private async void PauseActiveBtn_Click(object sender, RoutedEventArgs e)
        {
            var scope = _allRows.Where(r => r.RulesEnabled).ToList();
            await BulkToggleAsync(scope, false, "all ON blocks");
        }

        private async void ResumeSelectedBtn_Click(object sender, RoutedEventArgs e)
        {
            var scope = _allRows.Where(r => r.IsSelected).ToList();
            await BulkToggleAsync(scope, true, "your selection");
        }

        private async void DetailRestoreBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_detailGroup == null) return;
            await BulkToggleAsync(_detailGroup.AllRows.Where(r => r.HasDisabledRules).ToList(),
                true, _detailGroup.DisplayName);
        }

        private async void DetailStopBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_detailGroup == null) return;
            await BulkToggleAsync(_detailGroup.AllRows.Where(r => r.RulesEnabled).ToList(),
                false, _detailGroup.DisplayName);
        }

        // ── undo toast ─────────────────────────────────────────────────────

        private void ShowBulkToast(string message, List<(string kind, string key, bool wasEnabled)> snapshot)
        {
            _undoSnapshot = snapshot;
            BlockToastText.Text = message;
            BlockToastUndoBtn.Visibility = snapshot is { Count: > 0 } ? Visibility.Visible : Visibility.Collapsed;
            BlockToast.Visibility = Visibility.Visible;
            _toastTimer.Stop();
            _toastTimer.Start();
        }

        private void HideToast()
        {
            _toastTimer.Stop();
            BlockToast.Visibility = Visibility.Collapsed;
            _undoSnapshot = null;
        }

        private async void BlockToastUndo_Click(object sender, RoutedEventArgs e)
        {
            var snap = _undoSnapshot;
            _toastTimer.Stop();
            BlockToast.Visibility = Visibility.Collapsed;
            _undoSnapshot = null;
            if (snap == null || snap.Count == 0) return;

            // restore each target to its pre-action state
            var toOn = snap.Where(t => t.wasEnabled).Select(t => (t.kind, t.key)).ToList();
            var toOff = snap.Where(t => !t.wasEnabled).Select(t => (t.kind, t.key)).ToList();
            string undoErr = null;
            AutoCommand.Engines.Firewall.TargetToggleSnapshot lastSnap = null;
            if (toOn.Count > 0)
            {
                var res = await FirewallService.Instance.SetTargetsEnabledSnapshotAsync(toOn, true, toOff.Count == 0, null);
                lastSnap = res;
                if (res.Matched > 0 && string.IsNullOrEmpty(res.FirstError))
                    BlocksStore.SetStatuses(toOn, "on", "undo");
                else
                    undoErr ??= res.FirstError ?? "no matching firewall rules found";
            }
            if (toOff.Count > 0)
            {
                var res = await FirewallService.Instance.SetTargetsEnabledSnapshotAsync(toOff, false, true, null);
                lastSnap = res;
                if (res.Matched > 0 && string.IsNullOrEmpty(res.FirstError))
                    BlocksStore.SetStatuses(toOff, "off", "undo");
                else
                    undoErr ??= res.FirstError ?? "no matching firewall rules found";
            }
            if (lastSnap != null)
                await Helpers.FirewallBaselineManager.ApplyToggleSnapshotAsync(lastSnap);
            else
                await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            NotifyMonitorIfVisible();
            if (!string.IsNullOrEmpty(undoErr))
                ShowBulkToast($"Undo did not fully apply — {undoErr}", null);
            await ReloadAsync(lastSnap?.Inventory);
        }

        // ── audit digest ────────────────────────────────────────────────────

        /// <summary>
        /// The notification contract for audit events: everything is recorded
        /// silently, and surfaced here in aggregate — ONE toast per visit to
        /// the tab, counts by category, never one toast per event. A marker
        /// file (audit-seen.txt beside the store) tracks what the user has
        /// already been shown; the first visit adopts history silently so a
        /// fresh install doesn't replay the whole log.
        /// </summary>
        private void MaybeShowAuditDigest()
        {
            try
            {
                string marker = AuditTrail.VisitMarkerPath(BlocksStore.EventLogPath);
                DateTime lastSeen = AuditTrail.ReadSeenUtc(marker);

                if (!File.Exists(BlocksStore.EventLogPath)) return;

                using var fs = new FileStream(BlocksStore.EventLogPath, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                int tail = (int)Math.Min(fs.Length, 256 * 1024);
                fs.Seek(-tail, SeekOrigin.End);
                using var sr = new StreamReader(fs);

                int fleet = 0, toggles = 0, paused = 0, resumed = 0, created = 0, removed = 0;
                DateTime newest = lastSeen;
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    var f = line.Split('|');
                    if (f.Length < 6) continue;
                    if (!DateTime.TryParse(f[0], null,
                            System.Globalization.DateTimeStyles.RoundtripKind, out var utc)) continue;
                    if (utc <= lastSeen) continue;
                    if (utc > newest) newest = utc;
                    switch (f[1])
                    {
                        case "fleet-disabled":
                        case "fleet-enabled":
                        case "consolidated":
                        case "update-opened":
                        case "update-restored": fleet++; break;
                        case "rule-toggled": toggles++; break;
                        case "paused": paused++; break;
                        case "resumed": resumed++; break;
                        case "created": created++; break;
                        case "removed": removed++; break;
                    }
                }

                var parts = new List<string>();
                if (fleet > 0) parts.Add($"{fleet} fleet operation(s)");
                if (toggles > 0) parts.Add($"{toggles} manual rule toggle(s)");
                if (paused > 0) parts.Add($"{paused} block(s) paused");
                if (resumed > 0) parts.Add($"{resumed} block(s) resumed");
                if (removed > 0) parts.Add($"{removed} block(s) removed");
                if (created > 0) parts.Add($"{created} new block(s)");

                if (lastSeen == DateTime.MinValue) parts.Clear();   // first visit: adopt, don't replay

                if (parts.Count > 0)
                    ShowBulkToast("Since your last visit — " + string.Join(" · ", parts), null);

                AuditTrail.MarkSeenUtc(marker, newest);
            }
            catch { /* the digest is best-effort; the log stays authoritative */ }
        }

        // ── restore guide ─────────────────────────────────────────────────

        /// <summary>
        /// "A feature broke — which of my blocks is doing it?" The panel lists
        /// symptoms that have at least one ACTIVE matching block; picking one
        /// shows exactly which rules to lift, ranked by freshest attempt.
        /// </summary>
        private void RebuildRestorePanel(List<BlockRowVm> vms, int highImpactActive, int totalActive)
        {
            var bySymptom = ServiceOutageMap.Symptoms
                .Select(s => (sym: s, rows: vms.Where(v => v.RulesEnabled && ServiceOutageMap.Matches(s, v.Record)).ToList()))
                .Where(x => x.rows.Count > 0)
                .OrderByDescending(x => x.rows.Count)
                .ToList();

            RestorePanel.Visibility = bySymptom.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (bySymptom.Count == 0) return;

            RestoreBanner.Text = highImpactActive > 0
                ? $"🔴 {highImpactActive} of your {totalActive} blocking-ON blocks sit on services Windows depends on (Defender, sign-in, updates…). " +
                  "If something stopped working, pick it below and stop blocking exactly the rules that break it:"
                : $"If something stopped working, pick it below and stop blocking exactly the rules that break it:";

            string prev = (SymptomCombo.SelectedItem as ComboSymptom)?.Symptom.Id;
            SymptomCombo.SelectionChanged -= SymptomCombo_SelectionChanged;
            SymptomCombo.Items.Clear();
            foreach (var (sym, rows) in bySymptom)
                SymptomCombo.Items.Add(new ComboSymptom(sym, rows.Count));
            SymptomCombo.SelectionChanged += SymptomCombo_SelectionChanged;

            int restore = bySymptom.FindIndex(x => x.sym.Id == prev);
            SymptomCombo.SelectedIndex = restore >= 0 ? restore : 0;
        }

        private sealed class ComboSymptom
        {
            public readonly ServiceSymptom Symptom;
            private readonly int _n;
            public ComboSymptom(ServiceSymptom s, int n) { Symptom = s; _n = n; }
            public override string ToString() => $"{Symptom.Title}  ({_n} block{(_n == 1 ? "" : "s")})";
        }

        private void SymptomCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if ((SymptomCombo.SelectedItem as ComboSymptom)?.Symptom is not ServiceSymptom sym) return;
            _restoreSymptom = sym;

            // Rank by freshest connection attempt: the block still actively
            // swallowing traffic is the likely culprit, not a cold one.
            _restoreMatches = BlocksStore.Records
                .Where(r => r.Status != "off" && ServiceOutageMap.Matches(sym, r))
                .Select(r => (r, utc: _trafficCache.TryGetValue(r.Kind + r.Key, out var h) && h != null ? h.Value.utc : (DateTime?)null))
                .OrderByDescending(x => x.utc ?? DateTime.MinValue)
                .Select(x => new BlockRowVm
                {
                    Record = x.r,
                    HasRules = true,
                    RulesEnabled = true,
                    LastTrafficUtc = x.utc,
                    LastTraffic = x.utc != null ? $"{ShortAge(DateTime.UtcNow - x.utc.Value)} ago" : "no traffic found",
                })
                .ToList();

            MatchList.ItemsSource = _restoreMatches.Select(RestoreLine).ToList();

            PauseMatchedBtn.Content = $"⏸ Stop blocking for these {_restoreMatches.Count} block(s) — traffic resumes";
        }

        private static string GroupLabel(BlockRecord r)
        {
            string key = BlocksStore.ServiceGroupKey(r);
            return ServiceCatalog.TryGet(key, out var c) ? c.DisplayName : key;
        }

        /// <summary>One Restore-guide line: who is blocked, what it still
        /// tries, when it was blocked — the "which rule" answer at a glance.</summary>
        private static string RestoreLine(BlockRowVm v)
        {
            string group = GroupLabel(v.Record);
            string target = v.Record.IsIp ? v.Record.Key : System.IO.Path.GetFileName(v.Record.Key);
            string tried = v.LastTrafficUtc != null
                ? ShortAge(DateTime.UtcNow - v.LastTrafficUtc.Value) + " ago"
                : "no attempts since";
            string blocked = v.Record.CreatedUtc.ToLocalTime().ToString("MMM d HH:mm");
            return $"{group,-30} {target,-18} tried {tried,-16} blocked {blocked}";
        }

        private async void PauseMatchedBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_restoreSymptom == null || _restoreMatches.Count == 0) return;
            var sym = _restoreSymptom;

            var list = _restoreMatches.Select(v => (v.Record.Kind, v.Record.Key)).ToList();
            var matchSet = new HashSet<string>(
                list.Select(x => x.Kind + ":" + x.Key), StringComparer.OrdinalIgnoreCase);
            var affectedRows = _allRows.Where(r => matchSet.Contains(r.SelectionKey)).ToList();
            ApplyOptimisticToggle(affectedRows, false,
                $"Stopping blocking for '{sym.Title}' ({list.Count} target(s))…");

            var snap = await FirewallService.Instance.SetTargetsEnabledSnapshotAsync(list, false, true, null);
            if (snap.Matched == 0 || (snap.Changed == 0 && !string.IsNullOrEmpty(snap.FirstError)))
            {
                ShowBulkToast($"Stop blocking for '{sym.Title}' did not change any rules ({snap.Changed}/{snap.Matched})" +
                    (!string.IsNullOrEmpty(snap.FirstError) ? $" — {snap.FirstError}" : ""), null);
                await ReloadAsync(snap.Inventory);
                return;
            }
            BlocksStore.SetStatuses(list, "off", "restore-guide");
            await Helpers.FirewallBaselineManager.ApplyToggleSnapshotAsync(snap);
            NotifyMonitorIfVisible();
            ShowBulkToast($"Blocking stopped for '{sym.Title}' — {list.Count} target(s) OFF, traffic flows ({snap.Changed}/{snap.Matched} rules)",
                list.Select(v => (v.Kind, v.Key, true)).ToList());
            await ReloadAsync(snap.Inventory);
        }

        // ── actions ────────────────────────────────────────────────────────

        private async void RowToggle_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not BlockRowVm vm) return;
            bool enable = vm.HasDisabledRules || !vm.RulesEnabled;
            int expectedRules = vm.RulesCount;
            bool allowFastPath = vm.HasRules && vm.DuplicateRules == 0 &&
                (vm.Record.IsIp ? expectedRules == 2 : expectedRules == 1);

            ApplyOptimisticToggle(new[] { vm }, enable,
                $"{(enable ? "Restoring" : "Stopping")} blocking for {vm.Target}…");

            var snap = await FirewallService.Instance.ToggleSingleTargetSnapshotAsync(
                vm.Record.Kind, vm.Record.Key, expectedRules, allowFastPath, enable);
            if (snap.Matched == 0 || (snap.Changed == 0 && !string.IsNullOrEmpty(snap.FirstError)))
            {
                ShowBulkToast($"{(enable ? "Restore blocking" : "Stop blocking")} for '{vm.Target}' did not change any rules ({snap.Changed}/{snap.Matched})" +
                    (!string.IsNullOrEmpty(snap.FirstError) ? $" — {snap.FirstError}" : " — no matching firewall rules found"), null);
                await ReloadAsync(snap.Inventory);
                return;
            }
            BlocksStore.SetStatus(vm.Record.Kind, vm.Record.Key, enable ? "on" : "off");
            BlocksStore.AppendEvent(enable ? "resumed" : "paused", vm.Record.Kind, vm.Record.Key,
                $"{snap.Changed}/{snap.Matched} rules", "blocks-tab");
            await Helpers.FirewallBaselineManager.ApplyToggleSnapshotAsync(snap);
            NotifyMonitorIfVisible();

            if (snap.UsedFastPath && string.IsNullOrEmpty(snap.FirstError))
            {
                // Fast path toggled deterministic v2 rules directly with zero COM
                // enumerations — keep the optimistic UI state in place instead of
                // forcing a full firewall rescan.
                StatusText.Text = $"synced {DateTime.Now:HH:mm:ss}" +
                    (BlocksStore.Unrecognized.Count > 0
                        ? $" · {BlocksStore.Unrecognized.Count} unrecognized line(s) preserved in blocks.txt" : "");
                if (enable)
                    _ = EnrichRowsAsync(_allRows, null, ++_reloadGeneration);
            }
            else
            {
                await ReloadAsync(snap.Inventory);
            }
        }

        private async void RowRemove_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.Tag is not BlockRowVm vm) return;
            if (MessageBox.Show(
                    $"Permanently remove the block for\n{vm.Record.Key}?\n\nIts firewall rules are deleted and traffic resumes immediately. " +
                    (!vm.Record.IsIp
                        ? "This lifts every path the executable is blocked from — coverage siblings included, or they would re-block it on its next run. "
                        : "") +
                    "This is recorded in the block history log.",
                    "Remove block", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            int removed = vm.Record.IsIp
                ? await FirewallService.Instance.RemoveBlockRulesForIpAsync(vm.Record.Key)
                : await FirewallService.Instance.RemoveBlockRulesForAppAsync(vm.Record.Key);
            if (vm.Record.IsIp)
            {
                BlocksStore.Remove(vm.Record.Kind, vm.Record.Key, "blocks-tab");
            }
            else
            {
                string exeName = System.IO.Path.GetFileName(vm.Record.Key);
                AppBlockCoverageService.Instance.NotifyUnblocked(exeName);
                BlocksStore.RemoveForExeName(exeName, "blocks-tab");
            }
            BlockGateService.Instance.ForgetTarget(vm.Record.Kind, vm.Record.Key);
            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            NotifyMonitorIfVisible();
            // ConcurrentDictionary has no one-arg Remove — TryRemove is the drop-in
            _trafficCache.TryRemove(vm.Record.Kind + vm.Record.Key, out _);
            await ReloadAsync();
        }

        private async void RepairBtn_Click(object sender, RoutedEventArgs e)
        {
            RepairBtn.IsEnabled = false;
            try
            {
                StatusText.Text = "repairing attribution from Sysmon archive…";
                var progress = new Progress<string>(msg => StatusText.Text = msg);
                var (repaired, unresolved) = await BlockAttributionService.RepairAllAsync(progress);
                StatusText.Text = $"repaired {repaired}, unresolved {unresolved}";
                await ReloadAsync();
            }
            finally { RepairBtn.IsEnabled = true; }
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e) => await ReloadAsync();
    }
}
