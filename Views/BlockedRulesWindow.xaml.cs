using System.Collections.ObjectModel;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using AutoCommand.Services;
using AutoCommand.Helpers;

namespace AutoCommand.Views
{
    /// <summary>
    /// Fleet view over every AutoCommand-created firewall block: grouped by
    /// destination owner so the risky rows (Microsoft infra / Windows
    /// components) jump out, with bulk unblock, legacy consolidation, CSV
    /// export and re-enable-all (undo for the status-bar panic button).
    /// </summary>
    public partial class BlockedRulesWindow : Window
    {
        private class Row : INotifyPropertyChanged
        {
            public string Target, Kind, Key, Ip, AppPath, Class, Description;
            public int Rules, EnabledRules, Duplicates;
            public DateTime? Created;
            private int _hits;
            public int Hits
            {
                get => _hits;
                set { _hits = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HitsDisplay))); }
            }
            public bool IsRisky => Class.Contains("Microsoft") || Class.Contains("Akamai") ||
                                   Class.Contains("Gcore") || Class.Contains("Windows component");
            public string RulesSummary => EnabledRules == Rules ? Rules.ToString() : $"{EnabledRules}/{Rules} on";
            public string DupsDisplay => Duplicates > 0 ? $"+{Duplicates}" : "·";
            public string CreatedDisplay => Created?.ToString("yyyy-MM-dd HH:mm") ?? "legacy";
            public string HitsDisplay => Hits > 0 ? Hits.ToString() : "·";
            public string OwnerDisplay { get; set; } = "";
            public string Note => Description.Length > 160 ? Description[..160] + "…" : Description;
            public event PropertyChangedEventHandler PropertyChanged;
        }

        /// <summary>One aggregated (process, destination) rollup in the live feed grid.</summary>
        private class HitRow
        {
            public string Process { get; set; }
            public int Pid { get; set; }
            public string Destination { get; set; }
            public string Match { get; set; }
            public int Attempts { get; set; }
            public string FirstSeen { get; set; }
            public string LastSeen { get; set; }
            public string Image { get; set; }
        }

        private readonly ObservableCollection<Row> _rows = new();
        private readonly DispatcherTimer _hitsTimer = new() { Interval = TimeSpan.FromSeconds(15) };
        private string _migrationNote = "";
        private string _feedStatus = "live feed starting…";

        public BlockedRulesWindow()
        {
            InitializeComponent();
            WindowPlacement.ConstrainToMonitor(this);   // must fit an 800×600 screen
            var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
            view.GroupDescriptions.Add(new PropertyGroupDescription("Class"));
            RulesGrid.ItemsSource = view;
            // live refresh of both hit surfaces (rules-grid Hits column + feed
            // grid) — blocks fire silently, so without this the tab only ever
            // shows the state from the moment it was opened
            _hitsTimer.Tick += async (_, _) => await RefreshHitsAsync();
            _hitsTimer.Start();
            Closed += (_, _) => _hitsTimer.Stop();
            Loaded += async (_, _) =>
            {
                // async-void — an unhandled throw here takes the app down;
                // same non-modal failure rule as the tick below
                try
                {
                    // auto-migrate legacy-name rules on open — lossless (provenance
                    // carries over, protection unchanged), so users never have to
                    // know or care about the old naming scheme
                    int legacy = await FirewallService.Instance.CountLegacyBlocksAsync();
                    if (legacy > 0)
                    {
                        StatusText.Text = $"Migrating {legacy} legacy firewall rule(s) to the current naming scheme…";
                        var (targets, removedInbound, migratedOutbound) = await FirewallService.Instance.ConsolidateLegacyIpBlocksAsync();
                        _migrationNote = $"Auto-migrated {migratedOutbound} legacy rule(s) ({removedInbound} redundant inbound rules removed) across {targets} target(s). ";
                    }
                    await ReloadAsync();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[BlockedRulesWindow] load failed: {ex.Message}");
                    StatusText.Text = $"load failed: {ex.Message}";
                }
            };
        }

        private async Task ReloadAsync()
        {
            StatusText.Text = "Scanning firewall…";
            var inv = await FirewallService.Instance.GetBlockedInventoryAsync();
            var hits = await Task.Run(() => CollectHitsLastHour());

            _rows.Clear();
            foreach (var t in inv)
            {
                int h = 0;
                if (t.Kind == "ip" && hits.TryGetValue(t.Ip, out int v)) h = v;
                // app hits: the live feed attributes per process, the log per IP —
                // the aggregated feed grid below carries the process attribution
                string owner = "";
                if (t.Kind == "ip")
                {
                    var cached = RdapService.Instance.Cached(t.Ip);
                    if (cached != null)
                        owner = cached.IsNegative ? "lookup failed" :
                                $"{cached.Netname} · {(cached.Org ?? "?")} [{cached.Country}]";
                }
                _rows.Add(new Row
                {
                    Target = t.Target, Kind = t.Kind, Key = t.Key, Ip = t.Ip, AppPath = t.AppPath,
                    Class = t.Class, Rules = t.Rules, EnabledRules = t.EnabledRules, Duplicates = t.DuplicateRules,
                    Hits = h, Description = t.Description, Created = t.Created, OwnerDisplay = owner,
                });
            }

            await RefreshHitsAsync();
        }

        /// <summary>Merged per-IP hit counts, last hour: live Sysmon-joined feed +
        /// (when enabled) the firewall's own drop log. Feed is ground truth —
        /// it works with default settings and carries process attribution.</summary>
        private static Dictionary<string, int> CollectHitsLastHour()
        {
            var merged = BlockHitFeedService.Instance.FeedHitsByIp(60);
            foreach (var kv in FirewallService.GetRecentLogHits(60))
                merged[kv.Key] = Math.Max(merged.TryGetValue(kv.Key, out int f) ? f : 0, kv.Value.Count);
            return merged;
        }

        /// <summary>Refreshes both hit surfaces without rebuilding the rules grid.</summary>
        private async Task RefreshHitsAsync()
        {
            // the 15 s tick lands here — one service hiccup must never become
            // a recurring modal dialog, so failures surface in the status
            // line only
            try
            {
                try { BlockHitFeedService.Instance.Start(); } catch { }
                var feed = BlockHitFeedService.Instance;
                var hits = await Task.Run(() => CollectHitsLastHour());

                foreach (var row in _rows)
                    if (row.Kind == "ip" && hits.TryGetValue(row.Ip, out int v))
                        row.Hits = v;

                HitsGrid.ItemsSource = feed.Aggregates(60, 200).Select(x => new HitRow
                {
                    Process = x.Process,
                    Pid = x.Pid,
                    Destination = $"{x.DestIp}:{x.DestPort}",
                    Match = x.MatchKind == "ip" ? "IP block" : "app block",
                    Attempts = x.Count,
                    FirstSeen = x.FirstUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                    LastSeen = x.LastUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                    Image = x.Image,
                }).ToList();

                int liveCount = hits.Values.Sum();
                _feedStatus = feed.IsRunning
                    ? $"live feed: {liveCount} blocked connect(s) in the last hour"
                    : "live feed starting…";
                if (feed.WatcherError != null) _feedStatus += $" — {feed.WatcherError}";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[BlockedRulesWindow] hit refresh failed: {ex.Message}");
                _feedStatus = $"hit refresh failed: {ex.Message}";
            }
            UpdateStatusText();
        }

        private void UpdateStatusText()
        {
            int risky = _rows.Count(r => r.IsRisky);
            int disabled = _rows.Count(r => r.EnabledRules == 0);
            StatusText.Text =
                _migrationNote +
                $"{_rows.Count} blocked targets · {risky} risky (Microsoft/Windows — likely breakage, not threats) · {disabled} fully disabled · {_feedStatus}" +
                (FirewallService.FirewallDropLoggingOn()
                    ? ""
                    : " · firewall drop-logging off (optional second hit source; the live feed works without it)");
            ConsolidateBtn.IsEnabled = _rows.Any(r => r.Rules > 2 && r.Kind == "ip");
            int dups = _rows.Sum(r => r.Duplicates);
            DedupBtn.IsEnabled = dups > 0;
            DedupBtn.Content = dups > 0 ? $"🧹 Clean duplicates ({dups})" : "🧹 Clean duplicates";
            UnblockMsBtn.IsEnabled = risky > 0;
            EnableLogBtn.Visibility = FirewallService.FirewallDropLoggingOn()
                ? Visibility.Collapsed : Visibility.Visible;
        }

        private async void EnableLogBtn_Click(object sender, RoutedEventArgs e)
        {
            EnableLogBtn.IsEnabled = false;
            try
            {
                string err = await Task.Run(() => FirewallService.SetDropLogging(true));
                StatusText.Text = err == null
                    ? "Drop-logging enabled on all profiles — hit counts will appear as blocks fire."
                    : $"Drop-logging partially failed: {err}";
            }
            finally { EnableLogBtn.IsEnabled = true; }
            await ReloadAsync();
        }

        private async void RdapBtn_Click(object sender, RoutedEventArgs e)
        {
            var targets = _rows.Where(r => r.Kind == "ip" && r.Class == "Unclassified").ToList();
            if (targets.Count == 0)
            {
                StatusText.Text = "No unclassified IP targets — everything is already classified or verified.";
                return;
            }
            RdapBtn.IsEnabled = false;
            try
            {
                StatusText.Text = $"RDAP-verifying {targets.Count} target(s)… (cached results are instant)";
                int ok = 0, failed = 0, ms = 0, cached = 0;
                foreach (var r in targets)
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    var entry = await RdapService.Instance.LookupAsync(r.Ip, urgent: true);
                    sw.Stop();
                    if (sw.ElapsedMilliseconds < 50) cached++;
                    if (entry.IsNegative) failed++;
                    else
                    {
                        ok++;
                        r.OwnerDisplay = $"{entry.Netname} · {(entry.Org ?? "?")} [{entry.Country}]";
                    }
                    ms += (int)sw.ElapsedMilliseconds;
                }
                StatusText.Text = $"RDAP: {ok} verified, {failed} failed · {cached} served from cache · " +
                                  $"total {ms} ms · cache: {RdapService.Instance.EntryCount} block(s) in {RdapService.Instance.CachePath}";
            }
            finally { RdapBtn.IsEnabled = true; }
            await ReloadAsync();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            // async-void click — same non-modal failure rule as the tick
            try { await ReloadAsync(); }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[BlockedRulesWindow] refresh failed: {ex.Message}");
                StatusText.Text = $"refresh failed: {ex.Message}";
            }
        }

        private async void UnblockSelectedBtn_Click(object sender, RoutedEventArgs e)
        {
            var sel = RulesGrid.SelectedItems.Cast<Row>().ToList();
            if (sel.Count == 0) { MessageBox.Show("Select one or more rows first.", "Unblock"); return; }
            if (MessageBox.Show($"Permanently remove the block rules for {sel.Count} target(s)?\n" +
                string.Join("\n", sel.Select(r => $"  · {r.Target} ({r.Class}, {r.Rules} rules)")) +
                (sel.Any(r => r.Kind != "ip")
                    ? "\n\nApp targets lift every path the executable is blocked from (coverage siblings),\n" +
                      "or a surviving path would re-block it on its next run."
                    : ""),
                "Confirm unblock", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            int removed = 0;
            foreach (var r in sel)
                removed += r.Kind == "ip"
                    ? await FirewallService.Instance.RemoveBlockRulesForIpAsync(r.Ip)
                    : await FirewallService.Instance.RemoveBlockRulesForAppAsync(r.AppPath);
            StatusText.Text = $"Removed {removed} firewall rule(s).";
            await ReloadAsync();
        }

        private async void UnblockMsBtn_Click(object sender, RoutedEventArgs e)
        {
            var risky = _rows.Where(r => r.IsRisky).ToList();
            if (risky.Count == 0) return;
            if (MessageBox.Show(
                    $"These {risky.Count} targets are Microsoft / Windows infrastructure — blocking them breaks\n" +
                    "updates, notifications, sign-in or DNS rather than blocking threats.\n\n" +
                    string.Join("\n", risky.Select(r => $"  · {r.Target} ({r.Class}, {r.Rules} rules)")) +
                    "\n\nRemove ALL of them?",
                    "Unblock Microsoft-owned ⚠", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

            int removed = 0;
            foreach (var r in risky)
                removed += r.Kind == "ip"
                    ? await FirewallService.Instance.RemoveBlockRulesForIpAsync(r.Ip)
                    : await FirewallService.Instance.RemoveBlockRulesForAppAsync(r.AppPath);
            StatusText.Text = $"Removed {removed} rule(s) blocking Microsoft/Windows infrastructure.";
            await ReloadAsync();
        }

        private async void DedupBtn_Click(object sender, RoutedEventArgs e)
        {
            int dups = _rows.Sum(r => r.Duplicates);
            if (dups == 0) return;
            if (MessageBox.Show($"Retire {dups} exact-duplicate rule(s)?\n\n" +
                    "One rule per identity is kept with its provenance. Blocking is unchanged and\n" +
                    "continuous — each retiree is renamed to a quarantine name before removal, so\n" +
                    "the by-name delete can never take the keeper with it. Recorded in the block\n" +
                    "history log.",
                    "Clean duplicates", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            DedupBtn.IsEnabled = false;
            try
            {
                var (cleaned, retired, error) = await FirewallService.Instance.RemoveDuplicateBlockRulesAsync();
                BlocksStore.LogFleet("dedup-retired",
                    $"{retired} duplicate rule(s) retired across {cleaned} target(s)", "rules-tab");
                StatusText.Text = error == null
                    ? $"Removed {retired} duplicate rule(s) across {cleaned} target(s)."
                    : $"Removed {retired} duplicate rule(s); some failed: {error}";
            }
            finally { DedupBtn.IsEnabled = true; }
            await ReloadAsync();
        }

        private async void ConsolidateBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show(
                    "Legacy IP blocks created 4 rules each (TCP/UDP × in/out). This consolidates each set to the\n" +
                    "current 2-rule scheme (outbound TCP+UDP): inbound pair deleted, outbound pair renamed with\n" +
                    "provenance preserved. No protection is lost — inbound was already covered by stateful filtering.",
                    "Consolidate legacy", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            var (targets, removedIn, migratedOut) = await FirewallService.Instance.ConsolidateLegacyIpBlocksAsync();
            BlocksStore.LogFleet("consolidated",
                $"{targets} target(s): {removedIn} inbound deleted, {migratedOut} migrated to v2 naming", "manage-all");
            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            StatusText.Text = $"Consolidated {targets} target(s): {removedIn} redundant inbound rule(s) deleted, {migratedOut} migrated to v2 naming.";
            await ReloadAsync();
            if (BlocksView.Current != null) await BlocksView.Current.RefreshIfLoadedAsync();
        }

        private async void ReenableBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Re-enable ALL AutoCommand block rules? (Undoes 'Restore Internet'.)",
                    "Re-enable", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            var res = await FirewallService.Instance.SetAllBlocksEnabledAsync(true);
            BlocksStore.LogFleet("fleet-enabled",
                $"{res.Changed}/{res.Matched} rule(s) re-enabled", "manage-all");
            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            StatusText.Text = $"Re-enabled AutoCommand blocks ({res.Changed} rule(s) changed).";
            await ReloadAsync();
            if (BlocksView.Current != null) await BlocksView.Current.RefreshIfLoadedAsync();
        }

        private async void RestoreExceptRiskyBtn_Click(object sender, RoutedEventArgs e)
        {
            var risky = _rows.Where(r => r.IsRisky).ToList();
            var toRestore = _rows.Where(r => !r.IsRisky).ToList();
            if (toRestore.Count == 0) { MessageBox.Show("Nothing to restore — no non-risky blocks.", "Restore"); return; }

            var preview = new System.Text.StringBuilder();
            preview.AppendLine($"Restore {toRestore.Count} target(s) — everything EXCEPT these {risky.Count}, which stay");
            preview.AppendLine("disabled because blocking them breaks Windows rather than threats:");
            foreach (var r in risky.Take(12)) preview.AppendLine($"  · {r.Target}  ({r.Class})");
            if (risky.Count > 12) preview.AppendLine($"  … and {risky.Count - 12} more");
            preview.AppendLine().AppendLine("Kept-disabled targets remain listed (red rows) — re-enable");
            preview.AppendLine("individually anytime if you truly want them blocked.");
            if (MessageBox.Show(preview.ToString(), "Restore except Microsoft/Windows ⚠",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            var res = await FirewallService.Instance.SetAllBlocksEnabledAsync(true, skipRisky: true);
            BlocksStore.LogFleet("fleet-enabled",
                $"{res.Changed} rule(s) restored, {res.SkippedRisky} risky rule(s) kept disabled",
                "restore-except-risky");
            await Helpers.FirewallBaselineManager.AdoptLiveBlockRulesAsync();
            StatusText.Text = $"Restored {res.Changed} rule(s); kept {res.SkippedRisky} risky rule(s) disabled.";
            await ReloadAsync();
            if (BlocksView.Current != null) await BlocksView.Current.RefreshIfLoadedAsync();
        }

        // RFC-4180 minimal: quote a field holding a comma, quote or newline,
        // doubling internal quotes. Targets and descriptions come from
        // firewall data, not from us — they can contain anything.
        private static string CsvEscape(string value) =>
            value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r')
                ? $"\"{value.Replace("\"", "\"\"")}\""
                : value;

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV (*.csv)|*.csv",
                FileName = $"blocked-rules-{DateTime.Now:yyyyMMdd-HHmm}.csv"
            };
            if (dlg.ShowDialog() != true) return;
            var lines = new List<string> { "Target,Kind,Class,Rules,Enabled,Created,Hits10m,Description" };
            foreach (var r in _rows)
                lines.Add($"{CsvEscape(r.Target)},{CsvEscape(r.Kind)},{CsvEscape(r.Class)},{r.Rules},{r.EnabledRules}," +
                          $"{CsvEscape(r.CreatedDisplay)},{r.Hits},{CsvEscape(r.Description ?? "")}");
            File.WriteAllLines(dlg.FileName, lines);
            StatusText.Text = $"Exported {_rows.Count} rows → {dlg.FileName}";
        }
    }
}
