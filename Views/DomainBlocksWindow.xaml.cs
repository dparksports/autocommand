using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using AutoCommand.Contain.Core;

namespace AutoCommand.Views
{
    /// <summary>
    /// The domain-block manager: add/remove domains that AutoCommand keeps
    /// blocked across CDN rotations (DomainBlockSyncService does the syncing;
    /// this window is the user-facing list). Adding probes the BlockImpactProbe
    /// first so a CDN-shared address warns before the rules land — the same
    /// "think twice" line the per-IP confirm dialog carries.
    /// </summary>
    public partial class DomainBlocksWindow : Window
    {
        public DomainBlocksWindow()
        {
            InitializeComponent();
            DomainBlockSyncService.Instance.Start();   // idempotent; ensures list + map are loaded
            DomainBlockSyncService.Instance.BlocksChanged += OnBlocksChanged;
            Closed += (_, _) => DomainBlockSyncService.Instance.BlocksChanged -= OnBlocksChanged;
            Reload();
        }

        private sealed class Row
        {
            public string Domain;
            public string AddedDisplay;
            public string HoldingDisplay;
        }

        private void OnBlocksChanged() => Dispatcher.Invoke(Reload);

        private void Reload()
        {
            var rows = new List<Row>();
            foreach (var b in DomainBlockSyncService.Instance.All())
            {
                var (ips, rules) = DomainBlockSyncService.Instance.OwnedFor(b.Domain);
                rows.Add(new Row
                {
                    Domain = b.Domain,
                    AddedDisplay = b.AddedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
                    HoldingDisplay = ips == 0 ? "resolving…" : $"{ips} IP(s) · {rules} rule(s)",
                });
            }
            BlocksLv.ItemsSource = rows;
            StatusText.Text = rows.Count == 0
                ? "No domain blocks yet. Try one: type a hostname above and click Block domain."
                : $"{rows.Count} domain(s) — the DNS sync runs every 5 minutes and once at startup.";
        }

        private async void AddBtn_Click(object sender, RoutedEventArgs e) => await AddFromBoxAsync();

        private async void DomainBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await AddFromBoxAsync();
        }

        private async Task AddFromBoxAsync()
        {
            string domain = DomainBox.Text.Trim();
            if (domain.Length == 0) return;
            if (!DomainBlockSyncService.IsValidDomain(domain))
            {
                StatusText.Text = $"'{domain}' is not a DNS hostname (expect something like example.com).";
                return;
            }

            AddBtn.IsEnabled = false;
            try
            {
                StatusText.Text = $"Probing {domain} for shared infrastructure…";
                var impact = await BlockImpactProbe.ProbeAsync(domain);
                if (impact.Affected.Count > 0)
                {
                    string names = string.Join("\n  · ", impact.Affected.Select(s => $"{s.Domain} — {s.Story}"));
                    var proceed = MessageBox.Show(
                        $"These addresses are shared infrastructure — blocking {domain} also reaches:\n\n  · {names}\n\n" +
                        (impact.Incomplete ? "The probe could not check every service, so the list may be longer.\n\n" : "") +
                        "Block the domain anyway?", "Shared infrastructure detected",
                        MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                    if (proceed != MessageBoxResult.Yes)
                    {
                        StatusText.Text = $"Cancelled — {domain} was not blocked.";
                        return;
                    }
                }
                await DomainBlockSyncService.Instance.AddAsync(domain, "blocks-tab");
                DomainBox.Text = "";
                StatusText.Text = $"Blocked {domain} — rules materialize as its addresses resolve (see the Blocks list).";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Failed to add {domain}: {ex.Message}";
            }
            finally
            {
                AddBtn.IsEnabled = true;
            }
        }

        private async void RemoveRow_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.DataContext is not Row row) return;
            try
            {
                await DomainBlockSyncService.Instance.RemoveAsync(row.Domain, "blocks-tab");
                StatusText.Text = $"Removed {row.Domain} — its sync-created rules were retired (manual blocks kept).";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Failed to remove {row.Domain}: {ex.Message}";
            }
        }

        private async void SyncNowBtn_Click(object sender, RoutedEventArgs e)
        {
            SyncNowBtn.IsEnabled = false;
            StatusText.Text = "Syncing every domain against current DNS…";
            try
            {
                await DomainBlockSyncService.Instance.SyncAllAsync();
                StatusText.Text = "Sync complete — new addresses blocked, rotated addresses retired.";
            }
            finally
            {
                SyncNowBtn.IsEnabled = true;
            }
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();
    }
}
