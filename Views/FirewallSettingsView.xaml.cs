using System;
using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using AutoCommand.Helpers;
using AutoCommand.Models;
using System.Text;
using AutoCommand.Services;

namespace AutoCommand.Views
{
    public partial class FirewallSettingsView : UserControl
    {
        private List<FirewallRuleItem> _currentRules = new();

        public FirewallSettingsView()
        {
            InitializeComponent();
        }

        private async void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadRules();
            await UpdateBaselineStatusAsync();
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            await LoadRules();
            await UpdateBaselineStatusAsync();
        }

        private async Task UpdateBaselineStatusAsync()
        {
            var info = FirewallBaselineManager.BaselineInfo;
            if (FirewallBaselineManager.IsPaused)
            {
                BaselineStatusText.Text = $"Baseline auto-fix PAUSED until {FirewallBaselineManager.PausedUntilUtc.ToLocalTime():HH:mm}"
                                          + (info == null ? "" : $" — baseline has {info.Value.Count} rules");
            }
            else
            {
                BaselineStatusText.Text = info == null
                    ? "No baseline — apply a profile or click Re-baseline to capture one"
                    : $"Baseline: {info.Value.Count} rules (captured {info.Value.CapturedAt:yyyy-MM-dd HH:mm})";
            }
        }

        private async void RebaselineBtn_Click(object sender, RoutedEventArgs e)
        {
            RebaselineBtn.IsEnabled = false;
            try
            {
                var (count, at) = await FirewallBaselineManager.CaptureBaselineAsync();
                BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";
            }
            finally
            {
                RebaselineBtn.IsEnabled = true;
            }
        }

        private async void PauseEnforcementBtn_Click(object sender, RoutedEventArgs e)
        {
            FirewallBaselineManager.PauseForMinutes(15);
            await UpdateBaselineStatusAsync();
        }

        private async void RenameLegacyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show(
                    "Block rules still using the legacy \"AutoCommand IP Block / Process Block\" names will be\n" +
                    "recreated under the current AC-BLOCK naming scheme.\n\n" +
                    "• Lossless — descriptions (provenance) carry over\n" +
                    "• Redundant inbound duplicates are removed (covered by stateful filtering)\n" +
                    "• Protection is unchanged\n" +
                    "• The baseline is re-captured afterwards so the enforcer doesn't flag the new names",
                    "Rename legacy blocks", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            RenameLegacyBtn.IsEnabled = false;
            ProfileStatusText.Text = "Renaming legacy block rules…";
            try
            {
                var (targets, removedIn, migrated) = await FirewallService.Instance.ConsolidateLegacyIpBlocksAsync();

                // Names changed — re-capture so the enforcer doesn't report the new
                // AC-BLOCK names as drift (the baseline is keyed by rule name)
                var (count, at) = await FirewallBaselineManager.CaptureBaselineAsync();
                BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";

                ProfileStatusText.Text = $"Renamed legacy rules across {targets} target(s): "
                                         + $"{migrated} migrated to AC-BLOCK naming, {removedIn} redundant inbound rule(s) removed.";
            }
            catch (Exception ex)
            {
                ProfileStatusText.Text = $"Rename failed: {ex.Message}";
                MessageBox.Show($"Failed to rename legacy block rules: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                await LoadRules(); // refresh the grid and the button's enabled state
            }
        }

        private async void FilterChanged(object sender, RoutedEventArgs e) => await LoadRules();

        private async Task LoadRules()
        {
            int direction = InboundRadio.IsChecked == true ? 1 : 2;
            _currentRules = await FirewallService.Instance.LoadRulesAsync(direction);

            // Enabled rules first (then alphabetical) so the refreshed list reads top-down
            _currentRules = _currentRules.OrderByDescending(r => r.Enabled)
                                         .ThenBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase)
                                         .ToList();

            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_currentRules);
            view.GroupDescriptions.Clear();
            view.GroupDescriptions.Add(new System.Windows.Data.PropertyGroupDescription("DisplayName"));

            RulesGrid.ItemsSource = view;

            int enabled = _currentRules.Count(r => r.Enabled);
            string dir = direction == 1 ? "Inbound" : "Outbound";
            RuleCountText.Text = $"{_currentRules.Count} {dir} rules ({enabled} enabled)";

            int legacy = await FirewallService.Instance.CountLegacyBlocksAsync();
            RenameLegacyBtn.IsEnabled = legacy > 0;
            RenameLegacyBtn.ToolTip = legacy == 0
                ? "No legacy-named AutoCommand block rules — nothing to rename."
                : $"{legacy} legacy-named AutoCommand block rule(s) found. Click to rename them to the current AC-BLOCK scheme.";
        }

        private async void ToggleRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not FirewallRuleItem rule) return;
            bool newState = !rule.Enabled;
            await FirewallService.Instance.ToggleRuleAsync(rule.Name, newState);
            rule.Enabled = newState;
            // Rule-level toggles are invisible to the Blocks tab's pause
            // history (no store status flips) — audit them so a hand-toggled
            // AC-BLOCK rule still answers "who turned this off, when".
            BlocksStore.AppendEvent("rule-toggled", "-", rule.Name,
                newState ? "enabled" : "disabled", "firewall-tab");
            // Adopt the change into the baseline so the enforcer doesn't revert it
            FirewallBaselineManager.UpdateRuleState(rule.Name, newState);
        }

        private async void EnableGroup_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not FirewallRuleItem rule) return;
            ProfileStatusText.Text = $"Enabling group '{rule.DisplayGroup}'…";
            var r = await FirewallService.Instance.ToggleGroupAsync(rule.DisplayGroup, true);
            ProfileStatusText.Text = $"Group '{rule.DisplayGroup}': {r.Matched} matched, {r.Changed} changed, {r.Failed} failed"
                                     + (r.FirstError != null ? $" — {r.FirstError}" : "");
            await FirewallBaselineManager.UpdateGroupStateAsync(rule.DisplayGroup, true);
            await LoadRules();
        }

        private async void DisableGroup_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not FirewallRuleItem rule) return;
            ProfileStatusText.Text = $"Disabling group '{rule.DisplayGroup}'…";
            var r = await FirewallService.Instance.ToggleGroupAsync(rule.DisplayGroup, false);
            ProfileStatusText.Text = $"Group '{rule.DisplayGroup}': {r.Matched} matched, {r.Changed} changed, {r.Failed} failed"
                                     + (r.FirstError != null ? $" — {r.FirstError}" : "");
            await FirewallBaselineManager.UpdateGroupStateAsync(rule.DisplayGroup, false);
            await LoadRules();
        }

        private void SaveToConfig_Click(object sender, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not FirewallRuleItem rule) return;
            FirewallConfigManager.Instance.SetOverride(rule.Name, rule.Enabled);
            MessageBox.Show($"Saved: {rule.DisplayName} = {(rule.Enabled ? "Enabled" : "Disabled")}",
                "Config Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProfileCombo == null || ProfileCombo.SelectedIndex <= 0) return;

            string profileName = ((ComboBoxItem)ProfileCombo.SelectedItem).Content.ToString();

            if (profileName == "Shields Up")
            {
                // Far more destructive than the other profiles — spell out both steps
                const string warning =
                    "Shields Up performs two destructive steps:\n\n" +
                    "1. RESET TO DEFAULTS — every non-default rule is deleted, including\n" +
                    "    custom rules and AutoCommand's own AC-BLOCK rules.\n" +
                    "2. LOCKDOWN — every inbound and outbound rule is then disabled: all\n" +
                    "    unsolicited incoming traffic is blocked. Outbound traffic may still\n" +
                    "    flow depending on your firewall profile's default actions.\n\n" +
                    "Apply this profile?";
                if (MessageBox.Show(warning, "Confirm Shields Up",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                {
                    ProfileCombo.SelectedIndex = 0; // Reset to Custom
                    return;
                }
            }
            else if (MessageBox.Show($"Apply '{profileName}' profile?\n\nThis will modify your Windows Defender Firewall rules.",
                "Confirm Firewall Profile", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            {
                ProfileCombo.SelectedIndex = 0; // Reset to Custom
                return;
            }

            FirewallProfileService.ProfileType type;
            switch (profileName)
            {
                case "Shields Up + mDNS": type = FirewallProfileService.ProfileType.ShieldsUpMdns; break;
                case "Allow Discovery + Cast": type = FirewallProfileService.ProfileType.AllowDiscoveryCast; break;
                case "Allow Sharing + Discovery + Remote Desktop": type = FirewallProfileService.ProfileType.AllowSharingDiscoveryRemoteDesktop; break;
                case "Allow Sharing + Discovery": type = FirewallProfileService.ProfileType.AllowSharingDiscovery; break;
                case "Block Sharing + Discovery + Remote Desktop": type = FirewallProfileService.ProfileType.BlockSharingDiscoveryRemoteDesktop; break;
                case "Shields Up": type = FirewallProfileService.ProfileType.ShieldsUp; break;
                default:
                    ProfileCombo.SelectedIndex = 0;
                    return;
            }

            ProfileCombo.IsEnabled = false;
            RefreshBtn.IsEnabled = false;
            ProfileProgress.Visibility = Visibility.Visible;
            ProfileStatusText.Text = $"Applying '{profileName}' profile…";
            var progress = new Progress<string>(msg => ProfileStatusText.Text = msg);

            try
            {
                // The profile churns dozens of rule states — keep the drift
                // enforcer out of the apply window (its 60s tick must not
                // "fix" the transition); the re-capture below is atomic with
                // this apply (2026-10-30 field report §3).
                FirewallBaselineManager.PauseForMinutes(1);
                ProfileApplyResult result = await FirewallProfileService.Instance.ApplyProfile(type, progress);

                await LoadRules(); // Auto-refresh the grid so the new state is shown immediately

                // The profile's end state is now the expected state — capture it as the
                // baseline the Security Enforcer will enforce against future drift
                int baselineCount = 0;
                try
                {
                    var (count, at) = await FirewallBaselineManager.CaptureBaselineAsync();
                    baselineCount = count;
                    BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";
                }
                catch { }

                var sb = new StringBuilder();
                sb.AppendLine($"Profile '{profileName}' applied.");
                if (!string.IsNullOrEmpty(result.Notes)) sb.AppendLine(result.Notes);
                foreach (var g in result.Groups)
                {
                    if (g.GroupName == "Shields Up + mDNS (block all)" || g.GroupName == "Lockdown (reset to defaults)")
                        continue; // Covered by the Notes line
                    sb.AppendLine($"• {g.GroupName}: {g.Matched} matched, {g.Changed} changed"
                                  + (g.Failed > 0 ? $", {g.Failed} FAILED" : ""));
                }
                sb.AppendLine($"Total: {result.TotalChanged} rule(s) changed, {result.TotalFailed} failed.");
                if (baselineCount > 0)
                    sb.AppendLine($"Baseline captured with {baselineCount} rules — drift from this state will now be detected and fixed automatically.");
                if (result.TotalMatched == 0) sb.AppendLine("No matching rules were found — no changes were made.");
                if (result.FirstError != null) sb.AppendLine($"First error: {result.FirstError}");

                ProfileStatusText.Text = $"Profile '{profileName}': {result.TotalChanged} rule(s) changed, "
                                         + $"{result.TotalFailed} failed. Rules list refreshed.";

                MessageBox.Show(sb.ToString(), "Firewall Profile Complete", MessageBoxButton.OK,
                    result.TotalFailed > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ProfileStatusText.Text = $"Failed to apply '{profileName}': {ex.Message}";
                MessageBox.Show($"Failed to apply profile: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ProfileProgress.Visibility = Visibility.Collapsed;
                RefreshBtn.IsEnabled = true;
                // Reset combobox back to custom to allow re-selection later
                ProfileCombo.IsEnabled = true;
                ProfileCombo.SelectedIndex = 0;
            }
        }

        /// <summary>
        /// ⏪ Restore snapshot: re-import a pre-lockdown rule snapshot. Every
        /// "Shields Up" lockdown photographs the rule set before the reset
        /// deletes it; this is the undo — deleted rules are recreated from
        /// their photographed fields, surviving (default) rules are re-enabled
        /// to their photographed state. The restored state is re-captured as
        /// the drift baseline, exactly like a profile apply.
        /// </summary>
        private async void RestoreSnapshotBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Choose a pre-lockdown firewall snapshot",
                Filter = "Firewall snapshots (lockdown-*.json)|lockdown-*.json|JSON files (*.json)|*.json",
                InitialDirectory = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "AutoCommand", "firewall-snapshots")
            };
            if (dialog.ShowDialog() != true) return;

            if (MessageBox.Show(
                    $"Restore firewall rules from\n{System.IO.Path.GetFileName(dialog.FileName)}?\n\n" +
                    "Rules the lockdown deleted are recreated; rules that survived are re-enabled to their " +
                    "photographed state. Rules created after the snapshot are left untouched.",
                    "⏪ Restore snapshot", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;

            ProfileCombo.IsEnabled = false;
            RefreshBtn.IsEnabled = false;
            ProfileProgress.Visibility = Visibility.Visible;
            ProfileStatusText.Text = "Restoring snapshot…";
            var progress = new Progress<string>(msg => ProfileStatusText.Text = msg);

            try
            {
                // Same contract as a profile apply: keep the drift enforcer
                // out of the transition, then re-capture the end state as
                // the enforced baseline.
                FirewallBaselineManager.PauseForMinutes(1);
                var result = await FirewallService.Instance.RestoreFromSnapshotAsync(dialog.FileName, progress);
                await LoadRules();

                int baselineCount = 0;
                try
                {
                    var (count, at) = await FirewallBaselineManager.CaptureBaselineAsync();
                    baselineCount = count;
                    BaselineStatusText.Text = $"Baseline: {count} rules (captured {at:yyyy-MM-dd HH:mm})";
                }
                catch { }

                var sb = new StringBuilder();
                sb.AppendLine($"Snapshot restore: {result.Changed} rule(s) applied, {result.Failed} failed.");
                if (baselineCount > 0)
                    sb.AppendLine($"Baseline captured with {baselineCount} rules — drift from this state will now be detected and fixed automatically.");
                if (result.FirstError != null) sb.AppendLine($"First error: {result.FirstError}");
                ProfileStatusText.Text = $"Snapshot restore: {result.Changed} applied, {result.Failed} failed.";
                MessageBox.Show(sb.ToString(), "⏪ Restore snapshot", MessageBoxButton.OK,
                    result.Failed > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ProfileStatusText.Text = $"Snapshot restore failed: {ex.Message}";
                MessageBox.Show($"Snapshot restore failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ProfileProgress.Visibility = Visibility.Collapsed;
                RefreshBtn.IsEnabled = true;
                ProfileCombo.IsEnabled = true;
            }
        }
    }
}

