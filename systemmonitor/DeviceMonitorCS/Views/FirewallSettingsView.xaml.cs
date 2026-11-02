using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using DeviceMonitorCS.Helpers;

namespace DeviceMonitorCS.Views
{
    public partial class FirewallSettingsView : UserControl, INotifyPropertyChanged
    {
        // Data Collections
        public ObservableCollection<FirewallRule> InboundEnabledRules { get; set; } = new ObservableCollection<FirewallRule>();
        public ObservableCollection<FirewallRule> InboundDisabledRules { get; set; } = new ObservableCollection<FirewallRule>();
        
        public ObservableCollection<FirewallRule> OutboundEnabledRules { get; set; } = new ObservableCollection<FirewallRule>();
        public ObservableCollection<FirewallRule> OutboundDisabledRules { get; set; } = new ObservableCollection<FirewallRule>();

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        private bool _isInitialized = false;
        private bool _inboundLoaded = false;
        private bool _outboundLoaded = false;

        public FirewallSettingsView()
        {
            InitializeComponent();
        }

        public async void InitializeAndLoad()
        {
            if (_isInitialized) return;
            _isInitialized = true;
            
            // Only load Inbound initially
            await LoadRules("Inbound");
        }

        private async void MainTab_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.Source is TabControl tc && tc.SelectedItem is TabItem selectedTab)
            {
                // Ensure we only react to the main tab control, not nested ones (bubbling event)
                if (selectedTab.Tag?.ToString() == "Inbound")
                {
                    if (!_inboundLoaded) await LoadRules("Inbound");
                }
                else if (selectedTab.Tag?.ToString() == "Outbound")
                {
                    if (!_outboundLoaded) await LoadRules("Outbound");
                }
            }
        }

        private async void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            // Reset flags and reload CURRENTLY visible tab
            _inboundLoaded = false;
            _outboundLoaded = false;
            
            // Determine active tab
            // This is a bit manual since we don't have a viewmodel binding for SelectedIndex
            // But we can just rely on the SelectionChanged logic if we toggle selection or manually inspect
            // However, triggering SelectionChanged manually is messy.
            
            // Better: Check visibility or just reload both if already loaded?
            // Simple: Check which visual tab is selected?
            // Actually, just reload based on what was previously loaded to keep state consistent?
            // Or simplified: Just Load("Inbound") then if outbound was loaded, Load("Outbound")
            
            await LoadRules("Inbound");
            if (_outboundLoaded) await LoadRules("Outbound");
            // If strictly lazy, we only load the visible one. But checking IsSelected helper would need visual tree inspection or binding.
            // Let's stick to reloading what was previously marked as loaded.
        }

        private async Task LoadRules(string direction)
        {
            try
            {
                Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
                
                if (direction == "Inbound")
                {
                    InboundEnabledRules.Clear();
                    InboundDisabledRules.Clear();
                    _inboundLoaded = true;
                }
                else
                {
                    OutboundEnabledRules.Clear();
                    OutboundDisabledRules.Clear();
                    _outboundLoaded = true;
                }

                string script = $@"
$rules = Get-NetFirewallRule -Direction {direction}
$appFilters = Get-NetFirewallApplicationFilter
$portFilters = Get-NetFirewallPortFilter
$addrFilters = Get-NetFirewallAddressFilter

# Create hashtables for fast lookup by InstanceID
$appHash = @{{}}; $appFilters | ForEach-Object {{ $appHash[$_.InstanceID] = $_ }}
$portHash = @{{}}; $portFilters | ForEach-Object {{ $portHash[$_.InstanceID] = $_ }}
$addrHash = @{{}}; $addrFilters | ForEach-Object {{ $addrHash[$_.InstanceID] = $_ }}

$rules | ForEach-Object {{
    $r = $_
    $app = $appHash[$r.Name]
    $port = $portHash[$r.Name]
    $addr = $addrHash[$r.Name]
    
    [PSCustomObject]@{{
        Name = $r.Name
        DisplayName = $r.DisplayName
        DisplayGroup = $r.DisplayGroup
        Direction = $r.Direction.ToString()
        Enabled = if ($r.Enabled -eq 1 -or $r.Enabled -eq 'True') {{'Yes'}} else {{'No'}}
        Action = $r.Action.ToString()
        Profile = $r.Profile.ToString()
        Program = if ($app) {{ $app.Program }} else {{ '' }}
        Protocol = if ($port) {{ $port.Protocol }} else {{ '' }}
        LocalPort = if ($port -and $port.LocalPort) {{ ($port.LocalPort -join ',') }} else {{ '' }}
        RemotePort = if ($port -and $port.RemotePort) {{ ($port.RemotePort -join ',') }} else {{ '' }}
        RemoteAddress = if ($addr -and $addr.RemoteAddress) {{ ($addr.RemoteAddress -join ',') }} else {{ '' }}
    }}
}} | ConvertTo-Json -Depth 2
";
                string json = await RunPowershellAsync(script);

                if (string.IsNullOrWhiteSpace(json)) 
                {
                    // No rules found or error (silent fail preferred here than annoying popup if just empty)
                    return;
                }

                if (!json.TrimStart().StartsWith("[")) json = $"[{json}]";

                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var rules = JsonSerializer.Deserialize<FirewallRule[]>(json, options);
                
                if (rules == null) return;

                // PARTITIONING LOGIC
                // Group by DisplayGroup
                var groupedRules = rules.GroupBy(r => string.IsNullOrEmpty(r.DisplayGroup) ? "(Ungrouped)" : r.DisplayGroup).ToList();

                // Split into Enabled and Disabled Groups
                var enabledGroups = groupedRules.Where(g => g.Any(r => r.IsEnabledBool)).ToList();
                var disabledGroups = groupedRules.Where(g => g.All(r => !r.IsEnabledBool)).ToList();

                // SORTING: Enabled Groups by Rule Count (Ascending - "least rules on top")
                var sortedEnabledGroups = enabledGroups.OrderBy(g => g.Count()).ToList();

                // Add Enabled Rules (Sorted by Group Size)
                foreach(var group in sortedEnabledGroups)
                {
                    foreach(var rule in group)
                    {
                        if (string.IsNullOrEmpty(rule.DisplayGroup)) rule.DisplayGroup = "(Ungrouped)";
                        
                        if (direction == "Inbound") InboundEnabledRules.Add(rule);
                        else OutboundEnabledRules.Add(rule);
                    }
                }

                // Add Disabled Rules (Unsorted / Default Order)
                foreach (var group in disabledGroups)
                {
                    foreach (var rule in group)
                    {
                        if (string.IsNullOrEmpty(rule.DisplayGroup)) rule.DisplayGroup = "(Ungrouped)";

                        if (direction == "Inbound") InboundDisabledRules.Add(rule);
                        else OutboundDisabledRules.Add(rule);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading rules: {ex.Message}");
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private async void ToggleRule_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.CommandParameter is FirewallRule rule)
            {
                await ToggleRule(rule);
            }
        }

        private async void ToggleRuleCtx_Click(object sender, RoutedEventArgs e)
        {
            // Helper to get active grid would be complex due to 4 grids.
            // Simplified: User Right-clicked. The ContextMenu placement target is the DataGrid.
            if (sender is MenuItem mi && mi.Parent is ContextMenu cm && cm.PlacementTarget is DataGrid grid && grid.SelectedItem is FirewallRule rule)
            {
                await ToggleRule(rule);
            }
        }

        private async void GroupToggle_Click(object sender, RoutedEventArgs e)
        {
             if (sender is CheckBox cb && cb.Tag is string groupName)
             {
                 bool? isChecked = cb.IsChecked;
                 string targetState = isChecked == true ? "True" : "False";
                 string targetStateUi = isChecked == true ? "Yes" : "No";

                 Mouse.OverrideCursor = Cursors.Wait;
                 try
                 {
                     // PowerShell update (Scoped by Group Name - affects ALL rules in that group regardless of direction technically, but we usually want scoped)
                     // Standard Windows behavior: Group toggle affects all rules in that group.
                     await RunPowershellAsync($"Set-NetFirewallRule -DisplayGroup '{groupName}' -Enabled {targetState}");

                     // Update UI & Repartition
                     // Efficient way: Update properties, then move if necessary.
                     // Or Lazy way: Reload affected direction.
                     
                     // Since moving groups between tabs is visually complex to animate, reloading data might be cleanest
                     // But reloading is slow (3-5s).
                     // Ideally we verify if the group state flipped.
                     // "Enabled Groups" -> Disabled all rules -> Move to "Disabled Groups".
                     // "Disabled Groups" -> Enabled one rule -> Move to "Enabled Groups".
                     
                     // Let's implement full reload for correctness for now, as re-partitioning logic is complex to do in-place.
                     // Trigger reload for both if loaded?
                     
                     // Optimization: Only reload the affected directions.
                     if (_inboundLoaded) await LoadRules("Inbound");
                     if (_outboundLoaded) await LoadRules("Outbound");
                 }
                 catch (Exception ex)
                 {
                     MessageBox.Show($"Error toggling group: {ex.Message}");
                 }
                 finally
                 {
                     Mouse.OverrideCursor = null;
                 }
             }
        }

        private async Task ToggleRule(FirewallRule rule)
        {
            try
            {
                Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
                bool isEnabled = rule.Enabled != null && rule.Enabled.Equals("Yes", StringComparison.OrdinalIgnoreCase);
                string newState = isEnabled ? "False" : "True";

                await RunPowershellAsync($"Set-NetFirewallRule -Name '{rule.Name}' -Enabled {newState}");
                
                // Update Model locally
                rule.Enabled = isEnabled ? "No" : "Yes";
                
                // Persist State
                FirewallConfigManager.Instance.SetOverride(rule.Name, rule.Enabled);

                // Check RE-PARTITIONING requirement
                // If we disabled the LAST enabled rule in a group, the group should move to Disabled tab.
                // If we enabled a rule in a Disabled group, the group should move to Enabled tab.
                
                // For simplicity and robustness, currently triggering a Reload of that direction key.
                // Determine direction
                string dir = rule.Direction; // "Inbound" or "Outbound"
                await LoadRules(dir);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error updating rule: {ex.Message}");
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private void AskAiRule_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem mi && mi.Parent is ContextMenu cm && cm.PlacementTarget is DataGrid grid && grid.SelectedItem is FirewallRule rule)
            {
                var win = Window.GetWindow(this);
                var aiWin = new AskAiWindow(rule);
                if (win != null) aiWin.Owner = win;
                aiWin.ShowDialog();
            }
        }

        private void AskAiGroup_Click(object sender, RoutedEventArgs e)
        {
             // Simplified context finding logic
             string groupName = null;
             if (sender is MenuItem mi && mi.Tag is string t) groupName = t;

             if (!string.IsNullOrEmpty(groupName))
             {
                 // Need to find rules across all 4 lists? 
                 // Or just passed in rules? ContextMenu implementation used Tag binding.
                 // Let's just aggregate from all loaded lists to be safe.
                 var rules = new List<FirewallRule>();
                 rules.AddRange(InboundEnabledRules.Where(r => r.DisplayGroup == groupName));
                 rules.AddRange(InboundDisabledRules.Where(r => r.DisplayGroup == groupName));
                 rules.AddRange(OutboundEnabledRules.Where(r => r.DisplayGroup == groupName));
                 rules.AddRange(OutboundDisabledRules.Where(r => r.DisplayGroup == groupName));

                 var context = new 
                 {
                     Group = groupName,
                     TotalRules = rules.Count,
                     EnabledCount = rules.Count(r => r.IsEnabledBool),
                     RulesSample = rules.Take(20).Select(r => new { r.Name, r.DisplayName, r.Enabled, r.Action, r.Direction }).ToList()
                 };

                 var win = Window.GetWindow(this);
                 var aiWin = new AskAiWindow(context);
                 if (win != null) aiWin.Owner = win;
                 aiWin.ShowDialog();
             }
        }

        private void GroupExpander_Expanded(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement fe)
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    var groupItem = FindVisualParent<GroupItem>(fe);
                    if (groupItem != null)
                    {
                        var parent = ItemsControl.ItemsControlFromItemContainer(groupItem);
                        if (parent is DataGrid dataGrid)
                        {
                            dataGrid.InvalidateMeasure();
                            dataGrid.UpdateLayout();

                            if (dataGrid.Columns.Count > 0)
                            {
                                var col = dataGrid.Columns[0];
                                var w = col.Width;
                                col.Width = DataGridLength.Auto;
                                dataGrid.UpdateLayout();
                                col.Width = w;
                            }
                        }
                    }
                }), System.Windows.Threading.DispatcherPriority.ContextIdle);
            }
        }

        private static T FindVisualParent<T>(DependencyObject child) where T : DependencyObject
        {
            DependencyObject parentObject = System.Windows.Media.VisualTreeHelper.GetParent(child);
            if (parentObject == null) return null;
            if (parentObject is T parent) return parent;
            return FindVisualParent<T>(parentObject);
        }

        private async void ResetBtn_Click(object sender, RoutedEventArgs e)
        {
            var res = MessageBox.Show("Are you sure you want to reset Windows Firewall configuration to defaults? This may affect network connectivity.", "Confirm Reset", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes)
            {
                try
                {
                    Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
                    var psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall reset",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };
                    var p = Process.Start(psi);
                    await p.WaitForExitAsync();
                    
                    MessageBox.Show("Firewall reset command executed. Reloading rules...", "Success");
                    
                    // Reload everything that was loaded
                    if (_inboundLoaded) await LoadRules("Inbound");
                    if (_outboundLoaded) await LoadRules("Outbound");
                }
                catch (Exception ex)
                {
                     MessageBox.Show($"Error resetting firewall: {ex.Message}");
                }
                finally
                {
                    Mouse.OverrideCursor = null;
                }
            }
        }

        private async void ProfileSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_isInitialized) return;
            
            if (ProfileSelector.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                if (tag == "Custom") return; // No action

                Mouse.OverrideCursor = Cursors.Wait;
                try
                {
                    Services.FirewallProfileService.ProfileType profile;
                    if (Enum.TryParse(tag, out profile))
                    {
                        await Services.FirewallProfileService.Instance.ApplyProfile(profile);
                        MessageBox.Show($"Profile '{item.Content}' applied successfully.", "Profile Updated");
                        
                        // Reload Rules
                       if (_inboundLoaded) await LoadRules("Inbound");
                       if (_outboundLoaded) await LoadRules("Outbound");
                    }
                }
                catch (Exception ex)
                {
                     MessageBox.Show($"Error applying profile: {ex.Message}");
                }
                finally
                {
                    Mouse.OverrideCursor = null;
                }
            }
        }

        private Task<string> RunPowershellAsync(string script)
        {
            return Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-Command \"{script}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var p = Process.Start(psi);
                    if (p == null) return "";
                    
                    var output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    return output;
                }
                catch { return ""; }
            });
        }
    }

    public class FirewallRule : INotifyPropertyChanged
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string DisplayGroup { get; set; }
        public string Direction { get; set; }
        public string Action { get; set; }
        public string Profile { get; set; }
        public string Program { get; set; }
        public string Protocol { get; set; }
        public string LocalPort { get; set; }
        public string RemotePort { get; set; }
        public string RemoteAddress { get; set; }

        private string _enabled;
        public string Enabled 
        { 
            get => _enabled; 
            set 
            {
                if (_enabled != value)
                {
                    _enabled = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsEnabledBool));
                }
            } 
        }

        public bool IsEnabledBool => Enabled != null && Enabled.Equals("Yes", StringComparison.OrdinalIgnoreCase);

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public class GroupToEnabledStateConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // value is ReadOnlyObservableCollection<object> (the Items in the group)
            if (value is IList<object> items)
            {
                var rules = items.OfType<FirewallRule>().ToList();
                if (rules.Count == 0) return false;

                bool allEnabled = rules.All(r => r.IsEnabledBool);
                bool allDisabled = rules.All(r => !r.IsEnabledBool);

                if (allEnabled) return true;
                if (allDisabled) return false;
                return null; // Indeterminate
            }
            return false;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    public class GroupCountToExpansionStateConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int count)
            {
                // Expanded (true) if count <= 5, otherwise Collapsed (false)
                return count <= 5;
            }
            return false;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
