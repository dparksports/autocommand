using AutoCommand.Contain.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace AutoCommand.Views
{
    /// <summary>
    /// The service picker for service-scoped blocks: lets the user block ANY
    /// installed Windows service WITHOUT waiting for a live row — the
    /// row-menu path can only block services already seen connecting.
    /// Enumerates every Win32_Service with one background WMI query,
    /// overlays the catalog's authored descriptions/impact where they
    /// exist, and shows each service's ACTUAL host process: PID plus -k
    /// group for svchost-hosted services ("PID 2344 · svchost.exe -k netsvcs
    /// · N services share this host"), "own process" otherwise. Stopped
    /// services are listed too — the block is scoped by service NAME
    /// (rule.ServiceName), so it applies the moment the service starts.
    /// The selected key goes back to the caller, which runs the confirm +
    /// block flow.
    /// </summary>
    public partial class ServiceBlockWindow : Window
    {
        public string SelectedServiceKey { get; private set; }

        /// <summary>Every service, built once per load; the search box
        /// filters this into the live view.</summary>
        private List<ServiceRow> _all = new();

        public ServiceBlockWindow()
        {
            InitializeComponent();
            ServiceList.SelectionChanged += (_, _) =>
                BlockBtn.IsEnabled = ServiceList.SelectedItem is ServiceRow;
            Loaded += async (_, _) => await LoadServicesAsync();
        }

        /// <summary>Full enumeration on load (house pattern: background
        /// Task.Run + status text, per BlockedRulesWindow). Re-running on a
        /// later Loaded refreshes the live PIDs, which drift as svchost
        /// instances recycle.</summary>
        private async Task LoadServicesAsync()
        {
            ServiceList.ItemsSource = null;
            BlockBtn.IsEnabled = false;
            StatusText.Visibility = Visibility.Visible;
            try
            {
                var snapshot = await Task.Run(EnumerateServices);
                _all = BuildRows(snapshot);
                ApplyFilter();
            }
            finally
            {
                StatusText.Visibility = Visibility.Collapsed;
            }
        }

        /// <summary>One WMI query returns every user-mode service together
        /// with the two facts the host line needs: the live ProcessId, and
        /// the PathName ("svchost.exe -k netsvcs -p") that carries the -k
        /// group. Kernel drivers (Win32_SystemDriver) are deliberately out
        /// of scope — a ServiceName-scoped firewall rule cannot apply to
        /// them.</summary>
        private static List<ServiceSnapshot> EnumerateServices()
        {
            var rows = new List<ServiceSnapshot>();
            var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, Description, State, ProcessId, PathName FROM Win32_Service");

            foreach (var mo in searcher.Get())
            {
                rows.Add(new ServiceSnapshot(
                    Name: Convert.ToString(mo["Name"]) ?? string.Empty,
                    DisplayName: Convert.ToString(mo["DisplayName"]),
                    Description: Convert.ToString(mo["Description"]),
                    State: Convert.ToString(mo["State"]) ?? string.Empty,
                    ProcessId: uint.TryParse(Convert.ToString(mo["ProcessId"]), out var pid) ? pid : 0u,
                    PathName: Convert.ToString(mo["PathName"])));
            }

            return rows;
        }

        /// <summary>Overlays the authored catalog onto the live snapshot and
        /// composes each row's host line. Sibling counts come free: group
        /// the same snapshot by ProcessId — no extra WMI round trips.</summary>
        private List<ServiceRow> BuildRows(List<ServiceSnapshot> snapshot)
        {
            var servicesPerPid = snapshot
                .Where(s => s.ProcessId > 0)
                .GroupBy(s => s.ProcessId)
                .ToDictionary(g => g.Key, g => g.Count());

            var rows = new List<ServiceRow>(snapshot.Count);

            foreach (var s in snapshot)
            {
                var key = s.Name;
                var curated = ServiceCatalog.CuratedPhoneHomeKeys.Contains(key, StringComparer.OrdinalIgnoreCase);
                var hasCatalog = ServiceCatalog.TryGet(key, out var info);
                var isRunning = s.State.Equals("Running", StringComparison.OrdinalIgnoreCase);
                var isSvchost = !string.IsNullOrEmpty(s.PathName)
                                && s.PathName.IndexOf("svchost.exe", StringComparison.OrdinalIgnoreCase) >= 0;
                var group = isSvchost ? SvchostIdentity.Parse(s.PathName).Group : null;

                string host;
                if (isSvchost)
                {
                    var hostPart = group is null ? "svchost.exe" : $"svchost.exe -k {group}";
                    host = isRunning
                        ? $"PID {s.ProcessId} · {hostPart}"
                        : $"{hostPart} · not running";
                }
                else
                {
                    host = isRunning ? $"own process · PID {s.ProcessId}" : "own process · not running";
                }

                if (isRunning
                    && servicesPerPid.TryGetValue(s.ProcessId, out var hostCount)
                    && hostCount > 1)
                {
                    host += $" · {hostCount} services share this host";
                }

                rows.Add(new ServiceRow
                {
                    ServiceKey = key,
                    DisplayName = hasCatalog ? info.DisplayName : (s.DisplayName ?? key),
                    Description = hasCatalog
                        ? info.Description
                        : (string.IsNullOrWhiteSpace(s.Description)
                            ? "No description available — verify what this service does before blocking it."
                            : s.Description.Trim()),
                    ImpactLabel = hasCatalog
                        ? (info.Impact switch
                        {
                            ServiceImpact.High => "⚠ high impact",
                            ServiceImpact.Medium => "notable impact",
                            _ => "normal impact",
                        })
                        : "unlisted service",
                    ImpactBrush = hasCatalog
                        ? (info.Impact switch
                        {
                            ServiceImpact.High => new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71)),
                            ServiceImpact.Medium => new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
                            _ => new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
                        })
                        : new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
                    StateLabel = isRunning ? "Running" : "Stopped",
                    StateBrush = isRunning
                        ? new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80))
                        : new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
                    HostProcess = host,
                    IsCurated = curated,
                    GroupLabel = curated ? "Suggested — known phone-home offenders" : "All services",
                    IsRunning = isRunning,
                });
            }

            rows.Sort((a, b) =>
            {
                if (a.IsCurated != b.IsCurated) return a.IsCurated ? -1 : 1;
                if (a.IsRunning != b.IsRunning) return a.IsRunning ? -1 : 1;
                return string.Compare(a.DisplayName, b.DisplayName, StringComparison.CurrentCultureIgnoreCase);
            });

            return rows;
        }

        private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
            => ApplyFilter();

        /// <summary>Search box filter (case-insensitive across key, display
        /// name and description), grouped curated-first — the BlocksView
        /// search pattern.</summary>
        private void ApplyFilter()
        {
            var q = (SearchBox.Text ?? string.Empty).Trim();
            IEnumerable<ServiceRow> matches = _all;

            if (q.Length > 0)
            {
                matches = matches.Where(r =>
                    r.ServiceKey?.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0
                    || r.DisplayName?.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0
                    || r.Description?.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            var view = new ListCollectionView(matches.ToList());
            view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ServiceRow.GroupLabel)));
            ServiceList.ItemsSource = view;
            BlockBtn.IsEnabled = false;
        }

        private void BlockBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ServiceList.SelectedItem is ServiceRow row)
            {
                SelectedServiceKey = row.ServiceKey;
                DialogResult = true;
            }
        }

        /// <summary>One WMI service row — plain data extracted on the
        /// enumeration thread; no COM objects cross back to the UI.</summary>
        private sealed record ServiceSnapshot(
            string Name, string DisplayName, string Description,
            string State, uint ProcessId, string PathName);

        /// <summary>Row view-model for one service — public properties, not
        /// fields: the XAML bindings need them.</summary>
        public sealed class ServiceRow
        {
            public string ServiceKey { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
            public string ImpactLabel { get; set; }
            public Brush ImpactBrush { get; set; }
            public string StateLabel { get; set; }
            public Brush StateBrush { get; set; }
            public string HostProcess { get; set; }
            public bool IsCurated { get; set; }
            public string GroupLabel { get; set; }
            public bool IsRunning { get; set; }
        }
    }
}
