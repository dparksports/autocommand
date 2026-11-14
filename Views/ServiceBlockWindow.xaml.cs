using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using AutoCommand.Contain.Core;

namespace AutoCommand.Views
{
    /// <summary>
    /// The service picker for service-scoped blocks: lets the user block a
    /// curated svchost-hosted service WITHOUT waiting for a live row — the
    /// row-menu path can only block services already seen connecting. Lists
    /// the service catalog's curated entries (display name, key, impact,
    /// consequence story); the selected key goes back to the caller, which
    /// runs the confirm + block flow.
    /// </summary>
    public partial class ServiceBlockWindow : Window
    {
        public string SelectedServiceKey { get; private set; }

        public ServiceBlockWindow()
        {
            InitializeComponent();

            var items = new List<ServiceRow>();
            foreach (var key in ServiceCatalog.CuratedPhoneHomeKeys)
            {
                if (!ServiceCatalog.TryGet(key, out var info)) continue;
                items.Add(new ServiceRow
                {
                    ServiceKey = key,
                    DisplayName = info.DisplayName,
                    Description = info.Description,
                    ImpactLabel = info.Impact switch
                    {
                        ServiceImpact.High => "⚠ high impact",
                        ServiceImpact.Medium => "notable impact",
                        _ => "normal impact",
                    },
                    ImpactBrush = info.Impact switch
                    {
                        ServiceImpact.High => new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71)),
                        ServiceImpact.Medium => new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
                        _ => new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8)),
                    },
                });
            }
            ServiceList.ItemsSource = items;
            ServiceList.SelectionChanged += (_, _) =>
                BlockBtn.IsEnabled = ServiceList.SelectedItem is ServiceRow;
        }

        private void BlockBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ServiceList.SelectedItem is ServiceRow row)
            {
                SelectedServiceKey = row.ServiceKey;
                DialogResult = true;
            }
        }

        /// <summary>Row view-model for one catalog entry — public
        /// properties, not fields: the XAML bindings need them.</summary>
        public sealed class ServiceRow
        {
            public string ServiceKey { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
            public string ImpactLabel { get; set; }
            public Brush ImpactBrush { get; set; }
        }
    }
}
