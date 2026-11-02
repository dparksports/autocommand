using System.Windows;
using System.Windows.Controls;
using DeviceMonitorCS.ViewModels;

namespace DeviceMonitorCS.Controls
{
    public partial class StatusShieldControl : UserControl
    {
        public StatusShieldControl()
        {
            InitializeComponent();
            DataContext = SecurityStatusViewModel.Instance;
            
            // Listen for changes to update specific icon logic if needed beyond binding
            SecurityStatusViewModel.Instance.PropertyChanged += (s, e) =>
            {
               if (e.PropertyName == nameof(SecurityStatusViewModel.StatusIcon))
               {
                   UpdateIcon(SecurityStatusViewModel.Instance.StatusIcon);
               }
            };
            UpdateIcon(SecurityStatusViewModel.Instance.StatusIcon);
        }

        private void UpdateIcon(string iconName)
        {
            // Map names to Segoe MDL2 Assets hex codes
            switch(iconName)
            {
                case "CheckCircle": ShieldIcon.Text = "\uE73E"; break;
                case "AlertCircle": ShieldIcon.Text = "\uE7BA"; break;
                case "ShieldAlert": ShieldIcon.Text = "\uE7BA"; break; // Fallback
                case "ShieldCheck": ShieldIcon.Text = "\uE73E"; break;
                default: ShieldIcon.Text = "\uE73E"; break;
            }
        }
    }
}
