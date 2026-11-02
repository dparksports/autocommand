using System.Windows;
using DeviceMonitorCS.ViewModels;

namespace DeviceMonitorCS.Views
{
    public partial class SecurityAuditWizardView : Window
    {
        public SecurityAuditWizardView()
        {
            InitializeComponent();
            var vm = new SecurityAuditWizardViewModel();
            vm.RequestClose += () => 
            {
                this.DialogResult = true;
                this.Close();
            };
            DataContext = vm;
        }
    }
}
