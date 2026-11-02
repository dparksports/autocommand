using System.Windows;
using System.Windows.Controls;

namespace DeviceMonitorCS.Views
{
    public partial class DiagnosticsMainView : UserControl
    {
        private Dictionary<Type, UserControl> _subViewCache = new Dictionary<Type, UserControl>();

        public DiagnosticsMainView()
        {
            InitializeComponent();
            NavigateSub<PerformanceView>();
        }

        private void PerfBtn_Click(object sender, RoutedEventArgs e) => NavigateSub<PerformanceView>();
        private void TimelineBtn_Click(object sender, RoutedEventArgs e) => NavigateSub<TimelineView>();
        private void FirmwareBtn_Click(object sender, RoutedEventArgs e) => NavigateSub<FirmwareSettingsView>();
        private void DeviceMgmtBtn_Click(object sender, RoutedEventArgs e) => NavigateSub<DeviceManagementView>();
        private void ShutdownBtn_Click(object sender, RoutedEventArgs e) => NavigateSub<TrueShutdownView>();

        private void NavigateSub<T>() where T : UserControl, new()
        {
            Type type = typeof(T);
            if (!_subViewCache.ContainsKey(type))
            {
                _subViewCache[type] = new T();
                
                // Initialize if needed
                if (_subViewCache[type] is DeviceManagementView dmv) dmv.InitializeAndLoad();
                if (_subViewCache[type] is FirewallSettingsView fsv) fsv.InitializeAndLoad();
                if (_subViewCache[type] is ColdBootsView cbv) cbv.InitializeAndLoad();
                if (_subViewCache[type] is CommandPanelView cpv) cpv.InitializeAndLoad();
                if (_subViewCache[type] is TrueShutdownView tsv) tsv.InitializeAndLoad();
            }
            SubContentArea.Content = _subViewCache[type];
        }
    }
}
