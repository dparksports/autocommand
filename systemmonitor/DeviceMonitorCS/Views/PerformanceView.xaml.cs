using System.Collections.Generic;
using System.Windows.Controls;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class PerformanceView : UserControl
    {
        public PerformanceView()
        {
            InitializeComponent();
        }

        public void UpdateMetrics(PerformanceMetrics metrics)
        {
            // CPU
            CpuText.Text = $"{metrics.CpuUsage:F1}%";
            CpuBar.Value = metrics.CpuUsage;

            // RAM
            RamText.Text = $"{metrics.RamUsagePercent:F1}%";
            RamBar.Value = metrics.RamUsagePercent;
            RamDetails.Text = $"{metrics.AvailableRam:F1} GB free / {metrics.TotalRam:F1} GB";

            // Network
            NetDownText.Text = FormatSpeed(metrics.NetworkReceive);
            NetUpText.Text = FormatSpeed(metrics.NetworkSend);

            // GPU
            // GPU
            GpuList.ItemsSource = metrics.GpuMetrics;

            // Disk
            DiskList.ItemsSource = metrics.DiskMetrics;
        }

        private string FormatSpeed(float kbps)
        {
            if (kbps > 1024)
            {
                return $"{(kbps / 1024f):F1} MB/s";
            }
            return $"{kbps:F1} KB/s";
        }
    }
}
