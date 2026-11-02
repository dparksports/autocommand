using System;
using System.Globalization;
using System.Windows.Data;

namespace DeviceMonitorCS.Converters
{
    public class ActivityFeedConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string text)
            {
                // Simple keyword replacement
                if (text.Contains("VID_"))
                {
                    return "🔌 USB Device Connected/Disconnected";
                }
                if (text.Contains("SSTP") || text.Contains("WAN Miniport"))
                {
                    return "🛡️ VPN/Tunneling Attempt Blocked";
                }
                if (text.Contains("Hosted Network"))
                {
                    return "📡 Unauthorized Hotspot Blocked";
                }
                if (text.Contains("Firewall Rule"))
                {
                    return "🔥 Firewall Configuration Updated";
                }
                if (text.Contains("Scan Is Complete"))
                {
                    return "✅ System Scan Completed";
                }
                
                return "ℹ️ " + text;
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
