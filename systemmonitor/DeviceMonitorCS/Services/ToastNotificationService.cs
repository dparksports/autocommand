using System;
using System.Threading.Tasks;

namespace DeviceMonitorCS.Services
{
    public class ToastNotificationService
    {
        private static ToastNotificationService _instance;
        public static ToastNotificationService Instance => _instance ?? (_instance = new ToastNotificationService());

        private ToastNotificationService() { }

        public void ShowToast(string title, string message, object icon = null)
        {
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                var toast = new Views.ToastWindow(title, message);
                toast.Show();
            });
        }
    }
}
