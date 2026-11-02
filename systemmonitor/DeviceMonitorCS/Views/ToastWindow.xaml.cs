using System;
using System.Windows;
using System.Windows.Threading;
using System.Windows.Media.Animation;

namespace DeviceMonitorCS.Views
{
    public partial class ToastWindow : Window
    {
        public ToastWindow(string title, string message)
        {
            InitializeComponent();
            TitleText.Text = title;
            MessageText.Text = message;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Position Bottom Right
            var desktop = SystemParameters.WorkArea;
            this.Left = desktop.Right - this.Width - 10;
            this.Top = desktop.Bottom - this.Height - 10;

            // Fade In
            var anim = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.5));
            this.BeginAnimation(OpacityProperty, anim);

            // Auto Close
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            timer.Tick += (s, args) => 
            {
                timer.Stop();
                CloseDetails();
            };
            timer.Start();
        }

        private void CloseDetails()
        {
            var anim = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.5));
            anim.Completed += (s, e) => Close();
            this.BeginAnimation(OpacityProperty, anim);
        }
    }
}
