using System.Windows;

namespace DeviceMonitorCS.Views
{
    public partial class PrivacyConsentWindow : Window
    {
        public bool IsConsentGranted { get; private set; } = false;

        public PrivacyConsentWindow()
        {
            InitializeComponent();
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            IsConsentGranted = true;
            DialogResult = true;
            Close();
        }

        private void QuitButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void AgreeCheckBox_CheckedChanged(object sender, RoutedEventArgs e)
        {
            bool isAgreed = AgreeCheckBox.IsChecked == true;
            if (StartButton != null) StartButton.IsEnabled = isAgreed;
        }
    }
}
