using System.Windows;

namespace DeviceMonitorCS.Views
{
    public partial class FirmwareDetailWindow : Window
    {
        public FirmwareDetailWindow(string title, string content)
        {
            InitializeComponent();
            Title = title;
            TitleText.Text = title;
            ContentBox.Text = content;
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
