using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS.Views
{
    public partial class SecurityWarningDialog : Window
    {
        public bool Result { get; private set; } = false;
        private GeminiClient _client;

        public SecurityWarningDialog()
        {
            InitializeComponent();
            InitializeGemini();
        }

        private void InitializeGemini()
        {
            string apiKey = "";
            try
            {
                var keyPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "apikey.txt");
                if (System.IO.File.Exists(keyPath))
                {
                    apiKey = System.IO.File.ReadAllText(keyPath).Trim();
                }
                else
                {
                    var devPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "apikey.txt");
                    if (System.IO.File.Exists(devPath))
                    {
                        apiKey = System.IO.File.ReadAllText(devPath).Trim();
                    }
                }
            }
            catch { }

            if (!string.IsNullOrEmpty(apiKey))
            {
                _client = new GeminiClient(apiKey);
            }
            else
            {
                AskGeminiBtn.IsEnabled = false;
                AskGeminiBtn.ToolTip = "API Key not found (apikey.txt)";
            }
        }

        private async void AskGeminiBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_client == null) return;

            AskGeminiBtn.IsEnabled = false;
            GeminiResponseBorder.Visibility = Visibility.Visible;
            GeminiResponseText.Text = "Analyzing security context...";
            
            try
            {
                string prompt = "Explain the security risks of enabling 'WAN Miniport (SSTP)' and creating a firewall hole for it in Windows. Be concise (max 3 sentences). Explain why this increases attack surface.";
                string answer = await _client.AskAsync(prompt);
                GeminiResponseText.Text = answer;
            }
            catch (Exception ex)
            {
                GeminiResponseText.Text = $"Error: {ex.Message}";
            }
            finally
            {
                AskGeminiBtn.IsEnabled = true;
            }
        }

        private void AuthorizeBtn_Click(object sender, RoutedEventArgs e)
        {
            Result = true;
            Close();
        }

        private void CancelBtn_Click(object sender, RoutedEventArgs e)
        {
            Result = false;
            Close();
        }
    }
}
