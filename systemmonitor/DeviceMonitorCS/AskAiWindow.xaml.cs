using System;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeviceMonitorCS.Models;

namespace DeviceMonitorCS
{
    public partial class AskAiWindow : Window
    {
        private GeminiClient _client;
        private string _context;

        public AskAiWindow(object contextItem)
        {
            InitializeComponent();
            Loaded += Window_Loaded;

            try
            {
                _context = JsonSerializer.Serialize(contextItem, new JsonSerializerOptions { WriteIndented = true });
            }
            catch
            {
                _context = contextItem.ToString();
            }

            ContextBox.Text = _context;
            QuestionBox.Focus();
            QuestionBox.SelectAll();

            AskBtn.Click += AskBtn_Click;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
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
                    // Fallback using simple path traversal to find project root (only works in typical dev structure)
                    // Trying 3 levels up from bin/Debug/net8.0-windows
                    var devPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "apikey.txt");
                    if (System.IO.File.Exists(devPath))
                    {
                        apiKey = System.IO.File.ReadAllText(devPath).Trim();
                    }
                }
            }
            catch { }

            if (string.IsNullOrEmpty(apiKey))
            {
                MessageBox.Show("API Key not found. Please create 'apikey.txt' in the application directory with your Gemini API key.", "Configuration Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                Close();
                return;
            }

            _client = new GeminiClient(apiKey);
        }

        private async void AskBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(QuestionBox.Text)) return;

            // Clear previous actions
            ActionsPanel.Children.Clear();

            string question = QuestionBox.Text;
            string prompt = $"Here is a JSON object representing a system entity (e.g., a process, network connection, or event):\n\n{_context}\n\nUser Question: {question}\n\nPlease provide a concise explanation.";
            
            ResponseBox.Text = "Thinking...";
            AskBtn.IsEnabled = false;
            QuestionBox.IsEnabled = false;

            try
            {
                string answer = await _client.AskAsync(prompt);
                ResponseBox.Text = answer;

                // Parse for commands
                ParseAndCreateActions(answer);
            }
            catch (Exception ex)
            {
                ResponseBox.Text = $"Error: {ex.Message}";
            }
            finally
            {
                AskBtn.IsEnabled = true;
                QuestionBox.IsEnabled = true;
                QuestionBox.Focus();
            }
        }

        private void ParseAndCreateActions(string answer)
        {
            // Regex for parsing markdown code blocks: ```language code ```
            // Supports powershell, cmd, batch, or generic code blocks
            var regex = new Regex(@"```(powershell|cmd|batch|bash)?\s*([\s\S]*?)\s*```", RegexOptions.IgnoreCase);
            var matches = regex.Matches(answer);

            foreach (Match match in matches)
            {
                string lang = match.Groups[1].Value.ToLower();
                string code = match.Groups[2].Value.Trim();

                if (string.IsNullOrEmpty(lang)) lang = "Command";

                // Filter for likely executable commands on Windows
                if (lang == "powershell" || lang == "cmd" || lang == "batch" || lang == "")
                {
                    var btn = new Button
                    {
                        Content = $"Run {lang.ToUpper()}: {GetShortCodePreview(code)}",
                        Margin = new Thickness(0, 5, 0, 0),
                        Padding = new Thickness(10, 5, 10, 5),
                        HorizontalAlignment = HorizontalAlignment.Left,
                        Background = new SolidColorBrush(Color.FromRgb(221, 241, 255)), // Light Blue
                        BorderBrush = Brushes.Gray
                    };

                    btn.Click += (s, ev) => ExecuteCommand(code, lang);
                    ActionsPanel.Children.Add(btn);
                }
            }
        }

        private string GetShortCodePreview(string code)
        {
            var lines = code.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length > 0)
            {
                string preview = lines[0];
                if (preview.Length > 50) preview = preview.Substring(0, 47) + "...";
                if (lines.Length > 1) preview += " (+ more)";
                return preview;
            }
            return "Script";
        }

        private async void ExecuteCommand(string code, string lang)
        {
            try
            {
                var confirm = MessageBox.Show($"Are you sure you want to execute this command?\n\n{code}", "Confirm Execution", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (confirm != MessageBoxResult.Yes) return;

                if (lang == "cmd" || lang == "batch")
                {
                    var psi = new ProcessStartInfo("cmd.exe", $"/c {code}") { UseShellExecute = true };
                    Process.Start(psi);
                    return;
                }

                // Shell Execution for PowerShell to avoid SDK SingleFile compatibility issues
                ResponseBox.Text += "\n\n--- Executing PowerShell Command... ---";
                
                await Task.Run(() =>
                {
                    try
                    {
                        // Use EncodedCommand to safely pass multi-line scripts to powershell.exe
                        byte[] scriptBytes = System.Text.Encoding.Unicode.GetBytes(code);
                        string encodedScript = Convert.ToBase64String(scriptBytes);

                        var startInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedScript}",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using (var process = Process.Start(startInfo))
                        {
                            string output = process.StandardOutput.ReadToEnd();
                            string error = process.StandardError.ReadToEnd();
                            process.WaitForExit();

                            string combinedOutput = output;
                            if (!string.IsNullOrWhiteSpace(error))
                            {
                                combinedOutput += $"\nerrors:\n{error}";
                            }

                            Dispatcher.Invoke(() => 
                            { 
                                ResponseBox.Text += $"\n{combinedOutput}\n--- Execution Complete ---";
                                ResponseBox.ScrollToEnd();
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Dispatcher.Invoke(() => MessageBox.Show($"PowerShell Execution Failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error));
                    }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Execution failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
