using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The no-key chat, reframed for the gate: it answers from the gate's
    /// records (attempts, asks, holds). In-memory only; nothing about the
    /// conversation is persisted, and the answers are composed on this PC.
    /// </summary>
    public partial class HelpView : UserControl
    {
        private readonly List<string> _log = new();

        public HelpView()
        {
            InitializeComponent();
            ChatLog.ItemsSource = _log;
            _log.Add("Ask about the gate: what it holds, what waits for you, why the internet stopped.");
            ChatLog.Items.Refresh();
        }

        private void Suggestion_Click(object sender, RoutedEventArgs e) =>
            Ask((sender as Button)?.Content as string ?? "");

        private void QuestionBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) Ask(QuestionBox.Text);
        }

        private void AskBtn_Click(object sender, RoutedEventArgs e) => Ask(QuestionBox.Text);

        private async void Ask(string question)
        {
            if (string.IsNullOrWhiteSpace(question)) return;
            QuestionBox.Text = "";
            AskBtn.IsEnabled = false;
            AddLine($"You: {question.Trim()}");

            try
            {
                var facts = await LightServices.ChatFactsAsync();
                AddLine(TrialChatRouter.Answer(question, facts));
            }
            catch (Exception ex)
            {
                AddLine($"Something went wrong gathering the facts: {ex.Message}");
            }
            finally { AskBtn.IsEnabled = true; }
        }

        private void AddLine(string line)
        {
            _log.Add(line);
            _log.Add("");   // breathing room between exchanges
            ChatLog.Items.Refresh();
            if (ChatLog.Items.Count > 0)
                ChatLog.ScrollIntoView(ChatLog.Items[ChatLog.Items.Count - 1]);
        }
    }
}
