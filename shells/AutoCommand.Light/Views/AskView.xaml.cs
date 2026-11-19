using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace AutoCommand.Light.Views
{
    /// <summary>
    /// The no-key chat. Answers come from TrialChatRouter over facts
    /// gathered from this machine's live records — the model-free tier,
    /// deliberately: zero cost, zero abuse surface, and the answers are
    /// grounded in what actually happened on this PC. The question log is
    /// in-memory only; nothing about the conversation is persisted.
    /// </summary>
    public partial class AskView : UserControl
    {
        private readonly List<string> _log = new();

        public AskView()
        {
            InitializeComponent();
            ChatLog.ItemsSource = _log;
            _log.Add("Ask me about this PC's connections and blocks. Try a suggestion above.");
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
                var answer = TrialChatRouter.Answer(question, facts);
                AddLine(answer);
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
