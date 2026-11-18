using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

using AutoCommand.Agent.Core;
using AutoCommand.Agent.Core.DirectChat;

namespace AutoCommand.Views
{
    /// <summary>
    /// The "Ask AutoCommand" tab: the user converses directly with GLM — no
    /// MCP client in between. The model reads this machine through the same
    /// AgentToolRegistry the "Be My Guest" bridge serves, under the same
    /// confirmation policy (ChatToolRunner). Everything conversational is
    /// in-memory only: the transcript never touches disk, and the only
    /// persisted state is settings.json (inspectable), the DPAPI key, and
    /// the consent flag — the same honesty the rest of the app practices.
    ///
    /// Thread discipline: GLM deltas and tool events arrive on worker
    /// threads; every UI mutation is marshalled with Dispatcher.BeginInvoke.
    /// The conversation history kept for the API is user/assistant TEXT
    /// pairs only — the intermediate tool_call/tool-result turns live inside
    /// a single exchange (see GlmChatClient), so what a follow-up question
    /// re-sends is exactly what the user saw.
    /// </summary>
    public partial class DirectChatView : UserControl
    {
        /// <summary>One transcript row. Role picks the bubble; INPC on Text
        /// keeps the streaming assistant bubble growing without re-listing.</summary>
        public sealed class ChatMessage : INotifyPropertyChanged
        {
            public string Role { get; }
            private string _text = "";
            private string _toolLine = "";

            public ChatMessage(string role, string text) { Role = role; _text = text; }

            public bool IsUser => Role == "user";
            public bool IsAssistant => Role == "assistant";
            public bool IsTool => Role == "tool";

            public string Text { get => _text; private set { _text = value; Fire(nameof(Text)); } }
            public string ToolLine { get => _toolLine; private set { _toolLine = value; Fire(nameof(ToolLine)); } }

            public void Append(string piece) => Text += piece;
            public void SetText(string text) => Text = text;
            public void SetToolLine(string line) => ToolLine = line;

            public event PropertyChangedEventHandler PropertyChanged;
            private void Fire(string name) =>
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        private readonly ObservableCollection<ChatMessage> _messages = new();
        private ChatSettings _settings = new();
        private ChatToolRunner _runner;
        private CancellationTokenSource _cts;
        private ChatMessage _pendingToolChip;
        private bool _syncingControls;
        private bool _busy;

        public DirectChatView()
        {
            InitializeComponent();
            ChatList.ItemsSource = _messages;
            _runner = new ChatToolRunner(false);
        }

        // ── lifecycle ─────────────────────────────────────────────────────

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            // Re-read from disk every visit: settings.json is user-editable
            // and another instance of the app may have written it.
            _settings = ChatStore.Load();
            SyncControlsFromSettings();
            RefreshSetupCard();
            RefreshStatusLine();
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e) { }

        // ── setup / settings ──────────────────────────────────────────────

        private bool Ready => _settings.Consent && ChatStore.HasApiKey();

        private void SyncControlsFromSettings()
        {
            _syncingControls = true;
            try
            {
                var preset = _settings.EndpointPreset;
                var item = EndpointCombo.Items.Cast<ComboBoxItem>()
                    .FirstOrDefault(i => (string)i.Tag == preset);
                EndpointCombo.SelectedItem = item ?? EndpointCombo.Items[0];
                CustomUrlBox.Visibility = preset == "custom" ? Visibility.Visible : Visibility.Collapsed;
                CustomUrlBox.Text = _settings.CustomBaseUrl ?? "";
                ModelBox.Text = string.IsNullOrWhiteSpace(_settings.Model) ? ChatStore.DefaultModel : _settings.Model;
                AllowMutatingCheck.IsChecked = _settings.AllowMutating;
                KeyBox.Clear();
            }
            finally { _syncingControls = false; }
        }

        private void RefreshSetupCard()
        {
            bool consent = _settings.Consent;
            bool key = ChatStore.HasApiKey();
            KeyStateText.Text = key ? "key saved ✓" : "no key yet";
            SetupCard.Visibility = (consent && key) ? Visibility.Collapsed : Visibility.Visible;
            if (!consent && !key)
                SetupMissingText.Text = "Direct chat talks to a cloud model (GLM by Z.ai): what you type — and the tool answers the model reads — leaves this machine. " +
                    "Enable once, paste your API key, and ask.";
            else if (!consent)
                SetupMissingText.Text = "A key is saved, but the consent to talk to the model endpoint is missing. Enable direct chat to continue.";
            else
                SetupMissingText.Text = "Consent is on, but no API key is saved. Paste your Z.ai key under Chat settings ▸ Save key.";
        }

        private void RefreshStatusLine()
        {
            if (!Ready)
            {
                ChatStatusText.Text = "Not set up — enable direct chat above.";
                return;
            }
            var endpoint = ChatStore.ResolveBaseUrl(_settings);
            ChatStatusText.Text = $"{_settings.Model} · {endpoint} · " +
                (_settings.AllowMutating
                    ? "changes: allowed (each one asks)"
                    : "changes: off (read-only)") +
                " · transcript stays in memory";
        }

        private void EnableChatBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new ChatConsentDialog { Owner = Window.GetWindow(this) };
            dialog.ShowDialog();
            _settings = ChatStore.Load();       // the dialog wrote consent itself
            RefreshSetupCard();
            RefreshStatusLine();
            if (_settings.Consent && !ChatStore.HasApiKey())
            {
                SettingsExpander.IsExpanded = true;
                KeyBox.Focus();
            }
        }

        private void EndpointCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_syncingControls) return;
            _settings.EndpointPreset = (string)((ComboBoxItem)EndpointCombo.SelectedItem).Tag ?? "coding";
            CustomUrlBox.Visibility = _settings.EndpointPreset == "custom" ? Visibility.Visible : Visibility.Collapsed;
            ChatStore.Save(_settings);
            RefreshStatusLine();
        }

        private void CustomUrlBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (_syncingControls) return;
            _settings.CustomBaseUrl = CustomUrlBox.Text.Trim();
            ChatStore.Save(_settings);
            RefreshStatusLine();
        }

        private void ModelBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (_syncingControls) return;
            _settings.Model = string.IsNullOrWhiteSpace(ModelBox.Text) ? ChatStore.DefaultModel : ModelBox.Text.Trim();
            ChatStore.Save(_settings);
            RefreshStatusLine();
        }

        private void SaveKeyBtn_Click(object sender, RoutedEventArgs e)
        {
            var key = KeyBox.Password?.Trim();
            if (string.IsNullOrEmpty(key))
            {
                ChatStatusText.Text = "Paste a key first — nothing was saved.";
                return;
            }
            try
            {
                ChatStore.SaveApiKey(key);
                KeyBox.Clear();
                ChatStatusText.Text = "Key saved — encrypted with Windows DPAPI in %LOCALAPPDATA%\\AutoCommand\\chat\\key.bin.";
            }
            catch (Exception ex)
            {
                ChatStatusText.Text = "Key could not be saved: " + ex.Message;
            }
            RefreshSetupCard();
            RefreshStatusLine();
        }

        private void AllowMutatingCheck_Changed(object sender, RoutedEventArgs e)
        {
            if (_syncingControls) return;
            _settings.AllowMutating = AllowMutatingCheck.IsChecked == true;
            ChatStore.Save(_settings);
            // Grants were given under a different offer — a flipped toggle
            // starts a clean runner so "always" never outlives the toggle
            // state it was given under.
            _runner = new ChatToolRunner(_settings.AllowMutating);
            RefreshStatusLine();
        }

        private void ClearChatBtn_Click(object sender, RoutedEventArgs e)
        {
            _messages.Clear();
            _history.Clear();
            _pendingToolChip = null;
            _runner = new ChatToolRunner(_settings.AllowMutating);   // grants reset
            ChatStatusText.Text = "Conversation cleared — transcript never touched disk.";
        }

        // ── the send path ─────────────────────────────────────────────────

        private readonly JsonArray _history = new();   // {role, content} pairs only

        private void InputBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter) return;
            if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift)) return;   // newline
            e.Handled = true;
            _ = SendAsync();
        }

        private void SendBtn_Click(object sender, RoutedEventArgs e) => _ = SendAsync();

        private void StopBtn_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

        private void SetBusy(bool busy)
        {
            _busy = busy;
            SendBtn.IsEnabled = !busy;
            StopBtn.IsEnabled = busy;
            InputBox.IsEnabled = !busy;
            EnableChatBtn.IsEnabled = !busy;
        }

        private async Task SendAsync()
        {
            if (_busy) return;

            if (!_settings.Consent) { ChatStatusText.Text = "Enable direct chat first — no consent, no network."; return; }
            string apiKey = ChatStore.LoadApiKey();
            if (string.IsNullOrEmpty(apiKey)) { ChatStatusText.Text = "No API key saved — paste it under Chat settings ▸ Save key."; return; }

            var text = InputBox.Text.Trim();
            if (text.Length == 0) return;

            InputBox.Clear();
            _messages.Add(new ChatMessage("user", text));
            _history.Add(new JsonObject { ["role"] = "user", ["content"] = text });
            TrimHistory();

            var assistant = new ChatMessage("assistant", "");
            _messages.Add(assistant);
            ScrollToBottom();
            SetBusy(true);
            ChatStatusText.Text = "Thinking…";
            _cts = new CancellationTokenSource();
            string outcome = "ok";

            try
            {
                var tools = ChatStore.ChatToolsForSettings(_settings);
                var client = new GlmChatClient(ChatStore.ResolveBaseUrl(_settings), _settings.Model, apiKey);
                var result = await client.RunAsync(
                    SystemPrompt(), _history, tools, _runner,
                    onDelta: piece => Dispatcher.BeginInvoke(new Action(() => { assistant.Append(piece); ScrollToBottom(); })),
                    onTool: ev => Dispatcher.BeginInvoke(new Action(() => HandleToolEvent(ev))),
                    _cts.Token);

                assistant.SetText(result.Text);
                _history.Add(new JsonObject { ["role"] = "assistant", ["content"] = result.Text });
                ChatStatusText.Text = result.Usage != null
                    ? $"Done · tokens in/out: {result.Usage["prompt_tokens"]?.ToString() ?? "?"}/{result.Usage["completion_tokens"]?.ToString() ?? "?"}"
                    : "Done.";
            }
            catch (OperationCanceledException)
            {
                outcome = "cancelled";
                if (assistant.Text.Length == 0) assistant.SetText("⏹ stopped");
                else assistant.Append("\n\n⏹ stopped");
                ChatStatusText.Text = "Stopped — the request was cancelled.";
            }
            catch (GlmChatException ex)
            {
                outcome = "error";
                assistant.Append("\n⚠ " + ex.Message);
                ChatStatusText.Text = ex.Message;
            }
            catch (Exception ex)
            {
                outcome = "error";
                assistant.Append("\n⚠ Chat failed: " + ex.Message);
                ChatStatusText.Text = "Chat failed: " + ex.Message;
            }
            finally
            {
                // the request fact, never the text — "in memory only" covers
                // the log too
                _runner.LogChatTurn(
                    $"model={_settings.Model} preset={_settings.EndpointPreset}", outcome);
                _cts?.Dispose();
                _cts = null;
                SetBusy(false);
                ScrollToBottom();
            }
        }

        private void HandleToolEvent(ChatToolEvent ev)
        {
            if (ev.Result == null)
            {
                // pending: a chip that says the tool is running; replaced by
                // the final event (tool calls execute sequentially)
                _pendingToolChip = new ChatMessage("tool", "");
                _pendingToolChip.SetToolLine($"🔧 {ev.Name} … running");
                _messages.Add(_pendingToolChip);
                ScrollToBottom();
                ChatStatusText.Text = $"Tool: {ev.Name}…";
            }
            else
            {
                var chip = _pendingToolChip ?? new ChatMessage("tool", "");
                if (_pendingToolChip == null) _messages.Add(chip);
                chip.SetToolLine($"🔧 {ev.Name} → {(ev.IsError ? "error" : "ok")}");
                _pendingToolChip = null;
                ScrollToBottom();
            }
        }

        private void TrimHistory()
        {
            // Keep the re-sent context small: at most the last 20 turns,
            // dropped in whole pairs so the exchange never starts on an
            // orphaned assistant message.
            while (_history.Count > 20) _history.RemoveAt(0);
        }

        private void ScrollToBottom() =>
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                new Action(() => TranscriptScroller.ScrollToEnd()));

        // ── prompts (generated, never hand-maintained — the bridge lesson) ──

        private string SystemPrompt()
        {
            var identity = AutoCommand.Engines.Core.Identity.autocommand();
            var mutators = AgentToolRegistry.Names(true)
                .Where(n => AgentToolRegistry.Find(n, true)?.Mutating == true)
                .ToList();

            string mutatingText = _settings.AllowMutating && mutators.Count > 0
                ? $"Mutating tools ({string.Join(", ", mutators)}) each show a confirmation dialog in the app on every single call. " +
                  "The user may deny; a denial is final — never claim you changed anything unless the tool call reported ok. " +
                  "Everything else is read-only."
                : "This chat is strictly read-only: no tool that changes the machine is available, and you must not pretend otherwise.";

            return
                $"You are the built-in assistant of {identity.Name}, a local-first Windows network transparency and " +
                "containment tool: it lists every program talking to the internet, explains traffic in plain English, and offers " +
                "reversible firewall blocks, gates, domain blocks, Site Doctor diagnosis and Shields Up hardening. " +
                "Answer in plain English, briefly and concretely; cite what a tool actually returned rather than inventing data; " +
                "when asked about this machine, call the tools instead of guessing. " + mutatingText + " " +
                "If a tool returns an error, say so honestly and suggest what to try next. " +
                "Today is " + DateTime.Now.ToString("yyyy-MM-dd") + ".";
        }
    }
}
