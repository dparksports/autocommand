using System;
using AutoCommand.Agent.Core;
using AutoCommand.Engines.Bridge;
using AgentBridgeService = AutoCommand.Agent.Core.AgentBridgeService;
using McpClientCatalog = AutoCommand.Agent.Core.McpClientCatalog;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using AutoCommand.Services;

namespace AutoCommand.Views
{
    public partial class BeMyGuestView : UserControl
    {
        public BeMyGuestView()
        {
            InitializeComponent();
        }

        private void UserControl_Loaded(object sender, RoutedEventArgs e)
        {
            // AI access: mutating + autostart + wake preferences + live session status
            try
            {
                AgentAutostartCheck.IsChecked = PrefOn(AutostartPrefPath);
                AgentWakeCheck.IsChecked = PrefOn(WakePrefPath);
            }
            catch
            {
                AgentAutostartCheck.IsChecked = false;
                AgentWakeCheck.IsChecked = false;
            }
            PopulateClientButtons();
            StartAgentRefresh();
        }

        // -----------------------------------------------------------------------
        // AI access (agent bridge) — see Services/AgentBridgeService.cs
        // -----------------------------------------------------------------------

        private readonly System.Windows.Threading.DispatcherTimer _agentRefresh =
            new() { Interval = TimeSpan.FromSeconds(2) };

        private static string AutostartPrefPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "agent", "autostart_pref.txt");

        private static string WakePrefPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AutoCommand", "agent", "wake_pref.txt");

        private static bool PrefOn(string path)
        {
            try { return File.Exists(path) && File.ReadAllText(path).Trim() == "on"; }
            catch { return false; }
        }

        private static void WritePref(string path, bool on)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.WriteAllText(path, on ? "on" : "off");
            }
            catch { /* persistence best-effort */ }
        }

        private void UserControl_Unloaded(object sender, RoutedEventArgs e) => _agentRefresh.Stop();

        private void StartAgentRefresh()
        {
            RefreshAgentUi();
            // named handler or nothing unwires: a lambda -= creates a NEW
            // delegate, removes nothing — every tab re-load stacked another
            // 2-second refresh on the same timer
            _agentRefresh.Tick -= OnAgentRefreshTick;
            _agentRefresh.Tick += OnAgentRefreshTick;
            _agentRefresh.Start();
        }

        private void OnAgentRefreshTick(object sender, EventArgs e) => RefreshAgentUi();

        private void RefreshAgentUi()
        {
            var bridge = AgentBridgeService.Instance;
            bool running = bridge.IsRunning;
            StartAgentBtn.IsEnabled = !running;
            StopAgentBtn.IsEnabled = running;
            AgentStatusText.Text = running
                ? $"Session ACTIVE · 127.0.0.1:{bridge.Port} · client: {bridge.ClientName} · {bridge.ConnectedCalls} call(s)"
                : "Session off. The assistant can connect but every tool answers 'start the session'.";

            AgentActivityList.ItemsSource = AgentBridgeService.Instance.RecentActivity(30)
                .Select(l => l.Length > 160 ? l[..160] + "…" : l)
                .ToList();
        }

        private void StartAgentBtn_Click(object sender, RoutedEventArgs e)
        {
            // Tier-1 consent: this is the moment the user decides what an AI
            // assistant may read — state it plainly, in one dialog.
            var answer = MessageBox.Show(
                "Start an AI access session?\n\n" +
                "An AI assistant (e.g. ZCode) will be able to READ this machine's security telemetry:\n" +
                "live connections and their processes, svchost identities, PID provenance reports,\n" +
                "Sysmon events and trace analysis. What it reads can be repeated by the assistant.\n\n" +
                "• Read-only tools answer immediately while the session is on.\n" +
                "• The only mutating actions are block gates — temporary unblocks that ask\n" +
                "  you to confirm every single call in this app.\n" +
                "• The session ends when you stop it or close AutoCommand.\n\n" +
                "Start the session?",
                "Be My Guest — consent", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) return;

            // gates are always offered; every request confirms in the app -
            // there is no session-wide mutating stance to configure anymore
            var (ok, message) = AgentBridgeService.Instance.Start(allowMutating: true);
            if (!ok) MessageBox.Show(message, "Be My Guest", MessageBoxButton.OK, MessageBoxImage.Warning);
            RefreshAgentUi();
        }

        private void StopAgentBtn_Click(object sender, RoutedEventArgs e)
        {
            AgentBridgeService.Instance.Stop();
            RefreshAgentUi();
        }

        private void AgentAutostartCheck_Changed(object sender, RoutedEventArgs e)
        {
            bool on = AgentAutostartCheck.IsChecked == true;
            if (on)
            {
                // Ticking the box IS the tier-1 consent moment — the same
                // grant the Start button asks for, standing instead of per-click.
                var answer = MessageBox.Show(
                    "Start the AI access session automatically whenever AutoCommand runs?\n\n" +
                    "An AI assistant (e.g. ZCode) will be able to READ this machine's security telemetry " +
                    "whenever the app is open, without you starting the session each time:\n" +
                    "live connections and their processes, svchost identities, PID provenance reports,\n" +
                    "Sysmon events and trace analysis. What it reads can be repeated by the assistant.\n\n" +
                    "• Read-only tools answer immediately while a session is on.\n" +
                    "• The only mutating actions are block gates — temporary unblocks that\n" +
                    "  still ask you on every single call.\n" +
                    "• A session still ends when you stop it or close AutoCommand.\n\n" +
                    "Keep sessions automatic?",
                    "Be My Guest — consent", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
                if (answer != MessageBoxResult.Yes)
                {
                    AgentAutostartCheck.IsChecked = false;
                    return;
                }
            }
            WritePref(AutostartPrefPath, on);
        }

        private void AgentWakeCheck_Changed(object sender, RoutedEventArgs e)
        {
            bool on = AgentWakeCheck.IsChecked == true;
            if (on)
            {
                var answer = MessageBox.Show(
                    "Let your AI assistant open AutoCommand when it isn't running?\n\n" +
                    "When a tool call arrives and no session exists, the assistant's proxy may launch\n" +
                    "AutoCommand normally: Windows shows ONE UAC approval and the app opens at this tab.\n" +
                    "It can never start the session for you - you click Start here when you want it.\n\n" +
                    " If AutoCommand is already running, nothing launches; the assistant tells you\n" +
                    "  to start the session from this tab.\n\n" +
                    "Allow launch on knock?",
                    "Be My Guest — consent", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
                if (answer != MessageBoxResult.Yes)
                {
                    AgentWakeCheck.IsChecked = false;
                    return;
                }
            }
            WritePref(WakePrefPath, on);
        }

        /// <summary>
        /// One Register button per known MCP client, enabled when the client
        /// is detected on this machine. Anything undetected stays visible but
        /// disabled — and 'Copy MCP config' remains the universal fallback.
        /// </summary>
        private void PopulateClientButtons()
        {
            AgentClientsPanel.Children.Clear();
            foreach (var client in McpClientCatalog.Catalog)
            {
                bool detected = McpClientCatalog.IsDetected(client);
                var btn = new Button
                {
                    Content = "Register in " + client.DisplayName,
                    Tag = client,
                    Padding = new Thickness(10, 2, 10, 2),
                    Margin = new Thickness(0, 0, 8, 0),
                    IsEnabled = detected,
                    ToolTip = detected
                        ? client.ConfigPath
                        : client.DisplayName + " not detected on this machine — install it first, or use Copy MCP config.",
                };
                btn.Click += ClientRegisterBtn_Click;
                AgentClientsPanel.Children.Add(btn);
            }

            // Migration self-heal: registrations left over from a previous
            // install (the classic → AutoCommand II move, or any folder move)
            // point at an older versioned proxy — and a cleaned tools dir
            // leaves them broken outright. Detect here, offer one explicit
            // refresh; nothing is rewritten silently.
            try
            {
                var (currentProxy, _) = McpClientCatalog.ResolveAndInstallProxy();
                var stale = McpClientCatalog.FindStaleRegistrations(currentProxy);
                if (stale.Count > 0) AgentClientsPanel.Children.Insert(0, StaleBanner(stale));
            }
            catch { /* the scan is advisory — never block the tab */ }
        }

        /// <summary>One-line offer above the Register buttons: N stale
        /// registrations + the button that repairs them via the same
        /// resolve → preflight → Register path as a manual click.</summary>
        private UIElement StaleBanner(List<AutoCommand.Engines.Bridge.StaleMcpRegistration> stale)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            row.Children.Add(new TextBlock
            {
                Text = stale.Count == 1
                    ? "1 assistant still points at an older or missing AutoCommand proxy — refresh it to keep AI access working from this install."
                    : stale.Count + " assistants still point at an older or missing AutoCommand proxy — refresh them to keep AI access working from this install.",
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0),
                MaxWidth = 520,
                TextWrapping = TextWrapping.Wrap,
            });
            var refresh = new Button
            {
                Content = "Refresh registration" + (stale.Count == 1 ? "" : "s"),
                Padding = new Thickness(10, 2, 10, 2),
            };
            refresh.Click += (_, _) => RefreshStaleRegistrations(stale);
            row.Children.Add(refresh);
            return row;
        }

        private void RefreshStaleRegistrations(List<AutoCommand.Engines.Bridge.StaleMcpRegistration> stale)
        {
            var (proxy, installNote) = McpClientCatalog.ResolveAndInstallProxy();
            if (proxy == null)
            {
                MessageBox.Show(
                    "AutoCommand.AgentProxy.exe was not found next to the app.\n" +
                    "Reinstall AutoCommand (or rebuild from source) and try again.\n\n" + installNote,
                    "Be My Guest", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // same rule as a manual register: never point a client config at
            // a proxy that has not just proven it can start and speak MCP
            var (preOk, preMsg) = McpClientCatalog.PreflightProxy(proxy);
            if (!preOk)
            {
                MessageBox.Show(
                    "The proxy is installed but failed its startup preflight — nothing was refreshed:\n\n" + preMsg,
                    "Be My Guest", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            int ok = 0;
            var failures = new List<string>();
            foreach (var s in stale)
            {
                var (rOk, message) = McpClientCatalog.Register(s.Client, proxy);
                if (rOk) ok++;
                else failures.Add(s.Client.DisplayName + ":\n" + message);
            }
            MessageBox.Show(
                failures.Count == 0
                    ? "Refreshed " + ok + " registration" + (ok == 1 ? "" : "s") +
                      " to this install's proxy (v" + AppVersion() + ").\n\n" +
                      "Assistant sessions pick it up on their next connect — no other step needed."
                    : "Refreshed " + ok + ", failed " + failures.Count + ":\n\n" + string.Join("\n\n", failures),
                "Be My Guest", MessageBoxButton.OK,
                failures.Count == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
            PopulateClientButtons(); // re-render — the banner should now be gone
        }

        private static string AppVersion()
        {
            try { return System.Diagnostics.FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "0"; }
            catch { return "0"; }
        }

        private void ClientRegisterBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: McpClientRegistration client }) return;

            var (proxy, installNote) = McpClientCatalog.ResolveAndInstallProxy();
            if (proxy == null)
            {
                MessageBox.Show(
                    "AutoCommand.AgentProxy.exe was not found next to the app.\n" +
                    "Reinstall AutoCommand (or rebuild from source) and try again.\n\n" + installNote,
                    "Be My Guest", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // never point a client config at a proxy that cannot start: prove
            // it answers an MCP handshake here first, including under the
            // hostile DOTNET_ROOT that desktop MCP clients are known to export
            var (preOk, preMsg) = McpClientCatalog.PreflightProxy(proxy);
            if (!preOk)
            {
                MessageBox.Show(
                    "The proxy is installed but failed its startup preflight — it was NOT registered:\n\n" +
                    preMsg + "\n\n" + installNote,
                    "Be My Guest", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var (ok, message) = McpClientCatalog.Register(client, proxy);
            if (ok) message += "\n\nPreflight passed: the installed proxy answered an MCP handshake, " +
                               "including with a hostile DOTNET_ROOT.";
            MessageBox.Show(message, ok ? "Registered" : "AI access",
                MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }

        private void CopyAgentConfigBtn_Click(object sender, RoutedEventArgs e)
        {
            string proxy = McpClientCatalog.ResolveAndInstallProxy().Item1
                ?? "%LOCALAPPDATA%\\AutoCommand\\tools\\AutoCommand.AgentProxy.exe";
            string config =
                "{\n  \"mcp\": {\n    \"servers\": {\n      \"autocommand\": {\n" +
                "        \"command\": \"" + proxy.Replace("\\", "\\\\") + "\",\n" +
                "        \"args\": []\n" +
                "      }\n    }\n  }\n}";
            Clipboard.SetText(config);
            MessageBox.Show("MCP config copied — paste it into the client's mcp.servers config " +
                "(ZCode: ~/.zcode/cli/config.json or <repo>/.zcode/config.json).",
                "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void OpenAgentLogBtn_Click(object sender, RoutedEventArgs e)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AutoCommand", "agent");
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
        }
    }
}
