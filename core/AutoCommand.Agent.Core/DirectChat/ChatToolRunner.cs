using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AutoCommand.Agent.Core.DirectChat
{
    /// <summary>
    /// Executes the model's tool calls against the same
    /// <see cref="AgentToolRegistry"/> the MCP bridge serves, under the SAME
    /// per-call policy — this file is the C# mirror of the F# bridge's
    /// CallToolAsync / GrantKey / RequestConfirmation
    /// (Engines/Engines.Bridge/Bridge.fs). Keep the two in sync: a policy
    /// change made only here means the chat side and the MCP side disagree
    /// about what a mutation requires.
    ///
    /// Differences from the bridge, all deliberate:
    ///   • Chat keeps its OWN grant set — "always for this session" granted
    ///     in an MCP confirm window must not pre-approve chat mutations (and
    ///     vice versa). The grant lives as long as the runner, which the
    ///     chat view keeps for the app's session and rebuilds when the
    ///     mutator toggle flips.
    ///   • The mutating gate is the Ask tab's toggle, not the bridge
    ///     session's mutatingAllowed: chat always has a UI, so the question
    ///     is only whether the user offered mutators to the model at all.
    ///   • Activity lines are written directly to the shared
    ///     agent\activity.jsonl with client "direct-chat" — the engine's
    ///     LogActivity stamps its own MCP client name, which would mislabel
    ///     chat traffic.
    /// The safety invariants are NOT among the differences: dry_run is
    /// honored only where the handler consumes it (SupportsDryRun), mutating
    /// calls without a standing grant go through the shared
    /// AgentConfirmWindow via the engine's IAgentBridgeUI seam with the same
    /// 90-second deny-default timeout, and grants stay per-target (gates:
    /// per target AND duration — "1 minute for spotify.exe" must never cover
    /// "1 hour for spotify.exe", or any other target).
    /// </summary>
    public sealed class ChatToolRunner
    {
        public const string ClientName = "direct-chat";

        private readonly bool _allowMutating;
        private readonly object _grantLock = new();
        private readonly HashSet<string> _grants = new(StringComparer.Ordinal);
        private readonly string _activityPath;

        public ChatToolRunner(bool allowMutating)
            : this(allowMutating, null) { }

        /// <summary>dataRootOverride exists for the self-test (temp root),
        /// exactly like the bridge engine's portBaseOverride — production
        /// callers pass null and audit into the real agent dir.</summary>
        public ChatToolRunner(bool allowMutating, string dataRootOverride)
        {
            _allowMutating = allowMutating;
            var root = dataRootOverride ?? AutoCommand.Engines.Core.Identity.autocommand().DataRoot;
            _activityPath = Path.Combine(root, "agent", "activity.jsonl");
        }

        /// <summary>Whether the user offered mutating tools to the model at
        /// all. When false the registry is also described without mutators,
        /// so the model should never ask — this check is the backstop.</summary>
        public bool AllowMutating => _allowMutating;

        /// <summary>Runs one tool call the model requested; returns the text
        /// that goes back to the model and whether it is an error. Never
        /// throws — tool failures are content, not exceptions.</summary>
        public async Task<(string Content, bool IsError)> InvokeAsync(
            string name, JsonObject args, CancellationToken ct)
        {
            // find WITHOUT the mutating filter so a policy-disabled tool is
            // distinguishable from a typo — same message split as Bridge.fs.
            var tool = AgentToolRegistry.Find(name, true);
            if (tool == null)
            {
                var note = $"Unknown tool '{name}'. Available tools: {string.Join(", ", AgentToolRegistry.Names(_allowMutating))}.";
                LogActivity("tool", name, SummarizeArgs(args), "error");
                return (note, true);
            }

            if (tool.Mutating && !_allowMutating)
            {
                LogActivity("tool", name, SummarizeArgs(args), "error");
                return ($"Tool '{name}' exists, but this chat runs WITHOUT AutoCommand changes — " +
                        "turn on \"Allow AutoCommand changes\" in the Ask AutoCommand tab (it is off by default) " +
                        "and ask again.", true);
            }

            // dry_run=true is the documented "resolve and preview only"
            // contract — but ONLY where the handler consumes it. Mirrors the
            // bridge: applying the skip to every mutating tool once let
            // dry_run=true execute unconfirmed mutations on tools with no
            // dry-run implementation.
            bool dryRunRequested =
                args?["dry_run"] != null &&
                args["dry_run"].ToString().Trim().Equals("true", StringComparison.OrdinalIgnoreCase);

            if (tool.Mutating && dryRunRequested && !tool.SupportsDryRun)
            {
                LogActivity("tool", name, SummarizeArgs(args), "error");
                return ($"Tool '{name}' does not offer dry_run — call it without dry_run to run it for real; " +
                        "the user will be asked to confirm each call.", true);
            }

            if (tool.Mutating && !dryRunRequested &&
                !SessionGranted(GrantKey(name, args)))
            {
                var detail = tool.ConfirmDetail?.Invoke(args);
                var (allowed, note) = await RequestConfirmationAsync(
                    name, GrantKey(name, args),
                    string.IsNullOrEmpty(detail) ? "(no detail provided)" : detail, ct).ConfigureAwait(false);
                if (!allowed)
                {
                    LogActivity("tool", name, SummarizeArgs(args), "error");
                    return ($"User denied '{name}'" + (note.Length > 0 ? $" — {note}" : "") + ".", true);
                }
            }

            // Handlers are synchronous and thread-bound (kernel tables, COM
            // firewall) — same Task.Run wrap as the bridge's dispatch.
            string output;
            try
            {
                output = await Task.Run(() => tool.Handler(args)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                output = "tool failed: " + ex.Message;
                LogActivity("tool", name, SummarizeArgs(args), "error");
                return (output, true);
            }
            LogActivity("tool", name, SummarizeArgs(args), "ok");
            return (output, false);
        }

        // ── grants (mirror of Bridge.fs SessionGranted / GrantKey) ────────

        private bool SessionGranted(string grantKey)
        {
            lock (_grantLock) return _grants.Contains(grantKey);
        }

        /// <summary>What an "always for this session" grant covers — same
        /// contract as the bridge: gate tools grant PER TARGET AND PER
        /// DURATION (the dialog quotes the exact gate length), other tools
        /// grant per-target when their args carry an obvious target
        /// (ip / pid / task_path / door / rule_id / preset), else per-tool.</summary>
        private static string GrantKey(string toolName, JsonObject args)
        {
            args ??= new JsonObject();
            if (toolName == "open_gate" || toolName == "close_gate")
            {
                var target = args["target"]?.ToString().Trim().ToLowerInvariant() ?? "";
                var minutes = args["minutes"]?.ToString().Trim() ?? "";
                return $"{toolName}|{target}|{minutes}";
            }
            foreach (var key in new[] { "ip", "pid", "task_path", "door", "rule_id", "preset" })
            {
                var v = args[key];
                if (v != null)
                    return $"{toolName}|{v.ToString().Trim().ToLowerInvariant()}";
            }
            return toolName;
        }

        // ── confirmation (mirror of Bridge.fs RequestConfirmation) ────────

        /// <summary>Asks the user through the app's shared confirm seam (the
        /// same AgentConfirmWindow an MCP confirm uses). Deny by default:
        /// no UI, a failed dialog, a 90-second silence and a cancelled chat
        /// all land on "no".</summary>
        private async Task<(bool Allowed, string Note)> RequestConfirmationAsync(
            string toolName, string grantKey, string detail, CancellationToken ct)
        {
            // IsUiAvailable touches WPF thread-affine state — the seam
            // marshals internally, but a throw here (dispatcher shut down)
            // must read as "no UI", not crash the tool (the bridge's bug
            // report behind its own try/catch).
            var ui = AutoCommand.Engines.Bridge.AgentBridgeService.Ui;
            bool uiReady;
            try { uiReady = ui != null && ui.IsUiAvailable; }
            catch { uiReady = false; }
            if (!uiReady)
                return (false, "no UI is available to confirm with");

            var tcs = new TaskCompletionSource<(bool Allowed, bool Always, string Note)>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            using var cancelReg = ct.Register(() =>
                tcs.TrySetResult((false, false, "the chat was stopped")));

            try
            {
                // ShowConfirmAsync marshals to the UI thread itself and pops
                // the AgentConfirmWindow owned by the main window.
                var answer = await ui.ShowConfirmAsync(toolName, detail).ConfigureAwait(false);
                tcs.TrySetResult((answer.Item1, answer.Item2,
                    answer.Item1 ? "allowed by user" : "denied by user"));
            }
            catch (Exception ex)
            {
                tcs.TrySetResult((false, false, "confirm dialog failed: " + ex.Message));
            }

            var completed = await Task.WhenAny(
                tcs.Task, Task.Delay(AutoCommand.Engines.Bridge.AgentBridgeService.ConfirmTimeoutMs))
                .ConfigureAwait(false);
            if (completed != tcs.Task)
                return (false, $"no answer in {AutoCommand.Engines.Bridge.AgentBridgeService.ConfirmTimeoutMs / 1000}s");

            // The WhenAny already proved this task is done — the await
            // returns synchronously with the user's answer.
            var (allowed, always, note) = await tcs.Task.ConfigureAwait(false);

            if (allowed && always)
            {
                lock (_grantLock) _grants.Add(grantKey);
                LogActivity("session", "grant",
                    $"{grantKey} allowed for the rest of this chat" +
                    (grantKey != toolName ? " (this target only)" : ""), "ok");
            }
            return (allowed, note);
        }

        /// <summary>Audits one chat request WITHOUT its text — the activity
        /// log records that a request happened (detail = model/endpoint
        /// shape the caller passes, outcome), never what was said: the
        /// transcript's "in memory only" promise extends to the log.
        /// kind/what vocabulary matches the tool lines above so the
        /// Be My Guest-era file stays one dialect.</summary>
        public void LogChatTurn(string detail, string outcome) =>
            LogActivity("chat", "request", detail, outcome);

        // ── activity audit (mirror of Bridge.fs LogActivity) ──────────────

        private void LogActivity(string kind, string what, string detail, string outcome)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_activityPath));
                var line = new JsonObject();
                line["t"] = DateTime.Now.ToString("o");
                line["kind"] = kind;
                line["what"] = what;
                line["client"] = ClientName;
                if (!string.IsNullOrEmpty(detail)) line["detail"] = detail;
                if (!string.IsNullOrEmpty(outcome)) line["outcome"] = outcome;
                AutoCommand.Engines.Core.BufferedAppender.Append(_activityPath, line.ToJsonString());
            }
            catch { /* best-effort audit trail */ }
        }

        private static string SummarizeArgs(JsonObject args)
        {
            if (args == null) return "";
            var text = args.ToJsonString();
            return text.Length <= 120 ? text : text[..120] + "…";
        }
    }
}
