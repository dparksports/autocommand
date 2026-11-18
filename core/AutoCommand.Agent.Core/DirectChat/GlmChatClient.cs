using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AutoCommand.Agent.Core.DirectChat
{
    /// <summary>An API-level failure (auth, bad model, quota, provider error
    /// body) — permanent for the request, never retried with a different
    /// shape. The chat UI surfaces Message directly.</summary>
    public sealed class GlmChatException : Exception
    {
        public int? StatusCode { get; }
        public GlmChatException(string message, int? statusCode = null) : base(message) => StatusCode = statusCode;
    }

    /// <summary>One function the model asked the app to run.</summary>
    public sealed record ChatToolCall(string Id, string Name, string ArgsJson);

    /// <summary>One executed tool call, handed to the UI for its transcript
    /// chip. A pending event (Result == null) arrives before execution; the
    /// final event carries the tool's answer.</summary>
    public sealed record ChatToolEvent(string Name, string ArgsJson, string Result, bool IsError);

    /// <summary>What one user exchange produced.</summary>
    public sealed record ChatExchangeResult(string Text, JsonObject Usage);

    /// <summary>
    /// The direct-chat LLM client: an OpenAI-compatible chat/completions
    /// conversation against GLM (Z.ai Coding Plan endpoint by default; see
    /// ChatStore for the preset table). No NuGet — System.Text.Json and
    /// HttpClient, the house client style (UsagePingService / Rdap).
    ///
    /// Streaming: SSE deltas (content + tool_call argument fragments) are
    /// assembled until [DONE]; a stream that breaks before emitting anything
    /// falls back to one non-streaming request (the bridge's own transport is
    /// non-streaming, so a provider without SSE still works). A stream that
    /// breaks MID-answer never silently re-requests — the user already saw
    /// half the text, and a retry would print it twice.
    ///
    /// The tool loop (max 6 rounds) executes model tool_calls through
    /// ChatToolRunner — the same AgentToolRegistry the MCP bridge serves,
    /// under the same confirmation policy — and truncates each tool result
    /// before it re-enters the request. Only the plain user/assistant turns
    /// persist across exchanges; intermediate tool traffic stays inside one
    /// exchange, keeping the in-memory transcript (and anything a later
    /// question re-sends) small and inspectable.
    /// </summary>
    public sealed class GlmChatClient
    {
        /// <summary>Tool rounds per exchange. The registry's tools are one
        /// snapshot → answer by design; a model still looping after six has
        /// misread the toolset and needs a human-readable stop, not a hang.</summary>
        public const int MaxToolRounds = 6;

        /// <summary>Tool answers re-enter the request as message content; this
        /// bound keeps one verbose tool (a full monitor snapshot) from
        /// crowding out the conversation.</summary>
        public const int MaxToolResultChars = 8_000;

        private readonly string _baseUrl;
        private readonly string _model;
        private readonly string _apiKey;

        public GlmChatClient(string baseUrl, string model, string apiKey)
        {
            _baseUrl = (baseUrl ?? "").TrimEnd('/');
            _model = string.IsNullOrWhiteSpace(model) ? ChatStore.DefaultModel : model.Trim();
            _apiKey = apiKey ?? "";
        }

        /// <summary>Converts AgentToolRegistry.Descriptors() (MCP shape:
        /// name/description/inputSchema) to the OpenAI function-tool shape
        /// GLM accepts. One tiny transform — the registry stays the single
        /// source of the tool surface.</summary>
        public static JsonArray OpenAiToolsFromDescriptors(JsonArray descriptors)
        {
            var tools = new JsonArray();
            if (descriptors == null) return tools;
            foreach (var node in descriptors)
            {
                if (node is not JsonObject d) continue;
                tools.Add(new JsonObject
                {
                    ["type"] = "function",
                    ["function"] = new JsonObject
                    {
                        ["name"] = d["name"]?.DeepClone(),
                        ["description"] = d["description"]?.DeepClone(),
                        ["parameters"] = d["inputSchema"]?.DeepClone() ?? new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() },
                    }
                });
            }
            return tools;
        }

        /// <summary>Runs one user exchange to its final assistant text:
        /// request → (tool rounds) → answer. onDelta fires with streamed
        /// content fragments (UI thread marshalling is the caller's job);
        /// onTool fires once with a pending event before each tool runs and
        /// again with its result.</summary>
        public async Task<ChatExchangeResult> RunAsync(
            string systemPrompt,
            JsonArray conversation,
            JsonArray tools,
            ChatToolRunner runner,
            Action<string> onDelta,
            Action<ChatToolEvent> onTool,
            CancellationToken ct = default)
        {
            // The request-side message list: system + conversation + the
            // intermediate assistant/tool turns of THIS exchange only.
            var turn = new List<JsonObject>();
            foreach (var node in conversation ?? new JsonArray())
                if (node is JsonObject m) turn.Add((JsonObject)m.DeepClone());

            for (int round = 1; round <= MaxToolRounds; round++)
            {
                var completion = await SendWithFallbackAsync(systemPrompt, turn, tools, onDelta, ct).ConfigureAwait(false);

                if (completion.ToolCalls.Count == 0)
                {
                    // An answer that is only reasoning_content still tells the
                    // user something; an empty completion is a provider bug.
                    var text = completion.Content;
                    if (string.IsNullOrEmpty(text) && !string.IsNullOrEmpty(completion.Reasoning))
                        text = completion.Reasoning;
                    if (string.IsNullOrEmpty(text))
                        throw new GlmChatException("The model returned an empty answer — try again.");
                    return new ChatExchangeResult(text, completion.Usage);
                }

                // Assistant turn that asked for tools — its tool_calls must be
                // echoed back before the results (OpenAI contract; GLM keeps it).
                var assistant = new JsonObject
                {
                    ["role"] = "assistant",
                    ["content"] = string.IsNullOrEmpty(completion.Content) ? null : completion.Content
                };
                var calls = new JsonArray();
                foreach (var call in completion.ToolCalls)
                    calls.Add(new JsonObject
                    {
                        ["id"] = call.Id,
                        ["type"] = "function",
                        ["function"] = new JsonObject
                        {
                            ["name"] = call.Name,
                            ["arguments"] = call.ArgsJson
                        }
                    });
                assistant["tool_calls"] = calls;
                turn.Add(assistant);

                foreach (var call in completion.ToolCalls)
                {
                    ct.ThrowIfCancellationRequested();
                    var args = ParseArguments(call.ArgsJson);
                    onTool?.Invoke(new ChatToolEvent(call.Name, call.ArgsJson, null, false));

                    var (result, isError) = await runner.InvokeAsync(call.Name, args, ct).ConfigureAwait(false);

                    onTool?.Invoke(new ChatToolEvent(call.Name, call.ArgsJson, result, isError));
                    turn.Add(new JsonObject
                    {
                        ["role"] = "tool",
                        ["tool_call_id"] = call.Id,
                        ["content"] = Truncate(result, MaxToolResultChars)
                    });
                }
            }

            throw new GlmChatException(
                $"The model called tools for {MaxToolRounds} rounds without answering — ask it differently.");
        }

        // ── one completion request ────────────────────────────────────────

        private sealed class Completion
        {
            public string Content = "";
            public string Reasoning = "";
            public List<ChatToolCall> ToolCalls = new();
            public JsonObject Usage;
        }

        private async Task<Completion> SendWithFallbackAsync(
            string systemPrompt, List<JsonObject> turn, JsonArray tools,
            Action<string> onDelta, CancellationToken ct)
        {
            try
            {
                return await SendOnceAsync(systemPrompt, turn, tools, stream: true, onDelta, ct).ConfigureAwait(false);
            }
            catch (GlmChatException) { throw; }          // provider said no — a retry will too
            catch (OperationCanceledException) { throw; }
            catch (StreamBrokeException) { throw; }      // partial answer already shown — never re-request
            catch (Exception)
            {
                // stream never emitted anything (connection refused mid-setup,
                // SSE framing the parser choked on) → plain JSON, same turn
                return await SendOnceAsync(systemPrompt, turn, tools, stream: false, null, ct).ConfigureAwait(false);
            }
        }

        /// <summary>Thrown after a mid-stream failure when deltas already
        /// reached the UI — the signal that a fallback retry must NOT happen.</summary>
        private sealed class StreamBrokeException : Exception { }

        private async Task<Completion> SendOnceAsync(
            string systemPrompt, List<JsonObject> turn, JsonArray tools,
            bool stream, Action<string> onDelta, CancellationToken ct)
        {
            var messages = new JsonArray { new JsonObject { ["role"] = "system", ["content"] = systemPrompt } };
            foreach (var m in turn) messages.Add((JsonNode)m.DeepClone());

            var body = new JsonObject
            {
                ["model"] = _model,
                ["messages"] = messages,
                ["stream"] = stream
            };
            if (tools != null && tools.Count > 0)
            {
                body["tools"] = (JsonNode)tools.DeepClone();
                body["tool_choice"] = "auto";
            }

            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(300) };
            using var req = new HttpRequestMessage(HttpMethod.Post, _baseUrl + "/chat/completions");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
            if (stream) req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

            using var response = await client.SendAsync(
                req, stream ? HttpCompletionOption.ResponseHeadersRead : HttpCompletionOption.ResponseContentRead, ct)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var detail = await SafeErrorBodyAsync(response.Content, ct).ConfigureAwait(false);
                throw new GlmChatException(DescribeHttpError((int)response.StatusCode, detail), (int)response.StatusCode);
            }

            return stream ? await ReadSseAsync(response.Content, onDelta, ct).ConfigureAwait(false)
                          : ParseCompletion(JsonNode.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) as JsonObject);
        }

        private static async Task<string> SafeErrorBodyAsync(HttpContent content, CancellationToken ct)
        {
            try
            {
                var text = await content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return text.Length > 2_000 ? text[..2_000] + "…" : text;
            }
            catch { return "(unreadable error body)"; }
        }

        private static string DescribeHttpError(int status, string body)
        {
            // Providers answer errors as {error:{message}} — dig the human
            // sentence out before showing it; raw JSON goes in as-is otherwise.
            string message = null;
            try
            {
                if (JsonNode.Parse(body) is JsonObject o &&
                    o["error"] is JsonObject e && e["message"] is JsonValue v)
                    message = v.GetValue<string>();
            }
            catch { /* body was not JSON — fall through to the raw text */ }

            var hint = status switch
            {
                401 or 403 => " — check the API key in the Ask tab settings",
                404 => " — check the endpoint preset and model name",
                429 => " — rate limit or quota exhausted",
                _ => ""
            };
            var text = string.IsNullOrWhiteSpace(message) ? body : message;
            if (text.Length > 400) text = text[..400] + "…";
            return $"GLM API error {(status)}{hint}: {text}";
        }

        // ── SSE assembly ──────────────────────────────────────────────────

        private sealed class ToolCallAccum
        {
            public string Id = "";
            public string Name = "";
            public readonly StringBuilder Args = new();
        }

        private sealed class SseState
        {
            public readonly StringBuilder Content = new();
            public readonly StringBuilder Reasoning = new();
            public readonly Dictionary<int, ToolCallAccum> Calls = new();
            public JsonObject Usage;
            public int DeltasEmitted;   // > 0 ⇒ a fallback retry would double-print
        }

        private async Task<Completion> ReadSseAsync(HttpContent content, Action<string> onDelta, CancellationToken ct)
        {
            var state = new SseState();
            try
            {
                var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                using var reader = new StreamReader(stream, Encoding.UTF8);
                string line;
                while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) != null)
                {
                    if (ct.IsCancellationRequested) break;
                    // SSE frames: "data: {...}", comments (": ping") skipped
                    if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;
                    var payload = line["data:".Length..].Trim();
                    if (payload.Length == 0) continue;
                    if (payload == "[DONE]") break;

                    JsonObject chunk;
                    try { chunk = JsonNode.Parse(payload) as JsonObject; }
                    catch { continue; }                 // keep-alive noise — ignore
                    if (chunk == null) continue;

                    if (chunk["usage"] is JsonObject usage) state.Usage = (JsonObject)usage.DeepClone();

                    if (chunk["choices"] is not JsonArray choices || choices.Count == 0) continue;
                    if (choices[0] is not JsonObject choice) continue;
                    if (choice["delta"] is not JsonObject delta) continue;

                    if (delta["content"] is JsonValue contentVal &&
                        contentVal.GetValueKind() == System.Text.Json.JsonValueKind.String)
                    {
                        var piece = contentVal.GetValue<string>();
                        if (piece.Length > 0)
                        {
                            state.Content.Append(piece);
                            state.DeltasEmitted++;
                            onDelta?.Invoke(piece);
                        }
                    }
                    if (delta["reasoning_content"] is JsonValue reasonVal &&
                        reasonVal.GetValueKind() == System.Text.Json.JsonValueKind.String)
                        state.Reasoning.Append(reasonVal.GetValue<string>());

                    if (delta["tool_calls"] is JsonArray toolDeltas)
                        foreach (var td in toolDeltas)
                        {
                            if (td is not JsonObject t) continue;
                            var index = t["index"] is JsonValue iv ? iv.GetValue<int>() : state.Calls.Count;
                            if (!state.Calls.TryGetValue(index, out var acc))
                                state.Calls[index] = acc = new ToolCallAccum();
                            if (t["id"] is JsonValue idVal && idVal.GetValueKind() == System.Text.Json.JsonValueKind.String)
                                acc.Id = idVal.GetValue<string>();
                            if (t["function"] is JsonObject fn)
                            {
                                if (fn["name"] is JsonValue nameVal &&
                                    nameVal.GetValueKind() == System.Text.Json.JsonValueKind.String &&
                                    nameVal.GetValue<string>() is { Length: > 0 } n)
                                    acc.Name += n;      // fragmented names concatenate
                                if (fn["arguments"] is JsonValue argVal &&
                                    argVal.GetValueKind() == System.Text.Json.JsonValueKind.String)
                                    acc.Args.Append(argVal.GetValue<string>());
                            }
                        }
                }
            }
            catch (OperationCanceledException) { throw; }   // Stop button — never a fallback, never an error
            catch (Exception) when (state.DeltasEmitted > 0)
            {
                // Half the answer is already on screen — a non-streaming retry
                // would print it twice. Surface as an ordinary error; the
                // transcript keeps what arrived.
                throw new GlmChatException("The response stream broke mid-answer — the text above is what arrived.");
            }
            catch (Exception)
            {
                throw new StreamBrokeException();       // nothing shown → caller may fall back
            }

            var completion = new Completion
            {
                Content = state.Content.ToString(),
                Reasoning = state.Reasoning.ToString(),
                Usage = state.Usage
            };
            foreach (var acc in state.Calls.Values)
            {
                if (string.IsNullOrEmpty(acc.Name))
                    throw new GlmChatException("The model requested a tool without naming it — try again.");
                completion.ToolCalls.Add(new ChatToolCall(
                    string.IsNullOrEmpty(acc.Id) ? $"call_{completion.ToolCalls.Count}" : acc.Id,
                    acc.Name, acc.Args.ToString()));
            }
            return completion;
        }

        // ── non-streaming parse ───────────────────────────────────────────

        private static Completion ParseCompletion(JsonObject root)
        {
            if (root == null) throw new GlmChatException("The GLM API answered with something that is not JSON.");
            if (root["error"] is JsonObject err)
                throw new GlmChatException("GLM API error: " + (err["message"]?.ToString() ?? err.ToJsonString()));

            var completion = new Completion();
            if (root["usage"] is JsonObject usage) completion.Usage = (JsonObject)usage.DeepClone();
            if (root["choices"] is not JsonArray choices || choices.Count == 0 ||
                choices[0] is not JsonObject choice || choice["message"] is not JsonObject message)
                throw new GlmChatException("The GLM API answer has no message — try again.");

            if (message["content"] is JsonValue c && c.GetValueKind() == System.Text.Json.JsonValueKind.String)
                completion.Content = c.GetValue<string>();
            if (message["reasoning_content"] is JsonValue r && r.GetValueKind() == System.Text.Json.JsonValueKind.String)
                completion.Reasoning = r.GetValue<string>();

            if (message["tool_calls"] is JsonArray calls)
                foreach (var node in calls)
                {
                    if (node is not JsonObject tc || tc["function"] is not JsonObject fn) continue;
                    var name = fn["name"]?.ToString() ?? "";
                    if (name.Length == 0) continue;
                    completion.ToolCalls.Add(new ChatToolCall(
                        tc["id"]?.ToString() ?? $"call_{completion.ToolCalls.Count}",
                        name,
                        fn["arguments"] is JsonValue a && a.GetValueKind() == System.Text.Json.JsonValueKind.String
                            ? a.GetValue<string>() : (fn["arguments"]?.ToJsonString() ?? "{}")));
                }
            return completion;
        }

        private static JsonObject ParseArguments(string argsJson)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(argsJson)) return new JsonObject();
                if (JsonNode.Parse(argsJson) is JsonObject o) return o;
            }
            catch { /* malformed model JSON → empty args; the tool's own
                       validation produces the error the model sees */ }
            return new JsonObject();
        }

        internal static string Truncate(string text, int maxChars)
        {
            if (string.IsNullOrEmpty(text)) return text ?? "";
            return text.Length <= maxChars ? text : text[..maxChars] + "…\n(truncated)";
        }
    }
}
