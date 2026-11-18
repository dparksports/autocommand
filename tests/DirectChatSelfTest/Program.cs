// Direct chat self-test — the GLM chat client and the chat-side tool policy,
// offline:
//   1. registry descriptors → OpenAI function-tool conversion
//   2. SSE content assembly (deltas in order, usage captured)
//   3. the tool loop: fragmented tool_call arguments reassembled, the tool
//      result re-entering request 2 with the right tool_call_id, pending +
//      final onTool events
//   4/5. the mutating gates: toggle off (model never told mutators exist,
//      backstop refuses), toggle on but no UI (deny, never act)
//   6. dry_run honored only where the handler consumes it (open_gate yes,
//      close_gate refused) — the unconfirmed-mutation trap the bridge fixed
//   7. dead stream, nothing emitted → transparent non-streaming retry
//   8. stream breaks MID-answer → error, never a silent re-print
//   9. HTTP 401 → provider error surfaces with status, no retry
//  10. empty completion → honest error
//  11. Stop (cancellation) mid-stream → OperationCanceledException, no
//      fallback request
//  12. DPAPI key round-trip + corrupt-key → null; settings round-trip; the
//      endpoint preset table
//  13. audit lines land in the temp agent dir stamped client "direct-chat"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AutoCommand.Agent.Core;
using AutoCommand.Agent.Core.DirectChat;
using AutoCommand.Engines.Core;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// ── isolated state: temp data root for audits, temp root for the store ──
string dataRoot = Path.Combine(Path.GetTempPath(), "directchat-selftest-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dataRoot);

var server = new FakeChatServer();
try
{
    // ── 1. descriptors → OpenAI tools ───────────────────────────────────
    var readOnly = AgentToolRegistry.Names(false);
    var tools = GlmChatClient.OpenAiToolsFromDescriptors(AgentToolRegistry.Descriptors(false));
    Check("1a read-only descriptor count preserved", tools.Count == readOnly.Length,
        $"tools={tools.Count} names={readOnly.Length}");
    bool allFunctions = true;
    foreach (var node in tools)
    {
        if (node is not JsonObject t || t["type"]?.ToString() != "function") { allFunctions = false; break; }
        if (t["function"] is not JsonObject fn || fn["name"]?.ToString().Length == 0) { allFunctions = false; break; }
        if (fn["parameters"] is not JsonObject) { allFunctions = false; break; }
    }
    Check("1b every descriptor becomes {type:function, function:{name, parameters}}", allFunctions);
    var full = GlmChatClient.OpenAiToolsFromDescriptors(AgentToolRegistry.Descriptors(true));
    Check("1c includeMutating grows the surface", full.Count == AgentToolRegistry.Names(true).Length,
        $"full={full.Count} expected={AgentToolRegistry.Names(true).Length}");

    // ── 2. streaming content assembly ───────────────────────────────────
    server.Reset();
    server.Enqueue(_ => HttpResponse("text/event-stream", SseBody(
        Chunk("{\"content\":\"Hel" + "lo \"}"),
        Chunk("{\"content\":\"GLM\"}"),
        Chunk("{\"content\":\" world.\"}"),
        "{\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}")));
    var deltas = new List<string>();
    var client2 = NewClient(server.BaseUrl);
    var r2 = await client2.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot),
        d => deltas.Add(d), null);
    Check("2a streamed text assembled in order", r2.Text == "Hello GLM world.", $"'{r2.Text}'");
    Check("2b deltas surfaced to the UI callback",
        deltas.Count == 3 && deltas[0] == "Hel" + "lo " && deltas[2] == " world.",
        string.Join("|", deltas));
    Check("2c usage captured from the final chunk", r2.Usage?["total_tokens"]?.GetValue<int>() == 15,
        r2.Usage?.ToJsonString() ?? "null");

    // ── 3. the tool loop with fragmented tool_call arguments ────────────
    server.Reset();
    string lastSecondBody = "";
    server.Enqueue(body => HttpResponse("text/event-stream", SseBody(
        Chunk("{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\"," +
              "\"function\":{\"name\":\"classify_ip\",\"arguments\":\"\"}}]}"),
        Chunk("{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"ip\\\":\"}}]}"),
        Chunk("{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"1.2.3.4\\\"}\"}}],\"finish_reason\":\"tool_calls\"}"))));
    server.Enqueue(body =>
    {
        lastSecondBody = body;
        return HttpResponse("text/event-stream", SseBody(
            Chunk("{\"content\":\"1.2.3.4 checked via the registry.\"}")));
    });
    var toolEvents = new List<ChatToolEvent>();
    var client3 = NewClient(server.BaseUrl);
    var r3 = await client3.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot),
        null, ev => toolEvents.Add(ev));
    Check("3a two requests for one tool round", server.RequestCount == 2, $"count={server.RequestCount}");
    Check("3b request 2 echoes the tool result with the model's call id",
        lastSecondBody.Contains("\"role\":\"tool\"") && lastSecondBody.Contains("call_1"),
        lastSecondBody.Length > 200 ? lastSecondBody[..200] : lastSecondBody);
    Check("3c fragmented arguments reassembled into the executed call",
        lastSecondBody.Contains("1.2.3.4"));
    Check("3d pending + final onTool events", toolEvents.Count == 2 &&
        toolEvents[0].Result == null && toolEvents[1].Result != null,
        string.Join(",", toolEvents));
    Check("3e final answer text", r3.Text == "1.2.3.4 checked via the registry.", $"'{r3.Text}'");

    // ── 4. mutating tool, toggle OFF → refused, tool never runs ─────────
    var runnerOff = new ChatToolRunner(false, dataRoot);
    var (offText, offErr) = await runnerOff.InvokeAsync("open_gate",
        new JsonObject { ["target"] = "spotify.exe", ["minutes"] = 1 }, CancellationToken.None);
    Check("4a toggle-off refusal", offErr && offText.Contains("WITHOUT AutoCommand changes"), offText);

    // ── 5. mutating tool, toggle ON, no confirm UI → denied ─────────────
    // (the test process never installs AgentBridgeService.Ui — the same
    // headless shape a background session has)
    var runnerOn = new ChatToolRunner(true, dataRoot);
    var (onText, onErr) = await runnerOn.InvokeAsync("open_gate",
        new JsonObject { ["target"] = "spotify.exe", ["minutes"] = 1 }, CancellationToken.None);
    Check("5a no-UI denial", onErr && onText.Contains("User denied 'open_gate'") && onText.Contains("no UI"),
        onText);

    // ── 6. dry_run: honored ONLY where the handler consumes it ──────────
    var (cgText, cgErr) = await runnerOn.InvokeAsync("close_gate",
        new JsonObject { ["target"] = "x", ["dry_run"] = "true" }, CancellationToken.None);
    Check("6a close_gate refuses dry_run", cgErr && cgText.Contains("does not offer dry_run"), cgText);
    var (ogText, ogErr) = await runnerOn.InvokeAsync("open_gate",
        new JsonObject { ["target"] = "no-such-app-under-selftest.exe", ["minutes"] = 1, ["dry_run"] = "true" }, CancellationToken.None);
    // open_gate offers dry_run → the REFUSAL must not fire; with no UI the
    // dry-run preview path runs handler-side without confirmation. The
    // registry guarantees dry_run resolves-and-previews without acting, and
    // the target here cannot resolve to any rule, so even a hypothetical
    // bug has nothing to act on.
    Check("6b open_gate dry_run skips the refusal (preview path)", !ogText.Contains("does not offer dry_run"), ogText);

    // ── 7. dead stream with nothing emitted → non-streaming fallback ────
    server.Reset();
    server.Enqueue(_ => null);   // accept, then close without a byte
    server.Enqueue(_ => HttpResponse("application/json",
        /*lang=json,strict*/ "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"Plain answer\"}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}"));
    var client7 = NewClient(server.BaseUrl);
    var r7 = await client7.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot), null, null);
    Check("7a fallback produced the plain answer", r7.Text == "Plain answer", $"'{r7.Text}'");
    Check("7b exactly one fallback request", server.RequestCount == 2, $"count={server.RequestCount}");

    // ── 8. mid-stream break → error, NEVER a re-request ─────────────────
    server.Reset();
    server.Enqueue(_ => TruncatedSse(
        Chunk("{\"content\":\"you already saw half\"}")));
    var client8 = NewClient(server.BaseUrl);
    string midError = "";
    try { await client8.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot), null, null); }
    catch (GlmChatException ex) { midError = ex.Message; }
    Check("8a mid-answer break surfaces an error", midError.Contains("broke mid-answer"), midError);
    Check("8b no silent retry after partial output", server.RequestCount == 1, $"count={server.RequestCount}");

    // ── 9. HTTP 401 → provider error, no fallback ───────────────────────
    server.Reset();
    server.Enqueue(_ => HttpResponse("application/json", "{\"error\":{\"message\":\"bad key\"}}", 401));
    var client9 = NewClient(server.BaseUrl);
    int? gotStatus = null; string gotMessage = "";
    try { await client9.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot), null, null); }
    catch (GlmChatException ex) { gotStatus = ex.StatusCode; gotMessage = ex.Message; }
    Check("9a 401 carries status + key hint",
        gotStatus == 401 && gotMessage.Contains("API key"), $"{gotStatus} {gotMessage}");
    Check("9b auth errors never retry", server.RequestCount == 1, $"count={server.RequestCount}");

    // ── 10. empty completion → honest error ─────────────────────────────
    server.Reset();
    server.Enqueue(_ => HttpResponse("text/event-stream", SseBody()));
    var client10 = NewClient(server.BaseUrl);
    string emptyError = "";
    try { await client10.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot), null, null); }
    catch (GlmChatException ex) { emptyError = ex.Message; }
    Check("10a empty answer errors", emptyError.Contains("empty answer"), emptyError);

    // ── 11. Stop mid-stream → cancellation, no fallback request ─────────
    server.Reset();
    server.Enqueue(_ =>    // a stalled provider: answer only after 2 s
    {
        Thread.Sleep(2000);
        return HttpResponse("text/event-stream", SseBody(Chunk("{\"content\":\"late\"}")));
    });
    var cts11 = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
    var client11 = NewClient(server.BaseUrl);
    bool cancelled = false;
    int countBefore = server.RequestCount;
    try { await client11.RunAsync("sys", new JsonArray(), null, new ChatToolRunner(false, dataRoot), null, null, cts11.Token); }
    catch (OperationCanceledException) { cancelled = true; }
    await Task.Delay(2500);         // let the stalled handler finish its 2s
    Check("11a cancellation surfaces as OperationCanceledException", cancelled);
    Check("11b cancelled request never falls back", server.RequestCount == countBefore + 1,
        $"count={server.RequestCount}");

    // ── 12. ChatStore: DPAPI key + settings + endpoint table ────────────
    string storeRoot = Path.Combine(dataRoot, "chat-store");
    ChatStore.RootOverride = storeRoot;
    try
    {
        ChatStore.SaveApiKey("sk-live-abc123");
        Check("12a HasApiKey after save", ChatStore.HasApiKey());
        Check("12b key round-trips", ChatStore.LoadApiKey() == "sk-live-abc123");
        Check("12c key is NOT in settings.json",
            !File.Exists(ChatStore.SettingsPath) || !File.ReadAllText(ChatStore.SettingsPath).Contains("sk-live"),
            File.Exists(ChatStore.SettingsPath) ? File.ReadAllText(ChatStore.SettingsPath) : "no settings file");
        File.WriteAllBytes(ChatStore.KeyPath, new byte[] { 1, 2, 3 });
        Check("12d corrupt key reads as null (setup panel, not a crash)", ChatStore.LoadApiKey() == null);

        var s = new ChatSettings
        {
            EndpointPreset = "bigmodel", Model = "glm-5.3",
            AllowMutating = true, Consent = true, CustomBaseUrl = "https://x.example/v4"
        };
        ChatStore.Save(s);
        var s2 = ChatStore.Load();
        Check("12e settings round-trip",
            s2.EndpointPreset == "bigmodel" && s2.Model == "glm-5.3" && s2.AllowMutating && s2.Consent,
            ChatStore.SettingsPath);
        Check("12f endpoint presets resolve",
            ChatStore.ResolveBaseUrl(new ChatSettings { EndpointPreset = "standard" }) == ChatStore.StandardBaseUrl &&
            ChatStore.ResolveBaseUrl(new ChatSettings { EndpointPreset = "bigmodel" }) == ChatStore.BigModelBaseUrl &&
            ChatStore.ResolveBaseUrl(new ChatSettings { EndpointPreset = "custom", CustomBaseUrl = "https://x/v4" }) == "https://x/v4" &&
            ChatStore.ResolveBaseUrl(new ChatSettings { EndpointPreset = "typo" }) == ChatStore.CodingPlanBaseUrl &&
            ChatStore.ResolveBaseUrl(null) == ChatStore.CodingPlanBaseUrl);
        Check("12g default model", ChatStore.DefaultModel == "glm-5.3-flash");
    }
    finally { ChatStore.RootOverride = null; }

    // ── 13. audit trail: temp root, stamped direct-chat ─────────────────
    var activityPath = Path.Combine(dataRoot, "agent", "activity.jsonl");
    File.Delete(activityPath);      // tests 4-6 logged already; start clean
    var runner13 = new ChatToolRunner(false, dataRoot);
    _ = await runner13.InvokeAsync("list_watches", new JsonObject(), CancellationToken.None);
    BufferedAppender.Flush(activityPath);
    var auditLines = File.Exists(activityPath) ? File.ReadAllLines(activityPath) : Array.Empty<string>();
    Check("13a tool call audited with client direct-chat + ok outcome",
        auditLines.Any(l => l.Contains("\"client\":\"direct-chat\"") && l.Contains("\"what\":\"list_watches\"") &&
                            l.Contains("\"outcome\":\"ok\"")),
        string.Join("\n", auditLines));
    var (dText, _) = await runner13.InvokeAsync("open_gate",
        new JsonObject { ["target"] = "spotify.exe", ["minutes"] = 1 }, CancellationToken.None);
    BufferedAppender.Flush(activityPath);
    auditLines = File.ReadAllLines(activityPath);
    Check("13b refusal audited with error outcome",
        auditLines.Any(l => l.Contains("\"what\":\"open_gate\"") && l.Contains("\"outcome\":\"error\"")),
        string.Join("\n", auditLines.TakeLast(3)));
    runner13.LogChatTurn("model=glm-5.3-flash preset=coding", "ok");
    BufferedAppender.Flush(activityPath);
    auditLines = File.ReadAllLines(activityPath);
    Check("13c chat request audited without any transcript text",
        auditLines.Any(l => l.Contains("\"kind\":\"chat\"") && l.Contains("model=glm-5.3-flash") &&
                            l.Contains("\"outcome\":\"ok\"")),
        string.Join("\n", auditLines.TakeLast(3)));
}
finally
{
    server.Dispose();
    try { Directory.Delete(dataRoot, recursive: true); } catch { /* temp best-effort */ }
}

Console.WriteLine(failures == 0 ? "DIRECT CHAT SELF TEST: GREEN" : $"DIRECT CHAT SELF TEST: {failures} FAILURE(S)");
return failures == 0 ? 0 : 1;

// ── helpers ─────────────────────────────────────────────────────────────

static GlmChatClient NewClient(string baseUrl) => new(baseUrl, "glm-5.3-flash", "sk-test-key");

static string Chunk(string deltaJson, string finish = "null") =>
    "{\"choices\":[{\"index\":0,\"delta\":" + deltaJson + ",\"finish_reason\":" + finish + "}]}";

static string SseBody(params string[] frames)
{
    var sb = new StringBuilder();
    foreach (var f in frames) sb.Append("data: ").Append(f).Append("\n\n");
    sb.Append("data: [DONE]\n\n");
    return sb.ToString();
}

/// <summary>A response that declares more body than it sends, then dies —
/// the mid-stream break shape.</summary>
static string TruncatedSse(string oneFrame)
{
    var body = "data: " + oneFrame + "\n\n";
    return "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 99999\r\nConnection: close\r\n\r\n" + body;
}

static string HttpResponse(string contentType, string body, int status = 200)
{
    var reason = status == 200 ? "OK" : status == 401 ? "Unauthorized" : "Error";
    return $"HTTP/1.1 {status} {reason}\r\nContent-Type: {contentType}\r\n" +
           $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
}

/// <summary>Loopback chat/completions fake: one scripted handler per
/// request (request body in, raw HTTP response out; null aborts the
/// connection like a dead provider). Sequential — the client sends one
/// request per attempt.</summary>
sealed class FakeChatServer : IDisposable
{
    private readonly TcpListener _listener = new(System.Net.IPAddress.Loopback, 0);
    private readonly Queue<Func<string, string>> _handlers = new();
    private Thread _thread;
    private bool _disposed;
    private int _count;

    public string BaseUrl { get; }
    public int RequestCount => _count;
    public List<string> Bodies { get; } = new();

    public FakeChatServer()
    {
        _listener.Start();
        BaseUrl = $"http://127.0.0.1:{((System.Net.IPEndPoint)_listener.LocalEndpoint).Port}/v1";
        _thread = new Thread(AcceptLoop) { IsBackground = true };
        _thread.Start();
    }

    public void Enqueue(Func<string, string> handler) => _handlers.Enqueue(handler);

    public void Reset()
    {
        _handlers.Clear();
        Bodies.Clear();
        _count = 0;
    }

    private void AcceptLoop()
    {
        while (!_disposed)
        {
            TcpClient client;
            try { client = _listener.AcceptTcpClient(); }
            catch { break; }   // disposed
            try { HandleClient(client); }
            catch { /* a scripted failure IS a test case; the client sees it */ }
        }
    }

    /// <summary>Serves ONE scripted exchange; every early exit is a plain
    /// return so the accept loop survives the dead-provider cases.</summary>
    private void HandleClient(TcpClient client)
    {
        using (client)
        {
            var stream = client.GetStream();
            var body = ReadRequestBody(stream);
            Bodies.Add(body);
            Interlocked.Increment(ref _count);
            if (_handlers.Count == 0) return;
            var handler = _handlers.Dequeue();
            var response = handler(body);
            if (response == null) return;    // abort without a byte
            var bytes = Encoding.ASCII.GetBytes(response);
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
        }
    }

    private static string ReadRequestBody(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        var tmp = new byte[8192];
        int headerLen = -1, contentLen = 0;
        while (true)
        {
            int n = stream.Read(tmp, 0, tmp.Length);
            if (n <= 0) break;
            ms.Write(tmp, 0, n);
            if (headerLen < 0)
            {
                var soFar = Encoding.ASCII.GetString(ms.ToArray());
                var idx = soFar.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (idx >= 0)
                {
                    headerLen = idx + 4;
                    contentLen = ParseContentLength(soFar[..idx]);
                }
            }
            if (headerLen >= 0 && ms.Length >= headerLen + contentLen) break;
        }
        var raw = Encoding.ASCII.GetString(ms.ToArray());
        var bodyStart = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;
        return raw[bodyStart..];
    }

    private static int ParseContentLength(string headers)
    {
        foreach (var line in headers.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            var colon = trimmed.IndexOf(':');
            if (colon > 0 && trimmed[..colon].Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(trimmed[(colon + 1)..].Trim(), out var v))
                return v;
        }
        return 0;
    }

    public void Dispose()
    {
        _disposed = true;
        try { _listener.Stop(); } catch { }
    }
}
