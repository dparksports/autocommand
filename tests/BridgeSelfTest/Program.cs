// Bridge self-test — the transport/session layer, offline:
//   1. session lifecycle — Start writes session.json carrying THIS pid;
//      Stop deletes it only when the file is ours (a sibling instance's
//      exit must not revoke a live session's file — the field report where
//      a fresh mutating session lost its file and nothing could connect).
//   2. one dialect everywhere — 405/401/411 bodies are JSON-RPC error
//      objects, not ad-hoc {"error": "..."} shapes.
//   3. no bare closes — chunked/lengthless POST answers 411, malformed
//      bodies answer 400 -32700; nothing closes without a response.
//   4. escaping — tool JSON embedded as content.text uses \" not \u0022
//      (clients double-decoded around the escaped form), and
//      structuredContent hands capable clients the parsed object.
//   5. mutating policy text — a mutating tool in a non-mutating session
//      explains headless sessions, not the removed settings toggle.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using AutoCommand.Engines.Bridge;
using AutoCommand.Engines.Core;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

// ── isolated identity: temp data root, port base far from production ──
string root = Path.Combine(Path.GetTempPath(), "bridge-selftest-" + Guid.NewGuid().ToString("N"));
var identity = new AppIdentity(
    "BridgeSelfTest", root, "T-IP ", "T-APP ",
    null,                       // AdoptedRulePrefixes: the bridge never iterates it
    47931, "bridgeselftest");
var bridge = new AgentBridgeService(identity, new StubTools());

try
{
    // ── 1. session lifecycle ────────────────────────────────────────────
    var (ok, message) = bridge.Start(allowMutating: false);
    Check("1a Start succeeds", ok, message);

    string sessionPath = Path.Combine(root, "agent", "session.json");
    string sessionJson = File.Exists(sessionPath) ? File.ReadAllText(sessionPath) : "";
    var sessionNode = JsonNode.Parse(sessionJson) as JsonObject;
    Check("1b Start writes session.json carrying this pid",
        sessionNode?["pid"]?.GetValue<int>() == Environment.ProcessId,
        "pid=" + sessionNode?["pid"]);
    int port = sessionNode["port"].GetValue<int>();
    string token = sessionNode["token"].GetValue<string>();
    Check("1c session.json embeds no tool list (tools/list is authoritative)",
        sessionNode.ContainsKey("tools") == false);

    // raw HTTP/1.1, one request per connection — exactly what hand-rolled
    // clients send
    (int Status, string Body) Raw(string request)
    {
        using var c = new TcpClient("127.0.0.1", port);
        using var s = c.GetStream();
        byte[] bytes = Encoding.ASCII.GetBytes(request);
        s.Write(bytes, 0, bytes.Length);
        s.Flush();
        var buf = new byte[65536];
        using var ms = new MemoryStream();
        int n;
        c.ReceiveTimeout = 15000;
        try { while ((n = s.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n); }
        catch (ObjectDisposedException) { }
        catch (IOException) { }   // RST-after-response: the body checks below still judge
        string raw = Encoding.UTF8.GetString(ms.ToArray());
        int split = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string statusLine = raw.Substring(0, raw.IndexOf("\r\n", StringComparison.Ordinal));
        int status = int.Parse(statusLine.Split(' ')[1]);
        string body = split >= 0 ? raw.Substring(split + 4) : "";
        return (status, body);
    }
    string Post(string json, string auth = null)
    {
        byte[] payload = Encoding.UTF8.GetBytes(json);
        string a = auth ?? $"Bearer {token}";
        return "POST / HTTP/1.1\r\n" +
               $"Host: 127.0.0.1:{port}\r\n" +
               $"Authorization: {a}\r\n" +
               "Content-Type: application/json\r\n" +
               $"Content-Length: {payload.Length}\r\n" +
               "Connection: close\r\n\r\n" + json;
    }

    // ── 2. one dialect everywhere ───────────────────────────────────────
    var (get405, body405) = Raw($"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    var e405 = JsonNode.Parse(body405) as JsonObject;
    Check("2a GET -> 405 with a JSON-RPC error body",
        get405 == 405 && e405?["jsonrpc"]?.GetValue<string>() == "2.0" && e405["error"]?["code"]?.GetValue<int>() == -32001,
        $"status={get405} body={Trunc(body405)}");

    var (s401, body401) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}", "Bearer wrong"));
    var e401 = JsonNode.Parse(body401) as JsonObject;
    string msg401 = e401?["error"]?["message"]?.GetValue<string>() ?? "";
    Check("2b bad token -> 401 JSON-RPC body that explains a MISSING file too",
        s401 == 401 && e401?["error"]?["code"]?.GetValue<int>() == -32001 && msg401.Contains("no file = no active session"),
        $"status={s401} msg={Trunc(msg401)}");

    // ── 3. no bare closes ───────────────────────────────────────────────
    var (s411a, body411a) = Raw("POST / HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{port}\r\nAuthorization: Bearer " + token + "\r\nConnection: close\r\n\r\n");
    Check("3a POST without Content-Length -> 411 with a body (was: bare close)",
        s411a == 411 && (JsonNode.Parse(body411a) as JsonObject)?["error"] != null,
        $"status={s411a} body={Trunc(body411a)}");

    var (s411b, body411b) = Raw("POST / HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{port}\r\nAuthorization: Bearer " + token +
        "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n");
    Check("3b chunked POST -> 411 with a body",
        s411b == 411 && (JsonNode.Parse(body411b) as JsonObject)?["error"] != null,
        $"status={s411b} body={Trunc(body411b)}");

    var (s400, body400) = Raw(Post("this is not json"));
    var e400 = JsonNode.Parse(body400) as JsonObject;
    Check("3c malformed body -> 400 -32700, id null (was: throw into the void)",
        s400 == 400 && e400?["error"]?["code"]?.GetValue<int>() == -32700 && e400.ContainsKey("id") && e400["id"] == null,
        $"status={s400} body={Trunc(body400)}");

    // ── 4. handshake + tools over the wire ─────────────────────────────
    var (sInit, bodyInit) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"," +
        "\"params\":{\"protocolVersion\":\"2025-06-18\",\"clientInfo\":{\"name\":\"bridge-selftest\"}}}"));
    var init = (JsonNode.Parse(bodyInit) as JsonObject)?["result"];
    Check("4a initialize answers with serverInfo", sInit == 200 && init?["serverInfo"]?["name"]?.GetValue<string>() == "bridgeselftest");

    var (sList, bodyList) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"));
    var tools = (JsonNode.Parse(bodyList) as JsonObject)?["result"]?["tools"] as JsonArray;
    Check("4b tools/list carries the stub tool", sList == 200 && tools?.Any(t => t["name"].GetValue<string>() == "echo_state") == true);

    var (sCall, bodyCall) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\"," +
        "\"params\":{\"name\":\"echo_state\",\"arguments\":{}}}"));
    string callJson = bodyCall;
    Check("4c tool JSON in content.text uses \\\" escapes, not \\u0022",
        sCall == 200 && callJson.Contains("\\\"state\\\":") && !callJson.Contains("\\u0022"),
        Trunc(callJson));
    var structured = (JsonNode.Parse(bodyCall) as JsonObject)?["result"]?["structuredContent"];
    Check("4d structuredContent hands clients the parsed object",
        structured?["state"]?.GetValue<string>() == "ok");

    // ── 5. mutating policy text ─────────────────────────────────────────
    var (sMut, bodyMut) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\"," +
        "\"params\":{\"name\":\"open_gate\",\"arguments\":{\"target\":\"1.2.3.4\",\"minutes\":1}}}"));
    string mutText = ((JsonNode.Parse(bodyMut) as JsonObject)?["result"]?["content"] as JsonArray)?[0]?["text"]?.GetValue<string>() ?? "";
    Check("5a mutating tool in a non-mutating session explains headless sessions",
        sMut == 200 && mutText.Contains("WITHOUT mutating tools") && !mutText.Contains("Allow mutating tools"),
        Trunc(mutText));

    // ── 6. Stop deletes only OUR session file ───────────────────────────
    File.WriteAllText(sessionPath,
        new JsonObject { ["port"] = port, ["token"] = "x", ["pid"] = 999999 }.ToJsonString());
    bridge.Stop();
    Check("6a sibling-owned session.json survives this instance's Stop",
        File.Exists(sessionPath));

    var (ok2, _) = bridge.Start(allowMutating: false);
    Check("6b Start again succeeds after Stop", ok2);
    var again = JsonNode.Parse(File.ReadAllText(sessionPath)) as JsonObject;
    port = again["port"].GetValue<int>();
    token = again["token"].GetValue<string>();
    bridge.Stop();
    Check("6c own session.json is deleted on Stop", !File.Exists(sessionPath));

    // ── 7. gate path: dry_run never prompts; a throwing UI hook denies ──
    // Field bug this section pins: every mutating call (dry_run included)
    // failed with WPF's "The calling thread cannot access this object…"
    // because the engine's UI pre-check ran on the RPC listener thread.
    var (okMut, msgMut) = bridge.Start(allowMutating: true);
    Check("7a mutating session starts", okMut, msgMut);
    var mut = JsonNode.Parse(File.ReadAllText(sessionPath)) as JsonObject;
    port = mut["port"].GetValue<int>();
    token = mut["token"].GetValue<string>();

    // The reproduction: a UI hook whose availability check throws exactly
    // like reading a VerifyThread() WPF property off the UI thread.
    AutoCommand.Engines.Bridge.AgentBridgeService.Ui = new ThrowingUi();

    Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"initialize\"," +
        "\"params\":{\"protocolVersion\":\"2025-06-18\",\"clientInfo\":{\"name\":\"bridge-selftest\"}}}"));

    var (sDry, bodyDry) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"," +
        "\"params\":{\"name\":\"open_gate\",\"arguments\":{\"target\":\"1.2.3.4\",\"minutes\":1,\"dry_run\":\"true\"}}}"));
    var dryResult = (JsonNode.Parse(bodyDry) as JsonObject)?["result"];
    string dryText = (dryResult?["content"] as JsonArray)?[0]?["text"]?.GetValue<string>() ?? "";
    Check("7b dry_run bypasses confirmation entirely — handler runs, no crash",
        sDry == 200 && dryText.Contains("state") && !dryText.Contains("calling thread") &&
        (dryResult?["isError"]?.GetValue<bool>() ?? false) == false,
        Trunc(dryText));

    var (sThrow, bodyThrow) = Raw(Post("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\"," +
        "\"params\":{\"name\":\"open_gate\",\"arguments\":{\"target\":\"1.2.3.4\",\"minutes\":1}}}"));
    string throwText = (((JsonNode.Parse(bodyThrow) as JsonObject)?["result"])?["content"] as JsonArray)?[0]?["text"]?.GetValue<string>() ?? "";
    Check("7c UI hook throwing off-thread denies cleanly (no raw WPF text)",
        sThrow == 200 && throwText.Contains("no UI to confirm") && !throwText.Contains("calling thread"),
        Trunc(throwText));

    AutoCommand.Engines.Bridge.AgentBridgeService.Ui = null;
}
finally
{
    try { bridge.Stop(); } catch { }
    try { Directory.Delete(root, true); } catch { }
}

string Trunc(string s) => s.Length <= 110 ? s : s.Substring(0, 110) + "…";

Console.WriteLine(failures == 0 ? "BRIDGE SELF-TEST PASSED" : $"BRIDGE SELF-TEST FAILED ({failures} check(s))");
return failures == 0 ? 0 : 1;

// ── stub tool surface (types after all top-level statements) ──────────
sealed class StubTool : IAgentTool
{
    private readonly string _name;
    private readonly bool _mutating;
    public StubTool(string name, bool mutating) { _name = name; _mutating = mutating; }
    public string Name => _name;
    public bool Mutating => _mutating;
    public string ConfirmDetail(string argsJson) => "stub confirm: " + _name;
    public string Invoke(string argsJson) =>
        "{\"state\": \"ok\", \"note\": \"quote 'and' \\\"embedded\\\" text\"}";
}
sealed class StubTools : IAgentTools
{
    public IList<string> Names(bool allowMutating) =>
        allowMutating ? new List<string> { "echo_state", "open_gate" } : new List<string> { "echo_state" };
    public string ListTools(bool allowMutating) =>
        "[{\"name\":\"echo_state\",\"description\":\"stub read\"},{\"name\":\"open_gate\",\"description\":\"stub gate\"}]";
    public IAgentTool Find(string name, bool allowMutating) =>
        name == "echo_state" ? new StubTool(name, false)
        : name == "open_gate" ? new StubTool(name, true)
        : null;
    public string BuildMonitorSnapshot() => null;
}

/// <summary>The bug reproduction: an availability check that throws exactly
/// like WPF's VerifyThread() does when read from the RPC listener thread —
/// "a different thread owns it". The engine must not crash on it.</summary>
sealed class ThrowingUi : IAgentBridgeUI
{
    public bool IsUiAvailable => throw new InvalidOperationException(
        "The calling thread cannot access this object because a different thread owns it.");
    public void BeginInvokeOnUI(Action action) { }
    public Task<Tuple<bool, bool>> ShowConfirmAsync(string tool, string detail) =>
        Task.FromResult(Tuple.Create(false, false));
}
