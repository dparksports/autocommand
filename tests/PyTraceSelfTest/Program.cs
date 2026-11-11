// PyTrace self-test — the python instrumentation pair, offline:
//   • the embedded hook payload (the ii cross-assembly seam regression:
//     resource must resolve from the SAME assembly as its reader)
//   • installer round-trip (Install/IsInstalled/manifest/Uninstall removes
//     only our two files) against a fake site-packages in a temp dir
//   • env detection (venv layout, embedded-distribution refusal)
//   • ScanForVenvs (bounded hunt, skip list, streaming)
//   • PyTraceRecord parse + the reader tail (offset resume, per-pid store)
//   • `tls` verb (manual, driven by docs\selftest\run-selftest.ps1):
//     decrypt a REAL captured TLS session via the keylog.
//
// Everything runs against temp dirs injected through the service seams;
// the real %LOCALAPPDATA% pytrace state is never touched.
using System.Text;
using System.Text.Json;
using AutoCommand.Engines.Core;
using AutoCommand.Engines.Watch;
using AutoCommand.Forensics.Core;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

string tempRoot = Path.Combine(Path.GetTempPath(), "pytrace-selftest-" + Guid.NewGuid().ToString("N")[..8]);
WatchConfig.Configure(new AppIdentity(
    "PyTraceSelfTest", tempRoot, "TEST-IP ", "TEST-APP ",
    Microsoft.FSharp.Collections.ListModule.OfSeq(Array.Empty<string>()), 47821, "pytrace-selftest"));

if (args.Length > 0 && args[0] == "tls")
{
    // docs\selftest\run-selftest.ps1 drives this against a REAL captured
    // loopback TLS session: tls <client.bin> <server.bin> <keylog-dir>
    return RunRealTls(args);
}

// ── 1. the embedded payload ─────────────────────────────────────────
string payload;
try
{
    payload = PyTraceInstallerService.ReadPayloadText();
    Check("payload resource resolves from the reader's own assembly", payload.Length > 200);
    Check("payload registers an audit hook", payload.Contains("addaudithook", StringComparison.Ordinal));
    Check("payload sets SSLKEYLOGFILE", payload.Contains("SSLKEYLOGFILE", StringComparison.Ordinal));
    Check("payload honors the no-keylog opt-out", payload.Contains("no-keylog", StringComparison.Ordinal));
}
catch (Exception ex)
{
    Check("payload resource resolves from the reader's own assembly", false, ex.Message);
    Console.WriteLine($"{failures} CHECK(S) FAILED");
    return 1;
}

// ── 2. installer round-trip against a fake site-packages ────────────
string fakeSite = Path.Combine(tempRoot, "venv", "Lib", "site-packages");
string venvRoot = Path.GetFullPath(Path.Combine(tempRoot, "venv"));
Directory.CreateDirectory(fakeSite);
Directory.CreateDirectory(Path.Combine(venvRoot, "Scripts"));
File.WriteAllText(Path.Combine(venvRoot, "pyvenv.cfg"), "home = fake\n");
File.WriteAllText(Path.Combine(venvRoot, "Scripts", "python.exe"), "stub");

var installer = new PyTraceInstallerService(keylogDir: Path.Combine(tempRoot, "keylog"));
var env = PyTraceInstallerService.EnvFromExeDir(venvRoot, "selftest");
Check("venv layout detected", env != null && env.Source == "selftest" &&
      env.SitePackages.Replace('/', '\\').EndsWith("Lib\\site-packages", StringComparison.OrdinalIgnoreCase),
      env?.SitePackages ?? "(null)");
Check("fresh environment is not instrumented", !installer.IsInstalled(env.SitePackages));

Check("install succeeds", installer.Install(env) == null);
Check("IsInstalled after install", installer.IsInstalled(env.SitePackages));
Check("payload module written", File.Exists(Path.Combine(env.SitePackages, "PyTraceHook_ac.py")));
Check(".pth importer written", File.ReadAllText(Path.Combine(env.SitePackages, "PyTraceHook_ac.pth"))
      .TrimEnd() == "import PyTraceHook_ac");
Check("manifest records the environment",
      installer.LoadManifest().Count == 1 &&
      installer.LoadManifest()[0].Files.Count == 2);

// an unrelated file in site-packages must survive the uninstall
string stranger = Path.Combine(env.SitePackages, "not_ours.txt");
File.WriteAllText(stranger, "keep me");
Check("uninstall succeeds", installer.Uninstall(env.SitePackages) == null);
Check("our files removed", !File.Exists(Path.Combine(env.SitePackages, "PyTraceHook_ac.py")) &&
      !File.Exists(Path.Combine(env.SitePackages, "PyTraceHook_ac.pth")));
Check("manifest cleaned", installer.LoadManifest().Count == 0);
Check("unrelated files untouched", File.Exists(stranger));

// ── 3. embedded-distribution refusal ─────────────────────────────────
string embeddedRoot = Path.Combine(tempRoot, "embedded");
Directory.CreateDirectory(Path.Combine(embeddedRoot, "Lib", "site-packages"));
File.WriteAllText(Path.Combine(embeddedRoot, "python.exe"), "stub");
File.WriteAllText(Path.Combine(embeddedRoot, "python._pth"), "python311.zip\n");
var embedded = PyTraceInstallerService.EnvFromExeDir(embeddedRoot, "selftest");
Check("embedded distribution detected but refused",
      embedded != null && !embedded.CanInstrument &&
      (embedded.DisableReason ?? "").Contains("Embedded", StringComparison.Ordinal));

// ── 4. ScanForVenvs: bounded hunt with skip list ─────────────────────
string scanRoot = Path.Combine(tempRoot, "scan");
string needle = Path.Combine(scanRoot, "proj", "nested", "deeper", "venv");
Directory.CreateDirectory(Path.Combine(needle, "Scripts"));
Directory.CreateDirectory(Path.Combine(needle, "Lib", "site-packages"));
File.WriteAllText(Path.Combine(needle, "pyvenv.cfg"), "home = fake\n");
File.WriteAllText(Path.Combine(needle, "Scripts", "python.exe"), "stub");
// decoys: a node_modules tree (skip-listed) and a deep branch past maxDepth
Directory.CreateDirectory(Path.Combine(scanRoot, "proj", "node_modules", "pkg", "venvlike"));
Directory.CreateDirectory(Path.Combine(scanRoot, "proj", "very", "deep", "branch", "venvlike"));
var found = new List<string>();
PyTraceInstallerService.ScanForVenvs(new[] { scanRoot }, maxDepth: 6, maxDirectories: 10_000,
    e => found.Add(e.SitePackages), CancellationToken.None);
Check("scan finds the real venv", found.Count == 1 && found[0].Replace('/', '\\')
      .EndsWith("venv\\Lib\\site-packages", StringComparison.OrdinalIgnoreCase),
      string.Join(" | ", found));

// ── 5. record parse + reader tail ────────────────────────────────────
var record = JsonSerializer.Deserialize<PyTraceRecord>(
    """{"ts":1793500000.5,"pid":4242,"event":"subprocess.Popen","args":["'cmd.exe', '/c echo x'"],"stack":"  File \"t.py\", line 1, in <module>"}""");
Check("record parses (pid/event/stack)",
      record != null && record.Pid == 4242 && record.Event == "subprocess.Popen" &&
      (record.Stack ?? "").Contains("t.py", StringComparison.Ordinal) && record.Header.Contains("subprocess.Popen"));

string traceDir = PyTraceReaderService.TraceDir;
Directory.CreateDirectory(traceDir);
string traceFile = Path.Combine(traceDir, "trace-4242.jsonl");
var sb = new StringBuilder();
sb.AppendLine("""{"ts":1793500000.5,"pid":4242,"event":"subprocess.Popen","args":["a"],"stack":"File t.py line 1"}""");
sb.AppendLine("this line is not json at all");   // malformed — counted, never fatal
sb.AppendLine("""{"ts":1793500000.9,"pid":4242,"event":"os.system","args":[],"stack":"File t.py line 5"}""");
File.WriteAllText(traceFile, sb.ToString());

using var reader = new PyTraceReaderService();
reader.Start(); // loadExisting: tails the file written just above
Check("reader sees the pid", reader.HasTraceForPid(4242));
var got = reader.GetForPid(4242);
Check("reader stores valid records, skips malformed",
      got.Count == 2 && got[0].Event == "subprocess.Popen" && got[^1].Event == "os.system" &&
      reader.MalformedCount == 1,
      $"{got.Count} records, {reader.MalformedCount} malformed");

// tail resumes from the offset — an append adds exactly one record
File.AppendAllText(traceFile,
    """{"ts":1793500001.5,"pid":4242,"event":"os.startfile","args":[],"stack":"File t.py line 9"}""" + "\n");
var deadline = DateTime.UtcNow.AddSeconds(8);
while (reader.GetForPid(4242).Count < 3 && DateTime.UtcNow < deadline)
    Thread.Sleep(100);
Check("tail resumes from the offset", reader.GetForPid(4242).Count == 3,
      reader.GetForPid(4242).Count.ToString());
reader.Stop();

try { Directory.Delete(tempRoot, true); } catch { }

Console.WriteLine(failures == 0 ? "\nALL CHECKS PASSED" : $"\n{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;

// ── real-session decrypt (docs\selftest\run-selftest.ps1 verb) ───────
static int RunRealTls(string[] args)
{
    if (args.Length < 4)
    {
        Console.Error.WriteLine("usage: tls <client.bin> <server.bin> <keylog-dir>");
        return 1;
    }
    string tempRoot = Path.Combine(Path.GetTempPath(), "pytrace-tls-" + Guid.NewGuid().ToString("N")[..8]);
    AutoCommand.Engines.Watch.WatchConfig.Configure(new AutoCommand.Engines.Core.AppIdentity(
        "PyTraceSelfTest", tempRoot, "TEST-IP ", "TEST-APP ",
        Microsoft.FSharp.Collections.ListModule.OfSeq(Array.Empty<string>()), 47821, "pytrace-selftest"));

    var flow = new AutoCommand.Engines.Watch.TcpFlowRecord
    {
        ClientData = File.ReadAllBytes(args[1]),
        ServerData = File.ReadAllBytes(args[2]),
    };
    var keylog = new AutoCommand.Engines.Watch.TlsKeylogService(args[3]);
    keylog.Refresh();
    var result = AutoCommand.Engines.Watch.TlsDecryptor.Decrypt(flow, keylog);

    bool pass = result.Success && !string.IsNullOrEmpty(result.Sni) &&
                (result.HttpSummary ?? "").Length > 0;
    Console.WriteLine($"SNI: {result.Sni ?? "(none)"} · {result.TlsVersion ?? "?"} · {result.Status}");
    Console.WriteLine($"HTTP summary: {result.HttpSummary ?? "(none)"}");
    Console.WriteLine(pass ? "TLS-DECRYPT: PASS" : "TLS-DECRYPT: FAIL");
    try { Directory.Delete(tempRoot, true); } catch { }
    return pass ? 0 : 1;
}
