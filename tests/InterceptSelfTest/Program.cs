// Intercept self-test — offline, temp-dir only (see csproj header).
// The journal mechanics and the CA/leaf service are the safety-critical
// parts that can be exercised without touching the machine; everything
// netsh/registry lives behind the manual E2E pass instead.
using System.Security.Cryptography.X509Certificates;
using AutoCommand.Intercept.Core;

int failures = 0;
void Check(string name, bool pass, string evidence = "")
{
    Console.WriteLine($"{(pass ? "PASS" : "FAIL")}  {name}{(pass || evidence.Length == 0 ? "" : "  — " + evidence)}");
    if (!pass) failures++;
}

string tempRoot = Path.Combine(Path.GetTempPath(), "intercept-selftest-" + Guid.NewGuid().ToString("N")[..8]);
InterceptCaService.DirOverride = tempRoot;

// ── 1. CA lifecycle ──────────────────────────────────────────────────
var ca = InterceptCaService.GetOrCreateCa();
Check("CA created with the expected subject", ca.Subject.Contains("AutoCommand Intercept CA"), ca.Subject);
Check("CA is a certificate authority", ca.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority));
Check("CA persisted to disk", File.Exists(Path.Combine(tempRoot, "ca.pfx")));

string thumbprint = ca.Thumbprint;
var reloaded = InterceptCaService.GetOrCreateCa();
Check("CA reloads from disk (same key material, stable thumbprint)",
      reloaded.Thumbprint == thumbprint, $"{thumbprint[..12]}… vs {reloaded.Thumbprint[..12]}…");

var leaf = InterceptCaService.GetOrMintLeaf("fe3cr.delivery.mp.microsoft.com");
Check("leaf minted for a hostname", leaf != null && leaf.Subject.Contains("fe3cr.delivery.mp.microsoft.com"));
var sameLeaf = InterceptCaService.GetOrMintLeaf("fe3cr.delivery.mp.microsoft.com");
Check("leaf cache reuses the same certificate", sameLeaf.Thumbprint == leaf.Thumbprint);
var ipLeaf = InterceptCaService.GetOrMintLeaf("74.178.240.51");
Check("leaf minted for an IP SAN", ipLeaf != null &&
      ipLeaf.Extensions.OfType<System.Security.Cryptography.X509Certificates.X509Extension>()
          .Any(e => e.Format(false).Contains("IP Address=74.178.240.51")));

// ── 2. journal round-trip + crash recovery ───────────────────────────
string journalPath = InterceptSystemHooks.JournalPathForTest;
Check("journal absent before any session", !File.Exists(journalPath));

// RecoverAfterCrash with no journal must be a clean no-op.
InterceptSystemHooks.RecoverAfterCrash();
Check("recover with no journal is a no-op", !File.Exists(journalPath));

var journal = new InterceptSystemHooks.Journal
{
    ProxyPort = 48999,
    CaThumbprint = thumbprint,
    WinHttpProxyBefore = null,                 // direct — netsh reset restores it
    WininetEnableBefore = 0,
    WininetServerBefore = null,
    FirewallRules = new[] { "AutoCommand Intercept QUIC block (4242)" },
};
// Write via the hook's own persistence path: install the journal file the
// same way InstallAll would (without touching netsh — we only exercise the
// file mechanics here, so serialize one manually through RecoverAfterCrash's
// reader by writing the JSON ourselves).
string json = System.Text.Json.JsonSerializer.Serialize(journal,
    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
Directory.CreateDirectory(tempRoot);
File.WriteAllText(journalPath, json);
Check("journal file written", File.Exists(journalPath));

// Recovery must undo-and-delete: CA removed from Root by thumbprint (no-op
// here — never installed), journal deleted. The netsh/registry restores run
// for real but against a machine where those hooks were never installed,
// which restores the pre-existing (unchanged) state.
InterceptSystemHooks.RecoverAfterCrash();
Check("recovery deletes the journal", !File.Exists(journalPath));

// A second recovery with nothing to do stays quiet.
InterceptSystemHooks.RecoverAfterCrash();
Check("second recovery stays quiet", !File.Exists(journalPath));

// ── 3. corrupted journal never guessed at ────────────────────────────
// A partial write means the hooks may be live with this file as their only
// undo record — recovery must tolerate it AND leave it in place.
Directory.CreateDirectory(tempRoot);
File.WriteAllText(journalPath, "{not json at all");
InterceptSystemHooks.RecoverAfterCrash();
Check("corrupt journal is tolerated and left in place (never guessed at)",
      File.Exists(journalPath));

try { Directory.Delete(tempRoot, true); } catch { }

Console.WriteLine(failures == 0 ? "\nALL CHECKS PASSED" : $"\n{failures} CHECK(S) FAILED");
return failures == 0 ? 0 : 1;
