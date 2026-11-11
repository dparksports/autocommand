# Python instrumentation — offline self-test (no elevation, no internet).
#
# Verifies the three engine pieces that can be exercised headlessly:
#   1. The offline PyTraceSelfTest suite (payload embed, installer round-trip,
#      env detection, scan, reader tail — strict, also gates in CI)
#   2. The audit-hook payload end-to-end (stack capture + SSLKEYLOGFILE):
#      the REAL shipped payload runs inside a real python that spawns a child
#      and makes a TLS request
#   3. TLS decryption of a REAL captured session (1.3 by default, 1.2 with
#      -Tls12): python client -> relay (records both byte streams) -> python
#      TLS server, all on loopback, client writing the NSS keylog via the hook
#
# Needs on PATH: python (3.8+), openssl, dotnet (SDK 10).
#
#   cd autocommand-iii\docs\selftest
#   .\run-selftest.ps1              # TLS 1.3
#   .\run-selftest.ps1 -Tls12       # force the TLS 1.2 path
param([switch]$Tls12)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$appDir = Resolve-Path (Join-Path $here "..\..")
$harnessDir = Join-Path $appDir "tests\PyTraceSelfTest"
$payloadPath = Join-Path $appDir "core\AutoCommand.Forensics.Core\PyTraceHook.py"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pytrace-selftest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path "$tmp\hook" -Force | Out-Null

# The REAL shipped payload is what gets tested — copy it in as the module.
Copy-Item $payloadPath "$tmp\hook\PyTraceHook_ac.py"

& openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp\key.pem" -out "$tmp\cert.pem" -days 1 `
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>$null

$serverPort = 48811
$relayPort = 48812
$serverEnv = @{ LOCALAPPDATA = $tmp }
if ($Tls12) { $serverEnv["FORCE_TLS12"] = "1" }

$server = Start-Process -FilePath python -ArgumentList "`"$here\pytrace_tls_server.py`" $serverPort `"$tmp\cert.pem`" `"$tmp\key.pem`"" `
    -Environment $serverEnv -PassThru -WindowStyle Hidden -RedirectStandardOutput "$tmp\server.out"
Start-Sleep -Seconds 2
$relay = Start-Process -FilePath python -ArgumentList "`"$here\pytrace_relay.py`" $relayPort $serverPort `"$tmp`"" `
    -Environment @{ LOCALAPPDATA = $tmp } -PassThru -WindowStyle Hidden -RedirectStandardOutput "$tmp\relay.out"
Start-Sleep -Seconds 2

$env:LOCALAPPDATA = $tmp
$env:SELFTEST_CERT = "$tmp\cert.pem"
& python "$here\pytrace_tls_client.py" "$tmp\hook" $relayPort
if ($LASTEXITCODE -ne 0) { throw "TLS client failed — see output above." }
Start-Sleep -Seconds 1

$fail = 0

Write-Host "`n=== 1. Offline suite (payload embed, installer, envs, scan, reader) ===" -ForegroundColor Cyan
& dotnet run --project $harnessDir
if ($LASTEXITCODE -ne 0) { $fail = 1 }

Write-Host "`n=== 2. Audit-hook payload (trace + keylog written?) ===" -ForegroundColor Cyan
$trace = Get-ChildItem "$tmp\AutoCommand\pytrace\trace-*.jsonl" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($trace -and (Select-String -Path $trace.FullName -Pattern "subprocess.Popen" -Quiet) -and
    (Test-Path "$tmp\AutoCommand\pytrace\sslkeys.log")) {
    Write-Host "HOOK: PASS — stack recorded in $($trace.Name), keylog written"
} else {
    Write-Host "HOOK: FAIL — trace or keylog missing under $tmp\AutoCommand\pytrace"
    $fail = 1
}

Write-Host "`n=== 3. TLS decryption (real session via relay) ===" -ForegroundColor Cyan
& dotnet run --project $harnessDir -- tls "$tmp\client.bin" "$tmp\server.bin" "$tmp\AutoCommand\pytrace"
if ($LASTEXITCODE -ne 0) { $fail = 1 }

if ($fail -eq 0) {
    Write-Host "`nALL SELF-TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "`nSELF-TEST FAILURES — see above" -ForegroundColor Red
}
exit $fail
