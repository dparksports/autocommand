# Smoke test for AutoCommand.AgentProxy (no elevation needed).
# Publishes the self-contained single-file proxy exactly the way release.ps1
# does, then drives it over stdio:
#   1. offline handshake + tools + guidance (isError true)
#   2. protocol matrix: supported versions echoed, unknown ones negotiated
#      down, requests before initialize refused with -32002
#   3. online forwarding against a mock JSON-RPC listener (+ auth header)
#   4. mid-connection offline->online flip: exactly one tools/list_changed,
#      emitted AFTER the in-flight response, never before initialize
#   5. session restart mid-connection: new port/token -> next call recovers
#   6. error codes: dead-port forward -32603, unknown method -32601,
#      malformed JSON -32700 with id null
#   7. hostile DOTNET_ROOT: empty folder and (when present) a real .NET 8 root
#   8. session identity: a live pid whose exe lives in a directory unrelated
#      to the proxy's own must FORWARD (the 2026-11-11 field bug: deployed
#      proxies rejected the real app via a one-level-up directory guess),
#      legacy files without an exe and mismatched exes stay offline, and the
#      two offline states give different guidance
# The proxy is pointed at a THROWAWAY agent dir (AC_AGENT_DIR): the fake
# session.json names a live pid, and the machine's real proxies re-read
# session.json on every message - they must never see the fake one.
# Pure ASCII on purpose: Windows PowerShell 5.1 reads BOM-less scripts as
# ANSI and non-ASCII corrupts execution (see release.ps1's note).
$ErrorActionPreference = 'Stop'

$script:failures = 0
function Check([string]$name, [bool]$pass, [string]$detail = '') {
    $suffix = ''; if ($detail) { $suffix = ' - ' + $detail }
    if ($pass) { Write-Host "PASS $name$suffix" -ForegroundColor Green }
    else { Write-Host "FAIL $name$suffix" -ForegroundColor Red; $script:failures++ }
}

# -- publish the proxy exactly as release.ps1 ships it -----------------------
$scDir = Join-Path $env:TEMP 'agentproxy-sctest'
"publishing self-contained single-file proxy to $scDir ..."
dotnet publish (Join-Path (Split-Path $PSScriptRoot -Parent) 'AgentProxy\AutoCommand.AgentProxy.csproj') `
    -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true -o $scDir | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish of the proxy failed' }
$proxy = Join-Path $scDir 'AutoCommand.AgentProxy.exe'
$proxySize = (Get-Item $proxy).Length
"proxy: $proxy ($([math]::Round($proxySize / 1MB, 1)) MB)"
Check '0a proxy is a single-file self-contained bundle (sanity)' ($proxySize -gt 10MB) "size $proxySize bytes"

# -- helpers ------------------------------------------------------------------
$agentDir = Join-Path $env:TEMP ('agentproxy-smoke-' + [guid]::NewGuid().ToString('N'))
$sessionPath = Join-Path $agentDir 'session.json'

function Invoke-ProxyLines([string[]]$lines, [hashtable]$envOverrides = $null) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $proxy
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables['AC_AGENT_DIR'] = $agentDir
    if ($envOverrides) { foreach ($k in $envOverrides.Keys) { $psi.EnvironmentVariables[$k] = $envOverrides[$k] } }
    $p = [System.Diagnostics.Process]::Start($psi)
    # Drain stdout/stderr CONCURRENTLY with the write phase: the 31-tool
    # offline tools/list is ~14KB, larger than the pipe buffer - reading
    # only after WaitForExit deadlocks the proxy mid-response (the harness
    # bug that hid behind the old 6-tool surface)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    foreach ($l in $lines) { $p.StandardInput.WriteLine($l) }
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(30000)) { $p.Kill(); throw 'proxy did not exit after stdin closed' }
    [pscustomobject]@{ Stdout = $outTask.Result; Stderr = $errTask.Result }
}

# a raw-socket JSON-RPC mock "bridge": accepts exactly $accepts connections,
# answers each request with a fixed result ECHOING ITS OWN id back (a JSON-RPC
# response that does not echo the request id is protocol garbage), records
# what it saw
function Write-MockScript([string]$path, [int]$port, [int]$accepts) {
    $code = @"
`$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
`$listener.Start()
`$received = @()
for (`$i = 0; `$i -lt $accepts; `$i++) {
    `$client = `$listener.AcceptTcpClient()
    `$stream = `$client.GetStream()
    `$buf = New-Object byte[] 65536
    `$sb = New-Object System.Text.StringBuilder
    do { `$n = `$stream.Read(`$buf, 0, `$buf.Length); if (`$n -gt 0) { [void]`$sb.Append([System.Text.Encoding]::UTF8.GetString(`$buf, 0, `$n)) } } while (`$stream.DataAvailable)
    `$body = `$sb.ToString()
    `$received += `$body
    `$rid = 99
    try {
        # the raw stream is "POST / HTTP/1.1 ...headers... <blank> {json}" —
        # parse only what follows the blank line
        `$json = `$body
        `$idx = `$body.IndexOf("`r`n`r`n")
        if (`$idx -ge 0) { `$json = `$body.Substring(`$idx + 4) }
        `$req = `$json | ConvertFrom-Json
        if (`$req.id -ne `$null) { `$rid = `$req.id }
    } catch {}
    `$resp = '{"jsonrpc":"2.0","id":' + (`$rid | ConvertTo-Json) + ',"result":{"echo":"mock-ok"}}'
    `$bytes = [System.Text.Encoding]::UTF8.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: `$(`$resp.Length)`r`nConnection: close`r`n`r`n`$resp")
    `$stream.Write(`$bytes, 0, `$bytes.Length)
    `$client.Close()
}
`$listener.Stop()
`$received | Set-Content '$path'
"@
    $mockScript = Join-Path $env:TEMP ('agent-mock-' + $port + '.ps1')
    Set-Content $mockScript $code
    return $mockScript
}

function Start-Mock([int]$port, [int]$accepts, [string]$capturePath) {
    $scriptFile = Write-MockScript $capturePath $port $accepts
    $proc = Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptFile -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1200
    return $proc
}

function Set-Session([int]$port, [string]$token) {
    New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
    # pid + exe name THIS live process: the session identity check must
    # accept an app whose exe lives in a directory unrelated to the proxy's
    # own folder. powershell plays the app; its exe path is the identity.
    @{ port = $port; token = $token; pid = $PID; exe = (Get-Process -Id $PID).Path } |
        ConvertTo-Json | Set-Content $sessionPath
}

try {

    # == 1. offline stdio =====================================================
    "--- OFFLINE ---"
    $out = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
    )).Stdout
    $msgs = $out -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    $init = $msgs | Where-Object { $_.id -eq 1 }
    $tools = $msgs | Where-Object { $_.id -eq 2 }
    $call = $msgs | Where-Object { $_.id -eq 3 }
    Check '1a initialize answers serverInfo autocommand' ($init.result.serverInfo.name -eq 'autocommand') ''
    Check '1b serverInfo carries a version' ($init.result.serverInfo.version -and $init.result.serverInfo.version.Length -gt 0) $init.result.serverInfo.version
    $toolNames = @($tools.result.tools | ForEach-Object { $_.name })
    Check '1c offline tools list is the full surface (25+, first and last present)' `
        ($toolNames.Count -ge 25 -and $toolNames -contains 'get_monitor_rows' -and $toolNames -contains 'diagnose_wsl') `
        ("$($toolNames.Count) tools")
    Check '1d offline call answers guidance with isError=true' ($call.result.isError -eq $true) ''

    # == 2. protocol matrix + lifecycle =======================================
    '--- PROTOCOL MATRIX / LIFECYCLE ---'
    foreach ($v in '2024-11-05', '2025-03-26', '2025-06-18') {
        $r = (Invoke-ProxyLines ("{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"initialize`",`"params`":{`"protocolVersion`":`"$v`",`"clientInfo`":{`"name`":`"t`"}}}")).Stdout | ConvertFrom-Json
        Check "2a supported version $v echoed" ($r.result.protocolVersion -eq $v) $r.result.protocolVersion
    }
    foreach ($case in @(@{ label = 'unknown 1999-01-01'; send = '1999-01-01'; expect = '2025-06-18' },
                        @{ label = 'missing protocolVersion'; send = $null;  expect = '2025-06-18' })) {
        $line = if ($case.send) { "{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"initialize`",`"params`":{`"protocolVersion`":`"$($case.send)`",`"clientInfo`":{`"name`":`"t`"}}}" }
                else { '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"t"}}}' }
        $r = (Invoke-ProxyLines $line).Stdout | ConvertFrom-Json
        Check "2b $($case.label) negotiated to $($case.expect)" ($r.result.protocolVersion -eq $case.expect) $r.result.protocolVersion
    }
    $pre = (Invoke-ProxyLines '{"jsonrpc":"2.0","id":7,"method":"tools/list"}').Stdout | ConvertFrom-Json
    Check '2c request before initialize refused with -32002' ($pre.error.code -eq -32002) "code $($pre.error.code)"
    $seq = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":7,"method":"tools/list"}',
        '{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t"}}}',
        '{"jsonrpc":"2.0","id":9,"method":"tools/list"}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    Check '2d initialize then tools/list succeeds' (@(($seq | Where-Object { $_.id -eq 9 }).result.tools).Count -ge 25) ''

    # == 3. online forwarding against a mock listener =========================
    '--- ONLINE (mock listener) ---'
    $capA = Join-Path $env:TEMP 'agent-mockA-received.txt'
    Remove-Item $capA -ErrorAction SilentlyContinue
    $mockA = Start-Mock 47955 4 $capA   # initialize + initialized + 2 calls all get forwarded
    Set-Session 47955 'SMOKETOKEN0123456789'
    $out3 = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"get_svchost_identity","arguments":{"pid":4}}}',
        '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"tail_sysmon","arguments":{"minutes":5}}}'
    )).Stdout
    $fwd = $out3 -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    Check '3a initialize forwarded and answered (id echoed)' (($fwd | Where-Object { $_.id -eq 10 }).result.echo -eq 'mock-ok') ''
    Check '3b tool calls forwarded (echo from mock)' (@($fwd | Where-Object { ($_.id -eq 11 -or $_.id -eq 12) -and $_.result.echo -eq 'mock-ok' }).Count -eq 2) ''
    Wait-Process -Id $mockA.Id -Timeout 30 -ErrorAction SilentlyContinue
    if (-not $mockA.HasExited) { Stop-Process -Id $mockA.Id -Force }
    $received = (Get-Content $capA -ErrorAction SilentlyContinue) -join "`n"
    Check '3c bearer token reaches the bridge' ($received -match 'Bearer SMOKETOKEN0123456789') ''
    Check '3d Host header is loopback' ($received -match 'Host: 127\.0\.0\.1:47955') ''

    # == 4+5. flip ordering + session restart, one long-lived connection ======
    '--- FLIP ORDERING + SESSION RESTART (one connection) ---'
    Remove-Item $sessionPath -ErrorAction SilentlyContinue
    $capB = Join-Path $env:TEMP 'agent-mockB-received.txt'
    $capC = Join-Path $env:TEMP 'agent-mockC-received.txt'
    Remove-Item $capB, $capC -ErrorAction SilentlyContinue
    # initialize happens while still OFFLINE (answered by the proxy itself),
    # so each mock sees TWO forwarded connections once the session points at
    # it: the resync initialize the proxy replays upstream (a fresh bridge
    # instance never saw the client's handshake) + the actual call.
    # mockC takes over after the session restarts onto a new port/token.
    $mockB = Start-Mock 47956 2 $capB
    $mockC = Start-Mock 47957 2 $capC

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $proxy
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables['AC_AGENT_DIR'] = $agentDir
    $proc = [System.Diagnostics.Process]::Start($psi)

    # before any initialize: a call must be refused, NOT generate a flip notification
    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}')
    Start-Sleep -Milliseconds 600
    # initialize while still offline
    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}')
    Start-Sleep -Milliseconds 600
    # the "button press": session appears pointing at mockB
    Set-Session 47956 'FLIPTOKEN'
    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}')
    Start-Sleep -Milliseconds 1000
    # session restart: new port and token (mockB is exhausted, mockC takes over)
    Set-Session 47957 'RESTARTTOKEN'
    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}')
    $proc.StandardInput.Close()
    $proc.WaitForExit(20000) | Out-Null
    $live = $proc.StandardOutput.ReadToEnd() -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }

    $firstNotifIdx = -1; $notifCount = 0; $resp3Idx = -1
    for ($i = 0; $i -lt $live.Count; $i++) {
        if ($live[$i].method -eq 'notifications/tools/list_changed') {
            $notifCount++
            if ($firstNotifIdx -lt 0) { $firstNotifIdx = $i }
        }
        if ($live[$i].id -eq 3) { $resp3Idx = $i }
    }
    Check '4a exactly two tools/list_changed - one per bridge instance (flip + restart)' ($notifCount -eq 2) "count $notifCount"
    Check '4b list_changed comes AFTER the in-flight response' ($resp3Idx -ge 0 -and $firstNotifIdx -gt $resp3Idx) "response@$resp3Idx first notification@$firstNotifIdx"
    Check '4c no notification before initialize completed' ($firstNotifIdx -gt 0) "first notification@$firstNotifIdx"
    Check '4d pre-initialize call refused with -32002' (($live | Where-Object { $_.id -eq 1 }).error.code -eq -32002) ''
    Check '4e offline initialize answered' (($live | Where-Object { $_.id -eq 2 }).result.serverInfo.name -eq 'autocommand') ''
    Check '4f call after flip forwarded (mock-ok)' (($live | Where-Object { $_.id -eq 3 }).result.echo -eq 'mock-ok') ''
    Check '5a call after session restart recovered (mock-ok)' (($live | Where-Object { $_.id -eq 4 }).result.echo -eq 'mock-ok') ''
    Wait-Process -Id $mockB.Id -Timeout 30 -ErrorAction SilentlyContinue
    Wait-Process -Id $mockC.Id -Timeout 30 -ErrorAction SilentlyContinue
    if (-not $mockB.HasExited) { Stop-Process -Id $mockB.Id -Force }
    if (-not $mockC.HasExited) { Stop-Process -Id $mockC.Id -Force }
    $capCtext = (Get-Content $capC -ErrorAction SilentlyContinue) -join "`n"
    Check '5b restarted bridge saw the new token' ($capCtext -match 'Bearer RESTARTTOKEN') ''

    # == 6. error codes =======================================================
    '--- ERROR CODES ---'
    Set-Session 1 'DEADPORTTOKEN'   # nothing listens on port 1: connection refused
    $dead = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    Check '6a dead-port forward answers -32603 (not -32002)' (($dead | Where-Object { $_.id -eq 21 }).error.code -eq -32603) "code $(($dead | Where-Object { $_.id -eq 21 }).error.code)"
    Check '6b dead-port error keeps the human guidance' (($dead | Where-Object { $_.id -eq 21 }).error.message -match 'AI session') ''
    Remove-Item $sessionPath -ErrorAction SilentlyContinue
    $unk = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":30,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","id":31,"method":"resources/list"}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    Check '6c unknown method answers -32601' (($unk | Where-Object { $_.id -eq 31 }).error.code -eq -32601) ''
    $mal = (Invoke-ProxyLines 'not json').Stdout | ConvertFrom-Json
    Check '6d malformed JSON answers -32700 with id null' ($mal.error.code -eq -32700 -and $null -eq $mal.id) ''

    # == 7. hostile DOTNET_ROOT ===============================================
    '--- HOSTILE DOTNET_ROOT ---'
    if (Test-Path $sessionPath) { Remove-Item $sessionPath }
    $emptyRoot = Join-Path $env:TEMP 'agentproxy-empty-dotnet-root'
    New-Item -ItemType Directory -Force $emptyRoot | Out-Null
    $handshake = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"poison"}}}'
    $poisoned = Invoke-ProxyLines $handshake @{ DOTNET_ROOT = $emptyRoot; DOTNET_ROOT_X64 = $emptyRoot }
    Check '7a handshake survives an empty DOTNET_ROOT' ($poisoned.Stdout -match 'serverInfo') "stderr: $($poisoned.Stderr.Trim())"
    $net8Root = Join-Path $env:LOCALAPPDATA 'Programs\AutoClaw2\resources\vendor\dotnet'
    if (Test-Path (Join-Path $net8Root 'dotnet.exe')) {
        $poisoned8 = Invoke-ProxyLines $handshake @{ DOTNET_ROOT = $net8Root; DOTNET_ROOT_X64 = $net8Root }
        Check '7b handshake survives a real .NET-8-only DOTNET_ROOT (AutoClaw2 vendored)' ($poisoned8.Stdout -match 'serverInfo') "stderr: $($poisoned8.Stderr.Trim())"
    }
    else { '7b skipped: no .NET-8-only runtime found to poison with' }

    # == 8. session identity + honest offline guidance =======================
    '--- SESSION IDENTITY ---'
    # 8a legacy session file (no exe recorded) + a live pid that is not the
    #     app: the name guard alone must keep this OFFLINE
    @{ port = 47958; token = 'LEGACYTOKEN'; pid = $PID } | ConvertTo-Json | Set-Content $sessionPath
    $leg = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":40,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    Check '8a legacy session (no exe) + live non-AutoCommand pid stays offline' `
        (($leg | Where-Object { $_.id -eq 41 }).result.isError -eq $true) ''

    # 8b live pid but the recorded exe is someone else's: the exact-match
    #     impostor guard must hold even against a live process
    @{ port = 47958; token = 'IMPOSTORTOKEN'; pid = $PID; exe = "$env:WINDIR\System32\cmd.exe" } |
        ConvertTo-Json | Set-Content $sessionPath
    $imp = (Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":42,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    Check '8b live pid with a mismatched recorded exe stays offline' `
        (($imp | Where-Object { $_.id -eq 43 }).result.isError -eq $true) ''

    # 8c the two offline states say different things - the 2026-11-11 field
    #     report chased an app that was running fine because one message
    #     covered both states
    Remove-Item $sessionPath -ErrorAction SilentlyContinue
    $noFileText = ((Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":44,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.id -eq 45 }).result.content[0].text
    @{ port = 47958; token = 'DEADTOKEN'; pid = 12345 } | ConvertTo-Json | Set-Content $sessionPath
    $deadPidText = ((Invoke-ProxyLines @(
        '{"jsonrpc":"2.0","id":46,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke"}}}',
        '{"jsonrpc":"2.0","id":47,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
    )).Stdout -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.id -eq 47 }).result.content[0].text
    Check '8c no-session guidance names the session; dead-pid guidance names the app' `
        ($noFileText -match 'No AutoCommand AI session' -and $deadPidText -match 'no longer running' -and $noFileText -ne $deadPidText) ''
}
finally {
    # the throwaway agent dir must never leak into the machine's real one
    Remove-Item $agentDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "PROXY SMOKE TEST FAILED ($($script:failures) check(s))" -ForegroundColor Red; exit 1 }
Write-Host 'PROXY SMOKE TEST PASSED' -ForegroundColor Green
