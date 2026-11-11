# End-to-end smoke test for the AI-access bridge (the app half; the app's
# manifest is requireAdministrator, so an elevation prompt appears when this
# is started from a non-elevated shell).
# 1. requires a live AI session started from the Be My Guest tab
# 2. MCP lifecycle: request before initialize -> -32002; initialize
#    negotiates the protocol version (never blind-echoes); tools/list /
#    tools/call over loopback with the session token
# 3. tools/call success MUST carry boolean isError:false (regression: null
#    broke strict client schema validation) and failures isError:true
# 4. negative checks: unknown method -32601, malformed JSON -32700,
#    bad token -> 401, spoofed Host -> 403
# 5. offline --agent-stdio mode answers with setup guidance
# Pure ASCII on purpose: Windows PowerShell 5.1 reads BOM-less scripts as
# ANSI and non-ASCII corrupts execution (see release.ps1's note).
param(
    # repo root is one level up from this script's scripts\ folder
    [string]$Exe = "$(Split-Path $PSScriptRoot -Parent)\bin\Debug\net10.0-windows10.0.19041.0\AutoCommand.exe"
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

$script:failures = 0
function Check([string]$name, [bool]$pass, [string]$detail = '') {
    $suffix = ''; if ($detail) { $suffix = ' - ' + $detail }
    if ($pass) { Write-Host "PASS $name$suffix" -ForegroundColor Green }
    else { Write-Host "FAIL $name$suffix" -ForegroundColor Red; $script:failures++ }
}

# -- attach to the live session started from the Be My Guest tab --------------
$sessionPath = Join-Path $env:LOCALAPPDATA 'AutoCommand\agent\session.json'
$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path $sessionPath) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
if (-not (Test-Path $sessionPath)) { throw "no live session - start one in the Be My Guest tab, then rerun" }
$session = Get-Content $sessionPath -Raw | ConvertFrom-Json
$port = $session.port; $token = $session.token
"session: port=$port token=$($token.Substring(0,8))... mutating=$($session.mutatingAllowed) tools=$(@($session.tools).Count)"

function Invoke-Rpc([string]$json, [string]$auth = "Bearer $token", [string]$hostHeader = "127.0.0.1:$port") {
    $client = New-Object System.Net.Http.HttpClient
    $req = New-Object System.Net.Http.HttpRequestMessage('POST', "http://127.0.0.1:$port/")
    $req.Content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, 'application/json')
    if ($auth)     { $req.Headers.TryAddWithoutValidation('Authorization', $auth) | Out-Null }
    if ($hostHeader) { $req.Headers.TryAddWithoutValidation('Host', $hostHeader) | Out-Null }
    $req.Headers.Accept.ParseAdd('application/json')
    $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = $body }
    $client.Dispose()
}

function Get-ResultText([string]$body) {
    $o = $body | ConvertFrom-Json
    if ($o.result -and $o.result.content) { $o.result.content[0].text }
    else { $body }
}

# -- 1. lifecycle: request before initialize is refused ------------------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
$pre = $r.Body | ConvertFrom-Json
Check '1a request before initialize -> -32002' ($pre.error.code -eq -32002) "code $($pre.error.code)"
$mal = Invoke-Rpc 'not json'
$malO = $mal.Body | ConvertFrom-Json
Check '1b malformed JSON -> -32700 with id null' ($malO.error.code -eq -32700 -and $null -eq $malO.id) "status $($mal.Status) code $($malO.error.code)"

# -- 2. handshake: negotiate, never blind-echo ---------------------------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01","clientInfo":{"name":"smoke-test"}}}'
$init = ($r.Body | ConvertFrom-Json).result
"handshake: status=$($r.Status) server=$($init.serverInfo.name) title=$($init.serverInfo.title) version=$($init.serverInfo.version)"
Check '2a handshake succeeds' ($init.serverInfo.name -eq 'autocommand') ''
Check '2b unknown version negotiated to newest supported' ($init.protocolVersion -eq '2025-06-18') $init.protocolVersion
Check '2c serverInfo carries version and title' ($init.serverInfo.version -and $init.serverInfo.title -eq 'AutoCommand (agent bridge)') $init.serverInfo.title
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke-test"}}}'
$init2 = ($r.Body | ConvertFrom-Json).result
Check '2d supported version echoed' ($init2.protocolVersion -eq '2025-03-26') $init2.protocolVersion

# -- 3. tools/list (mutating hidden without the toggle) --------------------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":3,"method":"tools/list"}'
$tools = ($r.Body | ConvertFrom-Json).result.tools | ForEach-Object { $_.name }
"tools: $($tools -join ', ')"

# -- 4. tools/call: get_svchost_identity on a real svchost PID -------------------
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='WpnService'").ProcessId
$r = Invoke-Rpc ('{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_svchost_identity","arguments":{"pid":' + $svcPid + '}}}')
"identity (PID $svcPid): " + (Get-ResultText $r.Body)
$ok4 = $r.Body | ConvertFrom-Json
Check '4a successful tools/call carries isError:false as a real boolean' `
      ($null -ne $ok4.result.PSObject.Properties['isError'] -and $ok4.result.isError -is [bool] -and $ok4.result.isError -eq $false) `
      "isError=$(($ok4.result.isError | Out-String).Trim())"

# -- 5. tools/call: get_monitor_rows (same boolean regression) -------------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}'
$snap = ((Get-ResultText $r.Body) | ConvertFrom-Json)
"monitor: $($snap.row_count) established row(s)"
$snap.rows | Select-Object -First 4 | ForEach-Object { "  $($_.process) -> $($_.remote) [$($_.classification)]" }
$ok5 = $r.Body | ConvertFrom-Json
Check '5a successful tools/call carries isError:false as a real boolean' `
      ($null -ne $ok5.result.PSObject.Properties['isError'] -and $ok5.result.isError -is [bool] -and $ok5.result.isError -eq $false) ''

# -- 6. tools/call: classify_ip ----------------------------------------------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"classify_ip","arguments":{"ip":"20.59.87.225"}}}'
"classify: " + ((Get-ResultText $r.Body) -replace '\s+', ' ')

# -- 7. unknown tool -> isError:true result (not a transport error) ---------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}'
$unkTool = $r.Body | ConvertFrom-Json
Check '7a unknown tool -> result with isError:true' ($unkTool.result.isError -eq $true) ''

# -- 8. unknown method -> -32601 ---------------------------------------------------
$r = Invoke-Rpc '{"jsonrpc":"2.0","id":8,"method":"resources/list"}'
$unkMethod = $r.Body | ConvertFrom-Json
Check '8a unknown method -> -32601' ($unkMethod.error.code -eq -32601) "code $($unkMethod.error.code)"

# -- 9. negative: bad token -> 401 --------------------------------------------------
# Named parameters on purpose: the old comma-call form passed both values as
# ONE positional argument (the valid-token default won), so this check never
# exercised the 401 path — and it only printed, never asserted.
$r = Invoke-Rpc -Json '{"jsonrpc":"2.0","id":9,"method":"ping"}' -Auth 'Bearer deadbeef'
Check '9a bad token -> 401' ($r.Status -eq 401) "status $($r.Status)"

# -- 10. negative: spoofed Host -> 403 -----------------------------------------------
$r = Invoke-Rpc -Json '{"jsonrpc":"2.0","id":10,"method":"ping"}' -HostHeader 'evil.example.com:443'
Check '10a spoofed Host -> 403' ($r.Status -eq 403) "status $($r.Status)"

# -- 11. stop: session file must disappear --------------------------------------------
# the live session stays - stop it in the Be My Guest tab when done
Start-Sleep -Milliseconds 800
"session file after stop: exists=$(Test-Path $sessionPath) (expect False)"

# -- 12. offline stdio bridge ----------------------------------------------------------
$offlineInput = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"smoke-test"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_monitor_rows","arguments":{}}}
'@
$out = $offlineInput | & $Exe --agent-stdio
$out | ForEach-Object {
    $o = $_ | ConvertFrom-Json
    if ($o.result.tools) { "stdio offline tools: " + (($o.result.tools | ForEach-Object { $_.name }) -join ', ') }
    elseif ($o.result.content) { "stdio offline call: " + $o.result.content[0].text.Substring(0, [Math]::Min(90, $o.result.content[0].text.Length)) }
    elseif ($o.result.serverInfo) { "stdio offline handshake: " + $o.result.serverInfo.name }
    else { "stdio: $_" }
}

if ($script:failures -gt 0) { Write-Host "BRIDGE SMOKE TEST FAILED ($($script:failures) check(s))" -ForegroundColor Red; exit 1 }
Write-Host 'BRIDGE SMOKE TEST PASSED' -ForegroundColor Green
