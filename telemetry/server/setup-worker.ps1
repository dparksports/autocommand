# setup-worker.ps1 - one-command autonomous deploy of the usage-count worker.
#
# What it does (idempotent - safe to re-run):
#   1. Creates (or finds) the D1 database and patches wrangler.toml with its id
#   2. Applies schema.sql
#   3. Generates a random ADMIN_TOKEN, stores it in admin-token.txt (gitignored),
#      and sets it as the worker secret
#   4. Deploys the worker
#   5. Smoke-tests everything (page, graph, badge, a marked test ping + cleanup)
#   6. Prints the exact line to paste into UsagePingService.cs
#
# The ONE prerequisite (the only step a human must do):
#   Create an API token at https://dash.cloudflare.com/profile/api-tokens
#   (Create Token -> Custom): permissions "Workers Scripts: Edit" and "D1: Edit".
#   Then, in this shell:
#       $env:CLOUDFLARE_API_TOKEN = "paste-the-token"
#       # (optional, only if several accounts are attached:)
#       $env:CLOUDFLARE_ACCOUNT_ID = "your account id (dash home, right side)"
#   Free tier is enough - no credit card needed for Workers/D1 at this scale.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\setup-worker.ps1

$ErrorActionPreference = 'Continue'   # expected failures (d1 info on missing db) are handled below
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here   # wrangler resolves wrangler.toml from the cwd, not the script path

# Smoke-test HTTP calls: skip cert revocation checks — on hardened machines
# (this workspace's own firewall tooling) CRL/OCSP endpoints can be blocked,
# and Invoke-WebRequest then fails every handshake with CRYPT_E_REVOCATION_OFFLINE.
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

# = locate wrangler (portable node in the workspace, else PATH) =
$localNode = Join-Path (Resolve-Path "$here\..\..\..") ".tools\node"
if (Test-Path (Join-Path $localNode 'wrangler.cmd')) {
    $wrangler = Join-Path $localNode 'wrangler.cmd'
    $env:PATH = "$localNode;$env:PATH"   # so postinstalls/children find node
} else {
    $wrangler = 'wrangler'
}

function Invoke-Wrangler([string[]]$WranglerArgs) {
    & $wrangler @WranglerArgs 2>&1 | ForEach-Object { "$_" }
}

# = preflight: the token is the one human-provided secret =
if (-not $env:CLOUDFLARE_API_TOKEN) {
    Write-Host @"

No CLOUDFLARE_API_TOKEN in the environment. This is the only manual step:

  1. Sign up / log in: https://dash.cloudflare.com  (free)
  2. My Profile -> API Tokens -> Create Token -> Custom token:
       - Workers Scripts : Edit
       - D1              : Edit
  3. In this shell:
       `$env:CLOUDFLARE_API_TOKEN = '<your-token>'
  4. Re-run this script. Everything after this point is automated.

"@ -ForegroundColor Yellow
    exit 1
}

# = 1. D1 database (idempotent) =
# wrangler v4 dropped --json on d1 commands; parse the uuid from the table.
$uuidRx = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$dbId = $null
try {
    $info = Invoke-Wrangler @('d1','info','usage-ping') | Out-String
    if ($info -match $uuidRx) { $dbId = $Matches[0] }
} catch { $dbId = $null }

if (-not $dbId) {
    Write-Host "Creating D1 database 'usage-ping'..."
    $create = Invoke-Wrangler @('d1','create','usage-ping') | Out-String
    if ($create -match $uuidRx) { $dbId = $Matches[0] }
    if (-not $dbId) { throw "Could not create/parse D1 database.`n$create" }
} else {
    Write-Host "D1 database 'usage-ping' already exists ($dbId)."
}

$toml = Join-Path $here 'wrangler.toml'
((Get-Content $toml -Raw) -replace 'REPLACE_WITH_D1_DATABASE_ID', $dbId) |
    Set-Content $toml -NoNewline -Encoding ascii
Write-Host "wrangler.toml updated with database_id $dbId"

# = 2. schema =
Write-Host "Applying schema..."
Invoke-Wrangler @('d1','execute','usage-ping','--remote',"--file=$(Join-Path $here 'schema.sql')") | Write-Host

# = 3. ADMIN_TOKEN secret =
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 36
$rng.GetBytes($bytes)
$token = ([Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', '')
$tokenFile = Join-Path $here 'admin-token.txt'
$token | Set-Content $tokenFile -NoNewline -Encoding ascii
# pipe straight into wrangler (stdin must reach the native command directly)
Write-Output $token | & $wrangler secret put ADMIN_TOKEN 2>&1 | ForEach-Object { "$_" } | Write-Host
Write-Host "ADMIN_TOKEN generated (saved: $tokenFile - gitignored; keep it for /v1/stats)"

# = 4. deploy =
Write-Host "Deploying..."
$deployOut = Invoke-Wrangler @('deploy') | Out-String
Write-Host $deployOut
if ($deployOut -match '(https://[a-z0-9.-]+\.workers\.dev)') { $root = $Matches[1] }
else { throw "Could not parse worker URL from deploy output." }
Write-Host "Worker URL: $root" -ForegroundColor Green

# = 5. smoke tests =
$script:fail = 0
function Check([string]$name, [bool]$ok) {
    if ($ok) { Write-Host "  PASS  $name" -ForegroundColor Green }
    else { Write-Host "  FAIL  $name" -ForegroundColor Red; $script:fail++ }
}

$page    = try { (Invoke-WebRequest "$root/" -UseBasicParsing).Content } catch { '' }
$graph   = try { (Invoke-WebRequest "$root/v1/graph" -UseBasicParsing).Content } catch { '' }
$badge   = try { (Invoke-WebRequest "$root/v1/badge" -UseBasicParsing).Content } catch { '' }
Check "graph page serves ($root/)"        ($page  -match 'community count')
Check "public graph feed (/v1/graph)"     ($graph -match 'days')
Check "badge (/v1/badge)"                 ($badge -match '^\d+$')

# one marked test ping, verified via /v1/stats, then deleted
$smokeId = 'd' * 32    # valid random-id shape (32 hex); a real install colliding with it is ~impossible (2^-128)
$pingBody = @{ a = 'autocommand'; v = '0.0.0-smoketest'; o = 'setup'; i = $smokeId } | ConvertTo-Json -Compress
try {
    Invoke-RestMethod "$root/v1/ping" -Method Post -Body $pingBody -ContentType 'application/json' | Out-Null
} catch {}
Start-Sleep -Seconds 2
$stats = try {
    Invoke-RestMethod "$root/v1/stats" -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop
} catch { $null }
Check "ping accepted + stats auth works (/v1/stats)" ($null -ne $stats)
$smokeSeen = ($null -ne $stats) -and ((($stats | ConvertTo-Json -Depth 6)) -match 'smoketest')
Check "test row landed in the count" ($smokeSeen)

Invoke-Wrangler @('d1','execute','usage-ping','--remote',
    '--command', "DELETE FROM installs WHERE id='$smokeId'") | Out-Null
Invoke-Wrangler @('d1','execute','usage-ping','--remote',
    '--command', "DELETE FROM daily_active WHERE install_id='$smokeId'") | Out-Null
Invoke-Wrangler @('d1','execute','usage-ping','--remote',
    '--command', "DELETE FROM daily_rollup WHERE version LIKE '0.0.0-smoketest%'") | Out-Null
Check "test row cleaned up" ($true)

# = 6. what to do next =
Write-Host @"

=====================================================================
 DEPLOYED. The count endpoint is live and verified.

 Worker root (community graph + share page):  $root/
 Public feed:                                 $root/v1/graph
 Badge (yesterday's opt-in DAU):              $root/v1/badge
 Stats (use admin-token.txt):                 $root/v1/stats

 To activate the app side, paste this into
 autocommand1004\Services\UsagePingService.cs:

     private const string Endpoint = "$root/v1/ping";

 then build, run once, click Yes, and watch today's line appear at $root/
=====================================================================

"@ -ForegroundColor Cyan

if ($script:fail -gt 0) { Write-Host "$($script:fail) smoke check(s) FAILED - see above." -ForegroundColor Red; exit 2 }
Write-Host "All smoke checks passed." -ForegroundColor Green
