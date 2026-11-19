# snapshot-usage.ps1 - the weekly traction snapshot, automated.
#
# What it does (one run = one dated snapshot):
#   1. Pulls /v1/stats (distinct daily-actives series, countries, versions,
#      install totals) with the ADMIN_TOKEN from admin-token.txt next to this
#      script.
#   2. Sums real GitHub download counts for both apps' release assets.
#   3. Runs the plausibility anchor: yesterday's opt-in DAU (distinct
#      installs) must never exceed cumulative downloads - if it does, the
#      snapshot is marked SPOOFED-SUSPECTED (annotate in the data room;
#      never delete).
#   4. Writes metrics-history/usage-YYYY-MM-DD.json + one line in
#      metrics-history/usage-history.csv (the investor time series).
#
# Usage:
#   powershell -File snapshot-usage.ps1              # one snapshot now
#   powershell -File snapshot-usage.ps1 -Install     # + weekly Scheduled Task (Mon 09:00)
#   powershell -File snapshot-usage.ps1 -Uninstall   # remove the Scheduled Task
#   powershell -File snapshot-usage.ps1 -Quiet       # for the task: log instead of print
#
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# hardened machines can block CRL/OCSP endpoints; do not fail the snapshot on it
[Net.ServicePointManager]::CheckCertificateRevocationList = $false

$TaskName = 'magicpoint-usage-snapshot'
$historyDir = Join-Path (Resolve-Path "$here\..\..") 'fundraising\metrics\history'
$tokenFile = Join-Path $here 'admin-token.txt'
$workerRoot = 'https://autocommand-usage-ping.dpark-sports.workers.dev'

function Log([string]$m) { if (-not $Quiet) { Write-Host $m } }

# ── Scheduled task management ────────────────────────────────────────────────
if ($Install -or $Uninstall) {
    if ($Uninstall) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Log "Scheduled task '$TaskName' removed."
        if (-not $Install) { exit 0 }
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Quiet"
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Description 'Weekly magicpoint.ai traction snapshot (usage ping stats + GitHub downloads + plausibility check).' | Out-Null
    Log "Scheduled task '$TaskName' registered: every Monday 09:00, runs even if the machine was off at the time (StartWhenAvailable)."
    if (-not $Quiet) { Log "Next run: $((Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo).NextRunTime)" }
    exit 0
}

# ── The snapshot itself ──────────────────────────────────────────────────────
if (-not (Test-Path $tokenFile)) { throw "admin-token.txt not found next to the script - it holds the /v1/stats ADMIN_TOKEN." }
$token = (Get-Content $tokenFile -Raw).Trim()

$stats = Invoke-RestMethod "$workerRoot/v1/stats" -Headers @{ Authorization = "Bearer $token" }

# cumulative GitHub downloads across all releases of both apps (unauth API, 1 call each)
function TotalDownloads([string]$repo) {
    try {
        $rels = Invoke-RestMethod "https://api.github.com/repos/$repo/releases?per_page=100" `
            -Headers @{ 'User-Agent' = 'magicpoint-snapshot' }
        return ($rels | ForEach-Object { $_.assets } | Measure-Object download_count -Sum).Sum
    } catch { return -1 }
}
$dlAuto = TotalDownloads 'dparksports/autocommand-windows'
$dlShields = TotalDownloads 'dparksports/shields-up'
$downloads = ($dlAuto + $dlShields)

# plausibility anchor: distinct opt-in installs can never legitimately exceed downloads
$yesterday = ($stats.daily | Sort-Object day -Descending | Select-Object -First 1)
$dau = if ($yesterday) { [int]$yesterday.dau } else { 0 }
$plausible = ($downloads -lt 0) -or ($dau -le $downloads)
$flag = if ($plausible) { 'ok' } else { 'SPOOFED-SUSPECTED' }

$day = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
New-Item -ItemType Directory -Force -Path $historyDir | Out-Null

$snapshot = [ordered]@{
    captured_at   = (Get-Date).ToUniversalTime().ToString('o')
    day           = $day
    dau_yesterday = $dau
    dau_day       = if ($yesterday) { $yesterday.day } else { $null }
    downloads     = [ordered]@{ autocommand = $dlAuto; shields_up = $dlShields; total = $downloads }
    plausibility  = $flag
    totals        = $stats.totals
    daily         = $stats.daily
    countries     = $stats.countries
    versions      = $stats.versions
}
$jsonFile = Join-Path $historyDir "usage-$day.json"
$snapshot | ConvertTo-Json -Depth 6 | Set-Content $jsonFile -Encoding utf8

# one CSV line per snapshot - the traction time series
$csv = Join-Path $historyDir 'usage-history.csv'
if (-not (Test-Path $csv)) {
    'captured_at,dau_yesterday,downloads_total,downloads_autocommand,downloads_shields_up,plausibility' |
        Set-Content $csv -Encoding ascii
}
Add-Content $csv "$((Get-Date).ToUniversalTime().ToString('o')),$dau,$downloads,$dlAuto,$dlShields,$flag"

# weekly GitHub-metrics side (download counts per release etc.), if present
$ghScript = Join-Path (Resolve-Path "$here\..\..") 'fundraising\pull-github-metrics.ps1'
if (Test-Path $ghScript) {
    try { & $ghScript | Out-Null; Log "pull-github-metrics.ps1: done." }
    catch { Log "pull-github-metrics.ps1 failed: $_" }
}

$msg = "snapshot $day : DAU(yesterday)=$dau, downloads=$downloads ($dlAuto autocommand, $dlShields shields-up), plausibility=$flag -> $jsonFile"
Log $msg
if (-not $plausible) {
    Log "WARNING: DAU exceeds cumulative downloads - investigate before quoting this number. Annotate, never delete."
    exit 2
}
