# local-ci.ps1 - the ci.yml gate, runnable at the desk.
#
# Same steps in the same order as .github/workflows/ci.yml: vulnerability
# scan, Release build, Debug build, the strict offline suites, then the two
# live-channel suites (advisory). Exits non-zero on any strict failure.
#
# TMP/TEMP are redirected into the repo's .citmp for everything this script
# runs. In a normal terminal that changes nothing; under an agent sandbox it
# is REQUIRED: sandboxes run spawned .NET processes at Low integrity, and a
# Low-IL process cannot write to the user-profile Temp (Medium IL) - every
# suite's scratch root lives under GetTempPath(), so without the redirect
# they all die with UnauthorizedAccessException the moment they touch disk.
# (Observed 2026-11-11: freshly built suites red under the agent, green from
# the user's own shell - the token label, not the code, was the difference.)
#
# NOTE: keep this file pure ASCII, same reason as release.ps1.
#
# Usage:  powershell -File scripts\local-ci.ps1

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg)  { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

$citmp = Join-Path $repoRoot '.citmp'
New-Item -ItemType Directory -Force -Path $citmp | Out-Null
$env:TMP = $citmp; $env:TEMP = $citmp
Step "TMP/TEMP redirected to $citmp"

Step 'Dependency vulnerability scan'
$out = dotnet list AutoCommand.csproj package --vulnerable --include-transitive
Write-Host $out
if ($out -match 'has the following vulnerable packages') { Die 'vulnerable packages found' }

Step 'Build (Release)'
dotnet build AutoCommand.csproj -c Release --nologo
if ($LASTEXITCODE -ne 0) { Die 'Release build failed' }

Step 'Build (Debug)'
dotnet build AutoCommand.csproj -c Debug --nologo
if ($LASTEXITCODE -ne 0) { Die 'Debug build failed' }

# Same list as ci.yml (RainSelfTest stays out - manual visual harness).
$strict = @(
    'tests/NetWatchSelfTest',
    'tests/OneSettingsCadenceSelfTest',
    'tests/ContainSelfTest',
    'tests/ProxyInstallSelfTest',
    'tests/BridgeSelfTest',
    'tests/PyTraceSelfTest',
    'tests/InterceptSelfTest',
    'tests/HardenSelfTest',
    'tests/WslSelfTest',
    'tests/StartupHealthSelfTest',
    'tests/AllowListSelfTest',
    'tests/WatchSelfTest'
)
Step 'Offline suites (strict)'
foreach ($s in $strict) {
    Write-Host "== $s =="
    dotnet run --project $s
    if ($LASTEXITCODE -ne 0) { Die "$s failed" }
}

Step 'Live-channel suites (advisory - failures do not gate here)'
foreach ($s in @('tests/SiteDoctorSelfTest', 'tests/TaskAttributionSelfTest')) {
    Write-Host "== $s =="
    dotnet run --project $s
    if ($LASTEXITCODE -ne 0) { Write-Host "ADVISORY: $s failed (does not gate)" -ForegroundColor Yellow }
}

Step 'LOCAL CI: GREEN'
exit 0
