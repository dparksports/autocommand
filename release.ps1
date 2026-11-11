# release.ps1 - one-command release pipeline for AutoCommand.
#
# <Version> in AutoCommand.csproj is the single source of truth; everything else
# (assembly attributes, git tag, zip names, SHA256SUMS.txt, release title) is
# derived from it. Never type a version anywhere else.
#
# NOTE: keep this file pure ASCII. Windows PowerShell 5.1 reads BOM-less scripts
# as ANSI, and non-ASCII characters corrupt execution in ways that are no fun to
# debug (an em-dash once swallowed an exit statement).
#
# Usage:
#   powershell -File release.ps1 -Version 2026.10.16   # full release (pushes!)
#   powershell -File release.ps1 -Version 2026.10.14.2 # same-day follow-up (4th segment)
#   powershell -File release.ps1 -Version 2026.10.16 -Yes   # no confirm prompt
#   powershell -File release.ps1 -DryRun               # package + verify only
#
# Full release requires: clean working tree on master, a '## v<Version>'
# section already written AND COMMITTED in docs/release-notes-history.md (the
# single home for release notes - its section becomes the GitHub release body),
# and `gh` authenticated. Steps: bump csproj -> publish
# self-contained win-x64 -> verify the exe reports the csproj version -> zip app
# -> SHA256SUMS.txt (app zip + unblock script) -> confirm -> commit -> tag -> push ->
# gh release create. If it dies mid-run after the bump, the csproj is left
# modified - fix and re-run.
#
# The standalone SvchostAnalyzer.exe is not built or shipped anymore; the app
# traces in-process via SvchostAnalyzer.Core. The headless boot-autostart host
# is not distributed - already-installed copies keep working.

[CmdletBinding()]
param(
    [string]$Version,
    [switch]$DryRun,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg)  { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Assert-Exit([string]$what) {
    if ($LASTEXITCODE -ne 0) { Die "$what failed (exit $LASTEXITCODE)" }
}
function Get-HistoryNotes([string]$Version) {
    # The consolidated notes archive is the single home for release notes: the
    # section for this version (everything after its '## v<version>' heading,
    # up to the next '## v' line) becomes the GitHub release body. Same parse
    # contract as release.yml's attach step.
    $histPath = Join-Path $PSScriptRoot 'docs\release-notes-history.md'
    if (-not (Test-Path $histPath)) { Die 'docs/release-notes-history.md not found' }
    # [IO.File]::ReadAllText, NOT Get-Content: the archive is UTF-8 (release
    # titles carry em-dashes) and PS 5.1's Get-Content would decode it as ANSI.
    $hist = [System.IO.File]::ReadAllText($histPath)
    # $Version is already validated as \d+\.\d+\.\d+(\.\d+)? - no metacharacters;
    # the (?![\d.]) guard stops v2026.11.1 from matching v2026.11.10 headings.
    $m = [regex]::Match($hist, "(?ms)^## v$Version(?![\d.])[^\r\n]*\r?\n(.*?)(?=^## v\d|\z)")
    if (-not $m.Success) {
        Die "no '## v$Version' section in docs/release-notes-history.md - write the notes section at the top, commit it, then re-run (format contract is at the top of that file)"
    }
    return $m.Groups[1].Value.Trim()
}

Step "Parameters: Version=[$Version] DryRun=[$DryRun] Yes=[$Yes]"

# -- The source of truth ------------------------------------------------------
$csproj = Join-Path $PSScriptRoot 'AutoCommand.csproj'
$csprojText = [System.IO.File]::ReadAllText($csproj)
if ($csprojText -notmatch '(?m)^\s*<Version>([\d.]+)</Version>\s*$') {
    Die 'cannot read <Version> from AutoCommand.csproj'
}
$currentVersion = $Matches[1]

if (-not $DryRun) {
    if (-not $Version) { Die 'usage: release.ps1 -Version <N.N.N> (e.g. 2026.10.16) [-DryRun] [-Yes]' }
    # Three calendar segments, optional fourth for same-day follow-ups
    # (v2026.10.14.1) - keeps the date truthful instead of future-dating it.
    if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') { Die "version '$Version' must be calendar-dated, three parts or a fourth same-day segment (e.g. 2026.10.16 or 2026.10.14.1)" }
    if ([version]$Version -le [version]$currentVersion) {
        Die "v$Version must be greater than the current v$currentVersion"
    }
    git rev-parse -q --verify "refs/tags/v$Version" | Out-Null
    if ($LASTEXITCODE -eq 0) { Die "tag v$Version already exists" }
    if ((git branch --show-current) -ne 'master') { Die 'releases are cut from master only' }
    $dirty = git status --porcelain --untracked-files=no
    if ($dirty) { Die "working tree not clean - commit or stash first:`n$dirty" }
    Step "Reading notes for v$Version from docs/release-notes-history.md"
    $notesFile = 'publish/release-notes.md'
    $notes = Get-HistoryNotes $Version
    if (-not $notes) { Die "notes section for v$Version is empty" }
    [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot $notesFile), $notes,
        (New-Object System.Text.UTF8Encoding($false)))

    Step "Bumping AutoCommand.csproj to $Version (currently v$currentVersion)"
    $newText = $csprojText -replace "(?m)^(\s*<Version>)[\d.]+(</Version>\s*)$", "`${1}$Version`${2}"
    if ($newText -eq $csprojText) { Die 'failed to rewrite <Version> in AutoCommand.csproj' }
    [System.IO.File]::WriteAllText($csproj, $newText)

    # The proxy's csproj follows the app's version (serverInfo / deps.json
    # must never disagree with the release they shipped in).
    $proxyCsproj = Join-Path $PSScriptRoot 'AgentProxy\AutoCommand.AgentProxy.csproj'
    $proxyText = [System.IO.File]::ReadAllText($proxyCsproj)
    $newProxyText = $proxyText -replace "(?m)^(\s*<Version>)[\d.]+(</Version>\s*)$", "`${1}$Version`${2}"
    if ($newProxyText -eq $proxyText) { Die 'failed to rewrite <Version> in AgentProxy\AutoCommand.AgentProxy.csproj' }
    [System.IO.File]::WriteAllText($proxyCsproj, $newProxyText)
}

$relVersion = if ($DryRun) { $currentVersion } else { $Version }
$appZip     = "publish/AutoCommand-v$relVersion-win-x64.zip"
$unblockPs1 = "publish/unblock-autocommand.ps1"
$sumsFile   = "publish/SHA256SUMS.txt"

# -- Build --------------------------------------------------------------------
Step "Publishing self-contained win-x64 build (v$relVersion)"
dotnet publish AutoCommand.csproj -c Release -r win-x64 --self-contained true -o "publish/v$relVersion"
Assert-Exit 'dotnet publish'

# The AgentProxy MCP clients spawn: self-contained SINGLE FILE, so no
# framework lookup happens at spawn time. Bundle compression shrinks the
# 15.3 MB trimmed exe to 11.5 MB at a small one-time decompress cost at
# first spawn - verified against the stdio offline-guidance handshake. Desktop MCP clients are known to
# export their own DOTNET_ROOT (often an older .NET) for everything they
# spawn - a framework-dependent proxy dies in the apphost before any managed
# code runs ("You must install .NET to run this application"). The app's
# Register action copies this from the zip's tools\AgentProxy into
# %LOCALAPPDATA%\AutoCommand\tools\v<version>\ and points client configs at
# that stable path.
Step "Publishing self-contained single-file AgentProxy (tools)"
dotnet publish AgentProxy\AutoCommand.AgentProxy.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true /p:EnableCompressionInSingleFile=true -o "publish/v$relVersion/tools/AgentProxy"
Assert-Exit 'dotnet publish proxy'

# -- Verify the binaries carry the csproj version - the whole point -----------
$exe = "publish/v$relVersion/AutoCommand.exe"
$binaryVersion = (Get-Item $exe).VersionInfo.ProductVersion
if ($binaryVersion -ne $relVersion) {
    Die "published exe reports ProductVersion '$binaryVersion' but expected '$relVersion' - the version pipeline is broken"
}
Step "Verified exe ProductVersion: $binaryVersion"
$proxyExe = "publish/v$relVersion/tools/AgentProxy/AutoCommand.AgentProxy.exe"
$proxyVersion = (Get-Item $proxyExe).VersionInfo.ProductVersion
if ($proxyVersion -ne $relVersion) {
    Die "published proxy reports ProductVersion '$proxyVersion' but expected '$relVersion' - the version pipeline is broken"
}
Step "Verified proxy ProductVersion: $proxyVersion"

# -- Package ------------------------------------------------------------------
Step "Zipping release assets"
if (Test-Path $appZip) { Remove-Item $appZip }
Compress-Archive -Path "publish/v$relVersion/*" -DestinationPath $appZip

# Standalone unblock script - separate downloadable asset for users who cannot
# launch the app at all (Smart App Control / SmartScreen blocks on the
# downloaded zip's Mark-of-the-Web).
Copy-Item (Join-Path $PSScriptRoot 'unblock-autocommand.ps1') $unblockPs1 -Force

$sums = @(
    "{0}  {1}" -f (Get-FileHash $appZip -Algorithm SHA256).Hash.ToLower(), (Split-Path $appZip -Leaf)
    "{0}  {1}" -f (Get-FileHash $unblockPs1 -Algorithm SHA256).Hash.ToLower(), (Split-Path $unblockPs1 -Leaf)
)
[System.IO.File]::WriteAllLines((Join-Path $PSScriptRoot $sumsFile), $sums)
Step "Wrote $sumsFile (app + unblock script)"

if ($DryRun) {
    Step "Dry run complete - build, zips and checksums verified; nothing committed, tagged or uploaded"
    exit 0
}

# -- Fail-closed gate: nothing below may run without a validated version ------
if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
    Die "refusing to release: Version=[$Version] is not a valid calendar version"
}
if (-not $Yes) {
    $answer = Read-Host "About to commit, tag v$Version, PUSH to origin and create the GitHub release. Type 'release' to proceed"
    if ($answer -ne 'release') { Die 'aborted - nothing was committed, tagged or pushed' }
}

# -- Commit, tag, push, release -----------------------------------------------
Step "Committing and tagging v$Version"
git add AutoCommand.csproj AgentProxy\AutoCommand.AgentProxy.csproj
git commit -m "release: v$Version"
Assert-Exit 'git commit'
git tag "v$Version"
Assert-Exit 'git tag'

Step "Pushing master and tag"
git push origin master
Assert-Exit 'git push master'
git push origin "v$Version"
Assert-Exit 'git push tag'

Step "Creating GitHub release"
# Assets go up ONE PER gh CALL, not as one create-with-assets call: gh
# uploads in parallel and its own retry after a transient socket error
# races itself into HTTP 422 "ReleaseAsset.name already exists" (seen on
# two consecutive releases), then rolls back the whole release. Serial
# create-then-upload with --clobber cannot race itself.
gh release create "v$Version" --title "v$Version" --notes-file $notesFile
Assert-Exit 'gh release create (release shell)'
gh release upload "v$Version" $appZip --clobber
Assert-Exit 'gh release upload (app zip)'
gh release upload "v$Version" $unblockPs1 $sumsFile --clobber
Assert-Exit 'gh release upload (unblock script + sums)'

# -- README mirror retired -------------------------------------------------------
# This repository IS the former "archived original repo" (dparksports/
# autocommand-windows): AutoCommand II and III were consolidated back into it,
# so there is no frozen repo left to mirror the readme into. The old
# sync-archived-readme.ps1 step was removed with the consolidation.

Step "Released v${Version}: https://github.com/dparksports/autocommand/releases/tag/v${Version}"
