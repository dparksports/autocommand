# prune-releases.ps1 - keep only the newest release per day on the GitHub Releases page.
#
# AutoCommand versions are calendar-based (v2026.11.10.6 = date . build), and a
# busy day can ship several builds. The Releases page then reads like a build
# log, so this script keeps exactly one release per calendar day - the highest
# 4th-segment build (a tag with no 4th segment counts as build 0) - and deletes
# the rest. Day grouping uses the tag's date prefix, NOT the publish timestamp:
# published_at is UTC, so an evening local release can land on the "wrong" UTC
# day, and the tag prefix is the day the version actually names.
#
# The keeper of the newest day is always the newest release overall, so
# GitHub's "Latest" badge lands on it by construction. Tags that don't match
# the calendar pattern (legacy v3.x semver tags folded in from SystemMonitor)
# are reported and never touched. Drafts are never touched. --cleanup-tag
# removes the git tag too, so the Tags tab doesn't fill with orphans pointing
# at deleted releases.
#
# NOTE: keep this file pure ASCII, same reason as release.ps1.
#
# Usage:
#   powershell -File prune-releases.ps1            # dry run: prints keep/delete
#   powershell -File prune-releases.ps1 -Apply     # actually delete
#   powershell -File prune-releases.ps1 -Repo owner/name
#
# Requires `gh` authenticated. Idempotent - safe to run any time. release.yml
# runs it with -Apply as the last step of every publish, so same-day
# predecessors never accumulate in the first place.

[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$Repo
)

$ErrorActionPreference = 'Stop'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg)  { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

if (-not $Repo) {
    if ($env:GITHUB_REPOSITORY) { $Repo = $env:GITHUB_REPOSITORY }
    else {
        $url = git remote get-url origin 2>$null
        if ($url -match '[:/]([^/]+/[^/]+?)(?:\.git)?$') { $Repo = $Matches[1] }
        else { Die "cannot derive repo from '$url'; pass -Repo owner/name" }
    }
}

Step "listing releases for $Repo"
# jq filters drafts out here (never touched, never deleted); plain tag names
# avoid quoting pain between PowerShell and gh on Windows PowerShell 5.1.
$rows = gh api "repos/$Repo/releases?per_page=100" --paginate --jq '.[] | select(.draft | not) | .tag_name'
if ($LASTEXITCODE -ne 0) { Die 'gh api releases failed (is gh authenticated?)' }

# --- parse calendar tags: vYYYY.MM.DD[.build] --------------------------------
# releases: every non-draft tag; keep: highest-build release per day prefix.
$releases = New-Object System.Collections.Generic.List[hashtable]
$keep = @{}
foreach ($tag in $rows) {
    if ($tag -match '^v(\d{4}\.\d{1,2}\.\d{1,2})(?:\.(\d+))?$') {
        $r = @{ tag = $tag; day = $Matches[1]; build = if ($Matches[2]) { [int]$Matches[2] } else { 0 } }
        $releases.Add($r)
        $prev = $keep[$r.day]
        if (-not $prev -or $r.build -gt $prev.build) { $keep[$r.day] = $r }
    }
    else {
        Write-Host "skip non-calendar $tag (never deleted by this script)"
    }
}

# --- report / delete ----------------------------------------------------------
$deleted = 0
foreach ($r in $releases) {
    if ($keep[$r.day].tag -eq $r.tag) {
        Write-Host "keep              $($r.tag)" -ForegroundColor Green
    }
    elseif ($Apply) {
        Write-Host "delete            $($r.tag)" -ForegroundColor Yellow
        gh release delete $r.tag -R $Repo --yes --cleanup-tag
        if ($LASTEXITCODE -ne 0) { Die "gh release delete $($r.tag) failed" }
        $deleted++
    }
    else {
        Write-Host "delete            $($r.tag)   (dry run - pass -Apply)" -ForegroundColor Yellow
    }
}

if ($Apply) { Step "deleted $deleted release(s); $($keep.Count) day(s) remain" }
else { Step "dry run complete - nothing changed (pass -Apply to delete)" }
