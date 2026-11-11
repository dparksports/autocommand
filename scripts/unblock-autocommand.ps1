# unblock-autocommand.ps1 - remove the 'Mark-of-the-Web' from AutoCommand's
# files so Windows stops blocking the unsigned app.
#
# WHY: every file extracted from a downloaded zip carries a hidden
# Zone.Identifier marker. On machines with SmartScreen or Smart App Control
# (Windows 11 clean installs), that marker produces errors like
#   "An Application Control policy has blocked this file - dangerous file
#    from the web"
# and can break taskbar pins. Removing the marker is exactly what the
# built-in Unblock-File cmdlet does; file contents are never touched.
#
# HOW TO RUN (no Administrator needed for folders under your profile):
#   Right-click this script -> "Run with PowerShell".
#   By default it unblocks the folder the script sits in; to unblock a
#   different folder (e.g. a freshly extracted AutoCommand zip):
#     powershell -ExecutionPolicy Bypass -File .\unblock-autocommand.ps1 -Path "C:\Users\you\Downloads\AutoCommand-vX.Y.Z-win-x64"
#
# Place this script NEXT TO AutoCommand.exe (or pass -Path), run it once,
# then launch/pin AutoCommand normally.
#
# NOTE: keep this file pure ASCII. Windows PowerShell 5.1 reads BOM-less
# scripts as ANSI and non-ASCII characters corrupt execution.

param(
    [string]$Path = $PSScriptRoot,
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    Write-Host "Folder not found: $Path" -ForegroundColor Red
    exit 1
}

Write-Host "Removing the Mark-of-the-Web from files under:" -ForegroundColor Cyan
Write-Host "  $Path" -ForegroundColor Cyan
Write-Host ""

$scanned = 0
$unblocked = 0
$failed = 0

# Get-ChildItem -Force includes hidden files; the Zone.Identifier check keeps
# the count honest (Unblock-File on an unmarked file is a silent no-op).
Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $scanned++
    $marked = $null -ne (Get-Item -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue)
    if (-not $marked) { return }

    try {
        Unblock-File -LiteralPath $_.FullName -ErrorAction Stop
        $script:unblocked++
        Write-Host "  unblocked: $($_.FullName)" -ForegroundColor Green
    } catch {
        $script:failed++
        Write-Host "  FAILED:   $($_.FullName) - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host ("Done. {0} file(s) unblocked, {1} scanned, {2} failed." -f $unblocked, $scanned, $failed) -ForegroundColor Cyan

if ($failed -gt 0) {
    Write-Host "Some files are in use or in admin-only locations." -ForegroundColor Yellow
    Write-Host "Close the apps using them (or re-run this script as Administrator) and try again." -ForegroundColor Yellow
}

if ($unblocked -gt 0) {
    Write-Host ""
    Write-Host "AutoCommand will now launch normally - pins and shortcuts included." -ForegroundColor Green
}

if (-not $NoPause -and $Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive) {
    Write-Host ""
    Read-Host "Press Enter to close"
}
