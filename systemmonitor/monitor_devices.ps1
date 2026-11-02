# monitor_devices.ps1
# This script monitors device events using System.Management classes
# to provide structured event handling with initiator and type details.

Write-Host "Starting Device Monitor..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Cyan

# Helper to get the current initiator (logged-on user)
function Get-Initiator {
    try {
        $sys = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($sys.UserName) { return $sys.UserName }
        return "$env:USERDOMAIN\$env:USERNAME"
    }
    catch { return "Unknown" }
}

# Define a shared action for events
$action = {
    param($evtSender, $e)
    
    $evtArgs = $e.NewEvent # __InstanceCreationEvent, etc.
    $device = $evtArgs.TargetInstance # Win32_PnPEntity
    $className = $evtArgs.SystemProperties["__Class"].Value
    
    $eventType = "EVENT"
    $color = "Gray"
    
    switch ($className) {
        "__InstanceCreationEvent" { $eventType = "ADDED"; $color = "Green" }
        "__InstanceDeletionEvent" { $eventType = "REMOVED"; $color = "Red" }
        "__InstanceModificationEvent" { $eventType = "CHANGED"; $color = "Yellow" }
    }

    # Determine Type
    $type = "Unknown"
    if ($device.PNPClass) { $type = $device.PNPClass }
    elseif ($device.Service) { $type = "Service: $($device.Service)" }
    else { $type = "Device" }

    $initiator = Get-Initiator
    $timestamp = [DateTime]::Now.ToString("HH:mm:ss")
    $name = $device.Name
    if (-not $name) { $name = $device.Description }

    Write-Host "`n[$timestamp] $eventType" -ForegroundColor $color
    Write-Host "  Name:      $name" -ForegroundColor White
    Write-Host "  Id:        $($device.DeviceID)" -ForegroundColor Gray
    Write-Host "  Type:      $type" -ForegroundColor Gray
    Write-Host "  Initiator: $initiator" -ForegroundColor Yellow
}

# Create Watchers for Created, Deleted, and Modified events
# we use explicit WqlEventQuery objects to avoid raw query strings in the main flow

# 1. Added
$qAdd = New-Object System.Management.WqlEventQuery
$qAdd.EventClassName = "__InstanceCreationEvent"
$qAdd.WithinInterval = [TimeSpan]::FromSeconds(1)
$qAdd.Condition = "TargetInstance ISA 'Win32_PnPEntity'"
$wAdd = New-Object System.Management.ManagementEventWatcher $qAdd

# 2. Removed
$qRem = New-Object System.Management.WqlEventQuery
$qRem.EventClassName = "__InstanceDeletionEvent"
$qRem.WithinInterval = [TimeSpan]::FromSeconds(1)
$qRem.Condition = "TargetInstance ISA 'Win32_PnPEntity'"
$wRem = New-Object System.Management.ManagementEventWatcher $qRem

# 3. Changed
$qMod = New-Object System.Management.WqlEventQuery
$qMod.EventClassName = "__InstanceModificationEvent"
$qMod.WithinInterval = [TimeSpan]::FromSeconds(1)
$qMod.Condition = "TargetInstance ISA 'Win32_PnPEntity'"
$wMod = New-Object System.Management.ManagementEventWatcher $qMod

# Register the action using PowerShell's Register-ObjectEvent on the .NET watcher objects
Register-ObjectEvent -InputObject $wAdd -EventName "EventArrived" -SourceIdentifier "DeviceAdded" -Action $action | Out-Null
Register-ObjectEvent -InputObject $wRem -EventName "EventArrived" -SourceIdentifier "DeviceRemoved" -Action $action | Out-Null
Register-ObjectEvent -InputObject $wMod -EventName "EventArrived" -SourceIdentifier "DeviceChanged" -Action $action | Out-Null

# Start listening
$wAdd.Start()
$wRem.Start()
$wMod.Start()

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    # Stop and Dispose
    $wAdd.Stop(); $wAdd.Dispose()
    $wRem.Stop(); $wRem.Dispose()
    $wMod.Stop(); $wMod.Dispose()
    
    Unregister-Event -SourceIdentifier "DeviceAdded" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "DeviceRemoved" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "DeviceChanged" -ErrorAction SilentlyContinue
    
    Write-Host "Monitor stopped." -ForegroundColor Cyan
}
