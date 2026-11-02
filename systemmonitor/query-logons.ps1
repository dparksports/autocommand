# --- Date Range (change as needed) ---
# Last 90 days:
$start = (Get-Date).AddDays(-90)


# --- Collect events ---

# Boot events (Kernel-General 12 — reliable)
$boots = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 12
    StartTime = $start
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated

if (-not $boots) {
    Write-Host "No boot events found." -ForegroundColor Yellow
    return
}

# Shutdown events (4609, 6006)
$shutdowns = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = @(4609, 6006)
    StartTime = $start
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated

# Logon events (4624)
$logons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $start
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Properties[8].Value -in 2, 10 -and
    $_.Properties[5].Value -notmatch '^DWM-' -and
    $_.Properties[5].Value -notmatch '^UMFD-' -and
    $_.Properties[5].Value -ne 'SYSTEM'
} | Select-Object TimeCreated, @{
    Name = 'User'; Expression = { $_.Properties[5].Value }
}, @{
    Name = 'LogonID'; Expression = { $_.Properties[7].Value }
}, @{
    Name = 'LogonType'; Expression = { $_.Properties[8].Value }
}, @{
    Name = 'SourceIP'; Expression = { $_.Properties[18].Value }
}

# Deduplicate unlock events (same LogonID)
if ($logons) {
    $logons = $logons |
    Group-Object LogonID |
    ForEach-Object { $_.Group | Sort-Object TimeCreated | Select-Object -First 1 }
}

# Logoff events (4634)
$logoffs = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4634
    StartTime = $start
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated, @{
    Name = 'LogonID'; Expression = { $_.Properties[0].Value }
}


# --- Build boot-cycle table ---

$rows = foreach ($i in 0..($boots.Count - 1)) {

    $boot = $boots[$i]

    # Next boot (cycle boundary)
    $nextBoot = if ($i -lt $boots.Count - 1) { $boots[$i + 1].TimeCreated } else { $null }

    # Next shutdown after this boot
    $shutdown = $shutdowns |
    Where-Object { $_.TimeCreated -ge $boot.TimeCreated } |
    Select-Object -First 1

    # Determine cycle end (earliest of next boot or shutdown)
    if ($shutdown -and $nextBoot) {
        $cycleEnd = if ($shutdown.TimeCreated -lt $nextBoot) { $shutdown.TimeCreated } else { $nextBoot }
    }
    elseif ($shutdown) {
        $cycleEnd = $shutdown.TimeCreated
    }
    elseif ($nextBoot) {
        $cycleEnd = $nextBoot
    }
    else {
        $cycleEnd = $null
    }

    # All logons between boot and cycle end
    $sessionLogons = $logons |
    Where-Object {
        $_.TimeCreated -ge $boot.TimeCreated -and
        ($cycleEnd -eq $null -or $_.TimeCreated -le $cycleEnd)
    }

    # Build flattened session text
    $sessionText = foreach ($logon in $sessionLogons) {

        # Find matching logoff
        $logoff = $logoffs |
        Where-Object { $_.LogonID -eq $logon.LogonID } |
        Select-Object -First 1

        # Determine end time
        $end = if ($logoff) { $logoff.TimeCreated }
        elseif ($cycleEnd) { $cycleEnd }
        else { $null }

        # Format fields
        $logonTime = $logon.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $logoffTime = if ($logoff) { $logoff.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $endTime = if ($end) { $end.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $duration = if ($end) { ($end - $logon.TimeCreated).ToString() } else { "" }
        $sourceIP = if ($logon.LogonType -eq 10) { $logon.SourceIP } else { "" }

        # Flattened text line
        "$($logon.User) | $logonTime | $logoffTime | $endTime | $duration | Type $($logon.LogonType) | $sourceIP"
    }

    # Final row for this boot cycle
    [PSCustomObject]@{
        BootTime = $boot.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        CycleEnd = if ($cycleEnd) { $cycleEnd.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        Sessions = $sessionText -join "`n"
    }
}

$rows | Sort-Object BootTime
