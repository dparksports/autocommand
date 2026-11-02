# ============================
# CONFIG
# ============================
$start = (Get-Date).AddDays(-90)
$MaxSecondsDiff = 300 # Tolerance for matching 4608 to Boot

# ============================
# 1. COLLECT DATA (PATCHED)
# ============================
Write-Host "1. Querying Event Logs..."

# A. System Events (Standard Time Filter works here)
$sysEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'; Id = @(12, 6006, 1074); StartTime = $start
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName

# B. Security Events (PATCH: Use MaxEvents instead of StartTime)
#    We fetch the last 500 boot events. This bypasses the StartTime bug while keeping performance high.
try {
    $secBootEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4608
    } -MaxEvents 500 -ErrorAction Stop | Select-Object TimeCreated, Id, ProviderName
}
catch {
    Write-Warning "Failed to read Security Log 4608. Ensure you are running as ADMIN."
    $secBootEvents = @()
}

# C. Security Shutdowns (4609) - Also using MaxEvents for safety
$secShutdownEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4609
} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProviderName

# ============================
# 2. PREPARE SEARCH ARRAYS
# ============================

# Filter Master Boots (Kernel-General 12)
$boots = @($sysEvents | Where-Object { $_.ProviderName -match 'Kernel-General' -and $_.Id -eq 12 } | Sort-Object TimeCreated)

# Searchable List of 4608s (Sorted for Binary Search)
$all4608s = @($secBootEvents | Sort-Object TimeCreated)

# Searchable List of Shutdowns (Combined)
$allShutdowns = @(($sysEvents + $secShutdownEvents) | Where-Object { $_.Id -ne 12 } | Sort-Object TimeCreated)

Write-Host "   Stats: $($boots.Count) Boots | $($all4608s.Count) 4608 Events | $($allShutdowns.Count) Shutdowns"

# ============================
# 3. BINARY SEARCH FUNCTION
# ============================
function Find-NearestEvent {
    param (
        [datetime]$TargetTime,
        [array]$SortedEvents
    )

    if (-not $SortedEvents -or $SortedEvents.Count -eq 0) { return $null }

    $left = 0
    $right = $SortedEvents.Count - 1

    # Binary Search
    while ($left -le $right) {
        $mid = [math]::Floor(($left + $right) / 2)
        $midTime = $SortedEvents[$mid].TimeCreated

        if ($midTime -eq $TargetTime) { return $SortedEvents[$mid] }
        elseif ($midTime -lt $TargetTime) { $left = $mid + 1 }
        else { $right = $mid - 1 }
    }

    # $left is the insertion point. Check neighbors ($left) and ($left - 1)
    $c1 = if ($left -lt $SortedEvents.Count) { $SortedEvents[$left] } else { $null }
    $c2 = if (($left - 1) -ge 0) { $SortedEvents[$left - 1] } else { $null }

    $diff1 = if ($c1) { [math]::Abs(($c1.TimeCreated - $TargetTime).TotalSeconds) } else { [double]::MaxValue }
    $diff2 = if ($c2) { [math]::Abs(($c2.TimeCreated - $TargetTime).TotalSeconds) } else { [double]::MaxValue }

    # Return the closest neighbor
    return if ($diff1 -lt $diff2) { $c1 } else { $c2 }
}

# ============================
# 4. PROCESS SESSIONS
# ============================
$results = @()

for ($i = 0; $i -lt $boots.Count; $i++) {
    $boot = $boots[$i]
    $bootTime = $boot.TimeCreated

    # --- MATCH 4608 (BINARY SEARCH) ---
    $nearest4608 = Find-NearestEvent -TargetTime $bootTime -SortedEvents $all4608s
    
    # Validation: Is it close enough? (within 5 mins)
    $valid4608 = $null
    if ($nearest4608) {
        $secondsDiff = ($nearest4608.TimeCreated - $bootTime).TotalSeconds
        if ([math]::Abs($secondsDiff) -le $MaxSecondsDiff) {
            $valid4608 = $nearest4608
        }
    }

    # --- FIND END OF SESSION ---
    $nextBootTime = if ($i -lt ($boots.Count - 1)) { $boots[$i + 1].TimeCreated } else { Get-Date }
    
    $shutdown = $allShutdowns | Where-Object { 
        $_.TimeCreated -gt $bootTime -and $_.TimeCreated -lt $nextBootTime 
    } | Select-Object -Last 1

    if ($i -lt ($boots.Count - 1)) {
        if ($shutdown) {
            $endTime = $shutdown.TimeCreated
            $status = "Clean"
        }
        else {
            $endTime = $nextBootTime
            $status = "Dirty/Crash"
        }
    }
    else {
        if ($shutdown) {
            $endTime = $shutdown.TimeCreated
            $status = "Clean (Ended)"
        }
        else {
            $endTime = Get-Date
            $status = "Running"
        }
    }

    # --- FORMAT ---
    $uptime = New-TimeSpan -Start $bootTime -End $endTime
    $fmtUptime = "{0:dd}d {0:hh}h {0:mm}m" -f $uptime

    $missing = @()
    if (-not $valid4608) { $missing += "Sec(4608)" }

    $results += [PSCustomObject]@{
        BootTime      = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
        ShutdownTime  = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
        Status        = $status
        Uptime        = $fmtUptime
        KG12          = $bootTime.ToString("HH:mm:ss")
        Sec4608       = if ($valid4608) { 
            # Display time and diff (e.g., +9s)
            "{0} ({1:N0}s)" -f $valid4608.TimeCreated.ToString("HH:mm:ss"), ($valid4608.TimeCreated - $bootTime).TotalSeconds 
        }
        else { "---" }
        MissingEvents = $missing -join ", "
    }
}

$results | Sort-Object BootTime | Format-Table -AutoSize