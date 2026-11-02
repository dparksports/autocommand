# ------------------------------------------------------------
# SAFE READ-ONLY FIRMWARE + BOOT INFO ENUMERATION
# Compatible with PowerShell 7 (fixes encoding 437 error)
# ------------------------------------------------------------

# Fix legacy encoding issue for bcdedit output
[System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)

Write-Host "`n=== UEFI Firmware Tables ===" -ForegroundColor Cyan

try {
    $tables = Get-WmiObject -Namespace "root\wmi" -Class "MS_SystemFirmwareTable"
    foreach ($t in $tables) {
        Write-Host "----------------------------------------"
        Write-Host "Table Name: $($t.Name)"
        Write-Host "Table ID:   $($t.TableID)"
        Write-Host "Length:     $($t.TableLength)"
    }
}
catch {
    Write-Host "Unable to read firmware tables. System may not support UEFI or access is restricted."
}

Write-Host "`n=== Secure Boot Status ===" -ForegroundColor Cyan

try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "Secure Boot Enabled: $sb"
}
catch {
    Write-Host "Secure Boot status unavailable (Legacy BIOS or restricted)."
}

Write-Host "`n=== Boot Configuration Data (BCD) ===" -ForegroundColor Cyan

# Use cmd.exe to avoid PowerShell encoding issues
cmd /c "bcdedit /enum all"

Write-Host "`n=== System Firmware Info ===" -ForegroundColor Cyan

Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate
