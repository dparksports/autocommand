<#
.SYNOPSIS
    Safety Check: Mounts EFI, maintains a file integrity baseline, 
    calculates Authenticode Hash of bootloader, and checks against DBX.
#>

# ==========================================
#  CONFIG
# ==========================================
$DbxUpdatePath = "C:\Users\k2\Downloads\DBXUpdate.bin"
$BaselineDir = "$env:ProgramData\SystemMonitor"
$BaselineFile = "$BaselineDir\efi_baseline.json"
$SigcheckUrl = "https://live.sysinternals.com/sigcheck64.exe"
$SigcheckPath = "$PSScriptRoot\sigcheck64.exe"

# Handle unsaved script context
if ([string]::IsNullOrEmpty($PSScriptRoot)) { $SigcheckPath = "$env:TEMP\sigcheck64.exe" }

# Ensure Baseline Directory Exists
if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }

# ==========================================
#  HELPER FUNCTIONS
# ==========================================

function Write-Section {
    param([string]$Title)
    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "==========================================" -ForegroundColor Cyan
}

function Write-GridItem {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Color = "White"
    )
    # Format: Label (Fixed Width 16 chars) : Value
    Write-Host -NoNewline "$($Label.PadRight(16)) : " -ForegroundColor Cyan
    Write-Host $Value -ForegroundColor $Color
}

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    switch ($Type) {
        "Info" { Write-Host "[-] $Message" -ForegroundColor Gray }
        "Success" { Write-Host "[+] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "Error" { Write-Host "[x] $Message" -ForegroundColor Red }
    }
}

# ==========================================
#  1. PRE-FLIGHT CHECKS
# ==========================================

# Check Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Status "This script requires Administrator privileges." "Error"
    Break
}

# Setup Sigcheck
if (-not (Test-Path $SigcheckPath)) {
    Write-Status "Downloading Sigcheck64..."
    try {
        Invoke-WebRequest -Uri $SigcheckUrl -OutFile $SigcheckPath
    }
    catch {
        Write-Status "Failed to download Sigcheck." "Error"
        Break
    }
}

# Check DBX File
if (-not (Test-Path $DbxUpdatePath)) {
    Write-Status "DBXUpdate.bin not found at $DbxUpdatePath" "Warning"
    Write-Status "Skipping DBX comparison (Hash check only)." "Warning"
}

# ==========================================
#  2. MOUNT EFI
# ==========================================
Write-Section "EFI PARTITION ACCESS"
$EFIMounted = $false

try {
    if (Test-Path "Z:") {
        Write-Status "Z: drive in use. Unmounting..." "Warning"
        mountvol Z: /D
    }
    mountvol Z: /S
    if (Test-Path "Z:") {
        $EFIMounted = $true
        Write-Status "EFI Partition mounted to Z:" "Success"
    }
    else {
        throw "Mount failed"
    }
}
catch {
    Write-Status "Failed to mount EFI partition." "Error"
    Break
}

# ==========================================
#  3. EFI BASELINE & INSPECTION
# ==========================================
Write-Section "EFI INTEGRITY INSPECTION"
try {
    Write-Status "Scanning Z:\EFI for changes..."
    
    # Get current state
    $CurrentFiles = @{}
    $AllFiles = Get-ChildItem -Path "Z:\EFI" -Recurse -File
    
    foreach ($file in $AllFiles) {
        $Hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $RelPath = $file.FullName.Substring(3) # Remove Z:\
        $CurrentFiles[$RelPath] = $Hash
    }

    if (Test-Path $BaselineFile) {
        # Compare
        $Baseline = Get-Content $BaselineFile | ConvertFrom-Json -AsHashtable
        $ChangesFound = $false

        # Check New & Modified
        foreach ($path in $CurrentFiles.Keys) {
            if (-not $Baseline.ContainsKey($path)) {
                Write-GridItem "NEW FILE" $path "Yellow"
                $ChangesFound = $true
            }
            elseif ($Baseline[$path] -ne $CurrentFiles[$path]) {
                Write-GridItem "MODIFIED" "$path (Hash Changed)" "Red"
                $ChangesFound = $true
            }
        }

        # Check Deleted
        foreach ($path in $Baseline.Keys) {
            if (-not $CurrentFiles.ContainsKey($path)) {
                Write-GridItem "DELETED" $path "Gray"
                $ChangesFound = $true
            }
        }

        if (-not $ChangesFound) {
            Write-Status "EFI Partition matches baseline. No changes detected." "Success"
        }
        else {
            Write-Status "Updates detected. Updating baseline..." "Warning"
            $CurrentFiles | ConvertTo-Json | Set-Content $BaselineFile
        }

    }
    else {
        Write-Status "No baseline found. Creating new baseline..." "Warning"
        $CurrentFiles | ConvertTo-Json | Set-Content $BaselineFile
        Write-Status "Baseline saved to $BaselineFile" "Success"
    }

}
catch {
    Write-Status "Error during EFI inspection: $_" "Error"
}

# ==========================================
#  4. BOOTLOADER ANALYSIS
# ==========================================
Write-Section "BOOTLOADER ANALYSIS"
$Bootloader = "Z:\EFI\Microsoft\Boot\bootmgfw.efi"

if (Test-Path $Bootloader) {
    # Run Sigcheck
    $RawOutput = & $SigcheckPath -accepteula -a -h $Bootloader
    
    # Parse Output
    $Info = @{}
    foreach ($line in $RawOutput) {
        if ($line -match "^\s+([^:]+):\s+(.*)$") {
            $Key = $matches[1].Trim()
            $Val = $matches[2].Trim()
            $Info[$Key] = $Val
        }
    }

    # Display Grid
    Write-GridItem "File Path" "bootmgfw.efi"
    Write-GridItem "Publisher" ($Info["Publisher"] -replace "«", " ")
    Write-GridItem "Description" $Info["Description"]
    Write-GridItem "Product" ($Info["Product"] -replace "«", " ")
    Write-GridItem "Version" $Info["Prod version"]
    Write-GridItem "File Date" $Info["Signing date"]
    Write-Host ""
    Write-GridItem "Verified" $Info["Verified"] $(if ($Info["Verified"] -eq "Signed") { "Green" } else { "Red" })
    Write-GridItem "MachineType" $Info["MachineType"]
    Write-Host ""
    Write-GridItem "MD5" $Info["MD5"]
    Write-GridItem "SHA1" $Info["SHA1"]
    Write-GridItem "SHA256" $Info["SHA256"]
    Write-GridItem "PESHA1" $Info["PESHA1"]
    Write-GridItem "PE256" $Info["PE256"]

    # ==========================================
    #  5. DBX CHECK
    # ==========================================
    if (Test-Path $DbxUpdatePath) {
        Write-Section "DBX REVOCATION CHECK"
        
        $Bytes = [System.IO.File]::ReadAllBytes($DbxUpdatePath)
        $DbxHex = [System.BitConverter]::ToString($Bytes).Replace("-", "")
        
        # Check PE256 (Authenticode Hash) - Most likely DBX target
        $IsRevoked = $false
        
        if ($Info["PE256"] -and $DbxHex.Contains($Info["PE256"])) {
            Write-GridItem "STATUS" "DANGER: PE HASH FOUND IN DBX" "Red"
            $IsRevoked = $true
        }
        # Check SHA256 (File Hash)
        elseif ($Info["SHA256"] -and $DbxHex.Contains($Info["SHA256"])) {
            Write-GridItem "STATUS" "DANGER: FILE HASH FOUND IN DBX" "Red"
            $IsRevoked = $true
        } 
        else {
            Write-GridItem "STATUS" "SAFE: No Deny Signature Found" "Green"
        }

        if ($IsRevoked) {
            Write-Host "`nWarning: Applying this update WILL BRICK YOUR BOOTLOADER." -ForegroundColor Red
        }
        else {
            Write-Host "`nThis update appears safe to apply." -ForegroundColor Green
        }
    }

}
else {
    Write-Status "Bootloader not found at standard path." "Error"
}

# ==========================================
#  6. CLEANUP
# ==========================================
if ($EFIMounted) {
    Write-Host "`n"
    Write-Status "Unmounting EFI..."
    mountvol Z: /D
}
