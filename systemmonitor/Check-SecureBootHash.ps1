<#
.SYNOPSIS
    Calculates the Authenticode (PE) Hash of the active UEFI bootloader
    using Sysinternals Sigcheck and cross-references it with the local DBX.
#>

# 1. Check for Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges to access the EFI partition."
    Write-Warning "Please right-click PowerShell and select 'Run as Administrator'."
    Break
}

# 2. Setup Sigcheck Tool
$SigcheckUrl = "https://live.sysinternals.com/sigcheck64.exe"
$SigcheckPath = "$PSScriptRoot\sigcheck64.exe"

if (-not (Test-Path $SigcheckPath)) {
    Write-Host "[-] Sigcheck64.exe not found. Downloading from Sysinternals..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $SigcheckUrl -OutFile $SigcheckPath
        Write-Host "[+] Download complete." -ForegroundColor Green
    }
    catch {
        Write-Error "Could not download sigcheck. Please verify internet connection."
        Break
    }
}

# 3. Mount EFI Partition to temporary drive Z:
Write-Host "[-] Mounting EFI System Partition to Z:..." -ForegroundColor Cyan
$EFIMounted = $false
try {
    # Check if Z is free, otherwise find a free letter (simplified for Z here)
    if (Test-Path "Z:") { Write-Warning "Drive Z: is already in use. Please unmap it first."; Break }
    
    $null = mountvol Z: /S
    $EFIMounted = $true
}
catch {
    Write-Error "Failed to mount EFI partition. Ensure you are running as Admin."
    Break
}

# 4. Locate Bootloader
$BootloaderPath = "Z:\EFI\Microsoft\Boot\bootmgfw.efi"
if (-not (Test-Path $BootloaderPath)) {
    Write-Warning "Standard Windows Bootloader not found at $BootloaderPath"
    Write-Host "Checking alternate path Z:\EFI\Boot\bootx64.efi..."
    $BootloaderPath = "Z:\EFI\Boot\bootx64.efi"
}

if (Test-Path $BootloaderPath) {
    Write-Host "[+] Found Bootloader: $BootloaderPath" -ForegroundColor Green
    
    # 5. Get Certificate Thumbprint (PowerShell Native)
    $Signature = Get-AuthenticodeSignature $BootloaderPath
    $CertThumbprint = $Signature.SignerCertificate.Thumbprint
    
    # 6. Get PE SHA256 Hash (Using Sigcheck)
    # We parse the output because Sigcheck formats it as text
    Write-Host "[-] Calculating Authenticode (PE) Hash..." -ForegroundColor Cyan
    $SigOutput = & $SigcheckPath -accepteula -h $BootloaderPath
    
    # Extract the line starting with "PE SHA256:"
    $PEHashLine = $SigOutput | Where-Object { $_ -match "PE SHA256:\s+([A-Fa-f0-9]+)" }
    $PEHash = $null
    if ($PEHashLine -match "PE SHA256:\s+([A-Fa-f0-9]+)") {
        $PEHash = $matches[1]
    }

    # 7. Output Results
    Write-Host "`n--------------------------------------------------" 
    Write-Host "   SECURE BOOT ARTIFACTS REPORT"
    Write-Host "--------------------------------------------------" 
    Write-Host "File Analyzed:      $BootloaderPath"
    Write-Host "Signer Status:      $($Signature.Status)"
    Write-Host "Cert Thumbprint:    $CertThumbprint"
    Write-Host "PE SHA256 Hash:     $PEHash"
    Write-Host "--------------------------------------------------" 

    # 8. Quick DBX Check (Heuristic)
    # Checks if this hash string appears in the raw DBX variable
    try {
        $DBX = Get-SecureBootUEFI -Name dbx
        # Convert DBX bytes to a continuous hex string
        $DBXHex = ($DBX.Bytes | ForEach-Object { $_.ToString("X2") }) -join ""
        
        Write-Host "`n[?] Checking against current System DBX..."
        
        if ($DBXHex -match $PEHash) {
            Write-Host "[CRITICAL] YOUR BOOTLOADER HASH IS ALREADY IN THE DBX!" -ForegroundColor Red
        }
        else {
            Write-Host "[OK] PE Hash not found in current local DBX." -ForegroundColor Green
        }
        
        if ($DBXHex -match $CertThumbprint) {
            Write-Host "[CRITICAL] YOUR CERTIFICATE IS REVOKED IN THE DBX!" -ForegroundColor Red
        }
        else {
            Write-Host "[OK] Certificate Thumbprint not found in current local DBX." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Could not read SecureBoot variables (Are you in UEFI mode?)."
    }

}
else {
    Write-Error "Could not locate bootloader file."
}

# 9. Cleanup
if ($EFIMounted) {
    Write-Host "`n[-] Unmounting EFI Partition..." -ForegroundColor Cyan
    mountvol Z: /D
}