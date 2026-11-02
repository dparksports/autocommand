Add-Type -AssemblyName System.Security

function Parse-EfiSignatureList {
    param ( [string]$VarName )

    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host " PARSING DATABASE: $VarName" -ForegroundColor Cyan
    Write-Host "=========================================="

    try {
        $blob = Get-SecureBootUEFI -Name $VarName -ErrorAction Stop
    } catch {
        Write-Warning "Could not read $VarName (might be empty or access denied)."
        return
    }

    if (!$blob) { Write-Host "  [Empty]" -ForegroundColor DarkGray; return }

    $bytes = $blob.Bytes
    $offset = 0

    # Loop through the EFI_SIGNATURE_LIST structures
    while ($offset -lt $bytes.Length) {
        # --- READ LIST HEADER (28 Bytes min) ---
        if ($offset + 28 -gt $bytes.Length) { break }

        # 1. Signature Type GUID (16 bytes)
        $typeGuidBytes = $bytes[$offset..($offset+15)]
        $typeGuid = [Guid]::new($typeGuidBytes)

        # 2. List Size (4 bytes)
        $listSize = [BitConverter]::ToInt32($bytes, $offset+16)
        
        # 3. Header Size (4 bytes) - usually 0
        $headerSize = [BitConverter]::ToInt32($bytes, $offset+20)
        
        # 4. Size of Each Entry (4 bytes)
        $entrySize = [BitConverter]::ToInt32($bytes, $offset+24)

        # Identify Type
        $typeName = switch ($typeGuid.ToString()) {
            "a5c059a1-94e4-4aa7-87b5-ab155c2bf072" { "X.509 Certificate" }
            "c1c41626-504c-4b56-1e95-7985013b35bd" { "SHA-256 Hash" }
            default { "Unknown Type ($typeGuid)" }
        }

        Write-Host "`n>>> LIST TYPE: $typeName" -ForegroundColor Yellow
        Write-Host "    List Size: $listSize bytes | Entry Size: $entrySize bytes" -ForegroundColor DarkGray

        # --- READ ENTRIES ---
        # Data starts after the header (28 bytes) + any extra header size
        $dataStart = $offset + 28 + $headerSize
        $listEnd   = $offset + $listSize

        $currentEntryOffset = $dataStart

        while ($currentEntryOffset + $entrySize -le $listEnd) {
            
            # EFI_SIGNATURE_DATA structure:
            # 1. Signature Owner GUID (16 bytes)
            $ownerBytes = $bytes[$currentEntryOffset..($currentEntryOffset+15)]
            $ownerGuid  = [Guid]::new($ownerBytes)
            
            # 2. Signature Data (The rest)
            $sigDataStart = $currentEntryOffset + 16
            $sigDataEnd   = $currentEntryOffset + $entrySize - 1
            $sigBytes     = $bytes[$sigDataStart..$sigDataEnd]

            Write-Host "    --------------------------------------------------" -ForegroundColor DarkGray
            Write-Host "    [Entry Owner]: $ownerGuid" -ForegroundColor White
            
            if ($typeName -eq "X.509 Certificate") {
                try {
                    # Load into .NET X509 Parser
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$sigBytes)
                    
                    Write-Host "    Subject:    " -NoNewline; Write-Host $cert.Subject -ForegroundColor Green
                    Write-Host "    Issuer:     " $cert.Issuer
                    Write-Host "    Serial #:   " $cert.SerialNumber
                    Write-Host "    Valid From: " $cert.NotBefore
                    Write-Host "    Valid To:   " $cert.NotAfter
                    Write-Host "    Thumbprint: " $cert.Thumbprint
                } catch {
                    Write-Host "    [!] Error parsing Certificate data." -ForegroundColor Red
                }
            } 
            elseif ($typeName -eq "SHA-256 Hash") {
                # Just convert bytes to Hex string
                $hashStr = ($sigBytes | ForEach-Object { $_.ToString("X2") }) -join ""
                Write-Host "    Hash:       " -NoNewline; Write-Host $hashStr -ForegroundColor Red
            } 
            else {
                Write-Host "    [Raw Data]: " ($sigBytes.Length) "bytes"
            }

            $currentEntryOffset += $entrySize
        }

        # Jump to next list
        $offset += $listSize
    }
}

# --- RUN THE PARSER ---
Parse-EfiSignatureList "db"   # Allowed
Parse-EfiSignatureList "dbx"  # Blocked
Parse-EfiSignatureList "KEK"  # Key Exchange Keys