# ------------------------------------------------------------
# Decode ACPI MCFG Table (PCI Express Memory Mapped Config Space)
# ------------------------------------------------------------

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Firmware {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetSystemFirmwareTable(uint provider, uint id, IntPtr buffer, uint size);
}
"@

function Read-UInt32LE($bytes, $offset) {
    return [BitConverter]::ToUInt32($bytes, $offset)
}

function Read-UInt64LE($bytes, $offset) {
    return [BitConverter]::ToUInt64($bytes, $offset)
}

function Read-UInt16LE($bytes, $offset) {
    return [BitConverter]::ToUInt16($bytes, $offset)
}

# ACPI provider = 'ACPI' = 0x41435049
$provider = 0x41435049

# Table ID 'MCFG'
$id = [BitConverter]::ToUInt32([Text.Encoding]::ASCII.GetBytes("MCFG"), 0)

# First call: get required size
$size = [Firmware]::GetSystemFirmwareTable($provider, $id, [IntPtr]::Zero, 0)

if ($size -eq 0) {
    Write-Host "MCFG table not found."
    exit
}

$buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

# Retrieve table
[void][Firmware]::GetSystemFirmwareTable($provider, $id, $buffer, $size)

# Copy bytes
$bytes = New-Object byte[] $size
[System.Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $size)

[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

Write-Host "`n=== ACPI MCFG Table Found ===" -ForegroundColor Cyan
Write-Host "Total Size: $size bytes"

# ------------------------------------------------------------
# Decode ACPI Header (36 bytes)
# ------------------------------------------------------------

$signature = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
$length = Read-UInt32LE $bytes 4
$revision = $bytes[8]
$checksum = $bytes[9]
$oemid = [System.Text.Encoding]::ASCII.GetString($bytes, 10, 6)
$oemtable = [System.Text.Encoding]::ASCII.GetString($bytes, 16, 8)
$oemrev = Read-UInt32LE $bytes 24
$creatorid = [System.Text.Encoding]::ASCII.GetString($bytes, 28, 4)
$creatorrev = Read-UInt32LE $bytes 32

Write-Host "`n--- ACPI Header ---"
Write-Host "Signature:        $signature"
Write-Host "Length:           $length"
Write-Host "Revision:         $revision"
Write-Host "Checksum:         $checksum"
Write-Host "OEM ID:           $oemid"
Write-Host "OEM Table ID:     $oemtable"
Write-Host "OEM Revision:     $oemrev"
Write-Host "Creator ID:       $creatorid"
Write-Host "Creator Revision: $creatorrev"

# ------------------------------------------------------------
# Decode MCFG Allocation Structures
# ------------------------------------------------------------

$entryOffset = 44   # MCFG header is 44 bytes total
$entrySize = 16

Write-Host "`n--- PCIe Configuration Space Entries ---"

while ($entryOffset + $entrySize -le $size) {

    $base = Read-UInt64LE $bytes $entryOffset
    $segment = Read-UInt16LE $bytes ($entryOffset + 8)
    $startBus = $bytes[$entryOffset + 10]
    $endBus = $bytes[$entryOffset + 11]

    Write-Host "`nEntry at offset $entryOffset:"
    Write-Host "  Base Address:   0x$("{0:X16}" -f $base)"
    Write-Host "  Segment Group:  $segment"
    Write-Host "  Start Bus:      $startBus"
    Write-Host "  End Bus:        $endBus"

    $entryOffset += $entrySize
}

Write-Host "`n=== Done ==="
