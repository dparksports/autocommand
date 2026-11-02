Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Firmware {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetSystemFirmwareTable(uint provider, uint id, IntPtr buffer, uint size);
}
"@

# ACPI provider = 'ACPI' = 0x41435049
$provider = 0x41435049

# Table ID 'MCFG' as uint
$id = [BitConverter]::ToUInt32([Text.Encoding]::ASCII.GetBytes("MCFG"), 0)

# First call: get required size
$size = [Firmware]::GetSystemFirmwareTable($provider, $id, [IntPtr]::Zero, 0)

$buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

# Second call: retrieve table
[void][Firmware]::GetSystemFirmwareTable($provider, $id, $buffer, $size)

# Copy bytes
$bytes = New-Object byte[] $size
[System.Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $size)

[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

# Output raw bytes
$bytes
