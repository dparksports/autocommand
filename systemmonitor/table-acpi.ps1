Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class FW {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint EnumSystemFirmwareTables(uint provider, IntPtr buffer, uint size);
}
"@

# ACPI provider
$provider = 0x41435049

# First call: get size
$size = [FW]::EnumSystemFirmwareTables($provider, [IntPtr]::Zero, 0)

$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)

# Second call: retrieve table IDs
[FW]::EnumSystemFirmwareTables($provider, $buf, $size)

$bytes = New-Object byte[] $size
[System.Runtime.InteropServices.Marshal]::Copy($buf, $bytes, 0, $size)

[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)

# Convert 4‑byte table IDs into strings
for ($i = 0; $i -lt $bytes.Length; $i += 4) {
    [System.Text.Encoding]::ASCII.GetString($bytes, $i, 4)
}
