
# List all devices with "SSTP" in the name
Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.Name -like "*SSTP*" } | Select-Object Name, DeviceID, Status, Present, ConfigManagerErrorCode | Format-Table -AutoSize

# List all from Win32_NetworkAdapter that have SSTP
Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.Name -like "*SSTP*" } | Select-Object Name, DeviceID, NetConnectionStatus | Format-Table -AutoSize
