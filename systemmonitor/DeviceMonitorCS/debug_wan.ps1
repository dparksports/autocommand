
Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.Name -like "*WAN Miniport*" } | Select-Object Name, DeviceID, NetConnectionStatus, PNPDeviceID | Format-Table -AutoSize

Write-Host "--- Win32_PnPEntity ---"
Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.Name -like "*WAN Miniport*" } | Select-Object Name, DeviceID, Status, Present | Format-Table -AutoSize
