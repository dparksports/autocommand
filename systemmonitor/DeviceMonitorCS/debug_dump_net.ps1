
# GUID for Net Class
$guid = "{4d36e972-e325-11ce-bfc1-08002be10318}"
Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.ClassGuid -eq $guid } | Select-Object Name, DeviceID, Status, Present | Format-Table -AutoSize
