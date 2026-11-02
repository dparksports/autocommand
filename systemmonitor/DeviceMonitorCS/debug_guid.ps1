
$adp = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.Name -like "*WAN Miniport (IKEv2)*" }
if ($adp) {
    Write-Host "Found Adapter in Win32_NetworkAdapter:"
    $adp | Select-Object Name, DeviceID, PNPDeviceID | Format-List

    if ($adp.PNPDeviceID) {
        Write-Host "Checking PnP Device..."
        $dev = Get-PnpDevice -InstanceId $adp.PNPDeviceID
        $dev | Select-Object FriendlyName, Class, ClassGuid, InstanceId, Status | Format-List
    }
    else {
        Write-Host "No PNPDeviceID found on adapter."
        # Try generic search
        Get-PnpDevice -FriendlyName "*WAN Miniport (IKEv2)*" | Select-Object FriendlyName, Class, ClassGuid, InstanceId | Format-List
    }
}
else {
    Write-Host "WAN Miniport (IKEv2) not found in Win32_NetworkAdapter. Searching PnP directly..."
    Get-PnpDevice -FriendlyName "*WAN Miniport (IKEv2)*" | Select-Object FriendlyName, Class, ClassGuid, InstanceId | Format-List
}
