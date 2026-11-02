Add-Type -AssemblyName System.Drawing
$iconPath = "c:\Users\honey\mydevices\DeviceMonitorCS\app_icon.ico"
$pngPath = "c:\Users\honey\mydevices\DeviceMonitorCS\temp_icon.png"

try {
    $bitmap = New-Object System.Drawing.Bitmap($iconPath)
    $bitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    Write-Host "Conversion successful"
}
catch {
    Write-Host "Error: $_"
    exit 1
}
