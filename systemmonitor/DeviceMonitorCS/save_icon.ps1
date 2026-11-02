Add-Type -AssemblyName System.Drawing
$pngPath = "C:/Users/honey/.gemini/antigravity/brain/35aa13eb-df47-4c11-95ee-b269e628071d/app_icon_maximized_1767241780857.png"
$icoPath = "c:\Users\honey\mydevices\DeviceMonitorCS\app_icon.ico"

try {
    $bmp = [System.Drawing.Bitmap]::FromFile($pngPath)
    $icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    $stream = New-Object System.IO.FileStream($icoPath, 'Create')
    $icon.Save($stream)
    $stream.Close()
    $icon.Dispose()
    $bmp.Dispose()
    Write-Host "Success"
}
catch {
    Write-Host "Error: $_"
    exit 1
}
