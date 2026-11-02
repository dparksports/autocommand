Add-Type -AssemblyName System.Drawing

$sourcePng = Join-Path $PSScriptRoot "temp_icon.png"
$targetIco = Join-Path $PSScriptRoot "app_icon.ico"

function Convert-PngToIco {
    param ($pngPath, $icoPath)

    $bmp = [System.Drawing.Bitmap]::FromFile($pngPath)
    
    # Resize to 256x256 for better compatibility
    $resized = new-object System.Drawing.Bitmap(256, 256)
    $g = [System.Drawing.Graphics]::FromImage($resized)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($bmp, 0, 0, 256, 256)
    $g.Dispose()

    # Create Icon from handle
    $hIcon = $resized.GetHicon()
    $icon = [System.Drawing.Icon]::FromHandle($hIcon)
    
    $fs = New-Object System.IO.FileStream($icoPath, 'Create')
    $icon.Save($fs)
    $fs.Close()
    
    $icon.Dispose()
    # DestroyIcon is needed for HIcon but it's unmanaged w/e, PS process will exit
    $resized.Dispose()
    $bmp.Dispose()
    
    Write-Host "Created 256x256 icon at $icoPath"
}

try {
    Convert-PngToIco -pngPath $sourcePng -icoPath $targetIco
}
catch {
    Write-Host "Error: $_"
    exit 1
}
