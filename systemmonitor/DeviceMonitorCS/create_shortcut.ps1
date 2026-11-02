$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "DeviceMonitorCS.lnk"
$TargetDir = "C:\Users\honey\mydevices\DeviceMonitorCS\bin\Debug\net10.0-windows"
$Target = Join-Path $TargetDir "DeviceMonitorCS.exe"

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Target
$Shortcut.WorkingDirectory = $TargetDir
$Shortcut.Description = "Windows System Monitor"
$Shortcut.IconLocation = "C:\Users\honey\mydevices\DeviceMonitorCS\app_icon.ico"
$Shortcut.Save()
Write-Host "Shortcut created at $ShortcutPath with WorkingDirectory=$TargetDir"
