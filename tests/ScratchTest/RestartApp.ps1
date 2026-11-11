$ErrorActionPreference = 'Continue'
$root = 'C:\Users\honey\autocommand-project\autocommand1004'
$exe  = Join-Path $root 'bin\Release\net10.0-windows10.0.19041.0\AutoCommand.exe'

Stop-Process -Name AutoCommand -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Start-Process -FilePath $exe -WorkingDirectory $root
Start-Sleep -Seconds 4

$p = Get-Process AutoCommand -ErrorAction SilentlyContinue
if ($p) {
    'RESTARTED OK: PID(s) ' + (($p.Id) -join ', ')
} else {
    'ERROR: AutoCommand did not start'
}
