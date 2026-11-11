$ErrorActionPreference = 'SilentlyContinue'
Set-Location 'C:\Users\honey\autocommand-project\autocommand1004'

$p = Get-Process AutoCommand
if ($p) {
    $p | ForEach-Object {
        'RUNNING: PID {0}  started {1}' -f $_.Id, $_.StartTime
        '  path          : {0}' -f $_.Path
        '  productVersion: {0}' -f $_.FileVersionInfo.ProductVersion
    }
} else {
    'AutoCommand is not running'
}

'--- on-disk exes ---'
foreach ($f in 'publish_out\AutoCommand.exe', 'bin\Release\net10.0-windows10.0.19041.0\AutoCommand.exe') {
    if (Test-Path $f) {
        '{0,-58} -> {1}' -f $f, (Get-Item $f).VersionInfo.ProductVersion
    } else {
        '{0,-58} -> (missing)' -f $f
    }
}
