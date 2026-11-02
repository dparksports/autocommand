$boots = @()

$boots += Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4608 } -ErrorAction SilentlyContinue
$boots += Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6005 } -ErrorAction SilentlyContinue
$boots += Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 12 } -ErrorAction SilentlyContinue

$boots |
Sort-Object TimeCreated |
Select-Object TimeCreated, Id, ProviderName
