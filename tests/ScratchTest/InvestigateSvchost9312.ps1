$ErrorActionPreference = 'Continue'
$outPath = 'C:\Users\honey\autocommand-project\autocommand1004\ScratchTest\svchost_9312_investigation.txt'

$out = & {
    $log = 'Microsoft-Windows-Sysmon/Operational'
    $targetPid = 9312
    $ip = '92.223.96.6'

    "=== Live process check (PID 9312) ==="
    $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    if ($p) {
        "alive: {0}  started {1}" -f $p.ProcessName, $p.StartTime
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid"
        "  exe : {0}" -f $wmi.ExecutablePath
        "  cmd : {0}" -f $wmi.CommandLine
        "  services hosted in this svchost:"
        $svcs = Get-CimInstance Win32_Service -Filter "ProcessId = $targetPid"
        if ($svcs) { $svcs | ForEach-Object { "    {0} ({1}) - {2}" -f $_.Name, $_.State, $_.DisplayName } }
        else { "    (none found)" }
    } else {
        "PID 9312 is not running (already exited)"
    }

    "=== Live connections to $ip ==="
    $conns = Get-NetTCPConnection -RemoteAddress $ip -ErrorAction SilentlyContinue
    if ($conns) {
        $conns | ForEach-Object {
            "  {0}:{1} -> {2}:{3}  state={4}  owningPID={5}" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.State, $_.OwningProcess
        }
    } else { "  (none right now)" }

    "=== Sysmon EID3 for PID 9312 ==="
    $x = "*[System[EventID=3] and EventData[Data[@Name='ProcessId']='$targetPid']]"
    $events = Get-WinEvent -LogName $log -FilterXPath $x -MaxEvents 10
    if (-not $events) { "  no EID3 events for PID 9312 in current log" }
    foreach ($e in $events) {
        $d = @{}
        ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        "{0}  {1} -> {2}:{3}  proto={4} initiated={5} user={6}" -f $e.TimeCreated, $d['Image'], $d['DestinationIp'], $d['DestinationPort'], $d['Protocol'], $d['Initiated'], $d['User']
    }

    "=== Sysmon EID1 for PID 9312 (beware PID reuse — check timestamp) ==="
    $x = "*[System[EventID=1] and EventData[Data[@Name='ProcessId']='$targetPid']]"
    $e1 = Get-WinEvent -LogName $log -FilterXPath $x -MaxEvents 1
    if ($e1) {
        $d = @{}
        ([xml]$e1.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        "{0}  Image={1}" -f $e1.TimeCreated, $d['Image']
        "  cmd    : {0}" -f $d['CommandLine']
        "  parent : {0}" -f $d['ParentImage']
    } else { "  no EID1 events for PID 9312" }

    "=== Who else talks to $ip (latest 8) ==="
    $x = "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='$ip']]"
    $events = Get-WinEvent -LogName $log -FilterXPath $x -MaxEvents 8
    if (-not $events) { "  no EID3 events to $ip" }
    foreach ($e in $events) {
        $d = @{}
        ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        "{0}  PID={1,-6} {2}:{3}  proto={4}" -f $e.TimeCreated, $d['ProcessId'], $d['DestinationIp'], $d['DestinationPort'], $d['Protocol']
    }

    "=== PTR for $ip ==="
    $ptr = (Resolve-DnsName $ip -Type PTR -ErrorAction SilentlyContinue).NameHost
    if ($ptr) { "  $ip -> $ptr" } else { "  (no PTR record)" }
}
$out | Out-File -FilePath $outPath -Encoding utf8
