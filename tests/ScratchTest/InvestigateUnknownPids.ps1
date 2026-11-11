$ErrorActionPreference = 'Continue'
$outPath = 'C:\Users\honey\autocommand-project\autocommand1004\ScratchTest\sysmon_investigation.txt'

$out = & {
    $log  = 'Microsoft-Windows-Sysmon/Operational'
    $pids = '8203', '8208', '14456'
    $ips  = '172.182.252.137', '172.182.252.133'

    "=== Log health ==="
    $latest = Get-WinEvent -LogName $log -MaxEvents 1
    "oldest/retention check -> latest event: $($latest.TimeCreated)"

    "=== Sysmon EID3 for the unknown PIDs ==="
    foreach ($p in $pids) {
        $x = "*[System[EventID=3] and EventData[Data[@Name='ProcessId']='$p']]"
        $events = Get-WinEvent -LogName $log -FilterXPath $x -MaxEvents 3
        if (-not $events) { "PID $p : no EID3 events in current log" }
        foreach ($e in $events) {
            $d = @{}
            ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            "{0}  EID3  PID={1}" -f $e.TimeCreated, $p
            "    Image : {0}" -f $d['Image']
            "    Dest  : {0}  (hostname: {1})" -f $d['DestinationIp'], $d['DestinationHostname']
            "    User  : {0}" -f $d['User']
        }
    }

    "=== Sysmon EID1 (process creation) for the unknown PIDs ==="
    foreach ($p in $pids) {
        $x = "*[System[EventID=1] and EventData[Data[@Name='ProcessId']='$p']]"
        $e = Get-WinEvent -LogName $log -FilterXPath $x -MaxEvents 1
        if (-not $e) { "PID $p : no EID1 events in current log" }
        if ($e) {
            $d = @{}
            ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            "{0}  EID1  PID={1}" -f $e.TimeCreated, $p
            "    Image   : {0}" -f $d['Image']
            "    Cmdline : {0}" -f $d['CommandLine']
            "    Parent  : {0}" -f $d['ParentImage']
        }
    }

    "=== Who talks to those IPs (any PID, latest 5 each) ==="
    foreach ($ip in $ips) {
        $x = "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='$ip']]"
        $events = Get-WinEvent -LogName $log -FilterXPath $x -MaxEvents 5
        "--- $ip : $($events.Count) matching events"
        foreach ($e in $events) {
            $d = @{}
            ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            "{0}  PID={1,-6} {2}  host={3}" -f $e.TimeCreated, $d['ProcessId'], $d['Image'], $d['DestinationHostname']
        }
    }
}
$out | Out-File -FilePath $outPath -Encoding utf8
