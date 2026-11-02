# DeviceMonitorGUI.ps1
# A Native WPF Application for monitoring Device and Security events on Windows.

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.ServiceProcess

# XAML Definition for Main Window
# Added CheckBoxes for WiFi Direct and Kernel Debug
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Auto Command" Height="600" Width="1000" WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <Style TargetType="DataGrid">
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
        </Style>
    </Window.Resources>
    <DockPanel>
        <!-- Toolbar -->
        <ToolBarTray DockPanel.Dock="Top">
            <ToolBar>
                <CheckBox Name="VpnToggle" Content="VPN Service" FontSize="14" VerticalAlignment="Center" Margin="5"/>
                <Separator/>
                <CheckBox Name="WifiDirectToggle" Content="WiFi Direct" FontSize="14" VerticalAlignment="Center" Margin="5"/>
                <Separator/>
                <CheckBox Name="DebugToggle" Content="Kernel Debug" FontSize="14" VerticalAlignment="Center" Margin="5"/>
                <Separator/>
                <Button Name="ClearBtn" Content="Clear Events" Margin="5"/>
                <Separator/>
                <Button Name="TasksBtn" Content="Scheduled Tasks" Margin="5"/>
                <Separator/>
                <Button Name="NetworkAdaptersBtn" Content="Network Adapters" Margin="5"/>
            </ToolBar>
        </ToolBarTray>

        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="*"/>
                <RowDefinition Height="5"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            
            <!-- Top Pane: Device Events -->
            <GroupBox Grid.Row="0" Header="Device Events" Padding="5" Margin="5">
                <DataGrid Name="DeviceGrid">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="80"/>
                        <DataGridTextColumn Header="Event" Binding="{Binding EventType}" Width="80"/>
                        <DataGridTextColumn Header="Device Name" Binding="{Binding Name}" Width="150"/>
                        <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="100"/>
                        <DataGridTextColumn Header="Initiator" Binding="{Binding Initiator}" Width="*"/>
                    </DataGrid.Columns>
                </DataGrid>
            </GroupBox>

            <!-- Resizable Splitter 1 -->
            <GridSplitter Grid.Row="1" Height="5" HorizontalAlignment="Stretch" Background="LightGray"/>
            
            <!-- Middle Pane: Security Events -->
            <GroupBox Grid.Row="2" Header="Security Events" Padding="5" Margin="5">
                <DataGrid Name="SecurityGrid">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="80"/>
                        <DataGridTextColumn Header="EventID" Binding="{Binding Id}" Width="60"/>
                        <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="110"/>
                        <DataGridTextColumn Header="Activity" Binding="{Binding Activity}" Width="100"/>
                        <DataGridTextColumn Header="Account" Binding="{Binding Account}" Width="*"/>
                    </DataGrid.Columns>
                </DataGrid>
            </GroupBox>


        </Grid>
    </DockPanel>
</Window>
"@

# XAML Definition for Scheduled Tasks Window
$tasksXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Scheduled Tasks Manager" Height="500" Width="900" WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <Style TargetType="DataGrid">
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
        </Style>
    </Window.Resources>
    <DockPanel>
        <!-- Toolbar -->
        <ToolBarTray DockPanel.Dock="Top">
            <ToolBar>
                <Button Name="DisableBtn" Content="Disable" Margin="5" Width="70"/>
                <Button Name="StopBtn" Content="Stop" Margin="5" Width="70"/>
                <Button Name="StartBtn" Content="Start" Margin="5" Width="70"/>
                <Button Name="DeleteBtn" Content="Delete" Margin="5" Width="70"/>
                <Separator/>
                <Button Name="RefreshBtn" Content="Refresh" Margin="5" Width="70"/>
            </ToolBar>
        </ToolBarTray>

        <!-- Tasks Grid -->
        <GroupBox DockPanel.Dock="Top" Header="Scheduled Tasks Running as Admin" Padding="5" Margin="5">
            <DataGrid Name="TasksGrid" SelectionMode="Single">
                <DataGrid.Columns>
                    <DataGridTextColumn Header="Task Name" Binding="{Binding TaskName}" Width="250"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                    <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="*"/>
                    <DataGridTextColumn Header="User" Binding="{Binding User}" Width="150"/>
                </DataGrid.Columns>
            </DataGrid>
        </GroupBox>
    </DockPanel>
</Window>
"@

# XAML Definition for Network Adapters Window
$networkAdaptersXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Network Adapters Manager" Height="550" Width="1000" WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <Style TargetType="DataGrid">
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
        </Style>
    </Window.Resources>
    <DockPanel>
        <!-- Toolbar -->
        <ToolBarTray DockPanel.Dock="Top">
            <ToolBar>
                <Button Name="UninstallWifiDirectBtn" Content="Uninstall Microsoft WiFi Direct Virtual Adapter" Margin="5"/>
                <Separator/>
                <Button Name="UninstallWanMiniportBtn" Content="Uninstall All WAN Miniport" Margin="5"/>
                <Separator/>
                <Button Name="UninstallBluetoothPanBtn" Content="Uninstall Bluetooth Device (Personal Area Network)" Margin="5"/>
                <Separator/>
                <Button Name="UninstallIntelWifiBtn" Content="Uninstall Intel WiFi 6E AX210" Margin="5"/>
                <Separator/>
                <Button Name="RefreshAdaptersBtn" Content="Refresh" Margin="5" Width="70"/>
            </ToolBar>
        </ToolBarTray>

        <!-- Network Adapters Grid -->
        <GroupBox DockPanel.Dock="Top" Header="Network Adapters" Padding="5" Margin="5">
            <DataGrid Name="NetworkAdaptersGrid" SelectionMode="Single">
                <DataGrid.Columns>
                    <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="250"/>
                    <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="250"/>
                    <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="80"/>
                    <DataGridTextColumn Header="MAC Address" Binding="{Binding MacAddress}" Width="150"/>
                    <DataGridTextColumn Header="Interface Type" Binding="{Binding InterfaceType}" Width="*"/>
                </DataGrid.Columns>
            </DataGrid>
        </GroupBox>
    </DockPanel>
</Window>
"@

# Helper function to parse XAML
function Read-Xaml {
    param ($Xaml)
    $Reader = [System.Xml.XmlReader]::Create([System.IO.StringReader] $Xaml)
    [System.Windows.Markup.XamlReader]::Load($Reader)
}

# --- Backend Logic Handlers ---

function Get-Initiator {
    try {
        $sys = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($sys.UserName) { return $sys.UserName }
        return "$env:USERDOMAIN\$env:USERNAME"
    }
    catch { return "Unknown" }
}

# --- Service Management Logic ---

# 1. VPN
$vpnServices = @("RasMan", "IKEEXT", "PolicyAgent", "RemoteAccess")

function Update-VpnStatus {
    $isEnabled = $false
    foreach ($svcName in $vpnServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.StartType -ne 'Disabled') { $isEnabled = $true; break }
    }
    return $isEnabled
}

function Set-VpnState {
    param([bool]$Enable)
    $startType = if ($Enable) { "Manual" } else { "Disabled" }
    foreach ($svcName in $vpnServices) {
        try {
            Set-Service -Name $svcName -StartupType $startType -ErrorAction SilentlyContinue
            if (-not $Enable) { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue }
        }
        catch {}
    }
}

# 2. WiFi Direct
function Update-WifiDirectStatus {
    # Check if adapter matches "Wi-Fi Direct" and is "Up"
    $adapter = Get-NetAdapter -Name "*Wi-Fi Direct*" -ErrorAction SilentlyContinue
    if ($adapter -and $adapter.Status -eq "Up") { return $true }
    return $false
}

function Set-WifiDirectState {
    param([bool]$Enable)
    # Using Enable/Disable-NetAdapter
    # Note: Requires PowerShell 5.1+ and Admin
    if ($Enable) {
        Enable-NetAdapter -Name "*Wi-Fi Direct*" -Confirm:$false -ErrorAction SilentlyContinue
    }
    else {
        Disable-NetAdapter -Name "*Wi-Fi Direct*" -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# 3. Kernel Debug
function Update-DebugStatus {
    # bcdedit /enum {current} | findstr "debug"
    $bcd = bcdedit /enum "{current}"
    if ($bcd -match "debug\s+Yes") { return $true }
    return $false
}

function Set-DebugState {
    param([bool]$Enable)
    $state = if ($Enable) { "on" } else { "off" }
    Start-Process -FilePath "bcdedit.exe" -ArgumentList "/debug $state" -WindowStyle Hidden -Wait
}

# --- Scheduled Tasks Management Functions ---

function Show-TasksWindow {
    try {
        $tasksWindow = Read-Xaml $tasksXaml
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to load Tasks Window: $_", "Error", "OK", "Error")
        return
    }

    # Find Controls
    $tasksGrid = $tasksWindow.FindName("TasksGrid")
    $disableBtn = $tasksWindow.FindName("DisableBtn")
    $stopBtn = $tasksWindow.FindName("StopBtn")
    $startBtn = $tasksWindow.FindName("StartBtn")
    $deleteBtn = $tasksWindow.FindName("DeleteBtn")
    $refreshBtn = $tasksWindow.FindName("RefreshBtn")

    # Data Collection
    $tasksData = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
    $tasksGrid.ItemsSource = $tasksData

    # Function to load tasks
    $loadTasks = {
        try {
            $tasks = Get-ScheduledTask | Where-Object {
                $_.Principal.RunLevel -eq 'Highest'
            }
            
            $tasksData.Clear()
            foreach ($task in $tasks) {
                $action = "-"
                if ($task.Actions.Count -gt 0) {
                    $firstAction = $task.Actions[0]
                    if ($firstAction.Execute) {
                        $action = $firstAction.Execute
                        if ($firstAction.Arguments) {
                            $action += " " + $firstAction.Arguments
                        }
                    }
                }
                
                $tasksData.Add([PSCustomObject]@{
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                        State    = $task.State
                        Action   = $action
                        User     = $task.Principal.UserId
                    })
            }
        }
        catch {
            [System.Windows.MessageBox]::Show("Failed to load tasks: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }

    # Load tasks on window open
    & $loadTasks

    # Refresh Button
    $refreshBtn.Add_Click({ & $loadTasks })

    # Disable Button
    $disableBtn.Add_Click({
            $selected = $tasksGrid.SelectedItem
            if ($selected) {
                try {
                    Disable-ScheduledTask -TaskName $selected.TaskName -TaskPath $selected.TaskPath -ErrorAction Stop
                    [System.Windows.MessageBox]::Show("Task '$($selected.TaskName)' disabled successfully.", "Success", "OK", "Information")
                    & $loadTasks
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    if ($errorMsg -match "Access is denied") {
                        [System.Windows.MessageBox]::Show("Access Denied: This task is protected by the system or requires additional permissions.`n`nTask: $($selected.TaskName)`n`nSome Windows system tasks cannot be modified even with administrator rights.", "Permission Error", "OK", "Warning")
                    }
                    else {
                        [System.Windows.MessageBox]::Show("Failed to disable task: $errorMsg", "Error", "OK", "Error")
                    }
                }
            }
            else {
                [System.Windows.MessageBox]::Show("Please select a task first.", "No Selection", "OK", "Warning")
            }
        })

    # Stop Button
    $stopBtn.Add_Click({
            $selected = $tasksGrid.SelectedItem
            if ($selected) {
                try {
                    Stop-ScheduledTask -TaskName $selected.TaskName -TaskPath $selected.TaskPath -ErrorAction Stop
                    [System.Windows.MessageBox]::Show("Task '$($selected.TaskName)' stopped successfully.", "Success", "OK", "Information")
                    & $loadTasks
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    if ($errorMsg -match "Access is denied") {
                        [System.Windows.MessageBox]::Show("Access Denied: This task is protected by the system or requires additional permissions.`n`nTask: $($selected.TaskName)`n`nSome Windows system tasks cannot be modified even with administrator rights.", "Permission Error", "OK", "Warning")
                    }
                    else {
                        [System.Windows.MessageBox]::Show("Failed to stop task: $errorMsg", "Error", "OK", "Error")
                    }
                }
            }
            else {
                [System.Windows.MessageBox]::Show("Please select a task first.", "No Selection", "OK", "Warning")
            }
        })

    # Start Button
    $startBtn.Add_Click({
            $selected = $tasksGrid.SelectedItem
            if ($selected) {
                try {
                    Start-ScheduledTask -TaskName $selected.TaskName -TaskPath $selected.TaskPath -ErrorAction Stop
                    [System.Windows.MessageBox]::Show("Task '$($selected.TaskName)' started successfully.", "Success", "OK", "Information")
                    & $loadTasks
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    if ($errorMsg -match "Access is denied") {
                        [System.Windows.MessageBox]::Show("Access Denied: This task is protected by the system or requires additional permissions.`n`nTask: $($selected.TaskName)`n`nSome Windows system tasks cannot be modified even with administrator rights.", "Permission Error", "OK", "Warning")
                    }
                    else {
                        [System.Windows.MessageBox]::Show("Failed to start task: $errorMsg", "Error", "OK", "Error")
                    }
                }
            }
            else {
                [System.Windows.MessageBox]::Show("Please select a task first.", "No Selection", "OK", "Warning")
            }
        })

    # Delete Button
    $deleteBtn.Add_Click({
            $selected = $tasksGrid.SelectedItem
            if ($selected) {
                $result = [System.Windows.MessageBox]::Show(
                    "Are you sure you want to delete task '$($selected.TaskName)'? This action cannot be undone.",
                    "Confirm Delete",
                    "YesNo",
                    "Warning"
                )
                if ($result -eq "Yes") {
                    try {
                        Unregister-ScheduledTask -TaskName $selected.TaskName -TaskPath $selected.TaskPath -Confirm:$false -ErrorAction Stop
                        [System.Windows.MessageBox]::Show("Task '$($selected.TaskName)' deleted successfully.", "Success", "OK", "Information")
                        & $loadTasks
                    }
                    catch {
                        $errorMsg = $_.Exception.Message
                        if ($errorMsg -match "Access is denied") {
                            [System.Windows.MessageBox]::Show("Access Denied: This task is protected by the system or requires additional permissions.`n`nTask: $($selected.TaskName)`n`nSome Windows system tasks cannot be deleted even with administrator rights.", "Permission Error", "OK", "Warning")
                        }
                        else {
                            [System.Windows.MessageBox]::Show("Failed to delete task: $errorMsg", "Error", "OK", "Error")
                        }
                    }
                }
            }
            else {
                [System.Windows.MessageBox]::Show("Please select a task first.", "No Selection", "OK", "Warning")
            }
        })

    # Show the tasks window
    $tasksWindow.ShowDialog() | Out-Null
}

# --- Network Adapters Management Functions ---

function Show-NetworkAdaptersWindow {
    try {
        $adaptersWindow = Read-Xaml $networkAdaptersXaml
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to load Network Adapters Window: $_", "Error", "OK", "Error")
        return
    }

    # Find Controls
    $adaptersGrid = $adaptersWindow.FindName("NetworkAdaptersGrid")
    $uninstallWifiDirectBtn = $adaptersWindow.FindName("UninstallWifiDirectBtn")
    $uninstallWanMiniportBtn = $adaptersWindow.FindName("UninstallWanMiniportBtn")
    $uninstallBluetoothPanBtn = $adaptersWindow.FindName("UninstallBluetoothPanBtn")
    $uninstallIntelWifiBtn = $adaptersWindow.FindName("UninstallIntelWifiBtn")
    $refreshAdaptersBtn = $adaptersWindow.FindName("RefreshAdaptersBtn")

    # Data Collection
    $adaptersData = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
    $adaptersGrid.ItemsSource = $adaptersData

    # Function to load network adapters
    $loadAdapters = {
        try {
            $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
            
            $adaptersData.Clear()
            foreach ($adapter in $adapters) {
                $adaptersData.Add([PSCustomObject]@{
                        Name          = $adapter.Name
                        Description   = $adapter.InterfaceDescription
                        Status        = $adapter.Status
                        MacAddress    = $adapter.MacAddress
                        InterfaceType = $adapter.InterfaceType
                        DeviceID      = $adapter.DeviceID
                    })
            }
        }
        catch {
            [System.Windows.MessageBox]::Show("Failed to load network adapters: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }

    # Load adapters on window open
    & $loadAdapters

    # Refresh Button
    $refreshAdaptersBtn.Add_Click({ & $loadAdapters })

    # Helper function to uninstall device by name pattern
    $uninstallDevice = {
        param($namePattern, $deviceLabel)
        
        try {
            # Get PnP devices matching the pattern
            $devices = Get-PnpDevice | Where-Object { $_.FriendlyName -like $namePattern } -ErrorAction SilentlyContinue
            
            if (-not $devices -or $devices.Count -eq 0) {
                [System.Windows.MessageBox]::Show("No devices found matching: $deviceLabel", "Not Found", "OK", "Information")
                return
            }
            
            $deviceCount = if ($devices -is [array]) { $devices.Count } else { 1 }
            
            $result = [System.Windows.MessageBox]::Show(
                "Found $deviceCount device(s) matching '$deviceLabel'.`n`nAre you sure you want to uninstall? This may require a system restart.",
                "Confirm Uninstall",
                "YesNo",
                "Warning"
            )
            
            if ($result -eq "Yes") {
                $successCount = 0
                $failCount = 0
                
                foreach ($device in $devices) {
                    try {
                        # Use pnputil to remove the device
                        $instanceId = $device.InstanceId
                        $pnpResult = & pnputil /remove-device "$instanceId" 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            $successCount++
                        }
                        else {
                            $failCount++
                        }
                    }
                    catch {
                        $failCount++
                    }
                }
                
                if ($successCount -gt 0 -and $failCount -eq 0) {
                    [System.Windows.MessageBox]::Show("Successfully uninstalled $successCount device(s).`n`nYou may need to restart your computer for changes to take effect.", "Success", "OK", "Information")
                }
                elseif ($successCount -gt 0 -and $failCount -gt 0) {
                    [System.Windows.MessageBox]::Show("Uninstalled $successCount device(s), but $failCount device(s) failed.`n`nSome devices may be protected or in use.", "Partial Success", "OK", "Warning")
                }
                else {
                    [System.Windows.MessageBox]::Show("Failed to uninstall devices. They may be protected by the system or require elevated permissions.", "Failed", "OK", "Error")
                }
                
                & $loadAdapters
            }
        }
        catch {
            [System.Windows.MessageBox]::Show("Error during uninstall: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }

    # Uninstall Microsoft WiFi Direct Virtual Adapter
    $uninstallWifiDirectBtn.Add_Click({
            & $uninstallDevice "*Microsoft Wi-Fi Direct Virtual Adapter*" "Microsoft WiFi Direct Virtual Adapter"
        })

    # Uninstall All WAN Miniport
    $uninstallWanMiniportBtn.Add_Click({
            & $uninstallDevice "*WAN Miniport*" "WAN Miniport"
        })

    # Uninstall Bluetooth Device (Personal Area Network)
    $uninstallBluetoothPanBtn.Add_Click({
            & $uninstallDevice "*Bluetooth Device (Personal Area Network)*" "Bluetooth Device (Personal Area Network)"
        })

    # Uninstall Intel WiFi 6E AX210
    $uninstallIntelWifiBtn.Add_Click({
            & $uninstallDevice "*Intel*Wi-Fi 6E AX210*" "Intel WiFi 6E AX210"
        })

    # Show the network adapters window
    $adaptersWindow.ShowDialog() | Out-Null
}


# --- Main Script ---

# Load UI
try {
    $window = Read-Xaml $xaml
}
catch {
    Write-Error "Failed to load XAML: $_"
    exit 1
}

# Find Controls
$deviceGrid = $window.FindName("DeviceGrid")
$securityGrid = $window.FindName("SecurityGrid")
$vpnToggle = $window.FindName("VpnToggle")
$wifiToggle = $window.FindName("WifiDirectToggle")
$debugToggle = $window.FindName("DebugToggle")
$clearBtn = $window.FindName("ClearBtn")
$tasksBtn = $window.FindName("TasksBtn")
$networkAdaptersBtn = $window.FindName("NetworkAdaptersBtn")

# Data Collections
$deviceData = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$securityData = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

$deviceGrid.ItemsSource = $deviceData
$securityGrid.ItemsSource = $securityData

# Update Title with User Status
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    $window.Title = "Auto Command (Administrator) - User: $currentUser"
    
    # Initialize Toggles
    $vpnToggle.IsChecked = Update-VpnStatus
    $wifiToggle.IsChecked = Update-WifiDirectStatus
    $debugToggle.IsChecked = Update-DebugStatus
    
    # VPN Toggle Event
    $vpnToggle.Add_Click({
            $enabled = $vpnToggle.IsChecked
            Set-VpnState -Enable $enabled
        
            $stateStr = if ($enabled) { "ENABLED" } else { "DISABLED" }
            $deviceData.Insert(0, [PSCustomObject]@{
                    Time      = [DateTime]::Now.ToString("HH:mm:ss")
                    EventType = "CONFIG"
                    Name      = "VPN Services"
                    Type      = "System"
                    Initiator = "$currentUser ($stateStr)"
                })
        })

    # WiFi Toggle Event
    $wifiToggle.Add_Click({
            $enabled = $wifiToggle.IsChecked
            Set-WifiDirectState -Enable $enabled
        
            $stateStr = if ($enabled) { "ENABLED" } else { "DISABLED" }
            $deviceData.Insert(0, [PSCustomObject]@{
                    Time      = [DateTime]::Now.ToString("HH:mm:ss")
                    EventType = "CONFIG"
                    Name      = "WiFi Direct"
                    Type      = "Network"
                    Initiator = "$currentUser ($stateStr)"
                })
        })

    # Debug Toggle Event
    $debugToggle.Add_Click({
            $enabled = $debugToggle.IsChecked
            Set-DebugState -Enable $enabled
        
            $stateStr = if ($enabled) { "ENABLED" } else { "DISABLED" }
            $deviceData.Insert(0, [PSCustomObject]@{
                    Time      = [DateTime]::Now.ToString("HH:mm:ss")
                    EventType = "CONFIG"
                    Name      = "Kernel Debug"
                    Type      = "BootLoader"
                    Initiator = "$currentUser ($stateStr)"
                })
        })

}
else {
    $window.Title = "Auto Command (User) - User: $currentUser"
    $vpnToggle.IsEnabled = $false
    $wifiToggle.IsEnabled = $false
    $debugToggle.IsEnabled = $false
    $vpnToggle.Content = "Admin Required"
    
    $securityData.Add([PSCustomObject]@{
            Time     = "INFO"
            Id       = "-"
            Type     = "-"
            Activity = "Admin Rights Required"
            Account  = "Right-click -> Run as Admin"
        })
}

$clearBtn.Add_Click({
        $deviceData.Clear()
        $securityData.Clear()
    })

# Tasks Button - Open Scheduled Tasks Window
$tasksBtn.Add_Click({
        Show-TasksWindow
    })

# Network Adapters Button - Open Network Adapters Window
$networkAdaptersBtn.Add_Click({
        Show-NetworkAdaptersWindow
    })

# --- Device Monitoring Setup (System.Management) ---
$deviceAction = {
    param($evtSender, $e)
    
    $evtArgs = $e.NewEvent
    $device = $evtArgs.TargetInstance
    $className = $evtArgs.SystemProperties["__Class"].Value
    
    $eventType = "UNKNOWN"
    switch ($className) {
        "__InstanceCreationEvent" { $eventType = "ADDED" }
        "__InstanceDeletionEvent" { $eventType = "REMOVED" }
        "__InstanceModificationEvent" { $eventType = "CHANGED" }
    }

    # Extract Type
    $type = "Device"
    if ($device.PNPClass) { $type = $device.PNPClass }
    elseif ($device.Service) { $type = "Service: $($device.Service)" }

    $name = $device.Name
    if (-not $name) { $name = $device.Description }

    $item = [PSCustomObject]@{
        Time      = [DateTime]::Now.ToString("HH:mm:ss")
        EventType = $eventType
        Name      = $name
        Type      = $type
        Initiator = (Get-Initiator)
    }

    $window.Dispatcher.Invoke([Action] { $deviceData.Insert(0, $item) })
}

# Create Device Watchers - Explicit Property Setting
$qAdd = New-Object System.Management.WqlEventQuery
$qAdd.EventClassName = "__InstanceCreationEvent"
$qAdd.WithinInterval = [TimeSpan]::FromSeconds(1)
$qAdd.Condition = "TargetInstance ISA 'Win32_PnPEntity'"
$wAdd = New-Object System.Management.ManagementEventWatcher $qAdd

$qRem = New-Object System.Management.WqlEventQuery
$qRem.EventClassName = "__InstanceDeletionEvent"
$qRem.WithinInterval = [TimeSpan]::FromSeconds(1)
$qRem.Condition = "TargetInstance ISA 'Win32_PnPEntity'"
$wRem = New-Object System.Management.ManagementEventWatcher $qRem

Register-ObjectEvent -InputObject $wAdd -EventName "EventArrived" -Action $deviceAction | Out-Null
Register-ObjectEvent -InputObject $wRem -EventName "EventArrived" -Action $deviceAction | Out-Null

$wAdd.Start()
$wRem.Start()

# --- Security Monitoring Setup (Polling) ---
$lastRecordId = 0

# 1. Initial Load: Get last 20 events so the list isn't empty
try {
    if ($isAdmin) {
        $recent = Get-WinEvent -LogName 'Security' -MaxEvents 20 -ErrorAction SilentlyContinue | Sort-Object TimeCreated
        if ($recent) {
            foreach ($evt in $recent) {
                if ($evt.RecordId -gt $lastRecordId) { $lastRecordId = $evt.RecordId }
                
                # Re-use parsing logic (refactored below)
                $ProcessEvent = {
                    param($e)
                    $xml = [xml]$e.ToXml()
                    $data = $xml.Event.EventData.Data
                    
                    # Safe Account Extraction
                    $account = $null
                    if ($data) {
                        $account = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"
                        if (-not $account) { $account = ($data | Where-Object { $_.Name -match "AccountName|User|SubjectUserName" } | Select-Object -First 1)."#text" }
                    }
                    else {
                        # Fallback for events without EventData (Event 4624/4625 always have it, others might not)
                        $account = $e.UserId.Value
                    }
                    
                    if (-not $account) { $account = "N/A" }
                    
                    # LogonType Extraction
                    $logonType = $null
                    if ($data) {
                        $logonType = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"
                    }
                    $typeDesc = "-"
                    if ($logonType) {
                        $typeDesc = "Logon: $logonType"
                        switch ($logonType) {
                            "2" { $typeDesc = "Interactive" }
                            "3" { $typeDesc = "Network" }
                            "4" { $typeDesc = "Batch" }
                            "5" { $typeDesc = "Service" }
                            "7" { $typeDesc = "Unlock" }
                            "10" { $typeDesc = "RDP" }
                        }
                    }

                    $activity = $e.TaskDisplayName
                    if (-not $activity) { $activity = "Event $($e.Id)" }

                    return [PSCustomObject]@{
                        Time     = $e.TimeCreated.ToString("HH:mm:ss")
                        Id       = $e.Id
                        Type     = $typeDesc
                        Activity = $activity
                        Account  = $account
                    }
                }
                
                $item = &$ProcessEvent $evt
                $securityData.Insert(0, $item)
            }
        }
    }
}
catch {
    $securityData.Add([PSCustomObject]@{Time = "ERR"; Id = "-"; Type = "-"; Activity = "Init Failed"; Account = $_.Exception.Message })
}

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)
$timer.Add_Tick({
        try {
            if (-not $isAdmin) { return }

            $query = "*[System[(EventRecordID > $lastRecordId)]]"
            $events = Get-WinEvent -LogName 'Security' -FilterXPath $query -ErrorAction SilentlyContinue | Sort-Object TimeCreated
        
            if ($events) {
                foreach ($evt in $events) {
                    if ($evt.RecordId -gt $lastRecordId) { $lastRecordId = $evt.RecordId }
                
                    # Inline parsing (copy of logic above) to avoid scope issues in timer
                    $xml = [xml]$evt.ToXml()
                    $data = $xml.Event.EventData.Data
                
                    $account = $null
                    if ($data) {
                        $account = ($data | Where-Object { $_.Name -eq "TargetUserName" })."#text"
                        if (-not $account) { $account = ($data | Where-Object { $_.Name -match "AccountName|User|SubjectUserName" } | Select-Object -First 1)."#text" }
                    }
                    else {
                        $account = $evt.UserId.Value
                    }
                    if (-not $account) { $account = "N/A" }
                
                    $logonType = $null
                    if ($data) {
                        $logonType = ($data | Where-Object { $_.Name -eq "LogonType" })."#text"
                    }
                    $typeDesc = "-"
                    if ($logonType) {
                        $typeDesc = "Logon: $logonType"
                        switch ($logonType) {
                            "2" { $typeDesc = "Interactive" }
                            "3" { $typeDesc = "Network" }
                            "4" { $typeDesc = "Batch" }
                            "5" { $typeDesc = "Service" }
                            "7" { $typeDesc = "Unlock" }
                            "10" { $typeDesc = "RDP" }
                        }
                    }

                    $activity = $evt.TaskDisplayName
                    if (-not $activity) { $activity = "Event $($evt.Id)" }

                    $item = [PSCustomObject]@{
                        Time     = $evt.TimeCreated.ToString("HH:mm:ss")
                        Id       = $evt.Id
                        Type     = $typeDesc
                        Activity = $activity
                        Account  = $account
                    }
                    $securityData.Insert(0, $item)
                }
            }
        }
        catch {
            $securityData.Insert(0, [PSCustomObject]@{Time = "ERR"; Id = "POLL"; Type = "-"; Activity = $_.Exception.Message; Account = "-" })
        }
    })

$timer.Start()

# Cleanup on Close
$window.Add_Closed({
        $wAdd.Stop(); $wAdd.Dispose()
        $wRem.Stop(); $wRem.Dispose()
        $timer.Stop()
    
        Unregister-Event -SourceIdentifier "*" -ErrorAction SilentlyContinue
    })

# Show Window
$window.ShowDialog() | Out-Null
