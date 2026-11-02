Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# XAML for the UI with Advanced Visual Effects
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Pomodoro" Height="500" Width="350"
        WindowStartupLocation="CenterScreen"
        Background="#121212"
        ResizeMode="NoResize"
        WindowStyle="None"
        AllowsTransparency="True">

    <Window.Resources>
        <!-- Glossy Text Horizon Gradient -->
        <LinearGradientBrush x:Key="HorizonBrush" StartPoint="0.5,0" EndPoint="0.5,1">
            <GradientStop Color="#FFFFFF" Offset="0"/>
            <GradientStop Color="#D0E0FF" Offset="0.5"/>
            <GradientStop Color="#102040" Offset="0.5"/>
            <GradientStop Color="#4080FF" Offset="1"/>
        </LinearGradientBrush>
    </Window.Resources>

    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="0">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/> <!-- Glossy Title Bar -->
                <RowDefinition Height="Auto"/> <!-- Controls -->
                <RowDefinition Height="Auto"/> <!-- Timer -->
                <RowDefinition Height="*"/>    <!-- Stats -->
            </Grid.RowDefinitions>

            <!-- 1. Glossy Title Bar -->
            <Grid Grid.Row="0" x:Name="TitleBar" Height="80">
                <!-- Metallic Background Gradient -->
                <Grid.Background>
                    <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                        <GradientStop Color="#404040" Offset="0"/>
                        <GradientStop Color="#101010" Offset="0.5"/>
                        <GradientStop Color="#000000" Offset="1"/>
                    </LinearGradientBrush>
                </Grid.Background>
                
                <!-- Glass Highlight Overlay (Top Half) -->
                <Border VerticalAlignment="Top" Height="40">
                    <Border.Background>
                        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                            <GradientStop Color="#20FFFFFF" Offset="0"/>
                            <GradientStop Color="#05FFFFFF" Offset="1"/>
                        </LinearGradientBrush>
                    </Border.Background>
                </Border>

                <!-- Centered Container for Text & Reflection -->
                <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" Margin="0,5,0,0">
                    
                    <!-- Main Text -->
                    <TextBlock Text="Pomodoro"
                               FontSize="48"
                               FontWeight="Bold"
                               FontFamily="Arial"
                               Foreground="{StaticResource HorizonBrush}"
                               HorizontalAlignment="Center">
                        <TextBlock.Effect>
                            <DropShadowEffect Color="#00A0FF" BlurRadius="20" ShadowDepth="0" Opacity="0.6"/>
                        </TextBlock.Effect>
                    </TextBlock>

                    <!-- Reflection -->
                    <TextBlock Text="Pomodoro"
                               FontSize="48"
                               FontWeight="Bold"
                               FontFamily="Arial"
                               Foreground="{StaticResource HorizonBrush}"
                               HorizontalAlignment="Center"
                               RenderTransformOrigin="0.5,0.5"
                               Margin="0,-10,0,0"
                               Opacity="0.3">
                        <TextBlock.RenderTransform>
                            <ScaleTransform ScaleY="-1"/>
                        </TextBlock.RenderTransform>
                        <TextBlock.OpacityMask>
                            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                                <GradientStop Color="Transparent" Offset="0.3"/>
                                <GradientStop Color="Black" Offset="1"/>
                            </LinearGradientBrush>
                        </TextBlock.OpacityMask>
                    </TextBlock>
                </StackPanel>
                
                <!-- Close Button Logic would go here, omitting for simplicity -->
            </Grid>

            <!-- 2. Controls & Timer (Dark Themed) -->
            <StackPanel Grid.Row="1" Margin="0,20,0,10">
                <!-- Top Buttons -->
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                    <Button x:Name="btnDone" Content="Done" Foreground="#AAA" Background="Transparent" BorderThickness="0" FontSize="16" Margin="10,0" Cursor="Hand"/>
                    <Button x:Name="btnNewTask" Content="New Task" Foreground="#AAA" Background="Transparent" BorderThickness="0" FontSize="16" Margin="10,0" Cursor="Hand"/>
                    <Button x:Name="btnTimer" Content="Timer" Foreground="#AAA" Background="Transparent" BorderThickness="0" FontSize="16" Margin="10,0" Cursor="Hand"/>
                </StackPanel>
                
                <!-- Orange Flip-Clock Style Box -->
                <Border Margin="20,10" Background="#E67E22" Padding="5" CornerRadius="4">
                    <Border Background="#222" BorderBrush="#D35400" BorderThickness="2" Padding="10">
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                           <TextBlock x:Name="txtTimer" Text="00000" FontFamily="Consolas" FontSize="60" FontWeight="Bold" Foreground="White" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Border>
                </Border>
                
                <Grid Margin="30,0">
                    <TextBlock Text="mins" HorizontalAlignment="Center" Margin="-60,0,0,0" Foreground="Black" FontSize="12"/>
                    <TextBlock Text="secs" HorizontalAlignment="Center" Margin="60,0,0,0" Foreground="Black" FontSize="12"/>
                </Grid>
                
                <!-- Separator -->
                <Rectangle Height="4" Margin="0,15,0,0" Fill="#FFEA00"/> 
            </StackPanel>

            <!-- 3. Stats Section -->
             <Grid Grid.Row="3" Background="Black" Margin="0">
                 <StackPanel Margin="20">
                     <Border Background="#111" BorderThickness="1" BorderBrush="#333" Padding="5">
                         <TextBlock Text="Total Used" Foreground="White" FontSize="20" FontWeight="Normal" HorizontalAlignment="Left" Margin="10,2"/>
                     </Border>
                     
                     <!-- Red Digital Counter Style -->
                     <Border Margin="0,20,0,0" HorizontalAlignment="Center" BorderBrush="#555" BorderThickness="1" Background="#000">
                          <TextBlock x:Name="txtTotalUsed" Text="0 0 0 0 0 0" FontFamily="Consolas" FontSize="32" Foreground="#E74C3C" Padding="10,2"/>
                     </Border>
                 </StackPanel>
             </Grid>
             
        </Grid>
    </Border>
</Window>
"@

# Load XAML
try {
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)
}
catch {
    Write-Host "Error loading XAML: $_"
    exit
}

# Get controls
$btnDone = $window.FindName('btnDone')
$btnNewTask = $window.FindName('btnNewTask')
$btnTimer = $window.FindName('btnTimer')
$txtTimer = $window.FindName('txtTimer')
$txtTotalUsed = $window.FindName('txtTotalUsed')
$titleBar = $window.FindName('TitleBar')

# Window Drag Support
$titleBar.Add_MouseLeftButtonDown({
        $window.DragMove()
    })

# Logic
$secondsRemaining = 0
$totalUsed = 0

# Timer object
$dispatcherTimer = New-Object System.Windows.Threading.DispatcherTimer
$dispatcherTimer.Interval = [TimeSpan]::FromSeconds(1)

$dispatcherTimer.Add_Tick({
        if ($secondsRemaining -le 0) {
            $dispatcherTimer.Stop()
            return
        }
        $secondsRemaining--
        $txtTimer.Text = "{0:00000}" -f $secondsRemaining
    })

# Button events
$btnTimer.Add_Click({
        # Start 25 mins
        $secondsRemaining = 25 * 60
        $txtTimer.Text = "{0:00000}" -f $secondsRemaining
        $dispatcherTimer.Start()
    })

$btnDone.Add_Click({
        if ($secondsRemaining -gt 0) {
            $dispatcherTimer.Stop()
            $secondsRemaining = 0
            $txtTimer.Text = "00000"
        }
        $totalUsed++
        $txtTotalUsed.Text = "{0:0 0 0 0 0 0}" -f $totalUsed
    })

$btnNewTask.Add_Click({
        $dispatcherTimer.Stop()
        $secondsRemaining = 0
        $txtTimer.Text = "00000"
    })

# Show window
$window.ShowDialog() | Out-Null

