use std::process::Command;

pub struct GuiDialog;

impl GuiDialog {
    /// Determines whether GUI dialog prompt is enabled (defaults to true).
    pub fn is_enabled(no_gui_flag: bool) -> bool {
        if no_gui_flag {
            return false;
        }

        // Check CI and test environments
        if std::env::var("CI").is_ok() || std::env::var("HOOK_TEST_MODE").is_ok() {
            return false;
        }

        // Check explicit environment disables
        if let Ok(val) = std::env::var("AI_HOOK_GUI") {
            let v = val.trim().to_ascii_lowercase();
            if v == "0" || v == "false" || v == "no" || v == "off" {
                return false;
            }
        }
        if let Ok(val) = std::env::var("HOOK_NO_GUI") {
            let v = val.trim();
            if v == "1" || v.eq_ignore_ascii_case("true") {
                return false;
            }
        }

        // Default is enabled!
        true
    }

    /// Resolves the GUI countdown timeout in seconds (default: 60).
    pub fn resolve_timeout(cli_timeout: Option<u32>) -> u32 {
        if let Some(to) = cli_timeout {
            if to > 0 {
                return to;
            }
        }
        if let Ok(val) = std::env::var("AI_HOOK_GUI_TIMEOUT") {
            if let Ok(parsed) = val.trim().parse::<u32>() {
                if parsed > 0 {
                    return parsed;
                }
            }
        }
        if let Ok(val) = std::env::var("HOOK_GUI_TIMEOUT") {
            if let Ok(parsed) = val.trim().parse::<u32>() {
                if parsed > 0 {
                    return parsed;
                }
            }
        }
        60
    }

    /// Prompts the user with a modern, high-aesthetic system-level GUI dialog.
    /// Returns true if the user clicks "Allow", false on "Deny" or timeout.
    pub fn confirm(
        title: &str,
        reason: &str,
        command: &str,
        agent: &str,
        timeout_sec: u32,
    ) -> bool {
        #[cfg(target_os = "windows")]
        {
            return Self::prompt_windows_wpf(title, reason, command, agent, timeout_sec);
        }

        #[cfg(target_os = "macos")]
        {
            let body = if command.is_empty() {
                reason.to_string()
            } else {
                format!("{}\n\n即将执行：\n{}", reason, command)
            };
            return Self::prompt_macos_native(title, &body, timeout_sec);
        }

        #[cfg(target_os = "linux")]
        {
            let body = if command.is_empty() {
                reason.to_string()
            } else {
                format!("{}\n\n即将执行：\n{}", reason, command)
            };
            return Self::prompt_linux_native(title, &body, timeout_sec);
        }

        #[allow(unreachable_code)]
        false
    }

    #[cfg(target_os = "windows")]
    fn prompt_windows_wpf(
        title: &str,
        reason: &str,
        command: &str,
        agent: &str,
        timeout_sec: u32,
    ) -> bool {
        let ps_script = r###"
            param()
            Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

            # 1. System Theme Adaptive Detection (Windows Dark/Light mode)
            $isDark = $false
            $themeEnv = if ($env:AI_HOOK_THEME) { $env:AI_HOOK_THEME.Trim().ToLower() } else { "auto" }
            if ($themeEnv -eq "dark") {
                $isDark = $true
            } elseif ($themeEnv -eq "light") {
                $isDark = $false
            } else {
                try {
                    $themeVal = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction SilentlyContinue
                    if ($themeVal -eq 0) { $isDark = $true }
                } catch {}
            }

            # 2. Modern Fluent Color Palettes
            if ($isDark) {
                $cardBg     = "#181825"
                $cardBorder = "#313244"
                $titleFg    = "#CDD6F4"
                $reasonFg   = "#BAC2DE"
                $badgeBg    = "#3A1A1A"
                $badgeFg    = "#F38BA8"
                $agentBg    = "#252636"
                $agentFg    = "#A6ADC8"
                $codeBg     = "#11111B"
                $codeBorder = "#313244"
                $codeFg     = "#89DCEB"
                $timerFg    = "#A6ADC8"
                $denyBg     = "#313244"
                $denyFg     = "#CDD6F4"
                $allowBg    = "#10B981"
                $allowFg    = "#FFFFFF"
                $shadowCol  = "#000000"
                $shadowOpa  = "0.45"
            } else {
                $cardBg     = "#FFFFFF"
                $cardBorder = "#E2E8F0"
                $titleFg    = "#0F172A"
                $reasonFg   = "#334155"
                $badgeBg    = "#FEF2F2"
                $badgeFg    = "#DC2626"
                $agentBg    = "#F1F5F9"
                $agentFg    = "#475569"
                $codeBg     = "#0F172A"
                $codeBorder = "#1E293B"
                $codeFg     = "#38BDF8"
                $timerFg    = "#64748B"
                $denyBg     = "#F1F5F9"
                $denyFg     = "#475569"
                $allowBg    = "#10B981"
                $allowFg    = "#FFFFFF"
                $shadowCol  = "#0F172A"
                $shadowOpa  = "0.18"
            }

            # 3. Parameters & Smart Empty-Reason Fallback
            $Title = if ($env:AI_HOOK_DLG_TITLE) { $env:AI_HOOK_DLG_TITLE } else { "操作安全授权确认" }
            $RawReason = if ($env:AI_HOOK_DLG_REASON) { $env:AI_HOOK_DLG_REASON.Trim() } else { "" }
            $Command = if ($env:AI_HOOK_DLG_CMD) { $env:AI_HOOK_DLG_CMD } else { "" }
            $Agent = if ($env:AI_HOOK_DLG_AGENT) { $env:AI_HOOK_DLG_AGENT } else { "AI Agent" }
            $Timeout = if ($env:AI_HOOK_DLG_TIMEOUT) { [int]$env:AI_HOOK_DLG_TIMEOUT } else { 60 }

            $hasCommand = [bool]($Command -and $Command.Trim().Length -gt 0)
            $cmdVisibility = if ($hasCommand) { "Visible" } else { "Collapsed" }

            $effectiveReason = if ($RawReason.Length -gt 0) {
                $RawReason
            } elseif ($hasCommand) {
                "AI Agent 准备在当前工作区执行以下操作，请确认是否允许继续："
            } else {
                "AI Agent 发起了一项安全敏感操作，请确认是否授权继续执行。"
            }

            $safeTitle = [System.Security.SecurityElement]::Escape($Title)
            $safeReason = [System.Security.SecurityElement]::Escape($effectiveReason)
            $safeCmd = [System.Security.SecurityElement]::Escape($Command)
            $safeAgent = [System.Security.SecurityElement]::Escape($Agent)

            # 4. Adaptive Modern Card XAML
            $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$safeTitle"
        Width="620"
        SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        Topmost="True"
        ResizeMode="NoResize"
        WindowStyle="None"
        AllowsTransparency="True"
        Background="Transparent"
        FontFamily="Segoe UI, Microsoft YaHei UI, -apple-system, sans-serif">
    <Border Background="$cardBg"
            BorderBrush="$cardBorder"
            BorderThickness="1"
            CornerRadius="16"
            Margin="24">
        <Border.Effect>
            <DropShadowEffect BlurRadius="26" ShadowDepth="4" Opacity="$shadowOpa" Color="$shadowCol"/>
        </Border.Effect>
        <Grid Margin="26,22,26,24">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- Row 0: Header with Vector Shield -->
            <Grid Grid.Row="0" Margin="0,0,0,16">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <Border Background="$badgeBg" CornerRadius="7" Padding="8,5" Margin="0,0,10,0">
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <Viewbox Width="13" Height="13" Margin="0,0,5,0">
                            <Path Fill="$badgeFg" Data="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.67-3.13 8.94-7 10.08-3.87-1.14-7-5.41-7-10.08V6.3l7-3.12z"/>
                        </Viewbox>
                        <TextBlock Text="安全门禁" FontWeight="Bold" Foreground="$badgeFg" FontSize="12"/>
                    </StackPanel>
                </Border>

                <TextBlock Grid.Column="1" Text="$safeTitle" FontSize="15" FontWeight="Bold" VerticalAlignment="Center" Foreground="$titleFg"/>

                <Border Grid.Column="2" Background="$agentBg" CornerRadius="7" Padding="9,4">
                    <TextBlock Text="$safeAgent" FontSize="11.5" FontWeight="SemiBold" Foreground="$agentFg"/>
                </Border>
            </Grid>

            <!-- Row 1: Reason Text -->
            <TextBlock Grid.Row="1" Text="$safeReason" TextWrapping="Wrap" FontSize="13.5" LineHeight="20" Foreground="$reasonFg" Margin="0,0,0,16"/>

            <!-- Row 2: Code block (collapsed completely if empty) -->
            <Border Grid.Row="2" Visibility="$cmdVisibility" Background="$codeBg" BorderBrush="$codeBorder" BorderThickness="1" CornerRadius="9" Padding="14,12" Margin="0,0,0,20">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" MaxHeight="150">
                    <TextBlock Text="$safeCmd" FontFamily="Consolas, Cascadia Code, Courier New" FontSize="12.5" Foreground="$codeFg"/>
                </ScrollViewer>
            </Border>

            <!-- Row 3: Action Bar with Vector Clock -->
            <Grid Grid.Row="3">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Viewbox Width="14" Height="14" Margin="0,0,6,0">
                        <Path Fill="$timerFg" Data="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8zm.5-13h-1.2v6l5.2 3.1.6-1.1-4.6-2.7z"/>
                    </Viewbox>
                    <TextBlock Name="TxtCountdown" Text="剩余 $Timeout 秒自动拒绝" FontSize="12.5" Foreground="$timerFg" FontWeight="Medium" VerticalAlignment="Center"/>
                </StackPanel>

                <Button Name="BtnDeny" Grid.Column="1" Content="拒绝 (Esc)" Margin="0,0,10,0" Width="105" Height="36"
                        Background="$denyBg" Foreground="$denyFg" FontWeight="SemiBold" FontSize="13"
                        BorderThickness="0" Cursor="Hand">
                    <Button.Resources>
                        <Style TargetType="Border">
                            <Setter Property="CornerRadius" Value="8"/>
                        </Style>
                    </Button.Resources>
                </Button>

                <Button Name="BtnAllow" Grid.Column="2" Content="允许执行 (Enter)" Width="125" Height="36"
                        Background="$allowBg" Foreground="$allowFg" FontWeight="Bold" FontSize="13"
                        BorderThickness="0" Cursor="Hand">
                    <Button.Resources>
                        <Style TargetType="Border">
                            <Setter Property="CornerRadius" Value="8"/>
                        </Style>
                    </Button.Resources>
                </Button>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

            $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
            $win = [System.Windows.Markup.XamlReader]::Load($reader)

            $btnAllow = $win.FindName("BtnAllow")
            $btnDeny = $win.FindName("BtnDeny")
            $txtCountdown = $win.FindName("TxtCountdown")

            $result = 1

            $btnAllow.Add_Click({
                $script:result = 0
                $win.Close()
            })

            $btnDeny.Add_Click({
                $script:result = 1
                $win.Close()
            })

            $win.Add_KeyDown({
                param($s, $e)
                if ($e.Key -eq [System.Windows.Input.Key]::Escape) {
                    $script:result = 1
                    $win.Close()
                } elseif ($e.Key -eq [System.Windows.Input.Key]::Enter) {
                    $script:result = 0
                    $win.Close()
                }
            })

            $win.Add_MouseLeftButtonDown({
                param($s, $e)
                $win.DragMove()
            })

            $script:remaining = $Timeout
            $timer = New-Object System.Windows.Threading.DispatcherTimer
            $timer.Interval = [TimeSpan]::FromSeconds(1)
            $timer.Add_Tick({
                $script:remaining--
                $txtCountdown.Text = "剩余 $script:remaining 秒自动拒绝"
                if ($script:remaining -le 0) {
                    $timer.Stop()
                    $script:result = 1
                    $win.Close()
                }
            })
            $timer.Start()

            $win.ShowDialog() | Out-Null
            $timer.Stop()
            exit $result
        "###;

        let status = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(ps_script)
            .env("AI_HOOK_DLG_TITLE", title)
            .env("AI_HOOK_DLG_REASON", reason)
            .env("AI_HOOK_DLG_CMD", command)
            .env("AI_HOOK_DLG_AGENT", agent)
            .env("AI_HOOK_DLG_TIMEOUT", timeout_sec.to_string())
            .status();

        match status {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }

    #[cfg(target_os = "macos")]
    fn prompt_macos_native(title: &str, body: &str, timeout_sec: u32) -> bool {
        let clean_title = title.replace('"', "\\\"");
        let clean_body = body.replace('"', "\\\"");
        let script = format!(
            "display dialog \"{}\n\n即将执行：\n{}\n\n({} 秒内无响应将自动拒绝)\" with title \"安全门禁授权\" buttons {{\"拒绝\", \"允许\"}} default button \"拒绝\" cancel button \"拒绝\" with icon caution giving up after {}",
            clean_title, clean_body, timeout_sec, timeout_sec
        );

        let output = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output();

        match output {
            Ok(out) => {
                let res = String::from_utf8_lossy(&out.stdout);
                res.contains("button returned:允许")
            }
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn prompt_linux_native(title: &str, body: &str, timeout_sec: u32) -> bool {
        // Try zenity modern GTK dialog first
        let status = Command::new("zenity")
            .arg("--question")
            .arg(format!("--title=安全门禁授权: {}", title))
            .arg(format!("--text=即将执行：\n\n{}\n\n是否授权继续执行？\n({} 秒内无响应将自动拒绝)", body, timeout_sec))
            .arg(format!("--timeout={}", timeout_sec))
            .arg("--default-cancel")
            .status();

        if let Ok(s) = status {
            return s.success();
        }

        let kdialog_status = Command::new("kdialog")
            .arg("--title")
            .arg("安全门禁授权")
            .arg("--yesno")
            .arg(format!("即将执行：\n\n{}\n\n是否授权继续执行？", body))
            .status();

        match kdialog_status {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }
}
