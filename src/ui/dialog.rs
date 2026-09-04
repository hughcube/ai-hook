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
    pub fn confirm(title: &str, body: &str, timeout_sec: u32) -> bool {
        #[cfg(target_os = "windows")]
        {
            return Self::prompt_windows_fluent(title, body, timeout_sec);
        }

        #[cfg(target_os = "macos")]
        {
            return Self::prompt_macos_native(title, body, timeout_sec);
        }

        #[cfg(target_os = "linux")]
        {
            return Self::prompt_linux_native(title, body, timeout_sec);
        }

        #[allow(unreachable_code)]
        false
    }

    #[cfg(target_os = "windows")]
    fn prompt_windows_fluent(title: &str, body: &str, timeout_sec: u32) -> bool {
        let ps_script = r#"
            Add-Type -AssemblyName System.Windows.Forms, System.Drawing
            [System.Windows.Forms.Application]::EnableVisualStyles()

            $title = if ($env:HOOK_GUI_TITLE) { $env:HOOK_GUI_TITLE } else { "安全门禁权限确认" }
            $body = if ($env:HOOK_GUI_BODY) { $env:HOOK_GUI_BODY } else { "未知操作" }
            $to = if ($env:HOOK_GUI_TIMEOUT) { [int]$env:HOOK_GUI_TIMEOUT } else { 60 }

            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Antigravity 安全门禁授权 (Security Confirmation)"
            $form.Size = New-Object System.Drawing.Size(680, 480)
            $form.MinimumSize = New-Object System.Drawing.Size(540, 360)
            $form.StartPosition = "CenterScreen"
            $form.TopMost = $true
            $form.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
            $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $form.ShowIcon = $false

            # 1. 顶部现代化警示卡片 (Header Alert Card)
            $pnlTop = New-Object System.Windows.Forms.Panel
            $pnlTop.Dock = [System.Windows.Forms.DockStyle]::Top
            $pnlTop.Height = 70
            $pnlTop.Padding = New-Object System.Windows.Forms.Padding(18, 12, 18, 8)
            $form.Controls.Add($pnlTop)

            $cardAlert = New-Object System.Windows.Forms.Panel
            $cardAlert.Dock = [System.Windows.Forms.DockStyle]::Fill
            $cardAlert.BackColor = [System.Drawing.Color]::FromArgb(254, 242, 242)
            $cardAlert.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)
            $pnlTop.Controls.Add($cardAlert)

            $lblAlertTitle = New-Object System.Windows.Forms.Label
            $lblAlertTitle.Dock = [System.Windows.Forms.DockStyle]::Top
            $lblAlertTitle.Height = 22
            $lblAlertTitle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $lblAlertTitle.ForeColor = [System.Drawing.Color]::FromArgb(153, 27, 27)
            $lblAlertTitle.Text = "🛡️ " + $title
            $cardAlert.Controls.Add($lblAlertTitle)

            $lblAlertSub = New-Object System.Windows.Forms.Label
            $lblAlertSub.Dock = [System.Windows.Forms.DockStyle]::Fill
            $lblAlertSub.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
            $lblAlertSub.ForeColor = [System.Drawing.Color]::FromArgb(185, 28, 28)
            $lblAlertSub.Text = "操作命中安全防护规则。请仔细检查下方即将执行的代码与命令参数。"
            $cardAlert.Controls.Add($lblAlertSub)
            $lblAlertTitle.BringToFront()

            # 2. 底部现代化状态栏与吸附按钮 (Dock = Bottom)
            $pnlBottom = New-Object System.Windows.Forms.Panel
            $pnlBottom.Dock = [System.Windows.Forms.DockStyle]::Bottom
            $pnlBottom.Height = 68
            $pnlBottom.Padding = New-Object System.Windows.Forms.Padding(18, 10, 18, 14)
            $form.Controls.Add($pnlBottom)

            # 底部右侧现代化大按钮容器
            $pnlButtons = New-Object System.Windows.Forms.Panel
            $pnlButtons.Dock = [System.Windows.Forms.DockStyle]::Right
            $pnlButtons.Width = 250
            $pnlBottom.Controls.Add($pnlButtons)

            # 【允许执行】按钮 - 现代翠绿扁平风格
            $btnAllow = New-Object System.Windows.Forms.Button
            $btnAllow.Location = New-Object System.Drawing.Point(10, 4)
            $btnAllow.Size = New-Object System.Drawing.Size(110, 38)
            $btnAllow.Text = "允许执行"
            $btnAllow.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
            $btnAllow.ForeColor = [System.Drawing.Color]::White
            $btnAllow.BackColor = [System.Drawing.Color]::FromArgb(16, 185, 129)
            $btnAllow.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btnAllow.FlatAppearance.BorderSize = 0
            $btnAllow.Cursor = [System.Windows.Forms.Cursors]::Hand
            $btnAllow.DialogResult = [System.Windows.Forms.DialogResult]::Yes
            $pnlButtons.Controls.Add($btnAllow)

            # 【拒绝执行】按钮 - 现代柔红扁平风格
            $btnDeny = New-Object System.Windows.Forms.Button
            $btnDeny.Location = New-Object System.Drawing.Point(130, 4)
            $btnDeny.Size = New-Object System.Drawing.Size(110, 38)
            $btnDeny.Text = "拒绝执行"
            $btnDeny.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
            $btnDeny.ForeColor = [System.Drawing.Color]::White
            $btnDeny.BackColor = [System.Drawing.Color]::FromArgb(239, 68, 68)
            $btnDeny.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            $btnDeny.FlatAppearance.BorderSize = 0
            $btnDeny.Cursor = [System.Windows.Forms.Cursors]::Hand
            $btnDeny.DialogResult = [System.Windows.Forms.DialogResult]::No
            $pnlButtons.Controls.Add($btnDeny)
            $form.CancelButton = $btnDeny

            # 底部左侧倒计时胶囊标签
            $lblCountdown = New-Object System.Windows.Forms.Label
            $lblCountdown.Dock = [System.Windows.Forms.DockStyle]::Fill
            $lblCountdown.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
            $lblCountdown.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
            $lblCountdown.ForeColor = [System.Drawing.Color]::FromArgb(71, 85, 105)
            $lblCountdown.Text = "⏱️ 剩余确认时间：" + $to + " 秒（超时自动拒绝）"
            $pnlBottom.Controls.Add($lblCountdown)
            $pnlButtons.BringToFront()

            # 3. 中间代码展示卡片 (VS Code 暗色风格，支持水平和垂直滚动条)
            $pnlMiddle = New-Object System.Windows.Forms.Panel
            $pnlMiddle.Dock = [System.Windows.Forms.DockStyle]::Fill
            $pnlMiddle.Padding = New-Object System.Windows.Forms.Padding(18, 0, 18, 0)
            $form.Controls.Add($pnlMiddle)

            $txtCode = New-Object System.Windows.Forms.TextBox
            $txtCode.Dock = [System.Windows.Forms.DockStyle]::Fill
            $txtCode.Multiline = $true
            $txtCode.ReadOnly = $true
            $txtCode.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
            $txtCode.WordWrap = $false
            $txtCode.Font = New-Object System.Drawing.Font("Consolas", 10)
            $txtCode.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 46)
            $txtCode.ForeColor = [System.Drawing.Color]::FromArgb(205, 214, 244)
            $txtCode.BorderStyle = [System.Windows.Forms.BorderStyle]::None
            $txtCode.Text = $body
            $pnlMiddle.Controls.Add($txtCode)

            # 4. 实时动态秒级倒计时与自动销毁
            $script:timeLeft = $to
            $timer = New-Object System.Windows.Forms.Timer
            $timer.Interval = 1000
            $timer.Add_Tick({
                $script:timeLeft--
                $lblCountdown.Text = "⏱️ 剩余确认时间：" + $script:timeLeft + " 秒（超时自动拒绝）"
                if ($script:timeLeft -le 0) {
                    $timer.Stop()
                    $form.DialogResult = [System.Windows.Forms.DialogResult]::No
                    $form.Close()
                }
            })
            $timer.Start()

            $res = $form.ShowDialog()
            $timer.Stop()
            if ($res -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }
        "#;

        let status = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(ps_script)
            .env("HOOK_GUI_TITLE", title)
            .env("HOOK_GUI_BODY", body)
            .env("HOOK_GUI_TIMEOUT", timeout_sec.to_string())
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
