use std::process::Command;

pub struct GuiDialog;

impl GuiDialog {
    /// Prompts the user with a system-level GUI dialog.
    /// Returns true if the user clicks "Allow", false on "Deny" or timeout.
    pub fn confirm(title: &str, body: &str, timeout_sec: u32) -> bool {
        // 1. Check CI / headless test mode
        if std::env::var("HOOK_NO_GUI").is_ok()
            || std::env::var("CI").is_ok()
            || std::env::var("HOOK_TEST_MODE").is_ok()
        {
            return false;
        }

        // 2. Windows GUI dialog
        #[cfg(target_os = "windows")]
        {
            return Self::prompt_windows(title, body, timeout_sec);
        }

        // 3. macOS GUI dialog
        #[cfg(target_os = "macos")]
        {
            return Self::prompt_macos(title, body, timeout_sec);
        }

        // 4. Linux GUI dialog
        #[cfg(target_os = "linux")]
        {
            return Self::prompt_linux(title, body, timeout_sec);
        }

        #[allow(unreachable_code)]
        false
    }

    #[cfg(target_os = "windows")]
    fn prompt_windows(title: &str, body: &str, timeout_sec: u32) -> bool {
        let ps_script = r#"
            Add-Type -AssemblyName System.Windows.Forms, System.Drawing
            $title = if ($env:HOOK_GUI_TITLE) { $env:HOOK_GUI_TITLE } else { "安全门禁权限确认" }
            $body = if ($env:HOOK_GUI_BODY) { $env:HOOK_GUI_BODY } else { "未知命令" }
            $to = if ($env:HOOK_GUI_TIMEOUT) { [int]$env:HOOK_GUI_TIMEOUT } else { 60 }

            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Antigravity 安全门禁确认"
            $form.Size = New-Object System.Drawing.Size(650, 420)
            $form.MinimumSize = New-Object System.Drawing.Size(520, 320)
            $form.StartPosition = "CenterScreen"
            $form.TopMost = $true
            $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

            # 顶部提示区
            $pnlTop = New-Object System.Windows.Forms.Panel
            $pnlTop.Dock = [System.Windows.Forms.DockStyle]::Top
            $pnlTop.Height = 55
            $pnlTop.Padding = New-Object System.Windows.Forms.Padding(15, 10, 15, 5)

            $lblDesc = New-Object System.Windows.Forms.Label
            $lblDesc.Dock = [System.Windows.Forms.DockStyle]::Fill
            $lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
            $lblDesc.ForeColor = [System.Drawing.Color]::FromArgb(190, 40, 40)
            $lblDesc.Text = $title
            $pnlTop.Controls.Add($lblDesc)
            $form.Controls.Add($pnlTop)

            # 底部吸附面板 (Dock = Bottom)
            $pnlBottom = New-Object System.Windows.Forms.Panel
            $pnlBottom.Dock = [System.Windows.Forms.DockStyle]::Bottom
            $pnlBottom.Height = 65
            $form.Controls.Add($pnlBottom)

            # 底部右侧固定按钮容器 (宽 240px，绝对坐标排布)
            $pnlBtn = New-Object System.Windows.Forms.Panel
            $pnlBtn.Dock = [System.Windows.Forms.DockStyle]::Right
            $pnlBtn.Width = 240
            $pnlBottom.Controls.Add($pnlBtn)

            $btnYes = New-Object System.Windows.Forms.Button
            $btnYes.Location = New-Object System.Drawing.Point(10, 14)
            $btnYes.Size = New-Object System.Drawing.Size(100, 36)
            $btnYes.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
            $btnYes.Text = "允许"
            $btnYes.DialogResult = [System.Windows.Forms.DialogResult]::Yes
            $pnlBtn.Controls.Add($btnYes)

            $btnNo = New-Object System.Windows.Forms.Button
            $btnNo.Location = New-Object System.Drawing.Point(120, 14)
            $btnNo.Size = New-Object System.Drawing.Size(100, 36)
            $btnNo.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
            $btnNo.Text = "拒绝"
            $btnNo.DialogResult = [System.Windows.Forms.DialogResult]::No
            $pnlBtn.Controls.Add($btnNo)
            $form.CancelButton = $btnNo

            # 底部左侧倒计时
            $lblCountdown = New-Object System.Windows.Forms.Label
            $lblCountdown.Dock = [System.Windows.Forms.DockStyle]::Fill
            $lblCountdown.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
            $lblCountdown.ForeColor = [System.Drawing.Color]::FromArgb(180, 50, 50)
            $lblCountdown.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
            $lblCountdown.Padding = New-Object System.Windows.Forms.Padding(15, 0, 0, 0)
            $lblCountdown.Text = "⏱️ 剩余确认时间：" + $to + " 秒（超时自动拒绝）"
            $pnlBottom.Controls.Add($lblCountdown)
            $pnlBtn.BringToFront()

            # 中间区域：命令文本
            $pnlMiddle = New-Object System.Windows.Forms.Panel
            $pnlMiddle.Dock = [System.Windows.Forms.DockStyle]::Fill
            $pnlMiddle.Padding = New-Object System.Windows.Forms.Padding(15, 0, 15, 0)

            $txtBody = New-Object System.Windows.Forms.TextBox
            $txtBody.Dock = [System.Windows.Forms.DockStyle]::Fill
            $txtBody.Multiline = $true
            $txtBody.ReadOnly = $true
            $txtBody.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
            $txtBody.WordWrap = $false
            $txtBody.Font = New-Object System.Drawing.Font("Consolas", 9.5)
            $txtBody.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 250)
            $txtBody.Text = $body
            $pnlMiddle.Controls.Add($txtBody)
            $form.Controls.Add($pnlMiddle)

            # 实时倒计时
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

            $result = $form.ShowDialog()
            $timer.Stop()
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }
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
    fn prompt_macos(title: &str, body: &str, timeout_sec: u32) -> bool {
        let clean_title = title.replace('"', "\\\"");
        let clean_body = body.replace('"', "\\\"");
        let script = format!(
            "display dialog \"{}\\n\\n即将执行：\\n{}\\n\\n({} 秒内无响应将自动拒绝)\" with title \"安全门禁确认\" buttons {{\"拒绝\", \"允许\"}} default button \"拒绝\" with icon caution giving up after {}",
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
    fn prompt_linux(title: &str, body: &str, timeout_sec: u32) -> bool {
        // Try zenity first, then kdialog
        let status = Command::new("zenity")
            .arg("--question")
            .arg(format!("--title=安全门禁确认: {}", title))
            .arg(format!("--text=即将执行：\n\n{}\n\n是否授权继续执行？\n({} 秒内无响应将自动拒绝)", body, timeout_sec))
            .arg(format!("--timeout={}", timeout_sec))
            .arg("--default-cancel")
            .status();

        if let Ok(s) = status {
            return s.success();
        }

        let kdialog_status = Command::new("kdialog")
            .arg("--title")
            .arg("安全门禁确认")
            .arg("--yesno")
            .arg(format!("即将执行：\n\n{}\n\n是否授权继续执行？", body))
            .status();

        match kdialog_status {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }
}
