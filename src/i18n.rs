//! Lightweight locale detection for natural-language output (UI dialogs,
//! deny reasons, errors, logs, install/update messages, tutorial default).
//!
//! Detection order:
//! 1. `AI_HOOK_LANG=zh|en` explicit override (also accepted: `zh-CN`, `en_US`);
//! 2. Host locale env vars (`LC_ALL`, `LANG`, `LANGUAGE`): any `zh*` value
//!    selects Chinese, anything else falls through to English;
//! 3. Windows user locale from the registry (HKCU\Control Panel\International);
//! 4. Default: English (the safe international default).
//!
//! Detection is cached in a OnceLock and only ever runs on paths that emit
//! natural-language text — the pure fast path never pays for it.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

impl Lang {
    pub fn is_zh(self) -> bool {
        matches!(self, Lang::Zh)
    }

    /// Picks the localized string for this language.
    pub fn pick<'a>(self, zh: &'a str, en: &'a str) -> &'a str {
        if self.is_zh() { zh } else { en }
    }

    /// Formats a localized message for values that differ between languages.
    pub fn pick_fmt(self, zh: &str, en: &str, args: &[&dyn std::fmt::Display]) -> String {
        let template = self.pick(zh, en);
        let mut out = String::new();
        let mut rest = template;
        for arg in args {
            match rest.split_once("{}") {
                Some((head, tail)) => {
                    out.push_str(head);
                    out.push_str(&arg.to_string());
                    rest = tail;
                }
                None => break,
            }
        }
        out.push_str(rest);
        out
    }
}

pub fn lang() -> Lang {
    static LANG: OnceLock<Lang> = OnceLock::new();
    *LANG.get_or_init(detect)
}

fn parse_env_lang(value: &str) -> Option<Lang> {
    let v = value.trim().to_ascii_lowercase();
    if v.is_empty() {
        return None;
    }
    if v == "zh" || v.starts_with("zh-") || v.starts_with("zh_") || v == "chs" {
        return Some(Lang::Zh);
    }
    if v == "en" || v.starts_with("en-") || v.starts_with("en_") {
        return Some(Lang::En);
    }
    None
}

fn detect() -> Lang {
    // 1. Explicit override.
    if let Ok(v) = std::env::var("AI_HOOK_LANG") {
        if let Some(l) = parse_env_lang(&v) {
            return l;
        }
    }

    // 2. Host locale environment variables. Only an explicit Chinese locale
    //    forces Chinese; any other locale falls back to English defaults.
    for var in ["LC_ALL", "LANG", "LANGUAGE"] {
        if let Ok(v) = std::env::var(var) {
            if v.to_ascii_lowercase().starts_with("zh") {
                return Lang::Zh;
            }
        }
    }

    // 3. Windows user locale (registry read is ~ms; this only runs once).
    #[cfg(windows)]
    {
        if windows_user_locale_is_chinese() {
            return Lang::Zh;
        }
    }

    Lang::En
}

/// Reads HKCU\Control Panel\International\LocaleName (e.g. "zh-CN") or the
/// legacy hex LCID value "Locale" (e.g. "00000804").
#[cfg(windows)]
fn windows_user_locale_is_chinese() -> bool {
    use std::process::Command;

    let locale_name = Command::new("reg")
        .args([
            "query",
            r"HKCU\Control Panel\International",
            "/v",
            "LocaleName",
        ])
        .output();
    if let Ok(out) = locale_name {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("zh-") {
            return true;
        }
        // A definitely non-Chinese locale name means we can stop early.
        if text.contains("REG_SZ") && !text.to_ascii_lowercase().contains("zh") {
            return false;
        }
    }

    // Legacy LCID: zh-CN 0x0804, zh-TW 0x0404, zh-HK 0x0C04, zh-SG 0x1004,
    // zh-MO 0x1404.
    let locale = Command::new("reg")
        .args(["query", r"HKCU\Control Panel\International", "/v", "Locale"])
        .output();
    if let Ok(out) = locale {
        let text = String::from_utf8_lossy(&out.stdout);
        for lcid in ["00000804", "00000404", "00000c04", "00001004", "00001404"] {
            if text.contains(lcid) {
                return true;
            }
        }
    }
    false
}

// ================= GENERATED LANGUAGE TABLE =================
/// Central message catalog: every user-visible string lives here.
/// One variant per message; zh/en columns in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg {
    M000,
    M001,
    M002,
    M003,
    M004,
    M005,
    M006,
    M007,
    M008,
    M009,
    M010,
    M011,
    M012,
    M013,
    M014,
    M015,
    M016,
    M017,
    M018,
    M019,
    M020,
    M021,
    M022,
    M023,
    M024,
    M025,
    M026,
    M027,
    M028,
    M029,
    M030,
    M031,
    M032,
    M033,
    M034,
    M035,
    M036,
    M037,
    M038,
    M039,
    M040,
    M041,
    M042,
    M043,
    M044,
    M045,
    M046,
    M047,
    M048,
    M049,
    M050,
    M051,
    M052,
    M053,
    M054,
    M055,
    M056,
    M057,
    M058,
    M059,
    M060,
    M061,
    M062,
    M063,
    M064,
    M065,
    M066,
    M067,
    M068,
    M069,
    M070,
    M071,
    M072,
    M073,
    M074,
    M075,
    M076,
    M077,
    M078,
    M079,
    M080,
    M081,
    M082,
    M083,
    M084,
    M085,
    M086,
    M087,
    M088,
    M089,
    M090,
    M091,
    M092,
    M093,
    M094,
    M095,
    M096,
    M097,
    M098,
    M099,
    M100,
    M101,
    M102,
    M103,
    M104,
    /// Dialog allow-button word.
    AllowWord,
    /// Dialog deny-button word.
    DenyWord,
}

impl Msg {
    pub fn text(self, l: Lang) -> &'static str {
        match self {
            Msg::M000 => match l {
                Lang::Zh => {
                    "[ai-hook] 规则返回了 Promise(async 规则不受支持)。请把默认导出改为同步函数 (export default function(ctx, sys) {...})。检测到 Promise 时本规则已被按错误处理。"
                }
                Lang::En => {
                    "[ai-hook] Rule returned a Promise (async rules are not supported). Please export a synchronous function instead (export default function(ctx, sys) {...}). This rule is treated as failed."
                }
            },
            Msg::M001 => match l {
                Lang::Zh => "创建 JS 执行上下文失败: {}",
                Lang::En => "Failed to create JS execution context: {}",
            },
            Msg::M002 => match l {
                Lang::Zh => "规则 {} 返回了 false",
                Lang::En => "Rule {} returned false",
            },
            Msg::M003 => match l {
                Lang::Zh => "规则执行超时(超过 {});请检查规则内是否存在死循环",
                Lang::En => {
                    "Rule execution timed out (over {}); check the rule for an infinite loop"
                }
            },
            Msg::M004 => match l {
                Lang::Zh => "【规则引擎异常】规则 '{}' 执行失败,已按拒绝处理(不会静默放行):\\ n{}",
                Lang::En => {
                    "[Rule engine failure] Rule '{}' failed and the operation was DENIED (fail-closed; a broken rule never silently allows):\\ n{}"
                }
            },
            Msg::M005 => match l {
                Lang::Zh => "【安全门禁已拒绝】用户在弹窗中选择拒绝或倒计时超时:",
                Lang::En => {
                    "[Security gate] Rejected by the user in the dialog, or the countdown timed out:"
                }
            },
            Msg::M006 => match l {
                Lang::Zh => "命令",
                Lang::En => "Command",
            },
            Msg::M007 => match l {
                Lang::Zh => "即将执行",
                Lang::En => "About to run",
            },
            Msg::M008 => match l {
                Lang::Zh => "【硬阻断】免确认模式下未获得授权。请在终端手动执行:",
                Lang::En => {
                    "[Hard block] Not authorized in skip-confirmation (YOLO) mode. Please run manually in your terminal:"
                }
            },
            Msg::M009 => match l {
                Lang::Zh => "【硬阻断】用户拒绝或 Codex PreToolUse 不支持交互式确认。命令:",
                Lang::En => {
                    "[Hard block] Rejected by the user, or Codex PreToolUse does not support interactive confirmation."
                }
            },
            Msg::M010 => match l {
                Lang::Zh => "原因",
                Lang::En => "Reason",
            },
            Msg::M011 => match l {
                Lang::Zh => "安全门禁授权",
                Lang::En => "Security Gate",
            },
            Msg::M012 => match l {
                Lang::Zh => "是否授权继续执行？",
                Lang::En => "Authorize this operation?",
            },
            Msg::M013 => match l {
                Lang::Zh => "({} 秒内无响应将自动拒绝)",
                Lang::En => "(auto-deny after {}s with no response)",
            },
            Msg::M014 => match l {
                Lang::Zh => "不支持的平台或 CPU 架构: {} - {}。请从源码编译。",
                Lang::En => {
                    "Unsupported OS or CPU architecture: {} - {}. Please compile from source."
                }
            },
            Msg::M015 => match l {
                Lang::Zh => "正在检查 GitHub 上的最新版本:",
                Lang::En => "Checking for latest release from",
            },
            Msg::M016 => match l {
                Lang::Zh => "仓库 '{}' 中未找到已发布的 Release(HTTP 404)。",
                Lang::En => "No published releases found for repository '{}' (HTTP 404).",
            },
            Msg::M017 => match l {
                Lang::Zh => {
                    "GitHub API 访问受限或被禁止(HTTP 403)。可设置 GITHUB_TOKEN 环境变量后重试。"
                }
                Lang::En => {
                    "GitHub API rate limit exceeded or forbidden (HTTP 403). Try setting the GITHUB_TOKEN environment variable."
                }
            },
            Msg::M018 => match l {
                Lang::Zh => "查询 GitHub Release API 失败: {}",
                Lang::En => "Failed to query GitHub release API: {}",
            },
            Msg::M019 => match l {
                Lang::Zh => "解析 GitHub Release JSON 失败: {}",
                Lang::En => "Failed to parse GitHub release JSON: {}",
            },
            Msg::M020 => match l {
                Lang::Zh => "GitHub 响应中缺少 release 的 tag_name 字段",
                Lang::En => "Release tag_name is missing from GitHub response",
            },
            Msg::M021 => match l {
                Lang::Zh => "当前版本",
                Lang::En => "Current version",
            },
            Msg::M022 => match l {
                Lang::Zh => "最新版本",
                Lang::En => "Latest version",
            },
            Msg::M023 => match l {
                Lang::Zh => "ai-hook 已是最新版本",
                Lang::En => "ai-hook is already up to date",
            },
            Msg::M024 => match l {
                Lang::Zh => "最新 Release 中未找到任何发布资产",
                Lang::En => "No release assets found in the latest release",
            },
            Msg::M025 => match l {
                Lang::Zh => {
                    "在 Release {} 中未找到匹配的二进制或归档文件。候选: {:?}。该 Release 中可用的文件: [{}]"
                }
                Lang::En => {
                    "No matching binary or archive was found in release {}. Candidates: {:?}. Available in release: [{}]"
                }
            },
            Msg::M026 => match l {
                Lang::Zh => "发布资产缺少 browser_download_url 字段",
                Lang::En => "Asset browser_download_url is missing",
            },
            Msg::M027 => match l {
                Lang::Zh => "正在从 {} 下载 ...",
                Lang::En => "Downloading {} ...",
            },
            Msg::M028 => match l {
                Lang::Zh => "下载发布资产失败: {}",
                Lang::En => "Failed to download release asset: {}",
            },
            Msg::M029 => match l {
                Lang::Zh => "读取下载内容失败: {}",
                Lang::En => "Failed to read downloaded asset: {}",
            },
            Msg::M030 => match l {
                Lang::Zh => "下载内容超过 {} MB 安全上限,已中止更新。",
                Lang::En => "Downloaded asset exceeds the {} MB safety cap; aborting update.",
            },
            Msg::M031 => match l {
                Lang::Zh => "已下载",
                Lang::En => "Downloaded",
            },
            Msg::M032 => match l {
                Lang::Zh => "压缩包,正在解压",
                Lang::En => "archive). Extracting",
            },
            Msg::M033 => match l {
                Lang::Zh => "解析 zip 压缩包失败: {}",
                Lang::En => "Failed to parse zip archive: {}",
            },
            Msg::M034 => match l {
                Lang::Zh => "读取 zip 条目失败: {}",
                Lang::En => "Failed to read zip entry: {}",
            },
            Msg::M035 => match l {
                Lang::Zh => "创建临时输出文件失败: {}",
                Lang::En => "Failed to create temporary output file: {}",
            },
            Msg::M036 => match l {
                Lang::Zh => "解压文件失败: {}",
                Lang::En => "Failed to extract file: {}",
            },
            Msg::M037 => match l {
                Lang::Zh => "在 zip 压缩包中未找到二进制文件 '{}'",
                Lang::En => "Binary '{}' was not found inside the zip archive",
            },
            Msg::M038 => match l {
                Lang::Zh => "读取 tar 条目失败: {}",
                Lang::En => "Failed to read tar entries: {}",
            },
            Msg::M039 => match l {
                Lang::Zh => "检查 tar 条目失败: {}",
                Lang::En => "Failed to inspect tar entry: {}",
            },
            Msg::M040 => match l {
                Lang::Zh => "tar 路径无效: {}",
                Lang::En => "Invalid tar path: {}",
            },
            Msg::M041 => match l {
                Lang::Zh => "解压 tar 条目失败: {}",
                Lang::En => "Failed to unpack tar entry: {}",
            },
            Msg::M042 => match l {
                Lang::Zh => "在 tar.gz 压缩包中未找到二进制文件 '{}'",
                Lang::En => "Binary '{}' was not found inside the tar.gz archive",
            },
            Msg::M043 => match l {
                Lang::Zh => "裸可执行文件",
                Lang::En => "raw executable",
            },
            Msg::M044 => match l {
                Lang::Zh => "写入临时文件失败: {}",
                Lang::En => "Failed to write binary to temporary file: {}",
            },
            Msg::M045 => match l {
                Lang::Zh => "正在校验下载的可执行文件",
                Lang::En => "Verifying downloaded executable",
            },
            Msg::M046 => match l {
                Lang::Zh => {
                    "下载的临时可执行文件自检失败 (--version 无法运行)。已中止更新以避免损坏当前安装。请稍后重试,或手动下载安装。"
                }
                Lang::En => {
                    "The downloaded executable failed its self-check (--version did not run). Update aborted to avoid corrupting the current installation. Please retry later or download manually."
                }
            },
            Msg::M047 => match l {
                Lang::Zh => "正在原子替换当前可执行文件",
                Lang::En => "Applying self-replacement to executable",
            },
            Msg::M048 => match l {
                Lang::Zh => "自我替换失败: {}",
                Lang::En => "Self-replacement failed: {}",
            },
            Msg::M049 => match l {
                Lang::Zh => "ai-hook 已成功更新到",
                Lang::En => "Successfully updated ai-hook to",
            },
            Msg::M050 => match l {
                Lang::Zh => "可执行文件",
                Lang::En => "Binary",
            },
            Msg::M051 => match l {
                Lang::Zh => "二进制位置",
                Lang::En => "Binary Location",
            },
            Msg::M052 => match l {
                Lang::Zh => "可执行文件",
                Lang::En => "Executable",
            },
            Msg::M053 => match l {
                Lang::Zh => "所在目录",
                Lang::En => "Directory",
            },
            Msg::M054 => match l {
                Lang::Zh => "错误",
                Lang::En => "Error",
            },
            Msg::M055 => match l {
                Lang::Zh => "警告:读取 stdin 输入失败",
                Lang::En => "Warning: failed to read stdin payload",
            },
            Msg::M056 => match l {
                Lang::Zh => "JS 运行时初始化失败",
                Lang::En => "Failed to initialize JS runtime",
            },
            Msg::M057 => match l {
                Lang::Zh => "【规则引擎不可用】无法启动 JS 运行时,操作已被拒绝(不会静默放行)。",
                Lang::En => {
                    "[Rule engine unavailable] Failed to start the JS runtime; the operation was DENIED (fail-closed)."
                }
            },
            Msg::M058 => match l {
                Lang::Zh => "操作安全授权确认",
                Lang::En => "Security Authorization Required",
            },
            Msg::M059 => match l {
                Lang::Zh => "规则评估期间发生内部崩溃,操作已拒绝",
                Lang::En => "Internal panic during rule evaluation; denying operation",
            },
            Msg::M060 => match l {
                Lang::Zh => {
                    "【ai-hook 内部错误】规则引擎执行时发生内部崩溃,操作已被拒绝。请检查规则脚本是否为有效同步 JavaScript。"
                }
                Lang::En => {
                    "[ai-hook internal error] The rule engine crashed during evaluation; the operation was DENIED. Please check that the rule scripts are valid synchronous JavaScript."
                }
            },
            Msg::M061 => match l {
                Lang::Zh => "ai-hook 目标规则",
                Lang::En => "ai-hook Target Rules",
            },
            Msg::M062 => match l {
                Lang::Zh => "共",
                Lang::En => "Total",
            },
            Msg::M063 => match l {
                Lang::Zh => "未指定有效的规则脚本。",
                Lang::En => "No active rule scripts specified.",
            },
            Msg::M064 => match l {
                Lang::Zh => "请显式传入规则文件",
                Lang::En => "Pass script files explicitly",
            },
            Msg::M065 => match l {
                Lang::Zh => "或将规则放入项目目录",
                Lang::En => "Or place in project directory",
            },
            Msg::M066 => match l {
                Lang::Zh => "正在使用指定规则评估目标命令",
                Lang::En => "Testing command against specified security rules",
            },
            Msg::M067 => match l {
                Lang::Zh => "目标命令",
                Lang::En => "Target Command",
            },
            Msg::M068 => match l {
                Lang::Zh => "目标工具",
                Lang::En => "Target Tool",
            },
            Msg::M069 => match l {
                Lang::Zh => "目标文件",
                Lang::En => "Target File",
            },
            Msg::M070 => match l {
                Lang::Zh => "快速通道命中,耗时",
                Lang::En => "Fast Path Matched in",
            },
            Msg::M071 => match l {
                Lang::Zh => "最终决策",
                Lang::En => "Final Decision",
            },
            Msg::M072 => match l {
                Lang::Zh => "未提供用于测试的规则脚本。",
                Lang::En => "No rule scripts provided to test against.",
            },
            Msg::M073 => match l {
                Lang::Zh => "用法",
                Lang::En => "Usage",
            },
            Msg::M074 => match l {
                Lang::Zh => "初始化规则引擎失败",
                Lang::En => "Error initializing runner",
            },
            Msg::M075 => match l {
                Lang::Zh => "⚠️ 需确认",
                Lang::En => "⚠️ CONFIRM",
            },
            Msg::M076 => match l {
                Lang::Zh => "🛑 拒绝",
                Lang::En => "🛑 DENY",
            },
            Msg::M077 => match l {
                Lang::Zh => "✅ 放行",
                Lang::En => "✅ ALLOW",
            },
            Msg::M078 => match l {
                Lang::Zh => "◽ 跳过",
                Lang::En => "◽ PASS",
            },
            Msg::M079 => match l {
                Lang::Zh => "错误",
                Lang::En => "ERROR",
            },
            Msg::M080 => match l {
                Lang::Zh => "总耗时",
                Lang::En => "Total Duration",
            },
            Msg::M081 => match l {
                Lang::Zh => "开始压测",
                Lang::En => "Running benchmark",
            },
            Msg::M082 => match l {
                Lang::Zh => "共",
                Lang::En => "for",
            },
            Msg::M083 => match l {
                Lang::Zh => "次迭代,命令",
                Lang::En => "iterations on",
            },
            Msg::M084 => match l {
                Lang::Zh => "未提供用于压测的规则脚本。",
                Lang::En => "No rule scripts provided to benchmark.",
            },
            Msg::M085 => match l {
                Lang::Zh => "规则引擎初始化失败",
                Lang::En => "Runner init error",
            },
            Msg::M086 => match l {
                Lang::Zh => "目标规则",
                Lang::En => "Target Rules",
            },
            Msg::M087 => match l {
                Lang::Zh => "个脚本",
                Lang::En => "scripts",
            },
            Msg::M088 => match l {
                Lang::Zh => "总耗时",
                Lang::En => "Total Time",
            },
            Msg::M089 => match l {
                Lang::Zh => "迭代次数",
                Lang::En => "Iterations",
            },
            Msg::M090 => match l {
                Lang::Zh => "平均耗时",
                Lang::En => "Average",
            },
            Msg::M091 => match l {
                Lang::Zh => "每次执行",
                Lang::En => "per execution",
            },
            Msg::M092 => match l {
                Lang::Zh => "无法获取当前可执行文件路径",
                Lang::En => "Failed to get current executable path",
            },
            Msg::M093 => match l {
                Lang::Zh => "复制可执行文件到",
                Lang::En => "Failed to copy binary to",
            },
            Msg::M094 => match l {
                Lang::Zh => {
                    "提示:目标文件可能被正在运行的实例占用。请先关闭正在运行的 ai-hook/终端会话后重试,或使用 --target-dir 选择其它目录。"
                }
                Lang::En => {
                    "Hint: the target file may be locked by a running instance. Close any running ai-hook/terminal session and retry, or pick another directory with --target-dir."
                }
            },
            Msg::M095 => match l {
                Lang::Zh => "复制校验失败,大小不一致",
                Lang::En => "Failed to verify copied binary at",
            },
            Msg::M096 => match l {
                Lang::Zh => "已移除目标文件",
                Lang::En => "size mismatch",
            },
            Msg::M097 => match l {
                Lang::Zh => "✨ ai-hook 已成功安装到",
                Lang::En => "✨ Successfully installed ai-hook to",
            },
            Msg::M098 => match l {
                Lang::Zh => "✨ ai-hook 已位于",
                Lang::En => "✨ ai-hook is already located at",
            },
            Msg::M099 => match l {
                Lang::Zh => "全局命令已就绪!",
                Lang::En => "Global command ready!",
            },
            Msg::M100 => match l {
                Lang::Zh => "已在你的 PATH 中",
                Lang::En => "is already in your PATH",
            },
            Msg::M101 => match l {
                Lang::Zh => "未新增任何环境变量。你现在可以在任意终端直接运行 'ai-hook'。",
                Lang::En => {
                    "Zero extra environment variables added. You can run 'ai-hook' directly from any terminal."
                }
            },
            Msg::M102 => match l {
                Lang::Zh => "提示:",
                Lang::En => "Notice:",
            },
            Msg::M103 => match l {
                Lang::Zh => "当前不在你的 PATH 中",
                Lang::En => "is not currently present in your PATH",
            },
            Msg::M104 => match l {
                Lang::Zh => "如需使用且不修改 PATH,可用绝对路径运行",
                Lang::En => "To use without modifying PATH, you can run by absolute path",
            },
            Msg::AllowWord => match l {
                Lang::Zh => "允许",
                Lang::En => "Allow",
            },
            Msg::DenyWord => match l {
                Lang::Zh => "拒绝",
                Lang::En => "Deny",
            },
        }
    }
}

/// Current-language lookup for a message key.
pub fn t(msg: Msg) -> &'static str {
    msg.text(lang())
}
// ================= END GENERATED =================

/// Fills `{}` placeholders of a message template with display args
/// (dynamic templates cannot use format!, so placeholders are substituted
/// in order; excess args are ignored, missing placeholders are left as-is).
pub fn tf(msg: Msg, args: &[&dyn std::fmt::Display]) -> String {
    let template = msg.text(lang());
    let mut out = String::new();
    let mut rest = template;
    for arg in args {
        match rest.split_once("{}") {
            Some((head, tail)) => {
                out.push_str(head);
                out.push_str(&arg.to_string());
                rest = tail;
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}
