pub mod input;
pub mod output;

pub use input::{ConversationInfo, FileAction, FileContext, HookContext, Platform, env_flag_true};
pub use output::HookDecision;

/// 规则 confirm 决策在「宿主协议 ask」与「GUI 弹窗」之间的通道选择结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmPath {
    /// 弹系统置顶 GUI 窗(强制弹窗或「宿主不能 ask」的兜底)。
    Popup,
    /// 直接走宿主协议 ask:CC/CB 的 ask、Codex 0.152+ 普通模式的 ask、
    /// AGY 普通交互模式的 force_ask。
    Ask,
    /// 宿主不能 ask 且不弹窗 → fail-closed 自动拒绝。
    AutoDeny,
}

/// gui 字段三态语义(2026-09-05 约定,与 ai-hook tutorial 宿主矩阵配套):
///
/// | 规则 gui | 宿主能 ask | 宿主不能 ask |
/// |---|---|---|
/// | `true` / force_gui | 强制 Popup(穿透 --no-gui,仅 dry-run 除外) | 同左 |
/// | 缺省(不配置) | Ask,不弹窗 | GUI 可用则 Popup 兜底;不可用 AutoDeny |
/// | `false` | Ask,不弹窗 | AutoDeny(规则禁弹窗 → fail-closed) |
///
/// `forced` 由 CLI `--force-gui` / 环境 `AI_HOOK_FORCE_GUI` / 规则 `force_gui: true`
/// 汇聚而来;`gui: true` 与 force_gui 同级不可禁(2026-09-05 用户拍板)。
#[must_use]
pub fn confirm_path(
    gui: Option<bool>,
    forced: bool,
    ask_ok: bool,
    gui_enabled: bool,
    dry_run: bool,
) -> ConfirmPath {
    if forced || gui == Some(true) {
        // 强制弹窗:穿透 --no-gui / AI_HOOK_GUI=0 / CI 等开关;仅 dry-run 演练不真弹
        if dry_run {
            ConfirmPath::Ask
        } else {
            ConfirmPath::Popup
        }
    } else if gui == Some(false) {
        // 规则禁弹窗:能 ask 走 ask;不能 ask 直接拒绝
        if ask_ok {
            ConfirmPath::Ask
        } else {
            ConfirmPath::AutoDeny
        }
    } else if ask_ok {
        // 缺省 + 宿主能 ask:直接走协议 ask,不弹窗
        ConfirmPath::Ask
    } else if gui_enabled && !dry_run {
        // 缺省 + 宿主不能 ask:GUI 弹窗兜底
        ConfirmPath::Popup
    } else {
        // 缺省 + 宿主不能 ask + GUI 不可用(CI/--no-gui/测试):自动拒绝
        ConfirmPath::AutoDeny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confirm_path_gui_true_is_forced_popup() {
        // gui:true 强制弹窗:能 ask 也弹、穿透 gui_enabled=false
        assert_eq!(
            confirm_path(Some(true), false, true, true, false),
            ConfirmPath::Popup
        );
        assert_eq!(
            confirm_path(Some(true), false, false, false, false),
            ConfirmPath::Popup
        );
        // force_gui / CLI force 与 gui:true 同级
        assert_eq!(
            confirm_path(Some(false), true, false, false, false),
            ConfirmPath::Popup
        );
        assert_eq!(
            confirm_path(None, true, true, false, false),
            ConfirmPath::Popup
        );
        // dry-run 演练不真弹 → 降级 Ask(输出层按宿主协议演练)
        assert_eq!(
            confirm_path(Some(true), false, true, true, true),
            ConfirmPath::Ask
        );
        assert_eq!(
            confirm_path(Some(true), true, false, false, true),
            ConfirmPath::Ask
        );
    }

    #[test]
    fn test_confirm_path_default_ask_first_gui_fallback() {
        // 缺省 + 能 ask:一律 Ask(不弹窗)
        assert_eq!(
            confirm_path(None, false, true, true, false),
            ConfirmPath::Ask
        );
        assert_eq!(
            confirm_path(None, false, true, false, false),
            ConfirmPath::Ask
        );
        // 缺省 + 不能 ask:GUI 可用 → Popup 兜底;不可用 → AutoDeny
        assert_eq!(
            confirm_path(None, false, false, true, false),
            ConfirmPath::Popup
        );
        assert_eq!(
            confirm_path(None, false, false, false, false),
            ConfirmPath::AutoDeny
        );
        assert_eq!(
            confirm_path(None, false, false, true, true),
            ConfirmPath::AutoDeny
        );
    }

    #[test]
    fn test_confirm_path_gui_false_deny_when_no_ask() {
        // gui:false + 能 ask → Ask
        assert_eq!(
            confirm_path(Some(false), false, true, true, false),
            ConfirmPath::Ask
        );
        assert_eq!(
            confirm_path(Some(false), false, true, false, false),
            ConfirmPath::Ask
        );
        // gui:false + 不能 ask → AutoDeny(禁弹窗 fail-closed),无论 GUI 是否可用
        assert_eq!(
            confirm_path(Some(false), false, false, true, false),
            ConfirmPath::AutoDeny
        );
        assert_eq!(
            confirm_path(Some(false), false, false, false, false),
            ConfirmPath::AutoDeny
        );
    }
}
