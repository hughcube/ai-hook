pub mod cli;
pub mod engine;
pub mod fast_path;
pub mod i18n;
pub mod paths;
pub mod protocol;
pub mod tutorial;
pub mod ui;
pub mod update;

// ---------------------------------------------------------------------------
// Panic-safe stdout/stderr output macros.
//
// ai-hook runs as a Windows GUI-subsystem binary (no console) so that hosts
// which spawn the hook without an inherited console do not pay the conhost /
// console-allocation cost on every process start (~9 ms measured). A GUI
// process still gets real pipe handles whenever the host redirects stdout /
// stderr (every hook caller does), but when neither a console nor redirection
// is present, Rust's `println!`/`eprintln!` would panic on the invalid handle.
// These macros write and drop the error instead, keeping the decision path and
// every CLI subcommand panic-free in every host shape.
#[macro_export]
macro_rules! outln {
    () => {{
        use ::std::io::Write;
        let _ = ::std::io::stdout().lock().write_all(b"\n");
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let mut o = ::std::io::stdout().lock();
        let _ = writeln!(o, $($arg)*);
    }};
}

#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let _ = ::std::io::stdout().lock().write_fmt(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! errln {
    () => {{
        use ::std::io::Write;
        let _ = ::std::io::stderr().lock().write_all(b"\n");
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let mut o = ::std::io::stderr().lock();
        let _ = writeln!(o, $($arg)*);
    }};
}

pub use cli::{Cli, Commands};
pub use engine::{
    ErrorPolicy, RuleExecutionResult, RuleLoader, RuleRunner, RuleSource, SysContext,
};
pub use fast_path::check_fast_path;
pub use i18n::{Lang, lang};
pub use protocol::{
    ConversationInfo, FileAction, FileContext, HookContext, HookDecision, Platform, env_flag_true,
};
pub use ui::GuiDialog;
