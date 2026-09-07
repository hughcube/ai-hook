use crate::i18n::{Msg, t};
use clap::{Command, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Default)]
#[command(
    name = "ai-hook",
    author = "hugh.li",
    version = env!("CARGO_PKG_VERSION"),
    // clap's built-in -h/--help and -V/--version flags are not stored as
    // regular args, so `mut_arg` cannot touch them; we disable them and
    // register our own localized copies in `localized_command()`.
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Rule script files to execute (supports multiple scripts)
    #[arg(trailing_var_arg = true)]
    pub scripts: Vec<PathBuf>,

    /// Rule script files or directories (can be specified multiple times)
    #[arg(short, long, global = true)]
    pub rule: Vec<PathBuf>,

    /// Explicitly disable GUI popup (defaults to GUI enabled)
    #[arg(long, global = true)]
    pub no_gui: bool,

    /// Force GUI popup for all confirmations (even if agent supports terminal ask or rule specifies gui: false)
    #[arg(long, global = true, alias = "force-popup")]
    pub force_gui: bool,

    /// Override GUI countdown timeout in seconds (default: 60)
    #[arg(long, global = true)]
    pub timeout: Option<u32>,

    /// Dry run mode (does not trigger GUI popups)
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Allow command execution when a rule script fails (syntax/runtime error,
    /// timeout, async rule). Default is fail-closed: any rule error DENIES the
    /// command instead of silently allowing it.
    #[arg(long, global = true)]
    pub allow_on_error: bool,

    /// Disable the fast-path bypass so whitelisted read-only commands
    /// (git status, ls, cat, ...) are also evaluated by the rule engine
    #[arg(long, global = true)]
    pub no_fast_path: bool,

    /// Enable debug mode: record full raw input, normalized context, rule trace and decisions to log
    #[arg(long, global = true)]
    pub debug: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List specified or configured security rule scripts
    #[command(alias = "ls")]
    List {
        /// Explicit rule scripts to inspect
        #[arg(trailing_var_arg = true)]
        scripts: Vec<PathBuf>,
    },

    /// Test a specific command against given rule scripts
    Test {
        /// Command line string to simulate and test
        command: String,

        /// Simulated tool name (default: Bash)
        #[arg(short, long, default_value = "Bash")]
        tool: String,

        /// Simulated target file path
        #[arg(short, long, default_value = "")]
        file: String,

        /// Simulated host (default: claude_code)
        #[arg(short, long, default_value = "claude_code")]
        platform: String,

        /// Simulated lifecycle event (default: PreToolUse)
        #[arg(short = 'e', long, default_value = "PreToolUse")]
        event: String,

        /// User prompt text — only honored when event is UserPromptSubmit
        /// (rules keyed on ctx.prompt need it; the command argument is
        /// ignored for that event)
        #[arg(long, default_value = "")]
        prompt: String,

        /// Explicit rule scripts to test against
        #[arg()]
        scripts: Vec<PathBuf>,
    },

    /// Run benchmark over given rule scripts
    Bench {
        /// Number of iterations to evaluate (default: 1000)
        #[arg(short, long, default_value = "1000")]
        iterations: usize,

        /// Command string to benchmark against
        #[arg(short, long, default_value = "git status --short")]
        command: String,

        /// Simulated host (default: claude_code)
        #[arg(short, long, default_value = "claude_code")]
        platform: String,

        /// Explicit rule scripts to benchmark
        #[arg(trailing_var_arg = true)]
        scripts: Vec<PathBuf>,
    },

    /// Install binary to system PATH directory (auto-detects existing PATH directory with zero new env variables)
    Install {
        /// Target bin directory (default: auto-detected existing PATH directory)
        #[arg(short, long)]
        target_dir: Option<PathBuf>,

        /// Force overwrite even if the binary already exists at target location
        #[arg(short, long)]
        force: bool,
    },

    /// Update ai-hook to the latest release from GitHub
    #[command(alias = "upgrade")]
    Update {
        /// Force re-installation even if already at latest version
        #[arg(short, long)]
        force: bool,

        /// Custom GitHub repository in format owner/repo (default: hughcube/ai-hook)
        #[arg(long, default_value = "hughcube/ai-hook")]
        repo: String,
    },

    /// Display comprehensive tutorial and rule authoring guide
    #[command(alias = "guide")]
    Tutorial {
        /// Tutorial language: "zh" for Chinese or "en" for English
        /// (default: follow the system language)
        #[arg(short, long)]
        lang: Option<String>,
    },

    /// Clean and prune old log files (keeps the latest 14 files by default)
    #[command(alias = "prune")]
    Clean {
        /// Maximum log files to retain per category (default: 14, or from AI_HOOK_LOG_MAX_FILES)
        #[arg(short = 'n', long)]
        max_files: Option<usize>,

        /// Preview files that would be deleted without actually deleting them
        #[arg(long)]
        dry_run: bool,
    },

    /// Display version information
    Version,

    /// Print this message or the help of the given subcommand(s)
    #[command(alias = "h")]
    Help {
        /// The subcommand whose help should be displayed
        #[arg()]
        subcommand: Option<String>,
    },
}

/// Registers a localized `-h/--help` flag on `cmd`. Every command and
/// subcommand's built-in help flag must be disabled first and re-registered
/// here (it is the only way to localize the "Print help" row).
fn with_localized_help_flag(cmd: Command) -> Command {
    cmd.disable_help_flag(true).arg(
        clap::Arg::new("help")
            .short('h')
            .long("help")
            .action(clap::ArgAction::Help)
            .help(t(Msg::M114)),
    )
}

/// Registers a localized `-V/--version` flag on `cmd` (top level only).
fn with_localized_version_flag(cmd: Command) -> Command {
    cmd.disable_version_flag(true).arg(
        clap::Arg::new("version")
            .short('V')
            .long("version")
            .action(clap::ArgAction::Version)
            .help(t(Msg::M115)),
    )
}

/// Builds the clap command with help text from the language bundle.
///
/// Clap's own section headings ("Usage:", "Commands:", "Options:") and the
/// built-in `help` subcommand line are hard-coded by clap and stay English;
/// every other user-visible help string (about, command/argument/flag
/// descriptions, -h/-V rows) is localized at runtime via `t(Msg)`.
pub fn localized_command() -> Command {
    let version_str = env!("CARGO_PKG_VERSION");
    let about_text = format!("ai-hook {} - {}", version_str, t(Msg::M105));
    let long_about_text = format!("ai-hook {} - {}", version_str, t(Msg::M106));

    let cmd = Cli::command()
        .version(version_str)
        .about(about_text)
        .long_about(long_about_text);

    // Overwrite the help text of top-level arguments by their clap arg id.
    macro_rules! args_help {
        ($cmd:expr, [$(($id:literal, $msg:ident)),* $(,)?]) => {{
            let mut c = $cmd;
            $( c = c.mut_arg($id, |a| a.help(t(Msg::$msg))); )*
            c
        }};
    }
    // Overwrite a subcommand's about text plus its own arguments and give it
    // a localized -h flag (derive subcommands carry the built-in one too).
    macro_rules! sub_help {
        ($cmd:expr, $name:literal, $about:ident, [$(($id:literal, $msg:ident)),* $(,)?]) => {{
            let mut c = $cmd;
            c = c.mut_subcommand($name, |sub| {
                #[allow(unused_mut)]
                let mut s = sub.about(t(Msg::$about));
                $( s = s.mut_arg($id, |a| a.help(t(Msg::$msg))); )*
                with_localized_help_flag(s)
            });
            c
        }};
    }

    let cmd = with_localized_version_flag(with_localized_help_flag(cmd));

    let cmd = args_help!(
        cmd,
        [
            ("scripts", M107),
            ("rule", M108),
            ("no_gui", M109),
            ("force_gui", M110),
            ("timeout", M111),
            ("dry_run", M112),
            ("allow_on_error", M113),
            ("no_fast_path", M139),
            ("debug", M161),
        ]
    );

    let cmd = sub_help!(cmd, "list", M116, [("scripts", M117)]);
    let cmd = sub_help!(
        cmd,
        "test",
        M118,
        [
            ("command", M119),
            ("tool", M120),
            ("file", M121),
            ("platform", M155),
            ("event", M165),
            ("prompt", M166),
            ("scripts", M122),
        ]
    );
    let cmd = sub_help!(
        cmd,
        "bench",
        M123,
        [
            ("iterations", M124),
            ("command", M125),
            ("platform", M155),
            ("scripts", M126),
        ]
    );
    let cmd = sub_help!(
        cmd,
        "install",
        M127,
        [("target_dir", M128), ("force", M130)]
    );
    let cmd = sub_help!(cmd, "update", M129, [("force", M130), ("repo", M131)]);
    let cmd = sub_help!(cmd, "tutorial", M132, [("lang", M133)]);
    let cmd = sub_help!(cmd, "clean", M162, [("max_files", M163), ("dry_run", M164)]);
    let cmd = sub_help!(cmd, "version", M115, []);
    sub_help!(cmd, "help", M167, [("subcommand", M167)])
}
