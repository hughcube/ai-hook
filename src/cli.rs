use crate::i18n::{Msg, t};
use clap::{Command, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ai-hook",
    author = "hugh.li",
    version = env!("CARGO_PKG_VERSION"),
    // clap's built-in -h/--help and -V/--version flags are not stored as
    // regular args, so `mut_arg` cannot touch them; we disable them and
    // register our own localized copies in `localized_command()`.
    disable_help_flag = true,
    disable_version_flag = true
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
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List specified or configured security rule scripts
    List {
        /// Explicit rule scripts to inspect
        #[arg(trailing_var_arg = true)]
        scripts: Vec<PathBuf>,
    },

    /// Test a specific command against given rule scripts
    Test {
        /// Command line string to simulate and test
        command: String,

        /// Simulated tool name (default: run_command)
        #[arg(short, long, default_value = "run_command")]
        tool: String,

        /// Simulated target file path
        #[arg(short, long, default_value = "")]
        file: String,

        /// Explicit rule scripts to test against
        #[arg(trailing_var_arg = true)]
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

        /// Explicit rule scripts to benchmark
        #[arg(trailing_var_arg = true)]
        scripts: Vec<PathBuf>,
    },

    /// Install binary to system PATH directory (auto-detects existing PATH directory with zero new env variables)
    Install {
        /// Target bin directory (default: auto-detected existing PATH directory)
        #[arg(short, long)]
        target_dir: Option<PathBuf>,
    },

    /// Update ai-hook to the latest release from GitHub
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
    let cmd = Cli::command().about(t(Msg::M105)).long_about(t(Msg::M106));

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
            ("scripts", M122),
        ]
    );
    let cmd = sub_help!(
        cmd,
        "bench",
        M123,
        [("iterations", M124), ("command", M125), ("scripts", M126),]
    );
    let cmd = sub_help!(cmd, "install", M127, [("target_dir", M128)]);
    let cmd = sub_help!(cmd, "update", M129, [("force", M130), ("repo", M131)]);
    let cmd = sub_help!(cmd, "tutorial", M132, [("lang", M133)]);
    cmd
}
