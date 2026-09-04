use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ai-hook",
    author = "hugh.li <hugh.li0001@gmail.com>",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance, multi-agent unified hook dispatcher and autonomous rule engine",
    long_about = "A unified, nanosecond-latency security interceptor and governance dispatcher for AI Agents (Antigravity, Claude Code, CodeBuddy, Codex) powered by Rust and embedded QuickJS."
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

    /// Override GUI countdown timeout in seconds (default: 60)
    #[arg(long, global = true)]
    pub timeout: Option<u32>,

    /// Dry run mode (does not trigger GUI popups)
    #[arg(long, global = true)]
    pub dry_run: bool,
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

    /// Install binary to system bin directory (e.g. ~/bin/ai-hook)
    Install {
        /// Target bin directory (default: detects ~/bin or ~/.local/bin)
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
}
