use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secret-scanner-fast")]
#[command(about = "High-performance secret scanner for codebases")]
#[command(version)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan for secrets (default)
    Scan(ScanArgs),
    /// List available detection rules
    Rules(RulesArgs),
    /// Verify if a detected secret is valid (calls provider API)
    Verify(VerifyArgs),
    /// Create default config file
    Init(InitArgs),
    /// Generate man page
    Man(ManArgs),
}

#[derive(clap::Args)]
pub struct ManArgs {
    /// Output directory for man page
    #[arg(short, long, default_value = ".")]
    pub output: PathBuf,
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Path to scan (use - for stdin)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Write output to file instead of stdout
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value = "low")]
    pub min_severity: SeverityArg,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Show full secret values (default: redacted)
    #[arg(long)]
    pub no_redact: bool,

    /// Scan full git history
    #[arg(long)]
    pub git_history: bool,

    /// Only scan commits after this date (with --git-history)
    #[arg(long)]
    pub since: Option<String>,

    /// Only scan last N commits (with --git-history)
    #[arg(long)]
    pub commits: Option<usize>,

    /// Only scan staged changes (pre-commit mode)
    #[arg(long)]
    pub staged: bool,

    /// Only scan changes vs reference
    #[arg(long)]
    pub diff: Option<String>,

    /// Skip files larger than this (bytes)
    #[arg(long, default_value = "1048576")]
    pub max_file_size: u64,

    /// Additional paths to exclude (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Only scan paths matching pattern (repeatable)
    #[arg(long)]
    pub include: Vec<String>,

    /// Path to config file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Ignore config files
    #[arg(long)]
    pub no_config: bool,

    /// Ignore findings in baseline file
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Number of threads
    #[arg(long)]
    pub threads: Option<usize>,

    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Only show errors
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(clap::Args)]
pub struct RulesArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Filter by severity
    #[arg(long, value_enum)]
    pub severity: Option<SeverityArg>,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// The secret value to verify
    pub secret: String,

    /// Type of secret (aws, github, slack, stripe, etc.)
    #[arg(short, long)]
    pub secret_type: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// Create minimal config
    #[arg(long)]
    pub minimal: bool,

    /// Create config with all options documented
    #[arg(long)]
    pub full: bool,

    /// Output path
    #[arg(short, long, default_value = ".secretscanner.yaml")]
    pub output: PathBuf,

    /// Overwrite existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
}
