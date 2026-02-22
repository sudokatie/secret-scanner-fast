use crate::cli::args::{OutputFormat, ScanArgs, SeverityArg};
use crate::config::EnvConfig;
use crate::detection::rules::Severity;
use crate::output::csv::CsvFormatter;
use crate::output::json::JsonFormatter;
use crate::output::sarif::SarifFormatter;
use crate::output::text::TextFormatter;
use crate::output::ScanResult;
use crate::scanner::baseline;
use crate::scanner::file_scanner::FileScanner;
use crate::scanner::filter::PathFilter;
use crate::scanner::git_scanner::{GitScanner, HistoryOptions};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub struct ScanEngine {
    min_severity: Severity,
    format: OutputFormat,
    use_color: bool,
    redact: bool,
    max_file_size: u64,
    excludes: Vec<String>,
    includes: Vec<String>,
    threads: Option<usize>,
    output_path: Option<PathBuf>,
    verbose: u8,
    quiet: bool,
    baseline_fingerprints: HashSet<String>,
    // Git options
    git_history: bool,
    staged: bool,
    diff: Option<String>,
    since: Option<String>,
    commits: Option<usize>,
}

impl ScanEngine {
    pub fn from_args(args: &ScanArgs) -> Self {
        // Load environment config
        let env_config = EnvConfig::load();

        // Determine min_severity (CLI > env > default)
        let min_severity = if let Some(ref env_sev) = env_config.min_severity {
            match env_sev.to_lowercase().as_str() {
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            }
        } else {
            match args.min_severity {
                SeverityArg::Low => Severity::Low,
                SeverityArg::Medium => Severity::Medium,
                SeverityArg::High => Severity::High,
            }
        };

        // Determine no_color (CLI > env > NO_COLOR standard)
        let use_color = if args.no_color {
            false
        } else if let Some(no_color) = env_config.no_color {
            !no_color
        } else {
            !EnvConfig::no_color_env()
        };

        // Load baseline if specified
        let baseline_fingerprints = if let Some(ref baseline_path) = args.baseline {
            baseline::load_baseline(baseline_path).unwrap_or_else(|e| {
                eprintln!("Warning: Failed to load baseline: {}", e);
                HashSet::new()
            })
        } else {
            HashSet::new()
        };

        Self {
            min_severity,
            format: args.format,
            use_color,
            redact: !args.no_redact,
            max_file_size: args.max_file_size,
            excludes: args.exclude.clone(),
            includes: args.include.clone(),
            threads: args.threads,
            output_path: args.output.clone(),
            verbose: args.verbose,
            quiet: args.quiet,
            baseline_fingerprints,
            git_history: args.git_history,
            staged: args.staged,
            diff: args.diff.clone(),
            since: args.since.clone(),
            commits: args.commits,
        }
    }

    /// Log a message if not in quiet mode
    fn log(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{}", msg);
        }
    }

    /// Log a verbose message (only if verbose >= 1)
    fn log_verbose(&self, msg: &str) {
        if self.verbose >= 1 && !self.quiet {
            eprintln!("{}", msg);
        }
    }

    /// Log a debug message (only if verbose >= 2)
    fn log_debug(&self, msg: &str) {
        if self.verbose >= 2 && !self.quiet {
            eprintln!("[debug] {}", msg);
        }
    }

    /// Filter findings against baseline
    fn apply_baseline(&self, mut result: ScanResult) -> ScanResult {
        if !self.baseline_fingerprints.is_empty() {
            let before = result.findings.len();
            result.findings = baseline::filter_baseline(result.findings, &self.baseline_fingerprints);
            let filtered = before - result.findings.len();
            if filtered > 0 {
                self.log_verbose(&format!("Filtered {} findings from baseline", filtered));
            }
        }
        result
    }

    pub fn run(&self, path: &Path) -> io::Result<bool> {
        self.log_verbose(&format!("Scanning: {}", path.display()));
        self.log_debug(&format!("Min severity: {:?}", self.min_severity));
        self.log_debug(&format!("Max file size: {} bytes", self.max_file_size));

        // Handle stdin
        if path.to_string_lossy() == "-" {
            self.log_verbose("Reading from stdin");
            return self.scan_stdin();
        }

        // Handle git modes
        if self.staged || self.git_history || self.diff.is_some() {
            return self.scan_git(path);
        }

        // Build scanner
        let filter = PathFilter::new(path, &self.excludes, &self.includes);
        let mut scanner = FileScanner::new(path, self.min_severity)
            .with_filter(filter)
            .with_max_file_size(self.max_file_size);

        if let Some(threads) = self.threads {
            self.log_debug(&format!("Using {} threads", threads));
            scanner = scanner.with_threads(threads);
        }

        // Scan
        let result = if path.is_file() {
            self.log_debug("Scanning single file");
            scanner.scan_file(path)
        } else {
            self.log_debug("Scanning directory");
            scanner.scan_directory(path)
        };

        self.log_verbose(&format!(
            "Scanned {} files ({} bytes) in {:?}",
            result.files_scanned, result.bytes_scanned, result.scan_duration
        ));

        // Apply baseline filtering
        let result = self.apply_baseline(result);

        // Output
        self.output_result(&result)?;

        Ok(result.has_findings())
    }

    fn scan_git(&self, path: &Path) -> io::Result<bool> {
        let start = Instant::now();

        let git_scanner = GitScanner::new(path, self.min_severity).map_err(|e| {
            io::Error::other(format!("Git error: {}", e))
        })?;

        let findings = if self.staged {
            git_scanner.scan_staged()
        } else if let Some(ref reference) = self.diff {
            git_scanner.scan_diff(reference)
        } else {
            let opts = HistoryOptions {
                since: self.since.clone(),
                max_commits: self.commits,
            };
            git_scanner.scan_history(&opts)
        }
        .map_err(|e| io::Error::other(format!("Git error: {}", e)))?;

        let result = ScanResult {
            findings,
            files_scanned: 0, // Git mode doesn't count files
            bytes_scanned: 0,
            scan_duration: start.elapsed(),
        };

        // Apply baseline filtering
        let result = self.apply_baseline(result);

        self.output_result(&result)?;

        Ok(result.has_findings())
    }

    fn scan_stdin(&self) -> io::Result<bool> {
        let mut content = String::new();
        io::stdin().read_to_string(&mut content)?;

        let filter = PathFilter::new(Path::new("."), &self.excludes, &self.includes);
        let scanner = FileScanner::new(Path::new("."), self.min_severity)
            .with_filter(filter);

        let result = scanner.scan_stdin(&content);
        self.output_result(&result)?;

        Ok(result.has_findings())
    }

    fn output_result(&self, result: &ScanResult) -> io::Result<()> {
        // Get output writer
        let mut output: Box<dyn Write> = if let Some(ref path) = self.output_path {
            Box::new(File::create(path)?)
        } else {
            Box::new(io::stdout())
        };

        match self.format {
            OutputFormat::Text => {
                let mut formatter = TextFormatter::new(self.use_color);
                if !self.redact {
                    formatter = formatter.with_no_redact();
                }
                formatter.format_result(result)?;
            }
            OutputFormat::Json => {
                let mut formatter = JsonFormatter::new();
                if !self.redact {
                    formatter = formatter.no_redact();
                }
                formatter.format(&mut output, result)?;
            }
            OutputFormat::Sarif => {
                let mut formatter = SarifFormatter::new();
                if !self.redact {
                    formatter = formatter.no_redact();
                }
                formatter.format(&mut output, result)?;
            }
            OutputFormat::Csv => {
                let mut formatter = CsvFormatter::new();
                if !self.redact {
                    formatter = formatter.no_redact();
                }
                formatter.format(&mut output, result)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn default_args() -> ScanArgs {
        ScanArgs {
            path: PathBuf::from("."),
            format: OutputFormat::Text,
            output: None,
            min_severity: SeverityArg::Low,
            no_color: true,
            no_redact: false,
            git_history: false,
            since: None,
            commits: None,
            staged: false,
            diff: None,
            max_file_size: 1048576,
            exclude: vec![],
            include: vec![],
            config: None,
            no_config: false,
            baseline: None,
            threads: None,
            verbose: 0,
            quiet: false,
        }
    }

    #[test]
    fn test_engine_creation() {
        let args = default_args();
        let engine = ScanEngine::from_args(&args);

        assert_eq!(engine.min_severity, Severity::Low);
        assert!(!engine.use_color); // no_color = true
        assert!(engine.redact);
    }

    #[test]
    fn test_severity_mapping() {
        let mut args = default_args();

        args.min_severity = SeverityArg::High;
        let engine = ScanEngine::from_args(&args);
        assert_eq!(engine.min_severity, Severity::High);

        args.min_severity = SeverityArg::Medium;
        let engine = ScanEngine::from_args(&args);
        assert_eq!(engine.min_severity, Severity::Medium);
    }
}
