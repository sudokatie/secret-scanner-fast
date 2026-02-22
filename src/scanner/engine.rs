use crate::cli::args::{OutputFormat, ScanArgs, SeverityArg};
use crate::config::loader::load_config;
use crate::config::schema::Config;
use crate::config::EnvConfig;
use crate::detection::allowlist::Allowlist;
use crate::detection::matcher::CustomRule;
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
use regex::Regex;
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
    // Config-derived settings
    custom_rules: Vec<CustomRule>,
    allowlist: Allowlist,
    // Git options
    git_history: bool,
    staged: bool,
    diff: Option<String>,
    since: Option<String>,
    commits: Option<usize>,
    max_commit_depth: usize,
}

impl ScanEngine {
    pub fn from_args(args: &ScanArgs) -> Self {
        // Load environment config
        let env_config = EnvConfig::load();

        // Load config file (spec 5.2: CLI > current dir > git root > ~/.config)
        let config = if args.no_config {
            Config::default()
        } else {
            load_config(args.config.as_deref(), &args.path)
        };

        // Determine min_severity (CLI > env > config > default)
        let min_severity = match args.min_severity {
            SeverityArg::Low => {
                // CLI is default, check env then config
                if let Some(ref env_sev) = env_config.min_severity {
                    parse_severity(env_sev)
                } else {
                    parse_severity(&config.rules.min_severity)
                }
            }
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
        };

        // Determine no_color (CLI > env > config > NO_COLOR standard)
        let use_color = if args.no_color {
            false
        } else if let Some(no_color) = env_config.no_color {
            !no_color
        } else if !config.output.color {
            false
        } else {
            !EnvConfig::no_color_env()
        };

        // Determine redact (CLI > config)
        let redact = if args.no_redact {
            false
        } else {
            config.output.redact
        };

        // Merge excludes (CLI + config)
        let mut excludes = args.exclude.clone();
        excludes.extend(config.scan.exclude.clone());

        // Merge includes (CLI + config)
        let mut includes = args.include.clone();
        includes.extend(config.scan.include.clone());

        // Load baseline if specified
        let baseline_fingerprints = if let Some(ref baseline_path) = args.baseline {
            baseline::load_baseline(baseline_path).unwrap_or_else(|e| {
                eprintln!("Warning: Failed to load baseline: {}", e);
                HashSet::new()
            })
        } else {
            HashSet::new()
        };

        // Build allowlist from config (spec 2.4.2)
        let allowlist = Allowlist::from_config(
            &config.rules.allowlist,
            &config.rules.allow_fingerprints,
        );

        // Build custom rules from config (spec 5.1)
        let custom_rules = config
            .rules
            .custom_rules
            .iter()
            .filter_map(|cr| {
                let pattern = Regex::new(&cr.pattern).ok()?;
                Some(CustomRule {
                    id: cr.id.clone(),
                    description: cr.description.clone(),
                    pattern,
                    severity: parse_severity(&cr.severity),
                    entropy_threshold: cr.entropy_threshold,
                })
            })
            .collect();

        // Determine max_file_size (CLI overrides config)
        let max_file_size = if args.max_file_size != 1048576 {
            args.max_file_size // CLI provided non-default
        } else {
            config.scan.max_file_size
        };

        // Determine threads (CLI > config)
        let threads = args.threads.or_else(|| {
            if config.scan.threads > 0 {
                Some(config.scan.threads)
            } else {
                None
            }
        });

        Self {
            min_severity,
            format: args.format,
            use_color,
            redact,
            max_file_size,
            excludes,
            includes,
            threads,
            output_path: args.output.clone(),
            verbose: args.verbose,
            quiet: args.quiet,
            baseline_fingerprints,
            custom_rules,
            allowlist,
            git_history: args.git_history,
            staged: args.staged,
            diff: args.diff.clone(),
            since: args.since.clone(),
            commits: args.commits,
            max_commit_depth: config.git.max_commit_depth,
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
            result.findings =
                baseline::filter_baseline(result.findings, &self.baseline_fingerprints);
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
        self.log_debug(&format!("Custom rules: {}", self.custom_rules.len()));

        // Handle stdin
        if path.to_string_lossy() == "-" {
            self.log_verbose("Reading from stdin");
            return self.scan_stdin();
        }

        // Handle git modes
        if self.staged || self.git_history || self.diff.is_some() {
            return self.scan_git(path);
        }

        // Build scanner with config-derived settings
        let filter = PathFilter::new(path, &self.excludes, &self.includes);
        let mut scanner = FileScanner::new(path, self.min_severity)
            .with_filter(filter)
            .with_max_file_size(self.max_file_size)
            .with_custom_rules(self.custom_rules.clone())
            .with_allowlist(self.allowlist.clone());

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

        let git_scanner = GitScanner::new(path, self.min_severity)
            .map_err(|e| io::Error::other(format!("Git error: {}", e)))?
            .with_custom_rules(self.custom_rules.clone())
            .with_allowlist(self.allowlist.clone());

        let findings = if self.staged {
            git_scanner.scan_staged()
        } else if let Some(ref reference) = self.diff {
            git_scanner.scan_diff(reference)
        } else {
            let opts = HistoryOptions {
                since: self.since.clone(),
                max_commits: self.commits.or(Some(self.max_commit_depth)),
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
            .with_filter(filter)
            .with_custom_rules(self.custom_rules.clone())
            .with_allowlist(self.allowlist.clone());

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

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
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
            no_config: true, // Disable config for tests
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

    #[test]
    fn test_config_loading() {
        use std::fs;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join(".secretscanner.yaml");
        fs::write(
            &config_path,
            r#"
rules:
  min_severity: high
  custom_rules:
    - id: test-rule
      description: Test rule
      pattern: "TEST_[A-Z]{10}"
      severity: medium
  allowlist:
    - pattern: "EXAMPLE"
      reason: "Test value"
"#,
        )
        .unwrap();

        let mut args = default_args();
        args.path = temp.path().to_path_buf();
        args.no_config = false;

        let engine = ScanEngine::from_args(&args);

        // Should pick up config values
        assert_eq!(engine.min_severity, Severity::High);
        assert_eq!(engine.custom_rules.len(), 1);
        assert_eq!(engine.custom_rules[0].id, "test-rule");
    }
}
