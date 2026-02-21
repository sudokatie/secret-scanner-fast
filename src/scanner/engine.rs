use crate::cli::args::{OutputFormat, ScanArgs, SeverityArg};
use crate::detection::rules::Severity;
use crate::output::csv::CsvFormatter;
use crate::output::json::JsonFormatter;
use crate::output::sarif::SarifFormatter;
use crate::output::text::TextFormatter;
use crate::output::ScanResult;
use crate::scanner::file_scanner::FileScanner;
use crate::scanner::filter::PathFilter;
use crate::scanner::git_scanner::{GitScanner, HistoryOptions};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
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
    output_path: Option<std::path::PathBuf>,
    // Git options
    git_history: bool,
    staged: bool,
    diff: Option<String>,
    since: Option<String>,
    commits: Option<usize>,
}

impl ScanEngine {
    pub fn from_args(args: &ScanArgs) -> Self {
        let min_severity = match args.min_severity {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
        };

        Self {
            min_severity,
            format: args.format,
            use_color: !args.no_color,
            redact: !args.no_redact,
            max_file_size: args.max_file_size,
            excludes: args.exclude.clone(),
            includes: args.include.clone(),
            threads: args.threads,
            output_path: args.output.clone(),
            git_history: args.git_history,
            staged: args.staged,
            diff: args.diff.clone(),
            since: args.since.clone(),
            commits: args.commits,
        }
    }

    pub fn run(&self, path: &Path) -> io::Result<bool> {
        // Handle stdin
        if path.to_string_lossy() == "-" {
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
            scanner = scanner.with_threads(threads);
        }

        // Scan
        let result = if path.is_file() {
            scanner.scan_file(path)
        } else {
            scanner.scan_directory(path)
        };

        // Output
        self.output_result(&result)?;

        Ok(result.has_findings())
    }

    fn scan_git(&self, path: &Path) -> io::Result<bool> {
        let start = Instant::now();

        let git_scanner = GitScanner::new(path, self.min_severity).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Git error: {}", e))
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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Git error: {}", e)))?;

        let result = ScanResult {
            findings,
            files_scanned: 0, // Git mode doesn't count files
            bytes_scanned: 0,
            scan_duration: start.elapsed(),
        };

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
