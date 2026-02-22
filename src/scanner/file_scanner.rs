
use crate::detection::matcher::Matcher;
use crate::detection::rules::Severity;
use crate::output::finding::Finding;
use crate::output::ScanResult;
use crate::scanner::filter::PathFilter;
use crate::scanner::stream::StreamReader;
use rayon::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use walkdir::WalkDir;

pub struct FileScanner {
    matcher: Matcher,
    filter: PathFilter,
    stream_reader: StreamReader,
    max_file_size: u64,
    threads: Option<usize>,
}

impl FileScanner {
    pub fn new(root: &Path, min_severity: Severity) -> Self {
        Self {
            matcher: Matcher::new(min_severity),
            filter: PathFilter::new(root, &[], &[]),
            stream_reader: StreamReader::new(),
            max_file_size: 1024 * 1024, // 1MB default
            threads: None,
        }
    }

    pub fn with_excludes(mut self, excludes: &[String]) -> Self {
        // Recreate filter with excludes - need to know root
        self.filter = PathFilter::new(Path::new("."), excludes, &[]);
        self
    }

    pub fn with_includes(mut self, root: &Path, excludes: &[String], includes: &[String]) -> Self {
        self.filter = PathFilter::new(root, excludes, includes);
        self
    }

    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = Some(threads);
        self
    }

    pub fn with_filter(mut self, filter: PathFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Scan a directory tree for secrets
    pub fn scan_directory(&self, root: &Path) -> ScanResult {
        let start = Instant::now();
        let files_scanned = AtomicUsize::new(0);
        let bytes_scanned = AtomicU64::new(0);

        // Configure thread pool if specified
        if let Some(threads) = self.threads {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global()
                .ok();
        }

        // Collect files to scan
        let files: Vec<_> = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| self.filter.should_scan(e.path()))
            .collect();

        // Scan files in parallel
        let findings: Vec<Finding> = files
            .par_iter()
            .filter_map(|entry| {
                let path = entry.path();

                // Skip binary/large files
                if self.stream_reader.should_skip(path, self.max_file_size).unwrap_or(true) {
                    return None;
                }

                // Get file size for stats
                if let Ok(metadata) = std::fs::metadata(path) {
                    bytes_scanned.fetch_add(metadata.len(), Ordering::Relaxed);
                }
                files_scanned.fetch_add(1, Ordering::Relaxed);

                // Read and scan file
                let lines = self.stream_reader.read_file(path).ok()?;
                let mut file_findings = Vec::new();

                for (line_num, line) in lines {
                    let matches = self.matcher.match_line(&line, line_num, path);
                    file_findings.extend(matches);
                }

                if file_findings.is_empty() {
                    None
                } else {
                    Some(file_findings)
                }
            })
            .flatten()
            .collect();

        ScanResult {
            findings,
            files_scanned: files_scanned.load(Ordering::Relaxed),
            bytes_scanned: bytes_scanned.load(Ordering::Relaxed),
            scan_duration: start.elapsed(),
        }
    }

    /// Scan a single file
    pub fn scan_file(&self, path: &Path) -> ScanResult {
        let start = Instant::now();
        let mut result = ScanResult::new();

        if self.stream_reader.should_skip(path, self.max_file_size).unwrap_or(true) {
            return result;
        }

        if let Ok(metadata) = std::fs::metadata(path) {
            result.bytes_scanned = metadata.len();
        }
        result.files_scanned = 1;

        if let Ok(lines) = self.stream_reader.read_file(path) {
            for (line_num, line) in lines {
                let matches = self.matcher.match_line(&line, line_num, path);
                result.findings.extend(matches);
            }
        }

        result.scan_duration = start.elapsed();
        result
    }

    /// Scan content from stdin
    pub fn scan_stdin(&self, content: &str) -> ScanResult {
        let start = Instant::now();
        let findings = self.matcher.match_content(content, Path::new("-"));

        ScanResult {
            findings,
            files_scanned: 1,
            bytes_scanned: content.len() as u64,
            scan_duration: start.elapsed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_scan_file_with_secret() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.py");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "# config").unwrap();
        writeln!(file, "aws_key = AKIAIOSFODNN7EXAMPLE").unwrap();

        let scanner = FileScanner::new(temp.path(), Severity::Low);
        let result = scanner.scan_file(&file_path);

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "aws-access-key");
    }

    #[test]
    fn test_scan_directory() {
        let temp = TempDir::new().unwrap();

        // Create files with secrets
        let mut f1 = std::fs::File::create(temp.path().join("config.py")).unwrap();
        writeln!(f1, "key = AKIAIOSFODNN7EXAMPLE").unwrap();

        let mut f2 = std::fs::File::create(temp.path().join("app.js")).unwrap();
        writeln!(f2, "const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'").unwrap();

        // Create clean file
        let mut f3 = std::fs::File::create(temp.path().join("readme.md")).unwrap();
        writeln!(f3, "# My Project").unwrap();

        let scanner = FileScanner::new(temp.path(), Severity::Low);
        let result = scanner.scan_directory(temp.path());

        assert_eq!(result.files_scanned, 3);
        assert_eq!(result.findings.len(), 2); // AWS key + GitHub token
    }

    #[test]
    fn test_scan_stdin() {
        let scanner = FileScanner::new(Path::new("."), Severity::Low);
        let result = scanner.scan_stdin("key: AKIAIOSFODNN7EXAMPLE\n");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].location.file.to_string_lossy(), "-");
    }

    #[test]
    fn test_skip_binary() {
        let temp = TempDir::new().unwrap();
        let binary_path = temp.path().join("binary.bin");
        std::fs::write(&binary_path, &[0u8, 1, 2, 3, 0, 5, 6]).unwrap();

        let scanner = FileScanner::new(temp.path(), Severity::Low);
        let result = scanner.scan_file(&binary_path);

        assert_eq!(result.files_scanned, 0);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_max_file_size() {
        let temp = TempDir::new().unwrap();
        let large_path = temp.path().join("large.txt");
        let content = "AKIAIOSFODNN7EXAMPLE\n".repeat(1000);
        std::fs::write(&large_path, &content).unwrap();

        // Scanner with very small max size
        let scanner = FileScanner::new(temp.path(), Severity::Low)
            .with_max_file_size(100);

        let result = scanner.scan_file(&large_path);
        assert_eq!(result.files_scanned, 0); // Skipped due to size
    }
}
