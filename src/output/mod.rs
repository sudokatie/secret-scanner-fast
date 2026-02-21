pub mod finding;
pub mod json;
pub mod sarif;
pub mod text;

use crate::detection::rules::Severity;
use finding::Finding;
use std::time::Duration;

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub scan_duration: Duration,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            files_scanned: 0,
            bytes_scanned: 0,
            scan_duration: Duration::ZERO,
        }
    }

    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }

    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}
