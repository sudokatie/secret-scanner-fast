use crate::detection::rules::Severity;
use crate::output::finding::Finding;
use crate::output::ScanResult;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct JsonOutput {
    findings: Vec<JsonFinding>,
    summary: JsonSummary,
}

#[derive(Serialize)]
struct JsonFinding {
    rule_id: String,
    severity: String,
    file: String,
    line: usize,
    column: usize,
    end_column: usize,
    matched_value: String,
    context: String,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_info: Option<JsonGitInfo>,
}

#[derive(Serialize)]
struct JsonGitInfo {
    commit: String,
    author: String,
    date: String,
    message: String,
}

#[derive(Serialize)]
struct JsonSummary {
    total_findings: usize,
    high: usize,
    medium: usize,
    low: usize,
    files_scanned: usize,
    bytes_scanned: u64,
    scan_duration_ms: u128,
}

pub struct JsonFormatter {
    pretty: bool,
    redact: bool,
}

impl JsonFormatter {
    pub fn new() -> Self {
        Self {
            pretty: false,
            redact: true,
        }
    }

    #[allow(dead_code)] // Public API for library users
    pub fn pretty(mut self) -> Self {
        self.pretty = true;
        self
    }

    pub fn no_redact(mut self) -> Self {
        self.redact = false;
        self
    }

    fn convert_finding(&self, finding: &Finding) -> JsonFinding {
        let matched_value = if self.redact {
            finding.redacted_match()
        } else {
            finding.matched_value.clone()
        };

        JsonFinding {
            rule_id: finding.rule_id.clone(),
            severity: finding.severity.to_string(),
            file: finding.location.file.to_string_lossy().to_string(),
            line: finding.location.line,
            column: finding.location.column,
            end_column: finding.location.end_column,
            matched_value,
            context: finding.context.clone(),
            fingerprint: finding.fingerprint(),
            git_info: finding.git_info.as_ref().map(|g| JsonGitInfo {
                commit: g.commit_sha.clone(),
                author: g.author.clone(),
                date: g.date.clone(),
                message: g.message.clone(),
            }),
        }
    }

    pub fn format<W: Write>(&self, w: &mut W, result: &ScanResult) -> io::Result<()> {
        let output = JsonOutput {
            findings: result.findings.iter().map(|f| self.convert_finding(f)).collect(),
            summary: JsonSummary {
                total_findings: result.findings.len(),
                high: result.count_by_severity(Severity::High),
                medium: result.count_by_severity(Severity::Medium),
                low: result.count_by_severity(Severity::Low),
                files_scanned: result.files_scanned,
                bytes_scanned: result.bytes_scanned,
                scan_duration_ms: result.scan_duration.as_millis(),
            },
        };

        let json = if self.pretty {
            serde_json::to_string_pretty(&output)?
        } else {
            serde_json::to_string(&output)?
        };
        writeln!(w, "{}", json)?;

        Ok(())
    }

    #[allow(dead_code)] // Used in tests, public API for library users
    pub fn format_to_string(&self, result: &ScanResult) -> Result<String, serde_json::Error> {
        let output = JsonOutput {
            findings: result.findings.iter().map(|f| self.convert_finding(f)).collect(),
            summary: JsonSummary {
                total_findings: result.findings.len(),
                high: result.count_by_severity(Severity::High),
                medium: result.count_by_severity(Severity::Medium),
                low: result.count_by_severity(Severity::Low),
                files_scanned: result.files_scanned,
                bytes_scanned: result.bytes_scanned,
                scan_duration_ms: result.scan_duration.as_millis(),
            },
        };

        if self.pretty {
            serde_json::to_string_pretty(&output)
        } else {
            serde_json::to_string(&output)
        }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::finding::Location;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_result() -> ScanResult {
        ScanResult {
            findings: vec![Finding {
                rule_id: "aws-access-key".to_string(),
                severity: Severity::High,
                location: Location {
                    file: PathBuf::from("config.py"),
                    line: 10,
                    column: 5,
                    end_column: 25,
                },
                matched_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
                context: "key = AKIAIOSFODNN7EXAMPLE".to_string(),
                git_info: None,
            }],
            files_scanned: 5,
            bytes_scanned: 1024,
            scan_duration: Duration::from_millis(50),
        }
    }

    #[test]
    fn test_json_output() {
        let formatter = JsonFormatter::new();
        let result = test_result();
        let json = formatter.format_to_string(&result).unwrap();

        assert!(json.contains("aws-access-key"));
        assert!(json.contains("config.py"));
        assert!(json.contains("\"high\""));
        assert!(json.contains("\"total_findings\":1"));
        // Should be redacted by default
        assert!(json.contains("AKIA"));
        assert!(json.contains("..."));
    }

    #[test]
    fn test_json_no_redact() {
        let formatter = JsonFormatter::new().no_redact();
        let result = test_result();
        let json = formatter.format_to_string(&result).unwrap();

        assert!(json.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!json.contains("..."));
    }

    #[test]
    fn test_json_pretty() {
        let formatter = JsonFormatter::new().pretty();
        let result = test_result();
        let json = formatter.format_to_string(&result).unwrap();

        // Pretty output has newlines and indentation
        assert!(json.contains('\n'));
        assert!(json.contains("  "));
    }

    #[test]
    fn test_empty_result() {
        let formatter = JsonFormatter::new();
        let result = ScanResult::new();
        let json = formatter.format_to_string(&result).unwrap();

        assert!(json.contains("\"findings\":[]"));
        assert!(json.contains("\"total_findings\":0"));
    }
}
