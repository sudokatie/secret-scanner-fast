use crate::output::ScanResult;
use std::io::{self, Write};

pub struct CsvFormatter {
    redact: bool,
}

impl CsvFormatter {
    pub fn new() -> Self {
        Self { redact: true }
    }

    pub fn no_redact(mut self) -> Self {
        self.redact = false;
        self
    }

    /// Escape a value for CSV (handle commas, quotes, newlines)
    fn escape_value(value: &str) -> String {
        if value.contains(',') || value.contains('"') || value.contains('\n') {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }

    pub fn format<W: Write>(&self, w: &mut W, result: &ScanResult) -> io::Result<()> {
        // Header
        writeln!(w, "file,line,column,rule_id,severity,matched_value,fingerprint")?;

        // Rows
        for finding in &result.findings {
            let value = if self.redact {
                finding.redacted_match()
            } else {
                finding.matched_value.clone()
            };

            writeln!(
                w,
                "{},{},{},{},{},{},{}",
                Self::escape_value(&finding.location.file.to_string_lossy()),
                finding.location.line,
                finding.location.column,
                finding.rule_id,
                finding.severity,
                Self::escape_value(&value),
                finding.fingerprint()
            )?;
        }

        Ok(())
    }

    #[allow(dead_code)] // Used in tests, public API for library users
    pub fn format_to_string(&self, result: &ScanResult) -> String {
        let mut buf = Vec::new();
        self.format(&mut buf, result).unwrap();
        String::from_utf8(buf).unwrap()
    }
}

impl Default for CsvFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::rules::Severity;
    use crate::output::finding::{Finding, Location};
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
    fn test_csv_header() {
        let formatter = CsvFormatter::new();
        let result = ScanResult::new();
        let csv = formatter.format_to_string(&result);

        assert!(csv.starts_with("file,line,column,rule_id,severity,matched_value,fingerprint"));
    }

    #[test]
    fn test_csv_row() {
        let formatter = CsvFormatter::new();
        let result = test_result();
        let csv = formatter.format_to_string(&result);

        assert!(csv.contains("config.py"));
        assert!(csv.contains("10"));
        assert!(csv.contains("aws-access-key"));
        assert!(csv.contains("high"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(CsvFormatter::escape_value("simple"), "simple");
        assert_eq!(CsvFormatter::escape_value("has,comma"), "\"has,comma\"");
        assert_eq!(CsvFormatter::escape_value("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn test_csv_redact() {
        let formatter = CsvFormatter::new();
        let result = test_result();
        let csv = formatter.format_to_string(&result);

        // Should be redacted
        assert!(csv.contains("AKIA"));
        assert!(csv.contains("..."));
    }
}
