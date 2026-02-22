use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

/// Baseline file format (matches our JSON output)
#[derive(Deserialize)]
struct BaselineFile {
    findings: Vec<BaselineFinding>,
}

#[derive(Deserialize)]
struct BaselineFinding {
    fingerprint: String,
}

/// Load fingerprints from a baseline file
pub fn load_baseline(path: &Path) -> io::Result<HashSet<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let baseline: BaselineFile = serde_json::from_reader(reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(baseline
        .findings
        .into_iter()
        .map(|f| f.fingerprint)
        .collect())
}

/// Filter findings against a baseline
pub fn filter_baseline(
    findings: Vec<crate::output::finding::Finding>,
    baseline: &HashSet<String>,
) -> Vec<crate::output::finding::Finding> {
    findings
        .into_iter()
        .filter(|f| !baseline.contains(&f.fingerprint()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::rules::Severity;
    use crate::output::finding::{Finding, Location};
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn test_finding(value: &str) -> Finding {
        Finding {
            rule_id: "test".to_string(),
            severity: Severity::High,
            location: Location {
                file: PathBuf::from("test.py"),
                line: 1,
                column: 1,
                end_column: 20,
            },
            matched_value: value.to_string(),
            context: format!("x = {}", value),
            git_info: None,
        }
    }

    #[test]
    fn test_load_baseline() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{"findings": [{{"fingerprint": "abc123"}}, {{"fingerprint": "def456"}}]}}"#
        )
        .unwrap();

        let baseline = load_baseline(file.path()).unwrap();
        assert!(baseline.contains("abc123"));
        assert!(baseline.contains("def456"));
        assert!(!baseline.contains("other"));
    }

    #[test]
    fn test_filter_baseline() {
        let mut baseline = HashSet::new();
        let finding1 = test_finding("secret1");
        let fp1 = finding1.fingerprint();
        baseline.insert(fp1);

        let findings = vec![test_finding("secret1"), test_finding("secret2")];

        let filtered = filter_baseline(findings, &baseline);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].matched_value, "secret2");
    }

    #[test]
    fn test_empty_baseline() {
        let baseline = HashSet::new();
        let findings = vec![test_finding("secret1"), test_finding("secret2")];

        let filtered = filter_baseline(findings, &baseline);
        assert_eq!(filtered.len(), 2);
    }
}
