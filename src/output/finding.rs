use crate::detection::rules::Severity;
use sha2::{Sha256, Digest};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub location: Location,
    pub matched_value: String,
    pub context: String,
    pub git_info: Option<GitInfo>,
}

#[derive(Debug, Clone)]
pub struct Location {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone)]
pub struct GitInfo {
    pub commit_sha: String,
    pub author: String,
    pub date: String,
    pub message: String,
}

impl Finding {
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.rule_id);
        hasher.update(self.location.file.to_string_lossy().as_bytes());
        hasher.update(self.location.line.to_string().as_bytes());
        hasher.update(&self.matched_value);
        let result = hasher.finalize();
        hex::encode(&result[..8])
    }

    pub fn redacted_match(&self) -> String {
        redact_secret(&self.matched_value)
    }
}

/// Redact middle of secret, showing only first and last few chars
pub fn redact_secret(secret: &str) -> String {
    let len = secret.len();
    if len <= 8 {
        return "*".repeat(len);
    }
    let visible = 4.min(len / 4);
    format!(
        "{}...{}",
        &secret[..visible],
        &secret[len - visible..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_short() {
        assert_eq!(redact_secret("abc"), "***");
        assert_eq!(redact_secret("12345678"), "********");
    }

    #[test]
    fn test_redact_long() {
        let result = redact_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(result.starts_with("AKIA"));
        assert!(result.ends_with("MPLE"));
        assert!(result.contains("..."));
    }

    #[test]
    fn test_fingerprint_stable() {
        let finding = Finding {
            rule_id: "test".to_string(),
            severity: Severity::High,
            location: Location {
                file: PathBuf::from("test.py"),
                line: 10,
                column: 5,
                end_column: 20,
            },
            matched_value: "secret123".to_string(),
            context: "x = secret123".to_string(),
            git_info: None,
        };

        let fp1 = finding.fingerprint();
        let fp2 = finding.fingerprint();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16); // 8 bytes = 16 hex chars
    }
}
