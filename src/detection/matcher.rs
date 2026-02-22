#![allow(dead_code)]

use crate::detection::entropy::exceeds_threshold;
use crate::detection::patterns::{all_patterns, PatternEntry};
use crate::detection::rules::{Confidence, Rule, RuleRegistry, Severity};
use crate::output::finding::{Finding, Location};
use std::path::Path;

pub struct Matcher {
    patterns: Vec<PatternEntry>,
    min_severity: Severity,
    entropy_threshold: f64,
}

impl Matcher {
    pub fn new(min_severity: Severity) -> Self {
        let patterns: Vec<PatternEntry> = all_patterns()
            .into_iter()
            .filter(|p| p.severity >= min_severity)
            .collect();

        Self {
            patterns,
            min_severity,
            entropy_threshold: 3.5,
        }
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Match a single line, returning all findings
    pub fn match_line(&self, line: &str, line_num: usize, file: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            for cap in pattern.regex.captures_iter(line) {
                let full_match = cap.get(0).unwrap();

                // Get matched value (capture group or full match)
                let matched_value = if pattern.capture_group > 0 {
                    cap.get(pattern.capture_group)
                        .map(|m| m.as_str())
                        .unwrap_or(full_match.as_str())
                } else {
                    full_match.as_str()
                };

                // Apply entropy check for medium confidence patterns
                if pattern.confidence == Confidence::Medium
                    && !exceeds_threshold(matched_value, self.entropy_threshold) {
                        continue;
                    }

                findings.push(Finding {
                    rule_id: pattern.id.to_string(),
                    severity: pattern.severity,
                    location: Location {
                        file: file.to_path_buf(),
                        line: line_num,
                        column: full_match.start() + 1, // 1-indexed
                        end_column: full_match.end() + 1,
                    },
                    matched_value: matched_value.to_string(),
                    context: line.to_string(),
                    git_info: None,
                });
            }
        }

        findings
    }

    /// Match entire content (for stdin or git blobs)
    pub fn match_content(&self, content: &str, file: &Path) -> Vec<Finding> {
        content
            .lines()
            .enumerate()
            .flat_map(|(idx, line)| self.match_line(line, idx + 1, file))
            .collect()
    }

    /// Get rule registry built from patterns
    pub fn build_registry(&self) -> RuleRegistry {
        let mut registry = RuleRegistry::new();
        for pattern in all_patterns() {
            registry.add_rule(Rule {
                id: pattern.id.to_string(),
                description: pattern.description.to_string(),
                severity: pattern.severity,
                confidence: pattern.confidence,
                entropy_threshold: if pattern.confidence == Confidence::Medium {
                    Some(self.entropy_threshold)
                } else {
                    None
                },
            });
        }
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_aws_key() {
        let matcher = Matcher::new(Severity::Low);
        let findings = matcher.match_line(
            "aws_key = AKIAIOSFODNN7EXAMPLE",
            1,
            Path::new("test.py"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_match_github_token() {
        let matcher = Matcher::new(Severity::Low);
        let findings = matcher.match_line(
            "token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            5,
            Path::new("config.yml"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "github-token");
        assert_eq!(findings[0].location.line, 5);
    }

    #[test]
    fn test_severity_filter() {
        let matcher = Matcher::new(Severity::High);
        // Stripe test key is Low severity, should be filtered out
        // Using dynamic string to avoid GitHub push protection
        let test_key = format!("sk_test_{}", "z".repeat(24));
        let line = format!("key = {}", test_key);
        let findings = matcher.match_line(&line, 1, Path::new("test.py"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_entropy_filter() {
        let matcher = Matcher::new(Severity::Low);

        // Low entropy placeholder should be filtered
        let findings = matcher.match_line(
            "api_key = xxxxxxxxxxxxxxxxxxxx",
            1,
            Path::new("test.py"),
        );
        assert!(findings.is_empty());

        // High entropy value should match
        let findings = matcher.match_line(
            "api_key = aB3xK9mZ2pQ7wR5nY8tL",
            1,
            Path::new("test.py"),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_match_content() {
        let matcher = Matcher::new(Severity::Low);
        let content = "line1\nAKIAIOSFODNN7EXAMPLE\nline3";
        let findings = matcher.match_content(content, Path::new("test.py"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.line, 2);
    }

    #[test]
    fn test_column_positions() {
        let matcher = Matcher::new(Severity::Low);
        let findings = matcher.match_line(
            "    AKIAIOSFODNN7EXAMPLE",
            1,
            Path::new("test.py"),
        );
        assert_eq!(findings[0].location.column, 5); // 1-indexed, after 4 spaces
    }
}
