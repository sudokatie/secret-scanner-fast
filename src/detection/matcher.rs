use crate::detection::allowlist::Allowlist;
use crate::detection::context::should_filter;
use crate::detection::entropy::exceeds_threshold;
use crate::detection::patterns::{all_patterns, PatternEntry};
use crate::detection::rules::{Confidence, Rule, RuleRegistry, Severity};
use crate::output::finding::{Finding, Location};
use regex::Regex;
use std::path::Path;

/// Custom rule loaded from config
#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub pattern: Regex,
    pub severity: Severity,
    pub entropy_threshold: Option<f64>,
}

pub struct Matcher {
    patterns: Vec<PatternEntry>,
    custom_rules: Vec<CustomRule>,
    min_severity: Severity,
    entropy_threshold: f64,
    allowlist: Allowlist,
}

impl Matcher {
    pub fn new(min_severity: Severity) -> Self {
        let patterns: Vec<PatternEntry> = all_patterns()
            .into_iter()
            .filter(|p| p.severity >= min_severity)
            .collect();

        Self {
            patterns,
            custom_rules: Vec::new(),
            min_severity,
            entropy_threshold: 3.5,
            allowlist: Allowlist::new(),
        }
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    pub fn with_custom_rules(mut self, rules: Vec<CustomRule>) -> Self {
        // Filter custom rules by severity
        self.custom_rules = rules
            .into_iter()
            .filter(|r| r.severity >= self.min_severity)
            .collect();
        self
    }

    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Match a single line, returning all findings
    pub fn match_line(&self, line: &str, line_num: usize, file: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let file_str = file.to_string_lossy();

        // Match built-in patterns
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

                // Apply entropy check for medium AND low confidence patterns (spec 2.1.3)
                if (pattern.confidence == Confidence::Medium || pattern.confidence == Confidence::Low)
                    && !exceeds_threshold(matched_value, self.entropy_threshold)
                {
                    continue;
                }

                // Apply context validation (spec 2.3) - skip placeholders, test files, doc context
                if should_filter(matched_value, &file_str, line) {
                    continue;
                }

                let finding = Finding {
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
                };

                // Apply allowlist (spec 2.4.2)
                if self.allowlist.is_finding_allowed(matched_value, file, &finding.fingerprint()) {
                    continue;
                }

                findings.push(finding);
            }
        }

        // Match custom rules (spec 5.1)
        for rule in &self.custom_rules {
            for cap in rule.pattern.captures_iter(line) {
                let full_match = cap.get(0).unwrap();
                let matched_value = full_match.as_str();

                // Apply entropy check if threshold specified
                if let Some(threshold) = rule.entropy_threshold {
                    if !exceeds_threshold(matched_value, threshold) {
                        continue;
                    }
                }

                // Apply context validation
                if should_filter(matched_value, &file_str, line) {
                    continue;
                }

                let finding = Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    location: Location {
                        file: file.to_path_buf(),
                        line: line_num,
                        column: full_match.start() + 1,
                        end_column: full_match.end() + 1,
                    },
                    matched_value: matched_value.to_string(),
                    context: line.to_string(),
                    git_info: None,
                };

                // Apply allowlist
                if self.allowlist.is_finding_allowed(matched_value, file, &finding.fingerprint()) {
                    continue;
                }

                findings.push(finding);
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
                entropy_threshold: if pattern.confidence == Confidence::Medium
                    || pattern.confidence == Confidence::Low
                {
                    Some(self.entropy_threshold)
                } else {
                    None
                },
            });
        }
        // Add custom rules to registry
        for rule in &self.custom_rules {
            registry.add_rule(Rule {
                id: rule.id.clone(),
                description: rule.description.clone(),
                severity: rule.severity,
                confidence: Confidence::Medium, // Custom rules are medium confidence
                entropy_threshold: rule.entropy_threshold,
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
            "aws_key = AKIAIOSFODNN7REALKEY",
            1,
            Path::new("config.py"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_match_github_token() {
        let matcher = Matcher::new(Severity::Low);
        // Use realistic-looking token (not xxx placeholder)
        let findings = matcher.match_line(
            "token: ghp_aB3xK9mZ2pQ7wR5nY8tLaB3xK9mZ2pQ7wR5n",
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
        let test_key = format!("sk_test_{}", "z".repeat(24));
        let line = format!("key = {}", test_key);
        let findings = matcher.match_line(&line, 1, Path::new("config.py"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_entropy_filter_medium_confidence() {
        let matcher = Matcher::new(Severity::Low);

        // Low entropy placeholder should be filtered
        let findings = matcher.match_line(
            "api_key = xxxxxxxxxxxxxxxxxxxx",
            1,
            Path::new("config.py"),
        );
        assert!(findings.is_empty());

        // High entropy value should match
        let findings = matcher.match_line(
            "api_key = aB3xK9mZ2pQ7wR5nY8tL",
            1,
            Path::new("config.py"),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_context_filter_placeholder() {
        let matcher = Matcher::new(Severity::Low);

        // Placeholder value should be filtered (context validation)
        let findings = matcher.match_line(
            "aws_key = AKIAEXAMPLE12345678",
            1,
            Path::new("config.py"),
        );
        assert!(findings.is_empty(), "Placeholder 'EXAMPLE' should be filtered");
    }

    #[test]
    fn test_context_filter_test_path() {
        let matcher = Matcher::new(Severity::Low);

        // Test file + doc context should be filtered
        let findings = matcher.match_line(
            "# example: AKIAIOSFODNN7REALKEY",
            1,
            Path::new("tests/test_auth.py"),
        );
        assert!(findings.is_empty(), "Test file + doc context should be filtered");
    }

    #[test]
    fn test_match_content() {
        let matcher = Matcher::new(Severity::Low);
        let content = "line1\nAKIAIOSFODNN7REALKEY\nline3";
        let findings = matcher.match_content(content, Path::new("config.py"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.line, 2);
    }

    #[test]
    fn test_column_positions() {
        let matcher = Matcher::new(Severity::Low);
        let findings = matcher.match_line(
            "    AKIAIOSFODNN7REALKEY",
            1,
            Path::new("config.py"),
        );
        assert_eq!(findings[0].location.column, 5); // 1-indexed, after 4 spaces
    }

    #[test]
    fn test_custom_rules() {
        let custom = CustomRule {
            id: "internal-key".to_string(),
            description: "Internal API key".to_string(),
            pattern: Regex::new(r"INT_[A-Z0-9]{16}").unwrap(),
            severity: Severity::High,
            entropy_threshold: None,
        };

        let matcher = Matcher::new(Severity::Low).with_custom_rules(vec![custom]);

        let findings = matcher.match_line(
            "key = INT_ABCDEF1234567890",
            1,
            Path::new("config.py"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "internal-key");
    }

    #[test]
    fn test_allowlist_filters_finding() {
        let mut allowlist = Allowlist::new();
        allowlist.add_pattern("REALKEY").unwrap();

        let matcher = Matcher::new(Severity::Low).with_allowlist(allowlist);

        let findings = matcher.match_line(
            "aws_key = AKIAIOSFODNN7REALKEY",
            1,
            Path::new("config.py"),
        );
        assert!(findings.is_empty(), "Allowlisted pattern should be filtered");
    }

    #[test]
    fn test_low_confidence_entropy_filter() {
        let matcher = Matcher::new(Severity::Low);

        // Low entropy hex string should be filtered (low confidence pattern)
        let findings = matcher.match_line(
            "secret_key = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1,
            Path::new("config.py"),
        );
        assert!(findings.is_empty(), "Low entropy low-confidence should be filtered");
    }
}
