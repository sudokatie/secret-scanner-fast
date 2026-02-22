//! Context validation for reducing false positives
#![allow(dead_code)]

use once_cell::sync::Lazy;
use regex::Regex;

/// Words that suggest a value is a placeholder, not a real secret
static PLACEHOLDER_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(example|sample|test|fake|dummy|placeholder|your[_-]?|my[_-]?|xxx|change[_-]?me|insert[_-]?here|todo|fixme)").unwrap()
});

/// File paths that typically contain test/example data
static TEST_PATH_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(test|spec|mock|fixture|example|sample|demo)").unwrap()
});

/// Context around a match that suggests it's documentation/example
static DOC_CONTEXT_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(//\s*example|#\s*example|/\*.*example|```|e\.g\.|for example|such as)").unwrap()
});

/// Check if the matched value looks like a placeholder
pub fn is_placeholder(value: &str) -> bool {
    PLACEHOLDER_PATTERNS.is_match(value)
}

/// Check if the file path suggests test/example content
pub fn is_test_path(path: &str) -> bool {
    TEST_PATH_PATTERNS.is_match(path)
}

/// Check if the context line suggests documentation/example
pub fn is_doc_context(context: &str) -> bool {
    DOC_CONTEXT_PATTERNS.is_match(context)
}

/// Determine confidence adjustment based on context
pub fn confidence_adjustment(value: &str, path: &str, context: &str) -> f64 {
    let mut adjustment = 0.0;

    if is_placeholder(value) {
        adjustment -= 0.5;
    }

    if is_test_path(path) {
        adjustment -= 0.3;
    }

    if is_doc_context(context) {
        adjustment -= 0.4;
    }

    adjustment
}

/// Should this finding be filtered out based on context?
pub fn should_filter(value: &str, path: &str, context: &str) -> bool {
    // Strong placeholder indicators -> filter
    if is_placeholder(value) {
        return true;
    }

    // Test file + doc context -> probably example
    if is_test_path(path) && is_doc_context(context) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_detection() {
        assert!(is_placeholder("AKIAEXAMPLE12345678"));
        assert!(is_placeholder("your_api_key_here"));
        assert!(is_placeholder("test_secret_123"));
        assert!(is_placeholder("CHANGE_ME"));
        assert!(is_placeholder("xxx_placeholder"));

        assert!(!is_placeholder("AKIAIOSFODNN7REALKEY"));
        assert!(!is_placeholder("ghp_a1b2c3d4e5f6g7h8i9j0"));
    }

    #[test]
    fn test_test_path_detection() {
        assert!(is_test_path("src/test/config.py"));
        assert!(is_test_path("__tests__/auth.js"));
        assert!(is_test_path("spec/helpers.rb"));
        assert!(is_test_path("examples/demo.py"));
        assert!(is_test_path("fixtures/data.json"));

        assert!(!is_test_path("src/config.py"));
        assert!(!is_test_path("lib/auth.js"));
    }

    #[test]
    fn test_doc_context_detection() {
        assert!(is_doc_context("// example: AKIAIOSFODNN7EXAMPLE"));
        assert!(is_doc_context("# Example usage"));
        assert!(is_doc_context("```python"));
        assert!(is_doc_context("e.g. sk_live_xxx"));

        assert!(!is_doc_context("aws_key = AKIAIOSFODNN7REALKEY"));
    }

    #[test]
    fn test_should_filter() {
        // Placeholder in value -> filter
        assert!(should_filter("AKIAEXAMPLE1234", "src/config.py", "key = AKIAEXAMPLE1234"));

        // Test file + doc context -> filter
        assert!(should_filter(
            "AKIAIOSFODNN7REAL",
            "tests/auth_test.py",
            "# example: AKIAIOSFODNN7REAL"
        ));

        // Real value in production file -> don't filter
        assert!(!should_filter(
            "AKIAIOSFODNN7REAL",
            "src/config.py",
            "aws_key = AKIAIOSFODNN7REAL"
        ));
    }

    #[test]
    fn test_confidence_adjustment() {
        // Placeholder gets big penalty
        let adj = confidence_adjustment("EXAMPLE_KEY", "src/config.py", "key = EXAMPLE_KEY");
        assert!(adj < -0.4);

        // Test path gets penalty
        let adj = confidence_adjustment("REAL_KEY", "tests/test.py", "key = REAL_KEY");
        assert!(adj < -0.2);

        // Production code, no penalty
        let adj = confidence_adjustment("REAL_KEY", "src/config.py", "key = REAL_KEY");
        assert!((adj - 0.0).abs() < 0.01);
    }
}
