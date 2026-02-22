//! Context validation for reducing false positives and boosting confidence
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

/// Positive indicators - variable names that suggest real secrets (spec 2.3.1)
static SECRET_VAR_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(secret|key|token|password|credential|auth|private|api[_-]?key|access[_-]?key)").unwrap()
});

/// Config file extensions that increase confidence
static CONFIG_EXTENSIONS: &[&str] = &[".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf"];

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

/// Check if the context contains secret-related variable names (positive indicator)
pub fn has_secret_context(context: &str) -> bool {
    SECRET_VAR_PATTERNS.is_match(context)
}

/// Check if the file is a config file (positive indicator)
pub fn is_config_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    CONFIG_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Determine confidence adjustment based on context
/// Positive values increase confidence, negative values decrease it
pub fn confidence_adjustment(value: &str, path: &str, context: &str) -> f64 {
    let mut adjustment = 0.0;

    // Negative indicators (decrease confidence)
    if is_placeholder(value) {
        adjustment -= 0.5;
    }

    if is_test_path(path) {
        adjustment -= 0.3;
    }

    if is_doc_context(context) {
        adjustment -= 0.4;
    }

    // Positive indicators (increase confidence) - per spec 2.3.1
    if has_secret_context(context) {
        adjustment += 0.3;
    }

    if is_config_file(path) {
        adjustment += 0.2;
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
        // Placeholder gets penalty (-0.5) but secret context ("key") adds (+0.3)
        // Net: -0.2
        let adj = confidence_adjustment("EXAMPLE_VALUE", "src/config.py", "data = EXAMPLE_VALUE");
        assert!(adj < -0.4, "Expected strong negative for placeholder, got {}", adj);

        // Test path gets penalty (-0.3)
        // No positive indicators when value/context don't have secret words
        let adj = confidence_adjustment("abc123def456", "tests/test.py", "x = abc123def456");
        assert!(adj < -0.2, "Expected negative from test path, got {}", adj);

        // Production code with no indicators, no adjustment
        let adj = confidence_adjustment("abc123def456", "src/main.py", "x = abc123def456");
        assert!((adj - 0.0).abs() < 0.01, "Expected 0, got {}", adj);
    }

    #[test]
    fn test_has_secret_context() {
        assert!(has_secret_context("api_key = AKIAIOSFODNN7"));
        assert!(has_secret_context("AWS_SECRET_ACCESS_KEY=xxx"));
        assert!(has_secret_context("auth_token: bearer123"));
        assert!(has_secret_context("password: mypass"));
        assert!(has_secret_context("private_key = xyz"));

        assert!(!has_secret_context("username = admin"));
        assert!(!has_secret_context("count = 42"));
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file("config.yaml"));
        assert!(is_config_file("settings.json"));
        assert!(is_config_file(".env"));
        assert!(is_config_file("app.toml"));
        assert!(is_config_file("database.ini"));

        assert!(!is_config_file("main.py"));
        assert!(!is_config_file("app.js"));
    }

    #[test]
    fn test_positive_confidence_boost() {
        // Secret context boosts confidence
        let adj = confidence_adjustment("REAL_KEY", "config.yaml", "api_key = REAL_KEY");
        assert!(adj > 0.4); // +0.3 for secret context, +0.2 for config file

        // Config file alone boosts
        let adj = confidence_adjustment("REAL_KEY", "settings.json", "value = REAL_KEY");
        assert!(adj > 0.1);
    }
}
