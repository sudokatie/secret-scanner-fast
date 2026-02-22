//! Entropy calculation for validating randomness of potential secrets
#![allow(dead_code)]

use std::collections::HashMap;

/// Calculate Shannon entropy for a string
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq: HashMap<char, usize> = HashMap::new();

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Character set categories for threshold selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Charset {
    Hex,          // 0-9, a-f (16 chars, max entropy ~4.0)
    Base64,       // A-Z, a-z, 0-9, +, /, = (64 chars, max ~6.0)
    Alphanumeric, // A-Z, a-z, 0-9 (62 chars, max ~5.95)
}

impl Charset {
    /// Threshold for "high entropy" indicating likely random/secret
    pub fn threshold(&self) -> f64 {
        match self {
            Charset::Hex => 3.0,
            Charset::Base64 => 4.5,
            Charset::Alphanumeric => 4.0,
        }
    }

    /// Detect charset from string content
    pub fn detect(s: &str) -> Self {
        let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
        let has_base64_special = s.chars().any(|c| c == '+' || c == '/' || c == '=');
        let all_hex = s.chars().all(|c| c.is_ascii_hexdigit());

        if all_hex && s.len() > 8 && !has_upper {
            Charset::Hex
        } else if has_base64_special {
            Charset::Base64
        } else {
            // Alphanumeric is the default for mixed case or any other pattern
            Charset::Alphanumeric
        }
    }
}

/// Check if string has high entropy for its detected charset
pub fn is_high_entropy(s: &str) -> bool {
    let charset = Charset::detect(s);
    calculate_entropy(s) >= charset.threshold()
}

/// Check if entropy exceeds explicit threshold
pub fn exceeds_threshold(s: &str, threshold: f64) -> bool {
    calculate_entropy(s) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_single_char_repeated() {
        assert_eq!(calculate_entropy("aaaa"), 0.0);
        assert_eq!(calculate_entropy("xxxxxxxx"), 0.0);
    }

    #[test]
    fn test_two_chars_equal() {
        // "aabb" has 2 'a' and 2 'b', each p=0.5
        // H = -2 * (0.5 * log2(0.5)) = -2 * (0.5 * -1) = 1.0
        let entropy = calculate_entropy("aabb");
        assert!((entropy - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_high_entropy_string() {
        // Random-looking string should have high entropy
        let entropy = calculate_entropy("aB3xK9mZ2pQ7wR5");
        assert!(entropy > 3.5);
    }

    #[test]
    fn test_low_entropy_placeholder() {
        let entropy = calculate_entropy("xxxxxxxxxxxx");
        assert!(entropy < 1.0);
    }

    #[test]
    fn test_charset_detection_hex() {
        assert_eq!(Charset::detect("deadbeef1234"), Charset::Hex);
        assert_eq!(Charset::detect("0123456789abcdef"), Charset::Hex);
    }

    #[test]
    fn test_charset_detection_base64() {
        assert_eq!(Charset::detect("SGVsbG8gV29ybGQ="), Charset::Base64);
        assert_eq!(Charset::detect("abc+def/ghi="), Charset::Base64);
    }

    #[test]
    fn test_charset_detection_alphanumeric() {
        assert_eq!(Charset::detect("AbCdEfGh1234"), Charset::Alphanumeric);
    }

    #[test]
    fn test_is_high_entropy() {
        // Real API key should pass
        assert!(is_high_entropy("aB3xK9mZ2pQ7wR5nY8tL"));
        // Placeholder should fail
        assert!(!is_high_entropy("xxxxxxxxxxxxxxxxxxxx"));
        // Simple word should fail
        assert!(!is_high_entropy("password12345678"));
    }
}
