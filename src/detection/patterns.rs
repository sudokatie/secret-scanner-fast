use once_cell::sync::Lazy;
use regex::Regex;
use crate::detection::rules::{Severity, Confidence};

// High confidence patterns - unique prefixes, unambiguous
pub static AWS_ACCESS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b").unwrap()
});

pub static AWS_SECRET_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap()
});

pub static GITHUB_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36,}|ghr_[A-Za-z0-9]{36})\b").unwrap()
});

pub static GITLAB_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bglpat-[A-Za-z0-9\-]{20,}\b").unwrap()
});

pub static SLACK_BOT_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bxoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b").unwrap()
});

pub static SLACK_USER_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bxoxp-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b").unwrap()
});

pub static SLACK_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+").unwrap()
});

pub static STRIPE_LIVE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk_live_[A-Za-z0-9]{24,}\b").unwrap()
});

pub static STRIPE_TEST_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk_test_[A-Za-z0-9]{24,}\b").unwrap()
});

pub static TWILIO_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSK[a-f0-9]{32}\b").unwrap()
});

pub static SENDGRID_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b").unwrap()
});

pub static NPM_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap()
});

pub static PYPI_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bpypi-[A-Za-z0-9_-]{50,}\b").unwrap()
});

pub static DIGITALOCEAN_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdop_v1_[a-f0-9]{64}\b").unwrap()
});

pub static DISCORD_BOT_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b").unwrap()
});

pub static GOOGLE_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap()
});

pub static HEROKU_API_KEY: Lazy<Regex> = Lazy::new(|| {
    // Heroku API keys are UUIDs in heroku context
    Regex::new(r#"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"#).unwrap()
});

pub static FIREBASE_KEY: Lazy<Regex> = Lazy::new(|| {
    // Firebase server keys start with AAAA
    Regex::new(r"\bAAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{100,}\b").unwrap()
});

pub static PRIVATE_KEY_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----").unwrap()
});

// Medium confidence - need context/entropy validation
pub static GENERIC_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)api[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#).unwrap()
});

pub static GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)secret\s*[:=]\s*['"]?([a-zA-Z0-9_-]{16,})['"]?"#).unwrap()
});

pub static GENERIC_PASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)password\s*[:=]\s*['"]?([^\s'"]{8,})['"]?"#).unwrap()
});

pub static BEARER_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Bearer\s+([a-zA-Z0-9_\-.]{20,})").unwrap()
});

pub static BASIC_AUTH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Basic\s+([A-Za-z0-9+/]{20,}={0,2})").unwrap()
});

pub static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap()
});

pub static CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(mysql|postgres|postgresql|mongodb|redis)://[^:]+:[^@]+@[^\s'"]+$"#).unwrap()
});

/// Pattern entry with metadata
pub struct PatternEntry {
    pub id: &'static str,
    pub description: &'static str,
    pub regex: &'static Lazy<Regex>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub capture_group: usize, // 0 = full match, 1+ = capture group
}

/// Get all patterns with metadata
pub fn all_patterns() -> Vec<PatternEntry> {
    vec![
        PatternEntry { id: "aws-access-key", description: "AWS Access Key ID", regex: &AWS_ACCESS_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "aws-secret-key", description: "AWS Secret Access Key", regex: &AWS_SECRET_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 1 },
        PatternEntry { id: "github-token", description: "GitHub Personal Access Token", regex: &GITHUB_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "gitlab-token", description: "GitLab Personal Access Token", regex: &GITLAB_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "slack-bot-token", description: "Slack Bot Token", regex: &SLACK_BOT_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "slack-user-token", description: "Slack User Token", regex: &SLACK_USER_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "slack-webhook", description: "Slack Webhook URL", regex: &SLACK_WEBHOOK, severity: Severity::Medium, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "stripe-live-key", description: "Stripe Live Secret Key", regex: &STRIPE_LIVE_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "stripe-test-key", description: "Stripe Test Secret Key", regex: &STRIPE_TEST_KEY, severity: Severity::Low, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "twilio-api-key", description: "Twilio API Key", regex: &TWILIO_API_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "sendgrid-api-key", description: "SendGrid API Key", regex: &SENDGRID_API_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "npm-token", description: "npm Access Token", regex: &NPM_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "pypi-token", description: "PyPI API Token", regex: &PYPI_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "digitalocean-token", description: "DigitalOcean Personal Access Token", regex: &DIGITALOCEAN_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "discord-bot-token", description: "Discord Bot Token", regex: &DISCORD_BOT_TOKEN, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "google-api-key", description: "Google API Key", regex: &GOOGLE_API_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "heroku-api-key", description: "Heroku API Key", regex: &HEROKU_API_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 1 },
        PatternEntry { id: "firebase-key", description: "Firebase Server Key", regex: &FIREBASE_KEY, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "private-key", description: "Private Key File", regex: &PRIVATE_KEY_HEADER, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "generic-api-key", description: "Generic API Key", regex: &GENERIC_API_KEY, severity: Severity::Medium, confidence: Confidence::Medium, capture_group: 1 },
        PatternEntry { id: "generic-secret", description: "Generic Secret", regex: &GENERIC_SECRET, severity: Severity::Medium, confidence: Confidence::Medium, capture_group: 1 },
        PatternEntry { id: "generic-password", description: "Generic Password", regex: &GENERIC_PASSWORD, severity: Severity::Medium, confidence: Confidence::Medium, capture_group: 1 },
        PatternEntry { id: "bearer-token", description: "Bearer Token", regex: &BEARER_TOKEN, severity: Severity::Medium, confidence: Confidence::Medium, capture_group: 1 },
        PatternEntry { id: "basic-auth", description: "Basic Auth Credentials", regex: &BASIC_AUTH, severity: Severity::Medium, confidence: Confidence::Medium, capture_group: 1 },
        PatternEntry { id: "jwt", description: "JSON Web Token", regex: &JWT, severity: Severity::Medium, confidence: Confidence::High, capture_group: 0 },
        PatternEntry { id: "connection-string", description: "Database Connection String", regex: &CONNECTION_STRING, severity: Severity::High, confidence: Confidence::High, capture_group: 0 },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key() {
        assert!(AWS_ACCESS_KEY.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(AWS_ACCESS_KEY.is_match("ASIAXXX1234567890123")); // 16 chars after ASIA
        assert!(!AWS_ACCESS_KEY.is_match("AKIA123")); // Too short
        assert!(!AWS_ACCESS_KEY.is_match("XXIAIOSFODNN7EXAMPLE")); // Wrong prefix
    }

    #[test]
    fn test_github_token() {
        assert!(GITHUB_TOKEN.is_match("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(GITHUB_TOKEN.is_match("gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(GITHUB_TOKEN.is_match("ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(!GITHUB_TOKEN.is_match("ghp_short")); // Too short
    }

    #[test]
    fn test_slack_token() {
        // Using obviously fake patterns to avoid GitHub push protection
        let bot = format!("xoxb-{}-{}-{}", "1".repeat(12), "2".repeat(13), "abc");
        let user = format!("xoxp-{}-{}-{}-{}", "1".repeat(12), "2".repeat(12), "3".repeat(13), "xyz");
        assert!(SLACK_BOT_TOKEN.is_match(&bot));
        assert!(SLACK_USER_TOKEN.is_match(&user));
    }

    #[test]
    fn test_stripe_keys() {
        // Using obviously fake patterns to avoid GitHub push protection
        let live = format!("sk_live_{}", "x".repeat(24));
        let test = format!("sk_test_{}", "y".repeat(24));
        assert!(STRIPE_LIVE_KEY.is_match(&live));
        assert!(STRIPE_TEST_KEY.is_match(&test));
    }

    #[test]
    fn test_private_key() {
        assert!(PRIVATE_KEY_HEADER.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(PRIVATE_KEY_HEADER.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(PRIVATE_KEY_HEADER.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn test_jwt() {
        // Valid JWT structure
        assert!(JWT.is_match("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
    }

    #[test]
    fn test_connection_string() {
        assert!(CONNECTION_STRING.is_match("postgres://user:password@localhost:5432/db"));
        assert!(CONNECTION_STRING.is_match("mysql://root:secret@127.0.0.1/mydb"));
        assert!(CONNECTION_STRING.is_match("mongodb://admin:pass123@cluster.mongodb.net/test"));
    }

    #[test]
    fn test_generic_patterns() {
        assert!(GENERIC_API_KEY.is_match("api_key = 'abcdef1234567890abcdef'"));
        assert!(GENERIC_SECRET.is_match("secret: abcdefghijklmnop"));
        assert!(GENERIC_PASSWORD.is_match("password=mysecretpassword"));
    }

    #[test]
    fn test_heroku_api_key() {
        assert!(HEROKU_API_KEY.is_match("HEROKU_API_KEY=12345678-1234-1234-1234-123456789012"));
        assert!(HEROKU_API_KEY.is_match("heroku_api_key: 'abcdef12-3456-7890-abcd-ef1234567890'"));
        assert!(!HEROKU_API_KEY.is_match("not-a-uuid"));
    }

    #[test]
    fn test_firebase_key() {
        // Firebase server keys are long base64-ish strings
        let key = format!("AAAA{}:{}", "abcdefg", "x".repeat(100));
        assert!(FIREBASE_KEY.is_match(&key));
        assert!(!FIREBASE_KEY.is_match("AAAA:short")); // Too short
    }
}
