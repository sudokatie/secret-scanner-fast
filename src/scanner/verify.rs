//! Secret verification via provider APIs

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub secret_type: String,
    pub is_valid: bool,
    pub message: String,
    pub details: Option<String>,
}

/// Verify a secret by calling the provider API
pub fn verify_secret(
    secret: &str,
    secret_type: Option<&str>,
    timeout_secs: u64,
) -> Result<VerifyResult, String> {
    let detected_type = secret_type
        .map(String::from)
        .unwrap_or_else(|| detect_secret_type(secret));

    let timeout = Duration::from_secs(timeout_secs);

    match detected_type.as_str() {
        "aws" | "aws-access-key" => verify_aws(secret, timeout),
        "github" | "github-token" => verify_github(secret, timeout),
        "slack" | "slack-token" => verify_slack(secret, timeout),
        "stripe" | "stripe-key" => verify_stripe(secret, timeout),
        "npm" | "npm-token" => verify_npm(secret, timeout),
        "pypi" | "pypi-token" => verify_pypi(secret, timeout),
        _ => Ok(VerifyResult {
            secret_type: detected_type,
            is_valid: false,
            message: "Verification not supported for this secret type".to_string(),
            details: Some("Supported types: aws, github, slack, stripe, npm, pypi".to_string()),
        }),
    }
}

/// Auto-detect secret type from pattern
fn detect_secret_type(secret: &str) -> String {
    if secret.starts_with("AKIA") || secret.starts_with("ASIA") {
        "aws".to_string()
    } else if secret.starts_with("ghp_") || secret.starts_with("gho_") || secret.starts_with("ghs_") {
        "github".to_string()
    } else if secret.starts_with("xoxb-") || secret.starts_with("xoxp-") {
        "slack".to_string()
    } else if secret.starts_with("sk_live_") || secret.starts_with("sk_test_") {
        "stripe".to_string()
    } else if secret.starts_with("npm_") {
        "npm".to_string()
    } else if secret.starts_with("pypi-") {
        "pypi".to_string()
    } else {
        "unknown".to_string()
    }
}

fn verify_aws(_secret: &str, _timeout: Duration) -> Result<VerifyResult, String> {
    // AWS verification requires both access key and secret key
    // For access key alone, we can check format but not validity
    Ok(VerifyResult {
        secret_type: "aws".to_string(),
        is_valid: false,
        message: "AWS verification requires both access key and secret key".to_string(),
        details: Some("Use 'aws sts get-caller-identity' with both keys to verify".to_string()),
    })
}

fn verify_github(secret: &str, timeout: Duration) -> Result<VerifyResult, String> {
    // Call GitHub API to verify token
    let client = ureq::AgentBuilder::new()
        .timeout(timeout)
        .build();

    let response = client
        .get("https://api.github.com/user")
        .set("Authorization", &format!("Bearer {}", secret))
        .set("User-Agent", "secret-scanner-fast")
        .call();

    match response {
        Ok(resp) => {
            if resp.status() == 200 {
                let body = resp.into_string().unwrap_or_default();
                let login = extract_json_field(&body, "login");
                Ok(VerifyResult {
                    secret_type: "github".to_string(),
                    is_valid: true,
                    message: format!("Valid GitHub token for user: {}", login.unwrap_or("unknown")),
                    details: None,
                })
            } else {
                Ok(VerifyResult {
                    secret_type: "github".to_string(),
                    is_valid: false,
                    message: format!("Invalid or expired token (status: {})", resp.status()),
                    details: None,
                })
            }
        }
        Err(e) => Ok(VerifyResult {
            secret_type: "github".to_string(),
            is_valid: false,
            message: format!("Verification failed: {}", e),
            details: None,
        }),
    }
}

fn verify_slack(secret: &str, timeout: Duration) -> Result<VerifyResult, String> {
    let client = ureq::AgentBuilder::new()
        .timeout(timeout)
        .build();

    let response = client
        .get("https://slack.com/api/auth.test")
        .set("Authorization", &format!("Bearer {}", secret))
        .call();

    match response {
        Ok(resp) => {
            let body = resp.into_string().unwrap_or_default();
            let ok = body.contains("\"ok\":true");
            if ok {
                let team = extract_json_field(&body, "team");
                let user = extract_json_field(&body, "user");
                Ok(VerifyResult {
                    secret_type: "slack".to_string(),
                    is_valid: true,
                    message: format!("Valid Slack token for {}/{}", 
                        team.unwrap_or("unknown"), 
                        user.unwrap_or("unknown")),
                    details: None,
                })
            } else {
                Ok(VerifyResult {
                    secret_type: "slack".to_string(),
                    is_valid: false,
                    message: "Invalid or expired Slack token".to_string(),
                    details: None,
                })
            }
        }
        Err(e) => Ok(VerifyResult {
            secret_type: "slack".to_string(),
            is_valid: false,
            message: format!("Verification failed: {}", e),
            details: None,
        }),
    }
}

fn verify_stripe(secret: &str, timeout: Duration) -> Result<VerifyResult, String> {
    let client = ureq::AgentBuilder::new()
        .timeout(timeout)
        .build();

    // Use basic auth with API key
    let response = client
        .get("https://api.stripe.com/v1/balance")
        .set("Authorization", &format!("Bearer {}", secret))
        .call();

    match response {
        Ok(resp) => {
            if resp.status() == 200 {
                let is_test = secret.contains("_test_");
                Ok(VerifyResult {
                    secret_type: "stripe".to_string(),
                    is_valid: true,
                    message: format!("Valid Stripe {} key", if is_test { "test" } else { "live" }),
                    details: None,
                })
            } else {
                Ok(VerifyResult {
                    secret_type: "stripe".to_string(),
                    is_valid: false,
                    message: format!("Invalid Stripe key (status: {})", resp.status()),
                    details: None,
                })
            }
        }
        Err(e) => Ok(VerifyResult {
            secret_type: "stripe".to_string(),
            is_valid: false,
            message: format!("Verification failed: {}", e),
            details: None,
        }),
    }
}

fn verify_npm(secret: &str, timeout: Duration) -> Result<VerifyResult, String> {
    let client = ureq::AgentBuilder::new()
        .timeout(timeout)
        .build();

    let response = client
        .get("https://registry.npmjs.org/-/npm/v1/user")
        .set("Authorization", &format!("Bearer {}", secret))
        .call();

    match response {
        Ok(resp) => {
            if resp.status() == 200 {
                let body = resp.into_string().unwrap_or_default();
                let name = extract_json_field(&body, "name");
                Ok(VerifyResult {
                    secret_type: "npm".to_string(),
                    is_valid: true,
                    message: format!("Valid npm token for: {}", name.unwrap_or("unknown")),
                    details: None,
                })
            } else {
                Ok(VerifyResult {
                    secret_type: "npm".to_string(),
                    is_valid: false,
                    message: format!("Invalid npm token (status: {})", resp.status()),
                    details: None,
                })
            }
        }
        Err(e) => Ok(VerifyResult {
            secret_type: "npm".to_string(),
            is_valid: false,
            message: format!("Verification failed: {}", e),
            details: None,
        }),
    }
}

fn verify_pypi(_secret: &str, _timeout: Duration) -> Result<VerifyResult, String> {
    // PyPI doesn't have a simple auth check endpoint
    Ok(VerifyResult {
        secret_type: "pypi".to_string(),
        is_valid: false,
        message: "PyPI token verification requires attempting a publish".to_string(),
        details: Some("Use 'twine check' or attempt a test publish to verify".to_string()),
    })
}

/// Simple JSON field extractor (avoids full serde_json dependency)
fn extract_json_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let pattern = format!("\"{}\":\"", field);
    let start = json.find(&pattern)?;
    let value_start = start + pattern.len();
    let value_end = json[value_start..].find('"')?;
    Some(&json[value_start..value_start + value_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_secret_type() {
        assert_eq!(detect_secret_type("AKIAIOSFODNN7EXAMPLE"), "aws");
        assert_eq!(detect_secret_type("ghp_xxxxxxxxxxxx"), "github");
        assert_eq!(detect_secret_type("xoxb-123-456-abc"), "slack");
        assert_eq!(detect_secret_type("sk_live_xxxxx"), "stripe");
        assert_eq!(detect_secret_type("npm_xxxxx"), "npm");
        assert_eq!(detect_secret_type("pypi-xxxxx"), "pypi");
        assert_eq!(detect_secret_type("random"), "unknown");
    }

    #[test]
    fn test_extract_json_field() {
        let json = r#"{"login":"testuser","id":12345}"#;
        assert_eq!(extract_json_field(json, "login"), Some("testuser"));
        assert_eq!(extract_json_field(json, "missing"), None);
    }

    #[test]
    fn test_verify_unknown_type() {
        let result = verify_secret("random_string", None, 5).unwrap();
        assert!(!result.is_valid);
        assert!(result.message.contains("not supported"));
    }
}
