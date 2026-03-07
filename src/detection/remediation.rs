//! Remediation suggestions for detected secrets
//!
//! Provides provider-specific guidance on rotating secrets and best practices.

use serde::{Deserialize, Serialize};

/// Remediation advice for a detected secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    /// Human-readable title
    pub title: String,
    /// Step-by-step rotation instructions
    pub steps: Vec<String>,
    /// URL to provider's key management console
    pub management_url: Option<String>,
    /// URL to provider's rotation documentation
    pub docs_url: Option<String>,
    /// Suggested .env.example pattern
    pub env_pattern: Option<String>,
}

impl Remediation {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            steps: Vec::new(),
            management_url: None,
            docs_url: None,
            env_pattern: None,
        }
    }

    pub fn with_steps(mut self, steps: Vec<&str>) -> Self {
        self.steps = steps.into_iter().map(String::from).collect();
        self
    }

    pub fn with_management_url(mut self, url: &str) -> Self {
        self.management_url = Some(url.to_string());
        self
    }

    pub fn with_docs_url(mut self, url: &str) -> Self {
        self.docs_url = Some(url.to_string());
        self
    }

    pub fn with_env_pattern(mut self, pattern: &str) -> Self {
        self.env_pattern = Some(pattern.to_string());
        self
    }
}

/// Get remediation advice for a secret type
pub fn get_remediation(secret_type: &str) -> Remediation {
    match secret_type.to_lowercase().as_str() {
        "aws_access_key" | "aws_secret_key" | "aws" => aws_remediation(),
        "github_token" | "github" => github_remediation(),
        "gitlab_token" | "gitlab" => gitlab_remediation(),
        "slack_bot_token" | "slack_user_token" | "slack_webhook" | "slack" => slack_remediation(),
        "stripe_live_key" | "stripe_test_key" | "stripe" => stripe_remediation(),
        "twilio_api_key" | "twilio" => twilio_remediation(),
        "sendgrid_api_key" | "sendgrid" => sendgrid_remediation(),
        "npm_token" | "npm" => npm_remediation(),
        "pypi_token" | "pypi" => pypi_remediation(),
        "digitalocean_token" | "digitalocean" => digitalocean_remediation(),
        "discord_bot_token" | "discord" => discord_remediation(),
        "google_api_key" | "google" => google_remediation(),
        "heroku_api_key" | "heroku" => heroku_remediation(),
        "firebase_key" | "firebase" => firebase_remediation(),
        "private_key" | "rsa" | "ssh" => private_key_remediation(),
        "generic_api_key" | "api_key" => generic_api_key_remediation(),
        "generic_secret" | "secret" => generic_secret_remediation(),
        "generic_password" | "password" => generic_password_remediation(),
        _ => default_remediation(),
    }
}

fn aws_remediation() -> Remediation {
    Remediation::new("AWS Access Key")
        .with_steps(vec![
            "Go to AWS IAM Console",
            "Select the user associated with this key",
            "Under 'Security credentials', find the access key",
            "Click 'Deactivate' to immediately disable the key",
            "Create a new access key pair",
            "Update your application with the new credentials",
            "Delete the old access key once verified",
        ])
        .with_management_url("https://console.aws.amazon.com/iam/home#/security_credentials")
        .with_docs_url("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html")
        .with_env_pattern("AWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=")
}

fn github_remediation() -> Remediation {
    Remediation::new("GitHub Token")
        .with_steps(vec![
            "Go to GitHub Settings > Developer settings > Personal access tokens",
            "Find the compromised token (check prefix: ghp_, gho_, etc.)",
            "Click 'Delete' to revoke it immediately",
            "Generate a new token with minimal required scopes",
            "Update your application/CI with the new token",
        ])
        .with_management_url("https://github.com/settings/tokens")
        .with_docs_url("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens")
        .with_env_pattern("GITHUB_TOKEN=")
}

fn gitlab_remediation() -> Remediation {
    Remediation::new("GitLab Token")
        .with_steps(vec![
            "Go to GitLab > User Settings > Access Tokens",
            "Find and revoke the compromised token",
            "Create a new token with appropriate scopes",
            "Update your CI/CD variables",
        ])
        .with_management_url("https://gitlab.com/-/profile/personal_access_tokens")
        .with_docs_url("https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html")
        .with_env_pattern("GITLAB_TOKEN=")
}

fn slack_remediation() -> Remediation {
    Remediation::new("Slack Token/Webhook")
        .with_steps(vec![
            "Go to Slack API > Your Apps",
            "Select the affected app",
            "Navigate to OAuth & Permissions or Incoming Webhooks",
            "Regenerate the token/webhook URL",
            "Update your application",
        ])
        .with_management_url("https://api.slack.com/apps")
        .with_docs_url("https://api.slack.com/authentication/token-types")
        .with_env_pattern("SLACK_BOT_TOKEN=\nSLACK_WEBHOOK_URL=")
}

fn stripe_remediation() -> Remediation {
    Remediation::new("Stripe API Key")
        .with_steps(vec![
            "Go to Stripe Dashboard > Developers > API keys",
            "Click 'Roll key' on the compromised key",
            "Update your application with the new key",
            "The old key is automatically invalidated",
        ])
        .with_management_url("https://dashboard.stripe.com/apikeys")
        .with_docs_url("https://stripe.com/docs/keys")
        .with_env_pattern("STRIPE_SECRET_KEY=\nSTRIPE_PUBLISHABLE_KEY=")
}

fn twilio_remediation() -> Remediation {
    Remediation::new("Twilio API Key")
        .with_steps(vec![
            "Go to Twilio Console > Account > API keys",
            "Delete the compromised API key",
            "Create a new API key",
            "Update your application",
        ])
        .with_management_url("https://www.twilio.com/console/project/api-keys")
        .with_docs_url("https://www.twilio.com/docs/iam/keys/api-key")
        .with_env_pattern("TWILIO_ACCOUNT_SID=\nTWILIO_AUTH_TOKEN=")
}

fn sendgrid_remediation() -> Remediation {
    Remediation::new("SendGrid API Key")
        .with_steps(vec![
            "Go to SendGrid > Settings > API Keys",
            "Delete the compromised key",
            "Create a new API key with appropriate permissions",
            "Update your application",
        ])
        .with_management_url("https://app.sendgrid.com/settings/api_keys")
        .with_docs_url("https://docs.sendgrid.com/ui/account-and-settings/api-keys")
        .with_env_pattern("SENDGRID_API_KEY=")
}

fn npm_remediation() -> Remediation {
    Remediation::new("npm Token")
        .with_steps(vec![
            "Go to npmjs.com > Account > Access Tokens",
            "Revoke the compromised token",
            "Generate a new token",
            "Update your .npmrc or CI/CD",
        ])
        .with_management_url("https://www.npmjs.com/settings/tokens")
        .with_docs_url("https://docs.npmjs.com/creating-and-viewing-access-tokens")
        .with_env_pattern("NPM_TOKEN=")
}

fn pypi_remediation() -> Remediation {
    Remediation::new("PyPI Token")
        .with_steps(vec![
            "Go to pypi.org > Account settings > API tokens",
            "Revoke the compromised token",
            "Create a new scoped token",
            "Update your .pypirc or CI/CD",
        ])
        .with_management_url("https://pypi.org/manage/account/#api-tokens")
        .with_docs_url("https://pypi.org/help/#apitoken")
        .with_env_pattern("TWINE_PASSWORD=  # Use token as password")
}

fn digitalocean_remediation() -> Remediation {
    Remediation::new("DigitalOcean Token")
        .with_steps(vec![
            "Go to DigitalOcean > API > Tokens/Keys",
            "Delete the compromised token",
            "Generate a new token",
            "Update your doctl or application",
        ])
        .with_management_url("https://cloud.digitalocean.com/account/api/tokens")
        .with_docs_url("https://docs.digitalocean.com/reference/api/create-personal-access-token/")
        .with_env_pattern("DIGITALOCEAN_ACCESS_TOKEN=")
}

fn discord_remediation() -> Remediation {
    Remediation::new("Discord Bot Token")
        .with_steps(vec![
            "Go to Discord Developer Portal",
            "Select your application",
            "Navigate to Bot > Reset Token",
            "Update your bot application immediately",
        ])
        .with_management_url("https://discord.com/developers/applications")
        .with_docs_url("https://discord.com/developers/docs/topics/oauth2")
        .with_env_pattern("DISCORD_TOKEN=")
}

fn google_remediation() -> Remediation {
    Remediation::new("Google API Key")
        .with_steps(vec![
            "Go to Google Cloud Console > APIs & Services > Credentials",
            "Find and delete the compromised API key",
            "Create a new API key with restrictions",
            "Apply HTTP referrer/IP restrictions",
            "Update your application",
        ])
        .with_management_url("https://console.cloud.google.com/apis/credentials")
        .with_docs_url("https://cloud.google.com/docs/authentication/api-keys")
        .with_env_pattern("GOOGLE_API_KEY=")
}

fn heroku_remediation() -> Remediation {
    Remediation::new("Heroku API Key")
        .with_steps(vec![
            "Go to Heroku Dashboard > Account Settings",
            "Regenerate API Key",
            "Update your Heroku CLI config",
            "Update any CI/CD integrations",
        ])
        .with_management_url("https://dashboard.heroku.com/account")
        .with_docs_url("https://devcenter.heroku.com/articles/authentication")
        .with_env_pattern("HEROKU_API_KEY=")
}

fn firebase_remediation() -> Remediation {
    Remediation::new("Firebase Server Key")
        .with_steps(vec![
            "Go to Firebase Console > Project Settings > Cloud Messaging",
            "Generate a new server key",
            "Delete the old key",
            "Update your backend application",
        ])
        .with_management_url("https://console.firebase.google.com/")
        .with_docs_url("https://firebase.google.com/docs/cloud-messaging/auth-server")
        .with_env_pattern("FIREBASE_SERVER_KEY=")
}

fn private_key_remediation() -> Remediation {
    Remediation::new("Private Key")
        .with_steps(vec![
            "Generate a new key pair immediately",
            "Replace the private key in all systems",
            "Update any corresponding public keys",
            "Revoke access using the old key if possible",
            "Consider if any systems were compromised",
        ])
        .with_docs_url("https://www.ssh.com/academy/ssh/keygen")
        .with_env_pattern("# Store private keys in files, not env vars\n# Use: SSH_KEY_PATH=/path/to/key")
}

fn generic_api_key_remediation() -> Remediation {
    Remediation::new("Generic API Key")
        .with_steps(vec![
            "Identify the service this key belongs to",
            "Access the service's API key management page",
            "Revoke or rotate the compromised key",
            "Generate a new key with minimal permissions",
            "Update your application configuration",
        ])
        .with_env_pattern("API_KEY=")
}

fn generic_secret_remediation() -> Remediation {
    Remediation::new("Generic Secret")
        .with_steps(vec![
            "Identify what this secret is used for",
            "Generate a new secret value",
            "Update all systems using this secret",
            "Consider using a secrets manager (Vault, AWS Secrets Manager)",
        ])
        .with_env_pattern("SECRET=")
}

fn generic_password_remediation() -> Remediation {
    Remediation::new("Password")
        .with_steps(vec![
            "Change the password immediately",
            "Check for unauthorized access",
            "Enable 2FA/MFA if available",
            "Consider using a password manager",
            "Never commit passwords to version control",
        ])
        .with_env_pattern("# Use environment variables or secrets manager\nDB_PASSWORD=")
}

fn default_remediation() -> Remediation {
    Remediation::new("Secret/Credential")
        .with_steps(vec![
            "Identify the type and purpose of this secret",
            "Revoke or rotate the secret immediately",
            "Generate a new secret following best practices",
            "Store secrets in environment variables or a secrets manager",
            "Never commit secrets to version control",
            "Add patterns to .gitignore and use pre-commit hooks",
        ])
        .with_env_pattern("# Use .env files (not committed) or secrets manager")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_remediation() {
        let r = get_remediation("aws_access_key");
        assert_eq!(r.title, "AWS Access Key");
        assert!(!r.steps.is_empty());
        assert!(r.management_url.is_some());
        assert!(r.docs_url.is_some());
        assert!(r.env_pattern.is_some());
    }

    #[test]
    fn test_github_remediation() {
        let r = get_remediation("github_token");
        assert_eq!(r.title, "GitHub Token");
        assert!(r.management_url.unwrap().contains("github.com"));
    }

    #[test]
    fn test_slack_remediation() {
        let r = get_remediation("slack_bot_token");
        assert_eq!(r.title, "Slack Token/Webhook");
    }

    #[test]
    fn test_stripe_remediation() {
        let r = get_remediation("stripe_live_key");
        assert_eq!(r.title, "Stripe API Key");
        assert!(r.steps.iter().any(|s| s.contains("Roll key")));
    }

    #[test]
    fn test_unknown_type_fallback() {
        let r = get_remediation("unknown_secret_type");
        assert_eq!(r.title, "Secret/Credential");
        assert!(!r.steps.is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let r1 = get_remediation("AWS_ACCESS_KEY");
        let r2 = get_remediation("aws_access_key");
        assert_eq!(r1.title, r2.title);
    }

    #[test]
    fn test_env_patterns() {
        let r = get_remediation("npm");
        assert!(r.env_pattern.unwrap().contains("NPM_TOKEN"));
    }

    #[test]
    fn test_private_key() {
        let r = get_remediation("private_key");
        assert!(r.env_pattern.unwrap().contains("SSH_KEY_PATH"));
    }

    #[test]
    fn test_all_providers_have_steps() {
        let providers = vec![
            "aws", "github", "gitlab", "slack", "stripe",
            "twilio", "sendgrid", "npm", "pypi", "digitalocean",
            "discord", "google", "heroku", "firebase", "private_key",
        ];
        
        for provider in providers {
            let r = get_remediation(provider);
            assert!(!r.steps.is_empty(), "Provider {} should have steps", provider);
        }
    }
}
