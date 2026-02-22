use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub output: OutputConfig,

    #[serde(default)]
    pub rules: RulesConfig,

    #[serde(default)]
    pub git: GitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Paths to exclude (glob patterns)
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Paths to include (glob patterns)
    #[serde(default)]
    pub include: Vec<String>,

    /// Maximum file size to scan (bytes)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Number of threads (0 = auto)
    #[serde(default)]
    pub threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitConfig {
    /// Maximum commit depth for --git-history
    #[serde(default = "default_max_commit_depth")]
    pub max_commit_depth: usize,

    /// Scan all branches (not just current)
    #[serde(default)]
    pub scan_all_branches: bool,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            max_commit_depth: default_max_commit_depth(),
            scan_all_branches: false,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            exclude: Vec::new(),
            include: Vec::new(),
            max_file_size: default_max_file_size(),
            threads: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default output format
    #[serde(default = "default_format")]
    pub format: String,

    /// Whether to redact secrets by default
    #[serde(default = "default_true")]
    pub redact: bool,

    /// Whether to use colors
    #[serde(default = "default_true")]
    pub color: bool,

    /// Number of context lines around matches
    #[serde(default = "default_context_lines")]
    pub context_lines: usize,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            redact: true,
            color: true,
            context_lines: default_context_lines(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Minimum severity to report
    #[serde(default = "default_severity")]
    pub min_severity: String,

    /// Rule IDs to disable
    #[serde(default)]
    pub disable: Vec<String>,

    /// Patterns to allowlist (won't report matches)
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,

    /// Fingerprints to allowlist (specific findings to ignore)
    #[serde(default)]
    pub allow_fingerprints: Vec<String>,

    /// Custom detection rules
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            min_severity: default_severity(),
            disable: Vec::new(),
            allowlist: Vec::new(),
            allow_fingerprints: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Regex pattern to match
    pub pattern: String,

    /// Optional: only apply to specific files
    #[serde(default)]
    pub files: Vec<String>,

    /// Optional: reason for allowlisting
    #[serde(default)]
    pub reason: Option<String>,
}

/// Custom detection rule defined in config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Unique rule ID
    pub id: String,

    /// Human-readable description
    pub description: String,

    /// Regex pattern to match
    pub pattern: String,

    /// Severity level (low, medium, high)
    #[serde(default = "default_severity")]
    pub severity: String,

    /// Optional entropy threshold for validation
    #[serde(default)]
    pub entropy_threshold: Option<f64>,
}

fn default_max_file_size() -> u64 {
    1024 * 1024 // 1MB
}

fn default_format() -> String {
    "text".to_string()
}

fn default_severity() -> String {
    "low".to_string()
}

fn default_true() -> bool {
    true
}

fn default_context_lines() -> usize {
    1
}

fn default_max_commit_depth() -> usize {
    1000
}

impl Config {
    pub fn minimal() -> Self {
        Self::default()
    }

    pub fn full() -> Self {
        Self {
            scan: ScanConfig {
                exclude: vec![
                    "**/test/**".to_string(),
                    "**/*.test.*".to_string(),
                ],
                include: Vec::new(),
                max_file_size: 1024 * 1024,
                threads: 0,
            },
            output: OutputConfig {
                format: "text".to_string(),
                redact: true,
                color: true,
                context_lines: 1,
            },
            rules: RulesConfig {
                min_severity: "low".to_string(),
                disable: Vec::new(),
                allowlist: vec![AllowlistEntry {
                    pattern: "EXAMPLE|example|test|fake".to_string(),
                    files: Vec::new(),
                    reason: Some("Test/example values".to_string()),
                }],
                allow_fingerprints: Vec::new(),
                custom_rules: vec![CustomRule {
                    id: "internal-api-key".to_string(),
                    description: "Internal API key format".to_string(),
                    pattern: "INT_[A-Z0-9]{32}".to_string(),
                    severity: "high".to_string(),
                    entropy_threshold: None,
                }],
            },
            git: GitConfig {
                max_commit_depth: 1000,
                scan_all_branches: false,
            },
        }
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.scan.max_file_size, 1024 * 1024);
        assert!(config.output.redact);
    }

    #[test]
    fn test_config_to_yaml() {
        let config = Config::minimal();
        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("scan:"));
        assert!(yaml.contains("output:"));
    }

    #[test]
    fn test_full_config() {
        let config = Config::full();
        assert!(!config.scan.exclude.is_empty());
        assert!(!config.rules.allowlist.is_empty());
    }
}
