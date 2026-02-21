use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub output: OutputConfig,

    #[serde(default)]
    pub rules: RulesConfig,
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
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            redact: true,
            color: true,
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
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            min_severity: default_severity(),
            disable: Vec::new(),
            allowlist: Vec::new(),
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
            },
            rules: RulesConfig {
                min_severity: "low".to_string(),
                disable: Vec::new(),
                allowlist: vec![AllowlistEntry {
                    pattern: "EXAMPLE|example|test|fake".to_string(),
                    files: Vec::new(),
                    reason: Some("Test/example values".to_string()),
                }],
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
