//! Config loading with precedence from multiple locations

use crate::config::schema::Config;
use std::path::{Path, PathBuf};
use std::fs;

/// Config file names to search for
const CONFIG_NAMES: &[&str] = &[
    ".secretscanner.yaml",
    ".secretscanner.yml",
    ".secretscannerignore",  // Alternative name per spec
];

/// Load config with precedence:
/// 1. Explicit path (--config flag)
/// 2. Current directory
/// 3. Git repo root
/// 4. ~/.config/secretscanner/config.yaml
/// 5. Built-in defaults
pub fn load_config(explicit_path: Option<&Path>, scan_path: &Path) -> Config {
    // If explicit path given, use it
    if let Some(path) = explicit_path {
        if let Some(config) = load_from_path(path) {
            return config;
        }
    }

    // Check current directory
    for name in CONFIG_NAMES {
        let path = scan_path.join(name);
        if let Some(config) = load_from_path(&path) {
            return config;
        }
    }

    // Check git repo root
    if let Some(repo_root) = find_git_root(scan_path) {
        for name in CONFIG_NAMES {
            let path = repo_root.join(name);
            if let Some(config) = load_from_path(&path) {
                return config;
            }
        }
    }

    // Check ~/.config/secretscanner/
    if let Some(home) = dirs::home_dir() {
        let config_dir = home.join(".config").join("secretscanner");
        for name in &["config.yaml", "config.yml"] {
            let path = config_dir.join(name);
            if let Some(config) = load_from_path(&path) {
                return config;
            }
        }
    }

    // Fall back to defaults
    Config::default()
}

/// Load config from a specific path
fn load_from_path(path: &Path) -> Option<Config> {
    if !path.exists() {
        return None;
    }

    let content = fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&content).ok()
}

/// Find git repository root by walking up directories
fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    
    // Handle if start is a file
    if current.is_file() {
        current = current.parent()?.to_path_buf();
    }

    loop {
        if current.join(".git").exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_defaults_when_no_config() {
        let temp = TempDir::new().unwrap();
        let config = load_config(None, temp.path());
        assert_eq!(config.output.format, "text");
        assert!(config.output.redact);
    }

    #[test]
    fn test_load_from_current_dir() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join(".secretscanner.yaml");
        fs::write(&config_path, "output:\n  format: json\n").unwrap();

        let config = load_config(None, temp.path());
        assert_eq!(config.output.format, "json");
    }

    #[test]
    fn test_explicit_path_takes_precedence() {
        let temp = TempDir::new().unwrap();
        
        // Create config in current dir
        let local = temp.path().join(".secretscanner.yaml");
        fs::write(&local, "output:\n  format: text\n").unwrap();
        
        // Create explicit config
        let explicit = temp.path().join("custom.yaml");
        fs::write(&explicit, "output:\n  format: sarif\n").unwrap();

        let config = load_config(Some(&explicit), temp.path());
        assert_eq!(config.output.format, "sarif");
    }

    #[test]
    fn test_find_git_root() {
        let temp = TempDir::new().unwrap();
        let git_dir = temp.path().join(".git");
        fs::create_dir(&git_dir).unwrap();

        let nested = temp.path().join("src").join("lib");
        fs::create_dir_all(&nested).unwrap();

        let root = find_git_root(&nested);
        assert_eq!(root, Some(temp.path().to_path_buf()));
    }

    #[test]
    fn test_secretscannerignore_supported() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join(".secretscannerignore");
        fs::write(&config_path, "output:\n  format: csv\n").unwrap();

        let config = load_config(None, temp.path());
        assert_eq!(config.output.format, "csv");
    }
}
