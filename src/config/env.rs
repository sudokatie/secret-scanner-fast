use std::env;
use std::path::PathBuf;

/// Environment variable configuration
pub struct EnvConfig {
    pub min_severity: Option<String>,
    pub no_color: Option<bool>,
    pub config_path: Option<PathBuf>,
}

impl EnvConfig {
    pub fn load() -> Self {
        Self {
            min_severity: env::var("SECRET_SCANNER_MIN_SEVERITY").ok(),
            no_color: env::var("SECRET_SCANNER_NO_COLOR")
                .ok()
                .map(|v| v == "1" || v.to_lowercase() == "true"),
            config_path: env::var("SECRET_SCANNER_CONFIG")
                .ok()
                .map(PathBuf::from),
        }
    }

    /// Check if NO_COLOR env var is set (standard convention)
    pub fn no_color_env() -> bool {
        env::var("NO_COLOR").is_ok() || env::var("SECRET_SCANNER_NO_COLOR").is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to serialize env var tests (they share global state)
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_env_config_min_severity() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("SECRET_SCANNER_MIN_SEVERITY");
        env::remove_var("SECRET_SCANNER_NO_COLOR");
        env::remove_var("SECRET_SCANNER_CONFIG");

        env::set_var("SECRET_SCANNER_MIN_SEVERITY", "high");
        let config = EnvConfig::load();
        assert_eq!(config.min_severity, Some("high".to_string()));
        env::remove_var("SECRET_SCANNER_MIN_SEVERITY");
    }

    #[test]
    fn test_env_config_no_color() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("SECRET_SCANNER_MIN_SEVERITY");
        env::remove_var("SECRET_SCANNER_NO_COLOR");
        env::remove_var("SECRET_SCANNER_CONFIG");

        env::set_var("SECRET_SCANNER_NO_COLOR", "1");
        let config = EnvConfig::load();
        assert_eq!(config.no_color, Some(true));
        env::remove_var("SECRET_SCANNER_NO_COLOR");
    }

    #[test]
    fn test_env_config_none_when_unset() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("SECRET_SCANNER_MIN_SEVERITY");
        env::remove_var("SECRET_SCANNER_NO_COLOR");
        env::remove_var("SECRET_SCANNER_CONFIG");

        let config = EnvConfig::load();
        assert!(config.min_severity.is_none());
        assert!(config.no_color.is_none());
        assert!(config.config_path.is_none());
    }
}
