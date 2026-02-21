use regex::Regex;
use std::path::Path;

/// Entry in the allowlist
#[derive(Debug, Clone)]
pub struct AllowlistEntry {
    pub pattern: Regex,
    pub files: Option<Vec<String>>,
    pub reason: Option<String>,
}

impl AllowlistEntry {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: Regex::new(pattern)?,
            files: None,
            reason: None,
        })
    }

    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = Some(files);
        self
    }

    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    /// Check if this entry matches a finding
    pub fn matches(&self, value: &str, file: &Path) -> bool {
        // Check pattern against value
        if !self.pattern.is_match(value) {
            return false;
        }

        // If file filter is set, check it
        if let Some(ref files) = self.files {
            let file_str = file.to_string_lossy();
            if !files.iter().any(|f| file_str.contains(f)) {
                return false;
            }
        }

        true
    }
}

/// Collection of allowlist entries
pub struct Allowlist {
    entries: Vec<AllowlistEntry>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: AllowlistEntry) {
        self.entries.push(entry);
    }

    pub fn add_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        self.entries.push(AllowlistEntry::new(pattern)?);
        Ok(())
    }

    /// Check if a value/file combination should be allowed (skipped)
    pub fn is_allowed(&self, value: &str, file: &Path) -> bool {
        self.entries.iter().any(|e| e.matches(value, file))
    }

    /// Load from config allowlist entries
    pub fn from_config(entries: &[crate::config::schema::AllowlistEntry]) -> Self {
        let mut allowlist = Self::new();
        for entry in entries {
            if let Ok(regex) = Regex::new(&entry.pattern) {
                let mut al_entry = AllowlistEntry {
                    pattern: regex,
                    files: if entry.files.is_empty() {
                        None
                    } else {
                        Some(entry.files.clone())
                    },
                    reason: entry.reason.clone(),
                };
                allowlist.add(al_entry);
            }
        }
        allowlist
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_entry_matches() {
        let entry = AllowlistEntry::new("EXAMPLE|example").unwrap();

        assert!(entry.matches("AKIAEXAMPLE1234", Path::new("config.py")));
        assert!(entry.matches("example_key", Path::new("config.py")));
        assert!(!entry.matches("AKIAREALKEY1234", Path::new("config.py")));
    }

    #[test]
    fn test_allowlist_entry_with_files() {
        let entry = AllowlistEntry::new("test")
            .unwrap()
            .with_files(vec!["tests/".to_string()]);

        // Matches in test file
        assert!(entry.matches("test_key", Path::new("tests/config.py")));
        // Doesn't match in production file
        assert!(!entry.matches("test_key", Path::new("src/config.py")));
    }

    #[test]
    fn test_allowlist() {
        let mut allowlist = Allowlist::new();
        allowlist.add_pattern("EXAMPLE").unwrap();
        allowlist.add_pattern("test_").unwrap();

        assert!(allowlist.is_allowed("AKIAEXAMPLE", Path::new("config.py")));
        assert!(allowlist.is_allowed("test_api_key", Path::new("config.py")));
        assert!(!allowlist.is_allowed("AKIAREALKEY", Path::new("config.py")));
    }

    #[test]
    fn test_empty_allowlist() {
        let allowlist = Allowlist::new();
        assert!(!allowlist.is_allowed("anything", Path::new("file.py")));
    }
}
