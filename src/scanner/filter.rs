use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

/// Built-in paths to always skip
const DEFAULT_EXCLUDES: &[&str] = &[
    "**/.git/**",
    "**/node_modules/**",
    "**/vendor/**",
    "**/__pycache__/**",
    "**/target/**",
    "**/dist/**",
    "**/build/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/Cargo.lock",
    "**/poetry.lock",
    "**/*.wasm",
    "**/*.pyc",
    "**/*.pyo",
    "**/*.so",
    "**/*.dylib",
    "**/*.dll",
];

pub struct PathFilter {
    gitignore: Option<Gitignore>,
    excludes: GlobSet,
    includes: Option<GlobSet>,
}

impl PathFilter {
    pub fn new(root: &Path, exclude_patterns: &[String], include_patterns: &[String]) -> Self {
        // Load .gitignore if present
        let gitignore = {
            let gitignore_path = root.join(".gitignore");
            if gitignore_path.exists() {
                let mut builder = GitignoreBuilder::new(root);
                builder.add(&gitignore_path);
                builder.build().ok()
            } else {
                None
            }
        };

        // Build exclude patterns
        let mut exclude_builder = GlobSetBuilder::new();
        for pattern in DEFAULT_EXCLUDES {
            if let Ok(glob) = Glob::new(pattern) {
                exclude_builder.add(glob);
            }
        }
        for pattern in exclude_patterns {
            if let Ok(glob) = Glob::new(pattern) {
                exclude_builder.add(glob);
            }
        }
        let excludes = exclude_builder.build().unwrap_or_else(|_| GlobSet::empty());

        // Build include patterns
        let includes = if include_patterns.is_empty() {
            None
        } else {
            let mut include_builder = GlobSetBuilder::new();
            for pattern in include_patterns {
                if let Ok(glob) = Glob::new(pattern) {
                    include_builder.add(glob);
                }
            }
            include_builder.build().ok()
        };

        Self {
            gitignore,
            excludes,
            includes,
        }
    }

    /// Check if path should be scanned
    pub fn should_scan(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check gitignore
        if let Some(ref gi) = self.gitignore {
            if gi.matched(path, path.is_dir()).is_ignore() {
                return false;
            }
        }

        // Check exclude patterns
        if self.excludes.is_match(path) || self.excludes.is_match(path_str.as_ref()) {
            return false;
        }

        // Check include patterns (if specified, must match)
        if let Some(ref includes) = self.includes {
            if !includes.is_match(path) && !includes.is_match(path_str.as_ref()) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_default_excludes() {
        let temp = TempDir::new().unwrap();
        let filter = PathFilter::new(temp.path(), &[], &[]);

        // These should be excluded by default
        assert!(!filter.should_scan(Path::new("project/.git/config")));
        assert!(!filter.should_scan(Path::new("app/node_modules/pkg/index.js")));
        assert!(!filter.should_scan(Path::new("target/debug/binary")));
        assert!(!filter.should_scan(Path::new("bundle.min.js")));
        assert!(!filter.should_scan(Path::new("package-lock.json")));

        // These should be scanned
        assert!(filter.should_scan(Path::new("src/main.rs")));
        assert!(filter.should_scan(Path::new("config.yaml")));
    }

    #[test]
    fn test_custom_excludes() {
        let temp = TempDir::new().unwrap();
        let filter = PathFilter::new(temp.path(), &["**/secrets/**".to_string()], &[]);

        assert!(!filter.should_scan(Path::new("config/secrets/api.key")));
        assert!(filter.should_scan(Path::new("config/settings.yaml")));
    }

    #[test]
    fn test_includes() {
        let temp = TempDir::new().unwrap();
        let filter = PathFilter::new(temp.path(), &[], &["**/*.py".to_string()]);

        assert!(filter.should_scan(Path::new("src/main.py")));
        assert!(!filter.should_scan(Path::new("src/main.rs")));
    }

    #[test]
    fn test_gitignore() {
        let temp = TempDir::new().unwrap();
        let mut gitignore = std::fs::File::create(temp.path().join(".gitignore")).unwrap();
        writeln!(gitignore, "*.secret").unwrap();
        writeln!(gitignore, "private/**").unwrap();

        // Create the actual directory structure
        std::fs::create_dir_all(temp.path().join("private")).unwrap();
        std::fs::write(temp.path().join("api.secret"), "test").unwrap();
        std::fs::write(temp.path().join("private/data.txt"), "test").unwrap();

        let filter = PathFilter::new(temp.path(), &[], &[]);

        // These would be in .gitignore
        assert!(!filter.should_scan(&temp.path().join("api.secret")));
        assert!(!filter.should_scan(&temp.path().join("private/data.txt")));

        // These should be scanned
        assert!(filter.should_scan(&temp.path().join("config.yaml")));
    }
}
