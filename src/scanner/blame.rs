use crate::output::finding::GitInfo;
use git2::{BlameOptions, Repository};
use std::collections::HashMap;
use std::path::Path;

/// Git blame lookup for enriching findings with author info
pub struct BlameCache {
    repo: Repository,
    cache: HashMap<String, Vec<GitInfo>>,
}

impl BlameCache {
    /// Create a new blame cache for the repository at the given path
    pub fn new(path: &Path) -> Result<Self, git2::Error> {
        let repo = Repository::discover(path)?;
        Ok(Self {
            repo,
            cache: HashMap::new(),
        })
    }

    /// Get blame info for a specific file and line
    pub fn blame_line(&mut self, file: &Path, line: usize) -> Option<GitInfo> {
        let file_str = file.to_string_lossy().to_string();

        // Check cache first
        if let Some(blame_info) = self.cache.get(&file_str) {
            if line > 0 && line <= blame_info.len() {
                return Some(blame_info[line - 1].clone());
            }
        }

        // Compute blame for entire file and cache it
        if let Some(blame_info) = self.compute_file_blame(file) {
            let result = if line > 0 && line <= blame_info.len() {
                Some(blame_info[line - 1].clone())
            } else {
                None
            };
            self.cache.insert(file_str, blame_info);
            return result;
        }

        None
    }

    fn compute_file_blame(&self, file: &Path) -> Option<Vec<GitInfo>> {
        // Get workdir-relative path
        let workdir = self.repo.workdir()?;
        
        // Handle both absolute and relative paths
        let relative_path: std::borrow::Cow<Path> = if file.is_absolute() {
            match file.strip_prefix(workdir) {
                Ok(rel) => std::borrow::Cow::Borrowed(rel),
                Err(_) => return None, // File is not in this repo
            }
        } else {
            std::borrow::Cow::Borrowed(file)
        };

        let mut opts = BlameOptions::new();
        let blame = self
            .repo
            .blame_file(&relative_path, Some(&mut opts))
            .ok()?;

        // Count lines by iterating hunks
        let line_count: usize = blame.iter().map(|hunk| hunk.lines_in_hunk()).sum();

        let mut blame_info = Vec::with_capacity(line_count);

        for hunk in blame.iter() {
            let sig = hunk.final_signature();
            let commit_id = hunk.final_commit_id();

            // Get commit for message
            let message = self
                .repo
                .find_commit(commit_id)
                .ok()
                .and_then(|c| c.message().map(|s| s.lines().next().unwrap_or("").to_string()))
                .unwrap_or_default();

            let info = GitInfo {
                commit_sha: commit_id.to_string()[..8].to_string(),
                author: sig.name().unwrap_or("unknown").to_string(),
                date: chrono::DateTime::from_timestamp(sig.when().seconds(), 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_default(),
                message,
            };

            // Add one entry per line in the hunk
            for _ in 0..hunk.lines_in_hunk() {
                blame_info.push(info.clone());
            }
        }

        Some(blame_info)
    }
}

/// Filter findings by author
pub fn filter_by_author<'a>(
    findings: impl Iterator<Item = &'a mut crate::output::finding::Finding>,
    author: &str,
) -> Vec<&'a mut crate::output::finding::Finding> {
    let author_lower = author.to_lowercase();
    findings
        .filter(|f| {
            f.git_info
                .as_ref()
                .map(|gi| gi.author.to_lowercase().contains(&author_lower))
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn setup_git_repo() -> TempDir {
        let temp = TempDir::new().unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.email", "alice@test.com"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.name", "Alice"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Create a file with content
        std::fs::write(temp.path().join("test.py"), "line1\nline2\nline3\n").unwrap();

        Command::new("git")
            .args(["add", "test.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["commit", "-m", "initial commit"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        temp
    }

    #[test]
    fn test_blame_cache_creation() {
        let temp = setup_git_repo();
        let cache = BlameCache::new(temp.path());
        assert!(cache.is_ok());
    }

    #[test]
    fn test_blame_line() {
        let temp = setup_git_repo();
        let mut cache = BlameCache::new(temp.path()).unwrap();

        // Use relative path - that's what the blame expects
        let file_path = std::path::Path::new("test.py");
        let info = cache.blame_line(file_path, 1);

        assert!(info.is_some(), "Expected Some but got None for blame_line");
        let info = info.unwrap();
        assert_eq!(info.author, "Alice");
        assert!(!info.commit_sha.is_empty());
        assert_eq!(info.message, "initial commit");
    }

    #[test]
    fn test_blame_line_cached() {
        let temp = setup_git_repo();
        let mut cache = BlameCache::new(temp.path()).unwrap();

        // Use relative path
        let file_path = std::path::Path::new("test.py");

        // First call computes blame
        let info1 = cache.blame_line(file_path, 1);
        // Second call uses cache
        let info2 = cache.blame_line(file_path, 2);

        assert!(info1.is_some(), "Expected Some but got None for line 1");
        assert!(info2.is_some(), "Expected Some but got None for line 2");
        // Both from same commit
        assert_eq!(info1.unwrap().commit_sha, info2.unwrap().commit_sha);
    }

    #[test]
    fn test_blame_line_out_of_range() {
        let temp = setup_git_repo();
        let mut cache = BlameCache::new(temp.path()).unwrap();

        // Use relative path
        let file_path = std::path::Path::new("test.py");
        let info = cache.blame_line(file_path, 100);

        assert!(info.is_none());
    }

    #[test]
    fn test_blame_nonexistent_file() {
        let temp = setup_git_repo();
        let mut cache = BlameCache::new(temp.path()).unwrap();

        let file_path = temp.path().join("nonexistent.py");
        let info = cache.blame_line(&file_path, 1);

        assert!(info.is_none());
    }

    #[test]
    fn test_filter_by_author() {
        use crate::detection::rules::Severity;
        use crate::output::finding::{Finding, Location};
        use std::path::PathBuf;

        let mut findings = vec![
            Finding {
                rule_id: "test".to_string(),
                severity: Severity::High,
                location: Location {
                    file: PathBuf::from("a.py"),
                    line: 1,
                    column: 1,
                    end_column: 10,
                },
                matched_value: "secret".to_string(),
                context: "x = secret".to_string(),
                git_info: Some(GitInfo {
                    commit_sha: "abc123".to_string(),
                    author: "Alice".to_string(),
                    date: "2024-01-01".to_string(),
                    message: "commit 1".to_string(),
                }),
            },
            Finding {
                rule_id: "test".to_string(),
                severity: Severity::High,
                location: Location {
                    file: PathBuf::from("b.py"),
                    line: 1,
                    column: 1,
                    end_column: 10,
                },
                matched_value: "secret".to_string(),
                context: "x = secret".to_string(),
                git_info: Some(GitInfo {
                    commit_sha: "def456".to_string(),
                    author: "Bob".to_string(),
                    date: "2024-01-02".to_string(),
                    message: "commit 2".to_string(),
                }),
            },
        ];

        let filtered = filter_by_author(findings.iter_mut(), "alice");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].location.file.to_string_lossy(), "a.py");
    }

    #[test]
    fn test_filter_by_author_case_insensitive() {
        use crate::detection::rules::Severity;
        use crate::output::finding::{Finding, Location};
        use std::path::PathBuf;

        let mut findings = vec![Finding {
            rule_id: "test".to_string(),
            severity: Severity::High,
            location: Location {
                file: PathBuf::from("a.py"),
                line: 1,
                column: 1,
                end_column: 10,
            },
            matched_value: "secret".to_string(),
            context: "x = secret".to_string(),
            git_info: Some(GitInfo {
                commit_sha: "abc123".to_string(),
                author: "Alice Smith".to_string(),
                date: "2024-01-01".to_string(),
                message: "commit".to_string(),
            }),
        }];

        let filtered = filter_by_author(findings.iter_mut(), "ALICE");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_by_author_partial_match() {
        use crate::detection::rules::Severity;
        use crate::output::finding::{Finding, Location};
        use std::path::PathBuf;

        let mut findings = vec![Finding {
            rule_id: "test".to_string(),
            severity: Severity::High,
            location: Location {
                file: PathBuf::from("a.py"),
                line: 1,
                column: 1,
                end_column: 10,
            },
            matched_value: "secret".to_string(),
            context: "x = secret".to_string(),
            git_info: Some(GitInfo {
                commit_sha: "abc123".to_string(),
                author: "Alice Smith".to_string(),
                date: "2024-01-01".to_string(),
                message: "commit".to_string(),
            }),
        }];

        let filtered = filter_by_author(findings.iter_mut(), "smith");
        assert_eq!(filtered.len(), 1);
    }
}
