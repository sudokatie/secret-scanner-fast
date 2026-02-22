use crate::detection::allowlist::Allowlist;
use crate::detection::matcher::{CustomRule, Matcher};
use crate::detection::rules::Severity;
use crate::output::finding::{Finding, GitInfo};
use git2::{Commit, Repository};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct HistoryOptions {
    pub since: Option<String>,
    pub max_commits: Option<usize>,
}

pub struct GitScanner {
    repo: Repository,
    min_severity: Severity,
    custom_rules: Vec<CustomRule>,
    allowlist: Allowlist,
}

impl GitScanner {
    pub fn new(path: &Path, min_severity: Severity) -> Result<Self, git2::Error> {
        let repo = Repository::discover(path)?;
        Ok(Self {
            repo,
            min_severity,
            custom_rules: Vec::new(),
            allowlist: Allowlist::new(),
        })
    }

    pub fn with_custom_rules(mut self, rules: Vec<CustomRule>) -> Self {
        self.custom_rules = rules;
        self
    }

    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Build a configured matcher
    fn build_matcher(&self) -> Matcher {
        Matcher::new(self.min_severity)
            .with_custom_rules(self.custom_rules.clone())
            .with_allowlist(self.allowlist.clone())
    }

    /// Scan staged changes (for pre-commit hooks)
    pub fn scan_staged(&self) -> Result<Vec<Finding>, git2::Error> {
        let head = self.repo.head()?.peel_to_tree()?;
        let index = self.repo.index()?;

        let diff = self
            .repo
            .diff_tree_to_index(Some(&head), Some(&index), None)?;

        self.scan_diff_lines(&diff, None)
    }

    /// Scan diff against a reference (e.g., HEAD~5, main)
    pub fn scan_diff(&self, reference: &str) -> Result<Vec<Finding>, git2::Error> {
        let ref_obj = self.repo.revparse_single(reference)?;
        let ref_tree = ref_obj.peel_to_tree()?;

        let head = self.repo.head()?.peel_to_tree()?;

        let diff = self
            .repo
            .diff_tree_to_tree(Some(&ref_tree), Some(&head), None)?;

        self.scan_diff_lines(&diff, None)
    }

    /// Scan git history
    pub fn scan_history(&self, opts: &HistoryOptions) -> Result<Vec<Finding>, git2::Error> {
        let mut findings = Vec::new();
        let mut revwalk = self.repo.revwalk()?;
        revwalk.push_head()?;
        revwalk.set_sorting(git2::Sort::TIME)?;

        let max_commits = opts.max_commits.unwrap_or(100);
        let mut count = 0;

        for oid in revwalk {
            if count >= max_commits {
                break;
            }

            let oid = oid?;
            let commit = self.repo.find_commit(oid)?;

            // Check since filter
            if let Some(ref since) = opts.since {
                if let Ok(since_date) = chrono::NaiveDate::parse_from_str(since, "%Y-%m-%d") {
                    let commit_date = chrono::DateTime::from_timestamp(commit.time().seconds(), 0)
                        .map(|dt| dt.date_naive());
                    if let Some(cd) = commit_date {
                        if cd < since_date {
                            continue;
                        }
                    }
                }
            }

            // Scan commit diff
            let commit_findings = self.scan_commit(&commit)?;
            findings.extend(commit_findings);
            count += 1;
        }

        Ok(findings)
    }

    fn scan_commit(&self, commit: &Commit) -> Result<Vec<Finding>, git2::Error> {
        let tree = commit.tree()?;

        // Get parent tree for diff
        let parent_tree = if commit.parent_count() > 0 {
            Some(commit.parent(0)?.tree()?)
        } else {
            None
        };

        let diff = self
            .repo
            .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), None)?;

        let git_info = GitInfo {
            commit_sha: commit.id().to_string()[..8].to_string(),
            author: commit.author().name().unwrap_or("unknown").to_string(),
            date: chrono::DateTime::from_timestamp(commit.time().seconds(), 0)
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
            message: commit
                .message()
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
        };

        self.scan_diff_lines(&diff, Some(git_info))
    }

    fn scan_diff_lines(
        &self,
        diff: &git2::Diff,
        git_info: Option<GitInfo>,
    ) -> Result<Vec<Finding>, git2::Error> {
        let mut findings = Vec::new();
        let matcher = self.build_matcher();

        diff.foreach(
            &mut |_delta, _progress| true,
            None,
            None,
            Some(&mut |delta, _hunk, line| {
                // Only scan added lines
                if line.origin() != '+' {
                    return true;
                }

                let file_path = delta
                    .new_file()
                    .path()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("unknown"));

                if let Ok(content) = std::str::from_utf8(line.content()) {
                    let line_num = line.new_lineno().unwrap_or(0) as usize;
                    let mut line_findings = matcher.match_line(content, line_num, &file_path);

                    // Add git info to findings
                    for finding in &mut line_findings {
                        finding.git_info = git_info.clone();
                    }

                    findings.extend(line_findings);
                }

                true
            }),
        )?;

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn setup_git_repo() -> TempDir {
        let temp = TempDir::new().unwrap();

        // Initialize repo
        Command::new("git")
            .args(["init"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Configure git
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        temp
    }

    #[test]
    fn test_scan_staged_clean() {
        let temp = setup_git_repo();

        // Create and commit a clean file
        std::fs::write(temp.path().join("clean.py"), "x = 42\n").unwrap();
        Command::new("git")
            .args(["add", "clean.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Stage a clean change
        std::fs::write(temp.path().join("clean.py"), "x = 43\n").unwrap();
        Command::new("git")
            .args(["add", "clean.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        let scanner = GitScanner::new(temp.path(), Severity::Low).unwrap();
        let findings = scanner.scan_staged().unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_staged_with_secret() {
        let temp = setup_git_repo();

        // Create and commit initial file
        std::fs::write(temp.path().join("config.py"), "x = 42\n").unwrap();
        Command::new("git")
            .args(["add", "config.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Stage a file with secret (non-placeholder)
        std::fs::write(
            temp.path().join("config.py"),
            "aws_key = AKIAIOSFODNN7REALKEY\n",
        )
        .unwrap();
        Command::new("git")
            .args(["add", "config.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        let scanner = GitScanner::new(temp.path(), Severity::Low).unwrap();
        let findings = scanner.scan_staged().unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key");
    }

    #[test]
    fn test_scan_history() {
        let temp = setup_git_repo();

        // Create initial commit
        std::fs::write(temp.path().join("clean.py"), "x = 42\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Create commit with secret (non-placeholder)
        std::fs::write(
            temp.path().join("config.py"),
            "aws_key = AKIAIOSFODNN7REALKEY\n",
        )
        .unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "add config"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        let scanner = GitScanner::new(temp.path(), Severity::Low).unwrap();
        let findings = scanner.scan_history(&HistoryOptions::default()).unwrap();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "aws-access-key"));
        assert!(findings[0].git_info.is_some());
    }

    #[test]
    fn test_placeholder_filtered_in_git() {
        let temp = setup_git_repo();

        // Create and commit initial file
        std::fs::write(temp.path().join("config.py"), "x = 42\n").unwrap();
        Command::new("git")
            .args(["add", "config.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        // Stage a file with placeholder secret
        std::fs::write(
            temp.path().join("config.py"),
            "aws_key = AKIAEXAMPLE12345678\n",
        )
        .unwrap();
        Command::new("git")
            .args(["add", "config.py"])
            .current_dir(temp.path())
            .output()
            .unwrap();

        let scanner = GitScanner::new(temp.path(), Severity::Low).unwrap();
        let findings = scanner.scan_staged().unwrap();

        assert!(
            findings.is_empty(),
            "Placeholder EXAMPLE should be filtered"
        );
    }
}
