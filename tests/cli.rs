use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_help() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("secret-scanner-fast"));
}

#[test]
fn test_version() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .arg("--version")
        .assert()
        .success();
}

#[test]
fn test_scan_help() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn test_rules_help() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["rules", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn test_init_help() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--output"));
}

#[test]
fn test_scan_clean_directory() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("clean.py"), "# No secrets here\nx = 42\n").unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets found"));
}

#[test]
fn test_scan_finds_aws_key() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.py"),
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .failure() // Exit code 1 = findings
        .stdout(predicate::str::contains("aws-access-key"))
        .stdout(predicate::str::contains("Found 1 secrets"));
}

#[test]
fn test_scan_json_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.py"),
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", "--format", "json", temp.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"rule_id\""))
        .stdout(predicate::str::contains("\"aws-access-key\""));
}

#[test]
fn test_scan_csv_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.py"),
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", "--format", "csv", temp.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("file,line,column"))
        .stdout(predicate::str::contains("aws-access-key"));
}

#[test]
fn test_scan_sarif_output() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.py"),
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", "--format", "sarif", temp.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"$schema\""))
        .stdout(predicate::str::contains("2.1.0"));
}

#[test]
fn test_scan_min_severity_filter() {
    let temp = TempDir::new().unwrap();
    // Stripe test key is LOW severity
    let test_key = format!("sk_test_{}", "x".repeat(24));
    fs::write(
        temp.path().join("config.py"),
        format!("key = {}\n", test_key),
    )
    .unwrap();

    // With --min-severity high, should NOT find it
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args([
            "scan",
            "--min-severity",
            "high",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets found"));
}

#[test]
fn test_scan_stdin() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", "-"])
        .write_stdin("key = AKIAIOSFODNN7EXAMPLE\n")
        .assert()
        .failure()
        .stdout(predicate::str::contains("aws-access-key"));
}

#[test]
fn test_rules_list() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aws-access-key"))
        .stdout(predicate::str::contains("github-token"));
}

#[test]
fn test_rules_json() {
    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["rules", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("["))
        .stdout(predicate::str::contains("aws-access-key"));
}

#[test]
fn test_init_creates_config() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join(".secretscanner.yaml");

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["init", "--output", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("scan:"));
    assert!(content.contains("output:"));
}

#[test]
fn test_init_refuses_overwrite() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join(".secretscanner.yaml");
    fs::write(&config_path, "existing").unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["init", "--output", config_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_init_force_overwrite() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join(".secretscanner.yaml");
    fs::write(&config_path, "existing").unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args([
            "init",
            "--force",
            "--output",
            config_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("scan:")); // Was overwritten
}

#[test]
fn test_scan_skips_binary() {
    let temp = TempDir::new().unwrap();
    // Write binary file with null bytes
    fs::write(temp.path().join("binary.bin"), &[0u8, 1, 2, 3, 0, 5]).unwrap();
    // Write text file with secret
    fs::write(
        temp.path().join("config.py"),
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Scanned 1 files")); // Only scanned the text file
}

#[test]
fn test_scan_excludes_node_modules() {
    let temp = TempDir::new().unwrap();

    // node_modules is excluded by default
    fs::create_dir(temp.path().join("node_modules")).unwrap();
    fs::write(
        temp.path().join("node_modules/secret.js"),
        "aws_key = AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();

    // Create non-ignored file without secret
    fs::write(temp.path().join("clean.py"), "x = 42\n").unwrap();

    Command::cargo_bin("secret-scanner-fast")
        .unwrap()
        .args(["scan", temp.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets found"));
}
