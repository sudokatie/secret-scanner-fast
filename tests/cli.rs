use assert_cmd::Command;
use predicates::prelude::*;

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
