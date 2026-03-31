use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn scan_nonexistent_file() {
    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("scan")
        .arg("nonexistent.hex")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to read"));
}

#[test]
fn scan_invalid_hex() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bad.hex");
    std::fs::write(&file, "not valid hex!").unwrap();

    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("scan")
        .arg(file.as_os_str())
        .assert()
        .failure();
}

#[test]
fn scan_simple_bytecode() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.hex");
    // PUSH1 0x00 STOP — trivially safe
    std::fs::write(&file, "600000").unwrap();

    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("scan")
        .arg(file.as_os_str())
        .assert()
        .success()
        .stdout(predicate::str::contains("No issues found"));
}

#[test]
fn scan_shows_help() {
    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Parallel formal verification"));
}

#[test]
fn scan_shows_version() {
    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("--version")
        .assert()
        .success();
}
