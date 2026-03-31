use assert_cmd::Command;
use predicates::prelude::*;

fn fixture_path(name: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../tests/fixtures/{}", manifest, name)
}

#[test]
fn trivially_safe_contract() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("safe.hex");
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
fn solc_json_input() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("contract.json");
    std::fs::write(&file, r#"{"evm":{"deployedBytecode":{"object":"600000"}}}"#).unwrap();

    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("scan")
        .arg(file.as_os_str())
        .assert()
        .success()
        .stdout(predicate::str::contains("No issues found"));
}

#[test]
fn hex_with_0x_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("prefixed.hex");
    std::fs::write(&file, "0x600000").unwrap();

    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("scan")
        .arg(file.as_os_str())
        .assert()
        .success()
        .stdout(predicate::str::contains("No issues found"));
}

#[test]
fn inline_reentrancy_detected() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("reent.hex");
    // Minimal: 7x PUSH 0 + CALL + PUSH val + PUSH slot + SSTORE + STOP
    let mut hex = String::new();
    for _ in 0..7 {
        hex.push_str("6000");
    }
    hex.push_str("F1"); // CALL
    hex.push_str("6042"); // PUSH val
    hex.push_str("6000"); // PUSH slot
    hex.push_str("55"); // SSTORE
    hex.push_str("00"); // STOP
    std::fs::write(&file, &hex).unwrap();

    Command::cargo_bin("r-evm-verify")
        .unwrap()
        .arg("scan")
        .arg(file.as_os_str())
        .assert()
        .failure()
        .stdout(predicate::str::contains("Reentrancy"));
}
