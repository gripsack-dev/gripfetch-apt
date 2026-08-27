//! End-to-end exchange tests: spawn the built binary exactly the way
//! the core does (one JSON request on stdin, NDJSON on stdout) and
//! assert the protocol invariants that matter most: exactly one
//! response, diagnostics shaped, failures loud AND non-empty, the
//! capabilities op answered.

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

fn exchange(stdin: &str) -> (Vec<Value>, String, Option<i32>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gripfetch-apt"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .ok();
    let output = child.wait_with_output().expect("wait");
    let messages = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (messages, stderr, output.status.code())
}

fn responses(messages: &[Value]) -> Vec<&Value> {
    messages
        .iter()
        .filter(|m| m.get("type").and_then(Value::as_str) == Some("response"))
        .collect()
}

fn diagnostics(messages: &[Value]) -> Vec<&Value> {
    messages
        .iter()
        .filter(|m| m.get("type").and_then(Value::as_str) == Some("diagnostic"))
        .map(|m| m.get("diagnostic").expect("diagnostic field"))
        .collect()
}

#[test]
fn capabilities_declares_empty_throttle() {
    let (messages, _stderr, code) = exchange(r#"{"op":"capabilities"}"#);
    assert_eq!(code, Some(0), "capabilities must exit 0");
    let responses = responses(&messages);
    assert_eq!(responses.len(), 1, "one response");
    let throttle = &responses[0]["result"]["capabilities"]["throttle"];
    assert!(throttle.as_object().expect("throttle map").is_empty());
}

#[test]
fn fetch_without_package_is_a_loud_error() {
    let (messages, _stderr, code) =
        exchange(r#"{"op":"fetch","args":{},"dest_dir":"/tmp/gripfetch-apt-it-1"}"#);
    assert_ne!(code, Some(0));
    assert_eq!(responses(&messages).len(), 1, "still exactly one response");
    let errors: Vec<_> = diagnostics(&messages)
        .into_iter()
        .filter(|d| d.get("severity").and_then(Value::as_str) == Some("error"))
        .collect();
    assert!(!errors.is_empty(), "an error diagnostic is required");
    for diagnostic in diagnostics(&messages) {
        for field in ["code", "severity", "message", "labels"] {
            assert!(diagnostic.get(field).is_some(), "missing {field}");
        }
    }
}

#[test]
fn garbage_request_line_is_never_a_silent_death() {
    let (messages, stderr, code) = exchange("this is not json\n");
    assert_ne!(code, Some(0));
    assert_eq!(
        responses(&messages).len(),
        1,
        "one response even on garbage"
    );
    assert!(!stderr.trim().is_empty() || !diagnostics(&messages).is_empty());
}

#[test]
fn unknown_op_is_rejected_loudly() {
    let (messages, _stderr, code) = exchange(r#"{"op":"frobnicate"}"#);
    assert_ne!(code, Some(0));
    assert_eq!(responses(&messages).len(), 1);
    assert!(diagnostics(&messages)
        .iter()
        .any(|d| d.get("severity").and_then(Value::as_str) == Some("error")));
}

#[cfg(target_os = "linux")]
#[test]
fn unknown_package_fails_loudly_and_stages_a_note() {
    // a package no index knows: resolve fails, the fetch must fail
    // loudly — error diagnostic + response + nonzero exit + a staged
    // deterministic note (never an empty tree masquerading as success)
    let dest = std::env::temp_dir().join(format!("gripfetch-apt-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::create_dir_all(&dest).unwrap();
    let request = json!({
        "op": "fetch",
        "args": {"package": "definitely-not-a-real-package-gfa", "version": "1.0.0"},
        "dest_dir": dest,
    })
    .to_string();
    let (messages, _stderr, code) = exchange(&request);
    assert_ne!(
        code,
        Some(0),
        "an unfetchable package must fail the exchange"
    );
    assert_eq!(responses(&messages).len(), 1);
    let errors: Vec<_> = diagnostics(&messages)
        .into_iter()
        .filter(|d| d.get("severity").and_then(Value::as_str) == Some("error"))
        .collect();
    assert!(!errors.is_empty());
    let note = dest.join("gripfetch-apt-failure.txt");
    assert!(
        note.is_file(),
        "the deterministic failure note must be staged"
    );
    let text = std::fs::read_to_string(&note).unwrap();
    assert!(text.contains("A01"), "the note names the code");
    assert!(responses(&messages)[0]["result"]["provenance"].is_object());
    let _ = std::fs::remove_dir_all(&dest);
}

#[test]
fn version_flag_works() {
    let output = Command::new(env!("CARGO_BIN_EXE_gripfetch-apt"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("gripfetch-apt "), "got: {text}");
}
