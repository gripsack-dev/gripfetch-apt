//! The gripfetch wire protocol (plan/0002 §4, 0009 §2): one JSON
//! request on stdin, NDJSON messages on stdout, stderr is a log.
//!
//! Rules this module holds:
//! - exactly ONE `response` message per exchange, emitted last (the
//!   core stops reading at the first response);
//! - diagnostics are data — code/severity/message/labels (+ `help`
//!   on errors), never stderr prose;
//! - error-severity diagnostics fail the fetch even when a response
//!   follows, so the error path is: diagnostic, response, exit != 0.
//! - death is never silent.

use serde_json::{json, Map, Value};
use std::path::PathBuf;

/// Domain error codes (namespaced by the core as `gripfetch-apt/A01`…).
pub const NOT_FOUND: &str = "A01";
pub const VERSION_UNAVAILABLE: &str = "A02";
pub const LOCKED_GONE: &str = "A03";
pub const HASH_MISMATCH: &str = "A04";
pub const DOWNLOAD_FAILED: &str = "A05";
pub const MALFORMED_DEB: &str = "A06";
pub const PATH_TRAVERSAL: &str = "A07";
pub const APT_MISSING: &str = "A08";
pub const BAD_REQUEST: &str = "A09";

/// Warning codes.
pub const RESOLVED_LATEST: &str = "W01";
pub const INDEX_HASH_UNKNOWN: &str = "W02";

/// A failure to hand back over the wire: a code, a message, and an
/// optional `help` line (rendered by the core like its own).
#[derive(Debug, Clone)]
pub struct Fail {
    pub code: &'static str,
    pub message: String,
    pub help: Option<String>,
}

impl Fail {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Fail {
            code,
            message: message.into(),
            help: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}

/// The one request the core sends (capabilities exchanges carry only
/// `op` — every other field is optional and must be tolerated).
pub struct Request {
    pub id: Value,
    pub op: String,
    pub args: Value,
    pub dest_dir: Option<PathBuf>,
    pub locked: Option<Locked>,
}

/// A lockfile pin — present iff the lockfile has an entry for this
/// module; means *reproduce exactly*.
pub struct Locked {
    pub version: Option<String>,
    pub sha256: Option<String>,
}

pub fn parse_request(line: &str) -> Result<Request, Fail> {
    let value: Value = serde_json::from_str(line)
        .map_err(|e| Fail::new(BAD_REQUEST, format!("request is not valid JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| Fail::new(BAD_REQUEST, "request must be a JSON object, one per line"))?;
    let op = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| Fail::new(BAD_REQUEST, "request is missing the op field"))?
        .to_string();
    let locked = object.get("locked").and_then(parse_locked);
    Ok(Request {
        id: object.get("id").cloned().unwrap_or(json!(1)),
        op,
        args: object.get("args").cloned().unwrap_or_else(|| json!({})),
        dest_dir: object
            .get("dest_dir")
            .and_then(Value::as_str)
            .map(PathBuf::from),
        locked,
    })
}

fn parse_locked(value: &Value) -> Option<Locked> {
    let object = value.as_object()?;
    Some(Locked {
        version: object
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string),
        sha256: object
            .get("sha256")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn emit(message: Value) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, &message);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

/// A diagnostic (0004 §3 shape): data, never stderr prose. `help`
/// only when we have one — the field is optional in the IR.
pub fn emit_diagnostic(code: &str, severity: &str, message: &str, help: Option<&str>) {
    let mut diagnostic = Map::new();
    diagnostic.insert("code".into(), json!(code));
    diagnostic.insert("severity".into(), json!(severity));
    diagnostic.insert("message".into(), json!(message));
    diagnostic.insert("labels".into(), json!([]));
    if let Some(help) = help {
        diagnostic.insert("help".into(), json!(help));
    }
    emit(json!({
        "type": "diagnostic",
        "diagnostic": Value::Object(diagnostic),
    }));
}

/// A heartbeat (0002 §4): bytes so far / total when known. The core
/// logs it — it proves a long exchange is alive, nothing more.
pub fn emit_progress(current: u64, total: Option<u64>) {
    emit(json!({
        "type": "progress",
        "current": current,
        "total": total,
    }));
}

/// The terminal message — exactly one per exchange, emitted last.
pub fn emit_response(id: Value, result: Value) {
    emit(json!({
        "type": "response",
        "id": id,
        "result": result,
    }));
}

/// The error exit: diagnostic first (warnings flow, errors fail),
/// then the response (with whatever provenance is known — 0009 §2
/// rule 7 wants it in the run log even for failures), then a nonzero
/// exit. Never die silently.
pub fn die(fail: &Fail, id: Value, provenance: Value) -> std::process::ExitCode {
    emit_diagnostic(fail.code, "error", &fail.message, fail.help.as_deref());
    emit_response(id, json!({ "provenance": provenance }));
    // a short human tail — the core attaches it to gripfetch-apt/E02
    // only if we died without a response; here it is just a log line.
    eprintln!("gripfetch-apt/{}: {}", fail.code, fail.message);
    std::process::ExitCode::FAILURE
}
