//! gripfetch-apt — a gripsack fetcher plugin (plan/0002 §4, 0009 §2)
//! that fetches Debian packages through the HOST's apt. It wraps
//! apt-cache/apt-get; it never bundles an apt and never reimplements
//! one — enterprise mirrors configured in /etc/apt/sources.list.d are
//! inherited for free.
//!
//! Exchange: one JSON request on stdin, NDJSON on stdout, exactly one
//! `response`, stderr is a drained log. Codes A01.. are domain errors
//! (the core renders them as `gripfetch-apt/A01`).

mod apt;
mod ar;
mod deb;
mod proto;
mod version;

use proto::{Fail, Request};
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv
        .iter()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
    {
        println!("gripfetch-apt {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line).unwrap_or(0);
    if read == 0 || line.trim().is_empty() {
        eprintln!("gripfetch-apt: expected exactly one JSON request line on stdin");
        return ExitCode::FAILURE;
    }

    let request = match proto::parse_request(&line) {
        Ok(request) => request,
        Err(fail) => return proto::die(&fail, json!(1), json!({})),
    };

    match request.op.as_str() {
        "capabilities" => {
            // apt mirrors don't rate-limit like APIs do — an empty
            // budget map is the honest declaration (0002 §throttle).
            proto::emit_response(request.id, json!({ "capabilities": { "throttle": {} } }));
            ExitCode::SUCCESS
        }
        "fetch" => fetch(request),
        other => {
            let fail = Fail::new(proto::BAD_REQUEST, format!("unknown op {other:?}"));
            proto::die(&fail, request.id, partial_provenance(None, None, None))
        }
    }
}

fn fetch(request: Request) -> ExitCode {
    let id = request.id.clone();
    let package = package_of(&request);
    let version = version_of(&request);
    let provenance = partial_provenance(package.as_deref(), version.as_deref(), None);
    match fetch_inner(&request) {
        Ok(result) => {
            proto::emit_response(id, result);
            ExitCode::SUCCESS
        }
        Err(fail) => {
            stage_failure_note(&request, package.as_deref(), version.as_deref(), &fail);
            proto::die(&fail, id, provenance)
        }
    }
}

fn fetch_inner(request: &Request) -> Result<Value, Fail> {
    let package = package_of(request).ok_or_else(|| {
        Fail::new(
            proto::BAD_REQUEST,
            "args.package is required (a Debian package name)",
        )
    })?;
    let requested = version_of(request);
    let repos = apt::parse_repos(request.args.get("repos"))?;

    chatter(request.args.get("verbose_stderr_lines"));

    apt::require_apt_get()?;
    let apt_version = apt::apt_version();

    // resolve: enumerate, then pick (locked = reproduce exactly).
    let candidates = apt::available_versions(&package, &repos)?;
    if candidates.is_empty() {
        return Err(not_found(&package));
    }
    let chosen = choose(request, &package, requested.as_deref(), &candidates)?;

    let (filename, index_sha256) = apt::show(&package, &chosen.version);
    if index_sha256.is_none() {
        proto::emit_diagnostic(
            proto::INDEX_HASH_UNKNOWN,
            "warning",
            &format!(
                "the apt index for {package}={} carries no SHA256 — the pin will be computed from the downloaded bytes",
                chosen.version
            ),
            None,
        );
    }

    // fetch: download into scratch space (dest_dir only receives the
    // final payload tree), hash, verify, extract.
    let scratch = ScratchDir::new();
    let download = apt::download(&package, &chosen.version, scratch.path())?;
    proto::emit_progress(download.size, Some(download.size));
    let sha256 = apt::sha256_file(&download.deb)?;

    if let Some(locked) = &request.locked {
        if let Some(expected) = locked.sha256.as_deref().filter(|s| !s.is_empty()) {
            if !expected.eq_ignore_ascii_case(&sha256) {
                return Err(Fail::new(
                    proto::HASH_MISMATCH,
                    format!(
                        "locked pin for {package}={} expects sha256 {expected} but the mirror served {sha256} — refusing to stage",
                        locked.version.as_deref().unwrap_or("")
                    ),
                )
                .with_help("the mirror content changed under the pin; `grip update` re-pins, or pin the version your audit approved"));
            }
        }
    }
    if let Some(expected) = index_sha256.as_deref().filter(|s| !s.is_empty()) {
        if !expected.eq_ignore_ascii_case(&sha256) {
            return Err(Fail::new(
                proto::HASH_MISMATCH,
                format!(
                    "the apt index sha256 {expected} does not match the downloaded .deb ({sha256}) for {package}={}",
                    chosen.version
                ),
            )
            .with_help("a truncated or tampered download — retry, then report the mirror"));
        }
    }

    let dest = request
        .dest_dir
        .as_deref()
        .ok_or_else(|| Fail::new(proto::BAD_REQUEST, "fetch request is missing dest_dir"))?;
    let deb_bytes = std::fs::read(&download.deb)
        .map_err(|e| Fail::new(proto::DOWNLOAD_FAILED, format!("re-reading the .deb: {e}")))?;
    let mut progress = |count: u64| proto::emit_progress(count, None);
    let staged = deb::extract(&deb_bytes, dest, &mut progress)?;
    let _ = staged;

    let mirror = download
        .mirror
        .as_deref()
        .or_else(|| chosen.mirror())
        .map(str::to_string);
    let url = mirror
        .as_ref()
        .zip(filename.as_deref())
        .map(|(mirror, filename)| format!("{mirror}/{filename}"));

    Ok(json!({
        "version": chosen.version,
        "sha256": sha256,
        "url": url,
        "provenance": {
            "apt_version": apt_version,
            "mirror": mirror,
            "package": package,
            "version": chosen.version,
            "sha256": sha256,
            "filename": filename,
        },
    }))
}

/// Pick the version: locked wins and must reproduce exactly; then an
/// explicit args.version; then the newest (with a warning, since the
/// pin moves with the mirror — that is what `grip update` is for).
fn choose(
    request: &Request,
    package: &str,
    requested: Option<&str>,
    candidates: &[apt::Candidate],
) -> Result<apt::Candidate, Fail> {
    if let Some(locked) = &request.locked {
        let version = locked
            .version
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                Fail::new(
                    proto::BAD_REQUEST,
                    "the locked pin has no version to reproduce",
                )
            })?;
        return candidates
            .iter()
            .find(|candidate| candidate.version == version)
            .cloned()
            .ok_or_else(|| {
                Fail::new(
                    proto::LOCKED_GONE,
                    format!(
                        "locked version {version} of {package} is no longer served by any configured mirror (have: {})",
                        summarize(candidates),
                    ),
                )
                .with_help("the mirror moved on — `grip update` re-pins to what is served now")
            });
    }
    if let Some(version) = requested {
        return candidates
            .iter()
            .find(|candidate| candidate.version == version)
            .cloned()
            .ok_or_else(|| {
                Fail::new(
                    proto::VERSION_UNAVAILABLE,
                    format!(
                        "version {version} of {package} is not available{} (have: {})",
                        repos_note(request),
                        summarize(candidates),
                    ),
                )
            });
    }
    let newest = candidates
        .first()
        .ok_or_else(|| not_found(package))?
        .clone();
    proto::emit_diagnostic(
        proto::RESOLVED_LATEST,
        "warning",
        &format!(
            "no version pinned for {package} — resolved to {} (latest); `grip update` moves the pin",
            newest.version
        ),
        None,
    );
    Ok(newest)
}

fn not_found(package: &str) -> Fail {
    Fail::new(
        proto::NOT_FOUND,
        format!("{package} is not in any apt index this host knows about"),
    )
    .with_help("check the spelling, run `apt update`, or point sources.list.d at the mirror that carries it")
}

fn summarize(candidates: &[apt::Candidate]) -> String {
    if candidates.is_empty() {
        "nothing".to_string()
    } else {
        candidates
            .iter()
            .map(|candidate| candidate.version.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn repos_note(request: &Request) -> String {
    match request.args.get("repos").and_then(Value::as_array) {
        Some(repos) if !repos.is_empty() => " under the repos filter".to_string(),
        _ => String::new(),
    }
}

fn package_of(request: &Request) -> Option<String> {
    request
        .args
        .get("package")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|package| !package.is_empty())
        .map(str::to_string)
}

fn version_of(request: &Request) -> Option<String> {
    request
        .args
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(str::to_string)
}

/// Known-so-far provenance for failure responses — which package was
/// asked for, from which (if any) apt.
fn partial_provenance(package: Option<&str>, version: Option<&str>, mirror: Option<&str>) -> Value {
    json!({
        "apt_version": apt::apt_version(),
        "mirror": mirror,
        "package": package,
        "version": version,
        "sha256": Value::Null,
    })
}

/// The suite's stderr-flood probe: when asked, be chatty — stderr is
/// drained concurrently by the core, and this proves we do not fill
/// the pipe and deadlock.
fn chatter(arg: Option<&Value>) {
    let Some(lines) = arg.and_then(Value::as_u64) else {
        return;
    };
    let lines = lines.min(200_000);
    let mut stderr = std::io::stderr().lock();
    for i in 0..lines {
        let _ = writeln!(
            stderr,
            "gripfetch-apt stderr chatter {i}: stderr is a log, not a channel"
        );
    }
    let _ = stderr.flush();
}

/// A failed fetch still stages a deterministic note — an empty tree
/// must never masquerade as a successful fetch, and the core discards
/// staging on error anyway. No paths, no timestamps: byte-identical
/// across machines for the same failure.
fn stage_failure_note(
    request: &Request,
    package: Option<&str>,
    version: Option<&str>,
    fail: &Fail,
) {
    let Some(dest) = request.dest_dir.as_deref() else {
        return;
    };
    let note = format!(
        "gripfetch-apt {}: {}\n\npackage: {}\nversion: {}\n\nNo bytes were fetched from apt.\nThis deterministic note is staged so a failed fetch never looks like\nan empty success; the core discards staging on error.\n",
        fail.code,
        fail.message,
        package.unwrap_or("(unspecified)"),
        version.unwrap_or("(unspecified)"),
    );
    let _ = std::fs::create_dir_all(dest);
    let _ = std::fs::write(dest.join("gripfetch-apt-failure.txt"), note);
}

/// Scratch space for the .deb download, removed when dropped. dest_dir
/// receives only the final payload tree — never the archive itself.
struct ScratchDir {
    path: std::path::PathBuf,
}

impl ScratchDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gripfetch-apt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::create_dir_all(&path);
        ScratchDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
