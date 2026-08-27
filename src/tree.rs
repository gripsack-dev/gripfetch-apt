//! The canonical tree identity — a byte-for-byte mirror of the core's
//! `canonical_tree_hash` (gripsack-store/src/hash.rs) and the
//! conformance suite's `tree_hash`. The pinned reference vector lives
//! in BOTH of those (crates/gripsack-store/src/hash.rs and
//! tests/test_tree_hash.py in the suite); this file asserts it too.
//!
//! Algorithm (do not deviate — cross-implementation equality is the
//! point): entries under `dest` sorted by relative posix path; each
//! entry hashed as `<rel>\0<identity-hex>\0` where identity is the
//! sha256 hex of `link\0<target>` (symlink), `dir\0` (directory), or
//! `file\0<exec-byte><contents>` (regular file; exec-byte is 1 if any
//! execute bit is set). Symlinked directories are recorded, never
//! descended.

use crate::proto::{self, Fail};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical tree hash of everything staged under `dest`.
pub fn canonical_tree_hash(dest: &Path) -> Result<String, Fail> {
    let mut rels: Vec<String> = Vec::new();
    collect(dest, dest, &mut rels)?;
    rels.sort();
    let mut hasher = Sha256::new();
    for rel in &rels {
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        hasher.update(file_identity(&dest.join(rel))?.as_bytes());
        hasher.update(b"\0");
    }
    Ok(hex(&hasher.finalize()))
}

/// The core's canonical_file_hash: type marker + exec bit + contents.
fn file_identity(path: &Path) -> Result<String, Fail> {
    let meta = fs::symlink_metadata(path).map_err(|e| walk_fail(path, e))?;
    let body: Vec<u8> = if meta.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|e| walk_fail(path, e))?;
        let mut b = b"link\0".to_vec();
        b.extend(target.as_os_str().as_encoded_bytes());
        b
    } else if meta.is_dir() {
        b"dir\0".to_vec()
    } else {
        let mut b = b"file\0".to_vec();
        b.push(exec_byte(&meta));
        b.extend(fs::read(path).map_err(|e| walk_fail(path, e))?);
        b
    };
    Ok(hex(&Sha256::digest(&body)))
}

#[cfg(unix)]
fn exec_byte(meta: &fs::Metadata) -> u8 {
    use std::os::unix::fs::PermissionsExt;
    u8::from(meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn exec_byte(_meta: &fs::Metadata) -> u8 {
    0
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), Fail> {
    let read = fs::read_dir(dir).map_err(|e| walk_fail(dir, e))?;
    for item in read {
        let path: PathBuf = item.map_err(|e| walk_fail(dir, e))?.path();
        let rel = path
            .strip_prefix(root)
            .expect("walk stays under root")
            .to_string_lossy()
            .into_owned();
        let is_real_dir = path.is_dir() && !path.is_symlink();
        out.push(rel);
        if is_real_dir {
            collect(root, &path, out)?;
        }
    }
    Ok(())
}

fn walk_fail(path: &Path, error: std::io::Error) -> Fail {
    Fail::new(
        proto::HASH_MISMATCH,
        format!("hashing the staged tree at {}: {error}", path.display()),
    )
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned cross-implementation vector: the same tree, the same
    /// hex in the core (gripsack-store), the conformance suite, and here.
    #[test]
    fn matches_the_pinned_reference_vector() {
        let dir = std::env::temp_dir().join(format!("gfa-vec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::create_dir_all(dir.join("share")).unwrap();
        fs::write(dir.join("bin/hello"), b"#!/bin/sh\necho hello\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.join("bin/hello"), fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::symlink("hello", dir.join("bin/hi")).unwrap();
        }
        fs::write(dir.join("share/version.txt"), b"1.0\n").unwrap();

        let hash = canonical_tree_hash(&dir).unwrap();
        assert_eq!(
            hash,
            "cce3e9f819b476cc5abed85b83f2f1a01cac2abd4c2eb34f08b76d822739e595"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
