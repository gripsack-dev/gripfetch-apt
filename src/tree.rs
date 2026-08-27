//! The canonical tree identity — a byte-for-byte mirror of the core's
//! `canonical_tree_hash` (gripsack-store) / the conformance suite's
//! `tree_hash` (src/gripfetch_conformance/exchange.py).
//!
//! This is what `locked.sha256` holds on a pinned re-fetch: the core
//! hashes the previously STAGED payload itself, so a locked fetch
//! verifies the *staged tree*, not the .deb bytes (the .deb hash
//! stays in provenance — it is transport provenance, not the pin).
//!
//! Algorithm (do not deviate — cross-implementation equality is the
//! point): every entry under `dest`, sorted by relative posix path,
//! encoded as `F<rel>\0<sha256(content)>` / `L<rel>\0<link-target>` /
//! `D<rel>\0`, joined with `\n` (no trailing newline), sha256'd.

use crate::proto::{self, Fail};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical tree hash of everything staged under `dest`.
/// Symlinked directories are recorded as links, not descended into
/// (pathlib `rglob` semantics — symlink loops cannot blow this up).
pub fn canonical_tree_hash(dest: &Path) -> Result<String, Fail> {
    let mut entries: Vec<(String, Entry)> = Vec::new();
    collect(dest, dest, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    let mut first = true;
    for (rel, entry) in &entries {
        if !first {
            hasher.update(b"\n");
        }
        first = false;
        hasher.update(entry.encode(rel).as_bytes());
    }
    Ok(hex(&hasher.finalize()))
}

enum Entry {
    File { content_sha256: String },
    Link { target: String },
    Dir,
}

impl Entry {
    fn encode(&self, rel: &str) -> String {
        match self {
            Entry::File { content_sha256 } => format!("F{rel}\0{content_sha256}"),
            Entry::Link { target } => format!("L{rel}\0{target}"),
            Entry::Dir => format!("D{rel}\0"),
        }
    }
}

fn collect(root: &Path, dir: &Path, entries: &mut Vec<(String, Entry)>) -> Result<(), Fail> {
    let read = fs::read_dir(dir).map_err(|e| walk_fail(dir, e))?;
    for item in read {
        let path: PathBuf = item.map_err(|e| walk_fail(dir, e))?.path();
        let rel = path
            .strip_prefix(root)
            .expect("walk stays under root")
            .to_string_lossy()
            .to_string();
        let meta = fs::symlink_metadata(&path).map_err(|e| walk_fail(&path, e))?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|e| walk_fail(&path, e))?
                .to_string_lossy()
                .to_string();
            entries.push((rel, Entry::Link { target }));
        } else if meta.is_dir() {
            entries.push((rel.clone(), Entry::Dir));
            collect(root, &path, entries)?;
        } else if meta.is_file() {
            let bytes = fs::read(&path).map_err(|e| walk_fail(&path, e))?;
            entries.push((
                rel,
                Entry::File {
                    content_sha256: hex(&Sha256::digest(&bytes)),
                },
            ));
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

    /// Byte-for-byte parity with the suite's tree_hash: the expected
    /// value below was produced by running
    /// gripfetch_conformance.exchange.tree_hash over this exact tree.
    #[test]
    fn matches_the_reference_implementation() {
        let dir = std::env::temp_dir().join(format!("gfa-tree-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::create_dir_all(dir.join("usr/share/doc")).unwrap();
        fs::create_dir_all(dir.join("opt")).unwrap();
        fs::write(dir.join("bin/hello"), b"#!/bin/sh\n").unwrap();
        fs::write(dir.join("usr/share/doc/x"), b"GPL\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("hello", dir.join("bin/hx")).unwrap();

        let hash = canonical_tree_hash(&dir).unwrap();
        assert_eq!(
            hash,
            "d46ea043f3e9e1bc473030133ccc1db11b74c275f7f2511ebee6bc3fdd25c035"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_tree_same_hash_anywhere_and_renames_change_it() {
        let one = std::env::temp_dir().join(format!("gfa-tree-a-{}", std::process::id()));
        let two = std::env::temp_dir().join(format!("gfa-tree-b-{}-x", std::process::id()));
        for dir in [&one, &two] {
            let _ = fs::remove_dir_all(dir);
            fs::create_dir_all(dir.join("bin")).unwrap();
            fs::write(dir.join("bin/tool"), b"payload").unwrap();
        }
        assert_eq!(
            canonical_tree_hash(&one).unwrap(),
            canonical_tree_hash(&two).unwrap()
        );

        fs::write(two.join("bin/tool"), b"payload2").unwrap();
        assert_ne!(
            canonical_tree_hash(&one).unwrap(),
            canonical_tree_hash(&two).unwrap()
        );
        let _ = fs::remove_dir_all(&one);
        let _ = fs::remove_dir_all(&two);
    }

    #[test]
    fn symlinked_dirs_are_recorded_not_descended() {
        let dir = std::env::temp_dir().join(format!("gfa-tree-l-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("real/sub")).unwrap();
        fs::write(dir.join("real/sub/f"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("real", dir.join("alias")).unwrap();
        let hash = canonical_tree_hash(&dir).unwrap();
        // expected = Lalias\0real, Dreal\0, Dreal/sub\0, Freal/sub/f\0<sha256("x")>
        // joined with \n — nothing under alias/ may appear (no descent).
        // The constant is tree_hash(this exact fixture) from the suite.
        #[cfg(unix)]
        assert_eq!(
            hash,
            "476f14fc80bb01c6fb72a4ef3c9d73cb919f5a2c85d0bcd57b387777c052fb66"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
