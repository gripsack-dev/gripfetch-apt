//! .deb → payload tree. A .deb is an `ar` archive holding
//! `debian-binary`, `control.tar.*`, and `data.tar.*`; the data
//! member is the payload. This module:
//!
//! - decodes data.tar.{gz,xz,zst} (by magic bytes, not by name);
//! - REJECTS any member that would escape `dest_dir` (the traversal
//!   guard — a package or a tampered mirror never writes outside the
//!   staging area);
//! - maps `usr/bin/*` → `bin/*` at the payload root, so modules can
//!   write `install={"bin/rg": symlink(...)}`;
//! - never runs maintainer scripts (postinst & co) — gripsack is not
//!   a solver; config modules own system state.

use crate::ar;
use crate::proto::{self, Fail};
use flate2::read::MultiGzDecoder;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const XZ_MAGIC: &[u8; 6] = b"\xfd7zXZ\x00";
const ZSTD_MAGIC: &[u8; 4] = b"\x28\xb5\x2f\xfd";
const GZIP_MAGIC: &[u8; 2] = b"\x1f\x8b";

/// Extract the data.tar.* payload into `dest`; returns the number of
/// members staged. `progress` is called with the running count.
pub fn extract(deb: &[u8], dest: &Path, progress: &mut dyn FnMut(u64)) -> Result<u64, Fail> {
    let members = ar::entries(deb).map_err(|e| malformed(e.to_string()))?;
    let data = members
        .iter()
        .find(|m| m.name == "data.tar" || m.name.starts_with("data.tar."))
        .ok_or_else(|| malformed("no data.tar.* member".into()))?;
    let payload = &deb[data.data.clone()];
    let reader = decoder(payload).map_err(malformed)?;

    let mut archive = tar::Archive::new(reader);
    archive.set_overwrite(true);
    let mut count: u64 = 0;
    for entry in archive.entries().map_err(|e| malformed(e.to_string()))? {
        let mut entry = entry.map_err(|e| malformed(e.to_string()))?;
        let rel = entry
            .path()
            .map_err(|e| malformed(e.to_string()))?
            .to_path_buf();
        let Some(mapped) = map_path(&rel)? else {
            continue; // the archive root "./"
        };
        let target = dest.join(mapped);
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                fs::create_dir_all(&target).map_err(|e| io_fail(&target, e))?;
            }
            tar::EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| io_fail(parent, e))?;
                }
                let mut file = fs::File::create(&target).map_err(|e| io_fail(&target, e))?;
                std::io::copy(&mut entry, &mut file).map_err(|e| io_fail(&target, e))?;
                set_mode(&target, entry.header().mode().unwrap_or(0o644));
            }
            tar::EntryType::Symlink => {
                let link = entry
                    .link_name()
                    .map_err(|e| malformed(e.to_string()))?
                    .unwrap_or_default();
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| io_fail(parent, e))?;
                }
                let text = link.to_string_lossy().to_string();
                // an in-payload usr/bin target moves with the mapping
                let text = match text.strip_prefix("usr/bin/") {
                    Some(rest) => format!("bin/{rest}"),
                    None => text,
                };
                #[cfg(unix)]
                std::os::unix::fs::symlink(&text, &target).map_err(|e| io_fail(&target, e))?;
                #[cfg(not(unix))]
                fs::write(&target, format!("symlink:{text}")).map_err(|e| io_fail(&target, e))?;
            }
            tar::EntryType::Link => {
                let link = entry
                    .link_name()
                    .map_err(|e| malformed(e.to_string()))?
                    .unwrap_or_default();
                let link_text = link.to_string_lossy().to_string();
                let Some(source_rel) = map_path(&link)? else {
                    return Err(malformed(format!(
                        "hardlink target {link_text:?} is dot-only"
                    )));
                };
                let source = dest.join(source_rel);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| io_fail(parent, e))?;
                }
                fs::hard_link(&source, &target).map_err(|e| io_fail(&target, e))?;
            }
            _ => {} // fifos/devices are not payload
        }
        count += 1;
        if count.is_multiple_of(128) {
            progress(count);
        }
    }
    Ok(count)
}

/// Decompress the data member by magic (a tampered or unusual name
/// never selects the wrong codec).
fn decoder(payload: &[u8]) -> Result<Box<dyn Read + '_>, String> {
    if payload.starts_with(GZIP_MAGIC) {
        Ok(Box::new(MultiGzDecoder::new(payload)))
    } else if payload.starts_with(XZ_MAGIC) {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut &payload[..], &mut out).map_err(|e| e.to_string())?;
        Ok(Box::new(std::io::Cursor::new(out)))
    } else if payload.starts_with(ZSTD_MAGIC) {
        let decoder =
            ruzstd::decoding::StreamingDecoder::new(payload).map_err(|e| e.to_string())?;
        Ok(Box::new(decoder))
    } else {
        // no compression magic: treat as an uncompressed tar stream —
        // a garbage payload fails in the tar reader as malformed
        Ok(Box::new(std::io::Cursor::new(payload.to_vec())))
    }
}

/// Sanitize + remap one member path; `None` = harmless dot-only
/// entry (the archive root `./`), which stages nothing. Absolute
/// paths and any `..` component are REJECTED before anything is
/// ever joined onto dest_dir.
fn map_path(rel: &Path) -> Result<Option<PathBuf>, Fail> {
    let text = rel.to_string_lossy();
    if rel.as_os_str().is_empty() {
        return Err(traversal("(empty)"));
    }
    let mut components: Vec<std::ffi::OsString> = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => components.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(traversal(&text));
            }
        }
    }
    if components.is_empty() {
        return Ok(None); // "./" — the archive root, stages nothing
    }
    // usr/bin/* → bin/* at the payload root
    if components.len() >= 2 && components[0] == *"usr" && components[1] == *"bin" {
        components.remove(0);
    }
    Ok(Some(components.iter().collect()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn io_fail(path: &Path, error: std::io::Error) -> Fail {
    Fail::new(
        proto::MALFORMED_DEB,
        format!("could not stage {}: {error}", path.display()),
    )
}

fn malformed(detail: String) -> Fail {
    Fail::new(
        proto::MALFORMED_DEB,
        format!("the downloaded .deb is malformed: {detail}"),
    )
    .with_help("usually a truncated or corrupt download — retry, and report if it persists")
}

fn traversal(path: &str) -> Fail {
    Fail::new(
        proto::PATH_TRAVERSAL,
        format!(
            "archive member {path:?} would escape the destination directory — payload rejected"
        ),
    )
    .with_help("the package ships an unsafe path; that is a packaging bug or a tampered mirror")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ---- fixture builders -------------------------------------------------

    fn ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let mut header = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}",
                format!("{name}/"),
                "0",
                "0",
                "0",
                "100644",
                data.len()
            )
            .into_bytes();
            header.truncate(58);
            out.extend_from_slice(&header);
            out.extend_from_slice(b"`\n");
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    fn tar_gz(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
        // (path, kind: "f" | "d" | "l:target", content)
        let mut builder = tar::Builder::new(Vec::new());
        for &(path, kind, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mtime(1_700_000_000);
            match kind {
                "d" => {
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_mode(0o755);
                    header.set_size(0);
                    let dir = format!("{path}/");
                    builder.append_data(&mut header, dir, &b""[..]).unwrap();
                }
                link if link.starts_with("l:") => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_mode(0o777);
                    header.set_size(0);
                    header.set_link_name(link.trim_start_matches("l:")).unwrap();
                    builder.append_data(&mut header, path, &b""[..]).unwrap();
                }
                _ => {
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_mode(0o755);
                    header.set_size(content.len() as u64);
                    builder.append_data(&mut header, path, content).unwrap();
                }
            }
        }
        let raw = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        encoder.finish().unwrap()
    }

    fn fixture_deb(data_tar: &[u8]) -> Vec<u8> {
        ar_archive(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", &tar_gz(&[])),
            ("data.tar.gz", data_tar),
        ])
    }

    /// A raw hand-crafted header (the tar crate would refuse to build
    /// an unsafe name — the guard has to catch the real thing).
    fn raw_tar_member(name: &str, size: u64) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        // ustar: mode[100..108] uid gid, size[124..136]
        let size_field = format!("{size:011o}\0");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[156] = b'0'; // regular file
        for byte in &mut header[148..156] {
            *byte = b' ';
        }
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut out = header.to_vec();
        out.extend(std::iter::repeat_n(0u8, size as usize));
        out
    }

    // ---- tests ------------------------------------------------------------

    #[test]
    fn extracts_and_maps_usr_bin() {
        let dir = std::env::temp_dir().join(format!("gfa-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let data = tar_gz(&[
            ("usr/", "d", b""),
            ("usr/bin/", "d", b""),
            ("usr/bin/hello", "f", b"#!/bin/sh\necho hi\n"),
            ("usr/share/", "d", b""),
            ("usr/share/doc/hello/copyright", "f", b"GPL\n"),
            ("usr/bin/hx", "l:hello", b""),
        ]);
        let deb = fixture_deb(&data);
        let mut progress = |_| {};
        let count = extract(&deb, &dir, &mut progress).unwrap();
        assert_eq!(count, 6);
        assert_eq!(
            fs::read_to_string(dir.join("bin/hello")).unwrap(),
            "#!/bin/sh\necho hi\n"
        );
        assert!(fs::read_to_string(dir.join("usr/share/doc/hello/copyright")).is_ok());
        assert_eq!(
            fs::read_link(dir.join("bin/hx")).unwrap().to_string_lossy(),
            "hello"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("bin/hello"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        let dir = std::env::temp_dir().join(format!("gfa-trav-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let evil = raw_tar_member("../evil", 4);
        let deb = fixture_deb(&evil);
        let mut progress = |_| {};
        let fail = extract(&deb, &dir, &mut progress).unwrap_err();
        assert_eq!(fail.code, proto::PATH_TRAVERSAL);
        assert!(!dir.join("../evil").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_absolute_paths() {
        let dir = std::env::temp_dir().join(format!("gfa-abs-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let evil = raw_tar_member("/etc/passwd", 4);
        let deb = fixture_deb(&evil);
        let mut progress = |_| {};
        let fail = extract(&deb, &dir, &mut progress).unwrap_err();
        assert_eq!(fail.code, proto::PATH_TRAVERSAL);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_deb_without_data_member() {
        let dir = std::env::temp_dir().join(format!("gfa-nodata-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let deb = ar_archive(&[("debian-binary", b"2.0\n")]);
        let mut progress = |_| {};
        let fail = extract(&deb, &dir, &mut progress).unwrap_err();
        assert_eq!(fail.code, proto::MALFORMED_DEB);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn map_path_shapes() {
        assert_eq!(
            map_path(Path::new("usr/bin/rg")).unwrap().unwrap(),
            Path::new("bin/rg")
        );
        assert_eq!(
            map_path(Path::new("./usr/share/doc/x")).unwrap().unwrap(),
            Path::new("usr/share/doc/x")
        );
        assert_eq!(
            map_path(Path::new("bin/tool")).unwrap().unwrap(),
            Path::new("bin/tool")
        );
        assert_eq!(map_path(Path::new("./")).unwrap(), None);
        assert_eq!(map_path(Path::new(".")).unwrap(), None);
        assert!(map_path(Path::new("../escape")).is_err());
        assert!(map_path(Path::new("/etc/passwd")).is_err());
        assert!(map_path(Path::new("a/../../b")).is_err());
    }
}
