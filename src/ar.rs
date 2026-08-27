//! A minimal `ar` archive reader — the .deb container format.
//! Hand-rolled (spec: a 60-line reader beats a dependency): the .deb
//! profile of ar only needs 60-byte headers, GNU `//` long-name
//! tables, and even-byte padding.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArEntry {
    pub name: String,
    pub data: std::ops::Range<usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ArError(pub String);

impl std::fmt::Display for ArError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ar: {}", self.0)
    }
}

const GLOBAL_HEADER: &[u8; 8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;

/// Parse `buf` into entries (name + byte range — zero copy).
pub fn entries(buf: &[u8]) -> Result<Vec<ArEntry>, ArError> {
    if buf.len() < GLOBAL_HEADER.len() || &buf[..8] != GLOBAL_HEADER {
        return Err(ArError("not an ar archive (missing !<arch> magic)".into()));
    }
    let mut out = Vec::new();
    let mut long_names: &[u8] = &[];
    let mut cursor = GLOBAL_HEADER.len();
    while cursor + HEADER_LEN <= buf.len() {
        let header = &buf[cursor..cursor + HEADER_LEN];
        if &header[58..60] != b"`\n" {
            return Err(ArError(format!(
                "bad header magic at offset {cursor} (expected `\\n)"
            )));
        }
        let name_field = trim_field(&header[..16]);
        let size = parse_size(&header[48..58], cursor)?;
        let data_start = cursor + HEADER_LEN;
        let data_end = data_start + size;
        if data_end > buf.len() {
            return Err(ArError(format!(
                "entry {name_field:?} at offset {cursor} claims {size} bytes past end of archive"
            )));
        }
        let name = resolve_name(name_field, long_names)?;
        if name == "//" {
            long_names = &buf[data_start..data_end];
        } else {
            out.push(ArEntry {
                name,
                data: data_start..data_end,
            });
        }
        // members are padded to an even offset with \n
        cursor = data_end + (size & 1);
    }
    Ok(out)
}

fn trim_field(field: &[u8]) -> &str {
    std::str::from_utf8(field)
        .unwrap_or_default()
        .trim_end_matches([' ', '/'])
        .trim_end()
}

fn parse_size(field: &[u8], offset: usize) -> Result<usize, ArError> {
    let text = std::str::from_utf8(field)
        .map_err(|_| ArError(format!("non-utf8 size field at offset {offset}")))?
        .trim();
    text.parse::<usize>()
        .map_err(|_| ArError(format!("bad size field {text:?} at offset {offset}")))
}

/// GNU long names: `/123` indexes into the `//` string table (offset
/// 123, NUL/newline terminated). BSD `#1/NNN` names are not produced
/// by dpkg and are rejected loudly rather than misread.
fn resolve_name(field: &str, long_names: &[u8]) -> Result<String, ArError> {
    if field == "/" {
        return Err(ArError(
            "symbol-table entries are not expected in a .deb".into(),
        ));
    }
    if let Some(index) = field.strip_prefix('/') {
        let offset: usize = index
            .parse()
            .map_err(|_| ArError(format!("unresolvable GNU long-name reference {field:?}")))?;
        let end = long_names[offset..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\0')
            .map(|p| offset + p)
            .unwrap_or(long_names.len());
        let name = long_names
            .get(offset..end)
            .ok_or_else(|| ArError(format!("GNU long-name offset {offset} out of range")))?;
        return Ok(String::from_utf8_lossy(name)
            .trim_end_matches('/')
            .to_string());
    }
    if field.starts_with("#1/") {
        return Err(ArError(format!(
            "BSD-style extended name {field:?} is not used by .deb archives"
        )));
    }
    Ok(field.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = GLOBAL_HEADER.to_vec();
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

    #[test]
    fn parses_deb_shaped_archive() {
        let archive = build_archive(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", &[0x1f, 0x8b, 0x00]),
            ("data.tar.xz", b"0123456789"),
        ]);
        let parsed = entries(&archive).unwrap();
        let names: Vec<&str> = parsed.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["debian-binary", "control.tar.gz", "data.tar.xz"]);
        assert_eq!(&archive[parsed[2].data.clone()], b"0123456789");
    }

    #[test]
    fn odd_members_keep_alignment() {
        let archive = build_archive(&[("a", b"xyz"), ("b", b"yy")]);
        let parsed = entries(&archive).unwrap();
        assert_eq!(&archive[parsed[0].data.clone()], b"xyz");
        assert_eq!(&archive[parsed[1].data.clone()], b"yy");
    }

    #[test]
    fn rejects_non_ar_input() {
        assert!(entries(b"PK\x03\x04 nope").is_err());
        assert!(entries(b"").is_err());
    }

    #[test]
    fn rejects_truncated_member() {
        let mut archive = build_archive(&[("data.tar.gz", b"abc")]);
        archive.truncate(archive.len() - 2);
        assert!(entries(&archive).is_err());
    }
}
