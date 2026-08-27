//! Debian version comparison (dpkg `vercmp(3)` semantics, the
//! `~`-before-everything rule included) — needed to pick "newest"
//! from `apt-cache madison` output without shelling out to
//! `dpkg --compare-versions` per pair.
//!
//! Grammar: `[epoch:]upstream[-revision]`. Epoch compares numerically,
//! then upstream, then revision, each with the dpkg string order:
//! end-of-string sorts first, then `~`, then letters, then non-letters
//! (`+`, `.`, `:`…), with digit runs compared numerically.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebVersion {
    pub epoch: u64,
    pub upstream: String,
    pub revision: String,
}

pub fn parse(version: &str) -> DebVersion {
    let (epoch, rest) = match version.split_once(':') {
        Some((epoch, rest)) if epoch.chars().all(|c| c.is_ascii_digit()) => {
            (epoch.parse().unwrap_or(0), rest)
        }
        _ => (0, version),
    };
    let (upstream, revision) = match rest.rsplit_once('-') {
        Some((upstream, revision)) => (upstream, revision),
        None => (rest, ""),
    };
    DebVersion {
        epoch,
        upstream: upstream.to_string(),
        revision: revision.to_string(),
    }
}

/// Total order over Debian version strings.
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (va, vb) = (parse(a), parse(b));
    va.epoch
        .cmp(&vb.epoch)
        .then_with(|| cmp_fragment(&va.upstream, &vb.upstream))
        .then_with(|| cmp_fragment(&va.revision, &vb.revision))
}

/// dpkg's string order: compare non-digit runs lexically (with `~`
/// sorting before everything, including end-of-string), digit runs
/// numerically (an absent run is zero).
fn cmp_fragment(a: &str, b: &str) -> Ordering {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    loop {
        let first_a = non_digit_prefix(ab, i);
        let first_b = non_digit_prefix(bb, j);
        match lexical(&ab[i..first_a], &bb[j..first_b]) {
            Ordering::Equal => {}
            other => return other,
        }
        i = first_a;
        j = first_b;
        let end_a = digit_prefix(ab, i);
        let end_b = digit_prefix(bb, j);
        let num_a = ascii_digits_to_u64(&ab[i..end_a]);
        let num_b = ascii_digits_to_u64(&bb[j..end_b]);
        match num_a.cmp(&num_b) {
            Ordering::Equal => {}
            other => return other,
        }
        i = end_a;
        j = end_b;
        if i >= ab.len() && j >= bb.len() {
            return Ordering::Equal;
        }
    }
}

fn non_digit_prefix(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && !bytes[end].is_ascii_digit() {
        end += 1;
    }
    end
}

fn digit_prefix(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    end
}

fn ascii_digits_to_u64(bytes: &[u8]) -> u64 {
    // saturate rather than overflow on absurd digit runs
    bytes.iter().fold(0u64, |acc, &d| {
        acc.saturating_mul(10).saturating_add((d - b'0') as u64)
    })
}

/// The dpkg character order over non-digit runs: end-of-string < `~`
/// < letters < non-letters; shorter run padding acts as end-of-string.
fn lexical(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0usize, 0usize);
    loop {
        if a.get(i).is_none() && b.get(j).is_none() {
            return Ordering::Equal;
        }
        let ca = order(a.get(i));
        let cb = order(b.get(j));
        match ca.cmp(&cb) {
            Ordering::Equal => {}
            other => return other,
        }
        i += 1;
        j += 1;
    }
}

fn order(c: Option<&u8>) -> i32 {
    match c {
        None => 0,                           // end-of-string sorts first
        Some(b'~') => -1,                    // …after explicit `~`
        Some(&c) if c.is_ascii_digit() => 0, // unreachable; digits end runs
        Some(&c) if c.is_ascii_alphabetic() => c as i32,
        Some(&c) => c as i32 + 256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_suffixes_are_newer() {
        assert_eq!(cmp("2.10-3", "2.10-3build1"), Ordering::Less);
        assert_eq!(cmp("2.10-3build2", "2.10-3build1"), Ordering::Greater);
    }

    #[test]
    fn epochs_dominate() {
        assert_eq!(cmp("1:0.9", "2.0"), Ordering::Greater);
        assert_eq!(cmp("2:1.0", "2.0.1"), Ordering::Greater);
        assert_eq!(cmp("0.9", "1:0.1"), Ordering::Less);
    }

    #[test]
    fn tilde_sorts_before_release() {
        assert_eq!(cmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0~rc1", "1.0~rc2"), Ordering::Less);
        assert_eq!(cmp("1.0~~", "1.0~"), Ordering::Less);
    }

    #[test]
    fn digits_compare_numerically() {
        assert_eq!(cmp("1.2", "1.10"), Ordering::Less);
        assert_eq!(cmp("1.02", "1.2"), Ordering::Equal);
        assert_eq!(cmp("1:2.0-1", "1:2.0-01"), Ordering::Equal);
    }

    #[test]
    fn letters_before_non_letters() {
        assert_eq!(cmp("1.2a", "1.2+"), Ordering::Less);
        assert_eq!(cmp("1.2a", "1.2z"), Ordering::Less);
        assert_eq!(cmp("1.2", "1.2a"), Ordering::Less);
    }

    #[test]
    fn missing_revision_is_oldest() {
        assert_eq!(cmp("1.0-1", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.0", "1.0-1"), Ordering::Less);
    }

    #[test]
    fn newest_of_real_madison_output() {
        let mut versions = ["1.0.7-5ubuntu2", "14.0.0-1", "14.1.0-1", "13.0.0-2build1"];
        versions.sort_by(|a, b| cmp(a, b));
        assert_eq!(versions[versions.len() - 1], "14.1.0-1");
    }
}
