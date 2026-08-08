//! Normative numeric semver comparison (docs §7.1).
//!
//! Compare component-wise major.minor.patch ONLY. Reject a leading `v`,
//! prerelease (`-`), and build (`+`) suffixes, and non-numeric components.
//! No lexicographic/locale comparison.

use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

/// Parse a strict `major.minor.patch` version. Returns `None` for any
/// deviation: leading `v`, prerelease/build suffixes, non-numeric or extra
/// components, empty parts.
pub fn parse(s: &str) -> Option<Version> {
    if s.is_empty() || s.starts_with('v') || s.starts_with('V') {
        return None;
    }
    if s.contains('-') || s.contains('+') {
        return None;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut nums = [0u64; 3];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        nums[i] = match p.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return None,
        };
    }
    Some(Version {
        major: nums[0],
        minor: nums[1],
        patch: nums[2],
    })
}

/// Numeric component-wise comparison. Returns `None` if either side fails to
/// parse as strict `major.minor.patch`.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let va = parse(a)?;
    let vb = parse(b)?;
    Some(va.cmp(&vb))
}

pub fn to_string(v: &Version) -> String {
    format!("{}.{}.{}", v.major, v.minor, v.patch)
}
