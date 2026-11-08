//! SBOM generation for npm projects, from a committed `package-lock.json`.

use std::collections::BTreeMap;
use std::path::Path;

use npm_utils::package_json::lock::Lockfile;
use npm_utils::sbom;

use super::{ScanError, ScanReport, output_path};
use crate::config::Directory;

const LOCKFILE: &str = "package-lock.json";
const MANIFEST: &str = "package.json";

/// Generate CycloneDX and SPDX SBOMs for an npm project.
pub fn scan(directory: &Directory, output_dir: &Path) -> Result<ScanReport, ScanError> {
    let lock_path = directory.path.join(LOCKFILE);
    if !lock_path.is_file() {
        return Err(ScanError::MissingFile {
            dir: directory.path.clone(),
            file: LOCKFILE.to_string(),
        });
    }

    let contents = std::fs::read_to_string(&lock_path).map_err(|source| ScanError::Read {
        path: lock_path.clone(),
        source,
    })?;

    let lock = Lockfile::parse(&contents).map_err(|error| ScanError::Parse {
        path: lock_path.clone(),
        reason: error.to_string(),
    })?;

    let components = sbom::components(&lock);
    if components.is_empty() {
        return Err(ScanError::Parse {
            path: lock_path.clone(),
            reason: "no packages found in lockfile".to_string(),
        });
    }

    let dev_components = dev_flags(&lock).iter().filter(|dev| **dev).count();

    let (name, version) = project_identity(&directory.path, &lock_path);
    let created = timestamp(&lock_path)?;
    let namespace = format!("https://security-scan/{name}/{version}");

    let cyclonedx = sbom::to_cyclonedx(&components, &name, &version, Some(&created));
    let spdx = sbom::to_spdx(&components, &name, &namespace, &created);

    let out_dir = output_path(output_dir, &directory.path);
    std::fs::create_dir_all(&out_dir).map_err(|source| ScanError::Write {
        path: out_dir.clone(),
        source,
    })?;

    let cdx_path = out_dir.join("sbom.cdx.json");
    let spdx_path = out_dir.join("sbom.spdx.json");
    write(&cdx_path, &cyclonedx)?;
    write(&spdx_path, &spdx)?;

    let licenses = license_counts(&components);

    Ok(ScanReport {
        directory: directory.path.clone(),
        kind: directory.kind.clone(),
        outputs: vec![cdx_path, spdx_path],
        components: components.len(),
        dev_components,
        licenses,
    })
}

fn write(path: &Path, contents: &str) -> Result<(), ScanError> {
    std::fs::write(path, contents).map_err(|source| ScanError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// The dev-only flag for each component in the SBOM, in the same order.
///
/// `sbom::Component` does not carry the flag, so this mirrors
/// `sbom::components` — the same filter, sort and de-duplication — and keeps
/// the flag that the component drops. Counting this way makes the dev-only
/// count a share of the SBOM's components rather than of the lockfile's
/// entries.
fn dev_flags(lock: &Lockfile) -> Vec<bool> {
    let mut entries: Vec<(String, String, bool)> = lock
        .packages
        .iter()
        .filter(|p| p.key.contains("node_modules/") && !p.link)
        .map(|p| (p.name.clone(), p.version.clone(), p.dev))
        .collect();

    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    entries.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    entries.into_iter().map(|(_, _, dev)| dev).collect()
}

/// The project's name and version, taken from `package.json` when readable
/// and falling back to the lockfile's root entry.
fn project_identity(dir: &Path, lock_path: &Path) -> (String, String) {
    if let Some(identity) = read_identity(&dir.join(MANIFEST)) {
        return identity;
    }

    let fallback_name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    if let Some(identity) = read_identity(lock_path) {
        return identity;
    }

    (fallback_name, "0.0.0".to_string())
}

/// The `name` and `version` of a JSON document, if it has both.
fn read_identity(path: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let name = json.get("name")?.as_str()?;
    let version = json.get("version")?.as_str()?;
    Some((name.to_string(), version.to_string()))
}

/// Declared license -> number of packages under it.
fn license_counts(components: &[sbom::Component]) -> Vec<(String, usize)> {
    let summary = sbom::license_summary(components);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (license, packages) in summary {
        *counts.entry(license).or_insert(0) += packages.len();
    }
    let mut counts: Vec<(String, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts
}

/// The lockfile's modification time, as an RFC 3339 timestamp.
///
/// Using the lockfile's mtime rather than the current time keeps repeated
/// scans byte-for-byte identical, so an unchanged project produces an
/// unchanged SBOM.
fn timestamp(path: &Path) -> Result<String, ScanError> {
    let metadata = std::fs::metadata(path).map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let modified = metadata.modified().map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let seconds = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(format_rfc3339(seconds))
}

/// Format a Unix timestamp as an RFC 3339 UTC timestamp.
fn format_rfc3339(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    )
}

/// Convert a count of days since the Unix epoch into a calendar date.
///
/// This is Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };

    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn formats_a_known_timestamp() {
        // 2023-11-14T22:13:20Z
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn formats_a_leap_day() {
        // 2024-02-29T12:00:00Z
        assert_eq!(format_rfc3339(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn formats_the_end_of_a_year() {
        // 2025-12-31T23:59:59Z
        assert_eq!(format_rfc3339(1_767_225_599), "2025-12-31T23:59:59Z");
    }
}
