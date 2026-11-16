//! SBOM generation with cdxgen.
//!
//! Every configured project is handed to `cdxgen`, which reads the project's
//! manifests and lockfiles and writes a CycloneDX SBOM. The project version
//! is the short hash of the project's current git commit, so an SBOM names
//! exactly which revision was scanned.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use super::identity::Identity;
use super::{ScanError, output_path, run_streaming};
use crate::config::Directory;
use crate::dates::{civil_from_days, format_rfc3339};

/// The cdxgen binary to run, overridable with the `CDXGEN_PATH` environment
/// variable.
const CDXGEN: &str = "cdxgen";

/// The name of the SBOM written for each project.
const OUTPUT_NAME: &str = "sbom.cdx.json";

/// The manifest an npm project is expected to have.
const NPM_MANIFEST: &str = "package.json";

/// The SBOM cdxgen produced for a project.
pub struct Sbom {
    /// Where the SBOM was written.
    pub path: PathBuf,
    /// How many packages the SBOM describes.
    pub components: usize,
    /// How many of those are dev-only dependencies.
    pub dev_components: usize,
    /// Declared license -> number of packages under it, most common first.
    pub licenses: Vec<(String, usize)>,
}

/// Generate a CycloneDX SBOM for a project with cdxgen.
pub fn scan(
    directory: &Directory,
    output_dir: &Path,
    identity: &Identity,
) -> Result<Sbom, ScanError> {
    let project = &directory.path;

    if !project.is_dir() {
        return Err(ScanError::MissingDirectory {
            dir: project.clone(),
        });
    }

    if directory.kind == "npm" && !project.join(NPM_MANIFEST).is_file() {
        return Err(ScanError::MissingFile {
            dir: project.clone(),
            file: NPM_MANIFEST.to_string(),
        });
    }

    let out_dir = output_path(output_dir, project);
    std::fs::create_dir_all(&out_dir).map_err(|source| ScanError::Write {
        path: out_dir.clone(),
        source,
    })?;
    let sbom_path = out_dir.join(OUTPUT_NAME);

    run_cdxgen(project, &directory.kind, identity, &sbom_path)?;

    let document = normalize(&sbom_path, identity)?;
    let stats = Stats::of(&document);

    Ok(Sbom {
        path: sbom_path,
        components: stats.components,
        dev_components: stats.dev_components,
        licenses: stats.licenses,
    })
}

/// Run cdxgen over a project, writing its SBOM to `output`.
fn run_cdxgen(
    project: &Path,
    kind: &str,
    identity: &Identity,
    output: &Path,
) -> Result<(), ScanError> {
    let program = std::env::var("CDXGEN_PATH").unwrap_or_else(|_| CDXGEN.to_string());

    // cdxgen runs from the project's parent directory and is given the
    // project by name, so the paths it records in the SBOM stay relative
    // rather than embedding the user's home directory.
    let parent = project
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = project.file_name().unwrap_or_else(|| OsStr::new("."));

    // The output path is made absolute because cdxgen runs in the project's
    // parent directory, not in the scanner's.
    let output = std::path::absolute(output).unwrap_or_else(|_| output.to_path_buf());

    let mut command = Command::new(&program);
    command
        .arg("--output")
        .arg(output)
        .arg("--type")
        .arg(kind)
        .arg("--project-name")
        .arg(&identity.name)
        .arg("--project-version")
        .arg(&identity.version)
        // The scanner only reads the project; cdxgen must not install
        // anything into it.
        .arg("--no-install-deps")
        .arg("--json-pretty")
        .arg(name)
        .current_dir(parent);

    let result = run_streaming(&mut command).map_err(|source| ScanError::Command {
        program: program.clone(),
        source,
    })?;

    if !result.status.success() {
        return Err(ScanError::CommandFailed {
            program,
            status: result.status.to_string(),
            stderr: String::from_utf8_lossy(&result.stderr).trim().to_string(),
        });
    }

    Ok(())
}

/// Rewrite the parts of the SBOM that change on every run, so that scanning
/// an unchanged project produces an unchanged file.
///
/// cdxgen stamps the document with the current time and a random serial
/// number, and summarises the scan in an annotation naming the day it ran.
/// All of these are replaced with values derived from the project's git
/// commit, which keeps consecutive scans of the same revision byte-for-byte
/// identical and so leaves any real change to the dependencies to show up
/// as a difference.
fn normalize(path: &Path, identity: &Identity) -> Result<Value, ScanError> {
    let mut document: Value = read_json(path)?;

    if let Some(object) = document.as_object_mut() {
        object.insert(
            "serialNumber".to_string(),
            Value::String(serial_number(&identity.name, &identity.version)),
        );
    }

    if let Some(created_at) = identity.created_at {
        let created = format_rfc3339(created_at);
        normalize_timestamps(&mut document, &created);
        normalize_summary(&mut document, &format_date(created_at));
    }

    write_json(path, &document)?;
    Ok(document)
}

/// Replace every timestamp in the document with the given one.
fn normalize_timestamps(document: &mut Value, created: &str) {
    match document {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if key == "timestamp" {
                    *value = Value::String(created.to_string());
                } else {
                    normalize_timestamps(value, created);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_timestamps(item, created);
            }
        }
        _ => {}
    }
}

/// Point cdxgen's summary annotation at the scanned revision rather than at
/// the day the scan happened to run.
///
/// The annotation reads "This Software Bill-of-Materials (SBOM) document was
/// created on Sunday, November 8, 2026." cdxgen may word it differently in
/// a later release, in which case the annotation is left as it is.
fn normalize_summary(document: &mut Value, created: &str) {
    let Some(annotations) = document
        .get_mut("annotations")
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    for annotation in annotations {
        let Some(text) = annotation.get_mut("text") else {
            continue;
        };
        let Value::String(text) = text else {
            continue;
        };

        let Some(start) = text.find("was created on ") else {
            continue;
        };
        let rest = &text[start + "was created on ".len()..];
        let Some(end) = rest.find(". ") else {
            continue;
        };

        let mut rewritten = String::with_capacity(text.len());
        rewritten.push_str(&text[..start]);
        rewritten.push_str("was created for the revision committed on ");
        rewritten.push_str(created);
        rewritten.push_str(&rest[end..]);
        *text = rewritten;
    }
}

/// Read a JSON document from `path`.
fn read_json(path: &Path) -> Result<Value, ScanError> {
    let text = std::fs::read_to_string(path).map_err(|source| ScanError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    serde_json::from_str(&text).map_err(|source| ScanError::Parse {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

/// Write a JSON document to `path`.
fn write_json(path: &Path, document: &Value) -> Result<(), ScanError> {
    let mut text = serde_json::to_string_pretty(document).map_err(|source| ScanError::Parse {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })?;
    text.push('\n');

    std::fs::write(path, text).map_err(|source| ScanError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// A stable identifier for a project, in the `urn:uuid:` form CycloneDX
/// uses for a document's serial number.
///
/// This is a UUIDv8 — a custom, deterministic identifier — derived from the
/// project's name and version, so a project always gets the same serial
/// number and a new version gets a new one.
fn serial_number(name: &str, version: &str) -> String {
    let mut hash = FNV_OFFSET;
    for byte in name
        .as_bytes()
        .iter()
        .chain([b'@'].iter())
        .chain(version.as_bytes())
    {
        hash ^= u128::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    let mut bytes = hash.to_be_bytes();
    // Set the version and variant bits RFC 9562 requires of a UUIDv8.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The FNV-1a 128-bit offset basis.
const FNV_OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;

/// The FNV-1a 128-bit prime.
const FNV_PRIME: u128 = 0x0000000001000000000000000000013b;

/// The counts a scan reports about the SBOM it produced.
struct Stats {
    /// How many packages the SBOM describes.
    components: usize,
    /// How many of those are dev-only dependencies.
    dev_components: usize,
    /// Declared license -> number of packages under it, most common first.
    licenses: Vec<(String, usize)>,
}

impl Stats {
    /// Count the components, dev-only components and licenses in an SBOM.
    fn of(document: &Value) -> Self {
        let components = document
            .get("components")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);

        let mut dev_components = 0;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();

        if let Some(components) = document.get("components").and_then(Value::as_array) {
            for component in components {
                if is_dev_only(component) {
                    dev_components += 1;
                }

                for license in licenses_of(component) {
                    *counts.entry(license).or_insert(0) += 1;
                }
            }
        }

        let mut licenses: Vec<(String, usize)> = counts.into_iter().collect();
        licenses.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        Self {
            components,
            dev_components,
            licenses,
        }
    }
}

/// Whether cdxgen marked a component as a development-only dependency.
///
/// cdxgen records this as a `cdx:<type>:package:development` property.
pub(crate) fn is_dev_only(component: &Value) -> bool {
    component
        .get("properties")
        .and_then(Value::as_array)
        .is_some_and(|properties| {
            properties.iter().any(|property| {
                property
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.ends_with(":package:development"))
                    && property.get("value").and_then(Value::as_str) == Some("true")
            })
        })
}

/// The licenses declared by a component.
fn licenses_of(component: &Value) -> Vec<String> {
    let Some(licenses) = component.get("licenses").and_then(Value::as_array) else {
        return Vec::new();
    };

    licenses
        .iter()
        .filter_map(|entry| {
            if let Some(expression) = entry.get("expression").and_then(Value::as_str) {
                return Some(expression.to_string());
            }

            let license = entry.get("license")?;
            license
                .get("id")
                .or_else(|| license.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// The name of each month.
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// The name of each day of the week, starting with Sunday.
const WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

/// Format a Unix timestamp as a date, the way cdxgen writes one.
fn format_date(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    // The epoch, 1 January 1970, was a Thursday.
    let weekday = WEEKDAYS[(days + 4).rem_euclid(7) as usize];

    format!("{weekday}, {} {day}, {year}", MONTHS[(month - 1) as usize])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serial_numbers_are_uuids() {
        let serial = serial_number("goalkeepr", "c0c4364");
        assert!(serial.starts_with("urn:uuid:"));
        assert_eq!(serial.len(), "urn:uuid:".len() + 36);
        assert_eq!(
            serial.chars().filter(|c| *c == '-').count(),
            4,
            "a UUID has four dashes"
        );
    }

    #[test]
    fn serial_numbers_are_stable() {
        assert_eq!(
            serial_number("goalkeepr", "c0c4364"),
            serial_number("goalkeepr", "c0c4364")
        );
    }

    #[test]
    fn serial_numbers_change_with_the_version() {
        assert_ne!(
            serial_number("goalkeepr", "c0c4364"),
            serial_number("goalkeepr", "c0c4365")
        );
    }

    #[test]
    fn recognises_dev_only_components() {
        let dev = json!({
            "name": "vitest",
            "properties": [{"name": "cdx:npm:package:development", "value": "true"}]
        });
        let prod = json!({
            "name": "svelte",
            "properties": [{"name": "cdx:license:category", "value": "Permissive"}]
        });

        assert!(is_dev_only(&dev));
        assert!(!is_dev_only(&prod));
        assert!(!is_dev_only(&json!({})));
    }

    #[test]
    fn reads_licenses_by_id_name_and_expression() {
        let component = json!({
            "licenses": [
                {"license": {"id": "MIT"}},
                {"license": {"name": "Custom"}},
                {"expression": "MIT OR Apache-2.0"}
            ]
        });

        assert_eq!(
            licenses_of(&component),
            vec!["MIT", "Custom", "MIT OR Apache-2.0"]
        );
    }

    #[test]
    fn components_without_licenses_are_skipped() {
        assert!(licenses_of(&json!({})).is_empty());
        assert!(licenses_of(&json!({"licenses": []})).is_empty());
    }

    #[test]
    fn counts_components_and_licenses() {
        let document = json!({
            "components": [
                {"name": "a", "licenses": [{"license": {"id": "MIT"}}]},
                {
                    "name": "b",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "properties": [{"name": "cdx:npm:package:development", "value": "true"}]
                },
                {"name": "c", "licenses": [{"license": {"id": "ISC"}}]}
            ]
        });

        let stats = Stats::of(&document);
        assert_eq!(stats.components, 3);
        assert_eq!(stats.dev_components, 1);
        assert_eq!(
            stats.licenses,
            vec![("MIT".to_string(), 2), ("ISC".to_string(), 1)]
        );
    }

    #[test]
    fn formats_a_date_the_way_cdxgen_does() {
        // 2026-11-08 was a Sunday.
        assert_eq!(format_date(1_794_134_369), "Sunday, November 8, 2026");
    }

    #[test]
    fn formats_the_epoch_as_a_date() {
        // 1970-01-01 was a Thursday.
        assert_eq!(format_date(0), "Thursday, January 1, 1970");
    }

    #[test]
    fn replaces_every_timestamp() {
        let mut document = json!({
            "metadata": {"timestamp": "2026-11-08T20:45:25Z"},
            "citations": [{"timestamp": "2026-11-08T20:45:25Z"}],
            "components": [{"name": "a", "timestamp": "2026-11-08T20:45:25Z"}]
        });

        normalize_timestamps(&mut document, "2026-11-08T10:39:29Z");

        assert_eq!(document["metadata"]["timestamp"], "2026-11-08T10:39:29Z");
        assert_eq!(
            document["citations"][0]["timestamp"],
            "2026-11-08T10:39:29Z"
        );
        assert_eq!(
            document["components"][0]["timestamp"],
            "2026-11-08T10:39:29Z"
        );
    }

    #[test]
    fn points_the_summary_at_the_scanned_revision() {
        let mut document = json!({
            "annotations": [{
                "text": "This Software Bill-of-Materials (SBOM) document was created on Sunday, November 8, 2026. The xBOM tools used are: cdxgen."
            }]
        });

        normalize_summary(&mut document, "Sunday, November 8, 2026");

        assert_eq!(
            document["annotations"][0]["text"],
            "This Software Bill-of-Materials (SBOM) document was created for the revision committed on Sunday, November 8, 2026. The xBOM tools used are: cdxgen."
        );
    }

    #[test]
    fn leaves_an_unrecognised_summary_alone() {
        let mut document = json!({
            "annotations": [{"text": "Something else entirely."}]
        });

        normalize_summary(&mut document, "Sunday, November 8, 2026");

        assert_eq!(
            document["annotations"][0]["text"],
            "Something else entirely."
        );
    }
}
