//! CVE scanning with cve-bin-tool.
//!
//! The SBOM produced by cdxgen is handed to cve-bin-tool, which matches the
//! packages in it against its CVE database and writes a JSON report of the
//! vulnerabilities it found. Nothing here talks to an advisory service the
//! way `npm audit` does: the data comes from the SBOM and from cve-bin-tool's
//! own database.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use super::cdxgen::is_dev_only;
use super::identity::Identity;
use super::{ScanError, output_path, run_streaming};
use crate::config::Directory;

/// The program cve-bin-tool is run with, unless `CVE_BIN_TOOL_PATH` names
/// one to run instead.
const PROGRAM: &str = "uv";

/// The name of the report written for each project.
const OUTPUT_NAME: &str = "cve-report.json";

/// The severities a finding can have, most severe first. Anything the report
/// does not name is treated as less severe than all of these.
const SEVERITIES: [&str; 6] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"];

/// How much of a failed run's output to keep for the error message.
const STDERR_LINES: usize = 20;

/// What a CVE scan found.
pub struct CveScan {
    /// The report cve-bin-tool wrote.
    pub report: PathBuf,
    /// The findings, most severe first.
    pub cves: Vec<Cve>,
}

/// A vulnerability found in one of the project's packages.
#[derive(Debug, Clone)]
pub struct Cve {
    /// The CVE's identifier, e.g. `CVE-2026-45819`.
    pub number: String,
    /// How severe the CVE is, e.g. `HIGH`.
    pub severity: String,
    /// The CVSS score of the CVE.
    pub score: String,
    /// The package the CVE was found in.
    pub product: String,
    /// The version of that package.
    pub version: String,
    /// Whether the package is only needed to develop the project.
    pub dev_only: bool,
}

/// Scan an SBOM for known vulnerabilities with cve-bin-tool.
pub fn scan(
    directory: &Directory,
    output_dir: &Path,
    identity: &Identity,
    sbom: &Path,
    base_dir: &Path,
) -> Result<CveScan, ScanError> {
    let out_dir = output_path(output_dir, &directory.path);
    std::fs::create_dir_all(&out_dir).map_err(|source| ScanError::Write {
        path: out_dir.clone(),
        source,
    })?;
    let report_path = out_dir.join(OUTPUT_NAME);

    // cve-bin-tool will not write over an existing report: it picks a freshly
    // named file instead, which would leave this scan's findings somewhere
    // unexpected. The old report is removed first so that the report for a
    // scan always lands at the same path.
    if report_path.exists() {
        std::fs::remove_file(&report_path).map_err(|source| ScanError::Write {
            path: report_path.clone(),
            source,
        })?;
    }

    run(directory, identity, sbom, &report_path, base_dir)?;

    let cves = read_cves(&report_path, sbom)?;

    Ok(CveScan {
        report: report_path,
        cves,
    })
}

/// Run cve-bin-tool over an SBOM, writing its report to `report`.
fn run(
    directory: &Directory,
    identity: &Identity,
    sbom: &Path,
    report: &Path,
    base_dir: &Path,
) -> Result<(), ScanError> {
    let (program, prefix) = command();

    // The paths are made absolute because cve-bin-tool runs in the scanner's
    // own directory, not next to the SBOM.
    let sbom = std::path::absolute(sbom).unwrap_or_else(|_| sbom.to_path_buf());
    let report = std::path::absolute(report).unwrap_or_else(|_| report.to_path_buf());

    let mut command = Command::new(&program);
    command.args(prefix);
    command
        .arg("--sbom")
        .arg("cyclonedx")
        .arg("--sbom-file")
        .arg(&sbom)
        .arg("--output-file")
        .arg(&report)
        .arg("--format")
        .arg("json")
        .arg("--product")
        .arg(&identity.name)
        .arg("--release")
        .arg(&identity.version);

    if let Some(vendor) = &directory.vendor {
        command.arg("--vendor").arg(vendor);
    }

    // cve-bin-tool is run from the scanner's own directory, which is where
    // the virtual environment holding it lives.
    command.current_dir(base_dir);

    let result = run_streaming(&mut command).map_err(|source| ScanError::Command {
        program: program.clone(),
        source,
    })?;

    // cve-bin-tool exits with 1 when it finds vulnerabilities, which is a
    // successful scan. Anything else means the scan itself went wrong.
    match result.status.code() {
        Some(0) | Some(1) => Ok(()),
        _ => Err(ScanError::CommandFailed {
            program,
            status: result.status.to_string(),
            stderr: last_lines(&String::from_utf8_lossy(&result.stderr)),
        }),
    }
}

/// The program to run and the arguments that come before its own options.
///
/// cve-bin-tool is run through `uv`, which picks up the virtual environment
/// in the scanner's own directory. Setting `CVE_BIN_TOOL_PATH` to the path of
/// a cve-bin-tool binary runs that binary directly instead.
fn command() -> (String, Vec<String>) {
    match std::env::var("CVE_BIN_TOOL_PATH") {
        Ok(path) => (path, Vec::new()),
        Err(_) => (
            PROGRAM.to_string(),
            vec!["run".to_string(), "cve-bin-tool".to_string()],
        ),
    }
}

/// Read the findings out of a cve-bin-tool report.
///
/// The report is a list of findings, one per package and CVE. Findings in
/// packages that the SBOM marks as development-only are flagged, so that they
/// can be told apart from the ones that matter in a release.
fn read_cves(report: &Path, sbom: &Path) -> Result<Vec<Cve>, ScanError> {
    let text = std::fs::read_to_string(report).map_err(|source| ScanError::Read {
        path: report.to_path_buf(),
        source,
    })?;

    let document: Value = serde_json::from_str(&text).map_err(|source| ScanError::Parse {
        path: report.to_path_buf(),
        reason: source.to_string(),
    })?;

    let Some(entries) = document.as_array() else {
        return Ok(Vec::new());
    };

    let dev_only = dev_only_packages(sbom);

    let mut cves: Vec<Cve> = entries
        .iter()
        .map(|entry| Cve {
            number: field(entry, "cve_number"),
            severity: field(entry, "severity"),
            score: field(entry, "score"),
            product: field(entry, "product"),
            version: field(entry, "version"),
            dev_only: false,
        })
        .collect();

    for cve in &mut cves {
        cve.dev_only = dev_only.contains(&format!("{}@{}", cve.product, cve.version));
    }

    cves.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.product.cmp(&b.product))
            .then_with(|| a.number.cmp(&b.number))
    });

    Ok(cves)
}

/// The dev-only packages in an SBOM, as `name@version` pairs.
fn dev_only_packages(sbom: &Path) -> BTreeSet<String> {
    let Ok(text) = std::fs::read_to_string(sbom) else {
        return BTreeSet::new();
    };
    let Ok(document) = serde_json::from_str::<Value>(&text) else {
        return BTreeSet::new();
    };

    let mut packages = BTreeSet::new();
    if let Some(components) = document.get("components").and_then(Value::as_array) {
        for component in components {
            if !is_dev_only(component) {
                continue;
            }

            let name = component
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let version = component
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_default();

            packages.insert(format!("{name}@{version}"));
        }
    }

    packages
}

/// A string field of a finding, empty if it is not there.
fn field(entry: &Value, name: &str) -> String {
    entry
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// How severe a finding is, lower being more severe.
fn severity_rank(severity: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|known| known.eq_ignore_ascii_case(severity))
        .unwrap_or(SEVERITIES.len())
}

/// The last few lines of a program's output, for an error message.
fn last_lines(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(STDERR_LINES);
    lines[start..].join("\n")
}

/// How many findings there are of each severity, most severe first.
pub fn by_severity(cves: &[Cve]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for cve in cves {
        *counts.entry(cve.severity.clone()).or_insert(0) += 1;
    }

    let mut counts: Vec<(String, usize)> = counts.into_iter().collect();
    counts.sort_by_key(|(severity, _)| severity_rank(severity));

    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ranks_severities_from_most_to_least_serious() {
        assert!(severity_rank("CRITICAL") < severity_rank("HIGH"));
        assert!(severity_rank("HIGH") < severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") < severity_rank("LOW"));
        assert!(severity_rank("LOW") < severity_rank("UNKNOWN"));
    }

    #[test]
    fn ranks_unknown_severities_last() {
        assert_eq!(severity_rank("SOMETHING"), SEVERITIES.len());
    }

    #[test]
    fn keeps_the_last_lines_of_a_failed_run() {
        let text = "one\ntwo\nthree\nfour";
        assert_eq!(last_lines(text), "one\ntwo\nthree\nfour");
    }

    #[test]
    fn drops_all_but_the_last_lines_of_a_long_output() {
        let text = (1..=100)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let tail = last_lines(&text);
        let lines: Vec<&str> = tail.lines().collect();
        assert_eq!(lines.len(), STDERR_LINES);
        assert_eq!(lines[lines.len() - 1], "100");
    }

    #[test]
    fn counts_findings_by_severity() {
        let cves = vec![
            Cve {
                number: "CVE-1".to_string(),
                severity: "HIGH".to_string(),
                score: "7.5".to_string(),
                product: "a".to_string(),
                version: "1.0".to_string(),
                dev_only: false,
            },
            Cve {
                number: "CVE-2".to_string(),
                severity: "HIGH".to_string(),
                score: "7.5".to_string(),
                product: "b".to_string(),
                version: "1.0".to_string(),
                dev_only: false,
            },
            Cve {
                number: "CVE-3".to_string(),
                severity: "LOW".to_string(),
                score: "3.1".to_string(),
                product: "c".to_string(),
                version: "1.0".to_string(),
                dev_only: false,
            },
        ];

        let counts = by_severity(&cves);
        assert_eq!(
            counts,
            vec![("HIGH".to_string(), 2), ("LOW".to_string(), 1)]
        );
    }

    #[test]
    fn reads_findings_out_of_a_report() {
        let report = json!([
            {
                "vendor": "unknown",
                "product": "better-auth",
                "version": "1.4.22",
                "cve_number": "CVE-2026-114607",
                "severity": "CRITICAL",
                "score": "9.1"
            }
        ]);

        let entries = report.as_array().unwrap();
        assert_eq!(field(&entries[0], "cve_number"), "CVE-2026-114607");
        assert_eq!(field(&entries[0], "severity"), "CRITICAL");
        assert_eq!(field(&entries[0], "missing"), "");
    }
}
