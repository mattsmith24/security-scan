//! Email alerts sent when a scan finishes.
//!
//! Settings come from [`Config`]: the message is built from the projects a
//! scan reported on, and sending uses the SMTP relay configured alongside the
//! recipients. The pieces are added in this module so that the console scan
//! output stays independent of email.

use std::path::PathBuf;

use lettre::message::Mailbox;

use crate::config::{Config, Tls};
use crate::data_sources;
use crate::scanner::cve_bin_tool::{self, Cve};

/// The tick shown when no active finding is critical or high.
const CLEAN: &str = "\u{2705}";

/// The flashing light shown when an active finding is critical or high.
const ALERT: &str = "\u{1f6a8}";

/// How many findings a project section lists before summarising the rest.
const TOP_FINDINGS: usize = 10;

/// The prefix that starts every alert's subject.
pub const SUBJECT_PREFIX: &str = "[security-scan]";

/// Everything needed to build and send an alert.
#[derive(Debug, Clone)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub user: Option<String>,
    pub password: Option<String>,
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub prefix: String,
}

impl Settings {
    /// Build the alert settings from a loaded config.
    ///
    /// Returns `None` when email is off, which includes an `email = false`
    /// switch and any config missing recipients, a from address or an SMTP
    /// host.
    pub fn from_config(config: &Config) -> Option<Self> {
        if !config.email_enabled() {
            return None;
        }

        let smtp = config.smtp_settings()?;
        let from = config.email_from()?.clone();

        Some(Self {
            host: smtp.host.clone(),
            port: smtp.port,
            tls: smtp.tls,
            user: smtp.user.clone(),
            password: config.smtp_password().map(str::to_string),
            from,
            to: config.email_recipients().to_vec(),
            prefix: SUBJECT_PREFIX.to_string(),
        })
    }
}

/// What one scanned project contributes to an alert.
#[derive(Debug, Clone)]
pub struct ProjectSummary {
    /// The project's name, as shown in the email.
    pub name: String,
    /// The kind of project, e.g. `npm` or `rust`.
    pub kind: String,
    /// How many packages the SBOM described.
    pub components: usize,
    /// How many of those are dev-only dependencies.
    pub dev_components: usize,
    /// The findings, most severe first, including triaged ones.
    pub cves: Vec<Cve>,
    /// The project's `cve-report.json`, attached to the email.
    pub report: PathBuf,
}

/// The subject line for a finished scan.
///
/// The status is based on active findings only, matching what the console
/// prints: a finding the VEX has dismissed does not turn the subject red.
pub fn subject(prefix: &str, projects: &[ProjectSummary]) -> String {
    let active: Vec<Cve> = projects
        .iter()
        .flat_map(|project| &project.cves)
        .filter(|cve| !cve.is_triaged())
        .cloned()
        .collect();

    let serious = active.iter().any(|cve| {
        ["CRITICAL", "HIGH"]
            .iter()
            .any(|s| cve.severity.eq_ignore_ascii_case(s))
    });
    let status = if serious { ALERT } else { CLEAN };

    if active.is_empty() {
        let count = projects.len();
        let noun = if count == 1 { "project" } else { "projects" };
        return format!("{status} {prefix} {count} {noun} clean");
    }

    let counts: Vec<String> = cve_bin_tool::by_severity(&active)
        .iter()
        .map(|(severity, count)| format!("{count} {}", severity.to_ascii_lowercase()))
        .collect();

    format!("{status} {prefix} {}", counts.join(", "))
}

/// The plain-text body for a finished scan.
pub fn body(
    projects: &[ProjectSummary],
    failures: &[String],
    sources: &data_sources::Report,
) -> String {
    let mut sections: Vec<String> = Vec::new();

    if projects.is_empty() {
        sections.push("No projects were scanned.".to_string());
    } else {
        for project in projects {
            sections.push(describe_project(project));
        }
    }

    sections.push(describe_data_sources(sources));

    if !failures.is_empty() {
        let total = projects.len() + failures.len();
        let mut lines = vec![format!(
            "Incomplete scan: {} of {total} directories failed",
            failures.len()
        )];
        lines.extend(failures.iter().map(|failure| format!("  {failure}")));
        sections.push(lines.join("\n"));
    }

    sections.join("\n\n")
}

/// One project's paragraphs: counts, severities, and its worst findings.
fn describe_project(project: &ProjectSummary) -> String {
    let active: Vec<Cve> = project
        .cves
        .iter()
        .filter(|cve| !cve.is_triaged())
        .cloned()
        .collect();
    let filtered = project.cves.len() - active.len();

    let mut lines = vec![
        format!("{} ({})", project.name, project.kind),
        format!(
            "  {} packages, {} dev-only",
            project.components, project.dev_components
        ),
    ];

    if active.is_empty() {
        let line = match filtered {
            0 => "  no known vulnerabilities".to_string(),
            count => format!("  no known vulnerabilities ({count} filtered by the VEX)"),
        };
        lines.push(line);
        return lines.join("\n");
    }

    let counts: Vec<String> = cve_bin_tool::by_severity(&active)
        .iter()
        .map(|(severity, count)| format!("{count} {severity}"))
        .collect();
    let noun = if active.len() == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    lines.push(format!("  {} {noun} ({})", active.len(), counts.join(", ")));

    for cve in active.iter().take(TOP_FINDINGS) {
        let dev = if cve.dev_only { " (dev only)" } else { "" };
        lines.push(format!(
            "    {} {} {}@{} ({}){dev}",
            cve.severity, cve.number, cve.product, cve.version, cve.score
        ));
    }

    if active.len() > TOP_FINDINGS {
        lines.push(format!("    ... and {} more", active.len() - TOP_FINDINGS));
    }

    if filtered > 0 {
        lines.push(format!("  {filtered} filtered by the VEX"));
    }

    lines.join("\n")
}

/// The vulnerability-data paragraphs, including a warning for any source
/// that has no data or stale data.
fn describe_data_sources(report: &data_sources::Report) -> String {
    let updated = match report.updated {
        Some(at) => data_sources::describe_age(at, report.checked),
        None => "never".to_string(),
    };

    let mut lines = vec![format!("Vulnerability data (database updated {updated})")];

    if let Some(error) = &report.error {
        lines.push(format!("  {error}"));
    }

    lines.extend(report.lines());

    let problems = report.problems();
    if !problems.is_empty() {
        let names: Vec<&str> = problems.iter().map(|source| source.name).collect();
        let verb = if problems.len() == 1 { "needs" } else { "need" };
        lines.push(format!(
            "  warning: {} of {} data sources {verb} attention: {}",
            problems.len(),
            report.sources.len(),
            names.join(", ")
        ));
    }

    lines.join("\n")
}

/// Problems with the settings that do not stop an alert from being sent.
///
/// Gmail only accepts the authenticated address, or an alias verified for it,
/// in `From`. A different address usually means the message is rejected, so
/// say so before the scan runs rather than after it finishes.
pub fn warnings(settings: &Settings) -> Vec<String> {
    let Some(user) = settings.user.as_deref() else {
        return Vec::new();
    };

    let from = settings.from.email.to_string();
    if from.eq_ignore_ascii_case(user) {
        return Vec::new();
    }

    vec![format!(
        "warning: email_from ({from}) differs from smtp_user ({user}); \
         Gmail only accepts the authenticated address or a verified alias"
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Tls;

    fn settings(from: &str, user: Option<&str>) -> Settings {
        Settings {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: Tls::Starttls,
            user: user.map(str::to_string),
            password: user.map(|_| "app password".to_string()),
            from: from.parse().unwrap(),
            to: vec!["scan@example.com".parse().unwrap()],
            prefix: SUBJECT_PREFIX.to_string(),
        }
    }

    #[test]
    fn warns_when_from_differs_from_the_smtp_user() {
        let warnings = warnings(&settings("alerts@example.com", Some("scan@example.com")));

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("alerts@example.com"));
        assert!(warnings[0].contains("scan@example.com"));
        assert!(warnings[0].contains("verified alias"));
    }

    #[test]
    fn matching_addresses_do_not_warn() {
        assert!(warnings(&settings("scan@example.com", Some("scan@example.com"))).is_empty());
    }

    #[test]
    fn the_comparison_ignores_case() {
        assert!(warnings(&settings("Scan@Example.com", Some("scan@example.com"))).is_empty());
    }

    #[test]
    fn the_comparison_ignores_the_display_name() {
        let warnings = warnings(&settings(
            "Security Scan <scan@example.com>",
            Some("scan@example.com"),
        ));

        assert!(warnings.is_empty());
    }

    #[test]
    fn a_local_relay_without_a_user_does_not_warn() {
        assert!(warnings(&settings("scan@example.com", None)).is_empty());
    }

    fn cve(severity: &str, number: &str, remarks: &str) -> Cve {
        Cve {
            number: number.to_string(),
            severity: severity.to_string(),
            score: "9.8".to_string(),
            product: "left-pad".to_string(),
            version: "1.0.0".to_string(),
            remarks: remarks.to_string(),
            dev_only: false,
        }
    }

    fn project(name: &str, cves: Vec<Cve>) -> ProjectSummary {
        ProjectSummary {
            name: name.to_string(),
            kind: "npm".to_string(),
            components: 42,
            dev_components: 3,
            cves,
            report: PathBuf::from("/tmp/cve-report.json"),
        }
    }

    fn sources() -> data_sources::Report {
        const CHECKED: i64 = 1_172_800;
        const DAY: i64 = 86_400;

        data_sources::Report {
            database: PathBuf::from("/tmp/cve.db"),
            updated: Some(CHECKED - 2 * DAY),
            checked: CHECKED,
            stale_after_days: 7,
            sources: vec![
                data_sources::Source {
                    name: "NVD",
                    entries: 120,
                    newest: Some(CHECKED - DAY),
                    downloaded: Some(CHECKED - DAY),
                    state: data_sources::State::Ok,
                },
                data_sources::Source {
                    name: "OSV",
                    entries: 0,
                    newest: None,
                    downloaded: None,
                    state: data_sources::State::Missing,
                },
            ],
            error: None,
        }
    }

    #[test]
    fn a_clean_scan_gets_a_tick_and_a_project_count() {
        let projects = vec![project("alpha", vec![]), project("beta", vec![])];

        assert_eq!(
            subject(SUBJECT_PREFIX, &projects),
            "✅ [security-scan] 2 projects clean"
        );
    }

    #[test]
    fn a_single_clean_project_reads_naturally() {
        let projects = vec![project("alpha", vec![])];

        assert_eq!(
            subject(SUBJECT_PREFIX, &projects),
            "✅ [security-scan] 1 project clean"
        );
    }

    #[test]
    fn one_active_high_finding_turns_the_subject_red() {
        let projects = vec![project(
            "alpha",
            vec![cve("HIGH", "CVE-2026-1", "NewFound")],
        )];

        assert_eq!(
            subject(SUBJECT_PREFIX, &projects),
            "🚨 [security-scan] 1 high"
        );
    }

    #[test]
    fn a_critical_finding_turns_the_subject_red() {
        let projects = vec![project(
            "alpha",
            vec![cve("CRITICAL", "CVE-2026-1", "NewFound")],
        )];

        assert!(subject(SUBJECT_PREFIX, &projects).starts_with("🚨"));
    }

    #[test]
    fn triaged_findings_do_not_turn_the_subject_red() {
        let projects = vec![project(
            "alpha",
            vec![cve("HIGH", "CVE-2026-1", "NotAffected")],
        )];

        assert_eq!(
            subject(SUBJECT_PREFIX, &projects),
            "✅ [security-scan] 1 project clean"
        );
    }

    #[test]
    fn medium_findings_stay_green_but_are_counted() {
        let projects = vec![project(
            "alpha",
            vec![cve("MEDIUM", "CVE-2026-1", "NewFound")],
        )];

        assert_eq!(
            subject(SUBJECT_PREFIX, &projects),
            "✅ [security-scan] 1 medium"
        );
    }

    #[test]
    fn the_subject_counts_findings_across_projects() {
        let projects = vec![
            project(
                "alpha",
                vec![
                    cve("CRITICAL", "CVE-2026-1", "NewFound"),
                    cve("HIGH", "CVE-2026-2", "NewFound"),
                ],
            ),
            project(
                "beta",
                vec![
                    cve("HIGH", "CVE-2026-3", "NewFound"),
                    cve("HIGH", "CVE-2026-4", "Mitigated"),
                ],
            ),
        ];

        assert_eq!(
            subject(SUBJECT_PREFIX, &projects),
            "🚨 [security-scan] 1 critical, 2 high"
        );
    }

    #[test]
    fn the_body_lists_packages_and_the_severity_breakdown() {
        let projects = vec![project(
            "alpha",
            vec![
                cve("HIGH", "CVE-2026-1", "NewFound"),
                cve("MEDIUM", "CVE-2026-2", "NewFound"),
            ],
        )];

        let body = body(&projects, &[], &sources());

        assert!(body.contains("alpha (npm)"), "{body}");
        assert!(body.contains("42 packages, 3 dev-only"), "{body}");
        assert!(
            body.contains("2 vulnerabilities (1 HIGH, 1 MEDIUM)"),
            "{body}"
        );
        assert!(
            body.contains("HIGH CVE-2026-1 left-pad@1.0.0 (9.8)"),
            "{body}"
        );
    }

    #[test]
    fn the_body_lists_at_most_ten_findings() {
        let cves = (1..=12)
            .map(|n| cve("HIGH", &format!("CVE-2026-{n}"), "NewFound"))
            .collect();
        let projects = vec![project("alpha", cves)];

        let body = body(&projects, &[], &sources());

        assert!(body.contains("12 vulnerabilities"), "{body}");
        assert!(body.contains("CVE-2026-10"), "{body}");
        assert!(!body.contains("CVE-2026-11"), "{body}");
        assert!(body.contains("... and 2 more"), "{body}");
    }

    #[test]
    fn the_body_counts_findings_filtered_by_the_vex() {
        let projects = vec![project(
            "alpha",
            vec![
                cve("HIGH", "CVE-2026-1", "NewFound"),
                cve("HIGH", "CVE-2026-2", "FalsePositive"),
                cve("HIGH", "CVE-2026-3", "Mitigated"),
            ],
        )];

        let body = body(&projects, &[], &sources());

        assert!(body.contains("1 vulnerability"), "{body}");
        assert!(body.contains("2 filtered by the VEX"), "{body}");
    }

    #[test]
    fn the_body_says_when_a_project_is_clean() {
        let projects = vec![project(
            "alpha",
            vec![cve("LOW", "CVE-2026-1", "NotAffected")],
        )];

        let body = body(&projects, &[], &sources());

        assert!(
            body.contains("no known vulnerabilities (1 filtered by the VEX)"),
            "{body}"
        );
    }

    #[test]
    fn the_body_includes_the_vulnerability_data_and_its_warnings() {
        let body = body(&[project("alpha", vec![])], &[], &sources());

        assert!(
            body.contains("Vulnerability data (database updated 2 days ago)"),
            "{body}"
        );
        assert!(
            body.contains("warning: 1 of 2 data sources needs attention: OSV"),
            "{body}"
        );
    }

    #[test]
    fn the_body_flags_an_incomplete_scan() {
        let projects = vec![project("alpha", vec![]), project("beta", vec![])];
        let failures = vec!["/projects/gamma: no SBOM found".to_string()];

        let body = body(&projects, &failures, &sources());

        assert!(
            body.contains("Incomplete scan: 1 of 3 directories failed"),
            "{body}"
        );
        assert!(body.contains("/projects/gamma: no SBOM found"), "{body}");
    }
}
