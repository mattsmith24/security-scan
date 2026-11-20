//! Email alerts sent when a scan finishes.
//!
//! Settings come from [`Config`]: the message is built from the projects a
//! scan reported on, and sending uses the SMTP relay configured alongside the
//! recipients. The pieces are added in this module so that the console scan
//! output stays independent of email.

use std::path::PathBuf;
use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, Message, MultiPart, SinglePart};
use lettre::transport::smtp::Error as SmtpError;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use thiserror::Error;

use crate::config::{Config, Tls};
use crate::data_sources;
use crate::scanner::cve_bin_tool::{self, Cve};

/// The tick shown when no active finding is critical or high.
const CLEAN: &str = "\u{2705}";

/// The flashing light shown when an active finding is critical or high.
const ALERT: &str = "\u{1f6a8}";

/// How many findings a project section lists before summarising the rest.
const TOP_FINDINGS: usize = 10;

/// How large the attachments to one message may be in total.
const ATTACHMENT_LIMIT: usize = 10 * 1024 * 1024;

/// How long to wait on the SMTP server before giving up.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The prefix that starts every alert's subject.
pub const SUBJECT_PREFIX: &str = "[security-scan]";

/// Why an alert could not be built or sent.
#[derive(Debug, Error)]
pub enum EmailError {
    #[error("failed to build the message: {0}")]
    Build(#[from] lettre::error::Error),

    #[error("failed to configure the SMTP connection to {host}:{port}: {source}")]
    Configure {
        host: String,
        port: u16,
        #[source]
        source: SmtpError,
    },

    #[error("failed to send email through {host}:{port}: {source}{hint}")]
    Send {
        host: String,
        port: u16,
        #[source]
        source: SmtpError,
        hint: String,
    },
}

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

/// Build an alert message with a plain-text body and JSON attachments.
///
/// Attachments are `(filename, bytes)` pairs. When they total more than
/// [`ATTACHMENT_LIMIT`], the files that do not fit are left out and named in
/// the body instead, so a large scan still sends its findings.
pub fn message(
    settings: &Settings,
    subject: &str,
    body: &str,
    attachments: &[(String, Vec<u8>)],
) -> Result<Message, EmailError> {
    let (kept, skipped) = select_attachments(attachments);
    let text = body_with_attachment_note(body, &skipped);

    let mut builder = Message::builder()
        .from(settings.from.clone())
        .subject(subject);
    for recipient in &settings.to {
        builder = builder.to(recipient.clone());
    }

    let mut multipart = MultiPart::mixed().singlepart(SinglePart::plain(text));
    for (name, bytes) in kept {
        multipart = multipart.singlepart(attachment(name, bytes));
    }

    Ok(builder.multipart(multipart)?)
}

/// Split attachments into those that fit under the size limit and those that
/// do not, keeping the caller's order.
fn select_attachments(attachments: &[(String, Vec<u8>)]) -> (Vec<&(String, Vec<u8>)>, Vec<&str>) {
    let mut total = 0;
    let mut kept = Vec::new();
    let mut skipped = Vec::new();

    for item in attachments {
        let size = item.1.len();
        if total + size <= ATTACHMENT_LIMIT {
            total += size;
            kept.push(item);
        } else {
            skipped.push(item.0.as_str());
        }
    }

    (kept, skipped)
}

/// Add a note to the body when attachments were too large to send.
fn body_with_attachment_note(body: &str, skipped: &[&str]) -> String {
    if skipped.is_empty() {
        return body.to_string();
    }

    let mut text = body.to_string();
    text.push_str(&format!(
        "\n\nAttachments skipped (the total is over {} MB)\n",
        ATTACHMENT_LIMIT / 1024 / 1024
    ));
    for name in skipped {
        text.push_str(&format!("  {name}\n"));
    }

    text
}

/// One JSON file attachment.
fn attachment(name: &str, bytes: &[u8]) -> SinglePart {
    Attachment::new(name.to_string()).body(
        bytes.to_vec(),
        ContentType::parse("application/json").expect("valid content type"),
    )
}

/// Send a built message through the configured SMTP server.
pub fn send(settings: &Settings, message: &Message) -> Result<(), EmailError> {
    let transport = transport(settings)?;
    deliver(&transport, message, settings)
}

/// Build the transport for the configured TLS mode.
///
/// `relay` and `starttls_relay` validate certificates against the host and
/// pick lettre's default ports, which are then overridden with the configured
/// one. `builder_dangerous` sends unencrypted and is only for a local relay.
fn transport(settings: &Settings) -> Result<SmtpTransport, EmailError> {
    let builder = match settings.tls {
        Tls::Implicit => SmtpTransport::relay(&settings.host),
        Tls::Starttls => SmtpTransport::starttls_relay(&settings.host),
        Tls::None => Ok(SmtpTransport::builder_dangerous(&settings.host)),
    }
    .map_err(|source| EmailError::Configure {
        host: settings.host.clone(),
        port: settings.port,
        source,
    })?;

    let mut builder = builder.port(settings.port).timeout(Some(TIMEOUT));

    if let (Some(user), Some(password)) = (&settings.user, &settings.password) {
        builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
    }

    Ok(builder.build())
}

/// Hand a message to any transport, so tests can record it instead of
/// connecting.
fn deliver<T>(transport: &T, message: &Message, settings: &Settings) -> Result<(), EmailError>
where
    T: Transport<Error = SmtpError>,
{
    transport.send(message).map(|_| ()).map_err(|source| {
        let hint = send_hint(&source, settings.port);
        EmailError::Send {
            host: settings.host.clone(),
            port: settings.port,
            source,
            hint,
        }
    })
}

/// A hint for the common ways SMTP delivery fails.
fn send_hint(error: &SmtpError, port: u16) -> String {
    // Gmail answers a wrong password with 535 5.7.8 and an ordinary
    // password used where an App Password is needed with 534 5.7.9.
    if let Some(535 | 534) = error.status().map(u16::from) {
        return "; Gmail needs an App Password here, not the account password".to_string();
    }

    if error.is_timeout() {
        return "; the SMTP server did not answer within 30 seconds".to_string();
    }

    if error.is_tls() {
        return format!("; TLS failed; check smtp_tls and that port {port} is reachable");
    }

    if error.status().is_none() {
        return format!(
            "; check smtp_host, smtp_port ({port}) and that outbound connections are allowed"
        );
    }

    String::new()
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
    use std::cell::RefCell;

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

    fn render(message: &Message) -> String {
        String::from_utf8_lossy(&message.formatted()).into_owned()
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

    #[test]
    fn the_message_has_from_to_and_subject_headers() {
        let mut settings = settings("Security Scan <scan@example.com>", Some("scan@example.com"));
        settings.to = vec![
            "a@example.com".parse().unwrap(),
            "B <b@example.com>".parse().unwrap(),
        ];

        let message =
            message(&settings, "✅ [security-scan] 1 project clean", "body", &[]).unwrap();
        let formatted = render(&message);

        assert!(
            formatted.contains("From: \"Security Scan\" <scan@example.com>")
                || formatted.contains("From: Security Scan <scan@example.com>"),
            "{formatted}"
        );
        assert!(formatted.contains("a@example.com"), "{formatted}");
        assert!(formatted.contains("b@example.com"), "{formatted}");
        assert!(formatted.contains("Subject: "), "{formatted}");
        assert!(
            formatted.contains("Content-Type: text/plain"),
            "{formatted}"
        );
    }

    #[test]
    fn the_message_encodes_the_emoji_subject() {
        let message = message(
            &settings("scan@example.com", Some("scan@example.com")),
            "🚨 [security-scan] 1 high",
            "body",
            &[],
        )
        .unwrap();

        let formatted = render(&message);
        assert!(formatted.contains("Subject: =?utf-8?"), "{formatted}");
        assert!(!formatted.contains("Subject: 🚨"), "{formatted}");
    }

    #[test]
    fn the_message_attaches_json_files() {
        let attachments = vec![
            ("cve-report.json".to_string(), b"{}".to_vec()),
            ("data-sources.json".to_string(), b"[]".to_vec()),
        ];

        let message = message(
            &settings("scan@example.com", Some("scan@example.com")),
            "subject",
            "body",
            &attachments,
        )
        .unwrap();
        let formatted = render(&message);

        assert!(formatted.contains("multipart/mixed"), "{formatted}");
        assert!(formatted.contains("boundary="), "{formatted}");
        assert!(
            formatted.contains("filename=\"cve-report.json\""),
            "{formatted}"
        );
        assert!(
            formatted.contains("filename=\"data-sources.json\""),
            "{formatted}"
        );
        assert!(
            formatted.contains("Content-Disposition: attachment"),
            "{formatted}"
        );
        assert!(
            formatted.contains("Content-Type: application/json"),
            "{formatted}"
        );
    }

    #[test]
    fn an_oversized_attachment_is_left_out_and_named_in_the_body() {
        let attachments = vec![("huge.json".to_string(), vec![b'x'; ATTACHMENT_LIMIT + 1])];

        let message = message(
            &settings("scan@example.com", Some("scan@example.com")),
            "subject",
            "Findings are in the body.",
            &attachments,
        )
        .unwrap();
        let formatted = render(&message);

        assert!(!formatted.contains("filename=\"huge.json\""), "{formatted}");
        assert!(formatted.contains("Attachments skipped"), "{formatted}");
        assert!(formatted.contains("huge.json"), "{formatted}");
    }

    #[test]
    fn attachments_that_exactly_fill_the_limit_are_kept() {
        let attachments = vec![("full.json".to_string(), vec![b'x'; ATTACHMENT_LIMIT])];

        let (kept, skipped) = select_attachments(&attachments);

        assert_eq!(kept.len(), 1);
        assert!(skipped.is_empty());
    }

    #[test]
    fn later_attachments_are_skipped_until_they_fit_again() {
        let attachments = vec![
            ("first.json".to_string(), vec![0; 6 * 1024 * 1024]),
            ("second.json".to_string(), vec![0; 5 * 1024 * 1024]),
            ("small.json".to_string(), vec![0; 1024]),
        ];

        let (kept, skipped) = select_attachments(&attachments);

        let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["first.json", "small.json"]);
        assert_eq!(skipped, vec!["second.json"]);
    }

    #[test]
    fn the_body_lists_every_skipped_attachment() {
        let text = body_with_attachment_note("body", &["a.json", "b.json"]);

        assert!(text.starts_with("body\n\n"), "{text}");
        assert!(text.contains("a.json"), "{text}");
        assert!(text.contains("b.json"), "{text}");
    }

    #[derive(Default)]
    struct RecordingTransport {
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl Transport for RecordingTransport {
        type Ok = ();
        type Error = SmtpError;

        fn send_raw(
            &self,
            _envelope: &lettre::address::Envelope,
            email: &[u8],
        ) -> Result<Self::Ok, Self::Error> {
            self.sent.borrow_mut().push(email.to_vec());
            Ok(())
        }
    }

    #[test]
    fn send_hands_the_formatted_message_to_the_transport() {
        let settings = settings("scan@example.com", Some("scan@example.com"));
        let message = message(&settings, "subject", "body", &[]).unwrap();
        let transport = RecordingTransport::default();

        deliver(&transport, &message, &settings).unwrap();

        let sent = transport.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], message.formatted());
        assert!(String::from_utf8_lossy(&sent[0]).contains("Subject: subject"));
    }

    #[test]
    fn transport_builds_for_every_tls_mode() {
        for (tls, port) in [
            (Tls::Implicit, 465),
            (Tls::Starttls, 587),
            (Tls::None, 1025),
        ] {
            let mut settings = settings("scan@example.com", Some("scan@example.com"));
            settings.tls = tls;
            settings.port = port;

            assert!(transport(&settings).is_ok(), "{tls:?}");
        }
    }
}
