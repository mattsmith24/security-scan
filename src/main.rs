use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use security_scan::config::Config;
use security_scan::data_sources::{self, Report};
use security_scan::email::{self, ProjectSummary};
use security_scan::progress;
use security_scan::scanner::{self, ScanError, cve_bin_tool, cve_bin_tool::Cve};
use security_scan::triage;

const USAGE: &str = "\
usage: security-scan [config.toml] [output-dir] [--no-email]
       security-scan [config.toml] [output-dir] [--email-dry-run]
       security-scan triage <project> [--config config.toml] [--output output-dir]";

/// How a scan run should handle email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmailMode {
    /// Send an alert when the scan finishes.
    Send,

    /// Suppress the alert for this run.
    NoEmail,

    /// Print the message instead of sending it.
    DryRun,
}

/// The arguments for a scan run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScanMode {
    config: PathBuf,
    output: Option<PathBuf>,
    email: EmailMode,
}

/// What the command line asks the scanner to do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Scan(ScanMode),
    Triage,
    Help,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    match parse_mode(&args) {
        Ok(Mode::Scan(scan)) => scan_command(scan),
        Ok(Mode::Triage) => triage_command(&args[1..]),
        Ok(Mode::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Work out what the arguments ask for.
///
/// `triage` is a separate subcommand with its own parser, so it is recognised
/// before the scan flags are read. That keeps email flags out of its reach.
fn parse_mode(args: &[OsString]) -> Result<Mode, String> {
    if args.first().and_then(|arg| arg.to_str()) == Some("triage") {
        return Ok(Mode::Triage);
    }

    let mut config = None;
    let mut output = None;
    let mut no_email = false;
    let mut dry_run = false;

    for arg in args {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(Mode::Help),
            Some("--no-email") => no_email = true,
            Some("--email-dry-run") => dry_run = true,
            Some(flag) if flag.starts_with('-') => {
                return Err(format!("unknown option {flag}"));
            }
            _ if config.is_none() => config = Some(PathBuf::from(arg)),
            _ if output.is_none() => output = Some(PathBuf::from(arg)),
            _ => {
                return Err(format!("unexpected argument {}", arg.to_string_lossy()));
            }
        }
    }

    if no_email && dry_run {
        return Err("--no-email and --email-dry-run cannot be used together".to_string());
    }

    let email = match (no_email, dry_run) {
        (true, _) => EmailMode::NoEmail,
        (_, true) => EmailMode::DryRun,
        _ => EmailMode::Send,
    };

    Ok(Mode::Scan(ScanMode {
        config: config.unwrap_or_else(|| PathBuf::from("config.toml")),
        output,
        email,
    }))
}

/// Run the scans, then report on the vulnerability data they used.
fn scan_command(mode: ScanMode) -> ExitCode {
    let config_path = mode.config;
    let output_override = mode.output;

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_config_warnings(&config);
    print_email_warnings(&config);

    let email_settings = if mode.email == EmailMode::NoEmail {
        None
    } else {
        email::Settings::from_config(&config)
    };

    let output_dir = output_override.unwrap_or_else(|| config.output_dir());
    let base_dir = config.base_dir.clone();
    let osv_ecosystems = config.osv_ecosystems();
    let vex_enabled = config.vex_enabled();

    println!("config: {}", config_path.display());
    println!("output: {}", output_dir.display());
    if !osv_ecosystems.is_empty() {
        println!("osv ecosystems: {}", osv_ecosystems.join(", "));
    }
    println!();

    if !data_sources::database(&config.cache_dir()).is_file() {
        eprintln!("note: cve-bin-tool has no vulnerability database yet, so the");
        eprintln!("      first scan will download one. That can take a while.");
        eprintln!();
    }

    let mut failures = 0;
    let mut failure_messages = Vec::new();
    let mut projects = Vec::new();

    for directory in &config.directories {
        progress::heading(format!(
            "scanning {} ({})",
            directory.path.display(),
            directory.kind
        ));

        match scanner::scan(
            directory,
            &output_dir,
            &base_dir,
            &osv_ecosystems,
            vex_enabled,
        ) {
            Ok(report) => {
                println!(
                    "{} ({}): {} packages, {} dev-only",
                    report.directory.display(),
                    report.kind,
                    report.components,
                    report.dev_components,
                );
                for (license, count) in &report.licenses {
                    println!("    {license}: {count}");
                }
                for output in &report.outputs {
                    println!("    -> {}", output.display());
                }
                print_cves(&report.cves);

                projects.push(ProjectSummary {
                    name: report.name,
                    kind: report.kind,
                    components: report.components,
                    dev_components: report.dev_components,
                    cves: report.cves,
                    report: report.report,
                });
            }
            Err(error) => {
                let message = format!("{}: {error}", directory.path.display());
                eprintln!("{message}");

                // The OSV filter is global, so an SBOM that does not fit it
                // will not be scanned correctly however many directories
                // remain: stop rather than generate more SBOMs that cannot
                // be scanned.
                if matches!(error, ScanError::FilteredEcosystems { .. }) {
                    return ExitCode::FAILURE;
                }

                failures += 1;
                failure_messages.push(message);
            }
        }
    }

    // The vulnerability data cve-bin-tool scans against is shared by every
    // directory, so it is checked once, after the scans that may have
    // updated it. Data that failed to download leaves the findings
    // incomplete without anything else saying so.
    let report = data_sources::check(&config.cache_dir(), config.stale_after());
    print_data_sources(&report);
    write_data_sources(&report, &output_dir);

    if let Some(settings) = &email_settings {
        send_email(
            settings,
            &projects,
            &failure_messages,
            &report,
            &output_dir,
            mode.email,
        );
    }

    if failures > 0 {
        eprintln!(
            "\n{failures} of {} directories failed",
            config.directories.len()
        );
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Print config problems that do not stop the scan.
fn print_config_warnings(config: &Config) {
    for warning in config.warnings() {
        eprintln!("{warning}");
    }
}

/// Warn about email settings that look wrong, before the scan starts.
///
/// Only `scan_command` calls this: `triage` never sends email, so its
/// settings do not matter there.
fn print_email_warnings(config: &Config) {
    let Some(settings) = email::Settings::from_config(config) else {
        return;
    };

    for warning in email::warnings(&settings) {
        eprintln!("{warning}");
    }
}

/// Build and send the alert for a finished scan.
///
/// A dry run prints the formatted message instead of connecting. Any failure
/// is a warning: the scan's exit code still reflects the scan, not delivery.
fn send_email(
    settings: &email::Settings,
    projects: &[ProjectSummary],
    failures: &[String],
    sources: &Report,
    output_dir: &Path,
    mode: EmailMode,
) {
    let subject = email::subject(&settings.prefix, projects);
    let body = email::body(projects, failures, sources);
    let attachments = attachments(projects, output_dir);

    let message = match email::message(settings, &subject, &body, &attachments) {
        Ok(message) => message,
        Err(error) => {
            eprintln!("warning: {error}");
            return;
        }
    };

    if mode == EmailMode::DryRun {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout);
        let _ = stdout.write_all(&message.formatted());
        let _ = stdout.flush();
        return;
    }

    match email::send(settings, &message) {
        Ok(()) => {
            let recipients: Vec<String> = settings.to.iter().map(ToString::to_string).collect();
            println!("\nemail: sent to {}", recipients.join(", "));
        }
        Err(error) => eprintln!("warning: {error}"),
    }
}

/// Read the files an alert attaches: each project's CVE report and the
/// data-source report. Files that cannot be read are named as warnings and
/// left out.
fn attachments(projects: &[ProjectSummary], output_dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut attachments = Vec::new();

    for project in projects {
        match std::fs::read(&project.report) {
            Ok(bytes) => attachments.push((
                format!("{}-cve-report.json", attachment_name(&project.name)),
                bytes,
            )),
            Err(error) => eprintln!(
                "warning: failed to attach {}: {error}",
                project.report.display()
            ),
        }
    }

    let path = output_dir.join("data-sources.json");
    match std::fs::read(&path) {
        Ok(bytes) => attachments.push(("data-sources.json".to_string(), bytes)),
        Err(error) => eprintln!("warning: failed to attach {}: {error}", path.display()),
    }

    attachments
}

/// Make a project name safe to use in an attachment filename.
fn attachment_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();

    if cleaned.is_empty() {
        "project".to_string()
    } else {
        cleaned
    }
}

/// Triage the findings in one project's VEX.
fn triage_command(args: &[OsString]) -> ExitCode {
    let mut args = args.iter();

    let mut project = None;
    let mut config_path = PathBuf::from("config.toml");
    let mut output_override = None;

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config") => match args.next() {
                Some(path) => config_path = PathBuf::from(path),
                None => {
                    eprintln!("error: --config needs a path\n{USAGE}");
                    return ExitCode::FAILURE;
                }
            },
            Some("--output") => match args.next() {
                Some(path) => output_override = Some(PathBuf::from(path)),
                None => {
                    eprintln!("error: --output needs a path\n{USAGE}");
                    return ExitCode::FAILURE;
                }
            },
            Some("-h" | "--help") => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            Some(flag) if flag.starts_with('-') => {
                eprintln!("error: unknown option {flag}\n{USAGE}");
                return ExitCode::FAILURE;
            }
            _ if project.is_none() => project = Some(arg.to_string_lossy().into_owned()),
            _ => {
                eprintln!(
                    "error: unexpected argument {}\n{USAGE}",
                    arg.to_string_lossy()
                );
                return ExitCode::FAILURE;
            }
        }
    }

    let Some(project) = project else {
        eprintln!("error: triage needs a project name\n{USAGE}");
        return ExitCode::FAILURE;
    };

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let output_dir = output_override.unwrap_or_else(|| config.output_dir());
    print_config_warnings(&config);
    let vex = match triage::find_vex(&output_dir, &project) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("vex: {}", vex.display());
    println!();

    match triage::triage(&vex) {
        Ok(summary) => {
            print_triage(&summary);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Print what a triage session decided.
fn print_triage(summary: &triage::Summary) {
    if summary.counts.is_empty() {
        println!("no findings");
    } else {
        let counts: Vec<String> = summary
            .counts
            .iter()
            .map(|(state, count)| format!("{count} {}", triage::describe_state(state)))
            .collect();
        let noun = if summary.total == 1 {
            "finding"
        } else {
            "findings"
        };
        println!("{} {noun}: {}", summary.total, counts.join(", "));
    }

    if summary.changed {
        println!("decisions written to the VEX");
    } else {
        println!("no decisions changed");
    }
}

/// Print what the scanner knows about cve-bin-tool's data sources.
fn print_data_sources(report: &Report) {
    let updated = match report.updated {
        Some(at) => data_sources::describe_age(at, report.checked),
        None => "never".to_string(),
    };

    println!();
    println!("vulnerability data (database updated {updated}):");

    if let Some(error) = &report.error {
        println!("    {error}");
    }

    for line in report.lines() {
        println!("{line}");
    }

    let problems = report.problems();
    if problems.is_empty() {
        return;
    }

    let names: Vec<&str> = problems.iter().map(|source| source.name).collect();
    eprintln!(
        "warning: {} of {} data sources have no data or stale data: {}",
        problems.len(),
        report.sources.len(),
        names.join(", ")
    );
}

/// Write the data source report to the output directory, so that whatever
/// runs the scanner can read it.
fn write_data_sources(report: &Report, output_dir: &Path) {
    let path = output_dir.join("data-sources.json");

    if let Err(error) = std::fs::create_dir_all(output_dir) {
        eprintln!(
            "warning: failed to create {}: {error}",
            output_dir.display()
        );
        return;
    }

    if let Err(error) = std::fs::write(&path, data_sources::to_json(report)) {
        eprintln!("warning: failed to write {}: {error}", path.display());
    }
}

/// Print the vulnerabilities a scan found.
///
/// Findings the VEX has dismissed are left out of the summary, but remain in
/// the report, which records the state of every finding.
fn print_cves(cves: &[Cve]) {
    let filtered = cves.iter().filter(|cve| cve.is_triaged()).count();
    let active: Vec<Cve> = cves
        .iter()
        .filter(|cve| !cve.is_triaged())
        .cloned()
        .collect();

    if active.is_empty() {
        match filtered {
            0 => println!("    no known vulnerabilities"),
            count => println!("    no known vulnerabilities ({count} filtered by the VEX)"),
        }
        return;
    }

    let counts = cve_bin_tool::by_severity(&active);
    let summary: Vec<String> = counts
        .iter()
        .map(|(severity, count)| format!("{count} {severity}"))
        .collect();

    println!(
        "    {} vulnerabilities ({})",
        active.len(),
        summary.join(", ")
    );

    // The most severe findings are worth showing; the rest are in the
    // report.
    let shown = 10.min(active.len());
    for cve in &active[..shown] {
        let dev = if cve.dev_only { " (dev only)" } else { "" };
        println!(
            "        {} {} {}@{} ({}){dev}",
            cve.severity, cve.number, cve.product, cve.version, cve.score
        );
    }

    if shown < active.len() {
        println!("        ... and {} more", active.len() - shown);
    }

    if filtered > 0 {
        println!("    {filtered} filtered by the VEX");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn scan(config: &str, output: Option<&str>, email: EmailMode) -> Mode {
        Mode::Scan(ScanMode {
            config: PathBuf::from(config),
            output: output.map(PathBuf::from),
            email,
        })
    }

    #[test]
    fn the_default_run_uses_config_toml_and_sends_email() {
        assert_eq!(
            parse_mode(&[]).unwrap(),
            scan("config.toml", None, EmailMode::Send)
        );
    }

    #[test]
    fn a_config_and_output_directory_are_both_positional() {
        assert_eq!(
            parse_mode(&args(&["scan.toml", "out"])).unwrap(),
            scan("scan.toml", Some("out"), EmailMode::Send)
        );
    }

    #[test]
    fn no_email_suppresses_the_alert() {
        assert_eq!(
            parse_mode(&args(&["--no-email"])).unwrap(),
            scan("config.toml", None, EmailMode::NoEmail)
        );
    }

    #[test]
    fn email_dry_run_prints_instead_of_sending() {
        assert_eq!(
            parse_mode(&args(&["config.toml", "--email-dry-run"])).unwrap(),
            scan("config.toml", None, EmailMode::DryRun)
        );
    }

    #[test]
    fn the_two_email_flags_conflict() {
        assert!(parse_mode(&args(&["--no-email", "--email-dry-run"])).is_err());
    }

    #[test]
    fn triage_is_a_separate_mode_and_ignores_email_flags() {
        assert_eq!(
            parse_mode(&args(&["triage", "goalkeepr", "--email-dry-run"])).unwrap(),
            Mode::Triage
        );
    }

    #[test]
    fn help_is_recognised() {
        assert_eq!(parse_mode(&args(&["--help"])).unwrap(), Mode::Help);
        assert_eq!(parse_mode(&args(&["-h"])).unwrap(), Mode::Help);
    }

    #[test]
    fn unknown_options_are_rejected() {
        assert!(parse_mode(&args(&["--email"])).is_err());
    }

    #[test]
    fn a_third_positional_argument_is_rejected() {
        assert!(parse_mode(&args(&["a.toml", "out", "extra"])).is_err());
    }

    #[test]
    fn attachment_names_are_safe_for_filenames() {
        assert_eq!(attachment_name("my project"), "my-project");
        assert_eq!(attachment_name("a/b:c"), "a-b-c");
        assert_eq!(attachment_name(""), "project");
    }
}
