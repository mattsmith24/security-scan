use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use security_scan::config::Config;
use security_scan::data_sources::{self, Report};
use security_scan::email;
use security_scan::progress;
use security_scan::scanner::{self, ScanError, cve_bin_tool, cve_bin_tool::Cve};
use security_scan::triage;

const USAGE: &str = "\
usage: security-scan [config.toml] [output-dir]
       security-scan triage <project> [--config config.toml] [--output output-dir]";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    if args.first().and_then(|arg| arg.to_str()) == Some("triage") {
        return triage_command(&args[1..]);
    }

    scan_command(&args)
}

/// Run the scans, then report on the vulnerability data they used.
fn scan_command(args: &[OsString]) -> ExitCode {
    let mut args = args.iter();

    let config_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let output_override = args.next().map(PathBuf::from);

    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_config_warnings(&config);
    print_email_warnings(&config);

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
            }
            Err(error) => {
                eprintln!("{}: {error}", directory.path.display());

                // The OSV filter is global, so an SBOM that does not fit it
                // will not be scanned correctly however many directories
                // remain: stop rather than generate more SBOMs that cannot
                // be scanned.
                if matches!(error, ScanError::FilteredEcosystems { .. }) {
                    return ExitCode::FAILURE;
                }

                failures += 1;
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
