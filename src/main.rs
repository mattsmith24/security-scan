use std::path::{Path, PathBuf};
use std::process::ExitCode;

use security_scan::config::Config;
use security_scan::data_sources::{self, Report};
use security_scan::progress;
use security_scan::scanner::{self, cve_bin_tool, cve_bin_tool::Cve};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);

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

    let output_dir = output_override.unwrap_or_else(|| config.output_dir());
    let base_dir = config.base_dir.clone();

    println!("config: {}", config_path.display());
    println!("output: {}", output_dir.display());
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

        match scanner::scan(directory, &output_dir, &base_dir) {
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
        eprintln!("warning: failed to create {}: {error}", output_dir.display());
        return;
    }

    if let Err(error) = std::fs::write(&path, data_sources::to_json(report)) {
        eprintln!("warning: failed to write {}: {error}", path.display());
    }
}

/// Print the vulnerabilities a scan found.
fn print_cves(cves: &[Cve]) {
    if cves.is_empty() {
        println!("    no known vulnerabilities");
        return;
    }

    let counts = cve_bin_tool::by_severity(cves);
    let summary: Vec<String> = counts
        .iter()
        .map(|(severity, count)| format!("{count} {severity}"))
        .collect();

    println!(
        "    {} vulnerabilities ({})",
        cves.len(),
        summary.join(", ")
    );

    // The most severe findings are worth showing; the rest are in the
    // report.
    let shown = 10.min(cves.len());
    for cve in &cves[..shown] {
        let dev = if cve.dev_only { " (dev only)" } else { "" };
        println!(
            "        {} {} {}@{} ({}){dev}",
            cve.severity, cve.number, cve.product, cve.version, cve.score
        );
    }

    if shown < cves.len() {
        println!("        ... and {} more", cves.len() - shown);
    }
}
