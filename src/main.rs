use std::path::PathBuf;
use std::process::ExitCode;

use security_scan::config::Config;
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

    let mut failures = 0;

    for directory in &config.directories {
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

    if failures > 0 {
        eprintln!(
            "\n{failures} of {} directories failed",
            config.directories.len()
        );
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
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
