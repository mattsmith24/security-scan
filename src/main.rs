use std::path::PathBuf;
use std::process::ExitCode;

use security_scan::config::Config;
use security_scan::scanner;

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

    println!("config: {}", config_path.display());
    println!("output: {}", output_dir.display());
    println!();

    let mut failures = 0;

    for directory in &config.directories {
        match scanner::scan(directory, &output_dir) {
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
