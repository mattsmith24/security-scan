//! Scanning of the directories listed in the config file.

pub mod cdxgen;
pub mod cve_bin_tool;
pub mod identity;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use thiserror::Error;

use crate::config::Directory;
use crate::progress::Step;

use cve_bin_tool::Cve;
use identity::Identity;

/// A scan that completed, and what it produced.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// The directory that was scanned.
    pub directory: PathBuf,
    /// The kind of project it was recognised as.
    pub kind: String,
    /// The files written: the SBOM and the CVE report.
    pub outputs: Vec<PathBuf>,
    /// How many packages the SBOM describes.
    pub components: usize,
    /// How many of those are dev-only dependencies.
    pub dev_components: usize,
    /// Declared license -> number of packages under it, most common first.
    pub licenses: Vec<(String, usize)>,
    /// The vulnerabilities found in the project's packages, most severe
    /// first.
    pub cves: Vec<Cve>,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("no {file} found in {dir}")]
    MissingFile { dir: PathBuf, file: String },

    #[error("{dir} is not a directory")]
    MissingDirectory { dir: PathBuf },

    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse {path}: {reason}")]
    Parse { path: PathBuf, reason: String },

    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to run {program}: {source}")]
    Command {
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{program} failed with {status}: {stderr}")]
    CommandFailed {
        program: String,
        status: String,
        stderr: String,
    },

    #[error("unsupported directory type {kind:?}")]
    UnsupportedType { kind: String },
}

/// Scan one configured directory, writing its SBOM and CVE report into
/// `output_dir`.
///
/// `base_dir` is the directory the scanner itself lives in: cve-bin-tool is
/// run from there, so that it picks up the virtual environment holding it.
pub fn scan(
    directory: &Directory,
    output_dir: &Path,
    base_dir: &Path,
) -> Result<ScanReport, ScanError> {
    if directory.kind.trim().is_empty() {
        return Err(ScanError::UnsupportedType {
            kind: directory.kind.clone(),
        });
    }

    let identity = Identity::of(&directory.path, directory.name.as_deref());

    let step = Step::start("generating SBOM with cdxgen");
    let sbom = cdxgen::scan(directory, output_dir, &identity)?;
    step.finish(format!("SBOM: {} packages", sbom.components));

    let step = Step::start("scanning the SBOM for vulnerabilities with cve-bin-tool");
    let cves = cve_bin_tool::scan(directory, output_dir, &identity, &sbom.path, base_dir)?;
    step.finish(match cves.cves.len() {
        0 => "no known vulnerabilities".to_string(),
        count => format!("{count} vulnerabilities found"),
    });

    Ok(ScanReport {
        directory: directory.path.clone(),
        kind: directory.kind.clone(),
        outputs: vec![sbom.path, cves.report],
        components: sbom.components,
        dev_components: sbom.dev_components,
        licenses: sbom.licenses,
        cves: cves.cves,
    })
}

/// A command that ran, and the end of its error output.
pub(crate) struct Finished {
    pub status: ExitStatus,
    pub stderr: Vec<u8>,
}

/// Run a command, letting its output through as it is produced.
///
/// A step can take minutes: cve-bin-tool may download its vulnerability data,
/// and cdxgen may consult the package registry. Capturing their output until
/// they exit would leave the scanner silent for all of it. The command's
/// stdout goes straight to the scanner's own, and its stderr is copied
/// through while its last few kilobytes are kept for the error message if the
/// command fails.
pub(crate) fn run_streaming(command: &mut Command) -> io::Result<Finished> {
    let mut child = command
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stderr = child.stderr.take().expect("stderr was piped");
    let mut tail = Tail::default();
    let mut buffer = [0u8; 4096];

    {
        let mut output = io::stderr().lock();
        loop {
            let read = match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                // A signal arriving mid-read is not the end of the output.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };

            let chunk = &buffer[..read];
            tail.push(chunk);

            // Failing to write progress must not fail the scan.
            let _ = output.write_all(chunk);
            let _ = output.flush();
        }
    }

    let status = child.wait()?;

    Ok(Finished {
        status,
        stderr: tail.into_bytes(),
    })
}

/// How much of a command's error output to keep for an error message.
const TAIL_BYTES: usize = 8 * 1024;

/// The last part of a command's error output.
#[derive(Default)]
struct Tail {
    bytes: VecDeque<u8>,
}

impl Tail {
    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend(chunk.iter().copied());

        while self.bytes.len() > TAIL_BYTES {
            self.bytes.pop_front();
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        Vec::from(self.bytes)
    }
}

/// Build the directory that a scan's output goes into: `<output>/<parent>/<name>`.
///
/// The parent and name of the source directory are used so that two projects
/// with the same basename in different places do not collide.
pub(crate) fn output_path(output_dir: &Path, source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .map(|n| sanitize(&n.to_string_lossy()))
        .unwrap_or_else(|| "project".to_string());
    let parent = source
        .parent()
        .and_then(|p| p.file_name())
        .map(|p| sanitize(&p.to_string_lossy()))
        .unwrap_or_default();

    if parent.is_empty() {
        output_dir.join(name)
    } else {
        output_dir.join(parent).join(name)
    }
}

/// Replace anything that is not safe in a path component.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_paths_include_parent_and_name() {
        let out = output_path(Path::new("/out"), Path::new("/home/matt/goalkeepr"));
        assert_eq!(out, Path::new("/out/matt/goalkeepr"));
    }

    #[test]
    fn output_paths_do_not_collide_across_parents() {
        let a = output_path(Path::new("/out"), Path::new("/home/matt/goalkeepr"));
        let b = output_path(Path::new("/out"), Path::new("/srv/goalkeepr"));
        assert_ne!(a, b);
    }

    #[test]
    fn unsafe_names_are_sanitized() {
        assert_eq!(sanitize("my project!"), "my-project-");
        assert_eq!(sanitize("ok-name_1.2"), "ok-name_1.2");
    }

    #[test]
    fn streams_a_command_and_keeps_the_end_of_its_errors() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'one\\ntwo\\n' >&2; exit 3"]);

        let finished = run_streaming(&mut command).unwrap();

        assert_eq!(finished.status.code(), Some(3));
        assert_eq!(String::from_utf8_lossy(&finished.stderr), "one\ntwo\n");
    }

    #[test]
    fn keeps_only_the_last_of_a_long_output() {
        let mut tail = Tail::default();
        tail.push(&vec![b'x'; TAIL_BYTES + 10]);
        tail.push(b"end");

        let bytes = tail.into_bytes();
        assert_eq!(bytes.len(), TAIL_BYTES);
        assert!(bytes.ends_with(b"end"));
    }
}
