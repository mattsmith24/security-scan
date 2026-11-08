//! Scanning of the directories listed in the config file.

pub mod npm;

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::Directory;

/// A scan that completed, and what it produced.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// The directory that was scanned.
    pub directory: PathBuf,
    /// The kind of project it was recognised as.
    pub kind: String,
    /// The SBOM files written.
    pub outputs: Vec<PathBuf>,
    /// How many packages the SBOM describes.
    pub components: usize,
    /// How many of those are dev-only dependencies.
    pub dev_components: usize,
    /// Declared license -> number of packages under it, most common first.
    pub licenses: Vec<(String, usize)>,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("no {file} found in {dir}")]
    MissingFile { dir: PathBuf, file: String },

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

    #[error("unsupported directory type {kind:?}")]
    UnsupportedType { kind: String },
}

/// Scan one configured directory, writing its SBOM into `output_dir`.
pub fn scan(directory: &Directory, output_dir: &Path) -> Result<ScanReport, ScanError> {
    match directory.kind.as_str() {
        "npm" => npm::scan(directory, output_dir),
        other => Err(ScanError::UnsupportedType {
            kind: other.to_string(),
        }),
    }
}

/// Build the directory that a scan's output goes into: `<output>/<parent>/<name>`.
///
/// The parent and name of the source directory are used so that two projects
/// with the same basename in different places do not collide.
fn output_path(output_dir: &Path, source: &Path) -> PathBuf {
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
}
