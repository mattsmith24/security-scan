//! What an SBOM says about the project it describes.
//!
//! The name and version recorded for a project are worked out once per scan
//! and shared by every step that needs to name the project, so that the SBOM
//! and the CVE report agree on which revision was scanned.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// The manifest an npm project is expected to have.
const NPM_MANIFEST: &str = "package.json";

/// What the SBOM says about the project it describes.
pub struct Identity {
    /// The project's name.
    pub name: String,
    /// The project's version: the short hash of its current git commit.
    pub version: String,
    /// When the scanned revision was made, as a Unix timestamp.
    pub created_at: Option<i64>,
}

impl Identity {
    /// Work out the name and version of a project.
    ///
    /// The version is the short hash of the project's current git commit. A
    /// project that is not in git falls back to the version in its npm
    /// manifest, and then to `0.0.0`.
    pub fn of(project: &Path, name: Option<&str>) -> Self {
        let name = name
            .map(str::to_string)
            .unwrap_or_else(|| default_name(project));

        // The hash and the commit time come from one git call, so that they
        // always describe the same commit. A repository under active use can
        // move its HEAD between two calls.
        let commit = git_commit(project);
        let version = commit
            .as_ref()
            .map(|(hash, _)| hash.clone())
            .or_else(|| manifest_version(project))
            .unwrap_or_else(|| "0.0.0".to_string());

        // Without a commit to date the SBOM from, fall back to when the
        // manifest was last changed.
        let created_at = commit
            .and_then(|(_, at)| at)
            .or_else(|| manifest_modified(project));

        Self {
            name,
            version,
            created_at,
        }
    }
}

/// The short hash and commit time of a project's current git commit.
fn git_commit(project: &Path) -> Option<(String, Option<i64>)> {
    let output = git(project, &["show", "-s", "--format=%h %ct", "HEAD"])?;
    let mut parts = output.split_whitespace();

    let hash = parts.next()?.to_string();
    let at = parts.next().and_then(|t| t.parse().ok());

    Some((hash, at))
}

/// The project's directory name, used when the config does not name it.
fn default_name(project: &Path) -> String {
    project
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string())
}

/// The `version` field of the project's npm manifest, if it has one.
fn manifest_version(project: &Path) -> Option<String> {
    let text = std::fs::read_to_string(project.join(NPM_MANIFEST)).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    json.get("version")?.as_str().map(str::to_string)
}

/// When the project's npm manifest was last changed, as a Unix timestamp.
fn manifest_modified(project: &Path) -> Option<i64> {
    let metadata = std::fs::metadata(project.join(NPM_MANIFEST)).ok()?;
    let modified = metadata.modified().ok()?;
    let seconds = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Some(seconds)
}

/// Run a git command in `directory`, returning its trimmed output.
fn git(directory: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_a_project_after_its_directory() {
        let identity = Identity::of(Path::new("/home/matt/goalkeepr"), None);
        assert_eq!(identity.name, "goalkeepr");
    }

    #[test]
    fn prefers_the_configured_name() {
        let identity = Identity::of(Path::new("/home/matt/goalkeepr"), Some("keeper"));
        assert_eq!(identity.name, "keeper");
    }

    #[test]
    fn falls_back_to_a_placeholder_version() {
        // A directory that is not in git and has no manifest.
        let identity = Identity::of(Path::new("/nonexistent/project"), None);
        assert_eq!(identity.version, "0.0.0");
        assert_eq!(identity.created_at, None);
    }
}
