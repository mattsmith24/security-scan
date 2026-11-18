use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

/// Top-level configuration, read from `config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// The directories to scan. Each entry names a path and the kind of
    /// project it holds.
    #[serde(default)]
    pub directories: Vec<Directory>,

    /// Any other top-level settings, kept as raw TOML values so that global
    /// settings can be added without changing this code.
    #[serde(flatten)]
    pub global: BTreeMap<String, toml::Value>,

    /// The directory the config file lives in. Relative paths in the config
    /// are resolved against it.
    #[serde(skip)]
    pub base_dir: PathBuf,
}

/// A single entry of the `directories` list.
#[derive(Debug, Clone, Deserialize)]
pub struct Directory {
    /// Path to the directory to scan. Relative paths are resolved against the
    /// directory containing the config file.
    pub path: PathBuf,

    /// The kind of project in this directory, e.g. `rust` or `python`. This
    /// is the project type cdxgen is asked to scan for.
    #[serde(rename = "type")]
    pub kind: String,

    /// The name to record for the project in its SBOM. Defaults to the name
    /// of the directory being scanned.
    #[serde(default)]
    pub name: Option<String>,

    /// The vendor of the project, e.g. the name of the person or company
    /// that publishes it. cve-bin-tool is told about it so that the
    /// vulnerabilities it reports name the right supplier.
    #[serde(default)]
    pub vendor: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("config file {path} has no parent directory to resolve paths against")]
    NoParent { path: PathBuf },
}

impl Config {
    /// Read and parse the config file at `path`.
    ///
    /// Directory paths are resolved relative to the config file's own
    /// directory, so a config can be moved around without breaking. The
    /// config's own path is made absolute first, so that those paths do not
    /// depend on the directory the scanner happens to be run from.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path =
            std::path::absolute(path.as_ref()).unwrap_or_else(|_| path.as_ref().to_path_buf());
        let contents = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;

        let mut config: Config =
            toml::from_str(&contents).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.base_dir = base.to_path_buf();
        for directory in &mut config.directories {
            directory.path = resolve_path(&directory.path, base);
        }

        Ok(config)
    }

    /// Where scanned SBOMs are written.
    ///
    /// Controlled by the `output_dir` global setting, defaulting to
    /// `sbom-out` alongside the config file.
    pub fn output_dir(&self) -> PathBuf {
        let raw = self
            .global
            .get("output_dir")
            .and_then(|value| value.as_str())
            .unwrap_or("sbom-out");
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            path
        } else {
            self.base_dir.join(path)
        }
    }

    /// Look up a global setting by key.
    pub fn global_setting(&self, key: &str) -> Option<&toml::Value> {
        self.global.get(key)
    }

    /// How old a vulnerability data source's data may be before the scanner
    /// reports it as stale.
    ///
    /// Controlled by the `cve_data_stale_days` global setting, defaulting to
    /// seven days. cve-bin-tool downloads its data daily, so a source that
    /// has not been updated in a week has almost certainly stopped.
    pub fn stale_after(&self) -> Duration {
        let days = self
            .global
            .get("cve_data_stale_days")
            .and_then(|value| value.as_integer())
            .unwrap_or(DEFAULT_STALE_DAYS);

        Duration::from_secs((days.max(0) as u64) * 86_400)
    }

    /// The OSV ecosystems cve-bin-tool should download vulnerability data
    /// for.
    ///
    /// Controlled by the `osv_ecosystems` global setting, either an array of
    /// OSV ecosystem names such as `["npm", "PyPI"]` or a comma-separated
    /// string. An empty list leaves the OSV source unfiltered, which is what
    /// cve-bin-tool does by default.
    ///
    /// The scanner also uses this list to check the ecosystems an SBOM
    /// describes: a package from an ecosystem that the filter leaves out
    /// would be scanned without its OSV advisories, so that is an error
    /// rather than a quietly incomplete report.
    pub fn osv_ecosystems(&self) -> Vec<String> {
        let Some(value) = self.global.get("osv_ecosystems") else {
            return Vec::new();
        };

        let names: Vec<&str> = match value {
            toml::Value::Array(items) => items.iter().filter_map(toml::Value::as_str).collect(),
            toml::Value::String(names) => names.split(',').collect(),
            _ => return Vec::new(),
        };

        let mut ecosystems: Vec<String> = Vec::new();
        for name in names {
            let name = name.trim();
            if !name.is_empty()
                && !ecosystems
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(name))
            {
                ecosystems.push(name.to_string());
            }
        }

        ecosystems
    }

    /// Whether to generate and use a CycloneDX VEX for each project.
    ///
    /// Controlled by the `vex` global setting, defaulting to true. The VEX is
    /// written next to the project's SBOM and CVE report, and every later
    /// scan hands it back to cve-bin-tool so triage decisions are kept.
    pub fn vex_enabled(&self) -> bool {
        self.global
            .get("vex")
            .and_then(|value| value.as_bool())
            .unwrap_or(true)
    }

    /// The directory cve-bin-tool keeps its vulnerability data in.
    ///
    /// Controlled by the `cve_bin_tool_cache_dir` global setting, defaulting
    /// to the directory cve-bin-tool itself would use.
    pub fn cache_dir(&self) -> PathBuf {
        match self
            .global
            .get("cve_bin_tool_cache_dir")
            .and_then(|value| value.as_str())
        {
            Some(path) => resolve_path(Path::new(path), &self.base_dir),
            None => crate::data_sources::cache_dir(),
        }
    }
}

/// How many days a vulnerability data source's data may be old before the
/// scanner reports it as stale.
const DEFAULT_STALE_DAYS: i64 = 7;

/// Resolve `path` against `base`, expanding a leading `~` to the home
/// directory.
fn resolve_path(path: &Path, base: &Path) -> PathBuf {
    let path = expand_home(path);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

/// Expand a leading `~` to the current user's home directory.
fn expand_home(path: &Path) -> PathBuf {
    let Some(rest) = path.strip_prefix("~").ok() else {
        return path.to_path_buf();
    };

    let Ok(home) = std::env::var("HOME") else {
        return path.to_path_buf();
    };

    let mut expanded = PathBuf::from(home);
    if !rest.as_os_str().is_empty() {
        expanded.push(rest);
    }
    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(contents: &str) -> (tempdir::TempDir, PathBuf) {
        let dir = tempdir::TempDir::new();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn parses_directories_with_path_and_type() {
        let (_dir, path) = write_config(
            r#"
[[directories]]
path = "projects/alpha"
type = "rust"

[[directories]]
path = "projects/beta"
type = "python"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(config.directories.len(), 2);
        assert_eq!(config.directories[0].kind, "rust");
        assert_eq!(config.directories[1].kind, "python");
    }

    #[test]
    fn resolves_relative_paths_against_the_config_directory() {
        let (dir, path) = write_config(
            r#"
[[directories]]
path = "projects/alpha"
type = "rust"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(
            config.directories[0].path,
            dir.path().join("projects/alpha")
        );
    }

    #[test]
    fn keeps_global_settings() {
        let (_dir, path) = write_config(
            r#"
scan_interval_hours = 24

[[directories]]
path = "projects/alpha"
type = "rust"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(
            config.global_setting("scan_interval_hours"),
            Some(&toml::Value::Integer(24))
        );
    }

    #[test]
    fn reads_the_osv_ecosystems_to_download() {
        let (_dir, path) = write_config(
            r#"
osv_ecosystems = ["npm", "PyPI"]
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(config.osv_ecosystems(), vec!["npm", "PyPI"]);
    }

    #[test]
    fn accepts_a_comma_separated_osv_ecosystem_list() {
        let (_dir, path) = write_config(r#"osv_ecosystems = "npm, PyPI,Go""#);

        let config = Config::load(&path).unwrap();
        assert_eq!(config.osv_ecosystems(), vec!["npm", "PyPI", "Go"]);
    }

    #[test]
    fn osv_ecosystems_are_unfiltered_by_default() {
        let (_dir, path) = write_config("scan_interval_hours = 24\n");

        let config = Config::load(&path).unwrap();
        assert!(config.osv_ecosystems().is_empty());
    }

    #[test]
    fn ignores_empty_and_duplicate_osv_ecosystems() {
        let (_dir, path) = write_config(r#"osv_ecosystems = ["npm", "", "NPM", "PyPI"]"#);

        let config = Config::load(&path).unwrap();
        assert_eq!(config.osv_ecosystems(), vec!["npm", "PyPI"]);
    }

    #[test]
    fn parses_the_vendor_of_a_directory() {
        let (_dir, path) = write_config(
            r#"
[[directories]]
path = "projects/alpha"
type = "npm"
vendor = "mattsmith24"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(config.directories[0].vendor.as_deref(), Some("mattsmith24"));
    }

    #[test]
    fn the_vendor_is_optional() {
        let (_dir, path) = write_config(
            r#"
[[directories]]
path = "projects/alpha"
type = "npm"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(config.directories[0].vendor, None);
    }

    #[test]
    fn vex_is_enabled_by_default() {
        let (_dir, path) = write_config("scan_interval_hours = 24\n");

        let config = Config::load(&path).unwrap();
        assert!(config.vex_enabled());
    }

    #[test]
    fn vex_can_be_disabled() {
        let (_dir, path) = write_config("vex = false\n");

        let config = Config::load(&path).unwrap();
        assert!(!config.vex_enabled());
    }

    #[test]
    fn missing_directories_is_not_an_error() {
        let (_dir, path) = write_config("scan_interval_hours = 24\n");
        let config = Config::load(&path).unwrap();
        assert!(config.directories.is_empty());
    }

    #[test]
    fn reports_unreadable_config_files() {
        let error = Config::load("/nonexistent/config.toml").unwrap_err();
        assert!(matches!(error, ConfigError::Read { .. }));
    }

    #[test]
    fn reports_invalid_config_files() {
        let (_dir, path) = write_config("this is not toml {{{");
        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::Parse { .. }));
    }

    /// Minimal stand-in for a temp dir, to avoid an extra dependency.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempDir {
            path: PathBuf,
        }

        impl TempDir {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "security-scan-test-{}-{}",
                    std::process::id(),
                    next_id()
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        fn next_id() -> u64 {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        }
    }
}
