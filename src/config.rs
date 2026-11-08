use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
}

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
