use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use lettre::address::AddressError;
use lettre::message::Mailbox;
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

    /// The absolute path of the config file that was loaded.
    #[serde(skip)]
    pub path: PathBuf,

    /// Parsed and validated email settings.
    #[serde(skip)]
    email: EmailSettings,
}

/// How SMTP should secure its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    /// Upgrade a plain connection with STARTTLS (usually port 587).
    Starttls,

    /// Wrap the connection in TLS from the start (usually port 465).
    Implicit,

    /// Send no TLS. Only for a local relay such as Mailpit.
    None,
}

/// Where and how to reach the SMTP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub tls: Tls,

    /// The user to authenticate as. Absent means connect without auth.
    pub user: Option<String>,
}

/// Email settings after parsing, validation and defaults.
#[derive(Debug, Clone, Default)]
struct EmailSettings {
    enabled: bool,
    from: Option<Mailbox>,
    to: Vec<Mailbox>,
    smtp: Option<SmtpSettings>,
    password: Option<String>,
    warnings: Vec<String>,
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

    #[error("config setting `{key}` must be a string or an array of strings")]
    NotAnAddressList { key: &'static str },

    #[error("config setting `{key}` must be a string")]
    NotAString { key: &'static str },

    #[error("config setting `{key}` must be true or false")]
    NotABool { key: &'static str },

    #[error("invalid email address in `{key}`: {value:?}")]
    InvalidAddress {
        key: &'static str,
        value: String,
        #[source]
        source: AddressError,
    },

    #[error("`smtp_port` must be a whole number between 1 and 65535, not {value}")]
    InvalidSmtpPort { value: String },

    #[error("`smtp_tls` must be \"starttls\", \"implicit\" or \"none\", not {value:?}")]
    InvalidSmtpTls { value: String },

    #[error("`smtp_user` and `smtp_password` must be set together")]
    IncompleteSmtpCredentials,

    #[error(
        "`email_to` and `smtp_host` are set but `email_from` is missing; set the \
         address alerts should come from"
    )]
    MissingEmailFrom,
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
        config.path = path.clone();
        for directory in &mut config.directories {
            directory.path = resolve_path(&directory.path, base);
        }

        config.email = EmailSettings::parse(&config.global, &config.path)?;

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

    /// Whether scans should email their results when they finish.
    ///
    /// Email needs the `email` master switch (on by default), at least one
    /// recipient in `email_to`, an SMTP server in `smtp_host`, and an
    /// `email_from` address. Missing any of them leaves email off, so a
    /// config without email settings keeps working unchanged.
    pub fn email_enabled(&self) -> bool {
        self.email.enabled
    }

    /// The addresses an email about a scan is sent to.
    pub fn email_recipients(&self) -> &[Mailbox] {
        &self.email.to
    }

    /// The address email alerts are sent from, with its optional display
    /// name.
    pub fn email_from(&self) -> Option<&Mailbox> {
        self.email.from.as_ref()
    }

    /// The SMTP server to send through. `None` when `smtp_host` is unset or
    /// empty.
    pub fn smtp_settings(&self) -> Option<&SmtpSettings> {
        self.email.smtp.as_ref()
    }

    /// The password to authenticate to the SMTP server with.
    pub fn smtp_password(&self) -> Option<&str> {
        self.email.password.as_deref()
    }

    /// Problems with the config file that do not stop the scan, such as a
    /// password readable by other users.
    pub fn warnings(&self) -> &[String] {
        &self.email.warnings
    }
}

impl EmailSettings {
    /// Parse and validate the email settings from the config's global keys.
    fn parse(global: &BTreeMap<String, toml::Value>, path: &Path) -> Result<Self, ConfigError> {
        let to = match global.get("email_to") {
            Some(value) => parse_addresses("email_to", value)?,
            None => Vec::new(),
        };

        let from = match global.get("email_from") {
            Some(value) => {
                let raw = value
                    .as_str()
                    .ok_or(ConfigError::NotAString { key: "email_from" })?;
                Some(parse_address("email_from", raw)?)
            }
            None => None,
        };

        let user = string_setting(global, "smtp_user")?
            .map(str::trim)
            .filter(|user| !user.is_empty())
            .map(str::to_string);
        let password = string_setting(global, "smtp_password")?
            .map(str::trim)
            .filter(|password| !password.is_empty())
            .map(str::to_string);

        // Gmail and most relays reject an empty password or empty user, so a
        // half-filled pair is a mistake rather than a request for no auth.
        if user.is_some() != password.is_some() {
            return Err(ConfigError::IncompleteSmtpCredentials);
        }

        let smtp = match string_setting(global, "smtp_host")?
            .map(str::trim)
            .filter(|host| !host.is_empty())
        {
            Some(host) => {
                let port = parse_port(global)?;
                let tls = parse_tls(global, port)?;
                Some(SmtpSettings {
                    host: host.to_string(),
                    port,
                    tls,
                    user,
                })
            }
            None => None,
        };

        let switched_on = match global.get("email") {
            Some(value) => value
                .as_bool()
                .ok_or(ConfigError::NotABool { key: "email" })?,
            None => true,
        };

        let configured = !to.is_empty() && smtp.is_some();
        if switched_on && configured && from.is_none() {
            return Err(ConfigError::MissingEmailFrom);
        }

        let mut warnings = Vec::new();
        if password.is_some()
            && let Some(warning) = permission_warning(path)
        {
            warnings.push(warning);
        }

        Ok(Self {
            enabled: switched_on && configured && from.is_some(),
            from,
            to,
            smtp,
            password,
            warnings,
        })
    }
}

/// Read a global setting that must be a string, if it is present.
fn string_setting<'a>(
    global: &'a BTreeMap<String, toml::Value>,
    key: &'static str,
) -> Result<Option<&'a str>, ConfigError> {
    match global.get(key) {
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or(ConfigError::NotAString { key }),
        None => Ok(None),
    }
}

/// Parse `email_to`, which may be an array of addresses or a comma-separated
/// string. Empty entries are ignored so that a trailing comma is harmless.
fn parse_addresses(key: &'static str, value: &toml::Value) -> Result<Vec<Mailbox>, ConfigError> {
    let entries: Vec<&str> = match value {
        toml::Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().ok_or(ConfigError::NotAString { key }))
            .collect::<Result<_, _>>()?,
        toml::Value::String(text) => text.split(',').collect(),
        _ => return Err(ConfigError::NotAnAddressList { key }),
    };

    entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| parse_address(key, entry))
        .collect()
}

/// Parse one address, which may carry a display name.
fn parse_address(key: &'static str, raw: &str) -> Result<Mailbox, ConfigError> {
    raw.trim()
        .parse::<Mailbox>()
        .map_err(|source| ConfigError::InvalidAddress {
            key,
            value: raw.trim().to_string(),
            source,
        })
}

/// The SMTP port, defaulting to 587 (the submission port).
fn parse_port(global: &BTreeMap<String, toml::Value>) -> Result<u16, ConfigError> {
    let Some(value) = global.get("smtp_port") else {
        return Ok(DEFAULT_SMTP_PORT);
    };

    value
        .as_integer()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::InvalidSmtpPort {
            value: value.to_string(),
        })
}

/// The TLS mode, inferred from the port unless `smtp_tls` says otherwise.
fn parse_tls(global: &BTreeMap<String, toml::Value>, port: u16) -> Result<Tls, ConfigError> {
    let Some(value) = global.get("smtp_tls") else {
        return Ok(if port == 465 {
            Tls::Implicit
        } else {
            Tls::Starttls
        });
    };

    let text = value.as_str().ok_or_else(|| ConfigError::InvalidSmtpTls {
        value: value.to_string(),
    })?;

    match text.trim().to_ascii_lowercase().as_str() {
        "starttls" => Ok(Tls::Starttls),
        "implicit" => Ok(Tls::Implicit),
        "none" => Ok(Tls::None),
        _ => Err(ConfigError::InvalidSmtpTls {
            value: text.to_string(),
        }),
    }
}

/// Warn when the config file holds a password and other users can read it.
#[cfg(unix)]
fn permission_warning(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then(|| {
        format!(
            "warning: {} holds smtp_password but is readable by group or others; run `chmod 600 {}`",
            path.display(),
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn permission_warning(_path: &Path) -> Option<String> {
    None
}

/// How many days a vulnerability data source's data may be old before the
/// scanner reports it as stale.
const DEFAULT_STALE_DAYS: i64 = 7;

/// The submission port to send email through when `smtp_port` is unset.
const DEFAULT_SMTP_PORT: u16 = 587;

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

    /// A config with every email setting filled in.
    const EMAIL_CONFIG: &str = r#"
email_to = ["scan@example.com", "Other <other@example.com>"]
email_from = "Security Scan <scan@example.com>"
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_user = "scan@example.com"
smtp_password = "app password"
"#;

    fn email_config() -> Config {
        let (_dir, path) = write_config(EMAIL_CONFIG);
        Config::load(&path).unwrap()
    }

    #[test]
    fn email_is_disabled_by_default() {
        let (_dir, path) = write_config("scan_interval_hours = 24\n");
        let config = Config::load(&path).unwrap();

        assert!(!config.email_enabled());
        assert!(config.email_recipients().is_empty());
        assert!(config.email_from().is_none());
        assert!(config.smtp_settings().is_none());
        assert!(config.smtp_password().is_none());
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn email_is_enabled_when_fully_configured() {
        let config = email_config();

        assert!(config.email_enabled());
        assert_eq!(config.email_recipients().len(), 2);
        assert_eq!(
            config.email_from().unwrap().to_string(),
            "Security Scan <scan@example.com>"
        );
        assert_eq!(config.smtp_password(), Some("app password"));
    }

    #[test]
    fn reads_recipients_from_an_array() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com", "B <b@example.com>"]
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        let recipients: Vec<String> = config
            .email_recipients()
            .iter()
            .map(Mailbox::to_string)
            .collect();
        assert_eq!(recipients, vec!["a@example.com", "B <b@example.com>"]);
    }

    #[test]
    fn reads_recipients_from_a_comma_separated_string() {
        let (_dir, path) = write_config(
            r#"
email_to = "a@example.com, b@example.com"
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        let recipients: Vec<String> = config
            .email_recipients()
            .iter()
            .map(Mailbox::to_string)
            .collect();
        assert_eq!(recipients, vec!["a@example.com", "b@example.com"]);
    }

    #[test]
    fn ignores_empty_recipients() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com", "", " "]
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(config.email_recipients().len(), 1);
    }

    #[test]
    fn accepts_an_email_from_without_a_display_name() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        let from = config.email_from().unwrap();
        assert_eq!(from.name, None);
        assert_eq!(from.email.to_string(), "scan@example.com");
    }

    #[test]
    fn reports_a_malformed_email_from() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "not an address"
smtp_host = "smtp.example.com"
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::InvalidAddress {
                key: "email_from",
                ..
            }
        ));
    }

    #[test]
    fn reports_a_malformed_recipient() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com", "nope"]
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::InvalidAddress {
                key: "email_to",
                ..
            }
        ));
    }

    #[test]
    fn reports_an_email_to_of_the_wrong_type() {
        let (_dir, path) = write_config("email_to = 42\n");

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::NotAnAddressList { key: "email_to" }
        ));
    }

    #[test]
    fn infers_implicit_tls_for_port_465() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
smtp_port = 465
"#,
        );

        let config = Config::load(&path).unwrap();
        let smtp = config.smtp_settings().unwrap();
        assert_eq!(smtp.port, 465);
        assert_eq!(smtp.tls, Tls::Implicit);
    }

    #[test]
    fn infers_starttls_for_other_ports() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        let smtp = config.smtp_settings().unwrap();
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.tls, Tls::Starttls);
    }

    #[test]
    fn accepts_an_explicit_tls_mode() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
smtp_host = "127.0.0.1"
smtp_port = 1025
smtp_tls = "none"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert_eq!(config.smtp_settings().unwrap().tls, Tls::None);
    }

    #[test]
    fn reports_an_unknown_tls_mode() {
        let (_dir, path) = write_config(
            r#"
smtp_host = "smtp.example.com"
smtp_tls = "ssl-ish"
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::InvalidSmtpTls { .. }));
    }

    #[test]
    fn reports_an_invalid_smtp_port() {
        let (_dir, path) = write_config(
            r#"
smtp_host = "smtp.example.com"
smtp_port = 70000
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::InvalidSmtpPort { .. }));
    }

    #[test]
    fn reports_a_user_without_a_password() {
        let (_dir, path) = write_config(
            r#"
smtp_host = "smtp.example.com"
smtp_user = "scan@example.com"
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::IncompleteSmtpCredentials));
    }

    #[test]
    fn reports_a_password_without_a_user() {
        let (_dir, path) = write_config(
            r#"
smtp_host = "smtp.example.com"
smtp_password = "app password"
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::IncompleteSmtpCredentials));
    }

    #[test]
    fn allows_no_credentials_for_a_local_relay() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
smtp_host = "127.0.0.1"
smtp_port = 1025
smtp_tls = "none"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert!(config.email_enabled());
        let smtp = config.smtp_settings().unwrap();
        assert_eq!(smtp.user, None);
        assert_eq!(config.smtp_password(), None);
    }

    #[test]
    fn the_email_switch_turns_alerts_off() {
        let (_dir, path) = write_config(&format!("email = false\n{EMAIL_CONFIG}"));

        let config = Config::load(&path).unwrap();
        assert!(!config.email_enabled());
        // The addresses are still parsed, so a later switch back on needs no
        // other edit.
        assert_eq!(config.email_recipients().len(), 2);
    }

    #[test]
    fn email_needs_recipients() {
        let (_dir, path) = write_config(
            r#"
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert!(!config.email_enabled());
    }

    #[test]
    fn email_needs_an_smtp_host() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert!(!config.email_enabled());
    }

    #[test]
    fn reports_a_missing_email_from_when_alerts_are_configured() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
smtp_host = "smtp.example.com"
"#,
        );

        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::MissingEmailFrom));
    }

    #[cfg(unix)]
    #[test]
    fn warns_when_the_config_with_a_password_is_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = write_config(EMAIL_CONFIG);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let config = Config::load(&path).unwrap();
        let warnings = config.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("chmod 600"), "{warnings:?}");
    }

    #[cfg(unix)]
    #[test]
    fn does_not_warn_when_the_config_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, path) = write_config(EMAIL_CONFIG);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let config = Config::load(&path).unwrap();
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn does_not_warn_about_permissions_without_a_password() {
        let (_dir, path) = write_config(
            r#"
email_to = ["a@example.com"]
email_from = "scan@example.com"
smtp_host = "smtp.example.com"
"#,
        );

        let config = Config::load(&path).unwrap();
        assert!(config.warnings().is_empty());
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
