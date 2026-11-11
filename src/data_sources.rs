//! The health of the vulnerability data cve-bin-tool works from.
//!
//! cve-bin-tool downloads vulnerability data from several sources into a
//! local SQLite database, and scans against that database rather than
//! against an advisory service. A source that fails to download leaves the
//! scan quietly incomplete: cve-bin-tool still writes its report and exits
//! successfully, so nothing otherwise tells the user that the findings are
//! missing half their data.
//!
//! This module looks at what is actually in the database and in the cache
//! directory, so that the scanner can say when a source has no data, or has
//! data that is too old to trust.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use crate::dates::{format_rfc3339, parse_timestamp, unix_seconds};

/// The database cve-bin-tool keeps its vulnerability data in.
const DATABASE: &str = "cve.db";

/// The directory cve-bin-tool keeps its cache in, under the user's cache
/// directory.
const CACHE_DIRECTORY: &str = "cve-bin-tool";

/// How deep below the cache directory a source's files are looked for.
const MAX_DEPTH: usize = 4;

/// How a data source is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// The source has data, and it is recent enough to trust.
    Ok,
    /// The source has no data at all.
    Missing,
    /// The source has data, but none of it is recent.
    Stale,
}

impl State {
    /// How the state reads in a report.
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Missing => "missing",
            State::Stale => "stale",
        }
    }
}

/// What the scanner knows about one of cve-bin-tool's data sources.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    /// The source's name, as cve-bin-tool knows it.
    pub name: &'static str,
    /// How many rows the source has in the database.
    pub entries: usize,
    /// The date of the newest record the source has.
    #[serde(serialize_with = "serialize_time")]
    pub newest: Option<i64>,
    /// When the source last downloaded something.
    #[serde(serialize_with = "serialize_time")]
    pub downloaded: Option<i64>,
    /// How the source is doing.
    pub state: State,
}

/// What the check found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The database the data was checked in.
    pub database: PathBuf,
    /// When the database was last written.
    #[serde(serialize_with = "serialize_time")]
    pub updated: Option<i64>,
    /// When the check was made.
    #[serde(serialize_with = "serialize_time_value")]
    pub checked: i64,
    /// How old a source's data may be before it counts as stale, in days.
    pub stale_after_days: u64,
    /// Each source, in the order cve-bin-tool lists them.
    pub sources: Vec<Source>,
    /// Why the check could not be made, if it could not be made.
    pub error: Option<String>,
}

/// Write a time as an RFC 3339 timestamp, or as nothing if there is none.
fn serialize_time<S>(at: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match at {
        Some(at) => serializer.serialize_str(&format_rfc3339(*at)),
        None => serializer.serialize_none(),
    }
}

/// Write a time as an RFC 3339 timestamp.
fn serialize_time_value<S>(at: &i64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format_rfc3339(*at))
}

impl Report {
    /// The sources that have no data, or data that is too old.
    pub fn problems(&self) -> Vec<&Source> {
        self.sources
            .iter()
            .filter(|source| source.state != State::Ok)
            .collect()
    }

    /// A line describing each source, for printing.
    pub fn lines(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(|source| {
                let entries = match source.entries {
                    0 => "no data".to_string(),
                    count => format!("{count} entries"),
                };

                let mut line = format!(
                    "    {:<9} {:<8} {:<15} {}",
                    source.name,
                    source.state.as_str(),
                    entries,
                    source
                        .downloaded
                        .map(|at| format!("downloaded {}", describe_age(at, self.checked)))
                        .unwrap_or_else(|| "never downloaded".to_string()),
                );

                if source.state == State::Stale
                    && let Some(newest) = source.newest
                {
                    line.push_str(&format!(
                        ", newest record {}",
                        describe_age(newest, self.checked)
                    ));
                }

                line
            })
            .collect()
    }
}

/// Check the health of cve-bin-tool's data sources.
///
/// `cache_dir` is the directory cve-bin-tool keeps its cache in, and
/// `stale_after` how old a source's data may be before it counts as stale.
/// A source with no data at all is always reported, whatever the age.
pub fn check(cache_dir: &Path, stale_after: Duration) -> Report {
    let database = cache_dir.join(DATABASE);
    let checked = unix_seconds(SystemTime::now()).unwrap_or_default();
    let stale_after_days = stale_after.as_secs() / 86_400;

    let updated = std::fs::metadata(&database)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(unix_seconds);

    let Some(connection) = open(&database) else {
        let sources = DEFINITIONS
            .iter()
            .map(|definition| Source {
                name: definition.name,
                entries: 0,
                newest: None,
                downloaded: last_download(cache_dir, definition),
                state: State::Missing,
            })
            .collect();

        return Report {
            database: database.clone(),
            updated,
            checked,
            stale_after_days,
            sources,
            error: Some(format!(
                "no vulnerability database at {}",
                database.display()
            )),
        };
    };

    let mut sources = Vec::new();

    for definition in DEFINITIONS {
        let entries = count(&connection, definition);
        let newest = newest(&connection, definition, checked);
        let downloaded = last_download(cache_dir, definition);

        let state = if entries == 0 {
            State::Missing
        } else if is_stale(newest, downloaded, checked, stale_after) {
            State::Stale
        } else {
            State::Ok
        };

        sources.push(Source {
            name: definition.name,
            entries,
            newest,
            downloaded,
            state,
        });
    }

    Report {
        database,
        updated,
        checked,
        stale_after_days,
        sources,
        error: None,
    }
}

/// The cache directory cve-bin-tool keeps its data in.
///
/// This follows the same rule as cve-bin-tool itself: the user's cache
/// directory, which is `~/.cache` unless `XDG_CACHE_HOME` says otherwise.
pub fn cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".cache"))
                .unwrap_or_else(|| PathBuf::from(".cache"))
        });

    base.join(CACHE_DIRECTORY)
}

/// Open the database read-only, so that checking it cannot disturb a scan
/// that is running at the same time.
fn open(database: &Path) -> Option<Connection> {
    if !database.is_file() {
        return None;
    }

    Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
}

/// A data source cve-bin-tool can download.
struct Definition {
    /// The source's name, as cve-bin-tool knows it.
    name: &'static str,
    /// Where the source keeps the files it downloads.
    artifact: Artifact,
    /// How the source's rows are counted in the database.
    count: Count,
}

/// Where a source keeps the files it downloads.
enum Artifact {
    /// A directory the source downloads into. The first name is the one
    /// current versions of cve-bin-tool use; the rest are older names for
    /// the same directory.
    Directory(&'static [&'static str]),
    /// A file the source downloads.
    File(&'static str),
    /// Files in the cache directory whose names start with one string and
    /// end with another.
    Files(&'static str, &'static str),
}

/// How a source's rows are counted in the database.
enum Count {
    /// Rows in the tables that have a `data_source` column, naming the
    /// source as that column spells it.
    BySource(&'static [&'static str], &'static str),
    /// Rows counted by a query of the scanner's own.
    ByQuery(&'static str),
}

/// The sources, as cve-bin-tool's own list of them.
const DEFINITIONS: &[Definition] = &[
    Definition {
        name: "CURL",
        artifact: Artifact::File("vuln.json"),
        count: Count::BySource(&["cve_range"], "Curl"),
    },
    Definition {
        name: "EPSS",
        artifact: Artifact::Directory(&["epss"]),
        count: Count::ByQuery(
            "SELECT COUNT(*) FROM cve_metrics WHERE metric_id = \
             (SELECT metrics_id FROM metrics WHERE metrics_name = 'EPSS')",
        ),
    },
    Definition {
        name: "GAD",
        artifact: Artifact::Directory(&["gad"]),
        count: Count::BySource(&["cve_severity", "cve_range"], "GAD"),
    },
    Definition {
        name: "NVD",
        artifact: Artifact::Files("nvdcve-", ".json.gz"),
        count: Count::BySource(&["cve_severity", "cve_range"], "NVD"),
    },
    Definition {
        name: "OSV",
        artifact: Artifact::Directory(&["OSV", "osv"]),
        count: Count::BySource(&["cve_severity", "cve_range"], "OSV"),
    },
    Definition {
        name: "PURL2CPE",
        artifact: Artifact::Directory(&["purl2cpe"]),
        count: Count::ByQuery("SELECT COUNT(*) FROM purl2cpe"),
    },
    Definition {
        name: "REDHAT",
        artifact: Artifact::Directory(&["redhat"]),
        count: Count::BySource(&["cve_severity", "cve_range"], "REDHAT"),
    },
];

/// How many rows the source has in the database.
fn count(connection: &Connection, definition: &Definition) -> usize {
    match &definition.count {
        Count::BySource(tables, label) => tables
            .iter()
            .map(|table| {
                let sql = format!("SELECT COUNT(*) FROM {table} WHERE data_source = ?1");
                connection
                    .query_row(&sql, [*label], |row| row.get::<_, i64>(0))
                    .unwrap_or(0) as usize
            })
            .sum(),
        Count::ByQuery(sql) => connection
            .query_row(sql, [], |row| row.get::<_, i64>(0))
            .unwrap_or(0) as usize,
    }
}

/// The date of the newest record the source has, if it keeps dates.
///
/// Some sources record a date for every vulnerability they know about, and
/// some do not. cve-bin-tool writes a date in the future for the records
/// whose real date it does not know, so those are ignored here: only dates
/// that have already passed count.
fn newest(connection: &Connection, definition: &Definition, now: i64) -> Option<i64> {
    let Count::BySource(tables, label) = &definition.count else {
        return None;
    };

    // The dates are compared as their first ten characters, so that a date
    // written as `2026-11-09` and one written as `2026-11-09T00:00:00Z`
    // are treated as the same day.
    let cutoff = format_rfc3339(now + 86_400)[..10].to_string();
    let mut newest = None;

    for table in *tables {
        let sql = format!(
            "SELECT MAX(substr(last_modified, 1, 10)) FROM {table} \
             WHERE data_source = ?1 AND substr(last_modified, 1, 10) < ?2"
        );

        let Ok(Some(text)) = connection.query_row(&sql, [*label, cutoff.as_str()], |row| {
            row.get::<_, Option<String>>(0)
        }) else {
            continue;
        };

        let Some(at) = parse_timestamp(&text) else {
            continue;
        };

        if newest.is_none_or(|current| at > current) {
            newest = Some(at);
        }
    }

    newest
}

/// When the source last downloaded something, if it ever has.
fn last_download(cache_dir: &Path, definition: &Definition) -> Option<i64> {
    match &definition.artifact {
        Artifact::Directory(names) => names
            .iter()
            .filter_map(|name| newest_in(&cache_dir.join(name), 0))
            .max(),
        Artifact::File(name) => newest_in(&cache_dir.join(name), 0),
        Artifact::Files(prefix, suffix) => {
            let Ok(entries) = std::fs::read_dir(cache_dir) else {
                return None;
            };

            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name.starts_with(prefix) && name.ends_with(suffix)
                })
                .filter_map(|entry| {
                    let metadata = entry.metadata().ok()?;
                    let modified = metadata.modified().ok()?;
                    unix_seconds(modified)
                })
                .max()
        }
    }
}

/// The most recent modification time of a file, or of any file in a
/// directory and the directories below it.
fn newest_in(path: &Path, depth: usize) -> Option<i64> {
    let metadata = std::fs::metadata(path).ok()?;

    if metadata.is_file() {
        return metadata.modified().ok().and_then(unix_seconds);
    }

    // The directory's own time says when something was last added to it,
    // which is worth having even when the files inside it are not walked.
    let mut newest = metadata.modified().ok().and_then(unix_seconds);

    if depth >= MAX_DEPTH {
        return newest;
    }

    let Ok(entries) = std::fs::read_dir(path) else {
        return newest;
    };

    for entry in entries.filter_map(Result::ok) {
        if let Some(at) = newest_in(&entry.path(), depth + 1)
            && newest.is_none_or(|current| at > current)
        {
            newest = Some(at);
        }
    }

    newest
}

/// Whether a source's data is too old to trust.
///
/// The date of the newest record is the better guide, because it says how
/// far behind the vulnerabilities the source knows about are. Some sources
/// do not keep dates, and for those the time of the last download is used
/// instead.
fn is_stale(newest: Option<i64>, downloaded: Option<i64>, now: i64, stale_after: Duration) -> bool {
    let limit = now - stale_after.as_secs() as i64;

    match (newest, downloaded) {
        (Some(newest), _) => newest < limit,
        (None, Some(downloaded)) => downloaded < limit,
        (None, None) => false,
    }
}

/// How long ago something happened, in words.
pub fn describe_age(at: i64, now: i64) -> String {
    let seconds = now - at;

    if seconds < 0 {
        return "in the future".to_string();
    }

    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3600;

    match (days, hours) {
        (0, 0) => "just now".to_string(),
        (0, 1) => "an hour ago".to_string(),
        (0, hours) => format!("{hours} hours ago"),
        (1, _) => "a day ago".to_string(),
        (days, _) => format!("{days} days ago"),
    }
}

/// The report as a document, for writing to a file.
pub fn to_json(report: &Report) -> String {
    let mut text = serde_json::to_string_pretty(report).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_ages_in_words() {
        let now = 1_000_000;
        assert_eq!(describe_age(now, now), "just now");
        assert_eq!(describe_age(now - 3600, now), "an hour ago");
        assert_eq!(describe_age(now - 3600 * 5, now), "5 hours ago");
        assert_eq!(describe_age(now - 86_400, now), "a day ago");
        assert_eq!(describe_age(now - 86_400 * 3, now), "3 days ago");
        assert_eq!(describe_age(now + 10, now), "in the future");
    }

    #[test]
    fn data_older_than_the_limit_is_stale() {
        let now = 1_000_000;
        let stale_after = Duration::from_secs(7 * 86_400);

        assert!(is_stale(
            Some(now - 8 * 86_400),
            Some(now),
            now,
            stale_after
        ));
        assert!(!is_stale(
            Some(now - 6 * 86_400),
            Some(now),
            now,
            stale_after
        ));
    }

    #[test]
    fn the_download_time_is_used_when_there_are_no_dates() {
        let now = 1_000_000;
        let stale_after = Duration::from_secs(7 * 86_400);

        assert!(is_stale(None, Some(now - 8 * 86_400), now, stale_after));
        assert!(!is_stale(None, Some(now - 6 * 86_400), now, stale_after));
    }

    #[test]
    fn a_source_that_never_downloaded_is_not_stale_but_is_missing() {
        let now = 1_000_000;
        assert!(!is_stale(None, None, now, Duration::from_secs(86_400)));
    }

    #[test]
    fn finds_the_cache_directory_from_the_environment() {
        // The cache directory is where cve-bin-tool puts its database, so
        // the check looks there.
        assert!(cache_dir().ends_with(CACHE_DIRECTORY));
    }

    #[test]
    fn reports_a_missing_database() {
        let dir = std::env::temp_dir().join("security-scan-no-such-cache");
        let report = check(&dir, Duration::from_secs(7 * 86_400));

        assert!(report.error.is_some());
        assert_eq!(report.sources.len(), DEFINITIONS.len());
        assert!(report.problems().len() == DEFINITIONS.len());
        assert!(
            report
                .sources
                .iter()
                .all(|source| source.state == State::Missing)
        );
    }

    #[test]
    fn reads_the_state_of_each_source_from_the_database() {
        let cache = TempDir::new();
        let database = cache.path().join(DATABASE);
        let connection = Connection::open(&database).unwrap();

        // The tables cve-bin-tool keeps its data in, as it creates them.
        connection
            .execute_batch(
                "CREATE TABLE cve_severity (
                    cve_number TEXT, severity TEXT, description TEXT, score INTEGER,
                    cvss_version INTEGER, cvss_vector TEXT, data_source TEXT,
                    last_modified TIMESTAMP, PRIMARY KEY(cve_number, data_source));
                 CREATE TABLE cve_range (
                    cve_number TEXT, vendor TEXT, product TEXT, version TEXT,
                    versionStartIncluding TEXT, versionStartExcluding TEXT,
                    versionEndIncluding TEXT, versionEndExcluding TEXT,
                    data_source TEXT);
                 CREATE TABLE metrics (metrics_id INTEGER, metrics_name TEXT);
                 CREATE TABLE cve_metrics (
                    cve_number TEXT, metric_id INTEGER, metric_score REAL,
                    metric_field TEXT);
                 CREATE TABLE purl2cpe (purl TEXT, cpe TEXT);",
            )
            .unwrap();

        let now = unix_seconds(SystemTime::now()).unwrap();
        let yesterday = format_rfc3339(now - 86_400)[..10].to_string();
        let long_ago = format_rfc3339(now - 30 * 86_400)[..10].to_string();

        connection
            .execute(
                "INSERT INTO cve_severity VALUES ('CVE-1', 'HIGH', '', 7.5, 3, '', 'OSV', ?1)",
                [&yesterday],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO cve_severity VALUES ('CVE-2', 'HIGH', '', 7.5, 3, '', 'NVD', ?1)",
                [&long_ago],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO cve_range VALUES ('CVE-3', 'curl', 'curl', '8.0', '', '', '', '', 'Curl')",
                [],
            )
            .unwrap();
        connection
            .execute("INSERT INTO metrics VALUES (1, 'EPSS')", [])
            .unwrap();
        connection
            .execute("INSERT INTO cve_metrics VALUES ('CVE-4', 1, 0.5, 'EPSS')", [])
            .unwrap();
        connection
            .execute("INSERT INTO purl2cpe VALUES ('pkg:npm/a', 'cpe:2.3:a:a:1.0')", [])
            .unwrap();
        drop(connection);

        let report = check(cache.path(), Duration::from_secs(7 * 86_400));
        assert!(report.error.is_none());

        let state = |name: &str| {
            report
                .sources
                .iter()
                .find(|source| source.name == name)
                .map(|source| source.state)
        };

        assert_eq!(state("OSV"), Some(State::Ok));
        assert_eq!(state("NVD"), Some(State::Stale));
        assert_eq!(state("CURL"), Some(State::Ok));
        assert_eq!(state("EPSS"), Some(State::Ok));
        assert_eq!(state("PURL2CPE"), Some(State::Ok));
        assert_eq!(state("GAD"), Some(State::Missing));

        let osv = report.sources.iter().find(|s| s.name == "OSV").unwrap();
        assert_eq!(osv.entries, 1);
        assert_eq!(osv.newest, parse_timestamp(&yesterday));
    }

    /// A directory to put a test database in.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);

            let path = std::env::temp_dir().join(format!(
                "security-scan-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
