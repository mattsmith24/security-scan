//! Interactive triage of a project's VEX.
//!
//! The VEX next to a project's SBOM lists every finding cve-bin-tool
//! reported, with an `analysis` block saying what has been decided about it.
//! Triaging shows each finding in turn and records a decision for it, one
//! keypress at a time. The decisions are written back to the VEX, which the
//! next scan hands to cve-bin-tool, so a finding dismissed here stops being
//! reported without disappearing from the report.
//!
//! The states written are the ones cve-bin-tool maps to its remarks:
//! `not_affected`, `false_positive` and `resolved` are filtered out of the
//! summary, while `in_triage` and `exploitable` stay visible.
//!
//! A VEX records no severity, so findings are shown most severe first using
//! the CVE report written next to it, which cve-bin-tool fills in for every
//! finding.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use thiserror::Error;

use crate::scanner::cve_bin_tool;

/// The VEX file written next to each project's SBOM.
const VEX_NAME: &str = "vex.cdx.json";

/// The CVE report written next to the VEX, which records each finding's
/// severity.
const REPORT_NAME: &str = "cve-report.json";

/// The file a triage session writes before moving it into place.
const TMP_NAME: &str = "vex.triage.tmp";

/// How wide the wrapped description of a finding may be.
const WRAP_WIDTH: usize = 68;

/// The states a finding can be left in, and how to describe them.
const STATES: [(&str, &str); 5] = [
    ("not_affected", "not affected"),
    ("false_positive", "false positive"),
    ("resolved", "resolved"),
    ("exploitable", "exploitable"),
    ("in_triage", "in triage"),
];

/// The justifications CycloneDX allows for a `not_affected` finding.
const JUSTIFICATIONS: [(&str, &str); 9] = [
    (
        "code_not_present",
        "the vulnerable code is not in the project",
    ),
    (
        "code_not_reachable",
        "the vulnerable code cannot be reached from the project",
    ),
    (
        "requires_configuration",
        "the vulnerable code is only used with a configuration the project does not use",
    ),
    (
        "requires_dependency",
        "the vulnerable code needs a dependency the project does not have",
    ),
    (
        "requires_environment",
        "the vulnerable code only runs in an environment the project does not use",
    ),
    (
        "protected_by_compiler",
        "the compiler protects the vulnerable code",
    ),
    (
        "protected_at_runtime",
        "the vulnerable code is protected at runtime",
    ),
    (
        "protected_at_perimeter",
        "the vulnerable code is protected at the network perimeter",
    ),
    (
        "protected_by_mitigating_control",
        "another control mitigates the vulnerability",
    ),
];

#[derive(Debug, Error)]
pub enum TriageError {
    #[error("no VEX for project {project:?} in {dir}")]
    NoVex { project: String, dir: PathBuf },

    #[error("project {project:?} matches more than one VEX:\n    {paths}")]
    Ambiguous { project: String, paths: String },

    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse {path}: {reason}")]
    Parse { path: PathBuf, reason: String },

    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read a keypress: {0}")]
    Input(#[source] io::Error),
}

/// What a triage session did.
pub struct Summary {
    /// How many findings the VEX lists.
    pub total: usize,
    /// How many findings are in each state, known decisions first.
    pub counts: Vec<(String, usize)>,
    /// Whether anything was written back to the VEX.
    pub changed: bool,
}

/// Find the VEX of a project, by the name recorded in it.
///
/// The project's name is the one the scanner recorded for it in the VEX
/// metadata, which is also the name its report uses. The directory the VEX
/// sits in is accepted as well, so a project can be named by its directory.
pub fn find_vex(output_dir: &Path, project: &str) -> Result<PathBuf, TriageError> {
    if !output_dir.is_dir() {
        return Err(TriageError::NoVex {
            project: project.to_string(),
            dir: output_dir.to_path_buf(),
        });
    }

    let mut found = Vec::new();
    collect_vex(output_dir, &mut found)?;

    let mut matches: Vec<PathBuf> = found
        .into_iter()
        .filter(|path| names_project(path, project))
        .collect();

    match matches.len() {
        0 => Err(TriageError::NoVex {
            project: project.to_string(),
            dir: output_dir.to_path_buf(),
        }),
        1 => Ok(matches.remove(0)),
        _ => Err(TriageError::Ambiguous {
            project: project.to_string(),
            paths: matches
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<String>>()
                .join("\n    "),
        }),
    }
}

/// Collect every VEX below `dir`.
fn collect_vex(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), TriageError> {
    let entries = std::fs::read_dir(dir).map_err(|source| TriageError::Read {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| TriageError::Read {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|source| TriageError::Read {
            path: path.clone(),
            source,
        })?;

        if kind.is_dir() {
            collect_vex(&path, found)?;
        } else if kind.is_file() && entry.file_name() == VEX_NAME {
            found.push(path);
        }
    }

    Ok(())
}

/// Whether a VEX belongs to the named project.
fn names_project(path: &Path, project: &str) -> bool {
    if let Some(name) = document_name(path)
        && name.eq_ignore_ascii_case(project)
    {
        return true;
    }

    path.parent()
        .and_then(|parent| parent.file_name())
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(project))
}

/// The project name recorded in a VEX's metadata, if it has one.
fn document_name(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let document: Value = serde_json::from_str(&text).ok()?;

    document
        .get("metadata")?
        .get("component")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// Show the findings in a VEX and record what to do about each.
pub fn triage(path: &Path) -> Result<Summary, TriageError> {
    triage_with(path, &mut Terminal)
}

/// Triaging, with the keypresses and lines coming from `prompter`.
pub fn triage_with(path: &Path, prompter: &mut impl Prompter) -> Result<Summary, TriageError> {
    let mut document = read_json(path)?;

    let vulnerabilities = document
        .get_mut("vulnerabilities")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| TriageError::Parse {
            path: path.to_path_buf(),
            reason: "the document has no vulnerabilities".to_string(),
        })?;

    let total = vulnerabilities.len();
    let mut changed = false;
    let mut quit = false;

    let severities = severities(path);
    if total > 0 && severities.is_empty() {
        eprintln!("note: no {REPORT_NAME} next to the VEX, so findings keep VEX order");
    }
    let order = display_order(vulnerabilities, &severities);

    if total > 0 {
        let noun = if total == 1 { "finding" } else { "findings" };
        eprintln!();
        eprintln!(
            "triage {total} {noun}. Keys: n not affected, f false positive, \
             r resolved,"
        );
        eprintln!("e exploitable, t back to triage, s skip, q quit and save.");
        eprintln!();
    }

    for (position, &index) in order.iter().enumerate() {
        if quit {
            break;
        }

        let vulnerability = &mut vulnerabilities[index];
        let severity = severities.get(&finding_key(vulnerability));
        show(position + 1, total, vulnerability, severity);

        loop {
            let key = match prompter.key("  decision [n/f/r/e/t/s/q]: ") {
                Ok(Some(key)) => key.to_ascii_lowercase(),
                Ok(None) => {
                    quit = true;
                    break;
                }
                Err(source) => return Err(TriageError::Input(source)),
            };

            // Ctrl-C is read as a byte because the terminal is in raw mode.
            if key == 'q' || key == '\u{3}' {
                quit = true;
                break;
            }

            match key {
                'n' => {
                    let Some(justification) = choose_justification(prompter)? else {
                        continue;
                    };
                    let detail = line(prompter, "  detail (enter to skip): ")?;
                    set_decision(vulnerability, "not_affected", &detail, Some(justification));
                }
                'f' => {
                    let detail = line(prompter, "  reason (enter to skip): ")?;
                    set_decision(vulnerability, "false_positive", &detail, None);
                }
                'r' => {
                    let detail = line(prompter, "  detail, e.g. fixed in 1.2.3 (enter to skip): ")?;
                    set_decision(vulnerability, "resolved", &detail, None);
                }
                'e' => {
                    let detail = line(prompter, "  detail (enter to skip): ")?;
                    set_decision(vulnerability, "exploitable", &detail, None);
                }
                't' => {
                    set_decision(vulnerability, "in_triage", "", None);
                }
                's' => break,
                _ => {
                    eprintln!("  unknown key: press n, f, r, e, t, s or q");
                    continue;
                }
            }

            changed = true;
            break;
        }
    }

    let counts = count_states(vulnerabilities);

    if changed {
        write_json(path, &document)?;
    }

    Ok(Summary {
        total,
        counts,
        changed,
    })
}

/// Ask which justification applies to a `not_affected` finding.
fn choose_justification(prompter: &mut impl Prompter) -> Result<Option<&'static str>, TriageError> {
    eprintln!("  why is the project not affected?");
    for (index, (_, text)) in JUSTIFICATIONS.iter().enumerate() {
        eprintln!("    {} {text}", index + 1);
    }
    eprintln!("    b back");

    loop {
        let key = match prompter.key("  justification [1-9/b]: ") {
            Ok(Some(key)) => key,
            Ok(None) => return Ok(None),
            Err(source) => return Err(TriageError::Input(source)),
        };

        if key == 'b' || key == 'B' {
            return Ok(None);
        }

        if let Some(index) = key.to_digit(10)
            && index >= 1
            && index <= JUSTIFICATIONS.len() as u32
        {
            return Ok(Some(JUSTIFICATIONS[index as usize - 1].0));
        }

        eprintln!("  unknown choice: press 1 to 9, or b to go back");
    }
}

/// Prompt for a line of text, empty if the user just presses enter.
fn line(prompter: &mut impl Prompter, prompt: &str) -> Result<String, TriageError> {
    match prompter.line(prompt) {
        Ok(Some(text)) => Ok(text.trim().to_string()),
        Ok(None) => Ok(String::new()),
        Err(source) => Err(TriageError::Input(source)),
    }
}

/// The severity of a finding, as cve-bin-tool recorded it in the report.
struct Severity {
    name: String,
    score: String,
}

/// Read each finding's severity from the CVE report next to the VEX.
///
/// The report is keyed by the package a finding is in and its CVE number,
/// which is also what identifies a finding in the VEX. An unreadable or
/// missing report gives an empty map: triage still works, just in VEX order.
fn severities(vex: &Path) -> BTreeMap<(String, String), Severity> {
    let path = vex.with_file_name(REPORT_NAME);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<Value>>(&text) else {
        return BTreeMap::new();
    };

    let mut severities = BTreeMap::new();
    for entry in entries {
        let Some(product) = entry.get("product").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        let Some(number) = entry.get("cve_number").and_then(Value::as_str) else {
            continue;
        };

        severities.insert(
            (format!("{product}@{version}"), number.to_string()),
            Severity {
                name: entry
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                score: entry
                    .get("score")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
        );
    }

    severities
}

/// What identifies a finding in both the VEX and the CVE report.
fn finding_key(vulnerability: &Value) -> (String, String) {
    (
        string_field(vulnerability, "bom-ref"),
        string_field(vulnerability, "id"),
    )
}

/// The order findings are shown in: most severe first, then VEX order.
fn display_order(
    vulnerabilities: &[Value],
    severities: &BTreeMap<(String, String), Severity>,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..vulnerabilities.len()).collect();

    // The sort is stable, so findings of the same severity keep the order
    // the VEX lists them in, which groups them by package.
    order.sort_by_key(|&index| {
        severities
            .get(&finding_key(&vulnerabilities[index]))
            .map_or(usize::MAX, |severity| {
                cve_bin_tool::severity_rank(&severity.name)
            })
    });

    order
}

/// Show one finding: what it is, where it is, and what has been decided.
fn show(index: usize, total: usize, vulnerability: &Value, severity: Option<&Severity>) {
    let id = string_field(vulnerability, "id");
    let package = string_field(vulnerability, "bom-ref");
    let analysis = vulnerability.get("analysis");

    let state = analysis
        .and_then(|analysis| analysis.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("in_triage");

    eprintln!();
    eprintln!("[{index}/{total}] {id} in {package}");
    eprintln!("         state: {}", describe_state(state));

    if let Some(severity) = severity {
        match severity.score.as_str() {
            "" | "unknown" => eprintln!("         severity: {}", severity.name),
            score => eprintln!("         severity: {} ({score})", severity.name),
        }
    }

    if let Some(detail) = analysis
        .and_then(|analysis| analysis.get("detail"))
        .and_then(Value::as_str)
        && !detail.is_empty()
    {
        for line in wrap(detail, WRAP_WIDTH) {
            eprintln!("         detail: {line}");
        }
    }

    if let Some(justification) = analysis
        .and_then(|analysis| analysis.get("justification"))
        .and_then(Value::as_str)
        && !justification.is_empty()
    {
        eprintln!("         justification: {justification}");
    }

    let description = string_field(vulnerability, "description");
    for line in wrap(&description, WRAP_WIDTH) {
        eprintln!("         {line}");
    }
}

/// Record a decision in a finding's `analysis` block.
fn set_decision(vulnerability: &mut Value, state: &str, detail: &str, justification: Option<&str>) {
    let Some(object) = vulnerability.as_object_mut() else {
        return;
    };

    let analysis = object
        .entry("analysis")
        .or_insert_with(|| Value::Object(Map::new()));
    if !analysis.is_object() {
        *analysis = Value::Object(Map::new());
    }
    let analysis = analysis.as_object_mut().expect("analysis is an object");

    analysis.insert("state".to_string(), Value::String(state.to_string()));

    if detail.is_empty() {
        analysis.remove("detail");
    } else {
        analysis.insert("detail".to_string(), Value::String(detail.to_string()));
    }

    match justification {
        Some(justification) => {
            analysis.insert(
                "justification".to_string(),
                Value::String(justification.to_string()),
            );
        }
        None => {
            analysis.remove("justification");
        }
    }
}

/// How many findings are in each state, known decisions first.
fn count_states(vulnerabilities: &[Value]) -> Vec<(String, usize)> {
    let mut remaining: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

    for vulnerability in vulnerabilities {
        let state = vulnerability
            .get("analysis")
            .and_then(|analysis| analysis.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("in_triage")
            .to_ascii_lowercase();
        *remaining.entry(state).or_insert(0) += 1;
    }

    // Known decisions in the order they are offered, then anything else the
    // VEX happens to contain.
    let mut counts: Vec<(String, usize)> = Vec::new();
    for (state, _) in STATES {
        if let Some(count) = remaining.remove(state) {
            counts.push((state.to_string(), count));
        }
    }
    counts.extend(remaining);

    counts
}

/// A readable name for a state.
pub fn describe_state(state: &str) -> String {
    STATES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(state))
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| state.replace('_', " "))
}

/// A string field of a finding, empty if it is not there.
fn string_field(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Break text into lines no wider than `width`, on word boundaries.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();

    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.chars().count() + 1 + word.chars().count() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            lines.push(std::mem::take(&mut line));
            line.push_str(word);
        }
    }

    if !line.is_empty() {
        lines.push(line);
    }

    lines
}

/// Read a JSON document.
fn read_json(path: &Path) -> Result<Value, TriageError> {
    let text = std::fs::read_to_string(path).map_err(|source| TriageError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    serde_json::from_str(&text).map_err(|source| TriageError::Parse {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

/// Write a document to a temporary file and move it into place, so that a
/// failed triage leaves the previous VEX untouched.
fn write_json(path: &Path, document: &Value) -> Result<(), TriageError> {
    let mut text = serde_json::to_string_pretty(document).map_err(|source| TriageError::Parse {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })?;
    text.push('\n');

    let tmp = path.with_file_name(TMP_NAME);
    std::fs::write(&tmp, text).map_err(|source| TriageError::Write {
        path: tmp.clone(),
        source,
    })?;

    if let Err(source) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(TriageError::Write {
            path: path.to_path_buf(),
            source,
        });
    }

    Ok(())
}

/// Somewhere to read keypresses and lines from.
pub trait Prompter {
    /// Read a single keypress, or `None` at end of input.
    fn key(&mut self, prompt: &str) -> io::Result<Option<char>>;

    /// Read a line of text, or `None` at end of input.
    fn line(&mut self, prompt: &str) -> io::Result<Option<String>>;
}

/// The terminal, read one keypress at a time.
pub struct Terminal;

impl Prompter for Terminal {
    fn key(&mut self, prompt: &str) -> io::Result<Option<char>> {
        eprint!("{prompt}");
        io::stderr().flush()?;

        // Without a terminal (a pipe, or a test) there are no keypresses to
        // read: fall back to a line and use its first character.
        if !io::stdin().is_terminal() {
            return Ok(read_line()?.and_then(|line| line.chars().next()));
        }

        let raw = RawMode::enable()?;
        let mut byte = [0u8; 1];
        let read = io::stdin().lock().read(&mut byte)?;
        drop(raw);

        if read == 0 {
            return Ok(None);
        }

        let key = byte[0] as char;
        // The key was not echoed while the terminal was in raw mode.
        eprintln!("{key}");
        Ok(Some(key))
    }

    fn line(&mut self, prompt: &str) -> io::Result<Option<String>> {
        eprint!("{prompt}");
        io::stderr().flush()?;
        read_line()
    }
}

/// Read a line from stdin, without its newline.
fn read_line() -> io::Result<Option<String>> {
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }

    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// The terminal in raw mode, restored when this is dropped.
struct RawMode {
    saved: String,
}

impl RawMode {
    /// Put stdin's terminal into a mode where one keypress is read at a time,
    /// without being echoed.
    ///
    /// `stty` is given the setting to restore rather than reading it back
    /// later, so the terminal is left exactly as it was found.
    fn enable() -> io::Result<Self> {
        let saved = stty(&["-g"])?;

        // SIGINT is turned off so that Ctrl-C arrives as a keypress to act
        // on, rather than killing the process before the terminal is
        // restored.
        stty(&["-icanon", "-echo", "-isig", "min", "1", "time", "0"])?;

        Ok(Self { saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = stty(&[self.saved.trim()]);
    }
}

/// Run `stty` with the given arguments, returning its output.
///
/// `stty` reads and writes the settings of its own stdin, so it is given the
/// scanner's terminal; capturing its output would otherwise leave it with no
/// terminal to change.
fn stty(args: &[&str]) -> io::Result<String> {
    let output = std::process::Command::new("stty")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "stty {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    /// A prompter that replays a script and records the prompts it was given.
    struct Script {
        keys: VecDeque<char>,
        lines: VecDeque<String>,
        prompts: Vec<String>,
    }

    impl Script {
        fn new(keys: &str, lines: &[&str]) -> Self {
            Self {
                keys: keys.chars().collect(),
                lines: lines.iter().map(|line| line.to_string()).collect(),
                prompts: Vec::new(),
            }
        }
    }

    impl Prompter for Script {
        fn key(&mut self, prompt: &str) -> io::Result<Option<char>> {
            self.prompts.push(prompt.to_string());
            Ok(self.keys.pop_front())
        }

        fn line(&mut self, prompt: &str) -> io::Result<Option<String>> {
            self.prompts.push(prompt.to_string());
            Ok(self.lines.pop_front())
        }
    }

    fn vex(entries: Value) -> Value {
        json!({
            "bomFormat": "CycloneDX",
            "metadata": { "component": { "name": "goalkeepr" } },
            "vulnerabilities": entries,
        })
    }

    fn with_temp_document(document: &Value, f: impl FnOnce(&Path)) {
        let dir = std::env::temp_dir().join(format!(
            "security-scan-triage-{}-{}",
            std::process::id(),
            unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(VEX_NAME);
        std::fs::write(&path, serde_json::to_string_pretty(document).unwrap()).unwrap();

        f(&path);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn unique() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn finding(id: &str) -> Value {
        json!({
            "id": id,
            "bom-ref": "vite@8.0.16",
            "description": "A test finding",
            "analysis": { "state": "in_triage", "detail": "" },
        })
    }

    fn counts(summary: &Summary) -> Vec<(&str, usize)> {
        summary
            .counts
            .iter()
            .map(|(state, count)| (state.as_str(), *count))
            .collect()
    }

    #[test]
    fn records_a_not_affected_finding_with_a_justification() {
        let document = vex(json!([finding("GHSA-1")]));

        // Choose not affected, then justification 2, then the detail.
        let mut script = Script::new("n2", &["not used in production"]);

        with_temp_document(&document, |path| {
            triage_with(path, &mut script).unwrap();

            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let analysis = &written["vulnerabilities"][0]["analysis"];
            assert_eq!(analysis["state"], "not_affected");
            assert_eq!(analysis["justification"], "code_not_reachable");
            assert_eq!(analysis["detail"], "not used in production");
        });
    }

    #[test]
    fn records_a_false_positive_with_a_reason() {
        let document = vex(json!([finding("GHSA-1")]));
        let mut script = Script::new("f", &["the package is not installed"]);

        with_temp_document(&document, |path| {
            triage_with(path, &mut script).unwrap();

            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let analysis = &written["vulnerabilities"][0]["analysis"];
            assert_eq!(analysis["state"], "false_positive");
            assert_eq!(analysis["detail"], "the package is not installed");
            assert!(analysis.get("justification").is_none());
        });
    }

    #[test]
    fn resolved_clears_an_old_justification() {
        let document = vex(json!([{
            "id": "GHSA-1",
            "bom-ref": "vite@8.0.16",
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_present",
                "detail": "old reason",
            },
        }]));
        let mut script = Script::new("r", &["fixed in 8.0.17"]);

        with_temp_document(&document, |path| {
            triage_with(path, &mut script).unwrap();

            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let analysis = &written["vulnerabilities"][0]["analysis"];
            assert_eq!(analysis["state"], "resolved");
            assert_eq!(analysis["detail"], "fixed in 8.0.17");
            assert!(analysis.get("justification").is_none());
        });
    }

    #[test]
    fn going_back_to_triage_clears_the_decision() {
        let document = vex(json!([{
            "id": "GHSA-1",
            "bom-ref": "vite@8.0.16",
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_present",
                "detail": "old reason",
            },
        }]));
        let mut script = Script::new("t", &[]);

        with_temp_document(&document, |path| {
            triage_with(path, &mut script).unwrap();

            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let analysis = &written["vulnerabilities"][0]["analysis"];
            assert_eq!(analysis["state"], "in_triage");
            assert!(analysis.get("justification").is_none());
            assert!(analysis.get("detail").is_none());
        });
    }

    #[test]
    fn skipping_leaves_the_vex_alone() {
        let document = vex(json!([finding("GHSA-1")]));
        let before = serde_json::to_string_pretty(&document).unwrap();
        let mut script = Script::new("s", &[]);

        with_temp_document(&document, |path| {
            let summary = triage_with(path, &mut script).unwrap();
            assert!(!summary.changed);

            let after = std::fs::read_to_string(path).unwrap();
            assert_eq!(after.trim_end(), before);
        });
    }

    #[test]
    fn quitting_keeps_the_decisions_made_so_far() {
        let document = vex(json!([finding("GHSA-1"), finding("GHSA-2")]));
        // The first finding is triaged, then q quits before the second.
        let mut script = Script::new("tq", &[]);

        with_temp_document(&document, |path| {
            triage_with(path, &mut script).unwrap();

            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(
                written["vulnerabilities"][0]["analysis"]["state"],
                "in_triage"
            );
            assert_eq!(
                written["vulnerabilities"][1]["analysis"]["state"],
                "in_triage"
            );
        });
    }

    #[test]
    fn an_unknown_key_is_not_a_decision() {
        let document = vex(json!([finding("GHSA-1")]));
        // x is rejected, then s skips.
        let mut script = Script::new("xs", &[]);

        with_temp_document(&document, |path| {
            let summary = triage_with(path, &mut script).unwrap();
            assert!(!summary.changed);
            assert_eq!(counts(&summary), vec![("in_triage", 1)]);
        });
    }

    #[test]
    fn counts_the_findings_in_each_state() {
        let document = vex(json!([
            finding("A"),
            { "id": "B", "analysis": { "state": "not_affected" } },
            { "id": "C", "analysis": { "state": "not_affected" } },
            { "id": "D", "analysis": { "state": "resolved" } },
            { "id": "E", "analysis": { "state": "resolved_with_pedigree" } },
        ]));

        let mut script = Script::new("sssss", &[]);
        with_temp_document(&document, |path| {
            let summary = triage_with(path, &mut script).unwrap();
            assert_eq!(summary.total, 5);
            assert_eq!(
                counts(&summary),
                vec![
                    ("not_affected", 2),
                    ("resolved", 1),
                    ("in_triage", 1),
                    ("resolved_with_pedigree", 1),
                ]
            );
        });
    }

    fn write_report(path: &Path, entries: Value) {
        std::fs::write(
            path.with_file_name(REPORT_NAME),
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn shows_the_most_severe_findings_first() {
        let document = vex(json!([
            finding("GHSA-LOW"),
            finding("GHSA-CRITICAL"),
            finding("GHSA-HIGH"),
            finding("GHSA-MISSING"),
            finding("GHSA-MEDIUM"),
        ]));

        with_temp_document(&document, |path| {
            write_report(
                path,
                json!([
                    { "product": "vite", "version": "8.0.16", "cve_number": "GHSA-LOW", "severity": "LOW", "score": "2.0" },
                    { "product": "vite", "version": "8.0.16", "cve_number": "GHSA-CRITICAL", "severity": "CRITICAL", "score": "9.8" },
                    { "product": "vite", "version": "8.0.16", "cve_number": "GHSA-HIGH", "severity": "HIGH", "score": "7.5" },
                    { "product": "vite", "version": "8.0.16", "cve_number": "GHSA-MEDIUM", "severity": "MEDIUM", "score": "5.0" },
                ]),
            );

            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let vulnerabilities = written["vulnerabilities"].as_array().unwrap();

            let order = display_order(vulnerabilities, &severities(path));
            assert_eq!(order, vec![1, 2, 4, 0, 3]);
        });
    }

    #[test]
    fn keeps_vex_order_without_a_report() {
        let document = vex(json!([finding("A"), finding("B"), finding("C")]));

        with_temp_document(&document, |path| {
            let written: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let vulnerabilities = written["vulnerabilities"].as_array().unwrap();

            let severities = severities(path);
            assert!(severities.is_empty());
            assert_eq!(display_order(vulnerabilities, &severities), vec![0, 1, 2]);
        });
    }

    #[test]
    fn reads_severity_by_package_and_cve() {
        let document = vex(json!([finding("GHSA-1")]));

        with_temp_document(&document, |path| {
            write_report(
                path,
                json!([
                    { "product": "vite", "version": "8.0.16", "cve_number": "GHSA-1", "severity": "HIGH", "score": "7.5" },
                    { "product": "other", "version": "1.0.0", "cve_number": "GHSA-1", "severity": "LOW", "score": "2.0" },
                ]),
            );

            let severities = severities(path);
            let severity = severities
                .get(&("vite@8.0.16".to_string(), "GHSA-1".to_string()))
                .unwrap();
            assert_eq!(severity.name, "HIGH");
            assert_eq!(severity.score, "7.5");
        });
    }

    #[test]
    fn finds_a_project_by_the_name_in_its_vex() {
        let document = vex(json!([]));
        with_temp_document(&document, |path| {
            let output = path.parent().unwrap();

            assert_eq!(find_vex(output, "goalkeepr").unwrap(), path.to_path_buf());
            assert_eq!(find_vex(output, "GOALKEEPR").unwrap(), path.to_path_buf());
        });
    }

    #[test]
    fn finds_a_project_by_its_directory_name() {
        let mut document = vex(json!([]));
        document["metadata"]["component"]["name"] = json!("other");

        with_temp_document(&document, |path| {
            // The VEX lives in a directory named after the project.
            let project = path.parent().unwrap().join("goalkeepr");
            std::fs::create_dir_all(&project).unwrap();
            std::fs::rename(path, project.join(VEX_NAME)).unwrap();

            assert_eq!(
                find_vex(path.parent().unwrap(), "goalkeepr").unwrap(),
                project.join(VEX_NAME)
            );
        });
    }

    #[test]
    fn reports_a_project_with_no_vex() {
        let document = vex(json!([]));
        with_temp_document(&document, |path| {
            let error = find_vex(path.parent().unwrap(), "missing").unwrap_err();
            assert!(matches!(error, TriageError::NoVex { .. }));
            assert!(error.to_string().contains("missing"));
        });
    }

    #[test]
    fn breaks_long_descriptions_on_word_boundaries() {
        let lines = wrap("one two three four five", 9);
        assert_eq!(lines, vec!["one two", "three", "four five"]);
    }

    #[test]
    fn leaves_short_descriptions_alone() {
        assert_eq!(wrap("short text", 72), vec!["short text"]);
    }
}
