//! Progress messages while a scan runs.
//!
//! Results go to stdout, so that whatever runs the scanner can read them.
//! Progress goes to stderr and is flushed as it is written: when a scan is
//! waiting on a slow download, the last line printed is the only thing
//! saying what it is waiting for.

use std::io::Write;
use std::time::{Duration, Instant};

/// Print a line at the start of a scan.
pub fn heading(message: impl AsRef<str>) {
    write(message.as_ref(), 0);
}

/// Print an indented progress line, below the scan it belongs to.
pub fn status(message: impl AsRef<str>) {
    write(message.as_ref(), 1);
}

/// Write a progress line, indenting it `depth` levels.
fn write(message: &str, depth: usize) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{:indent$}{message}", "", indent = depth * 2);
    let _ = stderr.flush();
}

/// A step of a scan, timed so that it can say how long it took.
pub struct Step {
    started: Instant,
}

impl Step {
    /// Announce that a step has begun.
    pub fn start(label: impl AsRef<str>) -> Self {
        status(label);

        Self {
            started: Instant::now(),
        }
    }

    /// Report that the step finished, and what came of it.
    pub fn finish(self, detail: impl AsRef<str>) {
        status(format!(
            "{} ({})",
            detail.as_ref(),
            format_duration(self.started.elapsed())
        ));
    }
}

/// How long something took, in words.
fn format_duration(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();

    if seconds < 1.0 {
        format!("{}ms", elapsed.as_millis())
    } else if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        format!("{}m {:02}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_short_durations_in_milliseconds() {
        assert_eq!(format_duration(Duration::from_millis(240)), "240ms");
    }

    #[test]
    fn describes_seconds_with_one_decimal() {
        assert_eq!(format_duration(Duration::from_millis(1_240)), "1.2s");
    }

    #[test]
    fn describes_minutes_and_seconds() {
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 05s");
    }
}
