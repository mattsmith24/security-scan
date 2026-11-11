//! Dates and times, in the forms the scanner needs them.
//!
//! The scanner reads dates out of other tools' output: cdxgen's timestamps,
//! and the dates cve-bin-tool records for the vulnerabilities it knows
//! about. Those dates come in a few shapes — `2026-11-05`, `2026-11-05T00:00:00Z`
//! — so they are all parsed the same way here.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format a Unix timestamp as an RFC 3339 UTC timestamp.
pub fn format_rfc3339(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    )
}

/// Parse a date or timestamp into a Unix timestamp.
///
/// The date is the first ten characters, `YYYY-MM-DD`, and anything after it
/// — a time of day, a `Z` — is ignored, so that the time of day does not
/// depend on which format a tool happened to write. A date that cannot be
/// read, or that is not a real date, gives `None`.
pub fn parse_timestamp(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.len() < 10 {
        return None;
    }

    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: u32 = text.get(5..7)?.parse().ok()?;
    let day: u32 = text.get(8..10)?.parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400)
}

/// The number of seconds since the Unix epoch, for a time.
pub fn unix_seconds(time: SystemTime) -> Option<i64> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_secs()).ok()
}

/// Convert a count of days since the Unix epoch into a calendar date.
///
/// This is Howard Hinnant's `civil_from_days` algorithm.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };

    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Convert a calendar date into a count of days since the Unix epoch.
///
/// This is Howard Hinnant's `days_from_civil` algorithm, the inverse of
/// `civil_from_days`.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn formats_a_known_timestamp() {
        // 2023-11-14T22:13:20Z
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn formats_a_leap_day() {
        // 2024-02-29T12:00:00Z
        assert_eq!(format_rfc3339(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn formats_the_end_of_a_year() {
        // 2025-12-31T23:59:59Z
        assert_eq!(format_rfc3339(1_767_225_599), "2025-12-31T23:59:59Z");
    }

    #[test]
    fn parses_a_date() {
        assert_eq!(parse_timestamp("2026-11-05"), Some(1_793_836_800));
    }

    #[test]
    fn parses_a_timestamp() {
        assert_eq!(parse_timestamp("2026-11-05T00:00:00Z"), Some(1_793_836_800));
    }

    #[test]
    fn parses_a_timestamp_with_a_time() {
        // The time of day is ignored, so that a date and a timestamp for
        // the same day are the same date.
        assert_eq!(parse_timestamp("2026-11-05T13:45:02"), Some(1_793_836_800));
    }

    #[test]
    fn refuses_dates_it_cannot_read() {
        assert_eq!(parse_timestamp(""), None);
        assert_eq!(parse_timestamp("9999-12-05"), Some(253_399_968_000));
        assert_eq!(parse_timestamp("not a date"), None);
        assert_eq!(parse_timestamp("2026-13-01"), None);
        assert_eq!(parse_timestamp("2026-00-10"), None);
    }

    #[test]
    fn round_trips_dates() {
        for days in [-1_000_000, 0, 1, 19_000, 100_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
    }

    #[test]
    fn converts_dates_to_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 11, 5), 20_762);
    }
}
