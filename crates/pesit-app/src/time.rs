//! Time helpers.

use chrono::{SecondsFormat, Utc};

/// Current time in RFC 3339 with milliseconds (`2026-08-28T20:00:00.123Z`).
#[must_use]
pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Current time as `yyyyMMdd_HHmmss`.
#[must_use]
pub fn now_compact() -> String {
    Utc::now().format("%Y%m%d_%H%M%S").to_string()
}

/// Current date as `yyyy-MM-dd`.
#[must_use]
pub fn today() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

/// Current time as `HH-mm-ss`.
#[must_use]
pub fn now_time() -> String {
    Utc::now().format("%H-%M-%S").to_string()
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// Parse an RFC 3339 timestamp to milliseconds since the epoch.
#[must_use]
pub fn parse_millis(iso: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(iso)
        .ok()
        .map(|d| d.timestamp_millis())
}

/// PeSIT date/time (`yyMMddHHmmss`) for now.
#[must_use]
pub fn pesit_now() -> String {
    Utc::now().format("%y%m%d%H%M%S").to_string()
}
