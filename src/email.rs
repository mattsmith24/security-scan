//! Email alerts sent when a scan finishes.
//!
//! Settings come from [`Config`]: the message is built from the projects a
//! scan reported on, and sending uses the SMTP relay configured alongside the
//! recipients. The pieces are added in this module so that the console scan
//! output stays independent of email.

use lettre::message::Mailbox;

use crate::config::{Config, Tls};

/// The prefix that starts every alert's subject.
pub const SUBJECT_PREFIX: &str = "[security-scan]";

/// Everything needed to build and send an alert.
#[derive(Debug, Clone)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub user: Option<String>,
    pub password: Option<String>,
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub prefix: String,
}

impl Settings {
    /// Build the alert settings from a loaded config.
    ///
    /// Returns `None` when email is off, which includes an `email = false`
    /// switch and any config missing recipients, a from address or an SMTP
    /// host.
    pub fn from_config(config: &Config) -> Option<Self> {
        if !config.email_enabled() {
            return None;
        }

        let smtp = config.smtp_settings()?;
        let from = config.email_from()?.clone();

        Some(Self {
            host: smtp.host.clone(),
            port: smtp.port,
            tls: smtp.tls,
            user: smtp.user.clone(),
            password: config.smtp_password().map(str::to_string),
            from,
            to: config.email_recipients().to_vec(),
            prefix: SUBJECT_PREFIX.to_string(),
        })
    }
}

/// Problems with the settings that do not stop an alert from being sent.
///
/// Gmail only accepts the authenticated address, or an alias verified for it,
/// in `From`. A different address usually means the message is rejected, so
/// say so before the scan runs rather than after it finishes.
pub fn warnings(settings: &Settings) -> Vec<String> {
    let Some(user) = settings.user.as_deref() else {
        return Vec::new();
    };

    let from = settings.from.email.to_string();
    if from.eq_ignore_ascii_case(user) {
        return Vec::new();
    }

    vec![format!(
        "warning: email_from ({from}) differs from smtp_user ({user}); \
         Gmail only accepts the authenticated address or a verified alias"
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Tls;

    fn settings(from: &str, user: Option<&str>) -> Settings {
        Settings {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls: Tls::Starttls,
            user: user.map(str::to_string),
            password: user.map(|_| "app password".to_string()),
            from: from.parse().unwrap(),
            to: vec!["scan@example.com".parse().unwrap()],
            prefix: SUBJECT_PREFIX.to_string(),
        }
    }

    #[test]
    fn warns_when_from_differs_from_the_smtp_user() {
        let warnings = warnings(&settings("alerts@example.com", Some("scan@example.com")));

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("alerts@example.com"));
        assert!(warnings[0].contains("scan@example.com"));
        assert!(warnings[0].contains("verified alias"));
    }

    #[test]
    fn matching_addresses_do_not_warn() {
        assert!(warnings(&settings("scan@example.com", Some("scan@example.com"))).is_empty());
    }

    #[test]
    fn the_comparison_ignores_case() {
        assert!(warnings(&settings("Scan@Example.com", Some("scan@example.com"))).is_empty());
    }

    #[test]
    fn the_comparison_ignores_the_display_name() {
        let warnings = warnings(&settings(
            "Security Scan <scan@example.com>",
            Some("scan@example.com"),
        ));

        assert!(warnings.is_empty());
    }

    #[test]
    fn a_local_relay_without_a_user_does_not_warn() {
        assert!(warnings(&settings("scan@example.com", None)).is_empty());
    }
}
