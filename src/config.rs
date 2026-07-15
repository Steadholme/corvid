//! Runtime configuration, env-driven with working dev defaults.
//!
//! Every value keeps a dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database (the webmail render tests
//! and the SMTP state-machine tests need nothing). Production / the alt-port smoke override
//! each via the environment.
//!
//! Mail addressing model:
//! - `mail_domain` is the canonical sending domain (`w33d.xyz`, used for DKIM `d=` + the
//!   primary mailbox).
//! - `mail_hosts` is the set of recipient domains the inbound MTA accepts as "local"
//!   (`w33d.xyz` + `mail.w33d.xyz`).
//! - `local_parts` is the set of deliverable local-parts (`w33d`/`admin`/`postmaster`); each
//!   resolves to the single primary mailbox. `catchall` (off by default) additionally accepts
//!   any unknown local-part into the primary mailbox.

/// Default listen addresses — ALT ports on purpose (NEVER :25 in the build/test phase).
pub const DEFAULT_SMTP_ADDR: &str = "0.0.0.0:2525";
pub const DEFAULT_SUBMISSION_ADDR: &str = "0.0.0.0:2587";
pub const DEFAULT_WEBMAIL_ADDR: &str = "0.0.0.0:8800";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Inbound MTA listen address (`SMTP_ADDR`).
    pub smtp_addr: String,
    /// Submission listen address (`SUBMISSION_ADDR`).
    pub submission_addr: String,
    /// Webmail HTTP listen address (`WEBMAIL_ADDR`).
    pub webmail_addr: String,
    /// PEM cert chain for STARTTLS (`TLS_CERT`); empty disables STARTTLS advertisement.
    pub tls_cert: String,
    /// PEM private key for STARTTLS (`TLS_KEY`).
    pub tls_key: String,
    /// DKIM private key path (`DKIM_KEY_PATH`) — the existing OpenDKIM key.
    pub dkim_key_path: String,
    /// DKIM selector (`DKIM_SELECTOR`, default `default`).
    pub dkim_selector: String,
    /// Canonical mail domain (`MAIL_DOMAIN`) — DKIM `d=` + primary mailbox host.
    pub mail_domain: String,
    /// Recipient domains accepted as local (`MAIL_HOSTS`, comma-separated).
    pub mail_hosts: Vec<String>,
    /// Deliverable local-parts (lowercased).
    pub local_parts: Vec<String>,
    /// When true, unknown local-parts at a local host are accepted into the primary mailbox.
    pub catchall: bool,
    /// SMTP banner / EHLO hostname (`MAIL_HOSTNAME`, default `mail.<mail_domain>`).
    pub hostname: String,
    /// Max accepted message size in bytes (`MAX_MSG_SIZE`).
    pub max_msg_size: usize,
    /// Max recipients per transaction (`MAX_RCPTS`).
    pub max_rcpts: usize,
    /// Bearer token guarding the internal send API (`MAIL_SEND_TOKEN`). Empty disables the API.
    pub mail_send_token: String,
    /// Dedicated domains for SSO-provisioned temporary mailboxes (`TEMP_MAIL_DOMAINS`,
    /// comma-separated). MUST be distinct from `mail_hosts` so a temp address can never shadow a
    /// real mailbox. Empty disables temporary mail; a fresh address picks a random domain.
    pub temp_mail_domains: Vec<String>,
    /// Max active temporary mailboxes one SSO user may hold (`TEMP_MAIL_MAX_PER_USER`, default 10).
    pub temp_mail_max_per_user: usize,
    /// Temporary mailbox lifetime in seconds (`TEMP_MAIL_TTL_DAYS` days, default 7). GC'd after.
    pub temp_mail_ttl_secs: i64,
    /// SMTP submission (:587) AUTH username (`SUBMISSION_USER`). Empty falls back to the
    /// primary mailbox address.
    pub submission_user: String,
    /// SMTP submission AUTH password (`SUBMISSION_PASSWORD`). **Empty = fail-secure: the
    /// submission relay refuses every transaction** (no AUTH can succeed), so :587 is never
    /// an open relay even before an operator sets a credential.
    pub submission_password: String,
}

impl Config {
    /// Default development configuration (in-memory, no database, no TLS, no DKIM file).
    pub fn dev() -> Self {
        Config {
            smtp_addr: DEFAULT_SMTP_ADDR.to_string(),
            submission_addr: DEFAULT_SUBMISSION_ADDR.to_string(),
            webmail_addr: DEFAULT_WEBMAIL_ADDR.to_string(),
            tls_cert: String::new(),
            tls_key: String::new(),
            dkim_key_path: "/etc/opendkim/keys/w33d.xyz/default.private".to_string(),
            dkim_selector: "default".to_string(),
            mail_domain: "w33d.xyz".to_string(),
            mail_hosts: vec!["w33d.xyz".to_string(), "mail.w33d.xyz".to_string()],
            local_parts: vec![
                "w33d".to_string(),
                "admin".to_string(),
                "postmaster".to_string(),
            ],
            catchall: false,
            hostname: "mail.w33d.xyz".to_string(),
            max_msg_size: 10 * 1024 * 1024,
            max_rcpts: 100,
            mail_send_token: String::new(),
            temp_mail_domains: Vec::new(),
            temp_mail_max_per_user: 10,
            temp_mail_ttl_secs: 7 * 24 * 60 * 60,
            submission_user: String::new(),
            submission_password: String::new(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut c = Config::dev();
        if let Some(v) = env_nonempty("SMTP_ADDR") {
            c.smtp_addr = v;
        }
        if let Some(v) = env_nonempty("SUBMISSION_ADDR") {
            c.submission_addr = v;
        }
        if let Some(v) = env_nonempty("WEBMAIL_ADDR") {
            c.webmail_addr = v;
        }
        if let Some(v) = env_nonempty("TLS_CERT") {
            c.tls_cert = v;
        }
        if let Some(v) = env_nonempty("TLS_KEY") {
            c.tls_key = v;
        }
        if let Some(v) = env_nonempty("DKIM_KEY_PATH") {
            c.dkim_key_path = v;
        }
        if let Some(v) = env_nonempty("DKIM_SELECTOR") {
            c.dkim_selector = v;
        }
        if let Some(v) = env_nonempty("MAIL_DOMAIN") {
            c.mail_domain = v;
            // Keep the default hostname tracking the domain unless explicitly set.
            c.hostname = format!("mail.{}", c.mail_domain);
            c.mail_hosts = vec![c.mail_domain.clone(), format!("mail.{}", c.mail_domain)];
        }
        if let Some(v) = env_nonempty("MAIL_HOSTS") {
            c.mail_hosts = split_csv(&v);
        }
        if let Some(v) = env_nonempty("MAIL_LOCAL_PARTS") {
            c.local_parts = split_csv(&v).into_iter().map(|s| s.to_lowercase()).collect();
        }
        if let Some(v) = env_nonempty("MAIL_HOSTNAME") {
            c.hostname = v;
        }
        if env_flag("CORVID_CATCHALL") {
            c.catchall = true;
        }
        if let Some(v) = env_nonempty("MAX_MSG_SIZE").and_then(|s| s.parse().ok()) {
            c.max_msg_size = v;
        }
        if let Some(v) = env_nonempty("MAX_RCPTS").and_then(|s| s.parse().ok()) {
            c.max_rcpts = v;
        }
        if let Some(v) = env_nonempty("MAIL_SEND_TOKEN") {
            c.mail_send_token = v;
        }
        if let Some(v) = env_nonempty("TEMP_MAIL_MAX_PER_USER").and_then(|s| s.parse().ok()) {
            c.temp_mail_max_per_user = v;
        }
        if let Some(v) = env_nonempty("TEMP_MAIL_TTL_DAYS").and_then(|s| s.parse::<i64>().ok()) {
            c.temp_mail_ttl_secs = v.max(1) * 24 * 60 * 60;
        }
        if let Some(v) = env_nonempty("TEMP_MAIL_DOMAINS") {
            c.temp_mail_domains = split_csv(&v)
                .into_iter()
                .map(|domain| domain.to_ascii_lowercase())
                .collect();
        }
        if let Some(v) = env_nonempty("SUBMISSION_USER") {
            c.submission_user = v;
        }
        if let Some(v) = env_nonempty("SUBMISSION_PASSWORD") {
            c.submission_password = v;
        }
        c
    }

    /// Effective submission AUTH username: the configured `SUBMISSION_USER`, or the primary
    /// mailbox address when unset.
    pub fn submission_login(&self) -> String {
        if self.submission_user.is_empty() {
            self.primary_mailbox()
        } else {
            self.submission_user.clone()
        }
    }

    /// True when a submission credential is configured (so :587 can accept authenticated relay).
    /// When false the submission listener is fail-secure (rejects all relay).
    pub fn submission_enabled(&self) -> bool {
        !self.submission_password.is_empty()
    }

    /// The primary mailbox address (`w33d@<mail_domain>`) all local-parts deliver into.
    pub fn primary_mailbox(&self) -> String {
        format!("w33d@{}", self.mail_domain)
    }

    /// True when STARTTLS material is configured.
    pub fn tls_enabled(&self) -> bool {
        !self.tls_cert.is_empty() && !self.tls_key.is_empty()
    }

    /// Whether `domain` is explicitly allowlisted for temporary mailboxes.
    pub fn is_temp_mail_domain(&self, domain: &str) -> bool {
        self.temp_mail_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain.trim()))
    }

    /// Whether SSO-provisioned temporary mail is enabled (at least one dedicated domain).
    pub fn temp_mail_enabled(&self) -> bool {
        !self.temp_mail_domains.is_empty()
    }

    /// Pick a random allowlisted temporary-mail domain (uniform over the pool).
    pub fn random_temp_mail_domain(&self) -> Option<String> {
        use rand::seq::SliceRandom;
        self.temp_mail_domains.choose(&mut rand::rngs::OsRng).cloned()
    }

    /// Resolve a recipient address to its local mailbox, or `None` when not deliverable here.
    ///
    /// Accepts the address iff the domain is one of `mail_hosts` AND the local-part is in
    /// `local_parts` (or `catchall` is on). Every accepted recipient maps to the single
    /// primary mailbox (`w33d`/`admin`/`postmaster` are aliases of one inbox in v1).
    pub fn resolve_local(&self, addr: &str) -> Option<String> {
        let (lp, domain) = addr.rsplit_once('@')?;
        let lp = lp.to_lowercase();
        let domain = domain.to_lowercase();
        if !self.mail_hosts.iter().any(|h| h.eq_ignore_ascii_case(&domain)) {
            return None;
        }
        if self.local_parts.iter().any(|p| p == &lp) || self.catchall {
            Some(self.primary_mailbox())
        } else {
            None
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// A truthy env flag (`1`/`true`/`yes`, case-insensitive).
fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref().map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Split a comma-separated list, trimming and dropping empties.
fn split_csv(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_local_accepts_known_parts() {
        let c = Config::dev();
        assert_eq!(c.resolve_local("w33d@w33d.xyz").as_deref(), Some("w33d@w33d.xyz"));
        assert_eq!(c.resolve_local("admin@mail.w33d.xyz").as_deref(), Some("w33d@w33d.xyz"));
        assert_eq!(c.resolve_local("POSTMASTER@W33D.XYZ").as_deref(), Some("w33d@w33d.xyz"));
        assert!(c.resolve_local("nobody@w33d.xyz").is_none());
        assert!(c.resolve_local("w33d@example.com").is_none());
        assert!(c.resolve_local("malformed").is_none());
    }

    #[test]
    fn catchall_accepts_unknown_parts() {
        let mut c = Config::dev();
        c.catchall = true;
        assert_eq!(c.resolve_local("random@w33d.xyz").as_deref(), Some("w33d@w33d.xyz"));
        assert!(c.resolve_local("random@elsewhere.net").is_none());
    }

    #[test]
    fn temp_mail_domains_are_exact_and_do_not_enable_catchall() {
        let mut c = Config::dev();
        c.temp_mail_domains = vec![
            "mx.w33d.xyz".to_string(),
            "inbox.box.mx.w33d.xyz".to_string(),
        ];

        assert!(c.is_temp_mail_domain("MX.W33D.XYZ"));
        assert!(c.is_temp_mail_domain("inbox.box.mx.w33d.xyz"));
        assert!(!c.is_temp_mail_domain("w33d.xyz"));
        assert!(!c.is_temp_mail_domain("evil-mx.w33d.xyz"));
        assert!(c.resolve_local("anything@mx.w33d.xyz").is_none());
        assert!(c.resolve_local("anything@w33d.xyz").is_none());
    }
}
