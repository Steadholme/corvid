//! Corvid — sovereign mail server for the Steadholme stack.
//!
//! One cohesive service with four cooperating parts, all sharing one [`Store`]:
//! 1. an inbound ESMTP MTA ([`smtp`]) that accepts mail for the local mailboxes and stores it,
//! 2. a submission listener + outbound [`relay`] that DKIM-signs and delivers via destination MX,
//! 3. [`dkim`] signing that REUSES the existing OpenDKIM key (selector `default`, `d=w33d.xyz`),
//! 4. a [`webmail`] (axum) client served behind the gateway SSO at `mail.w33d.xyz`.
//!
//! The build needs NO database and NO network: the default store is in-memory and the SMTP
//! state machine + webmail render are driven in-process by the tests.

pub mod config;
pub mod delivery;
pub mod dkim;
pub mod dns;
pub mod model;
pub mod relay;
pub mod rfc822;
pub mod sanitize;
pub mod smtp;
pub mod spf;
pub mod store;
pub mod temp_mail;
pub mod util;
pub mod webmail;

use std::io::BufReader;
use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::dkim::DkimSigner;
use crate::model::Mailbox;
use crate::smtp::{run_listener, SmtpContext, SmtpRole};
use crate::store::{InMemoryStore, PgStore, Store};

pub use crate::util::{new_id, now_secs};

/// Shared webmail application state (cheap to clone — everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub signer: Option<Arc<DkimSigner>>,
}

/// Build the webmail router for `state` (used by `run` + the integration tests).
pub fn app(state: AppState) -> axum::Router {
    webmail::app(state)
}

/// The primary mailbox seeded into every deployment (`w33d@<domain>`, owner sub `w33d`).
fn primary_mailbox(config: &Config) -> Mailbox {
    Mailbox {
        addr: config.primary_mailbox(),
        owner_sub: "w33d".to_string(),
        expires_at: 0,
    }
}

/// Dev state: in-memory store with the primary mailbox seeded, dev config, no DKIM signer.
pub async fn build_dev_state() -> AppState {
    let config = Config::dev();
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_mailbox(&primary_mailbox(&config))
        .await
        .expect("in-memory seed never fails");
    AppState {
        config: Arc::new(config),
        store,
        signer: None,
    }
}

/// Build runtime state from the environment.
///
/// Store selected by `CORVID_STORE` (`memory` default | `postgres`). The DKIM signer is loaded
/// from `DKIM_KEY_PATH` when readable (a missing/unreadable key disables outbound signing rather
/// than failing startup). The primary mailbox is always provisioned (idempotent upsert).
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("CORVID_STORE").unwrap_or_else(|_| "memory".to_string());
    let require_persistence = require_persistence();
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let url = std::env::var("DATABASE_URL")
                .map_err(|_| "CORVID_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("CORVID_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&url).await.map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate().await.map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => {
            // Refuse to ride the volatile in-memory store when durability is required
            // (STEADHOLME_PROFILE=prod or REQUIRE_PERSISTENCE): every accepted message would be
            // lost on restart. Startup-only hard failure — never mid-request.
            if require_persistence {
                return Err(
                    "durability required (STEADHOLME_PROFILE=prod or REQUIRE_PERSISTENCE) but \
                     CORVID_STORE resolves to the volatile in-memory store: set CORVID_STORE=postgres \
                     and DATABASE_URL to persist mail"
                        .to_string(),
                );
            }
            Arc::new(InMemoryStore::new())
        }
        other => return Err(format!("unknown CORVID_STORE={other} (use memory|postgres)")),
    };
    tracing::info!(store = %store_kind, "durability posture");

    store
        .upsert_mailbox(&primary_mailbox(&config))
        .await
        .map_err(|e| format!("seed mailbox: {e}"))?;

    let signer = match DkimSigner::from_key_file(&config.dkim_key_path, &config.dkim_selector, &config.mail_domain) {
        Ok(s) => {
            tracing::info!(path = %config.dkim_key_path, selector = %config.dkim_selector, "DKIM signer loaded");
            Some(Arc::new(s))
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %config.dkim_key_path, "DKIM key unavailable — outbound signing disabled");
            None
        }
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        signer,
    })
}

/// True when this deployment must run on a durable store: `STEADHOLME_PROFILE=prod`
/// (case-insensitive) OR a truthy `REQUIRE_PERSISTENCE`. When false (the default, e.g. dev with
/// `STEADHOLME_PROFILE` unset) the in-memory store stays permitted.
fn require_persistence() -> bool {
    let profile_prod = std::env::var("STEADHOLME_PROFILE")
        .map(|v| v.trim().eq_ignore_ascii_case("prod"))
        .unwrap_or(false);
    profile_prod || env_truthy("REQUIRE_PERSISTENCE")
}

/// A truthy env flag (`1`/`true`/`yes`/`on`, case-insensitive). Mirrors `config::env_flag`.
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref().map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Build a STARTTLS acceptor from the configured cert/key, or `None` when TLS is not configured.
pub fn build_tls_acceptor(config: &Config) -> Result<Option<TlsAcceptor>, String> {
    if !config.tls_enabled() {
        return Ok(None);
    }
    install_crypto_provider();

    let cert_pem = std::fs::read(&config.tls_cert).map_err(|e| format!("read TLS_CERT: {e}"))?;
    let key_pem = std::fs::read(&config.tls_key).map_err(|e| format!("read TLS_KEY: {e}"))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(&cert_pem[..]))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse certs: {e}"))?;
    if certs.is_empty() {
        return Err("TLS_CERT contained no certificates".to_string());
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(&key_pem[..]))
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or_else(|| "TLS_KEY contained no private key".to_string())?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("build server config: {e}"))?;
    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

/// Install the `ring` crypto provider as the process default (idempotent).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Run the whole service: spawn the SMTP + submission listeners and the relay worker, then serve
/// the webmail in the foreground.
pub async fn run() -> Result<(), String> {
    install_crypto_provider();

    let state = build_state_from_env().await?;
    let config = state.config.clone();

    // Temporary mail no longer uses a separate anonymous listener — provisioning is SSO-gated
    // inside the webmail (see `temp_mail` + the /temp routes).

    let tls_acceptor = build_tls_acceptor(&config).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "TLS disabled (STARTTLS unavailable)");
        None
    });

    let ctx = Arc::new(SmtpContext {
        config: config.clone(),
        store: state.store.clone(),
        signer: state.signer.clone(),
        tls_acceptor,
    });

    // Inbound MTA.
    {
        let ctx = ctx.clone();
        let addr = config.smtp_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = run_listener(&addr, ctx, SmtpRole::Mta).await {
                tracing::error!(error = %e, "inbound MTA listener exited");
            }
        });
    }
    // Submission.
    {
        let ctx = ctx.clone();
        let addr = config.submission_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = run_listener(&addr, ctx, SmtpRole::Submission).await {
                tracing::error!(error = %e, "submission listener exited");
            }
        });
    }
    // Outbound relay worker.
    {
        let store = state.store.clone();
        let hostname = config.hostname.clone();
        let try_tls = std::env::var("RELAY_STARTTLS").map(|v| v != "0").unwrap_or(true);
        tokio::spawn(async move {
            relay::run_worker(store, hostname, try_tls).await;
        });
    }
    // Temporary-mail TTL garbage collector. SSO users provision disposable addresses from the
    // webmail itself (no separate listener); this background task reaps expired mailboxes hourly.
    if config.temp_mail_enabled() {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let removed = temp_mail::gc_expired(&state).await;
                if removed > 0 {
                    tracing::info!(removed, "temporary-mail GC reaped expired mailboxes");
                }
            }
        });
    }

    // Webmail (foreground).
    let addr: std::net::SocketAddr = config
        .webmail_addr
        .parse()
        .map_err(|e| format!("invalid WEBMAIL_ADDR: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind webmail {addr}: {e}"))?;
    tracing::info!(%addr, "Corvid webmail listening");
    axum::serve(listener, app(state))
        .await
        .map_err(|e| format!("webmail server error: {e}"))
}
