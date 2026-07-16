//! Temporary-mail core: SSO-owned disposable addresses.
//!
//! Only an SSO-authenticated webmail user can provision a temporary address. The HTTP handlers
//! live in [`crate::webmail`] so they inherit the gateway-verified identity, CSRF protection and
//! the sanitized message-render pipeline. This module owns the security-relevant logic:
//! ownership model, quota, unguessable address generation and TTL garbage collection.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::model::Mailbox;
use crate::store::StoreError;
use crate::{now_secs, AppState};

/// Synthetic `owner_sub` marking a mailbox temporary AND binding it to its SSO creator. Using a
/// prefixed form keeps temporary mailboxes out of the primary-inbox view (which matches
/// `owner_sub == user_sub` exactly) while still tying every temp address to one accountable user.
pub(crate) fn temporary_mailbox_owner(user_sub: &str) -> String {
    format!("temp:{user_sub}")
}

/// The SSO sub that owns a temporary mailbox, or `None` for a permanent mailbox.
pub(crate) fn temp_owner_user(mb: &Mailbox) -> Option<&str> {
    mb.owner_sub.strip_prefix("temp:")
}

/// A mailbox is temporary iff its owner carries the `temp:` marker.
pub(crate) fn is_temporary_mailbox(mb: &Mailbox) -> bool {
    mb.owner_sub.starts_with("temp:")
}

/// Whether `user_sub` owns temporary mailbox `mb` (authorization for read/delete).
pub(crate) fn owned_by(mb: &Mailbox, user_sub: &str) -> bool {
    temp_owner_user(mb) == Some(user_sub)
}

/// Whether a temporary mailbox is still live at `now` (not past its TTL).
pub(crate) fn is_live(mb: &Mailbox, now: i64) -> bool {
    mb.expires_at > now
}

/// A 96-bit CSPRNG local-part, lowercase ASCII only for compatibility with strict registration
/// forms. The `g` lead guarantees a letter-initial local-part.
fn random_local_part() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("g{}", hex::encode(bytes))
}

/// Why a provisioning request was refused.
pub(crate) enum ProvisionError {
    /// Temporary mail is not configured (no dedicated domains).
    Disabled,
    /// The user already holds the maximum number of active temporary addresses.
    QuotaExceeded,
    /// A storage failure occurred.
    Storage,
}

/// Provision a fresh temporary address for `user_sub`.
///
/// Security: enforces the per-user quota BEFORE creating anything, picks a random allowlisted
/// domain and a 96-bit random local-part (collision-checked against existing mailboxes), and
/// stores the mailbox with a hard TTL. The address is receive-only — it is never granted
/// submission credentials, so it can never send outbound mail.
pub(crate) async fn provision(state: &AppState, user_sub: &str) -> Result<String, ProvisionError> {
    if !state.config.temp_mail_enabled() {
        return Err(ProvisionError::Disabled);
    }
    let owner = temporary_mailbox_owner(user_sub);
    let limit = state.config.temp_mail_max_per_user;
    let now = now_secs();
    let active = state
        .store
        .list_temp_mailboxes(&owner)
        .await
        .map_err(|_| ProvisionError::Storage)?
        .into_iter()
        .filter(|mb| is_live(mb, now))
        .count();
    if active >= limit {
        return Err(ProvisionError::QuotaExceeded);
    }

    let domain = state
        .config
        .random_temp_mail_domain()
        .ok_or(ProvisionError::Disabled)?;

    let address = loop {
        let candidate = format!("{}@{}", random_local_part(), domain);
        match state.store.get_mailbox(&candidate).await {
            Ok(None) => break candidate,
            Ok(Some(_)) => continue,
            Err(_) => return Err(ProvisionError::Storage),
        }
    };

    let mailbox = Mailbox {
        addr: address.clone(),
        owner_sub: owner,
        expires_at: now.saturating_add(state.config.temp_mail_ttl_secs),
    };
    state
        .store
        .upsert_mailbox(&mailbox)
        .await
        .map_err(|_| ProvisionError::Storage)?;
    Ok(address)
}

/// Delete a temporary mailbox and its messages, but only if `user_sub` owns it. Returns whether
/// a mailbox was actually removed (`false` when it does not exist or belongs to someone else).
pub(crate) async fn release(
    state: &AppState,
    user_sub: &str,
    address: &str,
) -> Result<bool, StoreError> {
    let addr = address.to_ascii_lowercase();
    let owner = temporary_mailbox_owner(user_sub);
    state.store.delete_owned_temp_mailbox(&addr, &owner).await
}

/// Garbage-collect every temporary mailbox whose TTL elapsed. Returns the number removed.
pub(crate) async fn gc_expired(state: &AppState) -> usize {
    let now = now_secs();
    let expired = match state.store.expired_temp_mailboxes(now).await {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!("temporary-mail GC scan failed");
            return 0;
        }
    };
    let mut removed = 0;
    for addr in expired {
        match state.store.delete_expired_temp_mailbox(&addr, now).await {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(_) => tracing::warn!("temporary-mail GC delete failed"),
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_mb(addr: &str, user: &str, expires_at: i64) -> Mailbox {
        Mailbox {
            addr: addr.to_string(),
            owner_sub: temporary_mailbox_owner(user),
            expires_at,
        }
    }

    #[test]
    fn ownership_model_isolates_temp_from_primary_and_across_users() {
        let mb = temp_mb("g0@tmp.w33d.xyz", "u_alice", 100);
        assert!(is_temporary_mailbox(&mb));
        assert_eq!(temp_owner_user(&mb), Some("u_alice"));
        assert!(owned_by(&mb, "u_alice"));
        assert!(!owned_by(&mb, "u_bob"));

        let primary = Mailbox {
            addr: "w33d@w33d.xyz".to_string(),
            owner_sub: "u_alice".to_string(),
            expires_at: 0,
        };
        assert!(!is_temporary_mailbox(&primary));
        assert_eq!(temp_owner_user(&primary), None);
    }

    #[test]
    fn liveness_tracks_ttl() {
        let mb = temp_mb("g0@tmp.w33d.xyz", "u_alice", 100);
        assert!(is_live(&mb, 99));
        assert!(!is_live(&mb, 100));
        assert!(!is_live(&mb, 101));
    }

    #[test]
    fn local_parts_are_random_and_form_compatible() {
        let a = random_local_part();
        let b = random_local_part();
        assert_eq!(a.len(), 25);
        assert!(a.starts_with('g'));
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_ne!(a, b);
    }
}
