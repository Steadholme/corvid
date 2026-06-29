//! Advisory SPF (RFC 7208) check on the `MAIL FROM` domain.
//!
//! v1 is ADVISORY ONLY: the inbound MTA records the result in a `Received-SPF` header and
//! NEVER hard-rejects on it. The evaluation is intentionally bounded — it handles the
//! mechanisms that matter for a simple sender policy (`ip4`, `a`, `mx`, `all`) plus qualifiers;
//! `include`/`redirect`/`exists`/`ptr`/`ip6` are treated as non-matching (so they fall through
//! to the record's `all`). That is sufficient for an advisory header and avoids unbounded
//! recursion.

use std::net::Ipv4Addr;

use crate::dns;

/// The outcome of an SPF evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl SpfResult {
    /// The lowercase token used in the `Received-SPF` header.
    pub fn token(self) -> &'static str {
        match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
        }
    }
}

/// Evaluate SPF for `domain` from connecting IPv4 `client_ip`.
pub async fn check(domain: &str, client_ip: Ipv4Addr) -> SpfResult {
    let txts = match dns::resolve_txt(domain).await {
        Ok(t) => t,
        Err(_) => return SpfResult::TempError,
    };
    let Some(record) = txts.into_iter().find(|t| t.trim_start().starts_with("v=spf1")) else {
        return SpfResult::None;
    };

    for term in record.split_whitespace().skip(1) {
        let (qual, mech) = split_qualifier(term);
        if mechanism_matches(mech, domain, client_ip).await {
            return qual;
        }
    }
    // No mechanism matched and no `all` present -> neutral.
    SpfResult::Neutral
}

/// Split a leading qualifier (`+`/`-`/`~`/`?`) off a mechanism, defaulting to `+` (Pass).
fn split_qualifier(term: &str) -> (SpfResult, &str) {
    match term.chars().next() {
        Some('+') => (SpfResult::Pass, &term[1..]),
        Some('-') => (SpfResult::Fail, &term[1..]),
        Some('~') => (SpfResult::SoftFail, &term[1..]),
        Some('?') => (SpfResult::Neutral, &term[1..]),
        _ => (SpfResult::Pass, term),
    }
}

async fn mechanism_matches(mech: &str, domain: &str, ip: Ipv4Addr) -> bool {
    let lower = mech.to_ascii_lowercase();
    if lower == "all" {
        return true;
    }
    if let Some(spec) = lower.strip_prefix("ip4:") {
        return ip4_matches(spec, ip);
    }
    if lower == "a" || lower.starts_with("a:") {
        let target = lower.strip_prefix("a:").unwrap_or(domain);
        if let Ok(ips) = dns::resolve_a(target).await {
            return ips.contains(&ip);
        }
        return false;
    }
    if lower == "mx" || lower.starts_with("mx:") {
        let target = lower.strip_prefix("mx:").unwrap_or(domain);
        if let Ok(mxs) = dns::resolve_mx(target).await {
            for mx in mxs {
                if let Ok(ips) = dns::resolve_a(&mx.exchange).await {
                    if ips.contains(&ip) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    // include / redirect / exists / ptr / ip6 -> treated as non-matching (advisory v1).
    false
}

/// Match an IPv4 against an `ip4:addr` or `ip4:addr/prefix` spec.
fn ip4_matches(spec: &str, ip: Ipv4Addr) -> bool {
    let (addr, prefix) = match spec.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().unwrap_or(32)),
        None => (spec, 32),
    };
    let Ok(net) = addr.parse::<Ipv4Addr>() else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask: u32 = u32::MAX << (32 - prefix);
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip4_cidr_matching() {
        let ip: Ipv4Addr = "159.195.136.226".parse().unwrap();
        assert!(ip4_matches("159.195.136.226", ip));
        assert!(ip4_matches("159.195.136.0/24", ip));
        assert!(ip4_matches("159.195.0.0/16", ip));
        assert!(!ip4_matches("10.0.0.0/8", ip));
        assert!(!ip4_matches("garbage", ip));
    }

    #[test]
    fn qualifier_parsing() {
        assert_eq!(split_qualifier("-all").0, SpfResult::Fail);
        assert_eq!(split_qualifier("~all").0, SpfResult::SoftFail);
        assert_eq!(split_qualifier("?all").0, SpfResult::Neutral);
        assert_eq!(split_qualifier("ip4:1.2.3.4").0, SpfResult::Pass);
        assert_eq!(split_qualifier("+mx").1, "mx");
    }
}
