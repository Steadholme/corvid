//! DKIM signing + verification (RFC 6376), reusing the existing OpenDKIM key.
//!
//! Outbound mail is signed with the SAME private key the host Postfix/OpenDKIM already uses
//! (`/etc/opendkim/keys/w33d.xyz/default.private`, a PKCS#8 PEM), selector `default`,
//! `d=w33d.xyz`, so the published `default._domainkey.w33d.xyz` TXT keeps verifying with ZERO
//! DNS change. Algorithm: `rsa-sha256`, canonicalisation `relaxed/relaxed`, signed headers
//! From,To,Subject,Date,Message-ID,MIME-Version,Content-Type.
//!
//! [`verify`] re-implements the verifier independently (recompute body hash + header hash, then
//! RSA-verify against an SPKI DER public key) so the sign/verify round-trip — and a test that
//! verifies against the REAL published key params — proves the signature is valid.

use base64::Engine;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::rfc822::{header, parse_headers, split_headers_body};

/// Header fields signed, in order (also the `h=` list).
pub const SIGNED_HEADERS: &[&str] = &[
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
];

/// DKIM error surface.
#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    #[error("read key file {0}: {1}")]
    KeyFile(String, std::io::Error),
    #[error("decode private key: {0}")]
    PrivateKey(String),
    #[error("decode public key: {0}")]
    PublicKey(String),
    #[error("sign: {0}")]
    Sign(String),
    #[error("no DKIM-Signature header present")]
    NoSignature,
    #[error("malformed DKIM-Signature: {0}")]
    Malformed(String),
}

/// An outbound DKIM signer bound to one key + selector + domain.
pub struct DkimSigner {
    key: RsaPrivateKey,
    pub selector: String,
    pub domain: String,
}

impl DkimSigner {
    /// Load the signer from a PKCS#8 PEM private-key file (the OpenDKIM `default.private`).
    pub fn from_key_file(path: &str, selector: &str, domain: &str) -> Result<Self, DkimError> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| DkimError::KeyFile(path.to_string(), e))?;
        Self::from_pkcs8_pem(&pem, selector, domain)
    }

    /// Load the signer from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str, selector: &str, domain: &str) -> Result<Self, DkimError> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| DkimError::PrivateKey(e.to_string()))?;
        Ok(Self {
            key,
            selector: selector.to_string(),
            domain: domain.to_string(),
        })
    }

    /// Sign `raw` (full RFC822) and return the message with a `DKIM-Signature:` header
    /// prepended. Uses the current time for `t=`.
    pub fn sign(&self, raw: &str) -> Result<String, DkimError> {
        self.sign_at(raw, now_secs())
    }

    /// Sign with an explicit `t=` (deterministic, for tests).
    pub fn sign_at(&self, raw: &str, t: i64) -> Result<String, DkimError> {
        let (header_block, body) = split_headers_body(raw);
        let hdrs = parse_headers(header_block);

        // Body hash (bh=) over the relaxed-canonicalised body.
        let canon_body = canonicalize_body_relaxed(body);
        let bh = b64(&Sha256::digest(canon_body.as_bytes()));

        // Canonicalised signed headers, in the configured order, present ones only.
        let mut canon_headers = String::new();
        let mut present: Vec<&str> = Vec::new();
        for name in SIGNED_HEADERS {
            let lname = name.to_ascii_lowercase();
            if let Some(v) = header(&hdrs, &lname) {
                canon_headers.push_str(&canon_header_relaxed(&lname, &v, true));
                present.push(name);
            }
        }
        let h_tag = present.join(":");

        // The DKIM-Signature value WITHOUT the b= value (b= empty), used in the header hash.
        let dkim_value = format!(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
            self.domain, self.selector, t, h_tag, bh
        );
        let canon_dkim = canon_header_relaxed("dkim-signature", &dkim_value, false);

        let mut to_sign = canon_headers;
        to_sign.push_str(&canon_dkim);
        let digest = Sha256::digest(to_sign.as_bytes());

        let sig = self
            .key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| DkimError::Sign(e.to_string()))?;
        let b = b64(&sig);

        let header_line = format!("DKIM-Signature: {dkim_value}{b}");
        Ok(format!("{header_line}\r\n{raw}"))
    }
}

/// Verify the `DKIM-Signature` of `raw` against an SPKI DER public key. Returns `Ok(true)`
/// only when both the body hash and the RSA signature check out.
pub fn verify(raw: &str, public_key_der: &[u8]) -> Result<bool, DkimError> {
    let pubkey = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| DkimError::PublicKey(e.to_string()))?;

    let (header_block, body) = split_headers_body(raw);
    let hdrs = parse_headers(header_block);
    let dkim_raw = header(&hdrs, "dkim-signature").ok_or(DkimError::NoSignature)?;
    let tags = parse_tags(&dkim_raw);

    let bh_expected = strip_ws(tags.get("bh").ok_or_else(|| DkimError::Malformed("no bh".into()))?);
    let b_b64 = strip_ws(tags.get("b").ok_or_else(|| DkimError::Malformed("no b".into()))?);
    let h_list = tags.get("h").ok_or_else(|| DkimError::Malformed("no h".into()))?;

    // Body hash must match.
    let canon_body = canonicalize_body_relaxed(body);
    let bh = b64(&Sha256::digest(canon_body.as_bytes()));
    if bh != bh_expected {
        return Ok(false);
    }

    // Rebuild the signed header set listed in h=.
    let mut canon_headers = String::new();
    for name in h_list.split(':') {
        let lname = name.trim().to_ascii_lowercase();
        if let Some(v) = header(&hdrs, &lname) {
            canon_headers.push_str(&canon_header_relaxed(&lname, &v, true));
        }
    }
    // The DKIM-Signature header itself, with the b= value blanked, no trailing CRLF.
    let dkim_no_b = strip_b_value(&dkim_raw);
    let canon_dkim = canon_header_relaxed("dkim-signature", &dkim_no_b, false);

    let mut to_verify = canon_headers;
    to_verify.push_str(&canon_dkim);
    let digest = Sha256::digest(to_verify.as_bytes());

    let sig = base64::engine::general_purpose::STANDARD
        .decode(b_b64.as_bytes())
        .map_err(|e| DkimError::Malformed(format!("b= not base64: {e}")))?;

    Ok(pubkey
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig)
        .is_ok())
}

/// Build an SPKI DER public key from a DKIM TXT `p=` base64 value (whitespace tolerant).
pub fn public_key_der_from_p(p_b64: &str) -> Result<Vec<u8>, DkimError> {
    let compact = strip_ws(p_b64);
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| DkimError::PublicKey(format!("p= not base64: {e}")))
}

/// Extract the `p=` value from an OpenDKIM `default.txt` record (the `( "..." "..." )` form).
pub fn extract_p_from_txt(txt: &str) -> Option<String> {
    // Concatenate all quoted chunks, then read the value after `p=` up to the next `"` / `;`.
    let mut joined = String::new();
    let mut in_q = false;
    for c in txt.chars() {
        match c {
            '"' => in_q = !in_q,
            _ if in_q => joined.push(c),
            _ => {}
        }
    }
    let idx = joined.find("p=")?;
    let after = &joined[idx + 2..];
    let end = after.find(';').unwrap_or(after.len());
    Some(strip_ws(&after[..end]))
}

// ---------------------------------------------------------------------------
// Canonicalisation (relaxed/relaxed)
// ---------------------------------------------------------------------------

/// Relaxed header canonicalisation of a single (already unfolded) header.
/// `terminate` appends the CRLF (false for the trailing DKIM-Signature header).
fn canon_header_relaxed(name: &str, value: &str, terminate: bool) -> String {
    let name = name.to_ascii_lowercase();
    let v = collapse_wsp(value);
    let v = v.trim();
    if terminate {
        format!("{name}:{v}\r\n")
    } else {
        format!("{name}:{v}")
    }
}

/// Relaxed body canonicalisation: collapse WSP runs, strip trailing line WSP, drop trailing
/// empty lines, ensure a single trailing CRLF (empty body -> empty string).
fn canonicalize_body_relaxed(body: &str) -> String {
    let normalized = body.replace("\r\n", "\n");
    let mut lines: Vec<String> = normalized
        .split('\n')
        .map(|line| collapse_wsp(line).trim_end_matches([' ', '\t']).to_string())
        .collect();
    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return String::new();
    }
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out
}

/// Collapse every run of spaces/tabs to a single space (leaves other chars untouched).
fn collapse_wsp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_ws = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !prev_ws {
                out.push(' ');
            }
            prev_ws = true;
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out
}

/// Parse the `tag=value` pairs of a DKIM-Signature value into a map.
fn parse_tags(value: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for seg in value.split(';') {
        if let Some((k, v)) = seg.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// Blank the `b=` tag's value, preserving all other text (including exact spacing) byte-for-byte.
/// `split(';')`/`join(';')` round-trips the delimiters exactly, so only the b value changes.
fn strip_b_value(value: &str) -> String {
    value
        .split(';')
        .map(|seg| {
            if let Some(eq) = seg.find('=') {
                if seg[..eq].trim() == "b" {
                    return format!("{}=", &seg[..eq]);
                }
            }
            seg.to_string()
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Strip ALL whitespace (folding in `b=`/`bh=`/`p=` is insignificant).
fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Current wall-clock time in epoch seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_and_canon() {
        assert_eq!(collapse_wsp("a   b\t c"), "a b c");
        assert_eq!(canon_header_relaxed("Subject", "  hi   there  ", true), "subject:hi there\r\n");
    }

    #[test]
    fn body_canon_drops_trailing_blank_lines() {
        let c = canonicalize_body_relaxed("line one  \r\nline two\r\n\r\n\r\n");
        assert_eq!(c, "line one\r\nline two\r\n");
    }

    #[test]
    fn strip_b_keeps_layout_and_other_tags() {
        let v = "v=1; a=rsa-sha256; bh=AAAA; b=ZZZZ";
        assert_eq!(strip_b_value(v), "v=1; a=rsa-sha256; bh=AAAA; b=");
        // bh must be untouched even though it contains a 'b'.
        assert!(strip_b_value(v).contains("bh=AAAA"));
    }
}
