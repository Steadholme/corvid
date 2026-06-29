//! Small shared helpers (time, ids, line I/O).

use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Read a single CRLF/LF-terminated line (returned WITHOUT the terminator), buffering any
/// surplus bytes in `leftover` for the next call. `Ok(None)` on clean EOF with no pending data.
/// Errors if a line exceeds `max` bytes without a terminator (defends against unbounded input).
pub async fn read_line<S>(
    s: &mut S,
    leftover: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Option<String>>
where
    S: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 2048];
    loop {
        if let Some(pos) = leftover.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = leftover.drain(..=pos).collect();
            line.pop(); // '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        if leftover.len() > max {
            return Err(std::io::Error::other("line too long"));
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            if leftover.is_empty() {
                return Ok(None);
            }
            let line = std::mem::take(leftover);
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        leftover.extend_from_slice(&tmp[..n]);
    }
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh opaque id with a type prefix (e.g. `m_…`). 12 random bytes -> 24 hex chars.
pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

/// The current time formatted as an RFC 2822 mail `Date:` value.
pub fn email_date() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_string())
}

/// A fresh `Message-ID` value (`<random@domain>`).
pub fn message_id(domain: &str) -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("<{}.{}@{}>", now_secs(), hex::encode(bytes), domain)
}

/// The domain part of an address (lowercased), if present.
pub fn domain_of(addr: &str) -> Option<String> {
    addr.rsplit_once('@').map(|(_, d)| d.trim().to_lowercase())
}
