//! Minimal, defensive RFC822/MIME parsing for display.
//!
//! This is NOT a full MIME implementation — it extracts exactly what the webmail needs:
//! `From`/`To`/`Subject`/`Date`/`Message-ID` (RFC 2047 encoded-words decoded) plus a best-effort
//! plain-text body and a sanitised HTML body. It handles:
//! - header unfolding + case-insensitive lookup,
//! - RFC 2047 `=?charset?B/Q?...?=` words (UTF-8 / ASCII) in display headers,
//! - single-part bodies with `quoted-printable` / `base64` transfer encodings,
//! - one level of `multipart/*` (picking the text/plain and text/html alternatives).
//!
//! Anything it cannot decode degrades to the raw text rather than failing.

use crate::sanitize::sanitize_html;

/// The fields the webmail renders from a raw message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub message_id: String,
    /// Decoded plain-text body (best effort).
    pub body_text: String,
    /// Sanitised HTML body (empty when the message has no HTML part).
    pub body_html: String,
}

/// Parse a raw RFC822 message into the display fields.
pub fn parse(raw: &str) -> Parsed {
    let (headers, body) = split_headers_body(raw);
    let hdrs = parse_headers(headers);

    let content_type = header(&hdrs, "content-type").unwrap_or_default();
    let cte = header(&hdrs, "content-transfer-encoding").unwrap_or_default();
    let (body_text, body_html) = extract_body(&content_type, &cte, body);

    Parsed {
        from: decode_words(&header(&hdrs, "from").unwrap_or_default()),
        to: decode_words(&header(&hdrs, "to").unwrap_or_default()),
        subject: decode_words(&header(&hdrs, "subject").unwrap_or_default()),
        date: header(&hdrs, "date").unwrap_or_default(),
        message_id: header(&hdrs, "message-id").unwrap_or_default(),
        body_text,
        body_html,
    }
}

/// Split a message into its header block and body at the first blank line.
pub fn split_headers_body(raw: &str) -> (&str, &str) {
    if let Some(p) = raw.find("\r\n\r\n") {
        (&raw[..p], &raw[p + 4..])
    } else if let Some(p) = raw.find("\n\n") {
        (&raw[..p], &raw[p + 2..])
    } else {
        (raw, "")
    }
}

/// Parse a header block into `(lowercased-name, raw-value)` pairs with folding unwound.
pub fn parse_headers(block: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in block.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if (line.starts_with(' ') || line.starts_with('\t')) && !out.is_empty() {
            // Continuation of the previous header value (folding): join with a single space.
            let last = out.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(line.trim_start());
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    out
}

/// First value for a header name (case-insensitive).
pub fn header(hdrs: &[(String, String)], name: &str) -> Option<String> {
    hdrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}

/// Extract `(text, sanitised_html)` from a body given its content-type + transfer-encoding.
fn extract_body(content_type: &str, cte: &str, body: &str) -> (String, String) {
    let ct_lower = content_type.to_ascii_lowercase();

    if ct_lower.starts_with("multipart/") {
        if let Some(boundary) = param(content_type, "boundary") {
            return extract_multipart(&boundary, body);
        }
    }

    let decoded = decode_cte(body, cte);
    if ct_lower.starts_with("text/html") {
        (html_to_text(&decoded), sanitize_html(&decoded))
    } else {
        // text/plain or unknown -> treat as text.
        (decoded, String::new())
    }
}

/// Walk the parts of a multipart body, picking the text/plain + text/html alternatives.
/// Handles one level of nesting (e.g. multipart/mixed wrapping multipart/alternative).
fn extract_multipart(boundary: &str, body: &str) -> (String, String) {
    let mut text = String::new();
    let mut html = String::new();
    let delim = format!("--{boundary}");

    for part in body.split(&delim) {
        let part = part.trim_start_matches(['\r', '\n']);
        if part.is_empty() || part.starts_with("--") {
            continue; // preamble or the closing `--boundary--`
        }
        let (phdr_block, pbody) = split_headers_body(part);
        let phdrs = parse_headers(phdr_block);
        let pct = header(&phdrs, "content-type").unwrap_or_default();
        let pcte = header(&phdrs, "content-transfer-encoding").unwrap_or_default();
        let pct_lower = pct.to_ascii_lowercase();

        if pct_lower.starts_with("multipart/") {
            if let Some(inner) = param(&pct, "boundary") {
                let (t, h) = extract_multipart(&inner, pbody);
                if text.is_empty() {
                    text = t;
                }
                if html.is_empty() {
                    html = h;
                }
            }
            continue;
        }

        let decoded = decode_cte(pbody, &pcte);
        if pct_lower.starts_with("text/html") && html.is_empty() {
            html = sanitize_html(&decoded);
            if text.is_empty() {
                text = html_to_text(&decoded);
            }
        } else if pct_lower.starts_with("text/plain") && text.is_empty() {
            text = decoded;
        }
    }
    (text, html)
}

/// Decode a body according to its `Content-Transfer-Encoding`.
fn decode_cte(body: &str, cte: &str) -> String {
    match cte.trim().to_ascii_lowercase().as_str() {
        "base64" => {
            use base64::Engine;
            let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            match base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => body.to_string(),
            }
        }
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_string(),
    }
}

/// Decode a quoted-printable string (soft line breaks + `=XX` octets).
fn decode_quoted_printable(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'=' => {
                if i + 1 < bytes.len() && (bytes[i + 1] == b'\r' || bytes[i + 1] == b'\n') {
                    // Soft line break: skip the CR/LF that follow.
                    i += 1;
                    while i < bytes.len() && (bytes[i] == b'\r' || bytes[i] == b'\n') {
                        i += 1;
                    }
                } else if i + 2 < bytes.len() {
                    if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                        out.push(byte);
                        i += 3;
                    } else {
                        out.push(b'=');
                        i += 1;
                    }
                } else {
                    out.push(b'=');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode RFC 2047 encoded-words within a header value (display only).
pub fn decode_words(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        // charset?enc?text?=
        let Some(end) = after.find("?=") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let token = &after[..end];
        let parts: Vec<&str> = token.splitn(3, '?').collect();
        if parts.len() == 3 {
            let enc = parts[1].to_ascii_uppercase();
            let text = parts[2];
            let decoded = match enc.as_str() {
                "B" => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(text.as_bytes())
                        .ok()
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                }
                "Q" => Some(decode_q(text)),
                _ => None,
            };
            match decoded {
                Some(d) => out.push_str(&d),
                None => out.push_str(&rest[start..start + 2 + end + 2]),
            }
        } else {
            out.push_str(&rest[start..start + 2 + end + 2]);
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Decode an RFC 2047 "Q" word (`_` -> space, `=XX` octets).
fn decode_q(s: &str) -> String {
    decode_quoted_printable(&s.replace('_', " "))
}

/// Strip tags from HTML to derive a rough plain-text fallback.
fn html_to_text(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Extract a parameter (e.g. `boundary`, `charset`) from a structured header value.
fn param(value: &str, key: &str) -> Option<String> {
    for seg in value.split(';').skip(1) {
        let seg = seg.trim();
        if let Some((k, v)) = seg.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_plaintext() {
        let raw = "From: Alice <alice@example.com>\r\nTo: w33d@w33d.xyz\r\nSubject: Hi there\r\n\
                   Date: Mon, 29 Jun 2026 10:00:00 +0000\r\nMessage-ID: <abc@example.com>\r\n\r\n\
                   Hello world\r\n";
        let p = parse(raw);
        assert_eq!(p.from, "Alice <alice@example.com>");
        assert_eq!(p.to, "w33d@w33d.xyz");
        assert_eq!(p.subject, "Hi there");
        assert_eq!(p.message_id, "<abc@example.com>");
        assert!(p.body_text.contains("Hello world"));
        assert!(p.body_html.is_empty());
    }

    #[test]
    fn unfolds_headers() {
        let raw = "Subject: a very\r\n long subject\r\nFrom: x@y.z\r\n\r\nbody";
        let p = parse(raw);
        assert_eq!(p.subject, "a very long subject");
    }

    #[test]
    fn decodes_rfc2047_subject() {
        // "héllo" base64 in UTF-8.
        let raw = "Subject: =?UTF-8?B?aMOpbGxv?=\r\nFrom: x@y.z\r\n\r\nb";
        let p = parse(raw);
        assert_eq!(p.subject, "héllo");
    }

    #[test]
    fn decodes_quoted_printable_q_word() {
        let raw = "Subject: =?UTF-8?Q?Caf=C3=A9_time?=\r\nFrom: x@y.z\r\n\r\nb";
        let p = parse(raw);
        assert_eq!(p.subject, "Café time");
    }

    #[test]
    fn sanitises_html_body() {
        let raw = "Content-Type: text/html\r\n\r\n<p>hi</p><script>alert(1)</script>";
        let p = parse(raw);
        assert!(p.body_html.contains("<p>hi</p>"));
        assert!(!p.body_html.contains("<script"));
    }

    #[test]
    fn picks_alternative_parts() {
        let raw = "Content-Type: multipart/alternative; boundary=\"BB\"\r\n\r\n\
                   --BB\r\nContent-Type: text/plain\r\n\r\nplain body\r\n\
                   --BB\r\nContent-Type: text/html\r\n\r\n<b>rich</b>\r\n--BB--\r\n";
        let p = parse(raw);
        assert!(p.body_text.contains("plain body"));
        assert!(p.body_html.contains("<b>rich</b>"));
    }

    #[test]
    fn decodes_base64_body() {
        // "Hello base64" base64-encoded.
        let raw = "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n\
                   SGVsbG8gYmFzZTY0\r\n";
        let p = parse(raw);
        assert!(p.body_text.contains("Hello base64"));
    }
}
