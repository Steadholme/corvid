//! Minimal, defensive RFC822/MIME parsing for display.
//!
//! This is NOT a full MIME implementation — it extracts exactly what the webmail needs:
//! `From`/`To`/`Subject`/`Date`/`Message-ID` (RFC 2047 encoded-words decoded) plus a best-effort
//! plain-text body and a sanitised HTML body. It handles:
//! - header unfolding + case-insensitive lookup,
//! - RFC 2047 `=?charset?B/Q?...?=` words (UTF-8 / ASCII) in display headers,
//! - single-part bodies with `quoted-printable` / `base64` transfer encodings,
//! - recursive `multipart/*` (picking the text/plain and text/html alternatives).
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
/// Recurses through nested multipart trees (e.g. mixed -> related -> alternative).
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
        let disposition = header(&phdrs, "content-disposition").unwrap_or_default();
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

        if !is_body_part(&pct, &disposition) {
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

/// Decode a body according to its `Content-Transfer-Encoding` (lossy UTF-8 for display).
fn decode_cte(body: &str, cte: &str) -> String {
    String::from_utf8_lossy(&decode_cte_bytes(body, cte)).into_owned()
}

/// Decode a body according to its `Content-Transfer-Encoding` into raw bytes (attachment payloads
/// are binary — base64/quoted-printable are undone verbatim, unknown/`8bit` pass through).
fn decode_cte_bytes(body: &str, cte: &str) -> Vec<u8> {
    match cte.trim().to_ascii_lowercase().as_str() {
        "base64" => {
            use base64::Engine;
            let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            match base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => body.as_bytes().to_vec(),
            }
        }
        "quoted-printable" => qp_bytes(body),
        _ => body.as_bytes().to_vec(),
    }
}

/// Decode a quoted-printable string to text (soft line breaks + `=XX` octets, lossy UTF-8).
fn decode_quoted_printable(s: &str) -> String {
    String::from_utf8_lossy(&qp_bytes(s)).into_owned()
}

/// Decode a quoted-printable string into raw bytes (soft line breaks + `=XX` octets).
fn qp_bytes(s: &str) -> Vec<u8> {
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
    out
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

// ---------------------------------------------------------------------------
// Attachments — enumerate + extract the file parts of a stored multipart message.
// ---------------------------------------------------------------------------

/// One decoded attachment part of a message (filename, MIME type, raw bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    /// The declared file name (already sanitised: no path separators / control chars).
    pub filename: String,
    /// The base MIME type (`type/subtype`, no parameters), defaulting to
    /// `application/octet-stream`.
    pub content_type: String,
    /// The decoded payload bytes.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttachmentPart {
    attachment: Attachment,
    content_id: Option<String>,
    inline: bool,
}

/// Lightweight metadata for one attachment, used to render the read-view download list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// 0-based position among all extractable attachment parts — the stable download key.
    pub index: usize,
    pub filename: String,
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: usize,
}

/// Metadata for an inline attachment addressable from `cid:` URLs in an HTML body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineAttachmentMeta {
    /// 0-based position among all extractable attachment parts, matching [`extract_attachment`].
    pub index: usize,
    /// Normalised `Content-ID` without angle brackets.
    pub content_id: String,
    pub filename: String,
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: usize,
}

/// Enumerate the attachment parts of a raw message (Content-Disposition: attachment, or any part
/// carrying a `filename`/`name`). Best effort: an empty list for a single-part / text-only body.
pub fn list_attachments(raw: &str) -> Vec<AttachmentMeta> {
    collect_attachment_parts(raw)
        .into_iter()
        .enumerate()
        .filter(|(_, part)| !part.inline)
        .map(|(index, part)| AttachmentMeta {
            index,
            filename: part.attachment.filename,
            content_type: part.attachment.content_type,
            size: part.attachment.data.len(),
        })
        .collect()
}

/// Enumerate inline parts with a `Content-ID`, used to rewrite `cid:` image references.
pub fn list_inline_attachments(raw: &str) -> Vec<InlineAttachmentMeta> {
    collect_attachment_parts(raw)
        .into_iter()
        .enumerate()
        .filter_map(|(index, part)| {
            if !part.inline {
                return None;
            }
            let content_id = part.content_id?;
            Some(InlineAttachmentMeta {
                index,
                content_id,
                filename: part.attachment.filename,
                content_type: part.attachment.content_type,
                size: part.attachment.data.len(),
            })
        })
        .collect()
}

/// Extract the Nth attachment by the stable index exposed on [`AttachmentMeta`] and
/// [`InlineAttachmentMeta`].
pub fn extract_attachment(raw: &str, index: usize) -> Option<Attachment> {
    extract_attachment_with_inline(raw, index).map(|(attachment, _)| attachment)
}

/// Extract the Nth attachment and whether it should be served inline.
pub fn extract_attachment_with_inline(raw: &str, index: usize) -> Option<(Attachment, bool)> {
    let mut all = collect_attachment_parts(raw);
    (index < all.len()).then(|| {
        let part = all.swap_remove(index);
        (part.attachment, part.inline)
    })
}

/// Walk a message's MIME parts collecting extractable file/inline parts with decoded bodies.
fn collect_attachment_parts(raw: &str) -> Vec<AttachmentPart> {
    let (headers, body) = split_headers_body(raw);
    let hdrs = parse_headers(headers);
    let ct = header(&hdrs, "content-type").unwrap_or_default();
    let mut out = Vec::new();
    if ct.to_ascii_lowercase().starts_with("multipart/") {
        if let Some(boundary) = param(&ct, "boundary") {
            walk_attachments(&boundary, body, &mut out);
        }
    }
    out
}

/// Recurse the parts of a multipart body, pushing every attachment part into `out`.
fn walk_attachments(boundary: &str, body: &str, out: &mut Vec<AttachmentPart>) {
    let delim = format!("--{boundary}");
    for part in body.split(&delim) {
        let part = part.trim_start_matches(['\r', '\n']);
        if part.is_empty() || part.starts_with("--") {
            continue; // preamble or the closing `--boundary--`
        }
        let (phdr_block, pbody) = split_headers_body(part);
        let phdrs = parse_headers(phdr_block);
        let pct = header(&phdrs, "content-type").unwrap_or_default();
        let pct_lower = pct.to_ascii_lowercase();

        if pct_lower.starts_with("multipart/") {
            if let Some(inner) = param(&pct, "boundary") {
                walk_attachments(&inner, pbody, out);
            }
            continue;
        }

        let disposition = header(&phdrs, "content-disposition").unwrap_or_default();
        let disposition_kind = disposition_kind(&disposition);
        let is_attach = disposition_kind == "attachment";
        let content_type = content_type_base(&pct);
        let content_id = header(&phdrs, "content-id").and_then(|v| normalize_content_id(&v));
        let filename = param(&disposition, "filename").or_else(|| param(&pct, "name"));
        let is_inline = !is_attach
            && (disposition_kind == "inline"
                || (content_id.is_some() && content_type.starts_with("image/")));
        // A part is an attachment when it is explicitly dispositioned so, or names a file.
        let Some(name) = filename
            .filter(|n| !n.trim().is_empty())
            .or_else(|| is_attach.then(|| "attachment.bin".to_string()))
            .or_else(|| is_inline.then(|| "inline.bin".to_string()))
        else {
            continue;
        };

        let pcte = header(&phdrs, "content-transfer-encoding").unwrap_or_default();
        out.push(AttachmentPart {
            attachment: Attachment {
                filename: sanitize_filename(&name),
                content_type,
                data: decode_cte_bytes(pbody, &pcte),
            },
            content_id,
            inline: is_inline,
        });
    }
}

fn is_body_part(content_type: &str, disposition: &str) -> bool {
    let kind = disposition_kind(disposition);
    if kind == "attachment" {
        return false;
    }
    param(disposition, "filename").is_none() && param(content_type, "name").is_none()
}

fn disposition_kind(disposition: &str) -> String {
    disposition
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// The base `type/subtype` of a Content-Type value (parameters stripped), lowercased; defaults to
/// `application/octet-stream` for a blank/garbage value. Sanitised for safe header echoing.
pub fn content_type_base(ct: &str) -> String {
    let base = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();
    if clean.is_empty() {
        "application/octet-stream".to_string()
    } else {
        clean
    }
}

/// Sanitise an attachment file name for safe use in a `Content-Disposition` header and on disk:
/// drop path separators (`/`, `\`), control chars and quotes, keep the basename, cap the length.
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .take(200)
        .collect();
    if clean.is_empty() {
        "attachment.bin".to_string()
    } else {
        clean
    }
}

/// Normalise a Content-ID for matching against `cid:` URLs: strip brackets and compare
/// case-insensitively.
pub fn normalize_content_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let trimmed = trimmed
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(trimmed)
        .trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
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

    #[test]
    fn lists_and_extracts_mixed_attachment() {
        // multipart/mixed: a text body + one base64 file part ("hi\n").
        let raw = "Content-Type: multipart/mixed; boundary=\"MM\"\r\n\r\n\
                   --MM\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
                   --MM\r\nContent-Type: text/plain; name=\"note.txt\"\r\n\
                   Content-Transfer-Encoding: base64\r\n\
                   Content-Disposition: attachment; filename=\"note.txt\"\r\n\r\naGkK\r\n--MM--\r\n";

        // The body still decodes; the attachment is NOT mistaken for the body.
        let p = parse(raw);
        assert!(p.body_text.contains("see attached"));

        let metas = list_attachments(raw);
        assert_eq!(metas.len(), 1, "one attachment enumerated");
        assert_eq!(metas[0].index, 0);
        assert_eq!(metas[0].filename, "note.txt");
        assert_eq!(metas[0].content_type, "text/plain");
        assert_eq!(metas[0].size, 3, "decoded 'hi\\n'");

        let att = extract_attachment(raw, 0).expect("attachment 0 present");
        assert_eq!(att.data, b"hi\n");
        assert_eq!(att.filename, "note.txt");
        assert!(extract_attachment(raw, 1).is_none(), "no second attachment");
    }

    #[test]
    fn recurses_related_alternative_and_tracks_inline_cid() {
        let raw = "Content-Type: multipart/mixed; boundary=\"M\"\r\n\r\n\
                   --M\r\nContent-Type: multipart/related; boundary=\"R\"\r\n\r\n\
                   --R\r\nContent-Type: multipart/alternative; boundary=\"A\"\r\n\r\n\
                   --A\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain body\r\n\
                   --A\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
                   <p>rich <img src=\"cid:logo@example\"></p>\r\n--A--\r\n\
                   --R\r\nContent-Type: image/png; name=\"logo.png\"\r\n\
                   Content-Disposition: inline; filename=\"logo.png\"\r\n\
                   Content-ID: <logo@example>\r\n\
                   Content-Transfer-Encoding: base64\r\n\r\naW1n\r\n--R--\r\n\
                   --M\r\nContent-Type: text/plain; name=\"note.txt\"\r\n\
                   Content-Transfer-Encoding: base64\r\n\
                   Content-Disposition: attachment; filename=\"note.txt\"\r\n\r\nZmlsZQ==\r\n--M--\r\n";

        let parsed = parse(raw);
        assert!(parsed.body_text.contains("plain body"));
        assert!(
            parsed
                .body_html
                .contains("<img src=\"cid:logo@example\" />")
        );

        let inline = list_inline_attachments(raw);
        assert_eq!(inline.len(), 1);
        assert_eq!(inline[0].index, 0);
        assert_eq!(inline[0].content_id, "logo@example");
        assert_eq!(inline[0].filename, "logo.png");

        let visible = list_attachments(raw);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].index, 1);
        assert_eq!(visible[0].filename, "note.txt");

        let (img, is_inline) = extract_attachment_with_inline(raw, inline[0].index).unwrap();
        assert!(is_inline);
        assert_eq!(img.data, b"img");
        let (note, is_inline) = extract_attachment_with_inline(raw, visible[0].index).unwrap();
        assert!(!is_inline);
        assert_eq!(note.data, b"file");
    }

    #[test]
    fn plain_message_has_no_attachments() {
        let raw = "Content-Type: text/plain\r\n\r\njust text\r\n";
        assert!(list_attachments(raw).is_empty());
        assert!(extract_attachment(raw, 0).is_none());
    }

    #[test]
    fn sanitize_filename_strips_paths_and_controls() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\Users\\evil\\note.txt"), "note.txt");
        assert_eq!(sanitize_filename("a\"b.txt"), "ab.txt");
        assert_eq!(sanitize_filename("  \t "), "attachment.bin");
    }

    #[test]
    fn content_type_base_strips_params_and_defaults() {
        assert_eq!(content_type_base("text/plain; charset=utf-8"), "text/plain");
        assert_eq!(content_type_base(""), "application/octet-stream");
        assert_eq!(content_type_base("IMAGE/PNG"), "image/png");
    }
}
