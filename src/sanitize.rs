//! Conservative allow-list HTML sanitiser for rendering received mail in the webmail.
//!
//! Incoming mail HTML is hostile by default, so before it is embedded in a page it is run
//! through a hand-written tokeniser that:
//!
//! 1. DROPS `<script>` / `<style>` blocks entirely (tag AND content), so no active content or
//!    CSS-based exfiltration survives.
//! 2. Keeps only an allow-list of structural/formatting tags; any other tag's delimiters are
//!    removed (its text content is preserved as plain text).
//! 3. Strips every attribute except a tiny safe set (`href`/`src` scheme-checked the same way
//!    as the forum markdown renderer, plus `alt`/`title` and colour-only `span style`), so
//!    `onerror=` and layout/scriptable style never reach the output.
//! 4. Escapes stray `<` that do not start a recognised tag.
//!
//! This is deliberately strict rather than clever: unknown markup degrades to text, never to
//! executable HTML.

/// Tags whose start/end delimiters are preserved (their content is always kept as text).
const ALLOWED_TAGS: &[&str] = &[
    "a",
    "b",
    "i",
    "u",
    "em",
    "strong",
    "p",
    "br",
    "hr",
    "span",
    "div",
    "blockquote",
    "pre",
    "code",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "thead",
    "tbody",
    "tr",
    "td",
    "th",
    "img",
    "small",
    "sub",
    "sup",
    "dl",
    "dt",
    "dd",
];

/// Blocks dropped wholesale (tag + everything up to the matching close tag).
const DROP_BLOCKS: &[&str] = &[
    "script", "style", "title", "head", "iframe", "object", "embed",
];

/// Sanitise `html`, returning a string safe to embed directly inside page markup.
pub fn sanitize_html(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    let n = bytes.len();
    // When `Some(tag)`, we are skipping the content of a dropped block until its close tag.
    let mut skipping: Option<String> = None;

    while i < n {
        let c = bytes[i] as char;
        if c != '<' {
            if skipping.is_none() {
                out.push(c);
            }
            i += 1;
            continue;
        }

        // Comment / doctype / processing instruction — drop to the next '>'.
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map(|p| i + p + 3).unwrap_or(n);
            continue;
        }
        if i + 1 < n && (bytes[i + 1] == b'!' || bytes[i + 1] == b'?') {
            i = html[i..].find('>').map(|p| i + p + 1).unwrap_or(n);
            continue;
        }

        // Find the end of this tag, honouring quotes so a quoted '>' does not end it early.
        let Some(end) = find_tag_end(bytes, i) else {
            // Unterminated '<' — emit as escaped text.
            if skipping.is_none() {
                out.push_str("&lt;");
            }
            i += 1;
            continue;
        };
        let raw_tag = &html[i + 1..end]; // between '<' and '>'
        i = end + 1;

        let (name, is_close) = tag_name(raw_tag);
        if name.is_empty() {
            // e.g. a lone '<' followed by punctuation — already consumed; ignore.
            continue;
        }

        // Currently skipping a dropped block: only its matching close tag ends the skip.
        if let Some(skip) = &skipping {
            if is_close && name == *skip {
                skipping = None;
            }
            continue;
        }

        if DROP_BLOCKS.contains(&name.as_str()) {
            if !is_close && !is_self_closing(raw_tag) {
                skipping = Some(name);
            }
            continue;
        }

        if !ALLOWED_TAGS.contains(&name.as_str()) {
            // Unknown tag: drop the delimiters, keep surrounding text.
            continue;
        }

        if is_close {
            out.push_str(&format!("</{name}>"));
        } else {
            out.push_str(&rebuild_open_tag(&name, raw_tag, is_self_closing(raw_tag)));
        }
    }

    out
}

/// Index of the closing '>' for a tag starting at `start` ('<'), honouring quoted attributes.
fn find_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start + 1;
    let mut quote: Option<u8> = None;
    while j < bytes.len() {
        let b = bytes[j];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Some(j),
                _ => {}
            },
        }
        j += 1;
    }
    None
}

/// Extract the lowercased tag name and whether it is a close tag.
fn tag_name(raw: &str) -> (String, bool) {
    let raw = raw.trim();
    let (is_close, rest) = match raw.strip_prefix('/') {
        Some(r) => (true, r),
        None => (false, raw),
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    (name, is_close)
}

fn is_self_closing(raw: &str) -> bool {
    raw.trim_end().ends_with('/')
}

/// Rebuild an opening tag with only the safe attributes retained.
fn rebuild_open_tag(name: &str, raw: &str, self_closing: bool) -> String {
    let mut out = format!("<{name}");
    for (attr, val) in parse_attrs(raw) {
        let attr = attr.to_ascii_lowercase();
        let keep = match attr.as_str() {
            "href" | "src" => is_safe_url(&val),
            "alt" | "title" => true,
            "style" if name == "span" => sanitize_style(&val).is_some(),
            _ => false,
        };
        if keep {
            let val = if attr == "style" {
                sanitize_style(&val).unwrap_or_default()
            } else {
                val
            };
            out.push_str(&format!(" {}=\"{}\"", attr, esc_attr(&val)));
        }
    }
    if self_closing || matches!(name, "br" | "hr" | "img") {
        out.push_str(" />");
    } else {
        out.push('>');
    }
    out
}

/// Parse `attr="val"` / `attr='val'` / `attr=val` / bare `attr` pairs from a tag's interior.
fn parse_attrs(raw: &str) -> Vec<(String, String)> {
    // Drop the leading tag name (and any leading '/').
    let raw = raw.trim().trim_start_matches('/');
    let rest = match raw.find(|c: char| c.is_whitespace()) {
        Some(p) => &raw[p..],
        None => return Vec::new(),
    };
    let chars: Vec<char> = rest.chars().collect();
    let mut attrs = Vec::new();
    let mut k = 0;
    let len = chars.len();
    while k < len {
        while k < len && (chars[k].is_whitespace() || chars[k] == '/') {
            k += 1;
        }
        if k >= len {
            break;
        }
        let name_start = k;
        while k < len && chars[k] != '=' && !chars[k].is_whitespace() && chars[k] != '/' {
            k += 1;
        }
        let name: String = chars[name_start..k].iter().collect();
        if name.is_empty() {
            k += 1;
            continue;
        }
        while k < len && chars[k].is_whitespace() {
            k += 1;
        }
        let mut value = String::new();
        if k < len && chars[k] == '=' {
            k += 1;
            while k < len && chars[k].is_whitespace() {
                k += 1;
            }
            if k < len && (chars[k] == '"' || chars[k] == '\'') {
                let q = chars[k];
                k += 1;
                let vstart = k;
                while k < len && chars[k] != q {
                    k += 1;
                }
                value = chars[vstart..k].iter().collect();
                k += 1; // skip closing quote
            } else {
                let vstart = k;
                while k < len && !chars[k].is_whitespace() && chars[k] != '/' {
                    k += 1;
                }
                value = chars[vstart..k].iter().collect();
            }
        }
        attrs.push((name, value));
    }
    attrs
}

/// A URL is safe when it is `http(s)`/`mailto`/`cid`, or relative. Any other explicit scheme
/// (`javascript:`, `data:`, …) is rejected. Mirrors the forum markdown renderer.
pub fn is_safe_url(url: &str) -> bool {
    let u = url.trim();
    if u.is_empty() {
        return false;
    }
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("cid:")
    {
        return true;
    }
    let sep = u.find(['/', '?', '#']);
    match u.find(':') {
        None => true,
        Some(colon) => matches!(sep, Some(s) if s < colon),
    }
}

/// Keep only colour declarations in a `span style`. Everything layout-affecting or scriptable is
/// dropped, and an empty result removes the style attribute entirely.
fn sanitize_style(style: &str) -> Option<String> {
    let mut kept = Vec::new();
    for decl in style.split(';') {
        let Some((prop, val)) = decl.split_once(':') else {
            continue;
        };
        let prop = prop.trim().to_ascii_lowercase();
        if !matches!(prop.as_str(), "color" | "background-color") {
            continue;
        }
        let val = val.trim();
        if is_safe_css_color(val) {
            kept.push(format!("{prop}: {val}"));
        }
    }
    (!kept.is_empty()).then(|| kept.join("; "))
}

fn is_safe_css_color(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if lower.contains("url")
        || lower.contains("expression")
        || lower.contains('@')
        || lower.contains('\\')
        || lower.contains('<')
        || lower.contains('>')
        || lower.contains('&')
        || lower.contains('"')
        || lower.contains('\'')
    {
        return false;
    }
    if let Some(hex) = lower.strip_prefix('#') {
        return matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    if lower.chars().all(|c| c.is_ascii_alphabetic()) {
        return true;
    }
    for prefix in ["rgb(", "rgba(", "hsl(", "hsla("] {
        if lower.starts_with(prefix)
            && lower.ends_with(')')
            && lower[prefix.len()..lower.len() - 1].chars().all(|c| {
                c.is_ascii_digit() || c.is_ascii_whitespace() || matches!(c, ',' | '.' | '%' | '/')
            })
        {
            return true;
        }
    }
    false
}

/// Escape a value for safe inclusion inside a double-quoted attribute.
fn esc_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Strip HTML to a readable plain-text fallback for outbound `multipart/alternative`.
pub fn html_to_text(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            let next = html[i..].find('<').map(|p| i + p).unwrap_or(bytes.len());
            out.push_str(&decode_html_entities(&html[i..next]));
            i = next;
            continue;
        }
        let Some(end) = find_tag_end(bytes, i) else {
            out.push('<');
            i += 1;
            continue;
        };
        let raw_tag = &html[i + 1..end];
        let (name, is_close) = tag_name(raw_tag);
        match (name.as_str(), is_close) {
            ("br", _) => out.push('\n'),
            ("li", false) => {
                ensure_newline(&mut out);
                out.push_str("- ");
            }
            ("p" | "div" | "blockquote" | "h1" | "h2" | "h3" | "tr", false) => {
                ensure_newline(&mut out);
            }
            ("p" | "div" | "blockquote" | "h1" | "h2" | "h3" | "li" | "tr", true) => {
                out.push('\n');
            }
            _ => {}
        }
        i = end + 1;
    }
    normalise_text(&out)
}

fn ensure_newline(out: &mut String) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

fn normalise_text(text: &str) -> String {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::new();
    let mut blank = 0;
    for line in text.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            blank += 1;
            if blank <= 1 && !out.is_empty() {
                out.push('\n');
            }
            continue;
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(line);
        out.push('\n');
        blank = 0;
    }
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

fn decode_html_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after_amp = &rest[pos + 1..];
        let Some(end) = after_amp.find(';') else {
            out.push('&');
            rest = after_amp;
            continue;
        };
        let entity = &after_amp[..end];
        if let Some(ch) = decode_entity(entity) {
            out.push(ch);
            rest = &after_amp[end + 1..];
        } else {
            out.push('&');
            rest = after_amp;
        }
    }
    out.push_str(rest);
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(dec) = entity.strip_prefix('#') {
                dec.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                None
            }
        }
    }
}

/// Escape plain text (e.g. a text/plain body rendered into HTML).
pub fn esc_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_script_block_and_content() {
        let out = sanitize_html("before<script>alert(1)</script>after");
        assert!(!out.contains("<script"));
        assert!(!out.contains("alert(1)"));
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn strips_event_handlers_and_keeps_tag() {
        let out = sanitize_html(r#"<p onclick="evil()">hi</p>"#);
        assert!(out.contains("<p>hi</p>"));
        assert!(!out.contains("onclick"));
    }

    #[test]
    fn defuses_javascript_links() {
        let out = sanitize_html(r#"<a href="javascript:alert(1)">x</a>"#);
        assert!(!out.contains("javascript:"));
        assert!(out.contains("<a>x</a>"));
    }

    #[test]
    fn keeps_safe_link() {
        let out = sanitize_html(r#"<a href="https://w33d.xyz/p" onmouseover="x">go</a>"#);
        assert!(out.contains(r#"<a href="https://w33d.xyz/p">go</a>"#));
        assert!(!out.contains("onmouseover"));
    }

    #[test]
    fn keeps_only_safe_span_colour_style() {
        let out = sanitize_html(
            r#"<span style="color:#336699; position:absolute; background-color: rgb(1, 2, 3)">x</span>"#,
        );
        assert_eq!(
            out,
            r#"<span style="color: #336699; background-color: rgb(1, 2, 3)">x</span>"#
        );
        assert!(!out.contains("position"));
    }

    #[test]
    fn drops_dangerous_or_non_span_style() {
        let out = sanitize_html(
            r#"<span style="color:url(javascript:alert(1)); width:10px">x</span><p style="color:red">y</p>"#,
        );
        assert_eq!(out, "<span>x</span><p>y</p>");
    }

    #[test]
    fn drops_unknown_tags_keeps_text() {
        let out = sanitize_html("<marquee>scrolling</marquee>");
        assert_eq!(out, "scrolling");
    }

    #[test]
    fn neutralises_img_onerror() {
        let out = sanitize_html(r#"<img src="x" onerror="alert(1)">"#);
        assert!(!out.contains("onerror"));
        // src "x" is a relative URL -> kept.
        assert!(out.contains("<img src=\"x\" />"));
    }

    #[test]
    fn escapes_stray_lt() {
        let out = sanitize_html("a < b and c");
        assert!(out.contains("a &lt; b and c"));
    }

    #[test]
    fn html_to_text_keeps_readable_blocks_lists_and_entities() {
        let out = html_to_text(
            "<p>Hello&nbsp;<strong>rich</strong></p><ul><li>One</li><li>Two &amp; three</li></ul>",
        );
        assert_eq!(out, "Hello rich\n- One\n- Two & three");
    }
}
