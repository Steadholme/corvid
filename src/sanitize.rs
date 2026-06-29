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
//!    as the forum markdown renderer, plus `alt`/`title`), so `onerror=`, `style=`, etc. never
//!    reach the output.
//! 4. Escapes stray `<` that do not start a recognised tag.
//!
//! This is deliberately strict rather than clever: unknown markup degrades to text, never to
//! executable HTML.

/// Tags whose start/end delimiters are preserved (their content is always kept as text).
const ALLOWED_TAGS: &[&str] = &[
    "a", "b", "i", "u", "em", "strong", "p", "br", "hr", "span", "div", "blockquote", "pre",
    "code", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "thead", "tbody",
    "tr", "td", "th", "img", "small", "sub", "sup", "dl", "dt", "dd",
];

/// Blocks dropped wholesale (tag + everything up to the matching close tag).
const DROP_BLOCKS: &[&str] = &["script", "style", "title", "head", "iframe", "object", "embed"];

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
            _ => false,
        };
        if keep {
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

/// Escape a value for safe inclusion inside a double-quoted attribute.
fn esc_attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;")
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
}
