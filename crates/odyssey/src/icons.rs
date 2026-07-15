// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{raw, Html};

/// Canonical Steadholme product mark. The geometry is stable while `currentColor` lets each
/// Odyssey shell inherit its semantic product/accent color instead of freezing an old palette.
pub const STEADHOLME_MARK_SVG: &str = r#"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" stroke="currentColor" stroke-width="2.5" stroke-linejoin="miter"/><rect x="20" y="19" width="8" height="13" rx="1" fill="currentColor"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="currentColor" stroke-width="2.5"/></svg>"#;

pub fn steadholme_mark() -> Html {
    raw(STEADHOLME_MARK_SVG)
}

pub fn icon(name: &'static str) -> Html {
    raw(match name {
        "circle-check" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>"#
        }
        "triangle-alert" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/></svg>"#
        }
        "circle-alert" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>"#
        }
        "circle-info" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/></svg>"#
        }
        "copy" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>"#
        }
        "shield" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.7 9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z"/></svg>"#
        }
        "zap" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>"#
        }
        "key" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15 5 4 4"/><path d="m17 3 4 4"/></svg>"#
        }
        "database" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg>"#
        }
        "check" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>"#
        }
        "x" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>"#
        }
        "search" => {
            r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>"#
        }
        _ => {
            debug_assert!(false, "unknown icon: {name}");
            r#"<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"></svg>"#
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steadholme_mark_inherits_the_product_color() {
        assert!(STEADHOLME_MARK_SVG.contains("currentColor"));
        assert!(!STEADHOLME_MARK_SVG.contains("#4F46E5"));
        assert_eq!(steadholme_mark().as_str(), STEADHOLME_MARK_SVG);
    }
}
