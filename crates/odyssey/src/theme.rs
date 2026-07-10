// GENERATED FROM odyssey — DO NOT EDIT
//! Estate theme resolution — the LIGHT-first, three-state colour scheme mirror of `i18n`.
//!
//! The design system is authored LIGHT-first: `:root` holds the light token values and the dark
//! ramp is a value-only remap under `:root[data-theme="dark"]`. Activation is a display-only
//! preference carried by the gateway-owned `__Secure-theme` cookie (Domain=.w33d.xyz), set by
//! `/_gw/theme` exactly like `/_gw/lang`. It lives OUTSIDE both gateway HMACs — flipping it can
//! never forge identity, only repaint. Three states:
//!
//! * `light`  — the default; `<html>` gets NO `data-theme` attr so light output stays byte-identical
//!   to the pre-theme era (a hard contract: `beacon` asserts light token bytes).
//! * `dark`   — `<html data-theme="dark">`; the dark ramp applies unconditionally.
//! * `auto`   — `<html data-theme="auto">`; the dark ramp is media-gated by `prefers-color-scheme`.
//!
//! Zero-dependency, mirroring `resolve_locale`: the caller passes the raw `Cookie:` header it
//! already reads. No `http` types cross the boundary.

use crate::i18n::cookie_val;

/// The three resolved theme states, as the stable string a service threads into `ShellOpts.theme`.
/// Returned as `&'static str` (not an enum) so a service can pass it straight through with no new
/// type in its signature — the shell interprets it.
pub fn resolve_theme(cookie: Option<&str>) -> &'static str {
    if let Some(c) = cookie {
        if let Some(v) = cookie_val(c, "__Secure-theme") {
            match v {
                "dark" => return "dark",
                "auto" => return "auto",
                "light" => return "light",
                _ => {}
            }
        }
    }
    "light"
}

/// The `<html>` attribute fragment for a resolved theme. LIGHT returns the empty string so the
/// stamped tag is byte-identical to `<html lang="en">` (the shell tests + beacon assert this).
/// Includes its own leading space so the caller glues it directly after the `lang` attribute.
pub fn html_theme_attr(theme: &str) -> &'static str {
    match theme {
        "dark" => " data-theme=\"dark\"",
        "auto" => " data-theme=\"auto\"",
        _ => "",
    }
}

/// The `<meta name="color-scheme">` content for a resolved theme, so form controls, scrollbars, and
/// the UA canvas match. `dark` commits to dark; `auto` advertises both and lets the OS pick (paired
/// with the media-gated ramp); `light` stays light-only. Light returns `"light"` but the shell only
/// EMITS the meta for non-light themes, keeping light output byte-invariant.
pub fn color_scheme_meta(theme: &str) -> &'static str {
    match theme {
        "dark" => "dark",
        "auto" => "light dark",
        _ => "light",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_to_light() {
        assert_eq!(resolve_theme(None), "light");
        assert_eq!(resolve_theme(Some("a=1; b=2")), "light");
        assert_eq!(resolve_theme(Some("__Secure-theme=bogus")), "light");
    }

    #[test]
    fn resolve_reads_the_cookie() {
        assert_eq!(resolve_theme(Some("__Secure-theme=dark")), "dark");
        assert_eq!(resolve_theme(Some("x=1; __Secure-theme=auto")), "auto");
        assert_eq!(resolve_theme(Some("__Secure-theme=light; y=2")), "light");
    }

    #[test]
    fn light_stamps_nothing() {
        // The byte-invariance contract: light adds no attr and no meta value beyond "light".
        assert_eq!(html_theme_attr("light"), "");
        assert_eq!(html_theme_attr("dark"), " data-theme=\"dark\"");
        assert_eq!(html_theme_attr("auto"), " data-theme=\"auto\"");
    }

    #[test]
    fn color_scheme_tracks_theme() {
        assert_eq!(color_scheme_meta("light"), "light");
        assert_eq!(color_scheme_meta("dark"), "dark");
        assert_eq!(color_scheme_meta("auto"), "light dark");
    }
}
