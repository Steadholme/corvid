// GENERATED FROM odyssey — DO NOT EDIT
//! Sovereign, zero-dependency internationalization for the HOLDFAST estate.
//!
//! This module folds i18n into the `odyssey` design-system crate so it rides the SAME
//! `odyssey-vendor` distribution channel (and its `--check` CI gate) that already ships `APP_CSS`
//! to every service — with zero Cargo/Dockerfile churn. It is pure `std`: the catalogs are
//! compile-time-typed const tables living in `.rodata` (no runtime parse, no file IO, no external
//! crates, no CDN, no C deps), and the whole API resolves + looks up locale strings at render time.
//!
//! Scope is UI CHROME ONLY — nav/buttons/labels/empty-states/errors and the `<html lang>` tag.
//! User-generated and remote/federated content (posts, clips, mail, code, names) is NEVER
//! translated; it stays `esc(&value)` exactly as today.
//!
//! Locale is resolved per request from a `__Secure-lang` cookie (Domain=`.w33d.xyz`), then
//! `Accept-Language` negotiation, then the `En` default. It is display-only and never an
//! authorization input, so it stays outside the gateway HMAC.

pub mod en;
pub mod ja;
pub mod zh;

/// The supported UI locales. `repr(u8)` mirrors the catalog selector; add a locale by adding a
/// variant, a `mod`, a `TABLE`, and the `table()`/`bcp47()`/`code()` arms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Locale {
    En,
    Zh,
    Ja,
}

impl Default for Locale {
    fn default() -> Self {
        Locale::En
    }
}

impl Locale {
    /// The BCP-47 tag for the `<html lang="…">` attribute (drives CSS `:lang` font selection).
    pub fn bcp47(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh-Hans",
            Locale::Ja => "ja",
        }
    }

    /// The short code used in the `__Secure-lang` cookie and the `/_gw/lang?to=…` switcher.
    pub fn code(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh",
            Locale::Ja => "ja",
        }
    }

    /// Parse a cookie/switcher code (`en`/`zh`/`ja`) into a locale; `None` for anything else.
    pub fn from_code(s: &str) -> Option<Locale> {
        match s {
            "en" => Some(Locale::En),
            "zh" => Some(Locale::Zh),
            "ja" => Some(Locale::Ja),
            _ => None,
        }
    }

    /// Map a BCP-47 language tag to a locale by its primary subtag (`zh-CN`/`zh-Hant`→Zh,
    /// `ja-JP`→Ja, everything else→En). Never fails.
    pub fn from_tag(tag: &str) -> Locale {
        let primary = tag
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match primary.as_str() {
            "zh" => Locale::Zh,
            "ja" => Locale::Ja,
            _ => Locale::En,
        }
    }

    /// All supported locales, in display order (used to render the language switcher).
    pub fn all() -> [Locale; 3] {
        [Locale::En, Locale::Zh, Locale::Ja]
    }

    fn table(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Locale::En => en::TABLE,
            Locale::Zh => zh::TABLE,
            Locale::Ja => ja::TABLE,
        }
    }
}

/// Resolve the request locale. Priority: a valid `__Secure-lang` cookie, then `Accept-Language`
/// negotiation over the supported set, then `En`. Takes borrowed header strings (NOT an
/// `http::HeaderMap`) so `odyssey` keeps its zero-dependency status — each service passes the two
/// values it already reads.
pub fn resolve_locale(cookie: Option<&str>, accept_language: Option<&str>) -> Locale {
    if let Some(c) = cookie {
        if let Some(v) = cookie_val(c, "__Secure-lang") {
            if let Some(l) = Locale::from_code(v) {
                return l;
            }
        }
    }
    if let Some(al) = accept_language {
        if let Some(l) = negotiate(al) {
            return l;
        }
    }
    Locale::En
}

/// Extract a cookie value by exact name from a raw `Cookie:` header (`a=1; __Secure-lang=ja`).
fn cookie_val<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie.split(';') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// Negotiate `Accept-Language` against the supported set: pick the highest-q supported tag,
/// skipping unsupported ones rather than defaulting on them. Pure std; ties keep the first tag.
fn negotiate(al: &str) -> Option<Locale> {
    let mut best: Option<(f32, Locale)> = None;
    for part in al.split(',') {
        let mut it = part.split(';');
        let tag = it.next().unwrap_or("").trim();
        if tag.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for param in it {
            if let Some(qs) = param.trim().strip_prefix("q=") {
                q = qs.parse().unwrap_or(0.0);
            }
        }
        let primary = tag.split(['-', '_']).next().unwrap_or("").to_ascii_lowercase();
        let loc = match primary.as_str() {
            "zh" => Some(Locale::Zh),
            "ja" => Some(Locale::Ja),
            "en" => Some(Locale::En),
            _ => None,
        };
        if let Some(l) = loc {
            if best.map_or(true, |(bq, _)| q > bq) {
                best = Some((q, l));
            }
        }
    }
    best.map(|(_, l)| l)
}

fn find(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .binary_search_by(|(k, _)| (*k).cmp(key))
        .ok()
        .map(|i| table[i].1)
        .filter(|v| !v.is_empty())
}

/// The core lookup with the requested→English fallback, without the final raw-key fallback (so it
/// accepts a non-`'static` key, e.g. `tn`'s runtime-built `key.one`).
fn lookup(locale: Locale, key: &str) -> Option<&'static str> {
    find(locale.table(), key).or_else(|| find(en::TABLE, key))
}

/// Look up a UI string. Fallback chain: requested locale → English → the raw key (fail-VISIBLE:
/// never panics, never returns blank). `key` is `&'static str` because keys are compile-time string
/// literals (or `pub const` symbols) — this also lets a total miss return the key itself. The
/// result is PLAIN text; wrap it in your local `esc()` exactly as you already do for data.
pub fn t(locale: Locale, key: &'static str) -> &'static str {
    lookup(locale, key).unwrap_or(key)
}

/// Look up a string with named `{name}` interpolation, e.g.
/// `tf(loc, "clips.saved", &[("n", &count.to_string())])`.
pub fn tf(locale: Locale, key: &'static str, args: &[(&str, &str)]) -> String {
    let mut s = t(locale, key).to_string();
    for (name, val) in args {
        s = s.replace(&format!("{{{name}}}"), val);
    }
    s
}

/// Look up a pluralized string. English uses `key.one` for n==1 and `key` (the CLDR "other")
/// otherwise; Chinese and Japanese have no plural forms and always take the base key. Combine with
/// [`tf`] for the count.
pub fn tn(locale: Locale, key: &'static str, n: i64) -> &'static str {
    if matches!(locale, Locale::En) && n == 1 {
        if let Some(one) = lookup(locale, &format!("{key}.one")) {
            return one;
        }
    }
    t(locale, key)
}

const EN_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The abbreviated month name for a locale (`m` is 1..=12). English returns `Jan`..`Dec`; Chinese
/// and Japanese use the numeric `N月` form via [`fmt_date`], so this returns `""` for them.
pub fn month_abbr(locale: Locale, m: u8) -> &'static str {
    match locale {
        Locale::En => EN_MONTHS.get(m.saturating_sub(1) as usize).copied().unwrap_or(""),
        _ => "",
    }
}

/// Format a date from decomposed integer parts (so `odyssey` never depends on the `time` crate;
/// the caller decomposes with its own `time`). English: `Jul 7, 2026`. Chinese/Japanese: `2026年7月7日`.
pub fn fmt_date(locale: Locale, y: i32, m: u8, d: u8) -> String {
    match locale {
        Locale::En => format!("{} {}, {}", month_abbr(locale, m), d, y),
        Locale::Zh | Locale::Ja => format!("{y}年{m}月{d}日"),
    }
}

/// Format an integer with thousands grouping (`1,234,567`). Shared across en/zh/ja for the
/// foundation; the single hook for future locale-specific grouping (e.g. CJK 万/億).
pub fn fmt_int(_locale: Locale, n: i64) -> String {
    let neg = n < 0;
    let digits = n.unsigned_abs().to_string();
    let bytes = digits.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 3 + 1);
    if neg {
        out.push('-');
    }
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> [(&'static str, &'static [(&'static str, &'static str)]); 3] {
        [("en", en::TABLE), ("zh", zh::TABLE), ("ja", ja::TABLE)]
    }

    #[test]
    fn tables_are_sorted_by_key() {
        for (name, tbl) in tables() {
            for w in tbl.windows(2) {
                assert!(w[0].0 < w[1].0, "{name} not sorted: {:?} !< {:?}", w[0].0, w[1].0);
            }
        }
    }

    #[test]
    fn en_has_no_blank_values() {
        for (k, v) in en::TABLE {
            assert!(!v.is_empty(), "en key {k} is blank");
        }
    }

    #[test]
    fn zh_ja_keys_are_subset_of_en() {
        let has_en = |k: &str| en::TABLE.binary_search_by(|(kk, _)| (*kk).cmp(k)).is_ok();
        for (name, tbl) in [("zh", zh::TABLE), ("ja", ja::TABLE)] {
            for (k, _) in tbl {
                assert!(has_en(k), "{name} key {k} is not in en (untranslatable / typo)");
            }
        }
    }

    #[test]
    fn resolve_prefers_cookie_then_accept_language_then_default() {
        // Cookie wins over Accept-Language.
        assert_eq!(
            resolve_locale(Some("a=1; __Secure-lang=ja; b=2"), Some("zh,en;q=0.5")),
            Locale::Ja
        );
        // Unknown cookie value falls through to Accept-Language.
        assert_eq!(resolve_locale(Some("__Secure-lang=fr"), Some("zh-CN")), Locale::Zh);
        // No cookie → Accept-Language negotiation (highest q wins).
        assert_eq!(resolve_locale(None, Some("fr;q=1.0, ja;q=0.9, en;q=0.2")), Locale::Ja);
        // Unsupported tags are skipped, not defaulted on.
        assert_eq!(resolve_locale(None, Some("fr, de")), Locale::En);
        // Nothing → default En.
        assert_eq!(resolve_locale(None, None), Locale::En);
    }

    #[test]
    fn from_tag_maps_regional_variants() {
        assert_eq!(Locale::from_tag("zh-CN"), Locale::Zh);
        assert_eq!(Locale::from_tag("zh-Hant"), Locale::Zh);
        assert_eq!(Locale::from_tag("ja-JP"), Locale::Ja);
        assert_eq!(Locale::from_tag("en-US"), Locale::En);
        assert_eq!(Locale::from_tag("xx"), Locale::En);
    }

    #[test]
    fn t_falls_back_requested_then_en_then_key() {
        assert_eq!(t(Locale::Zh, "chrome.account"), "账户");
        // A key present in en but omitted in zh (clips.saved.one) falls back to en.
        assert_eq!(t(Locale::Zh, "clips.saved.one"), "Saved {n} clip");
        // A totally missing key returns itself (fail-visible).
        assert_eq!(t(Locale::En, "nonexistent.key"), "nonexistent.key");
    }

    #[test]
    fn tf_interpolates_named_args() {
        assert_eq!(tf(Locale::En, "clips.saved", &[("n", "3")]), "Saved 3 clips");
        assert_eq!(tf(Locale::Zh, "clips.saved", &[("n", "3")]), "已保存 3 条剪辑");
    }

    #[test]
    fn tn_selects_english_plural_only() {
        assert_eq!(tn(Locale::En, "clips.saved", 1), "Saved {n} clip");
        assert_eq!(tn(Locale::En, "clips.saved", 5), "Saved {n} clips");
        // zh/ja always take the base key regardless of n.
        assert_eq!(tn(Locale::Zh, "clips.saved", 1), "已保存 {n} 条剪辑");
    }

    #[test]
    fn fmt_date_orders_per_locale() {
        assert_eq!(fmt_date(Locale::En, 2026, 7, 7), "Jul 7, 2026");
        assert_eq!(fmt_date(Locale::Zh, 2026, 7, 7), "2026年7月7日");
        assert_eq!(fmt_date(Locale::Ja, 2026, 7, 7), "2026年7月7日");
    }

    #[test]
    fn fmt_int_groups_thousands() {
        assert_eq!(fmt_int(Locale::En, 1234567), "1,234,567");
        assert_eq!(fmt_int(Locale::En, -1000), "-1,000");
        assert_eq!(fmt_int(Locale::En, 42), "42");
    }

    #[test]
    fn bcp47_and_code_roundtrip() {
        for l in Locale::all() {
            assert_eq!(Locale::from_code(l.code()), Some(l));
        }
        assert_eq!(Locale::Zh.bcp47(), "zh-Hans");
    }
}
