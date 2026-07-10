// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{esc, raw, Html};
use crate::i18n::{t, Locale};
use crate::icons;
use crate::{dynamic_scripts_with, RuntimeOpts, APP_CSS};

pub struct Brand {
    pub tile_svg: &'static str,
    pub accent: &'static str,
    pub name: &'static str,
    pub sub: &'static str,
}

pub struct NavItem {
    pub href: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    pub active: bool,
}

pub struct Tab<'a> {
    pub href: &'a str,
    pub label: &'a str,
    pub active: bool,
}

#[derive(Default)]
pub struct TabsOpts {
    pub window: bool,
    pub sticky: bool,
}

pub struct UserBox {
    pub email: Option<String>,
    pub logout_url: &'static str,
}

pub struct ShellOpts {
    pub extra_css: &'static str,
    pub head_extra: Html,
    pub body_class: &'static str,
    /// The resolved UI locale — drives `<html lang>`, the chrome strings, and the CSS `:lang`
    /// CJK font selection. Defaults to `En`; a service opts in with
    /// `ShellOpts { locale: odyssey::resolve_locale(cookie, accept_language), ..Default::default() }`.
    pub locale: Locale,
    pub compact: bool,
    /// The resolved colour theme — `"light"` (default), `"dark"`, or `"auto"`. Drives the
    /// `<html data-theme>` attribute and the `color-scheme` meta. `"light"` stamps NOTHING (the
    /// output stays byte-identical to the pre-theme era); a service opts in with
    /// `ShellOpts { theme: odyssey::resolve_theme(cookie), ..Default::default() }`.
    pub theme: &'static str,
}

impl Default for ShellOpts {
    fn default() -> Self {
        Self {
            extra_css: "",
            head_extra: Html::default(),
            body_class: "",
            locale: Locale::En,
            compact: false,
            theme: "light",
        }
    }
}

/// Additive dynamic-shell options for Odyssey Wire navigation.
///
/// The generated app navigation swaps the children of the named `<main>` region. The fields are
/// private so the integration contract can grow without breaking downstream struct literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireShellOpts<'a> {
    region_id: &'a str,
    runtime: RuntimeOpts<'a>,
}

impl<'a> WireShellOpts<'a> {
    pub const fn new(region_id: &'a str) -> Self {
        Self {
            region_id,
            runtime: RuntimeOpts::new(),
        }
    }

    pub const fn runtime(mut self, runtime: RuntimeOpts<'a>) -> Self {
        self.runtime = runtime;
        self
    }

    pub const fn with_motion(mut self) -> Self {
        self.runtime = self.runtime.with_motion();
        self
    }

    pub const fn with_nonce(mut self, nonce: &'a str) -> Self {
        self.runtime = self.runtime.with_nonce(nonce);
        self
    }
}

impl<'a> Default for WireShellOpts<'a> {
    fn default() -> Self {
        Self::new("odyssey-main")
    }
}

pub struct PageHead<'a> {
    pub eyebrow: Option<&'a str>,
    pub glyph: Option<Html>,
    pub title: &'a str,
    pub meta: Html,
    pub actions: Html,
}

pub struct PageChrome<'a> {
    pub title: &'a str,
    pub brand: Brand,
    pub nav: &'a [NavItem],
    pub user: UserBox,
    pub footer: Html,
}

pub fn page_shell(chrome: PageChrome<'_>, body: Html, opts: ShellOpts) -> String {
    page_shell_impl(chrome, body, opts, None)
}

/// Render the standard shell with Wire-boosted app navigation and the internal runtime bundle.
///
/// This is additive to [`page_shell`]: existing services keep byte-identical static output, while
/// dynamic services get a stable main-region id, `data-wire-nav`, and Wire/Spark scripts. Motion
/// and a CSP nonce are opt-in through [`WireShellOpts`].
pub fn wire_page_shell(
    chrome: PageChrome<'_>,
    body: Html,
    opts: ShellOpts,
    wire: WireShellOpts<'_>,
) -> String {
    page_shell_impl(chrome, body, opts, Some(wire))
}

fn page_shell_impl(
    chrome: PageChrome<'_>,
    body: Html,
    opts: ShellOpts,
    wire: Option<WireShellOpts<'_>>,
) -> String {
    let mut body_attr = String::new();
    if !opts.body_class.is_empty() {
        body_attr.push_str(&format!(" class=\"{}\"", esc(opts.body_class)));
    }
    if opts.compact {
        body_attr.push_str(" data-density=\"compact\"");
    }
    let wire_target = wire.map(|opts| format!("#{}", opts.region_id));
    let nav = render_nav(chrome.nav, wire_target.as_deref());
    let main_attr = wire
        .map(|opts| format!(" id=\"{}\"", esc(opts.region_id)))
        .unwrap_or_default();
    let runtime_scripts = wire
        .map(|opts| format!("{}\n", dynamic_scripts_with(opts.runtime)))
        .unwrap_or_default();
    let footer = if chrome.footer.as_str().is_empty() {
        String::new()
    } else {
        format!("<footer class=\"site-foot\">{}</footer>", chrome.footer)
    };
    let tile_style = if chrome.brand.accent.is_empty() {
        String::new()
    } else {
        format!(" style=\"--app:{}\"", esc(chrome.brand.accent))
    };
    // Theme stamping is LIGHT-first: light emits neither the `data-theme` attr nor the
    // `color-scheme` meta, keeping the output byte-identical to the pre-theme era.
    let theme_attr = crate::theme::html_theme_attr(opts.theme);
    let color_scheme_meta = if theme_attr.is_empty() {
        String::new()
    } else {
        format!(
            "<meta name=\"color-scheme\" content=\"{}\">\n",
            crate::theme::color_scheme_meta(opts.theme)
        )
    };

    format!(
        concat!(
            "<!doctype html>\n",
            "<html lang=\"{lang}\"{theme_attr}>\n",
            "<head>\n",
            "<meta charset=\"utf-8\">\n",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n",
            "{color_scheme_meta}",
            "<title>{title}</title>\n",
            "<style>{css}{extra_css}</style>\n",
            "{head_extra}\n",
            "</head>\n",
            "<body{body_attr}>\n",
            "<header class=\"appbar\">",
            "<a class=\"appbar__brand\" href=\"/\">",
            "<span class=\"app-tile\"{tile_style}>{tile_svg}</span>",
            "<span class=\"appbar__name\"><b>{brand_name}</b><span>{brand_sub}</span></span>",
            "</a>",
            "{nav}",
            "<span class=\"appbar__spacer\"></span>",
            "<div class=\"appbar__right\">{theme_switcher}{switcher}{userbox}</div>",
            "</header>\n",
            "<main{main_attr} class=\"console\">{body}</main>\n",
            "{footer}\n",
            "{runtime_scripts}",
            "</body>\n",
            "</html>\n"
        ),
        lang = opts.locale.bcp47(),
        theme_attr = theme_attr,
        color_scheme_meta = color_scheme_meta,
        title = esc(chrome.title),
        css = APP_CSS,
        extra_css = opts.extra_css,
        head_extra = opts.head_extra,
        body_attr = body_attr,
        main_attr = main_attr,
        tile_style = tile_style,
        tile_svg = raw(chrome.brand.tile_svg),
        brand_name = esc(chrome.brand.name),
        brand_sub = esc(chrome.brand.sub),
        nav = nav,
        theme_switcher = render_theme_switcher(opts.theme, opts.locale),
        switcher = render_switcher(opts.locale),
        userbox = render_userbox(&chrome.user, opts.locale),
        body = body,
        footer = footer,
        runtime_scripts = runtime_scripts
    )
}

/// Render the standard app navigation as a standalone Wire boost scope.
///
/// `target` is a CSS selector such as `#odyssey-main`. Attribute names are fixed and the selector,
/// link URLs, and labels are HTML-escaped.
pub fn wire_nav(nav: &[NavItem], target: &str) -> Html {
    raw(render_nav(nav, Some(target)))
}

/// The estate language switcher as standalone markup, for services that render their OWN shell
/// (not [`page_shell`]) and want the switcher in their appbar. Emits the SAME SSR markup
/// `page_shell` uses: three script-native autonyms linking `/_gw/lang?to=…`, current locale marked
/// active, `role="group" aria-label="Language"`, zero JavaScript. Pair it with `locale.bcp47()` on
/// `<html lang>` and a per-request [`resolve_locale`](crate::resolve_locale).
pub fn lang_switcher(locale: Locale) -> Html {
    raw(render_switcher(locale))
}

/// The estate theme switcher as standalone markup, for own-shell services (see [`lang_switcher`]).
/// `theme` is the resolved `light` | `dark` | `auto`.
pub fn theme_switcher(theme: &str, locale: Locale) -> Html {
    raw(render_theme_switcher(theme, locale))
}

/// The estate language switcher: three script-native autonyms linking to the gateway-owned
/// `/_gw/lang?to=…` endpoint, which sets the `__Secure-lang` cookie (Domain=.w33d.xyz) and bounces
/// back. Pure SSR — works with no JavaScript. The current locale is marked active.
fn render_switcher(locale: Locale) -> String {
    let mut out = String::from("<div class=\"langswitch\" role=\"group\" aria-label=\"Language\">");
    for l in Locale::all() {
        let key = match l {
            Locale::En => "lang.name.en",
            Locale::Zh => "lang.name.zh",
            Locale::Ja => "lang.name.ja",
        };
        let (active, current) = if l == locale {
            (" is-active", " aria-current=\"true\"")
        } else {
            ("", "")
        };
        out.push_str(&format!(
            "<a class=\"langswitch__opt{}\" href=\"/_gw/lang?to={}\"{}>{}</a>",
            active,
            l.code(),
            current,
            esc(t(locale, key)).0
        ));
    }
    out.push_str("</div>");
    out
}

/// The estate theme switcher: three icon toggles (Light / Dark / System) linking the gateway-owned
/// `/_gw/theme?to=…` endpoint, which sets the display-only `__Secure-theme` cookie (Domain=.w33d.xyz,
/// OUTSIDE both gateway HMACs) and bounces back. Pure SSR — works with no JavaScript; the current
/// theme is marked active. Icons are inline SVG (sun / moon / monitor), sovereign and zero-network.
fn render_theme_switcher(theme: &str, locale: Locale) -> String {
    // (code, i18n key, inline SVG path body) for each state.
    const OPTS: [(&str, &str, &str); 3] = [
        (
            "light",
            "theme.light",
            "<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4\"/>",
        ),
        (
            "dark",
            "theme.dark",
            "<path d=\"M12 3a6.5 6.5 0 0 0 9 9 9 9 0 1 1-9-9Z\"/>",
        ),
        (
            "auto",
            "theme.auto",
            "<rect x=\"2\" y=\"3\" width=\"20\" height=\"14\" rx=\"2\"/><path d=\"M8 21h8M12 17v4\"/>",
        ),
    ];
    let label = esc(t(locale, "theme.label")).0;
    let mut out = format!(
        "<div class=\"themeswitch\" role=\"group\" aria-label=\"{}\">",
        label
    );
    for (code, key, svg) in OPTS {
        let (active, current) = if code == theme {
            (" is-active", " aria-current=\"true\"")
        } else {
            ("", "")
        };
        let title = esc(t(locale, key)).0;
        out.push_str(&format!(
            "<a class=\"themeswitch__opt{}\" href=\"/_gw/theme?to={}\" title=\"{}\" aria-label=\"{}\"{}>\
<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">{}</svg></a>",
            active, code, title, title, current, svg
        ));
    }
    out.push_str("</div>");
    out
}

pub fn layout_split(main: Html, side: Html) -> Html {
    Html(format!(
        "<div class=\"layout\"><div>{}</div><div>{}</div></div>",
        main, side
    ))
}

pub fn console_head(h1: &str, sub: Html) -> Html {
    Html(format!(
        "<div class=\"pagehead\"><div><h1>{}</h1>{}</div></div>",
        esc(h1),
        sub
    ))
}

pub fn tabs(aria_label: &str, items: &[Tab<'_>], o: TabsOpts) -> Html {
    let mut class = String::from("tabs");
    if o.window {
        class.push_str(" tabs--window");
    }
    if o.sticky {
        class.push_str(" tabs--sticky");
    }

    let mut out = format!(
        "<nav class=\"{}\" aria-label=\"{}\">",
        class,
        esc(aria_label)
    );
    for item in items {
        let active = if item.active { " is-active" } else { "" };
        let current = if item.active {
            " aria-current=\"page\""
        } else {
            ""
        };
        out.push_str(&format!(
            "<a class=\"tab{}\" href=\"{}\"{}>{}</a>",
            active,
            esc(item.href),
            current,
            esc(item.label)
        ));
    }
    out.push_str("</nav>");
    Html(out)
}

pub fn breadcrumb(locale: Locale, trail: &[(&str, &str)]) -> Html {
    if trail.is_empty() {
        return Html::default();
    }

    let mut out = format!(
        "<nav class=\"breadcrumb\" aria-label=\"{}\">",
        esc(t(locale, "nav.breadcrumb"))
    );
    for (idx, (href, label)) in trail.iter().enumerate() {
        if idx + 1 == trail.len() {
            out.push_str(&format!(
                "<span class=\"breadcrumb__item\" aria-current=\"page\">{}</span>",
                esc(label)
            ));
        } else {
            out.push_str(&format!("<a href=\"{}\">{}</a>", esc(href), esc(label)));
            out.push_str("<span class=\"breadcrumb__sep\" aria-hidden=\"true\">/</span>");
        }
    }
    out.push_str("</nav>");
    Html(out)
}

pub fn pagehead(h: PageHead<'_>) -> Html {
    let class = if h.glyph.is_some() {
        "pagehead pagehead--glyph"
    } else {
        "pagehead"
    };
    let glyph = h
        .glyph
        .map(|html| format!("<span class=\"glyph\">{html}</span>"))
        .unwrap_or_default();
    let eyebrow = h
        .eyebrow
        .map(|text| format!("<div class=\"pagehead__eyebrow\">{}</div>", esc(text)))
        .unwrap_or_default();
    let actions = if h.actions.as_str().is_empty() {
        String::new()
    } else {
        format!("<div class=\"pagehead__actions\">{}</div>", h.actions)
    };

    Html(format!(
        "<div class=\"{}\">{}<div>{}<h1>{}</h1>{}</div>{}</div>",
        class,
        glyph,
        eyebrow,
        esc(h.title),
        h.meta,
        actions
    ))
}

fn render_nav(nav: &[NavItem], wire_target: Option<&str>) -> String {
    if nav.is_empty() {
        return String::new();
    }

    let wire_attr = wire_target
        .map(|target| format!(" data-wire-nav=\"{}\"", esc(target)))
        .unwrap_or_default();
    let mut out = format!("<nav class=\"appbar__nav\"{wire_attr}>");
    for item in nav {
        let active = if item.active { " is-active" } else { "" };
        let current = if item.active {
            " aria-current=\"page\""
        } else {
            ""
        };
        out.push_str(&format!(
            "<a class=\"appnav{}\" href=\"{}\"{}>{}<span>{}</span></a>",
            active,
            esc(item.href),
            current,
            raw(item.icon),
            esc(item.label)
        ));
    }
    out.push_str("</nav>");
    out
}

fn render_userbox(user: &UserBox, locale: Locale) -> String {
    let (avatar, name, sub) = match user.email.as_deref() {
        Some(email) if !email.is_empty() => (
            esc(&initials(email)).0,
            esc(&local_part(email)).0,
            esc(email).0,
        ),
        _ => (
            icons::icon("key").0,
            esc(t(locale, "chrome.account")).0,
            esc(t(locale, "chrome.not_signed_in")).0,
        ),
    };

    // CSS focus-within controls this popover; without JS there is no truthful aria-expanded state.
    format!(
        concat!(
            "<div class=\"usermenu\">",
            "<button class=\"usermenu__btn\" type=\"button\" aria-haspopup=\"true\">",
            "<span class=\"avatar\" aria-hidden=\"true\">{avatar}</span>",
            "<span class=\"usermenu__name\">{name}</span>",
            "{caret}",
            "</button>",
            "<div class=\"usermenu__pop\">",
            "<div class=\"usermenu__head\"><span class=\"avatar avatar--lg\" aria-hidden=\"true\">{avatar}</span>",
            "<div><b>{name}</b><span>{sub}</span></div></div>",
            "<a class=\"menuitem\" href=\"/\">{apps}<span>{all_apps}</span></a>",
            "<a class=\"menuitem menuitem--danger\" href=\"{logout}\">{logout_icon}<span>{log_out}</span></a>",
            "</div>",
            "</div>"
        ),
        avatar = avatar,
        name = name,
        sub = sub,
        caret = caret_icon(),
        apps = icons::icon("database"),
        all_apps = esc(t(locale, "chrome.all_apps")).0,
        logout = esc(user.logout_url),
        logout_icon = icons::icon("x"),
        log_out = esc(t(locale, "chrome.log_out")).0
    )
}

fn caret_icon() -> Html {
    raw(
        r#"<svg class="usermenu__caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"#,
    )
}

fn initials(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    let letters: Vec<char> = local
        .split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect();
    if letters.is_empty() {
        return email
            .chars()
            .next()
            .unwrap_or('H')
            .to_uppercase()
            .to_string();
    }
    letters.into_iter().flat_map(|c| c.to_uppercase()).collect()
}

fn local_part(email: &str) -> String {
    email.split('@').next().unwrap_or(email).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    static NAV: [NavItem; 2] = [
        NavItem {
            href: "/services",
            label: "Services",
            icon: "",
            active: true,
        },
        NavItem {
            href: "/deploys?state=running&region=fsn1",
            label: "Deploys & jobs",
            icon: "",
            active: false,
        },
    ];

    fn chrome() -> PageChrome<'static> {
        PageChrome {
            title: "Test",
            brand: Brand {
                tile_svg: "",
                accent: "",
                name: "App",
                sub: "app.w33d.xyz",
            },
            nav: &[],
            user: UserBox {
                email: None,
                logout_url: "https://sso.w33d.xyz/_gw/auth/logout",
            },
            footer: Html::default(),
        }
    }

    fn chrome_with_nav() -> PageChrome<'static> {
        let mut chrome = chrome();
        chrome.nav = &NAV;
        chrome
    }

    #[test]
    fn shell_localizes_chrome_and_html_lang() {
        // English (default): the untranslated chrome + en lang tag.
        let en = page_shell(chrome(), Html::default(), ShellOpts::default());
        assert!(en.contains("<html lang=\"en\">"));
        assert!(en.contains(">Account<") && en.contains(">All apps<") && en.contains(">Log out<"));

        // Chinese: localized chrome + the BCP-47 tag that drives CSS :lang CJK fonts.
        let zh = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                locale: Locale::Zh,
                ..Default::default()
            },
        );
        assert!(
            zh.contains("<html lang=\"zh-Hans\">"),
            "zh lang tag drives CJK :lang fonts"
        );
        assert!(zh.contains("账户") && zh.contains("所有应用") && zh.contains("退出登录"));

        // Japanese.
        let ja = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                locale: Locale::Ja,
                ..Default::default()
            },
        );
        assert!(ja.contains("<html lang=\"ja\">"));
        assert!(ja.contains("アカウント") && ja.contains("ログアウト"));
    }

    #[test]
    fn shell_renders_language_switcher() {
        let out = page_shell(chrome(), Html::default(), ShellOpts::default());
        // Autonyms (each language in its own script) linking the gateway switcher endpoint.
        assert!(out.contains("href=\"/_gw/lang?to=zh\">中文"));
        assert!(out.contains("href=\"/_gw/lang?to=ja\">日本語"));
        // The active locale is marked.
        assert!(out.contains("langswitch__opt is-active\" href=\"/_gw/lang?to=en\""));
    }

    #[test]
    fn shell_stamps_theme_light_first() {
        // Light (default): NO data-theme attr on <html>, NO color-scheme meta — byte-invariant tag.
        // (The dark ramp `:root[data-theme=dark]` + `color-scheme:dark` live inside APP_CSS, so the
        // assertions target the html tag / meta tag specifically, not the whole document.)
        let light = page_shell(chrome(), Html::default(), ShellOpts::default());
        assert!(light.contains("<html lang=\"en\">\n"));
        assert!(!light.contains("<html lang=\"en\" data-theme"));
        assert!(!light.contains("<meta name=\"color-scheme\""));

        // Dark: data-theme attr glued onto <html> + the color-scheme meta.
        let dark = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                theme: "dark",
                ..Default::default()
            },
        );
        assert!(dark.contains("<html lang=\"en\" data-theme=\"dark\">"));
        assert!(dark.contains("<meta name=\"color-scheme\" content=\"dark\">"));

        // Auto: media-gated ramp advertises both schemes.
        let auto = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                theme: "auto",
                ..Default::default()
            },
        );
        assert!(auto.contains("<html lang=\"en\" data-theme=\"auto\">"));
        assert!(auto.contains("<meta name=\"color-scheme\" content=\"light dark\">"));
    }

    #[test]
    fn shell_renders_theme_switcher() {
        // Three icon toggles linking the gateway theme endpoint; current theme marked active.
        let dark = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                theme: "dark",
                ..Default::default()
            },
        );
        assert!(dark.contains("href=\"/_gw/theme?to=light\""));
        assert!(dark.contains("href=\"/_gw/theme?to=dark\""));
        assert!(dark.contains("href=\"/_gw/theme?to=auto\""));
        assert!(dark.contains("themeswitch__opt is-active\" href=\"/_gw/theme?to=dark\""));
    }

    #[test]
    fn tabs_emit_active_current_and_option_classes() {
        let html = tabs(
            "Primary <tabs>",
            &[
                Tab {
                    href: "/one",
                    label: "One",
                    active: false,
                },
                Tab {
                    href: "/two?x=1&y=2",
                    label: "Two & more",
                    active: true,
                },
            ],
            TabsOpts {
                window: true,
                sticky: true,
            },
        );

        assert!(html
            .as_str()
            .contains("class=\"tabs tabs--window tabs--sticky\""));
        assert_eq!(html.as_str().matches("is-active").count(), 1);
        assert!(html.as_str().contains("aria-current=\"page\""));
        assert!(html.as_str().contains("Primary &lt;tabs&gt;"));
        assert!(html.as_str().contains("/two?x=1&amp;y=2"));
        assert!(html.as_str().contains("Two &amp; more"));
    }

    #[test]
    fn breadcrumb_renders_separators_current_item_and_zh_label() {
        assert_eq!(breadcrumb(Locale::En, &[]).as_str(), "");

        let html = breadcrumb(
            Locale::Zh,
            &[("/", "Home"), ("/apps", "Apps"), ("/apps/relay", "Relay")],
        );

        assert!(html.as_str().contains("aria-label=\"面包屑导航\""));
        assert_eq!(html.as_str().matches("breadcrumb__sep").count(), 2);
        assert!(html.as_str().contains("<a href=\"/apps\">Apps</a>"));
        assert!(html
            .as_str()
            .contains("<span class=\"breadcrumb__item\" aria-current=\"page\">Relay</span>"));
        assert!(!html.as_str().contains("href=\"/apps/relay\""));
    }

    #[test]
    fn pagehead_omits_empty_slots_and_escapes_title() {
        let bare = pagehead(PageHead {
            eyebrow: None,
            glyph: None,
            title: "Ops <dash>",
            meta: Html::default(),
            actions: Html::default(),
        });
        assert!(bare.as_str().contains("class=\"pagehead\""));
        assert!(bare.as_str().contains("Ops &lt;dash&gt;"));
        assert!(!bare.as_str().contains("pagehead__actions"));
        assert!(!bare.as_str().contains("glyph"));

        let full = pagehead(PageHead {
            eyebrow: Some("Console"),
            glyph: Some(raw("<svg></svg>")),
            title: "Ops",
            meta: raw("<p>Status</p>"),
            actions: raw("<a>Action</a>"),
        });
        assert!(full.as_str().contains("class=\"pagehead pagehead--glyph\""));
        assert!(full
            .as_str()
            .contains("<span class=\"glyph\"><svg></svg></span>"));
        assert!(full.as_str().contains("pagehead__eyebrow"));
        assert!(full.as_str().contains("pagehead__actions"));
    }

    #[test]
    fn shell_compact_adds_density_attr_without_changing_default() {
        let default = page_shell(chrome(), Html::default(), ShellOpts::default());
        assert!(default.contains("<body>"));
        assert!(!default.contains("<body data-density=\"compact\">"));

        let compact = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                compact: true,
                ..Default::default()
            },
        );
        assert!(compact.contains("<body data-density=\"compact\">"));

        let compact_with_class = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                body_class: "console-x",
                compact: true,
                ..Default::default()
            },
        );
        assert!(compact_with_class.contains("<body class=\"console-x\" data-density=\"compact\">"));
    }

    #[test]
    fn lang_switcher_standalone_matches_page_shell() {
        // The exported switcher (for own-shell services) renders the three autonyms, the /_gw/lang
        // links, the group aria-label, and marks the current locale active.
        let sw = lang_switcher(Locale::Ja).0;
        assert!(sw.contains("aria-label=\"Language\""));
        assert!(sw.contains("/_gw/lang?to=en"));
        assert!(sw.contains("/_gw/lang?to=zh"));
        assert!(sw.contains("/_gw/lang?to=ja"));
        assert!(sw.contains("is-active"));
        assert!(sw.contains("aria-current=\"true\""));
        // It is byte-identical to what page_shell embeds for the same locale.
        let full = page_shell(
            chrome(),
            Html::default(),
            ShellOpts {
                locale: Locale::Ja,
                ..Default::default()
            },
        );
        assert!(full.contains(&sw));
        // theme_switcher is likewise exported and links the gateway theme endpoint.
        assert!(theme_switcher("dark", Locale::En)
            .0
            .contains("/_gw/theme?to="));
    }

    #[test]
    fn wire_nav_is_a_typed_escaped_boost_scope() {
        let nav = wire_nav(&NAV, "#workspace\" onmouseover=\"bad");

        assert!(nav.as_str().starts_with(
            "<nav class=\"appbar__nav\" data-wire-nav=\"#workspace&quot; onmouseover=&quot;bad\">"
        ));
        assert!(nav
            .as_str()
            .contains("href=\"/deploys?state=running&amp;region=fsn1\""));
        assert!(nav.as_str().contains("Deploys &amp; jobs"));
        assert!(nav
            .as_str()
            .contains("class=\"appnav is-active\" href=\"/services\" aria-current=\"page\""));
        assert_eq!(nav.as_str().matches("aria-current=\"page\"").count(), 1);
        assert!(!nav.as_str().contains("\" onmouseover=\""));
    }

    #[test]
    fn wire_page_shell_connects_nav_region_and_default_runtime() {
        let out = wire_page_shell(
            chrome_with_nav(),
            raw("<section id=\"services\">Ready</section>"),
            ShellOpts::default(),
            WireShellOpts::default(),
        );

        assert!(out.contains("<nav class=\"appbar__nav\" data-wire-nav=\"#odyssey-main\">"));
        assert!(out.contains(
            "<main id=\"odyssey-main\" class=\"console\"><section id=\"services\">Ready</section></main>"
        ));
        assert_eq!(out.matches("<script").count(), 1);
        assert!(out.contains("odyssey-wire v1"));
        assert!(out.contains("odyssey-spark v1"));
        assert!(!out.contains("odyssey-motion v1"));
        assert!(out.find("odyssey-wire v1") < out.find("odyssey-spark v1"));
    }

    #[test]
    fn wire_page_shell_can_add_motion_and_a_csp_nonce() {
        let out = wire_page_shell(
            chrome_with_nav(),
            Html::default(),
            ShellOpts {
                head_extra: raw("<meta name=\"application-name\" content=\"Ops\">"),
                ..Default::default()
            },
            WireShellOpts::new("workspace")
                .with_motion()
                .with_nonce("request-42\" data-bad=\"x"),
        );

        assert!(out.contains("<main id=\"workspace\" class=\"console\">"));
        assert!(out.contains("data-wire-nav=\"#workspace\""));
        assert!(out.contains("<meta name=\"application-name\" content=\"Ops\">"));
        assert!(out.contains("<script nonce=\"request-42&quot; data-bad=&quot;x\">"));
        assert!(!out.contains("\" data-bad=\""));
        assert!(out.contains("odyssey-motion v1"));
        assert!(out.find("odyssey-spark v1") < out.find("odyssey-motion v1"));
    }

    #[test]
    fn static_page_shell_keeps_legacy_markup_and_scripts_opt_in() {
        let out = page_shell(chrome_with_nav(), Html::default(), ShellOpts::default());

        assert!(out.contains("<nav class=\"appbar__nav\">"));
        assert!(!out.contains("<nav class=\"appbar__nav\" data-wire-nav"));
        assert!(out.contains("<main class=\"console\"></main>"));
        assert!(!out.contains("<main id="));
        assert!(!out.contains("<script"));
    }
}
