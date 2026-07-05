// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{esc, raw, Html};
use crate::icons;
use crate::APP_CSS;

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

pub struct UserBox {
    pub email: Option<String>,
    pub logout_url: &'static str,
}

pub struct ShellOpts {
    pub extra_css: &'static str,
    pub head_extra: Html,
    pub body_class: &'static str,
}

impl Default for ShellOpts {
    fn default() -> Self {
        Self {
            extra_css: "",
            head_extra: Html::default(),
            body_class: "",
        }
    }
}

pub struct PageChrome<'a> {
    pub title: &'a str,
    pub brand: Brand,
    pub nav: &'a [NavItem],
    pub user: UserBox,
    pub footer: Html,
}

pub fn page_shell(chrome: PageChrome<'_>, body: Html, opts: ShellOpts) -> String {
    let body_attr = if opts.body_class.is_empty() {
        String::new()
    } else {
        format!(" class=\"{}\"", esc(opts.body_class))
    };
    let nav = render_nav(chrome.nav);
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

    format!(
        concat!(
            "<!doctype html>\n",
            "<html lang=\"en\">\n",
            "<head>\n",
            "<meta charset=\"utf-8\">\n",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n",
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
            "<div class=\"appbar__right\">{userbox}</div>",
            "</header>\n",
            "<main class=\"console\">{body}</main>\n",
            "{footer}\n",
            "</body>\n",
            "</html>\n"
        ),
        title = esc(chrome.title),
        css = APP_CSS,
        extra_css = opts.extra_css,
        head_extra = opts.head_extra,
        body_attr = body_attr,
        tile_style = tile_style,
        tile_svg = raw(chrome.brand.tile_svg),
        brand_name = esc(chrome.brand.name),
        brand_sub = esc(chrome.brand.sub),
        nav = nav,
        userbox = render_userbox(&chrome.user),
        body = body,
        footer = footer
    )
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

fn render_nav(nav: &[NavItem]) -> String {
    if nav.is_empty() {
        return String::new();
    }

    let mut out = String::from("<nav class=\"appbar__nav\">");
    for item in nav {
        let active = if item.active { " is-active" } else { "" };
        out.push_str(&format!(
            "<a class=\"appnav{}\" href=\"{}\">{}<span>{}</span></a>",
            active,
            esc(item.href),
            raw(item.icon),
            esc(item.label)
        ));
    }
    out.push_str("</nav>");
    out
}

fn render_userbox(user: &UserBox) -> String {
    let (avatar, name, sub) = match user.email.as_deref() {
        Some(email) if !email.is_empty() => (
            esc(&initials(email)).0,
            esc(&local_part(email)).0,
            esc(email).0,
        ),
        _ => (
            icons::icon("key").0,
            String::from("Account"),
            String::from("Not signed in"),
        ),
    };

    format!(
        concat!(
            "<div class=\"usermenu\">",
            "<button class=\"usermenu__btn\" type=\"button\" aria-haspopup=\"true\" aria-expanded=\"false\">",
            "<span class=\"avatar\" aria-hidden=\"true\">{avatar}</span>",
            "<span class=\"usermenu__name\">{name}</span>",
            "{caret}",
            "</button>",
            "<div class=\"usermenu__pop\" role=\"menu\">",
            "<div class=\"usermenu__head\"><span class=\"avatar avatar--lg\" aria-hidden=\"true\">{avatar}</span>",
            "<div><b>{name}</b><span>{sub}</span></div></div>",
            "<a class=\"menuitem\" role=\"menuitem\" href=\"/\">{apps}<span>All apps</span></a>",
            "<a class=\"menuitem menuitem--danger\" role=\"menuitem\" href=\"{logout}\">{logout_icon}<span>Log out</span></a>",
            "</div>",
            "</div>"
        ),
        avatar = avatar,
        name = name,
        sub = sub,
        caret = caret_icon(),
        apps = icons::icon("database"),
        logout = esc(user.logout_url),
        logout_icon = icons::icon("x")
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
