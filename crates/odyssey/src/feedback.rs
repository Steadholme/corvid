// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{esc, Html};
use crate::i18n::{tf, Locale};
use crate::icons;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Ok,
    Warn,
    Down,
    Info,
    Accent,
    Neutral,
}

impl Tone {
    fn pill_class(self) -> &'static str {
        match self {
            Tone::Ok => "pill-ok",
            Tone::Warn => "pill-warn",
            Tone::Down => "pill-down",
            Tone::Info => "pill-info",
            Tone::Accent => "pill-accent",
            Tone::Neutral => "pill-neutral",
        }
    }

    fn toast_class(self) -> &'static str {
        match self {
            Tone::Ok => " toast--ok",
            Tone::Down => " toast--err",
            Tone::Warn | Tone::Info | Tone::Accent | Tone::Neutral => "",
        }
    }

    fn toast_mark(self) -> &'static str {
        match self {
            Tone::Ok => "ok",
            Tone::Down => "!",
            Tone::Warn => "!",
            Tone::Info => "i",
            Tone::Accent => "*",
            Tone::Neutral => "-",
        }
    }

    pub(crate) fn alert_class(self) -> &'static str {
        match self {
            Tone::Ok => " alert--ok",
            Tone::Warn => " alert--warn",
            Tone::Down => " alert--down",
            Tone::Info => " alert--info",
            Tone::Accent | Tone::Neutral => "",
        }
    }

    pub(crate) fn progress_class(self) -> &'static str {
        match self {
            Tone::Ok => " progress--ok",
            Tone::Warn => " progress--warn",
            Tone::Down => " progress--down",
            Tone::Info | Tone::Accent | Tone::Neutral => "",
        }
    }
}

fn alert_icon(tone: Tone) -> &'static str {
    match tone {
        Tone::Ok => "circle-check",
        Tone::Warn => "triangle-alert",
        Tone::Down => "circle-alert",
        Tone::Info | Tone::Accent | Tone::Neutral => "circle-info",
    }
}

pub fn pill(tone: Tone, label: &str) -> Html {
    Html(format!(
        "<span class=\"pill {}\">{}</span>",
        tone.pill_class(),
        esc(label)
    ))
}

pub fn toast(tone: Tone, msg: &str) -> Html {
    Html(format!(
        "<div class=\"toast{}\"><span class=\"toast__ico\">{}</span>{}</div>",
        tone.toast_class(),
        esc(tone.toast_mark()),
        esc(msg)
    ))
}

pub fn alert(tone: Tone, title: Option<&str>, body: &str) -> Html {
    let role = if matches!(tone, Tone::Down) {
        "alert"
    } else {
        "status"
    };
    let title = title
        .map(|text| format!("<div class=\"alert__title\">{}</div>", esc(text)))
        .unwrap_or_default();

    Html(format!(
        concat!(
            "<div class=\"alert{}\" role=\"{}\">",
            "<span class=\"alert__ico\">{}</span>",
            "<div class=\"alert__body\">{}{}</div>",
            "</div>"
        ),
        tone.alert_class(),
        role,
        icons::icon(alert_icon(tone)),
        title,
        esc(body)
    ))
}

pub fn modal(id: &str, title: &str, body: Html, foot: Html, open: bool) -> Html {
    let hidden = if open { "" } else { " hidden" };
    let foot = if foot.as_str().is_empty() {
        String::new()
    } else {
        format!("<div class=\"modal__foot\">{foot}</div>")
    };

    Html(format!(
        concat!(
            "<div class=\"modal\" id=\"{}\" role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"{}-title\"{}>",
            "<div class=\"modal__card\">",
            "<div class=\"modal__head\"><h2 id=\"{}-title\">{}</h2></div>",
            "<div class=\"modal__body\">{}</div>",
            "{}",
            "</div>",
            "</div>"
        ),
        esc(id),
        esc(id),
        hidden,
        esc(id),
        esc(title),
        body,
        foot
    ))
}

pub fn skeleton(lines: u8) -> Html {
    debug_assert!(lines > 0);
    let mut out = String::from("<div class=\"skeleton-group\" aria-hidden=\"true\">");
    for _ in 0..lines {
        out.push_str("<span class=\"skeleton skeleton--text\"></span>");
    }
    out.push_str("</div>");
    Html(out)
}

pub fn filter_chip(locale: Locale, label: &str, remove_href: &str) -> Html {
    let remove_label = tf(locale, "chip.remove", &[("name", label)]);
    Html(format!(
        "<span class=\"chip\">{}<a class=\"chip__remove\" href=\"{}\" aria-label=\"{}\">×</a></span>",
        esc(label),
        esc(remove_href),
        esc(&remove_label)
    ))
}

pub fn switch(name: &str, checked: bool) -> Html {
    let checked_attr = if checked { " checked" } else { "" };
    Html(format!(
        "<span class=\"switch\"><input type=\"checkbox\" role=\"switch\" aria-label=\"{}\" name=\"{}\"{}><i aria-hidden=\"true\"></i></span>",
        esc(name),
        esc(name),
        checked_attr
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_has_accessible_switch_semantics() {
        let html = switch("alerts", true);

        assert!(html.as_str().contains("role=\"switch\""));
        assert!(html.as_str().contains("aria-label=\"alerts\""));
        assert!(html.as_str().contains("checked"));
    }

    #[test]
    fn alert_maps_tone_to_class_role_and_icon() {
        let ok = alert(Tone::Ok, Some("Saved"), "All good");
        assert!(ok.as_str().contains("class=\"alert alert--ok\""));
        assert!(ok.as_str().contains("role=\"status\""));
        assert!(ok.as_str().contains("alert__title"));
        assert!(ok.as_str().contains("circle"));

        let down = alert(Tone::Down, None, "Bad <state>");
        assert!(down.as_str().contains("class=\"alert alert--down\""));
        assert!(down.as_str().contains("role=\"alert\""));
        assert!(!down.as_str().contains("alert__title"));
        assert!(down.as_str().contains("Bad &lt;state&gt;"));
    }

    #[test]
    fn modal_wires_label_hidden_and_optional_footer() {
        let closed = modal(
            "confirm<&",
            "Delete <key>",
            Html(String::from("<p>Body</p>")),
            Html::default(),
            false,
        );
        assert!(closed
            .as_str()
            .contains("id=\"confirm&lt;&amp;\" role=\"dialog\""));
        assert!(closed
            .as_str()
            .contains("aria-labelledby=\"confirm&lt;&amp;-title\" hidden"));
        assert!(closed.as_str().contains("Delete &lt;key&gt;"));
        assert!(!closed.as_str().contains("modal__foot"));

        let open = modal(
            "confirm",
            "Confirm",
            Html::default(),
            Html(String::from("foot")),
            true,
        );
        assert!(!open.as_str().contains(" hidden"));
        assert!(open
            .as_str()
            .contains("<div class=\"modal__foot\">foot</div>"));
    }

    #[test]
    fn skeleton_emits_decorative_lines_without_inline_styles() {
        let html = skeleton(3);

        assert!(html.as_str().contains("aria-hidden=\"true\""));
        assert_eq!(html.as_str().matches("skeleton skeleton--text").count(), 3);
        assert!(!html.as_str().contains("style="));
    }

    #[test]
    fn filter_chip_localizes_remove_label_and_escapes_values() {
        let html = filter_chip(Locale::Zh, "Ops & SRE", "/items?tag=ops&sre=1");

        assert!(html.as_str().contains("class=\"chip\""));
        assert!(html.as_str().contains("Ops &amp; SRE"));
        assert!(html.as_str().contains("href=\"/items?tag=ops&amp;sre=1\""));
        assert!(html.as_str().contains("aria-label=\"移除 Ops &amp; SRE\""));
    }
}
