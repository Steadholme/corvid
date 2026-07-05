// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{esc, Html};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Primary,
    Secondary,
    Ghost,
    Subtle,
    Danger,
}

impl Variant {
    fn class(self) -> &'static str {
        match self {
            Variant::Primary => "btn-primary",
            Variant::Secondary => "btn-secondary",
            Variant::Ghost => "btn-ghost",
            Variant::Subtle => "btn-subtle",
            Variant::Danger => "btn-danger",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtnOpts {
    pub small: bool,
    pub large: bool,
    pub busy: bool,
    pub kind: &'static str,
}

impl Default for BtnOpts {
    fn default() -> Self {
        Self {
            small: false,
            large: false,
            busy: false,
            kind: "button",
        }
    }
}

pub struct Csrf<'a>(pub &'a str);

pub fn button(label: &str, v: Variant, o: BtnOpts) -> Html {
    let classes = btn_classes(v, o);
    let busy = if o.busy {
        " aria-busy=\"true\" disabled"
    } else {
        ""
    };
    Html(format!(
        "<button class=\"{}\" type=\"{}\"{}>{}</button>",
        classes,
        esc(o.kind),
        busy,
        esc(label)
    ))
}

pub fn link_button(href: &str, label: &str, v: Variant, o: BtnOpts) -> Html {
    let classes = btn_classes(v, o);
    let busy = if o.busy {
        " aria-busy=\"true\" aria-disabled=\"true\""
    } else {
        ""
    };
    Html(format!(
        "<a class=\"{}\" href=\"{}\" role=\"button\"{}>{}</a>",
        classes,
        esc(href),
        busy,
        esc(label)
    ))
}

pub fn form(method: &'static str, action: &str, csrf: Csrf<'_>, body: Html) -> Html {
    Html(format!(
        concat!(
            "<form method=\"{}\" action=\"{}\">",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            "{}",
            "</form>"
        ),
        esc(method),
        esc(action),
        esc(csrf.0),
        body
    ))
}

pub fn field(label: &str, control: Html) -> Html {
    Html(format!(
        "<div class=\"field\"><label>{}</label>{}</div>",
        esc(label),
        control
    ))
}

pub fn field_hint(label: &str, control: Html, hint: &str) -> Html {
    Html(format!(
        "<div class=\"field\"><label>{}</label>{}<div class=\"hint\">{}</div></div>",
        esc(label),
        control,
        esc(hint)
    ))
}

pub fn checkbox_field(name: &str, label: &str, checked: bool) -> Html {
    let checked_attr = if checked { " checked" } else { "" };
    Html(format!(
        concat!(
            "<div class=\"field field--check\">",
            "<label class=\"check\"><input type=\"checkbox\" name=\"{}\" value=\"1\"{}> {}</label>",
            "</div>"
        ),
        esc(name),
        checked_attr,
        esc(label)
    ))
}

pub fn range_field(
    label: &str,
    name: &str,
    min: &str,
    max: &str,
    step: &str,
    value: &str,
    out_badge: bool,
) -> Html {
    let output = if out_badge {
        format!("<output class=\"pg__out\">{}</output>", esc(value))
    } else {
        String::new()
    };
    Html(format!(
        concat!(
            "<div class=\"field\"><label>{}</label>",
            "<div class=\"field__row\">",
            "<input type=\"range\" name=\"{}\" min=\"{}\" max=\"{}\" step=\"{}\" value=\"{}\">",
            "{}",
            "</div></div>"
        ),
        esc(label),
        esc(name),
        esc(min),
        esc(max),
        esc(step),
        esc(value),
        output
    ))
}

pub fn text_input(name: &str, value: &str) -> Html {
    Html(format!(
        "<input class=\"input\" type=\"text\" name=\"{}\" value=\"{}\">",
        esc(name),
        esc(value)
    ))
}

pub fn number_input(name: &str, min: &str, max: &str, value: &str) -> Html {
    Html(format!(
        "<input class=\"input\" type=\"number\" name=\"{}\" min=\"{}\" max=\"{}\" value=\"{}\">",
        esc(name),
        esc(min),
        esc(max),
        esc(value)
    ))
}

pub fn select(name: &str, options: &[(&str, &str)], selected: Option<&str>) -> Html {
    let mut out = format!("<select class=\"select\" name=\"{}\">", esc(name));
    for (value, label) in options {
        let selected_attr = if selected == Some(*value) {
            " selected"
        } else {
            ""
        };
        out.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            esc(value),
            selected_attr,
            esc(label)
        ));
    }
    out.push_str("</select>");
    Html(out)
}

pub fn textarea(name: &str, rows: u8, value: &str) -> Html {
    Html(format!(
        "<textarea class=\"textarea\" name=\"{}\" rows=\"{}\">{}</textarea>",
        esc(name),
        rows,
        esc(value)
    ))
}

fn btn_classes(v: Variant, o: BtnOpts) -> String {
    let mut classes = format!("btn {}", v.class());
    if o.small {
        classes.push_str(" btn-sm");
    }
    if o.large {
        classes.push_str(" btn-lg");
    }
    if o.busy {
        classes.push_str(" is-busy");
    }
    classes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_renders_variant_size_busy_and_escaped_label() {
        let html = button(
            "Save & continue",
            Variant::Primary,
            BtnOpts {
                small: true,
                busy: true,
                ..BtnOpts::default()
            },
        );
        assert!(html
            .as_str()
            .contains("class=\"btn btn-primary btn-sm is-busy\""));
        assert!(html.as_str().contains("aria-busy=\"true\""));
        assert!(html.as_str().contains("Save &amp; continue"));
    }

    #[test]
    fn range_field_emits_field_row_and_output_badge() {
        let html = range_field("Rate", "rate", "0", "100", "5", "45", true);
        assert!(html.as_str().contains("<div class=\"field__row\">"));
        assert!(html.as_str().contains("type=\"range\""));
        assert!(html
            .as_str()
            .contains("<output class=\"pg__out\">45</output>"));
    }

    #[test]
    fn checkbox_field_emits_check_classes() {
        let html = checkbox_field("enabled", "Enable relay", true);
        assert!(html.as_str().contains("class=\"field field--check\""));
        assert!(html.as_str().contains("class=\"check\""));
        assert!(html.as_str().contains("checked"));
    }
}
