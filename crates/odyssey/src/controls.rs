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

/// The HTML replacement mode used by Odyssey Wire.
///
/// This mirrors the audited runtime allowlist; callers cannot emit an arbitrary
/// `data-wire-swap` value through the typed helpers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WireSwap {
    #[default]
    Outer,
    Inner,
    Append,
    Prepend,
    Delete,
}

impl WireSwap {
    fn as_str(self) -> &'static str {
        match self {
            Self::Outer => "outer",
            Self::Inner => "inner",
            Self::Append => "append",
            Self::Prepend => "prepend",
            Self::Delete => "delete",
        }
    }
}

/// Typed, allowlisted Odyssey Wire attributes for links and forms.
///
/// Values are always HTML-escaped and attribute names are fixed by Odyssey.
/// Keeping the fields private also lets the contract grow without breaking
/// downstream struct literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireOpts<'a> {
    target: &'a str,
    select: Option<&'a str>,
    swap: WireSwap,
    busy: Option<&'a str>,
    success: Option<&'a str>,
    error: Option<&'a str>,
    push_history: bool,
    optimistic_delete: bool,
}

impl<'a> WireOpts<'a> {
    pub const fn new(target: &'a str) -> Self {
        Self {
            target,
            select: None,
            swap: WireSwap::Outer,
            busy: None,
            success: None,
            error: None,
            push_history: false,
            optimistic_delete: false,
        }
    }

    pub const fn select(mut self, selector: &'a str) -> Self {
        self.select = Some(selector);
        self
    }

    pub const fn swap(mut self, swap: WireSwap) -> Self {
        self.swap = swap;
        self.optimistic_delete = false;
        self
    }

    pub const fn busy_label(mut self, label: &'a str) -> Self {
        self.busy = Some(label);
        self
    }

    pub const fn success_message(mut self, message: &'a str) -> Self {
        self.success = Some(message);
        self
    }

    pub const fn error_message(mut self, message: &'a str) -> Self {
        self.error = Some(message);
        self
    }

    /// Push the final response URL into browser history for a wired link or GET form.
    /// POST forms deliberately ignore this option to avoid replayable mutation entries.
    pub const fn push_history(mut self) -> Self {
        self.push_history = true;
        self
    }

    /// Remove a wired form's target immediately and restore it if the request fails.
    /// The runtime only permits optimistic updates for delete swaps, so this builder
    /// selects that mode atomically. Link helpers intentionally ignore this flag so a
    /// state-changing optimistic action cannot be issued as an unsafe GET.
    pub const fn optimistic_delete(mut self) -> Self {
        self.swap = WireSwap::Delete;
        self.optimistic_delete = true;
        self
    }
}

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
    link_button_impl(href, label, v, o, "")
}

/// A progressively enhanced button-link backed by Odyssey Wire.
///
/// The ordinary `href` remains present, so navigation still works without JavaScript.
pub fn link_button_with_wire(
    href: &str,
    label: &str,
    v: Variant,
    o: BtnOpts,
    wire: WireOpts<'_>,
) -> Html {
    link_button_impl(
        href,
        label,
        v,
        o,
        &render_wire_attrs(wire, WireElement::Link),
    )
}

fn link_button_impl(href: &str, label: &str, v: Variant, o: BtnOpts, wire_attrs: &str) -> Html {
    let classes = btn_classes(v, o);
    let busy = if o.busy {
        " aria-busy=\"true\" aria-disabled=\"true\""
    } else {
        ""
    };
    Html(format!(
        "<a class=\"{}\" href=\"{}\" role=\"button\"{}{}>{}</a>",
        classes,
        esc(href),
        busy,
        wire_attrs,
        esc(label)
    ))
}

/// A plain progressively enhanced link backed by Odyssey Wire.
pub fn link_with_wire(href: &str, label: &str, wire: WireOpts<'_>) -> Html {
    Html(format!(
        "<a href=\"{}\"{}>{}</a>",
        esc(href),
        render_wire_attrs(wire, WireElement::Link),
        esc(label)
    ))
}

pub fn form(method: &'static str, action: &str, csrf: Csrf<'_>, body: Html) -> Html {
    form_impl(method, action, csrf, body, "", true)
}

/// A progressively enhanced form backed by Odyssey Wire.
///
/// The native method and action are retained as the no-JavaScript floor. Mutation forms include
/// the CSRF field; GET forms omit it so secrets never leak into URLs or browser history.
pub fn form_with_wire(
    method: &'static str,
    action: &str,
    csrf: Csrf<'_>,
    body: Html,
    wire: WireOpts<'_>,
) -> Html {
    let is_get = method.eq_ignore_ascii_case("get");
    form_impl(
        method,
        action,
        csrf,
        body,
        &render_wire_attrs(wire, WireElement::Form(is_get)),
        !is_get,
    )
}

fn form_impl(
    method: &'static str,
    action: &str,
    csrf: Csrf<'_>,
    body: Html,
    wire_attrs: &str,
    include_csrf: bool,
) -> Html {
    let csrf_field = if include_csrf {
        format!(
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            esc(csrf.0)
        )
    } else {
        String::new()
    };
    Html(format!(
        "<form method=\"{}\" action=\"{}\"{}>{}{}</form>",
        esc(method),
        esc(action),
        wire_attrs,
        csrf_field,
        body
    ))
}

#[derive(Clone, Copy)]
enum WireElement {
    Form(bool),
    Link,
}

fn render_wire_attrs(wire: WireOpts<'_>, element: WireElement) -> String {
    let action = match element {
        WireElement::Form(_) => "submit",
        WireElement::Link => "get",
    };
    let mut out = format!(
        " data-wire=\"{}\" data-wire-target=\"{}\" data-wire-swap=\"{}\"",
        action,
        esc(wire.target),
        wire.swap.as_str()
    );
    for (name, value) in [
        ("data-wire-select", wire.select),
        ("data-wire-busy", wire.busy),
        ("data-wire-ok", wire.success),
        ("data-wire-err", wire.error),
    ] {
        if let Some(value) = value {
            out.push_str(&format!(" {name}=\"{}\"", esc(value)));
        }
    }
    if matches!(element, WireElement::Link | WireElement::Form(true)) && wire.push_history {
        out.push_str(" data-wire-push");
    }
    if matches!(element, WireElement::Form(_)) && wire.optimistic_delete {
        out.push_str(" data-wire-optimistic");
    }
    out
}

pub fn field(label: &str, control: Html) -> Html {
    let id = field_control_id(label, control.as_str());
    let control = with_control_id(control, &id);
    Html(format!(
        "<div class=\"field\"><label for=\"{}\">{}</label>{}</div>",
        esc(&id),
        esc(label),
        control
    ))
}

pub fn field_hint(label: &str, control: Html, hint: &str) -> Html {
    let id = field_control_id(label, control.as_str());
    let control = with_control_id(control, &id);
    Html(format!(
        "<div class=\"field\"><label for=\"{}\">{}</label>{}<div class=\"hint\">{}</div></div>",
        esc(&id),
        esc(label),
        control,
        esc(hint)
    ))
}

pub fn field_err(msg: &str) -> Html {
    Html(format!("<div class=\"err\">{}</div>", esc(msg)))
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

pub fn text_input(name: &str, value: &str, attrs: &[(&str, &str)]) -> Html {
    let input_type = attr_pair_value(attrs, "type").unwrap_or("text");
    Html(format!(
        "<input class=\"input\" type=\"{}\" name=\"{}\" value=\"{}\"{}>",
        esc(input_type),
        esc(name),
        esc(value),
        render_attrs(attrs, &["type"])
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

pub fn select(
    name: &str,
    options: &[(&str, &str)],
    selected: Option<&str>,
    attrs: &[(&str, &str)],
) -> Html {
    let mut out = format!(
        "<select class=\"select\" name=\"{}\"{}>",
        esc(name),
        render_attrs(attrs, &[])
    );
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

pub fn textarea(name: &str, rows: u8, value: &str, attrs: &[(&str, &str)]) -> Html {
    Html(format!(
        "<textarea class=\"textarea\" name=\"{}\" rows=\"{}\"{}>{}</textarea>",
        esc(name),
        rows,
        render_attrs(attrs, &[]),
        esc(value)
    ))
}

fn render_attrs(attrs: &[(&str, &str)], skip: &[&str]) -> String {
    let mut out = String::new();
    for (name, value) in attrs {
        if name.is_empty()
            || skip
                .iter()
                .any(|skip_name| name.eq_ignore_ascii_case(skip_name))
        {
            continue;
        }
        out.push(' ');
        out.push_str(name);
        out.push_str("=\"");
        out.push_str(&esc(value).0);
        out.push('"');
    }
    out
}

fn attr_pair_value<'a>(attrs: &'a [(&str, &str)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find_map(|(attr_name, value)| attr_name.eq_ignore_ascii_case(name).then_some(*value))
}

fn field_control_id(label: &str, control: &str) -> String {
    if let Some(id) = control_attr(control, "id") {
        return id;
    }
    control_attr(control, "name")
        .filter(|name| !name.is_empty())
        .map(|name| slug_field_id(&name))
        .unwrap_or_else(|| slug_field_id(label))
}

fn control_attr(control: &str, attr: &str) -> Option<String> {
    let needle = format!(" {attr}=\"");
    let start = control.find(&needle)? + needle.len();
    let end = control[start..].find('"')?;
    Some(control[start..start + end].to_string())
}

fn slug_field_id(name: &str) -> String {
    let mut slug = String::new();
    let mut needs_dash = false;
    for ch in name.chars() {
        for lower in ch.to_lowercase() {
            if lower.is_ascii_alphanumeric() {
                if needs_dash && !slug.is_empty() {
                    slug.push('-');
                }
                slug.push(lower);
                needs_dash = false;
            } else if !slug.is_empty() {
                needs_dash = true;
            }
        }
    }

    if slug.is_empty() {
        String::from("field-control")
    } else {
        format!("field-{slug}")
    }
}

fn with_control_id(control: Html, id: &str) -> Html {
    if control_attr(control.as_str(), "id").is_some() {
        return control;
    }

    let mut out = control.0;
    for tag in ["input", "select", "textarea"] {
        if insert_id_attr(&mut out, tag, id) {
            return Html(out);
        }
    }
    Html(out)
}

fn insert_id_attr(out: &mut String, tag: &str, id: &str) -> bool {
    let Some(tag_start) = out.find(&format!("<{tag}")) else {
        return false;
    };
    let Some(tag_end) = out[tag_start..].find('>') else {
        return false;
    };
    out.insert_str(tag_start + tag_end, &format!(" id=\"{}\"", esc(id).0));
    true
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

    #[test]
    fn field_associates_label_and_control_by_name() {
        let html = field("Display name", text_input("user[name]", "Ada", &[]));

        assert!(html
            .as_str()
            .contains("<label for=\"field-user-name\">Display name</label>"));
        assert!(html.as_str().contains("id=\"field-user-name\""));
    }

    #[test]
    fn field_err_emits_error_markup() {
        let html = field_err("Bad & worse");

        assert_eq!(html.as_str(), "<div class=\"err\">Bad &amp; worse</div>");
    }

    #[test]
    fn control_attrs_passthrough_and_escape_values() {
        let input = text_input(
            "email",
            "",
            &[
                ("type", "email"),
                ("required", ""),
                ("autocomplete", "email"),
                ("placeholder", "a \"quoted\" value"),
            ],
        );
        assert!(input.as_str().contains("type=\"email\""));
        assert!(input.as_str().contains("required=\"\""));
        assert!(input.as_str().contains("autocomplete=\"email\""));
        assert!(input
            .as_str()
            .contains("placeholder=\"a &quot;quoted&quot; value\""));

        let select = select("region", &[("fsn1", "FSN1")], None, &[("required", "")]);
        assert!(select
            .as_str()
            .contains("<select class=\"select\" name=\"region\" required=\"\">"));

        let textarea = textarea("notes", 4, "Keep <safe>", &[("placeholder", "\"notes\"")]);
        assert!(textarea
            .as_str()
            .contains("placeholder=\"&quot;notes&quot;\""));
        assert!(textarea.as_str().contains("Keep &lt;safe&gt;"));
    }

    #[test]
    fn wired_form_keeps_native_contract_and_emits_allowlisted_attributes() {
        let html = form_with_wire(
            "post",
            "/services?scope=a&scope=b",
            Csrf("token<&\""),
            Html::default(),
            WireOpts::new("#service-grid")
                .select("#fresh-grid")
                .swap(WireSwap::Inner)
                .busy_label("Saving <now>")
                .success_message("Saved & replicated")
                .error_message("Try \"again\"")
                .push_history(),
        );

        assert!(html.as_str().starts_with(
            "<form method=\"post\" action=\"/services?scope=a&amp;scope=b\" data-wire=\"submit\""
        ));
        assert!(html.as_str().contains("data-wire-target=\"#service-grid\""));
        assert!(html.as_str().contains("data-wire-select=\"#fresh-grid\""));
        assert!(html.as_str().contains("data-wire-swap=\"inner\""));
        assert!(html
            .as_str()
            .contains("data-wire-busy=\"Saving &lt;now&gt;\""));
        assert!(html
            .as_str()
            .contains("data-wire-ok=\"Saved &amp; replicated\""));
        assert!(html
            .as_str()
            .contains("data-wire-err=\"Try &quot;again&quot;\""));
        assert!(!html.as_str().contains("data-wire-push"));
        assert!(html
            .as_str()
            .contains("name=\"csrf_token\" value=\"token&lt;&amp;&quot;\""));

        let get = form_with_wire(
            "get",
            "/services",
            Csrf("must-not-leak"),
            Html::default(),
            WireOpts::new("#service-grid").push_history(),
        );
        assert!(get.as_str().contains("data-wire-push"));
        assert!(!get.as_str().contains("csrf_token"));
        assert!(!get.as_str().contains("must-not-leak"));
    }

    #[test]
    fn wired_links_preserve_href_and_avoid_unsafe_optimistic_gets() {
        let wire = WireOpts::new("#service-grid")
            .swap(WireSwap::Inner)
            .push_history();
        let button = link_button_with_wire(
            "/services/7?confirm=1&hard=0",
            "Remove <relay>",
            Variant::Danger,
            BtnOpts::default(),
            wire,
        );

        assert!(button
            .as_str()
            .contains("href=\"/services/7?confirm=1&amp;hard=0\""));
        assert!(button
            .as_str()
            .contains("role=\"button\" data-wire=\"get\""));
        assert!(button.as_str().contains("data-wire-swap=\"inner\""));
        assert!(button.as_str().contains("data-wire-push"));
        assert!(!button.as_str().contains("data-wire-optimistic"));
        assert!(button.as_str().contains("Remove &lt;relay&gt;"));

        let plain = link_with_wire("/next", "Next", WireOpts::new("#main"));
        assert!(plain
            .as_str()
            .starts_with("<a href=\"/next\" data-wire=\"get\""));

        let unsafe_get = link_with_wire(
            "/delete",
            "Delete",
            WireOpts::new("#row-7").optimistic_delete(),
        );
        assert!(unsafe_get.as_str().contains("data-wire-swap=\"delete\""));
        assert!(!unsafe_get.as_str().contains("data-wire-optimistic"));
    }

    #[test]
    fn wire_values_cannot_break_out_into_unreviewed_attributes() {
        let html = link_with_wire(
            "/safe",
            "Safe",
            WireOpts::new("#main\" onclick=\"alert(1)").success_message("ok\" autofocus=\"true"),
        );

        assert!(html.as_str().contains("#main&quot; onclick=&quot;alert(1)"));
        assert!(html.as_str().contains("ok&quot; autofocus=&quot;true"));
        assert!(!html.as_str().contains("\" onclick=\""));
        assert!(!html.as_str().contains("\" autofocus=\""));

        let reset = link_with_wire(
            "/safe",
            "Safe",
            WireOpts::new("#main")
                .optimistic_delete()
                .swap(WireSwap::Append),
        );
        assert!(reset.as_str().contains("data-wire-swap=\"append\""));
        assert!(!reset.as_str().contains("data-wire-optimistic"));

        let delete_form = form_with_wire(
            "post",
            "/rows/7/delete",
            Csrf("token"),
            Html::default(),
            WireOpts::new("#row-7").optimistic_delete(),
        );
        assert!(delete_form.as_str().contains("data-wire-swap=\"delete\""));
        assert!(delete_form.as_str().contains("data-wire-optimistic"));
    }

    #[test]
    fn legacy_form_and_link_button_remain_unwired() {
        let legacy_form = form("post", "/save", Csrf("token"), Html::default());
        let legacy_link = link_button("/next", "Next", Variant::Primary, BtnOpts::default());

        assert!(!legacy_form.as_str().contains("data-wire"));
        assert!(!legacy_link.as_str().contains("data-wire"));
    }
}
