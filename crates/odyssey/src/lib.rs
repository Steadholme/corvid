// GENERATED FROM odyssey — DO NOT EDIT
pub const APP_CSS: &str = concat!(
    include_str!("../css/font.css"),
    include_str!("../css/tokens.css"),
    include_str!("../css/components.css"),
    include_str!("../css/motion.css")
);
pub const WIRE_JS: &str = include_str!("../js/wire.js");
pub const SPARK_JS: &str = include_str!("../js/spark.js");
/// W8 motion helper (same-document View Transition wrapper + FLIP list animator). The cross-document
/// continuity headline is pure CSS in motion.css and needs none of this; this is optional polish.
pub const MOTION_JS: &str = include_str!("../js/motion.js");

pub mod controls;
pub mod data;
pub mod feedback;
pub mod html;
pub mod i18n;
pub mod icons;
pub mod identity;
pub mod shell;
pub mod theme;

pub use controls::{
    button, checkbox_field, field, field_err, field_hint, form, form_with_wire, link_button,
    link_button_with_wire, link_with_wire, number_input, range_field, select, text_input, textarea,
    BtnOpts, Csrf, Variant, WireOpts, WireSwap,
};
pub use data::{card, card_list, empty_state, pager, progress, stat_tile, table, Col};
pub use feedback::{alert, filter_chip, modal, pill, skeleton, switch, toast, Tone};
pub use html::{esc, raw, Html};
pub use i18n::{fmt_date, fmt_int, month_abbr, resolve_locale, t, tf, tn, Locale};
pub use icons::{holdfast_mark, HOLDFAST_MARK_SVG};
pub use identity::{initial, letter_tile, tone};
pub use shell::{
    breadcrumb, console_head, lang_switcher, layout_split, page_shell, pagehead, tabs,
    theme_switcher, wire_nav, wire_page_shell, Brand, NavItem, PageChrome, PageHead, ShellOpts,
    Tab, TabsOpts, UserBox, WireShellOpts,
};
pub use theme::{color_scheme_meta, html_theme_attr, resolve_theme};

/// Options for the inline Odyssey internal runtime bundle.
///
/// Fields stay private so new runtime modules can be added without breaking downstream
/// struct literals. Use the builders to opt into Motion or attach a CSP nonce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeOpts<'a> {
    motion: bool,
    nonce: Option<&'a str>,
}

impl<'a> RuntimeOpts<'a> {
    pub const fn new() -> Self {
        Self {
            motion: false,
            nonce: None,
        }
    }

    pub const fn with_motion(mut self) -> Self {
        self.motion = true;
        self
    }

    pub const fn with_nonce(mut self, nonce: &'a str) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

/// Wire and Spark in one inline script block, preserving the original API.
///
/// Order is wire then spark. Both modules are document-delegated and init-idempotent, so the
/// ordering is not load-bearing for consumers.
pub fn dynamic_scripts() -> Html {
    dynamic_scripts_with(RuntimeOpts::new())
}

/// Build the audited internal runtime bundle, optionally including Motion and a CSP nonce.
///
/// All modules remain in one script element, so services make no external runtime-script request.
/// Wire itself may still perform the same-origin HTML requests declared by `data-wire-*` markup;
/// a CSP nonce lets strict-CSP services authorize the exact inline block per response.
pub fn dynamic_scripts_with(opts: RuntimeOpts<'_>) -> Html {
    let nonce = opts
        .nonce
        .map(|value| format!(" nonce=\"{}\"", esc(value)))
        .unwrap_or_default();
    let motion = if opts.motion {
        format!("\n{MOTION_JS}")
    } else {
        String::new()
    };
    raw(format!(
        "<script{nonce}>{WIRE_JS}\n{SPARK_JS}{motion}</script>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_css_contains_compact_density_block() {
        assert!(APP_CSS.contains("[data-density=\"compact\"]"));
        assert!(APP_CSS.contains("--tap:32px"));
        assert!(APP_CSS.contains("--fs-body:13.5px"));
    }

    #[test]
    fn dynamic_js_is_inline_safe_and_eval_free() {
        let banned = [
            ["</scr", "ipt"].concat(),
            ["ev", "al("].concat(),
            ["new ", "function"].concat(),
            ["document", ".write"].concat(),
            ["inner", "html"].concat(),
            ["outer", "html"].concat(),
            ["insert", "adjacent", "html"].concat(),
            ["{", "{"].concat(),
        ];
        for js in [WIRE_JS, SPARK_JS, MOTION_JS] {
            let lower = js.to_ascii_lowercase();
            for needle in &banned {
                assert!(
                    !lower.contains(needle),
                    "dynamic module contains forbidden token {needle}"
                );
            }
        }
        assert!(
            !SPARK_JS
                .to_ascii_lowercase()
                .contains(&["fetch", "("].concat()),
            "spark must stay network-free"
        );
        assert!(
            !MOTION_JS
                .to_ascii_lowercase()
                .contains(&["fetch", "("].concat()),
            "motion must stay network-free"
        );
    }

    #[test]
    fn dynamic_js_size_and_surface_are_locked() {
        assert!(WIRE_JS.lines().count() <= 500);
        assert!(SPARK_JS.lines().count() <= 700);
        assert!(WIRE_JS.contains("odyssey-wire v1"));
        assert!(WIRE_JS.contains("data-wire-target"));
        assert!(WIRE_JS.contains("data-wire-select"));
        // Boost region navigation (mark a shell scope; nav links go instant, no full reload).
        assert!(WIRE_JS.contains("data-wire-nav"));
        assert!(WIRE_JS.contains("data-wire-off"));
        assert!(WIRE_JS.contains("aria-current"));
        assert!(WIRE_JS.contains("wire:before"));
        assert!(WIRE_JS.contains("window.OdysseyWire"));
        assert!(WIRE_JS.contains("toast--ok"));
        // Directional history keeps both sides of an edge so mixed target regions survive
        // Back/Forward: Back uses the destination's outgoing contract, Forward its incoming one.
        assert!(WIRE_JS.contains("incoming:raw.incoming||null,outgoing:raw.outgoing||null"));
        assert!(WIRE_JS.contains("if(raw.index<from)return raw.outgoing||raw.incoming"));
        assert!(WIRE_JS.contains("if(raw.index>from)return raw.incoming||raw.outgoing"));
        assert!(WIRE_JS.contains("entry.outgoing=wireState(c)"));
        assert!(WIRE_JS.contains("incoming:incoming,outgoing:null"));
        assert!(WIRE_JS.contains("u.search=new URLSearchParams(fd).toString()"));
        assert!(WIRE_JS.contains("push=req.method==='GET'&&f.hasAttribute('data-wire-push')"));
        assert!(WIRE_JS.contains("a.classList.toggle('is-active',current)"));
        assert!(WIRE_JS.contains("(!lu.search||lu.search===w.location.search)"));
        assert!(WIRE_JS.contains("function trackScroll(){saveScroll(null,w.pageYOffset||0);}"));
        assert!(WIRE_JS.contains("w.addEventListener('scroll',trackScroll"));
        assert!(WIRE_JS.contains("w.addEventListener('pagehide',flushScroll)"));
        assert!(WIRE_JS.contains("err.name==='AbortError'"));
        assert!(WIRE_JS.contains("if(s.m!=='outer'&&s.m!=='inner'){w.location.reload();return;}"));
        assert!(WIRE_JS.contains("var ru=urlOf(r.url),ct=r.headers.get('Content-Type')||''"));

        let push = WIRE_JS.find("history.pushState({odysseyWire:").unwrap();
        let after = WIRE_JS.find("finish(trigger,'wire:after'").unwrap();
        assert!(
            push < after,
            "history must be visible to wire:after listeners"
        );
        let choose_direction = WIRE_JS.find("s=historyWire(raw,from)").unwrap();
        let enter_target = WIRE_JS.find("wireIndex=raw.index").unwrap();
        assert!(
            choose_direction < enter_target,
            "popstate must choose direction before entering the target index"
        );
        assert!(SPARK_JS.contains("odyssey-spark v1"));
        assert!(SPARK_JS.contains("data-spark-show"));
        assert!(SPARK_JS.contains("data-spark-click"));
        assert!(SPARK_JS.contains("window.OdysseySpark"));
        assert!(SPARK_JS.contains("odyssey:swap"));
        assert!(SPARK_JS.contains("toast--ok"));

        assert!(MOTION_JS.lines().count() <= 350);
        assert!(MOTION_JS.contains("odyssey-motion v1"));
        assert!(MOTION_JS.contains("window.OdysseyMotion"));
        assert!(MOTION_JS.contains("data-motion-list"));
        assert!(MOTION_JS.contains("startViewTransition"));

        let scripts = dynamic_scripts();
        assert_eq!(scripts.as_str().matches("<script>").count(), 1);
        assert!(scripts.as_str().contains("odyssey-wire v1"));
        assert!(scripts.as_str().contains("odyssey-spark v1"));
    }

    #[test]
    fn runtime_options_keep_default_compatible_and_add_motion_in_order() {
        let default = dynamic_scripts();
        assert_eq!(default.as_str().matches("<script").count(), 1);
        assert!(default.as_str().contains("odyssey-wire v1"));
        assert!(default.as_str().contains("odyssey-spark v1"));
        assert!(!default.as_str().contains("odyssey-motion v1"));

        let full = dynamic_scripts_with(
            RuntimeOpts::new()
                .with_motion()
                .with_nonce("request-7\" onload=\"bad"),
        );
        assert_eq!(full.as_str().matches("<script").count(), 1);
        assert!(full
            .as_str()
            .starts_with("<script nonce=\"request-7&quot; onload=&quot;bad\">"));
        assert!(!full.as_str().contains("\" onload=\""));
        assert!(full.as_str().contains("odyssey-motion v1"));

        let wire = full.as_str().find("odyssey-wire v1").unwrap();
        let spark = full.as_str().find("odyssey-spark v1").unwrap();
        let motion = full.as_str().find("odyssey-motion v1").unwrap();
        assert!(wire < spark && spark < motion);
    }

    #[test]
    fn public_init_composes_extended_forms() {
        let js = include_str!("../dist/odyssey.js");
        let forms_start = js.find("=== v1.1 forms-ext ===").unwrap();
        let data_start = js.find("=== v1.1 data-ext ===").unwrap();
        let forms = &js[forms_start..data_start];

        assert!(forms.contains("var formsInit = API.init;"));
        assert!(forms.contains("formsInit.call(API, root)"));
        assert!(forms.contains("API.initExtForms(root || document);"));
    }

    #[test]
    fn app_css_contains_dynamic_visibility_hooks() {
        assert!(APP_CSS.contains("[hidden]{display:none"));
        assert!(APP_CSS.contains("[data-spark-cloak]"));
    }

    #[test]
    fn app_css_contains_view_transition_layer() {
        // The cross-document continuity headline: @view-transition opt-in + the reduced-motion guard
        // that reaches the ::view-transition-* pseudos the global `*{animation:none}` rule cannot.
        assert!(APP_CSS.contains("@view-transition"));
        assert!(APP_CSS.contains("navigation:auto"));
        assert!(APP_CSS.contains("::view-transition-group(*)"));
        assert!(APP_CSS.contains("view-transition-name:ody-appbar"));
    }

    #[test]
    fn app_css_contains_motion_and_elevation_tokens() {
        assert!(APP_CSS.contains("--ease-out:"));
        assert!(APP_CSS.contains("--dur-3:240ms"));
        assert!(APP_CSS.contains("--elev-sticky"));
        // Dark scaffold ships ready but inert (nothing stamps data-theme this wave).
        assert!(APP_CSS.contains("[data-theme=\"dark\"]"));
    }

    #[test]
    fn app_css_contains_sovereign_atlas_visual_language() {
        assert!(APP_CSS.contains("--c-paper-0:#faf9f4"));
        assert!(APP_CSS.contains("--c-oxide-600:#b6422c"));
        assert!(APP_CSS.contains("--frame-rule:"));
        assert!(APP_CSS.contains("--surface-etched:"));
        assert!(APP_CSS.contains("background-size:48px 48px"));
        assert!(APP_CSS.contains("@media (forced-colors:active)"));
    }
}
