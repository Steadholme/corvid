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

pub use controls::{
    button, checkbox_field, field, field_err, field_hint, form, link_button, number_input,
    range_field, select, text_input, textarea, BtnOpts, Csrf, Variant,
};
pub use data::{card, card_list, empty_state, pager, progress, stat_tile, table, Col};
pub use feedback::{alert, filter_chip, modal, pill, skeleton, switch, toast, Tone};
pub use html::{esc, raw, Html};
pub use i18n::{fmt_date, fmt_int, month_abbr, resolve_locale, t, tf, tn, Locale};
pub use identity::{initial, letter_tile, tone};
pub use shell::{
    breadcrumb, console_head, layout_split, page_shell, pagehead, tabs, Brand, NavItem, PageChrome,
    PageHead, ShellOpts, Tab, TabsOpts, UserBox,
};

/// Both dynamic modules in one inline script block.
///
/// Order is wire then spark. Both modules are document-delegated and init-idempotent, so the
/// ordering is not load-bearing for consumers.
pub fn dynamic_scripts() -> Html {
    raw(format!("<script>{WIRE_JS}\n{SPARK_JS}</script>"))
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
            !SPARK_JS.to_ascii_lowercase().contains(&["fetch", "("].concat()),
            "spark must stay network-free"
        );
        assert!(
            !MOTION_JS.to_ascii_lowercase().contains(&["fetch", "("].concat()),
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
        assert!(WIRE_JS.contains("wire:before"));
        assert!(WIRE_JS.contains("window.OdysseyWire"));
        assert!(WIRE_JS.contains("toast--ok"));
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
}
