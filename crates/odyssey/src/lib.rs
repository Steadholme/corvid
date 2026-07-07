// GENERATED FROM odyssey — DO NOT EDIT
pub const APP_CSS: &str = concat!(
    include_str!("../css/font.css"),
    include_str!("../css/tokens.css"),
    include_str!("../css/components.css")
);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_css_contains_compact_density_block() {
        assert!(APP_CSS.contains("[data-density=\"compact\"]"));
        assert!(APP_CSS.contains("--tap:32px"));
        assert!(APP_CSS.contains("--fs-body:13.5px"));
    }
}
