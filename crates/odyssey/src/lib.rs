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
pub mod icons;
pub mod shell;

pub use controls::{
    button, checkbox_field, field, field_hint, form, link_button, number_input, range_field,
    select, text_input, textarea, BtnOpts, Csrf, Variant,
};
pub use data::{card, card_list, empty_state, stat_tile, table, Col};
pub use feedback::{pill, switch, toast, Tone};
pub use html::{esc, raw, Html};
pub use shell::{
    console_head, layout_split, page_shell, Brand, NavItem, PageChrome, ShellOpts, UserBox,
};
