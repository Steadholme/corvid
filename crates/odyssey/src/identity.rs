// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{esc, Html};

pub fn tone(key: &str) -> u8 {
    (key.bytes().map(usize::from).sum::<usize>() % 5 + 1) as u8
}

pub fn initial(s: &str) -> String {
    s.chars()
        .find(|ch| ch.is_alphanumeric())
        .map(|ch| ch.to_uppercase().collect())
        .unwrap_or_else(|| String::from("•"))
}

pub fn letter_tile(label: &str, tone_key: &str) -> Html {
    Html(format!(
        "<span class=\"letter-tile tone-{}\" aria-hidden=\"true\">{}</span>",
        tone(tone_key),
        esc(&initial(label))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tone_matches_estate_golden_vectors() {
        assert_eq!(tone("alice"), 1);
        assert_eq!(tone("support"), 3);
        assert_eq!(tone(""), 1);
        assert_eq!(tone("alice"), tone("alice"));
    }

    #[test]
    fn initial_finds_first_alphanumeric_and_uppercases() {
        assert_eq!(initial("alice"), "A");
        assert_eq!(initial("  张三"), "张");
        assert_eq!(initial("!"), "•");
    }

    #[test]
    fn letter_tile_emits_tone_class_and_escaped_initial() {
        let html = letter_tile("<script>Alice", "support");

        assert!(html.as_str().contains("class=\"letter-tile tone-3\""));
        assert!(html.as_str().contains("aria-hidden=\"true\""));
        assert!(html.as_str().contains(">S</span>"));
        assert!(!html.as_str().contains("<script>"));
    }
}
