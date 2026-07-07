// GENERATED FROM odyssey — DO NOT EDIT
use crate::feedback::Tone;
use crate::html::{esc, Html};
use crate::i18n::{t, Locale};
use crate::icons;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Col {
    pub label: &'static str,
    pub numeric: bool,
}

pub fn card(title: &str, body: Html) -> Html {
    Html(format!(
        concat!(
            "<div class=\"card\">",
            "<div class=\"card__head\"><div class=\"card__title\"><h2>{}</h2></div></div>",
            "<div class=\"card__body\">{}</div>",
            "</div>"
        ),
        esc(title),
        body
    ))
}

pub fn card_list(title: &str, body: Html) -> Html {
    Html(format!(
        concat!(
            "<div class=\"card\">",
            "<div class=\"card__head\"><div class=\"card__title\"><h2>{}</h2></div></div>",
            "<div class=\"card__body card__body--list\">{}</div>",
            "</div>"
        ),
        esc(title),
        body
    ))
}

pub fn table(locale: Locale, cols: &[Col], rows: Vec<Vec<Html>>) -> Html {
    if rows.is_empty() {
        return empty_state(locale, "database");
    }

    let mut out = String::from("<div class=\"table-wrap\"><table><thead><tr>");
    for col in cols {
        if col.numeric {
            out.push_str(&format!("<th class=\"num\">{}</th>", esc(col.label)));
        } else {
            out.push_str(&format!("<th>{}</th>", esc(col.label)));
        }
    }
    out.push_str("</tr></thead><tbody>");

    for row in rows {
        out.push_str("<tr>");
        for (idx, col) in cols.iter().enumerate() {
            let cell = row.get(idx).map(Html::as_str).unwrap_or("");
            if col.numeric {
                out.push_str(&format!("<td class=\"num\">{}</td>", cell));
            } else {
                out.push_str(&format!("<td>{}</td>", cell));
            }
        }
        out.push_str("</tr>");
    }

    out.push_str("</tbody></table></div>");
    Html(out)
}

pub fn stat_tile(label: &str, value: &str, spark: Option<Html>, sub: Option<&str>) -> Html {
    let sub = sub
        .map(|text| format!("<div class=\"stat__meta\">{}</div>", esc(text)))
        .unwrap_or_default();
    let spark = spark.map(|html| html.0).unwrap_or_default();
    Html(format!(
        concat!(
            "<div class=\"stat\">",
            "<div class=\"stat__label\">{}</div>",
            "<div class=\"stat__value\">{}</div>",
            "{}{}",
            "</div>"
        ),
        esc(label),
        esc(value),
        sub,
        spark
    ))
}

pub fn empty_state(locale: Locale, icon: &'static str) -> Html {
    Html(format!(
        concat!(
            "<div class=\"empty\">",
            "<div class=\"empty__ico\">{}</div>",
            "<h3>{}</h3>",
            "<p>{}</p>",
            "</div>"
        ),
        icons::icon(icon),
        esc(t(locale, "empty.no_data.title")),
        esc(t(locale, "empty.no_data.note"))
    ))
}

pub fn pager(locale: Locale, current: u64, total: u64, base: &str) -> Html {
    if total <= 1 {
        return Html::default();
    }
    debug_assert!(current >= 1 && current <= total);

    let prev = if current > 1 {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}{}\">{}</a>",
            esc(base),
            current - 1,
            esc(t(locale, "pager.prev"))
        )
    } else {
        format!(
            "<span class=\"btn btn-ghost btn-sm is-disabled\" aria-disabled=\"true\">{}</span>",
            esc(t(locale, "pager.prev"))
        )
    };
    let next = if current < total {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"{}{}\">{}</a>",
            esc(base),
            current + 1,
            esc(t(locale, "pager.next"))
        )
    } else {
        format!(
            "<span class=\"btn btn-ghost btn-sm is-disabled\" aria-disabled=\"true\">{}</span>",
            esc(t(locale, "pager.next"))
        )
    };

    let mut out = format!(
        "<nav class=\"pager\" aria-label=\"{}\">{}<span class=\"pager__spacer\"></span>",
        esc(t(locale, "pager.label")),
        prev
    );
    render_pager_window(&mut out, current, total, base);
    out.push_str(&next);
    out.push_str("</nav>");
    Html(out)
}

fn render_pager_window(out: &mut String, current: u64, total: u64, base: &str) {
    if total <= 7 {
        for page in 1..=total {
            render_page(out, page, current, base);
        }
        return;
    }

    render_page(out, 1, current, base);
    if current <= 4 {
        for page in 2..=5.min(total - 1) {
            render_page(out, page, current, base);
        }
        render_gap(out);
    } else if current >= total - 3 {
        render_gap(out);
        for page in (total - 4).max(2)..=total - 1 {
            render_page(out, page, current, base);
        }
    } else {
        render_gap(out);
        for page in current - 1..=current + 1 {
            render_page(out, page, current, base);
        }
        render_gap(out);
    }
    render_page(out, total, current, base);
}

fn render_page(out: &mut String, page: u64, current: u64, base: &str) {
    if page == current {
        out.push_str(&format!(
            "<span class=\"is-current\" aria-current=\"page\">{page}</span>"
        ));
    } else {
        out.push_str(&format!("<a href=\"{}{}\">{page}</a>", esc(base), page));
    }
}

fn render_gap(out: &mut String) {
    out.push_str("<span class=\"pager__gap\" aria-hidden=\"true\">…</span>");
}

pub fn progress(pct: u8, tone: Tone) -> Html {
    debug_assert!(pct <= 100);
    Html(format!(
        "<div class=\"progress{}\" role=\"progressbar\" aria-valuemin=\"0\" aria-valuemax=\"100\" aria-valuenow=\"{}\"><span class=\"progress__bar\" style=\"--w:{}%\"></span></div>",
        tone.progress_class(),
        pct,
        pct
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rows_render_empty_state_instead_of_table() {
        let html = table(
            Locale::En,
            &[Col {
                label: "Name",
                numeric: false,
            }],
            Vec::new(),
        );
        assert!(html.as_str().contains("class=\"empty\""));
        assert!(!html.as_str().contains("<table>"));
    }

    #[test]
    fn empty_state_renders_localized_zh_copy() {
        let html = empty_state(Locale::Zh, "database");

        assert!(html.as_str().contains("暂无数据"));
        assert!(html.as_str().contains("这里还没有内容。"));
    }

    #[test]
    fn pager_omits_single_page_sets_disabled_prev_and_escapes_base() {
        assert_eq!(pager(Locale::En, 1, 1, "/items?page=").as_str(), "");

        let html = pager(Locale::En, 1, 3, "/items?state=open&page=");
        assert!(html.as_str().contains("aria-label=\"Pagination\""));
        assert!(html.as_str().contains(
            "class=\"btn btn-ghost btn-sm is-disabled\" aria-disabled=\"true\">Previous"
        ));
        assert!(html
            .as_str()
            .contains("href=\"/items?state=open&amp;page=2\""));
        assert!(html
            .as_str()
            .contains("<span class=\"is-current\" aria-current=\"page\">1</span>"));
    }

    #[test]
    fn pager_long_window_uses_gaps_and_localized_zh_copy() {
        let html = pager(Locale::Zh, 10, 20, "/items?page=");

        assert_eq!(html.as_str().matches("pager__gap").count(), 2);
        assert!(html.as_str().contains("aria-label=\"分页\""));
        assert!(html.as_str().contains(">上一页<"));
        assert!(html.as_str().contains(">下一页<"));
        assert!(html.as_str().contains(">9</a>"));
        assert!(html
            .as_str()
            .contains("<span class=\"is-current\" aria-current=\"page\">10</span>"));
        assert!(html.as_str().contains(">11</a>"));
    }

    #[test]
    fn progress_emits_aria_value_tone_class_and_width_var() {
        let html = progress(63, Tone::Warn);

        assert!(html.as_str().contains("class=\"progress progress--warn\""));
        assert!(html.as_str().contains("role=\"progressbar\""));
        assert!(html.as_str().contains("aria-valuenow=\"63\""));
        assert!(html.as_str().contains("style=\"--w:63%\""));
    }
}
