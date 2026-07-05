// GENERATED FROM odyssey — DO NOT EDIT
use crate::html::{esc, Html};
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

pub fn table(cols: &[Col], rows: Vec<Vec<Html>>) -> Html {
    if rows.is_empty() {
        return empty_state("database", "No data", "There are no rows to display.");
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

pub fn empty_state(icon: &'static str, heading: &str, note: &str) -> Html {
    Html(format!(
        concat!(
            "<div class=\"empty\">",
            "<div class=\"empty__ico\">{}</div>",
            "<h3>{}</h3>",
            "<p>{}</p>",
            "</div>"
        ),
        icons::icon(icon),
        esc(heading),
        esc(note)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rows_render_empty_state_instead_of_table() {
        let html = table(
            &[Col {
                label: "Name",
                numeric: false,
            }],
            Vec::new(),
        );
        assert!(html.as_str().contains("class=\"empty\""));
        assert!(!html.as_str().contains("<table>"));
    }
}
