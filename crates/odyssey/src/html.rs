// GENERATED FROM odyssey — DO NOT EDIT
use std::fmt;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Html(pub String);

impl Html {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn concat<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Html>,
    {
        let mut out = String::new();
        for html in iter {
            out.push_str(html.as_str());
        }
        Html(out)
    }
}

impl fmt::Display for Html {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn esc(s: &str) -> Html {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    Html(out)
}

pub fn raw(s: impl Into<String>) -> Html {
    Html(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            esc("<script data-x=\"&\">'</script>").as_str(),
            "&lt;script data-x=&quot;&amp;&quot;&gt;&#x27;&lt;/script&gt;"
        );
    }
}
