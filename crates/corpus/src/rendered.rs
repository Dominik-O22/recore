//! The lines of text a page that GitHub rendered shows, read from the HTML GitHub returns for it:
//! a pull request's `body_html`, or what the `markdown` endpoint gives for a text.
//!
//! This reads GitHub's output and models none of its Markdown. Text counts only inside the
//! elements of [`BLOCKS`] and [`INLINE`], all the way up, so the text of a code block, a heading,
//! a table, a `<summary>` or an element a browser may not show, such as `<rp>`, is left out, as
//! are attributes and comments.

/// Elements that hold lines of prose: paragraphs and lists, and the quotes and `<details>` blocks
/// they sit in. A `<details>` block folds, and a click opens it.
const BLOCKS: [&str; 7] = ["p", "li", "ul", "ol", "blockquote", "details", "div"];
/// Markup within a line, whose text shows as part of it.
const INLINE: [&str; 15] = ["a", "b", "strong", "i", "em", "code", "del", "s", "ins", "sub", "sup", "kbd", "mark", "span", "g-emoji"];
/// Elements that have no content and no closing tag.
const VOID: [&str; 13] = ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];

/// The lines of prose the page shows, each trimmed, with markup reduced to its text and
/// character references turned back. A line ends at a line break of the text, at `<br>`, and
/// where an element other than [`INLINE`] markup starts or ends.
pub fn lines(html: &str) -> Vec<String> {
    let (mut open, mut lines, mut rest) = (Vec::<String>::new(), vec![String::new()], html);
    while !rest.is_empty() {
        if let Some(comment) = rest.strip_prefix("<!--") {
            rest = comment.find("-->").map_or("", |at| &comment[at + 3..]);
        } else if let Some(tag) = rest.strip_prefix('<').filter(|tag| tag.starts_with(|c: char| c.is_ascii_alphabetic() || c == '/')) {
            let end = tag_end(tag);
            let (body, closing) = match tag[..end].strip_prefix('/') {
                Some(body) => (body, true),
                None => (&tag[..end], false),
            };
            rest = tag.get(end + 1..).unwrap_or_default();
            let name = body.split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or_default().to_ascii_lowercase();
            if !INLINE.contains(&name.as_str()) {
                lines.push(String::new());
            }
            if closing {
                if let Some(at) = open.iter().rposition(|open| *open == name) {
                    open.truncate(at);
                }
            } else if !VOID.contains(&name.as_str()) && !body.ends_with('/') {
                open.push(name);
            }
        } else {
            // Past its first character, which may be a `<` that starts no tag.
            let end = rest.char_indices().skip(1).find(|&(_, c)| c == '<').map_or(rest.len(), |(at, _)| at);
            if open.iter().all(|name| BLOCKS.contains(&name.as_str()) || INLINE.contains(&name.as_str())) {
                for (index, part) in decode(&rest[..end]).split('\n').enumerate() {
                    if index > 0 {
                        lines.push(String::new());
                    }
                    lines.last_mut().expect("lines starts with one").push_str(part);
                }
            }
            rest = &rest[end..];
        }
    }
    lines.into_iter().map(|line| line.trim().to_string()).filter(|line| !line.is_empty()).collect()
}

/// Where the `>` that ends a tag is, past `<`, outside quoted attribute values; the end of the
/// text if none does.
fn tag_end(tag: &str) -> usize {
    let mut quote = None;
    for (at, c) in tag.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '>' => return at,
            None => {}
        }
    }
    tag.len()
}

/// Text with its character references turned back, such as `&gt;` to `>`. One it does not know
/// stays as it is.
fn decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let reference = rest[1..].find(';').map(|end| &rest[1..end + 1]);
        let c = reference.and_then(|name| match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => {
                let number = name.strip_prefix('#')?;
                let code = match number.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => number.parse(),
                };
                char::from_u32(code.ok()?)
            }
        });
        match (c, reference) {
            (Some(c), Some(name)) => {
                out.push(c);
                rest = &rest[name.len() + 2..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::losses::{Standing, judge};
    use std::path::Path;

    /// What the line of each case below loses in its run.
    const FOUND: &str = "Worse: corpus/recore starts found 100 -> 98 (-2)";

    /// Each `<case>.html` in tests/rendered is what GitHub rendered from `<case>.md` (with
    /// `gh api markdown -f mode=gfm -f context=Dominik-O22/recore -f text="$(cat <case>.md)"`), or
    /// a pull request's `body_html`. Its name says whether a run that lost [`FOUND`] accepts the
    /// loss with the lines of the page: `accepted-` or `not-named-`.
    #[test]
    fn a_line_counts_where_the_page_github_rendered_shows_it() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/rendered");
        let mut cases: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.extension().is_some_and(|e| e == "html")).collect();
        cases.sort();
        assert!(cases.len() >= 13, "{} cases in {}", cases.len(), dir.display());
        for case in cases {
            let name = case.file_stem().unwrap().to_string_lossy().into_owned();
            let expected = if name.starts_with("accepted-") { Standing::Accepted } else { Standing::NotNamed };
            let named = lines(&std::fs::read_to_string(&case).unwrap()).join("\n");
            assert_eq!(judge(FOUND, &named)[0].standing, expected, "{name}: {named}");
        }
    }

    #[test]
    fn markup_in_a_line_is_reduced_to_its_text() {
        let html = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/rendered/accepted-inline-markup.html")).unwrap();
        assert_eq!(lines(&html), ["Worse: corpus/recore starts found 100 -> 97 (-3) the truth is wrong & old, see here"]);
    }

    #[test]
    fn lines_end_at_line_breaks_and_blocks() {
        assert_eq!(lines("<p>a<br>\nb</p><p>c</p>\n<ul>\n<li>d <em>e</em></li>\n</ul>"), ["a", "b", "c", "d e"]);
        // Text inside an element that is not on the lists, and an attribute, is left out.
        assert_eq!(lines("<p>a<rp>b</rp>c<img alt=\"d > e\">f</p>"), ["a", "c", "f"]);
    }

    #[test]
    fn references_are_turned_back() {
        assert_eq!(decode("a -&gt; b &amp;&lt;&quot;&#39;&#x41;&#66; &unknown; & x;"), "a -> b &<\"'AB &unknown; & x;");
    }
}
