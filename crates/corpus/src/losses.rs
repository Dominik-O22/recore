//! Holds the losses of a run, the totals that got worse, to the `Worse:` lines of a pull
//! request's description, each of which accepts a loss it names with a reason.
//!
//! A line counts only where GitHub shows it, since the reviewer reads the rendered page: nothing
//! inside an HTML comment or other HTML GitHub renders as nothing counts (see [`shown`]).

use std::fmt;

/// A total that got worse in one run of a corpus, as a `Worse:` line names it:
/// `Worse: <corpus>/<run> <count> <base> -> <head> (<difference>)`, and in a description a
/// reason after it. `recore-decompile params --against` prints its losses in the same form.
#[derive(Debug, PartialEq, Eq)]
pub struct Loss<'a> {
    /// `<corpus>/<run>`, such as `corpus-thumb/recore-noframes` or `corpus-thumb/signatures`.
    pub run: &'a str,
    pub count: &'a str,
    pub base: u64,
    pub head: u64,
}

impl fmt::Display for Loss<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Worse: {} {} {} -> {} ({:+})", self.run, self.count, self.base, self.head, self.difference())
    }
}

impl<'a> Loss<'a> {
    fn difference(&self) -> i128 {
        i128::from(self.head) - i128::from(self.base)
    }

    /// The loss a line names and the reason that follows it, or `None` when the line is not in
    /// the form [`Loss`] prints, or its difference is not that of its totals.
    fn parse(line: &'a str) -> Option<(Self, &'a str)> {
        let (run, rest) = line.strip_prefix("Worse: ")?.split_once(' ')?;
        let (count_base, rest) = rest.split_once(" -> ")?;
        let (count, base) = count_base.rsplit_once(' ')?;
        let (head, rest) = rest.split_once(" (")?;
        let (difference, reason) = rest.split_once(')')?;
        let loss = Loss { run, count, base: base.parse().ok()?, head: head.parse().ok()? };
        (difference.parse::<i128>().ok()? == loss.difference()).then_some((loss, reason.trim()))
    }

    /// Whether a line that names this loss accepts `lost`: the same count of the same run, moved
    /// the same way and no farther. A line is an upper bound, since a signature count moves a
    /// little from run to run with the functions that reach the decompiler's time limit. The
    /// totals themselves are the base's too, and the base is main when the change lands.
    fn covers(&self, lost: &Loss) -> bool {
        let (named, actual) = (self.difference(), lost.difference());
        (self.run, self.count) == (lost.run, lost.count) && named.signum() == actual.signum() && named.abs() >= actual.abs()
    }
}

/// How a loss of a run, or a `Worse:` line of a description, stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A loss that a line names, with a reason, as large or larger.
    Accepted,
    /// A loss that no line names, or names smaller than it is.
    NotNamed,
    /// A line that names a count the run did not lose.
    NotLost,
    /// A line GitHub shows that starts `Worse:` and is not a loss in the form [`Loss`] prints
    /// with a reason after it, such as `Worse: none`.
    Unread,
    /// A line that starts `Worse:` where GitHub does not show it, which accepts nothing.
    Hidden,
}

impl Standing {
    pub fn label(self) -> &'static str {
        match self {
            Standing::Accepted => "accepted",
            Standing::NotNamed => "not named",
            Standing::NotLost => "not lost",
            Standing::Unread => "unread",
            Standing::Hidden => "hidden",
        }
    }

    /// Whether the run fails for it. A line that names no loss of the run protects nothing, so
    /// it only prints.
    pub fn fails(self) -> bool {
        matches!(self, Standing::NotNamed | Standing::Unread)
    }
}

/// A loss or a line, how it stands, and for a loss of a run that prints one, what that run left
/// out of its counts, such as the functions that reached the decompiler's time limit.
#[derive(Debug, PartialEq, Eq)]
pub struct Judged<'a> {
    pub standing: Standing,
    /// An accepted loss as the run lost it, with the reason of the line that accepted it. A loss
    /// no line names as the line to write. A line of the description as GitHub shows it.
    pub line: String,
    pub note: Option<&'a str>,
}

/// Holds the losses a run printed, its `Worse:` lines in `found`, to the `Worse:` lines of
/// `description`: each loss and each line, with how it stands. A run prints what it left out
/// of the counts of a run on a line `Left out: <corpus>/<run> <what>`.
pub fn judge<'a>(found: &'a str, description: &str) -> Vec<Judged<'a>> {
    let notes: Vec<(&str, &str)> = found.lines().filter_map(|line| line.strip_prefix("Left out: ")?.split_once(' ')).collect();
    let note = |run: &str| notes.iter().find(|(of, _)| *of == run).map(|(_, note)| *note);
    let shown = shown(description);
    let mut hidden = Vec::new();
    let mut named = Vec::new();
    for (raw, line) in description.split('\n').zip(shown.split('\n')) {
        let (raw, line) = (raw.trim_end_matches('\r'), line.trim_end_matches('\r'));
        if line.starts_with("Worse:") {
            named.push((line, Loss::parse(line).filter(|(_, why)| !why.is_empty())));
        } else if raw.starts_with("Worse:") {
            hidden.push(raw);
        }
    }
    let lost: Vec<Loss> = found.lines().filter_map(|line| Some(Loss::parse(line)?.0)).collect();
    let losses = lost.iter().map(|loss| {
        let accepting = named.iter().filter_map(|(_, named)| named.as_ref()).find(|(named, _)| named.covers(loss));
        let (standing, line) = match accepting {
            Some((_, why)) => (Standing::Accepted, format!("{loss} {why}")),
            None => (Standing::NotNamed, loss.to_string()),
        };
        Judged { standing, line, note: note(loss.run) }
    });
    let lines = named.iter().filter_map(|(line, loss)| {
        let standing = match loss {
            None => Standing::Unread,
            Some((loss, _)) if !lost.iter().any(|lost| (lost.run, lost.count) == (loss.run, loss.count)) => Standing::NotLost,
            Some(_) => return None,
        };
        Some(Judged { standing, line: line.to_string(), note: None })
    });
    let hidden = hidden.into_iter().map(|line| Judged { standing: Standing::Hidden, line: line.to_string(), note: None });
    losses.chain(lines).chain(hidden).collect()
}

/// Elements that have no content, or no closing tag, so hide nothing after them.
const VOID: [&str; 13] = ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];
/// Elements whose content GitHub shows: a `<details>` folds it, and a click opens it.
const SHOWN: [&str; 2] = ["details", "summary"];
/// What opens HTML that GitHub renders as nothing, and what closes it: a comment, CDATA, a
/// processing instruction and a declaration. Unclosed, it runs to the end, as it does there.
const UNSEEN: [(&str, &str); 4] = [("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>"), ("<!", ">")];

/// `text` as GitHub shows it, line for line, with what it renders as nothing left out: HTML
/// comments and the other constructs of [`UNSEEN`], tags with their attributes, the content of
/// an element other than [`SHOWN`] and [`VOID`] ones, such as `<video>` or `<rp>`, and link
/// reference definitions, whose titles may run over several lines.
///
/// It errs toward hiding: the content of an element GitHub shows, or HTML inside a code span,
/// is hidden here too. A line hidden that should not be accepts nothing, so its loss fails the
/// run as one no line names, and the run prints the line as hidden.
fn shown(text: &str) -> String {
    enum In {
        Text,
        Unseen(&'static str),
        Tag { quote: Option<char> },
        Definition,
    }
    let (mut state, mut tag, mut open, mut out) = (In::Text, String::new(), Vec::<String>::new(), String::new());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        match state {
            In::Definition if line.trim().is_empty() => state = In::Text,
            In::Text if definition(line) => state = In::Definition,
            _ => {}
        }
        let mut rest = line;
        while let Some(c) = rest.chars().next() {
            match &mut state {
                In::Definition => break,
                In::Unseen(closer) => match rest.find(*closer) {
                    Some(at) => {
                        rest = &rest[at + closer.len()..];
                        state = In::Text;
                    }
                    None => break,
                },
                In::Tag { quote } => {
                    rest = &rest[c.len_utf8()..];
                    match *quote {
                        Some(q) if c == q => *quote = None,
                        Some(_) => {}
                        None if c == '"' || c == '\'' => *quote = Some(c),
                        None if c == '>' => {
                            close(&tag, &mut open);
                            state = In::Text;
                        }
                        None => tag.push(c),
                    }
                }
                In::Text => {
                    if let Some((opener, closer)) = UNSEEN.iter().find(|(opener, _)| rest.starts_with(opener)) {
                        rest = &rest[opener.len()..];
                        state = In::Unseen(closer);
                    } else if starts_tag(rest) {
                        rest = &rest[1..];
                        tag.clear();
                        state = In::Tag { quote: None };
                    } else {
                        rest = &rest[c.len_utf8()..];
                        if open.is_empty() {
                            out.push(c);
                        }
                    }
                }
            }
        }
        if let In::Tag { quote: None } = state {
            tag.push(' ');
        }
    }
    out
}

/// Whether `text` starts with a tag, `<name` or `</name` and then a space, `/` or `>`, rather
/// than an autolink such as `<https://...>` or a `<` of prose.
fn starts_tag(text: &str) -> bool {
    let name = text.strip_prefix('<').map(|rest| rest.strip_prefix('/').unwrap_or(rest)).unwrap_or_default();
    let end = name.find(|c: char| !c.is_ascii_alphanumeric() && c != '-').unwrap_or(name.len());
    name.starts_with(|c: char| c.is_ascii_alphabetic()) && name[end..].chars().next().is_none_or(|c| c.is_whitespace() || c == '/' || c == '>')
}

/// Takes the tag that `>` closed, its text from after `<` on, into the elements open.
fn close(tag: &str, open: &mut Vec<String>) {
    let (end, name) = tag.strip_prefix('/').map_or((false, tag), |name| (true, name));
    let name = name.split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or_default().to_ascii_lowercase();
    if end {
        if let Some(at) = open.iter().rposition(|open| *open == name) {
            open.truncate(at);
        }
    } else if !tag.trim_end().ends_with('/') && !VOID.contains(&name.as_str()) && !SHOWN.contains(&name.as_str()) {
        open.push(name);
    }
}

/// Whether a line starts a link reference definition, `[label]: <destination> "title"`, after
/// the marks of a list or a quote: GitHub shows none of it, and its title runs to a blank line.
fn definition(line: &str) -> bool {
    let rest = line.trim_start_matches(|c: char| c.is_whitespace() || "->*+.)".contains(c) || c.is_ascii_digit());
    rest.starts_with('[') && rest.contains("]:")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOUND: &str = "Worse: corpus/recore starts found 100 -> 98 (-2)";

    fn standings<'a>(judged: &[Judged<'a>]) -> Vec<(Standing, String)> {
        judged.iter().map(|j| (j.standing, j.line.clone())).collect()
    }

    #[test]
    fn a_loss_is_accepted_when_a_line_names_it_with_a_reason() {
        let found = "Worse: corpus-thumb/signatures global types right 812 -> 811 (-1)\n\
                     Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2)";
        let named = "Fixes the returns.\r\n\r\n\
                     Worse: corpus-thumb/signatures global types right 812 -> 811 (-1) a knock-on of the right return\r\n\
                     Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2) the truth misses two\r\n";
        assert_eq!(
            standings(&judge(found, named)),
            [
                (Standing::Accepted, "Worse: corpus-thumb/signatures global types right 812 -> 811 (-1) a knock-on of the right return".into()),
                (Standing::Accepted, "Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2) the truth misses two".into()),
            ]
        );
    }

    #[test]
    fn a_line_accepts_a_loss_up_to_the_size_it_names() {
        // Main moved the base since the line was written, and the change lost as much or less.
        // What was accepted is what the run lost.
        for named in ["Worse: corpus/recore starts found 103 -> 101 (-2) why", "Worse: corpus/recore starts found 100 -> 95 (-5) why"] {
            assert_eq!(standings(&judge(FOUND, named)), [(Standing::Accepted, format!("{FOUND} why"))]);
        }
        // A larger loss is not named, and the line to write is the run's.
        assert_eq!(standings(&judge(FOUND, "Worse: corpus/recore starts found 100 -> 99 (-1) why")), [(Standing::NotNamed, FOUND.into())]);
        // A gain of that count, or a loss of another run or count, names nothing of this run.
        for other in ["Worse: corpus/recore starts found 100 -> 103 (+3) why", "Worse: corpus/recore-noframes starts found 100 -> 98 (-2) why", "Worse: corpus/recore mid-func 100 -> 98 (-2) why"] {
            let judged = judge(FOUND, other);
            assert_eq!(standings(&judged)[0], (Standing::NotNamed, FOUND.into()), "{other}");
        }
        assert_eq!(standings(&judge(FOUND, "Worse: corpus/recore mid-func 100 -> 98 (-2) why"))[1], (Standing::NotLost, "Worse: corpus/recore mid-func 100 -> 98 (-2) why".into()));
    }

    #[test]
    fn only_a_loss_not_named_and_a_line_out_of_form_fail_the_run() {
        let fails: Vec<Standing> = [Standing::Accepted, Standing::NotNamed, Standing::NotLost, Standing::Unread, Standing::Hidden].into_iter().filter(|s| s.fails()).collect();
        assert_eq!(fails, [Standing::NotNamed, Standing::Unread]);
        // A line whose loss did not happen is printed, and the run goes on.
        assert_eq!(standings(&judge("", &format!("{FOUND} why"))), [(Standing::NotLost, format!("{FOUND} why"))]);
    }

    #[test]
    fn a_line_without_a_reason_or_out_of_form_is_unread() {
        // No reason, a reason of spaces, a difference that is not the totals', no difference,
        // and a line that is no loss at all.
        for line in [FOUND.to_string(), format!("{FOUND}   "), "Worse: corpus/recore starts found 100 -> 98 (-1) why".into(), "Worse: corpus/recore starts found 100 -> 98 why".into(), "Worse: none".into()] {
            assert_eq!(standings(&judge(FOUND, &line)), [(Standing::NotNamed, FOUND.into()), (Standing::Unread, line.clone())], "{line:?}");
        }
        // A line that does not start the description's line is no `Worse:` line.
        assert_eq!(judge("", &format!("  {FOUND} why")), []);
    }

    #[test]
    fn a_line_github_does_not_show_accepts_nothing() {
        let line = "Worse: corpus/recore starts found 100 -> 97 (-3) hidden";
        for description in [
            // A comment over several lines, on one line around the line's reason, and one never
            // closed, which hides the rest of the page.
            format!("Fixes x.\n<!--\n{line}\n-->"),
            format!("<!-- a template's hint -->\n<!--\n\n{line}\n-->\n"),
            format!("Fixes x.\n<!--\n{line}"),
            // The other constructs GitHub renders as nothing.
            format!("<?php\n{line}\n?>"),
            format!("<!DOCTYPE\n{line}\n>"),
            format!("<![CDATA[\n{line}\n]]>"),
            // An attribute, quoted across lines and holding a `>`, and an attribute left open
            // across a blank line, which takes the rest of the page.
            format!("<a title=\"x > y\n{line}\n\">x</a>"),
            format!("<div title=\"\n\n{line}\n\">"),
            // The content of an element GitHub drops or a browser does not show.
            format!("<video>\n{line}\n</video>"),
            format!("<ruby>x<rp>\n{line}\n</rp></ruby>"),
            // The title of a link reference definition, alone or in a list.
            format!("[x]: /url \"\n{line}\n\""),
            format!("- [x]: /url '\n{line}\n'"),
        ] {
            assert_eq!(standings(&judge(FOUND, &description)), [(Standing::NotNamed, FOUND.into()), (Standing::Hidden, line.into())], "{description:?}");
        }
        // A reason in a comment is no reason.
        assert_eq!(judge(FOUND, &format!("{FOUND} <!-- why -->"))[1].standing, Standing::Unread);
    }

    #[test]
    fn a_line_github_shows_counts() {
        let line = format!("{FOUND} why");
        for description in [
            // A `<details>` folds it, and a click shows it.
            format!("<details><summary>Losses</summary>\n\n{line}\n</details>"),
            // After a comment or an element that closed, or an autolink.
            format!("<!-- a template's hint -->\n{line}"),
            format!("<!--\nhint\n-->{line}"),
            format!("<b>Losses</b><br>\n<img src=\"x.png\">\n<https://example.com>\n{line}"),
            format!("[x]: /url\n\n{line}"),
        ] {
            assert_eq!(standings(&judge(FOUND, &description)), [(Standing::Accepted, line.clone())], "{description:?}");
        }
    }

    #[test]
    fn a_loss_carries_what_its_run_left_out() {
        let found = format!("Left out: corpus/signatures for a timeout or after a lost worker, 3 in the base and 9 here\n{FOUND}\nWorse: corpus/signatures parameter counts right 50 -> 40 (-10)");
        let notes: Vec<Option<&str>> = judge(&found, "").iter().map(|j| j.note).collect();
        assert_eq!(notes, [None, Some("for a timeout or after a lost worker, 3 in the base and 9 here")]);
    }
}
