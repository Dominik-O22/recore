//! Holds the losses of a run, the totals that got worse, to the `Worse:` lines a change added to
//! the record of accepted losses, `bench/accepted-losses.txt`, each of which accepts a loss it
//! names with a reason. The record only grows: a line the change took out of it fails the run.

use std::collections::HashMap;
use std::fmt;

/// A total that got worse in one run of a corpus, as a `Worse:` line names it:
/// `Worse: <corpus>/<run> <count> <base> -> <head> (<difference>)`, and in a description a
/// reason after it in the record. `recore-decompile params --against` prints its losses in the
/// same form.
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

/// How a loss of a run, or a line of the record a change added or took out, stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A loss that a line names, with a reason, as large or larger.
    Accepted,
    /// A loss that no line names, or names smaller than it is.
    NotNamed,
    /// A line that names a count the run did not lose.
    NotLost,
    /// An added line that is not a loss in the form [`Loss`] prints with a reason after it, such
    /// as `Worse: none`.
    Unread,
    /// A line of the record at the base that the change took out or edited.
    Removed,
}

impl Standing {
    pub fn label(self) -> &'static str {
        match self {
            Standing::Accepted => "accepted",
            Standing::NotNamed => "not named",
            Standing::NotLost => "not lost",
            Standing::Unread => "unread",
            Standing::Removed => "removed",
        }
    }

    /// Whether the run fails for it. A line that names no loss of the run protects nothing, so
    /// it only prints.
    pub fn fails(self) -> bool {
        matches!(self, Standing::NotNamed | Standing::Unread | Standing::Removed)
    }
}

/// A loss or a line, how it stands, and for a loss of a run that prints one, what that run left
/// out of its counts, such as the functions that reached the decompiler's time limit.
#[derive(Debug, PartialEq, Eq)]
pub struct Judged<'a> {
    pub standing: Standing,
    /// An accepted loss as the run lost it, with the reason of the line that accepted it. A loss
    /// no line names as the line to add. A line of the record as it was written.
    pub line: String,
    pub note: Option<&'a str>,
}

/// Holds the losses a run printed, its `Worse:` lines in `found`, to the lines the change added
/// to the record, which held `before` at the base and holds `after` now: each loss, each added
/// line that names no loss of the run, and each line taken out, with how it stands. A run prints
/// what it left out of the counts of a run on a line `Left out: <corpus>/<run> <what>`.
pub fn judge<'a>(found: &'a str, before: &'a str, after: &'a str) -> Vec<Judged<'a>> {
    let notes: Vec<(&str, &str)> = found.lines().filter_map(|line| line.strip_prefix("Left out: ")?.split_once(' ')).collect();
    let note = |run: &str| notes.iter().find(|(of, _)| *of == run).map(|(_, note)| *note);
    let named: Vec<_> = minus(after, before).into_iter().map(|line| (line, Loss::parse(line).filter(|(_, why)| !why.is_empty()))).collect();
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
    let removed = minus(before, after).into_iter().map(|line| Judged { standing: Standing::Removed, line: line.to_string(), note: None });
    losses.chain(lines).chain(removed).collect()
}

/// The lines of the record in `from` that `taken` does not hold, each as often as `from` holds it
/// more. Order does not count, since two changes that each add a line merge in either order.
/// Blank lines and comments, which start `#`, are no part of the record.
fn minus<'a>(from: &'a str, taken: &str) -> Vec<&'a str> {
    fn records(text: &str) -> impl Iterator<Item = &str> {
        text.lines().filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
    }
    let mut left: HashMap<&str, usize> = HashMap::new();
    for line in records(taken) {
        *left.entry(line).or_default() += 1;
    }
    records(from)
        .filter(|line| match left.get_mut(line) {
            Some(count) if *count > 0 => {
                *count -= 1;
                false
            }
            _ => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOUND: &str = "Worse: corpus/recore starts found 100 -> 98 (-2)";
    /// The record at a base: its header and a loss an earlier change accepted.
    const BEFORE: &str = "# Every loss a change accepted.\n\nWorse: corpus-arm64/recore starts found 7 -> 6 (-1) an earlier change\n";

    fn standings(judged: &[Judged]) -> Vec<(Standing, String)> {
        judged.iter().map(|j| (j.standing, j.line.clone())).collect()
    }

    /// The record after a change appended `lines` to it.
    fn adding(lines: &str) -> String {
        format!("{BEFORE}{lines}\n")
    }

    #[test]
    fn a_loss_is_accepted_when_a_line_the_change_added_names_it_with_a_reason() {
        let found = "Worse: corpus-thumb/signatures global types right 812 -> 811 (-1)\n\
                     Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2)";
        let after = adding(
            "Worse: corpus-thumb/signatures global types right 812 -> 811 (-1) a knock-on of the right return\n\
             Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2) the truth misses two",
        );
        assert_eq!(
            standings(&judge(found, BEFORE, &after)),
            [
                (Standing::Accepted, "Worse: corpus-thumb/signatures global types right 812 -> 811 (-1) a knock-on of the right return".into()),
                (Standing::Accepted, "Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2) the truth misses two".into()),
            ]
        );
    }

    #[test]
    fn a_line_the_base_already_has_accepts_nothing() {
        let before = format!("{BEFORE}{FOUND} an earlier change\n");
        assert_eq!(standings(&judge(FOUND, &before, &before)), [(Standing::NotNamed, FOUND.into())]);
    }

    #[test]
    fn a_line_accepts_a_loss_up_to_the_size_it_names() {
        // Main moved the base since the line was written, and the change lost as much or less.
        // What was accepted is what the run lost.
        for named in ["Worse: corpus/recore starts found 103 -> 101 (-2) why", "Worse: corpus/recore starts found 100 -> 95 (-5) why"] {
            assert_eq!(standings(&judge(FOUND, "", named)), [(Standing::Accepted, format!("{FOUND} why"))]);
        }
        // A larger loss is not named, and the line to add is the run's.
        assert_eq!(standings(&judge(FOUND, "", "Worse: corpus/recore starts found 100 -> 99 (-1) why")), [(Standing::NotNamed, FOUND.into())]);
        // A gain of that count, or a loss of another run or count, names nothing of this run.
        for other in ["Worse: corpus/recore starts found 100 -> 103 (+3) why", "Worse: corpus/recore-noframes starts found 100 -> 98 (-2) why", "Worse: corpus/recore mid-func 100 -> 98 (-2) why"] {
            assert_eq!(standings(&judge(FOUND, "", other))[0], (Standing::NotNamed, FOUND.into()), "{other}");
        }
        assert_eq!(standings(&judge(FOUND, "", "Worse: corpus/recore mid-func 100 -> 98 (-2) why"))[1], (Standing::NotLost, "Worse: corpus/recore mid-func 100 -> 98 (-2) why".into()));
    }

    #[test]
    fn only_a_loss_not_named_a_line_out_of_form_and_a_line_taken_out_fail_the_run() {
        let all = [Standing::Accepted, Standing::NotNamed, Standing::NotLost, Standing::Unread, Standing::Removed];
        let fails: Vec<Standing> = all.into_iter().filter(|s| s.fails()).collect();
        assert_eq!(fails, [Standing::NotNamed, Standing::Unread, Standing::Removed]);
        // A line whose loss did not happen is printed, and the run goes on.
        assert_eq!(standings(&judge("", BEFORE, &adding(&format!("{FOUND} why")))), [(Standing::NotLost, format!("{FOUND} why"))]);
    }

    #[test]
    fn an_added_line_without_a_reason_or_out_of_form_is_unread() {
        // No reason, a reason of spaces, a difference that is not the totals', no difference, a
        // line that is no loss at all, and one that does not start the line.
        let lines = [
            FOUND.to_string(),
            format!("{FOUND}   "),
            "Worse: corpus/recore starts found 100 -> 98 (-1) why".into(),
            "Worse: corpus/recore starts found 100 -> 98 why".into(),
            "Worse: none".into(),
            format!("  {FOUND} why"),
        ];
        for line in lines {
            assert_eq!(standings(&judge(FOUND, BEFORE, &adding(&line))), [(Standing::NotNamed, FOUND.into()), (Standing::Unread, line.clone())], "{line:?}");
        }
        // Comments and blank lines are no part of the record.
        assert_eq!(judge("", BEFORE, &adding("\n# Worse: none\n   ")), []);
    }

    #[test]
    fn a_line_taken_out_or_edited_fails_and_one_moved_does_not() {
        let earlier = "Worse: corpus-arm64/recore starts found 7 -> 6 (-1) an earlier change";
        let edited = "Worse: corpus-arm64/recore starts found 7 -> 5 (-2) an earlier change";
        assert_eq!(standings(&judge("", BEFORE, "# Every loss a change accepted.\n")), [(Standing::Removed, earlier.into())]);
        let after = BEFORE.replace(earlier, edited);
        assert_eq!(standings(&judge("", BEFORE, &after)), [(Standing::NotLost, edited.into()), (Standing::Removed, earlier.into())]);
        // Two changes that each appended a line merge in either order, and a comment may change.
        let before = format!("{BEFORE}{FOUND} first\n");
        let after = format!("# The record.\n{FOUND} first\n{earlier}\n");
        assert_eq!(judge("", &before, &after), []);
    }

    #[test]
    fn a_loss_carries_what_its_run_left_out() {
        let found = format!("Left out: corpus/signatures for a timeout or after a lost worker, 3 in the base and 9 here\n{FOUND}\nWorse: corpus/signatures parameter counts right 50 -> 40 (-10)");
        let notes: Vec<Option<&str>> = judge(&found, "", "").iter().map(|j| j.note).collect();
        assert_eq!(notes, [None, Some("for a timeout or after a lost worker, 3 in the base and 9 here")]);
    }
}
