//! Holds the losses of a run, the totals that got worse, to `Worse:` lines, each of which
//! accepts a loss it names with a reason. The lines are a pull request's as the page GitHub
//! renders shows them (see [`crate::rendered`]), or typed for a run by hand.

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
    /// A line that starts `Worse:` and is not a loss in the form [`Loss`] prints with a reason
    /// after it, such as `Worse: none`.
    Unread,
}

impl Standing {
    pub fn label(self) -> &'static str {
        match self {
            Standing::Accepted => "accepted",
            Standing::NotNamed => "not named",
            Standing::NotLost => "not lost",
            Standing::Unread => "unread",
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
    /// no line names as the line to write. A `Worse:` line as it was named.
    pub line: String,
    pub note: Option<&'a str>,
}

/// Holds the losses a run printed, its `Worse:` lines in `found`, to the lines of `named` that
/// start `Worse:`: each loss and each line, with how it stands. A run prints what it left out of
/// the counts of a run on a line `Left out: <corpus>/<run> <what>`.
pub fn judge<'a>(found: &'a str, named: &str) -> Vec<Judged<'a>> {
    let notes: Vec<(&str, &str)> = found.lines().filter_map(|line| line.strip_prefix("Left out: ")?.split_once(' ')).collect();
    let note = |run: &str| notes.iter().find(|(of, _)| *of == run).map(|(_, note)| *note);
    let named: Vec<_> = named
        .lines()
        .filter(|line| line.starts_with("Worse:"))
        .map(|line| (line, Loss::parse(line).filter(|(_, why)| !why.is_empty())))
        .collect();
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
    losses.chain(lines).collect()
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
        let fails: Vec<Standing> = [Standing::Accepted, Standing::NotNamed, Standing::NotLost, Standing::Unread].into_iter().filter(|s| s.fails()).collect();
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
    fn a_loss_carries_what_its_run_left_out() {
        let found = format!("Left out: corpus/signatures for a timeout or after a lost worker, 3 in the base and 9 here\n{FOUND}\nWorse: corpus/signatures parameter counts right 50 -> 40 (-10)");
        let notes: Vec<Option<&str>> = judge(&found, "").iter().map(|j| j.note).collect();
        assert_eq!(notes, [None, Some("for a timeout or after a lost worker, 3 in the base and 9 here")]);
    }
}
