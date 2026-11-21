//! Compares two analyzer runs over one corpus binary by binary, so that a change shows every
//! count it made worse. The rounded percentages `score` prints hide a loss of a few dozen
//! functions in a corpus of a hundred thousand, and a gain in one binary hides a loss in another.
//!
//! A total that got worse is a loss, printed as a `Worse:` line. A pull request's description may
//! name a loss with that line and a reason, and [`judge`] holds the losses of a run to those lines.

use std::fmt;

use crate::score::Score;

/// Which way a count improves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Better {
    Higher,
    Lower,
}

/// A count by the name `score` gives it, how to read it from a score, and which way it improves.
type Count = (&'static str, fn(&Score) -> u64, Better);

/// The counts a change to the analysis can move. The truth's own counts are left out: both runs
/// are scored against the same truth.
const COUNTS: [Count; 12] = [
    ("starts found", |s| s.found, Better::Higher),
    ("mid-func", |s| s.mid_function, Better::Lower),
    ("in-cold", |s| s.in_fragment, Better::Lower),
    ("outside", |s| s.outside, Better::Lower),
    ("run-on", |s| s.run_on, Better::Lower),
    ("noreturn calls found", |s| s.found_noreturn_calls, Better::Higher),
    ("noreturn extra, uncorroborated", |s| s.extra_noreturn_calls - s.extra_noreturn_at_end, Better::Lower),
    ("bytes covered", |s| s.covered_bytes, Better::Higher),
    ("jump tables exact", |s| s.exact_tables, Better::Higher),
    ("jump tables missing targets", |s| s.tables_missing_targets, Better::Lower),
    ("jump tables extra targets", |s| s.tables_extra_targets, Better::Lower),
    ("jump tables unresolved", |s| s.unresolved_tables, Better::Lower),
];

/// How one count moved between the runs.
#[derive(Debug, PartialEq, Eq)]
pub struct Change {
    pub count: &'static str,
    /// The totals over the binaries the base read something of.
    pub base: u64,
    pub head: u64,
    /// Whether `lost` outweighs `gained`.
    pub worse: bool,
    /// Binaries where the count moved the wrong way, by how far, farthest first.
    pub lost: Vec<(String, u64)>,
    /// Binaries where it moved the right way, by how far, farthest first.
    pub gained: Vec<(String, u64)>,
    /// As `lost` and `gained`, for the binaries the base read nothing of, which have no say in
    /// `worse`.
    pub new_lost: Vec<(String, u64)>,
    pub new_gained: Vec<(String, u64)>,
}

/// The counts that moved from `base` to `head`, each a list of `(binary, score)` sorted by
/// name, and the binaries `base` scored that `head` has no analysis for.
pub fn compare(base: &[(String, Score)], head: &[(String, Score)]) -> (Vec<Change>, Vec<String>) {
    let at_head = |name: &str| head.binary_search_by(|(n, _)| n.as_str().cmp(name)).ok().map(|i| &head[i].1);
    let missing: Vec<String> = base.iter().filter(|(name, _)| at_head(name).is_none()).map(|(name, _)| name.clone()).collect();
    let pairs: Vec<(&str, &Score, &Score)> = base.iter().filter_map(|(name, b)| Some((name.as_str(), b, at_head(name)?))).collect();
    let changes = COUNTS
        .iter()
        .filter_map(|&(count, get, better)| {
            let (mut lost, mut gained, mut new_lost, mut new_gained) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for &(name, b, h) in &pairs {
                let read = !read_nothing(b);
                let (b, h) = (get(b), get(h));
                let (up, down) = (h.saturating_sub(b), b.saturating_sub(h));
                let (wrong, right) = if better == Better::Higher { (down, up) } else { (up, down) };
                if wrong > 0 {
                    if read { &mut lost } else { &mut new_lost }.push((name.to_string(), wrong));
                }
                if right > 0 {
                    if read { &mut gained } else { &mut new_gained }.push((name.to_string(), right));
                }
            }
            if [&lost, &gained, &new_lost, &new_gained].iter().all(|list| list.is_empty()) {
                return None;
            }
            for list in [&mut lost, &mut gained, &mut new_lost, &mut new_gained] {
                list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
            let read = pairs.iter().filter(|(_, sb, _)| !read_nothing(sb));
            let (base, head) = read.fold((0, 0), |(b, h), &(_, sb, sh)| (b + get(sb), h + get(sh)));
            Some(Change { count, base, head, worse: total(&lost) > total(&gained), lost, gained, new_lost, new_gained })
        })
        .collect();
    (changes, missing)
}

fn total(list: &[(String, u64)]) -> u64 {
    list.iter().map(|(_, n)| n).sum()
}

/// Whether the base found no function in a binary and covered none of its bytes, as when it
/// could not read its format. What the head reports there has nothing to be compared with.
fn read_nothing(score: &Score) -> bool {
    score.found + score.mid_function + score.in_fragment + score.outside == 0 && score.covered_bytes == 0
}

/// Prints the changes, worst first, with the binaries behind each.
pub fn print(changes: &[Change], missing: &[String]) {
    let binaries = |list: &[(String, u64)]| {
        let total = total(list);
        let named: Vec<String> = list.iter().take(4).map(|(name, n)| format!("{name} {n}")).collect();
        let more = if list.len() > 4 { format!(", {} more", list.len() - 4) } else { String::new() };
        format!("{total} in {} binaries ({}{more})", list.len(), named.join(", "))
    };
    if changes.is_empty() && missing.is_empty() {
        println!("  no count changed");
    }
    if !missing.is_empty() {
        println!("  worse   {} binaries have no analysis: {}", missing.len(), missing.join(", "));
    }
    let mut sorted: Vec<&Change> = changes.iter().collect();
    sorted.sort_by_key(|c| !c.worse);
    for c in sorted {
        let verdict = if c.worse {
            "worse"
        } else if c.lost.is_empty() && c.gained.is_empty() {
            "new"
        } else if total(&c.lost) == total(&c.gained) {
            "traded"
        } else {
            "better"
        };
        let delta = c.head as i64 - c.base as i64;
        println!("  {verdict:7} {:31} {} -> {} ({delta:+})", c.count, c.base, c.head);
        if !c.lost.is_empty() {
            println!("            lost   {}", binaries(&c.lost));
        }
        if !c.gained.is_empty() {
            println!("            gained {}", binaries(&c.gained));
        }
        if !c.new_lost.is_empty() {
            println!("            lost where the base read nothing   {}", binaries(&c.new_lost));
        }
        if !c.new_gained.is_empty() {
            println!("            gained where the base read nothing {}", binaries(&c.new_gained));
        }
    }
}

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

    /// Whether a line names this loss: the same count of the same run, moved as far. The totals
    /// themselves are the base's too, and the base is main when the change lands, which may
    /// have moved since the line was written.
    fn names(&self, other: &Loss) -> bool {
        (self.run, self.count, self.difference()) == (other.run, other.count, other.difference())
    }
}

/// The counts of `changes` that got worse, as losses of `run`.
pub fn losses<'a>(changes: &'a [Change], run: &'a str) -> Vec<Loss<'a>> {
    changes.iter().filter(|c| c.worse).map(|c| Loss { run, count: c.count, base: c.base, head: c.head }).collect()
}

/// How a loss of a run, or a `Worse:` line of a description, stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A loss that a line names, with a reason.
    Accepted,
    /// A loss that no line names.
    NotNamed,
    /// A line that names a loss the run does not show, or shows by another amount.
    NotLost,
    /// A line that starts `Worse:` and is not a loss in the form [`Loss`] prints with a reason
    /// after it.
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
}

/// Holds the losses a run printed, its `Worse:` lines in `found`, to the `Worse:` lines of
/// `named`: each loss and each named line, with how it stands. Only lines that start `Worse:`
/// are read, so `named` can be a pull request's whole description.
pub fn judge<'a>(found: &'a str, named: &'a str) -> Vec<(Standing, &'a str)> {
    type Lines<'a> = Vec<(&'a str, Option<Loss<'a>>)>;
    let worse = |text: &'a str| text.lines().filter(|line| line.starts_with("Worse:"));
    let lost: Lines = worse(found).map(|line| (line, Loss::parse(line).map(|(loss, _)| loss))).collect();
    let named: Lines = worse(named).map(|line| (line, Loss::parse(line).filter(|(_, why)| !why.is_empty()).map(|(loss, _)| loss))).collect();
    let among = |lines: &Lines, loss: &Loss| lines.iter().any(|(_, other)| other.as_ref().is_some_and(|other| other.names(loss)));
    let losses = lost.iter().map(|(line, loss)| (if loss.as_ref().is_some_and(|loss| among(&named, loss)) { Standing::Accepted } else { Standing::NotNamed }, *line));
    let lines = named.iter().filter_map(|(line, loss)| match loss {
        None => Some((Standing::Unread, *line)),
        Some(loss) => (!among(&lost, loss)).then_some((Standing::NotLost, *line)),
    });
    losses.chain(lines).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(name: &str, found: u64) -> (String, Score) {
        (name.to_string(), Score { found, ..Score::default() })
    }

    #[test]
    fn a_net_loss_is_worse_and_names_the_binaries_on_both_sides() {
        let base = [found("a", 100), found("b", 50), found("c", 10)];
        let head = [found("a", 52), found("b", 59), found("c", 10)];
        let (changes, missing) = compare(&base, &head);
        assert_eq!(missing, Vec::<String>::new());
        assert_eq!(
            changes,
            [Change {
                count: "starts found",
                base: 160,
                head: 121,
                worse: true,
                lost: vec![("a".to_string(), 48)],
                gained: vec![("b".to_string(), 9)],
                new_lost: vec![],
                new_gained: vec![],
            }]
        );
    }

    #[test]
    fn a_loss_that_a_gain_cancels_is_not_worse() {
        let score = |name: &str, n: u64| (name.to_string(), Score { found: n, mid_function: n, ..Score::default() });
        let (changes, _) = compare(&[score("a", 10), score("b", 10)], &[score("a", 7), score("b", 13)]);
        assert_eq!(changes.iter().map(|c| (c.count, c.worse)).collect::<Vec<_>>(), [("starts found", false), ("mid-func", false)]);
    }

    #[test]
    fn a_count_where_lower_is_better_is_worse_when_it_grows() {
        let base = [("a".to_string(), Score { mid_function: 3, ..Score::default() })];
        let head = [("a".to_string(), Score { mid_function: 5, ..Score::default() })];
        let (changes, _) = compare(&base, &head);
        assert_eq!(changes.iter().map(|c| (c.count, c.worse)).collect::<Vec<_>>(), [("mid-func", true)]);
    }

    #[test]
    fn what_a_binary_the_base_read_nothing_of_misplaces_is_not_worse() {
        let base = [found("a", 0)];
        let head = [("a".to_string(), Score { found: 10, mid_function: 2, ..Score::default() })];
        let (changes, _) = compare(&base, &head);
        let moved = |c: &Change| (c.count, c.worse, c.new_lost.clone(), c.new_gained.clone());
        assert_eq!(
            changes.iter().map(moved).collect::<Vec<_>>(),
            [("starts found", false, vec![], vec![("a".to_string(), 10)]), ("mid-func", false, vec![("a".to_string(), 2)], vec![])]
        );
    }

    #[test]
    fn a_binary_the_base_read_nothing_of_cannot_cancel_a_loss_in_another() {
        let base = [found("a", 0), found("b", 5)];
        let head = [found("a", 10), found("b", 4)];
        let (changes, _) = compare(&base, &head);
        assert_eq!(changes.iter().map(|c| (c.count, c.worse)).collect::<Vec<_>>(), [("starts found", true)]);
    }

    #[test]
    fn a_binary_without_analysis_at_head_is_missing() {
        let (changes, missing) = compare(&[found("a", 1), found("b", 1)], &[found("a", 1)]);
        assert_eq!((changes, missing), (vec![], vec!["b".to_string()]));
    }

    #[test]
    fn a_loss_prints_as_the_line_that_names_it() {
        let base = [found("a", 10)];
        let (changes, _) = compare(&base, &[found("a", 9)]);
        let lines: Vec<String> = losses(&changes, "corpus-thumb/recore").iter().map(Loss::to_string).collect();
        assert_eq!(lines, ["Worse: corpus-thumb/recore starts found 10 -> 9 (-1)"]);
        // A count that got better is no loss.
        assert!(losses(&compare(&base, &[found("a", 11)]).0, "corpus-thumb/recore").is_empty());
    }

    #[test]
    fn a_loss_is_accepted_when_a_line_names_it_with_a_reason() {
        let found = "Worse: corpus-thumb/signatures global types right 812 -> 811 (-1)\n\
                     Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2)";
        let named = "Fixes the returns.\r\n\r\n\
                     Worse: corpus-thumb/signatures global types right 812 -> 811 (-1) a knock-on of the right return\r\n\
                     Worse: corpus/recore noreturn extra, uncorroborated 40 -> 42 (+2) the truth misses two\r\n";
        assert_eq!(judge(found, named).iter().map(|j| j.0).collect::<Vec<_>>(), [Standing::Accepted, Standing::Accepted]);
    }

    #[test]
    fn a_line_holds_the_count_and_how_far_it_moved_not_the_base() {
        let found = "Worse: corpus/recore starts found 100 -> 98 (-2)";
        // Main moved the base since the line was written, and the change lost as much.
        assert_eq!(judge(found, "Worse: corpus/recore starts found 103 -> 101 (-2) why"), [(Standing::Accepted, found)]);
        // Another amount, another run, or another count names a loss the run does not show.
        for other in ["Worse: corpus/recore starts found 100 -> 99 (-1) why", "Worse: corpus/recore-noframes starts found 100 -> 98 (-2) why", "Worse: corpus/recore mid-func 100 -> 98 (-2) why"] {
            assert_eq!(judge(found, other), [(Standing::NotNamed, found), (Standing::NotLost, other)]);
        }
    }

    #[test]
    fn a_line_without_a_reason_or_out_of_form_is_unread() {
        let found = "Worse: corpus/recore starts found 100 -> 98 (-2)";
        // No reason, a difference that is not the totals', and no difference.
        for line in [found, "Worse: corpus/recore starts found 100 -> 98 (-1) why", "Worse: corpus/recore starts found 100 -> 98 why", "Worse: whatever got worse"] {
            assert_eq!(judge(found, line), [(Standing::NotNamed, found), (Standing::Unread, line)]);
        }
        // A line that does not start the description's line is no `Worse:` line.
        assert_eq!(judge("", &format!("  {found} why")), []);
    }
}
