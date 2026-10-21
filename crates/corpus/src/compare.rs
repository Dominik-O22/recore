//! Compares two analyzer runs over one corpus binary by binary, so that a change shows every
//! count it made worse. The rounded percentages `score` prints hide a loss of a few dozen
//! functions in a corpus of a hundred thousand, and a gain in one binary hides a loss in another.

use crate::score::Score;

/// Which way a count improves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Better {
    Higher,
    Lower,
}

/// The counts a change to the analysis can move, as `score` names them. The truth's own counts
/// are left out: both runs are scored against the same truth.
const COUNTS: [(&str, fn(&Score) -> u64, Better); 12] = [
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
    pub base: u64,
    pub head: u64,
    /// Whether the total moved the wrong way.
    pub worse: bool,
    /// Binaries where the count moved the wrong way, by how far, farthest first.
    pub lost: Vec<(String, u64)>,
    /// Binaries where it moved the right way, by how far, farthest first.
    pub gained: Vec<(String, u64)>,
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
            let (mut lost, mut gained) = (Vec::new(), Vec::new());
            for &(name, b, h) in &pairs {
                let (b, h) = (get(b), get(h));
                let (up, down) = (h.saturating_sub(b), b.saturating_sub(h));
                let (wrong, right) = if better == Better::Higher { (down, up) } else { (up, down) };
                if wrong > 0 {
                    lost.push((name.to_string(), wrong));
                }
                if right > 0 {
                    gained.push((name.to_string(), right));
                }
            }
            if lost.is_empty() && gained.is_empty() {
                return None;
            }
            lost.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            gained.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let (base, head) = pairs.iter().fold((0, 0), |(b, h), &(_, sb, sh)| (b + get(sb), h + get(sh)));
            let worse = if better == Better::Higher { head < base } else { head > base };
            Some(Change { count, base, head, worse, lost, gained })
        })
        .collect();
    (changes, missing)
}

/// Prints the changes, worst first, with the binaries behind each.
pub fn print(changes: &[Change], missing: &[String]) {
    let binaries = |list: &[(String, u64)]| {
        let total: u64 = list.iter().map(|(_, n)| n).sum();
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
        let verdict = if c.worse { "worse" } else if c.base == c.head { "traded" } else { "better" };
        let delta = c.head as i64 - c.base as i64;
        println!("  {verdict:7} {:31} {} -> {} ({delta:+})", c.count, c.base, c.head);
        if !c.lost.is_empty() {
            println!("            lost   {}", binaries(&c.lost));
        }
        if !c.gained.is_empty() {
            println!("            gained {}", binaries(&c.gained));
        }
    }
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
            }]
        );
    }

    #[test]
    fn a_count_where_lower_is_better_is_worse_when_it_grows() {
        let base = [("a".to_string(), Score { mid_function: 3, ..Score::default() })];
        let head = [("a".to_string(), Score { mid_function: 5, ..Score::default() })];
        let (changes, _) = compare(&base, &head);
        assert_eq!(changes.iter().map(|c| (c.count, c.worse)).collect::<Vec<_>>(), [("mid-func", true)]);
    }

    #[test]
    fn a_binary_without_analysis_at_head_is_missing() {
        let (changes, missing) = compare(&[found("a", 1), found("b", 1)], &[found("a", 1)]);
        assert_eq!((changes, missing), (vec![], vec!["b".to_string()]));
    }
}
