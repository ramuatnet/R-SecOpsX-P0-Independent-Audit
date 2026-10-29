//! T-1.2: literal extraction + the aho-corasick prefilter.
//!
//! Every rule pattern is decomposed into MANDATORY literal runs; a line
//! that contains none of a rule's mandatory runs cannot contain a match
//! of that rule, so only candidate lines ever reach the regex engine.
//!
//! Extraction is conservative in ONE direction -- a run is kept only
//! when every match MUST contain it. A dropped run weakens the
//! prefilter (correctness intact); a wrongly kept run loses findings,
//! so every uncertain construct drops:
//!
//!   * metacharacters split runs; escaped literals (`\.`, `\(`) join,
//!     backslash classes (`\d`, `\w`, `\1`) and line separators
//!     (`\n`, `\r` -- no single line holds them) split;
//!   * a run ending before `*` or `?` or `{0...}` is DROPPED -- the
//!     quantifier can delete it from a match; `+`/`{1...}` keep it;
//!   * runs inside character classes are never kept (a class matches
//!     ONE character from a set, never its text);
//!   * runs inside a GROUP are kept, but if the group's closing `)` is
//!     followed by a min-0 quantifier (`(abc)?`, `(abc){0,2}`) every
//!     run collected inside it is truncated away;
//!   * splitting happens at EVERY unescaped `|`: if any alternative
//!     yields zero mandatory runs, the rule is UNPREFILTERABLE and its
//!     regex runs on every line. Correctness over speed;
//!   * runs shorter than MIN_LITERAL are dropped as unselective;
//!   * `(?...)` group syntax (`(?:`, `(?P<name>`, `(?<name>`, inline
//!     flags, comments) is consumed, never mistaken for literal text.
//!     Anything unparseable here yields fewer runs or an ungated rule
//!     -- both fail SAFE (the regex still runs on the line).

use std::collections::{HashMap, HashSet};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::config::RuleConfig;

/// Shortest run worth prefiltering with; below this a rule is
/// effectively unselective and runs on all lines.
pub const MIN_LITERAL: usize = 4;

const META: &[char] = &['^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}'];
/// Backslash sequences that are classes/backrefs, NOT literal text.
const CLASS_ESCAPES: &[char] = &[
    'd', 'D', 'w', 'W', 's', 'S', 'b', 'B', 'A', 'z', 'Z', 'p', 'P', 'k', 'g', '1', '2', '3',
    '4', '5', '6', '7', '8', '9',
];

/// Decide whether the run ending at `at` survives the quantifier that
/// follows it there (module docs). `None` = keep.
fn quantifier_deletes(chars: &[char], at: usize) -> bool {
    match chars.get(at) {
        Some('*') | Some('?') => true,
        Some('{') => {
            let numeric = chars
                .get(at + 1)
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);
            if numeric {
                let mut k = at + 1;
                let mut min = 0u64;
                while let Some(d) = chars.get(k) {
                    if d.is_ascii_digit() {
                        min = min.saturating_mul(10).saturating_add(*d as u64 - '0' as u64);
                        k += 1;
                    } else {
                        break;
                    }
                }
                min == 0
            } else {
                false // literal '{'
            }
        }
        _ => false,
    }
}

/// Mandatory literal runs of one alternative (see module docs).
fn branch_literals(branch: &str) -> Vec<String> {
    let chars: Vec<char> = branch.chars().collect();
    let mut runs: Vec<String> = Vec::new();
    let mut cur = String::new();
    // runs.len() at each group open, for min-0 group truncation.
    let mut group_marks: Vec<usize> = Vec::new();
    let mut in_class = false;
    let mut i = 0usize;

    let flush = |cur: &mut String, runs: &mut Vec<String>, at: usize| {
        if cur.is_empty() {
            return;
        }
        if !quantifier_deletes(&chars, at) && cur.chars().count() >= MIN_LITERAL {
            runs.push(std::mem::take(cur));
        } else {
            cur.clear();
        }
    };

    while i < chars.len() {
        let c = chars[i];

        if in_class {
            // Class content is never literal TEXT; skip to the closing ']'.
            match c {
                '\\' => {
                    i = (i + 2).min(chars.len());
                }
                _ => {
                    i += 1;
                    // find the close (escape-aware); an unbalanced class
                    // simply swallows the rest -- fewer runs, always safe.
                    while i < chars.len() {
                        match chars[i] {
                            '\\' => i = (i + 2).min(chars.len()),
                            ']' => {
                                in_class = false;
                                i += 1;
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
            }
            // The run before the class was flushed at '[' above; nothing
            // accumulates while inside.
            continue;
        }

        match c {
            '\\' => {
                if let Some(&n) = chars.get(i + 1) {
                    if CLASS_ESCAPES.contains(&n) || n == 'n' || n == 'r' {
                        // class/backref/line-separator: split the run
                        flush(&mut cur, &mut runs, i + 2);
                    } else if n == 't' {
                        cur.push('\t');
                    } else if n == 'v' || n == 'f' {
                        cur.push(if n == 'v' { '\u{0b}' } else { '\u{0c}' });
                    } else if n == '0' {
                        cur.push('\0');
                    } else {
                        cur.push(n); // \. \( \\ \{ ... literal characters
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
            '(' if chars.get(i + 1) == Some(&'?') => {
                // Group syntax: flush AT the '(' -- `(abcd(?:x))` keeps
                // "abcd"; the group after it does not quantify it.
                flush(&mut cur, &mut runs, i);
                group_marks.push(runs.len());
                let mut j = i + 2; // past '(?'
                match chars.get(j).copied() {
                    Some(':') => j += 1,                 // (?:...)
                    Some('=') | Some('!') => j += 1,     // (?= (?!  (unsupported by regex crate anyway)
                    Some('#') => {
                        while j < chars.len() && chars[j] != ')' {
                            j += 1;
                        }
                        if j < chars.len() {
                            j += 1;
                        }
                    }
                    Some('<') => {
                        // (?<name>...) ; (?<= (?<! are lookbehind
                        while j < chars.len() && chars[j] != '>' {
                            j += 1;
                        }
                        if j < chars.len() {
                            j += 1;
                        }
                    }
                    Some('P') => {
                        j += 1;
                        if chars.get(j) == Some(&'<') {
                            while j < chars.len() && chars[j] != '>' {
                                j += 1;
                            }
                            if j < chars.len() {
                                j += 1;
                            }
                        } else if chars.get(j) == Some(&'=') {
                            while j < chars.len() && chars[j] != ')' {
                                j += 1;
                            }
                            if j < chars.len() {
                                j += 1;
                            }
                        }
                    }
                    Some(_) => {
                        // inline flags: (?i) (?ims) (?i:...)
                        while j < chars.len() && chars[j] != ')' && chars[j] != ':' {
                            j += 1;
                        }
                        if j < chars.len() {
                            j += 1; // consume ')' or ':'
                        }
                    }
                    None => {}
                }
                i = j;
            }
            '(' => {
                flush(&mut cur, &mut runs, i);
                group_marks.push(runs.len());
                i += 1;
            }
            ')' => {
                flush(&mut cur, &mut runs, i);
                i += 1;
                if let Some(mark) = group_marks.pop() {
                    // A min-0 quantifier after the group close deletes
                    // everything the group contributed.
                    if quantifier_deletes(&chars, i) {
                        runs.truncate(mark);
                    }
                }
            }
            '[' => {
                flush(&mut cur, &mut runs, i);
                in_class = true;
                i += 1;
                // optional negation
                if chars.get(i) == Some(&'^') {
                    i += 1;
                }
                // ']' as first content char is literal, not the close
                if chars.get(i) == Some(&']') {
                    i += 1;
                }
            }
            '|' => {
                // split_alternatives already removed top-level '|';
                // any '|' left here is group-internal edge cases from
                // unbalanced splits -- still split the run.
                flush(&mut cur, &mut runs, i);
                i += 1;
            }
            '{' => {
                // Quantifier or literal-brace: flush the pre-run at the
                // '{' (min-0 deletes it, min-1+ keeps it -- see
                // quantifier_deletes), then CONSUME a well-formed
                // {m}, {m,} or {m,n} as syntax. The digits are syntax,
                // not content: leaving them in the stream would turn
                // "{0,10}" into a mandatory literal "0,10" that matches
                // never contain -- a wrongly kept run silently kills the
                // rule (the one failure mode the extractor must not have).
                // A literal '{' (malformed quantifier, as Python re
                // treats it) simply flushes and the following chars stay
                // ordinary content -- weaker prefilter, never wrong.
                flush(&mut cur, &mut runs, i);
                i += 1;
                if chars.get(i).map_or(false, |d| d.is_ascii_digit()) {
                    while chars.get(i).map_or(false, |d| d.is_ascii_digit()) {
                        i += 1;
                    }
                    if chars.get(i) == Some(&',') {
                        i += 1;
                        while chars.get(i).map_or(false, |d| d.is_ascii_digit()) {
                            i += 1;
                        }
                    }
                    if chars.get(i) == Some(&'}') {
                        i += 1;
                    }
                }
            }
            _ if META.contains(&c) => {
                flush(&mut cur, &mut runs, i);
                i += 1;
            }
            _ => {
                cur.push(c);
                i += 1;
            }
        }
    }
    flush(&mut cur, &mut runs, i);
    runs
}

/// Split at EVERY unescaped `|` (over-splitting only makes rules
/// ungated, never wrong).
fn split_alternatives(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push(c);
            if let Some(n) = chars.next() {
                cur.push(n);
            }
            continue;
        }
        if c == '|' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// Mandatory literals of the whole pattern; `None` means some
/// alternative has no mandatory run, so the rule cannot be prefILTERED.
pub fn mandatory_literals(pattern: &str) -> Option<Vec<String>> {
    let mut all: Vec<String> = Vec::new();
    for branch in split_alternatives(pattern) {
        let runs = branch_literals(&branch);
        if runs.is_empty() {
            return None;
        }
        all.extend(runs);
    }
    if all.is_empty() {
        return None;
    }
    Some(all)
}

/// Per-rule prefilter data: literal ids (into the shared automata) and
/// whether the rule gates on candidates at all.
pub struct RulePrefilter {
    pub literal_ids: Vec<u32>,
    pub gated: bool,
}

pub struct Prefilter {
    /// case-sensitive automaton over the strict literal set
    ac_strict: Option<AhoCorasick>,
    /// ascii case-insensitive automaton over the i-flag literal set
    ac_ci: Option<AhoCorasick>,
    /// per-rule lookup
    pub rules: Vec<RulePrefilter>,
    pub unprefilterable: Vec<String>,
}

impl Prefilter {
    pub fn build(rules: &[RuleConfig]) -> Self {
        let mut strict_lits: Vec<String> = Vec::new();
        let mut ci_lits: Vec<String> = Vec::new();
        let mut strict_index: HashMap<String, u32> = HashMap::new();
        let mut ci_index: HashMap<String, u32> = HashMap::new();
        let mut rule_lits: Vec<Option<Vec<u32>>> = Vec::with_capacity(rules.len());
        let mut unprefilterable: Vec<String> = Vec::new();

        for rule in rules {
            let ci = rule.flags.contains('i');
            // T-1.3: the compiled rule program ships its literal set.
            // A raw scan config (no `literals`) extracts here instead --
            // both paths run the SAME extractor, so either input yields
            // an identical prefilter.
            let extracted: Option<Vec<String>> = match &rule.literals {
                Some(pre) => {
                    if pre.is_empty() {
                        None
                    } else {
                        Some(pre.clone())
                    }
                }
                None => mandatory_literals(&rule.pattern),
            };
            match extracted {
                None => {
                    unprefilterable.push(rule.id.clone());
                    rule_lits.push(None);
                }
                Some(lits) => {
                    let mut ids = Vec::new();
                    for lit in lits {
                        let key = if ci { lit.to_lowercase() } else { lit.clone() };
                        let (index, bucket) = if ci {
                            (&mut ci_index, &mut ci_lits)
                        } else {
                            (&mut strict_index, &mut strict_lits)
                        };
                        let id = *index.entry(key.clone()).or_insert_with(|| {
                            let id = bucket.len() as u32;
                            bucket.push(key);
                            id
                        });
                        ids.push(id);
                    }
                    rule_lits.push(Some(ids));
                }
            }
        }

        let ac_strict = if strict_lits.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&strict_lits)
                .ok()
        };
        let ac_ci = if ci_lits.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostFirst)
                .build(&ci_lits)
                .ok()
        };

        let per_rule = rule_lits
            .iter()
            .map(|lits| match lits {
                None => RulePrefilter {
                    literal_ids: Vec::new(),
                    gated: false,
                },
                Some(ids) => RulePrefilter {
                    literal_ids: ids.clone(),
                    gated: true,
                },
            })
            .collect();

        Self {
            ac_strict,
            ac_ci,
            rules: per_rule,
            unprefilterable,
        }
    }

    /// Literal ids hit anywhere in `line`.
    pub fn hits(&self, line: &str, scratch: &mut HashSet<u32>) {
        scratch.clear();
        if let Some(ac) = &self.ac_strict {
            for m in ac.find_iter(line) {
                scratch.insert(m.pattern().as_usize() as u32);
            }
        }
        if let Some(ac) = &self.ac_ci {
            for m in ac.find_iter(line) {
                scratch.insert(m.pattern().as_usize() as u32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_group_truncates_its_runs() {
        let lits = mandatory_literals("(abcd)?efgh").unwrap();
        assert!(!lits.contains(&"abcd".to_string()));
        assert!(lits.contains(&"efgh".to_string()));
        // nested quantifier: outer min-0 wipes everything inside.
        // (All runs >= MIN_LITERAL, otherwise the branch is legitimately
        // unprefilterable rather than wrong.)
        let lits = mandatory_literals("(abcd(?:efgh))?ijkl").unwrap();
        assert!(!lits.contains(&"abcd".to_string()));
        assert!(!lits.contains(&"efgh".to_string()));
        assert!(lits.contains(&"ijkl".to_string()));
        // short mandatory runs are dropped as unselective: the rule then
        // runs on every line (fail-safe), it is never falsely gated.
        assert!(mandatory_literals("(abc(?:def))?ghi").is_none());
    }

    #[test]
    fn quantified_group_keeps_run() {
        // (+ / {1,} mean at least one copy always matches)
        let lits = mandatory_literals("(shell=True)+").unwrap();
        assert!(lits.contains(&"shell=True".to_string()));
        let lits = mandatory_literals("(shell=True){1,4}").unwrap();
        assert!(lits.contains(&"shell=True".to_string()));
    }

    #[test]
    fn trailing_quantifier_on_run() {
        let lits = mandatory_literals("abcd{0,3}efgh").unwrap();
        assert!(!lits.contains(&"abcd".to_string()));
        assert!(lits.contains(&"efgh".to_string()));
        // an ESCAPED '+' is literal content, so it stays in the run
        let lits = mandatory_literals(r"os\.system\+").unwrap();
        assert!(lits.contains(&"os.system+".to_string()));
        // quantifier DIGITS are syntax: they must never become a
        // mandatory literal, or the gate would block every real match
        // for a text that appears nowhere (silent rule blackout).
        let lits = mandatory_literals("abcdef{0,100}ghij").unwrap();
        assert!(!lits.iter().any(|l| l.contains("100")), "digits leaked: {lits:?}");
        assert!(!lits.contains(&"abcdef".to_string())); // min-0 deletes it
        assert!(lits.contains(&"ghij".to_string()));
        let lits = mandatory_literals("abcdef{2,}ghij").unwrap();
        assert!(lits.contains(&"abcdef".to_string())); // min-2 keeps it
        assert!(!lits.iter().any(|l| l.contains("2,")));
        assert!(lits.contains(&"ghij".to_string()));
    }

    #[test]
    fn non_capturing_group_syntax_is_not_literal() {
        let lits = mandatory_literals("(?:abcd)efgh").unwrap();
        assert!(!lits.iter().any(|l| l.contains(':')));
        assert!(lits.contains(&"abcd".to_string()));
        assert!(lits.contains(&"efgh".to_string()));
    }

    #[test]
    fn alternative_without_runs_makes_rule_ungated() {
        assert!(mandatory_literals("abcd|x{0,2}").is_none());
    }

    #[test]
    fn class_content_never_literal() {
        let lits = mandatory_literals(r"[A-Za-z]{6,}secret_token").unwrap();
        assert!(lits.contains(&"secret_token".to_string()));
        assert!(!lits.iter().any(|l| l.contains('A') && l.contains('Z')));
        // a run split by a class still survives on its own
        let lits = mandatory_literals("abcd[xyz]").unwrap();
        assert!(lits.contains(&"abcd".to_string()));
    }

    #[test]
    fn named_group_syntax_kept_as_content() {
        let lits = mandatory_literals(r"(?P<cred>password=)[A-Za-z0-9]{6,}").unwrap();
        assert!(lits.contains(&"password=".to_string()));
        assert!(!lits.iter().any(|l| l.contains("P<")));
    }
}
