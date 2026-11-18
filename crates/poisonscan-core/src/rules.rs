//! Rule format (YAML, one rule per file) and compiled rule set.

use std::collections::HashSet;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};

/// Maximum compiled size per regex (bytes), keeps rule cost bounded.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> f32 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 10.0,
            Severity::Medium => 30.0,
            Severity::High => 60.0,
            Severity::Critical => 90.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Experimental,
    Stable,
    Deprecated,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    /// Any keyword or any regex matches.
    #[default]
    Any,
    /// At least one keyword AND at least one regex match.
    All,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub condition: Condition,
    /// Restrict to hidden/smuggled segments only.
    #[serde(default)]
    pub hidden_only: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exceptions {
    #[serde(default)]
    pub regex: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTests {
    #[serde(default)]
    pub positive: Vec<String>,
    #[serde(default)]
    pub negative: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub format: u32,
    pub id: String,
    pub title: String,
    pub version: u32,
    pub status: Status,
    pub author: String,
    pub date: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub severity: Severity,
    /// Empty = all channels.
    #[serde(default)]
    pub channel: Vec<String>,
    #[serde(rename = "match")]
    pub matcher: Match,
    #[serde(default)]
    pub exceptions: Exceptions,
    #[serde(default)]
    pub tests: RuleTests,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("{origin}: YAML: {source}")]
    Yaml {
        origin: String,
        source: serde_yaml::Error,
    },
    #[error("{id}: {msg}")]
    Invalid { id: String, msg: String },
    #[error("duplicate rule id {0}")]
    Duplicate(String),
    #[error("rule engine: {0}")]
    Build(String),
}

impl Rule {
    pub fn from_yaml(origin: &str, text: &str) -> Result<Rule, RuleError> {
        serde_yaml::from_str(text).map_err(|source| RuleError::Yaml {
            origin: origin.to_string(),
            source,
        })
    }

    /// Static checks that do not need the whole set.
    pub fn lint(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.format != crate::RULE_FORMAT {
            errs.push(format!("unsupported format {} (engine accepts {})", self.format, crate::RULE_FORMAT));
        }
        let id_ok = self.id.len() == 8
            && self.id.starts_with("PSN-")
            && self.id[4..].chars().all(|c| c.is_ascii_digit());
        if !id_ok {
            errs.push("id must look like PSN-0001".into());
        }
        if self.id.starts_with("PSN-B") {
            errs.push("PSN-Bxxx ids are reserved for built-in detectors".into());
        }
        if self.title.trim().is_empty() {
            errs.push("empty title".into());
        }
        if self.matcher.keywords.is_empty() && self.matcher.regex.is_empty() {
            errs.push("match needs at least one keyword or regex".into());
        }
        if self.matcher.condition == Condition::All
            && (self.matcher.keywords.is_empty() || self.matcher.regex.is_empty())
        {
            errs.push("condition: all needs both keywords and regex".into());
        }
        if self.matcher.keywords.iter().any(|k| k.trim().len() < 3) {
            errs.push("keywords must be at least 3 characters".into());
        }
        for r in self.matcher.regex.iter().chain(&self.exceptions.regex) {
            if let Err(e) = build_regex(r) {
                errs.push(format!("regex {r:?}: {e}"));
            }
            if boundary_next_to_non_ascii(r) {
                errs.push(format!("regex {r:?}: \\b next to a non-ASCII letter never matches (boundaries are ASCII); use (^|\\W) or drop it"));
            }
        }
        if self.status != Status::Deprecated && self.tests.positive.is_empty() {
            errs.push("at least one positive test example is required".into());
        }
        if self.status != Status::Deprecated && self.tests.negative.is_empty() {
            errs.push("at least one negative test example is required".into());
        }
        errs
    }
}

/// Rewrite `\b` / `\B` into ASCII word boundaries.
///
/// A Unicode `\b` makes the regex crate's fast DFA give up on any non-ASCII
/// haystack and fall back to a much slower engine (measured ~16x slower on
/// French text). Rules therefore get ASCII boundaries; `rules lint` rejects
/// a boundary placed right next to a non-ASCII letter, where it would never match.
pub(crate) fn ascii_boundaries(p: &str) -> String {
    let mut out = String::with_capacity(p.len() + 16);
    let mut chars = p.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(b @ ('b' | 'B')) if chars.peek() != Some(&'{') => {
                out.push_str("(?-u:\\");
                out.push(b);
                out.push(')');
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// `\b` immediately before or after a non-ASCII character can never match once
/// boundaries are ASCII-only (e.g. `\bécris`).
fn boundary_next_to_non_ascii(p: &str) -> bool {
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            if chars[i + 1] == 'b' {
                let before = i.checked_sub(1).map(|j| chars[j]);
                let after = chars.get(i + 2).copied();
                if before.is_some_and(|c| !c.is_ascii() && c.is_alphabetic())
                    || after.is_some_and(|c| !c.is_ascii() && c.is_alphabetic())
                {
                    return true;
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

fn build_regex(p: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(&ascii_boundaries(p))
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// A compiled, immutable set of rules. Deprecated rules are not loaded.
pub struct RuleSet {
    pub(crate) rules: Vec<Rule>,
    pub(crate) keywords: Option<AhoCorasick>,
    /// keyword pattern index -> rule index
    pub(crate) keyword_owner: Vec<usize>,
    pub(crate) regexes: RegexSet,
    /// regex pattern index -> rule index
    pub(crate) regex_owner: Vec<usize>,
    pub(crate) exceptions: Vec<Vec<Regex>>,
    /// Per-rule compiled regexes, used only to locate a match (explain), never in the hot path.
    pub(crate) rule_regexes: Vec<Vec<Regex>>,
    /// Identifier of the loaded rule content (stable hash), for re-scan decisions.
    pub fingerprint: String,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("rules", &self.rules.len())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl RuleSet {
    pub fn new(all: Vec<Rule>) -> Result<RuleSet, RuleError> {
        let mut seen = HashSet::new();
        for r in &all {
            if !seen.insert(r.id.clone()) {
                return Err(RuleError::Duplicate(r.id.clone()));
            }
            let errs = r.lint();
            if !errs.is_empty() {
                return Err(RuleError::Invalid {
                    id: r.id.clone(),
                    msg: errs.join("; "),
                });
            }
        }
        let mut rules: Vec<Rule> = all.into_iter().filter(|r| r.status != Status::Deprecated).collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));

        let mut kw = Vec::new();
        let mut keyword_owner = Vec::new();
        let mut rx = Vec::new();
        let mut regex_owner = Vec::new();
        let mut exceptions = Vec::new();
        let mut rule_regexes = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            for k in &r.matcher.keywords {
                kw.push(k.to_lowercase());
                keyword_owner.push(i);
            }
            for p in &r.matcher.regex {
                rx.push(ascii_boundaries(p));
                regex_owner.push(i);
            }
            rule_regexes.push(
                r.matcher
                    .regex
                    .iter()
                    .map(|p| build_regex(p).map_err(|e| RuleError::Build(e.to_string())))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            exceptions.push(
                r.exceptions
                    .regex
                    .iter()
                    .map(|p| build_regex(p).map_err(|e| RuleError::Build(e.to_string())))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        let keywords = if kw.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::Standard)
                    .build(&kw)
                    .map_err(|e| RuleError::Build(e.to_string()))?,
            )
        };
        let regexes = RegexSetBuilder::new(&rx)
            .case_insensitive(true)
            .size_limit(REGEX_SIZE_LIMIT * 8)
            .build()
            .map_err(|e| RuleError::Build(e.to_string()))?;

        let canonical = serde_json::to_string(&rules).unwrap_or_default();
        let fingerprint = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(canonical.as_bytes()));
        Ok(RuleSet {
            rules,
            keywords,
            keyword_owner,
            regexes,
            regex_owner,
            exceptions,
            rule_regexes,
            fingerprint,
        })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_are_rewritten_but_escapes_kept() {
        assert_eq!(ascii_boundaries(r"\bfoo\B"), r"(?-u:\b)foo(?-u:\B)");
        assert_eq!(ascii_boundaries(r"a\\b"), r"a\\b");
        assert_eq!(ascii_boundaries(r"\b{start}x"), r"\b{start}x");
        assert_eq!(ascii_boundaries(r"\d\s\."), r"\d\s\.");
    }

    #[test]
    fn ascii_boundary_still_matches_accented_text_around_words() {
        let r = build_regex(r"\btu\s+dois\b").unwrap();
        assert!(r.is_match("si tu dois répondre, évite"));
        assert!(!r.is_match("statu doisé"));
    }

    #[test]
    fn lint_rejects_boundary_next_to_accent() {
        assert!(boundary_next_to_non_ascii(r"\bécris"));
        assert!(!boundary_next_to_non_ascii(r"réponds\b"));
        assert!(boundary_next_to_non_ascii(r"précédé\b"));
        assert!(!boundary_next_to_non_ascii(r"\bignore\b"));
    }
}
