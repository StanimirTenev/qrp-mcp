//! qrp-mcp-core: the line gate of qrp-mcp (src/qrp_mcp/linegate.py), compiled.
//!
//! Given the lines of one file joined with "\n", it returns which lines any rule of the
//! scan could match. The gates are built in Python (linegate.Gate) and passed in as
//! strings, so the rules have one source; this crate only searches. Everything it
//! answers is a superset of what the Python gate answers: look-arounds are dropped or
//! replaced by the characters they look at, never narrowed. A line that is not plain --
//! printable ASCII and tabs -- is always returned for reading, with every pattern: beyond
//! ASCII the two regex dialects fold case differently, and Python's `\s` also matches the
//! control characters \x1c-\x1f, which this crate's ASCII `\s` does not. All
//! classification stays in Python.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
// Bytes and ASCII classes (?-u): every line this crate vouches for is plain, and on plain
// text they match as Python's do.
use regex::bytes::{Regex, RegexBuilder};

const SIZE_LIMIT: usize = 256 * (1 << 20);

type Lines = (Vec<usize>, Vec<usize>, Vec<(usize, Vec<usize>)>);

fn error(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn words_ac(words: &[String], kind: MatchKind) -> PyResult<AhoCorasick> {
    // A DFA: one table step per byte. The automatic choice took the NFA for this many
    // words, and the overlapping search of the patterns' literals then ran at ~50 MB/s,
    // most of the gate's time (release 3c).
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(kind)
        .kind(Some(AhoCorasickKind::DFA))
        .build(words)
        .map_err(error)
}

fn regex(pattern: &str) -> PyResult<Regex> {
    RegexBuilder::new(pattern)
        .size_limit(SIZE_LIMIT)
        .dfa_size_limit(SIZE_LIMIT)
        .build()
        .map_err(error)
}

/// Where each line starts, for lines split at b'\n'; one more entry than lines.
fn line_starts(bytes: &[u8]) -> Vec<usize> {
    let mut starts = Vec::with_capacity(bytes.len() / 32 + 2);
    starts.push(0);
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts.push(bytes.len() + 1);
    starts
}

/// Printable ASCII and tabs only.
fn plain(line: &[u8]) -> bool {
    line.iter().all(|&b| b == b'\t' || (0x20..0x7f).contains(&b))
}

fn line_of(starts: &[usize], pos: usize) -> usize {
    // The last start <= pos.
    match starts.binary_search(&pos) {
        Ok(i) => i,
        Err(i) => i - 1,
    }
}

#[pyclass(frozen)]
struct Gate {
    words: AhoCorasick,
    parts: Regex,
    /// The algorithm patterns' literals, and for each the patterns that carry it.
    pattern_words: AhoCorasick,
    word_patterns: Vec<Vec<usize>>,
    /// One per algorithm pattern; None when the patterns were not given.
    patterns: Option<Vec<Regex>>,
    blob: Regex,
}

#[pymethods]
impl Gate {
    /// `words`: literals, any case. `parts`: regexes in this crate's dialect.
    /// `pattern_literals[k]`: the literals one of which every match of algorithm pattern k
    /// holds, and `patterns[k]` that pattern in this crate's dialect. A pattern line is one
    /// where a pattern whose literal it holds matches it with its long hex and base64 runs
    /// (`blob`) blanked as detectors._masked blanks them; with `patterns` None, one that
    /// holds any of the literals.
    #[new]
    #[pyo3(signature = (words, parts, pattern_literals, patterns, blob))]
    fn new(
        words: Vec<String>,
        parts: Vec<String>,
        pattern_literals: Vec<Vec<String>>,
        patterns: Option<Vec<String>>,
        blob: String,
    ) -> PyResult<Self> {
        let joined = parts.iter().map(|p| format!("(?:{p})")).collect::<Vec<_>>().join("|");
        let parts = regex(&format!("(?im-u){joined}"))?;
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut unique: Vec<String> = Vec::new();
        let mut word_patterns: Vec<Vec<usize>> = Vec::new();
        for (k, literals) in pattern_literals.iter().enumerate() {
            for literal in literals {
                let key = literal.to_ascii_lowercase();
                let id = *index.entry(key.clone()).or_insert_with(|| {
                    unique.push(key);
                    word_patterns.push(Vec::new());
                    unique.len() - 1
                });
                if !word_patterns[id].contains(&k) {
                    word_patterns[id].push(k);
                }
            }
        }
        let patterns = match patterns {
            None => None,
            Some(list) => {
                if list.len() != pattern_literals.len() {
                    return Err(error("one regex per pattern's literals"));
                }
                Some(list.iter().map(|p| regex(&format!("(?-u){p}"))).collect::<PyResult<_>>()?)
            }
        };
        Ok(Gate {
            // Any occurrence marks its line, so the first one found is enough.
            words: words_ac(&words, MatchKind::LeftmostFirst)?,
            parts,
            // Every occurrence, overlapping ones too: `dh` inside `ecdh` selects other
            // patterns than `ecdh` does.
            pattern_words: words_ac(&unique, MatchKind::Standard)?,
            word_patterns,
            patterns,
            blob: regex(&format!("(?-u){blob}"))?,
        })
    }

    /// (lines to read, lines only an algorithm pattern could match, and for the lines of
    /// both that are ASCII the algorithm patterns that can match them), 0-based, ascending.
    fn hot_lines(&self, py: Python<'_>, text: &str) -> Lines {
        py.allow_threads(|| self.search(text))
    }
}

impl Gate {
    fn search(&self, text: &str) -> Lines {
        let bytes = text.as_bytes();
        let starts = line_starts(bytes);
        let n = starts.len() - 1;
        let mut hot = vec![false; n];
        let line_text = |i: usize| -> &[u8] { &bytes[starts[i]..starts[i + 1] - 1] };
        for (i, h) in hot.iter_mut().enumerate() {
            if !plain(line_text(i)) {
                *h = true;
            }
        }
        for m in self.words.find_iter(bytes) {
            hot[line_of(&starts, m.start())] = true;
        }
        let mut pos = 0;
        while pos <= bytes.len() {
            let Some(m) = self.parts.find_at(bytes, pos) else { break };
            let first = line_of(&starts, m.start());
            let last = line_of(&starts, m.end().saturating_sub(1).max(m.start()));
            for h in &mut hot[first..=last] {
                *h = true;
            }
            pos = starts[last + 1];
        }
        // For each line holding an algorithm pattern's literal: the patterns that match it,
        // with its long hex and base64 runs blanked as detectors._masked blanks them.
        let mut matching: Vec<Option<Vec<usize>>> = vec![None; n];
        let mut current = usize::MAX;
        let mut masked: Vec<u8> = Vec::new();
        let mut tried: Vec<usize> = vec![usize::MAX; self.patterns.as_ref().map_or(0, |p| p.len())];
        for m in self.pattern_words.find_overlapping_iter(bytes) {
            let i = line_of(&starts, m.start());
            let found = matching[i].get_or_insert_with(Vec::new);
            let Some(patterns) = &self.patterns else {
                continue;
            };
            if i != current {
                current = i;
                masked.clear();
                masked.extend_from_slice(line_text(i));
                let runs: Vec<(usize, usize)> =
                    self.blob.find_iter(&masked).map(|r| (r.start(), r.end())).collect();
                for (start, end) in runs {
                    for b in &mut masked[start + 1..end - 1] {
                        *b = b' ';
                    }
                }
            }
            for &k in &self.word_patterns[m.pattern().as_usize()] {
                if tried[k] != i {
                    tried[k] = i;
                    if patterns[k].is_match(&masked) {
                        found.push(k);
                    }
                }
            }
        }
        let read: Vec<usize> = (0..n).filter(|&i| hot[i]).collect();
        // Without the patterns, any line with a literal may be matched by one.
        let pattern_line = |i: usize| match &matching[i] {
            None => false,
            Some(found) => self.patterns.is_none() || !found.is_empty(),
        };
        let only_patterns: Vec<usize> = (0..n).filter(|&i| !hot[i] && pattern_line(i)).collect();
        // Which patterns can match each line to be read, where that is known: an ASCII line
        // and the patterns given. A line without a literal is matched by none.
        let mut allowed: Vec<(usize, Vec<usize>)> = Vec::new();
        if self.patterns.is_some() {
            for &i in read.iter().chain(only_patterns.iter()) {
                if plain(line_text(i)) {
                    let mut found = matching[i].clone().unwrap_or_default();
                    found.sort_unstable();
                    allowed.push((i, found));
                }
            }
        }
        (read, only_patterns, allowed)
    }
}

#[pymodule]
fn qrp_mcp_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Gate>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
