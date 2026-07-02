//! Layout department: text-based cops that scan raw source lines (no AST).
use super::{Cops, Offense};

impl<'a> Cops<'a> {
    /// Layout/LineLength — rubocop's check_line verbatim: character length
    /// plus a tab-indentation surcharge, then the exemption ladder — allowed
    /// patterns, shebang, permitted heredocs, RBS inline annotations, cop
    /// directives (length re-measured without the directive), and the
    /// AllowURI / AllowQualifiedName excessive-range dance.
    pub(crate) fn check_line_length(&mut self) {
        const COP: &str = "Layout/LineLength";
        if !self.on(COP) {
            return;
        }
        let comments = self.comments;
        let max = self.cfg.int(COP, "Max");
        let allow_uri = self.cfg.get(COP, "AllowURI") == Some("true");
        let allow_qn = self.cfg.get(COP, "AllowQualifiedName") == Some("true");
        let allow_rbs = self.cfg.get(COP, "AllowRBSInlineAnnotation") == Some("true");
        // IgnoreCopDirectives is the legacy name; explicit false wins over
        // AllowCopDirectives' default true.
        let allow_directives = match self.cfg.param(COP, "IgnoreCopDirectives") {
            Some("true") => true,
            Some("false") => false,
            _ => self.cfg.get(COP, "AllowCopDirectives") == Some("true"),
        };
        // get() hands back the default.yml "true" in merge-world; None only
        // when the section replaces defaults (spec harness) — nil is falsy.
        let heredoc_allow = self.cfg.get(COP, "AllowHeredoc").unwrap_or("false").to_string();
        // Tabs bill at the configured indentation width.
        let tab_width: usize = self
            .cfg
            .param("Layout/IndentationStyle", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.param(COP, "IndentationWidth").and_then(|v| v.parse().ok()))
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2);
        let uri_re = uri_regex(self.cfg.param(COP, "URISchemes"));

        for (li, raw) in self.src.split(|&b| b == b'\n').enumerate() {
            let line_no = li + 1;
            // ASCII fast path: bytes == chars, no decode, no allocation. A
            // line can only be an offense if it is long enough in BYTES
            // (chars <= bytes), so short lines bail immediately.
            let raw = if raw.last() == Some(&b'\r') { &raw[..raw.len() - 1] } else { raw };
            let tabs = raw.iter().take_while(|b| **b == b'\t').count();
            let indent_diff = tabs * tab_width.saturating_sub(1);
            if raw.len() + indent_diff <= max {
                continue;
            }
            let owned;
            let line: &str = if raw.is_ascii() {
                // SAFETY-free: is_ascii guarantees valid UTF-8
                std::str::from_utf8(raw).unwrap_or("")
            } else {
                owned = String::from_utf8_lossy(raw);
                &owned
            };
            let nchars = if raw.is_ascii() { raw.len() } else { line.chars().count() };
            let line_len = nchars + indent_diff;
            if line_len <= max {
                continue;
            }
            // ---- allowed_line? ----
            if self.allowed(COP, line.as_bytes()) {
                continue;
            }
            if li == 0 && line.starts_with("#!") {
                continue;
            }
            if let Some((_, _, delim, _)) = self
                .heredoc_lines
                .iter()
                .find(|(s, e, _, _)| line_no >= *s && line_no <= *e)
            {
                match heredoc_allow.as_str() {
                    "true" => continue,
                    "false" => {}
                    list => {
                        if crate::config::parse_allowed_list(list).iter().any(|d| d.as_bytes() == delim) {
                            continue;
                        }
                    }
                }
            }
            let comment = comments.iter().find(|(l, _, _)| *l == line_no);
            if allow_rbs && comment.is_some_and(|(_, off, end)| is_rbs_annotation(&self.src[*off..*end])) {
                continue;
            }
            if allow_directives {
                if let Some((_, coff, cend)) = comment {
                    if let Some(marker) = directive_marker_offset(&self.src[*coff..*cend]) {
                        // re-measure without the directive (explanatory text
                        // before the marker still counts)
                        let prefix = &self.src[self.idx.starts[li]..*coff + marker];
                        let len = String::from_utf8_lossy(prefix).trim_end().chars().count();
                        if len > max {
                            let mut message = format!("Line is too long. [{len}/{max}]");
                            if let Some(sfx) = self.eng.style_guide_suffix(COP) {
                                message.push_str(&sfx);
                            }
                            let correctable = self.ll_fix_for_line(line_no);
                            self.offenses.push(Offense { line: line_no, col: max + 1, cop: COP, correctable, message });
                        }
                        continue;
                    }
                }
            }
            // ---- AllowURI / AllowQualifiedName ----
            let mut col = max.saturating_sub(indent_diff) + 1; // highlight_start, 1-based
            if allow_uri || allow_qn {
                let uri_range = allow_uri
                    .then(|| find_excessive_range(line, uri_match_ranges(line, &uri_re).last().copied(), indent_diff, max))
                    .flatten();
                let qn_range = allow_qn
                    .then(|| {
                        let m = qualified_name_regex().find_iter(line).last().map(|m| (m.start(), m.end()));
                        find_excessive_range(line, m, indent_diff, max)
                    })
                    .flatten();
                let allowed_pos = |r: &(usize, usize)| r.0 < max && r.1 == line_len;
                let ok = match (&uri_range, &qn_range) {
                    (Some(u), Some(q)) => allowed_pos(u) && allowed_pos(q),
                    (Some(u), None) => allowed_pos(u),
                    (None, Some(q)) => allowed_pos(q),
                    (None, None) => false,
                };
                if ok {
                    continue;
                }
                if let Some(r) = uri_range.or(qn_range) {
                    if r.0 < max {
                        col = r.1 + 1;
                    }
                }
            }
            let mut message = format!("Line is too long. [{line_len}/{max}]");
            if let Some(sfx) = self.eng.style_guide_suffix(COP) {
                message.push_str(&sfx);
            }
            let correctable = self.ll_fix_for_line(line_no);
            self.offenses.push(Offense { line: line_no, col, cop: COP, correctable, message });
        }
    }

    /// Lint/EmptyFile — an empty (or, without AllowComments, comment-only)
    /// file. rubocop's add_global_offense anchors at 1:1.
    pub(crate) fn check_empty_file(&mut self) {
        const COP: &str = "Lint/EmptyFile";
        if !self.on(COP) {
            return;
        }
        let offending = self.src.is_empty()
            || (self.cfg.get(COP, "AllowComments") != Some("true")
                && self.src.split(|b| *b == b'\n').all(|l| {
                    let t: Vec<u8> = l.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
                    t.is_empty() || l.iter().find(|b| !b.is_ascii_whitespace()) == l.iter().find(|b| **b == b'#')
                        && t.first() == Some(&b'#')
                }));
        if offending {
            self.push(0, COP, false, "Empty file detected.");
        }
    }

    /// Layout/TrailingEmptyLines — the file must end in exactly one newline
    /// (`final_newline`, default) or one blank line (`final_blank_line`).
    pub(crate) fn check_trailing_empty_lines(&mut self) {
        const COP: &str = "Layout/TrailingEmptyLines";
        if !self.on(COP) || self.src.is_empty() {
            return;
        }
        // rubocop bails whenever __END__ appears (its regex is unanchored),
        // and on a file ending in a blank percent-string literal
        if self.src.windows(7).any(|w| w == b"__END__") || self.src.ends_with(b"%\n\n") {
            return;
        }
        let ws_len = self.src.iter().rev().take_while(|b| b.is_ascii_whitespace()).count();
        let newlines = self.src[self.src.len() - ws_len..].iter().filter(|b| **b == b'\n').count() as i64;
        let blank_lines = newlines - 1;
        let wanted: i64 = if self.cfg.enforced_style(COP) == "final_blank_line" { 1 } else { 0 };
        if blank_lines == wanted {
            return;
        }
        let mut begin = self.src.len() - ws_len;
        let fix_start = begin;
        if ws_len > 0 {
            begin += 1;
        }
        let msg = match blank_lines {
            -1 => "Final newline missing.".to_string(),
            0 => "Trailing blank line missing.".to_string(),
            n => {
                let instead = if wanted == 0 { String::new() } else { format!("instead of {wanted} ") };
                format!("{n} trailing blank lines {instead}detected.")
            }
        };
        self.push(begin, COP, true, msg);
        let rep: &[u8] = if wanted == 0 { b"\n" } else { b"\n\n" };
        self.fixes.push((fix_start, self.src.len(), rep.to_vec()));
    }

    /// Layout/InitialIndentation — the first line of code must not be indented.
    pub(crate) fn check_initial_indentation(&mut self, first_code: Option<usize>) {
        const COP: &str = "Layout/InitialIndentation";
        if !self.on(COP) {
            return;
        }
        let Some(off) = first_code else { return };
        let (line, col) = self.idx.loc(off);
        if col == 1 {
            return;
        }
        let ls0 = self.idx.starts[line - 1];
        let mut ls = ls0;
        // a leading BOM is not indentation (but counts as one CHAR for cols)
        if self.src[ls..].starts_with(&[0xEF, 0xBB, 0xBF]) {
            ls += 3;
        }
        if ls < off && self.src[ls..off].iter().all(|b| matches!(b, b' ' | b'\t')) {
            let col = String::from_utf8_lossy(&self.src[ls0..off]).chars().count() + 1;
            self.offenses.push(Offense { line, col, cop: COP, correctable: true,
                message: "Indentation of first line in file detected.".into() });
            self.fixes.push((ls, off, Vec::new()));
        }
    }

    /// Layout/TrailingWhitespace — `[[:blank:]]` (tab + Unicode Zs, so `　`
    /// counts) before the line end. Lines inside heredoc bodies are skipped
    /// under `AllowInHeredoc: true`; otherwise they're offenses whose fix
    /// must preserve the string value (rubocop wraps the run in `#{'…'}`).
    pub(crate) fn check_trailing_whitespace(&mut self) {
        const COP: &str = "Layout/TrailingWhitespace";
        if !self.on(COP) {
            return;
        }
        let allow_heredoc = self.cfg.get(COP, "AllowInHeredoc") == Some("true");
        for (li, line) in self.src.split(|&b| b == b'\n').enumerate() {
            let line_no = li + 1;
            // nothing at or after `__END__` is program text
            if self.data_line.is_some_and(|d| line_no >= d) {
                break;
            }
            let line = if line.last() == Some(&b'\r') { &line[..line.len() - 1] } else { line };
            // fast bail: an ASCII line whose last byte isn't space/tab cannot
            // end in a blank (multibyte blanks all have non-ASCII last bytes)
            match line.last() {
                None => continue,
                Some(b' ') | Some(b'\t') => {}
                Some(b) if b.is_ascii() => continue,
                _ => {}
            }
            let owned = String::from_utf8_lossy(line);
            let text: &str = &owned;
            if !text.chars().next_back().is_some_and(is_blank) {
                continue;
            }
            let heredoc = self
                .heredoc_lines
                .iter()
                .find(|(s, e, _, _)| line_no >= *s && line_no <= *e)
                .cloned();
            if allow_heredoc && heredoc.is_some() {
                continue;
            }
            // column (1-based, chars) and byte offset of the trailing run
            let mut col = text.chars().count() + 1;
            let mut run_bytes = 0;
            for c in text.chars().rev() {
                if !is_blank(c) {
                    break;
                }
                col -= 1;
                run_bytes += c.len_utf8();
            }
            let ls = self.idx.starts[li];
            self.offenses.push(Offense { line: line_no, col, cop: COP, correctable: true,
                message: "Trailing whitespace detected.".into() });
            let end = ls + text.len();
            match &heredoc {
                None => self.fixes.push((end - run_bytes, end, Vec::new())),
                Some((hs, he, _, stat)) => {
                    // rubocop's process_line_in_heredoc: pure-indentation
                    // whitespace lines are removable; other runs get wrapped
                    // in an interpolation (never touch a static heredoc).
                    let indent = (*hs..=*he)
                        .filter_map(|ln| {
                            let s = self.idx.starts[ln - 1];
                            let e = self.idx.starts.get(ln).copied().unwrap_or(self.src.len());
                            let line = &self.src[s..e];
                            if line.iter().all(|b| b.is_ascii_whitespace()) {
                                None
                            } else {
                                Some(line.iter().take_while(|b| matches!(b, b' ' | b'\t')).count())
                            }
                        })
                        .min()
                        .unwrap_or(0);
                    let whitespace_only = text.bytes().all(|b| matches!(b, b' ' | b'\t'));
                    let run_start = end - run_bytes;
                    if whitespace_only && text.len() <= indent {
                        self.fixes.push((run_start, end, Vec::new()));
                    } else if !stat {
                        let ws_start = if whitespace_only { ls + indent } else { run_start };
                        let inner = self.src[ws_start..end].to_vec();
                        let mut rep = b"#{'".to_vec();
                        rep.extend_from_slice(&inner);
                        rep.extend_from_slice(b"'}");
                        self.fixes.push((ws_start, end, rep));
                    }
                }
            }
        }
    }
}

/// Ruby's `[[:blank:]]`: tab plus the Unicode Zs (space separator) category.
fn is_blank(c: char) -> bool {
    matches!(c,
        '\t' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

// ---- Layout/LineLength helpers ----
fn cached(cell: &'static std::sync::OnceLock<regex::Regex>, pat: &str) -> &'static regex::Regex {
    cell.get_or_init(|| regex::Regex::new(pat).unwrap())
}
/// Approximates `URI::RFC2396_PARSER.make_regexp(schemes)`: an absolute URI
/// with one of the configured schemes (default http/https), running until a
/// character RFC2396 excludes (whitespace, `<>"`, the "unwise" set, backtick).
fn uri_regex(schemes: Option<&str>) -> regex::Regex {
    let schemes: Vec<String> = schemes
        .map(crate::config::parse_allowed_list)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["http".into(), "https".into()])
        .iter()
        .map(|s| regex::escape(s))
        .collect();
    // Structured like ruby's RFC2396 make_regexp: the hier part rejects
    // brackets (path chars), but query and fragment are URIC* — where `[` `]`
    // count as reserved and get swallowed. URI.parse then rejects them, which
    // is exactly what kills the exemption for a doc-link's trailing `]`.
    regex::Regex::new(&format!(
        r#"(?i)\b(?:{}):(?://)?[^\s<>"{{}}|\\^\x60\[\]?#]*(?:\?[^\s<>"{{}}|\\^\x60#]*)?(?:#[^\s<>"{{}}|\\^\x60]*)?"#,
        schemes.join("|")
    ))
    .unwrap()
}
/// rubocop's `qualified_name_regexp` verbatim.
fn qualified_name_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    cached(&RE, r"\b(?:[A-Z][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*\b")
}
/// `#:`, `#[...]`, or `#|` — an RBS inline annotation comment.
fn is_rbs_annotation(comment: &[u8]) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    cached(&RE, r"^#:|^#\[.+\]|^#\|").is_match(&String::from_utf8_lossy(comment))
}
/// Byte offset of the `# rubocop:` directive marker inside a comment — like
/// rubocop's DirectiveComment regexp, it may sit mid-comment (after
/// explanatory text).
fn directive_marker_offset(comment: &[u8]) -> Option<usize> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    cached(&RE, r"#\s*rubocop\s*:\s*(?:disable|todo|enable)\b")
        .find(&String::from_utf8_lossy(comment))
        .map(|m| m.start())
}
/// URI candidates on the line, as byte ranges — rubocop matches broadly and
/// then filters with `URI.parse` (`valid_uri?`); the practical rejection is a
/// `scheme::Opaque` shape, whose opaque part starts with another `:`.
fn uri_match_ranges(line: &str, re: &regex::Regex) -> Vec<(usize, usize)> {
    re.find_iter(line)
        .filter(|m| {
            m.as_str()
                .split_once(':')
                .is_none_or(|(_, rest)| !rest.starts_with(':'))
        })
        .filter(|m| valid_uri(m.as_str()))
        .map(|m| (m.start(), m.end()))
        .collect()
}

/// The practical slice of `URI.parse` (RFC3986): brackets are only legal as
/// an IPv6 host right after `//` — one swallowed into a query/fragment (see
/// uri_regex) makes the whole candidate invalid, killing the line-length
/// exemption exactly like rubocop.
fn valid_uri(s: &str) -> bool {
    let Some(first) = s.find(['[', ']']) else { return true };
    let Some(auth) = s.find("//") else { return false };
    if first != auth + 2 || !s[first..].starts_with('[') {
        return false;
    }
    match s[first + 1..].find([']', '/', '?', '#']) {
        Some(p) if s.as_bytes()[first + 1 + p] == b']' => {
            !s[first + 2 + p..].contains(['[', ']'])
        }
        _ => false,
    }
}

/// rubocop's `find_excessive_range`: the LAST match on the line (byte range),
/// end extended over an enclosing `{…}` and the following non-space run, both
/// endpoints shifted by the tab surcharge; None when it sits fully before Max
/// (char positions, 0-based begin, exclusive end).
fn find_excessive_range(line: &str, m: Option<(usize, usize)>, indent_diff: usize, max: usize) -> Option<(usize, usize)> {
    let (mstart, mend) = m?;
    let begin = line[..mstart].chars().count() + indent_diff;
    let mut end = begin - indent_diff + line[mstart..mend].chars().count();
    let chars: Vec<char> = line.chars().collect();
    // `{(\s|\S)*}$` — when the line ends in a brace group, extend to its `}`.
    static BRACE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if cached(&BRACE, r"\{[\s\S]*\}$").is_match(line) {
        if let Some(p) = chars[end.min(chars.len())..].iter().rposition(|c| *c == '}') {
            end += p + 1;
        }
    }
    // then any following non-space run (`^\S+(?=\s|$)`)
    end += chars[end.min(chars.len())..].iter().take_while(|c| !c.is_whitespace()).count();
    end += indent_diff;
    if begin < max && end < max {
        return None;
    }
    Some((begin, end))
}
