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

impl<'a> Cops<'a> {
    /// Layout/EmptyLineAfterMagicComment — the last leading magic comment
    /// must be followed by a blank line.
    pub(crate) fn check_empty_line_after_magic_comment(&mut self, first_code_line: Option<usize>) {
        const COP: &str = "Layout/EmptyLineAfterMagicComment";
        if !self.on(COP) {
            return;
        }
        // leading comments: before the first code line (all of them if none)
        let last_magic = self
            .comments
            .iter()
            .take_while(|(line, _, _)| first_code_line.is_none_or(|fc| *line < fc))
            .filter(|(_, s, e)| is_magic_comment(&self.src[*s..*e]))
            .last();
        let Some((line, _, _)) = last_magic else { return };
        let next_start = match self.idx.starts.get(*line) {
            Some(s) => *s,
            None => return, // no following line at all
        };
        let next_end = self.line_end(line + 1);
        if self.src[next_start..next_end].iter().all(|b| b.is_ascii_whitespace()) {
            return;
        }
        self.fixes.push((next_start, next_start, b"\n".to_vec()));
        self.push(next_start, COP, true, "Add an empty line after magic comments.");
    }

    /// Layout/EmptyLines — more than one consecutive blank line between
    /// tokens. "Blank" is a strictly empty line (whitespace-only lines break
    /// the run, exactly like rubocop's `.empty?`); heredoc bodies count as
    /// token lines (their content is one token to the lexer).
    pub(crate) fn check_empty_lines(&mut self) {
        const COP: &str = "Layout/EmptyLines";
        if !self.on(COP) {
            return;
        }
        // cheap gate, same as rubocop's raw_source include check
        if !self.src.windows(3).any(|w| w == b"\n\n\n") {
            return;
        }
        let nlines = self.idx.starts.len();
        let mut token = vec![false; nlines + 2];
        for line in 1..=nlines {
            let s = self.idx.starts[line - 1];
            let e = self.line_end(line);
            if self.src[s..e].iter().any(|b| !b.is_ascii_whitespace()) {
                token[line] = true;
            }
        }
        for (hs, he, _, _) in &self.heredoc_lines {
            for l in *hs..=(*he).min(nlines) {
                token[l] = true;
            }
        }
        for (hs, he) in &self.multiline_str_lines {
            for l in *hs..=(*he).min(nlines) {
                token[l] = true;
            }
        }
        fn is_empty(c: &Cops, line: usize) -> bool {
            match c.idx.starts.get(line - 1) {
                Some(s) => c.line_end(line) == *s,
                None => false,
            }
        }
        let mut prev = 1usize;
        for cur in 1..=nlines {
            if !token[cur] {
                continue;
            }
            if cur > prev && cur - prev > 2 {
                for line in prev + 1..cur {
                    if is_empty(self, line) && line >= 2 && is_empty(self, line - 1) {
                        let off = self.idx.starts[line - 1];
                        self.fixes.push((off, self.idx.starts.get(line).copied().unwrap_or(off), Vec::new()));
                        self.push(off, COP, true, "Extra blank line detected.");
                    }
                }
            }
            prev = cur;
        }
    }
}

/// A magic comment: frozen_string_literal / encoding / warn_indent /
/// shareable_constant_value / typed — simple, emacs (-*-), or vim form.
fn is_magic_comment(comment: &[u8]) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    cached(
        &RE,
        r"(?i)^#\s*(?:-\*-.*-\*-\s*$|(?:(?:frozen[_-]string[_-]literal)\s*:\s*(?:true|false)\b|(?:encoding|coding|warn[_-]indent|shareable[_-]constant[_-]value|typed)\s*:|rbs_inline\s*:\s*(?:enabled|disabled)\b)|vim:\s*(?:set\s+)?(?:ft|filetype|fileencoding|fenc)\s*[=:])",
    )
    .is_match(&String::from_utf8_lossy(comment))
}

impl<'a> Cops<'a> {
    /// Layout/SpaceBeforeComment — inline comments must have a space before the
    /// `#`; leading comments are fine, and doc comments (=begin/=end) are skipped.
    pub(crate) fn check_space_before_comment(&mut self) {
        const COP: &str = "Layout/SpaceBeforeComment";
        if !self.on(COP) {
            return;
        }
        for (line, comment_start, _comment_end) in self.comments {
            // Skip doc comments (=begin/=end)
            if comment_start + 1 < self.src.len() && self.src[*comment_start] == b'#' {
                if self.src[*comment_start + 1] == b'=' {
                    continue; // This is =begin or =end
                }
            }

            // Check if the comment starts at the line's first non-whitespace position
            let ls = self.idx.starts[line - 1];
            let line_start_non_ws = self.src[ls..].iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
            let first_non_ws_offset = ls + line_start_non_ws;

            // If the comment is at the start of the line (ignoring whitespace), it's fine
            if *comment_start == first_non_ws_offset {
                continue;
            }

            // Check if the byte immediately before the `#` is whitespace
            if *comment_start > 0 {
                let prev_byte = self.src[*comment_start - 1];
                if !prev_byte.is_ascii_whitespace() {
                    // Offense: no space before comment
                    self.push(*comment_start, COP, true, "Put a space before an end-of-line comment.");
                    // Fix: insert a space before the comment
                    self.fixes.push((*comment_start, *comment_start, b" ".to_vec()));
                }
            }
        }
    }

    /// Layout/SpaceAfterComma — a comma must be followed by whitespace
    /// (semicolons after and `}` under no_space hash style are exempt).
    pub(crate) fn check_space_after_comma(&mut self) {
        const COP: &str = "Layout/SpaceAfterComma";
        if !self.on(COP) || !self.src.contains(&b',') {
            return;
        }
        let rcurly_no_space =
            self.cfg.get("Layout/SpaceInsideHashLiteralBraces", "EnforcedStyle") == Some("no_space");
        for line in 1..=self.idx.starts.len() {
            let ls = self.idx.starts[line - 1];
            let le = self.line_end(line);
            // a trailing comment caps the code
            let code_end = self
                .comments
                .iter()
                .find(|(l, s, _)| *l == line && *s >= ls && *s < le)
                .map(|(_, s, _)| *s)
                .unwrap_or(le);
            for p in ls..code_end {
                if self.src[p] != b',' || self.in_lit_span(p) {
                    continue;
                }
                let Some(next) = self.src.get(p + 1) else { continue };
                if next.is_ascii_whitespace() || *next == b';' {
                    continue;
                }
                // rubocop's allowed_type?: `)`, `]`, `|` (and interpolation
                // ends) never need a space after a comma; `}` only under the
                // no_space hash-brace style
                if matches!(*next, b')' | b']' | b'|') {
                    continue;
                }
                if *next == b'}' && rcurly_no_space {
                    continue;
                }
                self.fixes.push((p + 1, p + 1, b" ".to_vec()));
                self.push(p, COP, true, "Space missing after comma.");
            }
        }
    }

    /// Layout/SpaceBeforeSemicolon — a semicolon must not be preceded by space
    /// (except after `{` when space is required per Layout/SpaceInsideBlockBraces).
    pub(crate) fn check_space_before_semicolon(&mut self) {
        const COP: &str = "Layout/SpaceBeforeSemicolon";
        if !self.on(COP) || !self.src.contains(&b';') {
            return;
        }
        let space_required_after_lcurly =
            self.cfg.get("Layout/SpaceInsideBlockBraces", "EnforcedStyle") != Some("no_space");
        for line in 1..=self.idx.starts.len() {
            let ls = self.idx.starts[line - 1];
            let le = self.line_end(line);
            // a trailing comment caps the code
            let code_end = self
                .comments
                .iter()
                .find(|(l, s, _)| *l == line && *s >= ls && *s < le)
                .map(|(_, s, _)| *s)
                .unwrap_or(le);
            for p in ls..code_end {
                if self.src[p] != b';' || self.in_lit_span(p) {
                    continue;
                }
                // Look back for whitespace before the semicolon
                if p == 0 || !self.src[p - 1].is_ascii_whitespace() {
                    continue;
                }
                // Find the start of the whitespace run
                let mut ws_start = p - 1;
                while ws_start > ls && self.src[ws_start - 1].is_ascii_whitespace() {
                    ws_start -= 1;
                }
                // Check if the character before the whitespace is a {
                // and space is required after { (the 'space' style)
                let prev_is_lcurly = ws_start > ls && self.src[ws_start - 1] == b'{';
                if prev_is_lcurly && space_required_after_lcurly {
                    continue;
                }
                // Emit offense at the start of the whitespace and remove the space
                self.fixes.push((ws_start, p, Vec::new()));
                self.push(ws_start, COP, true, "Space found before semicolon.");
            }
        }
    }

    /// Layout/SpaceAfterSemicolon — a semicolon must be followed by whitespace
    /// (closing parens, brackets, pipes, and string interpolation ends are exempt).
    pub(crate) fn check_space_after_semicolon(&mut self) {
        const COP: &str = "Layout/SpaceAfterSemicolon";
        if !self.on(COP) || !self.src.contains(&b';') {
            return;
        }
        let rcurly_no_space =
            self.cfg.get("Layout/SpaceInsideBlockBraces", "EnforcedStyle") == Some("no_space");
        for line in 1..=self.idx.starts.len() {
            let ls = self.idx.starts[line - 1];
            let le = self.line_end(line);
            // a trailing comment caps the code
            let code_end = self
                .comments
                .iter()
                .find(|(l, s, _)| *l == line && *s >= ls && *s < le)
                .map(|(_, s, _)| *s)
                .unwrap_or(le);
            for p in ls..code_end {
                if self.src[p] != b';' || self.in_lit_span(p) {
                    continue;
                }
                let Some(next) = self.src.get(p + 1) else { continue };
                if next.is_ascii_whitespace() {
                    continue;
                }
                // semicolon sequences (;;) are allowed
                if *next == b';' {
                    continue;
                }
                // rubocop's allowed_type?: `)`, `]`, `|` (and interpolation
                // ends) never need a space after a semicolon; `}` only when
                // block-brace style allows no_space
                if matches!(*next, b')' | b']' | b'|') {
                    continue;
                }
                if *next == b'}' && rcurly_no_space {
                    continue;
                }
                self.fixes.push((p + 1, p + 1, b" ".to_vec()));
                self.push(p, COP, true, "Space missing after semicolon.");
            }
        }
    }

    /// Layout/SpaceAfterNot — unary `!` must not be followed by whitespace
    /// before its operand (`! foo` is an offense; fix removes the space).
    pub(crate) fn check_space_after_not(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/SpaceAfterNot";
        if !self.on(COP) || node.name().as_slice() != b"!" {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        // Exclude the `not` keyword — only check the unary `!` operator
        if sel.as_slice() == b"not" {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let recv_start = recv.location().start_offset();
        let node_start = node.location().start_offset();
        // whitespace_after_operator?: distance from node start to receiver start > 1
        if recv_start - node_start <= 1 {
            return;
        }
        // Offense is on the whole node (from `!` to the start of receiver)
        self.push(node_start, COP, true, "Do not leave space between `!` and its argument.");
        // Fix: remove the whitespace between `!` (end_pos) and receiver start
        self.fixes.push((sel.end_offset(), recv_start, Vec::new()));
    }
}

impl<'a> Cops<'a> {
    /// Layout/SpaceBeforeComma — a comma must not be preceded by space
    /// (kept after `{` when the block-brace style wants that space).
    pub(crate) fn check_space_before_comma(&mut self) {
        const COP: &str = "Layout/SpaceBeforeComma";
        if !self.on(COP) || !self.src.contains(&b',') {
            return;
        }
        for line in 1..=self.idx.starts.len() {
            let ls = self.idx.starts[line - 1];
            let le = self.line_end(line);
            // a trailing comment caps the code
            let code_end = self
                .comments
                .iter()
                .find(|(l, s, _)| *l == line && *s >= ls && *s < le)
                .map(|(_, s, _)| *s)
                .unwrap_or(le);
            for p in ls..code_end {
                if self.src[p] != b',' || self.in_lit_span(p) {
                    continue;
                }
                // the whitespace run, bounded to THIS line — a leading
                // comma's "space" is the previous line's newline, which
                // rubocop's same-line token adjacency never flags
                let mut space_start = p;
                while space_start > ls && self.src[space_start - 1].is_ascii_whitespace() {
                    space_start -= 1;
                }
                if space_start == p || space_start == ls {
                    continue;
                }
                // space required after `{` unless the block-brace style says no_space
                if self.src[space_start - 1] == b'{'
                    && self.cfg.get("Layout/SpaceInsideBlockBraces", "EnforcedStyle") != Some("no_space")
                {
                    continue;
                }
                self.fixes.push((space_start, p, Vec::new()));
                self.push(space_start, COP, true, "Space found before comma.");
            }
        }
    }

    /// Layout/SpaceAfterMethodName — space between method name and opening parenthesis in def
    pub(crate) fn check_space_after_method_name(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/SpaceAfterMethodName";
        if !self.on(COP) {
            return;
        }
        let Some(lparen_loc) = node.lparen_loc() else { return };

        // Check if there's a space before the opening paren
        let lparen_start = lparen_loc.start_offset();
        if lparen_start == 0 {
            return;
        }

        let space_pos = lparen_start - 1;
        if self.src.get(space_pos) != Some(&b' ') {
            return;
        }

        // Report the offense at the space position
        self.push(space_pos, COP, true, "Do not put a space between a method name and the opening parenthesis.");
        // Fix: remove the space
        self.fixes.push((space_pos, lparen_start, Vec::new()));
    }
}

impl<'a> Cops<'a> {

    /// Layout/LeadingEmptyLines — the file must not have blank lines at the
    /// very start before the first code or comment.
    pub(crate) fn check_leading_empty_lines(&mut self, first_code_off: Option<usize>) {
        const COP: &str = "Layout/LeadingEmptyLines";
        if !self.on(COP) {
            return;
        }
        // The first token is either the first comment or the first code statement
        let first_comment_off = self.comments.first().map(|(_, s, _)| *s);
        let first_off = match (first_comment_off, first_code_off) {
            (Some(c), Some(d)) => Some(c.min(d)),
            (Some(c), None) => Some(c),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        let Some(off) = first_off else { return };
        let (line, _) = self.idx.loc(off);
        if line <= 1 {
            return;
        }
        // There are leading blank lines. The offense anchors on the first token.
        self.push(off, COP, true, "Unnecessary blank line at the beginning of the source.");
        // Fix: remove everything from byte 0 to the start of the line containing the first token
        let line_start = self.idx.starts[line - 1];
        self.fixes.push((0, line_start, Vec::new()));
    }
}

impl<'a> Cops<'a> {
    /// Layout/SpaceAfterColon — a colon in shorthand hash syntax (key:) or
    /// optional keyword parameters must be followed by whitespace. Note: the
    /// colon is not followed by space in Ruby 3.1+ value omission syntax (key:,).
    pub(crate) fn check_space_after_colon_pair(&mut self, node: &ruby_prism::AssocNode) {
        const COP: &str = "Layout/SpaceAfterColon";
        if !self.on(COP) {
            return;
        }
        // For shorthand syntax (key:), operator_loc is None
        if node.operator_loc().is_some() {
            return;
        }
        let key_loc = node.key().location();
        // The colon is the last byte of the key location
        let colon_pos = key_loc.end_offset() - 1;
        let after_colon_pos = key_loc.end_offset();
        // Ruby 3.1 value omission (`key:,`) and pattern-matching phantoms
        // (`in Foo[name:]` — prism gives the target a span overlapping the
        // key) have nothing real after the colon.
        if let Some(&b) = self.src.get(after_colon_pos) {
            if matches!(b, b',' | b'}' | b')' | b']') {
                return;
            }
        }
        if node.value().location().start_offset() < after_colon_pos {
            return;
        }
        // Check if the next byte is whitespace
        if let Some(&b) = self.src.get(after_colon_pos) {
            if !b.is_ascii_whitespace() {
                self.push(colon_pos, COP, true, "Space missing after colon.");
                self.fixes.push((after_colon_pos, after_colon_pos, b" ".to_vec()));
            }
        }
    }

    /// Layout/SpaceAfterColon — check optional keyword parameter (def foo(bar:baz))
    pub(crate) fn check_space_after_colon_kwoptarg(&mut self, node: &ruby_prism::OptionalKeywordParameterNode) {
        const COP: &str = "Layout/SpaceAfterColon";
        if !self.on(COP) {
            return;
        }
        let name_loc = node.name_loc();
        // In prism, name_loc includes the colon, so the colon is at end_offset() - 1
        let colon_pos = name_loc.end_offset() - 1;
        // Check if the next byte after the colon is whitespace
        if let Some(&b) = self.src.get(colon_pos + 1) {
            if !b.is_ascii_whitespace() {
                self.push(colon_pos, COP, true, "Space missing after colon.");
                self.fixes.push((colon_pos + 1, colon_pos + 1, b" ".to_vec()));
            }
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/SpaceInsideArrayPercentLiteral — checks for unnecessary additional
    /// spaces inside array percent literals (%i/%w/%I/%W).
    /// The regex pattern /(?:[\S&&[^\\]](?:\\ )*)( {2,})(?=\S)/ matches runs of 2+ spaces
    /// that are preceded by a non-escaped non-whitespace character.
    pub(crate) fn check_space_inside_array_percent_literal(&mut self, node: &ruby_prism::ArrayNode<'_>) {
        const COP: &str = "Layout/SpaceInsideArrayPercentLiteral";
        if !self.on(COP) {
            return;
        }

        // Check if this is a percent literal array
        let Some(opening) = node.opening_loc() else { return };
        let opening_bytes = opening.as_slice();

        // Must start with %
        if !opening_bytes.starts_with(b"%") || opening_bytes.len() < 2 {
            return;
        }

        // Check for %i, %I, %w, %W
        let literal_type = opening_bytes[1];
        if !matches!(literal_type, b'i' | b'I' | b'w' | b'W') {
            return;
        }

        let elements: Vec<_> = node.elements().iter().collect();
        if elements.len() < 2 {
            return;
        }

        // Scan for multiple spaces between consecutive elements
        for i in 0..elements.len() - 1 {
            let elem_end = elements[i].location().end_offset();
            let next_elem_start = elements[i + 1].location().start_offset();

            // Scan the gap between elements for multiple spaces
            // The gap starts at elem_end and ends before next_elem_start
            if elem_end < next_elem_start {
                self.find_space_gaps(elem_end, next_elem_start);
            }
        }
    }

    /// Find runs of 2+ consecutive spaces in the gap between two array elements.
    /// The gap should contain only whitespace and escaped spaces.
    fn find_space_gaps(&mut self, start: usize, end: usize) {
        const COP: &str = "Layout/SpaceInsideArrayPercentLiteral";
        const MSG: &str = "Use only a single space inside array percent literal.";

        let mut pos = start;

        while pos < end {
            // Check if we have a newline - if so, multi-line arrays are exempt
            if self.src[pos] == b'\n' {
                return;
            }

            // Look for 2+ consecutive regular spaces
            if self.src[pos] == b' ' {
                let space_start = pos;
                let mut space_count = 0;

                // Count consecutive spaces
                let mut space_pos = pos;
                while space_pos < end && self.src[space_pos] == b' ' {
                    space_count += 1;
                    space_pos += 1;
                }

                // If we have 2+ spaces, it's an offense
                // (The character after the spaces should be non-whitespace by definition of a gap)
                if space_count >= 2 {
                    // This is a valid match of 2+ spaces
                    self.push(space_start, COP, true, MSG);
                    // Fix: replace the multiple spaces with a single space
                    self.fixes.push((space_start, space_pos, b" ".to_vec()));
                    pos = space_pos;
                    continue;
                }

                pos = space_pos;
                continue;
            }

            // Skip escaped spaces (backslash followed by space)
            if self.src[pos] == b'\\' && pos + 1 < end && self.src[pos + 1] == b' ' {
                pos += 2;
                continue;
            }

            // Skip any other whitespace (shouldn't happen in a well-formed gap)
            if self.src[pos].is_ascii_whitespace() {
                pos += 1;
                continue;
            }

            // Unexpected non-whitespace character - shouldn't happen in a gap
            break;
        }
    }
}

impl<'a> Cops<'a> {

    /// Layout/SpaceInsideRangeLiteral — detect spaces inside .. and ... operators.
    pub(crate) fn check_space_inside_range_literal(&mut self, node: &ruby_prism::RangeNode<'_>) {
        const COP: &str = "Layout/SpaceInsideRangeLiteral";
        if !self.on(COP) {
            return;
        }

        let op_loc = node.operator_loc();
        let op_start = op_loc.start_offset();
        let op_end = op_loc.end_offset();

        // Get the operator bytes (.. or ...)
        let op_bytes = op_loc.as_slice();

        // A side without an operand (beginless/endless range) has no
        // "inside" there — surrounding space belongs to the context.
        let mut has_space_before = false;
        if node.left().is_some() && op_start > 0 && self.src[op_start - 1].is_ascii_whitespace() {
            has_space_before = true;
        }
        let mut has_space_after = false;
        if node.right().is_some() && op_end < self.src.len() && self.src[op_end].is_ascii_whitespace() {
            has_space_after = true;
        }

        // Determine if space after is part of a multiline (newline follows)
        let mut is_multiline = false;
        if has_space_after {
            // Check if there's a newline in the whitespace after the operator
            let mut check_pos = op_end;
            while check_pos < self.src.len() && self.src[check_pos].is_ascii_whitespace() {
                if self.src[check_pos] == b'\n' {
                    is_multiline = true;
                    break;
                }
                check_pos += 1;
            }
        }

        // Report offense if:
        // - Space before operator, OR
        // - Space after operator AND it's not a multiline
        if !has_space_before && (!has_space_after || is_multiline) {
            return;
        }

        // Get the range boundaries
        let range_start = node.location().start_offset();
        let range_end = node.location().end_offset();

        // Report the offense at the start of the range
        self.push(range_start, COP, true, "Space inside range literal.");

        // For the fix, reconstruct the range without spaces around the operator
        let range_bytes = &self.src[range_start..range_end];

        // Find the operator position within the range bytes
        let op_byte_pos = op_start - range_start;

        // Split the range into left, operator, and right parts
        let left = &range_bytes[..op_byte_pos];
        let right = &range_bytes[op_byte_pos + op_bytes.len()..];

        // Trim trailing whitespace from left
        let mut left_end = left.len();
        while left_end > 0 && left[left_end - 1].is_ascii_whitespace() {
            left_end -= 1;
        }
        let left_trimmed = &left[..left_end];

        // Trim leading whitespace from right
        let mut right_start = 0;
        while right_start < right.len() && right[right_start].is_ascii_whitespace() {
            right_start += 1;
        }
        let right_trimmed = &right[right_start..];

        // Build the fixed range
        let mut fixed = Vec::new();
        fixed.extend_from_slice(left_trimmed);
        fixed.extend_from_slice(op_bytes);
        fixed.extend_from_slice(right_trimmed);

        // Add the fix
        self.fixes.push((range_start, range_end, fixed));
    }
}

impl<'a> Cops<'a> {
    /// Layout/ConditionPosition — condition on a different line than if/unless/while/until.
    pub(crate) fn check_condition_position(&mut self, keyword: &[u8], keyword_off: usize, predicate: &ruby_prism::Node) {
        const COP: &str = "Layout/ConditionPosition";
        if !self.on(COP) {
            return;
        }

        // Get the line numbers
        let (kw_line, _) = self.idx.loc(keyword_off);
        let pred_loc = predicate.location();
        let (pred_line, _) = self.idx.loc(pred_loc.start_offset());

        // Skip if condition is on the same line as keyword
        if kw_line == pred_line {
            return;
        }

        // Report offense on the predicate
        let message = format!("Place the condition on the same line as `{}`.", String::from_utf8_lossy(keyword));
        self.push(pred_loc.start_offset(), COP, true, message);

        // Autocorrect: move the condition to the same line as the keyword
        // Get the bytes of the predicate
        let pred_start = pred_loc.start_offset();
        let pred_end = pred_loc.end_offset();
        let pred_bytes = &self.src[pred_start..pred_end];
        let pred_src = String::from_utf8_lossy(pred_bytes);

        // Find the whole line of the predicate to remove it (including leading whitespace and trailing newline)
        let pred_line_start = self.idx.starts[pred_line - 1];
        let pred_line_end = self.line_end(pred_line);

        // Include the newline after the condition line in the removal range
        let removal_end = if pred_line_end < self.src.len() && self.src[pred_line_end] == b'\n' {
            pred_line_end + 1
        } else {
            pred_line_end
        };

        // Insert the predicate after the keyword, with a leading space
        let kw_end = keyword_off + keyword.len();
        self.fixes.push((kw_end, kw_end, format!(" {}", pred_src).into_bytes()));

        // Remove the entire predicate line
        self.fixes.push((pred_line_start, removal_end, Vec::new()));
    }
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLinesAroundBeginBody — a `begin`/`end` block (kwbegin)
    /// must not have a blank line directly after `begin` or directly before
    /// its matching `end`. Ported from the `EmptyLinesAroundBody` mixin with
    /// `style` hardcoded to `:no_empty_lines` (see
    /// `EmptyLinesAroundBeginBody#style` — this cop never allows the
    /// "require a blank line" styles the mixin also supports for other
    /// cops).
    ///
    /// The mixin's `check_beginning`/`check_ending` anchor purely on the
    /// node's overall first/last source lines — the line carrying `begin`
    /// and the line carrying `end` — so inner `rescue`/`else`/`ensure`
    /// clauses are NOT specially walked: a blank line right before an inner
    /// `rescue`/`else` is simply not this cop's concern (confirmed by the
    /// spec fixture, e.g. "registers an offense for begin body starting
    /// with rescue" only flags the blank right after `begin`, not anything
    /// around the `rescue` keyword itself).
    pub(crate) fn check_empty_lines_around_begin_body(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Layout/EmptyLinesAroundBeginBody";
        if !self.on(COP) {
            return;
        }
        // `begin_keyword_loc` is None for the implicit BeginNode prism
        // synthesizes around a `def` body that has rescue/ensure clauses but
        // no explicit `begin`/`end` keywords in the source — there's no
        // `begin` keyword to anchor on, and rubocop's `on_kwbegin` never
        // fires for that case either, so this cop doesn't apply.
        let Some(begin_loc) = node.begin_keyword_loc() else { return };
        let Some(end_loc) = node.end_keyword_loc() else { return };

        // A strictly empty line (rubocop's `String#empty?` on
        // `processed_source.lines[n]` — whitespace-only lines do NOT count
        // as blank).
        fn is_blank_line(c: &super::Cops, line: usize) -> bool {
            match c.idx.starts.get(line - 1) {
                Some(&s) => c.line_end(line) == s,
                None => false,
            }
        }

        let begin_line = self.idx.loc(begin_loc.start_offset()).0;
        let end_line = self.idx.loc(end_loc.start_offset()).0;
        // rubocop: `return if node.single_line?`
        if begin_line == end_line {
            return;
        }

        let after_begin_line = begin_line + 1;
        let before_end_line = end_line - 1;

        // Flags a blank line: offense anchors on its (empty) content — a
        // 1-byte range at column 0 that is really just the line's own
        // newline — and the fix removes that newline, deleting the line.
        let flag = |c: &mut Self, line: usize, desc: &str| {
            let off = c.idx.starts[line - 1];
            c.fixes.push((off, off + 1, Vec::new()));
            c.push(off, COP, true, format!("Extra empty line detected at `begin` body {desc}."));
        };

        let after_blank = is_blank_line(self, after_begin_line);
        if after_blank {
            flag(self, after_begin_line, "beginning");
        }
        // When the body is exactly one blank line (`begin\n\nend`), the
        // "line right after `begin`" and "the line right before `end`" are
        // the SAME line. Real rubocop's `add_offense` dedupes identical
        // (cop, range) pairs within one investigation, so only the
        // beginning check (which runs first) ends up reporting — verified
        // against rubocop 1.88.0 directly, since the spec fixture doesn't
        // cover this edge case.
        if before_end_line == after_begin_line && after_blank {
            return;
        }
        if is_blank_line(self, before_end_line) {
            flag(self, before_end_line, "end");
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLinesAroundBlockBody — ported from rubocop's
    /// `EmptyLinesAroundBlockBody` cop + its `EmptyLinesAroundBody` mixin.
    /// Only two `EnforcedStyle`s apply to blocks (`no_empty_lines` default,
    /// `empty_lines`) — the mixin's namespace/deferred/beginning_only/
    /// ending_only branches are for other body kinds (class/module/method)
    /// and never reached from `on_block`.
    ///
    /// The mixin checks TWO fixed lines regardless of style: the line right
    /// after the opening (`do`/`{`) — call it `begin_line` — and the line
    /// right before the closing (`end`/`}`) — call it `pre_end_line`. Style
    /// controls (a) whether blank is required or forbidden there, and (b)
    /// where the offense/fix is anchored: `no_empty_lines` anchors both at
    /// the tested line itself (and removes it); `empty_lines` anchors the
    /// beginning at `begin_line` (inserts a newline before it) but anchors
    /// the END at the CLOSER's own line (`close_line`, one past
    /// `pre_end_line`) — this is rubocop's `offset = 2` special case in
    /// `check_source` for `:empty_lines` + an "end." message.
    ///
    /// Only multi-line blocks reach this (mirrors `node.single_line?`); a
    /// nil body under `empty_lines` style is exempt entirely (rubocop's
    /// `valid_body_style?`) since neither presence nor absence of a blank
    /// line can be enforced on nothing.
    pub(crate) fn check_empty_lines_around_block_body(&mut self, block: &ruby_prism::BlockNode<'_>) {
        const COP: &str = "Layout/EmptyLinesAroundBlockBody";
        if !self.on(COP) {
            return;
        }
        let open_off = block.opening_loc().start_offset();
        let close_off = block.closing_loc().start_offset();
        let open_line = self.idx.loc(open_off).0;
        let close_line = self.idx.loc(close_off).0;
        if close_line <= open_line {
            return; // single-line block — exempt, like `node.single_line?`
        }
        let style_empty = self.cfg.get(COP, "EnforcedStyle") == Some("empty_lines");
        if style_empty && block.body().is_none() {
            return; // `valid_body_style?`: nil body under empty_lines is exempt
        }
        let nlines = self.idx.starts.len();
        let is_blank = |c: &Self, line: usize| -> bool {
            if line < 1 || line > nlines {
                return false;
            }
            let s = c.idx.starts[line - 1];
            c.line_end(line) == s
        };
        let line_start = |c: &Self, line: usize| c.idx.starts[line - 1];
        // Delete the WHOLE line (through its trailing newline) — matches
        // rubocop's `corrector.remove(range)` on a zero-content blank line.
        let remove_line = |c: &mut Self, line: usize| {
            let s = line_start(c, line);
            let e = c.idx.starts.get(line).copied().unwrap_or_else(|| c.line_end(line));
            c.fixes.push((s, e, Vec::new()));
        };

        let begin_line = open_line + 1;
        let pre_end_line = close_line - 1;
        let begin_blank = is_blank(self, begin_line);
        let pre_end_blank = is_blank(self, pre_end_line);

        if !style_empty {
            if begin_blank {
                let off = line_start(self, begin_line);
                self.push(off, COP, true, "Extra empty line detected at block body beginning.");
                remove_line(self, begin_line);
            }
            if pre_end_blank {
                let off = line_start(self, pre_end_line);
                self.push(off, COP, true, "Extra empty line detected at block body end.");
                remove_line(self, pre_end_line);
            }
        } else {
            if !begin_blank {
                let off = line_start(self, begin_line);
                self.push(off, COP, true, "Empty line missing at block body beginning.");
                self.fixes.push((off, off, b"\n".to_vec()));
            }
            if !pre_end_blank {
                // Anchored one line further down than the tested line — the
                // closer's own line — per rubocop's offset-2 special case.
                let off = line_start(self, close_line);
                self.push(off, COP, true, "Empty line missing at block body end.");
                self.fixes.push((off, off, b"\n".to_vec()));
            }
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/SpaceInsideStringInterpolation — checks for whitespace within
    /// string interpolations (`#{...}`). Two styles:
    /// - `no_space` (default): no spaces just inside the delimiters
    /// - `space`: requires spaces just inside the delimiters
    pub(crate) fn check_space_inside_string_interpolation(
        &mut self,
        node: &ruby_prism::EmbeddedStatementsNode<'_>,
    ) {
        const COP: &str = "Layout/SpaceInsideStringInterpolation";
        if !self.on(COP) {
            return;
        }

        // Skip empty interpolations: #{}
        if node.statements().is_none() {
            return;
        }

        // Skip multiline interpolations
        let opening = node.opening_loc();
        let closing = node.closing_loc();
        let open_line = self.idx.loc(opening.start_offset()).0;
        let close_line = self.idx.loc(closing.start_offset()).0;
        if open_line != close_line {
            return;
        }

        let open_end = opening.end_offset();
        let close_start = closing.start_offset();

        // Check if there's a newline or comment between opening and closing
        // by checking if the content starts with comments/whitespace+newline
        if let Some(stmts) = node.statements() {
            if let Some(first_stmt) = stmts.body().iter().next() {
                let first_loc = first_stmt.location();
                // If the first statement's location is on a different line,
                // treat as multiline and skip
                if self.idx.loc(first_loc.start_offset()).0 != open_line {
                    return;
                }
            }
        }

        let style_is_space = self.cfg.get(COP, "EnforcedStyle") == Some("space");

        // Collect whitespace positions after opening delimiter
        let mut after_open_end = open_end;
        while after_open_end < close_start && self.src[after_open_end].is_ascii_whitespace() {
            if self.src[after_open_end] == b'\n' {
                return; // multiline, skip
            }
            after_open_end += 1;
        }

        // Collect whitespace positions before closing delimiter
        let mut before_close_start = close_start;
        while before_close_start > open_end && self.src[before_close_start - 1].is_ascii_whitespace() {
            if self.src[before_close_start - 1] == b'\n' {
                return; // multiline, skip
            }
            before_close_start -= 1;
        }

        let has_space_after_open = after_open_end > open_end;
        let has_space_before_close = close_start > before_close_start;

        if style_is_space {
            // For "space" style: require spaces on both sides
            if !has_space_after_open {
                // Report offense at the position of # (opening delimiter start)
                // opening_loc gives us the location of #{, so start_offset is the # position
                let report_pos = if open_end >= 2 { open_end - 2 } else { opening.start_offset() };
                self.push(report_pos, COP, true, "Use space inside string interpolation.");
                // Apply fix: add a single space after opening delimiter
                self.fixes.push((open_end, open_end, b" ".to_vec()));
            }
            if !has_space_before_close {
                // Report offense at the position of } (closing delimiter start)
                self.push(close_start, COP, true, "Use space inside string interpolation.");
                // Apply fix: add a single space before closing delimiter
                self.fixes.push((before_close_start, before_close_start, b" ".to_vec()));
            }
        } else {
            // For "no_space" style: remove spaces on both sides
            if has_space_after_open {
                // Report all spaces after opening delimiter
                self.push(open_end, COP, true, "Do not use space inside string interpolation.");
                self.fixes.push((open_end, after_open_end, Vec::new()));
            }
            if has_space_before_close {
                // Report all spaces before closing delimiter
                self.push(before_close_start, COP, true, "Do not use space inside string interpolation.");
                self.fixes.push((before_close_start, close_start, Vec::new()));
            }
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLinesAroundMethodBody — ported from rubocop's
    /// `EmptyLinesAroundMethodBody` cop + its `EmptyLinesAroundBody` mixin.
    /// `style` is hardcoded to `:no_empty_lines`
    /// (`EmptyLinesAroundMethodBody#style`) — this cop never allows the
    /// "require a blank line" styles the mixin also supports for other body
    /// kinds (class/module).
    ///
    /// For a regular (non-endless) `def`, the "beginning" line anchors on
    /// the SIGNATURE's last line — `node.rparen_loc()`'s line when the
    /// params are parenthesized (a multiline parameter list shifts this
    /// down, per the spec's "empty lines and arguments spanning multiple
    /// lines" examples), or the `def` keyword's own line otherwise —
    /// mirroring rubocop's `node.arguments.source_range&.last_line`. The
    /// "end" line anchors on the line right before the `end` keyword,
    /// exactly like `check_empty_lines_around_begin_body`, including that
    /// sibling's dedup for the single-blank-line-body case (`def foo\n\nend`)
    /// where the "beginning" and "end" lines coincide — verified against
    /// rubocop 1.88.0 directly, since the spec fixture doesn't cover it.
    /// Single-line defs (`node.single_line?`) are exempt.
    ///
    /// Endless defs (`def foo = quux`) have no `end` keyword to anchor an
    /// "end" check on, so rubocop special-cases them entirely
    /// (`offending_endless_method?` / `register_offense_for_endless_method`):
    /// only a blank line right after the `=` — when the body starts more
    /// than one line down from it — is ever flagged, always as "beginning".
    pub(crate) fn check_empty_lines_around_method_body(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/EmptyLinesAroundMethodBody";
        if !self.on(COP) {
            return;
        }

        // A strictly empty line (rubocop's `String#empty?` on
        // `processed_source.lines[n]` — whitespace-only lines do NOT count
        // as blank).
        fn is_blank_line(c: &super::Cops, line: usize) -> bool {
            match c.idx.starts.get(line - 1) {
                Some(&s) => c.line_end(line) == s,
                None => false,
            }
        }
        // Flags a blank line: offense anchors on its (empty) content — a
        // 1-byte range at column 0 that is really just the line's own
        // newline — and the fix removes that newline, deleting the line.
        let flag = |c: &mut Self, line: usize, desc: &str| {
            let off = c.idx.starts[line - 1];
            c.fixes.push((off, off + 1, Vec::new()));
            c.push(off, COP, true, format!("Extra empty line detected at method body {desc}."));
        };

        if let Some(equal_loc) = node.equal_loc() {
            // Endless method: `def foo = quux`. No `end` keyword — only the
            // "beginning" side can ever be checked.
            let Some(body) = node.body() else { return };
            let assignment_line = self.idx.loc(equal_loc.start_offset()).0;
            let body_first_line = self.idx.loc(body.location().start_offset()).0;
            if body_first_line > assignment_line + 1 && is_blank_line(self, assignment_line + 1) {
                flag(self, assignment_line + 1, "beginning");
            }
            return;
        }

        let Some(end_loc) = node.end_keyword_loc() else { return };
        let def_line = self.idx.loc(node.def_keyword_loc().start_offset()).0;
        let end_line = self.idx.loc(end_loc.start_offset()).0;
        if def_line == end_line {
            return; // single-line def — exempt, like `node.single_line?`
        }

        let first_line = match node.rparen_loc() {
            Some(rparen) => self.idx.loc(rparen.start_offset()).0,
            None => def_line,
        };
        let after_line = first_line + 1;
        let before_end_line = end_line - 1;

        let after_blank = is_blank_line(self, after_line);
        if after_blank {
            flag(self, after_line, "beginning");
        }
        if before_end_line == after_line && after_blank {
            return;
        }
        if is_blank_line(self, before_end_line) {
            flag(self, before_end_line, "end");
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/AssignmentIndentation — ports rubocop's `CheckAssignment` +
    /// `Alignment` mixins: when the right-hand-side of a multi-line
    /// assignment starts on a line of its own, that first line must be
    /// indented `configured_indentation_width` columns past the start of
    /// the assignment's own left-hand side.
    ///
    /// Every write-node visitor (`mod.rs`) calls `assignment_indentation_hook`
    /// with `(own_start_offset, operator_end_offset, rhs)` — this single
    /// entry point resolves the "leftmost multiple assignment" base (via
    /// `self.assignment_leftmost`, populated top-down since prism nodes
    /// carry no parent pointer) and then delegates to `check_assignment_indentation`,
    /// which is rubocop's `check_assignment` + `check_alignment` verbatim.
    ///
    /// `leftmost_multiple_assignment(node)` in upstream is:
    /// ```ruby
    /// def leftmost_multiple_assignment(node)
    ///   return node unless same_line?(node, node.parent) && node.parent.assignment?
    ///   leftmost_multiple_assignment(node.parent)  # <- return value discarded!
    ///   node.parent
    /// end
    /// ```
    /// Because the recursive call's result is thrown away, the method only
    /// ever climbs ONE level: node's own start if it doesn't share a line
    /// with an assignment parent, else the immediate parent's start —
    /// regardless of how much further the chain continues. We replicate
    /// that (bug-for-bug) via a one-shot override map instead of a real
    /// parent walk: whichever assignment visits `rhs` next looks itself up.
    pub(crate) fn assignment_indentation_hook(
        &mut self,
        own_start_offset: usize,
        operator_end_offset: usize,
        rhs: ruby_prism::Node,
    ) {
        // Tell a same-line chained rhs (`foo = bar = baz`) to use OUR start
        // as ITS leftmost base, before consuming `rhs` below.
        if is_assignment_like(&rhs) {
            let rhs_start = rhs.location().start_offset();
            if self.idx.loc(own_start_offset).0 == self.idx.loc(rhs_start).0 {
                self.assignment_leftmost.insert(rhs_start, own_start_offset);
            }
        }
        // Resolve any override left for US by an enclosing same-line
        // assignment (falls back to our own start otherwise).
        let base = self.assignment_leftmost.remove(&own_start_offset).unwrap_or(own_start_offset);
        self.check_assignment_indentation(base, operator_end_offset, rhs);
    }

    /// `check_assignment` + `Alignment#check_alignment` for a single-item
    /// `[rhs]` list (this cop only ever aligns the one rhs node).
    fn check_assignment_indentation(
        &mut self,
        lhs_start_offset: usize,
        operator_end_offset: usize,
        rhs: ruby_prism::Node,
    ) {
        const COP: &str = "Layout/AssignmentIndentation";
        if !self.on(COP) {
            return;
        }
        let rhs_loc = rhs.location();
        let rhs_start = rhs_loc.start_offset();
        let (op_line, _) = self.idx.loc(operator_end_offset);
        let (rhs_line, _) = self.idx.loc(rhs_start);
        // `return if same_line?(node.loc.operator, rhs)`.
        if op_line == rhs_line {
            return;
        }
        // `each_bad_alignment`'s `begins_its_line?` guard — only the first
        // non-whitespace token on its line can be misaligned.
        let line_start = self.idx.starts[rhs_line - 1];
        if !self.src[line_start..rhs_start].iter().all(u8::is_ascii_whitespace) {
            return;
        }
        let width = self.assignment_indentation_width(COP);
        let base = self.display_column(lhs_start_offset);
        let expected = base + width;
        let actual = self.display_column(rhs_start);
        if actual == expected {
            return;
        }
        self.push(
            rhs_start,
            COP,
            true,
            "Indent the first line of the right-hand-side of a multi-line assignment.",
        );
        // `AlignmentCorrector.correct`: replace the rhs's own leading
        // whitespace with exactly `expected` spaces (reindents its first
        // line; a genuinely multi-line rhs keeps its interior lines as-is —
        // no fixture here has one, and those are `IndentationConsistency`'s
        // and `EndAlignment`'s job upstream too).
        self.fixes.push((line_start, rhs_start, vec![b' '; expected]));
    }

    /// `Alignment#configured_indentation_width`: cop-local `IndentationWidth`,
    /// else `Layout/IndentationWidth`'s `Width`, else 2.
    fn assignment_indentation_width(&self, cop: &'static str) -> usize {
        self.cfg
            .param(cop, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }

    /// `Alignment#display_column`: the display width (Unicode East-Asian
    /// Width; fullwidth/wide characters count as 2 columns) of the text
    /// preceding `offset` on its own line.
    fn display_column(&self, offset: usize) -> usize {
        let (line, _) = self.idx.loc(offset);
        let line_start = self.idx.starts[line - 1];
        display_width(&self.src[line_start..offset])
    }
}

/// Is `node` one of the node kinds rubocop's `Node#assignment?` recognizes
/// (`lvasgn`/`ivasgn`/`cvasgn`/`gvasgn`/`casgn`/`masgn`/`op_asgn`/`or_asgn`/
/// `and_asgn`), reachable as the `value` of another write node — used to
/// detect a chained multiple assignment (`foo = bar = baz`).
///
/// Deliberately NOT covered (rubocop's `on_send` branch of `CheckAssignment`,
/// gated on `node.loc.operator` — true only for setter/index sends): attr
/// writers (`obj.attr = x`) and indexed assignment (`a[i] = x`), plain or
/// compound (prism's `CallOperatorWriteNode`/`CallOrWriteNode`/
/// `CallAndWriteNode`/`IndexOperatorWriteNode`/`IndexOrWriteNode`/
/// `IndexAndWriteNode`, and plain `CallNode` for `=`/`[]=`). None of the
/// fixture's examples exercise them.
fn is_assignment_like(node: &ruby_prism::Node) -> bool {
    node.as_local_variable_write_node().is_some()
        || node.as_local_variable_operator_write_node().is_some()
        || node.as_local_variable_or_write_node().is_some()
        || node.as_local_variable_and_write_node().is_some()
        || node.as_instance_variable_write_node().is_some()
        || node.as_instance_variable_operator_write_node().is_some()
        || node.as_instance_variable_or_write_node().is_some()
        || node.as_instance_variable_and_write_node().is_some()
        || node.as_class_variable_write_node().is_some()
        || node.as_class_variable_operator_write_node().is_some()
        || node.as_class_variable_or_write_node().is_some()
        || node.as_class_variable_and_write_node().is_some()
        || node.as_global_variable_write_node().is_some()
        || node.as_global_variable_operator_write_node().is_some()
        || node.as_global_variable_or_write_node().is_some()
        || node.as_global_variable_and_write_node().is_some()
        || node.as_constant_write_node().is_some()
        || node.as_constant_operator_write_node().is_some()
        || node.as_constant_or_write_node().is_some()
        || node.as_constant_and_write_node().is_some()
        || node.as_constant_path_write_node().is_some()
        || node.as_constant_path_operator_write_node().is_some()
        || node.as_constant_path_or_write_node().is_some()
        || node.as_constant_path_and_write_node().is_some()
        || node.as_multi_write_node().is_some()
}

/// Unicode East-Asian-Width column width, good enough for `Unicode::
/// DisplayWidth`'s default table on the ranges that matter here (CJK,
/// Hangul, fullwidth forms count as 2 columns; everything else is 1 —
/// combining marks aren't handled, no fixture exercises them).
fn display_width(bytes: &[u8]) -> usize {
    if bytes.is_ascii() {
        return bytes.len();
    }
    String::from_utf8_lossy(bytes).chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    let wide = matches!(cp,
        0x1100..=0x115F   // Hangul Jamo
        | 0x2E80..=0x303E // CJK Radicals .. CJK Symbols/Punctuation
        | 0x3041..=0x33FF // Hiragana .. CJK Compat
        | 0x3400..=0x4DBF // CJK Ext A
        | 0x4E00..=0x9FFF // CJK Unified Ideographs
        | 0xA000..=0xA4CF // Yi
        | 0xAC00..=0xD7A3 // Hangul syllables
        | 0xF900..=0xFAFF // CJK Compat Ideographs
        | 0xFE30..=0xFE4F // CJK Compat Forms
        | 0xFF00..=0xFF60 // Fullwidth Forms
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x3FFFD
    );
    if wide { 2 } else { 1 }
}
impl<'a> Cops<'a> {
    /// Layout/SpaceInsidePercentLiteralDelimiters — checks for unnecessary
    /// additional spaces inside the delimiters of %i/%w/%x literals.
    pub(crate) fn check_space_inside_percent_literal_delimiters_array(
        &mut self,
        node: &ruby_prism::ArrayNode<'_>,
    ) {
        const COP: &str = "Layout/SpaceInsidePercentLiteralDelimiters";
        if !self.on(COP) {
            return;
        }

        // Check if this is a percent literal array
        let Some(opening) = node.opening_loc() else { return };
        let opening_bytes = opening.as_slice();

        // Must start with %
        if !opening_bytes.starts_with(b"%") || opening_bytes.len() < 2 {
            return;
        }

        // Check for %i, %I, %w, %W
        let literal_type = opening_bytes[1];
        if !matches!(literal_type, b'i' | b'I' | b'w' | b'W') {
            return;
        }

        let Some(closing) = node.closing_loc() else { return };
        self.check_percent_literal_delimiters_content(opening, closing);
    }

    /// Layout/SpaceInsidePercentLiteralDelimiters — checks for unnecessary
    /// additional spaces inside the delimiters of %x literals.
    pub(crate) fn check_space_inside_percent_literal_delimiters_xstr(
        &mut self,
        node: &ruby_prism::XStringNode<'_>,
    ) {
        const COP: &str = "Layout/SpaceInsidePercentLiteralDelimiters";
        if !self.on(COP) {
            return;
        }

        // Check if this is a percent literal
        let opening = node.opening_loc();
        let opening_bytes = opening.as_slice();

        // Must start with %
        if !opening_bytes.starts_with(b"%") || opening_bytes.len() < 2 {
            return;
        }

        // Check for %x
        let literal_type = opening_bytes[1];
        if literal_type != b'x' {
            return;
        }

        let closing = node.closing_loc();
        self.check_percent_literal_delimiters_content(opening, closing);
    }

    // `%x( #{cmd} ... )` with interpolation is an InterpolatedXStringNode,
    // not an XStringNode — same geometry, same check.
    pub(crate) fn check_space_inside_percent_literal_delimiters_ixstr(
        &mut self,
        node: &ruby_prism::InterpolatedXStringNode<'_>,
    ) {
        const COP: &str = "Layout/SpaceInsidePercentLiteralDelimiters";
        if !self.on(COP) {
            return;
        }
        let opening = node.opening_loc();
        let opening_bytes = opening.as_slice();
        if !opening_bytes.starts_with(b"%") || opening_bytes.len() < 2 || opening_bytes[1] != b'x' {
            return;
        }
        self.check_percent_literal_delimiters_content(opening, node.closing_loc());
    }

    /// Check the content between opening and closing delimiters for
    /// unnecessary spaces. Handles both blank content and leading/trailing spaces.
    fn check_percent_literal_delimiters_content(
        &mut self,
        opening: ruby_prism::Location,
        closing: ruby_prism::Location,
    ) {
        const COP: &str = "Layout/SpaceInsidePercentLiteralDelimiters";
        const MSG: &str = "Do not use spaces inside percent literal delimiters.";

        let open_end = opening.end_offset();
        let close_start = closing.start_offset();

        // Get the body range (from end of opening delimiter to start of closing delimiter)
        if open_end >= close_start {
            return;
        }

        let body_slice = &self.src[open_end..close_start];

        // Check for blank content (only spaces and/or newlines)
        let is_blank = body_slice.iter().all(|&b| b == b' ' || b == b'\n' || b == b'\r');

        if is_blank {
            // If content is all whitespace, report the entire body range for removal
            if !body_slice.is_empty() {
                self.push(open_end, COP, true, MSG);
                self.fixes.push((open_end, close_start, vec![]));
            }
            return;
        }

        // Check for single-line literals with unnecessary leading/trailing spaces
        if !body_slice.contains(&b'\n') {
            // Single-line: check for leading and trailing spaces
            self.check_leading_spaces(open_end, close_start);
            self.check_trailing_spaces(open_end, close_start);
        }
    }

    /// Check for leading spaces after the opening delimiter (single-line only).
    fn check_leading_spaces(&mut self, start: usize, end: usize) {
        const COP: &str = "Layout/SpaceInsidePercentLiteralDelimiters";
        const MSG: &str = "Do not use spaces inside percent literal delimiters.";

        // Match leading spaces (but not escaped spaces)
        let mut pos = start;
        while pos < end && self.src[pos] == b' ' {
            pos += 1;
        }

        // If we found leading spaces, report them
        if pos > start {
            self.push(start, COP, true, MSG);
            self.fixes.push((start, pos, vec![]));
        }
    }

    /// Check for trailing spaces before the closing delimiter (single-line only).
    fn check_trailing_spaces(&mut self, start: usize, end: usize) {
        const COP: &str = "Layout/SpaceInsidePercentLiteralDelimiters";
        const MSG: &str = "Do not use spaces inside percent literal delimiters.";

        // Scan backwards from the end to find trailing spaces
        let mut pos = end;
        while pos > start && self.src[pos - 1] == b' ' {
            pos -= 1;
        }

        // If we found trailing spaces, check which ones should be reported
        if pos < end {
            // We found trailing spaces. Check the character before them.
            let char_before_spaces = if pos > start { self.src[pos - 1] } else { b'\n' };

            // If preceded by a backslash, we need special handling
            if char_before_spaces == b'\\' {
                // Check if the backslash itself is escaped by counting preceding backslashes
                let mut backslash_count = 0;
                let mut check_pos = pos - 1;
                while check_pos > start && self.src[check_pos] == b'\\' {
                    backslash_count += 1;
                    check_pos = check_pos.saturating_sub(1);
                }

                // If there's an odd number of backslashes, the first space after them is escaped
                if backslash_count % 2 == 1 {
                    // The first space after the backslash is escaped.
                    // But if there are multiple spaces, the ones after the first might not be escaped.
                    // Count spaces: if there's more than one, report the ones after the first.
                    let space_count = end - pos;
                    if space_count > 1 {
                        // Report all but the first space (which is escaped)
                        self.push(pos + 1, COP, true, MSG);
                        self.fixes.push((pos + 1, end, vec![]));
                    }
                    // If there's only one space and it's escaped, don't report
                    return;
                }
            }

            // If not preceded by a backslash (or even number of backslashes), report all trailing spaces
            self.push(pos, COP, true, MSG);
            self.fixes.push((pos, end, vec![]));
        }
    }
}


/// The `EnforcedStyle`s the `EmptyLinesAroundBody` mixin supports for
/// class/module bodies. `BeginningOnly`/`EndingOnly` are
/// `EmptyLinesAroundClassBody`-only additions to `SupportedStyles` —
/// `EmptyLinesAroundModuleBody`'s schema never lists them — but they're
/// modeled here too since both cops share this enum; `el_check_both`
/// resolves them down to a `NoEmptyLines`/`EmptyLines` pair before they
/// ever reach `el_check_beginning`/`el_check_ending`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ElStyle {
    NoEmptyLines,
    EmptyLines,
    EmptyLinesExceptNamespace,
    EmptyLinesSpecial,
    BeginningOnly,
    EndingOnly,
}

/// `EmptyLinesAroundBody#constant_definition?` — `{class module}` node
/// pattern.
fn el_is_constant_definition(node: &ruby_prism::Node) -> bool {
    node.as_class_node().is_some() || node.as_module_node().is_some()
}

/// `EmptyLinesAroundBody#empty_line_required?` —
/// `{any_def class module (send nil? {:private :protected :public})}`. The
/// `(send nil? ...)` branch matches only a BARE `private`/`protected`/
/// `public` call: no explicit receiver and no arguments (a node-pattern with
/// no trailing `...` requires the send to have exactly zero args).
fn el_empty_line_required(node: &ruby_prism::Node) -> bool {
    if node.as_def_node().is_some() || el_is_constant_definition(node) {
        return true;
    }
    if let Some(call) = node.as_call_node() {
        if call.receiver().is_none() && call.arguments().is_none() {
            return matches!(call.name().as_slice(), b"private" | b"protected" | b"public");
        }
    }
    false
}

/// Prism always wraps a >=1-statement body in a `StatementsNode`, whereas
/// whitequark only introduces its `begin` wrapper node once there are >= 2
/// top-level statements (a lone statement is left unwrapped). So a
/// single-child `StatementsNode` is whitequark's "non-begin" case — the
/// mixin's `body.begin_type?` branches only fire here when there are truly
/// >= 2 children.
fn el_stmts_children<'pr>(body: &ruby_prism::Node<'pr>) -> Option<Vec<ruby_prism::Node<'pr>>> {
    body.as_statements_node().map(|s| s.body().iter().collect())
}

/// `EmptyLinesAroundBody#namespace?`.
fn el_is_namespace(body: &ruby_prism::Node, with_one_child: bool) -> bool {
    match el_stmts_children(body) {
        Some(children) if children.len() == 1 => el_is_constant_definition(&children[0]),
        Some(_) if with_one_child => false,
        Some(children) => children.iter().all(el_is_constant_definition),
        None => el_is_constant_definition(body),
    }
}

/// `EmptyLinesAroundBody#first_child_requires_empty_line?`.
fn el_first_child_requires_empty_line(body: &ruby_prism::Node) -> bool {
    match el_stmts_children(body) {
        Some(children) => children.first().map(el_empty_line_required).unwrap_or(false),
        None => el_empty_line_required(body),
    }
}

/// `EmptyLinesAroundBody#first_empty_line_required_child`. Takes `body` by
/// value (unlike the other `el_*` helpers) since the "unwrapped single
/// statement" case has to hand the node itself back out, and `Node` isn't
/// `Clone`.
fn el_first_empty_line_required_child<'pr>(
    body: ruby_prism::Node<'pr>,
) -> Option<ruby_prism::Node<'pr>> {
    match body.as_statements_node() {
        Some(stmts) => stmts.body().iter().find(el_empty_line_required),
        None => {
            if el_empty_line_required(&body) {
                Some(body)
            } else {
                None
            }
        }
    }
}

/// `EmptyLinesAroundBody#deferred_message` — `node.type` for a `DefNode`
/// with a receiver is whitequark's `:defs` (singleton method); everything
/// else maps 1:1 onto the prism node kind.
fn el_deferred_message(node: &ruby_prism::Node) -> String {
    let kind = if let Some(def) = node.as_def_node() {
        if def.receiver().is_some() { "defs" } else { "def" }
    } else if node.as_class_node().is_some() {
        "class"
    } else if node.as_module_node().is_some() {
        "module"
    } else {
        "send"
    };
    format!("Empty line missing before first {kind} definition")
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLinesAroundModuleBody — ports rubocop's
    /// `EmptyLinesAroundModuleBody` cop, which is a thin `on_module` shim
    /// over the full `EmptyLinesAroundBody` mixin (unlike
    /// `EmptyLinesAroundBeginBody`/`EmptyLinesAroundMethodBody`, this cop's
    /// `EnforcedStyle` is configurable — all 4 `SupportedStyles` apply).
    ///
    /// A nil body (`module Foo\nend`) is exempt for every style except
    /// `no_empty_lines` (`valid_body_style?`); a single-line module
    /// (`module Foo; end`) is always exempt (`node.single_line?`).
    /// Otherwise the node's own first/last source line anchor the
    /// beginning/end checks exactly like the sibling cops: "beginning"
    /// tests the line right after the `module` keyword's own line, "end"
    /// tests the line right before the closing `end`.
    ///
    /// `empty_lines_except_namespace`/`empty_lines_special` additionally
    /// special-case a body that's itself just one (or, for `_special`,
    /// several) nested `class`/`module` — the fixture doesn't exercise
    /// `empty_lines_special` (nor its "deferred empty line before first
    /// def/class/module/bare-visibility-call" diagnostic), but the mixin
    /// logic is ported in full for parity with real rubocop.
    pub(crate) fn check_empty_lines_around_module_body(&mut self, node: &ruby_prism::ModuleNode) {
        const COP: &str = "Layout/EmptyLinesAroundModuleBody";
        if !self.on(COP) {
            return;
        }

        let style = match self.cfg.enforced_style(COP) {
            "empty_lines" => ElStyle::EmptyLines,
            "empty_lines_except_namespace" => ElStyle::EmptyLinesExceptNamespace,
            "empty_lines_special" => ElStyle::EmptyLinesSpecial,
            _ => ElStyle::NoEmptyLines,
        };

        let body = node.body();
        // `valid_body_style?`: `body.nil? && style != :no_empty_lines`.
        if body.is_none() && style != ElStyle::NoEmptyLines {
            return;
        }

        let node_loc = node.location();
        let first_line = self.idx.loc(node_loc.start_offset()).0;
        let last_line = self.idx.loc(node_loc.end_offset().saturating_sub(1)).0;
        if first_line == last_line {
            return; // `node.single_line?`
        }

        self.el_check(COP, "module", style, body, first_line, last_line);
    }

    /// Shared `check`/`check_empty_lines_except_namespace`/
    /// `check_empty_lines_special` dispatch from the `EmptyLinesAroundBody`
    /// mixin — common to `EmptyLinesAroundModuleBody`'s `on_module` and
    /// `EmptyLinesAroundClassBody`'s `on_class`/`on_sclass`, once each has
    /// resolved its own `style`/`body`/`first_line`/`last_line` (including
    /// the `on_class`-only `adjusted_first_line` and the `valid_body_style?`/
    /// `single_line?` guards, which live in the per-node-type callers since
    /// they run before this point in the mixin's `check`).
    fn el_check(
        &mut self,
        cop: &'static str,
        kind: &str,
        style: ElStyle,
        body: Option<ruby_prism::Node>,
        first_line: usize,
        last_line: usize,
    ) {
        match style {
            ElStyle::EmptyLinesExceptNamespace => {
                // Guaranteed `Some` here: a `nil` body already returned above
                // for every non-`no_empty_lines` style.
                let body = body.expect("checked above");
                let sub =
                    if el_is_namespace(&body, true) { ElStyle::NoEmptyLines } else { ElStyle::EmptyLines };
                self.el_check_both(cop, kind, sub, first_line, last_line);
            }
            ElStyle::EmptyLinesSpecial => {
                let Some(body) = body else { return };
                // Both mixin call sites (`check_empty_lines_except_namespace`
                // and `check_empty_lines_special`) pass `with_one_child:
                // true` — the `false` default is never actually used.
                if el_is_namespace(&body, true) {
                    self.el_check_both(cop, kind, ElStyle::NoEmptyLines, first_line, last_line);
                } else {
                    if el_first_child_requires_empty_line(&body) {
                        self.el_check_beginning(cop, kind, ElStyle::EmptyLines, first_line);
                    } else {
                        self.el_check_beginning(cop, kind, ElStyle::NoEmptyLines, first_line);
                        self.check_deferred_empty_line(cop, body);
                    }
                    self.el_check_ending(cop, kind, ElStyle::EmptyLines, last_line);
                }
            }
            other => self.el_check_both(cop, kind, other, first_line, last_line),
        }
    }

    /// A strictly empty line (rubocop's `String#empty?` on
    /// `processed_source.lines[n]` — whitespace-only lines do NOT count as
    /// blank).
    fn el_is_blank_line(&self, line: usize) -> bool {
        let nlines = self.idx.starts.len();
        if line < 1 || line > nlines {
            return false;
        }
        let s = self.idx.starts[line - 1];
        self.line_end(line) == s
    }

    /// `comment_line?` — the entire line (ignoring leading whitespace) is a
    /// comment.
    fn el_is_comment_line(&self, line: usize) -> bool {
        let nlines = self.idx.starts.len();
        if line < 1 || line > nlines {
            return false;
        }
        let s = self.idx.starts[line - 1];
        let e = self.line_end(line);
        match self.src[s..e].iter().position(|b| !b.is_ascii_whitespace()) {
            Some(i) => self.src[s + i] == b'#',
            None => false,
        }
    }

    /// `check_both` — plus the `beginning_only`/`ending_only` cases from
    /// the same-named mixin method (`EmptyLinesAroundClassBody`-only
    /// styles: each resolves to a fixed `NoEmptyLines`/`EmptyLines` pair
    /// rather than reusing `style` for both ends).
    fn el_check_both(&mut self, cop: &'static str, kind: &str, style: ElStyle, first_line: usize, last_line: usize) {
        match style {
            ElStyle::BeginningOnly => {
                self.el_check_beginning(cop, kind, ElStyle::EmptyLines, first_line);
                self.el_check_ending(cop, kind, ElStyle::NoEmptyLines, last_line);
            }
            ElStyle::EndingOnly => {
                self.el_check_beginning(cop, kind, ElStyle::NoEmptyLines, first_line);
                self.el_check_ending(cop, kind, ElStyle::EmptyLines, last_line);
            }
            _ => {
                self.el_check_beginning(cop, kind, style, first_line);
                self.el_check_ending(cop, kind, style, last_line);
            }
        }
    }

    /// `check_beginning` + `check_source`/`check_line` for the "beginning"
    /// anchor (`desc == 'beginning'`, so `check_line`'s `offset` is always
    /// 1): tests the line right after the node's own first line, and
    /// (for both styles) anchors the offense/fix at that same tested line.
    fn el_check_beginning(&mut self, cop: &'static str, kind: &str, style: ElStyle, first_line: usize) {
        let tested_line = first_line + 1;
        match style {
            ElStyle::NoEmptyLines => {
                if self.el_is_blank_line(tested_line) {
                    let off = self.idx.starts[tested_line - 1];
                    if self.el_offended.insert((cop, off)) {
                        self.push(off, cop, true, format!("Extra empty line detected at {kind} body beginning."));
                        self.fixes.push((off, off + 1, Vec::new()));
                    }
                }
            }
            ElStyle::EmptyLines => {
                if !self.el_is_blank_line(tested_line) {
                    let off = self.idx.starts[tested_line - 1];
                    if self.el_offended.insert((cop, off)) {
                        self.push(off, cop, true, format!("Empty line missing at {kind} body beginning."));
                        self.fixes.push((off, off, b"\n".to_vec()));
                    }
                }
            }
            ElStyle::EmptyLinesExceptNamespace
            | ElStyle::EmptyLinesSpecial
            | ElStyle::BeginningOnly
            | ElStyle::EndingOnly => unreachable!(),
        }
    }

    /// `check_ending` + `check_source`/`check_line` for the "end" anchor
    /// (`desc == 'end'`): tests the line right before the node's closing
    /// `end`. `no_empty_lines` anchors at that same tested line;
    /// `empty_lines` anchors one line further down — the closer's own line
    /// (`check_line`'s `offset = 2` special case for an "end." message).
    fn el_check_ending(&mut self, cop: &'static str, kind: &str, style: ElStyle, last_line: usize) {
        let tested_line = last_line - 1;
        match style {
            ElStyle::NoEmptyLines => {
                if self.el_is_blank_line(tested_line) {
                    let off = self.idx.starts[tested_line - 1];
                    if self.el_offended.insert((cop, off)) {
                        self.push(off, cop, true, format!("Extra empty line detected at {kind} body end."));
                        self.fixes.push((off, off + 1, Vec::new()));
                    }
                }
            }
            ElStyle::EmptyLines => {
                if !self.el_is_blank_line(tested_line) {
                    let off = self.idx.starts[last_line - 1];
                    if self.el_offended.insert((cop, off)) {
                        self.push(off, cop, true, format!("Empty line missing at {kind} body end."));
                        self.fixes.push((off, off, b"\n".to_vec()));
                    }
                }
            }
            ElStyle::EmptyLinesExceptNamespace
            | ElStyle::EmptyLinesSpecial
            | ElStyle::BeginningOnly
            | ElStyle::EndingOnly => unreachable!(),
        }
    }

    /// `check_deferred_empty_line` + `previous_line_ignoring_comments`:
    /// only reached under `empty_lines_special` when the body's first
    /// "empty line required" child ISN'T also the first statement overall
    /// (that case is handled by `el_check_beginning` instead). Walks
    /// upward from the line right before that child, skipping over any
    /// contiguous leading comment lines, and — unless the line it lands on
    /// is already blank — inserts a blank line right before it.
    fn check_deferred_empty_line(&mut self, cop: &'static str, body: ruby_prism::Node) {
        let Some(node) = el_first_empty_line_required_child(body) else { return };
        let node_first_line = self.idx.loc(node.location().start_offset()).0;

        let mut tested_line = node_first_line.saturating_sub(1).max(1);
        while tested_line > 1 && self.el_is_comment_line(tested_line) {
            tested_line -= 1;
        }
        if self.el_is_blank_line(tested_line) {
            return;
        }

        let anchor_line = tested_line + 1;
        let Some(&off) = self.idx.starts.get(anchor_line - 1) else { return };
        if self.el_offended.insert((cop, off)) {
            self.push(off, cop, true, el_deferred_message(&node));
            self.fixes.push((off, off, b"\n".to_vec()));
        }
    }
}

/// `EnforcedStyle` for `Layout/EmptyLinesAroundClassBody` — unlike
/// `EmptyLinesAroundModuleBody`, this cop's schema also lists
/// `beginning_only`/`ending_only` (see `config/default.yml`).
fn el_class_style(raw: &str) -> ElStyle {
    match raw {
        "empty_lines" => ElStyle::EmptyLines,
        "empty_lines_except_namespace" => ElStyle::EmptyLinesExceptNamespace,
        "empty_lines_special" => ElStyle::EmptyLinesSpecial,
        "beginning_only" => ElStyle::BeginningOnly,
        "ending_only" => ElStyle::EndingOnly,
        _ => ElStyle::NoEmptyLines,
    }
}

impl<'a> super::Cops<'a> {
    /// Layout/EmptyLinesAroundClassBody — ports rubocop's
    /// `EmptyLinesAroundClassBody` cop: a thin `on_class`/`on_sclass` shim
    /// over the shared `EmptyLinesAroundBody` mixin (see
    /// `check_empty_lines_around_module_body` above, whose `el_*` helpers
    /// this reuses in full). Two differences from the module cop:
    ///
    /// - its `SupportedStyles` additionally include `beginning_only`/
    ///   `ending_only` (`el_class_style` above, `el_check_both`'s extra
    ///   match arms);
    /// - `on_class` passes `adjusted_first_line: node.parent_class.last_line`
    ///   when the class has a superclass expression — so for e.g.
    ///   `class Foo < Struct.new(\n  ...\n)\n\n  body\nend`, the "beginning"
    ///   check treats the superclass's own closing line as the class's
    ///   effective first line, and looks for a blank line right after it
    ///   (not right after the `class Foo < Struct.new(` line). `on_sclass`
    ///   has no superclass, so it never adjusts.
    ///
    /// Both entry points share the KIND = 'class' message text (i.e.
    /// "class body ..." even for `class << self`) since rubocop's `KIND`
    /// is a cop-level constant, not per-node.
    pub(crate) fn check_empty_lines_around_class_body(&mut self, node: &ruby_prism::ClassNode) {
        const COP: &str = "Layout/EmptyLinesAroundClassBody";
        if !self.on(COP) {
            return;
        }

        let style = el_class_style(self.cfg.enforced_style(COP));

        let body = node.body();
        // `valid_body_style?`: `body.nil? && style != :no_empty_lines`.
        if body.is_none() && style != ElStyle::NoEmptyLines {
            return;
        }

        let node_loc = node.location();
        let first_line = self.idx.loc(node_loc.start_offset()).0;
        let last_line = self.idx.loc(node_loc.end_offset().saturating_sub(1)).0;
        if first_line == last_line {
            return; // `node.single_line?`
        }

        // `first_line = node.parent_class.last_line if node.parent_class`.
        let first_line = match node.superclass() {
            Some(sc) => self.idx.loc(sc.location().end_offset().saturating_sub(1)).0,
            None => first_line,
        };

        self.el_check(COP, "class", style, body, first_line, last_line);
    }

    /// `on_sclass` — `check(node, node.body)`, no `adjusted_first_line`.
    pub(crate) fn check_empty_lines_around_sclass_body(&mut self, node: &ruby_prism::SingletonClassNode) {
        const COP: &str = "Layout/EmptyLinesAroundClassBody";
        if !self.on(COP) {
            return;
        }

        let style = el_class_style(self.cfg.enforced_style(COP));

        let body = node.body();
        if body.is_none() && style != ElStyle::NoEmptyLines {
            return;
        }

        let node_loc = node.location();
        let first_line = self.idx.loc(node_loc.start_offset()).0;
        let last_line = self.idx.loc(node_loc.end_offset().saturating_sub(1)).0;
        if first_line == last_line {
            return;
        }

        self.el_check(COP, "class", style, body, first_line, last_line);
    }
}
impl<'a> super::Cops<'a> {

    /// Layout/LeadingCommentSpace — comments must have a leading space after
    /// the `#` denoting the start of the comment. Special syntax like `#++`,
    /// `#--`, `#=` (sprockets), `=begin`/`=end` are exempt. Config gates:
    /// AllowDoxygenCommentStyle (`#*`), AllowGemfileRubyComment (`#ruby` in
    /// Gemfile), AllowRBSInlineAnnotation (`#:`, `#[...]`, `#|`),
    /// AllowSteepAnnotation (`#$` or `#:`). Shebangs (`#!`) are exempt on
    /// line 1 and when they continue from a previous shebang line. Rackup
    /// options (`#\`) are exempt on line 1 of `config.ru` only.
    pub(crate) fn check_leading_comment_space(&mut self) {
        const COP: &str = "Layout/LeadingCommentSpace";
        if !self.on(COP) {
            return;
        }

        let filename = std::path::Path::new(self.rel_path).file_name().map(|f| f.to_string_lossy());
        let is_gemfile = filename.as_ref().is_some_and(|f| f.as_ref() == "Gemfile");
        let is_config_ru = filename.as_ref().is_some_and(|f| f.as_ref() == "config.ru");

        for (line, start, end) in self.comments {
            let comment_text = String::from_utf8_lossy(&self.src[*start..*end]);

            // Check if the comment needs a space after the #
            // Pattern: one or more # followed immediately by a non-# non-space non-= char
            // Exclude: #++, #--, and patterns that don't match
            if !needs_leading_space(&comment_text) {
                continue;
            }


            // Skip if on first line and it's a shebang
            if *line == 1 && comment_text.starts_with("#!") {
                continue;
            }

            // Skip if on first line in config.ru and it's rackup options
            if *line == 1 && is_config_ru && comment_text.starts_with("#\\") {
                continue;
            }

            // Check for shebang continuation: #! on non-first-line but previous
            // line also has a #! without an offense
            if comment_text.starts_with("#!") && *line > 1 {
                if let Some((prev_l, prev_s, prev_e)) = self.comments.iter().find(|(l, _, _)| *l == *line - 1) {
                    let prev_text = String::from_utf8_lossy(&self.src[*prev_s..*prev_e]);
                    if prev_text.starts_with("#!") {
                        // Check if the previous line was marked as an offense
                        let has_offense = self.offenses.iter().any(|off| {
                            off.line == *prev_l && off.cop == COP
                        });
                        if !has_offense {
                            // Previous line has #! without offense, so this is continuation
                            continue;
                        }
                    }
                }
            }

            // Check AllowDoxygenCommentStyle
            if self.cfg.get(COP, "AllowDoxygenCommentStyle") == Some("true") && comment_text.starts_with("#*") {
                continue;
            }

            // Check AllowGemfileRubyComment
            if self.cfg.get(COP, "AllowGemfileRubyComment") == Some("true")
                && is_gemfile
                && comment_text.starts_with("#ruby")
            {
                continue;
            }

            // Check AllowRBSInlineAnnotation
            if self.cfg.get(COP, "AllowRBSInlineAnnotation") == Some("true") {
                if comment_text.starts_with("#:") || comment_text.starts_with("#|") {
                    continue;
                }
                // Check for #[...] pattern
                if comment_text.starts_with("#[") && comment_text.contains(']') {
                    continue;
                }
            }

            // Check AllowSteepAnnotation
            if self.cfg.get(COP, "AllowSteepAnnotation") == Some("true") {
                if comment_text.starts_with("#$") || comment_text.starts_with("#:") {
                    continue;
                }
            }

            // Register offense and fix: insert space after the # character
            self.push(*start, COP, true, "Missing space after `#`.");
            self.fixes.push((*start + 1, *start + 1, b" ".to_vec()));
        }
    }
}

/// Check if a comment needs a leading space after #.
/// Pattern: one or more # followed immediately by a non-# non-space non-= char.
/// Excludes: #++, #-- (RDoc syntax).
fn needs_leading_space(comment: &str) -> bool {
    // Must start with #
    if !comment.starts_with('#') {
        return false;
    }

    // Exclude #++ and #--
    if comment.starts_with("#++") || comment.starts_with("#--") {
        return false;
    }

    // Count leading # characters
    let hash_count = comment.chars().take_while(|&c| c == '#').count();
    if hash_count == 0 {
        return false;
    }

    // Check what comes after the # characters
    match comment.chars().nth(hash_count) {
        None => false, // Just # or ##... with nothing after
        Some(c) if c == ' ' => false, // Already has a space
        Some(c) if c == '=' => false, // Sprockets directive (#=)
        Some(c) if c == '#' => false, // More # characters (not a match)
        Some(_) => true, // Some other character - needs a space
    }
}

impl<'a> Cops<'a> {
    /// Layout/BlockEndNewline — checks whether the end statement of a do..end
    /// block or closing `}` of a { } block is on its own line (for multiline blocks).
    pub(crate) fn check_block_end_newline(&mut self, node: &ruby_prism::BlockNode) {
        let last_child_end = self.find_block_last_child_end_offset(node);
        self.check_block_end_newline_core(node.opening_loc(), node.closing_loc(), last_child_end, node.body());
    }

    // `-> { ... }` is a whitequark :block (upstream's on_block fires) but a
    // distinct LambdaNode in prism — same geometry, same check.
    pub(crate) fn check_block_end_newline_lambda(&mut self, node: &ruby_prism::LambdaNode) {
        let last_child_end = if let Some(body) = node.body() {
            match body.as_statements_node().and_then(|st| st.body().iter().last()) {
                Some(last_stmt) => last_stmt.location().end_offset(),
                None => body.location().end_offset(),
            }
        } else if let Some(params) = node.parameters() {
            params.location().end_offset()
        } else {
            node.opening_loc().end_offset()
        };
        self.check_block_end_newline_core(node.opening_loc(), node.closing_loc(), last_child_end, node.body());
    }

    fn check_block_end_newline_core(
        &mut self,
        open_loc: ruby_prism::Location,
        close_loc: ruby_prism::Location,
        offense_start: usize,
        body: Option<ruby_prism::Node>,
    ) {
        const COP: &str = "Layout/BlockEndNewline";
        if !self.on(COP) {
            return;
        }

        let open_line = self.idx.loc(open_loc.start_offset()).0;
        let close_line = self.idx.loc(close_loc.start_offset()).0;

        // Single-line blocks are OK
        if open_line == close_line {
            return;
        }

        // Check if the end/} is on its own line (begins_its_line?)
        let close_off = close_loc.start_offset();
        let (close_line_num, _) = self.idx.loc(close_off);
        let line_start = self.idx.starts[close_line_num - 1];

        // Check if everything from line start to close_off is whitespace
        let begins_line = self.src[line_start..close_off].iter().all(|b| b.is_ascii_whitespace());
        if begins_line {
            return; // end/} is already on its own line
        }

        // The offense range spans THROUGH the `}`/`end` (upstream joins the
        // last child's end with node.loc.end), so the lstripped replacement
        // carries the terminator with it.
        let close_end = close_loc.end_offset();
        let range_source = &self.src[offense_start..close_end];
        let trimmed = String::from_utf8_lossy(range_source).trim_start().to_string();
        if trimmed.starts_with(';') {
            return;
        }

        // Report the offense at the end/} location
        let (offense_line, offense_col) = self.idx.loc(close_off);
        let message = format!("Expression at {}, {} should be on its own line.", offense_line, offense_col);
        self.push(close_off, COP, true, message);

        let replacement = format!("\n{}", trimmed).into_bytes();
        // Check if there's a heredoc in the block body
        let heredoc_end_off = self.find_last_heredoc_offset(body);
        if let Some(heredoc_off) = heredoc_end_off {
            // For heredoc case: remove the offense range and insert after the
            // heredoc terminator (before its newline)
            self.fixes.push((offense_start, close_end, Vec::new()));
            self.fixes.push((heredoc_off, heredoc_off, replacement));
        } else {
            // Normal case: replace with newline + trimmed content
            self.fixes.push((offense_start, close_end, replacement));
        }
    }

    /// Find the end offset of the last child in the block
    /// This includes body statements or parameters, whichever comes last
    fn find_block_last_child_end_offset(&self, node: &ruby_prism::BlockNode) -> usize {
        // Try to find the end offset of the last statement in the body
        if let Some(body) = node.body() {
            if let Some(stmts) = body.as_statements_node() {
                if let Some(last_stmt) = stmts.body().iter().last() {
                    return last_stmt.location().end_offset();
                }
            }
            // Single non-statements node body
            return body.location().end_offset();
        }

        // No body - try parameters
        if let Some(params) = node.parameters() {
            return params.location().end_offset();
        }

        // Fallback to the opening bracket
        node.opening_loc().end_offset()
    }

    /// Find the end offset of the last heredoc argument in the block body
    /// Returns the offset right after the heredoc closing delimiter and its trailing newline
    fn find_last_heredoc_offset(&self, body: Option<ruby_prism::Node>) -> Option<usize> {
        let Some(body_node) = body else { return None };

        // If body is a StatementsNode, extract the last statement
        // Otherwise work with the body itself
        if let Some(stmts) = body_node.as_statements_node() {
            // Get the last statement in the StatementsNode
            if let Some(last_stmt) = stmts.body().iter().last() {
                if let Some(call) = last_stmt.as_call_node() {
                    return self.find_heredoc_in_call_node(&call);
                }
            }
        }

        // Check if the body itself is a call
        if let Some(call) = body_node.as_call_node() {
            return self.find_heredoc_in_call_node(&call);
        }

        None
    }

    /// Helper function to find heredoc in a call node
    fn find_heredoc_in_call_node(&self, call: &ruby_prism::CallNode) -> Option<usize> {
        if let Some(arguments) = call.arguments() {
            // Search arguments in reverse for a heredoc
            let args: Vec<_> = arguments.arguments().iter().collect();
            for arg in args.iter().rev() {
                if let Some(str_node) = arg.as_string_node() {
                    if let Some(opening) = str_node.opening_loc() {
                        let opening_bytes = opening.as_slice();
                        // Check if it's a heredoc (starts with <<)
                        if opening_bytes.len() >= 2 && &opening_bytes[0..2] == b"<<" {
                            if let Some(closing) = str_node.closing_loc() {
                                // Position right after the terminator text
                                // ("EOS") — prism's closing loc includes the
                                // trailing newline; upstream's heredoc_end
                                // token does not, so back over it.
                                let mut off = closing.end_offset();
                                while off > closing.start_offset()
                                    && (self.src[off - 1] == b'\n' || self.src[off - 1] == b'\r')
                                {
                                    off -= 1;
                                }
                                return Some(off);
                            }
                        }
                    }
                } else if let Some(interp_str) = arg.as_interpolated_string_node() {
                    if let Some(opening) = interp_str.opening_loc() {
                        let opening_bytes = opening.as_slice();
                        if opening_bytes.len() >= 2 && &opening_bytes[0..2] == b"<<" {
                            if let Some(closing) = interp_str.closing_loc() {
                                // Position right after the terminator text —
                                // see the StringNode branch above.
                                let mut off = closing.end_offset();
                                while off > closing.start_offset()
                                    && (self.src[off - 1] == b'\n' || self.src[off - 1] == b'\r')
                                {
                                    off -= 1;
                                }
                                return Some(off);
                            }
                        }
                    }
                }
            }
        }

        // Recursively check the receiver (for chained calls like foo(...).bar(...))
        if let Some(receiver) = call.receiver() {
            if let Some(recv_call) = receiver.as_call_node() {
                return self.find_heredoc_in_call_node(&recv_call);
            }
        }

        None
    }
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLinesAroundAttributeAccessor — ported from rubocop's cop
    /// of the same name (`on_send` + a handful of private helpers).
    ///
    /// Upstream needs `node.right_sibling` plus a `return if
    /// node.parent.if_type?` guard, because whitequark leaves a SOLE
    /// statement inside an `if`/`unless` branch un-wrapped (its `parent` is
    /// the `if` node itself, whose OTHER child — the other branch — would
    /// otherwise leak in as a false "sibling"). Prism never does that: every
    /// branch (then/else/elsif), every `def`/`class`/`module`/block body, and
    /// the top-level program each get their OWN `StatementsNode`, so "the
    /// next element in the immediately-enclosing statement list" is already
    /// exactly upstream's guarded `next_line_node` — no parent/if-type check
    /// needed. That's why this runs entirely inside `visit_statements_node`
    /// instead of a generic per-node parent/sibling walk.
    pub(crate) fn check_empty_lines_around_attribute_accessor(&mut self, stmts: &ruby_prism::StatementsNode<'_>) {
        const COP: &str = "Layout/EmptyLinesAroundAttributeAccessor";
        if !self.on(COP) {
            return;
        }
        let body: Vec<_> = stmts.body().iter().collect();
        for i in 0..body.len() {
            let Some(call) = body[i].as_call_node() else { continue };
            if !Self::el_attr_is_accessor_call(&call) {
                continue;
            }
            let loc = call.location();
            let last_line = self.idx.loc(loc.end_offset().saturating_sub(1)).0;
            if self.el_attr_next_lines_ok(last_line) {
                continue;
            }
            if !self.el_attr_requires_empty_line(COP, body.get(i + 1)) {
                continue;
            }
            self.push(loc.start_offset(), COP, true, "Add an empty line after attribute accessor.");
            // `autocorrect`: normally insert right after the accessor's own
            // last line; but if THAT line's follower is a `# rubocop:enable`
            // directive comment, the corrector swaps in the comment's own
            // range instead — the blank line lands after the directive, not
            // between the accessor and it.
            let pos = self
                .el_attr_comment_at(last_line + 1)
                .filter(|_| self.el_attr_enable_directive_at(last_line + 1))
                .map(|(_, e)| e)
                .unwrap_or_else(|| self.line_end(last_line));
            self.fixes.push((pos, pos, b"\n".to_vec()));
        }
    }

    /// `SendNode#attribute_accessor?`: an implicit-receiver call to
    /// `attr_reader`/`attr_writer`/`attr_accessor`/`attr` with at least one
    /// argument (a bare `attr_accessor` with no args does NOT match — prism
    /// only builds an `ArgumentsNode` when there's ≥1 argument).
    fn el_attr_is_accessor_call(call: &ruby_prism::CallNode<'_>) -> bool {
        call.receiver().is_none()
            && matches!(call.name().as_slice(), b"attr_reader" | b"attr_writer" | b"attr_accessor" | b"attr")
            && call.arguments().is_some()
    }

    /// `next_line_empty_or_enable_directive_comment?`: the line right after
    /// `last_line` is blank (or past EOF), OR it's a `# rubocop:enable ...`
    /// directive AND the line after THAT is blank (or past EOF).
    fn el_attr_next_lines_ok(&self, last_line: usize) -> bool {
        if self.el_attr_line_blank(last_line + 1) {
            return true;
        }
        self.el_attr_enable_directive_at(last_line + 1) && self.el_attr_line_blank(last_line + 2)
    }

    /// `next_line_empty?`: `processed_source[line]` is `nil` (past EOF) or
    /// blank (empty / all whitespace) — NOT the same as the stricter
    /// zero-length check other `EmptyLinesAround*` cops use here, since
    /// upstream calls Ruby's `String#blank?` (whitespace-only counts).
    fn el_attr_line_blank(&self, line: usize) -> bool {
        match self.idx.starts.get(line - 1) {
            None => true,
            Some(&s) => self.src[s..self.line_end(line)].iter().all(|b| b.is_ascii_whitespace()),
        }
    }

    /// The comment (start, end) whose own line is `line`, if any.
    fn el_attr_comment_at(&self, line: usize) -> Option<(usize, usize)> {
        self.comments.iter().find(|(l, _, _)| *l == line).map(|&(_, s, e)| (s, e))
    }

    /// `next_line_enable_directive_comment?` — `DirectiveComment#enabled?`:
    /// specifically the `enable` verb (not `disable`/`todo`).
    fn el_attr_enable_directive_at(&self, line: usize) -> bool {
        let Some((s, e)) = self.el_attr_comment_at(line) else { return false };
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| regex::Regex::new(r"^#\s*rubocop\s*:\s*(disable|todo|enable)\s+\S").unwrap());
        let t = String::from_utf8_lossy(&self.src[s..e]);
        re.captures(&t).is_some_and(|c| &c[1] == "enable")
    }

    /// `require_empty_line?`: no next statement → false. `alias foo bar` /
    /// `alias $a $b` → allowed (thus no empty line required) when
    /// `AllowAliasSyntax` (default true). Otherwise: required UNLESS the next
    /// statement is itself a send whose `AllowedMethods` (default
    /// `alias_method`, `public`, `protected`, `private`) covers it, or is
    /// itself another attribute accessor.
    fn el_attr_requires_empty_line(&self, cop: &str, next: Option<&ruby_prism::Node<'_>>) -> bool {
        let Some(next) = next else { return false };
        let is_alias = next.as_alias_method_node().is_some() || next.as_alias_global_variable_node().is_some();
        if is_alias {
            return self.cfg.get(cop, "AllowAliasSyntax") == Some("false");
        }
        let Some(call) = next.as_call_node() else { return true };
        !(Self::el_attr_is_accessor_call(&call) || self.allowed(cop, call.name().as_slice()))
    }
}

impl<'a> Cops<'a> {
    /// Layout/SpaceInLambdaLiteral — checks for spaces between `->` and `(`
    /// in lambda literals. EnforcedStyle: require_no_space (default) or require_space.
    pub(crate) fn check_space_in_lambda_literal(&mut self, node: &ruby_prism::LambdaNode) {
        const COP: &str = "Layout/SpaceInLambdaLiteral";
        if !self.on(COP) {
            return;
        }

        // Upstream's `arrow_lambda_with_args?`: ANY lambda with arguments,
        // parenthesized or not (`-> x do` counts; `->() {}` has an empty
        // args list and does not).
        let Some(params) = node.parameters() else { return };
        let Some(bp) = params.as_block_parameters_node() else { return };
        if bp.parameters().is_none() {
            return;
        }

        let arrow_end = node.operator_loc().end_offset();
        // whitequark's `parent.children[1]` range: the args node, whose span
        // includes the parens when present — prism's BlockParametersNode.
        let args_start = bp.location().start_offset();
        // `arrow.end.join(parentheses.begin)` — emptiness, not space content.
        let has_space = args_start > arrow_end;

        let style = self.cfg.enforced_style(COP);
        if style == "require_space" && !has_space {
            let msg = "Use a space between `->` and `(` in lambda literals.";
            self.push(node.location().start_offset(), COP, true, msg);
            self.fixes.push((args_start, args_start, b" ".to_vec()));
        } else if style == "require_no_space" && has_space {
            let msg = "Do not use spaces between `->` and `(` in lambda literals.";
            self.push(arrow_end, COP, true, msg);
            self.fixes.push((arrow_end, args_start, Vec::new()));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Layout/SpaceAroundEqualsInParameterDefault — Checks that the equals signs
    /// in parameter default assignments have or don't have surrounding space
    /// depending on configuration (EnforcedStyle: space or no_space).
    pub(crate) fn check_space_around_equals_in_parameter_default(&mut self, node: &ruby_prism::OptionalParameterNode) {
        const COP: &str = "Layout/SpaceAroundEqualsInParameterDefault";
        if !self.on(COP) {
            return;
        }

        let style = self.cfg.enforced_style(COP);
        let node_loc = node.location();
        let start = node_loc.start_offset();
        let end = node_loc.end_offset();

        // Find the equals sign within the node's source
        let equals_pos = self.src[start..end]
            .iter()
            .position(|&b| b == b'=')
            .map(|p| start + p);

        let Some(eq_pos) = equals_pos else {
            return;
        };

        // Check spacing before the equals sign (space after the parameter name)
        let space_before = eq_pos > 0 && self.src[eq_pos - 1].is_ascii_whitespace();

        // Check spacing after the equals sign
        let space_after = eq_pos + 1 < self.src.len() && self.src[eq_pos + 1].is_ascii_whitespace();

        let is_correct = match style {
            "space" => space_before && space_after,
            "no_space" => !space_before && !space_after,
            _ => return,
        };

        if is_correct {
            return;
        }

        // Calculate param_end: position right after the parameter name
        let mut param_end = eq_pos - 1;
        while param_end > start && self.src[param_end].is_ascii_whitespace() {
            param_end -= 1;
        }
        param_end += 1; // Move to after the last non-whitespace char

        // Find the range: from end of the parameter name to start of the value
        let mut value_start = eq_pos + 1;
        while value_start < end && self.src[value_start].is_ascii_whitespace() {
            value_start += 1;
        }

        // Report offense at the start of the range (param_end)
        let msg = if style == "space" {
            "Surrounding space missing in default value assignment.".to_string()
        } else {
            "Surrounding space detected in default value assignment.".to_string()
        };

        self.push(param_end, COP, true, msg);

        // Create the fix: replace the range from end of parameter name to start of value
        let replacement = if style == "space" {
            b" = ".to_vec()
        } else {
            b"=".to_vec()
        };

        self.fixes.push((param_end, value_start, replacement));
    }
}

impl<'a> Cops<'a> {
    /// Layout/EndOfLine — checks for Windows-style (CR+LF) vs Unix-style (LF)
    /// line endings. Three styles supported: native (platform-dependent),
    /// lf (Unix), crlf (Windows). Hooks from text-level check, scans all lines
    /// before __END__ and reports only the first offense.
    pub(crate) fn check_end_of_line(&mut self) {
        const COP: &str = "Layout/EndOfLine";
        if !self.on(COP) {
            return;
        }
        if self.src.is_empty() {
            return;
        }

        let configured_style = self.cfg.enforced_style(COP); // native / lf / crlf
        // native = platform line ending; this build never targets Windows.
        let effective_style = if configured_style == "native" { "lf" } else { configured_style };

        // Upstream gates on `last_line = processed_source.tokens.last.line`:
        // trailing blank lines and __END__ data carry no tokens and are never
        // checked. Comments ARE tokens, so "last line with any non-whitespace
        // content before __END__" is the same boundary.
        let mut last_line = 0usize;
        for (i, &start) in self.idx.starts.iter().enumerate() {
            let line_no = i + 1;
            if self.data_line.is_some_and(|d| line_no >= d) {
                break;
            }
            let end = self.idx.starts.get(i + 1).copied().unwrap_or(self.src.len());
            if self.src[start..end].iter().any(|b| !b.is_ascii_whitespace()) {
                last_line = line_no;
            }
        }

        for i in 0..last_line {
            // The line INCLUDING its terminator, like String#each_line.
            let start = self.idx.starts[i];
            let end = self.idx.starts.get(i + 1).copied().unwrap_or(self.src.len());
            let line = &self.src[start..end];

            let offense = match effective_style {
                // `line.end_with?("\r", "\r\n")`
                "lf" => {
                    if line.ends_with(b"\r\n") || line.ends_with(b"\r") {
                        Some("Carriage return character detected.")
                    } else {
                        None
                    }
                }
                _ => {
                    // crlf: MSG_MISSING unless the line ends \r\n; but if the
                    // LAST checked line has no LF at all, a missing CR there
                    // is unimportant (`unimportant_missing_cr?`).
                    if line.ends_with(b"\r\n") {
                        None
                    } else if i + 1 == last_line && !line.ends_with(b"\n") {
                        None
                    } else {
                        Some("Carriage return character missing.")
                    }
                }
            };

            if let Some(msg) = offense {
                // Not autocorrectable upstream (Base without AutoCorrector).
                self.push(start, COP, false, msg);
                // Usually all or none of a file's lines share their ending;
                // upstream reports only the first offense.
                break;
            }
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLinesAroundExceptionHandlingKeywords — ported from
    /// rubocop's cop of the same name, which (unlike the `EmptyLinesAround*`
    /// family above) does NOT check the body's own beginning/end — it walks
    /// the `rescue`/`else`/`ensure` KEYWORDS inside a `def`/block/`begin`
    /// body and flags a blank line immediately above or below each one.
    ///
    /// rubocop's `keyword_locations` (via `keyword_locations_in_rescue` /
    /// `keyword_locations_in_ensure`) recurses through whitequork's nested
    /// `:ensure`/`:rescue` node shapes, but prism collapses all three
    /// clauses onto ONE `BeginNode` (`rescue_clause`/`else_clause`/
    /// `ensure_clause` fields) — so the same flat set of keywords is
    /// obtained directly: the `ensure` keyword (if any), then the `else`
    /// keyword (if any — only legal alongside `rescue`), then each `rescue`
    /// keyword in source order via `RescueNode#subsequent`. This mirrors the
    /// nesting order rubocop actually produces (`keyword_locations_in_ensure`
    /// prepends its own keyword to its nested rescue-body's
    /// `[else, *rescue_keywords]`), which matters only for which message
    /// wins when `add_offense`'s location-dedup collapses two adjacent
    /// checks onto the same blank line (see below).
    fn el_ex_keyword_locations(begin: &ruby_prism::BeginNode) -> Vec<(usize, &'static str)> {
        let mut locs = Vec::new();
        if let Some(ens) = begin.ensure_clause() {
            locs.push((ens.ensure_keyword_loc().start_offset(), "ensure"));
        }
        if let Some(els) = begin.else_clause() {
            locs.push((els.else_keyword_loc().start_offset(), "else"));
        }
        let mut cur = begin.rescue_clause();
        while let Some(r) = cur {
            locs.push((r.keyword_loc().start_offset(), "rescue"));
            cur = r.subsequent();
        }
        locs
    }

    /// `last_body_and_end_on_same_line?` — an early-exit guard computed ONCE
    /// per `check_body` call (it depends only on the body/enclosing `end`,
    /// not on which keyword is being tested): when the tail of the body
    /// collapses onto the same physical line as the enclosing `end`, every
    /// keyword's before/after check is skipped for this body.
    ///
    /// - With an `ensure` clause present (rubocop's non-`rescue_type?`
    ///   branch — `ensure` is always the outermost wrapper when both
    ///   `ensure` and `rescue` occur): compares the `ensure` body's own last
    ///   content line (or the `ensure` keyword's own line when the `ensure`
    ///   body is empty) against `end_line`.
    /// - Otherwise, with only a `rescue` clause: compares the `else`
    ///   keyword's line (if present) or the LAST `rescue` clause's own
    ///   keyword line against `end_line`.
    fn el_ex_last_body_and_end_on_same_line(&self, begin: &ruby_prism::BeginNode, end_line: usize) -> bool {
        let last_line = if let Some(ens) = begin.ensure_clause() {
            match ens.statements().and_then(|s| s.body().iter().last()) {
                Some(n) => self.idx.loc(n.location().end_offset()).0,
                None => self.idx.loc(ens.ensure_keyword_loc().start_offset()).0,
            }
        } else if let Some(els) = begin.else_clause() {
            self.idx.loc(els.else_keyword_loc().start_offset()).0
        } else {
            let mut cur = begin.rescue_clause();
            let mut line = 0usize;
            while let Some(r) = cur {
                line = self.idx.loc(r.keyword_loc().start_offset()).0;
                cur = r.subsequent();
            }
            line
        };
        last_line == end_line
    }

    /// `check_body` — shared by the `def`/block ("implicit" `body` — a plain
    /// `BeginNode` prism synthesizes around a rescue/ensure/else-bearing body,
    /// spanning through the def's/block's own closing keyword, per the
    /// prism-vs-whitequark trap) and explicit `begin`/`end` (kwbegin) call
    /// sites: `body` is the node to inspect (`None`/non-`BeginNode` bodies
    /// have no keywords to check — mirrors rubocop's `case node.type` falling
    /// through to `[]` for anything but `:rescue`/`:ensure`), `owner_line` is
    /// the `def`/block-selector/`begin` keyword's own line, and `end_line` is
    /// the enclosing `end` (or block closer)'s own line.
    pub(crate) fn check_empty_lines_around_exception_handling_keywords(
        &mut self,
        body: Option<ruby_prism::Node>,
        owner_line: usize,
        end_line: usize,
    ) {
        const COP: &str = "Layout/EmptyLinesAroundExceptionHandlingKeywords";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body else { return };
        let Some(begin) = body.as_begin_node() else { return };
        let locs = Self::el_ex_keyword_locations(&begin);
        if locs.is_empty() {
            return;
        }
        if self.el_ex_last_body_and_end_on_same_line(&begin, end_line) {
            return;
        }

        for (off, keyword) in locs {
            let line = self.idx.loc(off).0;
            if line == owner_line {
                continue;
            }
            // below the keyword
            if self.el_is_blank_line(line + 1) {
                let boff = self.idx.starts[line];
                if self.el_offended.insert((COP, boff)) {
                    self.push(boff, COP, true, format!("Extra empty line detected after the `{keyword}`."));
                    self.fixes.push((boff, boff + 1, Vec::new()));
                }
            }
            // above the keyword
            if line >= 2 && self.el_is_blank_line(line - 1) {
                let boff = self.idx.starts[line - 2];
                if self.el_offended.insert((COP, boff)) {
                    self.push(boff, COP, true, format!("Extra empty line detected before the `{keyword}`."));
                    self.fixes.push((boff, boff + 1, Vec::new()));
                }
            }
        }
    }

    /// `on_def`/`on_defs` (prism unifies both under `DefNode`): `owner_line`
    /// is the def's own first line (the `def` keyword always starts the
    /// node); `end_line` is `None` for an endless `def` — which has no
    /// `end_keyword_loc` and whose body can never be a rescue/ensure-bearing
    /// `BeginNode` anyway (a `rescue` modifier there parses as a distinct
    /// `RescueModifierNode`, not a clause on the method body), so skipping is
    /// safe.
    pub(crate) fn check_empty_lines_around_exception_handling_keywords_def(&mut self, node: &ruby_prism::DefNode) {
        let Some(end_loc) = node.end_keyword_loc() else { return };
        let owner_line = self.idx.loc(node.location().start_offset()).0;
        let end_line = self.idx.loc(end_loc.start_offset()).0;
        self.check_empty_lines_around_exception_handling_keywords(node.body(), owner_line, end_line);
    }

    /// `on_block`/`on_numblock` (prism has no separate numbered-block node
    /// type — both alias to the same `BlockNode`): `owner_line` anchors on
    /// the enclosing call's own SELECTOR (`message_loc`), not the receiver
    /// chain, per the prism-vs-whitequark block-range trap — matching
    /// whitequork's block node, whose own `loc.line` starts at the `send`
    /// node it wraps. Only reached from `visit_call_node`'s block handling
    /// (mirroring this port's `Layout/EmptyLinesAroundBlockBody`, which is
    /// likewise never invoked for a block attached to `super`/`zsuper`).
    pub(crate) fn check_empty_lines_around_exception_handling_keywords_block(
        &mut self,
        call: &ruby_prism::CallNode,
        block: &ruby_prism::BlockNode,
    ) {
        let owner_off = call.message_loc().map(|l| l.start_offset()).unwrap_or_else(|| call.location().start_offset());
        let owner_line = self.idx.loc(owner_off).0;
        let end_line = self.idx.loc(block.closing_loc().start_offset()).0;
        self.check_empty_lines_around_exception_handling_keywords(block.body(), owner_line, end_line);
    }

    /// `on_kwbegin`: only explicit `begin`/`end` blocks reach here — the
    /// implicit `BeginNode` prism synthesizes around a `def`/block's own
    /// rescue/ensure body has no `begin_keyword_loc` and is handled by the
    /// `_def`/`_block` entry points above instead (matching rubocop's
    /// `on_kwbegin`, which never fires for that implicit shape either).
    /// Unlike those two, the node inspected for keywords IS the visited node
    /// itself, not a separate `body` field — prism's `BeginNode` holds its
    /// own `rescue_clause`/`else_clause`/`ensure_clause` directly, where
    /// whitequork nests a distinct child node under the `kwbegin` wrapper.
    pub(crate) fn check_empty_lines_around_exception_handling_keywords_kwbegin(
        &mut self,
        node: &ruby_prism::BeginNode,
    ) {
        let Some(begin_loc) = node.begin_keyword_loc() else { return };
        let Some(end_loc) = node.end_keyword_loc() else { return };
        let owner_line = self.idx.loc(begin_loc.start_offset()).0;
        let end_line = self.idx.loc(end_loc.start_offset()).0;
        self.check_empty_lines_around_exception_handling_keywords(Some(node.as_node()), owner_line, end_line);
    }
}

/// Layout/SpaceBeforeFirstArg (+ the `PrecedingFollowingAlignment` mixin's
/// `aligned_with_something?` path — the only path this cop reaches).
impl<'a> Cops<'a> {
    /// `RuboCop::AST::Node::OPERATOR_METHODS` — used by `operator_method?` to
    /// exempt calls like `foo + bar`/`foo[bar]` (their "first argument" is
    /// really an operand, not something this cop should space-check).
    const SBFA_OPERATOR_METHODS: &'static [&'static [u8]] = &[
        b"|", b"^", b"&", b"<=>", b"==", b"===", b"=~", b">", b">=", b"<", b"<=", b"<<", b">>",
        b"+", b"-", b"*", b"/", b"%", b"**", b"~", b"+@", b"-@", b"!@", b"~@", b"[]", b"[]=",
        b"!", b"!=", b"!~", b"`",
    ];

    /// `on_send`/`on_csend` (prism visits both through one `CallNode`):
    /// checks that exactly one space separates a method name from its first
    /// argument in a parenthesis-less call.
    pub(crate) fn check_space_before_first_arg(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/SpaceBeforeFirstArg";
        if !self.on(COP) {
            return;
        }
        // `regular_method_call_with_arguments?`: has args, and is neither an
        // operator method (`foo + bar`, `foo[bar]`) nor a setter (`foo.x = y`
        // — prism's `equal_loc` is the setter_method?/`loc?(:operator)` signal).
        let name = node.name().as_slice();
        let Some(args) = node.arguments() else { return };
        if args.arguments().iter().next().is_none() {
            return;
        }
        if Self::SBFA_OPERATOR_METHODS.contains(&name) || node.equal_loc().is_some() {
            return;
        }
        // `node.parenthesized?`
        if node.opening_loc().is_some() {
            return;
        }
        let first_arg = args.arguments().iter().next().unwrap();
        let arg_start = first_arg.location().start_offset();

        // `range_with_surrounding_space(first_arg, side: :left)` with the
        // (default) `newlines: true, continuations: false, whitespace: false`
        // options: eat a run of spaces/tabs, THEN a run of newlines.
        let mut space_start = arg_start;
        while space_start > 0 && matches!(self.src[space_start - 1], b' ' | b'\t') {
            space_start -= 1;
        }
        while space_start > 0 && self.src[space_start - 1] == b'\n' {
            space_start -= 1;
        }
        if arg_start - space_start == 1 {
            return;
        }
        if !self.sbfa_expect_params_after_method_name(node, &first_arg, arg_start) {
            return;
        }
        self.push(space_start, COP, true, "Put one space between the method name and the first argument.");
        self.fixes.push((space_start, arg_start, b" ".to_vec()));
    }

    /// `expect_params_after_method_name?`.
    fn sbfa_expect_params_after_method_name(
        &self,
        node: &ruby_prism::CallNode,
        first_arg: &ruby_prism::Node,
        arg_start: usize,
    ) -> bool {
        // `no_space_between_method_name_and_first_argument?`
        if let Some(sel) = node.message_loc() {
            if sel.end_offset() == arg_start {
                return true;
            }
        }
        // `same_line?(first_arg, node)` — a send node's own line is where its
        // FULL expression starts (receiver chain included, per prism's
        // translation — unlike block nodes, a `CallNode`'s location starts at
        // the receiver, not the selector).
        let node_line = self.idx.loc(node.location().start_offset()).0;
        let arg_line = self.idx.loc(arg_start).0;
        if node_line != arg_line {
            return false;
        }
        let allow_for_alignment = self.cfg.get("Layout/SpaceBeforeFirstArg", "AllowForAlignment") != Some("false");
        !(allow_for_alignment && self.sbfa_aligned_with_something(first_arg))
    }

    /// `PrecedingFollowingAlignment#aligned_with_something?` ->
    /// `aligned_with_adjacent_line?(range, method(:aligned_token?))`.
    fn sbfa_aligned_with_something(&self, node: &ruby_prism::Node) -> bool {
        let loc = node.location();
        let begin = loc.start_offset();
        let end = loc.end_offset();
        let range_line = self.idx.loc(begin).0; // 1-based
        let range_col = begin - self.idx.starts[range_line - 1]; // 0-based byte column
        let range_src = &self.src[begin..end];
        let total_lines = self.idx.starts.len();

        // pre = (range.line - 2).downto(0); post = range.line.upto(lines.size - 1)
        // (both are 0-based line indices; `range.line` is 1-based, so `post`
        // starting AT `range_line` really means "one past the range's own
        // 0-based index", i.e. the next line).
        let pre: Vec<usize> = if range_line >= 2 { (0..=range_line - 2).rev().collect() } else { Vec::new() };
        let post: Vec<usize> = if range_line < total_lines { (range_line..total_lines).collect() } else { Vec::new() };

        // Both passes are `line_ranges.any?` in upstream: each range commits
        // to its own first candidate line's verdict, but a false verdict from
        // `pre` does NOT short-circuit — `post` still gets its own check.
        // First pass: any non-blank, non-standalone-comment adjacent line.
        for lines in [&pre, &post] {
            if self.sbfa_first_candidate(lines, range_col, range_src, None) == Some(true) {
                return true;
            }
        }
        // Second pass: same indentation as the range's own line.
        let cur_line = self.sbfa_line_bytes(range_line);
        let base_indent = Self::sbfa_first_nonspace(cur_line);
        for lines in [&pre, &post] {
            if self.sbfa_first_candidate(lines, range_col, range_src, base_indent) == Some(true) {
                return true;
            }
        }
        false
    }

    /// `aligned_with_line?`: scans `lines` (0-based) for the first one that
    /// is non-blank, isn't a standalone comment line, and (when `indent` is
    /// given) has that exact indentation — then commits to that single
    /// line's `aligned_token?` verdict. `None` means no such line exists.
    fn sbfa_first_candidate(
        &self,
        lines: &[usize],
        range_col: usize,
        range_src: &[u8],
        indent: Option<usize>,
    ) -> Option<bool> {
        for &lineno0 in lines {
            let line1 = lineno0 + 1;
            if self.sbfa_standalone_comment_line(line1) {
                continue;
            }
            let text = self.sbfa_line_bytes(line1);
            let Some(idx0) = Self::sbfa_first_nonspace(text) else { continue };
            if let Some(want) = indent {
                if want != idx0 {
                    continue;
                }
            }
            return Some(Self::sbfa_aligned_token(range_col, range_src, text));
        }
        None
    }

    /// `aligned_token?` = `aligned_words?` (a word starts at the same column
    /// on the adjacent line, or an identical token sits there) OR
    /// `aligned_equals_operator?`.
    fn sbfa_aligned_token(range_col: usize, range_src: &[u8], line: &[u8]) -> bool {
        if Self::sbfa_aligned_words(range_col, range_src, line) {
            return true;
        }
        Self::sbfa_aligned_equals_operator(range_col, range_src, line)
    }

    fn sbfa_aligned_words(range_col: usize, range_src: &[u8], line: &[u8]) -> bool {
        if range_col >= 1 {
            if let (Some(&a), Some(&b)) = (line.get(range_col - 1), line.get(range_col)) {
                if Self::sbfa_rb_space(a) && !Self::sbfa_rb_space(b) {
                    return true;
                }
            }
        }
        let end = range_col + range_src.len();
        end <= line.len() && &line[range_col..end] == range_src
    }

    /// `aligned_equals_operator?` -> `aligned_with_preceding_equals?` /
    /// `aligned_with_append_operator?`. Both of those only ever fire when the
    /// checked RANGE's own source ends with `=` or equals `<<` verbatim —
    /// for this cop the range is always an argument's source, which is
    /// syntactically never either of those in real code (an argument can't
    /// itself be a bare trailing `=`), so this is a fast, exact `false` in
    /// every case this cop can actually reach. The rare, unreachable-in-
    /// practice branch is still ported (a best-effort scan for the first
    /// assignment/comparison-ish token on the line, skipping quoted
    /// strings/comments) so the code path is complete rather than silently
    /// dropped.
    fn sbfa_aligned_equals_operator(range_col: usize, range_src: &[u8], line: &[u8]) -> bool {
        let ends_with_eq = range_src.last() == Some(&b'=');
        let is_lshift = range_src == b"<<";
        if !ends_with_eq && !is_lshift {
            return false;
        }
        let Some((tok_is_lshift, tok_is_equal_sign, tok_end_col)) = Self::sbfa_first_alignment_token(line) else {
            return false;
        };
        let range_last_col = range_col + range_src.len();
        if range_last_col != tok_end_col {
            return false;
        }
        (is_lshift && tok_is_equal_sign) || (ends_with_eq && (tok_is_lshift || tok_is_equal_sign))
    }

    /// Best-effort `tokens_within(line_range).detect { ASSIGNMENT_OR_COMPARISON_TOKENS }`:
    /// the first `=`, `==`, `===`, `!=`, `<=`, `>=`, compound-assignment
    /// (`tOP_ASGN`), or `<<` on the line, skipping over quoted-string and
    /// comment contents so operators inside strings aren't mistaken for real
    /// tokens. Returns (is_lshift, is_equal_sign, end_col).
    fn sbfa_first_alignment_token(line: &[u8]) -> Option<(bool, bool, usize)> {
        const TOKENS: &[(&[u8], bool, bool)] = &[
            (b"**=", false, true),
            (b"<<=", false, true),
            (b">>=", false, true),
            (b"&&=", false, true),
            (b"||=", false, true),
            (b"===", false, false),
            (b"==", false, false),
            (b"!=", false, false),
            (b"<=", false, false),
            (b">=", false, false),
            (b"<<", true, false),
            (b"+=", false, true),
            (b"-=", false, true),
            (b"*=", false, true),
            (b"/=", false, true),
            (b"%=", false, true),
            (b"&=", false, true),
            (b"|=", false, true),
            (b"^=", false, true),
        ];
        let n = line.len();
        let mut i = 0usize;
        while i < n {
            match line[i] {
                b'#' => break,
                b'\'' => {
                    i = Self::sbfa_skip_quoted(line, i, b'\'');
                    continue;
                }
                b'"' => {
                    i = Self::sbfa_skip_quoted(line, i, b'"');
                    continue;
                }
                _ => {}
            }
            if let Some(&(tok, is_lshift, is_eq)) = TOKENS.iter().find(|(tok, ..)| line[i..].starts_with(tok)) {
                return Some((is_lshift, is_eq, i + tok.len()));
            }
            if line[i] == b'=' {
                // bare `=` (tEQL) — but not `=>` (hash rocket) or `=~` (match op).
                let next = line.get(i + 1).copied();
                if next != Some(b'>') && next != Some(b'~') {
                    return Some((false, true, i + 1));
                }
            }
            i += 1;
        }
        None
    }

    fn sbfa_skip_quoted(line: &[u8], start: usize, quote: u8) -> usize {
        let n = line.len();
        let mut i = start + 1;
        while i < n {
            if line[i] == b'\\' && i + 1 < n {
                i += 2;
                continue;
            }
            if line[i] == quote {
                return i + 1;
            }
            i += 1;
        }
        n
    }

    fn sbfa_rb_space(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
    }

    fn sbfa_first_nonspace(bytes: &[u8]) -> Option<usize> {
        bytes.iter().position(|b| !Self::sbfa_rb_space(*b))
    }

    /// `processed_source.lines[line - 1]` — 1-based `line`'s text, excluding
    /// its trailing newline (or an empty slice past EOF).
    fn sbfa_line_bytes(&self, line: usize) -> &[u8] {
        match self.idx.starts.get(line - 1) {
            Some(&s) => &self.src[s..self.line_end(line)],
            None => &[],
        }
    }

    /// `aligned_comment_lines`: does a comment begin its own line (only
    /// whitespace precedes it on that physical line)?
    fn sbfa_standalone_comment_line(&self, line: usize) -> bool {
        self.comments.iter().any(|&(l, s, _)| {
            if l != line {
                return false;
            }
            let Some(&line_start) = self.idx.starts.get(line - 1) else { return false };
            self.src[line_start..s].iter().all(|b| b.is_ascii_whitespace())
        })
    }
}

impl<'a> super::Cops<'a> {
    /// Layout/CommentIndentation — ports rubocop's `check`/`correct_indentation`
    /// verbatim. For every OWN-LINE comment (only whitespace precedes the `#`
    /// on its physical line — excludes trailing `code # comment` comments
    /// AND `=begin`/`=end` document comments, whose own first line starts
    /// with `=`, not `#`), the correct indentation is derived from the FIRST
    /// non-blank line strictly after the comment: normally that line's own
    /// indentation, plus one indentation width when the line dedents (`end`,
    /// a closing bracket, or — under `Layout/AccessModifierIndentation:
    /// outdent` — an access modifier). Lines starting `else`/`elsif`/`when`/
    /// `in`/`rescue`/`ensure` get a second look: if the comment matches
    /// keyword+width instead of the keyword's own column, it's accepted too
    /// (but the ORIGINAL, pre-adjustment column_delta is what autocorrect
    /// uses). `AllowForAlignment` (default false) additionally accepts a
    /// comment whose column matches the nearest preceding TRAILING
    /// (non-own-line) comment. Autocorrect chains backward through
    /// adjacent-line comments (any kind) sharing the SAME original column as
    /// the one being fixed, reusing the same delta for the whole run — this
    /// is what lets a block of misaligned continuation comments move
    /// together in one shot instead of one at a time.
    pub(crate) fn check_comment_indentation(&mut self) {
        const COP: &str = "Layout/CommentIndentation";
        if !self.on(COP) {
            return;
        }
        if self.comments.is_empty() {
            return;
        }
        let allow_for_alignment = self.cfg.get(COP, "AllowForAlignment") == Some("true");
        let width = self.ci_indentation_width();

        let cols: Vec<i64> = self.comments.iter().map(|&(_, s, _)| self.ci_column0(s)).collect();
        let own_line: Vec<bool> =
            self.comments.iter().map(|&(l, s, _)| self.ci_own_line(l, s)).collect();

        // Pass 1 (read-only): decide which comments offend, and their
        // message + the ORIGINAL column_delta (rubocop keeps @column_delta
        // from before the two_alternatives adjustment, for autocorrect).
        let mut offending: Vec<(usize, i64, String)> = Vec::new();
        for ix in 0..self.comments.len() {
            if !own_line[ix] {
                continue;
            }
            let (line, _, _) = self.comments[ix];
            let next = self.ci_line_after(line);
            let mut correct = self.ci_correct_indentation(next, width);
            let column = cols[ix];
            let delta = correct - column;
            if delta == 0 {
                continue;
            }
            if let Some(nl) = next {
                if ci_two_alternatives(nl) {
                    correct += width;
                    if column == correct {
                        continue;
                    }
                }
            }
            if allow_for_alignment {
                let mut j = ix;
                let mut aligned = false;
                while j > 0 {
                    j -= 1;
                    if !own_line[j] {
                        aligned = cols[j] == column;
                        break;
                    }
                }
                if aligned {
                    continue;
                }
            }
            let msg = format!("Incorrect indentation detected (column {column} instead of {correct}).");
            offending.push((ix, delta, msg));
        }

        // Pass 2 (mutating): register offenses + autocorrect.
        // `AlignmentCorrector` no-ops entirely under `Layout/IndentationStyle:
        // tabs` (detection still fires — only the fix is suppressed).
        let using_tabs = self.cfg.enforced_style("Layout/IndentationStyle") == "tabs";
        for (ix, delta, msg) in offending {
            let start = self.comments[ix].1;
            self.push(start, COP, true, msg);
            if using_tabs {
                continue;
            }
            self.ci_autocorrect_one(ix, delta);
            let mut below = ix;
            while below > 0 {
                let above = below - 1;
                let (above_line, above_start, _) = self.comments[above];
                let (below_line, _, _) = self.comments[below];
                if above_line != below_line - 1 || self.ci_column0(above_start) != cols[below] {
                    break;
                }
                self.ci_autocorrect_one(above, delta);
                below = above;
            }
        }
    }

    /// `Alignment#configured_indentation_width`: the cop's own
    /// `IndentationWidth` (no schema default — meaningful only when a user
    /// sets it directly on this cop), else `Layout/IndentationWidth`'s
    /// `Width` (schema default 2).
    fn ci_indentation_width(&self) -> i64 {
        self.cfg
            .get("Layout/CommentIndentation", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()).unwrap_or(2)
            })
    }

    /// `comment.loc.column`: 0-based CHARACTER column (not `Alignment`'s
    /// display-width column — this cop compares raw `loc.column` values).
    fn ci_column0(&self, off: usize) -> i64 {
        let (line, mut col) = self.idx.loc(off);
        let prefix = &self.src[self.idx.starts[line - 1]..off];
        if !prefix.is_ascii() {
            col = String::from_utf8_lossy(prefix).chars().count() + 1;
        }
        (col - 1) as i64
    }

    /// `own_line_comment?`: the physical line the comment starts on matches
    /// `/\A\s*#/`. True for a whole-line `#...` comment; false for a
    /// trailing `code # comment`, and false for a `=begin`/`=end` document
    /// comment even though nothing but whitespace precedes its start offset
    /// (its first physical line is `=begin`, which doesn't start with `#`).
    fn ci_own_line(&self, line: usize, start: usize) -> bool {
        if self.src.get(start) != Some(&b'#') {
            return false;
        }
        let line_start = self.idx.starts[line - 1];
        self.src[line_start..start].iter().all(|b| b.is_ascii_whitespace())
    }

    /// `processed_source.lines[line - 1]`, excluding the trailing newline.
    fn ci_line_bytes(&self, line: usize) -> &'a [u8] {
        &self.src[self.idx.starts[line - 1]..self.line_end(line)]
    }

    /// `line_after_comment`: the first non-blank physical line strictly
    /// after `comment_line`, or `None` at EOF.
    fn ci_line_after(&self, comment_line: usize) -> Option<&'a [u8]> {
        let total = self.idx.starts.len();
        ((comment_line + 1)..=total)
            .map(|l| self.ci_line_bytes(l))
            .find(|bytes| !bytes.iter().all(|b| b.is_ascii_whitespace()))
    }

    /// `correct_indentation`: 0 with no next line; else the next line's own
    /// indentation, plus one width when it dedents (`less_indented?`).
    fn ci_correct_indentation(&self, next_line: Option<&[u8]>, width: i64) -> i64 {
        let Some(line) = next_line else { return 0 };
        let indent = line.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0) as i64;
        indent + if self.ci_less_indented(line) { width } else { 0 }
    }

    /// `less_indented?`: the next line starts (after its own indentation)
    /// with `end`, a closing bracket, or — under
    /// `Layout/AccessModifierIndentation: outdent` — an access modifier.
    fn ci_less_indented(&self, line: &[u8]) -> bool {
        let indent = line.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(line.len());
        let rest = &line[indent..];
        if ci_word_at(rest, b"end") || matches!(rest.first(), Some(b')' | b'}' | b']')) {
            return true;
        }
        self.cfg.enforced_style("Layout/AccessModifierIndentation") == "outdent"
            && [b"private".as_slice(), b"protected", b"public"].iter().any(|w| ci_word_at(rest, w))
    }

    /// `AlignmentCorrector.correct` specialized to a single-line comment
    /// token: insert `delta` spaces before it (widen), or delete the
    /// `-delta` bytes immediately before it — but ONLY when they're all
    /// spaces/tabs, the same guard rubocop uses to avoid corrupting
    /// non-whitespace content when the assumption doesn't hold.
    fn ci_autocorrect_one(&mut self, ix: usize, delta: i64) {
        let start = self.comments[ix].1;
        if delta > 0 {
            self.fixes.push((start, start, vec![b' '; delta as usize]));
        } else if delta < 0 {
            let n = (-delta) as usize;
            if n <= start && self.src[start - n..start].iter().all(|&b| b == b' ' || b == b'\t') {
                self.fixes.push((start - n, start, Vec::new()));
            }
        }
    }
}

/// `two_alternatives?`: the next line starts (after indentation) with a
/// mid-statement keyword that has a "deeper OR keyword-aligned" comment
/// convention.
fn ci_two_alternatives(line: &[u8]) -> bool {
    let indent = line.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(line.len());
    let rest = &line[indent..];
    [b"else".as_slice(), b"elsif", b"when", b"in", b"rescue", b"ensure"]
        .iter()
        .any(|w| ci_word_at(rest, w))
}

/// `rest` starts with `word`, immediately followed by a non-word byte (or
/// end of line) — a `\b`-terminated literal match.
fn ci_word_at(rest: &[u8], word: &[u8]) -> bool {
    rest.len() >= word.len()
        && &rest[..word.len()] == word
        && rest.get(word.len()).is_none_or(|&c| !(c.is_ascii_alphanumeric() || c == b'_'))
}

// ============================================================================
// Layout/DotPosition
// ============================================================================
impl<'a> Cops<'a> {
    /// Layout/DotPosition — `.`/`&.` position in multi-line method chains
    /// (rubocop's `on_send`/`on_csend`; prism unifies both into one
    /// `CallNode`, `is_safe_navigation`/the raw operator text telling them
    /// apart). `call_operator_loc` can also hold `::`, but rubocop-ast's
    /// `dot?`/`safe_navigation?` only match a literal `.`/`&.` source — `::`
    /// chains are never flagged, mirrored below by comparing the raw bytes.
    pub(crate) fn check_dot_position(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/DotPosition";
        if !self.on(COP) {
            return;
        }
        let Some(dot_loc) = node.call_operator_loc() else { return };
        let op = dot_loc.as_slice();
        if op != b"." && op != b"&." {
            return;
        }
        let Some(receiver) = node.receiver() else { return };

        // `selector_range`: the message location, or — for the implicit
        // `#call` form (`l.(1)`, no method name) — the opening paren.
        let selector_off = node
            .message_loc()
            .or_else(|| node.opening_loc())
            .map(|l| l.start_offset())
            .unwrap_or_else(|| dot_loc.end_offset());

        let dot_off = dot_loc.start_offset();
        let (dot_line, _) = self.idx.loc(dot_off);
        let (selector_line, _) = self.idx.loc(selector_off);
        let receiver_end_off = receiver.location().end_offset();
        let (receiver_end_line_plain, _) = self.idx.loc(receiver_end_off);

        // `same_line?(selector_range, end_range(node.receiver))`.
        if selector_line == receiver_end_line_plain {
            return;
        }

        // `receiver_end_line`: a receiver whose last argument (or the
        // receiver itself) is a heredoc effectively "ends" on the heredoc's
        // closing-delimiter line — prism's own node span, though, ends right
        // after the parens on the physical line the call was written on.
        let receiver_line = dot_position_receiver_end_line(self, &receiver).unwrap_or(receiver_end_line_plain);

        // `line_between?`: a >1 line gap (comment or blank line) is left alone.
        if selector_line as isize - receiver_line.max(dot_line) as isize > 1 {
            return;
        }

        let trailing = self.cfg.get(COP, "EnforcedStyle") == Some("trailing");
        let correct = if trailing { dot_line != selector_line } else { dot_line == selector_line };
        if correct {
            return;
        }

        let op_str = std::str::from_utf8(op).unwrap_or(".");
        let message = if trailing {
            format!("Place the {op_str} on the previous line, together with the method call receiver.")
        } else {
            format!("Place the {op_str} on the next line, together with the method name.")
        };
        self.push(dot_off, COP, true, message);

        // --- autocorrect ---
        // `processed_source[dot.line - 1].strip == '.'` — rubocop compares
        // against the LITERAL string '.', not `dot.source`, so a `&.` alone
        // on its own line does NOT take the whole-line branch. Ported as-is.
        let dot_end_off = dot_loc.end_offset();
        let line_start = self.idx.starts[dot_line - 1];
        let next_line_start = self.idx.starts.get(dot_line).copied().unwrap_or(self.src.len());
        let stripped = std::str::from_utf8(&self.src[line_start..next_line_start]).unwrap_or("").trim();
        if stripped.as_bytes() == b"." {
            self.fixes.push((line_start, next_line_start, Vec::new()));
        } else {
            self.fixes.push((dot_off, dot_end_off, Vec::new()));
        }
        if trailing {
            self.fixes.push((receiver_end_off, receiver_end_off, op.to_vec()));
        } else {
            self.fixes.push((selector_off, selector_off, op.to_vec()));
        }
    }
}

/// `DotPosition#receiver_end_line`: `None` unless the receiver — or, when the
/// receiver is itself a call, one of its arguments — is a heredoc, in which
/// case the line is the heredoc's closing-delimiter line rather than the
/// receiver's own (textually earlier) span end.
fn dot_position_receiver_end_line(cops: &Cops, node: &ruby_prism::Node) -> Option<usize> {
    if let Some(call) = node.as_call_node() {
        return call
            .arguments()
            .and_then(|args| args.arguments().iter().filter_map(|arg| dot_position_heredoc_line(cops, &arg)).max());
    }
    dot_position_heredoc_line(cops, node)
}

/// Line number of a heredoc node's closing delimiter (the `HEREDOC` token
/// line itself — prism's `closing_loc` also spans the trailing newline, but
/// its START is exactly the terminator line rubocop's `heredoc_end.line` names).
fn dot_position_heredoc_line(cops: &Cops, node: &ruby_prism::Node) -> Option<usize> {
    let closing = if let Some(n) = node.as_string_node() {
        if n.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) { n.closing_loc() } else { None }
    } else if let Some(n) = node.as_interpolated_string_node() {
        if n.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) { n.closing_loc() } else { None }
    } else if let Some(n) = node.as_x_string_node() {
        if n.opening_loc().as_slice().starts_with(b"<<") { Some(n.closing_loc()) } else { None }
    } else if let Some(n) = node.as_interpolated_x_string_node() {
        if n.opening_loc().as_slice().starts_with(b"<<") { Some(n.closing_loc()) } else { None }
    } else {
        None
    };
    closing.map(|c| cops.idx.loc(c.start_offset()).0)
}

impl<'a> super::Cops<'a> {
    /// Layout/AccessModifierIndentation — a bare `private`/`protected`/
    /// `public`/`module_function` call (no receiver, no args, no block —
    /// upstream's `bare_access_modifier?`) sitting directly in a
    /// class/module/singleton-class/block body must be indented like the
    /// method defs around it (`EnforcedStyle: indent`, default) or like the
    /// container's own opening keyword (`outdent`).
    ///
    /// Ported from `check_body`/`check_modifier`: only runs when the body has
    /// 2+ direct statements — upstream's `node.body&.begin_type?` guard. A
    /// single-statement body (even a lone bare modifier) is never checked;
    /// prism always wraps 1+ statements in a `StatementsNode` (unlike
    /// whitequark, which leaves a lone statement unwrapped), so the length
    /// check stands in for whitequark's begin/non-begin distinction. Also
    /// skipped: a body whose implicit `rescue`/`ensure` makes prism return a
    /// `BeginNode` instead of a bare `StatementsNode` (`body.as_statements_node()`
    /// fails) — matches upstream, whose translated body there isn't
    /// `begin_type?` either. A modifier on the SAME line as the container's
    /// own start is exempt (`class A; private; def foo; end; end`).
    ///
    /// The offense/correction math (`column_offset_between` +
    /// `AlignmentCorrector::correct`, both specialized to a single-line node
    /// since a bare modifier call is always one token on one line): `offset =
    /// modifier's own 0-based column − the container's closing keyword's
    /// 0-based column`; `delta = expected_offset − offset`, where
    /// `expected_offset` is 0 under `outdent` or the configured indentation
    /// width under `indent`. `delta == 0` needs no offense; otherwise insert
    /// `delta` spaces immediately before the modifier (delta > 0) or delete
    /// the `-delta` bytes immediately before it (delta < 0) — mirroring
    /// `AlignmentCorrector`'s two branches for a node that's the very first
    /// thing on its line.
    fn access_modifier_indentation_body(
        &mut self,
        container_start: usize,
        end_start: usize,
        body: Option<ruby_prism::Node>,
    ) {
        const COP: &str = "Layout/AccessModifierIndentation";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body else { return };
        let Some(stmts) = body.as_statements_node() else { return };
        if stmts.body().len() < 2 {
            return;
        }
        let container_line = self.idx.loc(container_start).0;
        let end_col0 = self.idx.loc(end_start).1 - 1;
        let outdent = self.cfg.enforced_style(COP) == "outdent";
        let width = self.ami_indentation_width();
        let expected: isize = if outdent { 0 } else { width as isize };

        for child in stmts.body().iter() {
            let Some(call) = child.as_call_node() else { continue };
            if call.receiver().is_some() || call.block().is_some() {
                continue;
            }
            if call.arguments().is_some_and(|a| !a.arguments().is_empty()) {
                continue;
            }
            let name = call.name();
            let name = name.as_slice();
            if !matches!(name, b"public" | b"protected" | b"private" | b"module_function") {
                continue;
            }
            let start = call.location().start_offset();
            let (line, col) = self.idx.loc(start);
            if line == container_line {
                continue;
            }
            let offset = col as isize - 1 - end_col0 as isize;
            let delta = expected - offset;
            if delta == 0 {
                continue;
            }
            let style_word = if outdent { "Outdent" } else { "Indent" };
            let name_str = String::from_utf8_lossy(name);
            self.push(start, COP, true, format!("{style_word} access modifiers like `{name_str}`."));
            if delta > 0 {
                self.fixes.push((start, start, vec![b' '; delta as usize]));
            } else {
                let n = (-delta) as usize;
                if n <= start {
                    self.fixes.push((start - n, start, Vec::new()));
                }
            }
        }
    }

    pub(crate) fn check_access_modifier_indentation_class(&mut self, node: &ruby_prism::ClassNode) {
        self.access_modifier_indentation_body(
            node.location().start_offset(),
            node.end_keyword_loc().start_offset(),
            node.body(),
        );
    }

    pub(crate) fn check_access_modifier_indentation_module(&mut self, node: &ruby_prism::ModuleNode) {
        self.access_modifier_indentation_body(
            node.location().start_offset(),
            node.end_keyword_loc().start_offset(),
            node.body(),
        );
    }

    pub(crate) fn check_access_modifier_indentation_sclass(&mut self, node: &ruby_prism::SingletonClassNode) {
        self.access_modifier_indentation_body(
            node.location().start_offset(),
            node.end_keyword_loc().start_offset(),
            node.body(),
        );
    }

    /// For `on_block`, upstream's container-start line is the FULL
    /// underlying call's start (including any receiver chain — verified live
    /// against real RuboCop's prism translation: `Test = Class.new do` and a
    /// multi-line-receiver probe both showed the translated `:block` node's
    /// `.loc` starting at the call's own beginning, not just at `do`). Here
    /// we only have the raw prism `BlockNode`, whose own `.location()` starts
    /// at the block's opening (`do`/`{`) — every fixture example has a
    /// single-line call header before `do`, where the two coincide, so this
    /// is unobservable in-repo; a receiver chain wrapping onto its own line
    /// before a trailing `do` is unrepresented and could disagree with
    /// upstream on the same-line exemption.
    pub(crate) fn check_access_modifier_indentation_block(&mut self, node: &ruby_prism::BlockNode) {
        self.access_modifier_indentation_body(
            node.location().start_offset(),
            node.closing_loc().start_offset(),
            node.body(),
        );
    }

    /// `Alignment#configured_indentation_width`: cop-local `IndentationWidth`
    /// (no schema default for this cop — meaningful only when a user sets it
    /// directly), else `Layout/IndentationWidth`'s `Width` (schema default 2).
    fn ami_indentation_width(&self) -> usize {
        self.cfg
            .get("Layout/AccessModifierIndentation", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()).unwrap_or(2)
            })
    }
}

impl<'a> super::Cops<'a> {
    /// Layout/CaseIndentation — checks how each `when`/`in` branch of a
    /// `case`/`case ... in` expression is indented relative to the `case`
    /// keyword (`EnforcedStyle: case`, the default) or the `end` keyword
    /// (`EnforcedStyle: end`), optionally requiring one extra
    /// `configured_indentation_width` step in (`IndentOneStep`). Ports
    /// rubocop's `CaseIndentation` cop.
    ///
    /// The `ConfigurableEnforcedStyle` bookkeeping upstream
    /// (`correct_style_detected`/`opposite_style_detected`/
    /// `unrecognized_style_detected`, called from `check_when`/
    /// `detect_incorrect_style`) only feeds `--auto-gen-config`'s detected-
    /// style tracking — it never affects the offense range, message, or
    /// autocorrection — so it's skipped entirely.
    ///
    /// All `column`s below are rubocop's raw parser columns (byte offset
    /// from the start of the line): this cop, unlike `Alignment#check_alignment`,
    /// never calls the Unicode-aware `display_column`.
    pub(crate) fn check_case_indentation(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Layout/CaseIndentation";
        if !self.on(COP) {
            return;
        }
        let case_kw_start = node.case_keyword_loc().start_offset();
        let end_kw_start = node.end_keyword_loc().start_offset();
        let case_line = self.idx.loc(case_kw_start).0;
        let end_line = self.idx.loc(end_kw_start).0;
        if case_line == end_line {
            return; // `return if case_node.single_line?`
        }
        let style_is_end = self.cfg.enforced_style(COP) == "end";
        if style_is_end && self.end_and_last_conditional_same_line(end_line, node.else_clause(), node.conditions().iter().last())
        {
            return;
        }
        let case_col = self.idx.loc(case_kw_start).1 - 1;
        let end_col = self.idx.loc(end_kw_start).1 - 1;
        let base_col = if style_is_end { end_col } else { case_col };
        let indent_one_step = self.cfg.get(COP, "IndentOneStep") == Some("true");
        let width = if indent_one_step { self.case_indentation_width(COP) } else { 0 };
        let expected = base_col + width;
        let style_str: &'static str = if style_is_end { "end" } else { "case" };
        for branch in node.conditions().iter() {
            let Some(when_node) = branch.as_when_node() else { continue };
            self.check_case_branch(when_node.keyword_loc().start_offset(), "when", expected, indent_one_step, style_str, COP);
        }
    }

    /// Same as `check_case_indentation`, for `case ... in` (prism's
    /// `CaseMatchNode`/`InNode` — rubocop's `on_case_match` +
    /// `in_pattern_branches`).
    pub(crate) fn check_case_match_indentation(&mut self, node: &ruby_prism::CaseMatchNode) {
        const COP: &str = "Layout/CaseIndentation";
        if !self.on(COP) {
            return;
        }
        let case_kw_start = node.case_keyword_loc().start_offset();
        let end_kw_start = node.end_keyword_loc().start_offset();
        let case_line = self.idx.loc(case_kw_start).0;
        let end_line = self.idx.loc(end_kw_start).0;
        if case_line == end_line {
            return;
        }
        let style_is_end = self.cfg.enforced_style(COP) == "end";
        if style_is_end && self.end_and_last_conditional_same_line(end_line, node.else_clause(), node.conditions().iter().last())
        {
            return;
        }
        let case_col = self.idx.loc(case_kw_start).1 - 1;
        let end_col = self.idx.loc(end_kw_start).1 - 1;
        let base_col = if style_is_end { end_col } else { case_col };
        let indent_one_step = self.cfg.get(COP, "IndentOneStep") == Some("true");
        let width = if indent_one_step { self.case_indentation_width(COP) } else { 0 };
        let expected = base_col + width;
        let style_str: &'static str = if style_is_end { "end" } else { "case" };
        for branch in node.conditions().iter() {
            let Some(in_node) = branch.as_in_node() else { continue };
            self.check_case_branch(in_node.in_loc().start_offset(), "in", expected, indent_one_step, style_str, COP);
        }
    }

    /// `end_and_last_conditional_same_line?`: with `EnforcedStyle: end`, the
    /// whole check is skipped when the `end` keyword shares a line with the
    /// case's last conditional content — the `else` keyword if there's an
    /// `else` clause, otherwise the last `when`/`in` branch's own start
    /// (rubocop's `node.child_nodes.last`, which — absent an `else` — is
    /// always that last branch).
    fn end_and_last_conditional_same_line(
        &self,
        end_line: usize,
        else_clause: Option<ruby_prism::ElseNode>,
        last_branch: Option<ruby_prism::Node>,
    ) -> bool {
        let last_conditional_line = match else_clause {
            Some(e) => Some(self.idx.loc(e.else_keyword_loc().start_offset()).0),
            None => last_branch.map(|b| self.idx.loc(b.location().start_offset()).0),
        };
        last_conditional_line == Some(end_line)
    }

    /// `check_when` + `incorrect_style`'s `AutoCorrector` block (minus the
    /// pure `ConfigurableEnforcedStyle` bookkeeping — see above): compares
    /// the `when`/`in` keyword's column against the already-resolved
    /// `expected` column (`base_column(case_node, style) + indentation_width`)
    /// and, on mismatch, registers the offense. The corrector reindents the
    /// keyword's leading whitespace to `expected` columns, but only when
    /// that leading text is ALL whitespace (`whitespace.source.strip.empty?`)
    /// — a `when` sharing its line with `case` (e.g.
    /// `case test when something`) is reported but left uncorrected, since
    /// the "whitespace" range there is actually `case test `.
    fn check_case_branch(
        &mut self,
        keyword_start: usize,
        branch_type: &str,
        expected: usize,
        indent_one_step: bool,
        style: &str,
        cop: &'static str,
    ) {
        let (line, col1) = self.idx.loc(keyword_start);
        let when_col = col1 - 1;
        if when_col == expected {
            return;
        }
        let depth = if indent_one_step { "one step more than" } else { "as deep as" };
        self.push(keyword_start, cop, true, format!("Indent `{branch_type}` {depth} `{style}`."));
        let line_start = self.idx.starts[line - 1];
        if self.src[line_start..keyword_start].iter().all(u8::is_ascii_whitespace) {
            self.fixes.push((line_start, keyword_start, vec![b' '; expected]));
        }
    }

    /// `Alignment#configured_indentation_width`: cop-local `IndentationWidth`
    /// — a raw `cop_config` read with no schema default, hence `cfg.param`
    /// (user-set only) rather than `cfg.get` — else `Layout/IndentationWidth`'s
    /// `Width`, else 2.
    fn case_indentation_width(&self, cop: &'static str) -> usize {
        self.cfg
            .param(cop, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }
}

impl<'a> super::Cops<'a> {
    /// Layout/EmptyLinesAroundAccessModifier — ported from rubocop's cop of
    /// the same name (`on_send` + a handful of private helpers), run here
    /// inside `visit_statements_node` (sibling-context style, like
    /// `check_empty_lines_around_attribute_accessor` above — see its doc
    /// comment for why "the next element in this exact statement list" is
    /// already prism's equivalent of upstream's guarded `right_sibling`).
    ///
    /// A bare `public`/`protected`/`private`/`module_function` call — no
    /// receiver, no arguments — is upstream's `bare_access_modifier?`. A
    /// literal block (`private { ... }`) and a `&sym`/`&blk` block-pass
    /// (`private(&:foo)`) both land in prism's `CallNode::block()` (the trap
    /// noted in the brief: `&:sym` isn't a `BlockNode`), and BOTH disqualify
    /// the call here — matching upstream's combined `bare_access_modifier? &&
    /// !block_literal?` gate: a literal block never has a bare shape in
    /// prism's own AST to begin with (irrelevant), while whitequark's
    /// `bare_access_modifier_declaration?` pattern already treats a
    /// block-pass as an extra child making it NON-bare, and non-bare access
    /// modifiers are never processed by `on_send` at all. Either way the
    /// verdict is "skip entirely", so a single `call.block().is_some()` check
    /// covers both upstream code paths.
    ///
    /// Beyond the bare shape, upstream's `bare_access_modifier?` also
    /// requires `in_macro_scope?` — a recursive parent-chain walk through
    /// class/module/sclass (always true), a `Class.new`/`Module.new`/
    /// `Struct.new`/`Data.define` block (always true), or transparently
    /// through kwbegin/any-block/if-branch wrappers, bottoming out at the
    /// top-level program (true) or a `def` (false, and NOT a wrapper, so it
    /// blocks the recursion). See the `el_am_scope` field doc in mod.rs for
    /// how that recursion is translated into a push/pop stack maintained by
    /// `visit_class_node`/`visit_module_node`/`visit_singleton_class_node`/
    /// `visit_def_node`/`visit_block_node` (transparent wrappers — any other
    /// block, an explicit `begin...end`, an `if`/`unless` branch — simply
    /// don't touch the stack, which is exactly "inherit the enclosing
    /// scope").
    pub(crate) fn check_empty_lines_around_access_modifier(&mut self, stmts: &ruby_prism::StatementsNode<'_>) {
        const COP: &str = "Layout/EmptyLinesAroundAccessModifier";
        // One-shot flag `visit_block_node` set right before descending into
        // THIS exact statements list, if (and only if) it's a block's own
        // body — consumed unconditionally, cop-enabled or not, so a later
        // unrelated statements list never sees a stale value.
        let is_block_body = std::mem::take(&mut self.el_am_block_owns_next_stmts);
        if !self.on(COP) {
            return;
        }
        if !self.el_am_scope.last().copied().unwrap_or(true) {
            return;
        }
        let body: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        let style = self.cfg.enforced_style(COP); // "around" (default) / "only_before"
        for i in 0..body.len() {
            let Some(call) = body[i].as_call_node() else { continue };
            if call.receiver().is_some() || call.arguments().is_some() || call.block().is_some() {
                continue;
            }
            let name_id = call.name();
            let name = name_id.as_slice();
            if !matches!(name, b"public" | b"protected" | b"private" | b"module_function") {
                continue;
            }
            let loc = call.location();
            let start = loc.start_offset();
            let first_line = self.idx.loc(start).0;
            let last_line = self.idx.loc(loc.end_offset().saturating_sub(1)).0;
            // `same_line?(node, node.right_sibling)`
            if body.get(i + 1).is_some_and(|n| self.idx.loc(n.location().start_offset()).0 == first_line) {
                continue;
            }
            let expected = if style == "only_before" {
                self.el_am_allowed_only_before(name, first_line, last_line)
            } else {
                self.el_am_previous_line_empty(first_line) && self.el_am_next_line_empty(last_line)
            };
            if expected {
                continue;
            }
            let modifier = String::from_utf8_lossy(name);
            let message = if style == "only_before" {
                if self.el_am_next_line_empty(last_line) {
                    format!("Remove a blank line after `{modifier}`.")
                } else {
                    format!("Keep a blank line before `{modifier}`.")
                }
            } else if self.el_am_block_start(first_line) || self.el_am_class_def(first_line) {
                format!("Keep a blank line after `{modifier}`.")
            } else {
                format!("Keep a blank line before and after `{modifier}`.")
            };
            self.push(start, COP, true, message);

            // autocorrect — `range_by_whole_lines(node.source_range)`: the
            // access modifier is always a single physical line (a bare call
            // has no room for a newline), so this is just that one line.
            let line_start = self.idx.starts[first_line - 1];
            let line_end = self.line_end(last_line);
            if self.el_am_should_insert_before(is_block_body, &body, i, first_line) {
                self.fixes.push((line_start, line_start, b"\n".to_vec()));
            }
            if self.el_am_should_insert_after(is_block_body, &body, i) {
                if style == "only_before" {
                    // `next_empty_line_range`: the blank line's own lone
                    // terminator — a 1-byte removal collapses it.
                    if self.el_am_next_line_empty_and_exists(last_line) {
                        let blank_start = self.idx.starts[last_line];
                        self.fixes.push((blank_start, blank_start + 1, Vec::new()));
                    }
                } else if !self.el_am_next_line_empty(last_line) {
                    self.fixes.push((line_end, line_end, b"\n".to_vec()));
                }
            }
        }
    }

    /// `block_start?`: is `line` the line right after the most-recently-seen
    /// block's own opening line? (rubocop's `@block_line` — see the field
    /// doc for its non-restoring overwrite semantics.)
    fn el_am_block_start(&self, line: usize) -> bool {
        self.el_am_block_line.is_some_and(|b| line == b + 1)
    }

    /// `class_def?`: is `line` right after the most-recently-seen class-like
    /// construct's own first line? (rubocop's `@class_or_module_def_first_line`.)
    fn el_am_class_def(&self, line: usize) -> bool {
        self.el_am_class_first_line.is_some_and(|f| line == f + 1)
    }

    /// `body_end?`, folded into `next_line_empty?` below: is `line` right
    /// before the most-recently-seen class-like construct's own last line?
    /// (rubocop's `@class_or_module_def_last_line`.)
    fn el_am_body_end(&self, line: usize) -> bool {
        self.el_am_class_last_line.is_some_and(|l| line + 1 == l)
    }

    /// `comment_line?`: the WHOLE line, ignoring leading whitespace, is a
    /// comment (`/^\s*#/` — purely textual, same as upstream).
    fn el_am_comment_line(&self, line: usize) -> bool {
        let Some(&s) = self.idx.starts.get(line - 1) else { return false };
        let e = self.line_end(line);
        match self.src[s..e].iter().position(|b| !b.is_ascii_whitespace()) {
            Some(p) => self.src[s + p] == b'#',
            None => false,
        }
    }

    /// `previous_line_empty?`: scans upward from `first_line`, skipping
    /// full-comment lines. Nothing found (start of file, or everything above
    /// is a comment) counts as empty. Otherwise empty iff `first_line` is
    /// right after a block/class start, or the found line is blank.
    fn el_am_previous_line_empty(&self, first_line: usize) -> bool {
        let mut found: Option<usize> = None;
        for line in (1..first_line).rev() {
            if self.el_am_comment_line(line) {
                continue;
            }
            found = Some(line);
            break;
        }
        let Some(line) = found else { return true };
        self.el_am_block_start(first_line) || self.el_am_class_def(first_line) || self.el_attr_line_blank(line)
    }

    /// `next_line_empty?`.
    fn el_am_next_line_empty(&self, last_line: usize) -> bool {
        self.el_am_body_end(last_line) || self.el_attr_line_blank(last_line + 1)
    }

    /// `next_line_empty_and_exists?`.
    fn el_am_next_line_empty_and_exists(&self, last_line: usize) -> bool {
        self.el_am_next_line_empty(last_line) && (last_line + 1) != self.idx.starts.len()
    }

    /// The exact text of `line` (no trimming), or `None` past EOF.
    fn el_am_line_text(&self, line: usize) -> Option<&[u8]> {
        let &s = self.idx.starts.get(line - 1)?;
        Some(&self.src[s..self.line_end(line)])
    }

    /// `allowed_only_before_style?`.
    fn el_am_allowed_only_before(&self, name: &[u8], first_line: usize, last_line: usize) -> bool {
        // `special_modifier?`: bare `private`/`protected` only (not `public`
        // or `module_function`).
        if matches!(name, b"private" | b"protected") {
            if self.el_am_line_text(last_line + 1).is_some_and(|t| t == b"end") {
                return true;
            }
            if self.el_am_next_line_empty_and_exists(last_line) {
                return false;
            }
        }
        self.el_am_previous_line_empty(first_line)
    }

    /// `no_empty_lines_around_block_body?` — Layout/EmptyLinesAroundBlockBody's
    /// OWN `EnforcedStyle`, defaulting (per its schema) to `no_empty_lines`.
    fn el_am_no_empty_lines_around_block_body(&self) -> bool {
        self.cfg.get("Layout/EmptyLinesAroundBlockBody", "EnforcedStyle") == Some("no_empty_lines")
    }

    /// `should_insert_line_before?`. `body`/`i` stand in for upstream's
    /// `node.parent.children`/`node == node.parent.children[i]` — prism's
    /// uniform `StatementsNode` makes "sole child" (`body.len() == 1`, no
    /// whitequark `:begin` wrapper) and "first child" (`i == 0`) the same
    /// distinction upstream draws via `node.parent.begin_type?`.
    fn el_am_should_insert_before(
        &self,
        is_block_body: bool,
        body: &[ruby_prism::Node],
        i: usize,
        first_line: usize,
    ) -> bool {
        if self.el_am_previous_line_empty(first_line) {
            return false;
        }
        if !(is_block_body && self.el_am_no_empty_lines_around_block_body()) {
            return true;
        }
        if body.len() == 1 {
            return true;
        }
        i != 0
    }

    /// `should_insert_line_after?`.
    fn el_am_should_insert_after(&self, is_block_body: bool, body: &[ruby_prism::Node], i: usize) -> bool {
        if !(is_block_body && self.el_am_no_empty_lines_around_block_body()) {
            return true;
        }
        i != body.len() - 1
    }
}
impl<'a> super::Cops<'a> {

    /// Layout/BeginEndAlignment — checks whether the `end` keyword of a
    /// `begin` block is properly aligned with the `begin` keyword or with the
    /// start of the line (depending on `EnforcedStyleAlignWith` config).
    ///
    /// Two modes are supported:
    /// - `begin` (align end with begin keyword column)
    /// - `start_of_line` (default, align end with line start indentation)
    pub(crate) fn check_begin_end_alignment(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Layout/BeginEndAlignment";
        if !self.on(COP) {
            return;
        }

        // Only check explicit `begin...end` blocks (with begin keyword).
        let Some(begin_loc) = node.begin_keyword_loc() else {
            return;
        };
        let Some(end_loc) = node.end_keyword_loc() else {
            return;
        };

        // This cop's style knob is EnforcedStyleAlignWith, not EnforcedStyle.
        let style = self.cfg.get(COP, "EnforcedStyleAlignWith").unwrap_or("start_of_line");
        let end_pos = end_loc.start_offset();
        let (end_line, end_col) = self.idx.loc(end_pos);

        // A single-line begin...end can't be misaligned (upstream's
        // EndKeywordAlignment skips when keyword and end share a line).
        if self.idx.loc(begin_loc.start_offset()).0 == end_line {
            return;
        }

        // Determine alignment target based on style (all columns are 1-indexed for logic).
        let (align_col, align_line, align_source): (usize, usize, String) = match style {
            "begin" => {
                // Align with the `begin` keyword column.
                let (begin_line, begin_col) = self.idx.loc(begin_loc.start_offset());
                (begin_col, begin_line, "begin".to_string())
            }
            _ => {
                // Default: `start_of_line` — align with the start of the line where begin is.
                let (begin_line, _) = self.idx.loc(begin_loc.start_offset());
                let line_start_offset = self.idx.starts[begin_line - 1];
                let line_end = self.line_end(begin_line);
                let line_src = &self.src[line_start_offset..line_end];

                // Find first non-whitespace column (0-indexed), convert to 1-indexed for comparison.
                let col = line_src
                    .iter()
                    .position(|&b| b != b' ' && b != b'\t')
                    .unwrap_or(0) + 1;
                let line_text = String::from_utf8_lossy(line_src).trim().to_string();
                (col, begin_line, line_text)
            }
        };

        // Check alignment: if columns match (both 1-indexed), it's correct.
        if end_col == align_col {
            return;
        }

        // Misaligned: report offense. Message uses 0-indexed columns.
        let msg = format!(
            "`end` at {}, {} is not aligned with `{}` at {}, {}.",
            end_line,
            end_col - 1,  // Convert to 0-indexed for message
            align_source,
            align_line,
            align_col - 1  // Convert to 0-indexed for message
        );
        self.push(end_pos, COP, true, &msg);

        // AlignmentCorrector: shift the `end` keyword to the target column —
        // pad with spaces, or eat leading whitespace when over-indented.
        let delta = align_col as isize - end_col as isize;
        if delta > 0 {
            self.fixes.push((end_pos, end_pos, vec![b' '; delta as usize]));
        } else {
            let n = (-delta) as usize;
            let line_start = self.idx.starts[end_line - 1];
            if end_pos >= n
                && end_pos - n >= line_start
                && self.src[end_pos - n..end_pos].iter().all(|&b| b == b' ' || b == b'\t')
            {
                self.fixes.push((end_pos - n, end_pos, Vec::new()));
            }
        }
    }
}

impl<'a> Cops<'a> {
    /// Layout/EmptyLineBetweenDefs — ported from rubocop's `on_begin`, which
    /// walks consecutive sibling pairs of a `:begin` statement sequence.
    /// Prism's `StatementsNode` gives that same sibling list uniformly for
    /// EVERY scope (program/class/module/def/block bodies, if/else branches,
    /// kwbegin bodies) — including single-statement lists, where the
    /// pairwise walk below is simply a no-op — so this runs generically from
    /// `visit_statements_node`, same as `EmptyLinesAroundAttributeAccessor`.
    ///
    /// Both "def/class/module" and "macro call, with or without a literal
    /// block" collapse cleanly under prism: unlike whitequark's separate
    /// `:block`/`:numblock`/`:itblock` wrapper node (whose FIRST CHILD is the
    /// underlying `:send`), prism represents a call-with-block as a single
    /// `CallNode` whose `block()` field holds the `BlockNode` — so
    /// `foo do end`/`foo { }`/numbered-param/`it`-param blocks are ALL just
    /// "a CallNode with a block" here, no separate numblock/itblock handling
    /// needed. `&:sym` block-pass args live in `.arguments()`, never in
    /// `.block()`, so they never look like a block form here.
    ///
    /// The offense anchor and the `blank_lines_count_between`/`single_line?`
    /// line math only ever need each node's OWN start/end line — upstream's
    /// `def_location`/`def_start`/`def_end` branch on node type (keyword vs.
    /// send vs. block-join) only because whitequark's block-node range starts
    /// at the selector, not the receiver; prism's `CallNode#location` is
    /// already receiver-inclusive (spanning through the block's own `end`),
    /// so every candidate type's own `location()` already gives the same
    /// start/end upstream reconstructs by hand.
    pub(crate) fn check_empty_line_between_defs(&mut self, stmts: &ruby_prism::StatementsNode<'_>) {
        const COP: &str = "Layout/EmptyLineBetweenDefs";
        if !self.on(COP) {
            return;
        }
        let body: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        for pair in body.windows(2) {
            if self.eld_candidate(COP, &pair[0]) && self.eld_candidate(COP, &pair[1]) {
                self.eld_check_defs(COP, &pair[0], &pair[1]);
            }
        }
    }

    /// `candidate?`: a def (`EmptyLineBetweenMethodDefs`), a class
    /// (`EmptyLineBetweenClassDefs`), a module (`EmptyLineBetweenModuleDefs`),
    /// or a configured `DefLikeMacros` call (with or without a block).
    fn eld_candidate(&self, cop: &str, node: &ruby_prism::Node<'_>) -> bool {
        if node.as_def_node().is_some() {
            return self.cfg.get(cop, "EmptyLineBetweenMethodDefs") != Some("false");
        }
        if node.as_class_node().is_some() {
            return self.cfg.get(cop, "EmptyLineBetweenClassDefs") != Some("false");
        }
        if node.as_module_node().is_some() {
            return self.cfg.get(cop, "EmptyLineBetweenModuleDefs") != Some("false");
        }
        if let Some(call) = node.as_call_node() {
            return self.eld_macro_candidate(cop, &call);
        }
        false
    }

    /// `macro_candidate?` + `SendNode#macro?`: an implicit-receiver call
    /// whose name is listed in `DefLikeMacros` (empty by default — absent
    /// from the generated schema since its default is the array `[]`),
    /// sitting directly in a macro scope. Reuses
    /// `EmptyLinesAroundAccessModifier`'s `el_am_scope` stack, which already
    /// tracks upstream's exact `in_macro_scope?` predicate (root, or a
    /// class/module/sclass/constructor-block body, transparent through
    /// kwbegin/begin/any-block/if-branch wrappers).
    fn eld_macro_candidate(&self, cop: &str, call: &ruby_prism::CallNode<'_>) -> bool {
        if call.receiver().is_some() || !self.el_am_scope.last().copied().unwrap_or(true) {
            return false;
        }
        let macros: Vec<String> =
            self.cfg.get(cop, "DefLikeMacros").map(crate::config::parse_allowed_list).unwrap_or_default();
        macros.iter().any(|m| m.as_bytes() == call.name().as_slice())
    }

    fn eld_check_defs(&mut self, cop: &'static str, prev: &ruby_prism::Node<'_>, node: &ruby_prism::Node<'_>) {
        let count = self.eld_blank_lines_between(prev, node);
        let (min, max) = self.eld_number_of_empty_lines(cop);
        if count >= min && count <= max {
            return;
        }
        if self.eld_multiple_blank_line_groups(prev, node) {
            return;
        }
        if self.eld_single_line(prev)
            && self.eld_single_line(node)
            && self.cfg.get(cop, "AllowAdjacentOneLineDefs") != Some("false")
        {
            return;
        }
        let kind = Self::eld_node_kind(node);
        let expected = Self::eld_expected_lines(min, max);
        let msg = format!("Expected {expected} between {kind} definitions; found {count}.");
        self.push(node.location().start_offset(), cop, true, msg);
        self.eld_autocorrect(prev, node, count, min, max);
    }

    /// `blank_lines_count_between`: physical lines strictly between the two
    /// nodes (exclusive of both) that are empty or whitespace-only.
    fn eld_blank_lines_between(&self, prev: &ruby_prism::Node<'_>, node: &ruby_prism::Node<'_>) -> usize {
        let Some((first, last)) = self.eld_between_lines(prev, node) else { return 0 };
        (first..=last).filter(|&l| self.el_attr_line_blank(l)).count()
    }

    /// The physical line range strictly between `prev`'s own last line and
    /// `node`'s own first line, or `None` when there's nothing in between
    /// (adjacent lines, or squeezed onto the same line via a semicolon).
    fn eld_between_lines(&self, prev: &ruby_prism::Node<'_>, node: &ruby_prism::Node<'_>) -> Option<(usize, usize)> {
        let first_end_line = self.idx.loc(prev.location().end_offset().saturating_sub(1)).0;
        let second_start_line = self.idx.loc(node.location().start_offset()).0;
        if second_start_line < first_end_line + 2 {
            return None;
        }
        Some((first_end_line + 1, second_start_line - 1))
    }

    /// `multiple_blank_lines_groups?`: true when the between-lines contain a
    /// blank line occurring AFTER a non-blank one (e.g. a comment sandwiched
    /// between two separate blank-line groups) — upstream always allows that
    /// shape, regardless of `NumberOfEmptyLines`.
    fn eld_multiple_blank_line_groups(&self, prev: &ruby_prism::Node<'_>, node: &ruby_prism::Node<'_>) -> bool {
        let Some((first, last)) = self.eld_between_lines(prev, node) else { return false };
        let mut blank_start = None;
        let mut non_blank_end = None;
        for (i, line) in (first..=last).enumerate() {
            if self.el_attr_line_blank(line) {
                blank_start = Some(i);
            } else if non_blank_end.is_none() {
                non_blank_end = Some(i);
            }
        }
        matches!((blank_start, non_blank_end), (Some(b), Some(n)) if b > n)
    }

    /// `single_line?`: the node's own first and last source line coincide.
    fn eld_single_line(&self, node: &ruby_prism::Node<'_>) -> bool {
        let loc = node.location();
        self.idx.loc(loc.start_offset()).0 == self.idx.loc(loc.end_offset().saturating_sub(1)).0
    }

    /// `node_type`: def -> method; a call with a block -> block; a bare call
    /// -> send; class/module pass through as themselves.
    fn eld_node_kind(node: &ruby_prism::Node<'_>) -> &'static str {
        if node.as_def_node().is_some() {
            return "method";
        }
        if node.as_class_node().is_some() {
            return "class";
        }
        if node.as_module_node().is_some() {
            return "module";
        }
        if let Some(call) = node.as_call_node() {
            return if call.block().is_some() { "block" } else { "send" };
        }
        "send"
    }

    /// `minimum_empty_lines`/`maximum_empty_lines`: `NumberOfEmptyLines` is
    /// either a scalar (min == max) or a `[min, max]` array; unset it falls
    /// back to the schema default (`1`).
    fn eld_number_of_empty_lines(&self, cop: &str) -> (usize, usize) {
        let raw = self.cfg.get(cop, "NumberOfEmptyLines").unwrap_or("1").trim();
        if raw.starts_with('[') {
            let nums: Vec<i64> =
                crate::config::parse_allowed_list(raw).iter().filter_map(|s| s.trim().parse().ok()).collect();
            let min = nums.first().copied().unwrap_or(1).max(0) as usize;
            let max = nums.last().copied().unwrap_or(min as i64).max(0) as usize;
            (min, max)
        } else {
            let v = raw.parse::<i64>().unwrap_or(1).max(0) as usize;
            (v, v)
        }
    }

    /// `expected_lines`: `"min..max empty lines"` when they differ (a Ruby
    /// `Range#to_s`), else `"N empty line(s)"`.
    fn eld_expected_lines(min: usize, max: usize) -> String {
        if min != max {
            format!("{min}..{max} empty lines")
        } else {
            let word = if max == 1 { "line" } else { "lines" };
            format!("{max} empty {word}")
        }
    }

    /// `autocorrect`: find the first newline at/after `prev`'s own end —
    /// unless `node` starts before that point (both squeezed onto one
    /// physical line via a semicolon, so no such newline lies between them),
    /// in which case anchor right before `node` instead. Too many blank
    /// lines: remove the surplus bytes there. Too few: insert the shortfall
    /// right after that newline.
    fn eld_autocorrect(
        &mut self,
        prev: &ruby_prism::Node<'_>,
        node: &ruby_prism::Node<'_>,
        count: usize,
        min: usize,
        max: usize,
    ) {
        let end_pos = prev.location().end_offset();
        let mut newline_pos =
            self.src[end_pos..].iter().position(|&b| b == b'\n').map(|i| end_pos + i).unwrap_or(self.src.len());
        let begin_pos = node.location().start_offset();
        if newline_pos > begin_pos {
            newline_pos = begin_pos.saturating_sub(1);
        }
        if count > max {
            let difference = count - max;
            self.fixes.push((newline_pos, newline_pos + difference, Vec::new()));
        } else {
            let difference = min - count;
            self.fixes.push((newline_pos + 1, newline_pos + 1, "\n".repeat(difference).into_bytes()));
        }
    }
}

// ===========================================================================
// Layout/MultilineArrayBraceLayout, Layout/MultilineHashBraceLayout,
// Layout/MultilineMethodDefinitionBraceLayout
//
// Ported from rubocop's shared `RuboCop::Cop::MultilineLiteralBraceLayout`
// mixin (lib/rubocop/cop/mixin/multiline_literal_brace_layout.rb) plus its
// `MultilineLiteralBraceCorrector`
// (lib/rubocop/cop/correctors/multiline_literal_brace_corrector.rb). All
// three cops share identical layout/correction logic; only the "children"
// (array elements / hash pairs / method parameters), the opening/closing
// token locations, and the four message strings differ per cop.
// ===========================================================================

/// The four style-specific message strings a cop's `SAME_LINE_MESSAGE` /
/// `NEW_LINE_MESSAGE` / `ALWAYS_NEW_LINE_MESSAGE` / `ALWAYS_SAME_LINE_MESSAGE`
/// constants hold.
struct MlblMessages {
    same_line: &'static str,
    new_line: &'static str,
    always_new_line: &'static str,
    always_same_line: &'static str,
}

impl<'a> Cops<'a> {
    /// `Layout::MultilineArrayBraceLayout#on_array` — `check_brace_layout(node)`.
    pub(crate) fn check_multiline_array_brace_layout(&mut self, node: &ruby_prism::ArrayNode) {
        const COP: &str = "Layout/MultilineArrayBraceLayout";
        if !self.on(COP) {
            return;
        }
        // `implicit_literal?`: `!node.loc.begin` — a comma-separated implicit
        // array (`foo = a,\nb`) has no brackets at all.
        let Some(open) = node.opening_loc() else { return };
        let Some(close) = node.closing_loc() else { return };
        let children: Vec<ruby_prism::Node> = node.elements().iter().collect();
        const MSGS: MlblMessages = MlblMessages {
            same_line: "The closing array brace must be on the same line as the last array \
                element when the opening brace is on the same line as the first array element.",
            new_line: "The closing array brace must be on the line after the last array \
                element when the opening brace is on a separate line from the first array \
                element.",
            always_new_line: "The closing array brace must be on the line after the last array \
                element.",
            always_same_line: "The closing array brace must be on the same line as the last \
                array element.",
        };
        self.check_multiline_literal_brace(
            COP,
            &MSGS,
            (open.start_offset(), open.end_offset()),
            (close.start_offset(), close.end_offset()),
            &children,
            open.start_offset(),
        );
    }

    /// `Layout::MultilineHashBraceLayout#on_hash` — `check_brace_layout(node)`.
    /// A braceless keyword-argument hash (`foo(a: 1, b: 2)`) is a distinct
    /// prism node kind (`KeywordHashNode`), never visited here, so the
    /// "implicit" case rubocop guards against never reaches this hook at all.
    pub(crate) fn check_multiline_hash_brace_layout(&mut self, node: &ruby_prism::HashNode) {
        const COP: &str = "Layout/MultilineHashBraceLayout";
        if !self.on(COP) {
            return;
        }
        let open = node.opening_loc();
        let close = node.closing_loc();
        let children: Vec<ruby_prism::Node> = node.elements().iter().collect();
        const MSGS: MlblMessages = MlblMessages {
            same_line: "Closing hash brace must be on the same line as the last hash element \
                when opening brace is on the same line as the first hash element.",
            new_line: "Closing hash brace must be on the line after the last hash element when \
                opening brace is on a separate line from the first hash element.",
            always_new_line: "Closing hash brace must be on the line after the last hash \
                element.",
            always_same_line: "Closing hash brace must be on the same line as the last hash \
                element.",
        };
        self.check_multiline_literal_brace(
            COP,
            &MSGS,
            (open.start_offset(), open.end_offset()),
            (close.start_offset(), close.end_offset()),
            &children,
            open.start_offset(),
        );
    }

    /// `Layout::MultilineMethodDefinitionBraceLayout#on_def`/`#on_defs` —
    /// `check_brace_layout(node.arguments)`. Prism folds `def`/`defs` into
    /// one `DefNode`; its `lparen_loc`/`rparen_loc` stand in for whitequark's
    /// implicit-vs-explicit `arguments` node `loc.begin`/`loc.end`, and the
    /// ordered parameter list (requireds, optionals, rest, posts, keywords,
    /// keyword_rest, block — Ruby's fixed parameter order) stands in for its
    /// `children`.
    pub(crate) fn check_multiline_method_definition_brace_layout(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/MultilineMethodDefinitionBraceLayout";
        if !self.on(COP) {
            return;
        }
        let Some(lparen) = node.lparen_loc() else { return };
        let Some(rparen) = node.rparen_loc() else { return };
        let Some(params) = node.parameters() else { return };
        let children = mlbl_ordered_params(&params);
        const MSGS: MlblMessages = MlblMessages {
            same_line: "Closing method definition brace must be on the same line as the last \
                parameter when opening brace is on the same line as the first parameter.",
            new_line: "Closing method definition brace must be on the line after the last \
                parameter when opening brace is on a separate line from the first parameter.",
            always_new_line: "Closing method definition brace must be on the line after the \
                last parameter.",
            always_same_line: "Closing method definition brace must be on the same line as the \
                last parameter.",
        };
        self.check_multiline_literal_brace(
            COP,
            &MSGS,
            (lparen.start_offset(), lparen.end_offset()),
            (rparen.start_offset(), rparen.end_offset()),
            &children,
            lparen.start_offset(),
        );
    }

    /// Ported `MultilineLiteralBraceLayout#check_brace_layout` (minus the
    /// early `ignored_literal?`/heredoc guards, folded in below) plus
    /// `#check`/`#check_symmetrical`/`#check_new_line`/`#check_same_line`,
    /// plus `MultilineLiteralBraceCorrector#call` and everything it calls.
    fn check_multiline_literal_brace(
        &mut self,
        cop: &'static str,
        msgs: &MlblMessages,
        open: (usize, usize),
        close: (usize, usize),
        children: &[ruby_prism::Node],
        node_start: usize,
    ) {
        // `empty_literal?`
        if children.is_empty() {
            return;
        }
        // `single_line?` — the whole literal (brace-to-brace) fits one line.
        let whole_start_line = self.idx.loc(open.0).0;
        let whole_end_line = self.idx.loc(close.1.saturating_sub(1).max(open.0)).0;
        if whole_start_line == whole_end_line {
            return;
        }

        let last = children.last().expect("checked non-empty above");
        // `last_line_heredoc?(node.children.last)`: a heredoc's own
        // `location()` covers only its opener line (the body/terminator are
        // separate `content_loc`/`closing_loc`), so any composite node's
        // location that recursively contains one is unreliable for "last
        // line" purposes — moving the brace could land it mid-heredoc.
        // rubocop's recursive line comparison amounts in practice to "does
        // the last child contain a heredoc anywhere" (a heredoc terminator
        // is always at-or-after its own opener's line, and Ruby's grammar
        // forces anything textually after a heredoc argument onto a later
        // line), so skip the whole check whenever one is found.
        if mlbl_subtree_has_heredoc(last) {
            return;
        }

        let first = &children[0];
        let opening_same = self.idx.loc(open.0).0 == self.idx.loc(first.location().start_offset()).0;
        let last_start = last.location().start_offset();
        let last_end = last.location().end_offset();
        let last_line = self.idx.loc(last_end.saturating_sub(1).max(last_start)).0;
        let closing_same = self.idx.loc(close.0).0 == last_line;

        let style = self.cfg.enforced_style(cop);
        let message: &str = match style {
            "new_line" => {
                if !closing_same {
                    return;
                }
                msgs.always_new_line
            }
            "same_line" => {
                if closing_same {
                    return;
                }
                msgs.always_same_line
            }
            _ => match (opening_same, closing_same) {
                (true, true) | (false, false) => return,
                (true, false) => msgs.same_line,
                (false, true) => msgs.new_line,
            },
        };

        self.push(close.0, cop, true, message.to_string());

        // ---- MultilineLiteralBraceCorrector ----
        if closing_same {
            // `correct_same_line_brace`: push the closing token onto its own
            // line, disturbing nothing else.
            self.fixes.push((close.0, close.0, b"\n".to_vec()));
            return;
        }

        // `new_line_needed_before_closing_brace?`: a trailing comment on the
        // last child's own line blocks the move only when the literal is
        // ITSELF a call's receiver or (non-safe-nav) positional argument —
        // rubocop declines to untangle the comment from a resumed chain.
        let last_commented = self.mlbl_comment_at_line(last_line);
        if last_commented && self.mlbl_is_chained_or_argument(node_start) {
            // Offense stands; no correction (matches upstream leaving it
            // uncorrected here).
            return;
        }

        // `last_element_range_with_trailing_comma(node).end`
        let insert_at = self.mlbl_last_element_end_with_comma(last_end);

        // `range_with_surrounding_space(node.loc.end, side: :left)`
        let left_start = self.mlbl_left_space_start(close.0);
        self.fixes.push((left_start, close.0, Vec::new()));

        // `correct_heredoc_argument_method_chain`: when THIS node is itself
        // the dot-chained receiver of an outer call and its own first
        // argument is a heredoc, the outer call's `.method_name` tail is
        // uprooted from just past the closing token and reattached right
        // after the relocated token — pushed BEFORE that token's own
        // re-insertion below so the two same-position inserts land in the
        // right visual order (closing token, then the chained method).
        if let Some(&(dot_start, parent_end)) = self.mmcbl_heredoc_chain.get(&node_start) {
            let chain_text = self.src[dot_start..parent_end].to_vec();
            self.fixes.push((dot_start, parent_end, Vec::new()));
            self.fixes.push((insert_at, insert_at, chain_text));
        }

        if last_commented {
            // `select_content_to_be_inserted_after_last_element`: drag
            // everything from the closing token through the end of ITS own
            // line (e.g. a trailing comma from an enclosing literal) along
            // with the brace, past the comment.
            let line_end = self.mlbl_end_of_line(close.0);
            let text = self.src[close.0..line_end].to_vec();
            self.fixes.push((close.0, line_end, Vec::new()));
            self.fixes.push((insert_at, insert_at, text));
        } else {
            // The closing token itself must be removed from its old spot,
            // not just the space to its left — `corrector.remove(range_
            // with_surrounding_space(node.loc.end, side: :left))` deletes
            // BOTH in one range upstream; the leading-space delete above
            // only covers the space, so the token's own bytes need their
            // own removal here.
            self.fixes.push((close.0, close.1, Vec::new()));
            let text = self.src[close.0..close.1].to_vec();
            self.fixes.push((insert_at, insert_at, text));
        }
    }

    fn mlbl_comment_at_line(&self, line: usize) -> bool {
        self.comments.iter().any(|(l, _, _)| *l == line)
    }

    /// `node.chained?` (`parent&.call_type? && parent.receiver == node`) OR
    /// `node.argument?` (`parent&.send_type? && parent.arguments.include?
    /// (node)`) for the array/hash LITERAL itself — `mlbl_call_child` was
    /// populated with exactly those start offsets while visiting calls.
    /// Method-definition brace layout never calls this (its "node" — the
    /// parameter list — is never a call's receiver/argument).
    fn mlbl_is_chained_or_argument(&self, literal_start: usize) -> bool {
        self.mlbl_call_child.contains(&literal_start)
    }

    /// `range_with_surrounding_space(children(node).last.source_range,
    /// side: :right).end.resize(1)` compared against `,`: the position right
    /// after the last child's trailing horizontal whitespace + newlines,
    /// taken as a trailing comma only if that's what's actually there.
    fn mlbl_last_element_end_with_comma(&self, last_end: usize) -> usize {
        let mut pos = last_end;
        while pos < self.src.len() && matches!(self.src[pos], b' ' | b'\t') {
            pos += 1;
        }
        while pos < self.src.len() && self.src[pos] == b'\n' {
            pos += 1;
        }
        if pos < self.src.len() && self.src[pos] == b',' {
            pos + 1
        } else {
            last_end
        }
    }

    /// `range_with_surrounding_space(range, side: :left)` at its default
    /// (`newlines: true, whitespace: false`): walk left over horizontal
    /// whitespace, then over newlines.
    fn mlbl_left_space_start(&self, end: usize) -> usize {
        let mut pos = end;
        while pos > 0 && matches!(self.src[pos - 1], b' ' | b'\t') {
            pos -= 1;
        }
        while pos > 0 && self.src[pos - 1] == b'\n' {
            pos -= 1;
        }
        pos
    }

    /// The end of the (unterminated) line starting at `start` — used as
    /// `range_by_whole_lines(node.source_range).end.end_pos` (default
    /// `include_final_newline: false`), specialized to a range whose own
    /// last line IS the line `start` sits on.
    fn mlbl_end_of_line(&self, start: usize) -> usize {
        let mut pos = start;
        while pos < self.src.len() && self.src[pos] != b'\n' {
            pos += 1;
        }
        pos
    }
}

/// A `def`'s parameters in Ruby's fixed grammar order (requireds, optionals,
/// rest, posts, keywords, keyword_rest, block) as generic nodes — the
/// method-definition cop's `children(node)`.
fn mlbl_ordered_params<'pr>(p: &ruby_prism::ParametersNode<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    let mut v = Vec::new();
    for n in p.requireds().iter() {
        v.push(n);
    }
    for n in p.optionals().iter() {
        v.push(n);
    }
    if let Some(n) = p.rest() {
        v.push(n);
    }
    for n in p.posts().iter() {
        v.push(n);
    }
    for n in p.keywords().iter() {
        v.push(n);
    }
    if let Some(n) = p.keyword_rest() {
        v.push(n);
    }
    if let Some(n) = p.block() {
        v.push(n.as_node());
    }
    v
}

/// `last_line_heredoc?`'s recursive descent, collapsed to "does this
/// subtree contain a heredoc-opened string/xstring anywhere" (see the
/// doc comment on its call site for why that's equivalent in practice).
/// Reuses prism's own default traversal (`ruby_prism::Visit`) for every
/// node kind except the four string flavors that can open a heredoc.
struct MlblHeredocFinder {
    found: bool,
}
impl<'pr> ruby_prism::Visit<'pr> for MlblHeredocFinder {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        if node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) {
            self.found = true;
        }
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        if node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) {
            self.found = true;
        }
        ruby_prism::visit_interpolated_string_node(self, node);
    }
    fn visit_x_string_node(&mut self, node: &ruby_prism::XStringNode<'pr>) {
        if node.opening_loc().as_slice().starts_with(b"<<") {
            self.found = true;
        }
    }
    fn visit_interpolated_x_string_node(&mut self, node: &ruby_prism::InterpolatedXStringNode<'pr>) {
        if node.opening_loc().as_slice().starts_with(b"<<") {
            self.found = true;
        }
        ruby_prism::visit_interpolated_x_string_node(self, node);
    }
}
fn mlbl_subtree_has_heredoc(node: &ruby_prism::Node) -> bool {
    use ruby_prism::Visit;
    let mut f = MlblHeredocFinder { found: false };
    f.visit(node);
    f.found
}

impl<'a> super::Cops<'a> {
    /// Layout/DefEndAlignment — checks whether a `def`/`defs`'s `end` is
    /// aligned with the `def` keyword (`EnforcedStyleAlignWith: def`) or
    /// with the start of the enclosing statement (`start_of_line`, the
    /// default). Ported from the `EndKeywordAlignment` mixin's
    /// `check_end_kw_in_node`/`check_end_kw_alignment` plus the cop's own
    /// `on_send`/`autocorrect` overrides for the `private def foo; end`
    /// modifier form.
    ///
    /// `on_def` (plain, unwrapped defs): upstream builds a ONE-entry hash
    /// `{ style => node.loc.keyword }` — regardless of which style is
    /// configured, the sole alignment target is always the `def` keyword's
    /// own location (a plain `def` line already begins with `def`, so
    /// `start_of_line` never needs a distinct "start of the physical line"
    /// computation here). Style only matters once a modifier call wraps the
    /// def — see `check_def_end_alignment_send`.
    pub(crate) fn check_def_end_alignment(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/DefEndAlignment";
        if !self.on(COP) {
            return;
        }
        let def_start = node.location().start_offset();
        // A def-modifier chain (`private def foo; end`) already claimed
        // this def via `on_send` — visited before we ever recurse down
        // into the def itself — rubocop's `ignore_node`/`ignored_node?`.
        if self.dea_ignored.contains(&def_start) {
            return;
        }
        // Endless methods (`def foo = 1`) have no `end` keyword.
        let Some(end_loc) = node.end_keyword_loc() else { return };
        let kw_loc = node.def_keyword_loc();
        let style = self.cfg.get(COP, "EnforcedStyleAlignWith").unwrap_or("start_of_line");
        self.dea_report(COP, def_start, end_loc, kw_loc.start_offset(), kw_loc.end_offset(), true, style);
    }

    /// `on_send` + `def_modifier?` + `each_descendant(:any_def).first`: a
    /// receiverless call whose (possibly further-nested) sole first
    /// argument is ultimately a `def`/`defs` node — `private def foo; end`,
    /// or a multi-level chain like `foo bar def m; end`. Every qualifying
    /// call in such a chain reaches this (outermost visited first, since
    /// our traversal is top-down); only the FIRST one to see a given def
    /// actually checks/offends — `ignore_node` makes every later visit
    /// (including the def's own `on_def`) a no-op.
    pub(crate) fn check_def_end_alignment_send(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/DefEndAlignment";
        if !self.on(COP) {
            return;
        }
        let Some((method_def, parent_start)) = dea_def_modifier(node) else { return };
        let def_start = method_def.location().start_offset();
        // The immediate (one-level) wrapping call — used only by the
        // AUTOCORRECT anchor (`node.parent&.send_type?`), which can differ
        // from the DETECTION target below in a multi-level chain: upstream
        // anchors the offense MESSAGE to the outermost call in the chain,
        // but its own `autocorrect` override anchors the FIX to the def's
        // direct parent — a real (if obscure) upstream quirk, ported as-is.
        self.dea_parent.insert(def_start, parent_start);
        if self.dea_ignored.contains(&def_start) {
            return;
        }
        self.dea_ignored.insert(def_start);
        let Some(end_loc) = method_def.end_keyword_loc() else { return };
        let kw_loc = method_def.def_keyword_loc();
        let style = self.cfg.get(COP, "EnforcedStyleAlignWith").unwrap_or("start_of_line");
        let (align_start, align_end, literal_def) = if style == "def" {
            (kw_loc.start_offset(), kw_loc.end_offset(), true)
        } else {
            // `start_of_line`: align with THIS call's own start (the
            // outermost qualifying call in the chain — inner calls are
            // already ignored by the time they'd reach here) through the
            // end of the `def` keyword — upstream's `range_between(expr.
            // begin_pos, method_def.loc.keyword.end_pos)`.
            (node.location().start_offset(), kw_loc.end_offset(), false)
        };
        self.dea_report(COP, def_start, end_loc, align_start, align_end, literal_def, style);
    }

    /// Shared match/offense/autocorrect core for both entry points above —
    /// `check_end_kw_alignment` + `add_offense_for_misalignment` +
    /// `matching_ranges`/`same_line?`/`column_offset_between`. No offense
    /// when `end` shares a line with the align target OR sits in the same
    /// column; otherwise reports with upstream's byte-for-byte message
    /// format and pushes the `AlignmentCorrector.align_end` fix.
    fn dea_report(
        &mut self,
        cop: &'static str,
        def_start: usize,
        end_loc: ruby_prism::Location,
        align_start: usize,
        align_end: usize,
        literal_def: bool,
        style: &str,
    ) {
        let end_pos = end_loc.start_offset();
        let (end_line, end_col) = self.idx.loc(end_pos);
        let (align_line, align_col) = self.idx.loc(align_start);
        if align_line == end_line || align_col == end_col {
            return;
        }
        let align_source = if literal_def {
            "def".to_string()
        } else {
            String::from_utf8_lossy(&self.src[align_start..align_end]).into_owned()
        };
        let msg = format!(
            "`end` at {}, {} is not aligned with `{}` at {}, {}.",
            end_line,
            end_col - 1,
            align_source,
            align_line,
            align_col - 1
        );
        self.push(end_pos, cop, true, &msg);

        // `autocorrect`: style `def` (or a plain, unwrapped def) aligns to
        // the def's own column; `start_of_line` on a modifier-chain def
        // aligns to the IMMEDIATE wrapping call's column instead (may
        // differ from `align_col` above in a multi-level chain).
        let correction_col = if style == "start_of_line" {
            match self.dea_parent.get(&def_start) {
                Some(&parent_start) => self.idx.loc(parent_start).1,
                None => align_col,
            }
        } else {
            align_col
        };
        self.dea_autocorrect(end_pos, end_line, correction_col);
    }

    /// `AlignmentCorrector.align_end`: replace the `end` line's leading
    /// whitespace with `target_col` indentation characters when the line
    /// starts with nothing but whitespace before `end`; otherwise (e.g. a
    /// body statement sharing the line via `;`) leave that prefix untouched
    /// and insert a newline + fresh indentation right before `end` instead.
    fn dea_autocorrect(&mut self, end_pos: usize, end_line: usize, target_col_1idx: usize) {
        let target_col0 = target_col_1idx.saturating_sub(1);
        let line_start = self.idx.starts[end_line - 1];
        let prefix = &self.src[line_start..end_pos];
        let use_tabs = self.cfg.enforced_style("Layout/IndentationStyle") == "tabs";
        let indentation = vec![if use_tabs { b'\t' } else { b' ' }; target_col0];
        if prefix.iter().all(|&b| b == b' ' || b == b'\t') {
            self.fixes.push((line_start, end_pos, indentation));
        } else {
            let mut repl = Vec::with_capacity(1 + indentation.len());
            repl.push(b'\n');
            repl.extend(indentation);
            self.fixes.push((end_pos, end_pos, repl));
        }
    }
}

/// `def_modifier`: peels a chain of receiverless calls whose (only ever the
/// FIRST) argument is itself either the target `def`/`defs` node or another
/// such call, mirroring rubocop-ast's `MethodDispatchNode#def_modifier`
/// (`private def foo; end`, or a nested `foo bar def m; end`). Returns the
/// target def node together with the START OFFSET of its immediate
/// (one-level) wrapping call — always the innermost link in the chain,
/// regardless of which level `call` itself is (calling this on any link
/// walks the rest of the way down).
fn dea_def_modifier<'pr>(call: &ruby_prism::CallNode<'pr>) -> Option<(ruby_prism::DefNode<'pr>, usize)> {
    if call.receiver().is_some() {
        return None;
    }
    let first = call.arguments()?.arguments().iter().next()?;
    if let Some(def) = first.as_def_node() {
        return Some((def, call.location().start_offset()));
    }
    if let Some(inner) = first.as_call_node() {
        return dea_def_modifier(&inner);
    }
    None
}

/// Layout/ClosingHeredocIndentation's own heredoc-type test, factored out so
/// `visit_call_node` (in `mod.rs`) can eagerly recognize a heredoc sitting in
/// receiver/argument position while populating `chi_call_root`/
/// `chi_heredoc_ctx` — mirrors `dot_position_heredoc_line`'s node-kind
/// dispatch, but returns the OPENING token's start offset (the coordinate
/// this cop keys everything on) rather than the closing line.
pub(crate) fn chi_heredoc_offset(node: &ruby_prism::Node) -> Option<usize> {
    let opening = if let Some(n) = node.as_string_node() {
        n.opening_loc()
    } else if let Some(n) = node.as_interpolated_string_node() {
        n.opening_loc()
    } else if let Some(n) = node.as_x_string_node() {
        Some(n.opening_loc())
    } else if let Some(n) = node.as_interpolated_x_string_node() {
        Some(n.opening_loc())
    } else {
        None
    }?;
    opening.as_slice().starts_with(b"<<").then(|| opening.start_offset())
}

impl<'a> super::Cops<'a> {
    /// Layout/ClosingHeredocIndentation — a `<<~`/`<<-` heredoc's closing
    /// delimiter must line up with either (a) the physical line the heredoc
    /// itself opens on (the plain case: `on_heredoc`'s default comparison),
    /// or, when the heredoc is a call's receiver (`chained?`) or a direct
    /// positional argument (`argument?`), (b) the line the OUTERMOST call in
    /// that direct chain of nested calls itself starts on — upstream's
    /// `argument_indentation_correct?` / `find_node_used_heredoc_argument`.
    /// Bare `<<`/`<<"..."` heredocs (`SIMPLE_HEREDOC`) are never checked.
    ///
    /// The chain-climbing half is precomputed in `visit_call_node`, top-down,
    /// into `chi_heredoc_ctx` (this heredoc's opening offset -> (root call's
    /// own start offset, is_argument)) before this ever runs — by the time a
    /// heredoc node is visited every enclosing call that could claim it has
    /// already been visited.
    pub(crate) fn check_closing_heredoc_indentation(
        &mut self,
        opening_loc: Option<ruby_prism::Location>,
        closing_loc: Option<ruby_prism::Location>,
    ) {
        const COP: &str = "Layout/ClosingHeredocIndentation";
        if !self.on(COP) {
            return;
        }
        let Some(opening) = opening_loc else { return };
        let op = opening.as_slice();
        if !op.starts_with(b"<<") {
            return;
        }
        // `SIMPLE_HEREDOC = '<<'`: skip unless the marker right after `<<` is
        // `~` or `-` (quoting, e.g. `<<~"ID"`, doesn't change this).
        if !matches!(op.get(2), Some(b'~') | Some(b'-')) {
            return;
        }
        let Some(closing) = closing_loc else { return };

        let node_start = opening.start_offset();
        let opening_indent = self.chi_indent_level(node_start);
        let closing_indent = self.chi_indent_level(closing.start_offset());
        if opening_indent == closing_indent {
            return;
        }

        // `argument_indentation_correct?`: only when the heredoc is a call's
        // receiver or argument, compared against that call's (climbed) root.
        let is_argument = match self.chi_heredoc_ctx.get(&node_start) {
            Some(&(root, is_argument)) => {
                if self.chi_indent_level(root) == closing_indent {
                    return;
                }
                is_argument
            }
            None => false,
        };

        let opening_line = self.chi_line_text(node_start);
        let closing_line = self.chi_line_text(closing.start_offset());
        let message = if is_argument {
            format!(
                "`{}` is not aligned with `{}` or beginning of method definition.",
                closing_line.trim(),
                opening_line.trim()
            )
        } else {
            format!("`{}` is not aligned with `{}`.", closing_line.trim(), opening_line.trim())
        };
        self.push(closing.start_offset(), COP, true, message);

        // `indented_end`: replace the closing line's own leading run of
        // `closing_indent` spaces with `opening_indent` spaces — a plain
        // prefix swap, since `chi_line_text`'s start-of-line offset is
        // exactly where that leading whitespace begins.
        let line_start = self.idx.starts[self.idx.loc(closing.start_offset()).0 - 1];
        self.fixes.push((line_start, line_start + closing_indent, vec![b' '; opening_indent]));
    }

    /// `indent_level`: count of leading ASCII spaces (NOT tabs — the cop's
    /// own override, `source_line[/\A */].length`, shadows the `Heredoc`
    /// mixin's whitespace-line-minimum version) on the physical line `off`
    /// sits on.
    fn chi_indent_level(&self, off: usize) -> usize {
        let line = self.idx.loc(off).0;
        let start = self.idx.starts[line - 1];
        self.src[start..].iter().take_while(|&&b| b == b' ').count()
    }

    /// `Range#source_line`: the full physical line `off` sits on, no
    /// trailing newline.
    fn chi_line_text(&self, off: usize) -> &'a str {
        let line = self.idx.loc(off).0;
        let start = self.idx.starts[line - 1];
        let end = self.line_end(line);
        std::str::from_utf8(&self.src[start..end]).unwrap_or("")
    }
}

impl<'a> super::Cops<'a> {
    /// `Layout::MultilineMethodCallBraceLayout#on_send`/`#on_csend` —
    /// `check_brace_layout(node)`, reusing the same
    /// `MultilineLiteralBraceLayout` engine as the array/hash/method-def
    /// cops above. The "brace" is the call's own parens (`lparen`/`rparen`
    /// via `opening_loc`/`closing_loc`); `children(node)` is `node.arguments`
    /// — a receiverless/braceless call (`foo 1, 2`) has neither, so
    /// `opening_loc`/`closing_loc` being absent stands in for
    /// `implicit_literal?`, and a call with no arguments (`puts` or
    /// `puts()`) yields an empty `children`, which the shared engine already
    /// treats as `empty_literal?`.
    ///
    /// The cop's own `single_line_ignoring_receiver?` override — `same_line?
    /// (node.loc.begin, node.loc.end)` — short-circuits `ignored_literal?`
    /// before it ever falls through to the base `node.single_line?` check
    /// (which additionally spans the receiver/method-name chain). Since
    /// `loc.begin`/`loc.end` being on different lines already forces the
    /// full node's own span to be multi-line too, `node.single_line?` can
    /// never add anything `single_line_ignoring_receiver?` didn't already
    /// decide — exactly the shared engine's existing open/close-only
    /// single-line guard, so no extra override is needed here.
    pub(crate) fn check_multiline_method_call_brace_layout(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/MultilineMethodCallBraceLayout";
        if !self.on(COP) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let Some(close) = node.closing_loc() else { return };
        let mut children: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        // whitequark's send args include a `&block` pass as the last argument;
        // prism keeps it out of `arguments()` (in `block()`), so fold it back.
        if let Some(block) = node.block() {
            if block.as_block_argument_node().is_some() {
                children.push(block);
            }
        }
        const MSGS: MlblMessages = MlblMessages {
            same_line: "Closing method call brace must be on the same line as the last argument \
                when opening brace is on the same line as the first argument.",
            new_line: "Closing method call brace must be on the line after the last argument \
                when opening brace is on a separate line from the first argument.",
            always_new_line: "Closing method call brace must be on the line after the last \
                argument.",
            always_same_line: "Closing method call brace must be on the same line as the last \
                argument.",
        };
        self.check_multiline_literal_brace(
            COP,
            &MSGS,
            (open.start_offset(), open.end_offset()),
            (close.start_offset(), close.end_offset()),
            &children,
            node.location().start_offset(),
        );
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/EmptyComment — `on_new_investigation`. When `AllowMarginComment`
    /// is true (default), consecutive same-column comment lines are joined
    /// (`concat_consecutive_comments`) into one unit before the empty-comment
    /// test, so a "margin" (blank-hash / text / blank-hash) block reads as
    /// non-empty overall even though its bookend lines are individually bare
    /// `#`s. When false, each comment is tested alone. Either way, every
    /// comment inside a unit that tests empty gets its own offense (and its
    /// own autocorrect) — `investigate` iterates `chunk[1]`, not the chunk as
    /// a whole.
    pub(crate) fn check_empty_comment(&mut self) {
        const COP: &str = "Layout/EmptyComment";
        if !self.on(COP) {
            return;
        }
        if self.comments.is_empty() {
            return;
        }
        const MSG: &str = "Source code comment is empty.";
        let allow_border = self.cfg.get(COP, "AllowBorderComment") == Some("true");
        let allow_margin = self.cfg.get(COP, "AllowMarginComment") == Some("true");

        // `comment.text.strip` — the comment token's source text (starts at
        // `#`) with surrounding whitespace removed. A single comment line
        // never itself contains a newline, so testing each chunk member's
        // stripped text against the appropriate single-line pattern is
        // equivalent to rubocop's `/\A(#\n)+\z/` (border-allowed) /
        // `/\A(#+\n)+\z/` (border-disallowed) match against the members'
        // joined `"#{text.strip}\n"` units.
        let is_empty_unit = |text: &[u8]| -> bool {
            let t = std::str::from_utf8(text).unwrap_or("").trim();
            if allow_border { t == "#" } else { !t.is_empty() && t.bytes().all(|b| b == b'#') }
        };

        if allow_margin {
            // `concat_consecutive_comments`: `chunk_while { |i, j| i.loc.line.succ
            // == j.loc.line && i.loc.column == j.loc.column }`.
            let mut ix = 0;
            while ix < self.comments.len() {
                let mut end = ix + 1;
                let (mut prev_line, prev_start, _) = self.comments[ix];
                let mut prev_col = self.ec_column(prev_start);
                while end < self.comments.len() {
                    let (line, start, _) = self.comments[end];
                    let col = self.ec_column(start);
                    if prev_line + 1 == line && prev_col == col {
                        prev_line = line;
                        prev_col = col;
                        end += 1;
                    } else {
                        break;
                    }
                }
                let chunk = &self.comments[ix..end];
                if chunk.iter().all(|&(_, s, e)| is_empty_unit(&self.src[s..e])) {
                    let offenders: Vec<(usize, usize, usize)> = chunk.to_vec();
                    for (line, start, end) in offenders {
                        self.push(start, COP, true, MSG);
                        self.ec_autocorrect(line, start, end);
                    }
                }
                ix = end;
            }
        } else {
            let comments = self.comments.to_vec();
            for (line, start, end) in comments {
                if is_empty_unit(&self.src[start..end]) {
                    self.push(start, COP, true, MSG);
                    self.ec_autocorrect(line, start, end);
                }
            }
        }
    }

    /// `comment.loc.column`: 0-based CHARACTER column.
    fn ec_column(&self, off: usize) -> usize {
        let (line, mut col) = self.idx.loc(off);
        let prefix = &self.src[self.idx.starts[line - 1]..off];
        if !prefix.is_ascii() {
            col = String::from_utf8_lossy(prefix).chars().count() + 1;
        }
        col - 1
    }

    /// `previous_token`/`same_line?` reduce to: is there non-whitespace
    /// content before the comment on its own physical line? If so it's a
    /// trailing comment — remove from the whitespace run right before `#`
    /// through the comment's end (rubocop's `range_with_surrounding_space`
    /// with `newlines: false`, which eats a whole run of spaces/tabs but
    /// stops at a newline). Otherwise it's a standalone comment line —
    /// remove the whole physical line, including its trailing newline
    /// (`range_by_whole_lines(include_final_newline: true)`).
    fn ec_autocorrect(&mut self, line: usize, start: usize, end: usize) {
        let line_start = self.idx.starts[line - 1];
        let trailing = !self.src[line_start..start].iter().all(u8::is_ascii_whitespace);
        if trailing {
            let mut ws_start = start;
            while ws_start > line_start
                && (self.src[ws_start - 1] == b' ' || self.src[ws_start - 1] == b'\t')
            {
                ws_start -= 1;
            }
            self.fixes.push((ws_start, end, Vec::new()));
        } else {
            let line_end = self.idx.starts.get(line).copied().unwrap_or(self.src.len());
            self.fixes.push((line_start, line_end, Vec::new()));
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/IndentationStyle — flags the first "wrong" whitespace run in a
    /// line's leading indentation: under `EnforcedStyle: spaces` (default) a
    /// tab anywhere in the leading run is wrong; under `tabs` a literal
    /// space is. Mirrors rubocop's `find_offense`/`autocorrect_lambda_for_*`
    /// verbatim, including the regex's backtracking behavior (see
    /// `find_offense_match` below) and its floor-division tab/space
    /// conversion.
    ///
    /// Heredoc body lines and (non-single-line) quoted `str`/`dstr` literal
    /// lines are exempt (`in_string_literal?`) — mirrored with the engine's
    /// existing `heredoc_lines`/`multiline_str_lines` line tables rather
    /// than a bespoke AST walk. Nothing at or after `__END__` is lintable
    /// text.
    pub(crate) fn check_indentation_style(&mut self) {
        const COP: &str = "Layout/IndentationStyle";
        if !self.on(COP) {
            return;
        }
        let tabs_style = self.cfg.enforced_style(COP) == "tabs";
        // `configured_indentation_width`: own cop's `IndentationWidth` (no
        // schema default — absent unless user-set) else
        // `Layout/IndentationWidth`'s `Width` (schema default "2").
        let width: usize = self
            .cfg
            .get(COP, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
            .max(1);
        // `message`: `type: style == :spaces ? 'Tab' : 'Space'` — driven by
        // the CONFIGURED style, not by what the matched run actually
        // contains.
        let msg = if tabs_style { "Space detected in indentation." } else { "Tab detected in indentation." };
        let nlines = self.idx.starts.len();
        for line_no in 1..=nlines {
            // nothing at or after `__END__` is program text
            if self.data_line.is_some_and(|d| line_no >= d) {
                break;
            }
            let s = self.idx.starts[line_no - 1];
            let e = self.line_end(line_no);
            let line = &self.src[s..e];
            let Some(match_len) = find_offense_match(line, tabs_style) else { continue };
            // `in_string_literal?`: the whole matched run must fall inside a
            // heredoc body or a multi-line quoted string's expression range.
            // Since the match always starts at column 0, this reduces to
            // "is the line itself one of those tracked body/string lines".
            if self.heredoc_lines.iter().any(|(hs, he, _, _)| line_no >= *hs && line_no <= *he)
                || self.multiline_str_lines.iter().any(|(hs, he)| line_no >= *hs && line_no <= *he)
            {
                continue;
            }
            let match_end = s + match_len;
            self.push(s, COP, true, msg);
            let matched = &self.src[s..match_end];
            let replacement = if matched.contains(&b'\t') {
                // autocorrect_lambda_for_tabs: every tab -> `width` spaces;
                // any other byte (a plain space) passes through unchanged.
                let mut out = Vec::with_capacity(matched.len() * width);
                for &b in matched {
                    if b == b'\t' {
                        out.extend(std::iter::repeat_n(b' ', width));
                    } else {
                        out.push(b);
                    }
                }
                out
            } else {
                // autocorrect_lambda_for_spaces: the whole match (guaranteed
                // to be pure `\s`, no tabs) collapses to `len / width` tabs
                // — floor division, per rubocop's own rounding-down test.
                vec![b'\t'; matched.len() / width]
            };
            self.fixes.push((s, match_end, replacement));
        }
    }
}

/// Ruby's `\s`: space, tab, CR, LF, form feed, vertical tab. `\n` can't
/// occur within a single line's slice, but the others can (`\r` on CRLF
/// sources, rare `\f`/`\v`).
fn is_ruby_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | 0x0C | 0x0B)
}

/// The closed form of `/\A\s*\t+/` (style spaces) / `/\A\s* +/` (style
/// tabs)'s backtracking: `\s*` greedily eats the whole leading-whitespace
/// run, then the engine backs it off one character at a time until the
/// trailing quantifier (one-or-more of the target byte) can match — which
/// happens at the LAST occurrence of the target byte in the run (nothing to
/// its right can be a further occurrence, by definition of "last"). So the
/// match is always `[0, last_target_index]` inclusive — never extending
/// past the target into trailing whitespace of a different kind. Returns
/// the match's byte length, or `None` when the leading run has no such
/// byte at all (rubocop's `match` returning nil).
fn find_offense_match(line: &[u8], tabs_style: bool) -> Option<usize> {
    let ws_end = line.iter().position(|&b| !is_ruby_ws(b)).unwrap_or(line.len());
    let target = if tabs_style { b' ' } else { b'\t' };
    line[..ws_end].iter().rposition(|&b| b == target).map(|p| p + 1)
}


impl<'a> super::Cops<'a> {
    /// Layout/ParameterAlignment — checks that the parameters of a
    /// multi-line method definition (`def`/`defs`, a single prism
    /// `DefNode` with an optional `receiver` covering both) are aligned: to
    /// the first parameter's own column (`EnforcedStyle: with_first_parameter`,
    /// the default), or to the `def` line's own indentation plus one
    /// configured indentation step (`with_fixed_indentation`). Ports
    /// rubocop's `ParameterAlignment` cop + the shared `Alignment` mixin's
    /// `check_alignment`/`each_bad_alignment`/`register_offense`, and the
    /// `AlignmentCorrector` autocorrector.
    ///
    /// `on_def` (aliased `on_defs`) bails out when there are fewer than 2
    /// parameters (`node.arguments.size < 2` — nothing to misalign). The
    /// individual parameter nodes come from `mlbl_ordered_params`, which
    /// walks prism's `ParametersNode` fields in Ruby's fixed grammar order
    /// (requireds, optionals, rest, posts, keywords, keyword_rest, block) —
    /// identical to their source order, since Ruby's own grammar enforces
    /// that ordering textually too. (Not covered: a bare `...` forwarding
    /// parameter, which prism represents outside these fields entirely, and
    /// which the fixture never exercises.)
    ///
    /// `each_bad_alignment`'s core loop: walking the params in order, only a
    /// parameter that (a) starts a NEW source line relative to the previous
    /// param's line, and (b) is the first non-whitespace token on that line
    /// (`begins_its_line?`, replicated as an all-whitespace scan from the
    /// line start) is a candidate; its bad-alignment `column_delta` is
    /// `base_column - display_column(param)` (the Unicode East-Asian-Width-
    /// aware column, via the shared `display_column` helper). A zero delta
    /// is fine; otherwise it's an offense anchored at the parameter's own
    /// start (matching `current.source_range`'s begin — e.g. the `*` of a
    /// splat, not just the identifier after it).
    ///
    /// NOT ported: `Alignment#check_alignment`'s `@current_offenses`
    /// overlap guard (registers the offense without autocorrecting when its
    /// range falls inside an offense already added earlier in THIS SAME
    /// investigation). It only matters when one parameter's own range
    /// (e.g. a multi-line default value) swallows a later line that also
    /// starts a misaligned parameter — no fixture example has a multi-line
    /// parameter, so it's unobservable here.
    pub(crate) fn check_parameter_alignment(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/ParameterAlignment";
        if !self.on(COP) {
            return;
        }
        let Some(params) = node.parameters() else { return };
        let items = mlbl_ordered_params(&params);
        if items.len() < 2 {
            return;
        }
        let fixed_indentation = self.cfg.enforced_style(COP) == "with_fixed_indentation";
        let base = if fixed_indentation {
            let kw_start = node.def_keyword_loc().start_offset();
            let (line, _) = self.idx.loc(kw_start);
            let line_start = self.idx.starts[line - 1];
            let mut p = line_start;
            while p < self.src.len() && self.src[p].is_ascii_whitespace() {
                p += 1;
            }
            let indentation_of_line = p - line_start;
            indentation_of_line + self.parameter_alignment_indentation_width(COP)
        } else {
            self.display_column(items[0].location().start_offset())
        };
        let mut prev_line: Option<usize> = None;
        for item in &items {
            let start = item.location().start_offset();
            let (line, _) = self.idx.loc(start);
            let starts_new_line = prev_line.map_or(true, |p| line > p);
            if starts_new_line {
                let line_start = self.idx.starts[line - 1];
                let begins_its_line = self.src[line_start..start].iter().all(u8::is_ascii_whitespace);
                if begins_its_line {
                    let actual = self.display_column(start);
                    if actual != base {
                        let delta = base as isize - actual as isize;
                        let msg = if fixed_indentation {
                            "Use one level of indentation for parameters following the first line of a multi-line method definition."
                        } else {
                            "Align the parameters of a method definition if they span more than one line."
                        };
                        self.push(start, COP, true, msg);
                        let end = item.location().end_offset();
                        self.parameter_alignment_correct(start, end, delta);
                    }
                }
            }
            prev_line = Some(line);
        }
    }

    /// `AlignmentCorrector.correct`'s per-line loop, specialized to the
    /// single misaligned parameter node (upstream's `autocorrect(corrector,
    /// node)` always gets the one bad parameter, never the whole list).
    /// Walks each physical line the parameter's own source spans (almost
    /// always just one — no fixture parameter is multi-line), starting at
    /// the node's OWN begin offset (not the physical line's start) for line
    /// 1, then at each subsequent line's true start: widening (`delta > 0`)
    /// inserts `delta` spaces immediately before that position; narrowing
    /// removes `-delta` bytes, taken from the run starting at that position
    /// if it itself is a space (an interior line's own leading whitespace)
    /// or from just before it otherwise (the gap between the previous token
    /// and the node's own start, on line 1). Skips a would-be removal whose
    /// bytes aren't purely spaces/tabs (`/\A[ \t]+\z/`), matching upstream
    /// leaving such a case uncorrected.
    fn parameter_alignment_correct(&mut self, start: usize, end: usize, delta: isize) {
        if delta == 0 {
            return;
        }
        let mut line_begin = start;
        loop {
            if delta > 0 {
                if self.src.get(line_begin) != Some(&b'\n') {
                    self.fixes.push((line_begin, line_begin, vec![b' '; delta as usize]));
                }
            } else {
                let n = (-delta) as usize;
                let starts_with_space = self.src.get(line_begin) == Some(&b' ');
                let (rs, re) = if starts_with_space { (line_begin, line_begin + n) } else { (line_begin.saturating_sub(n), line_begin) };
                if re <= self.src.len() && rs < re && self.src[rs..re].iter().all(|&b| b == b' ' || b == b'\t') {
                    self.fixes.push((rs, re, Vec::new()));
                }
            }
            // Advance to the next physical line within [start, end), if any.
            let mut p = line_begin;
            while p < end && self.src[p] != b'\n' {
                p += 1;
            }
            if p >= end {
                break;
            }
            line_begin = p + 1;
        }
    }

    /// `Alignment#configured_indentation_width`: cop-local `IndentationWidth`
    /// (no schema default for this cop — meaningful only when a user sets it
    /// directly), else `Layout/IndentationWidth`'s `Width` (schema default 2).
    fn parameter_alignment_indentation_width(&self, cop: &'static str) -> usize {
        self.cfg
            .get(cop, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }
}


impl<'a> Cops<'a> {
    /// Layout/SpaceBeforeBlockBraces — verbatim port of `on_block`/`check_empty`/
    /// `check_non_empty`. Shared by brace blocks (`ruby_prism::BlockNode`, which
    /// covers `{}`, numbered-param, and `it`-param blocks alike — prism doesn't
    /// split those into separate node kinds) AND stabby lambda literals
    /// (`ruby_prism::LambdaNode`), since rubocop's own Prism translator rewrites
    /// a `LambdaNode` into the very same "block whose send is `lambda`" `:block`
    /// shape it uses for `lambda do...end` — `on_block` fires on both alike.
    /// Both node kinds expose plain (non-`Option`) `opening_loc`/`closing_loc`.
    pub(crate) fn check_space_before_block_braces<'x>(
        &mut self,
        opening: &ruby_prism::Location<'x>,
        closing: &ruby_prism::Location<'x>,
    ) {
        const COP: &str = "Layout/SpaceBeforeBlockBraces";
        if !self.on(COP) {
            return;
        }
        // `node.keywords?`: `do`...`end` blocks never take this cop's brace-space
        // rule — only the `{`-opened form does.
        if opening.as_slice() != b"{" {
            return;
        }
        const MISSING_MSG: &str = "Space missing to the left of {.";
        const DETECTED_MSG: &str = "Space detected to the left of {.";

        let left_brace = opening.start_offset();
        let closing_start = closing.start_offset();
        let no_space_style = self.cfg.get(COP, "EnforcedStyle") == Some("no_space");

        // `conflict_with_block_delimiters?`: no_space + a multiline brace block
        // would fight Style/BlockDelimiters' `line_count_based` autocorrection —
        // rubocop silently skips the offense rather than register one that
        // autocorrection would immediately re-break.
        if no_space_style {
            let block_delimiters_line_count_based =
                self.cfg.get("Style/BlockDelimiters", "EnforcedStyle").unwrap_or("line_count_based")
                    == "line_count_based";
            if block_delimiters_line_count_based {
                let open_line = self.idx.loc(left_brace).0;
                let close_line = self.idx.loc(closing_start).0;
                if open_line != close_line {
                    return;
                }
            }
        }

        // `range_with_surrounding_space(left_brace)` (defaults: side: :both,
        // newlines: true, whitespace: false, continuations: false) — only the
        // LEFT expansion is ever read (`space_plus_brace.begin_pos`), so we only
        // need to replicate that half: skip a run of spaces/tabs immediately
        // before `{`, then (from wherever that stops) a run of newlines. Unlike
        // a plain `\s*` scan, indentation on the line above a lone `\n{` is
        // NOT re-consumed after the newline run (the generic-whitespace pass is
        // disabled by default) — this loop mirrors that exact ordering.
        let src = self.src;
        let mut pos = left_brace;
        while pos > 0 && matches!(src[pos - 1], b' ' | b'\t') {
            pos -= 1;
        }
        while pos > 0 && src[pos - 1] == b'\n' {
            pos -= 1;
        }
        let space_begin = pos;
        let used_style_space = space_begin != left_brace;

        // `empty_braces?`: `loc.begin.end_pos == loc.end.begin_pos` — nothing
        // (not even a space) between `{` and `}`.
        let empty_braces = opening.end_offset() == closing_start;

        if empty_braces {
            // `style_for_empty_braces`: explicit space/no_space, or (if the key
            // is truly absent — only possible under `__replace_defaults__`)
            // fall back to the main `style`.
            let style_empty_space = match self.cfg.get(COP, "EnforcedStyleForEmptyBraces") {
                Some("no_space") => false,
                Some("space") => true,
                _ => !no_space_style,
            };
            if style_empty_space == used_style_space {
                return; // `handle_different_styles_for_empty_braces` — no offense either way
            }
            if style_empty_space {
                // range = left_brace, msg = MISSING_MSG; autocorrect: source is
                // "{" (not `\s`) -> `insert_before` a space.
                self.push(left_brace, COP, true, MISSING_MSG);
                self.fixes.push((left_brace, left_brace, b" ".to_vec()));
            } else {
                // range = [space_begin, left_brace), msg = DETECTED_MSG;
                // autocorrect: source is whitespace -> remove it.
                self.push(space_begin, COP, true, DETECTED_MSG);
                self.fixes.push((space_begin, left_brace, Vec::new()));
            }
            return;
        }

        // `check_non_empty`/`case used_style; when style ... when :space ...
        // else ...`.
        let target_style_space = !no_space_style;
        if used_style_space == target_style_space {
            return; // `correct_style_detected` — no offense
        }
        if used_style_space {
            // `space_detected`
            self.push(space_begin, COP, true, DETECTED_MSG);
            self.fixes.push((space_begin, left_brace, Vec::new()));
        } else {
            // `space_missing`
            self.push(left_brace, COP, true, MISSING_MSG);
            self.fixes.push((left_brace, left_brace, b" ".to_vec()));
        }
    }
}


/// Layout/SpaceAroundKeyword — every hook lives in `mod.rs`'s `visit_*`
/// overrides (one per keyword-bearing node type rubocop's cop dispatches
/// on: `on_and`/`on_or`/`on_if`(+`unless`)/`on_case`(+`case_match`)/
/// `on_when`/`on_in_pattern`/`on_match_pattern_p`/`on_ensure`/`on_for`/
/// `on_kwbegin`/`on_block`(+numblock/itblock)/`on_break`/`on_next`/
/// `on_return`/`on_yield`/`on_super`/`on_zsuper`/`on_defined?`/`on_send`
/// (`not`)/`on_resbody`/`on_rescue`/`on_postexe`/`on_preexe`/`on_while`/
/// `on_until`); this impl holds the actual `check`/`check_keyword`/
/// `check_begin`/`check_end`/`space_before_missing?`/`space_after_missing?`/
/// `preceded_by_operator?` port.
impl<'a> Cops<'a> {
    const SAK_COP: &'static str = "Layout/SpaceAroundKeyword";

    const SAK_ACCEPT_LEFT_PAREN: [&'static [u8]; 7] =
        [b"break", b"defined?", b"next", b"not", b"rescue", b"super", b"yield"];
    const SAK_ACCEPT_LEFT_BRACKET: [&'static [u8]; 2] = [b"super", b"yield"];

    /// rubocop-ast's `MethodIdentifierPredicates::OPERATOR_METHODS`.
    fn sak_is_operator_method(name: &[u8]) -> bool {
        matches!(
            name,
            b"|" | b"^" | b"&" | b"<=>" | b"==" | b"===" | b"=~" | b">" | b">=" | b"<" | b"<="
                | b"<<" | b">>" | b"+" | b"-" | b"*" | b"/" | b"%" | b"**" | b"~" | b"+@" | b"-@"
                | b"!@" | b"~@" | b"[]" | b"[]=" | b"!" | b"!=" | b"!~" | b"`"
        )
    }

    /// Classifies a node for `sak_preceded_by_operator`'s ancestor climb —
    /// rubocop's `preceded_by_operator?`:
    /// ```ruby
    /// node.each_ancestor do |ancestor|
    ///   return true if ancestor.operator_keyword? || ancestor.range_type?
    ///   return false unless ancestor.send_type?
    ///   return true if ancestor.operator_method?
    /// end
    /// false
    /// ```
    /// 1 = `and`/`or` (`operator_keyword?` — true for the TYPE regardless of
    /// `&&`/`and` spelling) or a range literal (`range_type?`) — climb
    /// ACCEPTS. 2 = a `send`/`csend` whose method IS an operator method —
    /// also ACCEPTS. 3 = any other `send`/`csend` — "regular dotted method
    /// calls bind more tightly than operators", so the climb continues PAST
    /// it. 0 = anything else — the first non-send ancestor REJECTS outright.
    pub(crate) fn sak_classify(node: &ruby_prism::Node) -> u8 {
        if node.as_and_node().is_some() || node.as_or_node().is_some() || node.as_range_node().is_some() {
            return 1;
        }
        if let Some(call) = node.as_call_node() {
            return if Self::sak_is_operator_method(call.name().as_slice()) { 2 } else { 3 };
        }
        0
    }

    /// The climb starts at the checked node's PARENT — `sak_ancestors`'
    /// TOP entry is the node currently being visited (pushed on entry by
    /// `visit_branch_node_enter`/`visit_leaf_node_enter`), so skip it first.
    fn sak_preceded_by_operator(&self) -> bool {
        let mut it = self.sak_ancestors.iter().rev();
        it.next();
        for &k in it {
            match k {
                1 | 2 => return true,
                3 => continue,
                _ => return false,
            }
        }
        false
    }

    /// rubocop's `space_before_missing?`: the byte immediately before the
    /// keyword's start isn't one of `[\s(|{\[;,*=]`.
    fn sak_space_before_missing(&self, start: usize) -> bool {
        if start == 0 {
            return false;
        }
        !matches!(
            self.src[start - 1],
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | b'(' | b'|' | b'{' | b'[' | b';' | b',' | b'*' | b'='
        )
    }

    /// rubocop's `space_after_missing?`: EOF is treated as accepted
    /// (`accepted_opening_delimiter?` returns true when `char` is nil), then
    /// the `[`/`(` opening-delimiter exceptions (`ACCEPT_LEFT_SQUARE_BRACKET`
    /// / `ACCEPT_LEFT_PAREN`, keyed off the exact keyword text), then the
    /// unconditional `&.` safe-navigation and (for `super` only) `::`
    /// namespace-operator exceptions, then the general
    /// `[\s;,#\\)}\].]` allowlist.
    fn sak_space_after_missing(&self, end: usize, kw: &[u8]) -> bool {
        let Some(&ch) = self.src.get(end) else { return false };
        if Self::SAK_ACCEPT_LEFT_BRACKET.contains(&kw) && ch == b'[' {
            return false;
        }
        if Self::SAK_ACCEPT_LEFT_PAREN.contains(&kw) && ch == b'(' {
            return false;
        }
        if ch == b'&' && self.src.get(end + 1) == Some(&b'.') {
            return false;
        }
        if kw == b"super" && ch == b':' && self.src.get(end + 1) == Some(&b':') {
            return false;
        }
        !matches!(
            ch,
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | b';' | b',' | b'#' | b'\\' | b')' | b'}' | b']' | b'.'
        )
    }

    /// rubocop's `check_keyword`: full before+after check for a keyword or
    /// operator range. `kw` is the range's exact source text — the message
    /// interpolates it verbatim (`range.source`), and it's also the lookup
    /// key for the paren/bracket/namespace-operator exceptions.
    pub(crate) fn sak_check(&mut self, start: usize, end: usize, kw: &[u8]) {
        if !self.on(Self::SAK_COP) {
            return;
        }
        let kw_str = String::from_utf8_lossy(kw);
        if self.sak_space_before_missing(start) && !self.sak_preceded_by_operator() {
            self.push(start, Self::SAK_COP, true, format!("Space before keyword `{kw_str}` is missing."));
            self.fixes.push((start, start, b" ".to_vec()));
        }
        if self.sak_space_after_missing(end, kw) {
            self.push(start, Self::SAK_COP, true, format!("Space after keyword `{kw_str}` is missing."));
            self.fixes.push((end, end, b" ".to_vec()));
        }
    }

    /// rubocop's `check_end`: before-ONLY (no after-check, and no
    /// `preceded_by_operator?` guard either — `check_end` never calls it).
    /// Deduped by offset: an `elsif` chain's nested `IfNode`s (and an
    /// `UnlessNode`'s `else_clause`-less `end`) all report the outer `if`'s
    /// SAME `end_keyword_loc` in prism; rubocop's own `Base#add_offense`
    /// collapses the repeat visits onto one offense via range-identity —
    /// `sak_end_seen` reproduces that explicitly since we have no such
    /// range-dedup layer.
    pub(crate) fn sak_check_end(&mut self, start: usize, kw: &[u8]) {
        if !self.on(Self::SAK_COP) {
            return;
        }
        if !self.sak_end_seen.insert(start) {
            return;
        }
        if self.sak_space_before_missing(start) {
            self.push(start, Self::SAK_COP, true, format!("Space before keyword `{}` is missing.", String::from_utf8_lossy(kw)));
            self.fixes.push((start, start, b" ".to_vec()));
        }
    }
}


/// Layout/SpaceInsideParens collects every REAL round-paren token in the
/// file — upstream scans `processed_source.sorted_tokens` (a lexer token
/// stream), which we don't have; instead we walk the AST once and pull the
/// paren locations off every node kind that can own a literal `(`/`)` pair:
/// grouping (`ParenthesesNode`), call argument parens, `def`/`defined?`/
/// `super`/`yield` parens, `(a, b)` multi-target/-write parens, a lambda's
/// `BlockParametersNode` (`->(x) {}`), and a pattern-match pin (`^(expr)`).
/// Each is guarded by an `as_slice() == "("/")" ` check so lookalikes that
/// share the same `opening_loc`/`closing_loc` fields but are NOT `tLPAREN`/
/// `tRPAREN` tokens upstream — `[]`/`[]=` index calls (bracket), block
/// params written with pipes (`|...|`) — never get mistaken for real paren
/// tokens. String/regexp/percent-literal delimiters (which can also be `(`/
/// `)`, e.g. `%(...)`) are never visited here at all, since none of those
/// node kinds are in this list.
#[derive(Default)]
struct SipParenFinder {
    opens: Vec<usize>,
    closes: Vec<usize>,
}
impl SipParenFinder {
    fn add_pair(&mut self, open: ruby_prism::Location, close: ruby_prism::Location) {
        if open.as_slice() == b"(" && close.as_slice() == b")" {
            self.opens.push(open.start_offset());
            self.closes.push(close.start_offset());
        }
    }
}
impl<'pr> ruby_prism::Visit<'pr> for SipParenFinder {
    fn visit_parentheses_node(&mut self, node: &ruby_prism::ParenthesesNode<'pr>) {
        self.add_pair(node.opening_loc(), node.closing_loc());
        ruby_prism::visit_parentheses_node(self, node);
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if let (Some(o), Some(c)) = (node.opening_loc(), node.closing_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_call_node(self, node);
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let (Some(o), Some(c)) = (node.lparen_loc(), node.rparen_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_def_node(self, node);
    }
    fn visit_defined_node(&mut self, node: &ruby_prism::DefinedNode<'pr>) {
        if let (Some(o), Some(c)) = (node.lparen_loc(), node.rparen_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_defined_node(self, node);
    }
    fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
        if let (Some(o), Some(c)) = (node.lparen_loc(), node.rparen_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_super_node(self, node);
    }
    fn visit_yield_node(&mut self, node: &ruby_prism::YieldNode<'pr>) {
        if let (Some(o), Some(c)) = (node.lparen_loc(), node.rparen_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_yield_node(self, node);
    }
    fn visit_multi_target_node(&mut self, node: &ruby_prism::MultiTargetNode<'pr>) {
        if let (Some(o), Some(c)) = (node.lparen_loc(), node.rparen_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_multi_target_node(self, node);
    }
    fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
        if let (Some(o), Some(c)) = (node.lparen_loc(), node.rparen_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_multi_write_node(self, node);
    }
    fn visit_block_parameters_node(&mut self, node: &ruby_prism::BlockParametersNode<'pr>) {
        if let (Some(o), Some(c)) = (node.opening_loc(), node.closing_loc()) {
            self.add_pair(o, c);
        }
        ruby_prism::visit_block_parameters_node(self, node);
    }
    fn visit_pinned_expression_node(&mut self, node: &ruby_prism::PinnedExpressionNode<'pr>) {
        self.add_pair(node.lparen_loc(), node.rparen_loc());
        ruby_prism::visit_pinned_expression_node(self, node);
    }
}

/// Skip a run of ASCII whitespace forward from `pos`; returns the resulting
/// position and whether a `\n` was among the skipped bytes (upstream's
/// `same_line?`, inverted).
fn sip_skip_ws_forward(src: &[u8], mut pos: usize) -> (usize, bool) {
    let mut crossed_nl = false;
    while pos < src.len() && src[pos].is_ascii_whitespace() {
        if src[pos] == b'\n' {
            crossed_nl = true;
        }
        pos += 1;
    }
    (pos, crossed_nl)
}

/// Same as `sip_skip_ws_forward`, but backward: `pos` is an exclusive upper
/// bound, and the result is the (still exclusive) position right after the
/// nearest preceding non-whitespace byte.
fn sip_skip_ws_backward(src: &[u8], mut pos: usize) -> (usize, bool) {
    let mut crossed_nl = false;
    while pos > 0 && src[pos - 1].is_ascii_whitespace() {
        if src[pos - 1] == b'\n' {
            crossed_nl = true;
        }
        pos -= 1;
    }
    (pos, crossed_nl)
}

impl<'a> Cops<'a> {
    /// Layout/SpaceInsideParens — verbatim port of the upstream token-pair
    /// scan (`on_new_investigation`/`correct_extraneous_space`/
    /// `process_with_space_style`/`process_with_compact_style`, all walking
    /// `processed_source.sorted_tokens` two at a time). We don't have a real
    /// token stream, so this instead collects every real paren TOKEN once
    /// (`SipParenFinder`, see above) and, for each one, walks outward to its
    /// real neighboring token via `sip_skip_ws_forward`/`_backward` — safe
    /// because upstream's `Token#space_after?`/`#space_before?` only ever
    /// peek at the ONE byte just past a token's edge, and real tokens are
    /// never separated by anything but whitespace (a comment or another
    /// token would BE the neighbor, not something further away): so "is
    /// there a gap" collapses exactly to "did whitespace-skipping move".
    ///
    /// Every paren is checked in exactly one direction to avoid double-
    /// counting a shared gap between two adjacent parens: opens always look
    /// RIGHTWARD (the pair is always `parens?`-relevant since `token1.
    /// left_parens?`); closes look RIGHTWARD too, but ONLY act when that
    /// lands on another close (the `))`-style double-close pair, relevant
    /// via `token2.right_parens?` — that pair's `token1` is the FIRST close,
    /// never producible by scanning outward from an open), and closes also
    /// look LEFTWARD (the primary "space before `)`" check), but that scan
    /// is skipped whenever the left neighbor is itself a collected paren
    /// (open or close) — that gap was already handled from the OTHER
    /// paren's rightward scan.
    pub(crate) fn check_space_inside_parens(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Layout/SpaceInsideParens";
        if !self.on(COP) {
            return;
        }
        let mut finder = SipParenFinder::default();
        ruby_prism::visit_program_node(&mut finder, node);
        let SipParenFinder { mut opens, mut closes } = finder;
        opens.sort_unstable();
        opens.dedup();
        closes.sort_unstable();
        closes.dedup();
        let open_set: std::collections::HashSet<usize> = opens.iter().copied().collect();
        let close_set: std::collections::HashSet<usize> = closes.iter().copied().collect();
        let src = self.src;
        let style = self.cfg.enforced_style(COP);
        const MSG: &str = "Space inside parentheses detected.";
        const MSG_SPACE: &str = "No space inside parentheses detected.";

        for &o in &opens {
            let end = o + 1;
            let (f, crossed_nl) = sip_skip_ws_forward(src, end);
            let has_gap = f > end;
            let is_comment = src.get(f) == Some(&b'#');
            let is_close = close_set.contains(&f);
            let is_open2 = open_set.contains(&f);
            let same_line = !crossed_nl;

            if is_close {
                // Adjacent open→close pair: `correct_extraneous_space_in_
                // empty_parens` (space/compact — no `same_line?` check, it
                // only compares the literal joined source to `"()"`) vs.
                // the general no_space rule (DOES require `same_line?`).
                let offense = if style == "space" || style == "compact" { has_gap } else { same_line && has_gap };
                if offense {
                    self.push(end, COP, true, MSG);
                    self.fixes.push((end, f, Vec::new()));
                }
                continue;
            }
            if style == "compact" && is_open2 {
                // Two adjacent opens under `compact`
                // (`correct_extraneous_space_between_consecutive_parens`) —
                // upstream only fixes when the gap is EXACTLY one plain
                // space character; anything else (incl. 0, tabs, newlines,
                // 2+ spaces) is left alone.
                if has_gap && f == end + 1 && src[end] == b' ' {
                    self.push(end, COP, true, MSG);
                    self.fixes.push((end, f, Vec::new()));
                }
                continue;
            }
            match style {
                "space" | "compact" => {
                    if is_comment {
                        continue;
                    }
                    if same_line && !has_gap {
                        self.push(end, COP, true, MSG_SPACE);
                        self.fixes.push((end, end, b" ".to_vec()));
                    }
                }
                _ => {
                    if !is_comment && same_line && has_gap {
                        self.push(end, COP, true, MSG);
                        self.fixes.push((end, f, Vec::new()));
                    }
                }
            }
        }

        for &o in &closes {
            // Rightward: only ever relevant when it lands on ANOTHER close
            // (double-close adjacency) — a close followed by anything else
            // is never `parens?`-relevant upstream.
            let end = o + 1;
            let (f2, crossed_nl2) = sip_skip_ws_forward(src, end);
            let has_gap2 = f2 > end;
            let is_close2 = close_set.contains(&f2);
            let same_line2 = !crossed_nl2;
            if is_close2 {
                match style {
                    "compact" => {
                        if has_gap2 && f2 == end + 1 && src[end] == b' ' {
                            self.push(end, COP, true, MSG);
                            self.fixes.push((end, f2, Vec::new()));
                        }
                    }
                    "space" => {
                        if same_line2 && !has_gap2 {
                            self.push(f2, COP, true, MSG_SPACE);
                            self.fixes.push((f2, f2, b" ".to_vec()));
                        }
                    }
                    _ => {
                        if same_line2 && has_gap2 {
                            self.push(end, COP, true, MSG);
                            self.fixes.push((end, f2, Vec::new()));
                        }
                    }
                }
            }

            // Leftward: the primary "space before `)`" check — skipped when
            // the left neighbor is itself a collected paren, since that gap
            // was already handled above from THAT paren's rightward scan.
            let (b, crossed_nl) = sip_skip_ws_backward(src, o);
            let has_gap_l = b < o;
            let left_is_paren = b > 0 && (open_set.contains(&(b - 1)) || close_set.contains(&(b - 1)));
            if left_is_paren {
                continue;
            }
            let same_line_l = !crossed_nl;
            match style {
                "space" | "compact" => {
                    if same_line_l && !has_gap_l {
                        self.push(o, COP, true, MSG_SPACE);
                        self.fixes.push((o, o, b" ".to_vec()));
                    }
                }
                _ => {
                    if same_line_l && has_gap_l {
                        self.push(b, COP, true, MSG);
                        self.fixes.push((b, o, Vec::new()));
                    }
                }
            }
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/FirstParameterIndentation — checks the indentation of the
    /// first parameter of a multi-line `def`/`defs` (a single prism
    /// `DefNode`, with or without a `receiver`, covers both — matching
    /// rubocop's `on_def`/`alias on_defs`). Ports `on_def`/`check` plus the
    /// shared `MultilineElementIndentation#check_first`, called from
    /// `check` as `check_first(first_elem, left_parenthesis, nil, 0)` —
    /// i.e. `left_brace = left_parenthesis` (the def's own opening paren),
    /// `left_parenthesis = nil`, `offset = 0`.
    ///
    /// Passing `nil` for `left_parenthesis` makes two branches of
    /// `MultilineElementIndentation#indent_base`/`detected_styles_for_column`
    /// permanently dead for this call site: the `special_inside_parentheses`
    /// branch (guarded on that argument being truthy — and this cop's
    /// `SupportedStyles`, `consistent`/`align_parentheses`, never include
    /// `special_inside_parentheses` anyway, so `style` could never equal it
    /// either) is skipped entirely, leaving only the `align_parentheses`
    /// ("the position of the opening parenthesis") and the fallback
    /// "start of the line where the left parenthesis is" bases.
    ///
    /// NOT ported: `indent_base`'s `hash_pair_where_value_beginning_with`
    /// check — `first_elem.parent` is always the `ParametersNode` here, and
    /// ITS parent is the `DefNode` itself, never a `pair_type?` node, so
    /// that branch is unreachable for this cop (it matters only for
    /// `Layout/First{Hash,Array}ElementIndentation`, which reuse the same
    /// mixin for literal elements, not method definitions). Also not
    /// ported: `ConfigurableEnforcedStyle`'s `detected_style`/
    /// `ambiguous_style_detected` bookkeeping — it only feeds
    /// `--auto-gen-config` and never affects whether an offense is
    /// registered or how autocorrect behaves.
    ///
    /// Autocorrect reuses `parameter_alignment_correct` (Layout/
    /// ParameterAlignment's port of `AlignmentCorrector.correct`
    /// specialized to a single misaligned node) verbatim — upstream's
    /// `autocorrect` here is the exact same one-liner,
    /// `AlignmentCorrector.correct(corrector, processed_source, node,
    /// @column_delta)`.
    pub(crate) fn check_first_parameter_indentation(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/FirstParameterIndentation";
        if !self.on(COP) {
            return;
        }
        // `node.arguments.empty?`
        let items = match node.parameters() {
            Some(p) => mlbl_ordered_params(&p),
            None => Vec::new(),
        };
        if items.is_empty() {
            return;
        }
        // `node.arguments.loc.begin.nil?` — defs called without parentheses
        // (`def abc foo, bar`) are ignored entirely.
        let Some(lparen) = node.lparen_loc() else { return };
        let left_paren_start = lparen.start_offset();
        let first = &items[0];
        let first_start = first.location().start_offset();
        let first_end = first.location().end_offset();

        let (paren_line, _) = self.idx.loc(left_paren_start);
        let (first_line, _) = self.idx.loc(first_start);
        // `same_line?(first_elem, left_parenthesis)`
        if first_line == paren_line {
            return;
        }

        let align_parentheses = self.cfg.enforced_style(COP) == "align_parentheses";
        let paren_line_start = self.idx.starts[paren_line - 1];
        let (base_column, base_description): (usize, &'static str) = if align_parentheses {
            (left_paren_start - paren_line_start, "the position of the opening parenthesis")
        } else {
            // `left_brace.source_line =~ /\S/` — the column of the first
            // non-whitespace byte on the line containing the opening paren.
            let mut p = paren_line_start;
            while p < self.src.len() && matches!(self.src[p], b' ' | b'\t') {
                p += 1;
            }
            (p - paren_line_start, "the start of the line where the left parenthesis is")
        };

        // `Alignment#configured_indentation_width`, shared verbatim with
        // Layout/ParameterAlignment's own identical fallback chain.
        let indentation_width = self.parameter_alignment_indentation_width(COP);
        let expected_column = base_column + indentation_width;
        let first_line_start = self.idx.starts[first_line - 1];
        let actual_column = first_start - first_line_start;

        if expected_column == actual_column {
            return;
        }

        self.push(
            first_start,
            COP,
            true,
            format!(
                "Use {indentation_width} spaces for indentation in method args, relative to {base_description}."
            ),
        );
        let delta = expected_column as isize - actual_column as isize;
        self.parameter_alignment_correct(first_start, first_end, delta);
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/EmptyLinesAroundArguments — flags a blank line sitting
    /// directly inside a multi-line call's argument list: right before any
    /// argument's own start, or right before the closing `)`. Mirrors
    /// rubocop's `on_send`/`extra_lines`/`empty_range_for_starting_point`
    /// verbatim.
    ///
    /// Both `.` and `&.` sends are the same prism `CallNode` (no separate
    /// `csend`), so a single hook covers rubocop's `on_send`/`alias on_csend`
    /// pair.
    ///
    /// The whole thing is a pure byte/line scan over the raw source text —
    /// exactly like rubocop's own `RangeHelp#range_with_surrounding_space`,
    /// which walks the buffer's characters, not the AST — so nested blank
    /// lines (inside a literal argument, a block body, or a heredoc body)
    /// are naturally exempt: the backward scan from each anchor point always
    /// stops at the nearest non-whitespace byte, which is that argument's
    /// own last token, never reaching past it into nested content. A
    /// heredoc's own `StringNode` location in prism covers only its opening
    /// token line (`<<~TAG`), never its body/terminator, so a call whose
    /// only argument is a heredoc (`bar(<<-DOCS)`) is `single_line?` and
    /// skipped outright — matching rubocop's real (non-heredoc-aware)
    /// source for this cop.
    pub(crate) fn check_empty_lines_around_arguments(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/EmptyLinesAroundArguments";
        if !self.on(COP) {
            return;
        }
        let loc = node.location();
        let first_line = self.idx.loc(loc.start_offset()).0;
        let last_line = self.idx.loc(loc.end_offset()).0;
        if first_line == last_line {
            return; // `node.single_line?`
        }
        let Some(args) = node.arguments() else { return };
        let arg_list: Vec<_> = args.arguments().iter().collect();
        if arg_list.is_empty() {
            return;
        }
        // `receiver_and_method_call_on_different_lines?`: skip when there's
        // a receiver whose own last line differs from the selector's line —
        // a bare `nil&.line` selector (e.g. `foo.(args)`, no method name
        // token) always counts as "different".
        if let Some(receiver) = node.receiver() {
            let recv_last_line = self.idx.loc(receiver.location().end_offset()).0;
            let same_line = node
                .message_loc()
                .is_some_and(|m| self.idx.loc(m.start_offset()).0 == recv_last_line);
            if !same_line {
                return;
            }
        }
        for arg in &arg_list {
            self.elaa_check_starting_point(arg.location().start_offset());
        }
        if let Some(closing) = node.closing_loc() {
            self.elaa_check_starting_point(closing.start_offset());
        }
    }

    /// `empty_range_for_starting_point`: scan backward from `start` over a
    /// `\s` run (rubocop's `range_with_surrounding_space(..., whitespace:
    /// true, side: :left)` — spaces, tabs, and newlines all fold into one
    /// walk). If that run crosses more than one line boundary, the line
    /// just above `start`'s own line is a blank (or whitespace-only) line
    /// sitting inside the call's argument list — flag it and remove it
    /// whole (content plus its own trailing newline), same as rubocop's
    /// `corrector.remove(range)` on `source_buffer.line_range(last_line -
    /// 1).adjust(end_pos: 1)`.
    fn elaa_check_starting_point(&mut self, start: usize) {
        const COP: &str = "Layout/EmptyLinesAroundArguments";
        let mut begin = start;
        while begin > 0 && is_elaa_ws(self.src[begin - 1]) {
            begin -= 1;
        }
        let first_line = self.idx.loc(begin).0;
        let last_line = self.idx.loc(start).0;
        if last_line <= first_line + 1 {
            return;
        }
        let blank_line = last_line - 1;
        let line_start = self.idx.starts[blank_line - 1];
        let line_end = self.idx.starts.get(blank_line).copied().unwrap_or_else(|| self.line_end(blank_line));
        self.push(line_start, COP, true, "Empty line detected around arguments.");
        self.fixes.push((line_start, line_end, Vec::new()));
    }
}

/// Ruby's `\s` (Onigmo): space, tab, newline, CR, form feed, vertical tab —
/// the same set `range_with_surrounding_space(whitespace: true)` walks over,
/// crucially including `\n` (unlike the single-line-only `is_ruby_ws` used by
/// `IndentationStyle` above).
fn is_elaa_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x0B)
}


impl<'a> super::Cops<'a> {
    /// Layout/ArrayAlignment — checks that the elements of a multi-line
    /// array literal are aligned: to the first element's own column
    /// (`EnforcedStyle: with_first_element`, the default), or to the
    /// enclosing line's own indentation plus one configured indentation
    /// step (`with_fixed_indentation`). Ports rubocop's `ArrayAlignment`
    /// cop + the shared `Alignment` mixin's `check_alignment`/
    /// `each_bad_alignment`/`register_offense`, and the `AlignmentCorrector`
    /// autocorrector — see `check_parameter_alignment` above for the same
    /// mixin ported for `Layout/ParameterAlignment`. This port additionally
    /// needs two things that cop never exercises: (a) `Alignment#check_
    /// alignment`'s overlap guard (`@current_offenses`), needed because an
    /// array literal can nest inside another array literal, each getting
    /// its own `on_array` investigation; and (b) `AlignmentCorrector`'s
    /// heredoc taboo-range guard, needed because an array ELEMENT (e.g. a
    /// hash literal) can itself contain a heredoc whose body must not be
    /// re-indented as a side effect of shifting the element's own lines.
    ///
    /// `on_array` bails out when there are fewer than 2 elements
    /// (`node.children.size < 2`) or when the array IS the bare RHS value
    /// of a mass assignment (`node.parent&.masgn_type?` — prism represents
    /// `a, b = 1, 2`'s RHS as an opening-less `ArrayNode`; membership is
    /// tracked via `aa_masgn_rhs`, populated by `visit_multi_write_node`
    /// before it descends into the value).
    ///
    /// `each_bad_alignment`'s core loop: walking the elements in order,
    /// only one that (a) starts a NEW source line relative to the previous
    /// element's line, and (b) is the first non-whitespace token on that
    /// line (`begins_its_line?`) is a candidate; its bad-alignment
    /// `column_delta` is `base - display_column(element)` (the Unicode
    /// East-Asian-Width-aware column). A zero delta is fine; otherwise
    /// it's an offense anchored at the element's own start.
    pub(crate) fn check_array_alignment(&mut self, node: &ruby_prism::ArrayNode) {
        const COP: &str = "Layout/ArrayAlignment";
        if !self.on(COP) {
            return;
        }
        let items: Vec<ruby_prism::Node> = node.elements().iter().collect();
        if items.len() < 2 {
            return;
        }
        let node_start = node.location().start_offset();
        if self.aa_masgn_rhs.contains(&node_start) {
            return;
        }
        let fixed_indentation = self.cfg.enforced_style(COP) == "with_fixed_indentation";
        let base = if fixed_indentation {
            // `target_method_lineno`: `node.bracketed?` -> the array's own
            // start line; else (a bare comma-list RHS of an ordinary,
            // non-masgn assignment) the enclosing write node's own start
            // line, via `aa_unbracketed_rhs_parent` (falls back to the
            // array's own start when absent — unreached in practice, since
            // a bracketless `ArrayNode` only ever occurs as some
            // assignment's value, but kept total rather than panicking).
            let lineno_offset = if node.opening_loc().is_some() {
                node_start
            } else {
                self.aa_unbracketed_rhs_parent.get(&node_start).copied().unwrap_or(node_start)
            };
            let (line, _) = self.idx.loc(lineno_offset);
            let line_start = self.idx.starts[line - 1];
            let mut p = line_start;
            while p < self.src.len() && self.src[p].is_ascii_whitespace() {
                p += 1;
            }
            let indentation_of_line = p - line_start;
            indentation_of_line + self.aa_indentation_width(COP)
        } else {
            self.display_column(items[0].location().start_offset())
        };

        let mut prev_line: Option<usize> = None;
        for item in &items {
            let start = item.location().start_offset();
            let (line, _) = self.idx.loc(start);
            let starts_new_line = prev_line.map_or(true, |p| line > p);
            if starts_new_line {
                let line_start = self.idx.starts[line - 1];
                let begins_its_line = self.src[line_start..start].iter().all(u8::is_ascii_whitespace);
                if begins_its_line {
                    let actual = self.display_column(start);
                    if actual != base {
                        let delta = base as isize - actual as isize;
                        let end = item.location().end_offset();
                        let msg = if fixed_indentation {
                            "Use one level of indentation for elements following the first line of a multi-line array."
                        } else {
                            "Align the elements of an array literal if they span more than one line."
                        };
                        // `Alignment#check_alignment`'s overlap guard: an
                        // offense node entirely within an already-registered
                        // (necessarily enclosing) offense's range is still
                        // reported, but its correction is dropped —
                        // `register_offense(expr, nil)`, and `AlignmentCorrector
                        // .correct` no-ops on a `nil` node.
                        let within_prior =
                            self.aa_registered_ranges.iter().any(|&(rs, re)| start >= rs && end <= re);
                        self.push(start, COP, !within_prior, msg);
                        if !within_prior {
                            self.array_alignment_correct(start, end, delta);
                        }
                        self.aa_registered_ranges.push((start, end));
                    }
                }
            }
            prev_line = Some(line);
        }
    }

    /// Populates `aa_unbracketed_rhs_parent` for `target_method_lineno`'s
    /// non-`bracketed?` branch: when a plain (non-masgn) assignment's value
    /// is a bracketless `ArrayNode` (`var = 1, 2` / `var =\n  1,\n  2`),
    /// record that array's start offset -> this write node's own LHS start
    /// offset, standing in for rubocop's `node.parent.loc.line` (a plain
    /// write node's `loc.line` is the line its LHS name starts on).
    pub(crate) fn aa_note_unbracketed_rhs(&mut self, lhs_start: usize, value: &ruby_prism::Node) {
        if let Some(arr) = value.as_array_node() {
            if arr.opening_loc().is_none() {
                self.aa_unbracketed_rhs_parent.insert(arr.location().start_offset(), lhs_start);
            }
        }
    }

    /// `Alignment#configured_indentation_width`: the cop's own
    /// `IndentationWidth` (no schema default — meaningful only when a user
    /// sets it directly on this cop), else `Layout/IndentationWidth`'s
    /// `Width` (schema default 2).
    fn aa_indentation_width(&self, cop: &'static str) -> usize {
        self.cfg
            .get(cop, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }

    /// `AlignmentCorrector.correct`, ported for the single misaligned array
    /// element (upstream's `autocorrect(corrector, node)` always gets the
    /// one bad element). Walks each physical line the element's own source
    /// spans, starting at the element's OWN begin offset (not the physical
    /// line's start) for line 1, then at each subsequent line's true
    /// start: widening (`delta > 0`) inserts `delta` spaces immediately
    /// before that position; narrowing removes `-delta` bytes, taken from
    /// the run starting at that position if it's itself a space (an
    /// interior line's own leading whitespace) or from just before it
    /// otherwise (the gap between the previous token and the element's own
    /// start, on line 1). Skips a would-be removal whose bytes aren't
    /// purely spaces/tabs, matching upstream leaving such a case
    /// uncorrected.
    ///
    /// Two upstream guards ported here that `parameter_alignment_correct`
    /// never needs (no fixture parameter is multi-line or contains a
    /// heredoc): `using_tabs?` (`Layout/IndentationStyle: EnforcedStyle:
    /// tabs` disables `AlignmentCorrector` globally — the offense still
    /// fires, only the fix is suppressed) and a heredoc taboo-range guard
    /// (`inside_string_ranges`/`taboo_ranges`, restricted to the heredoc
    /// case the fixture exercises: a hash-literal array element whose
    /// value is a heredoc must have its OWN lines re-indented while the
    /// heredoc's body content and its closing delimiter line stay
    /// untouched — `self.heredoc_lines`' `(body_start_line, body_end_line,
    /// ..)` entries, extended one line further to also cover the
    /// terminator's own line). NOT ported: the non-heredoc "multi-line
    /// quoted string interior" taboo case, and `block_comment_within?` (a
    /// `=begin`/`=end` document comment inside the node disables the WHOLE
    /// correction) — neither is exercised by the fixture.
    fn array_alignment_correct(&mut self, start: usize, end: usize, delta: isize) {
        if delta == 0 {
            return;
        }
        if self.cfg.enforced_style("Layout/IndentationStyle") == "tabs" {
            return;
        }
        let mut line_begin = start;
        loop {
            let (line_no, _) = self.idx.loc(line_begin);
            let taboo = self.heredoc_lines.iter().any(|&(hs, he, _, _)| line_no >= hs && line_no <= he + 1);
            if !taboo {
                if delta > 0 {
                    if self.src.get(line_begin) != Some(&b'\n') {
                        self.fixes.push((line_begin, line_begin, vec![b' '; delta as usize]));
                    }
                } else {
                    let n = (-delta) as usize;
                    let starts_with_space = self.src.get(line_begin) == Some(&b' ');
                    let (rs, re) = if starts_with_space {
                        (line_begin, line_begin + n)
                    } else {
                        (line_begin.saturating_sub(n), line_begin)
                    };
                    if re <= self.src.len()
                        && rs < re
                        && self.src[rs..re].iter().all(|&b| b == b' ' || b == b'\t')
                    {
                        self.fixes.push((rs, re, Vec::new()));
                    }
                }
            }
            // Advance to the next physical line within [start, end), if any.
            let mut p = line_begin;
            while p < end && self.src[p] != b'\n' {
                p += 1;
            }
            if p >= end {
                break;
            }
            line_begin = p + 1;
        }
    }
}


// ============================================================================
// Layout/SpaceAroundMethodCallOperator
// ============================================================================
impl<'a> Cops<'a> {
    /// Layout/SpaceAroundMethodCallOperator — no spaces around a `.`/`&.`
    /// call operator (rubocop's `on_send`/`on_csend`, unified into one
    /// prism `CallNode` — `dot?`/`safe_navigation?` only match a literal
    /// `.`/`&.` source; a `::` call operator, e.g. `Foo::bar`, is a
    /// DIFFERENT operator string and is never checked here) and around the
    /// `::` that connects a namespace to a constant (rubocop's `on_const`,
    /// prism's `ConstantPathNode` — see `check_space_after_double_colon`
    /// below). Each check only fires when the gap is ENTIRELY spaces/tabs
    /// (`SPACES_REGEXP = /\A[ \t]+\z/`) — a newline (multi-line chains) or
    /// any other character (e.g. a comment) in the gap leaves it alone.
    pub(crate) fn check_space_around_method_call_operator(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/SpaceAroundMethodCallOperator";
        if !self.on(COP) {
            return;
        }
        let Some(dot_loc) = node.call_operator_loc() else { return };
        let op = dot_loc.as_slice();
        if op != b"." && op != b"&." {
            return;
        }
        // `check_space_before_dot`: receiver end .. dot begin. The receiver
        // is always present for a `.`/`&.` call.
        if let Some(receiver) = node.receiver() {
            self.samco_check(receiver.location().end_offset(), dot_loc.start_offset());
        }
        // `check_space_after_dot`: dot end .. selector begin, where the
        // selector is the `(` of a bare `Proc#call` shorthand (`foo.()`,
        // no explicit method name — `message_loc` is absent) rather than
        // the (nonexistent) selector location.
        let selector_off = if node.name().as_slice() == b"call" && node.message_loc().is_none() {
            node.opening_loc().map(|l| l.start_offset())
        } else {
            node.message_loc().map(|l| l.start_offset())
        };
        if let Some(selector_off) = selector_off {
            self.samco_check(dot_loc.end_offset(), selector_off);
        }
    }

    /// `on_const`'s `check_space_after_double_colon` — only the space AFTER
    /// the `::` is checked (never before); prism gives each level of a
    /// `Foo::Bar::Baz` chain — including a leading `::` cbase, e.g.
    /// `::Foo` — its own `ConstantPathNode` with its own
    /// `delimiter_loc`/`name_loc`, so recursing into `parent` isn't needed:
    /// the normal `visit_constant_path_node` traversal already visits every
    /// level.
    pub(crate) fn check_space_after_double_colon(&mut self, node: &ruby_prism::ConstantPathNode) {
        const COP: &str = "Layout/SpaceAroundMethodCallOperator";
        if !self.on(COP) {
            return;
        }
        let delimiter = node.delimiter_loc();
        let name = node.name_loc();
        self.samco_check(delimiter.end_offset(), name.start_offset());
    }

    /// Shared `check_space`: offense (correctable, removing the range) iff
    /// `[begin_off, end_off)` is non-empty and consists ENTIRELY of spaces
    /// and/or tabs — a newline or any other byte (e.g. a comment) in the
    /// gap disqualifies it, matching rubocop's `SPACES_REGEXP.match?`.
    fn samco_check(&mut self, begin_off: usize, end_off: usize) {
        const COP: &str = "Layout/SpaceAroundMethodCallOperator";
        if end_off <= begin_off {
            return;
        }
        let gap = &self.src[begin_off..end_off];
        if !gap.iter().all(|&b| b == b' ' || b == b'\t') {
            return;
        }
        self.push(begin_off, COP, true, "Avoid using spaces around a method call operator.");
        self.fixes.push((begin_off, end_off, Vec::new()));
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/SpaceAroundBlockParameters — checks the spacing inside and
    /// after a block's parameter pipes `{ |a, b| }`, and after the closing
    /// pipe before the body. Also covers a stabby lambda's `(...)` argument
    /// list: upstream's `on_block` fires for BOTH shapes because whitequark
    /// parses `->(x) { }` as a `:block` node whose args node uses `(`/`)` as
    /// its delimiters instead of `|`/`|`; prism instead gives lambdas their
    /// own `LambdaNode`, but its `BlockParametersNode` has the identical
    /// `opening_loc`/`closing_loc` shape, so the same core check applies to
    /// both `visit_block_node` and `visit_lambda_node`.
    /// EnforcedStyleInsidePipes: no_space (default) or space.
    pub(crate) fn check_space_around_block_parameters(&mut self, node: &ruby_prism::BlockNode) {
        let Some(params) = node.parameters() else { return };
        self.sabp_check(&params, node.body());
    }

    /// See `check_space_around_block_parameters` doc for why lambdas share
    /// the same core check.
    pub(crate) fn check_space_around_block_parameters_lambda(&mut self, node: &ruby_prism::LambdaNode) {
        let Some(params) = node.parameters() else { return };
        self.sabp_check(&params, node.body());
    }

    fn sabp_check(&mut self, params: &ruby_prism::Node, body: Option<ruby_prism::Node>) {
        const COP: &str = "Layout/SpaceAroundBlockParameters";
        if !self.on(COP) {
            return;
        }
        // A numbered-param (`_1`) or `it`-param block has no `BlockParametersNode`
        // at all (upstream's `pipes?` never applies to it either).
        let Some(bp) = params.as_block_parameters_node() else { return };
        let Some(opening) = bp.opening_loc() else { return };
        let Some(closing) = bp.closing_loc() else { return };

        // Flattened, source-ordered parameter list — regular params (in
        // Ruby's fixed grammar order: required, optional, rest, post,
        // keyword, keyword-rest, block) followed by any `; shadow` locals,
        // matching whitequark's flat `args.children` (shadowargs included).
        let args = sabp_flatten_args(&bp);
        if args.is_empty() {
            // `->() { }` / `{ || }`: upstream's `node.arguments?` is false.
            return;
        }

        let space_style = self.cfg.get(COP, "EnforcedStyleInsidePipes") == Some("space");
        let opening_end = opening.end_offset();
        let closing_start = closing.start_offset();

        let first_start = args[0].location().start_offset();
        let last_loc = args[args.len() - 1].location();
        let (last_start, last_end) = (last_loc.start_offset(), last_loc.end_offset());
        // A trailing comma (`|x, |`) belongs to "last" for the gap check
        // even though the insertion point below stays anchored to the bare
        // arg — matches upstream's `last_end_pos_inside_pipes`.
        let last_end_for_gap = sabp_last_end_pos_inside_pipes(self.src, last_end, closing_start);

        if space_style {
            // check_opening_pipe_space
            self.sabp_check_space_missing(opening_end, first_start, first_start, "before first block parameter");
            self.sabp_check_no_space(opening_end, first_start.saturating_sub(1), "Extra space before first");
            // check_closing_pipe_space — `check_space` is called WITHOUT a
            // node here (bare `last` range), so this is insert-AFTER, not
            // insert-before: the space lands right after the bare arg,
            // ahead of any trailing comma (`|x, |` -> `|x ,|`, not `|x, |`
            // gaining a second space before `,`).
            self.sabp_check_space_missing_range(
                last_end_for_gap,
                closing_start,
                last_start,
                last_end,
                "after last block parameter",
            );
            self.sabp_check_no_space(last_end_for_gap + 1, closing_start, "Extra space after last");
        } else {
            // check_no_space_style_inside_pipes
            self.sabp_check_no_space(opening_end, first_start, "Space before first");
            self.sabp_check_no_space(last_end_for_gap, closing_start, "Space after last");
        }

        // check_after_closing_pipe — only when the block has a body.
        if let Some(b) = &body {
            let body_start = b.location().start_offset();
            self.sabp_check_space_missing_range(
                closing.end_offset(),
                body_start,
                closing.start_offset(),
                closing.end_offset(),
                "after closing `|`",
            );
        }

        // check_each_arg — for EnforcedStyleInsidePipes: space, the first
        // arg's "extra space before" is already fully handled above
        // (`check_opening_pipe_space` computes the exact same range for it,
        // and upstream's `current_offense_locations` dedup would otherwise
        // silently drop this second, differently-worded, call).
        for (i, arg) in args.iter().enumerate() {
            self.sabp_check_arg(arg, space_style && i == 0);
        }
    }

    /// `check_arg`: recurses into a destructured `(a, b)` parameter's own
    /// sub-elements first (never skipped, even for the top-level first arg),
    /// then — unless `skip_self` — flags more-than-one space immediately
    /// preceding `arg` itself.
    fn sabp_check_arg(&mut self, arg: &ruby_prism::Node, skip_self: bool) {
        if let Some(mt) = arg.as_multi_target_node() {
            for sub in mt.lefts().iter() {
                self.sabp_check_arg(&sub, false);
            }
            // A bare trailing comma (`(x, )`) parses as a synthetic
            // `ImplicitRestNode` marker, not a real child in whitequark's
            // mlhs — skip it, same as `sabp_flatten_args` does at the top
            // level.
            if let Some(r) = mt.rest() {
                if r.as_implicit_rest_node().is_none() {
                    self.sabp_check_arg(&r, false);
                }
            }
            for sub in mt.rights().iter() {
                self.sabp_check_arg(&sub, false);
            }
        }
        if skip_self {
            return;
        }
        let expr_start = arg.location().start_offset();
        let begin = sabp_left_space_begin(self.src, expr_start);
        self.sabp_check_no_space(begin, expr_start.saturating_sub(1), "Extra space before");
    }

    /// `check_space` (the `node` overload): fires only when the gap is
    /// exactly empty (no space at all), highlighting `node_start` itself and
    /// inserting a single space immediately before it.
    fn sabp_check_space_missing(&mut self, gap_begin: usize, gap_end: usize, node_start: usize, msg: &str) {
        const COP: &str = "Layout/SpaceAroundBlockParameters";
        if gap_begin != gap_end {
            return;
        }
        self.push(node_start, COP, true, format!("Space {msg} missing."));
        self.fixes.push((node_start, node_start, b" ".to_vec()));
    }

    /// `check_space` (the `range` overload): fires only when the gap is
    /// exactly empty, highlighting `[anchor_start, anchor_end)` and
    /// inserting a single space right after `anchor_end`.
    fn sabp_check_space_missing_range(
        &mut self,
        gap_begin: usize,
        gap_end: usize,
        anchor_start: usize,
        anchor_end: usize,
        msg: &str,
    ) {
        const COP: &str = "Layout/SpaceAroundBlockParameters";
        if gap_begin != gap_end {
            return;
        }
        self.push(anchor_start, COP, true, format!("Space {msg} missing."));
        self.fixes.push((anchor_end, anchor_end, b" ".to_vec()));
    }

    /// `check_no_space`: fires when `[begin, end)` is non-empty and doesn't
    /// span a line break (upstream explicitly bails on a `\n`-containing
    /// range — that's `Layout/MultilineBlockLayout`'s turf).
    fn sabp_check_no_space(&mut self, begin: usize, end: usize, msg: &str) {
        const COP: &str = "Layout/SpaceAroundBlockParameters";
        if begin >= end {
            return;
        }
        if self.src[begin..end].contains(&b'\n') {
            return;
        }
        self.push(begin, COP, true, format!("{msg} block parameter detected."));
        self.fixes.push((begin, end, Vec::new()));
    }
}

/// Layout/SpaceAroundBlockParameters: flattens a `BlockParametersNode` into
/// its source-ordered parameter list — required/optional/rest/post/keyword/
/// keyword-rest/block (Ruby's fixed grammar order already matches physical
/// source order for any legal parameter list), followed by `; shadow`
/// locals. Mirrors whitequark's flat `args.children` (which interleaves
/// shadowargs at the end, in source order, the same way).
fn sabp_flatten_args<'pr>(bp: &ruby_prism::BlockParametersNode<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    let mut out = Vec::new();
    if let Some(params) = bp.parameters() {
        for n in params.requireds().iter() {
            out.push(n);
        }
        for n in params.optionals().iter() {
            out.push(n);
        }
        // A bare trailing comma (`|x, |`) parses as a synthetic
        // `ImplicitRestNode` marker — whitequark's args node has no
        // corresponding child for it at all, so it must not become "last".
        if let Some(r) = params.rest() {
            if r.as_implicit_rest_node().is_none() {
                out.push(r);
            }
        }
        for n in params.posts().iter() {
            out.push(n);
        }
        for n in params.keywords().iter() {
            out.push(n);
        }
        if let Some(kr) = params.keyword_rest() {
            out.push(kr);
        }
        if let Some(b) = params.block() {
            out.push(b.as_node());
        }
    }
    for n in bp.locals().iter() {
        out.push(n);
    }
    out
}

/// `last_end_pos_inside_pipes`: extends `last_end` past a single trailing
/// comma (`|x, |`) up to (but not through) the closing pipe/paren — the only
/// other token that can legally appear in that gap.
fn sabp_last_end_pos_inside_pipes(src: &[u8], last_end: usize, closing_start: usize) -> usize {
    match src[last_end..closing_start].iter().position(|&b| b == b',') {
        Some(rel) => last_end + rel + 1,
        None => last_end,
    }
}

/// `range_with_surrounding_space(expr, side: :left)`'s default phases run in
/// this fixed order — consume contiguous spaces/tabs, then contiguous
/// `\`-newline continuations, then contiguous bare newlines — and are never
/// re-run once a later phase advances past a boundary the earlier phase
/// would have matched. Crossing a newline here is exactly what later makes
/// `sabp_check_no_space` reject the range (a multi-line param list is
/// `Layout/MultilineBlockLayout`'s turf, not this cop's).
fn sabp_left_space_begin(src: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos > 0 && matches!(src[pos - 1], b' ' | b'\t') {
        pos -= 1;
    }
    while pos >= 2 && &src[pos - 2..pos] == b"\\\n" {
        pos -= 2;
    }
    while pos > 0 && src[pos - 1] == b'\n' {
        pos -= 1;
    }
    pos
}


/// Layout/HeredocIndentation shared helpers (free functions so they're usable
/// without an existing offense/`self` borrow conflict inside the corrector).

/// Ruby's `\s` character class (ASCII-only, no `/u`): space, tab, CR, FF, VT
/// — used for the leading-whitespace counts this cop's `indent_level`
/// (`Heredoc` mixin) and `heredoc_end`'s own gsub rely on. `\n` is
/// deliberately excluded — these are always called on content that's
/// already been split on newlines, so it never appears mid-slice.
fn hi_is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | 0x0b | 0x0c)
}

fn hi_ws_len(s: &[u8]) -> usize {
    s.iter().take_while(|&&b| hi_is_ws(b)).count()
}

/// `str.lines` for a heredoc body: split on `\n`, dropping the trailing
/// empty piece a body ending in `\n` produces (every non-empty heredoc body
/// ends in `\n` — it always runs up to, but not including, the closing
/// delimiter's own line).
fn hi_body_lines(body: &str) -> Vec<&str> {
    let mut v: Vec<&str> = body.split('\n').collect();
    if v.last() == Some(&"") {
        v.pop();
    }
    v
}

/// `Heredoc#indent_level`: minimum leading-whitespace width across all
/// lines, EXCLUDING lines that are entirely whitespace (blank lines don't
/// participate — `.reject { |line| line.end_with?("\n") }`, true exactly
/// when the leading-whitespace match consumed the whole line including its
/// terminator).
fn hi_min_indent(lines: &[&str]) -> usize {
    let mut min: Option<usize> = None;
    for line in lines {
        let ws = hi_ws_len(line.as_bytes());
        if ws == line.len() {
            continue;
        }
        min = Some(min.map_or(ws, |m| m.min(ws)));
    }
    min.unwrap_or(0)
}

impl<'a> super::Cops<'a> {
    /// `configured_indentation_width` (`Alignment` mixin): this cop's own
    /// `IndentationWidth` param (no schema default — `Layout/
    /// HeredocIndentation` doesn't ship one) falling back to `Layout/
    /// IndentationWidth`'s `Width` (schema default 2), then a hardcoded 2.
    fn hi_configured_width(&self) -> usize {
        self.cfg
            .param("Layout/HeredocIndentation", "IndentationWidth")
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse::<usize>().ok()))
            .unwrap_or(2)
    }

    /// Leading-whitespace width of the physical line containing byte offset
    /// `off` — `base_indent_level`'s `indent_level(base_line)` collapses to
    /// this (a heredoc's own opening line, or its closing-delimiter line,
    /// is never blank, so the multi-line `indent_level`'s "reject blank
    /// lines" branch never applies).
    fn hi_line_indent(&self, off: usize) -> usize {
        let line = self.idx.loc(off).0;
        let start = self.idx.starts[line - 1];
        let end = self.line_end(line);
        hi_ws_len(&self.src[start..end])
    }

    /// `line_too_long?` — deliberately reads `Layout/LineLength`'s RAW
    /// `Enabled` param (not `cfg.cop_config_enabled`/`self.on`): the oracle
    /// harness's own `AllCops: DisabledByDefault: true` (scoping which cop
    /// THIS run investigates) has no equivalent in the real spec's `:config`
    /// shared context, where `other_cops` sections are merged in WITHOUT an
    /// `Enabled` key and default to enabled — `Config#enable_cop?`'s
    /// `cop_options.fetch('Enabled') { !for_all_cops['DisabledByDefault'] }`
    /// with a real config's `AllCops` never carrying that flag.
    fn hi_line_too_long(&self, base_indent: usize, width: usize, body_lines: &[&str]) -> bool {
        if self.cfg.param("Layout/LineLength", "Enabled") == Some("false") {
            return false; // `max_line_length` returns nil -> falsy
        }
        let max = self.cfg.get("Layout/LineLength", "Max").and_then(|v| v.parse::<i64>().ok()).unwrap_or(120);
        if self.cfg.get("Layout/LineLength", "AllowHeredoc") == Some("true") {
            return false; // `unlimited_heredoc_length?`
        }
        let body_indent = hi_min_indent(body_lines) as i64;
        let expected_indent = (base_indent + width) as i64;
        let increase_indent_level = expected_indent - body_indent;
        let longest = body_lines.iter().map(|l| l.chars().count() as i64).max().unwrap_or(0);
        longest + increase_indent_level >= max
    }

    /// `adjust_squiggly`: reindents every body line (only the shared
    /// `body_indent_level`-wide leading run is touched — shorter/blank
    /// lines whose own prefix doesn't reach that width are left as-is,
    /// exactly like the upstream `gsub(/^[^\S\r\n]{n}/, ...)`), then, if the
    /// closing delimiter is currently indented LESS than the heredoc's own
    /// opening line, pulls it in to match.
    fn hi_adjust_squiggly(
        &mut self,
        closing: ruby_prism::Location,
        body_start: usize,
        body_end: usize,
        body_lines: &[&str],
        body_indent_level: usize,
        base_indent: usize,
        width: usize,
    ) {
        let correct_body_indent = base_indent + width;
        let mut new_body = String::new();
        for (i, line) in body_lines.iter().enumerate() {
            if i > 0 {
                new_body.push('\n');
            }
            let ws = hi_ws_len(line.as_bytes());
            if ws >= body_indent_level {
                new_body.push_str(&" ".repeat(correct_body_indent));
                new_body.push_str(&line[body_indent_level..]);
            } else {
                new_body.push_str(line);
            }
        }
        new_body.push('\n');
        self.fixes.push((body_start, body_end, new_body.into_bytes()));

        let end_indent = hi_ws_len(closing.as_slice());
        if end_indent < base_indent {
            let start = closing.start_offset();
            self.fixes.push((start, start + end_indent, vec![b' '; base_indent]));
        }
    }

    /// `adjust_minus`: `heredoc_beginning.sub(/<<-?/, '<<~')` — strip the
    /// opening token's leading `<<` (and an optional immediately-following
    /// `-`), splice `<<~` back in front of whatever's left (quote char and/or
    /// delimiter name).
    fn hi_adjust_minus(&mut self, opening: ruby_prism::Location) {
        let slice = opening.as_slice();
        let mut rest = &slice[2.min(slice.len())..];
        if rest.first() == Some(&b'-') {
            rest = &rest[1..];
        }
        let mut new = Vec::with_capacity(3 + rest.len());
        new.extend_from_slice(b"<<~");
        new.extend_from_slice(rest);
        self.fixes.push((opening.start_offset(), opening.end_offset(), new));
    }

    /// Layout/HeredocIndentation — `Heredoc#on_str`/`#on_dstr`/`#on_xstr`.
    /// whitequark's `xstring_compose` builds a plain `:xstr` node whether or
    /// not it has interpolation (there's no separate `:dxstr` type), so
    /// `#on_xstr` — aliased to `#on_str` — covers `InterpolatedXStringNode`
    /// too; it's wired up from `visit_interpolated_x_string_node` just like
    /// the other three heredoc-capable node kinds. `opening_loc`/`closing_
    /// loc` are the heredoc's own delimiter locations; `body_start`/
    /// `body_end` bracket `node.loc.heredoc_body` — for a plain `StringNode`/
    /// `XStringNode` that's `content_loc()` directly, for an interpolated
    /// one (`InterpolatedStringNode`/`InterpolatedXStringNode`) it's the
    /// first part's start through the closing delimiter's own start
    /// (mirrors `HeredocFinder::add_span`).
    pub(crate) fn check_heredoc_indentation(
        &mut self,
        opening_loc: Option<ruby_prism::Location>,
        closing_loc: Option<ruby_prism::Location>,
        body_start: usize,
        body_end: usize,
    ) {
        const COP: &str = "Layout/HeredocIndentation";
        if !self.on(COP) {
            return;
        }
        let Some(opening) = opening_loc else { return };
        let op = opening.as_slice();
        if !op.starts_with(b"<<") {
            return;
        }
        let Some(closing) = closing_loc else { return };
        if body_start >= body_end {
            return; // `body.strip.empty?`
        }
        // upstream's `heredoc_body` always starts at COLUMN 0 of the line
        // after the opener; an interpolated heredoc's first part is the
        // `#{...}` itself, whose start offset would drop the line's leading
        // whitespace and fake a zero min-indent (rails plugin_helpers.rb).
        let body_start = self.idx.starts[self.idx.loc(body_start).0 - 1];
        let Ok(body) = std::str::from_utf8(&self.src[body_start..body_end]) else { return };
        if body.trim().is_empty() {
            return; // `body.strip.empty?`
        }

        let body_lines = hi_body_lines(body);
        let body_indent_level = hi_min_indent(&body_lines);
        // `node.source[/^<<([~-])/, 1]` — '~', '-', or bare (neither).
        let indent_type = match op.get(2) {
            Some(b'~') => Some(b'~'),
            Some(b'-') => Some(b'-'),
            _ => None,
        };
        let width = self.hi_configured_width();
        let base_indent = self.hi_line_indent(opening.start_offset());

        // `heredoc_squish?`: only relevant off the squiggly branch (upstream
        // never even calls it when `heredoc_indent_type == '~'`).
        let squish = indent_type != Some(b'~') && self.squish_heredoc.contains(&opening.start_offset());

        if indent_type == Some(b'~') {
            let expected_indent_level = base_indent + width;
            if expected_indent_level == body_indent_level {
                return;
            }
        } else if !(body_indent_level == 0 || squish) {
            return;
        }

        if self.hi_line_too_long(base_indent, width, &body_lines) {
            return;
        }

        let message = match indent_type {
            Some(b'~') => format!("Use {width} spaces for indentation in a heredoc."),
            Some(b'-') => {
                format!("Use {width} spaces for indentation in a heredoc by using `<<~` instead of `<<-`.")
            }
            _ => format!("Use {width} spaces for indentation in a heredoc by using `<<~` instead of `<<`."),
        };
        self.push(body_start, COP, true, message);

        if indent_type == Some(b'~') {
            self.hi_adjust_squiggly(closing, body_start, body_end, &body_lines, body_indent_level, base_indent, width);
        } else if squish {
            self.hi_adjust_squiggly(closing, body_start, body_end, &body_lines, body_indent_level, base_indent, width);
            self.hi_adjust_minus(opening);
        } else {
            self.hi_adjust_minus(opening);
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/SpaceInsideHashLiteralBraces — ports `SpaceInsideHashLiteralBraces#on_hash`
    /// (aliased `on_hash_pattern`) together with the shared `SurroundingSpace` mixin's
    /// `check`/`expect_space?`/`offense?`/`incorrect_style_detected`/`autocorrect` and
    /// `check_whitespace_only_hash`.
    ///
    /// Callers pass just the byte offsets of the opening/closing brace characters —
    /// `HashNode`'s `opening_loc`/`closing_loc` are non-optional (prism always gives a
    /// braced hash literal its own node kind; a braceless keyword-argument hash is a
    /// distinct `KeywordHashNode` that never reaches this check at all, matching
    /// upstream's `tokens.first.left_brace?` guard being unconditionally true for
    /// `on_hash`). `HashPatternNode`'s brace locations are optional (`in a:, b:` has none)
    /// and, when present, may point at `[`/`]` for the `Foo[a: 1]` constant-bracket pattern
    /// form instead of `{`/`}` — the explicit byte check below (`src[open_start] == '{'`)
    /// is our equivalent of upstream's `token.left_brace?`/`right_curly_brace?` typed
    /// guard.
    ///
    /// Upstream walks the raw *token* stream within the node (`tokens_within`) and
    /// inspects only the first/last TWO tokens. We replicate this with byte scanning
    /// directly on the source, which is equivalent because: (1) `token.space_after?` only
    /// needs to know whether at least one space/tab character immediately follows a
    /// token — a single boolean, not an exact count (rubocop accepts `bar = {    }` under
    /// `EnforcedStyleForEmptyBraces: space` just as readily as `bar = { }`); (2) the "on a
    /// different line" / "is a comment" early-outs (`token1.line < token2.line`,
    /// `token2.comment?`) only need to distinguish a run of plain spaces/tabs from a run
    /// that hits a newline or a `#` first, since a comment always extends to end-of-line;
    /// (3) `is_same_braces` (which lets `compact` collapse successive braces in nested
    /// hashes, e.g. `{{ a: 1 } => { b: 2 }}`) only needs to know whether the byte
    /// immediately across the gap is itself `{`/`}` — true exactly when an adjacent hash
    /// literal's own brace sits there, since string/heredoc literal delimiters are always
    /// separated from a hash's brace by their own closing quote character (verified
    /// against the `h = {a: '{'}` fixture case: the quote, not the string's inner `{`,
    /// is what our scan actually sees adjacent to the hash's own brace).
    ///
    /// Each `HashNode`/`HashPatternNode` (nested ones included) is visited independently,
    /// so the "successive braces collapse" behavior for nested hashes falls out for free:
    /// the outer hash's own closing-brace-side check sees the inner hash's closing brace
    /// as its immediate left neighbor, exactly as upstream's `tokens[-2]` would.
    ///
    /// NOT ported: `ConfigurableEnforcedStyle`'s `correct_style_detected`/
    /// `ambiguous_style_detected`/`unexpected_style_detected` bookkeeping — it only feeds
    /// `--auto-gen-config`'s `detected_style` tracking and never affects whether an offense
    /// is registered or how autocorrect behaves.
    ///
    /// Residual risk not exercised by the fixture: a `%{...}` percent-string literal's OWN
    /// closing delimiter is a raw `}` character. If that percent-literal is a hash value
    /// sitting directly against the hash's own closing brace (e.g. `{a: %{str}}`), upstream
    /// would NOT treat that adjacency as `is_same_braces` (the percent-literal's terminator
    /// is a distinct token type, not `tRCURLY`), but our plain byte check would. This only
    /// matters under `EnforcedStyle: compact`, and only changes whether that one adjacent
    /// pair is required to have a space — not exercised anywhere in the spec fixture.
    pub(crate) fn check_space_inside_hash_literal_braces(&mut self, open_start: usize, close_start: usize) {
        const COP: &str = "Layout/SpaceInsideHashLiteralBraces";
        if !self.on(COP) {
            return;
        }
        let src = self.src;
        if src.get(open_start) != Some(&b'{') || src.get(close_start) != Some(&b'}') {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        let no_space_for_empty =
            self.cfg.get(COP, "EnforcedStyleForEmptyBraces").unwrap_or("no_space") == "no_space";
        let open_end = open_start + 1;

        let mut p1 = open_end;
        while p1 < close_start && sihlb_is_space_tab(src[p1]) {
            p1 += 1;
        }
        let has_content = src[open_end..close_start].iter().any(|&b| !sihlb_is_ws(b));

        if p1 == close_start {
            // `tokens.size == 2`: adjacent braces, or spaces/tabs only with no
            // newline in between — the only token pair upstream ever checks
            // for this hash is `(tokens[0], tokens[1])` == `({, })`, i.e. the
            // `is_empty_braces` branch of `check`.
            let has_space = close_start > open_end;
            self.sihlb_apply(COP, true, open_start, open_end, close_start, has_space, false, true, style, no_space_for_empty);
        } else if src[p1] == b'\n' {
            if !has_content {
                // `check_whitespace_only_hash`: the entire interior is
                // whitespace (including at least one newline) — only fires
                // under `no_space` for empty braces; `check()` itself never
                // runs here either since `tokens.size == 2`.
                if no_space_for_empty {
                    self.push(open_end, COP, true, "Space inside empty hash literal braces detected.");
                    self.fixes.push((open_end, close_start, Vec::new()));
                }
            }
            // else: real content starts on a later line — `token1.line <
            // token2.line`; no offense from the open-brace side.
        } else if src[p1] == b'#' {
            // `token2.comment?` — a comment right after the brace also
            // implies a line break; no offense from the open-brace side.
        } else {
            let has_space = p1 > open_end;
            let is_same_braces = src[p1] == b'{';
            self.sihlb_apply(COP, true, open_start, open_end, p1, has_space, is_same_braces, false, style, no_space_for_empty);
        }

        if has_content {
            let mut q = close_start;
            while q > open_end && sihlb_is_space_tab(src[q - 1]) {
                q -= 1;
            }
            if src[q - 1] != b'\n' {
                let has_space = q < close_start;
                let is_same_braces = src[q - 1] == b'}';
                self.sihlb_apply(COP, false, close_start, q, close_start, has_space, is_same_braces, false, style, no_space_for_empty);
            }
            // else: the last real token before the closing brace sits on an
            // earlier line; no offense from the close-brace side.
        }
    }

    /// Shared offense/autocorrect logic for one brace side, porting
    /// `SurroundingSpace`'s `expect_space?`/`offense?`/`incorrect_style_detected`/
    /// `autocorrect`. `is_left` selects which physical brace anchors a "missing space"
    /// offense (`{` at `brace_pos` for the open side, `}` at `brace_pos` for the close
    /// side) and on which side of it a space gets inserted.
    #[allow(clippy::too_many_arguments)]
    fn sihlb_apply(
        &mut self,
        cop: &'static str,
        is_left: bool,
        brace_pos: usize,
        gap_start: usize,
        gap_end: usize,
        has_space: bool,
        is_same_braces: bool,
        is_empty_braces: bool,
        style: &str,
        no_space_for_empty: bool,
    ) {
        let expect_space = if is_same_braces && style == "compact" {
            false
        } else if is_empty_braces {
            !no_space_for_empty
        } else {
            style != "no_space"
        };
        let offense = if expect_space { !has_space } else { has_space };
        if !offense {
            return;
        }
        let inside_what = if is_empty_braces {
            "empty hash literal braces"
        } else if is_left {
            "{"
        } else {
            "}"
        };
        let problem = if expect_space { "missing" } else { "detected" };
        let msg = format!("Space inside {inside_what} {problem}.");
        if expect_space {
            self.push(brace_pos, cop, true, msg);
            let ins = if is_left { brace_pos + 1 } else { brace_pos };
            self.fixes.push((ins, ins, b" ".to_vec()));
        } else {
            self.push(gap_start, cop, true, msg);
            self.fixes.push((gap_start, gap_end, Vec::new()));
        }
    }
}

fn sihlb_is_space_tab(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn sihlb_is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
}


impl<'a> Cops<'a> {
    /// Layout/SpaceInsideReferenceBrackets — port of `on_send`/`autocorrect`
    /// plus the `SurroundingSpace`/`ConfigurableEnforcedStyle` mixins.
    /// Upstream walks a real Lexer token stream (`tokens_within(node)`,
    /// `left_ref_bracket`/`closing_bracket` token-index scans) to find the
    /// reference brackets belonging to a `[]`/`[]=` send and their true
    /// partner, guarding against lookalikes (array-literal brackets,
    /// method-call parens on `obj.[](x)`/`def self.[]`). We don't have a
    /// token stream, but prism's `opening_loc`/`closing_loc` on the node
    /// kinds below already give the CORRECTLY PAIRED bracket locations for
    /// THIS call directly (no nesting-depth scan needed) — filtering to
    /// literal `"["`/`"]"` bytes (vs `"("`/`")"` for the explicit dot-call
    /// form `subject.[](0)`) reproduces upstream's `left_ref_bracket?`
    /// token-type check for free, and `def Vector.[](*array)` is a
    /// `DefNode` never routed here at all.
    ///
    /// KNOWN DIVERGENCE: upstream's `left_ref_bracket` has a quirk for
    /// `[]=` sends — because `tokens_within(node)` spans the WHOLE call
    /// (receiver through the assigned value), and the method finds the
    /// FIRST `tLBRACK2` token in that entire range whenever `node.method?
    /// (:[]=)`, a chained bracketed receiver (`c[1][2] = 3`) gets its
    /// spacing checked against the RECEIVER's inner bracket (`c[1]`), not
    /// this call's own (`[2]`) — a real upstream bug, never exercised by
    /// the fixture (every `[]=`-chain example there uses a plain
    /// non-bracketed receiver). We always use this call's own (correctly
    /// paired, semantically "right") bracket instead.
    fn sirb_check(
        &mut self,
        opening: ruby_prism::Location,
        closing: ruby_prism::Location,
        has_args: bool,
        span_start: usize,
        span_end: usize,
    ) {
        const COP: &str = "Layout/SpaceInsideReferenceBrackets";
        if !self.on(COP) {
            return;
        }
        // `left_ref_bracket?`'s token-type guard: only a literal `[`/`]`
        // bracket pair qualifies. An explicit dot-call (`subject.[](0)`)
        // has `(`/`)` opening/closing instead — upstream's `tokens.find(&:
        // left_ref_bracket?)` would find nothing and bail via `return
        // unless left_token`.
        if opening.as_slice() != b"[" || closing.as_slice() != b"]" {
            return;
        }
        let src = self.src;
        let open_end = opening.end_offset();
        let close_start = closing.start_offset();

        if !has_args {
            // `empty_brackets?`/`empty_offenses`/`SpaceCorrector.
            // empty_corrections` — anchor and fix cover the interior
            // (`open_end..close_start`); the offense range for the
            // ANCHOR itself is the whole `[...]` text
            // (`range_between(left.begin_pos, right.end_pos)`), but only
            // its START offset matters for line:col.
            let style = self.cfg.get(COP, "EnforcedStyleForEmptyBrackets").unwrap_or("no_space");
            let interior_len = close_start - open_end;
            let space_between = interior_len == 1 && src.get(open_end) == Some(&b' ');
            let no_char_between = interior_len == 0;
            if style == "space" && !space_between {
                self.push(opening.start_offset(), COP, true, "Use one space inside empty reference brackets.");
                self.fixes.push((open_end, close_start, b" ".to_vec()));
            } else if style == "no_space" && !no_char_between {
                self.push(opening.start_offset(), COP, true, "Do not use space inside empty reference brackets.");
                self.fixes.push((open_end, close_start, Vec::new()));
            }
            return;
        }

        // `return if node.multiline?` — only guards the non-empty branch;
        // the empty-bracket check above runs regardless of line span.
        let (start_line, _) = self.idx.loc(span_start);
        let (end_line, _) = self.idx.loc(span_end.saturating_sub(1).max(span_start));
        if start_line != end_line {
            return;
        }

        let style = self.cfg.enforced_style(COP);
        if style == "no_space" {
            // `no_space_offenses`: flag (and strip) a run of spaces/tabs
            // clinging to either bracket's inner side.
            if matches!(src.get(open_end), Some(b' ') | Some(b'\t')) {
                let mut run_end = open_end;
                while matches!(src.get(run_end), Some(b' ') | Some(b'\t')) {
                    run_end += 1;
                }
                self.push(open_end, COP, true, "Do not use space inside reference brackets.");
                self.fixes.push((open_end, run_end, Vec::new()));
            }
            if matches!(src.get(close_start.wrapping_sub(1)), Some(b' ') | Some(b'\t')) {
                let mut run_start = close_start;
                while run_start > open_end && matches!(src.get(run_start - 1), Some(b' ') | Some(b'\t')) {
                    run_start -= 1;
                }
                self.push(run_start, COP, true, "Do not use space inside reference brackets.");
                self.fixes.push((run_start, close_start, Vec::new()));
            }
        } else {
            // `space_offenses`: flag (and insert) a single space on
            // either bracket's inner side when ENTIRELY absent — an
            // already-present run of 2+ spaces is left alone (upstream
            // only checks presence, never excess, for this style).
            if !matches!(src.get(open_end), Some(b' ') | Some(b'\t')) {
                self.push(opening.start_offset(), COP, true, "Use space inside reference brackets.");
                self.fixes.push((open_end, open_end, b" ".to_vec()));
            }
            if !matches!(src.get(close_start.wrapping_sub(1)), Some(b' ') | Some(b'\t')) {
                self.push(closing.start_offset(), COP, true, "Use space inside reference brackets.");
                self.fixes.push((close_start, close_start, b" ".to_vec()));
            }
        }
    }

    /// `[]`/`[]=` sends written with real bracket syntax (plain reads
    /// `a[b]`, plain reference-assigns `a[b] = c` — the latter's own
    /// `node.location()` legitimately extends through the assigned value,
    /// matching upstream's `node.multiline?` check on the same node).
    pub(crate) fn check_space_inside_reference_brackets_call(&mut self, node: &ruby_prism::CallNode) {
        if !self.on("Layout/SpaceInsideReferenceBrackets") {
            return;
        }
        if !matches!(node.name().as_slice(), b"[]" | b"[]=") {
            return;
        }
        let (Some(opening), Some(closing)) = (node.opening_loc(), node.closing_loc()) else {
            return;
        };
        let has_args = node.arguments().is_some();
        let span = node.location();
        self.sirb_check(opening, closing, has_args, span.start_offset(), span.end_offset());
    }

    /// `IndexTargetNode` — the `[]=`-shaped assignment-target form used in
    /// multiple-assignment / `for`-loop / rescue-variable targets (e.g.
    /// `a[1], b[2] = 1, 2`); rubocop-ast's Prism translation gives each
    /// element a `send`/`:[]=` node bounded to just `a[1]` (no trailing
    /// `=`/value), matching this node's own (already bounded) location.
    pub(crate) fn check_space_inside_reference_brackets_target(&mut self, node: &ruby_prism::IndexTargetNode) {
        if !self.on("Layout/SpaceInsideReferenceBrackets") {
            return;
        }
        let opening = node.opening_loc();
        let closing = node.closing_loc();
        let has_args = node.arguments().is_some();
        let span = node.location();
        self.sirb_check(opening, closing, has_args, span.start_offset(), span.end_offset());
    }

    /// `IndexOperatorWriteNode`/`IndexAndWriteNode`/`IndexOrWriteNode`
    /// (`a[1] += 2`, `&&=`, `||=`) — rubocop-ast's Prism translation
    /// decomposes each of these into an `op_asgn`/`and_asgn`/`or_asgn`
    /// wrapping a plain `send`/`:[]` READ node bounded to `receiver[args]`
    /// only (NOT the operator/value), so upstream's `node.multiline?`
    /// there only ever sees that bounded span. We rebuild the same bounded
    /// span (`receiver.location.start` .. `closing_loc.end`) here, since
    /// these node kinds' own `location()` extends through the value.
    pub(crate) fn check_space_inside_reference_brackets_write(
        &mut self,
        receiver: Option<ruby_prism::Node>,
        opening: ruby_prism::Location,
        closing: ruby_prism::Location,
        has_args: bool,
    ) {
        if !self.on("Layout/SpaceInsideReferenceBrackets") {
            return;
        }
        let Some(receiver) = receiver else {
            return;
        };
        let start = receiver.location().start_offset();
        let end = closing.end_offset();
        self.sirb_check(opening, closing, has_args, start, end);
    }
}



/// Layout/SpaceInsideBlockBraces — port of `on_block`/`on_numblock`/
/// `on_itblock` (all aliased to the same method upstream) plus its private
/// helpers (`check_inside`/`adjacent_braces`/`braces_with_contents_inside`/
/// `check_left_brace`/`check_right_brace`/`(no_)?space_inside_(left|right)
/// _brace`/`pipe?`/`no_space`/`space`/`offense`/`style_for_empty_braces`).
/// Prism gives every brace-delimited block (plain, `_1`-numbered, `it`) the
/// SAME `BlockNode` shape, so — exactly like upstream's alias trio — one
/// hook handles all three; only `node.parameters()` distinguishes them (a
/// `BlockParametersNode` for the pipe form, `NumberedParametersNode`/
/// `ItParametersNode` — or nothing — otherwise).
///
/// `chain_start` is the byte offset of upstream's `node.source_range.column`
/// — used only by the multiline right-brace alignment check
/// (`aligned_braces?`). Upstream's whitequark `block` node's own expression
/// spans the FULL receiver chain (`foo.bar.baz { ... }`'s block node starts
/// at `foo`, column 0), which is exactly prism's raw owning-call-or-`super`
/// node's `location()` (that node's span already includes any receiver —
/// confirmed empirically against real rubocop, not the bare "starts at the
/// selector" raw-prism `BlockNode#location` shape). The caller passes the
/// `rp_ancestors` entry directly below our own (the block's one and only
/// possible owner — see `dm_owning_call_start`'s doc for why that lookup is
/// always correct).
impl<'a> Cops<'a> {
    const SIBB_COP: &'static str = "Layout/SpaceInsideBlockBraces";

    /// Ruby's `/\s/` character class (used for the `\A\S`/`\S$`/`\S`
    /// membership tests on `inner`, and the offense corrector's `/\s/`
    /// case arm) — space, tab, CR, LF, FF, VT.
    fn sibb_is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x0b)
    }

    /// Forward twin of `range_with_surrounding_space(..., side: :right)`
    /// (defaults `newlines: true, whitespace: false, continuations: false`):
    /// skip a run of spaces/tabs, THEN (from wherever that stops) a run of
    /// newlines — sequential, not a combined scan. Mirrors
    /// `check_space_before_block_braces`'s backward twin (see its doc).
    fn sibb_skip_fwd(src: &[u8], mut pos: usize) -> usize {
        while pos < src.len() && matches!(src[pos], b' ' | b'\t') {
            pos += 1;
        }
        while pos < src.len() && src[pos] == b'\n' {
            pos += 1;
        }
        pos
    }

    /// Backward twin, for `side: :left`. Also reports whether any `\n` byte
    /// was skipped — upstream's `brace_with_space.source.match?(/\R/)`; the
    /// only newlines that CAN land in that range come from here, since the
    /// range's other edge is the brace's own (non-newline) character.
    fn sibb_skip_back(src: &[u8], mut pos: usize) -> (usize, bool) {
        while pos > 0 && matches!(src[pos - 1], b' ' | b'\t') {
            pos -= 1;
        }
        let mut crossed_nl = false;
        while pos > 0 && src[pos - 1] == b'\n' {
            crossed_nl = true;
            pos -= 1;
        }
        (pos, crossed_nl)
    }

    /// `inner_last_space_count`: `inner.split("\n").last.count(' ')`.
    /// Ruby's default `String#split` drops ALL trailing empty pieces (not
    /// just one) — so a `}` sitting alone at column 0 (inner ends with a
    /// bare `\n`, nothing after) resolves to the line BEFORE that blank
    /// tail, not `""`. Strip trailing `\n`s first, then take the tail after
    /// the last remaining `\n` (or the whole thing if none remain).
    fn sibb_inner_last_space_count(inner: &[u8]) -> usize {
        let mut end = inner.len();
        while end > 0 && inner[end - 1] == b'\n' {
            end -= 1;
        }
        let stripped = &inner[..end];
        let start = stripped.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
        stripped[start..].iter().filter(|&&b| b == b' ').count()
    }

    /// `style_for_empty_braces`: `Some(true)` => `:space`, `Some(false)` =>
    /// `:no_space`, `None` => upstream's `raise 'Unknown
    /// EnforcedStyleForEmptyBraces selected!'` (an invalid config value —
    /// see `check_space_inside_block_braces`'s callers for how that's
    /// handled: treated as a no-op rather than aborting the process).
    fn sibb_style_for_empty_braces(&self) -> Option<bool> {
        match self.cfg.get(Self::SIBB_COP, "EnforcedStyleForEmptyBraces") {
            Some("space") => Some(true),
            Some("no_space") => Some(false),
            _ => None,
        }
    }

    fn sibb_style_no_space(&self) -> bool {
        self.cfg.get(Self::SIBB_COP, "EnforcedStyle") == Some("no_space")
    }

    fn sibb_space_before_params(&self) -> bool {
        self.cfg.get(Self::SIBB_COP, "SpaceBeforeBlockParameters") == Some("true")
    }

    /// `offense`: registers at `[begin, end)` (already guarded by callers to
    /// have `begin <= end`, but check anyway to mirror upstream's own
    /// `return if begin_pos > end_pos`) and dispatches the autocorrection
    /// exactly like upstream's `case range.source`.
    fn sibb_offense(&mut self, begin: usize, end: usize, msg: &'static str) {
        if begin > end {
            return;
        }
        self.push(begin, Self::SIBB_COP, true, msg);
        let range_src = &self.src[begin..end];
        if range_src.iter().any(|&b| Self::sibb_is_ws(b)) {
            self.fixes.push((begin, end, Vec::new()));
        } else if range_src == b"{}" {
            self.fixes.push((begin, end, b"{ }".to_vec()));
        } else if range_src == b"{|" {
            self.fixes.push((begin, end, b"{ |".to_vec()));
        } else {
            // `insert_before`: a zero-width insert right before `begin`;
            // `[begin, end)` itself is left untouched.
            self.fixes.push((begin, begin, b" ".to_vec()));
        }
    }

    /// `no_space`: upstream only offends when the configured style is
    /// `:space` (otherwise the "no space" state is already what the style
    /// wants — `correct_style_detected`, a no-op for us).
    fn sibb_no_space(&mut self, begin: usize, end: usize, msg: &'static str) {
        if !self.sibb_style_no_space() {
            self.sibb_offense(begin, end, msg);
        }
    }

    /// `space`: the mirror image — offends only under `:no_space`.
    fn sibb_space(&mut self, begin: usize, end: usize, msg: &'static str) {
        if self.sibb_style_no_space() {
            self.sibb_offense(begin, end, msg);
        }
    }

    pub(crate) fn check_space_inside_block_braces(&mut self, node: &ruby_prism::BlockNode, chain_start: usize) {
        if !self.on(Self::SIBB_COP) {
            return;
        }
        let opening = node.opening_loc();
        // `node.keywords?`: `do`...`end` blocks are Layout/SpaceAroundKeyword
        // turf, not ours — only the `{`-opened form is in scope here.
        if opening.as_slice() != b"{" {
            return;
        }
        let closing = node.closing_loc();
        let left_brace_start = opening.start_offset();
        let left_brace_end = opening.end_offset();
        let right_brace_start = closing.start_offset();
        let right_brace_end = closing.end_offset();

        let open_line = self.idx.loc(left_brace_start).0;
        let close_line = self.idx.loc(right_brace_start).0;
        // Multi-line EMPTY braces are exempt entirely — registering (and
        // autocorrecting) here would collapse them to single-line empty
        // braces, fighting this very cop's own next pass (upstream's
        // comment references rubocop/rubocop#7363).
        if node.body().is_none() && open_line != close_line {
            return;
        }

        if left_brace_end == right_brace_start {
            // `adjacent_braces`: literally `{}`, nothing between.
            if self.sibb_style_for_empty_braces() == Some(true) {
                self.sibb_offense(left_brace_start, right_brace_end, "Space missing inside empty braces.");
            }
            return;
        }

        let src = self.src;
        let inner = &src[left_brace_end..right_brace_start];
        if inner.iter().any(|&b| !Self::sibb_is_ws(b)) {
            self.sibb_braces_with_contents(
                node,
                inner,
                left_brace_start,
                left_brace_end,
                right_brace_start,
                right_brace_end,
                chain_start,
            );
        } else if self.sibb_style_for_empty_braces() == Some(false) {
            self.sibb_offense(left_brace_end, right_brace_start, "Space inside empty braces detected.");
        }
    }

    /// `braces_with_contents_inside` + `check_left_brace`/`check_right_brace`
    /// dispatch (folded into one to avoid threading 7 positional args
    /// through an extra layer).
    fn sibb_braces_with_contents(
        &mut self,
        node: &ruby_prism::BlockNode,
        inner: &[u8],
        left_brace_start: usize,
        left_brace_end: usize,
        right_brace_start: usize,
        right_brace_end: usize,
        chain_start: usize,
    ) {
        // `node.arguments.loc.begin if node.block_type?`: the pipe location,
        // present only for an ordinary (non-numbered, non-`it`) block that
        // actually declares `|...|` — `NumberedParametersNode`/
        // `ItParametersNode` (or no parameters at all) both yield `None`
        // here, matching upstream's `nil` in either case.
        let args_delim = node
            .parameters()
            .and_then(|p| p.as_block_parameters_node())
            .and_then(|bp| bp.opening_loc())
            .map(|l| (l.start_offset(), l.end_offset()));

        self.sibb_check_left_brace(inner, left_brace_start, left_brace_end, args_delim);

        let single_line = self.idx.loc(left_brace_start).0 == self.idx.loc(right_brace_start).0;
        self.sibb_check_right_brace(
            inner,
            left_brace_start,
            right_brace_start,
            right_brace_end,
            single_line,
            chain_start,
        );
    }

    fn sibb_check_left_brace(
        &mut self,
        inner: &[u8],
        left_brace_start: usize,
        left_brace_end: usize,
        args_delim: Option<(usize, usize)>,
    ) {
        let starts_non_ws = inner.first().is_some_and(|&b| !Self::sibb_is_ws(b));
        if starts_non_ws {
            // `no_space_inside_left_brace`
            match args_delim {
                Some((d_begin, d_end)) => {
                    if left_brace_end == d_begin && self.sibb_space_before_params() {
                        self.sibb_offense(left_brace_start, d_end, "Space between { and | missing.");
                    }
                    // else: `correct_style_detected` — no offense.
                }
                None => {
                    // We indicate the position after the left brace, matching
                    // upstream's comment on distinguishing left- vs
                    // right-side missing space during autocorrect.
                    self.sibb_no_space(left_brace_end, left_brace_end + 1, "Space missing inside {.");
                }
            }
        } else {
            // `space_inside_left_brace`
            match args_delim {
                Some((d_begin, _)) => {
                    if !self.sibb_space_before_params() {
                        self.sibb_offense(left_brace_end, d_begin, "Space between { and | detected.");
                    }
                    // else: `correct_style_detected` — no offense.
                }
                None => {
                    let end = Self::sibb_skip_fwd(self.src, left_brace_end);
                    self.sibb_space(left_brace_end, end, "Space inside { detected.");
                }
            }
        }
    }

    fn sibb_check_right_brace(
        &mut self,
        inner: &[u8],
        left_brace_start: usize,
        right_brace_start: usize,
        right_brace_end: usize,
        single_line: bool,
        chain_start: usize,
    ) {
        let ends_non_ws = inner.last().is_some_and(|&b| !Self::sibb_is_ws(b));
        if single_line && ends_non_ws {
            self.sibb_no_space(right_brace_start, right_brace_end, "Space missing inside }.");
            return;
        }

        let column = self.idx.loc(chain_start).1 - 1;
        let right_column = self.idx.loc(right_brace_start).1 - 1;
        let left_line = self.idx.loc(left_brace_start).0;
        let right_line = self.idx.loc(right_brace_start).0;
        let multiline_block = left_line != right_line;
        if multiline_block {
            let aligned = right_column == column || Self::sibb_inner_last_space_count(inner) == column;
            if aligned {
                return;
            }
        }

        self.sibb_space_inside_right_brace(inner, right_brace_start, right_brace_end, right_column, column);
    }

    fn sibb_space_inside_right_brace(
        &mut self,
        inner: &[u8],
        right_brace_start: usize,
        right_brace_end: usize,
        right_column: usize,
        column: usize,
    ) {
        let (back_pos, crossed_nl) = Self::sibb_skip_back(self.src, right_brace_start);
        let mut begin_pos = back_pos;
        let mut end_pos = right_brace_end - 1;

        if crossed_nl {
            let diff = right_column as isize - column as isize;
            begin_pos = (end_pos as isize - diff).max(0) as usize;
        }

        if inner.last() == Some(&b']') {
            end_pos -= 1;
            let diff = Self::sibb_inner_last_space_count(inner) as isize - column as isize;
            begin_pos = (end_pos as isize - diff).max(0) as usize;
        }

        self.sibb_space(begin_pos, end_pos, "Space inside } detected.");
    }
}


/// Layout/SpaceInsideArrayLiteralBrackets — verbatim-behavior port of the
/// upstream `SurroundingSpace`-based token-pair logic (`on_array`/
/// `on_array_pattern`, `issue_offenses`, `compact_offenses`, and the
/// `SpaceCorrector`/`SurroundingSpace` mixin helpers it calls into), adapted
/// to prism the same way `Layout/SpaceInsideParens` was (see that cop's doc
/// comment): we don't have a real lexer token stream, so every place
/// upstream walks `processed_source.tokens_within(node)` to find "the next
/// real token" is replaced here with a byte-level whitespace skip — safe
/// because a plain space/tab is NEVER itself a distinct token upstream (only
/// comments and `tNL` newline-separators are), so "the next real token"
/// always collapses to "the next non-whitespace byte", and "did we cross a
/// `tNL`" collapses to "did that skip cross a `\n` byte".
///
/// Two upstream node-shape differences are already handled for free by
/// prism: `find_node_with_brackets`'s ancestor climb (whitequark wraps
/// `ADT[pattern]` in a separate `const-pattern` node whose OWN `array-
/// pattern` child has no brackets of its own) doesn't apply — prism's
/// `ArrayPatternNode` carries the leading constant directly (see
/// `check_space_inside_array_pattern_literal_brackets`'s doc comment) — and
/// a bracketless array/pattern (`a = 1, 2` / `in a, b, c, d`) has `None`
/// opening/closing locations we just skip on, matching `array_brackets`
/// returning `nil, nil` for it.
///
/// Every one of the four style branches below needs the SAME two low-level
/// facts about each bracket's outward-facing byte: is there a plain space/
/// tab immediately adjacent (`extra_space?`/`SINGLE_SPACE_REGEXP`, used for
/// the offense DECISION), and where does that run of plain space/tab end
/// (`side_space_range` with `include_newlines: false`, used for both the
/// offense's anchor position and — for `no_space`/`space`/the compact
/// "ordinary side" fallback — the correction range too, since upstream's
/// `SpaceCorrector.remove_space`/`add_space` compute the exact same range).
/// `compact`'s "collapse adjacent brackets" correction is the one exception:
/// its OFFENSE anchor still uses the space/tab-only skip (hence the `^{}`
/// zero-width offense when the gap is a bare newline with no leading space),
/// but its CORRECTION range uses the full whitespace skip (crossing
/// newlines), matching `compact()`'s `include_newlines: true`.
impl<'a> Cops<'a> {
    /// `on_array`: `node.array_type? && !node.square_brackets?` bails out on
    /// a bracketless array (`a = 1, 2`, `opening_loc: None`) and on a
    /// percent-literal array (`%w[...]`/`%i[...]`, whose `opening_loc` is
    /// the multi-byte `%w`/`%i`/... marker, never the bare `[` this cop
    /// cares about).
    pub(crate) fn check_space_inside_array_literal_brackets(&mut self, node: &ruby_prism::ArrayNode) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        if !self.on(COP) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        if open.as_slice() != b"[" {
            return;
        }
        let Some(close) = node.closing_loc() else { return };
        self.silb_run(node.location().start_offset(), open.start_offset(), close.start_offset());
    }

    /// `on_array_pattern` (aliased to `on_array` upstream). Prism embeds a
    /// leading constant directly on `ArrayPatternNode` — `ADT[*head, tail]`
    /// parses with `constant: Some(ADT)` and `opening_loc`/`closing_loc`
    /// pointing at the REAL `[`/`]`, spanning the pattern from `ADT` through
    /// `]` — so there is no separate wrapper node to climb to and no
    /// `square_brackets?` guard to apply (a `[`-delimited pattern is always
    /// real brackets; the only bracketless shape, `in a, b, c, d`, simply has
    /// `opening_loc: None` and is skipped below, same as upstream's
    /// `array_brackets` returning `nil, nil` for it). `FindPatternNode`
    /// (`in [*, x, *]`) is a distinct prism node kind never routed here,
    /// matching upstream never aliasing `on_find_pattern`.
    pub(crate) fn check_space_inside_array_pattern_literal_brackets(&mut self, node: &ruby_prism::ArrayPatternNode) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        if !self.on(COP) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let Some(close) = node.closing_loc() else { return };
        self.silb_run(node.location().start_offset(), open.start_offset(), close.start_offset());
    }

    fn silb_run(&mut self, node_start: usize, open_pos: usize, close_pos: usize) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        let src = self.src;
        let open_end = open_pos + 1; // `[` is always exactly one byte.

        // `empty_brackets?`: no token at all (not even a comment) between
        // the two bracket tokens — collapses to "nothing but whitespace (of
        // any kind, any amount, including zero)" between them.
        if src[open_end..close_pos].iter().all(|&b| silb_is_ws(b)) {
            self.silb_empty(open_pos, open_end, close_pos);
            return;
        }

        let style = self.cfg.enforced_style(COP);
        let (fwd_pos, fwd_crossed_nl) = silb_skip_ws_forward(src, open_end);
        let (bwd_pos, bwd_crossed_nl) = silb_skip_ws_backward(src, close_pos);
        // `node.single_line?`: the closing bracket is always the node's own
        // last byte (for both `ArrayNode` and `ArrayPatternNode`), so
        // comparing against it directly stands in for the node's own
        // `location.end`.
        let single_line = self.idx.loc(node_start).0 == self.idx.loc(close_pos).0;
        // `end_has_own_line?`: on the closing bracket's OWN physical line,
        // is everything before it whitespace? That's exactly "did the
        // backward whitespace skip cross a `\n` to reach the previous real
        // content" — if it didn't, real content sits on the SAME line as
        // the bracket; if it did, the bracket's line has nothing before it
        // but whitespace. `node.single_line?` forces this false outright,
        // but a single-line node's backward skip can never cross a `\n`
        // anyway (there isn't one inside it), so this is a redundant-but-
        // harmless special case, not a distinct behavior.
        let end_ok = !single_line && bwd_crossed_nl;

        match style {
            "space" => self.silb_space(open_pos, open_end, close_pos, fwd_crossed_nl, end_ok),
            "compact" => self.silb_compact(open_pos, open_end, close_pos, fwd_pos, bwd_pos, fwd_crossed_nl, end_ok),
            _ => {
                // `next_to_comment?`: `no_space`'s `start_ok` override — the
                // char immediately after the left bracket, once ALL
                // whitespace is skipped, is a comment marker.
                let next_to_comment = src[fwd_pos] == b'#';
                self.silb_no_space(open_end, close_pos, next_to_comment, end_ok);
            }
        }
    }

    /// `empty_offenses`/`SpaceCorrector.empty_corrections`: exact-count
    /// checks (`space_between?`/`no_character_between?`), not presence
    /// checks, so unlike the non-empty branches this needs no start/end-of-
    /// line reasoning at all.
    fn silb_empty(&mut self, open_pos: usize, open_end: usize, close_pos: usize) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        let src = self.src;
        // Resolved param, not `enforced_style` — `EnforcedStyleForEmptyBrackets`
        // isn't one of this cop's `SupportedStyles` (that's the OTHER param,
        // `EnforcedStyle`), so an invalid/unrecognized value must match
        // neither `offending_empty_space?` nor `offending_empty_no_space?`
        // (both do exact string equality) rather than silently falling back.
        let empty_style = self.cfg.get(COP, "EnforcedStyleForEmptyBrackets").unwrap_or("no_space");
        match empty_style {
            "space" => {
                let exactly_one_space = close_pos == open_end + 1 && src.get(open_end) == Some(&b' ');
                if !exactly_one_space {
                    self.push(open_pos, COP, true, "Use one space inside empty array brackets.");
                    self.fixes.push((open_end, close_pos, b" ".to_vec()));
                }
            }
            "no_space" => {
                if open_end != close_pos {
                    self.push(open_pos, COP, true, "Do not use space inside empty array brackets.");
                    self.fixes.push((open_end, close_pos, Vec::new()));
                }
            }
            _ => {}
        }
    }

    /// `space_offenses` (style `:space`). `extra_space?`'s restricted
    /// space/tab-only check, OR'd with `start_ok`/`end_ok`
    /// (`next_to_newline?`/`end_has_own_line?`) — both sides are otherwise
    /// independent (no compact-style bracket-adjacency logic here). The fix
    /// (`SpaceCorrector.add_space`) is safe to apply unconditionally
    /// whenever the offense fires: reaching the `push` means the immediate
    /// byte is neither a plain space/tab NOR (via `start_ok`/`end_ok`) does a
    /// newline separate it from the next real content, so it's some other
    /// non-whitespace byte — inserting exactly one space is always correct.
    fn silb_space(&mut self, open_pos: usize, open_end: usize, close_pos: usize, start_ok: bool, end_ok: bool) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        let src = self.src;
        if !(silb_is_sp_tab(src[open_end]) || start_ok) {
            self.push(open_pos, COP, true, "Use space inside array brackets.");
            self.fixes.push((open_end, open_end, b" ".to_vec()));
        }
        if !(silb_is_sp_tab(src[close_pos - 1]) || end_ok) {
            self.push(close_pos, COP, true, "Use space inside array brackets.");
            self.fixes.push((close_pos, close_pos, b" ".to_vec()));
        }
    }

    /// `no_space_offenses` (style `:no_space`). `start_ok` here is
    /// `next_to_comment?`, NOT `next_to_newline?` (see `silb_run`'s dispatch)
    /// — a `[` immediately followed by a newline never trips `extra_space?`
    /// in the first place (`SINGLE_SPACE_REGEXP` only matches ` `/`\t`), so
    /// `no_space` style needs no newline-awareness at all, only the
    /// comment-adjacency exemption (`a = [ # comment`). Offense range AND
    /// fix range are the SAME space/tab-only span
    /// (`SpaceCorrector.remove_space` uses the identical `side_space_range`
    /// formula as the offense).
    fn silb_no_space(&mut self, open_end: usize, close_pos: usize, next_to_comment: bool, end_ok: bool) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        let src = self.src;
        let start_ok = next_to_comment;
        if silb_is_sp_tab(src[open_end]) && !start_ok {
            let end = silb_skip_sp_tab_forward(src, open_end);
            self.push(open_end, COP, true, "Do not use space inside array brackets.");
            self.fixes.push((open_end, end, Vec::new()));
        }
        if silb_is_sp_tab(src[close_pos - 1]) && !end_ok {
            let start = silb_skip_sp_tab_backward(src, close_pos);
            self.push(start, COP, true, "Do not use space inside array brackets.");
            self.fixes.push((start, close_pos, Vec::new()));
        }
    }

    /// `compact_offenses`/`compact_corrections` (style `:compact`). Each
    /// side independently qualifies for the "collapse adjacent brackets"
    /// treatment (`qualifies_for_compact?`: the next real byte outward,
    /// after skipping ALL whitespace, is itself a bracket — `multi_dimensional_array?`
    /// — AND at least one whitespace byte of any kind actually separates
    /// them), falls back to the ordinary single-array `space_offenses`
    /// handling when it ISN'T adjacent to another bracket at all, or (the
    /// third, silent case: adjacent to another bracket with ZERO gap
    /// already) needs nothing. Each side's offense-or-not is independent,
    /// but upstream's per-node `autocorrect` always recomputes BOTH sides
    /// once ANY offense fires on the node (guarded only by `ignore_node`,
    /// not by which specific side triggered it) — safe to mirror by pushing
    /// a fix for whichever side(s) actually need one (the "already fine"
    /// cases only ever produce a no-op fix upstream too: a zero-length
    /// removal, or a skipped insert).
    #[allow(clippy::too_many_arguments)]
    fn silb_compact(
        &mut self,
        open_pos: usize,
        open_end: usize,
        close_pos: usize,
        fwd_pos: usize,
        bwd_pos: usize,
        start_ok: bool,
        end_ok: bool,
    ) {
        const COP: &str = "Layout/SpaceInsideArrayLiteralBrackets";
        let src = self.src;
        let mut any_offense = false;
        let mut left_fix: Option<(usize, usize, Vec<u8>)> = None;
        let mut right_fix: Option<(usize, usize, Vec<u8>)> = None;

        let multi_dim_left = src[fwd_pos] == b'[';
        if multi_dim_left && silb_is_ws(src[open_end]) {
            self.push(open_end, COP, true, "Do not use space inside array brackets.");
            any_offense = true;
            left_fix = Some((open_end, fwd_pos, Vec::new()));
        } else if !multi_dim_left && !(silb_is_sp_tab(src[open_end]) || start_ok) {
            self.push(open_pos, COP, true, "Use space inside array brackets.");
            any_offense = true;
            left_fix = Some((open_end, open_end, b" ".to_vec()));
        }

        let multi_dim_right = src[bwd_pos - 1] == b']';
        if multi_dim_right && silb_is_ws(src[close_pos - 1]) {
            let start = silb_skip_sp_tab_backward(src, close_pos);
            self.push(start, COP, true, "Do not use space inside array brackets.");
            any_offense = true;
            right_fix = Some((bwd_pos, close_pos, Vec::new()));
        } else if !multi_dim_right && !(silb_is_sp_tab(src[close_pos - 1]) || end_ok) {
            self.push(close_pos, COP, true, "Use space inside array brackets.");
            any_offense = true;
            right_fix = Some((close_pos, close_pos, b" ".to_vec()));
        }

        if any_offense {
            if let Some(f) = left_fix {
                self.fixes.push(f);
            }
            if let Some(f) = right_fix {
                self.fixes.push(f);
            }
        }
    }
}

/// Ruby's `\s`: space, tab, newline, CR, form feed, vertical tab — the exact
/// byte class `Parser::Source::Range`-based `\G\s` token-adjacency checks
/// (`Token#space_after?`/`#space_before?`) match, broader than Rust's
/// `u8::is_ascii_whitespace` (which omits vertical tab).
fn silb_is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// `SurroundingSpace::SINGLE_SPACE_REGEXP` (`/[ \t]/`) — the restricted class
/// `extra_space?` tests the single adjacent byte against.
fn silb_is_sp_tab(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

/// Skip a run of Ruby-whitespace bytes forward from `pos`, reporting whether
/// a `\n` was among them — `reposition(src, pos, +1, include_newlines: true)`
/// paired with the "did we cross a line" question upstream answers via
/// separate token-line comparisons (`next_to_newline?`/`end_has_own_line?`).
fn silb_skip_ws_forward(src: &[u8], mut pos: usize) -> (usize, bool) {
    let mut crossed_nl = false;
    while pos < src.len() && silb_is_ws(src[pos]) {
        if src[pos] == b'\n' {
            crossed_nl = true;
        }
        pos += 1;
    }
    (pos, crossed_nl)
}

/// Same as `silb_skip_ws_forward`, but backward: `pos` is an exclusive upper
/// bound, and the result is the (still exclusive) position right after the
/// nearest preceding non-whitespace byte.
fn silb_skip_ws_backward(src: &[u8], mut pos: usize) -> (usize, bool) {
    let mut crossed_nl = false;
    while pos > 0 && silb_is_ws(src[pos - 1]) {
        if src[pos - 1] == b'\n' {
            crossed_nl = true;
        }
        pos -= 1;
    }
    (pos, crossed_nl)
}

/// `reposition(src, pos, +1, include_newlines: false)` — space/tab only,
/// stopping at (not crossing) a newline.
fn silb_skip_sp_tab_forward(src: &[u8], mut pos: usize) -> usize {
    while pos < src.len() && silb_is_sp_tab(src[pos]) {
        pos += 1;
    }
    pos
}

/// `reposition(src, pos, -1, include_newlines: false)` — space/tab only,
/// backward; `pos` is an exclusive upper bound, result is the start of the
/// trailing space/tab run (still exclusive-upper-bound convention, i.e. the
/// range `[result, pos)` is exactly that run).
fn silb_skip_sp_tab_backward(src: &[u8], mut pos: usize) -> usize {
    while pos > 0 && silb_is_sp_tab(src[pos - 1]) {
        pos -= 1;
    }
    pos
}


// ---- Layout/EmptyLineAfterGuardClause ----
//
// Ports `on_if` verbatim (fires for `if`/`unless`/ternary alike — whitequark
// folds all three into one `:if` node type, so upstream's single `on_if`
// hook already covers every case prism splits into `IfNode`/`UnlessNode`)
// plus the `RangeHelp`/`Util`/`DirectiveComment` machinery it leans on.
//
// `node.right_sibling`/`node.parent` (needed by `correct_style?`'s
// `next_line_rescue_or_ensure?`/`next_sibling_parent_empty_or_else?`/
// `next_sibling_empty_or_guard_clause?` trio): whitequark leaves a SOLE
// statement inside ANY body slot (an if/unless branch, a rescue/ensure
// protected body, a resbody handler, a def/block body, the top-level
// program) unwrapped — its `parent` is the owning construct directly, not a
// `:begin` wrapper. Exhaustive case analysis against every fixture shape
// shows this makes EVERY sole-statement guard clause exempt regardless of
// what construct it's the sole statement of: an if/unless branch's sole
// guard always resolves exempt whether or not the `if` has an `else`/`elsif`
// (either the `nil`-sibling short-circuit or the `next_sibling_parent_
// empty_or_else?` short-circuit fires — the latter is unconditionally true
// whenever `subsequent` is present at all, since the "parent" of an
// unwrapped else/elsif slot is always the SAME outer if-node, which by
// definition has an else there); a rescue/ensure PROTECTED body's sole
// guard is exempt via `next_line_rescue_or_ensure?` firing directly; a
// resbody handler's sole guard, and a def/block/top-level sole body, are
// exempt via the plain out-of-bounds/nil-parent case. And a guard that's the
// LAST of 2+ statements in any body is likewise always exempt (the `:begin`
// wrapper bounds `right_sibling` at nil there, regardless of what's outside
// it). So the whole trio collapses to: within the STATEMENTS list this guard
// is literally an element of, is there a FOLLOWING element? Prism, unlike
// whitequark, wraps every body (even a 1-statement one) in a `StatementsNode`
// uniformly, so this is exactly "the next element of `stmts.body()`, if
// any" — computed directly in `check_empty_line_after_guard_clause`
// (`visit_statements_node`), the same idiom `Layout/EmptyLinesAroundAttributeAccessor`
// already established for this exact whitequark-unwrap mismatch, rather
// than needing any parent/sibling tracking machinery. A guard embedded
// elsewhere (a call receiver/argument, hash value, etc. — never a direct
// `StatementsNode` element) is consequently never even examined here; this
// matches upstream's own outcome for the one fixture example that exercises
// it (`if cond then return end.then { 42 }`), since a non-list
// `right_sibling` there resolves to something that isn't an `AST::Node` at
// all. A contrived counterexample (a guard clause as a bare array literal
// element, say) could in principle diverge from this since array elements
// ARE real sibling `AST::Node`s — not exercised by the fixture, and not
// reproduced here.
//
// `multiple_statements_on_line?` (`parent.begin_type? && same_line?(node,
// node.right_sibling)`): "not sole" is already established by the moment
// this runs (`correct_style?` already returned when there's no following
// sibling), so it's just "does the immediate next element start on the same
// physical line as this guard".
//
// Heredoc handling (`last_heredoc_argument`/`heredoc_line`/`autocorrect`'s
// heredoc branch): only reachable for a genuine `if`/`unless` MODIFIER form
// (`modifier_form?` — a ternary has no `if`/`unless` keyword at all, so it's
// excluded even though it also lacks an `end`). The search root
// (`last_heredoc_argument_node`) special-cases an `and`-wrapped branch (take
// the LHS — deliberately NOT `or`, matching upstream: no fixture exercises
// an `or`-wrapped guard needing heredoc search) and a heredoc literally
// inside the condition, falling back to the branch's own last child (its
// last call argument, or `return`/`break`/`next`'s wrapped value) otherwise;
// the recursive descent (`elagc_find_heredoc`) then walks arguments (FORWARD
// order — NOT `Style/GuardClause`'s `reverse_each`; a genuine difference
// between the two cops' own upstream sources, confirmed against both) and
// the receiver chain, unwrapping both `begin` (explicit `begin...end`/
// implicit rescue bodies) and prism's distinct `ParenthesesNode` (whitequark
// folds parenthesized groups into the SAME `begin_type?` the unwrap loop
// already targets) at each step. The terminator's own physical line always
// equals whitequark's computed `heredoc_line`: a heredoc's content can only
// ever start on the line right after the statement's own (single, since
// modifier-form) source line, so `heredoc_body.last_line`'s parser-boundary
// quirk (confirmed via live `Prism.parse`/`RuboCop::ProcessedSource` probes
// during porting) always lands exactly on the terminator's line — no
// separate line-arithmetic needed, just `closing_loc`'s own start line.
//
// Offense anchor: `self.push` only tracks a start offset (line:col — no
// end/length), so `heredoc_end`'s exact END coordinate never matters for
// detection, only its START (confirmed live: it's column 0 of the
// terminator's own line, i.e. `closing_loc.start_offset()` as-is, INCLUDING
// leading indentation — not the bare delimiter text). The END only matters
// for autocorrect's insertion point, which trims `closing_loc`'s trailing
// `\n`/`\r\n` to land right where `corrector.insert_after` would.
impl<'a> super::Cops<'a> {
    /// `on_if`, hooked from `visit_statements_node` (see the module doc for
    /// why prism's uniform `StatementsNode` wrapping makes that sufficient,
    /// unlike upstream's generic `node.right_sibling` walk).
    pub(crate) fn check_empty_line_after_guard_clause(&mut self, stmts: &ruby_prism::StatementsNode<'_>) {
        const COP: &str = "Layout/EmptyLineAfterGuardClause";
        if !self.on(COP) {
            return;
        }
        let body: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        let len = body.len();
        for i in 0..len {
            let node = &body[i];
            if !elagc_is_if_or_unless(node) {
                continue;
            }
            let sibling = if len > 1 && i + 1 < len { Some(&body[i + 1]) } else { None };
            self.elagc_check(node, sibling);
        }
    }

    fn elagc_check(&mut self, node: &ruby_prism::Node<'_>, sibling: Option<&ruby_prism::Node<'_>>) {
        const COP: &str = "Layout/EmptyLineAfterGuardClause";
        const MSG: &str = "Add empty line after guard clause.";
        if self.elagc_correct_style(node, sibling) {
            return;
        }
        if self.elagc_multiple_statements_on_line(node, sibling) {
            return;
        }
        if elagc_modifier_form(node) {
            if let Some(root) = elagc_heredoc_search_root(node) {
                if let Some(heredoc_node) = elagc_find_heredoc(root) {
                    if let Some(closing) = elagc_heredoc_closing_loc(&heredoc_node) {
                        let term_line = self.idx.loc(closing.start_offset()).0;
                        if self.elagc_next_lines_ok(term_line) {
                            return;
                        }
                        self.push(closing.start_offset(), COP, true, MSG);
                        let mut end = closing.end_offset();
                        if end > closing.start_offset() && self.src[end - 1] == b'\n' {
                            end -= 1;
                            if end > closing.start_offset() && self.src[end - 1] == b'\r' {
                                end -= 1;
                            }
                        }
                        let next_line = term_line + 1;
                        let pos = if self.elagc_next_line_allowed_directive(next_line) {
                            self.el_attr_comment_at(next_line).map(|(_, e)| e).unwrap_or(end)
                        } else {
                            end
                        };
                        self.fixes.push((pos, pos, b"\n".to_vec()));
                        return;
                    }
                }
            }
        }
        let last_line = self.idx.loc(node.location().end_offset().saturating_sub(1)).0;
        if self.elagc_next_lines_ok(last_line) {
            return;
        }
        let anchor =
            elagc_end_kw_loc(node).map(|l| l.start_offset()).unwrap_or_else(|| node.location().start_offset());
        self.push(anchor, COP, true, MSG);
        let next_line = last_line + 1;
        let pos = if self.elagc_next_line_allowed_directive(next_line) {
            self.el_attr_comment_at(next_line).map(|(_, e)| e).unwrap_or_else(|| self.line_end(last_line))
        } else {
            self.line_end(last_line)
        };
        self.fixes.push((pos, pos, b"\n".to_vec()));
    }

    /// `correct_style?`: see the module doc for why the sibling-based trio
    /// collapses to a single "does a following statement exist" check.
    fn elagc_correct_style(&self, node: &ruby_prism::Node<'_>, sibling: Option<&ruby_prism::Node<'_>>) -> bool {
        if !self.elagc_own_branch_is_guard(node) {
            return true;
        }
        match sibling {
            None => true,
            Some(sib) => elagc_is_if_or_unless(sib) && self.elagc_contains_guard_clause(sib),
        }
    }

    /// `multiple_statements_on_line?`.
    fn elagc_multiple_statements_on_line(
        &self,
        node: &ruby_prism::Node<'_>,
        sibling: Option<&ruby_prism::Node<'_>>,
    ) -> bool {
        let Some(sib) = sibling else { return false };
        let node_line = self.idx.loc(node.location().start_offset()).0;
        let sib_line = self.idx.loc(sib.location().start_offset()).0;
        node_line == sib_line
    }

    /// `node.if_branch&.guard_clause?` (rubocop-ast's `Node#guard_clause?`:
    /// and/or unwrap to the RHS, then `match_guard_clause?` — single-line
    /// bare `raise`/`fail`, or `return`/`break`/`next`).
    fn elagc_own_branch_is_guard(&self, node: &ruby_prism::Node<'_>) -> bool {
        let Some(stmts) = elagc_statements(node) else { return false };
        let mut it = stmts.body().iter();
        let Some(branch) = it.next() else { return false };
        if it.next().is_some() {
            return false;
        }
        if let Some(op) = branch.as_and_node() {
            let target = op.right();
            return self.elagc_single_line(&target) && elagc_bare_guard_type(&target);
        }
        if let Some(op) = branch.as_or_node() {
            let target = op.right();
            return self.elagc_single_line(&target) && elagc_bare_guard_type(&target);
        }
        self.elagc_single_line(&branch) && elagc_bare_guard_type(&branch)
    }

    /// `contains_guard_clause?`: `branch.guard_clause?` (and/or unwrap +
    /// single-line) OR `guard_clause_branch?` (the cop's own bare pattern —
    /// no unwrap, no single-line restriction) — an intentional asymmetry
    /// with `elagc_own_branch_is_guard` (confirmed against the "accepts
    /// multiple guard clauses using `and return`" fixture example).
    fn elagc_contains_guard_clause(&self, sibling: &ruby_prism::Node<'_>) -> bool {
        let Some(stmts) = elagc_statements(sibling) else { return false };
        let mut it = stmts.body().iter();
        let Some(branch) = it.next() else { return false };
        if it.next().is_some() {
            return false;
        }
        if elagc_bare_guard_type(&branch) {
            return true;
        }
        let target = if let Some(op) = branch.as_and_node() {
            op.right()
        } else if let Some(op) = branch.as_or_node() {
            op.right()
        } else {
            return false;
        };
        self.elagc_single_line(&target) && elagc_bare_guard_type(&target)
    }

    fn elagc_single_line(&self, n: &ruby_prism::Node<'_>) -> bool {
        let l = n.location();
        self.idx.loc(l.start_offset()).0 == self.idx.loc(l.end_offset().saturating_sub(1)).0
    }

    /// `next_line_empty_or_allowed_directive_comment?`, expressed over plain
    /// 1-based physical lines (same idiom as `Layout/EmptyLinesAroundAttributeAccessor`'s
    /// `el_attr_next_lines_ok`) rather than upstream's 0-based-array-vs-
    /// 1-based-line-number indexing trick.
    fn elagc_next_lines_ok(&self, last_line: usize) -> bool {
        if self.el_attr_line_blank(last_line + 1) {
            return true;
        }
        self.elagc_next_line_allowed_directive(last_line + 1) && self.el_attr_line_blank(last_line + 2)
    }

    /// `next_line_allowed_directive_comment?`: `DirectiveComment#enabled?`
    /// (a `# rubocop:enable ...` comment — `el_attr_enable_directive_at`
    /// already implements this exact regex for
    /// `Layout/EmptyLinesAroundAttributeAccessor`) OR a SimpleCov
    /// `:nocov:`/`simplecov:disable`/`simplecov:enable` directive comment.
    fn elagc_next_line_allowed_directive(&self, line: usize) -> bool {
        let Some((s, e)) = self.el_attr_comment_at(line) else { return false };
        if self.el_attr_enable_directive_at(line) {
            return true;
        }
        let text = String::from_utf8_lossy(&self.src[s..e]);
        elagc_is_simplecov_comment(&text)
    }
}

/// `if_type?`/`unless_type?` — whitequark folds both (plus ternaries) into
/// one `:if` node type; prism keeps `IfNode`/`UnlessNode` distinct.
fn elagc_is_if_or_unless(n: &ruby_prism::Node<'_>) -> bool {
    n.as_if_node().is_some() || n.as_unless_node().is_some()
}

/// `modifier_form?`: `(if? || unless?) && !loc?(:end)` — a ternary (no
/// `if`/`unless` keyword at all) is explicitly excluded even though it also
/// has no `end`.
fn elagc_modifier_form(n: &ruby_prism::Node<'_>) -> bool {
    if elagc_end_kw_loc(n).is_some() {
        return false;
    }
    if let Some(i) = n.as_if_node() {
        return i.if_keyword_loc().is_some();
    }
    n.as_unless_node().is_some()
}

fn elagc_end_kw_loc<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Location<'pr>> {
    if let Some(i) = n.as_if_node() {
        return i.end_keyword_loc();
    }
    if let Some(u) = n.as_unless_node() {
        return u.end_keyword_loc();
    }
    None
}

fn elagc_predicate<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    if let Some(i) = n.as_if_node() {
        return Some(i.predicate());
    }
    if let Some(u) = n.as_unless_node() {
        return Some(u.predicate());
    }
    None
}

/// `if_branch` (normalized): the `then`-branch's statements, for either node
/// kind.
fn elagc_statements<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::StatementsNode<'pr>> {
    if let Some(i) = n.as_if_node() {
        return i.statements();
    }
    if let Some(u) = n.as_unless_node() {
        return u.statements();
    }
    None
}

/// `match_guard_clause?`'s node-shape half (no single-line check — callers
/// apply that separately, since one caller — `guard_clause_branch?` — never
/// does).
fn elagc_bare_guard_type(n: &ruby_prism::Node<'_>) -> bool {
    if n.as_return_node().is_some() || n.as_break_node().is_some() || n.as_next_node().is_some() {
        return true;
    }
    if let Some(call) = n.as_call_node() {
        return call.receiver().is_none() && matches!(call.name().as_slice(), b"raise" | b"fail");
    }
    false
}

fn elagc_is_simplecov_comment(text: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^#\s*(?::nocov:|simplecov\s*:\s*(?:disable|enable)\b)").unwrap());
    re.is_match(text)
}

/// `last_heredoc_argument_node`: the search-root selector, run ONCE against
/// the top `if`/`unless` node itself (every recursive step afterward is a
/// plain pass-through in upstream, since only an if/unless node
/// `respond_to?(:if_branch)`).
fn elagc_heredoc_search_root<'pr>(node: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let stmts = elagc_statements(node)?;
    let body: Vec<ruby_prism::Node> = stmts.body().iter().collect();
    let branch = body.first()?;
    if let Some(op) = branch.as_and_node() {
        return Some(op.left());
    }
    if let Some(condition) = elagc_predicate(node) {
        if mlbl_subtree_has_heredoc(&condition) {
            return Some(condition);
        }
    }
    elagc_last_branch_child(branch)
}

/// `node.if_branch.children.last`: the branch's own last argument (a bare
/// `raise`/`fail` call) or wrapped value (`return`/`break`/`next`) — `None`
/// for a bare no-argument guard (whitequark's `.last` on an empty/symbol-only
/// children tail never resolves to anything heredoc-shaped either).
fn elagc_last_branch_child<'pr>(branch: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let args = if let Some(c) = branch.as_call_node() {
        c.arguments()
    } else if let Some(r) = branch.as_return_node() {
        r.arguments()
    } else if let Some(b) = branch.as_break_node() {
        b.arguments()
    } else if let Some(x) = branch.as_next_node() {
        x.arguments()
    } else {
        None
    };
    args.and_then(|a| a.arguments().iter().last())
}

/// `last_heredoc_argument`'s recursive descent (begin/parens-unwrap, heredoc
/// check, forward-order argument scan, receiver climb) — mirrors
/// `Style/GuardClause`'s own heredoc finder, except this cop's upstream
/// source iterates arguments FORWARD (`.each`), not `reverse_each` like
/// `Style/GuardClause` does — a genuine difference between the two cops'
/// own upstream sources, reproduced verbatim.
fn elagc_find_heredoc<'pr>(node: ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let mut n = node;
    loop {
        if let Some(b) = n.as_begin_node() {
            if let Some(first) = b.statements().and_then(|s| s.body().iter().next()) {
                n = first;
                continue;
            }
        } else if let Some(p) = n.as_parentheses_node() {
            if let Some(body) = p.body() {
                if let Some(stmts) = body.as_statements_node() {
                    if let Some(first) = stmts.body().iter().next() {
                        n = first;
                        continue;
                    }
                } else {
                    n = body;
                    continue;
                }
            }
        }
        break;
    }
    if super::breakable::is_heredoc_node(&n) {
        return Some(n);
    }
    let call = n.as_call_node();
    let ret = n.as_return_node();
    let brk = n.as_break_node();
    let nxt = n.as_next_node();
    if call.is_none() && ret.is_none() && brk.is_none() && nxt.is_none() {
        return None;
    }
    let args = call
        .as_ref()
        .and_then(|c| c.arguments())
        .or_else(|| ret.as_ref().and_then(|r| r.arguments()))
        .or_else(|| brk.as_ref().and_then(|b| b.arguments()))
        .or_else(|| nxt.as_ref().and_then(|x| x.arguments()));
    if let Some(args) = args {
        for arg in args.arguments().iter() {
            if let Some(found) = elagc_find_heredoc(arg) {
                return Some(found);
            }
        }
    }
    let recv = call?.receiver()?;
    elagc_find_heredoc(recv)
}

/// `heredoc_node.loc.heredoc_end`'s LOCATION: prism's `closing_loc` for a
/// heredoc string already starts at column 0 of the terminator's own
/// physical line (matching whitequark's `heredoc_end`, which — confirmed
/// live against real `RuboCop::ProcessedSource` output during porting —
/// spans the WHOLE line including leading indentation, not just the bare
/// delimiter text) through a trailing `\n`.
fn elagc_heredoc_closing_loc<'pr>(node: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Location<'pr>> {
    if let Some(n) = node.as_string_node() {
        n.closing_loc()
    } else if let Some(n) = node.as_interpolated_string_node() {
        n.closing_loc()
    } else if let Some(n) = node.as_x_string_node() {
        Some(n.closing_loc())
    } else if let Some(n) = node.as_interpolated_x_string_node() {
        Some(n.closing_loc())
    } else {
        None
    }
}


/// `PrecedingFollowingAlignment#aligned_with_equals_sign`'s three-way
/// verdict: `None` — no relevant preceding assignment to compare against
/// (first in its block, so nothing to flag); `Yes` — already aligned;
/// `No` — misaligned (the only case `check_assignment` flags).
enum EsAlignment {
    None,
    Yes,
    No,
}

/// Layout/ExtraSpacing's single whole-file AST walk: collects (1) every
/// multiline hash/keyword-hash pair's `key.end..value.begin` byte range —
/// upstream's `ignored_ranges` (Layout/HashAlignment's territory, so a
/// misaligned `=>`/`:` there is never "extra spacing") — and (2) every `=`
/// position that LOOKS like a bare assignment but isn't one: an optarg
/// default (`def foo(a = 1)`) or an endless method's own `=`
/// (`remove_equals_in_def`), both excluded from assignment-operator
/// detection.
struct EsPairCollector {
    ignored_ranges: Vec<(usize, usize)>,
    excluded_eq: std::collections::HashSet<usize>,
}
impl EsPairCollector {
    fn es_collect_pairs<'pr>(&mut self, hash_loc: ruby_prism::Location<'pr>, elements: ruby_prism::NodeList<'pr>) {
        // `pair.parent.single_line?` — only a MULTILINE hash/kwargs exempts
        // its pairs' key..value gap (that's Layout/HashAlignment's job).
        if !hash_loc.as_slice().contains(&b'\n') {
            return;
        }
        for el in elements.iter() {
            if let Some(assoc) = el.as_assoc_node() {
                let key_end = assoc.key().location().end_offset();
                let value_start = assoc.value().location().start_offset();
                if value_start > key_end {
                    self.ignored_ranges.push((key_end, value_start));
                }
            }
        }
    }
}
impl<'pr> ruby_prism::Visit<'pr> for EsPairCollector {
    fn visit_hash_node(&mut self, node: &ruby_prism::HashNode<'pr>) {
        self.es_collect_pairs(node.location(), node.elements());
        ruby_prism::visit_hash_node(self, node);
    }
    fn visit_keyword_hash_node(&mut self, node: &ruby_prism::KeywordHashNode<'pr>) {
        self.es_collect_pairs(node.location(), node.elements());
        ruby_prism::visit_keyword_hash_node(self, node);
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        self.excluded_eq.insert(node.operator_loc().start_offset());
        ruby_prism::visit_optional_parameter_node(self, node);
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let Some(eq) = node.equal_loc() {
            self.excluded_eq.insert(eq.start_offset());
        }
        ruby_prism::visit_def_node(self, node);
    }
}

impl<'a> Cops<'a> {
    /// Layout/ExtraSpacing — flags runs of 2+ horizontal-whitespace bytes
    /// between two adjacent lexical tokens on the same line
    /// (`MSG_UNNECESSARY`, `Unnecessary spacing detected.`), ported from
    /// rubocop's `on_new_investigation` + `PrecedingFollowingAlignment`
    /// mixin, with three independent escape hatches:
    ///
    ///   - `AllowForAlignment` (default true): the run is fine if the
    ///     FOLLOWING token lines up with something on the nearest
    ///     qualifying line above/below (identical text at that column, or —
    ///     failing that — the nearest line at the SAME indentation as the
    ///     token's own line). Reuses `Layout/SpaceBeforeFirstArg`'s already-
    ///     ported `sbfa_*` helpers (same mixin, same algorithm) via
    ///     `es_aligned_with_something` — just against an arbitrary byte
    ///     range instead of a single AST node.
    ///   - `AllowBeforeTrailingComments` (default false): a run right
    ///     before a trailing `#` comment is fine regardless of alignment.
    ///   - `ForceEqualSignAlignment` (default false): every line's first
    ///     real assignment operator (`=` or a compound `OP_ASGN`, minus
    ///     optarg defaults and endless-`def` equals signs) is instead
    ///     checked against the nearest PRECEDING assignment at the same
    ///     indentation (`MSG_UNALIGNED_ASGN`, `` `=` is not aligned with
    ///     the preceding assignment.``) — replacing, not augmenting, the
    ///     normal spacing check for that one token. Autocorrect re-aligns
    ///     the WHOLE contiguous same-indentation block of assignments to
    ///     the widest column, mirroring `align_equal_signs`.
    ///
    /// Real rubocop drives this off `processed_source.tokens` (parser-gem
    /// tokens via whitequark); prism exposes no equivalent token stream. This
    /// ports the algorithm onto the raw byte source instead: `self.lit_spans`
    /// (every string/symbol/regexp/heredoc-body byte span, already tracked
    /// for other text-based cops) and `self.comments` stand in for literal
    /// and comment tokens, and everything else is scanned byte-by-byte, with
    /// `es_token_len` approximating "how long is the lexical token starting
    /// here" (identifier/keyword, number, or the longest matching operator/
    /// punctuation lexeme) — enough to reproduce rubocop's column-based
    /// alignment predicates without a real lexer. Known gap: `=begin`/`=end`
    /// block comments aren't modeled as opaque past their first line (no
    /// fixture example exercises one).
    pub(crate) fn check_extra_spacing(&mut self, root: &ruby_prism::Node) {
        const COP: &str = "Layout/ExtraSpacing";
        if !self.on(COP) || self.src.is_empty() {
            return;
        }

        use ruby_prism::Visit;
        let mut collector = EsPairCollector { ignored_ranges: Vec::new(), excluded_eq: std::collections::HashSet::new() };
        collector.visit(root);
        let ignored_ranges = collector.ignored_ranges;
        let excluded_eq = collector.excluded_eq;

        let allow_for_alignment = self.cfg.get(COP, "AllowForAlignment") != Some("false");
        let allow_before_comments = self.cfg.get(COP, "AllowBeforeTrailingComments") == Some("true");
        let force_eq_align = self.cfg.get(COP, "ForceEqualSignAlignment") == Some("true");

        let aligned_comment_lines = self.es_build_aligned_comments();
        let comment_by_line: std::collections::HashMap<usize, (usize, usize)> =
            self.comments.iter().map(|&(l, s, e)| (l, (s, e))).collect();
        let nlines = self.idx.starts.len();

        // Per-line first REAL assignment operator (after excluding optarg
        // defaults / endless-method `=`) — only meaningful under
        // ForceEqualSignAlignment, which routes MSG_UNNECESSARY away from it.
        let mut assign_map: std::collections::HashMap<usize, (usize, usize)> = std::collections::HashMap::new();
        if force_eq_align {
            for line in 1..=nlines {
                let ls = self.idx.starts[line - 1];
                let code_end = comment_by_line.get(&line).map_or_else(|| self.line_end(line), |&(s, _)| s);
                if let Some(tok) = self.es_find_assignment(ls, code_end, &excluded_eq) {
                    assign_map.insert(line, tok);
                }
            }
        }

        for line in 1..=nlines {
            let ls = self.idx.starts[line - 1];
            let le = self.line_end(line);
            let comment = comment_by_line.get(&line).copied();
            let code_end = comment.map_or(le, |(s, _)| s);

            let mut i = ls;
            let mut prev_end: Option<usize> = None;
            while i < code_end {
                if let Some(e) = self.es_lit_containing_end(i) {
                    if let Some(pe) = prev_end {
                        self.es_check_other(
                            COP,
                            pe,
                            i,
                            e,
                            false,
                            allow_for_alignment,
                            allow_before_comments,
                            &ignored_ranges,
                            &aligned_comment_lines,
                        );
                    }
                    prev_end = Some(e);
                    i = e;
                    continue;
                }
                let b = self.src[i];
                if b.is_ascii_whitespace() {
                    i += 1;
                    continue;
                }
                let tok_end = i + self.es_token_len(i).max(1);
                if let Some(pe) = prev_end {
                    let is_assign = force_eq_align && assign_map.get(&line) == Some(&(i, tok_end));
                    if !is_assign {
                        self.es_check_other(
                            COP,
                            pe,
                            i,
                            tok_end,
                            false,
                            allow_for_alignment,
                            allow_before_comments,
                            &ignored_ranges,
                            &aligned_comment_lines,
                        );
                    }
                }
                prev_end = Some(tok_end);
                i = tok_end;
            }

            // Trailing comment: only a real gap when there's non-blank code
            // earlier on this SAME line — a standalone comment line has no
            // same-line predecessor token (`token1.line != token2.line`
            // upstream), so leading whitespace before it is never flagged.
            if let (Some(pe), Some((cstart, cend))) = (prev_end, comment) {
                self.es_check_other(
                    COP,
                    pe,
                    cstart,
                    cend,
                    true,
                    allow_for_alignment,
                    allow_before_comments,
                    &ignored_ranges,
                    &aligned_comment_lines,
                );
            }
        }

        if force_eq_align {
            self.es_check_assignments(COP, &assign_map);
        }
    }

    /// `check_other`/`extra_space_range`: given the gap between `token1`'s
    /// end (`token1_end`) and `token2`'s span (`token2_start..token2_end`)
    /// on one physical line, flag+fix the "extra" whitespace (all but the
    /// last one character of the gap) unless an escape hatch applies.
    #[allow(clippy::too_many_arguments)]
    fn es_check_other(
        &mut self,
        cop: &'static str,
        token1_end: usize,
        token2_start: usize,
        token2_end: usize,
        is_comment: bool,
        allow_for_alignment: bool,
        allow_before_comments: bool,
        ignored_ranges: &[(usize, usize)],
        aligned_comment_lines: &std::collections::HashSet<usize>,
    ) {
        if is_comment && allow_before_comments {
            return;
        }
        let start_pos = token1_end;
        let end_pos = token2_start.wrapping_sub(1);
        if end_pos <= start_pos {
            return;
        }
        if allow_for_alignment {
            let aligned = if is_comment {
                let line = self.idx.loc(token2_start).0;
                aligned_comment_lines.contains(&line)
            } else {
                self.es_aligned_with_something(token2_start, token2_end)
            };
            if aligned {
                return;
            }
        }
        if ignored_ranges.iter().any(|&(s, e)| start_pos >= s && start_pos < e) {
            return;
        }
        self.push(start_pos, cop, true, "Unnecessary spacing detected.");
        self.fixes.push((start_pos, end_pos, Vec::new()));
    }

    /// `PrecedingFollowingAlignment#aligned_with_something?` generalized to
    /// an arbitrary byte range instead of an AST node — same algorithm as
    /// `sbfa_aligned_with_something` (reuses its `sbfa_first_candidate`
    /// helper directly), duplicated here only because that one is typed to
    /// take a `&ruby_prism::Node`.
    fn es_aligned_with_something(&self, begin: usize, end: usize) -> bool {
        let range_line = self.idx.loc(begin).0;
        let range_col = begin - self.idx.starts[range_line - 1];
        let range_src = &self.src[begin..end];
        let total_lines = self.idx.starts.len();
        let pre: Vec<usize> = if range_line >= 2 { (0..=range_line - 2).rev().collect() } else { Vec::new() };
        let post: Vec<usize> = if range_line < total_lines { (range_line..total_lines).collect() } else { Vec::new() };
        for lines in [&pre, &post] {
            if self.sbfa_first_candidate(lines, range_col, range_src, None) == Some(true) {
                return true;
            }
        }
        let cur_line = self.sbfa_line_bytes(range_line);
        let base_indent = Self::sbfa_first_nonspace(cur_line);
        for lines in [&pre, &post] {
            if self.sbfa_first_candidate(lines, range_col, range_src, base_indent) == Some(true) {
                return true;
            }
        }
        false
    }

    /// `aligned_locations`: for each pair of TEXTUALLY CONSECUTIVE comments
    /// (file order, not necessarily adjacent lines) whose start columns
    /// match, both their lines are "aligned for comment purposes" — used
    /// only when `token2` is itself a trailing comment.
    fn es_build_aligned_comments(&self) -> std::collections::HashSet<usize> {
        let mut set = std::collections::HashSet::new();
        for w in self.comments.windows(2) {
            let (l1, s1, _) = w[0];
            let (l2, s2, _) = w[1];
            let c1 = s1 - self.idx.starts[l1 - 1];
            let c2 = s2 - self.idx.starts[l2 - 1];
            if c1 == c2 {
                set.insert(l1);
                set.insert(l2);
            }
        }
        set
    }

    /// The literal/heredoc-body span CONTAINING `pos` (start <= pos < end),
    /// whether `pos` is its exact start or a continuation line of a
    /// multiline literal — mirrors `in_lit_span`'s own lookup (same sorted
    /// `self.lit_spans`), just returning the end offset to jump to instead
    /// of a bool.
    fn es_lit_containing_end(&self, pos: usize) -> Option<usize> {
        let i = self.lit_spans.partition_point(|&(s, _)| s <= pos);
        if i > 0 && pos < self.lit_spans[i - 1].1 {
            Some(self.lit_spans[i - 1].1)
        } else {
            None
        }
    }

    /// Length of the lexical token starting at `pos` (already known to be
    /// real code — not whitespace, not inside a literal): an identifier/
    /// keyword/ivar/gvar run, a number (with a `.digits` float tail), the
    /// longest matching multi-char operator lexeme, or one byte of
    /// punctuation. Approximates real tokenization closely enough for the
    /// column-alignment predicates that consult a token's own text/length.
    fn es_token_len(&self, pos: usize) -> usize {
        let b = self.src[pos];
        if b.is_ascii_alphabetic() || b == b'_' || b == b'@' || b == b'$' {
            let mut i = pos;
            if self.src[i] == b'@' {
                i += 1;
                if self.src.get(i) == Some(&b'@') {
                    i += 1;
                }
            } else if self.src[i] == b'$' {
                i += 1;
            }
            while i < self.src.len() && (self.src[i].is_ascii_alphanumeric() || self.src[i] == b'_') {
                i += 1;
            }
            if i < self.src.len() && matches!(self.src[i], b'?' | b'!') {
                i += 1;
            }
            return (i - pos).max(1);
        }
        if b.is_ascii_digit() {
            let mut i = pos;
            while i < self.src.len() && (self.src[i].is_ascii_digit() || self.src[i] == b'_') {
                i += 1;
            }
            if i < self.src.len() && self.src[i] == b'.' && self.src.get(i + 1).is_some_and(u8::is_ascii_digit) {
                i += 1;
                while i < self.src.len() && (self.src[i].is_ascii_digit() || self.src[i] == b'_') {
                    i += 1;
                }
            }
            return i - pos;
        }
        const MULTI: &[&[u8]] = &[
            b"**=", b"<<=", b">>=", b"&&=", b"||=", b"<=>", b"===", b"...", b"..", b"==", b"!=", b"<=", b">=", b"=~",
            b"=>", b"->", b"::", b"&.", b"<<", b">>", b"**", b"+=", b"-=", b"*=", b"/=", b"%=", b"&=", b"|=", b"^=",
        ];
        for m in MULTI {
            if self.src[pos..].starts_with(m) {
                return m.len();
            }
        }
        1
    }

    /// The first REAL assignment operator (`assignment_tokens`: `tEQL` or
    /// `tOP_ASGN`, i.e. `=` or a compound `+=`/`-=`/.../`||=`) in
    /// `src[ls..code_end]` — skipping literal spans, comparison/spaceship
    /// operators (`==`, `===`, `!=`, `<=`, `>=`, `<=>`, never assignments),
    /// `=>` (hash rocket) and `=~` (match), and any `=` in `excluded`
    /// (optarg defaults, endless-`def`).
    fn es_find_assignment(&self, ls: usize, code_end: usize, excluded: &std::collections::HashSet<usize>) -> Option<(usize, usize)> {
        const ASSIGN_OPS: &[&[u8]] =
            &[b"**=", b"<<=", b">>=", b"&&=", b"||=", b"+=", b"-=", b"*=", b"/=", b"%=", b"&=", b"|=", b"^="];
        const CMP_SKIP: &[&[u8]] = &[b"<=>", b"===", b"==", b"!=", b"<=", b">="];
        let mut i = ls;
        while i < code_end {
            if let Some(e) = self.es_lit_containing_end(i) {
                i = e;
                continue;
            }
            let rest = &self.src[i..code_end];
            if let Some(op) = ASSIGN_OPS.iter().find(|op| rest.starts_with(**op)) {
                if !excluded.contains(&i) {
                    return Some((i, i + op.len()));
                }
                i += op.len();
                continue;
            }
            if let Some(op) = CMP_SKIP.iter().find(|op| rest.starts_with(**op)) {
                i += op.len();
                continue;
            }
            if self.src[i] == b'=' {
                let next = self.src.get(i + 1).copied();
                if next == Some(b'>') || next == Some(b'~') {
                    i += 2;
                    continue;
                }
                if !excluded.contains(&i) {
                    return Some((i, i + 1));
                }
            }
            i += 1;
        }
        None
    }

    /// `processed_source.line_indentation`: the leading-whitespace run's
    /// length — for a BLANK line (all whitespace or empty), that's the
    /// line's own full length, not zero (matches `/^(\s*)/` on a blank
    /// string matching the whole thing).
    fn es_line_indentation(&self, line: usize) -> usize {
        let bytes = self.sbfa_line_bytes(line);
        bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len())
    }

    fn es_line_blank(&self, line: usize) -> bool {
        self.sbfa_line_bytes(line).iter().all(u8::is_ascii_whitespace)
    }

    /// `PrecedingFollowingAlignment#relevant_assignment_lines`: walking
    /// `line_range` (already-materialized, since it may run in either
    /// direction), collect the assignment lines that stay at the SAME
    /// indentation as `line_range`'s first line, stopping at a dedent (on a
    /// non-blank line) or a blank line once we've left that indentation
    /// level.
    fn es_relevant_assignment_lines(
        &self,
        line_range: &[usize],
        assign_map: &std::collections::HashMap<usize, (usize, usize)>,
    ) -> Vec<usize> {
        let mut result = Vec::new();
        let Some(&first) = line_range.first() else { return result };
        let original_line_indent = self.es_line_indentation(first);
        let mut relevant_at_level = true;
        for &line_number in line_range {
            let current_indent = self.es_line_indentation(line_number);
            let blank = self.es_line_blank(line_number);
            if (current_indent < original_line_indent && !blank) || (relevant_at_level && blank) {
                break;
            }
            if current_indent == original_line_indent && assign_map.contains_key(&line_number) {
                result.push(line_number);
            }
            if !blank {
                relevant_at_level = current_indent == original_line_indent;
            }
        }
        result
    }

    /// `all_relevant_assignment_lines`: the union of the downward
    /// (`line.downto(1)`) and upward (`line.upto(last)`) relevant-line
    /// scans — the FULL same-indentation block of assignments `line`
    /// belongs to, used by autocorrect to align every member at once.
    fn es_all_relevant_assignment_lines(
        &self,
        line: usize,
        assign_map: &std::collections::HashMap<usize, (usize, usize)>,
    ) -> Vec<usize> {
        let nlines = self.idx.starts.len();
        let down: Vec<usize> = (1..=line).rev().collect();
        let up: Vec<usize> = (line..=nlines).collect();
        let mut res = self.es_relevant_assignment_lines(&down, assign_map);
        res.extend(self.es_relevant_assignment_lines(&up, assign_map));
        res.sort_unstable();
        res.dedup();
        res
    }

    /// `aligned_with_equals_sign(token, line_range)`: is `tok` (on
    /// `token_line`) aligned with the SECOND entry of the relevant-
    /// assignment-lines scan over `line_range` (the first entry is always
    /// `tok`'s own line) — `None` when there's no such preceding assignment
    /// to compare against, `Yes`/`No` otherwise (reusing
    /// `sbfa_aligned_equals_operator`, the same end-column comparison
    /// `PrecedingFollowingAlignment#aligned_equals_operator?` performs).
    fn es_aligned_with_equals_sign(
        &self,
        token_line: usize,
        tok_start: usize,
        tok_end: usize,
        line_range: &[usize],
        assign_map: &std::collections::HashMap<usize, (usize, usize)>,
    ) -> EsAlignment {
        let token_line_indent = self.es_line_indentation(token_line);
        let assignment_lines = self.es_relevant_assignment_lines(line_range, assign_map);
        let Some(&relevant_line_number) = assignment_lines.get(1) else { return EsAlignment::None };
        let relevant_indent = self.es_line_indentation(relevant_line_number);
        if relevant_indent < token_line_indent {
            return EsAlignment::None;
        }
        let token_col = tok_start - self.idx.starts[token_line - 1];
        let ok =
            Self::sbfa_aligned_equals_operator(token_col, &self.src[tok_start..tok_end], self.sbfa_line_bytes(relevant_line_number));
        if ok {
            EsAlignment::Yes
        } else {
            EsAlignment::No
        }
    }

    /// `align_column`: the column this assignment operator's end would sit
    /// at if the padding immediately before it were collapsed to nothing
    /// (the `+ 1` reserves the single mandatory space).
    fn es_align_column(&self, tok_start: usize, tok_end: usize) -> isize {
        let line = self.idx.loc(tok_start).0;
        let ls = self.idx.starts[line - 1];
        let col0 = tok_start - ls;
        let line_bytes = self.sbfa_line_bytes(line);
        let leading = &line_bytes[..col0.min(line_bytes.len())];
        let trailing_spaces = leading.iter().rev().take_while(|&&b| b == b' ').count();
        let last_column = tok_end - ls;
        last_column as isize - trailing_spaces as isize + 1
    }

    /// `check_assignment` + `align_equal_signs`: detect every misaligned
    /// assignment line (`MSG_UNALIGNED_ASGN`), then — independent of WHICH
    /// offending token triggers it, since `align_to` is the same either way
    /// — realign every token in each offending block to the widest column,
    /// deduplicated per token exactly like upstream's `@corrected` set (a
    /// token already aligned by an earlier block-mate is left alone).
    fn es_check_assignments(&mut self, cop: &'static str, assign_map: &std::collections::HashMap<usize, (usize, usize)>) {
        let mut lines: Vec<usize> = assign_map.keys().copied().collect();
        lines.sort_unstable();
        // `@corrected`: a token already realigned by an earlier offense in
        // the SAME block contributes no new edit to a later offense's own
        // corrector call — such an offense is still reported (rubocop's
        // `add_offense` always fires), but with no actual replacement it's
        // NOT "correctable" in the CLI's `[Correctable]` sense (matches real
        // rubocop: only the first offense touching a given block ends up
        // marked correctable; its block-mates that were re-aligned as a
        // side effect are reported but not individually correctable).
        let mut corrected: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &line in &lines {
            let &(s, e) = &assign_map[&line];
            let down: Vec<usize> = (1..=line).rev().collect();
            if !matches!(self.es_aligned_with_equals_sign(line, s, e, &down, assign_map), EsAlignment::No) {
                continue;
            }
            let block = self.es_all_relevant_assignment_lines(line, assign_map);
            let toks: Vec<(usize, usize)> = block.iter().filter_map(|l| assign_map.get(l).copied()).collect();
            let align_to = toks.iter().map(|&(ts, te)| self.es_align_column(ts, te)).max();
            let mut made_edit = false;
            if let Some(align_to) = align_to {
                for (ts, te) in toks {
                    if !corrected.insert(ts) {
                        continue;
                    }
                    let last_col = (te - self.idx.starts[self.idx.loc(ts).0 - 1]) as isize;
                    let diff = align_to - last_col;
                    if diff > 0 {
                        self.fixes.push((ts, ts, vec![b' '; diff as usize]));
                        made_edit = true;
                    } else if diff < 0 {
                        let n = (-diff) as usize;
                        self.fixes.push((ts.saturating_sub(n), ts, Vec::new()));
                        made_edit = true;
                    }
                }
            }
            self.push(s, cop, made_edit, "`=` is not aligned with the preceding assignment.");
        }
    }
}



impl<'a> super::Cops<'a> {
    /// Layout/ClosingParenthesisIndentation (+ the shared `Alignment` mixin).
    /// Checks a HANGING closing `)`/`]` (preceded only by whitespace on its
    /// own line — `begins_its_line?`) for three call sites, each supplying
    /// its own `(left_paren, right_paren, elements)` triple before falling
    /// into the one shared `cpi_check` core (`check`/`check_for_elements`/
    /// `check_for_no_elements` collapsed together, since Rust doesn't need
    /// the empty/non-empty split into two separate methods the way upstream
    /// does for readability):
    ///   - `on_send`/`on_csend` -> a `CallNode`'s own `opening_loc`/
    ///     `closing_loc` (nil for a receiverless/braceless call, e.g.
    ///     `foo bar` or the `x * (...)` operator call itself — the `(...)`
    ///     there belongs to the ARGUMENT, a separate `ParenthesesNode`, not
    ///     this send), `elements` = `node.arguments` PLUS a trailing
    ///     `&block` `BlockArgumentNode` folded back in (prism keeps it out
    ///     of `arguments()`, in `block()` instead — mirrors
    ///     `check_multiline_method_call_brace_layout`'s identical fold).
    ///     Also fires generically for `[]`/`[]=` index calls (their
    ///     `opening_loc`/`closing_loc` are `[`/`]`) exactly as upstream's
    ///     `on_send` does — the hardcoded `` `)` `` in both messages is a
    ///     known upstream quirk carried over verbatim, not a bug in this
    ///     port.
    ///   - `on_begin` -> a `ParenthesesNode`'s `opening_loc`/`closing_loc`
    ///     (always present — parens always have both delimiters), whose
    ///     `elements` unwrap the `body` one level: `None` -> empty (bare
    ///     `()`), a `StatementsNode` -> its own `body()` list (the common
    ///     case, even for a SINGLE grouped expression like `(y + z)` —
    ///     prism always wraps statement lists in `StatementsNode`
    ///     regardless of length, confirmed live), anything else -> a
    ///     one-element list of that bare node (mirrors
    ///     `check_immutable_recursive`'s established fallback for the same
    ///     "body isn't a StatementsNode" edge). This is the ONLY site that
    ///     fires for whitequark's `:begin` node type; a `def`/top-level body
    ///     with 2+ statements and NO parens is also whitequark `:begin`
    ///     upstream, but never reaches prism's `visit_parentheses_node` at
    ///     all (it's a bare `StatementsNode`), so the "accepts begin nodes
    ///     that are not grouped expressions" fixture example is
    ///     unobservable by construction here rather than needing an
    ///     explicit guard.
    ///   - `on_def` (aliased `on_defs` upstream; prism unifies both into one
    ///     `DefNode` with an optional `receiver`, so one hook covers both)
    ///     -> the def's OWN `lparen_loc`/`rparen_loc` (`None` for a
    ///     paren-less def — `def foo a, b; end` — skipped entirely, whereas
    ///     `def foo(); end` still has both, just empty `elements`),
    ///     `elements` = `mlbl_ordered_params` (requireds/optionals/rest/
    ///     posts/keywords/keyword_rest/block, ParameterAlignment's existing
    ///     order-preserving flattener — identical grammar-order semantics to
    ///     whitequark's `node.arguments.children`, confirmed empty for
    ///     `parameters() == None` exactly when whitequark's `arguments.children`
    ///     would be `[]` too).
    ///
    /// Column bookkeeping is plain BYTE offset from each line's own start
    /// (matching every other alignment-family cop in this file, e.g.
    /// `check_parameter_alignment`/`check_first_parameter_indentation`) —
    /// NOT `display_column`'s Unicode-East-Asian-Width-aware count, because
    /// upstream's OWN `expected_column`/`all_elements_aligned?`/
    /// `correct_column_candidates` all read `.loc.column` directly (plain
    /// parser column), never routing through the `Alignment` mixin's
    /// `display_column` helper — that helper is only used by
    /// `check_alignment`/`each_bad_alignment`, which THIS cop's `check`
    /// override bypasses entirely (it has its own hand-rolled `check`/
    /// `check_for_elements`/`check_for_no_elements`, not the mixin's shared
    /// `check_alignment`).
    ///
    /// Autocorrect reuses `parameter_alignment_correct` verbatim (this
    /// cop's own `autocorrect` is upstream's other exact one-liner call to
    /// `AlignmentCorrector.correct`, and `right_paren` is always a
    /// single-character, single-line range, so the shared per-line-loop
    /// helper degenerates to exactly one iteration) — plus, unlike that
    /// helper, an explicit `Layout/IndentationStyle: EnforcedStyle: tabs`
    /// guard (`AlignmentCorrector.using_tabs?`), since this port's own
    /// `cpi_check` is the natural place to add it back (not exercised by
    /// the fixture, but a one-line addition for fidelity).
    pub(crate) fn check_closing_parenthesis_indentation_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/ClosingParenthesisIndentation";
        if !self.on(COP) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let Some(close) = node.closing_loc() else { return };
        let mut elements: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if let Some(block) = node.block() {
            if block.as_block_argument_node().is_some() {
                elements.push(block);
            }
        }
        let node_col = self.cpi_column(node.location().start_offset());
        self.cpi_check(open, close, &elements, node_col);
    }

    pub(crate) fn check_closing_parenthesis_indentation_begin(&mut self, node: &ruby_prism::ParenthesesNode) {
        const COP: &str = "Layout/ClosingParenthesisIndentation";
        if !self.on(COP) {
            return;
        }
        let open = node.opening_loc();
        let close = node.closing_loc();
        let elements: Vec<ruby_prism::Node> = match node.body() {
            None => Vec::new(),
            Some(b) => match b.as_statements_node() {
                Some(s) => s.body().iter().collect(),
                None => vec![b],
            },
        };
        // The `ParenthesesNode`'s own location always starts at `(`, so its
        // "own start column" candidate (upstream: `node.loc.column` for the
        // `check(node, node.children)` call site) is identical to
        // `left_paren.column` — no separate computation needed.
        let node_col = self.cpi_column(open.start_offset());
        self.cpi_check(open, close, &elements, node_col);
    }

    pub(crate) fn check_closing_parenthesis_indentation_def(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/ClosingParenthesisIndentation";
        if !self.on(COP) {
            return;
        }
        let Some(open) = node.lparen_loc() else { return };
        let Some(close) = node.rparen_loc() else { return };
        let elements: Vec<ruby_prism::Node> = match node.parameters() {
            Some(p) => mlbl_ordered_params(&p),
            None => Vec::new(),
        };
        // Upstream calls `check(node.arguments, node.arguments)` — the
        // whitequark `args` node's OWN location also starts at `(`, so its
        // "own start column" candidate again coincides with
        // `left_paren.column` exactly as in the `begin` case above.
        let node_col = self.cpi_column(open.start_offset());
        self.cpi_check(open, close, &elements, node_col);
    }

    /// 0-based BYTE column of `offset` on its own physical line.
    fn cpi_column(&self, offset: usize) -> usize {
        let (line, _) = self.idx.loc(offset);
        offset - self.idx.starts[line - 1]
    }

    /// `processed_source.line_indentation(line)`: count of leading
    /// space/tab bytes on physical line `line`.
    fn cpi_line_indentation(&self, line: usize) -> usize {
        let start = self.idx.starts[line - 1];
        let mut p = start;
        while p < self.src.len() && (self.src[p] == b' ' || self.src[p] == b'\t') {
            p += 1;
        }
        p - start
    }

    /// `Alignment#configured_indentation_width`: cop-local `IndentationWidth`
    /// (schema default `~`/nil — meaningful only when a user sets it
    /// directly), else `Layout/IndentationWidth`'s `Width` (schema default
    /// 2), else a hardcoded 2.
    fn cpi_indentation_width(&self) -> usize {
        self.cfg
            .get("Layout/ClosingParenthesisIndentation", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }

    /// `all_elements_aligned?`: when the FIRST element is a hash-shaped node
    /// (an explicit `{...}` `HashNode` OR the implicit bundled-trailing-
    /// keyword-args `KeywordHashNode` — both are whitequark's single
    /// `:hash` node type, hence the one `hash_type?` test upstream), compare
    /// the columns of ITS OWN pair/splat elements instead of the outer
    /// `elements` list; otherwise compare the outer elements' own columns
    /// directly. `true` iff there's exactly one distinct column among them
    /// (`.uniq.one?` — note this is `false`, not `true`, for an empty list,
    /// though that's unreachable here since `elements` is already known
    /// non-empty by the only call site).
    fn cpi_all_elements_aligned(&self, elements: &[ruby_prism::Node]) -> bool {
        let first = &elements[0];
        let cols: Vec<usize> = if let Some(h) = first.as_hash_node() {
            h.elements().iter().map(|c| self.cpi_column(c.location().start_offset())).collect()
        } else if let Some(h) = first.as_keyword_hash_node() {
            h.elements().iter().map(|c| self.cpi_column(c.location().start_offset())).collect()
        } else {
            elements.iter().map(|e| self.cpi_column(e.location().start_offset())).collect()
        };
        let mut uniq = cols.clone();
        uniq.sort_unstable();
        uniq.dedup();
        uniq.len() == 1
    }

    /// The shared core: `check`/`check_for_elements`/`check_for_no_elements`
    /// collapsed into one, keyed on `elements.is_empty()` exactly like
    /// upstream's own dispatch. `node_col` is the empty-branch's third
    /// `correct_column_candidates` entry (`node.loc.column`) — see each call
    /// site above for what it means per node kind.
    fn cpi_check(
        &mut self,
        left_paren: ruby_prism::Location,
        right_paren: ruby_prism::Location,
        elements: &[ruby_prism::Node],
        node_col: usize,
    ) {
        const COP: &str = "Layout/ClosingParenthesisIndentation";
        let rstart = right_paren.start_offset();
        let (rline, _) = self.idx.loc(rstart);
        let rline_start = self.idx.starts[rline - 1];
        // `begins_its_line?`: every byte before the closing delimiter on its
        // own line must be whitespace.
        if !self.src[rline_start..rstart].iter().all(|&b| b == b' ' || b == b'\t') {
            return;
        }
        let right_col = rstart - rline_start;
        let lstart = left_paren.start_offset();
        let (lline, _) = self.idx.loc(lstart);
        let left_col = lstart - self.idx.starts[lline - 1];

        let correct_column = if elements.is_empty() {
            // `correct_column_candidates`: line indentation of the opening
            // delimiter's own line, the opening delimiter's own column, and
            // the caller-supplied `node.loc.column`.
            let line_indent = self.cpi_line_indentation(lline);
            let candidates = [line_indent, left_col, node_col];
            if candidates.contains(&right_col) {
                return;
            }
            // "select the first one of candidates" — always the line
            // indentation, never the other two.
            candidates[0]
        } else {
            let first_start = elements[0].location().start_offset();
            let (first_line, _) = self.idx.loc(first_start);
            if first_line > lline {
                // `line_break_after_left_paren?`
                let source_indent = self.cpi_line_indentation(first_line);
                let width = self.cpi_indentation_width();
                source_indent.saturating_sub(width)
            } else if self.cpi_all_elements_aligned(elements) {
                left_col
            } else {
                self.cpi_line_indentation(first_line)
            }
        };

        if correct_column == right_col {
            return;
        }

        let message = if correct_column == left_col {
            "Align `)` with `(`.".to_string()
        } else {
            format!("Indent `)` to column {correct_column} (not {right_col})")
        };
        self.push(rstart, COP, true, message);

        if self.cfg.enforced_style("Layout/IndentationStyle") != "tabs" {
            let delta = correct_column as isize - right_col as isize;
            self.parameter_alignment_correct(rstart, rstart + 1, delta);
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Layout/IndentationConsistency — checks that entities on the same
    /// logical depth share the same indentation (`EnforcedStyle: normal`,
    /// the default), or that `protected`/`private` sections inside a
    /// class/module/`class_constructor?` block may each have their OWN
    /// internal indentation baseline as long as it's consistent within that
    /// section (`EnforcedStyle: indented_internal_methods`). Ports rubocop's
    /// `IndentationConsistency` cop + the shared `Alignment` mixin's
    /// `check_alignment`/`each_bad_alignment`/`register_offense`, and the
    /// `AlignmentCorrector` autocorrector — see `check_parameter_alignment`/
    /// `check_array_alignment` above for the same mixin ported to other cops.
    ///
    /// Hooked from TWO call sites in `mod.rs`, matching whitequark's two
    /// implicit multi-statement node shapes:
    /// - `on_begin` (from `visit_statements_node`): fires for a
    ///   `StatementsNode` with 2+ statements — every whitequark `:begin`
    ///   node is exactly that (a single-statement body is never wrapped at
    ///   all upstream, unlike prism's unconditional `StatementsNode`).
    /// - `on_kwbegin` (from `visit_begin_node`): fires only for an EXPLICIT
    ///   `begin...end` (`begin_keyword_loc` present) whose body has no
    ///   `rescue`/`ensure` clause — verified live (`Parser::CurrentRuby`)
    ///   that whitequark's `:kwbegin` node then has the raw statement list
    ///   as its OWN direct children (0, 1, or 2+ of them), unlike the
    ///   rescue/ensure case, where `:kwbegin` wraps exactly ONE child (the
    ///   nested `:rescue`/`:ensure` node) — a single-item list can never
    ///   produce an offense against a self-derived base column, so that
    ///   shape is skipped entirely as a guaranteed no-op.
    ///
    /// `node_start` is the begin/kwbegin's own start offset — used both to
    /// look up `ic_parent_of_body` (standing in for whitequark's
    /// `node.parent`, populated only for `ClassNode`/`ModuleNode`/
    /// `SingletonClassNode` bodies and `class_constructor?` block bodies —
    /// see that field's doc) and to test equality against
    /// `ic_top_level_stmts_start` (whitequark's `node.parent` is `nil`
    /// there).
    pub(crate) fn check_indentation_consistency(&mut self, node_start: usize, items_raw: Vec<ruby_prism::Node>) {
        const COP: &str = "Layout/IndentationConsistency";
        if !self.on(COP) {
            return;
        }
        let in_macro_scope =
            Some(node_start) == self.ic_top_level_stmts_start || self.ic_parent_of_body.contains_key(&node_start);
        if self.cfg.enforced_style(COP) == "indented_internal_methods" {
            // `check_indented_internal_methods_style`: a bare access
            // modifier is a group divider (excluded from every group), not
            // a member of one.
            let mut groups: Vec<Vec<ruby_prism::Node>> = vec![Vec::new()];
            for child in items_raw {
                if self.ic_bare_access_modifier(&child, in_macro_scope) {
                    groups.push(Vec::new());
                } else {
                    groups.last_mut().unwrap().push(child);
                }
            }
            for group in groups {
                self.ic_check_alignment(&group, None);
            }
        } else {
            // `check_normal_style`: a bare access modifier is excluded from
            // the checked list too, but (unlike the grouped style) doesn't
            // split it — the whole rest of the body is one list, optionally
            // pinned to the modifier's own column as its base.
            let base = self.ic_base_column_for_normal_style(node_start, &items_raw, in_macro_scope);
            let filtered: Vec<ruby_prism::Node> =
                items_raw.into_iter().filter(|c| !self.ic_bare_access_modifier(c, in_macro_scope)).collect();
            self.ic_check_alignment(&filtered, base);
        }
    }

    /// `bare_access_modifier?`: a bare (no-receiver, no-block, no-argument —
    /// `private()`'s empty parens count as "no argument" too, matching
    /// whitequark's identical `s(:send, nil, :private)` for both) call to
    /// `public`/`protected`/`private`/`module_function`, whose `macro?` +
    /// `in_macro_scope?` predicate — "sits directly in a class/module/
    /// sclass body, a `class_constructor?` block body, or the top-level
    /// program" — is approximated by the caller-computed `in_macro_scope`
    /// flag. NOT covered: `in_macro_scope?`'s further recursion through a
    /// nested `kwbegin`/`begin`/`any_block`/non-condition-`if` wrapper that
    /// is ITSELF in macro scope (e.g. a bare `private` sitting inside a
    /// plain `if`/`begin` inside a class body) — no fixture example nests a
    /// modifier that way.
    fn ic_bare_access_modifier(&self, node: &ruby_prism::Node, in_macro_scope: bool) -> bool {
        if !in_macro_scope {
            return false;
        }
        let Some(call) = node.as_call_node() else { return false };
        if call.receiver().is_some() || call.block().is_some() {
            return false;
        }
        if call.arguments().is_some_and(|a| !a.arguments().is_empty()) {
            return false;
        }
        matches!(call.name().as_slice(), b"public" | b"protected" | b"private" | b"module_function")
    }

    /// `base_column_for_normal_style`: `None` (meaning "derive from the
    /// first non-modifier item") unless the RAW first child (before the
    /// bare-modifier filter) is itself a bare access modifier. When it is:
    /// short-circuit to the modifier's own column directly when this
    /// begin/kwbegin IS the top-level program's own body (whitequark's
    /// `node.parent` is `nil`); otherwise compare it against the tracked
    /// parent's own starting column, using the modifier's column only when
    /// it's indented deeper than the parent.
    fn ic_base_column_for_normal_style(
        &self,
        node_start: usize,
        items_raw: &[ruby_prism::Node],
        in_macro_scope: bool,
    ) -> Option<usize> {
        let first = items_raw.first()?;
        if !self.ic_bare_access_modifier(first, in_macro_scope) {
            return None;
        }
        let access_modifier_indent = self.display_column(first.location().start_offset());
        if Some(node_start) == self.ic_top_level_stmts_start {
            return Some(access_modifier_indent);
        }
        let parent_start = *self.ic_parent_of_body.get(&node_start)?;
        let module_indent = self.display_column(parent_start);
        if access_modifier_indent > module_indent {
            Some(access_modifier_indent)
        } else {
            None
        }
    }

    /// `Alignment#check_alignment` + `each_bad_alignment` + `register_offense`:
    /// walks `items` in order; a candidate is one that starts a NEW source
    /// line relative to the previous item's line AND is the first
    /// non-whitespace token on that line (`begins_its_line?`). Its
    /// bad-alignment `column_delta` is `base - display_column(item)` (the
    /// Unicode East-Asian-Width-aware column via `display_column`); a zero
    /// delta needs no offense. `base` defaults to the FIRST item's own
    /// column when `explicit_base` is `None` — `Option::None` here means
    /// exactly "absent" and mirrors Ruby's `||=` (which does NOT override an
    /// explicit `0`, since `0` is truthy in Ruby — `Some(0)` likewise stays
    /// `0` here rather than being replaced).
    ///
    /// `@current_offenses`'s overlap guard: an offense node entirely within
    /// an already-registered (necessarily enclosing) offense's range is
    /// still reported, but its correction is dropped — `register_offense
    /// (expr, nil)`, and `AlignmentCorrector.correct` no-ops on a `nil` node.
    fn ic_check_alignment(&mut self, items: &[ruby_prism::Node], explicit_base: Option<usize>) {
        const COP: &str = "Layout/IndentationConsistency";
        if items.is_empty() {
            return;
        }
        let base = explicit_base.unwrap_or_else(|| self.display_column(items[0].location().start_offset()));
        let mut prev_line: Option<usize> = None;
        for item in items {
            let start = item.location().start_offset();
            let (line, _) = self.idx.loc(start);
            let starts_new_line = prev_line.map_or(true, |p| line > p);
            if starts_new_line {
                let line_start = self.idx.starts[line - 1];
                let begins_its_line = self.src[line_start..start].iter().all(u8::is_ascii_whitespace);
                if begins_its_line {
                    let actual = self.display_column(start);
                    let delta = base as isize - actual as isize;
                    if delta != 0 {
                        let end = item.location().end_offset();
                        let within_prior =
                            self.ic_registered_ranges.iter().any(|&(rs, re)| start >= rs && end <= re);
                        self.push(start, COP, !within_prior, "Inconsistent indentation detected.");
                        if !within_prior {
                            self.ic_correct(start, end, delta);
                        }
                        self.ic_registered_ranges.push((start, end));
                    }
                }
            }
            prev_line = Some(line);
        }
    }

    /// `AlignmentCorrector.correct`, ported for the single misaligned item
    /// (upstream's `autocorrect(corrector, node)` always gets the one bad
    /// node) — the identical per-physical-line-walk algorithm as
    /// `array_alignment_correct`/`parameter_alignment_correct` above (see
    /// either's doc): starting at the item's OWN begin offset (not the
    /// physical line's start) for line 1, then at each subsequent line's
    /// true start, widening (`delta > 0`) inserts `delta` spaces immediately
    /// before that position; narrowing removes `-delta` bytes, taken from
    /// the run starting at that position if it's itself a space (an
    /// interior line's own leading whitespace) or from just before it
    /// otherwise. Skips a would-be removal whose bytes aren't purely
    /// spaces/tabs. The `using_tabs?` global disable (`Layout/
    /// IndentationStyle: EnforcedStyle: tabs`) is ported; the heredoc/
    /// quoted-string taboo-range guard and the `=begin`/`=end` block-comment
    /// guard are NOT — no fixture example's misaligned item spans a
    /// heredoc, a multi-line string, or a block comment.
    fn ic_correct(&mut self, start: usize, end: usize, delta: isize) {
        if delta == 0 {
            return;
        }
        if self.cfg.enforced_style("Layout/IndentationStyle") == "tabs" {
            return;
        }
        let mut line_begin = start;
        loop {
            if delta > 0 {
                if self.src.get(line_begin) != Some(&b'\n') {
                    self.fixes.push((line_begin, line_begin, vec![b' '; delta as usize]));
                }
            } else {
                let n = (-delta) as usize;
                let starts_with_space = self.src.get(line_begin) == Some(&b' ');
                let (rs, re) = if starts_with_space {
                    (line_begin, line_begin + n)
                } else {
                    (line_begin.saturating_sub(n), line_begin)
                };
                if re <= self.src.len() && rs < re && self.src[rs..re].iter().all(|&b| b == b' ' || b == b'\t') {
                    self.fixes.push((rs, re, Vec::new()));
                }
            }
            let mut p = line_begin;
            while p < end && self.src[p] != b'\n' {
                p += 1;
            }
            if p >= end {
                break;
            }
            line_begin = p + 1;
        }
    }
}

/// Layout/IndentationConsistency: `class_constructor?`'s `any_block` branch,
/// checked directly on a `CallNode` (from `visit_call_node`, before its
/// `block` is visited): a call to `new` on a bare/`::`-qualified
/// `Class`/`Module`/`Struct` constant, or `define` on `Data`, matching
/// `global_const?`'s `(const {nil? cbase} %1)` — a plain top-level constant
/// reference or one with a leading `::`, never a deeper-namespaced one
/// (`Foo::Struct.new` doesn't match).
pub(crate) fn ic_is_class_constructor_call(call: &ruby_prism::CallNode, src: &[u8]) -> bool {
    if call.is_safe_navigation() {
        return false;
    }
    let Some(r) = call.receiver() else { return false };
    let l = r.location();
    let recv = &src[l.start_offset()..l.end_offset()];
    match call.name().as_slice() {
        b"new" => matches!(recv, b"Class" | b"::Class" | b"Module" | b"::Module" | b"Struct" | b"::Struct"),
        b"define" => matches!(recv, b"Data" | b"::Data"),
        _ => false,
    }
}



impl<'a> super::Cops<'a> {
    /// Layout/ArgumentAlignment — checks that the arguments of a multi-line
    /// method CALL (as opposed to Layout/ParameterAlignment's method
    /// *definition*) are aligned: to the first argument's own column
    /// (`EnforcedStyle: with_first_argument`, the default), or to the
    /// call's own selector line's indentation plus one configured
    /// indentation step (`with_fixed_indentation`). Ports rubocop's
    /// `ArgumentAlignment` cop + the shared `Alignment` mixin's
    /// `check_alignment`/`each_bad_alignment`/`register_offense`, and the
    /// `AlignmentCorrector` autocorrector — see `check_parameter_alignment`
    /// and `check_array_alignment` above for the same shared mixin ported
    /// for the sibling cops.
    ///
    /// `on_send` (prism unifies `on_send`/`alias on_csend` into one
    /// `CallNode` hook — the only place `csend`-ness matters here is the
    /// `[]=` exclusion below) bails out when: (a) `multiple_arguments?` is
    /// false (fewer than 2 raw arguments, UNLESS the sole argument is a
    /// braceless keyword hash with >= 2 pairs — prism's `KeywordHashNode`,
    /// distinct from an explicit `{...}` `HashNode`, which never flattens);
    /// (b) this is a plain (non-safe-nav) `[]=` indexed-assignment send
    /// (`a[b] = c`, rewritten by prism into an ordinary `CallNode` named
    /// `:[]=` with no `call_operator_loc` of its own — safe navigation
    /// earlier in the receiver chain, e.g. `Test&.config[x] = y`, doesn't
    /// change THIS call's own operator, so it's excluded exactly the same);
    /// or (c) `with_first_argument_style? && enforce_hash_argument_with_
    /// separator?` (autocorrect_incompatible_with_other_cops?` — the
    /// default `key`/`key` HashAlignment styles never satisfy this, so it's
    /// only reachable with an explicit user config the fixture never sets).
    ///
    /// `flattened_arguments`: rubocop's `node.arguments` also has an
    /// explicit `&block` block-pass as its own trailing element (prism
    /// keeps it out of `ArgumentsNode` entirely, as `node.block` instead —
    /// `argalign_call_items` below re-appends it when present, mirroring
    /// that). Under `with_fixed_indentation`, only the LAST raw argument is
    /// flattened into its own individual pairs when it's a braceless hash
    /// (`arguments_with_last_arg_pairs`); otherwise (the default style),
    /// only the FIRST raw argument is flattened the same way
    /// (`arguments_or_first_arg_pairs`) — a trailing braceless hash after
    /// other positional args counts as a single item for that style
    /// (matching the fixture's `func2(do_something, foo: ..., bar: ...)`
    /// case, where only ONE offense fires, anchored at the hash's own
    /// start, yet the autocorrect still reindents every line inside the
    /// hash's own range — see `argalign_correct`'s per-line loop).
    ///
    /// `each_bad_alignment`'s core loop: walking the items in order, only
    /// one that (a) starts a NEW source line relative to the previous
    /// item's line, and (b) is the first non-whitespace token on that line
    /// (`begins_its_line?`) is a candidate; its bad-alignment
    /// `column_delta` is `base - display_column(item)` (the Unicode
    /// East-Asian-Width-aware column). A zero delta is fine; otherwise it's
    /// an offense anchored at the item's own start.
    ///
    /// `Alignment#check_alignment`'s `@current_offenses` overlap guard IS
    /// ported here (via `argalign_registered_ranges`, this cop's own
    /// separate cop-instance-wide accumulator — see its field doc) because
    /// the fixture's "doesn't crash and burn when there are nested issues"
    /// regression test exercises it directly: a `build(:house, :rooms =>
    /// [...])` call whose bracketed array value contains further
    /// misaligned nested `build(...)` calls, each getting its own `on_send`
    /// investigation. Without the guard, the outer call's own correction
    /// (reindenting every line in its multi-line hash-pair item, including
    /// all the nested calls' lines) and the inner calls' own corrections
    /// would both target overlapping byte ranges; upstream avoids the
    /// collision by still registering the inner offense but skipping its
    /// correction (`register_offense(expr, nil)`), which is safe because a
    /// LATER pass (this engine reruns the whole lint after applying
    /// non-overlapping fixes) picks it up again once the outer rewrite has
    /// already resolved that region. NOT ported: `AlignmentCorrector`'s
    /// non-heredoc "multi-line quoted string interior" taboo case and
    /// `block_comment_within?` — neither is exercised by the fixture (the
    /// one heredoc example, `class_eval(<<-EOS, __FILE__, __LINE__ + 1)`,
    /// has all three arguments on ITS OWN single source line, so it never
    /// even reaches `each_bad_alignment`'s "begins a new line" branch).
    pub(crate) fn check_argument_alignment(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/ArgumentAlignment";
        if !self.on(COP) {
            return;
        }
        let items_base = argalign_call_items(node);
        if !argalign_multiple_arguments(&items_base) {
            return;
        }
        // `node.call_type? && node.method?(:[]=)`: only THIS call's own
        // operator matters, not any safe navigation earlier in the
        // receiver chain (`is_safe_navigation()` mirrors `csend_type?`).
        if !node.is_safe_navigation() && node.name().as_slice() == b"[]=" {
            return;
        }
        let fixed_indentation = self.cfg.enforced_style(COP) == "with_fixed_indentation";
        if !fixed_indentation && self.argalign_hash_separator_style() {
            return;
        }

        let items: Vec<ruby_prism::Node> = if fixed_indentation {
            argalign_with_last_arg_pairs(items_base)
        } else {
            argalign_or_first_arg_pairs(items_base)
        };
        let Some(first) = items.first() else { return };

        let base = if fixed_indentation {
            // `target_method_lineno`: `node.loc.selector` (prism's
            // `message_loc` — present for every named call AND for a bare
            // `[]`/`[]=` bracket call alike, absent only for the
            // `.()`-shorthand `Proc#call`), else the opening-paren's line.
            let lineno_offset = node
                .message_loc()
                .map(|l| l.start_offset())
                .or_else(|| node.opening_loc().map(|l| l.start_offset()))
                .unwrap_or_else(|| node.location().start_offset());
            let (line, _) = self.idx.loc(lineno_offset);
            let line_start = self.idx.starts[line - 1];
            let mut p = line_start;
            while p < self.src.len() && self.src[p].is_ascii_whitespace() {
                p += 1;
            }
            let indentation_of_line = p - line_start;
            indentation_of_line + self.argalign_indentation_width(COP)
        } else {
            self.display_column(first.location().start_offset())
        };

        let mut prev_line: Option<usize> = None;
        for item in &items {
            let start = item.location().start_offset();
            let (line, _) = self.idx.loc(start);
            let starts_new_line = prev_line.map_or(true, |p| line > p);
            if starts_new_line {
                let line_start = self.idx.starts[line - 1];
                let begins_its_line = self.src[line_start..start].iter().all(u8::is_ascii_whitespace);
                if begins_its_line {
                    let actual = self.display_column(start);
                    if actual != base {
                        let delta = base as isize - actual as isize;
                        let end = item.location().end_offset();
                        let msg = if fixed_indentation {
                            "Use one level of indentation for arguments following the first line of a multi-line method call."
                        } else {
                            "Align the arguments of a method call if they span more than one line."
                        };
                        let within_prior = self
                            .argalign_registered_ranges
                            .iter()
                            .any(|&(rs, re)| start >= rs && end <= re);
                        self.push(start, COP, !within_prior, msg);
                        if !within_prior {
                            self.argalign_correct(start, end, delta);
                        }
                        self.argalign_registered_ranges.push((start, end));
                    }
                }
            }
            prev_line = Some(line);
        }
    }

    /// `Alignment#configured_indentation_width`: the cop's own
    /// `IndentationWidth` (no schema default — meaningful only when a user
    /// sets it directly on this cop), else `Layout/IndentationWidth`'s
    /// `Width` (schema default 2) — identical fallback chain to
    /// `parameter_alignment_indentation_width`/`aa_indentation_width`.
    fn argalign_indentation_width(&self, cop: &'static str) -> usize {
        self.cfg
            .get(cop, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }

    /// `autocorrect_incompatible_with_other_cops?`'s `enforce_hash_argument_
    /// with_separator?`: true when `Layout/HashAlignment` is itself enabled
    /// (`for_enabled_cop`) and EITHER of its two separator-style params
    /// (`EnforcedColonStyle`/`EnforcedHashRocketStyle`) is set to (or, for
    /// `AllowMultipleStyles`'s array form, includes) `'separator'`. The
    /// schema default for both is the plain string `'key'`, so this is
    /// unreachable unless a config explicitly opts in.
    fn argalign_hash_separator_style(&self) -> bool {
        if !self.cfg.cop_config_enabled("Layout/HashAlignment") {
            return false;
        }
        ["EnforcedColonStyle", "EnforcedHashRocketStyle"]
            .iter()
            .any(|&style| self.cfg.get("Layout/HashAlignment", style).unwrap_or("key").contains("separator"))
    }

    /// `AlignmentCorrector.correct`, ported for the single misaligned
    /// argument/pair node — see `array_alignment_correct`'s doc for the
    /// full per-line walk this is copied from verbatim (widen/narrow logic,
    /// the `using_tabs?` global disable, and the heredoc taboo-range
    /// guard).
    fn argalign_correct(&mut self, start: usize, end: usize, delta: isize) {
        if delta == 0 {
            return;
        }
        if self.cfg.enforced_style("Layout/IndentationStyle") == "tabs" {
            return;
        }
        let mut line_begin = start;
        loop {
            let (line_no, _) = self.idx.loc(line_begin);
            let taboo = self.heredoc_lines.iter().any(|&(hs, he, _, _)| line_no >= hs && line_no <= he + 1);
            if !taboo {
                if delta > 0 {
                    if self.src.get(line_begin) != Some(&b'\n') {
                        self.fixes.push((line_begin, line_begin, vec![b' '; delta as usize]));
                    }
                } else {
                    let n = (-delta) as usize;
                    let starts_with_space = self.src.get(line_begin) == Some(&b' ');
                    let (rs, re) = if starts_with_space {
                        (line_begin, line_begin + n)
                    } else {
                        (line_begin.saturating_sub(n), line_begin)
                    };
                    if re <= self.src.len()
                        && rs < re
                        && self.src[rs..re].iter().all(|&b| b == b' ' || b == b'\t')
                    {
                        self.fixes.push((rs, re, Vec::new()));
                    }
                }
            }
            // Advance to the next physical line within [start, end), if any.
            let mut p = line_begin;
            while p < end && self.src[p] != b'\n' {
                p += 1;
            }
            if p >= end {
                break;
            }
            line_begin = p + 1;
        }
    }
}

/// The raw list rubocop's `node.arguments` produces for a `CallNode`: every
/// element of prism's own `ArgumentsNode` (positional, splat, keyword-hash,
/// block-splat alike — one item per top-level argument), PLUS an explicit
/// `&block` block-pass appended at the end when present (prism keeps that
/// out of `ArgumentsNode` entirely, as the call's separate `block` field —
/// a `do...end`/`{}` block literal there is a DIFFERENT prism node kind,
/// `BlockNode`, and is correctly never appended: rubocop's own AST keeps
/// block literals out of `node.arguments` too, wrapping the whole send in a
/// separate `:block` node instead).
fn argalign_call_items<'pr>(node: &ruby_prism::CallNode<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    let mut items: Vec<ruby_prism::Node> = match node.arguments() {
        Some(a) => a.arguments().iter().collect(),
        None => Vec::new(),
    };
    if let Some(b) = node.block() {
        if b.as_block_argument_node().is_some() {
            items.push(b);
        }
    }
    items
}

/// `multiple_arguments?`: at least 2 raw items, or exactly 1 that's itself
/// a braceless keyword hash (prism's `KeywordHashNode`) with >= 2 pairs.
fn argalign_multiple_arguments(items: &[ruby_prism::Node]) -> bool {
    if items.len() >= 2 {
        return true;
    }
    items.first().and_then(|f| f.as_keyword_hash_node()).is_some_and(|kw| kw.elements().len() >= 2)
}

/// `arguments_or_first_arg_pairs`: if the FIRST item is a braceless keyword
/// hash, flatten it into its own individual pair nodes (`AssocNode`/
/// `AssocSplatNode`); otherwise the raw item list is used as-is (an
/// explicit `{...}` `HashNode` — prism's distinct node kind for a braced
/// hash literal — is never flattened, matching `!braces?`).
fn argalign_or_first_arg_pairs<'pr>(items: Vec<ruby_prism::Node<'pr>>) -> Vec<ruby_prism::Node<'pr>> {
    if let Some(kw) = items.first().and_then(|f| f.as_keyword_hash_node()) {
        return kw.elements().iter().collect();
    }
    items
}

/// `arguments_with_last_arg_pairs`: the raw items minus the last, plus
/// either the LAST item's own pairs (if it's a braceless keyword hash) or
/// the last item itself unchanged.
fn argalign_with_last_arg_pairs<'pr>(mut items: Vec<ruby_prism::Node<'pr>>) -> Vec<ruby_prism::Node<'pr>> {
    let Some(last) = items.pop() else { return items };
    match last.as_keyword_hash_node() {
        Some(kw) => items.extend(kw.elements().iter()),
        None => items.push(last),
    }
    items
}


impl<'a> Cops<'a> {
    /// Layout/MultilineBlockLayout — ported from `on_block` (aliased to
    /// `on_numblock`/`on_itblock`; all three collapse to prism's single
    /// `BlockNode` — see `check_multiline_block_layout_block`) plus a stabby
    /// lambda's `LambdaNode` (RuboCop's translation treats `-> (x) { }` as a
    /// `:block` node too — `BlockNode#lambda?` is `send_node.method?
    /// (:lambda)` — so `on_block` fires for it exactly the same way; see
    /// `check_multiline_block_layout_lambda`).
    ///
    /// Two known traps this leans on:
    ///   - `node.source_range` (used for `needed_length_for_args`'s column/
    ///     first-line math AND `autocorrect_body`'s indent width) is
    ///     receiver-chain-inclusive for a do/end-or-brace block — i.e. it's
    ///     the OWNING CALL's own range (`foo.bar do...end` starts at `foo`),
    ///     never prism's own `BlockNode::location()` (which starts at `do`/
    ///     `{`, per the "block ranges start at the selector" trap). The
    ///     owning call's start is recovered from `rp_ancestors` (see
    ///     `mbl_outer_start`). A stabby lambda has no owning call — prism's
    ///     `LambdaNode::location()` already spans the whole literal from
    ///     `->`, so it needs no lookup at all.
    ///   - a def-with-rescue/ensure-shaped block body is an implicit prism
    ///     `BeginNode` spanning from the first statement THROUGH the block's
    ///     own `end` — never use ITS location as "the body's start"; drill
    ///     into `.statements()` first (same fix as `dn_compute_def_last_child`
    ///     elsewhere in this file).
    ///
    /// Offense anchors only ever need a START offset (the oracle grades on
    /// the first `^` position, not the full underlined range), so unlike
    /// upstream's `range_between(expr.begin_pos, expr.end_pos)` this never
    /// bothers constructing an end position for detection purposes.
    fn check_multiline_block_layout(
        &mut self,
        opening: ruby_prism::Location<'_>,
        closing: ruby_prism::Location<'_>,
        parameters: Option<ruby_prism::Node<'_>>,
        body: Option<ruby_prism::Node<'_>>,
        outer_start: usize,
    ) {
        const COP: &str = "Layout/MultilineBlockLayout";
        const ARG_MSG: &str = "Block argument expression is not on the same line as the block start.";
        const MSG: &str = "Block body expression is on the same line as the block start.";
        if !self.on(COP) {
            return;
        }
        let begin_off = opening.start_offset();
        let begin_end = opening.end_offset();
        let begin_line = self.idx.loc(begin_off).0;
        // `single_line?`: `loc.begin.line == loc.end.line` — the block's OWN
        // opening/closing delimiters, never the (possibly receiver-chain-
        // inclusive) outer range.
        if begin_line == self.idx.loc(closing.start_offset()).0 {
            return;
        }

        // `node.arguments?`/`node.arguments`: only an explicit `|...|` (or
        // stabby-lambda `(...)`) parameter list counts — a numbered (`_1`)
        // or `it` param block has none (upstream's `arguments` returns `[]`
        // for those block types).
        let args = parameters.as_ref().and_then(|p| p.as_block_parameters_node());

        let args_on_beginning_line = match &args {
            None => true,
            Some(a) => begin_line == self.idx.loc(a.location().end_offset().saturating_sub(1)).0,
        };

        let mut arg_offense = false;
        if !args_on_beginning_line {
            let a = args.as_ref().unwrap();
            let needs_break = self
                .mbl_max_line_length()
                .is_some_and(|max| self.mbl_needed_length_for_args(outer_start, a) > max);
            if !needs_break {
                self.push(a.location().start_offset(), COP, true, ARG_MSG);
                arg_offense = true;
            }
        }

        // `node.body`: prism always wraps a non-empty body in a
        // `StatementsNode`, unwrapping (or not) never changes the START
        // offset used here (a `StatementsNode`'s own location always starts
        // exactly where its first child starts) — so there is no need to
        // replicate whitequark's single-statement unwrap at all, only the
        // def-with-rescue `BeginNode` trap.
        let body_start = body.as_ref().map(|b| self.mbl_body_start(b));

        let mut body_offense = false;
        if let Some(bstart) = body_start {
            if self.idx.loc(bstart).0 == begin_line {
                self.push(bstart, COP, true, MSG);
                body_offense = true;
            }
        }

        if !arg_offense && !body_offense {
            return;
        }

        // ---- autocorrect (upstream's `autocorrect`, run unconditionally
        // once either offense fires — the two conditions are mutually
        // exclusive in practice: multi-line args always push the body past
        // `begin_line`, so both never fire on the same node at once, but the
        // body-move side effect below can still trigger off an ARG_MSG-only
        // offense) ----
        let mut expr_before_body: Option<usize> = None;
        if !args_on_beginning_line {
            let a = args.as_ref().unwrap();
            self.mbl_autocorrect_arguments(begin_end, a);
            expr_before_body = Some(a.location().end_offset());
        }
        if let Some(bstart) = body_start {
            let anchor = expr_before_body.unwrap_or(begin_off);
            if self.idx.loc(anchor).0 == self.idx.loc(bstart).0 {
                let block_start_col = self.idx.loc(outer_start).1 - 1;
                let indent = format!("\n  {}", " ".repeat(block_start_col));
                self.fixes.push((bstart, bstart, indent.into_bytes()));
            }
        }
    }

    /// Hook for a `do...end`/`{}` call block. `outer_start` is the OWNING
    /// CALL's own prism start offset (receiver-chain-inclusive), recovered
    /// from the ancestor frame `visit_branch_node_enter` just pushed for it
    /// — see the trap note on `check_multiline_block_layout`.
    pub(crate) fn check_multiline_block_layout_block(&mut self, node: &ruby_prism::BlockNode<'_>) {
        let fallback = node.location().start_offset();
        let outer_start = self.mbl_owning_call_start(fallback);
        self.check_multiline_block_layout(node.opening_loc(), node.closing_loc(), node.parameters(), node.body(), outer_start);
    }

    /// Hook for a stabby lambda. Its own prism `location()` already spans
    /// the whole `-> ... end`/`-> { }` literal from the `->` operator, which
    /// is exactly upstream's (receiver-less) `node.source_range` here.
    pub(crate) fn check_multiline_block_layout_lambda(&mut self, node: &ruby_prism::LambdaNode<'_>) {
        let outer_start = node.location().start_offset();
        self.check_multiline_block_layout(node.opening_loc(), node.closing_loc(), node.parameters(), node.body(), outer_start);
    }

    /// Nearest enclosing `Call` ancestor's own start offset — `rp_ancestors`
    /// always has THIS block's own just-pushed frame on top, so skip it,
    /// same as `style::Cops::rp_parent` (private to that module; reimplemented
    /// here directly off the shared `rp_ancestors` field rather than reaching
    /// across module boundaries for a one-off lookup).
    fn mbl_owning_call_start(&self, fallback: usize) -> usize {
        let len = self.rp_ancestors.len();
        self.rp_ancestors[..len.saturating_sub(1)]
            .iter()
            .rev()
            .find_map(|f| f.as_ref())
            .filter(|k| k.tag == super::style::RpTag::Call)
            .map(|k| k.start)
            .unwrap_or(fallback)
    }

    /// `node.body`'s real start offset, peeling the implicit rescue/ensure
    /// `BeginNode` wrapper the same way `dn_compute_def_last_child` does for
    /// `def` bodies (its location spans from here through the block's own
    /// `end`, never usable directly).
    fn mbl_body_start(&self, body: &ruby_prism::Node<'_>) -> usize {
        if let Some(b) = body.as_begin_node() {
            if let Some(stmts) = b.statements() {
                return stmts.location().start_offset();
            }
        }
        body.location().start_offset()
    }

    fn mbl_max_line_length(&self) -> Option<i64> {
        if self.cfg.param("Layout/LineLength", "Enabled") == Some("false") {
            return None; // `max_line_length` returns nil -> falsy
        }
        Some(self.cfg.get("Layout/LineLength", "Max").and_then(|v| v.parse::<i64>().ok()).unwrap_or(120))
    }

    /// `needed_length_for_args`: how long the line would be if the (still
    /// multi-line) block header were joined onto one line.
    fn mbl_needed_length_for_args(&self, outer_start: usize, args: &ruby_prism::BlockParametersNode<'_>) -> i64 {
        let col = (self.idx.loc(outer_start).1 - 1) as i64;
        let rest = &self.src[outer_start..];
        let first_line_end = rest.iter().position(|&b| b == b'\n').map(|n| outer_start + n).unwrap_or(self.src.len());
        let first_line = &self.src[outer_start..first_line_end];
        // `characters_needed_for_space_and_pipes`: the opening pipe already
        // trails the first line (`lambda do |\n...`) needs only the closing
        // pipe; otherwise both pipes AND the joining space are still needed.
        let chars_needed: i64 = if first_line.ends_with(b"|") { 1 } else { 3 };
        col + chars_needed + mbl_char_count(first_line) as i64 + mbl_char_count(self.mbl_block_arg_string(args).as_bytes()) as i64
    }

    /// `autocorrect_arguments`: replace everything from right after the
    /// opening delimiter through the closing pipe (plus any trailing
    /// spaces/tabs before a newline — `range_with_surrounding_space(side:
    /// :right, newlines: false)`) with the joined `" |args|"`.
    fn mbl_autocorrect_arguments(&mut self, begin_end: usize, args: &ruby_prism::BlockParametersNode<'_>) {
        let args_end = args.location().end_offset();
        let mut end_pos = args_end;
        while end_pos < self.src.len() && matches!(self.src[end_pos], b' ' | b'\t') {
            end_pos += 1;
        }
        let replacement = format!(" |{}|", self.mbl_block_arg_string(args));
        self.fixes.push((begin_end, end_pos, replacement.into_bytes()));
    }

    /// `block_arg_string`: the flattened, comma-joined parameter list —
    /// `sabp_flatten_args` already gives the exact source-ordered child list
    /// upstream's whitequark `args.children` would (regular params in
    /// Ruby's fixed grammar order, then any `; shadow` locals, bare trailing
    /// commas excluded).
    fn mbl_block_arg_string(&self, args: &ruby_prism::BlockParametersNode<'_>) -> String {
        let children = sabp_flatten_args(args);
        self.mbl_join_children(args, &children)
    }

    fn mbl_join_children(&self, top: &ruby_prism::BlockParametersNode<'_>, children: &[ruby_prism::Node<'_>]) -> String {
        let parts: Vec<String> = children.iter().map(|arg| self.mbl_arg_text(top, arg)).collect();
        let mut s = parts.join(", ");
        if self.mbl_include_trailing_comma(top) {
            s.push(',');
        }
        s
    }

    fn mbl_arg_text(&self, top: &ruby_prism::BlockParametersNode<'_>, arg: &ruby_prism::Node<'_>) -> String {
        if let Some(mt) = arg.as_multi_target_node() {
            let mut inner: Vec<ruby_prism::Node> = Vec::new();
            inner.extend(mt.lefts().iter());
            if let Some(r) = mt.rest() {
                if r.as_implicit_rest_node().is_none() {
                    inner.push(r);
                }
            }
            inner.extend(mt.rights().iter());
            format!("({})", self.mbl_join_children(top, &inner))
        } else {
            let loc = arg.location();
            String::from_utf8_lossy(&self.src[loc.start_offset()..loc.end_offset()]).into_owned()
        }
    }

    /// `include_trailing_comma?`: exactly one plain required param anywhere
    /// in the WHOLE tree (top-level or nested inside a destructured group)
    /// AND the raw pipe-to-pipe source contains a comma.
    fn mbl_include_trailing_comma(&self, top: &ruby_prism::BlockParametersNode<'_>) -> bool {
        let count = top.parameters().map(|p| self.mbl_count_required_list(&p)).unwrap_or(0);
        if count != 1 {
            return false;
        }
        let loc = top.location();
        self.src[loc.start_offset()..loc.end_offset()].contains(&b',')
    }

    fn mbl_count_required_list(&self, params: &ruby_prism::ParametersNode<'_>) -> usize {
        let mut c = 0;
        for n in params.requireds().iter() {
            c += self.mbl_count_required(&n);
        }
        for n in params.posts().iter() {
            c += self.mbl_count_required(&n);
        }
        c
    }

    fn mbl_count_required(&self, node: &ruby_prism::Node<'_>) -> usize {
        if node.as_required_parameter_node().is_some() {
            return 1;
        }
        if let Some(mt) = node.as_multi_target_node() {
            let mut c = 0;
            for n in mt.lefts().iter() {
                c += self.mbl_count_required(&n);
            }
            for n in mt.rights().iter() {
                c += self.mbl_count_required(&n);
            }
            return c;
        }
        0
    }
}

/// ASCII fast path, same convention as `Layout/LineLength`'s own char count.
fn mbl_char_count(bytes: &[u8]) -> usize {
    if bytes.is_ascii() {
        bytes.len()
    } else {
        String::from_utf8_lossy(bytes).chars().count()
    }
}


// ---------------------------------------------------------------------
// Layout/HashAlignment — ports `HashAlignmentStyles` (the `KeyAlignment`/
// `TableAlignment`/`SeparatorAlignment`/`KeywordSplatAlignment` delta
// classes + `HashElementNode`/`HashElementDelta`) and the cop itself
// (`lib/rubocop/cop/layout/hash_alignment.rb`) ~verbatim.
// ---------------------------------------------------------------------

/// One hash "element" — a `pair` (`AssocNode`) or a `kwsplat`/forwarded
/// `**` (`AssocSplatNode`) — reduced to the byte offsets the delta math
/// below needs. For a pair, `start` is the KEY's own start, which is always
/// the pair's own overall start too (a pair's range begins at its key); for
/// a kwsplat, `start` is the `**` operator's start (rubocop-ast's
/// `KeywordSplatNode#node_parts` duck-types `key`/`value` to the whole node
/// itself, so "key" and the node's own range coincide there too).
///
/// prism merges a colon-label key's trailing `:` into the KEY node's own
/// location (`key: 1`'s key `SymbolNode` spans `"key:"`, not just `"key"`),
/// unlike whitequark's parser gem where `pair.key.source_range` excludes
/// the colon and `pair.loc.operator` is the colon's own 1-byte range
/// (starting exactly where the excluded key ends). `key_end`/`op_start`/
/// `op_end` below undo that merge: `key_end` is the DISPLAY key end (colon
/// excluded — matches whitequark's `key.source_range.end`), `op_start`/
/// `op_end` bracket the separator itself (for a colon: `key_end` and
/// `key_end + 1`, i.e. the one excluded byte; for a hash rocket: prism's
/// own `operator_loc`). Every formula below reads columns as plain
/// DIFFERENCES between two such offsets, so which "base" `idx.loc` counts
/// from (0- or 1-indexed) never matters — only the one absolute use (the
/// left-edge clamp in `ha_correct`) explicitly normalizes to 0-based.
#[derive(Clone, Copy)]
struct HaElem {
    kwsplat: bool,
    hash_rocket: bool,
    start: usize,
    end: usize,
    key_end: usize,
    op_start: usize,
    op_end: usize,
    value_start: usize,
    value_omitted: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum HaFormat {
    Key,
    Table,
    Separator,
    KwSplat,
}

impl HaFormat {
    fn message(self) -> &'static str {
        match self {
            HaFormat::Key => "Align the keys of a hash literal if they span more than one line.",
            HaFormat::Table => {
                "Align the keys and values of a hash literal if they span more than one line."
            }
            HaFormat::Separator => {
                "Align the separators of a hash literal if they span more than one line."
            }
            HaFormat::KwSplat => {
                "Align keyword splats with the rest of the hash if it spans more than one line."
            }
        }
    }
}

/// A pending correction's `{ key:, separator:, value: }` — `None` means the
/// key was absent from the Ruby delta hash (never computed, so it never
/// participates in `good_alignment?`'s "all zero" check and defaults to 0
/// in `correct_node`).
#[derive(Clone, Copy, Default)]
struct HaDelta {
    key: Option<isize>,
    separator: Option<isize>,
    value: Option<isize>,
}
impl HaDelta {
    /// `good_alignment?`: every PRESENT delta is zero (vacuously true for
    /// `{}, e.g. `SeparatorAlignment#deltas_for_first_pair`).
    fn good(&self) -> bool {
        [self.key, self.separator, self.value].iter().all(|d| d.map_or(true, |v| v == 0))
    }
}

/// `check_delta`: record that `elem_start` was considered under `fmt`
/// (inserting an empty bucket + noting insertion ORDER even when the delta
/// turns out to be good — `add_offenses`'s `min_by` ties break by this
/// order), then, only if the delta is bad, remember it for correction and
/// push the element onto that format's offense list (which — mirroring
/// upstream exactly — can end up holding the very first pair's own start
/// TWICE: once from `deltas_for_first_pair`, once again from the main
/// `node.children` loop re-deriving the same delta for it. Harmless: both
/// computations agree, `ha_register` dedupes by start before emitting).
fn ha_note_delta(
    order: &mut Vec<HaFormat>,
    buckets: &mut std::collections::HashMap<HaFormat, Vec<usize>>,
    deltas: &mut std::collections::HashMap<(HaFormat, usize), HaDelta>,
    fmt: HaFormat,
    elem_start: usize,
    delta: HaDelta,
) {
    if !buckets.contains_key(&fmt) {
        order.push(fmt);
        buckets.insert(fmt, Vec::new());
    }
    if delta.good() {
        return;
    }
    deltas.insert((fmt, elem_start), delta);
    buckets.get_mut(&fmt).unwrap().push(elem_start);
}

impl<'a> super::Cops<'a> {
    fn ha_line(&self, off: usize) -> usize {
        self.idx.loc(off).0
    }
    fn ha_col(&self, off: usize) -> isize {
        self.idx.loc(off).1 as isize
    }
    /// `HashElementNode#same_line?`: `loc.last_line == other.loc.line ||
    /// loc.line == other.loc.last_line` (a multiline element is "on the
    /// same line" as another if it shares EITHER of its own two boundary
    /// lines with either of the other's).
    fn ha_same_line(&self, a: &HaElem, b: &HaElem) -> bool {
        let a_first = self.ha_line(a.start);
        let a_last = self.ha_line(a.end.saturating_sub(1).max(a.start));
        let b_first = self.ha_line(b.start);
        let b_last = self.ha_line(b.end.saturating_sub(1).max(b.start));
        a_last == b_first || a_first == b_last
    }
    /// `Util#begins_its_line?`: every byte before `off` on its own line is
    /// whitespace.
    fn ha_begins_its_line(&self, off: usize) -> bool {
        let line = self.ha_line(off);
        let line_start = self.idx.starts[line - 1];
        self.src[line_start..off].iter().all(|&b| b == b' ' || b == b'\t')
    }
    /// `key.source.length` (display key text, colon excluded) in CHARACTERS
    /// — `TableAlignment#max_key_width`.
    fn ha_key_chars(&self, e: &HaElem) -> isize {
        String::from_utf8_lossy(&self.src[e.start..e.key_end]).chars().count() as isize
    }

    /// Reduce a hash's `elements()` (pairs + kwsplats, in source order) to
    /// `HaElem`s — see the struct doc for the colon-merge adjustment.
    fn ha_collect(&self, elements: &[ruby_prism::Node]) -> Vec<HaElem> {
        elements
            .iter()
            .filter_map(|e| {
                if let Some(assoc) = e.as_assoc_node() {
                    let kloc = assoc.key().location();
                    let raw_key_end = kloc.end_offset();
                    let value = assoc.value();
                    let value_omitted = value.as_implicit_node().is_some();
                    let (op_start, op_end, hash_rocket, key_end) =
                        if let Some(op) = assoc.operator_loc() {
                            (op.start_offset(), op.end_offset(), true, raw_key_end)
                        } else {
                            let ke = raw_key_end.saturating_sub(1);
                            (ke, raw_key_end, false, ke)
                        };
                    Some(HaElem {
                        kwsplat: false,
                        hash_rocket,
                        start: kloc.start_offset(),
                        end: assoc.location().end_offset(),
                        key_end,
                        op_start,
                        op_end,
                        value_start: value.location().start_offset(),
                        value_omitted,
                    })
                } else if let Some(splat) = e.as_assoc_splat_node() {
                    let l = splat.location();
                    Some(HaElem {
                        kwsplat: true,
                        hash_rocket: false,
                        start: l.start_offset(),
                        end: l.end_offset(),
                        key_end: l.end_offset(),
                        op_start: l.start_offset(),
                        op_end: l.end_offset(),
                        value_start: l.start_offset(),
                        value_omitted: false,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// `EnforcedHashRocketStyle`/`EnforcedColonStyle`: a scalar style name,
    /// OR (`AllowMultipleStyles`) a list of them — `new_alignment`'s
    /// `formats = [formats] if formats.is_a? String; formats.uniq.map {...}`.
    /// An unrecognized style name is dropped rather than raising (upstream
    /// raises a bare `RuntimeError`, which just aborts that one check — for
    /// us that's equivalent to the format list ending up unable to satisfy
    /// `checkable_layout?`, which is exactly what an empty list does below).
    fn ha_style_list(&self, key: &str) -> Vec<HaFormat> {
        const COP: &str = "Layout/HashAlignment";
        let raw = self.cfg.get(COP, key).unwrap_or("key");
        let names: Vec<String> = if raw.trim_start().starts_with('[') {
            crate::config::parse_allowed_list(raw)
        } else {
            vec![raw.trim().to_string()]
        };
        let mut out = Vec::new();
        for n in names {
            let fmt = match n.as_str() {
                "key" => HaFormat::Key,
                "table" => HaFormat::Table,
                "separator" => HaFormat::Separator,
                _ => continue,
            };
            if !out.contains(&fmt) {
                out.push(fmt);
            }
        }
        out
    }

    // ---- KeyAlignment ----
    /// `KeyAlignment#separator_delta`.
    fn ha_ka_separator_delta(&self, p: &HaElem) -> isize {
        if p.hash_rocket {
            (self.ha_col(p.key_end) + 1) - self.ha_col(p.op_start)
        } else {
            0
        }
    }
    /// `KeyAlignment#value_delta`.
    fn ha_ka_value_delta(&self, p: &HaElem) -> isize {
        if p.value_omitted || self.ha_line(p.start) != self.ha_line(p.value_start) {
            return 0;
        }
        (self.ha_col(p.op_end) + 1) - self.ha_col(p.value_start)
    }

    // ---- TableAlignment (ValueAlignment) ----
    /// `TableAlignment#hash_rocket_delta`.
    fn ha_ta_hash_rocket_delta(&self, first: &HaElem, current: &HaElem, max_key_width: isize) -> isize {
        self.ha_col(first.start) + max_key_width + 1 - self.ha_col(current.op_start)
    }
    /// `TableAlignment#value_delta`.
    fn ha_ta_value_delta(
        &self,
        first: &HaElem,
        current: &HaElem,
        max_key_width: isize,
        max_delim_width: isize,
    ) -> isize {
        if current.value_omitted {
            return 0;
        }
        (self.ha_col(first.start) + max_key_width + max_delim_width) - self.ha_col(current.value_start)
    }

    // ---- SeparatorAlignment (ValueAlignment) ----
    /// `SeparatorAlignment#key_delta` — `first_pair.key_delta(current, :right)`.
    fn ha_sa_key_delta(&self, first: &HaElem, current: &HaElem) -> isize {
        if self.ha_same_line(first, current) {
            0
        } else {
            self.ha_col(first.key_end) - self.ha_col(current.key_end)
        }
    }
    /// `SeparatorAlignment#hash_rocket_delta` — `first_pair.delimiter_delta(current)`.
    fn ha_sa_hash_rocket_delta(&self, first: &HaElem, current: &HaElem) -> isize {
        if self.ha_same_line(first, current) || first.hash_rocket != current.hash_rocket {
            0
        } else {
            self.ha_col(first.op_start) - self.ha_col(current.op_start)
        }
    }
    /// `SeparatorAlignment#value_delta` — `first_pair.value_delta(current)`.
    fn ha_sa_value_delta(&self, first: &HaElem, current: &HaElem) -> isize {
        if current.value_omitted {
            return 0;
        }
        if self.ha_same_line(first, current) {
            0
        } else {
            self.ha_col(first.value_start) - self.ha_col(current.value_start)
        }
    }

    /// `on_hash`/`on_keyword_hash` (explicit `{}` vs. an implicit trailing
    /// keyword-args group are two distinct prism node kinds; rubocop-ast's
    /// `hash_type?` covers both under one node).
    pub(crate) fn check_hash_alignment_hash(&mut self, node: &ruby_prism::HashNode) {
        let l = node.location();
        let elems = self.ha_collect(&node.elements().iter().collect::<Vec<_>>());
        self.ha_process(l.start_offset(), l.end_offset(), elems);
    }
    pub(crate) fn check_hash_alignment_keyword_hash(&mut self, node: &ruby_prism::KeywordHashNode) {
        let l = node.location();
        let elems = self.ha_collect(&node.elements().iter().collect::<Vec<_>>());
        self.ha_process(l.start_offset(), l.end_offset(), elems);
    }

    /// `on_hash`'s early-return gate: `autocorrect_incompatible_with_other_
    /// cops?(node) || ignored_node?(node) || node.pairs.empty? ||
    /// node.single_line?`, then the `checkable_layout?` gate before
    /// `check_pairs`.
    fn ha_process(&mut self, start: usize, end: usize, elems: Vec<HaElem>) {
        const COP: &str = "Layout/HashAlignment";
        if !self.on(COP) {
            return;
        }
        if self.ha_incompatible.contains(&start) || self.ha_ignored.contains(&start) {
            return;
        }
        if elems.is_empty() {
            return;
        }
        if self.ha_line(start) == self.ha_line(end.saturating_sub(1).max(start)) {
            return; // single_line?
        }
        let real: Vec<HaElem> = elems.iter().copied().filter(|e| !e.kwsplat).collect();
        if real.is_empty() {
            return; // node.pairs.empty?
        }
        let rocket_styles = self.ha_style_list("EnforcedHashRocketStyle");
        let colon_styles = self.ha_style_list("EnforcedColonStyle");
        let mixed = real.iter().any(|p| p.hash_rocket != real[0].hash_rocket);
        let same_line_pairs = real.windows(2).any(|w| self.ha_same_line(&w[0], &w[1]));
        let checkable = |fmt: HaFormat| -> bool {
            match fmt {
                HaFormat::Key | HaFormat::KwSplat => true,
                HaFormat::Table | HaFormat::Separator => !mixed && !same_line_pairs,
            }
        };
        if !rocket_styles.iter().any(|f| checkable(*f)) || !colon_styles.iter().any(|f| checkable(*f)) {
            return;
        }
        self.ha_check_pairs(&elems, &real, &rocket_styles, &colon_styles);
    }

    /// `check_pairs`: the `deltas_for_first_pair` pass, then `node.children`
    /// (every pair AND kwsplat, in source order — including the first pair
    /// again), then `add_offenses`.
    fn ha_check_pairs(&mut self, elems: &[HaElem], real: &[HaElem], rocket: &[HaFormat], colon: &[HaFormat]) {
        let first = real[0];
        let max_key_width: isize = real.iter().map(|p| self.ha_key_chars(p)).max().unwrap_or(0);
        let max_delim_width: isize = real.iter().map(|p| if p.hash_rocket { 4 } else { 2 }).max().unwrap_or(0);

        let mut order: Vec<HaFormat> = Vec::new();
        let mut buckets: std::collections::HashMap<HaFormat, Vec<usize>> = std::collections::HashMap::new();
        let mut deltas: std::collections::HashMap<(HaFormat, usize), HaDelta> = std::collections::HashMap::new();
        let mut by_start: std::collections::HashMap<usize, HaElem> = std::collections::HashMap::new();
        for e in elems {
            by_start.insert(e.start, *e);
        }

        let alignment_for = |e: &HaElem| -> Vec<HaFormat> {
            if e.kwsplat {
                vec![HaFormat::KwSplat]
            } else if e.hash_rocket {
                rocket.to_vec()
            } else {
                colon.to_vec()
            }
        };

        // `register_offenses_with_format`'s correction block reads
        // `column_deltas[alignment_for(offense).first.class][offense]` — NOT
        // the delta under whichever format `min_by` picked for OFFENSE
        // SELECTION. `alignment_for(offense).first` is the FIRST style in
        // THAT element's own (rocket-or-colon) configured list, so with e.g.
        // `EnforcedHashRocketStyle: [table, key]` the winning format (for
        // deciding WHICH pairs get flagged, and the message) can be `key`
        // while the correction actually applied to each flagged pair is
        // `table`'s (or vice-versa) — and if that first-listed style judges
        // the pair as ALREADY good (no entry ever landed in `deltas`), the
        // flagged offense gets NO correction at all (its `unless delta.nil?`
        // guard) even though it's reported. `rocket[0]`/`colon[0]` are safe:
        // `ha_process`'s gate already proved both lists are non-empty.
        let first_style_of = |e: &HaElem| -> HaFormat {
            if e.kwsplat {
                HaFormat::KwSplat
            } else if e.hash_rocket {
                rocket[0]
            } else {
                colon[0]
            }
        };
        let first_style: std::collections::HashMap<usize, HaFormat> =
            elems.iter().map(|e| (e.start, first_style_of(e))).collect();

        for fmt in alignment_for(&first) {
            let delta = match fmt {
                HaFormat::Key => HaDelta {
                    key: None,
                    separator: Some(self.ha_ka_separator_delta(&first)),
                    value: Some(self.ha_ka_value_delta(&first)),
                },
                HaFormat::Table => {
                    let sep = if first.hash_rocket {
                        self.ha_ta_hash_rocket_delta(&first, &first, max_key_width)
                    } else {
                        0
                    };
                    let val = self.ha_ta_value_delta(&first, &first, max_key_width, max_delim_width) - sep;
                    HaDelta { key: None, separator: Some(sep), value: Some(val) }
                }
                HaFormat::Separator | HaFormat::KwSplat => HaDelta::default(),
            };
            ha_note_delta(&mut order, &mut buckets, &mut deltas, fmt, first.start, delta);
        }

        for cur in elems {
            for fmt in alignment_for(cur) {
                let delta = match fmt {
                    HaFormat::Key => {
                        if !self.ha_begins_its_line(cur.start) {
                            HaDelta::default()
                        } else {
                            let key_delta = if self.ha_same_line(&first, cur) {
                                0
                            } else {
                                self.ha_col(first.start) - self.ha_col(cur.start)
                            };
                            HaDelta {
                                key: Some(key_delta),
                                separator: Some(self.ha_ka_separator_delta(cur)),
                                value: Some(self.ha_ka_value_delta(cur)),
                            }
                        }
                    }
                    HaFormat::Table => {
                        let key_delta = if self.ha_same_line(&first, cur) {
                            0
                        } else {
                            self.ha_col(first.start) - self.ha_col(cur.start)
                        };
                        let sep_delta = if cur.hash_rocket {
                            self.ha_ta_hash_rocket_delta(&first, cur, max_key_width) - key_delta
                        } else {
                            0
                        };
                        let val_delta =
                            self.ha_ta_value_delta(&first, cur, max_key_width, max_delim_width) - key_delta - sep_delta;
                        HaDelta { key: Some(key_delta), separator: Some(sep_delta), value: Some(val_delta) }
                    }
                    HaFormat::Separator => {
                        let key_delta = self.ha_sa_key_delta(&first, cur);
                        let sep_delta = if cur.hash_rocket {
                            self.ha_sa_hash_rocket_delta(&first, cur) - key_delta
                        } else {
                            0
                        };
                        let val_delta = self.ha_sa_value_delta(&first, cur) - key_delta - sep_delta;
                        HaDelta { key: Some(key_delta), separator: Some(sep_delta), value: Some(val_delta) }
                    }
                    HaFormat::KwSplat => {
                        if !self.ha_begins_its_line(cur.start) {
                            HaDelta::default()
                        } else {
                            let key_delta = if self.ha_same_line(&first, cur) {
                                0
                            } else {
                                self.ha_col(first.start) - self.ha_col(cur.start)
                            };
                            HaDelta { key: Some(key_delta), separator: None, value: None }
                        }
                    }
                };
                ha_note_delta(&mut order, &mut buckets, &mut deltas, fmt, cur.start, delta);
            }
        }

        let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();

        // `kwsplat_offenses = offenses_by.delete(KeywordSplatAlignment)` —
        // always registered, independent of the key/table/separator vote.
        if let Some(list) = buckets.get(&HaFormat::KwSplat).cloned() {
            self.ha_register(HaFormat::KwSplat, &list, &deltas, &by_start, &first_style, &mut seen);
        }

        // `offenses_by.min_by { |_, v| v.length }` — ties keep the format
        // seen FIRST (insertion order recorded by `ha_note_delta`, mirroring
        // Ruby `Hash`'s order-preserving iteration + `min_by`'s "only
        // replace on strictly less" semantics).
        let mut best: Option<(HaFormat, usize)> = None;
        for fmt in &order {
            if *fmt == HaFormat::KwSplat {
                continue;
            }
            let len = buckets.get(fmt).map(|v| v.len()).unwrap_or(0);
            match best {
                None => best = Some((*fmt, len)),
                Some((_, blen)) if len < blen => best = Some((*fmt, len)),
                _ => {}
            }
        }
        if let Some((fmt, _)) = best {
            let list = buckets.get(&fmt).cloned().unwrap_or_default();
            self.ha_register(fmt, &list, &deltas, &by_start, &first_style, &mut seen);
        }
    }

    /// `register_offenses_with_format`: `add_offense` per flagged element —
    /// `seen` mirrors rubocop-core's `current_offense_locations` Set (an
    /// element can appear twice in `list`, see `ha_note_delta`'s doc; only
    /// the first registration survives, exactly like upstream's `add_offense
    /// unless current_offense_locations.add?(range)`). The MESSAGE comes
    /// from `fmt` (the winning format), but the correction delta is looked
    /// up under `first_style` — see that variable's doc in `ha_check_pairs`.
    fn ha_register(
        &mut self,
        fmt: HaFormat,
        list: &[usize],
        deltas: &std::collections::HashMap<(HaFormat, usize), HaDelta>,
        by_start: &std::collections::HashMap<usize, HaElem>,
        first_style: &std::collections::HashMap<usize, HaFormat>,
        seen: &mut std::collections::HashSet<usize>,
    ) {
        const COP: &str = "Layout/HashAlignment";
        let msg = fmt.message();
        for &start in list {
            if !seen.insert(start) {
                continue;
            }
            let Some(&elem) = by_start.get(&start) else { continue };
            self.push(elem.start, COP, true, msg);
            let correct_fmt = first_style.get(&start).copied().unwrap_or(fmt);
            if let Some(&delta) = deltas.get(&(correct_fmt, start)) {
                self.ha_correct(&elem, delta);
            }
        }
    }

    /// `correct_node`: a kwsplat (never `respond_to?(:value_omission?)`) or
    /// an omitted-value pair (`a:`) both fall to `correct_no_value` (shift
    /// the WHOLE element by its `key` delta); otherwise `correct_key_value`
    /// shifts key/separator/value independently, clamping the key's own
    /// leftward shift so it never crosses column 0.
    fn ha_correct(&mut self, e: &HaElem, d: HaDelta) {
        if e.kwsplat || e.value_omitted {
            let kd = d.key.unwrap_or(0);
            self.ha_adjust(kd, e.start);
            return;
        }
        let sep = d.separator.unwrap_or(0);
        let val = d.value.unwrap_or(0);
        let mut key_delta = d.key.unwrap_or(0);
        let key_col0 = self.ha_col(e.start) - 1; // 0-based, for the absolute clamp only
        if key_delta < -key_col0 {
            key_delta = -key_col0;
        }
        self.ha_adjust(key_delta, e.start);
        self.ha_adjust(sep, e.op_start);
        self.ha_adjust(val, e.value_start);
    }
    /// `adjust`: insert `delta` spaces before `pos`, or remove `-delta`
    /// bytes immediately before it.
    fn ha_adjust(&mut self, delta: isize, pos: usize) {
        if delta > 0 {
            self.fixes.push((pos, pos, vec![b' '; delta as usize]));
        } else if delta < 0 {
            let n = (-delta) as usize;
            self.fixes.push((pos.saturating_sub(n), pos, Vec::new()));
        }
    }

    /// `on_send`/`on_csend`/`on_super`/`on_yield`'s `ignore_hash_argument?`:
    /// the call's last argument, if it's hash-typed (explicit `{}` or an
    /// implicit trailing keyword-args group), gets `ignore_node`d per
    /// `EnforcedLastArgumentHashStyle`.
    pub(crate) fn ha_ignore_last_arg(&mut self, args: Option<ruby_prism::ArgumentsNode>) {
        const COP: &str = "Layout/HashAlignment";
        if !self.on(COP) {
            return;
        }
        let Some(args) = args else { return };
        let Some(last) = args.arguments().iter().last() else { return };
        let (start, braces) = if let Some(h) = last.as_hash_node() {
            (h.location().start_offset(), true)
        } else if let Some(kh) = last.as_keyword_hash_node() {
            (kh.location().start_offset(), false)
        } else {
            return;
        };
        let style = self.cfg.get(COP, "EnforcedLastArgumentHashStyle").unwrap_or("always_inspect");
        let ignore = match style {
            "always_ignore" => true,
            "ignore_explicit" => braces,
            "ignore_implicit" => !braces,
            _ => false, // "always_inspect" (default) and anything unrecognized
        };
        if ignore {
            self.ha_ignored.insert(start);
        }
    }

    /// `autocorrect_incompatible_with_other_cops?`: only relevant when
    /// `Layout/ArgumentAlignment` is `with_fixed_indentation` — for every
    /// hash-typed argument of THIS call with at least one real pair, compare
    /// its first pair's line against the preceding argument (or, lacking
    /// one, the call's own selector — or, lacking THAT too, e.g. `foo.(...)`,
    /// the whole call expression).
    pub(crate) fn ha_check_fixed_indentation(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/HashAlignment";
        if !self.on(COP) {
            return;
        }
        if self.cfg.get("Layout/ArgumentAlignment", "EnforcedStyle") != Some("with_fixed_indentation") {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        for (i, arg) in list.iter().enumerate() {
            let (hash_start, elements): (usize, Vec<ruby_prism::Node>) = if let Some(h) = arg.as_hash_node() {
                (h.location().start_offset(), h.elements().iter().collect())
            } else if let Some(kh) = arg.as_keyword_hash_node() {
                (kh.location().start_offset(), kh.elements().iter().collect())
            } else {
                continue;
            };
            let elems = self.ha_collect(&elements);
            let Some(first_real) = elems.iter().find(|e| !e.kwsplat) else { continue };
            let pair_line = self.ha_line(first_real.start);
            let (sel_first, sel_last) = if i > 0 {
                let l = list[i - 1].location();
                (self.ha_line(l.start_offset()), self.ha_line(l.end_offset().saturating_sub(1)))
            } else if let Some(ml) = node.message_loc() {
                let l = self.ha_line(ml.start_offset());
                (l, l)
            } else {
                let l = node.location();
                (self.ha_line(l.start_offset()), self.ha_line(l.end_offset().saturating_sub(1)))
            };
            if sel_first == pair_line || sel_last == pair_line {
                self.ha_incompatible.insert(hash_start);
            }
        }
    }
}


// ============================================================================
// Layout/IndentationWidth
//
// Ported from rubocop's `IndentationWidth` cop plus the mixins it includes:
// `EndKeywordAlignment` (unused here beyond `ConfigurableEnforcedStyle`'s
// style-parameter override — this cop's OWN `EnforcedStyleAlignWith` powers
// `block_body_indentation_base`, nothing to do with `end`-keyword alignment
// itself), `Alignment` (`configured_indentation_width`, the `AlignmentCorrector`
// autocorrect), `CheckAssignment` (the `on_lvasgn`-family + `on_send` dispatch
// for an if/while/until used as an assignment's right-hand side), and
// `AllowedPattern` (`AllowedPatterns`, reused via the engine's generic
// `Cops::allowed` — populated from the SAME per-cop `AllowedPatterns` config
// section this cop's schema entry declares).
//
// The core primitive is `check_indentation(base, body, style)`: is `body`'s
// own first line indented exactly `configured_indentation_width` columns past
// `base`'s line? Every hook below (rescue/resbody/ensure/kwbegin/block/class/
// module/sclass/send/def/while/until/case/case_match/if/unless/assignment)
// ultimately just resolves a `(base, body)` pair and calls it — see
// `iw_check_indentation`.
// ============================================================================

/// Where a `def`/block/class/module's implicit rescue/ensure `BeginNode`
/// content STARTS — prism gives this synthetic (no explicit `begin` keyword)
/// wrapper the exact SAME `location()` as the enclosing construct itself
/// (verified directly against `ruby-prism`: for `def foo\n  a = 1\nrescue\n
/// a = 2\nend`, the body `BeginNode`'s `location()` starts at byte 0 — the
/// `def` keyword — not at `a = 1`), so its raw start offset is as unusable as
/// its end offset (see `iw_begin_node_content_end` for the same trap on the
/// other side). Whitequark's own rescue/ensure-wrapper node instead starts at
/// the first REAL clause: the leading (pre-rescue) statements if any, else
/// the first `rescue`, else (only reachable if a rescue-less body somehow
/// still parses an `else`) the `else`, else `ensure` alone. A near-duplicate
/// of `metrics::ml_begin_node_content_start` kept local to this dept file
/// rather than shared across dept files.
fn iw_begin_node_content_start(b: &ruby_prism::BeginNode) -> usize {
    if let Some(stmts) = b.statements() {
        return stmts.location().start_offset();
    }
    if let Some(resc) = b.rescue_clause() {
        return resc.location().start_offset();
    }
    if let Some(els) = b.else_clause() {
        return els.location().start_offset();
    }
    if let Some(ens) = b.ensure_clause() {
        return ens.location().start_offset();
    }
    b.location().start_offset()
}

/// The symmetric counterpart to `iw_begin_node_content_start`: where the
/// content actually ENDS, instead of prism's `BeginNode::location()` end,
/// which extends through the enclosing construct's own `end` keyword.
fn iw_begin_node_content_end(b: &ruby_prism::BeginNode) -> usize {
    if let Some(ens) = b.ensure_clause() {
        return match ens.statements() {
            Some(s) => s.location().end_offset(),
            None => ens.ensure_keyword_loc().end_offset(),
        };
    }
    if let Some(els) = b.else_clause() {
        return match els.statements() {
            Some(s) => s.location().end_offset(),
            None => els.else_keyword_loc().end_offset(),
        };
    }
    if let Some(mut resc) = b.rescue_clause() {
        while let Some(next) = resc.subsequent() {
            resc = next;
        }
        return match resc.statements() {
            Some(s) => s.location().end_offset(),
            None => resc.location().end_offset(),
        };
    }
    match b.statements() {
        Some(s) => s.location().end_offset(),
        None => b.location().end_offset(),
    }
}

/// A `check_indentation` "body" node's true content start: for a def/block/
/// class/module's implicit rescue/ensure wrapper (a `BeginNode` with no
/// `begin_keyword_loc`, OR the SAME `BeginNode` reused as its own "body" by
/// `check_indentation_width_kwbegin` for an EXPLICIT `begin...rescue...end`),
/// `iw_begin_node_content_start`; otherwise the node's own plain start.
fn iw_body_start(body: &ruby_prism::Node) -> usize {
    match body.as_begin_node() {
        Some(b) if b.rescue_clause().is_some() || b.ensure_clause().is_some() => {
            iw_begin_node_content_start(&b)
        }
        _ => body.location().start_offset(),
    }
}

/// The symmetric counterpart used for the offense/autocorrect TARGET's own
/// end (never the "is this a rescue/ensure body at all" body passed to
/// `check_indentation` itself — see `iw_offense`'s narrowing).
fn iw_target_end(target: &ruby_prism::Node) -> usize {
    match target.as_begin_node() {
        Some(b) if b.rescue_clause().is_some() || b.ensure_clause().is_some() => {
            iw_begin_node_content_end(&b)
        }
        _ => target.location().end_offset(),
    }
}

/// `MethodDispatchNode#bare_access_modifier?`: a receiverless, argument-less,
/// block-less `public`/`protected`/`private`/`module_function` call.
fn iw_is_bare_access_modifier(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    call.receiver().is_none()
        && call.arguments().is_none_or(|a| a.arguments().len() == 0)
        && call.block().is_none()
        && matches!(call.name().as_slice(), b"public" | b"protected" | b"private" | b"module_function")
}

/// `MethodDispatchNode#access_modifier?`: `bare_access_modifier? ||
/// non_bare_access_modifier?` — same four names, but WITH arguments allowed
/// too (`private :foo`). Used only to SKIP a statement in
/// `check_members_for_normal_style`, where every candidate is already a
/// direct child of a class/module/sclass/qualifying-block body (inherently
/// in macro scope), so the `macro?`/`in_macro_scope?` half of upstream's
/// predicate is always true here and not separately reproduced.
fn iw_is_access_modifier_call(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    call.receiver().is_none()
        && matches!(call.name().as_slice(), b"public" | b"protected" | b"private" | b"module_function")
}

/// `MethodDispatchNode#special_modifier?`: a bare access modifier whose name
/// is `private`/`protected` specifically — NOT `public`/`module_function`.
fn iw_is_special_modifier(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    call.receiver().is_none()
        && call.arguments().is_none_or(|a| a.arguments().len() == 0)
        && call.block().is_none()
        && matches!(call.name().as_slice(), b"private" | b"protected")
}

/// `starts_with_access_modifier?`: `body`'s FIRST statement (only meaningful
/// when `body` is a plain multi/single-statement wrapper, never a
/// rescue/ensure `BeginNode`) is a bare access modifier.
fn iw_starts_with_access_modifier(body: &ruby_prism::Node) -> bool {
    let Some(stmts) = body.as_statements_node() else { return false };
    match stmts.body().iter().next() {
        Some(first) => iw_is_bare_access_modifier(&first),
        None => false,
    }
}

/// `contains_access_modifier?`: `body` is a GENUINE multi-statement wrapper
/// (2+ children — prism always wraps even a lone statement, unlike
/// whitequark, so a 1-child `StatementsNode` does NOT count as `begin_type?`
/// here) with at least one bare-access-modifier child anywhere in it.
fn iw_contains_access_modifier(body: Option<ruby_prism::Node>) -> bool {
    let Some(body) = body else { return false };
    let Some(stmts) = body.as_statements_node() else { return false };
    if stmts.body().len() < 2 {
        return false;
    }
    stmts.body().iter().any(|c| iw_is_bare_access_modifier(&c))
}

/// `Util#first_part_of_call_chain`: unwrap a trailing method-call chain
/// (`a.b.c`, walking `.receiver` — prism folds a `call-with-block` into the
/// same `CallNode`, so upstream's separate `any_block_type?` branch is
/// structurally unreachable here) down to its ultimate receiver-root.
/// Returns `None` if the chain bottoms out at a receiverless call (the
/// `while node` loop exits with `node = nil` in that case upstream).
fn iw_first_part_of_call_chain(mut node: Option<ruby_prism::Node>) -> Option<ruby_prism::Node> {
    loop {
        match node {
            Some(n) => {
                if let Some(call) = n.as_call_node() {
                    node = call.receiver();
                } else {
                    return Some(n);
                }
            }
            None => return None,
        }
    }
}

/// `AlignmentCorrector`'s `inside_string_ranges`/`inside_string_range`: byte
/// ranges this cop's autocorrect must never touch — a heredoc's body PLUS its
/// closing terminator line, or (for a plain delimited string literal) just
/// the text strictly between its opening and closing delimiters. Scoped to a
/// single autocorrect target's own subtree (`node.each_node(:any_str)`).
struct IwTabooFinder {
    ranges: Vec<(usize, usize)>,
}
impl IwTabooFinder {
    fn note(&mut self, opening: Option<ruby_prism::Location>, closing: Option<ruby_prism::Location>, content: Option<ruby_prism::Location>) {
        let (Some(o), Some(c)) = (opening, closing) else { return };
        if o.as_slice().starts_with(b"<<") {
            let body_start = content.map(|c| c.start_offset()).unwrap_or_else(|| o.end_offset());
            // prism's heredoc `closing_loc` includes the terminator's own
            // trailing newline (`"GOO\n"`); whitequark's `loc.heredoc_end`
            // does not — trim it so the very NEXT physical line's start
            // isn't wrongly swallowed into the protected zone (`within?`'s
            // `<=` would otherwise treat that boundary as still "inside").
            let mut end = c.end_offset();
            if c.as_slice().last() == Some(&b'\n') {
                end -= 1;
            }
            self.ranges.push((body_start, end));
        } else {
            self.ranges.push((o.end_offset(), c.start_offset()));
        }
    }
}
impl<'pr> ruby_prism::Visit<'pr> for IwTabooFinder {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        self.note(node.opening_loc(), node.closing_loc(), Some(node.content_loc()));
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        self.note(node.opening_loc(), node.closing_loc(), None);
        ruby_prism::visit_interpolated_string_node(self, node);
    }
    fn visit_x_string_node(&mut self, node: &ruby_prism::XStringNode<'pr>) {
        self.note(Some(node.opening_loc()), Some(node.closing_loc()), Some(node.content_loc()));
    }
    fn visit_interpolated_x_string_node(&mut self, node: &ruby_prism::InterpolatedXStringNode<'pr>) {
        self.note(Some(node.opening_loc()), Some(node.closing_loc()), None);
        ruby_prism::visit_interpolated_x_string_node(self, node);
    }
}

impl<'a> super::Cops<'a> {
    /// `Alignment#configured_indentation_width` for this cop's OWN mixin use:
    /// `cop_config['IndentationWidth']` is always nil here (this cop's own
    /// schema has no such key — only `Width`), so it collapses to
    /// `config.for_cop('Layout/IndentationWidth')['Width']` — itself.
    fn iw_configured_width(&self) -> i64 {
        self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()).unwrap_or(2)
    }

    /// `Util#begins_its_line?`: nothing but whitespace precedes `off` on its
    /// own physical line.
    fn iw_begins_its_line(&self, off: usize) -> bool {
        let (line, _) = self.idx.loc(off);
        let line_start = self.idx.starts[line - 1];
        self.src[line_start..off].iter().all(|b| b.is_ascii_whitespace())
    }

    /// `RangeHelp#effective_column` (no BOM handling — irrelevant here): the
    /// 0-based CHARACTER column of `off` on its own line (not byte column,
    /// not `Alignment#display_column`'s Unicode East-Asian display width —
    /// this cop's own indentation math is plain character columns).
    fn iw_char_col(&self, off: usize) -> i64 {
        let (line, byte_col) = self.idx.loc(off);
        let line_start = self.idx.starts[line - 1];
        let prefix = &self.src[line_start..off];
        if prefix.is_ascii() {
            (byte_col - 1) as i64
        } else {
            String::from_utf8_lossy(prefix).chars().count() as i64
        }
    }

    /// `AllowedPattern#allowed_line?`: any of this cop's configured
    /// `AllowedPatterns` matches the FULL PHYSICAL LINE `off` sits on —
    /// reuses the engine's generic `Cops::allowed`, whose per-cop pattern
    /// table is populated straight from the same config section.
    fn iw_allowed_line(&self, off: usize) -> bool {
        let (line, _) = self.idx.loc(off);
        let line_start = self.idx.starts[line - 1];
        let line_end = self.line_end(line);
        self.allowed("Layout/IndentationWidth", &self.src[line_start..line_end])
    }

    /// `IndentationWidth#line_uses_tabs?`: the text from line start through
    /// `off` (its own column) contains a literal tab.
    fn iw_line_uses_tabs(&self, off: usize) -> bool {
        let (line, _) = self.idx.loc(off);
        let line_start = self.idx.starts[line - 1];
        self.src[line_start..off].contains(&b'\t')
    }

    /// `IndentationWidth#visual_column`: tabs count as a full configured
    /// indentation width each, spaces count as 1 — used only for the
    /// `EnforcedStyle: tabs` + mixed-whitespace `column_offset_between`
    /// override below (invisible to the oracle's own fixture parsing — see
    /// the dept-level doc comment — but implemented for genuine verbatim
    /// fidelity to upstream regardless).
    fn iw_visual_column(&self, off: usize) -> i64 {
        let (line, _) = self.idx.loc(off);
        let line_start = self.idx.starts[line - 1];
        let indent = &self.src[line_start..off];
        let tabs = indent.iter().filter(|&&b| b == b'\t').count() as i64;
        let spaces = indent.iter().filter(|&&b| b == b' ').count() as i64;
        tabs * self.iw_configured_width() + spaces
    }

    /// `IndentationWidth#column_offset_between` override: plain character-
    /// column difference UNLESS `EnforcedStyle: tabs` and at least one of the
    /// two lines actually contains a tab, in which case tabs/spaces are
    /// weighed by `iw_visual_column` instead.
    fn iw_column_offset(&self, body_start: usize, base_start: usize) -> i64 {
        let using_tabs = self.cfg.enforced_style("Layout/IndentationStyle") == "tabs";
        if using_tabs && (self.iw_line_uses_tabs(base_start) || self.iw_line_uses_tabs(body_start)) {
            return self.iw_visual_column(body_start) - self.iw_visual_column(base_start);
        }
        self.iw_char_col(body_start) - self.iw_char_col(base_start)
    }

    /// `IndentationWidth#skip_check?`.
    fn iw_skip_check(&self, base_start: usize, body: &ruby_prism::Node) -> bool {
        if self.iw_allowed_line(base_start) {
            return true;
        }
        let body_start = iw_body_start(body);
        if self.idx.loc(body_start).0 == self.idx.loc(base_start).0 {
            return true;
        }
        if iw_starts_with_access_modifier(body) {
            return true;
        }
        let (line, _) = self.idx.loc(body_start);
        let line_start = self.idx.starts[line - 1];
        !self.src[line_start..body_start].iter().all(|b| b.is_ascii_whitespace())
    }

    /// `IndentationWidth#indentation_to_check?`: `skip_check?` first, then —
    /// for a rescue/ensure-shaped `body` (see `iw_body_start`'s doc) — only
    /// when there's a genuine (non-empty) protected main body; otherwise
    /// always checked.
    fn iw_indentation_to_check(&self, base_start: usize, body: &ruby_prism::Node) -> bool {
        if self.iw_skip_check(base_start, body) {
            return false;
        }
        if let Some(b) = body.as_begin_node() {
            if b.rescue_clause().is_some() || b.ensure_clause().is_some() {
                return b.statements().is_some();
            }
        }
        true
    }

    /// `IndentationWidth#check_indentation`: the shared core every hook below
    /// funnels through. `base_start` is a byte offset standing in for
    /// upstream's `base_loc` — only its OWN start position is ever read
    /// downstream (never an end/length), so a bare offset loses nothing.
    fn iw_check_indentation(&mut self, base_start: usize, body: Option<ruby_prism::Node>, style: &'static str) {
        let Some(body) = body else { return };
        if !self.iw_indentation_to_check(base_start, &body) {
            return;
        }
        let body_start = iw_body_start(&body);
        let indentation = self.iw_column_offset(body_start, base_start);
        let width = self.iw_configured_width();
        if width - indentation == 0 {
            return;
        }
        self.iw_offense(body, indentation, style, width);
    }

    /// `IndentationWidth#offense` + `#offending_range` + `#message`: narrows
    /// `body` to its own first child when it's a plain multi/single-statement
    /// wrapper (never for a rescue/ensure `BeginNode` — whitequark's
    /// `:rescue`/`:ensure` node types are never `begin_type?`; a genuinely
    /// PARENTHESIZED multi-statement group, upstream's other exemption, has
    /// no prism equivalent reachable from any of this cop's body positions),
    /// registers the offense, and — unless another already-registered
    /// offense's own target nests this one — autocorrects.
    fn iw_offense(&mut self, body: ruby_prism::Node, indentation: i64, style: &'static str, width: i64) {
        const COP: &str = "Layout/IndentationWidth";
        let target: ruby_prism::Node = match body.as_statements_node() {
            Some(stmts) => stmts.body().iter().next().unwrap_or(body),
            None => body,
        };
        let target_start = iw_body_start(&target);
        let using_tabs = self.cfg.enforced_style("Layout/IndentationStyle") == "tabs";
        let anchor = if using_tabs {
            let (line, _) = self.idx.loc(target_start);
            self.idx.starts[line - 1]
        } else if indentation >= 0 {
            target_start.saturating_sub(indentation as usize)
        } else {
            target_start
        };
        let message = self.iw_message(indentation, style, width);
        let t_start = target_start;
        let t_end = iw_target_end(&target);
        let nested = self.iw_other_offense_in_same_range(t_start, t_end);
        self.push(anchor, COP, true, message);
        if !nested {
            self.iw_autocorrect_align(&target, t_start, t_end, (width - indentation) as isize);
        }
    }

    /// `IndentationWidth#message` + `#message_for_tabs`/`#message_for_spaces`.
    fn iw_message(&self, indentation: i64, style: &'static str, width: i64) -> String {
        let name = if style == "normal" { String::new() } else { format!(" {style}") };
        if self.cfg.enforced_style("Layout/IndentationStyle") == "tabs" {
            let actual_tabs = indentation.div_euclid(width.max(1));
            format!("Use 1 (not {actual_tabs}) tabs for{name} indentation.")
        } else {
            format!("Use {width} (not {indentation}) spaces for{name} indentation.")
        }
    }

    /// `IndentationWidth#other_offense_in_same_range?`: does THIS target
    /// range nest inside one already registered this run? If not, register
    /// it (so a LATER nested offense is suppressed instead).
    fn iw_other_offense_in_same_range(&mut self, start: usize, end: usize) -> bool {
        if self.iw_offense_ranges.iter().any(|&(s, e)| start >= s && end <= e) {
            return true;
        }
        self.iw_offense_ranges.push((start, end));
        false
    }

    /// `AlignmentCorrector.correct`: shift every physical line `target` spans
    /// by the same `delta` columns — widen by inserting `delta` spaces right
    /// before each line's own first character (never on an entirely blank
    /// line), or shrink by deleting up to `-delta` leading whitespace bytes.
    /// A no-op entirely under `EnforcedStyle: tabs`, inside a `=begin`/`=end`
    /// block comment contained in `target`'s own span, or wherever a
    /// heredoc/string-literal descendant's protected content would be hit.
    fn iw_autocorrect_align(&mut self, target: &ruby_prism::Node, node_start: usize, node_end: usize, delta: isize) {
        if delta == 0 {
            return;
        }
        if self.cfg.enforced_style("Layout/IndentationStyle") == "tabs" {
            return;
        }
        if self.iw_block_comment_within(node_start, node_end) {
            return;
        }
        use ruby_prism::Visit;
        let mut finder = IwTabooFinder { ranges: Vec::new() };
        finder.visit(target);
        let taboo = finder.ranges;
        let within_taboo = |r: (usize, usize)| taboo.iter().any(|&(ts, te)| r.0 >= ts && r.1 <= te);

        let (start_line, _) = self.idx.loc(node_start);
        let last_byte = node_end.saturating_sub(1).max(node_start);
        let (end_line, _) = self.idx.loc(last_byte);

        for line in start_line..=end_line {
            let cur_begin = if line == start_line { node_start } else { self.idx.starts[line - 1] };
            if delta > 0 {
                if self.src.get(cur_begin) == Some(&b'\n') {
                    continue;
                }
                if within_taboo((cur_begin, cur_begin)) {
                    continue;
                }
                self.fixes.push((cur_begin, cur_begin, vec![b' '; delta as usize]));
            } else {
                let n = (-delta) as usize;
                let starts_with_space = self.src.get(cur_begin) == Some(&b' ');
                let (rs, re) = if starts_with_space {
                    (cur_begin, (cur_begin + n).min(self.src.len()))
                } else {
                    (cur_begin.saturating_sub(n), cur_begin)
                };
                if re <= rs {
                    continue;
                }
                if !self.src[rs..re].iter().all(|&b| b == b' ' || b == b'\t') {
                    continue;
                }
                if within_taboo((rs, re)) {
                    continue;
                }
                self.fixes.push((rs, re, Vec::new()));
            }
        }
    }

    /// `AlignmentCorrector.block_comment_within?`: a `=begin`/`=end` document
    /// comment fully contained in `[start, end)`.
    fn iw_block_comment_within(&self, start: usize, end: usize) -> bool {
        self.comments.iter().any(|&(_, s, e)| self.src.get(s) == Some(&b'=') && s >= start && e <= end)
    }

    // ---- check_members (class/module/sclass bodies + indented_internal_methods blocks) ----

    /// `IndentationWidth#check_members` + `#select_check_member` +
    /// `#check_members_for_normal_style` / `#check_members_for_indented_
    /// internal_methods_style` / `#each_member`.
    fn iw_check_members(&mut self, base_start: usize, body: Option<ruby_prism::Node>) {
        let Some(body) = body else { return };
        let first = body.as_statements_node().and_then(|s| s.body().iter().next());
        let use_first = first.as_ref().is_some_and(iw_is_bare_access_modifier);
        let outdent = use_first && self.cfg.enforced_style("Layout/AccessModifierIndentation") == "outdent";
        let children_2plus: Option<Vec<ruby_prism::Node>> = body.as_statements_node().and_then(|s| {
            let v: Vec<ruby_prism::Node> = s.body().iter().collect();
            if v.len() >= 2 {
                Some(v)
            } else {
                None
            }
        });
        if outdent {
            self.iw_check_indentation(base_start, None, "normal");
        } else if use_first {
            self.iw_check_indentation(base_start, first, "normal");
        } else {
            self.iw_check_indentation(base_start, Some(body), "normal");
        }
        let Some(children) = children_2plus else { return };
        if self.cfg.enforced_style("Layout/IndentationConsistency") == "indented_internal_methods" {
            let style = "indented_internal_methods";
            let mut previous_modifier: Option<ruby_prism::Node> = None;
            for member in children {
                if iw_is_special_modifier(&member) {
                    previous_modifier = Some(member);
                } else if let Some(prev) = previous_modifier.take() {
                    self.iw_check_indentation(prev.location().start_offset(), Some(member), style);
                }
            }
        } else {
            for member in children {
                if iw_is_access_modifier_call(&member) {
                    continue;
                }
                self.iw_check_indentation(base_start, Some(member), "normal");
            }
        }
    }

    fn iw_check_class_like(&mut self, keyword_start: usize, body: Option<ruby_prism::Node>) {
        if let Some(b) = &body {
            if self.idx.loc(iw_body_start(b)).0 == self.idx.loc(keyword_start).0 {
                return;
            }
        }
        self.iw_check_members(keyword_start, body);
    }

    pub(crate) fn check_indentation_width_class(&mut self, node: &ruby_prism::ClassNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        self.iw_check_class_like(node.class_keyword_loc().start_offset(), node.body());
    }
    pub(crate) fn check_indentation_width_module(&mut self, node: &ruby_prism::ModuleNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        self.iw_check_class_like(node.module_keyword_loc().start_offset(), node.body());
    }
    pub(crate) fn check_indentation_width_sclass(&mut self, node: &ruby_prism::SingletonClassNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        self.iw_check_class_like(node.class_keyword_loc().start_offset(), node.body());
    }

    // ---- on_block ----

    /// `IndentationWidth#block_body_indentation_base` + `#dot_on_new_line?` +
    /// `#selector_on_new_line?`: only consulted under `EnforcedStyleAlignWith:
    /// relative_to_receiver`.
    fn iw_block_body_base(&self, call: &ruby_prism::CallNode, end_start: usize) -> usize {
        let Some(dot) = call.call_operator_loc() else { return end_start };
        let Some(receiver) = call.receiver() else { return end_start };
        let recv_last_line = self.idx.loc(receiver.location().end_offset().saturating_sub(1)).0;
        let dot_line = self.idx.loc(dot.start_offset()).0;
        if recv_last_line < dot_line {
            return dot.start_offset();
        }
        if let Some(sel) = call.message_loc() {
            if recv_last_line < self.idx.loc(sel.start_offset()).0 {
                return sel.start_offset();
            }
        }
        end_start
    }

    /// `IndentationWidth#on_block` (+ `on_numblock`/`on_itblock`, all one
    /// prism `CallNode`+`BlockNode` pair). Called from `visit_call_node`
    /// alongside this cop's block-attached siblings.
    pub(crate) fn check_indentation_width_block(&mut self, call: &ruby_prism::CallNode, block: &ruby_prism::BlockNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let end_start = block.closing_loc().start_offset();
        if !self.iw_begins_its_line(end_start) {
            return;
        }
        let style_rel = self.cfg.get(COP, "EnforcedStyleAlignWith").unwrap_or("start_of_line") == "relative_to_receiver";
        let base_start = if style_rel { self.iw_block_body_base(call, end_start) } else { end_start };
        self.iw_check_indentation(base_start, block.body(), "normal");
        if self.cfg.enforced_style("Layout/IndentationConsistency") != "indented_internal_methods" {
            return;
        }
        if !iw_contains_access_modifier(block.body()) {
            return;
        }
        self.iw_check_members(end_start, block.body());
    }

    // ---- rescue / resbody / ensure / kwbegin / for ----

    pub(crate) fn check_indentation_width_rescue(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        if node.rescue_clause().is_none() {
            return;
        }
        let Some(els) = node.else_clause() else { return };
        let kw = els.else_keyword_loc().start_offset();
        self.iw_check_indentation(kw, els.statements().map(|s| s.as_node()), "normal");
    }

    pub(crate) fn check_indentation_width_resbody(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let mut cur = node.rescue_clause();
        while let Some(r) = cur {
            let kw = r.keyword_loc().start_offset();
            self.iw_check_indentation(kw, r.statements().map(|s| s.as_node()), "normal");
            cur = r.subsequent();
        }
    }

    pub(crate) fn check_indentation_width_ensure(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let Some(ens) = node.ensure_clause() else { return };
        let kw = ens.ensure_keyword_loc().start_offset();
        self.iw_check_indentation(kw, ens.statements().map(|s| s.as_node()), "normal");
    }

    /// `IndentationWidth#on_kwbegin`: only an EXPLICIT `begin...end` (a
    /// `begin_keyword_loc` implies this isn't the implicit rescue/ensure
    /// wrapper prism synthesizes around a def/block body — that shape is
    /// handled by the `_rescue`/`_ensure`/`_def`/`_block` entry points
    /// instead). When this same node ALSO carries a rescue/ensure clause
    /// directly (prism flattens the whole `begin/rescue/else/ensure/end`
    /// onto one node, where whitequark nests a distinct `:rescue`/`:ensure`
    /// child under the `:kwbegin` wrapper), `body` is this SAME node — its
    /// content-adjusted start/end (see `iw_body_start`/`iw_target_end`) already
    /// gives exactly the child whitequark would report. Otherwise `body` is
    /// this node's own (possibly absent) plain statement list.
    pub(crate) fn check_indentation_width_kwbegin(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        if node.begin_keyword_loc().is_none() {
            return;
        }
        let Some(end_loc) = node.end_keyword_loc() else { return };
        let end_start = end_loc.start_offset();
        if !self.iw_begins_its_line(end_start) {
            return;
        }
        let body: Option<ruby_prism::Node> = if node.rescue_clause().is_some() || node.ensure_clause().is_some() {
            Some(node.as_node())
        } else {
            node.statements().map(|s| s.as_node())
        };
        self.iw_check_indentation(end_start, body, "normal");
    }

    pub(crate) fn check_indentation_width_for(&mut self, node: &ruby_prism::ForNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let kw = node.for_keyword_loc().start_offset();
        self.iw_check_indentation(kw, node.statements().map(|s| s.as_node()), "normal");
    }

    // ---- def ----

    pub(crate) fn check_indentation_width_def(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let start = node.location().start_offset();
        if self.iw_ignored.contains(&start) {
            return;
        }
        let kw = node.def_keyword_loc().start_offset();
        self.iw_check_indentation(kw, node.body(), "normal");
    }

    // ---- send: adjacent def-modifier + CheckAssignment#on_send ----

    /// `IndentationWidth#on_send` (`super` — `CheckAssignment#on_send` — then
    /// this cop's own `adjacent_def_modifier?` branch) + `on_csend` (prism
    /// unifies both into one `CallNode`).
    pub(crate) fn check_indentation_width_send(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        // `CheckAssignment#on_send`: ANY call whose LAST argument is (after
        // unwrapping a trailing receiver-chain) an if/while/until used as a
        // value — covers a setter/index-assignment RHS (`foo.bar = if x; y;
        // end`, `foo[i] = ...`), which prism represents as a plain `CallNode`
        // rather than a dedicated write-node type.
        if let Some(args) = node.arguments() {
            if let Some(last) = args.arguments().iter().last() {
                self.check_indentation_width_assignment(node.location().start_offset(), last);
            }
        }
        // `adjacent_def_modifier?`: `(send nil? _ (any_def ...))` — a
        // receiverless call with EXACTLY one argument that is directly a
        // `def`/`defs` (no recursion through further wrapping calls, unlike
        // `Layout/DefEndAlignment`'s `def_modifier?`).
        if node.receiver().is_some() {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let items: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        if items.len() != 1 {
            return;
        }
        let Some(def) = items[0].as_def_node() else { return };
        let def_start = def.location().start_offset();
        let style = self.cfg.get("Layout/DefEndAlignment", "EnforcedStyleAlignWith").unwrap_or("start_of_line");
        let base_start = if style == "def" {
            def_start
        } else {
            // `leftmost_modifier_of` — see `iw_chain_stack`'s field doc.
            self.iw_chain_stack.first().copied().unwrap_or_else(|| node.location().start_offset())
        };
        self.iw_ignored.insert(def_start);
        self.iw_check_indentation(base_start, def.body(), "normal");
    }

    // ---- if / unless / while / until (+ CheckAssignment dispatch) ----

    fn iw_check_if_core(&mut self, body: Option<ruby_prism::Node>, subsequent: Option<ruby_prism::Node>, base_start: usize) {
        self.iw_check_indentation(base_start, body, "normal");
        let Some(subsequent) = subsequent else { return };
        if subsequent.as_if_node().is_some() {
            // an `elsif` link: it gets its own `on_if` call when visited.
            return;
        }
        if let Some(else_node) = subsequent.as_else_node() {
            let kw = else_node.else_keyword_loc().start_offset();
            self.iw_check_indentation(kw, else_node.statements().map(|s| s.as_node()), "normal");
        }
    }

    fn iw_dispatch_if(&mut self, node: &ruby_prism::IfNode, base_start: usize) {
        let start = node.location().start_offset();
        if self.iw_ignored.contains(&start) {
            return;
        }
        if node.if_keyword_loc().is_none() {
            return; // ternary
        }
        if node.end_keyword_loc().is_none() {
            return; // modifier form
        }
        self.iw_check_if_core(node.statements().map(|s| s.as_node()), node.subsequent(), base_start);
    }

    fn iw_dispatch_unless(&mut self, node: &ruby_prism::UnlessNode, base_start: usize) {
        let start = node.location().start_offset();
        if self.iw_ignored.contains(&start) {
            return;
        }
        if node.end_keyword_loc().is_none() {
            return; // modifier form
        }
        self.iw_check_indentation(base_start, node.statements().map(|s| s.as_node()), "normal");
        if let Some(else_node) = node.else_clause() {
            let kw = else_node.else_keyword_loc().start_offset();
            self.iw_check_indentation(kw, else_node.statements().map(|s| s.as_node()), "normal");
        }
    }

    fn iw_check_while_until_core(
        &mut self,
        node_start: usize,
        is_begin_modifier: bool,
        kw_start: usize,
        pred_start: usize,
        body: Option<ruby_prism::Node>,
        base_start: usize,
    ) {
        if self.iw_ignored.contains(&node_start) {
            return;
        }
        // `on_while` (and `on_until`, aliased) is never invoked upstream for
        // the `begin...end while cond` post-condition-loop shape (a distinct
        // whitequark `:while_post`/`:until_post` node type) — see
        // `is_begin_modifier`'s use in `visit_while_node`/`visit_until_node`.
        if is_begin_modifier {
            return;
        }
        // `ConditionalNode#single_line_condition?`: the keyword and the
        // predicate's own first line coincide.
        if self.idx.loc(kw_start).0 != self.idx.loc(pred_start).0 {
            return;
        }
        self.iw_check_indentation(base_start, body, "normal");
    }

    fn iw_dispatch_while(&mut self, node: &ruby_prism::WhileNode, base_start: usize) {
        let start = node.location().start_offset();
        self.iw_check_while_until_core(
            start,
            node.is_begin_modifier(),
            node.keyword_loc().start_offset(),
            node.predicate().location().start_offset(),
            node.statements().map(|s| s.as_node()),
            base_start,
        );
    }
    fn iw_dispatch_until(&mut self, node: &ruby_prism::UntilNode, base_start: usize) {
        let start = node.location().start_offset();
        self.iw_check_while_until_core(
            start,
            node.is_begin_modifier(),
            node.keyword_loc().start_offset(),
            node.predicate().location().start_offset(),
            node.statements().map(|s| s.as_node()),
            base_start,
        );
    }

    pub(crate) fn check_indentation_width_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let start = node.location().start_offset();
        self.iw_dispatch_if(node, start);
    }
    pub(crate) fn check_indentation_width_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let start = node.location().start_offset();
        self.iw_dispatch_unless(node, start);
    }
    pub(crate) fn check_indentation_width_while(&mut self, node: &ruby_prism::WhileNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let start = node.location().start_offset();
        self.iw_dispatch_while(node, start);
    }
    pub(crate) fn check_indentation_width_until(&mut self, node: &ruby_prism::UntilNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let start = node.location().start_offset();
        self.iw_dispatch_until(node, start);
    }

    // ---- case / case_match ----

    pub(crate) fn check_indentation_width_case(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let mut last_kw: Option<usize> = None;
        for cond in node.conditions().iter() {
            if let Some(w) = cond.as_when_node() {
                let kw = w.keyword_loc().start_offset();
                last_kw = Some(kw);
                self.iw_check_indentation(kw, w.statements().map(|s| s.as_node()), "normal");
            }
        }
        if let Some(kw) = last_kw {
            self.iw_check_indentation(kw, node.else_clause().and_then(|e| e.statements()).map(|s| s.as_node()), "normal");
        }
    }

    pub(crate) fn check_indentation_width_case_match(&mut self, node: &ruby_prism::CaseMatchNode) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let mut last_kw: Option<usize> = None;
        for cond in node.conditions().iter() {
            if let Some(inn) = cond.as_in_node() {
                let kw = inn.in_loc().start_offset();
                last_kw = Some(kw);
                self.iw_check_indentation(kw, inn.statements().map(|s| s.as_node()), "normal");
            }
        }
        if let Some(kw) = last_kw {
            self.iw_check_indentation(kw, node.else_clause().and_then(|e| e.statements()).map(|s| s.as_node()), "normal");
        }
    }

    // ---- CheckAssignment: on_lvasgn family + masgn ----

    /// `IndentationWidth#check_assignment`: called from every write-node
    /// visitor (`assignment_write!`-family macros + `visit_multi_write_node`)
    /// with `own_start_offset` = the write node's OWN start (same position as
    /// its `name_loc`/`target` — a plain/path/masgn write's whitequark node
    /// always starts there too) and `rhs` = its value expression.
    pub(crate) fn check_indentation_width_assignment(&mut self, own_start_offset: usize, rhs: ruby_prism::Node) {
        const COP: &str = "Layout/IndentationWidth";
        if !self.on(COP) {
            return;
        }
        let Some(rhs) = iw_first_part_of_call_chain(Some(rhs)) else { return };
        let rhs_start = rhs.location().start_offset();
        let end_style = self.cfg.get("Layout/EndAlignment", "EnforcedStyleAlignWith").unwrap_or("keyword");
        let own_line = self.idx.loc(own_start_offset).0;
        let rhs_line = self.idx.loc(rhs_start).0;
        // `EndKeywordAlignment#variable_alignment?` + `#line_break_before_keyword?`.
        let variable_alignment = end_style != "keyword" && !(rhs_line > own_line);
        let base_start = if variable_alignment { own_start_offset } else { rhs_start };
        // whitequark folds `unless` into the same `:if` node type `on_if`
        // already handles — mirrored here with a parallel `UnlessNode` arm.
        let matched = if let Some(ifn) = rhs.as_if_node() {
            self.iw_dispatch_if(&ifn, base_start);
            true
        } else if let Some(un) = rhs.as_unless_node() {
            self.iw_dispatch_unless(&un, base_start);
            true
        } else if let Some(w) = rhs.as_while_node() {
            self.iw_dispatch_while(&w, base_start);
            true
        } else if let Some(u) = rhs.as_until_node() {
            self.iw_dispatch_until(&u, base_start);
            true
        } else {
            false
        };
        if matched {
            self.iw_ignored.insert(rhs_start);
        }
    }
}
