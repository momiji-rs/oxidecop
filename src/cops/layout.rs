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

    const SAK_ACCEPT_LEFT_PAREN: [&'static [u8]; 6] =
        [b"break", b"defined?", b"next", b"not", b"rescue", b"super"];
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
