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

