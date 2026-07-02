//! Layout department: text-based cops that scan raw source lines (no AST).
use super::{Cops, Offense};

impl<'a> Cops<'a> {
    /// Layout/LineLength — rubocop's check_line verbatim: character length
    /// plus a tab-indentation surcharge, then the exemption ladder — allowed
    /// patterns, shebang, permitted heredocs, RBS inline annotations, cop
    /// directives (length re-measured without the directive), and the
    /// AllowURI / AllowQualifiedName excessive-range dance.
    pub(crate) fn check_line_length(&mut self, comments: &[(usize, usize, Vec<u8>)]) {
        const COP: &str = "Layout/LineLength";
        if !self.on(COP) {
            return;
        }
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
        let heredoc_allow = self.cfg.get(COP, "AllowHeredoc").unwrap_or("true").to_string();
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
            let owned = String::from_utf8_lossy(raw);
            let line = owned.strip_suffix('\r').unwrap_or(&owned);
            let nchars = line.chars().count();
            let tabs = line.chars().take_while(|c| *c == '\t').count();
            let indent_diff = tabs * tab_width.saturating_sub(1);
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
            if let Some((_, _, delim)) = self
                .heredoc_lines
                .iter()
                .find(|(s, e, _)| line_no >= *s && line_no <= *e)
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
            if allow_rbs && comment.is_some_and(|(_, _, t)| is_rbs_annotation(t)) {
                continue;
            }
            if allow_directives {
                if let Some((_, coff, t)) = comment {
                    if is_directive_comment(t) {
                        // re-measure without the trailing directive
                        let prefix = &self.src[self.idx.starts[li]..*coff];
                        let len = String::from_utf8_lossy(prefix).trim_end().chars().count();
                        if len > max {
                            self.offenses.push(Offense { line: line_no, col: max + 1, cop: COP, correctable: false,
                                message: format!("Line is too long. [{len}/{max}]") });
                        }
                        continue;
                    }
                }
            }
            // ---- AllowURI / AllowQualifiedName ----
            let mut col = max.saturating_sub(indent_diff) + 1; // highlight_start, 1-based
            if allow_uri || allow_qn {
                let uri_range = allow_uri
                    .then(|| find_excessive_range(line, &uri_re, indent_diff, max))
                    .flatten();
                let qn_range = allow_qn
                    .then(|| find_excessive_range(line, qualified_name_regex(), indent_diff, max))
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
            self.offenses.push(Offense { line: line_no, col, cop: COP, correctable: false,
                message: format!("Line is too long. [{line_len}/{max}]") });
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
            let text = String::from_utf8_lossy(line);
            let text = text.strip_suffix('\r').unwrap_or(&text);
            if !text.chars().next_back().is_some_and(is_blank) {
                continue;
            }
            let in_heredoc = self.heredoc_lines.iter().any(|(s, e, _)| line_no >= *s && line_no <= *e);
            if allow_heredoc && in_heredoc {
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
            if !in_heredoc {
                let end = ls + text.len();
                self.fixes.push((end - run_bytes, end, Vec::new())); // strip the run
            }
            // inside a heredoc the whitespace is string CONTENT — rubocop's
            // correction wraps it in an interpolation; we report but leave
            // `--fix` alone rather than corrupt the value.
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
    regex::Regex::new(&format!(
        r#"(?i)\b(?:{}):(?://)?[^\s<>"{{}}|\\^\x60\[\]]+"#,
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
fn is_directive_comment(comment: &[u8]) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    cached(&RE, r"^#\s*rubocop\s*:\s*(?:disable|todo|enable)\b").is_match(&String::from_utf8_lossy(comment))
}
/// rubocop's `find_excessive_range`: the LAST regexp match on the line, end
/// extended over an enclosing `{…}` and the following non-space run, both
/// endpoints shifted by the tab surcharge; None when it sits fully before Max
/// (char positions, 0-based begin, exclusive end).
fn find_excessive_range(line: &str, re: &regex::Regex, indent_diff: usize, max: usize) -> Option<(usize, usize)> {
    let m = re.find_iter(line).last()?;
    let begin = line[..m.start()].chars().count() + indent_diff;
    let mut end = begin - indent_diff + line[m.start()..m.end()].chars().count();
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
