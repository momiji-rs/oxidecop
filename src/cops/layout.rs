//! Layout department: text-based cops that scan raw source lines (no AST).
use super::{Cops, Offense};

impl<'a> Cops<'a> {
    /// Layout/LineLength — display width (chars, not bytes) over `Max`.
    pub(crate) fn check_line_length(&mut self) {
        if !self.on("Layout/LineLength") {
            return;
        }
        let max = self.cfg.int("Layout/LineLength", "Max");
        for (li, line) in self.src.split(|&b| b == b'\n').enumerate() {
            let len = String::from_utf8_lossy(line).chars().count();
            if len > max && !self.allowed("Layout/LineLength", line) {
                self.offenses.push(Offense { line: li + 1, col: max + 1, cop: "Layout/LineLength", correctable: false,
                    message: format!("Line is too long. [{len}/{max}]") });
            }
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
            let in_heredoc = self.heredoc_lines.iter().any(|(s, e)| line_no >= *s && line_no <= *e);
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
