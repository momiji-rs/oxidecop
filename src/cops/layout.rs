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

    /// Layout/TrailingWhitespace — spaces/tabs before the line end.
    pub(crate) fn check_trailing_whitespace(&mut self) {
        if !self.on("Layout/TrailingWhitespace") {
            return;
        }
        for (li, line) in self.src.split(|&b| b == b'\n').enumerate() {
            let ls = self.idx.starts[li];
            let (col, trim_start) = match line.iter().rposition(|&c| c != b' ' && c != b'\t') {
                Some(pos) if pos + 1 < line.len() => (pos + 2, ls + pos + 1),
                None if !line.is_empty() => (1, ls),
                _ => continue,
            };
            self.offenses.push(Offense { line: li + 1, col, cop: "Layout/TrailingWhitespace", correctable: true,
                message: "Trailing whitespace detected.".into() });
            self.fixes.push((trim_start, ls + line.len(), Vec::new())); // strip the trailing ws
        }
    }
}
