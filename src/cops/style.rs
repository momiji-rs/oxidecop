//! Style department: imperative cop logic too stateful for the DECLARATIVE
//! table (constructed suggestions, block-shape analysis, text-level checks).
//! Imperative cops still use node patterns as MATCHERS — parsed once, exactly
//! like rubocop's `def_node_matcher`.
use super::Cops;
use crate::nodepattern::{self, Pat};
use std::sync::OnceLock;

/// A rubocop `def_node_matcher` equivalent: the pattern string parses once.
fn matcher(cell: &'static OnceLock<Pat>, pattern: &str) -> &'static Pat {
    cell.get_or_init(|| nodepattern::parse(pattern))
}

impl<'a> Cops<'a> {
    /// Style/StringLiterals on a plain string — rubocop's `wrong_quotes?` over
    /// the literal's full source. Heredocs / %-literals / `?c` have other
    /// openings and fall through untouched; strings inside `#{}` interpolation
    /// and strings claimed by a multiline-concat check are exempt.
    pub(crate) fn check_string_literals(&mut self, node: &ruby_prism::StringNode) {
        if !self.on("Style/StringLiterals") || self.interp_depth > 0 {
            return;
        }
        let l = node.location();
        if self.str_ignore.iter().any(|(s, e)| l.start_offset() >= *s && l.start_offset() < *e) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let src = self.node_src(&node.as_node());
        let c = node.content_loc().as_slice();
        match self.cfg.enforced_style("Style/StringLiterals") {
            "single_quotes" if open.as_slice() == b"\"" => {
                if !double_quotes_required(src) {
                    self.push(l.start_offset(), "Style/StringLiterals", true, MSG_SINGLE);
                    // fix: `"c"` -> `'c'`, unescaping `\"` -> `"` (`\\` stays)
                    let mut rep = vec![b'\''];
                    let mut i = 0;
                    while i < c.len() {
                        if c[i] == b'\\' && matches!(c.get(i + 1), Some(b'"')) {
                            rep.push(b'"');
                            i += 2;
                        } else if c[i] == b'\\' && matches!(c.get(i + 1), Some(b'\\')) {
                            rep.extend_from_slice(b"\\\\");
                            i += 2;
                        } else {
                            rep.push(c[i]);
                            i += 1;
                        }
                    }
                    rep.push(b'\'');
                    self.fixes.push((l.start_offset(), l.end_offset(), rep));
                }
            }
            "double_quotes" if open.as_slice() == b"'" => {
                if !single_quotes_required(src) {
                    self.push(l.start_offset(), "Style/StringLiterals", true, MSG_DOUBLE);
                    // fix: `'c'` -> `"c"`, unescaping `\'` -> `'` (`\\` stays)
                    let mut rep = vec![b'"'];
                    let mut i = 0;
                    while i < c.len() {
                        if c[i] == b'\\' && c.get(i + 1) == Some(&b'\'') {
                            rep.push(b'\'');
                            i += 2;
                        } else {
                            rep.push(c[i]);
                            i += 1;
                        }
                    }
                    rep.push(b'"');
                    self.fixes.push((l.start_offset(), l.end_offset(), rep));
                }
            }
            _ => {}
        }
    }

    /// Style/StringLiterals with `ConsistentQuotesInMultiline: true` on a
    /// string continued across lines with `\` — parsed as an interpolated-
    /// string container whose parts are themselves quoted literals. Mixed
    /// quotes are one "Inconsistent quote style." offense on the whole node;
    /// a consistent-but-wrong quote is one style offense. Either way the
    /// parts are claimed (rubocop's `ignore_node`) so `on_str` skips them.
    pub(crate) fn check_string_concat(&mut self, node: &ruby_prism::InterpolatedStringNode) {
        const COP: &str = "Style/StringLiterals";
        if !self.on(COP) || self.cfg.param(COP, "ConsistentQuotesInMultiline") != Some("true") {
            return;
        }
        // Heredocs keep their parts.
        if node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) {
            return;
        }
        // Every part must itself be a string literal (a `#{}` part means this
        // is ordinary interpolation, not concatenation).
        let parts: Vec<ruby_prism::Node> = node.parts().iter().collect();
        let openings: Vec<Option<Vec<u8>>> = parts
            .iter()
            .map(|p| {
                if let Some(s) = p.as_string_node() {
                    Some(s.opening_loc().map(|o| o.as_slice().to_vec()).unwrap_or_default())
                } else {
                    p.as_interpolated_string_node()
                        .map(|d| d.opening_loc().map(|o| o.as_slice().to_vec()).unwrap_or_default())
                }
            })
            .collect();
        if openings.iter().any(|o| o.is_none()) || parts.is_empty() {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        let l = node.location();
        let mut quotes: Vec<&[u8]> = openings.iter().map(|o| o.as_deref().unwrap()).filter(|q| !q.is_empty()).collect();
        quotes.dedup();
        quotes.sort();
        quotes.dedup();
        let offense = if quotes.len() > 1 {
            Some("Inconsistent quote style.".to_string())
        } else if quotes == [b"'" as &[u8]] && style == "double_quotes" {
            // All parts must be wrong for the node to be an offense.
            parts
                .iter()
                .all(|p| !single_quotes_required(self.node_src(p)))
                .then(|| MSG_DOUBLE.to_string())
        } else if quotes == [b"\"" as &[u8]] && style == "single_quotes" {
            // Accepted if ANY part is interpolated or genuinely needs `"`.
            let accept = parts.iter().any(|p| {
                p.as_interpolated_string_node().is_some() || double_quotes_required(self.node_src(p))
            });
            (!accept).then(|| MSG_SINGLE.to_string())
        } else {
            None
        };
        if let Some(msg) = offense {
            self.push(l.start_offset(), COP, false, msg);
        }
        self.str_ignore.push((l.start_offset(), l.end_offset()));
    }

    /// Style/NumericLiterals — int and float literals over MinDigits want `_`
    /// thousands grouping. rubocop's check verbatim: judge the INTEGER PART
    /// (sign stripped, before any `.`/`e`); skip 0-prefixed (non-decimal)
    /// literals, AllowedNumbers, and anchored AllowedPatterns; flag ungrouped
    /// runs, any 4-digit run, and short groups (`_\d{1,2}_`, or trailing too
    /// under Strict).
    pub(crate) fn check_numeric_literals(&mut self, node: &ruby_prism::Node) {
        const COP: &str = "Style/NumericLiterals";
        if !self.on(COP) {
            return;
        }
        let s = String::from_utf8_lossy(self.node_src(node)).into_owned();
        let unsigned = s.trim_start_matches(['+', '-']);
        let int_part = unsigned.split(['e', 'E', '.']).next().unwrap_or("");
        if int_part.starts_with('0') {
            return; // 0x/0b/0o/octal/plain zero — rubocop punts on non-decimal
        }
        if let Some(v) = self.cfg.get(COP, "AllowedNumbers") {
            if crate::config::parse_allowed_list(v).iter().any(|n| n == int_part) {
                return;
            }
        }
        // NumericLiterals anchors its AllowedPatterns (`\A...\z`), unlike the
        // generic mixin — compiled here, on the rare configs that set them.
        if let Some(v) = self.cfg.get(COP, "AllowedPatterns") {
            for p in crate::config::parse_allowed_list(v) {
                if regex::Regex::new(&format!(r"\A(?:{p})\z")).is_ok_and(|re| re.is_match(int_part)) {
                    return;
                }
            }
        }
        if int_part.len() < self.cfg.int(COP, "MinDigits") {
            return;
        }
        let ungrouped = int_part.bytes().all(|b| b.is_ascii_digit());
        let four_run = int_part.as_bytes().windows(4).any(|w| w.iter().all(|b| b.is_ascii_digit()));
        let strict = self.cfg.param(COP, "Strict") == Some("true");
        let short_group = {
            let groups: Vec<&str> = int_part.split('_').collect();
            // `_\d{1,2}_` — an inner group of 1-2 digits; Strict also rejects
            // a short FINAL group (`_\d{1,2}$`).
            let inner = groups.len() > 2
                && groups[1..groups.len() - 1].iter().any(|g| !g.is_empty() && g.len() <= 2);
            let last = groups.len() > 1 && groups.last().is_some_and(|g| !g.is_empty() && g.len() <= 2);
            inner || (strict && last)
        };
        if !(ungrouped || four_run || short_group) {
            return;
        }
        let l = node.location();
        self.push(l.start_offset(), COP, true,
            "Use underscores(_) as thousands separator and separate every 3 digits with them.");
        // fix (rubocop's format_number): regroup the integer part, keep the
        // rest (`.`/`e` suffix) verbatim.
        if let Ok(v) = int_part.replace('_', "").parse::<i128>() {
            let digits = v.abs().to_string();
            let mut grouped = String::new();
            for (i, c) in digits.chars().enumerate() {
                if i > 0 && (digits.len() - i) % 3 == 0 {
                    grouped.push('_');
                }
                grouped.push(c);
            }
            let sign = if s.starts_with('-') { "-" } else { "" };
            let rest = &unsigned[int_part.len()..];
            self.fixes.push((l.start_offset(), l.end_offset(), format!("{sign}{grouped}{rest}").into_bytes()));
        }
    }

    /// Style/Documentation — a class/module wants a comment on the line above.
    pub(crate) fn check_documentation(&mut self, start_off: usize, kind: &str, name: &ruby_prism::Node) {
        if !self.on("Style/Documentation") {
            return;
        }
        let (line, _) = self.idx.loc(start_off);
        if !self.comment_lines.contains(&(line.wrapping_sub(1))) {
            let nm = String::from_utf8_lossy(self.node_src(name)).to_string();
            self.push(start_off, "Style/Documentation", false,
                format!("Missing top-level documentation comment for `{kind} {nm}`."));
        }
    }

    /// Style/FrozenStringLiteralComment — text-based, runs once per file.
    /// Three styles (rubocop's cop verbatim): `always` wants a valid magic
    /// comment among the leading comment lines; `never` forbids one;
    /// `always_true` demands it be literally `true`.
    /// `comments` are all comments (line, offset, text); `first_code_line`
    /// bounds the "leading" region (comments strictly before the first code).
    pub(crate) fn check_frozen_string_literal(&mut self, comments: &[(usize, usize, Vec<u8>)], first_code_line: Option<usize>) {
        const COP: &str = "Style/FrozenStringLiteralComment";
        if !self.on(COP) {
            return;
        }
        // rubocop bails on a token-less file (empty / whitespace-only).
        if comments.is_empty() && first_code_line.is_none() {
            return;
        }
        let vals: Vec<(usize, usize, Option<String>)> = comments
            .iter()
            .map(|(l, off, t)| (*l, *off, fsl_value(&String::from_utf8_lossy(t))))
            .collect();
        let is_leading = |l: usize| first_code_line.is_none_or(|fc| l < fc);
        // The first LEADING comment that specifies frozen_string_literal (any
        // value, even an invalid one) decides always_true's enabled/disabled.
        let first_specified = vals
            .iter()
            .filter(|(l, _, _)| is_leading(*l))
            .filter_map(|(_, _, v)| v.as_deref())
            .next();
        // "Comment exists" (always/never) counts only VALID values (true/false).
        let exists_valid = vals
            .iter()
            .filter(|(l, _, _)| is_leading(*l))
            .any(|(_, _, v)| matches!(v.as_deref(), Some("true" | "false")));
        // The unnecessary/disabled offense anchors on the first token ANYWHERE
        // whose text specifies frozen_string_literal (rubocop scans all tokens).
        let specified_off = vals.iter().find(|(_, _, v)| v.is_some()).map(|(_, off, _)| *off);
        match self.cfg.enforced_style(COP) {
            "never" => {
                if exists_valid {
                    if let Some(off) = specified_off {
                        self.push(off, COP, true, "Unnecessary frozen string literal comment.");
                        self.remove_comment_fix(off);
                    }
                }
            }
            "always_true" => match first_specified {
                Some("true") => {}
                Some(_) => {
                    if let Some(off) = specified_off {
                        self.push(off, COP, true, "Frozen string literal comment must be set to `true`.");
                        self.replace_line_fix(off, b"# frozen_string_literal: true");
                    }
                }
                None => {
                    self.push(0, COP, true, "Missing magic comment `# frozen_string_literal: true`.");
                    self.insert_fsl_fix(comments, first_code_line);
                }
            },
            _ => {
                // "always" (default)
                if !exists_valid {
                    self.push(0, COP, true, "Missing frozen string literal comment.");
                    self.insert_fsl_fix(comments, first_code_line);
                }
            }
        }
    }

    /// End offset of 1-based `line` (the position of its `\n`, or EOF).
    fn line_end(&self, line: usize) -> usize {
        self.idx.starts.get(line).map_or(self.src.len(), |s| s - 1)
    }

    /// Insert `# frozen_string_literal: true` below the last special comment
    /// (shebang, then an encoding comment — rubocop's `last_special_comment`),
    /// or at the very top when there is none.
    fn insert_fsl_fix(&mut self, comments: &[(usize, usize, Vec<u8>)], first_code_line: Option<usize>) {
        let is_leading = |l: usize| first_code_line.is_none_or(|fc| l < fc);
        let mut special: Option<usize> = None; // its line
        let mut next = 0; // index of the token to test for an encoding comment
        if let Some((l, _, t)) = comments.first() {
            if is_leading(*l) && t.starts_with(b"#!") {
                special = Some(*l);
                next = 1;
            }
        }
        if let Some((l, _, t)) = comments.get(next) {
            if is_leading(*l) && encoding_re().is_match(&String::from_utf8_lossy(t)) {
                special = Some(*l);
            }
        }
        match special {
            Some(line) => {
                let pos = self.line_end(line);
                self.fixes.push((pos, pos, b"\n# frozen_string_literal: true".to_vec()));
            }
            None => self.fixes.push((0, 0, b"# frozen_string_literal: true\n".to_vec())),
        }
    }

    /// Remove a comment starting at `off` plus the whitespace after it
    /// (rubocop's `range_with_surrounding_space(..., side: :right)`).
    fn remove_comment_fix(&mut self, off: usize) {
        let mut end = self.line_end(self.idx.loc(off).0);
        while end < self.src.len() && matches!(self.src[end], b' ' | b'\t' | b'\r' | b'\n') {
            end += 1;
        }
        self.fixes.push((off, end, Vec::new()));
    }

    /// Replace the whole line containing `off` with `rep`.
    fn replace_line_fix(&mut self, off: usize, rep: &[u8]) {
        let line = self.idx.loc(off).0;
        self.fixes.push((self.idx.starts[line - 1], self.line_end(line), rep.to_vec()));
    }

    /// Style/RedundantReturn — a `return` in tail position of a def (or a
    /// `define_method`/`lambda` block). rubocop's `check_branch` walks tail
    /// positions recursively: the last statement, both arms of a non-ternary
    /// if/unless, every case/when + else, rescue clauses (+ else, or the body
    /// when no else), and through begin groupings.
    pub(crate) fn check_redundant_return(&mut self, node: &ruby_prism::DefNode) {
        if !self.on("Style/RedundantReturn") {
            return;
        }
        if let Some(b) = node.body() {
            self.rr_branch(&b);
        }
    }
    pub(crate) fn rr_branch(&mut self, node: &ruby_prism::Node) {
        if let Some(stmts) = node.as_statements_node() {
            if let Some(last) = stmts.body().iter().last() {
                self.rr_branch(&last);
            }
        } else if let Some(ret) = node.as_return_node() {
            self.rr_return(&ret);
        } else if let Some(c) = node.as_case_node() {
            for w in c.conditions().iter() {
                if let Some(s) = w.as_when_node().and_then(|w| w.statements()) {
                    self.rr_branch(&s.as_node());
                }
            }
            if let Some(s) = c.else_clause().and_then(|e| e.statements()) {
                self.rr_branch(&s.as_node());
            }
        } else if let Some(c) = node.as_case_match_node() {
            for i in c.conditions().iter() {
                if let Some(s) = i.as_in_node().and_then(|i| i.statements()) {
                    self.rr_branch(&s.as_node());
                }
            }
            if let Some(s) = c.else_clause().and_then(|e| e.statements()) {
                self.rr_branch(&s.as_node());
            }
        } else if let Some(i) = node.as_if_node() {
            if i.if_keyword_loc().is_none() {
                return; // ternary
            }
            if let Some(s) = i.statements() {
                self.rr_branch(&s.as_node());
            }
            if let Some(sub) = i.subsequent() {
                self.rr_branch(&sub); // ElseNode, or an elsif IfNode
            }
        } else if let Some(u) = node.as_unless_node() {
            if let Some(s) = u.statements() {
                self.rr_branch(&s.as_node());
            }
            if let Some(s) = u.else_clause().and_then(|e| e.statements()) {
                self.rr_branch(&s.as_node());
            }
        } else if let Some(e) = node.as_else_node() {
            if let Some(s) = e.statements() {
                self.rr_branch(&s.as_node());
            }
        } else if let Some(b) = node.as_begin_node() {
            if let Some(r) = b.rescue_clause() {
                let mut cur = Some(r);
                while let Some(rn) = cur {
                    if let Some(s) = rn.statements() {
                        self.rr_branch(&s.as_node());
                    }
                    cur = rn.subsequent();
                }
                // rescue-else is a branch; the main body is a tail only when
                // there is no else (rubocop's `unless node.else?`).
                if let Some(s) = b.else_clause().and_then(|e| e.statements()) {
                    self.rr_branch(&s.as_node());
                } else if let Some(s) = b.statements() {
                    self.rr_branch(&s.as_node());
                }
            } else if let Some(s) = b.statements() {
                self.rr_branch(&s.as_node());
            }
        }
    }
    fn rr_return(&mut self, ret: &ruby_prism::ReturnNode) {
        const COP: &str = "Style/RedundantReturn";
        let args: Vec<ruby_prism::Node> =
            ret.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        let multi = args.len() > 1;
        let allow_multi = self.cfg.param(COP, "AllowMultipleReturnValues") == Some("true");
        if allow_multi && multi {
            return;
        }
        let kw = ret.keyword_loc();
        self.push(kw.start_offset(), COP, true, if multi {
            "Redundant `return` detected. To return multiple values, use an array."
        } else {
            "Redundant `return` detected."
        });
        let l = ret.location();
        if args.is_empty() {
            // bare `return` -> `nil`
            self.fixes.push((l.start_offset(), l.end_offset(), b"nil".to_vec()));
        } else {
            // drop the keyword (+ trailing space); bracket multiple values
            let mut kw_end = kw.end_offset();
            while kw_end < self.src.len() && matches!(self.src[kw_end], b' ' | b'\t') {
                kw_end += 1;
            }
            self.fixes.push((kw.start_offset(), kw_end, Vec::new()));
            if multi {
                let s = args.first().unwrap().location().start_offset();
                let e = args.last().unwrap().location().end_offset();
                self.fixes.push((s, s, b"[".to_vec()));
                self.fixes.push((e, e, b"]".to_vec()));
            }
        }
    }

    /// Style/ZeroLengthPredicate — `x.size == 0` → `empty?`, `x.size > 0` →
    /// `!empty?`, `x.size.zero?` → `empty?`. Transcribed from rubocop's cop:
    /// its `def_node_matcher` patterns verbatim, matched on the OUTER
    /// (comparison/predicate) node; messages interpolate the captured pieces.
    pub(crate) fn check_zero_length(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/ZeroLengthPredicate";
        if !self.on(COP) {
            return;
        }
        let n = node.as_node();
        // rubocop's `non_polymorphic_collection?`: File/Tempfile/StringIO/
        // File::Stat implement #size but not #empty? — never flag those.
        static NON_POLY: OnceLock<Pat> = OnceLock::new();
        let non_poly = matcher(&NON_POLY,
            "{(send (send (send (const {nil? cbase} :File) :stat _) ...) ...) \
              (send (send (send (const {nil? cbase} {:File :Tempfile :StringIO}) {:new :open} ...) ...) ...) \
              (send (send (send (const (const {nil? cbase} :File) :Stat) :new ...) ...) ...)}");
        if nodepattern::matches(non_poly, &n, self.src).is_some() {
            return;
        }
        // `x.size.zero?` / `x&.length&.zero?` — offense spans selector..end so
        // the message shows the real dispatch (`length&.zero?`).
        static PREDICATE: OnceLock<Pat> = OnceLock::new();
        if nodepattern::matches(matcher(&PREDICATE, "(call (call (...) {:length :size}) :zero?)"), &n, self.src).is_some() {
            if let Some(sel) = node.receiver().and_then(|r| r.as_call_node()).and_then(|c| c.message_loc()) {
                let (sel, end) = (sel.start_offset(), node.location().end_offset());
                let cur = String::from_utf8_lossy(&self.src[sel..end]).into_owned();
                self.push(sel, COP, true, format!("Use `empty?` instead of `{cur}`."));
                self.fixes.push((sel, end, b"empty?".to_vec()));
            }
            return;
        }
        // Comparison shapes. Captures come out [lhs, op, rhs] in source order,
        // so the message's "current" is just the captures joined. The nonzero
        // shapes require a plain send for the size/length dispatch — rubocop
        // only checks them from on_send, so `x&.size > 0` is never flagged.
        static ZERO: OnceLock<Pat> = OnceLock::new();
        static NONZERO: OnceLock<Pat> = OnceLock::new();
        let zero_cmp = matcher(&ZERO,
            "{(call (call (...) ${:length :size}) $:== (int $0)) \
              (call (int $0) $:== (call (...) ${:length :size})) \
              (call (call (...) ${:length :size}) $:< (int $1)) \
              (call (int $1) $:> (call (...) ${:length :size}))}");
        let nonzero_cmp = matcher(&NONZERO,
            "{(call (send (...) ${:length :size}) ${:> :!=} (int $0)) \
              (call (int $0) ${:< :!=} (send (...) ${:length :size}))}");
        let (caps, zero) = if let Some(c) = nodepattern::matches(zero_cmp, &n, self.src) {
            (c, true)
        } else if let Some(c) = nodepattern::matches(nonzero_cmp, &n, self.src) {
            (c, false)
        } else {
            return;
        };
        let current = caps.join(" ");
        let l = node.location();
        self.push(l.start_offset(), COP, true,
            if zero { format!("Use `empty?` instead of `{current}`.") }
            else { format!("Use `!empty?` instead of `{current}`.") });
        // fix: `recv.size == 0` -> `recv.empty?` / `recv.size > 0` -> `!recv.empty?`
        let inner = node
            .receiver()
            .and_then(|r| len_call(&r))
            .or_else(|| {
                node.arguments()
                    .and_then(|a| a.arguments().iter().next())
                    .and_then(|a| len_call(&a))
            });
        if let Some(ic) = inner {
            let recv = String::from_utf8_lossy(self.node_src(&ic.receiver().unwrap())).into_owned();
            let dot = ic
                .call_operator_loc()
                .map(|o| String::from_utf8_lossy(o.as_slice()).into_owned())
                .unwrap_or_else(|| ".".into());
            let bang = if zero { "" } else { "!" };
            self.fixes.push((l.start_offset(), l.end_offset(), format!("{bang}{recv}{dot}empty?").into_bytes()));
        }
    }

    /// Style/NumericPredicate: under `predicate` style flag `x {==,>,<} 0` (and
    /// inverted) → suggest `x.zero?/positive?/negative?`; under `comparison`
    /// style flag those predicates → suggest the comparison. Returns the offense
    /// (whole-node offset, rendered message) or None. Verbatim rubocop logic.
    pub(crate) fn numeric_predicate(&self, node: &ruby_prism::CallNode) -> Option<(usize, String)> {
        if !self.on("Style/NumericPredicate") {
            return None;
        }
        let name = node.name().as_slice();
        // AllowedMethods/Patterns: the offending method OR any ancestor call/block.
        if self.allowed("Style/NumericPredicate", name)
            || self.call_stack.iter().any(|n| self.allowed("Style/NumericPredicate", n))
        {
            return None;
        }
        let recv = node.receiver();
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        let node_off = node.location().start_offset();
        let current = String::from_utf8_lossy(self.node_src(&node.as_node())).into_owned();

        let prefer = match self.cfg.enforced_style("Style/NumericPredicate") {
            "comparison" => {
                // flag `x.zero?/positive?/negative?` (receiver, no args)
                let r = recv?;
                if !args.is_empty() {
                    return None;
                }
                let op = match name {
                    b"zero?" => "==",
                    b"positive?" => ">",
                    b"negative?" => "<",
                    _ => return None,
                };
                let rsrc = String::from_utf8_lossy(self.node_src(&r));
                let negated = self.call_stack.last().is_some_and(|n| n.as_slice() == b"!");
                if negated {
                    format!("({rsrc} {op} 0)")
                } else {
                    format!("{rsrc} {op} 0")
                }
            }
            _ => {
                // predicate style: flag `x {==,>,<} 0` and the inverted `0 {..} x`
                if args.len() != 1 {
                    return None;
                }
                let op: &[u8] = match name {
                    b"==" => b"==",
                    b">" => b">",
                    b"<" => b"<",
                    _ => return None,
                };
                let r = recv?;
                let arg = &args[0];
                if is_int_zero(arg, self.src) && !is_gvar(&r) {
                    format!("{}.{}", paren_src(&r, self.src), predicate_for(op, false))
                } else if is_int_zero(&r, self.src) && !is_gvar(arg) {
                    format!("{}.{}", paren_src(arg, self.src), predicate_for(op, true))
                } else {
                    return None;
                }
            }
        };
        Some((node_off, format!("Use `{prefer}` instead of `{current}`.")))
    }

    /// Shared "symbol proc" shape check for a block/lambda body: the sole param
    /// is one plain positional (`|x|`) or a single numbered param (`_1`), and the
    /// body is one parameterless, blockless call on that param. Returns the
    /// called method name (e.g. `upcase`) or None.
    pub(crate) fn proc_shape(&self, params: Option<ruby_prism::Node>, body: Option<ruby_prism::Node>) -> Option<String> {
        let params = params?;
        let varname: Vec<u8> = if let Some(bp) = params.as_block_parameters_node() {
            let pn = bp.parameters()?;
            let reqs: Vec<_> = pn.requireds().iter().collect();
            if reqs.len() != 1
                || pn.optionals().iter().count() > 0
                || pn.rest().is_some()
                || pn.posts().iter().count() > 0
                || pn.keywords().iter().count() > 0
                || pn.keyword_rest().is_some()
                || pn.block().is_some()
            {
                return None;
            }
            reqs[0].as_required_parameter_node()?.name().as_slice().to_vec()
        } else if let Some(np) = params.as_numbered_parameters_node() {
            if np.maximum() != 1 {
                return None;
            }
            b"_1".to_vec()
        } else {
            return None;
        };
        let stmts = body?.as_statements_node()?;
        let mut it = stmts.body().iter();
        let first = it.next()?;
        if it.next().is_some() {
            return None;
        }
        let call = first.as_call_node()?;
        if call.receiver()?.as_local_variable_read_node()?.name().as_slice() != varname.as_slice()
            || call.arguments().is_some()
            || call.block().is_some()
        {
            return None;
        }
        Some(String::from_utf8_lossy(call.name().as_slice()).into_owned())
    }

    /// Style/SymbolProc for a method-call block `recv.m { |x| x.meth }` →
    /// `recv.m(&:meth)`. Offense range is the block (`{`..`}`).
    pub(crate) fn symbol_proc(&self, node: &ruby_prism::CallNode) -> Option<(usize, String)> {
        if !self.on("Style/SymbolProc") {
            return None;
        }
        let block = node.block()?.as_block_node()?;
        let method = self.proc_shape(block.parameters(), block.body())?;
        let block_method = node.name();
        let bm = block_method.as_slice();
        // ActiveSupport gating: `proc`/`lambda`/`Proc.new` blocks are only
        // candidates when ActiveSupportExtensionsEnabled is off (the default).
        if self.cfg.active_support() {
            if matches!(bm, b"lambda" | b"proc") {
                return None;
            }
            if bm == b"new" && node.receiver().is_some_and(|r| matches!(self.node_src(&r), b"Proc" | b"::Proc")) {
                return None;
            }
        }
        // AllowedMethods/Patterns on the block's method (default [define_method]).
        if self.allowed("Style/SymbolProc", bm) {
            return None;
        }
        // Unsafe on literal hash/array receivers: `{}.{reject,select}`, `[].{min,max}`.
        if let Some(r) = node.receiver() {
            if r.as_hash_node().is_some() && matches!(bm, b"reject" | b"select") {
                return None;
            }
            if r.as_array_node().is_some() && matches!(bm, b"min" | b"max") {
                return None;
            }
        }
        // AllowMethodsWithArguments: skip when enabled and the dispatch has args.
        if self.cfg.param("Style/SymbolProc", "AllowMethodsWithArguments") == Some("true")
            && node.arguments().is_some()
        {
            return None;
        }
        if self.cfg.param("Style/SymbolProc", "AllowComments") == Some("true")
            && self.block_has_inner_comment(block.opening_loc().start_offset(), block.closing_loc().start_offset())
        {
            return None;
        }
        Some((
            block.opening_loc().start_offset(),
            format!("Pass `&:{method}` as an argument to `{}` instead of a block.", String::from_utf8_lossy(bm)),
        ))
    }

    /// Style/SymbolProc for a `super { |x| x.meth }` / `super(...) { … }` block →
    /// `super(&:meth)`. `super` is always a candidate (no ActiveSupport gating).
    pub(crate) fn symbol_proc_super(&self, block: &ruby_prism::Node, has_args: bool) -> Option<(usize, String)> {
        if !self.on("Style/SymbolProc") {
            return None;
        }
        let block = block.as_block_node()?;
        let method = self.proc_shape(block.parameters(), block.body())?;
        if self.allowed("Style/SymbolProc", b"super") {
            return None;
        }
        // AllowMethodsWithArguments: skip when enabled and `super` has arguments.
        if self.cfg.param("Style/SymbolProc", "AllowMethodsWithArguments") == Some("true") && has_args {
            return None;
        }
        if self.cfg.param("Style/SymbolProc", "AllowComments") == Some("true")
            && self.block_has_inner_comment(block.opening_loc().start_offset(), block.closing_loc().start_offset())
        {
            return None;
        }
        Some((
            block.opening_loc().start_offset(),
            format!("Pass `&:{method}` as an argument to `super` instead of a block."),
        ))
    }

    /// Style/SymbolProc for an arrow lambda literal `->(x) { x.meth }` →
    /// `lambda(&:meth)`. Only a candidate when ActiveSupport extensions are off.
    pub(crate) fn symbol_proc_lambda(&self, node: &ruby_prism::LambdaNode) -> Option<(usize, String)> {
        if !self.on("Style/SymbolProc") || self.cfg.active_support() {
            return None;
        }
        let method = self.proc_shape(node.parameters(), node.body())?;
        if self.allowed("Style/SymbolProc", b"lambda") {
            return None;
        }
        if self.cfg.param("Style/SymbolProc", "AllowComments") == Some("true")
            && self.block_has_inner_comment(node.opening_loc().start_offset(), node.closing_loc().start_offset())
        {
            return None;
        }
        Some((
            node.opening_loc().start_offset(),
            format!("Pass `&:{method}` as an argument to `lambda` instead of a block."),
        ))
    }
}

// ---- Style/ZeroLengthPredicate helper ----
/// A `.length`/`.size` call with an explicit receiver.
fn len_call<'pr>(x: &ruby_prism::Node<'pr>) -> Option<ruby_prism::CallNode<'pr>> {
    x.as_call_node()
        .filter(|c| matches!(c.name().as_slice(), b"length" | b"size") && c.receiver().is_some())
}

// ---- Style/StringLiterals helpers ----
const MSG_SINGLE: &str =
    "Prefer single-quoted strings when you don't need string interpolation or special symbols.";
const MSG_DOUBLE: &str =
    "Prefer double-quoted strings unless you need single quotes to avoid extra backslashes for escaping.";

/// rubocop's `double_quotes_required?` over a literal's full source: true if it
/// contains a `'`, or an odd run of backslashes introducing a real escape
/// sequence (i.e. not followed by `"` — `/'|(?<!\\)\\{2}*\\(?![\\"])/x`).
fn double_quotes_required(src: &[u8]) -> bool {
    if src.contains(&b'\'') {
        return true;
    }
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\' {
            let start = i;
            while i < src.len() && src[i] == b'\\' {
                i += 1;
            }
            if (i - start) % 2 == 1 && src.get(i) != Some(&b'"') {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// The single-quoted literal genuinely needs single quotes — rubocop's
/// `/" | \\[^'\\] | \#[@{$]/x` over the full source: a `"`, an escape other
/// than `\'`/`\\`, or text that would interpolate under double quotes.
fn single_quotes_required(src: &[u8]) -> bool {
    for i in 0..src.len() {
        match src[i] {
            b'"' => return true,
            b'\\' => {
                if let Some(&c) = src.get(i + 1) {
                    if c != b'\'' && c != b'\\' {
                        return true;
                    }
                }
            }
            b'#' => {
                if matches!(src.get(i + 1), Some(b'@' | b'{' | b'$')) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

// ---- Style/FrozenStringLiteralComment helpers: MagicComment parsing ----
fn re(cell: &'static std::sync::OnceLock<regex::Regex>, pat: &str) -> &'static regex::Regex {
    cell.get_or_init(|| regex::Regex::new(pat).unwrap())
}
/// rubocop's `Encoding::ENCODING_PATTERN` (used to place the autocorrect
/// insertion below an encoding comment).
fn encoding_re() -> &'static regex::Regex {
    static ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    re(&ENC, r"#.*coding\s?[:=]\s?(?:UTF|utf)-8")
}
/// The `frozen_string_literal` value a magic-comment line specifies, lowercased
/// (`"true"`/`"false"`/anything else), or None when the line doesn't specify
/// one. Mirrors rubocop's `MagicComment.parse`: the emacs `-*- k: v; ... -*-`
/// form, vim comments (which cannot specify it), then the simple form — which
/// only counts when it is the whole comment.
fn fsl_value(line: &str) -> Option<String> {
    static EMACS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static EMACS_TOK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static VIM: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SIMPLE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if let Some(c) = re(&EMACS, r"-\*-(.+)-\*-").captures(line) {
        let tok = re(&EMACS_TOK, r"(?i)^frozen[_-]string[_-]literal\s*:\s*([[:alnum:]_-]+)$");
        c[1].split(';')
            .find_map(|t| tok.captures(t.trim()).map(|c| c[1].to_lowercase()))
    } else if re(&VIM, r"#\s*vim:\s*\S").is_match(line) {
        None
    } else {
        re(&SIMPLE, r"(?i)^\s*#\s*frozen[_-]string[_-]literal:\s*([[:alnum:]_-]+)\s*$")
            .captures(line)
            .map(|c| c[1].to_lowercase())
    }
}

// ---- Style/NumericPredicate helpers ----
fn is_int_zero(node: &ruby_prism::Node, src: &[u8]) -> bool {
    node.as_integer_node()
        .map(|i| {
            let l = i.location();
            &src[l.start_offset()..l.end_offset()] == b"0"
        })
        .unwrap_or(false)
}
fn is_gvar(node: &ruby_prism::Node) -> bool {
    node.as_global_variable_read_node().is_some()
}
/// A binary-operator send like `foo - 1` (operator name + receiver + one arg).
fn is_binary_op(node: &ruby_prism::Node) -> bool {
    node.as_call_node()
        .map(|c| {
            c.receiver().is_some()
                && c.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0) == 1
                && c.name().as_slice().first().is_some_and(|b| !b.is_ascii_alphanumeric() && *b != b'_')
        })
        .unwrap_or(false)
}
/// rubocop's `parenthesized_source`: wrap a bare binary operation in parens.
fn paren_src(node: &ruby_prism::Node, src: &[u8]) -> String {
    let l = node.location();
    let s = String::from_utf8_lossy(&src[l.start_offset()..l.end_offset()]);
    if is_binary_op(node) {
        format!("({s})")
    } else {
        s.into_owned()
    }
}
/// The predicate for a comparison operator (`==`→zero?, `>`→positive?, `<`→
/// negative?); when `inverted` (e.g. `0 < x`), `>`/`<` swap first.
fn predicate_for(op: &[u8], inverted: bool) -> &'static str {
    let eff: &[u8] = if inverted {
        match op {
            b">" => b"<",
            b"<" => b">",
            o => o,
        }
    } else {
        op
    };
    match eff {
        b"==" => "zero?",
        b">" => "positive?",
        b"<" => "negative?",
        _ => "",
    }
}
