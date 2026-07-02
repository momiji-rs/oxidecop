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

    /// Style/Documentation — rubocop's check verbatim. A class/module needs a
    /// real documentation comment directly above unless it is a pure namespace
    /// (all children are constant declarations), carries `#:nodoc:` on its
    /// header (or an ancestor's `#:nodoc: all`), is in AllowedConstants, or
    /// its body is only include/extend/prepend statements. A class with no
    /// body is skipped outright; annotation (`# TODO:`), magic-comment, and
    /// rubocop-directive lines do not count as documentation.
    pub(crate) fn check_documentation(
        &mut self,
        kind: &str,
        node_start: usize,
        constant_path: &ruby_prism::Node,
        body: Option<ruby_prism::Node>,
    ) {
        const COP: &str = "Style/Documentation";
        if !self.on(COP) {
            return;
        }
        if kind == "class" && body.is_none() {
            return;
        }
        if body.as_ref().is_some_and(is_namespace) {
            return;
        }
        let line = self.idx.loc(node_start).0;
        if self.has_documentation_comment(line) {
            return;
        }
        let name_src = self.node_src(constant_path);
        let short = name_src.rsplit(|&b| b == b':').next().unwrap_or(name_src);
        if let Some(v) = self.cfg.param(COP, "AllowedConstants") {
            if crate::config::parse_allowed_list(v).iter().any(|c| c.as_bytes() == short) {
                return;
            }
        }
        if self.nodoc_on_line(line, false) || self.nodoc_all_stack.iter().any(|b| *b) {
            return;
        }
        if body.as_ref().is_some_and(|b| include_statements_only(b)) {
            return;
        }
        let mut parts = self.mod_stack.clone();
        parts.push(String::from_utf8_lossy(name_src).into_owned());
        let ident = parts.join("::").replace("::::", "::");
        self.push(node_start, COP, false,
            format!("Missing top-level documentation comment for `{kind} {ident}`."));
    }
    /// Track the enclosing class/module for qualified Documentation messages
    /// and `#:nodoc: all` inheritance.
    pub(crate) fn enter_namespace(&mut self, node_start: usize, constant_path: &ruby_prism::Node) {
        let name = String::from_utf8_lossy(self.node_src(constant_path)).into_owned();
        self.mod_stack.push(name);
        let line = self.idx.loc(node_start).0;
        self.nodoc_all_stack.push(self.nodoc_on_line(line, true));
    }
    pub(crate) fn leave_namespace(&mut self) {
        self.mod_stack.pop();
        self.nodoc_all_stack.pop();
    }
    /// A `#:nodoc:` (or `#:nodoc: all` when `require_all`) trailing comment on
    /// this line.
    fn nodoc_on_line(&self, line: usize, require_all: bool) -> bool {
        static NODOC: OnceLock<regex::Regex> = OnceLock::new();
        static NODOC_ALL: OnceLock<regex::Regex> = OnceLock::new();
        let re = if require_all {
            NODOC_ALL.get_or_init(|| regex::Regex::new(r"^#\s*:nodoc:\s+all\s*$").unwrap())
        } else {
            NODOC.get_or_init(|| regex::Regex::new(r"^#\s*:nodoc:").unwrap())
        };
        self.comments
            .iter()
            .find(|(l, _, _)| *l == line)
            .is_some_and(|(_, _, t)| re.is_match(&String::from_utf8_lossy(t)))
    }
    /// rubocop's `documentation_comment?`: a comment block ends directly above
    /// the node, and at least one of its lines is real prose — not a `# TODO:`
    /// style annotation, magic comment, or rubocop directive.
    fn has_documentation_comment(&self, node_line: usize) -> bool {
        if node_line < 2 || !self.comment_lines.contains(&(node_line - 1)) {
            return false;
        }
        static ANNOTATION: OnceLock<regex::Regex> = OnceLock::new();
        static MAGIC: OnceLock<regex::Regex> = OnceLock::new();
        static DIRECTIVE: OnceLock<regex::Regex> = OnceLock::new();
        let annotation = ANNOTATION.get_or_init(|| {
            regex::Regex::new(r"^#\s*(?:TODO|FIXME|OPTIMIZE|HACK|REVIEW|NOTE)\b").unwrap()
        });
        let magic = MAGIC
            .get_or_init(|| regex::Regex::new(r"^#\s*(frozen_string_literal|encoding):").unwrap());
        let directive = DIRECTIVE.get_or_init(|| {
            regex::Regex::new(r"^#\s*rubocop\s*:\s*(?:disable|todo|enable)\b").unwrap()
        });
        let mut line = node_line - 1;
        while line >= 1 && self.comment_lines.contains(&line) {
            if let Some((_, off, t)) = self.comments.iter().find(|(l, _, _)| *l == line) {
                // A trailing comment (code before it) is not a doc line and
                // ends the block (`module A # The A Module` documents nothing).
                if !self.src[self.idx.starts[line - 1]..*off].iter().all(|b| b.is_ascii_whitespace()) {
                    break;
                }
                let t = String::from_utf8_lossy(t);
                if !annotation.is_match(&t) && !magic.is_match(&t) && !directive.is_match(&t) {
                    return true;
                }
            }
            if line == 1 {
                break;
            }
            line -= 1;
        }
        false
    }

    /// Style/FrozenStringLiteralComment — text-based, runs once per file.
    /// Three styles (rubocop's cop verbatim): `always` wants a valid magic
    /// comment among the leading comment lines; `never` forbids one;
    /// `always_true` demands it be literally `true`.
    /// `comments` are all comments (line, offset, text); `first_code_line`
    /// bounds the "leading" region (comments strictly before the first code).
    pub(crate) fn check_frozen_string_literal(&mut self, first_code_line: Option<usize>) {
        const COP: &str = "Style/FrozenStringLiteralComment";
        if !self.on(COP) {
            return;
        }
        let comments = self.comments;
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
                    self.insert_fsl_fix(first_code_line);
                }
            },
            _ => {
                // "always" (default)
                if !exists_valid {
                    self.push(0, COP, true, "Missing frozen string literal comment.");
                    self.insert_fsl_fix(first_code_line);
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
    fn insert_fsl_fix(&mut self, first_code_line: Option<usize>) {
        let comments = self.comments;
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

    /// Style/EvenOdd — `x % 2 == 0` → `x.even?` etc. rubocop's matcher
    /// verbatim; which predicate depends on the operator and the compared int.
    pub(crate) fn check_even_odd(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/EvenOdd";
        if !self.on(COP) {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        let pat = matcher(&PAT,
            "(send {(send $_ :% (int 2)) (begin (send $_ :% (int 2)))} ${:== :!=} (int ${0 1}))");
        let Some(caps) = nodepattern::matches(pat, &node.as_node(), self.src) else { return };
        // caps: [base, operator, compared-int]
        let method = match (caps[2].as_str(), caps[1].as_str()) {
            ("0", "==") | ("1", "!=") => "even",
            ("0", "!=") | ("1", "==") => "odd",
            _ => return,
        };
        let l = node.location();
        self.push(l.start_offset(), COP, true, format!("Replace with `Integer#{method}?`."));
        self.fixes.push((l.start_offset(), l.end_offset(), format!("{}.{method}?", caps[0]).into_bytes()));
    }

    /// Style/Dir — `File.expand_path(File.dirname(__FILE__))` and
    /// `File.dirname(File.realpath(__FILE__))` → `__dir__`.
    pub(crate) fn check_dir(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/Dir";
        if !self.on(COP) {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        let pat = matcher(&PAT,
            "{(send (const {nil? cbase} :File) :expand_path (send (const {nil? cbase} :File) :dirname $_)) \
              (send (const {nil? cbase} :File) :dirname (send (const {nil? cbase} :File) :realpath $_))}");
        let Some(caps) = nodepattern::matches(pat, &node.as_node(), self.src) else { return };
        // rubocop's #file_keyword?: the inner argument must be literally __FILE__
        if caps[0] != "__FILE__" {
            return;
        }
        let l = node.location();
        self.push(l.start_offset(), COP, true,
            "Use `__dir__` to get an absolute path to the current file's directory.");
        self.fixes.push((l.start_offset(), l.end_offset(), b"__dir__".to_vec()));
    }

    /// Style/StringChars — `split('')` / `split("")` / `split(//)` → `chars`.
    pub(crate) fn check_string_chars(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/StringChars";
        if !self.on(COP) || node.name().as_slice() != b"split" {
            return;
        }
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.len() != 1 || !matches!(self.node_src(&args[0]), b"//" | b"''" | b"\"\"") {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        let (start, end) = (sel.start_offset(), node.location().end_offset());
        let cur = String::from_utf8_lossy(&self.src[start..end]).into_owned();
        self.push(start, COP, true, format!("Use `chars` instead of `{cur}`."));
        self.fixes.push((start, end, b"chars".to_vec()));
    }

    /// Style/NestedFileDirname — `File.dirname(File.dirname(path))` →
    /// `File.dirname(path, 2)`. Fires on the OUTERMOST of a dirname chain
    /// (rubocop guards on `node.parent`; we mark the inner calls instead).
    pub(crate) fn check_nested_file_dirname(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/NestedFileDirname";
        // rubocop: minimum_target_ruby_version 3.1
        if !self.on(COP) || self.cfg.target_ruby() < 3.1 {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        let pat = matcher(&PAT, "(send (const {cbase nil?} :File) :dirname ...)");
        let l = node.location();
        if self.dirname_ignore.contains(&l.start_offset()) {
            return;
        }
        let is_dirname = |n: &ruby_prism::Node| nodepattern::matches(pat, n, self.src).is_some();
        if !is_dirname(&node.as_node()) {
            return;
        }
        let Some(arg) = first_call_arg(node) else { return };
        if !is_dirname(&arg) {
            return;
        }
        // walk the chain, claiming inner dirname calls and counting levels
        let mut level = 1;
        let mut cur = arg;
        loop {
            self.dirname_ignore.push(cur.location().start_offset());
            level += 1;
            let inner = cur.as_call_node().and_then(|c| first_call_arg(&c));
            match inner {
                Some(i) if is_dirname(&i) => cur = i,
                Some(i) => {
                    let path = String::from_utf8_lossy(self.node_src(&i)).into_owned();
                    let Some(sel) = node.message_loc() else { return };
                    let (start, end) = (sel.start_offset(), l.end_offset());
                    self.push(start, COP, true, format!("Use `dirname({path}, {level})` instead."));
                    self.fixes.push((start, end, format!("dirname({path}, {level})").into_bytes()));
                    return;
                }
                None => return,
            }
        }
    }

    /// Style/UnpackFirst — `x.unpack(fmt).first` / `[0]` / `.slice(0)` /
    /// `.at(0)` → `unpack1(fmt)`. Offense spans the unpack selector to the
    /// node end so the message quotes the real dispatch.
    pub(crate) fn check_unpack_first(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/UnpackFirst";
        if !self.on(COP) {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        let pat = matcher(&PAT,
            "{(call (call (...) :unpack (...)) :first) \
              (call (call (...) :unpack (...)) {:[] :slice :at} (int 0))}");
        if nodepattern::matches(pat, &node.as_node(), self.src).is_none() {
            return;
        }
        let Some(unpack) = node.receiver().and_then(|r| r.as_call_node()) else { return };
        let Some(sel) = unpack.message_loc() else { return };
        let Some(arg) = first_call_arg(&unpack) else { return };
        let (start, end) = (sel.start_offset(), node.location().end_offset());
        let current = String::from_utf8_lossy(&self.src[start..end]).into_owned();
        let fmt = String::from_utf8_lossy(self.node_src(&arg)).into_owned();
        self.push(start, COP, true, format!("Use `unpack1({fmt})` instead of `{current}`."));
        self.fixes.push((start, end, format!("unpack1({fmt})").into_bytes()));
    }

    /// Style/RandomWithOffset — `rand(6) + 1`, `1 + rand(6)`, `rand(6).succ`
    /// and friends should be ranges. rubocop's three matchers verbatim.
    pub(crate) fn check_random_with_offset(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/RandomWithOffset";
        if !self.on(COP)
            || !matches!(node.name().as_slice(), b"+" | b"-" | b"succ" | b"pred" | b"next")
            || node.receiver().is_none()
        {
            return;
        }
        static INT_OP_RAND: OnceLock<Pat> = OnceLock::new();
        static RAND_OP_INT: OnceLock<Pat> = OnceLock::new();
        static RAND_MODIFIED: OnceLock<Pat> = OnceLock::new();
        const RAND: &str =
            "(send {nil? (const {nil? cbase} :Random) (const {nil? cbase} :Kernel)} :rand {int (range int int)})";
        let n = node.as_node();
        let hit = nodepattern::matches(matcher(&INT_OP_RAND, &format!("(send int {{:+ :-}} {RAND})")), &n, self.src)
            .or_else(|| nodepattern::matches(matcher(&RAND_OP_INT, &format!("(send {RAND} {{:+ :-}} int)")), &n, self.src))
            .or_else(|| nodepattern::matches(matcher(&RAND_MODIFIED, &format!("(send {RAND} {{:succ :pred :next}})")), &n, self.src));
        if hit.is_some() {
            self.push(node.location().start_offset(), COP, true,
                "Prefer ranges when generating random numbers instead of integers with offsets.");
        }
    }

    /// Style/NegatedIf — `if !x` → `unless x` (rubocop's NegativeConditional:
    /// a single `!` on the condition, no else branch, style-gated on the
    /// modifier form).
    pub(crate) fn check_negated_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/NegatedIf";
        if !self.on(COP) {
            return;
        }
        let Some(kw) = node.if_keyword_loc() else { return }; // ternary
        if kw.as_slice() != b"if" || node.subsequent().is_some() {
            return; // elsif, or an else/elsif branch exists
        }
        let modifier = node.end_keyword_loc().is_none();
        match self.cfg.enforced_style(COP) {
            "prefix" if modifier => return,
            "postfix" if !modifier => return,
            _ => {}
        }
        // unwrap parens (taking the last statement), bail on empty `()`
        let mut cond = node.predicate();
        while let Some(p) = cond.as_parentheses_node() {
            let Some(last) = p.body().and_then(|b| b.as_statements_node()).and_then(|s| s.body().iter().last())
            else {
                return;
            };
            cond = last;
        }
        // single_negative?: `(send !(send _ :!) :!)`
        let Some(call) = cond.as_call_node() else { return };
        if call.name().as_slice() != b"!" {
            return;
        }
        let Some(recv) = call.receiver() else { return };
        if recv.as_call_node().is_some_and(|c| c.name().as_slice() == b"!") {
            return; // double negation is Style/DoubleNegation's business
        }
        let l = node.location();
        self.push(l.start_offset(), COP, true, "Favor `unless` over `if` for negative conditions.");
        // fix: swap the keyword and drop the `!`
        self.fixes.push((kw.start_offset(), kw.end_offset(), b"unless".to_vec()));
        self.fixes.push((call.location().start_offset(), recv.location().start_offset(), Vec::new()));
    }

    /// Lint/BooleanSymbol — `:true` / `:false` literals (outside `%i[]`).
    pub(crate) fn check_boolean_symbol(&mut self, node: &ruby_prism::SymbolNode) {
        const COP: &str = "Lint/BooleanSymbol";
        if !self.on(COP) {
            return;
        }
        let l = node.location();
        if self.percent_sym_spans.iter().any(|(s, e)| l.start_offset() >= *s && l.start_offset() < *e) {
            return;
        }
        let Some(v) = node.value_loc() else { return };
        let value = &self.src[v.start_offset()..v.end_offset()];
        if !matches!(value, b"true" | b"false") {
            return;
        }
        let value = String::from_utf8_lossy(value).into_owned();
        self.push(l.start_offset(), COP, true,
            format!("Symbol with a boolean name - you probably meant to use `{value}`."));
        // fix: `:true` -> `true` (the `key:` label form is left alone).
        if self.src[l.start_offset()] == b':' {
            self.fixes.push((l.start_offset(), l.end_offset(), value.into_bytes()));
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
        // `x&.meth` is NOT a symbol-proc candidate — `&:meth` raises on nil
        // where safe navigation returns it (rubocop's pattern requires `send`).
        if call.is_safe_navigation() {
            return None;
        }
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

// ---- Style/Documentation helpers ----
/// rubocop's `namespace?`: every statement in the body is a constant
/// declaration — a class/module definition, a constant assignment, or a
/// `public_constant`/`private_constant` visibility call.
fn is_namespace(body: &ruby_prism::Node) -> bool {
    let Some(stmts) = body.as_statements_node() else {
        return is_constant_declaration(body);
    };
    stmts.body().iter().all(|n| is_constant_declaration(&n))
}
fn is_constant_declaration(n: &ruby_prism::Node) -> bool {
    if n.as_class_node().is_some()
        || n.as_module_node().is_some()
        || n.as_constant_write_node().is_some()
        || n.as_constant_path_write_node().is_some()
    {
        return true;
    }
    n.as_call_node().is_some_and(|c| {
        c.receiver().is_none()
            && matches!(c.name().as_slice(), b"public_constant" | b"private_constant")
            && c.arguments().is_some_and(|a| {
                let args: Vec<_> = a.arguments().iter().collect();
                args.len() == 1 && (args[0].as_symbol_node().is_some() || args[0].as_string_node().is_some())
            })
    })
}
/// rubocop's `include_statement_only?`: the body is nothing but bare
/// `include`/`extend`/`prepend Const` statements.
fn include_statements_only(body: &ruby_prism::Node) -> bool {
    if let Some(stmts) = body.as_statements_node() {
        return stmts.body().iter().all(|n| include_statements_only(&n));
    }
    body.as_call_node().is_some_and(|c| {
        c.receiver().is_none()
            && matches!(c.name().as_slice(), b"include" | b"extend" | b"prepend")
            && c.arguments().is_some_and(|a| {
                let args: Vec<_> = a.arguments().iter().collect();
                args.len() == 1
                    && (args[0].as_constant_read_node().is_some() || args[0].as_constant_path_node().is_some())
            })
    })
}

/// The first positional argument of a call.
fn first_call_arg<'pr>(c: &ruby_prism::CallNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    c.arguments().and_then(|a| a.arguments().iter().next())
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
