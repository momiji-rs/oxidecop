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
        if !self.hot.string_literals || self.interp_depth > 0 {
            return;
        }
        let l = node.location();
        if self.str_ignore.iter().any(|(s, e)| l.start_offset() >= *s && l.start_offset() < *e) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let src = self.node_src(&node.as_node());
        // The parser gem turns a MULTILINE plain string into a dstr, which
        // on_str never sees (and on_dstr ignores unless
        // ConsistentQuotesInMultiline) — prism keeps it one node, so match
        // that routing here.
        if !self.hot.consistent_quotes && src.contains(&b'\n') {
            return;
        }
        let c = node.content_loc().as_slice();
        match self.hot.string_style {
            1 if open.as_slice() == b"\"" => {
                if !double_quotes_required(src) {
                    self.push(l.start_offset(), "Style/StringLiterals", true, MSG_SINGLE);
                    if c.contains(&b'\n') {
                        return; // whitequark sees multi-line literals as dstr: no fix
                    }
                    // rubocop's to_string_literal on the RUNTIME string:
                    // unescape (only \\ and \" can occur here), then
                    // backslashes double and `\"` collapses to `"`.
                    let mut runtime = Vec::new();
                    let mut i = 0;
                    while i < c.len() {
                        if c[i] == b'\\' && matches!(c.get(i + 1), Some(b'"') | Some(b'\\')) {
                            runtime.push(c[i + 1]);
                            i += 2;
                        } else {
                            runtime.push(c[i]);
                            i += 1;
                        }
                    }
                    let mut esc = Vec::new();
                    for b in &runtime {
                        if *b == b'\\' {
                            esc.extend_from_slice(b"\\\\");
                        } else {
                            esc.push(*b);
                        }
                    }
                    // gsub('\"', '"') — literal backslash-quote collapses
                    let mut rep = vec![b'\''];
                    let mut i = 0;
                    while i < esc.len() {
                        if esc[i] == b'\\' && esc.get(i + 1) == Some(&b'"') {
                            rep.push(b'"');
                            i += 2;
                        } else {
                            rep.push(esc[i]);
                            i += 1;
                        }
                    }
                    rep.push(b'\'');
                    self.fixes.push((l.start_offset(), l.end_offset(), rep));
                }
            }
            2 if open.as_slice() == b"'" => {
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
        if !self.hot.string_literals || !self.hot.consistent_quotes {
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
        let style = self.hot.string_style;
        let l = node.location();
        let mut quotes: Vec<&[u8]> = openings.iter().map(|o| o.as_deref().unwrap()).filter(|q| !q.is_empty()).collect();
        quotes.dedup();
        quotes.sort();
        quotes.dedup();
        let offense = if quotes.len() > 1 {
            Some("Inconsistent quote style.".to_string())
        } else if quotes == [b"'" as &[u8]] && style == 2 {
            // All parts must be wrong for the node to be an offense.
            parts
                .iter()
                .all(|p| !single_quotes_required(self.node_src(p)))
                .then(|| MSG_DOUBLE.to_string())
        } else if quotes == [b"\"" as &[u8]] && style == 1 {
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
        if !self.hot.numeric_literals {
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
        if int_part.len() < self.hot.min_digits {
            return;
        }
        let ungrouped = int_part.bytes().all(|b| b.is_ascii_digit());
        let four_run = int_part.as_bytes().windows(4).any(|w| w.iter().all(|b| b.is_ascii_digit()));
        let strict = self.hot.numeric_strict;
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
        // fix (rubocop's format_number): whitespace stripped (a folded
        // `-\n 123` join), regroup the integer part, keep the suffix.
        let int_clean: String = int_part.chars().filter(|c| !c.is_whitespace()).collect();
        let int_part = int_clean.as_str();
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
            let rest: String = unsigned
                .chars()
                .filter(|c| !c.is_whitespace())
                .skip(int_part.len())
                .collect();
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
        let ident = parts.join("::"); // `class ::X` nested yields `Parent::::X` — so does rubocop
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
            .is_some_and(|(_, off, end)| re.is_match(&String::from_utf8_lossy(&self.src[*off..*end])))
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
            if let Some((_, off, end)) = self.comments.iter().find(|(l, _, _)| *l == line) {
                // A trailing comment (code before it) is not a doc line and
                // ends the block (`module A # The A Module` documents nothing).
                if !self.src[self.idx.starts[line - 1]..*off].iter().all(|b| b.is_ascii_whitespace()) {
                    break;
                }
                let t = String::from_utf8_lossy(&self.src[*off..*end]);
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
            .map(|(l, off, end)| {
                (*l, *off, fsl_value(&String::from_utf8_lossy(&self.src[*off..*end])))
            })
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
    pub(crate) fn line_end(&self, line: usize) -> usize {
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
        if let Some((l, off, end)) = comments.first() {
            if is_leading(*l) && self.src[*off..*end].starts_with(b"#!") {
                special = Some(*l);
                next = 1;
            }
        }
        if let Some((l, off, end)) = comments.get(next) {
            if is_leading(*l) && encoding_re().is_match(&String::from_utf8_lossy(&self.src[*off..*end])) {
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

    /// Replace the whole line containing `off` with `rep` — except an emacs
    /// magic comment, whose VALUE token is rewritten in place.
    fn replace_line_fix(&mut self, off: usize, rep: &[u8]) {
        let line = self.idx.loc(off).0;
        let (ls, le) = (self.idx.starts[line - 1], self.line_end(line));
        let text = String::from_utf8_lossy(&self.src[ls..le]).into_owned();
        if text.contains("-*-") {
            static VAL: OnceLock<regex::Regex> = OnceLock::new();
            let re = VAL.get_or_init(|| {
                regex::Regex::new(r"(?i)(frozen[_-]string[_-]literal\s*:\s*)[[:alnum:]_-]+").unwrap()
            });
            if let Some(m) = re.captures(&text) {
                let g = m.get(0).unwrap();
                let pre = m.get(1).unwrap().as_str().len();
                self.fixes.push((ls + g.start() + pre, ls + g.end(), b"true".to_vec()));
                return;
            }
        }
        self.fixes.push((ls, le, rep.to_vec()));
    }

    /// Style/RedundantReturn — a `return` in tail position of a def (or a
    /// `define_method`/`lambda` block). rubocop's `check_branch` walks tail
    /// positions recursively: the last statement, both arms of a non-ternary
    /// if/unless, every case/when + else, rescue clauses (+ else, or the body
    /// when no else), and through begin groupings.
    pub(crate) fn check_redundant_return(&mut self, node: &ruby_prism::DefNode) {
        if !self.hot.redundant_return {
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
            // drop the keyword (+ trailing space); bracket multiple values;
            // a single splat loses its `*`
            let mut kw_end = kw.end_offset();
            while kw_end < self.src.len() && matches!(self.src[kw_end], b' ' | b'\t') {
                kw_end += 1;
            }
            self.fixes.push((kw.start_offset(), kw_end, Vec::new()));
            if !multi {
                if let Some(sp) = args[0].as_splat_node() {
                    let s0 = sp.location().start_offset();
                    self.fixes.push((s0, s0 + 1, Vec::new()));
                } else if args[0].as_keyword_hash_node().is_some() {
                    let al = args[0].location();
                    self.fixes.push((al.start_offset(), al.start_offset(), b"{".to_vec()));
                    self.fixes.push((al.end_offset(), al.end_offset(), b"}".to_vec()));
                }
            }
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
        if !self.hot.zero_length {
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
        if !self.hot.even_odd {
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
        if !self.hot.dir {
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
        if !self.hot.string_chars || node.name().as_slice() != b"split" {
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
        // rubocop: minimum_target_ruby_version 3.1 (folded into the flag)
        if !self.hot.nested_file_dirname {
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
        let kind = if nodepattern::matches(matcher(&INT_OP_RAND, &format!("(send int {{:+ :-}} {RAND})")), &n, self.src).is_some() {
            1
        } else if nodepattern::matches(matcher(&RAND_OP_INT, &format!("(send {RAND} {{:+ :-}} int)")), &n, self.src).is_some() {
            2
        } else if nodepattern::matches(matcher(&RAND_MODIFIED, &format!("(send {RAND} {{:succ :pred :next}})")), &n, self.src).is_some() {
            3
        } else {
            return;
        };
        self.push(node.location().start_offset(), COP, true,
            "Prefer ranges when generating random numbers instead of integers with offsets.");
        self.random_with_offset_fix(node, kind);
    }

    /// The range rewrite: `rand(6) + 1` → `rand(1..6)` etc.
    fn random_with_offset_fix(&mut self, node: &ruby_prism::CallNode, kind: u8) {
        let int_of = |n: &ruby_prism::Node| -> Option<i64> {
            let l = n.location();
            std::str::from_utf8(&self.src[l.start_offset()..l.end_offset()])
                .ok()?
                .replace('_', "")
                .parse()
                .ok()
        };
        // locate the rand call (receiver side for kinds 2/3, argument for 1)
        let rand_call = match kind {
            1 => node.arguments().and_then(|a| a.arguments().iter().next()).and_then(|a| a.as_call_node()),
            _ => node.receiver().and_then(|r| r.as_call_node()),
        };
        let Some(rand_call) = rand_call else { return };
        let prefix = match rand_call.receiver() {
            Some(r) => format!("{}.rand", String::from_utf8_lossy(self.node_src(&r))),
            None => "rand".to_string(),
        };
        let Some(rand_arg) = rand_call.arguments().and_then(|a| a.arguments().iter().next()) else {
            return;
        };
        let (left, right) = if let Some(r) = rand_arg.as_range_node() {
            let (Some(b), Some(e)) = (r.left(), r.right()) else { return };
            let (Some(b), Some(e)) = (int_of(&b), int_of(&e)) else { return };
            if r.operator_loc().as_slice() == b"..." { (b, e - 1) } else { (b, e) }
        } else if let Some(v) = int_of(&rand_arg) {
            (0, v - 1)
        } else {
            return;
        };
        let plus = node.name().as_slice() == b"+";
        let rep = match kind {
            1 => {
                let Some(off) = node.receiver().and_then(|r| int_of(&r)) else { return };
                if plus {
                    format!("{prefix}({}..{})", off + left, off + right)
                } else {
                    format!("{prefix}({}..{})", off - right, off - left)
                }
            }
            2 => {
                let Some(off) =
                    node.arguments().and_then(|a| a.arguments().iter().next()).and_then(|a| int_of(&a))
                else {
                    return;
                };
                if plus {
                    format!("{prefix}({}..{})", left + off, right + off)
                } else {
                    format!("{prefix}({}..{})", left - off, right - off)
                }
            }
            _ => {
                if matches!(node.name().as_slice(), b"succ" | b"next") {
                    format!("{prefix}({}..{})", left + 1, right + 1)
                } else {
                    format!("{prefix}({}..{})", left - 1, right - 1)
                }
            }
        };
        let l = node.location();
        self.fixes.push((l.start_offset(), l.end_offset(), rep.into_bytes()));
    }

    /// Style/NegatedIf — `if !x` → `unless x` (rubocop's NegativeConditional:
    /// a single `!` on the condition, no else branch, style-gated on the
    /// modifier form).
    pub(crate) fn check_negated_if(&mut self, node: &ruby_prism::IfNode) {
        if !self.hot.negated_if {
            return;
        }
        const COP: &str = "Style/NegatedIf";
        let Some(kw) = node.if_keyword_loc() else { return }; // ternary
        if kw.as_slice() != b"if" || node.subsequent().is_some() {
            return; // elsif, or an else/elsif branch exists
        }
        let modifier = node.end_keyword_loc().is_none();
        match self.hot.negated_if_style {
            1 if modifier => return,
            2 if !modifier => return,
            _ => {}
        }
        let Some((bang_start, recv_start)) = single_negative(node.predicate()) else { return };
        let l = node.location();
        self.push(l.start_offset(), COP, true, "Favor `unless` over `if` for negative conditions.");
        // fix: swap the keyword and drop the `!`
        self.fixes.push((kw.start_offset(), kw.end_offset(), b"unless".to_vec()));
        self.fixes.push((bang_start, recv_start, Vec::new()));
    }

    /// Style/NegatedWhile — `while !x` → `until x` and vice versa (shares
    /// rubocop's NegativeConditional with NegatedIf, minus the style gate).
    pub(crate) fn check_negated_while(&mut self, predicate: ruby_prism::Node, node_start: usize, kw: ruby_prism::Location, until: bool) {
        const COP: &str = "Style/NegatedWhile";
        if !self.on(COP) {
            return;
        }
        let Some((bang_start, recv_start)) = single_negative(predicate) else { return };
        let (inverse, current) = if until { ("while", "until") } else { ("until", "while") };
        self.push(node_start, COP, true,
            format!("Favor `{inverse}` over `{current}` for negative conditions."));
        self.fixes.push((kw.start_offset(), kw.end_offset(), inverse.as_bytes().to_vec()));
        self.fixes.push((bang_start, recv_start, Vec::new()));
    }

    /// Style/CharacterLiteral — `?a` → `'a'` (interpolations included).
    pub(crate) fn check_character_literal(&mut self, node: &ruby_prism::StringNode) {
        const COP: &str = "Style/CharacterLiteral";
        if !self.on(COP) {
            return;
        }
        if node.opening_loc().is_none_or(|o| o.as_slice() != b"?") {
            return;
        }
        let l = node.location();
        let src = self.node_src(&node.as_node());
        if !(2..=3).contains(&src.len()) {
            return;
        }
        self.push(l.start_offset(), COP, true,
            "Do not use the character literal - use string literal instead.");
        let inner = &src[1..];
        let rep = if inner.len() == 2 || inner == b"'" {
            let mut r = vec![b'"'];
            r.extend_from_slice(inner);
            r.push(b'"');
            r
        } else {
            let mut r = vec![b'\''];
            r.extend_from_slice(inner);
            r.push(b'\'');
            r
        };
        self.fixes.push((l.start_offset(), l.end_offset(), rep));
    }

    /// Style/UnlessElse — `unless ... else ... end`.
    pub(crate) fn check_unless_else(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/UnlessElse";
        if !self.on(COP) {
            return;
        }
        let Some(else_clause) = node.else_clause() else { return };
        let nl = node.location();
        let nested = self
            .unless_else_spans
            .iter()
            .any(|(s, e)| nl.start_offset() >= *s && nl.start_offset() < *e);
        self.push(nl.start_offset(), COP, !nested,
            "Do not use `unless` with `else`. Rewrite these with the positive case first.");
        if nested {
            return; // rubocop's ignore_node: only the outermost gets corrected
        }
        self.unless_else_spans.push((nl.start_offset(), nl.end_offset()));
        // swap keyword to `if` and exchange the two bodies
        let kw = node.keyword_loc();
        self.fixes.push((kw.start_offset(), kw.end_offset(), b"if".to_vec()));
        let cond_end = node
            .then_keyword_loc()
            .map(|t| t.end_offset())
            .unwrap_or_else(|| node.predicate().location().end_offset());
        let else_kw = else_clause.else_keyword_loc();
        let Some(end_kw) = node.end_keyword_loc() else { return };
        let body_range = (cond_end, else_kw.start_offset());
        let else_range = (else_kw.end_offset(), end_kw.start_offset());
        let body_text = self.src[body_range.0..body_range.1].to_vec();
        let else_text = self.src[else_range.0..else_range.1].to_vec();
        self.fixes.push((body_range.0, body_range.1, else_text));
        self.fixes.push((else_range.0, else_range.1, body_text));
    }

    /// Style/StderrPuts — `$stderr.puts x` → `warn x`.
    pub(crate) fn check_stderr_puts(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/StderrPuts";
        if !self.on(COP) || node.name().as_slice() != b"puts" || node.arguments().is_none() {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let recv_src = self.node_src(&recv);
        let is_stderr = (recv.as_global_variable_read_node().is_some() && recv_src == b"$stderr")
            || (matches!(recv_src, b"STDERR" | b"::STDERR")
                && (recv.as_constant_read_node().is_some() || recv.as_constant_path_node().is_some()));
        if !is_stderr {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        let (start, end) = (node.location().start_offset(), sel.end_offset());
        let bad = format!("{}.puts", String::from_utf8_lossy(recv_src));
        self.push(start, COP, true,
            format!("Use `warn` instead of `{bad}` to allow such output to be disabled."));
        self.fixes.push((start, end, b"warn".to_vec()));
    }

    /// Style/WhileUntilDo — no `do` on a multi-line while/until.
    pub(crate) fn check_while_until_do(
        &mut self,
        predicate: &ruby_prism::Node,
        do_kw: Option<ruby_prism::Location>,
        node_loc: ruby_prism::Location,
        body_start: Option<usize>,
        keyword: &str,
    ) {
        const COP: &str = "Style/WhileUntilDo";
        if !self.on(COP) {
            return;
        }
        let Some(do_kw) = do_kw else { return };
        let (start_line, _) = self.idx.loc(node_loc.start_offset());
        let (end_line, _) = self.idx.loc(node_loc.end_offset().saturating_sub(1));
        if start_line == end_line {
            return;
        }
        let do_line = self.idx.loc(do_kw.start_offset()).0;
        if body_start.is_some_and(|b| self.idx.loc(b).0 == do_line) {
            return;
        }
        self.push(do_kw.start_offset(), COP, true,
            format!("Do not use `do` with multi-line `{keyword}`."));
        self.fixes.push((predicate.location().end_offset(), do_kw.end_offset(), Vec::new()));
    }

    /// Style/MultilineIfThen — no `then` on a multi-line if/unless.
    pub(crate) fn check_multiline_if_then(
        &mut self,
        then_kw: Option<ruby_prism::Location>,
        end_kw: Option<ruby_prism::Location>,
        body_start: Option<usize>,
        keyword: &str,
    ) {
        const COP: &str = "Style/MultilineIfThen";
        if !self.on(COP) {
            return;
        }
        if end_kw.is_none() {
            return; // modifier / ternary forms keep their shape
        }
        let Some(then_kw) = then_kw else { return };
        if then_kw.as_slice() != b"then" {
            return;
        }
        let then_line = self.idx.loc(then_kw.start_offset()).0;
        if body_start.is_some_and(|b| self.idx.loc(b).0 == then_line) {
            return;
        }
        self.push(then_kw.start_offset(), COP, true,
            format!("Do not use `then` for multi-line `{keyword}`."));
        // remove `then` plus surrounding space to the left (newlines too)
        let mut s = then_kw.start_offset();
        while s > 0 && matches!(self.src[s - 1], b' ' | b'\t' | b'\n' | b'\r') {
            s -= 1;
        }
        self.fixes.push((s, then_kw.end_offset(), Vec::new()));
    }

    /// Style/Not — `not x` → `!x` (or the opposite comparison operator).
    pub(crate) fn check_not(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/Not";
        if !self.on(COP) || node.name().as_slice() != b"!" {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        if sel.as_slice() != b"not" {
            return;
        }
        self.push(sel.start_offset(), COP, true, "Use `!` instead of `not`.");
        // `not` plus the space(s) after it
        let mut sel_end = sel.end_offset();
        while sel_end < self.src.len() && self.src[sel_end] == b' ' {
            sel_end += 1;
        }
        let Some(recv) = node.receiver() else { return };
        if let Some(c) = recv.as_call_node() {
            let opposite: Option<&[u8]> = match c.name().as_slice() {
                b"==" => Some(b"!="),
                b"!=" => Some(b"=="),
                b"<=" => Some(b">"),
                b">" => Some(b"<="),
                b"<" => Some(b">="),
                b">=" => Some(b"<"),
                _ => None,
            };
            if let (Some(op), Some(csel)) = (opposite, c.message_loc()) {
                self.fixes.push((sel.start_offset(), sel_end, Vec::new()));
                self.fixes.push((csel.start_offset(), csel.end_offset(), op.to_vec()));
                return;
            }
        }
        // and/or/ternary/binary sends need parens
        let needs_parens = recv.as_and_node().is_some()
            || recv.as_or_node().is_some()
            || recv.as_if_node().is_some_and(|i| i.if_keyword_loc().is_none())
            || recv.as_call_node().is_some_and(|c| {
                c.receiver().is_some()
                    && c.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0) == 1
                    && !c.name().as_slice().first().is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            });
        if needs_parens {
            self.fixes.push((sel.start_offset(), sel_end, b"!(".to_vec()));
            let e = node.location().end_offset();
            self.fixes.push((e, e, b")".to_vec()));
        } else {
            self.fixes.push((sel.start_offset(), sel_end, b"!".to_vec()));
        }
    }

    /// Lint/BooleanSymbol — `:true` / `:false` literals (outside `%i[]`).
    pub(crate) fn check_boolean_symbol(&mut self, node: &ruby_prism::SymbolNode) {
        const COP: &str = "Lint/BooleanSymbol";
        if !self.hot.boolean_symbol {
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
        if self.src[l.start_offset()] == b':' {
            // `:true` -> `true`
            self.fixes.push((l.start_offset(), l.end_offset(), value.into_bytes()));
        } else if node.closing_loc().is_some_and(|c| c.as_slice() == b":") {
            // hash-shorthand key `true:` -> `true =>`
            self.fixes.push((l.start_offset(), l.end_offset(), format!("{value} =>").into_bytes()));
        }
    }

    /// Style/SymbolLiteral — `:"foo"` where the quoted content is itself a
    /// plain word-like symbol (rubocop's `/\A:["'][A-Za-z_]\w*["']\z/`) → `:foo`.
    pub(crate) fn check_symbol_literal(&mut self, node: &ruby_prism::SymbolNode) {
        const COP: &str = "Style/SymbolLiteral";
        if !self.on(COP) {
            return;
        }
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re = re(&RE, r#"\A:["'][A-Za-z_]\w*["']\z"#);
        let l = node.location();
        let src = &self.src[l.start_offset()..l.end_offset()];
        let Ok(text) = std::str::from_utf8(src) else { return };
        if !re.is_match(text) {
            return;
        }
        self.push(l.start_offset(), COP, true, "Do not use strings for word-like symbol literals.");
        let replacement: Vec<u8> = src.iter().copied().filter(|&b| b != b'\'' && b != b'"').collect();
        self.fixes.push((l.start_offset(), l.end_offset(), replacement));
    }

    /// Style/NumericPredicate: under `predicate` style flag `x {==,>,<} 0` (and
    /// inverted) → suggest `x.zero?/positive?/negative?`; under `comparison`
    /// style flag those predicates → suggest the comparison. Returns the offense
    /// (whole-node offset, rendered message) or None. Verbatim rubocop logic.
    pub(crate) fn numeric_predicate(&self, node: &ruby_prism::CallNode) -> Option<(usize, String)> {
        if !self.hot.numeric_predicate {
            return None;
        }
        let name = node.name().as_slice();
        // AllowedMethods/Patterns: the offending method OR any ancestor call/block.
        if self.allowed("Style/NumericPredicate", name)
            || self
                .call_stack
                .iter()
                .any(|sp| self.allowed("Style/NumericPredicate", &self.src[sp.0..sp.1]))
        {
            return None;
        }
        let recv = node.receiver();
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        let node_off = node.location().start_offset();
        let current = String::from_utf8_lossy(self.node_src(&node.as_node())).into_owned();

        let prefer = match self.hot.numeric_pred_comparison {
            true => {
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
                let negated = self.call_stack.last().is_some_and(|sp| &self.src[sp.0..sp.1] == b"!");
                if negated {
                    format!("({rsrc} {op} 0)")
                } else {
                    format!("{rsrc} {op} 0")
                }
            }
            false => {
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
        if !self.hot.symbol_proc {
            return None;
        }
        let block = node.block()?.as_block_node()?;
        let method = self.proc_shape(block.parameters(), block.body())?;
        let block_method = node.name();
        let bm = block_method.as_slice();
        // ActiveSupport gating: `proc`/`lambda`/`Proc.new` blocks are only
        // candidates when ActiveSupportExtensionsEnabled is off (the default).
        if self.hot.active_support {
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
        if self.hot.symbol_proc_allow_args && node.arguments().is_some() {
            return None;
        }
        if self.hot.symbol_proc_allow_comments
            && self.block_has_inner_comment(block.opening_loc().start_offset(), block.closing_loc().start_offset())
        {
            return None;
        }
        Some((
            block.opening_loc().start_offset(),
            format!("Pass `&:{method}` as an argument to `{}` instead of a block.", String::from_utf8_lossy(bm)),
        ))
    }

    /// Autocorrect for the method-call SymbolProc form: drop the block, pass
    /// `&:method` (appending to existing parenthesized args when present).
    pub(crate) fn symbol_proc_fix(&mut self, node: &ruby_prism::CallNode, msg: &str) {
        let Some(method) = msg.strip_prefix("Pass `&:").and_then(|m| m.split('`').next()) else {
            return;
        };
        let Some(block) = node.block() else { return };
        let bl = block.location();
        let node_end = node.location().end_offset();
        if let Some(cl) = node.closing_loc() {
            match node.arguments().and_then(|a| a.arguments().iter().last()) {
                Some(last) => {
                    // insert after the last arg (reusing its trailing comma)
                    let mut at = last.location().end_offset();
                    let rep = if self.src.get(at) == Some(&b',') {
                        at += 1;
                        format!(" &:{method}")
                    } else {
                        format!(", &:{method}")
                    };
                    self.fixes.push((at, at, rep.into_bytes()));
                }
                None => {
                    // `m(   )` -> `m(&:x)`: rewrite the whole paren group
                    let (os, oe) = (
                        node.opening_loc().map(|o| o.start_offset()).unwrap_or(cl.start_offset()),
                        cl.end_offset(),
                    );
                    self.fixes.push((os, oe, format!("(&:{method})").into_bytes()));
                }
            }
            // remove the block plus the space before it
            let mut bs = bl.start_offset();
            while bs > 0 && self.src[bs - 1] == b' ' {
                bs -= 1;
            }
            self.fixes.push((bs, node_end.max(bl.end_offset()), Vec::new()));
        } else {
            // no parens: replace ` { block }` with `(&:x)`
            let mut bs = bl.start_offset();
            while bs > 0 && self.src[bs - 1] == b' ' {
                bs -= 1;
            }
            self.fixes.push((bs, bl.end_offset(), format!("(&:{method})").into_bytes()));
        }
    }

    /// Style/SymbolProc for a `super { |x| x.meth }` / `super(...) { … }` block →
    /// `super(&:meth)`. `super` is always a candidate (no ActiveSupport gating).
    pub(crate) fn symbol_proc_super(
        &mut self,
        block: &ruby_prism::Node,
        has_args: bool,
        last_arg_end: Option<usize>,
    ) -> Option<(usize, String)> {
        if !self.hot.symbol_proc {
            return None;
        }
        let block = block.as_block_node()?;
        let method = self.proc_shape(block.parameters(), block.body())?;
        if self.allowed("Style/SymbolProc", b"super") {
            return None;
        }
        // AllowMethodsWithArguments: skip when enabled and `super` has arguments.
        if self.hot.symbol_proc_allow_args && has_args {
            return None;
        }
        if self.hot.symbol_proc_allow_comments
            && self.block_has_inner_comment(block.opening_loc().start_offset(), block.closing_loc().start_offset())
        {
            return None;
        }
        // fix: `super { |x| x.m }` -> `super(&:m)`;
        // with args, `&:m` joins the existing paren list
        let mut bs = block.opening_loc().start_offset();
        while bs > 0 && self.src[bs - 1] == b' ' {
            bs -= 1;
        }
        match last_arg_end {
            Some(at) => {
                self.fixes.push((at, at, format!(", &:{method}").into_bytes()));
                self.fixes.push((bs, block.closing_loc().end_offset(), Vec::new()));
            }
            None => {
                self.fixes.push((bs, block.closing_loc().end_offset(), format!("(&:{method})").into_bytes()));
            }
        }
        Some((
            block.opening_loc().start_offset(),
            format!("Pass `&:{method}` as an argument to `super` instead of a block."),
        ))
    }

    /// Style/SymbolProc for an arrow lambda literal `->(x) { x.meth }` →
    /// `lambda(&:meth)`. Only a candidate when ActiveSupport extensions are off.
    pub(crate) fn symbol_proc_lambda(&mut self, node: &ruby_prism::LambdaNode) -> Option<(usize, String)> {
        if !self.hot.symbol_proc || self.hot.active_support {
            return None;
        }
        let method = self.proc_shape(node.parameters(), node.body())?;
        if self.allowed("Style/SymbolProc", b"lambda") {
            return None;
        }
        if self.hot.symbol_proc_allow_comments
            && self.block_has_inner_comment(node.opening_loc().start_offset(), node.closing_loc().start_offset())
        {
            return None;
        }
        // fix: `->(x) { x.m }` -> `lambda(&:m)`
        let l = node.location();
        self.fixes.push((l.start_offset(), l.end_offset(), format!("lambda(&:{method})").into_bytes()));
        Some((
            node.opening_loc().start_offset(),
            format!("Pass `&:{method}` as an argument to `lambda` instead of a block."),
        ))
    }
}

/// rubocop's `single_negative?` on a condition: unwrap parens (taking the
/// last statement; empty `()` bails), then require a single non-double `!`
/// call. Returns (bang start, receiver start) for the autocorrect.
fn single_negative(mut cond: ruby_prism::Node) -> Option<(usize, usize)> {
    while let Some(p) = cond.as_parentheses_node() {
        cond = p.body().and_then(|b| b.as_statements_node()).and_then(|s| s.body().iter().last())?;
    }
    let call = cond.as_call_node()?;
    if call.name().as_slice() != b"!" {
        return None;
    }
    let recv = call.receiver()?;
    if recv.as_call_node().is_some_and(|c| c.name().as_slice() == b"!") {
        return None; // double negation is Style/DoubleNegation's business
    }
    Some((call.location().start_offset(), recv.location().start_offset()))
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
pub(crate) fn fsl_value(line: &str) -> Option<String> {
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

impl<'a> super::Cops<'a> {
    /// Style/ColonMethodCall — `Foo::bar` method calls (camel-case "methods"
    /// and the JRuby `Java::` interop tree are fine).
    pub(crate) fn check_colon_method_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/ColonMethodCall";
        if !self.on(COP) {
            return;
        }
        let Some(dot) = node.call_operator_loc() else { return };
        if dot.as_slice() != b"::" || node.receiver().is_none() {
            return;
        }
        // a "camel-case method" (Array::Integer(...)-style casts) is allowed
        if node.name().as_slice().first().is_some_and(u8::is_ascii_uppercase) {
            return;
        }
        // walk the receiver chain to its root; a bare `Java` root is interop
        let mut root = node.receiver().unwrap();
        while let Some(c) = root.as_call_node() {
            match c.receiver() {
                Some(r) => root = r,
                None => break,
            }
        }
        if root.as_constant_read_node().is_some_and(|c| c.name().as_slice() == b"Java") {
            return;
        }
        self.fixes.push((dot.start_offset(), dot.end_offset(), b".".to_vec()));
        self.push(dot.start_offset(), COP, true, "Do not use `::` for method calls.");
    }
}

impl<'a> super::Cops<'a> {
    /// Style/EmptyLiteral — `Array.new`/`Hash.new`/`String.new`/`Array[]`/
    /// `Hash[]`/`Array([])`/`Hash([])` → literal `[]`/`{}`/`''`.
    pub(crate) fn check_empty_literal(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/EmptyLiteral";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"new" | b"[]" | b"Array" | b"Hash") {
            return;
        }
        let recv_const = node.receiver().and_then(|r| empty_lit_const(&r));
        let argc = node.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0);
        let empty_array_arg = argc == 1
            && node.arguments().is_some_and(|a| {
                a.arguments()
                    .iter()
                    .next()
                    .and_then(|x| x.as_array_node().map(|arr| arr.elements().iter().count() == 0))
                    .unwrap_or(false)
            });
        let has_block = node.block().is_some();

        enum Kind { Array, Hash, Str }
        let kind = match (recv_const.as_deref(), name) {
            (Some("Array"), b"new") if (argc == 0 || empty_array_arg) && !has_block => Kind::Array,
            (Some("Array"), b"[]") if argc == 0 => Kind::Array,
            (None, b"Array") if empty_array_arg && node.receiver().is_none() => Kind::Array,
            (Some("Hash"), b"new") if argc == 0 && !has_block => Kind::Hash,
            (Some("Hash"), b"[]") if argc == 0 => Kind::Hash,
            (None, b"Hash") if empty_array_arg && node.receiver().is_none() => Kind::Hash,
            (Some("String"), b"new") if argc == 0 && !self.frozen_strings() => Kind::Str,
            _ => return,
        };
        let l = node.location();
        let current = String::from_utf8_lossy(&self.src[l.start_offset()..l.end_offset()]).into_owned();
        let (msg, lit) = match kind {
            Kind::Array => (format!("Use array literal `[]` instead of `{current}`."), "[]".to_string()),
            Kind::Hash => (format!("Use hash literal `{{}}` instead of `{current}`."), "{}".to_string()),
            Kind::Str => {
                let prefer = self.preferred_string_literal();
                (format!("Use string literal `{prefer}` instead of `String.new`."), prefer)
            }
        };
        // A Hash literal opening an unparenthesized argument list would parse
        // as a block — rewrite the whole list with parens (rubocop verbatim).
        if matches!(kind, Kind::Hash) {
            if let Some((first_start, spans)) = self.bare_arg_frames.last() {
                if *first_start == l.start_offset() {
                    let rest: Vec<String> = std::iter::once("{}".to_string())
                        .chain(spans.iter().skip(1).map(|(s, e)| {
                            String::from_utf8_lossy(&self.src[*s..*e]).into_owned()
                        }))
                        .collect();
                    let last_end = spans.last().map(|(_, e)| *e).unwrap_or(l.end_offset());
                    self.fixes.push((first_start - 1, last_end, format!("({})", rest.join(", ")).into_bytes()));
                    self.push(l.start_offset(), COP, true, msg);
                    return;
                }
            }
        }
        self.fixes.push((l.start_offset(), l.end_offset(), lit.into_bytes()));
        self.push(l.start_offset(), COP, true, msg);
    }

    /// Whether string literals are frozen here (FrozenStringLiteral mixin):
    /// the magic comment decides; absent one, an enabled FSC cop implies the
    /// project keeps files frozen — unless StringLiteralsFrozenByDefault is
    /// explicitly set either way.
    fn frozen_strings(&self) -> bool {
        match self.fsl_enabled {
            Some(v) => v,
            None => match self.cfg.param("AllCops", "StringLiteralsFrozenByDefault") {
                Some(v) => v == "true",
                None => self.on("Style/FrozenStringLiteralComment"),
            },
        }
    }

    fn preferred_string_literal(&self) -> String {
        if self.cfg.get("Style/StringLiterals", "EnforcedStyle") == Some("double_quotes") {
            "\"\"".to_string()
        } else {
            "''".to_string()
        }
    }
}

/// A bare (or ::-rooted) constant receiver's name, for Style/EmptyLiteral.
fn empty_lit_const(node: &ruby_prism::Node) -> Option<String> {
    if let Some(c) = node.as_constant_read_node() {
        return Some(String::from_utf8_lossy(c.name().as_slice()).into_owned());
    }
    if let Some(p) = node.as_constant_path_node() {
        if p.parent().is_none() {
            return Some(String::from_utf8_lossy(p.name()?.as_slice()).into_owned());
        }
    }
    None
}

impl<'a> super::Cops<'a> {
    /// Whether a byte offset sits inside a literal's content (string/regex/
    /// symbol text) — semicolons there are data.
    pub(crate) fn in_lit_span(&self, pos: usize) -> bool {
        self.in_literal(pos)
    }

    fn in_literal(&self, pos: usize) -> bool {
        let i = self.lit_spans.partition_point(|(s, _)| *s <= pos);
        i > 0 && pos < self.lit_spans[i - 1].1
    }

    fn semicolon_offense(&mut self, off: usize, remove: bool) {
        if !self.semi_flagged.insert(off) {
            return;
        }
        if remove {
            // an endless range before the `;` must gain parens, or removal
            // changes parsing (rubocop wraps the range node)
            let before = self.src[..off].iter().rposition(|b| !b.is_ascii_whitespace());
            if let Some(b) = before {
                if self.src[b] == b'.' {
                    if let Some((rs, re)) = self.range_spans.iter().find(|(_, e)| *e == b + 1).copied() {
                        self.fixes.push((rs, rs, b"(".to_vec()));
                        self.fixes.push((re, re, b")".to_vec()));
                    }
                }
                // a value-omission label: parenthesize the kwargs and drop
                // the space after the selector (`m key:;` -> `m(key:)`)
                if self.src[b] == b':' {
                    if let Some((ks, ke, sel_end)) = self.vo_kwargs.iter().find(|(_, e, _)| *e == b + 1).copied() {
                        self.fixes.push((sel_end, ks, b"(".to_vec()));
                        self.fixes.push((ke, ke, b")".to_vec()));
                    }
                }
            }
            self.fixes.push((off, off + 1, Vec::new()));
        }
        self.push(off, "Style/Semicolon", true, "Do not use semicolons to terminate expressions.");
    }

    /// Style/Semicolon part 1 (rubocop's on_begin): statements sequences with
    /// multiple expressions ending on one line — every raw `;` on such a line
    /// is an offense (yes, rubocop scans the raw line).
    pub(crate) fn check_semicolon_separators(&mut self, node: &ruby_prism::StatementsNode) {
        const COP: &str = "Style/Semicolon";
        if !self.on(COP) || self.cfg.get(COP, "AllowAsExpressionSeparator") == Some("true") {
            return;
        }
        let exprs: Vec<_> = node.body().iter().collect();
        if exprs.len() < 2 {
            return;
        }
        let l = node.location();
        if !self.src[l.start_offset()..l.end_offset()].contains(&b';') {
            return;
        }
        let mut last_lines: Vec<usize> = exprs
            .iter()
            .map(|e| self.idx.loc(e.location().end_offset().saturating_sub(1)).0)
            .collect();
        last_lines.sort_unstable();
        let mut i = 0;
        while i < last_lines.len() {
            let line = last_lines[i];
            let mut j = i;
            while j < last_lines.len() && last_lines[j] == line {
                j += 1;
            }
            if j - i > 1 {
                let (ls, le) = (self.idx.starts[line - 1], self.line_end(line));
                // a heredoc OPENED before the semicolon suppresses the
                // line-break fix (breaking would orphan the body)
                let heredoc_here = self.heredoc_lines.iter().any(|(hs, _, _, _)| hs.saturating_sub(1) == line);
                for p in ls..le {
                    if self.src[p] == b';' {
                        if !self.semi_flagged.insert(p) {
                            continue;
                        }
                        let opened_before = heredoc_here
                            && self.src[ls..p].windows(2).any(|w| w == b"<<")
                            && !self.in_literal(p);
                        if !opened_before {
                            self.fixes.push((p, p + 1, b"\n".to_vec()));
                        }
                        self.push(p, "Style/Semicolon", true,
                            "Do not use semicolons to terminate expressions.");
                    }
                }
            }
            i = j;
        }
    }

    /// Style/Semicolon part 2: line terminators and openers — a `;` that ends
    /// a line (comments aside), starts one, or hugs a brace.
    pub(crate) fn check_semicolon_lines(&mut self) {
        const COP: &str = "Style/Semicolon";
        if !self.on(COP) || !self.src.contains(&b';') {
            return;
        }
        for line in 1..=self.idx.starts.len() {
            let ls = self.idx.starts[line - 1];
            let le = self.line_end(line);
            // strip a trailing comment: code ends at the comment start
            let code_end = self
                .comments
                .iter()
                .find(|(l, s, _)| *l == line && *s >= ls && *s < le)
                .map(|(_, s, _)| *s)
                .unwrap_or(le);
            let code = &self.src[ls..code_end];
            let semis: Vec<usize> = code
                .iter()
                .enumerate()
                .filter(|(i, b)| **b == b';' && !self.in_literal(ls + i))
                .map(|(i, _)| ls + i)
                .collect();
            let Some(&last) = semis.last() else { continue };
            let first = semis[0];
            // trailing: nothing but whitespace after the last semicolon
            if self.src[last + 1..code_end].iter().all(|b| b.is_ascii_whitespace()) {
                self.semicolon_offense(last, true);
                continue;
            }
            // line opener: `;` is the first non-whitespace on the line
            if self.src[ls..first].iter().all(|b| b.is_ascii_whitespace()) {
                self.semicolon_offense(first, true);
                continue;
            }
            // `; }` before a closing brace at end of line — or before an
            // interpolation's `}` followed only by the string's closing quote
            if let Some(p) = semis.iter().rev().find(|p| {
                let rest = &self.src[**p + 1..code_end];
                let t: Vec<u8> = rest.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
                t == b"}" || t == b"}\"" || t == b"}'"
            }) {
                self.semicolon_offense(*p, true);
                continue;
            }
            // `{ ;` right after an opening brace
            if let Some(p) = semis.iter().find(|p| {
                self.src[ls..**p].iter().rev().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
            }) {
                self.semicolon_offense(*p, true);
            }
        }
    }
}

/// Ruby's built-in global variables (Style/GlobalVars never flags them).
const BUILT_IN_GVARS: &[&str] = &[
    "$:", "$LOAD_PATH", "$\"", "$LOADED_FEATURES", "$0", "$PROGRAM_NAME", "$!",
    "$ERROR_INFO", "$@", "$ERROR_POSITION", "$;", "$FS", "$FIELD_SEPARATOR", "$,",
    "$OFS", "$OUTPUT_FIELD_SEPARATOR", "$/", "$RS", "$INPUT_RECORD_SEPARATOR",
    "$\\", "$ORS", "$OUTPUT_RECORD_SEPARATOR", "$.", "$NR", "$INPUT_LINE_NUMBER",
    "$_", "$LAST_READ_LINE", "$>", "$DEFAULT_OUTPUT", "$<", "$DEFAULT_INPUT",
    "$$", "$PID", "$PROCESS_ID", "$?", "$CHILD_STATUS", "$~", "$LAST_MATCH_INFO",
    "$=", "$IGNORECASE", "$*", "$ARGV", "$&", "$MATCH", "$`", "$PREMATCH", "$'",
    "$POSTMATCH", "$+", "$LAST_PAREN_MATCH", "$stdin", "$stdout", "$stderr",
    "$DEBUG", "$FILENAME", "$VERBOSE", "$SAFE", "$-0", "$-a", "$-d", "$-F",
    "$-i", "$-I", "$-l", "$-p", "$-v", "$-w", "$CLASSPATH", "$JRUBY_VERSION",
    "$JRUBY_REVISION", "$ENV_JAVA",
];

impl<'a> super::Cops<'a> {
    /// whitequark's lexer reads `#$-X` inside an interpolating string as a
    /// `$-X` gvar interpolation; real Ruby (and prism) treat it as plain
    /// text. rubocop therefore flags it — replicate for byte parity.
    pub(crate) fn check_gvar_artifact(&mut self, node: &ruby_prism::StringNode) {
        if !self.on("Style/GlobalVars") {
            return;
        }
        let interpolating = match node.opening_loc() {
            Some(o) => o.as_slice().starts_with(b"\"") || o.as_slice().starts_with(b"%Q") || o.as_slice().starts_with(b"%W"),
            None => true, // a text part of an interpolated string
        };
        if !interpolating {
            return;
        }
        let c = node.content_loc();
        let content = &self.src[c.start_offset()..c.end_offset()];
        for i in 0..content.len().saturating_sub(2) {
            if content[i] == b'#' && content[i + 1] == b'$' && content[i + 2] == b'-'
                && (i == 0 || content[i - 1] != b'\\')
            {
                if let Some(ch) = content.get(i + 3) {
                    if ch.is_ascii_alphanumeric() || *ch == b'_' {
                        let name = format!("$-{}", *ch as char);
                        if !BUILT_IN_GVARS.contains(&name.as_str()) {
                            self.push(c.start_offset() + i + 1, "Style/GlobalVars", false,
                                "Do not introduce global variables.");
                        }
                        // rubocop's VariableInterpolation fires on the same
                        // phantom gvar interpolation
                        if self.on("Style/VariableInterpolation") {
                            self.push(c.start_offset() + i + 1, "Style/VariableInterpolation", false,
                                format!("Replace interpolated variable `{name}` with expression `#{{{name}}}`."));
                        }
                    }
                }
            }
        }
    }

    /// Style/GlobalVars — user-introduced globals (built-ins and
    /// AllowedVariables pass).
    pub(crate) fn check_global_var(&mut self, name: &[u8], name_start: usize) {
        const COP: &str = "Style/GlobalVars";
        if !self.on(COP) {
            return;
        }
        let name = String::from_utf8_lossy(name);
        if BUILT_IN_GVARS.contains(&name.as_ref()) {
            return;
        }
        if let Some(v) = self.cfg.param(COP, "AllowedVariables") {
            if crate::config::parse_allowed_list(v)
                .iter()
                .any(|a| a == name.as_ref() || format!("${a}") == name.as_ref())
            {
                return;
            }
        }
        self.push(name_start, COP, false, "Do not introduce global variables.");
    }
}

impl<'a> super::Cops<'a> {
    /// Style/DefWithParentheses — `def foo()` with an empty parameter list
    /// drops the parens (kept for one-line non-endless defs and when `=`
    /// follows, where removal changes parsing).
    pub(crate) fn check_def_with_parentheses(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/DefWithParentheses";
        if !self.on(COP) {
            return;
        }
        let (Some(lp), Some(rp)) = (node.lparen_loc(), node.rparen_loc()) else { return };
        if node.parameters().is_some() {
            return;
        }
        let l = node.location();
        let single_line = self.idx.loc(l.start_offset()).0
            == self.idx.loc(l.end_offset().saturating_sub(1)).0;
        let endless = node.equal_loc().is_some();
        if single_line && !endless {
            return;
        }
        if self.src.get(rp.end_offset()) == Some(&b'=') {
            return;
        }
        self.fixes.push((lp.start_offset(), rp.end_offset(), Vec::new()));
        self.push(lp.start_offset(), COP, true,
            "Omit the parentheses in defs when the method doesn't accept any arguments.");
    }

    /// Style/WhenThen — `when x;` (semicolon separating a `when` clause's
    /// condition from its body) → `when x then`. Prism doesn't record the
    /// `;`/`then` separator as a distinct field on `WhenNode` the way it does
    /// for `IfNode`/`UnlessNode` (`then_keyword_loc` is `None` for `;`), so
    /// the `;` is located by scanning from the end of the last condition to
    /// the start of the body.
    pub(crate) fn check_when_then(&mut self, node: &ruby_prism::WhenNode) {
        const COP: &str = "Style/WhenThen";
        if !self.on(COP) || node.then_keyword_loc().is_some() {
            return;
        }
        let Some(statements) = node.statements() else { return }; // empty branch
        let nl = node.location();
        if self.src[nl.start_offset()..nl.end_offset()].contains(&b'\n') {
            return; // multiline `when` clause
        }
        let conditions: Vec<ruby_prism::Node> = node.conditions().iter().collect();
        let Some(last_cond) = conditions.last() else { return };
        let mut pos = last_cond.location().end_offset();
        let stmt_start = statements.location().start_offset();
        while pos < stmt_start && matches!(self.src[pos], b' ' | b'\t') {
            pos += 1;
        }
        if pos >= stmt_start || self.src[pos] != b';' {
            return;
        }
        let expression = conditions
            .iter()
            .map(|c| String::from_utf8_lossy(self.node_src(c)))
            .collect::<Vec<_>>()
            .join(", ");
        self.push(pos, COP, true,
            format!("Do not use `when {expression};`. Use `when {expression} then` instead."));
        self.fixes.push((pos, pos + 1, b" then".to_vec()));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/Proc — `Proc.new { ... }` (block form, any block shape) →
    /// `proc { ... }`. Verbatim matcher:
    /// `(any_block $(send (const {nil? cbase} :Proc) :new) ...)`.
    pub(crate) fn check_proc_new(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/Proc";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"new" || node.arguments().is_some() {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if empty_lit_const(&recv).as_deref() != Some("Proc") {
            return;
        }
        // Only a literal block (curly/do-end, incl. numbered-params and `it`
        // blocks — prism represents those as ordinary BlockNodes) counts.
        if node.block().and_then(|b| b.as_block_node()).is_none() {
            return;
        }
        let Some(msg_loc) = node.message_loc() else { return };
        let start = recv.location().start_offset();
        let end = msg_loc.end_offset();
        self.fixes.push((start, end, b"proc".to_vec()));
        self.push(start, COP, true, "Use `proc` instead of `Proc.new`.");
    }
}


impl<'a> super::Cops<'a> {

    /// Style/ColonMethodDefinition — a singleton method defined using `::`
    /// (e.g. `def self::bar`) instead of `.` (`def self.bar`). Only defs
    /// with an explicit receiver (prism's `DefNode#receiver`) are singleton
    /// method definitions; autocorrect swaps the `::` operator for `.`.
    pub(crate) fn check_colon_method_definition(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/ColonMethodDefinition";
        if !self.on(COP) || node.receiver().is_none() {
            return;
        }
        let Some(op) = node.operator_loc() else { return };
        if self.src.get(op.start_offset()..op.end_offset()) != Some(b"::".as_slice()) {
            return;
        }
        self.fixes.push((op.start_offset(), op.end_offset(), b".".to_vec()));
        self.push(op.start_offset(), COP, true, "Do not use `::` for defining class methods.");
    }
}

impl<'a> super::Cops<'a> {
    /// Style/Strip — `lstrip.rstrip` or `rstrip.lstrip` can be replaced
    /// by `strip`. Matches the outer call node where the method is the second
    /// in the chain. The receiver must be a call to the opposite method.
    pub(crate) fn check_strip(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/Strip";
        if !self.on(COP) {
            return;
        }

        let name = node.name().as_slice();
        let is_lstrip = name == b"lstrip";
        let is_rstrip = name == b"rstrip";

        if !is_lstrip && !is_rstrip {
            return;
        }

        // Check if receiver is a call to the opposite method
        let Some(recv) = node.receiver() else { return };
        let Some(recv_call) = recv.as_call_node() else { return };
        let recv_name = recv_call.name().as_slice();

        let is_opposite = (is_lstrip && recv_name == b"rstrip") || (is_rstrip && recv_name == b"lstrip");
        if !is_opposite {
            return;
        }

        // Get the message location of the inner call and end of outer call
        let Some(inner_msg_loc) = recv_call.message_loc() else { return };
        let outer_end = node.location().end_offset();

        let start = inner_msg_loc.start_offset();
        let end = outer_end;

        // Get the text being replaced for the message
        let methods_text = String::from_utf8_lossy(&self.src[start..end]);
        let message = format!("Use `strip` instead of `{}`.", methods_text);

        self.fixes.push((start, end, b"strip".to_vec()));
        self.push(start, COP, true, message);
    }
}

impl<'a> super::Cops<'a> {
    /// Style/VariableInterpolation — checks for shorthand variable interpolation
    /// (like `"#@ivar"`, `"#@@cvar"`, `"#$gvar"`) and suggests wrapping them in
    /// braces (`"#{@ivar}"`). In prism, these are EmbeddedVariableNode containing
    /// the variable node. The offense is reported on the variable, and the fix
    /// wraps the entire `#variable` with braces.
    pub(crate) fn check_variable_interpolation(&mut self, node: &ruby_prism::EmbeddedVariableNode) {
        const COP: &str = "Style/VariableInterpolation";
        if !self.on(COP) {
            return;
        }
        let var = node.variable();
        let var_src = self.node_src(&var);
        let message = format!(
            "Replace interpolated variable `{}` with expression `#{{{}}}`.",
            String::from_utf8_lossy(var_src),
            String::from_utf8_lossy(var_src)
        );
        // Report offense at the variable location
        self.push(var.location().start_offset(), COP, true, &message);
        // Fix: wrap the entire #variable with braces, changing #@ivar to #{@ivar}
        let node_loc = node.location();
        let replacement = {
            let mut result = b"#{".to_vec();
            result.extend_from_slice(var_src);
            result.extend_from_slice(b"}");
            result
        };
        self.fixes.push((node_loc.start_offset(), node_loc.end_offset(), replacement));
    }
}

impl<'a> super::Cops<'a> {
    /// Style/TrailingBodyOnModule — a multiline `module` whose body trails on
    /// the `module` keyword's own line (`module Foo; body`,
    /// `module Foo extend self`, `module Foo body`, `module Foo def bar; end`).
    /// Ports RuboCop's `TrailingBody` mixin (`trailing_body?`/`first_part_of`)
    /// plus `LineBreakCorrector.correct_trailing_body`.
    ///
    /// Note on `first_part_of`: whitequark's AST leaves a lone body statement
    /// unwrapped and only introduces a `begin` node once there are >= 2
    /// top-level statements, so the mixin special-cases `begin_type?` to grab
    /// just the first child. Prism always wraps a module's body in a
    /// `StatementsNode`, single statement or not, so "first element of the
    /// body list" is the uniform equivalent of both branches here.
    pub(crate) fn check_trailing_body_on_module(&mut self, node: &ruby_prism::ModuleNode) {
        const COP: &str = "Style/TrailingBodyOnModule";
        if !self.on(COP) {
            return;
        }
        let nl = node.location();
        let node_start = nl.start_offset();
        let node_end = nl.end_offset();
        let start_line = self.idx.loc(node_start).0;
        let end_line = self.idx.loc(node_end.saturating_sub(1)).0;
        if start_line == end_line {
            return; // not `node.multiline?`
        }
        let Some(body) = node.body() else { return };
        let Some(stmts) = body.as_statements_node() else { return };
        let Some(first_stmt) = stmts.body().iter().next() else { return };
        let fl = first_stmt.location();
        if self.idx.loc(fl.start_offset()).0 != start_line {
            return; // body doesn't trail on the module's own line
        }
        let range_start = fl.start_offset();

        self.push(range_start, COP, true, "Place the first line of module body on its own line.");

        // --- autocorrect: LineBreakCorrector.correct_trailing_body ---
        let keyword = node.module_keyword_loc();
        let keyword_col = self.idx.loc(keyword.start_offset()).1 - 1;
        let width = self.cfg.int("Layout/IndentationWidth", "Width");

        // An end-of-line comment on the module's own line moves above the
        // `module` line entirely (LineBreakCorrector#move_comment), indented
        // to the module's own column.
        if let Some(&(_, cstart, cend)) =
            self.comments.iter().find(|(line, _, _)| *line == start_line)
        {
            let mut ins = self.src[cstart..cend].to_vec();
            ins.push(b'\n');
            ins.extend(std::iter::repeat_n(b' ', keyword_col));
            self.fixes.push((node_start, node_start, ins));
            self.fixes.push((cstart, cend, Vec::new()));
        }

        // Break the line before the first body statement, indented one step
        // past the `module` keyword (LineBreakCorrector#break_line_before).
        let mut brk = vec![b'\n'];
        brk.extend(std::iter::repeat_n(b' ', keyword_col + width));
        self.fixes.push((range_start, range_start, brk));

        // The `;` separating the module header from the body, if any. Only
        // scanning the header span (before the body starts) means a `;`
        // *inside* the first statement itself (`def bar; end`) is untouched.
        if let Some(rel) = self.src[node_start..range_start].iter().position(|&b| b == b';') {
            let pos = node_start + rel;
            self.fixes.push((pos, pos + 1, Vec::new()));
        }
    }
}
impl<'a> super::Cops<'a> {
    /// Style/TrailingBodyOnClass — `class Foo; body` / `class << self; body`
    /// where the body trails the class keyword on its opening line, but the
    /// class as a whole is multiline (`class Foo; end` on one line is fine).
    /// Ported from rubocop's `TrailingBody` mixin + `LineBreakCorrector`.
    /// Shared by `visit_class_node` and `visit_singleton_class_node` — this
    /// mirrors rubocop's `on_sclass` alias of `on_class`.
    ///
    /// `keyword_start` is the offset of the `class` keyword (== the node's
    /// own location start for both `ClassNode`/`SingletonClassNode`, so it
    /// doubles as "insert before the node" for the comment-move step).
    pub(crate) fn check_trailing_body_on_class(
        &mut self,
        keyword_start: usize,
        node_end: usize,
        body: Option<ruby_prism::Node>,
    ) {
        const COP: &str = "Style/TrailingBodyOnClass";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body else { return }; // no body at all
        // `node.multiline?`: the class...end block itself spans >1 line.
        let start_line = self.idx.loc(keyword_start).0;
        let end_line = self.idx.loc(node_end.saturating_sub(1)).0;
        if start_line == end_line {
            return;
        }
        // `same_line?(node, body)`: body starts on the class's first line.
        if self.idx.loc(body.location().start_offset()).0 != start_line {
            return;
        }
        // `first_part_of`: a bare statement list (`begin_type?`) offends at
        // its first statement; anything else (e.g. a rescue/ensure wrapper)
        // offends at the whole body.
        let first_start = body
            .as_statements_node()
            .and_then(|s| s.body().iter().next())
            .map(|n| n.location().start_offset())
            .unwrap_or_else(|| body.location().start_offset());

        self.push(first_start, COP, true, "Place the first line of class body on its own line.");

        // configured_indentation_width: cop-local IndentationWidth, else
        // Layout/IndentationWidth's Width, else 2.
        let width: usize = self
            .cfg
            .param(COP, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2);
        let keyword_col = self.idx.loc(keyword_start).1 - 1; // 0-based column

        // `break_line_before`: push the first body token onto its own,
        // freshly-indented line.
        let indent = " ".repeat(keyword_col + width);
        self.fixes.push((first_start, first_start, format!("\n{indent}").into_bytes()));

        // `move_comment`: an EOL comment on the class's opening line moves
        // above the class, at the class's own indentation.
        if let Some(&(_, cs, ce)) = self.comments.iter().find(|(line, _, _)| *line == start_line) {
            let mut ins = self.src[cs..ce].to_vec();
            ins.push(b'\n');
            ins.extend(std::iter::repeat(b' ').take(keyword_col));
            self.fixes.push((keyword_start, keyword_start, ins));
            self.fixes.push((cs, ce, Vec::new()));
        }

        // `remove_semicolon`: the `;` directly separating the class header
        // from the trailing body (as opposed to plain whitespace).
        if let Some(scan) = self.src.get(keyword_start..first_start) {
            if let Some(rel) = scan.iter().rposition(|&b| b == b';') {
                let sc = keyword_start + rel;
                self.fixes.push((sc, sc + 1, Vec::new()));
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/RedundantCapitalW — `%W[...]` / `%W(...)` with no interpolation
    /// and no special escapes → use `%w`. Fix downcases the W in the opening
    /// delimiter (e.g., `%W[cat dog]` → `%w[cat dog]`).
    pub(crate) fn check_redundant_capital_w(&mut self, node: &ruby_prism::ArrayNode) {
        const COP: &str = "Style/RedundantCapitalW";
        if !self.on(COP) {
            return;
        }

        // Check if opening delimiter is %W
        let Some(open_loc) = node.opening_loc() else { return };
        if !open_loc.as_slice().starts_with(b"%W") {
            return;
        }

        // Check if any element requires interpolation (is interpolated or has escapes)
        for element in node.elements().iter() {
            // If it's an interpolated string (has #{...}), we need %W
            if element.as_interpolated_string_node().is_some() {
                return;
            }

            // If it's a string node, check if its source requires double quotes
            // (i.e., has escape sequences that only %W would preserve)
            if let Some(str_node) = element.as_string_node() {
                let l = str_node.location();
                let raw_src = &self.src[l.start_offset()..l.end_offset()];
                if double_quotes_required(raw_src) {
                    return;
                }
            }
        }

        // If we get here, no interpolation and no escapes, so %w would work
        let l = node.location();
        self.push(
            l.start_offset(),
            COP,
            true,
            "Do not use `%W` unless interpolation is needed. If not, use `%w`.",
        );

        // Fix: replace W with w in opening delimiter
        let open_start = open_loc.start_offset();
        let open_end = open_loc.end_offset();
        let open_src = &self.src[open_start..open_end];
        let mut replacement = open_src.to_vec();
        // Replace the first occurrence of 'W' with 'w'
        for byte in &mut replacement {
            if *byte == b'W' {
                *byte = b'w';
                break;
            }
        }
        self.fixes.push((open_start, open_end, replacement));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/EmptyLambdaParameter — an arrow lambda (`->`) with an EMPTY but
    /// present parameter list: `-> () { ... }`. The parens are redundant;
    /// autocorrect drops them (and the whitespace around them) entirely.
    ///
    /// Ported from rubocop's `EmptyLambdaParameter` cop plus its shared
    /// `EmptyParameter` mixin (`check`/`empty_arguments?`). Only arrow-lambda
    /// literals are in scope — `lambda { || ... }` and `super { || ... }` use
    /// ordinary block syntax with no `LambdaNode`, so this visitor never sees
    /// them (mirrors rubocop's `node.lambda_literal?` guard).
    pub(crate) fn check_empty_lambda_parameter(&mut self, node: &ruby_prism::LambdaNode<'_>) {
        const COP: &str = "Style/EmptyLambdaParameter";
        if !self.on(COP) {
            return;
        }
        // `-> { }` — no parameter list at all: rubocop's `args` node has no
        // source location and `empty_and_without_delimiters?` short-circuits.
        let Some(params) = node.parameters() else { return };
        let Some(bp) = params.as_block_parameters_node() else { return };
        // rubocop's NodePattern `(args)` only matches a ZERO-arity args node
        // — any real parameter (or block-local `;`-declared var) means this
        // isn't the "empty" case at all, regardless of parens.
        if bp.parameters().is_some() || bp.locals().iter().next().is_some() {
            return;
        }
        // "without delimiters" (bare, unparenthesized empty list) is exempt;
        // only a written, empty `()` offends.
        let Some(open) = bp.opening_loc() else { return };
        let open_start = open.start_offset();
        let close_end = bp.closing_loc().map(|c| c.end_offset()).unwrap_or_else(|| open.end_offset());

        self.push(open_start, COP, true, "Omit parentheses for the empty lambda parameters.");

        // autocorrect: `range_between(send_node.end, args.end)` in rubocop —
        // the send node for an arrow lambda IS the `->` operator itself, so
        // this removes everything from right after `->` through the closing
        // paren (e.g. the ` ()` in `-> () { ... }`).
        let remove_start = node.operator_loc().end_offset();
        self.fixes.push((remove_start, close_end, Vec::new()));
    }
}

impl<'a> super::Cops<'a> {
    /// Style/IfUnlessModifierOfIfUnless — a modifier `if`/`unless` whose body
    /// is itself an if/unless/ternary conditional: `cond ? a : b if x`,
    /// `raise if y if x`, `(if a; b; end) if x`. Ported from rubocop's
    /// `on_if` — rubocop's parser AST unifies `if`/`unless`/ternary under a
    /// single `:if` node type, so a single handler covers all three body
    /// shapes via `node.body.if_type?`. Prism keeps `IfNode`/`UnlessNode`
    /// distinct, so `visit_if_node` and `visit_unless_node` both call in
    /// here once they've confirmed modifier form; a ternary body is still
    /// just an `IfNode` (with `if_keyword_loc` absent), so no extra case is
    /// needed to recognize it.
    ///
    /// Autocorrect mirrors rubocop's corrector exactly:
    ///   corrector.wrap(node.if_branch, "#{keyword} #{condition}\n", "\nend")
    ///   corrector.remove(if_branch.source_range.end.join(condition.source_range.end))
    /// i.e. wrap the body in a real `keyword condition ... end` block and
    /// drop the now-redundant trailing modifier annotation.
    ///
    /// Push order within a single node matters for `main.rs`'s fix-applier
    /// (stable sort, descending by start offset; same-start ties keep
    /// vector order): the removal (body_end, cond_end) must be pushed
    /// before the zero-width suffix insert at body_end, so it's applied
    /// first and doesn't get skipped by the `e <= last_start` guard.
    ///
    /// This check is called from `visit_if_node`/`visit_unless_node` AFTER
    /// recursing into children (post-order). For doubly-nested modifiers
    /// (`a if inner if outer`), that ensures the inner node's zero-width
    /// prefix-insert (at the shared body-start offset 0) is pushed before
    /// the outer node's — so the outer's insert is applied last and ends up
    /// outermost (`if outer\nif inner\n...`), matching rubocop's
    /// insert-before semantics (first-registered ends up leftmost).
    pub(crate) fn check_if_unless_modifier_of_if_unless(
        &mut self,
        keyword: &str,
        kw_loc: ruby_prism::Location,
        cond: ruby_prism::Node,
        body_stmts: Option<ruby_prism::StatementsNode>,
    ) {
        const COP: &str = "Style/IfUnlessModifierOfIfUnless";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body_stmts.and_then(|s| s.body().iter().next()) else { return };
        if body.as_if_node().is_none() && body.as_unless_node().is_none() {
            return;
        }
        self.push(kw_loc.start_offset(), COP, true,
            format!("Avoid modifier `{keyword}` after another conditional."));

        let body_loc = body.location();
        let (body_start, body_end) = (body_loc.start_offset(), body_loc.end_offset());
        let cond_end = cond.location().end_offset();
        let cond_src = self.node_src(&cond).to_vec();

        self.fixes.push((body_end, cond_end, Vec::new()));
        self.fixes.push((body_end, body_end, b"\nend".to_vec()));
        let mut prefix = format!("{keyword} ").into_bytes();
        prefix.extend(cond_src);
        prefix.push(b'\n');
        self.fixes.push((body_start, body_start, prefix));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/EmptyBlockParameter — `foo { || bar }` / `foo do || bar end`.
    /// Empty pipes on a block declare no parameters, so they're redundant.
    /// Ported from rubocop's `EmptyBlockParameter` + its `EmptyParameter`
    /// mixin. Note rubocop's node pattern `(block _ $(args) _)` only
    /// captures an `args` node with ZERO children — i.e. non-empty pipes
    /// (`|x|`) or block-locals (`|; x|`) never match — then
    /// `empty_and_without_delimiters?` (`loc.expression.nil?`) filters out
    /// the case with no pipes at all. Ported to prism: offend only when
    /// `block.parameters()` is a `BlockParametersNode` (pipes present) whose
    /// own `parameters()` is absent and `locals()` is empty.
    ///
    /// Arrow lambdas (`-> () { }`) are `LambdaNode` in prism, not a
    /// `CallNode` with a block, so they never reach this hook — mirroring
    /// rubocop's own `send_node.lambda_literal?` guard in `on_block`. A
    /// brace/do-end block on the `lambda` METHOD (`lambda { || }`) is a
    /// plain `CallNode` + `BlockNode` and DOES match, per the spec.
    pub(crate) fn check_empty_block_parameter(&mut self, block: &ruby_prism::BlockNode<'_>) {
        const COP: &str = "Style/EmptyBlockParameter";
        if !self.on(COP) {
            return;
        }
        let Some(params) = block.parameters().and_then(|p| p.as_block_parameters_node()) else {
            return;
        };
        if params.parameters().is_some() || params.locals().iter().next().is_some() {
            return;
        }
        let loc = params.location();
        let (start, end) = (loc.start_offset(), loc.end_offset());
        self.push(start, COP, true, "Omit pipes for the empty block parameters.");
        // `range_between(block.loc.begin.end_pos, node.source_range.end_pos)`:
        // remove everything from right after the opening `{`/`do` through
        // the closing pipe — this eats the space before `||` too, but
        // leaves any space/text after the closing pipe untouched.
        let remove_start = block.opening_loc().end_offset();
        self.fixes.push((remove_start, end, Vec::new()));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/DoubleCopDisableDirective — a line with two (or more)
    /// `# rubocop:disable`/`# rubocop:todo` markers packed into ONE comment
    /// (`code # rubocop:disable A # rubocop:disable B`): only the first
    /// directive has any effect, so the second is dead text — usually a sign
    /// of a stale auto-generated comment. Ported verbatim from rubocop's
    /// `on_new_investigation`: `comment.text.scan(/# rubocop:(?:disable|todo)/)
    /// .size > 1`. Prism gives ONE comment token for the whole trailing text,
    /// so this is a plain per-comment scan over `self.comments` — no AST
    /// needed, hence the standalone hook call (not tied to any node visit).
    pub(crate) fn check_double_cop_disable_directive(&mut self) {
        const COP: &str = "Style/DoubleCopDisableDirective";
        if !self.on(COP) {
            return;
        }
        static DIRECTIVE: OnceLock<regex::Regex> = OnceLock::new();
        let directive =
            DIRECTIVE.get_or_init(|| regex::Regex::new(r"# rubocop:(?:disable|todo)").unwrap());
        // The autocorrect regex has a LEADING space (` # rubocop:...`), so it
        // never matches the first directive (which opens the comment with no
        // preceding space) — mirroring `corrector.replace(comment,
        // comment.text.gsub(%r{ # rubocop:(disable|todo)}, ','))`.
        static REPLACE: OnceLock<regex::Regex> = OnceLock::new();
        let replace =
            REPLACE.get_or_init(|| regex::Regex::new(r" # rubocop:(?:disable|todo)").unwrap());
        for &(_, start, end) in self.comments {
            let text = String::from_utf8_lossy(&self.src[start..end]);
            if directive.find_iter(&text).count() <= 1 {
                continue;
            }
            self.push(start, COP, true, "More than one disable comment on one line.");
            let corrected = replace.replace_all(&text, ",");
            self.fixes.push((start, end, corrected.into_owned().into_bytes()));
        }
    }
}
impl<'a> super::Cops<'a> {
    /// Style/ClassCheck — enforces consistent use of `Object#is_a?` /
    /// `Object#kind_of?` per the `EnforcedStyle` config (default `is_a?`).
    /// Ported from rubocop's `ClassCheck`: `RESTRICT_ON_SEND = %i[is_a?
    /// kind_of?]`, offends when the call's method name doesn't match the
    /// configured style, anchored on the selector (`node.loc.selector`),
    /// and the fix simply renames the selector to the other spelling.
    /// Applies identically to `.` and `&.` calls (rubocop aliases
    /// `on_csend` to `on_send`); prism represents both as `CallNode` so no
    /// extra dispatch is needed here.
    pub(crate) fn check_class_check(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/ClassCheck";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        let is_a = name == b"is_a?";
        let kind_of = name == b"kind_of?";
        if !is_a && !kind_of {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        if (style == "is_a?" && is_a) || (style == "kind_of?" && kind_of) {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        let (prefer, current, replacement) =
            if is_a { ("kind_of?", "is_a?", "kind_of?") } else { ("is_a?", "kind_of?", "is_a?") };
        self.push(
            sel.start_offset(),
            COP,
            true,
            format!("Prefer `Object#{prefer}` over `Object#{current}`."),
        );
        self.fixes.push((sel.start_offset(), sel.end_offset(), replacement.as_bytes().to_vec()));
    }
}

impl<'a> super::Cops<'a> {
    /// Style/ClassMethods — `def ClassName.method` inside a class/module
    /// should be `def self.method`. Ported from rubocop's Style/ClassMethods.
    /// Checks both direct DefNodes and DefNodes nested in a StatementsNode body.
    pub(crate) fn check_class_methods(
        &mut self,
        constant_path: &ruby_prism::Node,
        body: Option<ruby_prism::Node>,
    ) {
        const COP: &str = "Style/ClassMethods";
        if !self.on(COP) {
            return;
        }

        let Some(body_node) = body else { return };

        // Get the class/module name
        let class_name = self.node_src(constant_path);

        // Handle direct DefNode
        if let Some(def_node) = body_node.as_def_node() {
            self.check_class_method_def(class_name, &def_node);
            return;
        }

        // Handle StatementsNode containing DefNodes
        if let Some(stmts) = body_node.as_statements_node() {
            for stmt in stmts.body().iter() {
                if let Some(def_node) = stmt.as_def_node() {
                    self.check_class_method_def(class_name, &def_node);
                }
            }
        }
    }

    fn check_class_method_def(
        &mut self,
        class_name: &[u8],
        def_node: &ruby_prism::DefNode,
    ) {
        const COP: &str = "Style/ClassMethods";
        let Some(receiver) = def_node.receiver() else { return };

        // Get the receiver name as bytes
        let receiver_name = self.node_src(&receiver);

        // Compare: only trigger if receiver matches class name
        if receiver_name != class_name {
            return;
        }

        // Get the method name
        let method_name = String::from_utf8_lossy(def_node.name().as_slice());

        let message = format!(
            "Use `self.{}` instead of `{}.{}`.",
            method_name,
            String::from_utf8_lossy(class_name),
            method_name
        );

        self.push(receiver.location().start_offset(), COP, true, message);

        // Fix: replace receiver with "self"
        let (start, end) = (receiver.location().start_offset(), receiver.location().end_offset());
        self.fixes.push((start, end, b"self".to_vec()));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/TrailingBodyOnMethodDefinition — a multiline method definition
    /// (`def foo; body` / `def self.foo; body`) whose body trails on the
    /// `def` keyword's own line. Endless defs (`def foo = body`) are always
    /// on one line as far as this cop cares and are skipped by the caller
    /// (`node.endless?`) before this runs.
    /// Ported from rubocop's `TrailingBody` mixin + `LineBreakCorrector`,
    /// the same shape as `check_trailing_body_on_class` above but keyed off
    /// the `def` keyword instead of `class`/`module`.
    pub(crate) fn check_trailing_body_on_method_definition(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/TrailingBodyOnMethodDefinition";
        if !self.on(COP) {
            return;
        }
        let Some(body) = node.body() else { return }; // no body at all
        let keyword = node.def_keyword_loc();
        let keyword_start = keyword.start_offset();
        let node_end = node.location().end_offset();
        // `node.multiline?`: the def...end block itself spans >1 line.
        let start_line = self.idx.loc(keyword_start).0;
        let end_line = self.idx.loc(node_end.saturating_sub(1)).0;
        if start_line == end_line {
            return;
        }
        // `same_line?(node, body)`: body starts on the def's first line.
        // A def with rescue/ensure wraps the body in a BeginNode whose span
        // starts back at the def line in prism — whitequark anchors at the
        // first real statement, so use that.
        let body_start = body
            .as_begin_node()
            .and_then(|bn| bn.statements())
            .and_then(|st| st.body().iter().next().map(|n| n.location().start_offset()))
            .unwrap_or_else(|| body.location().start_offset());
        if self.idx.loc(body_start).0 != start_line {
            return;
        }
        // `first_part_of`: a bare statement list (`begin_type?`) offends at
        // its first statement; anything else (e.g. a rescue/ensure wrapper)
        // offends at the whole body.
        let first_start = body
            .as_statements_node()
            .and_then(|s| s.body().iter().next())
            .map(|n| n.location().start_offset())
            .unwrap_or_else(|| body.location().start_offset());

        self.push(
            first_start,
            COP,
            true,
            "Place the first line of a multi-line method definition's body on its own line.",
        );

        // configured_indentation_width: cop-local IndentationWidth, else
        // Layout/IndentationWidth's Width, else 2.
        let width: usize = self
            .cfg
            .param(COP, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2);
        let keyword_col = self.idx.loc(keyword_start).1 - 1; // 0-based column

        // `break_line_before`: push the first body token onto its own,
        // freshly-indented line.
        let indent = " ".repeat(keyword_col + width);
        self.fixes.push((first_start, first_start, format!("\n{indent}").into_bytes()));

        // `move_comment`: an EOL comment on the def's opening line moves
        // above the def, at the def's own indentation.
        if let Some(&(_, cs, ce)) = self.comments.iter().find(|(line, _, _)| *line == start_line) {
            let mut ins = self.src[cs..ce].to_vec();
            ins.push(b'\n');
            ins.extend(std::iter::repeat(b' ').take(keyword_col));
            self.fixes.push((keyword_start, keyword_start, ins));
            self.fixes.push((cs, ce, Vec::new()));
        }

        // `remove_semicolon`: the `;` directly separating the def header
        // from the trailing body (as opposed to plain whitespace).
        if let Some(scan) = self.src.get(keyword_start..first_start) {
            if let Some(rel) = scan.iter().rposition(|&b| b == b';') {
                let sc = keyword_start + rel;
                self.fixes.push((sc, sc + 1, Vec::new()));
            }
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Style/MultilineBlockChain — chaining a method call onto a MULTILINE
    /// block: `foo do ... end.bar { }`. Ported from rubocop's `on_block`,
    /// which walks `node.send_node`'s call-node descendants
    /// (`each_node(:call)`, preorder — so send_node itself is checked
    /// first) for the first one whose RECEIVER is a block node that spans
    /// multiple lines, then `break`s. The offense range starts at that
    /// receiver's closing `end`/`}` and runs through the end of send_node.
    ///
    /// Prism fuses rubocop's separate Block node + send_node into one
    /// CallNode (the block just hangs off `.block()`), so what rubocop
    /// calls "on_block firing per block node" is here: any CallNode WITH a
    /// block attached, checked using itself (minus its own `.block()`) as
    /// the send_node. Walking `.receiver()` links one at a time reproduces
    /// each_node(:call)'s preorder descent through the receiver chain: a
    /// receiver that's a call WITHOUT a block, or WITH a single-line block,
    /// isn't a match — rubocop's traversal doesn't stop there either, it
    /// keeps descending into THAT receiver's own receiver. A receiver
    /// that's a call WITH a multiline block IS a match: push the offense
    /// and stop. Later links in a longer chain are caught independently
    /// when `on_block` later fires on THEIR OWN attached block (this
    /// function runs once per call-with-block, from `visit_call_node`).
    ///
    /// Only the offense START position matters for this port — `self.push`
    /// takes no end offset, and the oracle diff only compares line:col +
    /// message, never underline width — so there's no need to compute
    /// rubocop's `node.send_node.source_range.end_pos`.
    ///
    /// No autocorrect: rubocop's cop doesn't extend `AutoCorrector`.
    pub(crate) fn check_multiline_block_chain(&mut self, outer: &ruby_prism::CallNode<'_>) {
        const COP: &str = "Style/MultilineBlockChain";
        if !self.on(COP) {
            return;
        }
        // rubocop's on_block fires only for REAL brace/do blocks — a
        // block-pass argument (`map(&:line)`) is not a block node
        if outer.block().and_then(|b| b.as_block_node()).is_none() {
            return;
        }
        let Some(mut cur) = outer.receiver() else { return };
        loop {
            let Some(call) = cur.as_call_node() else { return };
            if let Some(block) = call.block().and_then(|b| b.as_block_node()) {
                let bloc = block.location();
                let start_line = self.idx.loc(bloc.start_offset()).0;
                let end_line = self.idx.loc(bloc.end_offset().saturating_sub(1)).0;
                if start_line != end_line {
                    let start = block.closing_loc().start_offset();
                    self.push(start, COP, false, "Avoid multi-line chains of blocks.");
                    return;
                }
            }
            let Some(next) = call.receiver() else { return };
            cur = next;
        }
    }
}
impl<'a> super::Cops<'a> {

    /// Style/OptionalArguments — optional positional parameters that come
    /// before required positional parameters should be moved to the end.
    /// Ported from rubocop's `each_misplaced_optional_arg`: for each optional
    /// parameter, check if there are any required positional parameters (either
    /// `.requireds()` or `.posts()`) that come after it in the source, and if
    /// so, flag the optional parameter.
    ///
    /// No autocorrect: rubocop's cop doesn't extend `AutoCorrector`.
    pub(crate) fn check_optional_arguments(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/OptionalArguments";
        if !self.on(COP) {
            return;
        }

        let Some(params) = node.parameters() else { return };

        let optionals: Vec<_> = params.optionals().iter().collect();
        if optionals.is_empty() {
            return;
        }

        // Collect all required positional parameters (both regular and posts)
        let mut requireds: Vec<_> = params.requireds().iter().collect();
        requireds.extend(params.posts().iter());

        if requireds.is_empty() {
            return;
        }

        // For each optional parameter, check if there's any required parameter
        // that comes after it (has a greater start offset in the source)
        for optional in optionals {
            let opt_start = optional.location().start_offset();
            for required in &requireds {
                let req_start = required.location().start_offset();
                if req_start > opt_start {
                    self.push(
                        opt_start,
                        COP,
                        false,
                        "Optional arguments should appear at the end of the argument list.",
                    );
                    break;
                }
            }
        }
    }
}

impl<'a> super::Cops<'a> {

    /// Style/RedundantFileExtensionInRequire — `require 'foo.rb'` is
    /// redundant; Ruby tries adding `.rb` automatically if the name is not found.
    /// Only string literals are checked; identifiers/expressions are ignored.
    pub(crate) fn check_redundant_file_extension_in_require(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/RedundantFileExtensionInRequire";
        let name = node.name().as_slice();
        if !matches!(name, b"require" | b"require_relative") || !self.on(COP) {
            return;
        }
        let Some(args_node) = node.arguments() else { return };
        let args = args_node.arguments();
        if args.iter().count() != 1 {
            return;
        }
        let arg = args.iter().next().unwrap();
        let Some(str_node) = arg.as_string_node() else { return };
        let content = str_node.content_loc().as_slice();
        if !content.ends_with(b".rb") {
            return;
        }
        // The offense is positioned at the `.rb` part (last 3 bytes of the string content).
        let loc = str_node.content_loc();
        let start_offset = loc.end_offset() - 3;
        let end_offset = loc.end_offset();
        self.push(start_offset, COP, true, "Redundant `.rb` file extension detected.");
        self.fixes.push((start_offset, end_offset, Vec::new()));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/MultilineWhenThen — a `then` keyword is redundant on a `when`
    /// clause whose body sits on a following line. Verbatim RuboCop logic
    /// (`on_when`/`require_then?`):
    ///   - skip when there's no real `then` keyword (bare `when x` or the
    ///     `;` form, which `Style/WhenThen` owns instead);
    ///   - skip when the `when` conditions themselves span multiple lines
    ///     (`then` is required there regardless of the body);
    ///   - skip when the body starts on the same line as the `when`
    ///     keyword (single-line `when x then body` — `then` is required);
    ///   - otherwise flag the `then` keyword and (autocorrect) remove it
    ///     plus any contiguous horizontal whitespace directly before it
    ///     (`range_with_surrounding_space(side: :left, newlines: false)`).
    pub(crate) fn check_multiline_when_then(&mut self, node: &ruby_prism::WhenNode) {
        const COP: &str = "Style/MultilineWhenThen";
        if !self.on(COP) {
            return;
        }
        let Some(then_loc) = node.then_keyword_loc() else { return }; // no `then` (or `;`)
        let conditions: Vec<ruby_prism::Node> = node.conditions().iter().collect();
        let Some(first_cond) = conditions.first() else { return };
        let last_cond = conditions.last().unwrap();
        let first_line = self.idx.loc(first_cond.location().start_offset()).0;
        let last_line = self.idx.loc(last_cond.location().end_offset().saturating_sub(1)).0;
        if first_line != last_line {
            return; // conditions span multiple lines -> `then` required
        }
        if let Some(body) = node.statements() {
            let when_line = self.idx.loc(node.location().start_offset()).0;
            let body_line = self.idx.loc(body.location().start_offset()).0;
            if when_line == body_line {
                return; // body on the same line as `when` -> `then` required
            }
        }
        let then_start = then_loc.start_offset();
        let then_end = then_loc.end_offset();
        self.push(then_start, COP, true, "Do not use `then` for multiline `when` statement.");
        let mut start = then_start;
        while start > 0 && matches!(self.src[start - 1], b' ' | b'\t') {
            start -= 1;
        }
        self.fixes.push((start, then_end, Vec::new()));
    }
}
impl<'a> super::Cops<'a> {
    /// Style/MultilineIfModifier — a modifier `if`/`unless` whose BODY spans
    /// more than one line (`{ ... } if cond`, `begin ... end if cond`, or any
    /// multiline expression used as the body). Ported from rubocop's `on_if`
    /// (`StatementModifier`/`Alignment` mixins): `node.modifier_form? &&
    /// node.body.multiline?` — note it's the BODY's own multiline-ness that
    /// matters, not the whole node's (a one-line body with a multiline
    /// CONDITION, e.g. `run if cond &&\n       cond2`, is NOT an offense).
    ///
    /// Ported to prism: `node.body` (rubocop's single AST child; wraps
    /// multiple statements in an implicit `begin` node) is
    /// `node.statements().body().first()` here — modifier form always
    /// carries exactly one top-level statement, itself a `BeginNode` for the
    /// explicit `begin...end` form.
    ///
    /// Autocorrect ports `to_normal_if`/`indented_body` verbatim: reindent
    /// each body line by replacing its leading `offset(node)`-width prefix
    /// (in bytes: `node`'s own column) with `indentation(node)` (that column
    /// plus `Layout/IndentationWidth`'s `Width`, default 2), then wrap
    /// `keyword cond\n<reindented body>\nend` (the `end` reindented to the
    /// node's own original column, since the corrector replaces the node's
    /// ENTIRE source range — the node's original leading whitespace on its
    /// source line is untouched, outside the replaced range).
    ///
    /// Nested modifiers (`body if inner if outer`): both the inner and outer
    /// `If`/`UnlessNode` share the exact same start offset (the body's own
    /// start), since a modifier node's location begins at its body, not its
    /// keyword. Called PRE-order (before recursing into children) so the
    /// OUTER node is checked first — matching rubocop's real traversal order
    /// (outer's `on_if` fires before the nested inner one, and
    /// `ignore_node`/`part_of_ignored_node?` suppresses the inner's OFFENSE
    /// for that round). `multiline_if_mod_seen` reproduces that suppression:
    /// only the first (outermost) node visited at a given start offset gets
    /// an offense pushed. The FIX is pushed for every eligible node
    /// regardless — rubocop's own `expect_correction` loops the cop to a
    /// fixed point (`RuboCop::RSpec::ExpectOffense#expect_correction`'s
    /// `loop: true` default), and so does oxidecop's `apply_fixes_iter`;
    /// each round's overlap-guard in `apply_fixes` applies only ONE of the
    /// overlapping (same-start) fixes per pass (whichever was pushed first —
    /// here, the outer's, matching rubocop's round 1), leaving the untouched
    /// inner "if inner" suffix attached as plain text to be picked up as a
    /// fresh top-level modifier on the NEXT round — converging to the same
    /// fully-nested `if outer\n  if inner\n    ...\n  end\nend` result
    /// rubocop reaches after 2 rounds of its own loop.
    pub(crate) fn check_multiline_if_modifier(
        &mut self,
        keyword: &str,
        node_loc: ruby_prism::Location,
        cond: ruby_prism::Node,
        body_stmts: Option<ruby_prism::StatementsNode>,
    ) {
        const COP: &str = "Style/MultilineIfModifier";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body_stmts.and_then(|s| s.body().iter().next()) else { return };
        let body_loc = body.location();
        // `node.body.multiline?` under rubocop's PRISM translation: a block
        // body's range starts at the SELECTOR, not the receiver chain — so
        // `a\n .bar { .. } unless c` (braces on one line) is single-line to
        // rubocop even though the chain spans two.
        let body_start = body
            .as_call_node()
            .filter(|c| c.block().and_then(|b| b.as_block_node()).is_some())
            .and_then(|c| c.message_loc().map(|m| m.start_offset()))
            .unwrap_or_else(|| body_loc.start_offset());
        let start_line = self.idx.loc(body_start).0;
        let end_line = self.idx.loc(body_loc.end_offset().saturating_sub(1)).0;
        if start_line == end_line {
            return; // not `node.body.multiline?`
        }

        let node_start = node_loc.start_offset();
        let node_end = node_loc.end_offset();
        if self.multiline_if_mod_seen.insert(node_start) {
            self.push(
                node_start,
                COP,
                true,
                format!("Favor a normal {keyword}-statement over a modifier clause in a multiline statement."),
            );
        }

        let cond_src = self.node_src(&cond).to_vec();
        let body_src = self.node_src(&body).to_vec();
        let offset_len = self.idx.loc(node_start).1 - 1;
        let width = self.cfg.int("Layout/IndentationWidth", "Width");
        let indentation_len = offset_len + width;

        let mut replacement = Vec::new();
        replacement.extend_from_slice(keyword.as_bytes());
        replacement.push(b' ');
        replacement.extend_from_slice(&cond_src);
        replacement.push(b'\n');
        replacement.extend(reindent_body(&body_src, offset_len, indentation_len));
        replacement.push(b'\n');
        replacement.extend(std::iter::repeat_n(b' ', offset_len));
        replacement.extend_from_slice(b"end");

        self.fixes.push((node_start, node_end, replacement));
    }
}

/// Ports `MultilineIfModifier#indented_body`: prepend `node`'s own column of
/// spaces to `body`'s raw source (rubocop's `body.source` starts flush — the
/// FIRST line has no leading whitespace of its own, since the body node's
/// range begins right at its first non-space character), then replace each
/// line's leading `offset_len`-byte whitespace run with `indentation_len`
/// spaces. Ruby's `/^\s{#{offset_len}}/` with `offset_len == 0` matches a
/// zero-width prefix unconditionally — i.e. every line just gets
/// `indentation_len` spaces PREPENDED, whatever its existing indentation.
fn reindent_body(body_src: &[u8], offset_len: usize, indentation_len: usize) -> Vec<u8> {
    let mut body_source = vec![b' '; offset_len];
    body_source.extend_from_slice(body_src);
    let mut out = Vec::new();
    for line in body_source.split_inclusive(|&b| b == b'\n') {
        if line == b"\n" {
            out.extend_from_slice(line);
            continue;
        }
        if line.len() >= offset_len && line[..offset_len].iter().all(|&b| b == b' ') {
            out.extend(std::iter::repeat_n(b' ', indentation_len));
            out.extend_from_slice(&line[offset_len..]);
        } else {
            out.extend_from_slice(line);
        }
    }
    out
}
impl<'a> super::Cops<'a> {
    /// Style/ClassVars — assignments to class variables (both direct and via
    /// `class_variable_set`). Reads and gets are allowed; message interpolates
    /// the variable name.
    pub(crate) fn check_class_vars(&mut self, class_var: &[u8], name_start: usize) {
        const COP: &str = "Style/ClassVars";
        if !self.on(COP) {
            return;
        }
        let class_var = String::from_utf8_lossy(class_var);
        let msg = format!("Replace class var {} with a class instance var.", class_var);
        self.push(name_start, COP, false, msg);
    }

    pub(crate) fn check_class_variable_set(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/ClassVars";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"class_variable_set" {
            return;
        }
        if let Some(args) = node.arguments() {
            if let Some(first_arg) = args.arguments().first() {
                let arg_src = self.node_src(&first_arg).to_vec();
                self.check_class_vars(&arg_src, first_arg.location().start_offset());
            }
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Style/MinMax on an array literal (or bracket-less implicit array,
    /// e.g. the RHS of `bar = foo.min, foo.max`) — ports rubocop's
    /// `min_max_candidate` node-matcher applied to `on_array`:
    /// `(array (send [$_receiver !nil?] :min) (send [$_receiver !nil?] :max))`.
    /// The offense/replacement range is the array node's own `source_range`,
    /// which already excludes the brackets when `opening_loc` is absent.
    pub(crate) fn check_min_max_array(&mut self, node: &ruby_prism::ArrayNode) {
        if !self.on("Style/MinMax") {
            return;
        }
        let elements = node.elements();
        if elements.iter().count() != 2 {
            return;
        }
        let mut it = elements.iter();
        let first = it.next().unwrap();
        let last = it.next().unwrap();
        let l = node.location();
        self.check_min_max_pair(&first, &last, l.start_offset(), l.end_offset());
    }

    /// Style/MinMax on `return foo.min, foo.max` — rubocop aliases `on_return`
    /// to the same matcher (`{array return}` in the pattern), but the offense
    /// range there is `argument_range` (first arg's start .. last arg's end),
    /// NOT the return node's own source range (which would include `return`).
    pub(crate) fn check_min_max_return(&mut self, node: &ruby_prism::ReturnNode) {
        if !self.on("Style/MinMax") {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let arguments = args.arguments();
        if arguments.iter().count() != 2 {
            return;
        }
        let mut it = arguments.iter();
        let first = it.next().unwrap();
        let last = it.next().unwrap();
        let start = first.location().start_offset();
        let end = last.location().end_offset();
        self.check_min_max_pair(&first, &last, start, end);
    }

    /// Shared matcher body: `first`/`last` must be bare (no args, no block,
    /// not safe-navigation) `.min`/`.max` calls on an EXPLICIT and IDENTICAL
    /// receiver (compared by source bytes, like `Lint/DuplicateHashKey`).
    fn check_min_max_pair(&mut self, first: &ruby_prism::Node, last: &ruby_prism::Node, start: usize, end: usize) {
        const COP: &str = "Style/MinMax";
        let Some(first_call) = first.as_call_node() else { return };
        let Some(last_call) = last.as_call_node() else { return };
        if first_call.name().as_slice() != b"min" || last_call.name().as_slice() != b"max" {
            return;
        }
        if first_call.arguments().is_some() || last_call.arguments().is_some() {
            return;
        }
        if first_call.block().is_some() || last_call.block().is_some() {
            return;
        }
        if first_call.is_safe_navigation() || last_call.is_safe_navigation() {
            return;
        }
        let Some(recv1) = first_call.receiver() else { return };
        let Some(recv2) = last_call.receiver() else { return };
        let recv1_src = self.node_src(&recv1);
        if recv1_src != self.node_src(&recv2) {
            return;
        }
        let offender = String::from_utf8_lossy(&self.src[start..end]).into_owned();
        let receiver = String::from_utf8_lossy(recv1_src).into_owned();
        self.push(start, COP, true, format!("Use `{receiver}.minmax` instead of `{offender}`."));
        let mut replacement = recv1_src.to_vec();
        replacement.extend_from_slice(b".minmax");
        self.fixes.push((start, end, replacement));
    }
}

impl<'a> super::Cops<'a> {
    /// Style/TrailingMethodEndStatement — a multiline `def`/`def self.foo`
    /// whose closing `end` trails the body's last statement on the same
    /// line (`def foo\n  bar; end`). Ported verbatim from rubocop's
    /// `TrailingMethodEndStatement#trailing_end?` +
    /// `body_and_end_on_same_line?`:
    ///   - `node.endless?` / no `end` keyword at all → skip (handled by the
    ///     caller via `end_keyword_loc`/`equal_loc`, and defensively here);
    ///   - no body at all (`def no_op; end`) → skip;
    ///   - the whole `def ... end` node fits on one line (not
    ///     `node.multiline?`) → skip;
    ///   - the body's last line isn't the same as the `end` keyword's line
    ///     → skip (nothing trailing).
    /// Autocorrect ports `insert_before(node.loc.end, "\n" + ' ' *
    /// node.loc.keyword.column)`: break onto a new line indented to match
    /// the `def` keyword's own column, leaving any whitespace that used to
    /// separate the body from `end` as trailing whitespace on the body's
    /// line (see the `expect_correction` fixtures — a literal trailing
    /// space is expected there).
    pub(crate) fn check_trailing_method_end_statement(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/TrailingMethodEndStatement";
        if !self.on(COP) {
            return;
        }
        let Some(body) = node.body() else { return }; // `def no_op; end`
        let Some(end_loc) = node.end_keyword_loc() else { return }; // endless def
        let keyword = node.def_keyword_loc();
        let keyword_start = keyword.start_offset();
        let end_start = end_loc.start_offset();

        // `node.multiline?`: the whole def...end node spans more than one line.
        let start_line = self.idx.loc(keyword_start).0;
        let end_line = self.idx.loc(end_start).0;
        if start_line == end_line {
            return;
        }

        // `body_and_end_on_same_line?`: node.children.last (the body, since
        // rescue/ensure wrappers are themselves the body node in prism) ends
        // on the same line as the `end` keyword. A prism BeginNode (def with
        // rescue/ensure) extends through the def's own `end` keyword, unlike
        // whitequark's rescue/ensure wrapper nodes which stop at their last
        // clause's content — unwrap to the content end.
        let body_end = match body.as_begin_node() {
            Some(b) => begin_node_content_end(&b),
            None => body.location().end_offset(),
        };
        let body_last_line = self.idx.loc(body_end.saturating_sub(1)).0;
        if body_last_line != end_line {
            return;
        }

        self.push(end_start, COP, true, "Place the end statement of a multi-line method on its own line.");

        // `node.loc.keyword.column`: 0-based column of the `def` keyword.
        let keyword_col = self.idx.loc(keyword_start).1 - 1;
        let indent = " ".repeat(keyword_col);
        self.fixes.push((end_start, end_start, format!("\n{indent}").into_bytes()));
    }
}

/// Where a def-body BeginNode's *content* ends, mirroring whitequark's
/// rescue/ensure wrapper ranges: the ensure body if present, else the else
/// body, else the last rescue clause, else the plain statements. Empty
/// clauses fall back to their keyword, like whitequark.
fn begin_node_content_end(b: &ruby_prism::BeginNode) -> usize {
    if let Some(ens) = b.ensure_clause() {
        return match ens.statements() {
            Some(stmts) => stmts.location().end_offset(),
            None => ens.ensure_keyword_loc().end_offset(),
        };
    }
    if let Some(els) = b.else_clause() {
        return match els.statements() {
            Some(stmts) => stmts.location().end_offset(),
            None => els.else_keyword_loc().end_offset(),
        };
    }
    if let Some(mut resc) = b.rescue_clause() {
        while let Some(next) = resc.subsequent() {
            resc = next;
        }
        return match resc.statements() {
            Some(stmts) => stmts.location().end_offset(),
            None => resc.location().end_offset(),
        };
    }
    match b.statements() {
        Some(stmts) => stmts.location().end_offset(),
        None => b.location().end_offset(),
    }
}

impl<'a> super::Cops<'a> {
    /// Style/OptionalBooleanParameter: an optional POSITIONAL parameter whose
    /// default is a boolean literal (`def foo(bar = false)`) hides its
    /// meaning at call sites (`foo(true)`) — prefer a keyword argument
    /// (`def foo(bar: false)`). `AllowedMethods` (default:
    /// `respond_to_missing?`, whose boolean 3rd arg is dictated by Ruby's own
    /// dispatch protocol, not the author) exempts specific method names.
    /// Ports rubocop's `on_def`/`alias on_defs`: prism's `DefNode` already
    /// covers both `def foo` and `def self.foo`, so one hook suffices.
    pub(crate) fn check_optional_boolean_parameter(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/OptionalBooleanParameter";
        if !self.on(COP) {
            return;
        }
        if self.allowed(COP, node.name().as_slice()) {
            return;
        }
        let Some(params) = node.parameters() else { return };
        for param in params.optionals().iter() {
            let Some(opt) = param.as_optional_parameter_node() else { continue };
            let value = opt.value();
            if value.as_true_node().is_none() && value.as_false_node().is_none() {
                continue;
            }
            let name = opt.name().as_slice();
            let original = self.node_src(&param);
            let default_src = self.node_src(&value);
            let mut replacement = Vec::with_capacity(name.len() + 2 + default_src.len());
            replacement.extend_from_slice(name);
            replacement.extend_from_slice(b": ");
            replacement.extend_from_slice(default_src);
            let msg = format!(
                "Prefer keyword arguments for arguments with a boolean default value; \
                 use `{}` instead of `{}`.",
                String::from_utf8_lossy(&replacement),
                String::from_utf8_lossy(original),
            );
            self.push(param.location().start_offset(), COP, false, msg);
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/NestedTernaryOperator — Detects ternary operators nested
    /// inside other ternary operators. The offense is registered on the
    /// inner (nested) ternary, and the outer ternary is converted to an
    /// if/else/end block as the autocorrect.
    pub(crate) fn check_nested_ternary_operator(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/NestedTernaryOperator";
        if !self.on(COP) {
            return;
        }
        // Only process ternaries (no if_keyword_loc means it's a `?:` ternary)
        if node.if_keyword_loc().is_some() {
            return;
        }
        // Find all nested ternaries within this outer ternary (excluding the outer itself)
        let mut nested_ternaries = Vec::new();
        collect_nested_ternaries_excluding_root(&node.as_node(), &mut nested_ternaries, node.location().start_offset());

        // Report an offense for each nested ternary (avoiding duplicates)
        let mut has_new_offenses = false;
        for nested_offset in &nested_ternaries {
            if self.nested_ternary_reported.insert(*nested_offset) {
                self.push(
                    *nested_offset,
                    COP,
                    true,
                    "Ternary operators must not be nested. Prefer `if` or `else` constructs instead.".to_string(),
                );
                has_new_offenses = true;
            }
        }

        // Apply autocorrect to the outer ternary ONLY if this ternary's offenses are new.
        // This avoids double-correcting when nested ternaries are visited multiple times.
        if has_new_offenses {
            self.autocorrect_nested_ternary(node);
        }
    }

    fn autocorrect_nested_ternary(&mut self, node: &ruby_prism::IfNode) {
        let node_loc = node.location();
        let node_start = node_loc.start_offset();
        let node_end = node_loc.end_offset();

        // Get the offset of the node's first column (for indentation purposes)
        let (_, col) = self.idx.loc(node_start);
        let indent_len = col - 1;

        // Ensure this is actually a ternary (has a `?` keyword)
        if node.then_keyword_loc().is_none() {
            return;
        }

        // Get the condition source
        let cond_src = self.node_src(&node.predicate()).to_vec();

        // Get the then-branch source (between `?` and `:`)
        let then_branch_src = if let Some(stmts) = node.statements() {
            let stmts_src = self.node_src(&stmts.as_node());
            remove_surrounding_parens(stmts_src)
        } else {
            b"".to_vec()
        };

        // Get the else-branch source - need to extract just the value part without the else keyword
        let else_branch_src = if let Some(subseq) = node.subsequent() {
            // For ternary, subsequent is an ElseNode; we need the statements inside
            if let Some(else_node) = subseq.as_else_node() {
                if let Some(else_stmts) = else_node.statements() {
                    self.node_src(&else_stmts.as_node()).to_vec()
                } else {
                    b"".to_vec()
                }
            } else {
                // Fallback to the entire node if not an ElseNode
                self.node_src(&subseq).to_vec()
            }
        } else {
            b"".to_vec()
        };

        // Build the replacement: `if condition\nthen_branch\nelse\nelse_branch\nend`
        // We preserve the original indentation within branches and only add
        // indentation at the start of the else keyword.
        let mut replacement = b"if ".to_vec();
        replacement.extend_from_slice(&cond_src);
        replacement.push(b'\n');
        replacement.extend_from_slice(&then_branch_src);
        replacement.push(b'\n');
        replacement.extend(std::iter::repeat_n(b' ', indent_len));
        replacement.extend_from_slice(b"else\n");
        replacement.extend_from_slice(&else_branch_src);
        replacement.push(b'\n');
        replacement.extend(std::iter::repeat_n(b' ', indent_len));
        replacement.extend_from_slice(b"end");

        self.fixes.push((node_start, node_end, replacement));
    }
}

/// Collect all nested ternary operators within the given node, excluding the root.
/// A ternary is an IfNode with no if_keyword_loc.
fn collect_nested_ternaries_excluding_root(node: &ruby_prism::Node, out: &mut Vec<usize>, root_offset: usize) {
    struct Finder<'a> {
        out: &'a mut Vec<usize>,
        root_offset: usize,
        is_root: bool,
    }
    impl<'pr, 'a> ruby_prism::Visit<'pr> for Finder<'a> {
        fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
            let offset = node.location().start_offset();
            // Check if this is a ternary (no if_keyword_loc)
            if node.if_keyword_loc().is_none() {
                // Skip the root node on the first visit
                if offset != self.root_offset || !self.is_root {
                    self.out.push(offset);
                }
                self.is_root = false;
            }
            ruby_prism::visit_if_node(self, node);
        }
    }
    let mut f = Finder { out, root_offset, is_root: true };
    use ruby_prism::Visit;
    f.visit(node);
}

/// Remove surrounding parentheses from source code if present.
fn remove_surrounding_parens(src: &[u8]) -> Vec<u8> {
    if src.len() >= 2 && src[0] == b'(' && src[src.len() - 1] == b')' {
        src[1..src.len() - 1].to_vec()
    } else {
        src.to_vec()
    }
}
impl<'a> super::Cops<'a> {
    /// Style/RedundantSortBy — Identifies places where `sort_by { ... }`
    /// can be replaced by `sort`. Detects three patterns:
    /// 1. Regular block: `sort_by { |x| x }`
    /// 2. Numbered block: `sort_by { _1 }`
    /// 3. It-block: `sort_by { it }`
    pub(crate) fn check_redundant_sort_by(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/RedundantSortBy";
        if !self.on(COP) {
            return;
        }

        // Check if this is a `.sort_by` call
        if node.name().as_slice() != b"sort_by" {
            return;
        }

        // Must have a block
        let Some(block_node) = node.block().and_then(|b| b.as_block_node()) else {
            return;
        };

        // Check the block parameters and body
        let Some(message) = self.redundant_sort_by_pattern(&block_node) else {
            return;
        };

        // The offense range spans from the selector start to the block's end
        let selector_start = node.message_loc().map(|l| l.start_offset()).unwrap_or_else(|| node.location().start_offset());
        let block_end = block_node.location().end_offset();

        self.push(selector_start, COP, true, message);
        self.fixes.push((selector_start, block_end, b"sort".to_vec()));
    }

    /// Check if a block is a redundant sort_by pattern.
    /// Returns the message string if redundant, None otherwise.
    fn redundant_sort_by_pattern(&self, block: &ruby_prism::BlockNode) -> Option<String> {
        let params = block.parameters();
        let body = block.body()?;

        // Get the block body statements
        let stmts = body.as_statements_node()?;
        let mut body_iter = stmts.body().iter();
        let first_stmt = body_iter.next()?;

        // Body must be a single statement
        if body_iter.next().is_some() {
            return None;
        }

        // Check for regular block pattern: { |x| x }
        if let Some(bp) = params.as_ref().and_then(|p| p.as_block_parameters_node()) {
            // Must have exactly one required parameter
            let params_node = bp.parameters()?;
            let requireds: Vec<_> = params_node.requireds().iter().collect();
            if requireds.len() != 1
                || params_node.optionals().iter().count() > 0
                || params_node.rest().is_some()
                || params_node.posts().iter().count() > 0
                || params_node.keywords().iter().count() > 0
                || params_node.keyword_rest().is_some()
                || params_node.block().is_some()
            {
                return None;
            }

            let param_name = requireds[0].as_required_parameter_node()?.name();
            let param_name_str = String::from_utf8_lossy(param_name.as_slice());

            // Check if body is just a reference to that parameter
            let lvar = first_stmt.as_local_variable_read_node()?;
            if lvar.name().as_slice() == param_name.as_slice() {
                return Some(format!("Use `sort` instead of `sort_by {{ |{}| {} }}`.", param_name_str, param_name_str));
            }
            return None;
        }

        // Check for numbered block pattern: { _1 }
        if let Some(_np) = params.as_ref().and_then(|p| p.as_numbered_parameters_node()) {
            // Check if body is just `_1`
            let lvar = first_stmt.as_local_variable_read_node()?;
            if lvar.name().as_slice() == b"_1" {
                return Some("Use `sort` instead of `sort_by { _1 }`.".to_string());
            }
            return None;
        }

        // Check for it-block pattern: { it }
        if let Some(_ip) = params.as_ref().and_then(|p| p.as_it_parameters_node()) {
            // For it-blocks, the body is an ItLocalVariableReadNode (not LocalVariableReadNode)
            if first_stmt.as_it_local_variable_read_node().is_some() {
                return Some("Use `sort` instead of `sort_by { it }`.".to_string());
            }
            return None;
        }

        None
    }
}


impl<'a> super::Cops<'a> {
    /// Style/RedundantPercentQ — `%q(...)`/`%Q(...)` where a plain `'...'`/
    /// `"..."` literal would do just as well.
    ///
    /// rubocop routes this through `on_str`/`on_dstr`: a plain (non-
    /// interpolated) literal is a `str` node and is checked as-is; one with
    /// real interpolation is a `dstr` node checked as a whole (its inner
    /// parts have no delimiters of their own, so rubocop's
    /// `string_literal?` guard — `loc?(:begin) && loc?(:end)` — skips them).
    /// `%q` itself never interpolates, so it is always the plain-`str` case.
    /// Both routes funnel into the same text-level check over the node's raw
    /// source, which is what `check_redundant_percent_q` below implements.
    pub(crate) fn check_redundant_percent_q_str(&mut self, node: &ruby_prism::StringNode) {
        if !self.on("Style/RedundantPercentQ") {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let Some(close) = node.closing_loc() else { return };
        let l = node.location();
        self.check_redundant_percent_q(l.start_offset(), l.end_offset(), open, close, true);
    }

    /// Same check, routed for a `dstr` node (a `%Q(...)` with real `#{}`
    /// interpolation). Inner parts lack their own opening/closing delimiters
    /// and bail out via the same guard, matching rubocop's `string_literal?`.
    pub(crate) fn check_redundant_percent_q_dstr(&mut self, node: &ruby_prism::InterpolatedStringNode) {
        if !self.on("Style/RedundantPercentQ") {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let Some(close) = node.closing_loc() else { return };
        let l = node.location();
        self.check_redundant_percent_q(l.start_offset(), l.end_offset(), open, close, false);
    }

    /// The shared body of rubocop's `check` — a pure text-level analysis over
    /// `node.source` (`start..end`), plus the `loc.begin`/`loc.end`
    /// (`open`/`close`) delimiter ranges the autocorrect rewrites.
    /// `is_str_type` mirrors rubocop's `node.str_type?` (true only when the
    /// checked node is the plain, non-interpolated literal itself).
    fn check_redundant_percent_q(
        &mut self,
        start: usize,
        end: usize,
        open: ruby_prism::Location,
        close: ruby_prism::Location,
        is_str_type: bool,
    ) {
        const COP: &str = "Style/RedundantPercentQ";
        let src = &self.src[start..end];
        if !(src.starts_with(b"%q") || src.starts_with(b"%Q")) {
            return;
        }
        // `interpolated_quotes?` — a literal `'` AND `"` anywhere in the
        // source means quoting either way needs escapes, so both variants
        // are left alone regardless of anything else.
        if src.contains(&b'\'') && src.contains(&b'"') {
            return;
        }
        let is_capital = src[1] == b'Q';
        let allowed = if is_capital { acceptable_capital_q(src, is_str_type) } else { acceptable_q(src) };
        if allowed {
            return;
        }
        let (q_type, extra): (&str, &str) = if is_capital {
            ("%Q", ", or for dynamic strings that contain double quotes")
        } else {
            ("%q", "")
        };
        self.push(
            start,
            COP,
            true,
            format!(
                "Use `{q_type}` only for strings that contain both single quotes and double quotes{extra}."
            ),
        );
        // Delimiter choice — rubocop's `/\A%Q[^"]+\z|'/.match?(node.source)`:
        // a `%Q` with no `"` anywhere after it, or any literal `'` anywhere,
        // picks `"`; otherwise `'`.
        let percent_q_no_dquote = src.starts_with(b"%Q") && src.len() > 2 && !src[2..].contains(&b'"');
        let delimiter: u8 = if percent_q_no_dquote || src.contains(&b'\'') { b'"' } else { b'\'' };
        self.fixes.push((open.start_offset(), open.end_offset(), vec![delimiter]));
        self.fixes.push((close.start_offset(), close.end_offset(), vec![delimiter]));
    }
}

/// rubocop's `STRING_INTERPOLATION_REGEXP` (`/#\{.+\}/`) — a purely textual
/// heuristic over the literal's raw source (`%q` never actually
/// interpolates, but the check still runs over its source text as if it
/// might). `.` doesn't cross a newline, so the search for the closing `}`
/// stops at line boundaries, same as the Ruby regex without `/m`.
fn looks_interpolated(src: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < src.len() {
        if src[i] == b'#' && src[i + 1] == b'{' {
            let mut j = i + 2;
            while j < src.len() && src[j] != b'\n' {
                if src[j] == b'}' && j > i + 2 {
                    return true;
                }
                j += 1;
            }
        }
        i += 1;
    }
    false
}

/// rubocop's `acceptable_q?` — a `%q` is left alone when it has
/// interpolation-like syntax alongside a single quote (requoting with `"`
/// would activate real interpolation), or when it already contains a "real"
/// escape (`\X` for `X != \\`, e.g. `\'`) that a bare requote would corrupt.
fn acceptable_q(src: &[u8]) -> bool {
    if looks_interpolated(src) && src.contains(&b'\'') {
        return true;
    }
    // `src.scan(/\\./).any? { |m| m =~ /\\[^\\]/ }` — non-overlapping
    // backslash+char pairs scanned left to right; a pair whose second byte
    // isn't itself a backslash is a "real" (non-backslash) escape. `.`
    // doesn't match `\n`, so a backslash immediately before a newline (or at
    // the very end of the source) never starts a match.
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\' {
            match src.get(i + 1) {
                Some(b'\n') | None => i += 1,
                Some(b'\\') => i += 2,
                Some(_) => return true,
            }
        } else {
            i += 1;
        }
    }
    false
}

/// rubocop's `acceptable_capital_q?` — a `%Q` is left alone when it contains
/// a literal `"` and either looks interpolated, or (for a genuinely static,
/// `str`-typed node) its content couldn't be re-quoted as single-quoted
/// without a `double_quotes_required?` escape anyway.
fn acceptable_capital_q(src: &[u8], is_str_type: bool) -> bool {
    src.contains(&b'"') && (looks_interpolated(src) || (is_str_type && double_quotes_required(src)))
}
impl<'a> super::Cops<'a> {
    /// Style/EachForSimpleLoop — Checks for loops which iterate a constant
    /// number of times, using a `Range` literal and `#each`. This can be done
    /// more readably using `Integer#times`. Only applies if the block takes no
    /// parameters.
    pub(crate) fn check_each_for_simple_loop(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/EachForSimpleLoop";
        if !self.on(COP) {
            return;
        }

        // Check if this is a call to .each
        if node.name().as_slice() != b"each" {
            return;
        }

        // Get the receiver and check if it's a range
        let Some(receiver) = node.receiver() else {
            return;
        };

        // Try to get a range node (may be wrapped in ParenthesesNode or BeginNode)
        let range_node = if let Some(rn) = receiver.as_range_node() {
            rn
        } else if let Some(pn) = receiver.as_parentheses_node() {
            let Some(pn_body) = pn.body() else { return };
            let Some(pn_stmts) = pn_body.as_statements_node() else { return };
            let mut iter = pn_stmts.body().iter();
            let Some(first) = iter.next() else { return };
            // Only match if there's a single statement in the parentheses
            if iter.next().is_some() {
                return;
            }
            match first.as_range_node() {
                Some(rn) => rn,
                None => return,
            }
        } else if let Some(bn) = receiver.as_begin_node() {
            let Some(bn_stmts) = bn.statements() else { return };
            let mut iter = bn_stmts.body().iter();
            let Some(first) = iter.next() else { return };
            // Only match if there's a single statement in the begin block
            if iter.next().is_some() {
                return;
            }
            match first.as_range_node() {
                Some(rn) => rn,
                None => return,
            }
        } else {
            return;
        };

        // Extract start and end values from the range
        let Some(left) = range_node.left() else { return };
        let Some(right) = range_node.right() else { return };

        // Parse integer values
        let int_of = |n: &ruby_prism::Node| -> Option<i64> {
            let l = n.location();
            std::str::from_utf8(&self.src[l.start_offset()..l.end_offset()])
                .ok()?
                .replace('_', "")
                .parse()
                .ok()
        };

        let Some(start_val) = int_of(&left) else { return };
        let Some(end_val) = int_of(&right) else { return };

        // Check if block has no parameters
        let has_block = node.block().and_then(|b| b.as_block_node()).is_some();
        if !has_block {
            return;
        }

        let block = node.block().and_then(|b| b.as_block_node()).unwrap();

        // Block must have no parameters (empty args)
        let params_empty = if let Some(params) = block.parameters() {
            // Check if it's empty block parameters (pipes present but no params)
            if let Some(bp) = params.as_block_parameters_node() {
                bp.parameters().is_none() && bp.locals().iter().next().is_none()
            } else {
                // No block parameters node means no pipes at all
                false
            }
        } else {
            // No parameters node means no pipes at all - this is what we want
            true
        };

        if !params_empty {
            return;
        }

        // Calculate the number of iterations
        let is_exclusive = range_node.operator_loc().as_slice() == b"...";
        let count = if is_exclusive {
            end_val - start_val
        } else {
            end_val - start_val + 1
        };

        // Push the offense
        let message = "Use `Integer#times` for a simple loop which iterates a fixed number of times.";
        self.push(node.location().start_offset(), COP, true, message);

        // Add the autocorrection
        // Replace from the start of the call to the start of the block with "N.times "
        let block_start = block.location().start_offset();
        let replacement = format!("{}.times ", count);
        self.fixes.push((
            node.location().start_offset(),
            block_start,
            replacement.into_bytes(),
        ));
    }
}


impl<'a> super::Cops<'a> {
    /// Style/ComparableClamp — `if x < low; low; elsif high < x; high; else; x; end`
    /// (any of rubocop's 8 syntactic variants — `<`/`>`, either operand order,
    /// either branch testing the min-bound or max-bound first) → `x.clamp(low, high)`.
    /// `minimum_target_ruby_version 2.4` gates the whole cop (both checks below).
    ///
    /// rubocop's `on_if` fires per if-node, including each nested `elsif`
    /// IfNode independently (an `elsif` chain is just nested `if`s in the
    /// `else` slot, and the AST walker visits each one) — so does this: it's
    /// called from `visit_if_node` for every `if`/`elsif`, and the pattern
    /// match only succeeds at the ONE node whose own then-branch, whose
    /// subsequent's then-branch, and whose subsequent's else all line up
    /// with the two comparisons (verified empirically: a 3-way chain like
    /// `if cond; …; elsif x>high; high; elsif low>x; low; else; x; end` only
    /// matches at the `elsif x>high` node, not the outer `if cond` — its own
    /// condition isn't a comparison — nor the inner `elsif low>x` — its own
    /// `else` is the terminal value directly, not a nested if).
    ///
    /// Offense anchor: `node.location().start_offset()`. Verified against
    /// live `Prism.parse` output that an `elsif` IfNode's raw location START
    /// is the `elsif` keyword itself (unlike its raw END, which — naively —
    /// runs through the chain's shared `end`; see the autocorrect comment
    /// below for why that matters there but not here).
    pub(crate) fn check_comparable_clamp_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/ComparableClamp";
        if !self.on(COP) || self.cfg.target_ruby() < 2.4 {
            return;
        }
        let Some(m) = clamp_if_match(node, self.src) else { return };
        let prefer = format!(
            "{}.clamp({}, {})",
            clamp_parenthesize(&m.else_body, self.src),
            String::from_utf8_lossy(m.min_src),
            String::from_utf8_lossy(m.max_src),
        );
        let start = node.location().start_offset();
        self.push(start, COP, true, format!("Use `{prefer}` instead of `if/elsif/else`."));

        let is_elsif = node.if_keyword_loc().is_some_and(|k| k.as_slice() == b"elsif");
        if is_elsif {
            // rubocop's Prism→Parser translation (`visit_if_node`) omits the
            // `end` token for an `elsif` IfNode's own `loc.expression` — it
            // ends at the tail of the chain's final `else` VALUE instead
            // (recursively, regardless of chain depth), never swallowing the
            // shared `end` keyword. `else_body`'s own end offset IS that
            // tail, since it's the innermost value already.
            // rubocop issues this as two separate Corrector ops
            // (`insert_before` + `replace`, both anchored at `start`) — our
            // `Fix` model can't represent two edits sharing a start/end
            // boundary as non-overlapping, so they're folded into one
            // replacement spanning the same net range with the same net text.
            let (_, col) = self.idx.loc(start);
            let width = self.clamp_indentation_width();
            let indent = " ".repeat(col.saturating_sub(1) + width);
            let end = m.else_body.location().end_offset();
            self.fixes.push((start, end, format!("else\n{indent}{prefer}").into_bytes()));
        } else if let Some(end_kw) = node.end_keyword_loc() {
            self.fixes.push((start, end_kw.end_offset(), prefer.into_bytes()));
        }
    }

    /// rubocop's Alignment#configured_indentation_width: the cop's own
    /// `IndentationWidth` param if set, else `Layout/IndentationWidth`'s
    /// `Width` (schema default 2 — Style/ComparableClamp itself has no
    /// params, so this always falls through to the Layout default or an
    /// explicit user override of it).
    fn clamp_indentation_width(&self) -> usize {
        self.cfg
            .get("Style/ComparableClamp", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| self.cfg.int("Layout/IndentationWidth", "Width"))
    }

    /// Style/ComparableClamp — `[[x, low].max, high].min` (and the 3 other
    /// shapes: max/min swapped, and the wrapped pair on either side of the
    /// outer array). Never autocorrected: rubocop's own rationale is that a
    /// reversed `clamp` range raises `ArgumentError`, and a min/max chain
    /// built from arbitrary values can't be statically proven to be ordered.
    pub(crate) fn check_comparable_clamp_min_max(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/ComparableClamp";
        if !self.on(COP) || self.cfg.target_ruby() < 2.4 {
            return;
        }
        let outer = node.name();
        let outer = outer.as_slice();
        if outer != b"min" && outer != b"max" {
            return;
        }
        if !clamp_zero_args(node) {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let Some(arr) = recv.as_array_node() else { return };
        let elems: Vec<ruby_prism::Node> = arr.elements().iter().collect();
        if elems.len() != 2 {
            return;
        }
        let inner_name: &[u8] = if outer == b"min" { b"max" } else { b"min" };
        let is_inner_match = |n: &ruby_prism::Node| -> bool {
            let Some(call) = n.as_call_node() else { return false };
            if call.name().as_slice() != inner_name || !clamp_zero_args(&call) {
                return false;
            }
            let Some(inner_arr) = call.receiver().and_then(|r| r.as_array_node()) else { return false };
            inner_arr.elements().iter().count() == 2
        };
        if is_inner_match(&elems[0]) || is_inner_match(&elems[1]) {
            self.push(node.location().start_offset(), COP, false, "Use `Comparable#clamp` instead.");
        }
    }
}

/// A `min`/`max` (or comparison) call with no explicit arguments — `.min`
/// and `.min()` are structurally identical (zero args either way); a call
/// with a block is STILL zero-arg (Prism keeps a call's block on the same
/// `CallNode`, unlike whitequark's separate wrapping `block` node, but that
/// wrapping happens ABOVE this send in rubocop's translated tree either way
/// — the send node's own arg arity is unaffected either representation).
fn clamp_zero_args(call: &ruby_prism::CallNode) -> bool {
    match call.arguments() {
        None => true,
        Some(a) => a.arguments().iter().next().is_none(),
    }
}

/// The `(if_body, elsif_body, else_body)` triple + the min/max values,
/// once `if_elsif_else_condition?` + rubocop's `on_if` body logic both
/// succeed. `else_body` is kept as a NODE (not just its source text) because
/// `parenthesize_if_needed` inspects its type.
struct ClampIfMatch<'a> {
    else_body: ruby_prism::Node<'a>,
    min_src: &'a [u8],
    max_src: &'a [u8],
}

/// Ports rubocop's `if_elsif_else_condition?` node-pattern (8 alternatives)
/// PLUS the `on_if` body's own cross-checks (`min_condition?`) into one pass:
/// the def_node_matcher's `_x`/`_min`/`_max` metavariables are unified here
/// by comparing SOURCE TEXT across occurrences — the same approach this
/// codebase already uses for structural node equality (see
/// `check_duplicate_elsif_condition`), and equivalent to whitequark's
/// location-blind `Node#==` for the simple identifier/expression operands
/// these patterns compare (two occurrences of the same source text are the
/// same AST shape either way; the only gap is byte-identical-but-reformatted
/// duplicates, e.g. `a+b` vs `a + b`, which none of rubocop's own examples
/// exercise).
fn clamp_if_match<'a>(node: &ruby_prism::IfNode<'a>, src: &'a [u8]) -> Option<ClampIfMatch<'a>> {
    let if_body = clamp_single_value(node.statements())?;
    let inner = node.subsequent()?.as_if_node()?;
    let elsif_body = clamp_single_value(inner.statements())?;
    let else_node = inner.subsequent()?.as_else_node()?;
    let else_body = clamp_single_value(else_node.statements())?;

    let if_body_src = clamp_node_src(&if_body, src);
    let elsif_body_src = clamp_node_src(&elsif_body, src);
    let else_body_src = clamp_node_src(&else_body, src);

    let (is_min1, x1, bound1) = clamp_classify_branch(&node.predicate(), if_body_src, src)?;
    let (is_min2, x2, bound2) = clamp_classify_branch(&inner.predicate(), elsif_body_src, src)?;

    if is_min1 == is_min2 || x1 != x2 || x1 != else_body_src {
        return None;
    }
    let (min_src, max_src) = if is_min1 { (bound1, bound2) } else { (bound2, bound1) };
    Some(ClampIfMatch { else_body, min_src, max_src })
}

/// A branch body normalized to rubocop-ast's `if_branch`/`else_branch`
/// shape: the sole statement when there's exactly one (rubocop only wraps
/// 2+ statements in a `begin` node — a shape none of the fixture's examples
/// use, and one whose `.source` could never equal a bare comparison operand
/// anyway, so treating it as a non-match is behaviorally equivalent).
fn clamp_single_value<'a>(stmts: Option<ruby_prism::StatementsNode<'a>>) -> Option<ruby_prism::Node<'a>> {
    let body: Vec<ruby_prism::Node<'a>> = stmts?.body().iter().collect();
    (body.len() == 1).then(|| body.into_iter().next().unwrap())
}

/// Normalizes a `<`/`>` comparison send into its two operands in
/// "smaller < larger" semantic order, regardless of surface spelling
/// (`a < b` and `b > a` both mean "a is smaller"). `None` for anything else
/// (wrong method name, wrong arity, no receiver).
fn clamp_comparison_operands<'a>(node: &ruby_prism::Node<'a>) -> Option<(ruby_prism::Node<'a>, ruby_prism::Node<'a>)> {
    let call = node.as_call_node()?;
    let is_lt = match call.name().as_slice() {
        b"<" => true,
        b">" => false,
        _ => return None,
    };
    let recv = call.receiver()?;
    let args: Vec<ruby_prism::Node<'a>> =
        call.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
    if args.len() != 1 {
        return None;
    }
    let rhs = args.into_iter().next().unwrap();
    Some(if is_lt { (recv, rhs) } else { (rhs, recv) })
}

/// rubocop's `min_condition?`, generalized to classify EITHER branch (not
/// just the outer `if`'s): does `cond` (a `<`/`>` comparison) relate `body`'s
/// value as the min-bound or the max-bound? Returns
/// `(is_min, x_source, bound_source)` — `is_min` true when `cond` has the
/// "`body` is the value `x` must not fall below" shape (`x < body` /
/// `body > x`), false for "`x` must not exceed `body`" (`body < x` / `x >
/// body`). `x_source` is whichever operand ISN'T `body`, for the caller's
/// cross-branch unification.
fn clamp_classify_branch<'a>(
    cond: &ruby_prism::Node<'a>,
    body_src: &'a [u8],
    src: &'a [u8],
) -> Option<(bool, &'a [u8], &'a [u8])> {
    let (smaller, larger) = clamp_comparison_operands(cond)?;
    let small_src = clamp_node_src(&smaller, src);
    let large_src = clamp_node_src(&larger, src);
    if body_src == large_src {
        Some((true, small_src, large_src))
    } else if body_src == small_src {
        Some((false, large_src, small_src))
    } else {
        None
    }
}

fn clamp_node_src<'a>(n: &ruby_prism::Node<'a>, src: &'a [u8]) -> &'a [u8] {
    let l = n.location();
    &src[l.start_offset()..l.end_offset()]
}

/// rubocop's `parenthesize_if_needed`: `a + b` must become `(a + b).clamp(…)`,
/// not `a + b.clamp(…)` (which parses as `a + (b.clamp(…))`).
fn clamp_parenthesize(node: &ruby_prism::Node, src: &[u8]) -> String {
    let text = String::from_utf8_lossy(clamp_node_src(node, src)).into_owned();
    if clamp_needs_parens(node) {
        format!("({text})")
    } else {
        text
    }
}

/// `node.type?(:and, :or, :if, :range) || node.assignment? ||
/// (node.send_type? && (node.operator_method? || node.unary_operation?))`.
/// `:if` covers both prism `IfNode` and `UnlessNode` (rubocop's Prism→Parser
/// translation maps both to the whitequark `:if` type, swapping branches for
/// `unless`). `:range` covers both `..`/`...` (prism's `RangeNode` either
/// way; whitequark's `irange`/`erange` both group under `Node#range_type?`).
fn clamp_needs_parens(node: &ruby_prism::Node) -> bool {
    if node.as_and_node().is_some()
        || node.as_or_node().is_some()
        || node.as_if_node().is_some()
        || node.as_unless_node().is_some()
        || node.as_range_node().is_some()
        || clamp_is_assignment_like(node)
    {
        return true;
    }
    node.as_call_node().is_some_and(|c| clamp_is_operator_method(c.name().as_slice()))
}

/// rubocop-ast's `Node#assignment?` (`ASSIGNMENTS` = equals- + shorthand-
/// assignment types), over Prism's per-variable-kind write node families.
fn clamp_is_assignment_like(node: &ruby_prism::Node) -> bool {
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

/// rubocop-ast's `MethodIdentifierPredicates::OPERATOR_METHODS`.
const CLAMP_OPERATOR_METHODS: &[&[u8]] = &[
    b"|", b"^", b"&", b"<=>", b"==", b"===", b"=~", b">", b">=", b"<", b"<=", b"<<", b">>", b"+", b"-", b"*",
    b"/", b"%", b"**", b"~", b"+@", b"-@", b"!@", b"~@", b"[]", b"[]=", b"!", b"!=", b"!~", b"`",
];
fn clamp_is_operator_method(name: &[u8]) -> bool {
    CLAMP_OPERATOR_METHODS.contains(&name)
}

impl<'a> super::Cops<'a> {
    /// Style/RedundantFreeze — checks for uses of `Object#freeze` on immutable objects.
    pub(crate) fn check_redundant_freeze(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/RedundantFreeze";
        if !self.on(COP) || node.name().as_slice() != b"freeze" {
            return;
        }

        let Some(receiver) = node.receiver() else { return };

        // Check if the receiver is an immutable object
        if !self.is_immutable_literal_or_operation(&receiver) {
            return;
        }

        // Report offense and add fix
        self.push(
            node.location().start_offset(),
            COP,
            true,
            "Do not freeze immutable objects, as freezing them has no effect.",
        );

        // Fix: remove `.freeze` (remove the dot and selector)
        if let (Some(dot), Some(msg)) = (node.call_operator_loc(), node.message_loc()) {
            self.fixes.push((dot.start_offset(), msg.end_offset(), vec![]));
        }
    }

    /// Check if the node is an immutable literal, frozen string, or operation that produces immutable
    fn is_immutable_literal_or_operation(&self, node: &ruby_prism::Node) -> bool {
        // Check the node after unwrapping begin nodes
        self.check_immutable_recursive(node)
    }

    /// Recursively check if a node is immutable, stripping parentheses/begin nodes
    fn check_immutable_recursive(&self, node: &ruby_prism::Node) -> bool {
        // Unwrap parentheses nodes
        if let Some(paren) = node.as_parentheses_node() {
            if let Some(body) = paren.body() {
                // ParenthesesNode body is typically a StatementsNode, so unwrap it
                if let Some(stmts) = body.as_statements_node() {
                    if let Some(first) = stmts.body().iter().next() {
                        return self.check_immutable_recursive(&first);
                    }
                } else {
                    // If body is not a StatementsNode, recurse on it directly
                    return self.check_immutable_recursive(&body);
                }
            }
        }

        // Unwrap begin nodes (from rescue/ensure blocks)
        if let Some(begin) = node.as_begin_node() {
            if let Some(stmts) = begin.statements() {
                if let Some(first) = stmts.body().iter().next() {
                    return self.check_immutable_recursive(&first);
                }
            }
        }

        // Check basic immutable literals
        if node.as_integer_node().is_some()
            || node.as_float_node().is_some()
            || node.as_symbol_node().is_some()
            || node.as_interpolated_symbol_node().is_some()
            || node.as_true_node().is_some()
            || node.as_false_node().is_some()
            || node.as_nil_node().is_some()
            || node.as_rational_node().is_some()
            || node.as_imaginary_node().is_some()
        {
            return true;
        }

        // Check for frozen string literal
        if node.as_string_node().is_some() && self.frozen_string_literal_enabled() {
            return true;
        }

        // Regexp and Range literals are frozen in Ruby 3.0+
        if self.cfg.target_ruby() >= 3.0 {
            if node.as_regular_expression_node().is_some() {
                return true;
            }
            if node.as_range_node().is_some() {
                return true;
            }
        }

        // Check operations that produce immutable objects
        self.operation_produces_immutable(node)
    }

    /// Check if frozen strings are enabled (FrozenStringLiteral mixin)
    fn frozen_string_literal_enabled(&self) -> bool {
        match self.fsl_enabled {
            Some(true) => true,
            Some(false) => false,
            None => {
                // Check StringLiteralsFrozenByDefault setting
                match self.cfg.param("AllCops", "StringLiteralsFrozenByDefault") {
                    Some(v) => v == "true",
                    None => false,
                }
            }
        }
    }

    /// Check if the receiver expression produces an immutable object
    fn operation_produces_immutable(&self, node: &ruby_prism::Node) -> bool {
        // (send {float int} {:+ :- :* :** :/ :% :<<} _)
        if self.is_numeric_arithmetic(node) {
            return true;
        }

        // (send !{(str _) array} {:+ :- :* :** :/ :%} {float int})
        if self.is_reverse_numeric_arithmetic(node) {
            return true;
        }

        // (send _ {:== :=== :!= :<= :>= :< :>} _)
        if self.is_comparison(node) {
            return true;
        }

        // (send _ {:count :length :size} ...)
        if self.is_collection_size_method(node) {
            return true;
        }

        false
    }

    /// Check for (send {float int} {:+ :- :* :** :/ :% :<<} _)
    fn is_numeric_arithmetic(&self, node: &ruby_prism::Node) -> bool {
        let Some(call) = node.as_call_node() else { return false };
        let Some(receiver) = call.receiver() else { return false };

        // Receiver must be float or int
        let receiver_is_numeric = receiver.as_float_node().is_some() || receiver.as_integer_node().is_some();
        if !receiver_is_numeric {
            return false;
        }

        // Method must be an arithmetic operator
        matches!(
            call.name().as_slice(),
            b"+" | b"-" | b"*" | b"**" | b"/" | b"%" | b"<<"
        )
    }

    /// Check for (send !{(str _) array} {:+ :- :* :** :/ :%} {float int})
    fn is_reverse_numeric_arithmetic(&self, node: &ruby_prism::Node) -> bool {
        let Some(call) = node.as_call_node() else { return false };
        let Some(receiver) = call.receiver() else { return false };

        // Receiver must NOT be a string or array
        if receiver.as_string_node().is_some() || receiver.as_array_node().is_some() {
            return false;
        }

        // Method must be an arithmetic operator (excluding <<)
        if !matches!(call.name().as_slice(), b"+" | b"-" | b"*" | b"**" | b"/" | b"%") {
            return false;
        }

        // There must be exactly one argument and it must be float or int
        let Some(args) = call.arguments() else { return false };
        let args_vec: Vec<_> = args.arguments().iter().collect();
        if args_vec.len() != 1 {
            return false;
        }

        args_vec[0].as_float_node().is_some() || args_vec[0].as_integer_node().is_some()
    }

    /// Check for (send _ {:== :=== :!= :<= :>= :< :>} _)
    fn is_comparison(&self, node: &ruby_prism::Node) -> bool {
        let Some(call) = node.as_call_node() else { return false };

        // Must have a receiver
        call.receiver().is_some()
            && matches!(
                call.name().as_slice(),
                b"==" | b"===" | b"!=" | b"<=" | b">=" | b"<" | b">"
            )
    }

    /// Check for (send _ {:count :length :size} ...)
    fn is_collection_size_method(&self, node: &ruby_prism::Node) -> bool {
        let Some(call) = node.as_call_node() else { return false };

        matches!(call.name().as_slice(), b"count" | b"length" | b"size")
    }
}

impl<'a> super::Cops<'a> {
    /// Style/NilLambda — a lambda/proc/`Proc.new` whose body always
    /// evaluates to a bare `nil` (explicitly, or via `return`/`next`/`break
    /// nil`) can be replaced by an empty lambda/proc. Ports upstream's
    /// `nil_return?` node-pattern (`{ ({return next break} nil) (nil) }`)
    /// applied to `node.body`, gated by `Node#lambda_or_proc?`.
    ///
    /// Two prism shapes cover the whitequark `on_block(node)` single
    /// callback: `lambda`/`proc`/`Proc.new` with a literal `{ }`/`do...end`
    /// block is a `CallNode` whose `.block()` is a `BlockNode` (handled
    /// here, from `visit_call_node`); stabby `-> { }`/`->(x) { }` is its own
    /// `LambdaNode` with no enclosing call at all (handled by
    /// `check_nil_lambda_stabby`, from `visit_lambda_node`).
    pub(crate) fn check_nil_lambda_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/NilLambda";
        if !self.on(COP) {
            return;
        }
        let Some(kind) = nil_lambda_kind(node) else { return };
        let Some(block) = node.block().and_then(|b| b.as_block_node()) else { return };
        let Some(body_loc) = nil_lambda_body_loc(block.body()) else { return };
        let single_line = !self.src[block.opening_loc().start_offset()..block.closing_loc().end_offset()]
            .contains(&b'\n');
        self.emit_nil_lambda(node.location().start_offset(), kind, body_loc, single_line);
    }

    /// Stabby lambda literal (`-> { }`) — always the `lambda` kind, per
    /// `BlockNode#lambda?` (`send_node.method?(:lambda)`, which is what
    /// whitequork's parser translation gives every `->` literal).
    pub(crate) fn check_nil_lambda_stabby(&mut self, node: &ruby_prism::LambdaNode) {
        const COP: &str = "Style/NilLambda";
        if !self.on(COP) {
            return;
        }
        let Some(body_loc) = nil_lambda_body_loc(node.body()) else { return };
        let single_line =
            !self.src[node.opening_loc().start_offset()..node.closing_loc().end_offset()].contains(&b'\n');
        self.emit_nil_lambda(node.location().start_offset(), "lambda", body_loc, single_line);
    }

    /// Shared offense + autocorrect: `RangeHelp#range_with_surrounding_space`
    /// (single-line blocks — strip the body plus immediately adjacent
    /// horizontal whitespace, then any newlines) or
    /// `range_by_whole_lines(..., include_final_newline: true)` (multiline —
    /// strip the body's WHOLE line, trailing newline included).
    fn emit_nil_lambda(
        &mut self,
        start: usize,
        kind: &str,
        body_loc: ruby_prism::Location,
        single_line: bool,
    ) {
        const COP: &str = "Style/NilLambda";
        self.push(start, COP, true, format!("Use an empty {kind} instead of always returning nil."));
        let (b_start, b_end) = (body_loc.start_offset(), body_loc.end_offset());
        let (rs, re) = if single_line {
            nil_lambda_surrounding_space(self.src, b_start, b_end)
        } else {
            nil_lambda_whole_lines(self.src, b_start, b_end)
        };
        self.fixes.push((rs, re, Vec::new()));
    }
}

/// Which kind of nil-lambda-eligible call `node` is — `lambda`/`proc` (bare,
/// no receiver) or `Proc.new`/`::Proc.new` — or `None` if it's neither.
/// Mirrors upstream's combined `Node#lambda_or_proc?` as applied to a
/// `CallNode` already known to carry a literal block, keeping the two kinds
/// (for the message text) distinct instead of collapsing to one bool.
fn nil_lambda_kind(call: &ruby_prism::CallNode) -> Option<&'static str> {
    let name = call.name().as_slice();
    if call.receiver().is_none() && name == b"lambda" {
        return Some("lambda");
    }
    if call.receiver().is_none() && name == b"proc" {
        return Some("proc");
    }
    if name == b"new" && call.receiver().is_some_and(|r| nil_lambda_is_proc_const(&r)) {
        return Some("proc");
    }
    None
}

/// Upstream's `#global_const?(:Proc)`: a bare `Proc` constant, or one
/// anchored at the top level (`::Proc`).
fn nil_lambda_is_proc_const(node: &ruby_prism::Node) -> bool {
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == b"Proc";
    }
    if let Some(c) = node.as_constant_path_node() {
        return c.parent().is_none() && c.name().is_some_and(|n| n.as_slice() == b"Proc");
    }
    false
}

/// Upstream's `nil_return?` node-pattern (`{ ({return next break} nil) (nil) }`)
/// applied to the block/lambda body — `None` for an empty body, a
/// multi-statement body (whitequork wraps those in a `begin` node the
/// pattern never matches), or any other single-statement shape; `Some` of
/// the SINGLE offending statement's own source range otherwise (never the
/// body wrapper's range — matches `node.body.source_range` when `node.body`
/// is that lone statement, unwrapped).
fn nil_lambda_body_loc(body: Option<ruby_prism::Node>) -> Option<ruby_prism::Location> {
    let stmts = body?.as_statements_node()?;
    let items: Vec<_> = stmts.body().iter().collect();
    if items.len() != 1 {
        return None;
    }
    nil_lambda_is_nil_return(&items[0]).then(|| items[0].location())
}

/// Does `node` match `({return next break} nil)` or bare `(nil)`?
fn nil_lambda_is_nil_return(node: &ruby_prism::Node) -> bool {
    if node.as_nil_node().is_some() {
        return true;
    }
    let args = if let Some(r) = node.as_return_node() {
        r.arguments()
    } else if let Some(n) = node.as_next_node() {
        n.arguments()
    } else if let Some(b) = node.as_break_node() {
        b.arguments()
    } else {
        return false;
    };
    let Some(args) = args else { return false };
    let items: Vec<_> = args.arguments().iter().collect();
    items.len() == 1 && items[0].as_nil_node().is_some()
}

/// `RangeHelp#range_with_surrounding_space(range)` at its default
/// (`side: :both, newlines: true, whitespace: false`) — extend both ends
/// over immediately adjacent horizontal whitespace, then over newlines (but
/// not any further generic whitespace).
fn nil_lambda_surrounding_space(src: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {
    while start > 0 && matches!(src[start - 1], b' ' | b'\t') {
        start -= 1;
    }
    while start > 0 && src[start - 1] == b'\n' {
        start -= 1;
    }
    while end < src.len() && matches!(src[end], b' ' | b'\t') {
        end += 1;
    }
    while end < src.len() && src[end] == b'\n' {
        end += 1;
    }
    (start, end)
}

/// `RangeHelp#range_by_whole_lines(range, include_final_newline: true)` —
/// expand to the full line(s) the range spans, plus the trailing newline.
fn nil_lambda_whole_lines(src: &[u8], start: usize, end: usize) -> (usize, usize) {
    let mut s = start;
    while s > 0 && src[s - 1] != b'\n' {
        s -= 1;
    }
    let mut e = end;
    while e < src.len() && src[e] != b'\n' {
        e += 1;
    }
    if e < src.len() {
        e += 1;
    }
    (s, e)
}
use ruby_prism::Visit;

// Style/RedundantSelf ------------------------------------------------------
//
// Ported from rubocop's on_send/on_def/on_block/on_lvasgn/on_masgn/on_or_asgn
// /on_and_asgn/on_op_asgn/on_if/on_while/on_until/on_in_pattern family. The
// upstream cop keys a `Hash.new { |h, k| h[k] = [] }.compare_by_identity`
// (`@local_variables_scopes`) by AST node identity: `add_scope` assigns the
// SAME Array object to every descendant of a def/block, so a name pushed via
// any descendant's entry is visible to the whole scope from that point on;
// un-scoped (top-level) nodes each get their own private Array. We port this
// as:
//   - `rs_scope_stack`: one shared `Rc<RefCell<Vec<name>>>` per active
//     def/block scope (see `visit_def_node`/`visit_block_node` in mod.rs) —
//     pushing a name mutates the object every descendant already points at.
//   - `rs_narrow`: (byte-span, name) pairs recorded once, up front, for
//     un-scoped top-level exemptions — span containment stands in for
//     "is the candidate call an each_ancestor of the node the identity-keyed
//     entry belonged to", which holds for any well-formed AST nesting.
//   - `rs_block_stack`: (is a plain — not numbered/`it` — block; has NO
//     `|...|` delimiters at all) per enclosing block, for `it_method_in_block?`.
//
// Two prism-vs-whitequark shape differences make several upstream guards
// (`allow_self`, the `node.parent&.mlhs_type?` check) unreachable dead code
// here, for free:
//   - `self.foo ||= x` / `&&=` / `+=` and masgn attr targets (`a, self.b = c,
//     d`) are fused into their own write/target node kinds (CallOrWriteNode,
//     CallAndWriteNode, CallOperatorWriteNode, CallTargetNode) — there is no
//     separate reachable `CallNode` standing in for "self.foo" the way
//     whitequark's translated AST exposes one as `on_or_asgn`'s `.lhs`, so
//     `visit_call_node` (our `on_send`) never even sees a candidate there.
//   - a plain single write (`self.foo = bar`) IS a genuine `CallNode` (name
//     `foo=`), but carries prism's own `equal_loc` — exactly upstream's
//     `setter_method?` (`loc?(:operator)`) signal — so it's excluded via
//     `rs_regular_method_call` the same way, no extra plumbing needed.
impl<'a> Cops<'a> {
    /// `on_send`: `node.self_receiver? && regular_method_call?(node)` plus
    /// the scope/kernel-method/`it`-in-block exemptions.
    pub(crate) fn check_redundant_self(&mut self, node: &ruby_prism::CallNode) {
        if !self.on("Style/RedundantSelf") {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if recv.as_self_node().is_none() {
            return;
        }
        if !self.rs_regular_method_call(node) {
            return;
        }
        if self.rs_it_method_in_block(node) {
            return;
        }
        let name = node.name().as_slice();
        if RS_KERNEL_METHODS.contains(&name) {
            return;
        }
        if self.rs_scope_allows(node.location().start_offset(), name) {
            return;
        }
        let recv_loc = recv.location();
        self.push(recv_loc.start_offset(), "Style/RedundantSelf", true, "Redundant `self` detected.");
        // Two separate removals, exactly like upstream's
        // `corrector.remove(node.receiver)` + `corrector.remove(node.loc.dot)`
        // — NOT one merged span, so stray whitespace between `self` and `.`
        // (`self . foo`) is left untouched just like the real cop.
        self.fixes.push((recv_loc.start_offset(), recv_loc.end_offset(), Vec::new()));
        if let Some(dot) = node.call_operator_loc() {
            self.fixes.push((dot.start_offset(), dot.end_offset(), Vec::new()));
        }
    }

    /// `regular_method_call?`: not an operator, a keyword-named method, a
    /// camelCase (constant-look-alike) call, a setter, or `self.()`.
    fn rs_regular_method_call(&self, node: &ruby_prism::CallNode) -> bool {
        let name = node.name().as_slice();
        if RS_OPERATOR_METHODS.contains(&name) {
            return false;
        }
        if RS_KEYWORDS.contains(&name) {
            return false;
        }
        if name.first().is_some_and(u8::is_ascii_uppercase) {
            return false;
        }
        // `setter_method?` (`loc?(:operator)`) — prism's `equal_loc` is set
        // exactly for the `x.y = z` assignment-sugar shape.
        if node.equal_loc().is_some() {
            return false;
        }
        // `implicit_call?`: `self.()`, not `self.call`.
        if name == b"call" && node.message_loc().is_none() {
            return false;
        }
        true
    }

    /// `it_method_in_block?`: bare `self.it` inside the nearest enclosing
    /// PLAIN block (skipping `_1`/`it`-numbered ones, matching upstream's
    /// `each_ancestor(:block)` type filter) that has no `|...|` at all.
    fn rs_it_method_in_block(&self, node: &ruby_prism::CallNode) -> bool {
        if node.name().as_slice() != b"it" {
            return false;
        }
        let Some(&(_, no_delims)) = self.rs_block_stack.iter().rev().find(|(is_plain, _)| *is_plain) else {
            return false;
        };
        if !no_delims {
            return false;
        }
        let args_empty = node.arguments().is_none_or(|a| a.arguments().iter().count() == 0);
        args_empty && node.block().is_none()
    }

    /// Does the current scope (if any) or a recorded top-level narrow
    /// exemption make `self.<name>` at `off` redundant?
    fn rs_scope_allows(&self, off: usize, name: &[u8]) -> bool {
        if let Some(top) = self.rs_scope_stack.last() {
            if top.borrow().iter().any(|n| n.as_slice() == name) {
                return true;
            }
        }
        self.rs_narrow.iter().any(|(s, e, n)| off >= *s && off < *e && n.as_slice() == name)
    }

    /// `add_lhs_to_local_variables_scopes`: if `rhs` is itself a call with
    /// arguments, the name disambiguates each ARGUMENT subtree; otherwise it
    /// disambiguates `rhs` itself (and, transitively, everything nested
    /// inside it).
    pub(crate) fn rs_lvar_write(&mut self, lhs: &[u8], rhs: &ruby_prism::Node) {
        if let Some(call) = rhs.as_call_node() {
            if let Some(args) = call.arguments() {
                let arglist: Vec<_> = args.arguments().iter().collect();
                if !arglist.is_empty() {
                    for a in &arglist {
                        let l = a.location();
                        self.rs_push_name(l.start_offset(), l.end_offset(), lhs);
                    }
                    return;
                }
            }
        }
        let l = rhs.location();
        self.rs_push_name(l.start_offset(), l.end_offset(), lhs);
    }

    /// Record `name` as disambiguating `self.name` — scope-wide if a
    /// def/block scope is active (shared Array semantics), otherwise narrowly
    /// scoped to `[start, end)` (this node's own un-scoped identity entry).
    pub(crate) fn rs_push_name(&mut self, start: usize, end: usize, name: &[u8]) {
        if let Some(top) = self.rs_scope_stack.last() {
            top.borrow_mut().push(name.to_vec());
        } else {
            self.rs_narrow.push((start, end, name.to_vec()));
        }
    }

    /// `on_if`/`on_while`/`on_until` (prism gives `unless` its own node, so
    /// `visit_unless_node` calls this too): `node.each_descendant(:lvasgn,
    /// :masgn)`, exempting `node.condition` for each name found ANYWHERE in
    /// the whole conditional (predicate, body, elsif/else) — order-agnostic,
    /// mirroring upstream's full pre-scan before any children are visited.
    pub(crate) fn rs_scan_conditional(&mut self, whole: &ruby_prism::Node, predicate: &ruby_prism::Node) {
        if !self.on("Style/RedundantSelf") {
            return;
        }
        let mut c = RsAssignCollector { assign_names: Vec::new() };
        c.visit(whole);
        if c.assign_names.is_empty() {
            return;
        }
        let l = predicate.location();
        let (s, e) = (l.start_offset(), l.end_offset());
        for name in c.assign_names {
            self.rs_push_name(s, e, &name);
        }
    }

    /// `on_in_pattern`/`add_match_var_scopes`: every match-var bound by this
    /// `in` clause's PATTERN disambiguates `self.x` anywhere in the whole
    /// clause (pattern, guard, and body — `node`'s own span, matching
    /// upstream's `@local_variables_scopes[in_pattern_node]`). Scanning only
    /// `node.pattern()` (not `node.statements()`, the executed body) matters:
    /// prism reuses `LocalVariableTargetNode` for BOTH pattern bindings and
    /// ordinary masgn targets, and only the former count as upstream's
    /// `:match_var` node type.
    pub(crate) fn check_redundant_self_in_pattern(&mut self, node: &ruby_prism::InNode) {
        if !self.on("Style/RedundantSelf") {
            return;
        }
        let mut c = RsMatchVarCollector { names: Vec::new() };
        c.visit(&node.pattern());
        if c.names.is_empty() {
            return;
        }
        let l = node.location();
        let (s, e) = (l.start_offset(), l.end_offset());
        for name in c.names {
            self.rs_push_name(s, e, &name);
        }
    }
}

/// Style/RedundantSelf: names introduced by a parameter list (def OR block —
/// `BlockParametersNode` wraps the identical `ParametersNode` shape).
/// Recurses into destructured `(a, b)` parameters (`MultiTargetNode`, reused
/// by prism for both masgn targets and destructured params) the way
/// upstream's `on_argument` recurses via `on_args` for an `mlhs_type?` node.
pub(crate) fn rs_params_of(params: &ruby_prism::ParametersNode) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    for n in params.requireds().iter() {
        rs_collect_param_name(&mut names, &n);
    }
    for n in params.optionals().iter() {
        rs_collect_param_name(&mut names, &n);
    }
    if let Some(r) = params.rest() {
        rs_collect_param_name(&mut names, &r);
    }
    for n in params.posts().iter() {
        rs_collect_param_name(&mut names, &n);
    }
    for n in params.keywords().iter() {
        rs_collect_param_name(&mut names, &n);
    }
    if let Some(kr) = params.keyword_rest() {
        rs_collect_param_name(&mut names, &kr);
    }
    if let Some(b) = params.block() {
        if let Some(nm) = b.name() {
            names.push(nm.as_slice().to_vec());
        }
    }
    names
}

fn rs_collect_param_name(names: &mut Vec<Vec<u8>>, n: &ruby_prism::Node) {
    if let Some(p) = n.as_required_parameter_node() {
        names.push(p.name().as_slice().to_vec());
    } else if let Some(p) = n.as_optional_parameter_node() {
        names.push(p.name().as_slice().to_vec());
    } else if let Some(p) = n.as_rest_parameter_node() {
        if let Some(nm) = p.name() {
            names.push(nm.as_slice().to_vec());
        }
    } else if let Some(p) = n.as_keyword_rest_parameter_node() {
        if let Some(nm) = p.name() {
            names.push(nm.as_slice().to_vec());
        }
    } else if let Some(p) = n.as_required_keyword_parameter_node() {
        names.push(p.name().as_slice().to_vec());
    } else if let Some(p) = n.as_optional_keyword_parameter_node() {
        names.push(p.name().as_slice().to_vec());
    } else if let Some(p) = n.as_multi_target_node() {
        for c in p.lefts().iter() {
            rs_collect_param_name(names, &c);
        }
        if let Some(r) = p.rest() {
            rs_collect_param_name(names, &r);
        }
        for c in p.rights().iter() {
            rs_collect_param_name(names, &c);
        }
    } else if let Some(p) = n.as_splat_node() {
        if let Some(e) = p.expression() {
            rs_collect_param_name(names, &e);
        }
    }
    // `NoKeywordsParameterNode` (`**nil`) and anything else carries no name.
}

/// Style/RedundantSelf: collects `LocalVariableWriteNode`/`MultiWriteNode`
/// names anywhere in an if/unless/while/until subtree — upstream's
/// `node.each_descendant(:lvasgn, :masgn)`.
struct RsAssignCollector {
    assign_names: Vec<Vec<u8>>,
}
impl<'pr> ruby_prism::Visit<'pr> for RsAssignCollector {
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        self.assign_names.push(node.name().as_slice().to_vec());
        ruby_prism::visit_local_variable_write_node(self, node);
    }
    fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
        for t in node.lefts().iter().chain(node.rights().iter()) {
            if let Some(lv) = t.as_local_variable_target_node() {
                self.assign_names.push(lv.name().as_slice().to_vec());
            }
        }
        ruby_prism::visit_multi_write_node(self, node);
    }
}

/// Style/RedundantSelf: collects `LocalVariableTargetNode` ("match_var" in
/// whitequark) names within a `case/in` pattern.
struct RsMatchVarCollector {
    names: Vec<Vec<u8>>,
}
impl<'pr> ruby_prism::Visit<'pr> for RsMatchVarCollector {
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        self.names.push(node.name().as_slice().to_vec());
    }
}

/// `RedundantSelf::KEYWORDS` — verbatim.
const RS_KEYWORDS: &[&[u8]] = &[
    b"alias", b"and", b"begin", b"break", b"case", b"class", b"def", b"defined?", b"do",
    b"else", b"elsif", b"end", b"ensure", b"false", b"for", b"if", b"in", b"module",
    b"next", b"nil", b"not", b"or", b"redo", b"rescue", b"retry", b"return", b"self",
    b"super", b"then", b"true", b"undef", b"unless", b"until", b"when", b"while",
    b"yield", b"__FILE__", b"__LINE__", b"__ENCODING__",
];

/// `RuboCop::AST::Node::MethodIdentifierPredicates::OPERATOR_METHODS`.
const RS_OPERATOR_METHODS: &[&[u8]] = &[
    b"|", b"^", b"&", b"<=>", b"==", b"===", b"=~", b">", b">=", b"<", b"<=", b"<<", b">>",
    b"+", b"-", b"*", b"/", b"%", b"**", b"~", b"+@", b"-@", b"!@", b"~@", b"[]", b"[]=",
    b"!", b"!=", b"!~", b"`",
];

/// `RedundantSelf::KERNEL_METHODS = Kernel.methods(false)` under ruby 3.4.1
/// (the interpreter rubocop 1.88.0 runs on) — includes some camelCase names
/// (`Array`, `Complex`, ...) that `rs_regular_method_call`'s camel-case guard
/// would already have excluded first; kept for fidelity with the source list.
const RS_KERNEL_METHODS: &[&[u8]] = &[
    b"Array", b"Complex", b"Float", b"Hash", b"Integer", b"Rational", b"String",
    b"__callee__", b"__dir__", b"__method__", b"`", b"abort", b"at_exit", b"autoload",
    b"autoload?", b"binding", b"block_given?", b"caller", b"caller_locations", b"catch",
    b"eval", b"exec", b"exit", b"exit!", b"fail", b"fork", b"format", b"gets",
    b"global_variables", b"iterator?", b"lambda", b"load", b"local_variables", b"loop",
    b"open", b"p", b"print", b"printf", b"proc", b"putc", b"puts", b"raise", b"rand",
    b"readline", b"readlines", b"require", b"require_relative", b"select",
    b"set_trace_func", b"sleep", b"spawn", b"sprintf", b"srand", b"syscall", b"system",
    b"test", b"throw", b"trace_var", b"trap", b"untrace_var", b"warn",
];

impl<'a> super::Cops<'a> {
    /// Style/StabbyLambdaParentheses — checks for parentheses around stabby
    /// lambda arguments. Two styles: `require_parentheses` (default) requires
    /// parentheses around non-empty parameter lists; `require_no_parentheses`
    /// forbids them.
    ///
    /// Ported from rubocop's `StabbyLambdaParentheses` cop using
    /// `ConfigurableEnforcedStyle` mixin.
    pub(crate) fn check_stabby_lambda_parentheses(&mut self, node: &ruby_prism::LambdaNode<'_>) {
        const COP: &str = "Style/StabbyLambdaParentheses";
        if !self.on(COP) {
            return;
        }

        // Only process if there are parameters
        let Some(params) = node.parameters() else { return };
        let Some(bp) = params.as_block_parameters_node() else { return };

        // Skip if parameters node is empty (no actual parameters)
        if bp.parameters().is_none() && bp.locals().iter().next().is_none() {
            return;
        }

        // Determine the style: default is "require_parentheses"
        let enforce_parentheses = self
            .cfg
            .get(COP, "EnforcedStyle")
            .map(|v| v != "require_no_parentheses")
            .unwrap_or(true);

        // Check if parentheses are present
        let has_parens = bp.opening_loc().is_some();

        // Determine if we should flag this
        let should_flag = if enforce_parentheses {
            !has_parens // Missing parentheses when require_parentheses
        } else {
            has_parens // Has parentheses when require_no_parentheses
        };

        if !should_flag {
            return;
        }

        // Get the location of the entire parameters node
        let params_loc = bp.location();
        let offense_start = params_loc.start_offset();

        // Determine message based on style
        let msg = if enforce_parentheses {
            "Wrap stabby lambda arguments with parentheses."
        } else {
            "Do not wrap stabby lambda arguments with parentheses."
        };

        self.push(offense_start, COP, true, msg);

        // Generate the fix
        if enforce_parentheses {
            // Add parentheses around the parameters
            let params_end = params_loc.end_offset();
            self.fixes.push((offense_start, offense_start, b"(".to_vec()));
            self.fixes.push((params_end, params_end, b")".to_vec()));
        } else {
            // Remove parentheses
            let open_loc = bp.opening_loc().unwrap();
            let close_loc = bp.closing_loc().unwrap();
            let open_start = open_loc.start_offset();
            let close_end = close_loc.end_offset();

            self.fixes.push((open_start, open_loc.end_offset(), Vec::new()));
            self.fixes.push((close_loc.start_offset(), close_end, Vec::new()));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/BlockComments — disallow `=begin`/`=end` document comments in
    /// favor of `#`-prefixed line comments. rubocop iterates
    /// `processed_source.comments` and flags every `comment.document?` (a
    /// prism `EmbDocComment`); rather than threading a comment-kind tag
    /// through `self.comments`, we lean on the fact that only an embedded
    /// doc comment's raw text can start with the literal `=begin` — an
    /// ordinary `#` comment never does.
    ///
    /// Autocorrect (`parts`/`eq_end_part` in the source) splits the comment
    /// into three byte ranges and rewrites them independently:
    ///   - `eq_begin` = the leading `"=begin\n"` (removed)
    ///   - `eq_end`   = the trailing `"=end"` line (removed)
    ///   - `contents` = everything between them, reindented with `# ` via
    ///     `block_comment_reindent` below (verbatim port of the cop's three
    ///     chained `gsub`s), then substituted in place.
    /// An empty `contents` (bare `=begin`/`=end` with nothing between) is
    /// left untouched by the replace step, so the whole block simply
    /// vanishes.
    pub(crate) fn check_block_comments(&mut self) {
        const COP: &str = "Style/BlockComments";
        if !self.on(COP) {
            return;
        }

        // "=begin\n".len()
        const BEGIN_LEN: usize = 7;
        // "\n=end".len() — used to size the trailing chunk when the comment's
        // own text ends in a newline (the overwhelmingly common case: there
        // is more source, or a final trailing newline, after `=end`).
        const END_LEN: usize = 5;

        for &(_line, start, end) in self.comments {
            if !self.src[start..end].starts_with(b"=begin") {
                continue;
            }

            self.push(start, COP, true, "Do not use block comments.");

            let eq_begin_end = (start + BEGIN_LEN).min(end);

            let text = &self.src[start..end];
            let eq_end_begin = if text.last() == Some(&b'\n') {
                end.saturating_sub(END_LEN)
            } else {
                // Comment is the literal last bytes of the file (no trailing
                // newline at all) — rubocop's own `chomp`-based branch hits
                // here too, though on a whitequark-padded buffer; prism
                // gives us the raw span, so we fall back to just the bare
                // `"=end"` (4 bytes) with no assumed padding.
                end.saturating_sub(4)
            }
            .max(eq_begin_end);

            if eq_end_begin > eq_begin_end {
                let contents = String::from_utf8_lossy(&self.src[eq_begin_end..eq_end_begin]).into_owned();
                let replacement = block_comment_reindent(&contents);
                self.fixes.push((eq_begin_end, eq_end_begin, replacement.into_bytes()));
            }

            self.fixes.push((start, eq_begin_end, Vec::new()));
            self.fixes.push((eq_end_begin, end, Vec::new()));
        }
    }
}

/// Verbatim port of `BlockComments#parts`' content transform:
/// `contents.source.gsub(/\A/, '# ').gsub("\n\n", "\n#\n").gsub(/\n(?=[^#])/, "\n# ")`
fn block_comment_reindent(s: &str) -> String {
    // gsub(/\A/, '# ') — prefix the very start of the string.
    let prefixed = format!("# {s}");
    // gsub("\n\n", "\n#\n") — literal, non-overlapping, left-to-right.
    let doubled = prefixed.replace("\n\n", "\n#\n");
    // gsub(/\n(?=[^#])/, "\n# ") — every `\n` followed by a non-`#` char
    // (a `\n` with nothing after it, i.e. at the very end of the string,
    // never matches the lookahead).
    let chars: Vec<char> = doubled.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(doubled.len());
    for (i, &c) in chars.iter().enumerate() {
        out.push(c);
        if c == '\n' && i + 1 < n && chars[i + 1] != '#' {
            out.push('#');
            out.push(' ');
        }
    }
    out
}

impl<'a> super::Cops<'a> {
    /// Style/GlobalStdStream — `STDIN`/`STDOUT`/`STDERR` → `$stdin`/`$stdout`/
    /// `$stderr`. Called from `visit_constant_read_node` for a bare
    /// constant, and from `visit_constant_path_node` only when
    /// `node.parent().is_none()` (a `::`-rooted constant with no further
    /// namespace, e.g. `::STDOUT`). Any deeper namespacing (`Foo::STDOUT`,
    /// `::Foo::STDOUT`, `foo::STDOUT`) is always a `ConstantPathNode` with
    /// `parent().is_some()`, so neither call site ever reaches this
    /// function for it — that structural split (prism gives `::STDOUT` a
    /// `parent: None` directly, instead of whitequark's explicit `cbase`
    /// child two levels down for deeper paths) stands in for upstream's
    /// `namespaced?` guard without needing to walk a `cbase` chain.
    pub(crate) fn check_global_std_stream(&mut self, name: &[u8], start: usize, end: usize) {
        const COP: &str = "Style/GlobalStdStream";
        if !self.on(COP) {
            return;
        }
        let gvar_name: &[u8] = match name {
            b"STDIN" => b"$stdin",
            b"STDOUT" => b"$stdout",
            b"STDERR" => b"$stderr",
            _ => return,
        };
        // upstream's `const_to_gvar_assignment?` exemption — see
        // `check_global_std_stream_gvasgn`.
        if self.gss_gvasgn_skip.contains(&start) {
            return;
        }
        self.push(
            start,
            COP,
            true,
            format!(
                "Use `{}` instead of `{}`.",
                String::from_utf8_lossy(gvar_name),
                String::from_utf8_lossy(name)
            ),
        );
        self.fixes.push((start, end, gvar_name.to_vec()));
    }

    /// Style/GlobalStdStream — upstream's `const_to_gvar_assignment?`
    /// node-pattern match `(gvasgn %1 (const nil? _))`: a plain
    /// `$stdout = STDOUT`-style assignment (bare `ConstantReadNode` value,
    /// matching gvar name) is exempt from the offense. Only a bare
    /// `ConstantReadNode` value ever qualifies — a `::`-rooted
    /// `ConstantPathNode` value (e.g. `$stdin = ::STDIN`) has a non-nil
    /// `cbase` namespace in whitequark terms, fails the pattern's
    /// `(const nil? _)` guard, and is NOT exempt (confirmed against live
    /// rubocop 1.88.0: `$stdin = ::STDIN` DOES register an offense).
    /// Called eagerly from `visit_global_variable_write_node` before it
    /// descends into `node.value()`, so `gss_gvasgn_skip` is already
    /// populated by the time the constant itself is visited.
    pub(crate) fn check_global_std_stream_gvasgn(&mut self, gvar_name: &[u8], value: &ruby_prism::Node) {
        if !self.on("Style/GlobalStdStream") {
            return;
        }
        let Some(c) = value.as_constant_read_node() else { return };
        let expected: &[u8] = match c.name().as_slice() {
            b"STDIN" => b"$stdin",
            b"STDOUT" => b"$stdout",
            b"STDERR" => b"$stderr",
            _ => return,
        };
        if expected == gvar_name {
            self.gss_gvasgn_skip.insert(c.location().start_offset());
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/EmptyElse — flags a redundant `else`-clause that's either
    /// completely empty or contains only the literal `nil`, gated by
    /// `EnforcedStyle` (`empty`/`nil`/`both`, default `both`) and
    /// `AllowComments` (default `false`). Ported from rubocop's
    /// `Style::EmptyElse` (`include OnNormalIfUnless, ConfigurableEnforcedStyle`).
    ///
    /// Prism quirk vs whitequark: an `if`/`elsif`/`else` chain is nested
    /// `IfNode`s linked via `subsequent()`, just like whitequark's nested
    /// `:if` nodes reached through `else_branch` — BUT unlike whitequark,
    /// prism gives EVERY level (each `elsif`, not just the outermost `if`)
    /// its own `end_keyword_loc` pointing at the real trailing `end`. Ruby's
    /// `base_node` climbs ancestors purely to find a node whose `loc.end`
    /// is actually set (whitequark's nested elsif nodes lack one); that
    /// climb is unnecessary here; any level's `end_keyword_loc` already
    /// points at the same, real `end`. So instead of visiting (and
    /// re-deriving the chain from) every nested elsif independently like
    /// upstream's `on_if` does, we fire once from the genuine top of the
    /// chain (`if_keyword_loc` == "if", never "elsif") and walk `subsequent()`
    /// down to the terminal branch ourselves — equivalent in outcome (only
    /// the deepest level's immediate else-branch can ever be empty/nil,
    /// exactly as upstream's per-level `empty_check`/`nil_check` guards
    /// only fire there) without needing ancestor-climbing machinery.
    pub(crate) fn check_empty_else_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/EmptyElse";
        if !self.on(COP) {
            return;
        }
        // `end_keyword_loc` is None for both a ternary (`a ? b : c`, no
        // keyword either) and modifier-form (`body if cond`, keyword but no
        // `end`) — matches upstream's `node.modifier_form? || node.ternary?`
        // guard in one shot. The `if_keyword_loc().as_slice() != "if"` guard
        // only lets the true top of the chain proceed (an `elsif` is visited
        // separately by the traversal but must not re-walk/re-report here).
        let Some(end_kw) = node.end_keyword_loc() else { return };
        let Some(kw) = node.if_keyword_loc() else { return };
        if kw.as_slice() != b"if" {
            return;
        }
        let mut cur = node.subsequent();
        let else_node = loop {
            match cur {
                None => return, // no `else` anywhere in the chain: nothing to flag
                Some(n) => match n.as_if_node() {
                    Some(elsif) => {
                        cur = elsif.subsequent();
                        continue;
                    }
                    None => break n.as_else_node().expect("if/unless subsequent is else or elsif"),
                },
            }
        };
        self.ee_check(COP, &else_node, end_kw.start_offset(), "if");
    }

    /// Style/EmptyElse for `unless ... else ... end` — prism's `UnlessNode`
    /// never chains into further branches, so this is the single-level case.
    pub(crate) fn check_empty_else_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/EmptyElse";
        if !self.on(COP) {
            return;
        }
        let Some(end_kw) = node.end_keyword_loc() else { return };
        let Some(else_node) = node.else_clause() else { return };
        self.ee_check(COP, &else_node, end_kw.start_offset(), "if");
    }

    /// Style/EmptyElse for `case ... else ... end` — rubocop's cop only
    /// hooks `on_case` (never `on_case_match`), so `case/in` pattern
    /// matching is intentionally out of scope, matching upstream exactly.
    pub(crate) fn check_empty_else_case(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Style/EmptyElse";
        if !self.on(COP) {
            return;
        }
        let Some(else_node) = node.else_clause() else { return };
        self.ee_check(COP, &else_node, node.end_keyword_loc().start_offset(), "case");
    }

    /// Shared detection + autocorrect for the three entry points above.
    /// `end_start` is the start offset of the enclosing statement's own
    /// (always-real, in prism) `end` keyword — the autocorrect removal's end
    /// boundary, verbatim from rubocop's
    /// `range_between(node.loc.else.begin_pos, base_node(node).loc.end.begin_pos)`.
    /// `kind` is whitequark's `node.type.to_s` equivalent ("if" for both
    /// `if` and `unless` — whitequark represents `unless` as an `:if` node
    /// too — "case" for `case`), used only to resolve `Style/MissingElse`'s
    /// cross-cop autocorrect veto below.
    fn ee_check(&mut self, cop: &'static str, else_node: &ruby_prism::ElseNode, end_start: usize, kind: &str) {
        let style = self.cfg.enforced_style(cop);
        let empty_style = style == "empty" || style == "both";
        let nil_style = style == "nil" || style == "both";
        let stmts = else_node.statements();
        let is_empty = stmts.is_none();
        let is_nil_only = stmts.as_ref().is_some_and(|s| {
            s.body().len() == 1 && s.body().first().is_some_and(|n| n.as_nil_node().is_some())
        });
        if !(empty_style && is_empty) && !(nil_style && is_nil_only) {
            return;
        }
        let else_kw = else_node.else_keyword_loc();
        // `comment_in_else?`: rubocop's `contains_comment?` treats the range
        // as an INCLUSIVE line span (`range.line..range.last_line`), from the
        // `else` keyword's line through the enclosing `end`'s line.
        let start_line = self.idx.loc(else_kw.start_offset()).0;
        let end_line = self.idx.loc(end_start).0;
        let has_comment = self.comments.iter().any(|(line, _, _)| *line >= start_line && *line <= end_line);
        // `AllowComments` only gates DETECTION; the autocorrect's own
        // `comment_in_else?` guard below is unconditional (fires even when
        // `AllowComments` is false, per upstream's `autocorrect` method).
        let allow_comments = self.cfg.get(cop, "AllowComments") == Some("true");
        if allow_comments && has_comment {
            return;
        }
        let forbidden = has_comment || self.ee_missing_else_forbids(kind);
        self.push(else_kw.start_offset(), cop, !forbidden, "Redundant `else`-clause.");
        if !forbidden {
            self.fixes.push((else_kw.start_offset(), end_start, Vec::new()));
        }
    }

    /// `Style::EmptyElse#autocorrect_forbidden?`/`#missing_else_style`: reads
    /// the `Style/MissingElse` section directly rather than through
    /// `self.cfg.get`/`self.on`, because `Style/MissingElse` isn't one of
    /// this engine's implemented cops and so carries no schema-driven
    /// enabled-by-default resolution — `Config::get`'s schema fallback only
    /// covers PARAMETER defaults, not `Enabled`. Read the raw param with
    /// rubocop's real default.yml value (`Enabled: false`) as the fallback,
    /// exactly like upstream's `missing_cfg.fetch('Enabled')`.
    fn ee_missing_else_forbids(&self, kind: &str) -> bool {
        if self.cfg.param("Style/MissingElse", "Enabled") != Some("true") {
            return false;
        }
        let style = self.cfg.get("Style/MissingElse", "EnforcedStyle").unwrap_or("both");
        style == kind || style == "both"
    }
}

/// Style/SelfAssignment: `x = x + 1` -> `x += 1`. Ports upstream's
/// `on_lvasgn`/`on_ivasgn`/`on_cvasgn` -> `check`, which only ever looks at
/// the PLAIN `=` write node (not the `+=`/`||=`/`&&=` shorthand write-node
/// families, which are already correct and have their own prism node
/// types) — hence hooking only `LocalVariableWriteNode`/
/// `InstanceVariableWriteNode`/`ClassVariableWriteNode`, never their
/// `OperatorWrite`/`OrWrite`/`AndWrite` siblings.
///
/// Two RHS shapes are recognized, matching upstream exactly:
/// - `rhs.send_type? && rhs.arguments.one?` (a `CallNode`, safe-navigation
///   excluded since prism's `csend`-equivalent is a distinct whitequark
///   type upstream's `send_type?` never matches) whose `method_name` is one
///   of `OPS` and whose receiver is a bare read of the SAME var/type
///   (`target_node = s(var_type, var_name)`) — `x = x + 1`, `x = x.+(y)`.
/// - `rhs.operator_keyword?` (`AndNode`/`OrNode` — covers `&&`/`and` and
///   `||`/`or` alike, since whitequark unifies both spellings into a single
///   `:and`/`:or` type) whose `lhs` is that same bare var read — `x = x ||
///   y`, `x = x && y`.
///
/// Autocorrect (`apply_autocorrect`) inserts the operator text right before
/// the assignment's own `=` (`node.loc.operator`) and replaces the WHOLE
/// rhs expression with the source text of whichever sub-node upstream calls
/// `new_rhs` (`rhs.first_argument` for the send shape, `rhs.rhs` for the
/// boolean shape) — never a reconstructed string, so any incidental
/// whitespace inside that sub-expression survives verbatim.
const SELF_ASSIGNMENT_OPS: &[&[u8]] =
    &[b"+", b"-", b"*", b"**", b"/", b"%", b"^", b"<<", b">>", b"|", b"&"];

/// Which variable kind (`var_type` in upstream) the LHS is — determines
/// what shape of bare variable-read node the RHS receiver/lhs must
/// structurally equal (`target_node = s(var_type, var_name)`).
enum SelfAssignmentVarKind<'a> {
    Lvar(&'a [u8]),
    Ivar(&'a [u8]),
    Cvar(&'a [u8]),
}

impl SelfAssignmentVarKind<'_> {
    fn matches(&self, node: &ruby_prism::Node) -> bool {
        match self {
            SelfAssignmentVarKind::Lvar(name) => {
                node.as_local_variable_read_node().is_some_and(|v| v.name().as_slice() == *name)
            }
            SelfAssignmentVarKind::Ivar(name) => {
                node.as_instance_variable_read_node().is_some_and(|v| v.name().as_slice() == *name)
            }
            SelfAssignmentVarKind::Cvar(name) => {
                node.as_class_variable_read_node().is_some_and(|v| v.name().as_slice() == *name)
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    pub(crate) fn check_self_assignment_shorthand_lvar(&mut self, node: &ruby_prism::LocalVariableWriteNode) {
        self.self_assignment_shorthand_check(
            node.location().start_offset(),
            node.operator_loc().start_offset(),
            &node.value(),
            &SelfAssignmentVarKind::Lvar(node.name().as_slice()),
        );
    }
    pub(crate) fn check_self_assignment_shorthand_ivar(&mut self, node: &ruby_prism::InstanceVariableWriteNode) {
        self.self_assignment_shorthand_check(
            node.location().start_offset(),
            node.operator_loc().start_offset(),
            &node.value(),
            &SelfAssignmentVarKind::Ivar(node.name().as_slice()),
        );
    }
    pub(crate) fn check_self_assignment_shorthand_cvar(&mut self, node: &ruby_prism::ClassVariableWriteNode) {
        self.self_assignment_shorthand_check(
            node.location().start_offset(),
            node.operator_loc().start_offset(),
            &node.value(),
            &SelfAssignmentVarKind::Cvar(node.name().as_slice()),
        );
    }

    /// Shared `check` + `check_send_node`/`check_boolean_node` + autocorrect
    /// dispatch — see the module-level doc comment above for the ported
    /// shapes.
    fn self_assignment_shorthand_check(
        &mut self,
        whole_start: usize,
        op_start: usize,
        rhs: &ruby_prism::Node,
        kind: &SelfAssignmentVarKind,
    ) {
        const COP: &str = "Style/SelfAssignment";
        if !self.on(COP) {
            return;
        }
        if let Some(call) = rhs.as_call_node() {
            // `rhs.send_type?`: prism folds `&.` into the same `CallNode`,
            // but whitequark's `send_type?` is `false` for its `csend`
            // counterpart — exclude safe-navigation to match.
            if call.is_safe_navigation() {
                return;
            }
            let args: Vec<ruby_prism::Node> =
                call.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
            if args.len() != 1 {
                return;
            }
            let method = call.name().as_slice();
            if !SELF_ASSIGNMENT_OPS.contains(&method) {
                return;
            }
            let Some(receiver) = call.receiver() else { return };
            if !kind.matches(&receiver) {
                return;
            }
            let method_str = String::from_utf8_lossy(method).into_owned();
            self.push(whole_start, COP, true, format!("Use self-assignment shorthand `{method_str}=`."));
            let call_loc = call.location();
            self.self_assignment_apply_fix(
                op_start,
                &method_str,
                (call_loc.start_offset(), call_loc.end_offset()),
                &args[0],
            );
        } else if let Some(and) = rhs.as_and_node() {
            self.self_assignment_boolean_check(
                whole_start,
                op_start,
                &and.left(),
                &and.right(),
                &and.operator_loc(),
                &and.location(),
                kind,
            );
        } else if let Some(or) = rhs.as_or_node() {
            self.self_assignment_boolean_check(
                whole_start,
                op_start,
                &or.left(),
                &or.right(),
                &or.operator_loc(),
                &or.location(),
                kind,
            );
        }
    }

    /// `check_boolean_node`: `rhs.lhs == target_node`; message/autocorrect
    /// operator is the LITERAL operator source (`&&`/`and`/`||`/`or`), not a
    /// normalized spelling.
    #[allow(clippy::too_many_arguments)]
    fn self_assignment_boolean_check(
        &mut self,
        whole_start: usize,
        op_start: usize,
        lhs: &ruby_prism::Node,
        new_rhs: &ruby_prism::Node,
        operator_loc: &ruby_prism::Location,
        whole_rhs_loc: &ruby_prism::Location,
        kind: &SelfAssignmentVarKind,
    ) {
        const COP: &str = "Style/SelfAssignment";
        if !kind.matches(lhs) {
            return;
        }
        let operator =
            String::from_utf8_lossy(&self.src[operator_loc.start_offset()..operator_loc.end_offset()])
                .into_owned();
        self.push(whole_start, COP, true, format!("Use self-assignment shorthand `{operator}=`."));
        self.self_assignment_apply_fix(
            op_start,
            &operator,
            (whole_rhs_loc.start_offset(), whole_rhs_loc.end_offset()),
            new_rhs,
        );
    }

    /// `apply_autocorrect`: `corrector.insert_before(node.loc.operator,
    /// operator)` then `corrector.replace(rhs, new_rhs.source)`.
    fn self_assignment_apply_fix(
        &mut self,
        op_start: usize,
        operator: &str,
        replace_range: (usize, usize),
        new_rhs: &ruby_prism::Node,
    ) {
        self.fixes.push((op_start, op_start, operator.as_bytes().to_vec()));
        let nl = new_rhs.location();
        let new_src = self.src[nl.start_offset()..nl.end_offset()].to_vec();
        self.fixes.push((replace_range.0, replace_range.1, new_src));
    }
}

impl<'a> super::Cops<'a> {
    /// Style/SingleLineMethods — a single-line `def`/`defs` WITH a body
    /// (`def foo; body end`). Endless methods (`def foo = body`, Ruby 3.0+)
    /// are always accepted outright (`node.endless?`); a body-less one-liner
    /// (`def foo; end`) is accepted too unless `AllowIfMethodIsEmpty: false`
    /// (default `true`).
    ///
    /// Ported from rubocop's `on_def`/`on_defs` (aliased) + `Alignment` +
    /// `LineBreakCorrector`. The autocorrect BRANCHES into either an endless
    /// method or a multiline one; every edge below was live-probed against
    /// the actual rubocop 1.88.0 gem (`rubocop -a --only
    /// Style/SingleLineMethods` on scratch files, and
    /// `RuboCop::ProcessedSource#ast` dumps) because `correct_to_endless?`'s
    /// guards read subtly differently once ported off whitequark's node
    /// types onto prism's:
    ///
    /// - `target_ruby_version < 3.0`, or `Style/EndlessMethod` disabled/
    ///   disallowing (`disallow_endless_method_style?`: rubocop's
    ///   `cop_enabled?` is `!!config['Enabled']`, so upstream's own
    ///   `Enabled: pending` default.yml entry is TRUTHY and counts as "on" —
    ///   matches `self.cfg.enabled`'s "no explicit `false`" default; ONLY an
    ///   explicit `Enabled: false` or `EnforcedStyle: disallow` blocks it) →
    ///   always multiline, never endless.
    /// - a `nil` body (empty one-liner method, only reachable when
    ///   `AllowIfMethodIsEmpty: false`) → always multiline.
    /// - the def's own name ends in `=` and isn't a comparison operator
    ///   (`==`/`===`/`!=`/`<=`/`>=`) — a setter (`foo=`) can't be written as
    ///   an endless method → always multiline.
    /// - the body is `return`/`break`/`next` → always multiline.
    /// - the body is `if`/`unless`/`while`/`until` (rubocop's
    ///   `basic_conditional?` — both the full-block AND modifier forms of
    ///   `unless` alias to `if` in rubocop's own whitequark-parity AST;
    ///   both prism node types are covered here) → always multiline.
    ///   `case`/`case`-with-`in` are NOT in this set — confirmed live: they
    ///   DO convert to endless.
    /// - the body is `:begin`-typed: EITHER 2+ top-level statements
    ///   (rubocop's implicit multi-statement wrap — prism: a
    ///   `StatementsNode` with 2+ children) OR a bare `(expr)` single
    ///   statement (prism: `ParenthesesNode` — whitequark quirk: parens
    ///   synthesize a `:begin` node even around one expression) → always
    ///   multiline.
    /// - the body is an explicit `begin...end` keyword block (prism:
    ///   `BeginNode` WITH a `begin_keyword_loc`, reached by unwrapping a
    ///   single-statement `StatementsNode`) — rubocop's `:kwbegin` — →
    ///   always multiline.
    /// - a `rescue`/`ensure` clause attached DIRECTLY to the `def` with no
    ///   `begin` keyword at all (prism: a `BeginNode` with NO
    ///   `begin_keyword_loc`, returned straight from `def.body` with no
    ///   `StatementsNode` wrapper at all) is `:rescue`/`:ensure`-typed in
    ///   rubocop's AST, NOT `:begin`/`:kwbegin` — so it is NOT blocked.
    ///   Confirmed live: `def foo; x; rescue; y; end` really is "corrected"
    ///   by actual rubocop 1.88.0 to the broken `def foo() = x; rescue; y`.
    ///   Ported verbatim (bug and all) — not exercised by the fixture.
    /// - anything else (a plain call, literal, `case`, a call-with-block,
    ///   ...) → endless.
    pub(crate) fn check_single_line_methods(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/SingleLineMethods";
        if !self.on(COP) {
            return;
        }
        let loc = node.location();
        let start_line = self.idx.loc(loc.start_offset()).0;
        let end_line = self.idx.loc(loc.end_offset().saturating_sub(1)).0;
        if start_line != end_line {
            return; // node.single_line?
        }
        if node.equal_loc().is_some() {
            return; // node.endless?
        }
        let body = node.body();
        let allow_empty = self.cfg.get(COP, "AllowIfMethodIsEmpty") == Some("true");
        if allow_empty && body.is_none() {
            return;
        }
        self.push(loc.start_offset(), COP, true, "Avoid single-line method definitions.");
        let kind = match body {
            Some(b) => classify_slm_body(b),
            None => SlmBody::None,
        };
        if self.slm_correct_to_endless_ok(node, &kind) {
            self.slm_correct_to_endless(node, &kind);
        } else {
            self.slm_correct_to_multiline(node, &kind);
        }
    }

    /// `correct_to_endless?` — see the big doc comment above for the full,
    /// live-probed guard-by-guard mapping.
    fn slm_correct_to_endless_ok(&self, node: &ruby_prism::DefNode, kind: &SlmBody) -> bool {
        if self.cfg.target_ruby() < 3.0 {
            return false;
        }
        // `disallow_endless_method_style?`
        if !self.cfg.enabled("Style/EndlessMethod") {
            return false;
        }
        if self.cfg.enforced_style("Style/EndlessMethod") == "disallow" {
            return false;
        }
        match kind {
            SlmBody::None | SlmBody::Paren(_) | SlmBody::Multi(_) | SlmBody::KwBegin(_) => false,
            SlmBody::Other(n) => {
                if n.as_if_node().is_some()
                    || n.as_unless_node().is_some()
                    || n.as_while_node().is_some()
                    || n.as_until_node().is_some()
                    || n.as_return_node().is_some()
                    || n.as_break_node().is_some()
                    || n.as_next_node().is_some()
                {
                    return false;
                }
                // `body_node.parent.assignment_method?`: the DEF's own name
                // (its "parent", from the body's point of view) ends in `=`
                // and isn't a comparison operator.
                let name = node.name().as_slice();
                !(name.ends_with(b"=") && !matches!(name, b"==" | b"===" | b"!=" | b"<=" | b">="))
            }
        }
    }

    /// `correct_to_endless` — `def #{receiver}#{name}#{arguments} = #{body}`,
    /// replacing the node's entire source range. `arguments` is the params
    /// list's OWN literal source (parens included when the user wrote them,
    /// EXCLUDED when they didn't — matching a genuine rubocop quirk where a
    /// parenless single param glues onto the method name with no space,
    /// e.g. `def some_methodarg = body`), or the literal `"()"` when there
    /// are no params at all.
    fn slm_correct_to_endless(&mut self, node: &ruby_prism::DefNode, kind: &SlmBody) {
        let SlmBody::Other(body) = kind else { return };
        let mut out: Vec<u8> = b"def ".to_vec();
        if let Some(recv) = node.receiver() {
            out.extend_from_slice(self.node_src(&recv));
            out.push(b'.');
        }
        out.extend_from_slice(node.name().as_slice());
        match node.parameters() {
            Some(params) => {
                let mut s = params.location().start_offset();
                let mut e = params.location().end_offset();
                if let Some(lp) = node.lparen_loc() {
                    s = lp.start_offset();
                }
                if let Some(rp) = node.rparen_loc() {
                    e = rp.end_offset();
                }
                out.extend_from_slice(&self.src[s..e]);
            }
            None => out.extend_from_slice(b"()"),
        }
        out.extend_from_slice(b" = ");
        out.extend_from_slice(&self.slm_method_body_source(body));
        let loc = node.location();
        self.fixes.push((loc.start_offset(), loc.end_offset(), out));
    }

    /// `method_body_source` + `require_parentheses?` — a bare (no-block,
    /// non-safe-nav) call whose method name isn't a comparison/arithmetic
    /// operator and takes at least one argument gets its args parenthesized
    /// and comma-joined from their own sources (`head :ok` -> `head(:ok)`,
    /// `head :ok, :bar` -> `head(:ok, :bar)`); everything else (including a
    /// call already using parens — reconstructed identically) keeps its
    /// literal source verbatim.
    fn slm_method_body_source(&self, body: &ruby_prism::Node) -> Vec<u8> {
        if let Some(call) = body.as_call_node() {
            if call.block().is_none() && !call.is_safe_navigation() {
                let name = call.name().as_slice();
                let arithmetic = matches!(name, b"+" | b"-" | b"*" | b"/" | b"%" | b"**");
                let comparison =
                    matches!(name, b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<");
                let args = call.arguments();
                let has_args = args.as_ref().is_some_and(|a| !a.arguments().is_empty());
                if !arithmetic && has_args && !comparison {
                    let mut out = Vec::new();
                    if let Some(recv) = call.receiver() {
                        out.extend_from_slice(self.node_src(&recv));
                        out.push(b'.');
                    }
                    out.extend_from_slice(name);
                    out.push(b'(');
                    let mut first = true;
                    for a in args.unwrap().arguments().iter() {
                        if !first {
                            out.extend_from_slice(b", ");
                        }
                        first = false;
                        out.extend_from_slice(self.node_src(&a));
                    }
                    out.push(b')');
                    return out;
                }
            }
        }
        self.node_src(body).to_vec()
    }

    /// `correct_to_multiline` — break the body (and, for 2+ statements,
    /// EACH top-level statement) onto its own freshly-indented line, then
    /// the `end` keyword onto its own line at the `def`'s own indentation,
    /// then move an end-of-line comment above the `def`. Ported from
    /// `LineBreakCorrector.break_line_before`/`move_comment` — the same
    /// primitives `check_trailing_body_on_method_definition` applies for a
    /// different cop.
    fn slm_correct_to_multiline(&mut self, node: &ruby_prism::DefNode, kind: &SlmBody) {
        let keyword_start = node.def_keyword_loc().start_offset();
        let keyword_col = self.idx.loc(keyword_start).1 - 1; // 0-based
        let width: usize = self
            .cfg
            .param("Style/SingleLineMethods", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2);
        let indent1 = " ".repeat(keyword_col + width);
        match kind {
            SlmBody::None => {} // no body at all -> nothing to break before `end`
            SlmBody::Paren(n) | SlmBody::KwBegin(n) | SlmBody::Other(n) => {
                let start = n.location().start_offset();
                self.fixes.push((start, start, format!("\n{indent1}").into_bytes()));
            }
            SlmBody::Multi(items) => {
                for it in items.iter() {
                    let start = it.location().start_offset();
                    self.fixes.push((start, start, format!("\n{indent1}").into_bytes()));
                }
            }
        }
        // `break_line_before(corrector, node, node.loc.end, indent_steps: 0)`
        if let Some(end_loc) = node.end_keyword_loc() {
            let end_start = end_loc.start_offset();
            let indent0 = " ".repeat(keyword_col);
            self.fixes.push((end_start, end_start, format!("\n{indent0}").into_bytes()));
        }
        // `move_comment`: an EOL comment on the def's own opening line moves
        // above the def, at the def's own indentation.
        let start_line = self.idx.loc(keyword_start).0;
        if let Some(&(_, cs, ce)) = self.comments.iter().find(|(line, _, _)| *line == start_line) {
            let mut ins = self.src[cs..ce].to_vec();
            ins.push(b'\n');
            ins.extend(std::iter::repeat(b' ').take(keyword_col));
            self.fixes.push((keyword_start, keyword_start, ins));
            self.fixes.push((cs, ce, Vec::new()));
        }
    }
}

/// A `def`/`defs` node's BODY the way rubocop-ast's Prism translation
/// surfaces it (see `check_single_line_methods`'s doc comment for the full
/// mapping + live-probed edge cases): unwrap a `StatementsNode` with
/// exactly one statement to that statement; 2+ statements become an
/// implicit, delimiter-less `:begin` group; everything else (including a
/// `BeginNode` reached WITHOUT going through a `StatementsNode` at all —
/// the def's own direct rescue/ensure) passes through as itself.
enum SlmBody<'pr> {
    None,
    /// A bare `(expr)` single statement — `:begin`-typed, WITH delimiters
    /// (`parenthesized_call?`): broken onto its own line as ONE unit,
    /// parens included.
    Paren(ruby_prism::Node<'pr>),
    /// 2+ top-level statements — `:begin`-typed, no delimiters: each
    /// statement gets its own line.
    Multi(ruby_prism::NodeList<'pr>),
    /// An explicit `begin...end` keyword block — `:kwbegin`.
    KwBegin(ruby_prism::Node<'pr>),
    /// Anything else (a single non-parenthesized statement, or a `BeginNode`
    /// reached directly — the def's own rescue/ensure).
    Other(ruby_prism::Node<'pr>),
}

fn classify_slm_body<'pr>(body: ruby_prism::Node<'pr>) -> SlmBody<'pr> {
    if let Some(stmts) = body.as_statements_node() {
        let items = stmts.body();
        return match items.len() {
            0 => SlmBody::None,
            1 => slm_classify_single(items.iter().next().unwrap()),
            _ => SlmBody::Multi(items),
        };
    }
    slm_classify_single(body)
}

fn slm_classify_single<'pr>(n: ruby_prism::Node<'pr>) -> SlmBody<'pr> {
    if n.as_parentheses_node().is_some() {
        return SlmBody::Paren(n);
    }
    if let Some(b) = n.as_begin_node() {
        if b.begin_keyword_loc().is_some() {
            return SlmBody::KwBegin(n);
        }
    }
    SlmBody::Other(n)
}

impl<'a> super::Cops<'a> {
    /// Style/PreferredHashMethods: checks for uses of Hash#has_key?/has_value?
    /// (short style) or Hash#key?/value? (verbose style) and suggests the
    /// preferred variant based on EnforcedStyle config (default: short).
    pub(crate) fn check_preferred_hash_methods(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/PreferredHashMethods";
        if !self.on(COP) {
            return;
        }

        let method_name = node.name().as_slice();

        // Check if the method has exactly one argument
        let args_count = node.arguments().map(|a| a.arguments().len()).unwrap_or(0);
        if args_count != 1 {
            return;
        }

        let style = self.cfg.enforced_style(COP);

        // Determine if this is an offending selector based on the style
        let offending = if style == "verbose" {
            matches!(method_name, b"key?" | b"value?")
        } else {
            // short is the default
            matches!(method_name, b"has_key?" | b"has_value?")
        };

        if !offending {
            return;
        }

        // Get the preferred method name
        let preferred = if style == "verbose" {
            // Convert key? -> has_key?, value? -> has_value?
            if method_name == b"key?" {
                "has_key?".to_string()
            } else {
                "has_value?".to_string()
            }
        } else {
            // Convert has_key? -> key?, has_value? -> value?
            if method_name == b"has_key?" {
                "key?".to_string()
            } else {
                "value?".to_string()
            }
        };

        let current_name = String::from_utf8_lossy(method_name).into_owned();
        let message = format!(
            "Use `Hash#{}` instead of `Hash#{}`.",
            preferred, current_name
        );

        // Report the offense at the selector location
        if let Some(msg_loc) = node.message_loc() {
            self.push(msg_loc.start_offset(), COP, true, &message);

            // Add the fix: replace the method selector
            self.fixes.push((
                msg_loc.start_offset(),
                msg_loc.end_offset(),
                preferred.as_bytes().to_vec(),
            ));
        }
    }
}

impl<'a> Cops<'a> {
    /// Style/NumericLiteralPrefix: Checks for octal, hex, binary, and decimal
    /// literals using uppercase prefixes and corrects them to lowercase prefix
    /// or no prefix (in case of decimals). Also ensures octal style matches
    /// EnforcedOctalStyle config.
    pub(crate) fn check_numeric_literal_prefix(&mut self, node: &ruby_prism::IntegerNode) {
        const COP: &str = "Style/NumericLiteralPrefix";
        if !self.on(COP) {
            return;
        }

        let src = self.node_src(&node.as_node());
        let src_str = String::from_utf8_lossy(src);

        // Determine the literal type and get the message/fix
        if let Some((msg, fix)) = self.literal_type_and_fix(&src_str) {
            let l = node.location();
            self.push(l.start_offset(), COP, true, msg);
            self.fixes.push((l.start_offset(), l.end_offset(), fix.into_bytes()));
        }
    }

    /// Determine the type of numeric literal and return (message, replacement) if
    /// an offense should be reported.
    fn literal_type_and_fix(&self, literal: &str) -> Option<(&'static str, String)> {
        let octal_zero_only_regex = regex::Regex::new(r"^0[Oo][0-7]+$").ok()?;
        let octal_regex = regex::Regex::new(r"^0O?[0-7]+$").ok()?;
        let hex_regex = regex::Regex::new(r"^0X[0-9A-F]+$").ok()?;
        let binary_regex = regex::Regex::new(r"^0B[01]+$").ok()?;
        let decimal_regex = regex::Regex::new(r"^0[dD][0-9]+$").ok()?;

        let octal_zero_only = self.cfg.get(
            "Style/NumericLiteralPrefix",
            "EnforcedOctalStyle",
        ).map(|v| v == "zero_only").unwrap_or(false);

        // Check for octal literals
        if octal_zero_only_regex.is_match(literal) && octal_zero_only {
            // 0O1234 or 0o1234 when we want bare 0
            let fixed = literal.replace("0O", "0").replace("0o", "0");
            return Some(("Use 0 for octal literals.", fixed));
        }
        if octal_regex.is_match(literal) && !octal_zero_only {
            // 01234 or 0O1234 when we want 0o (lowercase)
            if literal.starts_with("0O") {
                let fixed = literal.replacen("0O", "0o", 1);
                return Some(("Use 0o for octal literals.", fixed));
            } else if literal.starts_with("0") && !literal.starts_with("0o") {
                // Plain octal like 01234
                let fixed = format!("0o{}", &literal[1..]);
                return Some(("Use 0o for octal literals.", fixed));
            }
        }
        if hex_regex.is_match(literal) {
            // Has uppercase X
            let fixed = literal.replacen("0X", "0x", 1);
            return Some(("Use 0x for hexadecimal literals.", fixed));
        }
        if binary_regex.is_match(literal) {
            // Has uppercase B
            let fixed = literal.replacen("0B", "0b", 1);
            return Some(("Use 0b for binary literals.", fixed));
        }
        if decimal_regex.is_match(literal) {
            // Has 0d or 0D prefix - remove it
            let fixed = if literal.starts_with("0d") {
                literal[2..].to_string()
            } else {
                literal[2..].to_string()
            };
            return Some(("Do not use prefixes for decimal literals.", fixed));
        }

        None
    }
}
impl<'a> super::Cops<'a> {

    /// Style/Sample — shuffle.first/shuffle.last/shuffle[]/shuffle.at/shuffle.slice → sample.
    pub(crate) fn check_sample(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/Sample";
        if !self.hot.sample {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        // Match patterns like: shuffle.first, shuffle[0], shuffle.at(0), etc.
        // The pattern is: (call (call <receiver> :shuffle <args>) <method> <method_args>)
        let pat = matcher(&PAT,
            "{(call (call _ :shuffle) :first)\
              (call (call _ :shuffle) :first (...))\
              (call (call _ :shuffle) :last)\
              (call (call _ :shuffle) :last (...))\
              (call (call _ :shuffle) :[] (...))\
              (call (call _ :shuffle) :[] (...) (...))\
              (call (call _ :shuffle) :at (...))\
              (call (call _ :shuffle) :slice)\
              (call (call _ :shuffle) :slice (...))\
              (call (call _ :shuffle) :slice (...) (...))\
              (call (call _ :shuffle (...)) :first)\
              (call (call _ :shuffle (...)) :first (...))\
              (call (call _ :shuffle (...)) :last)\
              (call (call _ :shuffle (...)) :last (...))\
              (call (call _ :shuffle (...)) :[] (...))\
              (call (call _ :shuffle (...)) :[] (...) (...))\
              (call (call _ :shuffle (...)) :at (...))\
              (call (call _ :shuffle (...)) :slice)\
              (call (call _ :shuffle (...)) :slice (...))\
              (call (call _ :shuffle (...)) :slice (...) (...))}");
        if nodepattern::matches(pat, &node.as_node(), self.src).is_none() {
            return;
        }

        let method_name = node.name();

        // Get receiver (the shuffle call node)
        let Some(receiver) = node.receiver() else { return };
        let Some(shuffle_call) = receiver.as_call_node() else { return };

        // Get shuffle's arguments
        let shuffle_arg_src = shuffle_call.arguments()
            .and_then(|a| a.arguments().iter().next())
            .map(|n| String::from_utf8_lossy(self.node_src(&n)).into_owned());

        // Get this call's arguments (the method being called on shuffle)
        let method_args_opt = node.arguments().map(|a| a.arguments());

        // Determine if offensive
        if !self.is_sample_offensive_opt(method_name.as_slice(), method_args_opt.as_ref()) {
            return;
        }

        // Build correction
        let correct = self.sample_correction_opt(shuffle_arg_src.as_deref(), method_name.as_slice(), method_args_opt.as_ref());

        // Get source range: from shuffle's selector to end of this call
        let shuffle_loc = match shuffle_call.message_loc() {
            Some(sel_loc) => (sel_loc.start_offset(), node.location().end_offset()),
            None => return,
        };
        let incorrect = String::from_utf8_lossy(&self.src[shuffle_loc.0..shuffle_loc.1]).into_owned();
        let message = format!("Use `{correct}` instead of `{incorrect}`.");

        self.push(shuffle_loc.0, COP, true, message);
        self.fixes.push((shuffle_loc.0, shuffle_loc.1, correct.into_bytes()));
    }

    fn is_sample_offensive_opt(&self, method: &[u8], args: Option<&ruby_prism::NodeList>) -> bool {
        let args = match args {
            Some(a) => a,
            None => return matches!(method, b"first" | b"last"),
        };

        match method {
            b"first" | b"last" => true,
            b"[]" | b"at" | b"slice" => {
                self.sample_size_opt(Some(args)).is_some()
            }
            _ => false,
        }
    }

    // Returns Some(size_string) if the size can be determined, None if unknown
    fn sample_size_opt(&self, args: Option<&ruby_prism::NodeList>) -> Option<String> {
        let args = args?;

        let int_of = |n: &ruby_prism::Node| -> Option<i64> {
            let l = n.location();
            std::str::from_utf8(&self.src[l.start_offset()..l.end_offset()])
                .ok()?
                .replace('_', "")
                .parse()
                .ok()
        };

        if args.is_empty() {
            return None;
        }

        if args.len() == 1 {
            let arg = &args.iter().next()?;

            // Check if it's a range
            if let Some(range_node) = arg.as_range_node() {
                let (Some(b), Some(e)) = (range_node.left(), range_node.right()) else { return None };
                let (Some(b), Some(e)) = (int_of(&b), int_of(&e)) else { return None };
                if b != 0 {
                    return None; // Not starting at 0
                }
                let is_exclusive = range_node.operator_loc().as_slice() == b"...";
                let size = if is_exclusive { e } else { e + 1 };
                return Some(size.to_string());
            }

            // Check if it's an integer literal
            if let Some(v) = int_of(arg) {
                if v == 0 || v == -1 {
                    return Some("unknown".to_string()); // Offensive
                }
                return None; // Not offensive
            }

            return None; // Unknown
        }

        if args.len() == 2 {
            // For [offset, length], only offensive if offset == 0
            let first = &args.iter().next()?;
            if let Some(v) = int_of(first) {
                if v == 0 {
                    // Return the second argument as the size
                    let second = &args.iter().nth(1)?;
                    let size_src = String::from_utf8_lossy(self.node_src(second)).into_owned();
                    return Some(size_src);
                }
            }
            return None;
        }

        None
    }

    fn sample_correction_opt(&self, shuffle_arg: Option<&str>, method: &[u8], args: Option<&ruby_prism::NodeList>) -> String {
        let sample_arg = self.get_sample_arg_opt(method, args);

        let mut parts = Vec::new();
        if let Some(arg) = sample_arg {
            parts.push(arg);
        }
        if let Some(sarg) = shuffle_arg {
            parts.push(sarg.to_string());
        }

        if parts.is_empty() {
            "sample".to_string()
        } else {
            format!("sample({})", parts.join(", "))
        }
    }

    fn get_sample_arg_opt(&self, method: &[u8], args: Option<&ruby_prism::NodeList>) -> Option<String> {
        let args = args?;

        let int_of = |n: &ruby_prism::Node| -> Option<i64> {
            let l = n.location();
            std::str::from_utf8(&self.src[l.start_offset()..l.end_offset()])
                .ok()?
                .replace('_', "")
                .parse()
                .ok()
        };

        match method {
            b"first" | b"last" => {
                if !args.is_empty() {
                    let arg = &args.iter().next()?;
                    Some(String::from_utf8_lossy(self.node_src(arg)).into_owned())
                } else {
                    None
                }
            }
            b"[]" | b"slice" => {
                if args.len() == 1 {
                    let arg = &args.iter().next()?;
                    if let Some(range_node) = arg.as_range_node() {
                        let (Some(b), Some(e)) = (range_node.left(), range_node.right()) else { return None };
                        let (Some(b), Some(e)) = (int_of(&b), int_of(&e)) else { return None };
                        if b != 0 {
                            return None;
                        }
                        let is_exclusive = range_node.operator_loc().as_slice() == b"...";
                        let size = if is_exclusive { e } else { e + 1 };
                        return Some(size.to_string());
                    }
                    None
                } else if args.len() == 2 {
                    let first = &args.iter().next()?;
                    if let Some(v) = int_of(first) {
                        if v == 0 {
                            let second = &args.iter().nth(1)?;
                            return Some(String::from_utf8_lossy(self.node_src(second)).into_owned());
                        }
                    }
                    None
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/Attr — `attr :name` → `attr_reader :name`, `attr :name, true` → `attr_accessor :name`,
    /// `attr :name, false` → `attr_reader :name`. The `attr` method with a single argument
    /// creates a reader (like `attr_reader`), but with a second boolean argument it creates
    /// an accessor (deprecated in Ruby 1.9). Use `attr_reader` or `attr_accessor` to make intent explicit.
    pub(crate) fn check_attr(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/Attr";
        if !self.on(COP) {
            return;
        }

        // Must be bare `attr` with no receiver
        if node.receiver().is_some() {
            return;
        }

        // Must be named `attr`
        if node.name().as_slice() != b"attr" {
            return;
        }

        // Must have arguments
        let Some(args) = node.arguments() else { return };
        if args.arguments().is_empty() {
            return;
        }

        // Check if there's a custom `attr` method defined in any enclosing class/module.
        // If so, skip the offense (the custom method takes precedence).
        if self.has_custom_attr_method() {
            return;
        }

        // Get the replacement method name based on the second argument
        let last_arg = args.arguments().iter().last();
        let replacement = if let Some(arg) = last_arg {
            // Check if the second argument (if only 2+ args) is a boolean
            if args.arguments().len() > 1 {
                if let Some(_) = arg.as_true_node() {
                    "attr_accessor".to_string()
                } else if let Some(_) = arg.as_false_node() {
                    "attr_reader".to_string()
                } else {
                    "attr_reader".to_string()
                }
            } else {
                // Single argument or non-boolean second argument
                "attr_reader".to_string()
            }
        } else {
            "attr_reader".to_string()
        };

        let message = format!("Do not use `attr`. Use `{}` instead.", replacement);
        let msg_loc = node.message_loc().map(|l| l.start_offset()).unwrap_or_else(|| node.location().start_offset());

        self.push(msg_loc, COP, true, message);

        // Autocorrect: replace `attr` with the replacement method
        if let Some(msg_loc) = node.message_loc() {
            self.fixes.push((msg_loc.start_offset(), msg_loc.end_offset(), replacement.into_bytes()));

            // If there's a second argument that's a boolean, remove it
            if args.arguments().len() > 1 {
                let arg_list: Vec<_> = args.arguments().iter().collect();
                if let Some(first_arg) = arg_list.first() {
                    if let Some(last_arg) = arg_list.last() {
                        if last_arg.as_true_node().is_some() || last_arg.as_false_node().is_some() {
                            // Find the position after the first argument
                            let first_arg_end = first_arg.location().end_offset();
                            // Remove from after the first argument to the end of the last argument
                            self.fixes.push((first_arg_end, last_arg.location().end_offset(), Vec::new()));
                        }
                    }
                }
            }
        }
    }

    /// Check if there's a custom `attr` method defined in any enclosing class/module.
    fn has_custom_attr_method(&self) -> bool {
        // Check the stack - if any enclosing class/module has a custom attr method, return true
        self.style_attr_custom_method_stack.iter().any(|&has_custom| has_custom)
    }
}

impl<'a> super::Cops<'a> {
    /// Style/MissingRespondToMissing — `method_missing`/`def self.
    /// method_missing` defined without a matching `respond_to_missing?`
    /// (matching KIND: plain `def` only satisfies plain `def`, `def self.`
    /// only satisfies `def self.` — upstream's `grand_parent.each_descendant
    /// (node.type)`, i.e. it re-scans for the SAME whitequark node type the
    /// offending def has).
    ///
    /// Upstream's scan root is `grand_parent = node.parent.parent` — two
    /// hops up the whitequark AST from the `method_missing` def. Because
    /// whitequark elides the `:begin` wrapper for single-statement bodies,
    /// that root is USUALLY the immediately enclosing class/module/`class
    /// << self`, but can occasionally land one level higher (when that
    /// class/module is itself the sole statement of ITS enclosing body) or
    /// come up `nil` (terminating the ancestor chain, e.g. a bare top-level
    /// `method_missing`, or one inside a class that is itself the whole
    /// file's only statement) — `nil` unconditionally means "no
    /// `respond_to_missing?` found", i.e. always offend. This port always
    /// scans the NEAREST enclosing class/module/sclass body (`respond_to_
    /// missing_stack`, pushed/popped in `mod.rs`'s `visit_class_node`/
    /// `visit_module_node`/`visit_singleton_class_node` via `Self::scan_
    /// respond_to_missing`), which reproduces upstream's result for every
    /// case actually exercised by the fixture (including the `nil` case:
    /// with no enclosing class/module/sclass at all, `respond_to_missing_
    /// stack` is empty here too, so the cop always fires, matching
    /// upstream's `return false unless (grand_parent = ...)` guard).
    /// Diverges from upstream only in the rare case where the enclosing
    /// class/module is itself a lone statement AND has sibling statements
    /// of its own one level further out that upstream's widened scan would
    /// pick up — not exercised by the fixture.
    ///
    /// The scan is a full recursive descendant walk (`RespondToMissingCollector`,
    /// mirroring `RsAssignCollector`'s pattern) that does NOT stop at nested
    /// class/module/sclass boundaries, matching upstream's `each_descendant`
    /// (which also flattens through nested scopes) verbatim.
    ///
    /// Never autocorrectable upstream (no `extend AutoCorrector`).
    pub(crate) fn check_missing_respond_to_missing(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/MissingRespondToMissing";
        if !self.on(COP) || node.name().as_slice() != b"method_missing" {
            return;
        }
        let is_singleton = node.receiver().is_some();
        let implemented = self.respond_to_missing_stack.last().is_some_and(|&(has_def, has_defs)| {
            if is_singleton { has_defs } else { has_def }
        });
        if implemented {
            return;
        }
        self.push(node.location().start_offset(), COP, false,
            "When using `method_missing`, define `respond_to_missing?`.");
    }

    /// Scans `body`'s entire subtree (any depth — see `check_missing_
    /// respond_to_missing`'s doc comment) for `def`/`def self.` nodes named
    /// `respond_to_missing?`. Returns `(has_plain_def, has_self_def)`.
    pub(crate) fn scan_respond_to_missing(body: &Option<ruby_prism::Node>) -> (bool, bool) {
        let Some(b) = body else { return (false, false) };
        let mut c = RespondToMissingCollector::default();
        c.visit(b);
        (c.has_def, c.has_defs)
    }
}

/// Style/MissingRespondToMissing: collects whether `respond_to_missing?` is
/// defined ANYWHERE in a subtree, as a plain `def` and/or a `def self.`
/// (singleton) — see `check_missing_respond_to_missing`'s doc comment.
#[derive(Default)]
struct RespondToMissingCollector {
    has_def: bool,
    has_defs: bool,
}
impl<'pr> ruby_prism::Visit<'pr> for RespondToMissingCollector {
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if node.name().as_slice() == b"respond_to_missing?" {
            if node.receiver().is_some() {
                self.has_defs = true;
            } else {
                self.has_def = true;
            }
        }
        ruby_prism::visit_def_node(self, node);
    }
}

impl<'a> super::Cops<'a> {
    /// Style/HashLikeCase — a `case-when` mapping literal (string/symbol)
    /// conditions 1:1 onto literal bodies, with no `else`, reads better as a
    /// hash lookup. Ports rubocop's node-pattern (`hash_like_case?`) plus its
    /// `MinBranchesCount` mixin (`min_branches_count?`):
    ///
    ///   (case _ (when ${str_type? sym_type?} $[!nil? recursive_basic_literal?])+ nil?)
    ///
    /// Node-pattern ARITY is significant here, not just node TYPE: a `when`
    /// with more than one comma-separated value (2+ `conditions()`, e.g.
    /// `when 'a', 'b'`) or with zero statements has the wrong shape to match
    /// `(when $cond $body)` at all, which fails the repetition (`+`) for the
    /// WHOLE case node — no partial offense — verified live against rubocop
    /// 1.88 (`when 'a', 'b'` blocks the offense entirely, even alongside
    /// otherwise-conforming branches).
    ///
    /// The trailing `nil?` matches rubocop's raw case-node sexp, where an
    /// ABSENT `else` and a syntactically EMPTY `else` (keyword with no
    /// statements) are indistinguishable — both render as a bare `nil`
    /// child, since whitequark doesn't wrap `else` in its own node — verified
    /// live: `case x; when 'a'; 'A'; when 'b'; 'B'; else; end` still offends
    /// (`ps.ast` for that source is `s(:case, ..., s(:when, ...), nil)`).
    /// Only a NON-empty `else` body blocks the match.
    pub(crate) fn check_hash_like_case(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Style/HashLikeCase";
        if !self.on(COP) {
            return;
        }

        let min_branches = self
            .cfg
            .get(COP, "MinBranchesCount")
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(3) as usize;

        let branches = node.conditions();
        if branches.len() < min_branches {
            return;
        }

        if node.else_clause().is_some_and(|e| e.statements().is_some()) {
            return;
        }

        let mut cond_repr: Option<ruby_prism::Node> = None;
        let mut body_repr: Option<ruby_prism::Node> = None;

        for branch in branches.iter() {
            // `case`/`when` conditions are always `WhenNode`s (`case`/`in`
            // uses a separate `CaseMatchNode`/`InNode` pair entirely), but
            // stay defensive rather than assume.
            let Some(when_node) = branch.as_when_node() else { return };

            let mut whens = when_node.conditions().iter();
            let Some(condition) = whens.next() else { return };
            if whens.next().is_some() {
                return;
            }
            if condition.as_string_node().is_none() && condition.as_symbol_node().is_none() {
                return;
            }

            let Some(body) = hash_like_case_body(&when_node) else { return };
            if !super::lint_cops::is_recursive_basic_literal(&body) {
                return;
            }

            match &cond_repr {
                None => cond_repr = Some(condition),
                Some(first) if std::mem::discriminant(first) == std::mem::discriminant(&condition) => {}
                Some(_) => return,
            }
            match &body_repr {
                None => body_repr = Some(body),
                Some(first) if std::mem::discriminant(first) == std::mem::discriminant(&body) => {}
                Some(_) => return,
            }
        }

        self.push(node.location().start_offset(), COP, false, "Consider replacing `case-when` with a hash lookup.");
    }
}

/// The `when` clause's body position the way rubocop's sexp represents it: a
/// SINGLE statement stands for itself; 2+ statements collapse to their
/// enclosing (`:begin`-typed, in whitequark) statements list — matched here
/// by returning the `StatementsNode` itself, since `is_recursive_basic_literal`
/// already recurses through `StatementsNode` the same way it would a `:begin`
/// node; zero statements is the sexp's bare `nil`, which never matches
/// (`None`).
fn hash_like_case_body<'pr>(when_node: &ruby_prism::WhenNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let stmts = when_node.statements()?;
    let body = stmts.body();
    match body.len() {
        0 => None,
        1 => body.iter().next(),
        _ => Some(stmts.as_node()),
    }
}

/// Whether rubocop's real (whitequark/`parser`-gem) lexer would collapse
/// this percent-literal's raw content into a single `str` token, matching
/// `Parser::Builders::Default#collapse_string_parts?` (`parts.one?`): the
/// lexer splits content into a fresh token right after each embedded raw
/// `\n` (the newline stays attached to the token that ends there), and a
/// trailing empty token — content ending exactly at a newline, or content
/// that's entirely empty — is never emitted at all. Exactly one surviving
/// token means `str`; zero (empty content) or 2+ (multiline content) means
/// `dstr`.
fn whitequark_collapses_to_str(content: &[u8]) -> bool {
    let mut segments = 0usize;
    let mut start = 0usize;
    for (i, &b) in content.iter().enumerate() {
        if b == b'\n' {
            segments += 1;
            start = i + 1;
        }
    }
    if start < content.len() {
        segments += 1;
    }
    segments == 1
}

impl<'a> Cops<'a> {
    /// Style/PercentQLiterals — enforces `%q` vs `%Q` per `EnforcedStyle`
    /// (`lower_case_q` default / `upper_case_q`).
    ///
    /// Ported from rubocop's `PercentQLiterals` cop, which mixes in
    /// `PercentLiteral` + `ConfigurableEnforcedStyle` and only defines
    /// `on_str` — never `on_dstr`. So this only ever fires on a genuinely
    /// non-interpolated string literal, a prism `StringNode`. A `%Q(...)`
    /// with real `#{}` interpolation parses as an `InterpolatedStringNode`
    /// instead and is never checked at all, which is why the "with
    /// interpolation" spec examples for both styles are always accepted.
    ///
    /// `PercentLiteral#type(node)` is `node.loc.begin.source[0..-2]` — the
    /// opening delimiter token minus its last byte (the bracket char), e.g.
    /// `"%Q("[0..-2] == "%Q"`. Only an exact `%Q`/`%q` (not `%w`, `%i`, bare
    /// `%(`, etc.) is in scope; that's `type(node)` restricted to `%Q`/`%q`
    /// in `process(node, '%Q', '%q')`.
    pub(crate) fn check_percent_q_literals(&mut self, node: &ruby_prism::StringNode<'_>) {
        const COP: &str = "Style/PercentQLiterals";
        if !self.on(COP) {
            return;
        }
        let Some(opening) = node.opening_loc() else { return };
        let ob = opening.as_slice();
        if !ob.starts_with(b"%") {
            return;
        }
        let ty = &ob[..ob.len() - 1];
        let is_capital = match ty {
            b"%Q" => true,
            b"%q" => false,
            _ => return,
        };

        // prism-vs-whitequark trap: rubocop's actual (whitequark/`parser`
        // gem) lexer emits a fresh string-content token right after every
        // embedded raw newline, and `Builders::Default#string_compose` only
        // collapses to a plain `str` node (what `on_str` requires) when
        // exactly one non-empty token survives — a trailing empty token
        // (content ending exactly at a newline, or content that's entirely
        // empty) is dropped rather than counted. So `%Q()` and any `%Q(...)`
        // whose content spans 2+ raw source lines become a `dstr` under
        // whitequark and are NEVER checked by this cop at all, even though
        // there's no real `#{}` interpolation anywhere. Prism has no such
        // quirk — it hands back a plain `StringNode` for both — so this has
        // to be special-cased here rather than falling out of the node type.
        if !whitequark_collapses_to_str(node.content_loc().as_slice()) {
            return;
        }

        // `ConfigurableEnforcedStyle` — default `lower_case_q`.
        let upper_style = self.cfg.get(COP, "EnforcedStyle").is_some_and(|v| v == "upper_case_q");

        // `correct_literal_style?` — already in the desired style, nothing
        // to flag.
        if upper_style == is_capital {
            return;
        }

        let l = node.location();
        let start = l.start_offset();
        let end = l.end_offset();
        let src = &self.src[start..end];

        // `ast = parse(corrected(node.source)).ast; return if node.children
        // != ast&.children`. `corrected` swaps the case of the single letter
        // right after `%` (guaranteed to be the first occurrence of that
        // character anywhere in the source, so a plain byte swap at index 1
        // matches Ruby's `src.sub(src[1], src[1].swapcase)` exactly). Then
        // it's a genuine re-parse: escape-sequence semantics differ between
        // `%q` (only `\\` and `\<delimiter>` are special) and `%Q` (full
        // double-quote escapes, plus real `#{}` interpolation), so whether
        // the content — or even the node shape (`str` vs `dstr`) — survives
        // the swap can only be answered by actually re-parsing, not by a
        // text heuristic.
        let mut corrected = src.to_vec();
        corrected[1] = if is_capital { b'q' } else { b'Q' };
        let result = ruby_prism::parse(&corrected);
        if result.errors().next().is_some() {
            // Reparse failed (e.g. `%q(\u)` -> `%Q(\u)` is an invalid escape)
            // — rubocop's `parse` returns a nil ast, so `node.children != nil`
            // is true and the offense is skipped.
            return;
        }
        let Some(program) = result.node().as_program_node() else { return };
        let mut stmts = program.statements().body().iter();
        let Some(first) = stmts.next() else { return };
        if stmts.next().is_some() {
            return;
        }
        // If the swap turned this into a real interpolated string (`dstr`),
        // the node shape is entirely different from the original `str`
        // node's children — skip. Otherwise compare the actual unescaped
        // string content.
        let Some(new_str) = first.as_string_node() else { return };
        if new_str.unescaped() != node.unescaped() {
            return;
        }

        let (message, new_char): (&str, u8) = if upper_style {
            ("Use `%Q` instead of `%q`.", b'Q')
        } else {
            ("Do not use `%Q` unless interpolation is needed. Use `%q`.", b'q')
        };
        self.push(start, COP, true, message);
        let char_off = opening.start_offset() + 1;
        self.fixes.push((char_off, char_off + 1, vec![new_char]));
    }

    /// Style/BarePercentLiterals — enforces `%()` vs `%Q()` per `EnforcedStyle`
    /// (`bare_percent` default / `percent_q`).
    ///
    /// Ported from rubocop's `BarePercentLiterals` cop, which checks both
    /// `on_str` and `on_dstr` via a shared `check` method. This handles
    /// percent-literal strings that don't require re-parsing (unlike
    /// PercentQLiterals which must check semantic equivalence).
    ///
    /// The fix is a simple text replacement: swap `%Q(...)` <-> `%(...)`.
    fn check_bare_percent_literals_impl(&mut self, opening: Option<ruby_prism::Location>, l: ruby_prism::Location) {
        const COP: &str = "Style/BarePercentLiterals";
        if !self.on(COP) {
            return;
        }
        let Some(open) = opening else { return };
        let open_src = open.as_slice();
        if !open_src.starts_with(b"%") {
            return;
        }

        // Determine the EnforcedStyle: bare_percent (default) or percent_q
        let enforce_percent_q = self.cfg.get(COP, "EnforcedStyle").is_some_and(|v| v == "percent_q");

        // Check which style violations exist
        let is_percent_q = open_src.starts_with(b"%Q");
        let is_bare = open_src.starts_with(b"%") && !is_percent_q;

        // Determine if we need to flag this
        let should_flag = if enforce_percent_q {
            // percent_q style: bare % is wrong, %Q is correct
            is_bare
        } else {
            // bare_percent style: %Q is wrong, bare % is correct
            is_percent_q
        };

        if !should_flag {
            return;
        }

        // Generate message and replacement
        let (message, new_prefix) = if enforce_percent_q {
            // Bare percent should be %Q
            ("Use `%Q` instead of `%`.", b"%Q".to_vec())
        } else {
            // %Q should be bare percent
            ("Use `%` instead of `%Q`.", b"%".to_vec())
        };

        self.push(l.start_offset(), COP, true, message);

        // Replace the opening delimiter: swap % <-> %Q
        // The opening_loc contains the full delimiter like "%(", "%Q(", "%{", "%Q{", etc.
        let mut replacement = new_prefix;
        // Append the delimiter character(s) from the original opening
        if open_src.len() > 2 {
            replacement.extend_from_slice(&open_src[2..]);
        } else if open_src.len() > 1 {
            replacement.push(open_src[1]);
        }
        self.fixes.push((open.start_offset(), open.end_offset(), replacement));
    }

    pub(crate) fn check_bare_percent_literals_str(&mut self, node: &ruby_prism::StringNode<'_>) {
        self.check_bare_percent_literals_impl(node.opening_loc(), node.location());
    }

    pub(crate) fn check_bare_percent_literals_dstr(&mut self, node: &ruby_prism::InterpolatedStringNode<'_>) {
        self.check_bare_percent_literals_impl(node.opening_loc(), node.location());
    }
}

impl<'a> super::Cops<'a> {
    /// Style/NestedParenthesizedCalls — a parenthesis-less method call
    /// nested directly (one level deep, as receiver or argument — NOT
    /// recursively) inside the argument list of a PARENTHESIZED call must
    /// itself get parens. Verbatim port of `on_send`/`allowed_omission?`/
    /// `allowed?`: `node.each_child_node(:call)` in whitequark walks only
    /// the send node's immediate AST children (receiver + each argument),
    /// which is why `method(block_taker { another_method 1 })` is clean —
    /// `another_method 1` sits two levels down, inside the block body, and
    /// is never visited from `method`'s own on_send. Every parenthesized
    /// call anywhere in the tree gets its own independent check (this hook
    /// runs for every `CallNode`, not just outermost ones), so
    /// `foo(bar(baz qux))` still flags `baz qux` — via `bar(...)`'s own
    /// on_send, since `bar(...)` is itself parenthesized.
    pub(crate) fn check_nested_parenthesized_calls(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/NestedParenthesizedCalls";
        if !self.on(COP) {
            return;
        }
        if !npc_parenthesized(node.opening_loc()) {
            return;
        }
        let outer_arg_count = node.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0);

        let mut candidates: Vec<ruby_prism::Node> = Vec::new();
        if let Some(r) = node.receiver() {
            candidates.push(r);
        }
        if let Some(a) = node.arguments() {
            candidates.extend(a.arguments().iter());
        }

        for cand in candidates {
            let Some(nested) = cand.as_call_node() else { continue };
            if self.npc_allowed_omission(&nested, outer_arg_count) {
                continue;
            }
            let loc = nested.location();
            let source = String::from_utf8_lossy(&self.src[loc.start_offset()..loc.end_offset()]).into_owned();
            self.push(loc.start_offset(), COP, true, format!("Add parentheses to nested method call `{source}`."));
            self.npc_autocorrect(&nested);
        }
    }

    /// `allowed_omission?`: skip a nested call that has no arguments, is
    /// already parenthesized, is a setter (`obj.attr = val`), is an
    /// operator method (`a + b`, `a[i]`, ...), or is individually allowed
    /// via `allowed?` (see below).
    fn npc_allowed_omission(&self, nested: &ruby_prism::CallNode, outer_arg_count: usize) -> bool {
        let nested_args = nested.arguments();
        let nested_arg_count = nested_args.as_ref().map(|a| a.arguments().iter().count()).unwrap_or(0);
        if nested_arg_count == 0 {
            return true;
        }
        if npc_parenthesized(nested.opening_loc()) {
            return true;
        }
        if nested.is_attribute_write() {
            return true;
        }
        if RS_OPERATOR_METHODS.contains(&nested.name().as_slice()) {
            return true;
        }
        // `allowed?`: the OUTER (parenthesized) call has exactly one
        // argument, the nested call's own method name is in
        // `AllowedMethods`, and the nested call itself has exactly one
        // argument.
        outer_arg_count == 1
            && nested_arg_count == 1
            && self.allowed("Style/NestedParenthesizedCalls", nested.name().as_slice())
    }

    /// `autocorrect`: replace the (possibly backslash-continued,
    /// whitespace-padded) gap between the nested call's selector and its
    /// first argument with `(`, then insert `)` right after the last
    /// argument. Mirrors `range_with_surrounding_space(first_arg.begin,
    /// side: :left, whitespace: true, continuations: true)` — see
    /// `npc_leading_space_start` for the exact left-extension algorithm.
    fn npc_autocorrect(&mut self, nested: &ruby_prism::CallNode) {
        let Some(args) = nested.arguments() else { return };
        let items: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        let (Some(first), Some(last)) = (items.first(), items.last()) else { return };
        let first_start = first.location().start_offset();
        let last_end = last.location().end_offset();
        let leading_start = npc_leading_space_start(self.src, first_start);
        self.fixes.push((leading_start, first_start, b"(".to_vec()));
        self.fixes.push((last_end, last_end, b")".to_vec()));
    }
}

/// `ParameterizedNode#parenthesized?` (`loc_is?(:end, ')')`, equivalent
/// here to checking the opening delimiter of the argument list is `(` —
/// excludes `[...]` (aref) and bare unparenthesized calls alike).
fn npc_parenthesized(opening: Option<ruby_prism::Location>) -> bool {
    opening.is_some_and(|o| o.as_slice() == b"(")
}

/// `RangeHelp#range_with_surrounding_space(range: first_arg.begin, side:
/// :left, whitespace: true, continuations: true)` — rubocop's `final_pos`
/// walks left through FOUR separate, sequential phases, each fully
/// consumed before the next starts: horizontal whitespace, then
/// backslash-newline continuations, then bare newlines, then (since
/// `whitespace: true`) any remaining `\s` at all (which can eat back
/// through more spaces/newlines the earlier phases already stopped at
/// their own boundaries).
fn npc_leading_space_start(src: &[u8], mut pos: usize) -> usize {
    while pos > 0 && matches!(src[pos - 1], b' ' | b'\t') {
        pos -= 1;
    }
    while pos >= 2 && &src[pos - 2..pos] == b"\\\n" {
        pos -= 2;
    }
    while pos > 0 && src[pos - 1] == b'\n' {
        pos -= 1;
    }
    while pos > 0 && matches!(src[pos - 1], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        pos -= 1;
    }
    pos
}
impl<'a> super::Cops<'a> {
    /// Style/StringLiteralsInInterpolation — strings inside `#{}` interpolations
    /// must match the configured quote style. Only runs when inside an
    /// interpolation (interp_depth > 0). Similar to check_string_literals but
    /// operates on strings within interpolations and uses different messaging.
    pub(crate) fn check_string_literals_in_interpolation(&mut self, node: &ruby_prism::StringNode) {
        const COP: &str = "Style/StringLiteralsInInterpolation";
        if !self.hot.string_literals_in_interpolation || self.interp_depth == 0 {
            return;
        }
        // Upstream's inside_interpolation? counts only dstr/dsym/regexp
        // parents — a string whose nearest #{} belongs to an xstring
        // (interp_depth exactly one past the depth recorded when that
        // xstr was entered) is exempt; a deeper dstr re-qualifies.
        if self.xstr_interp_base.last().is_some_and(|&b| self.interp_depth == b + 1) {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let src = self.node_src(&node.as_node());
        let l = node.location();
        let c = node.content_loc().as_slice();

        match self.hot.string_interp_style {
            1 if open.as_slice() == b"\"" => {
                // Prefer single quotes, but have double quotes
                if !double_quotes_required(src) {
                    self.push(l.start_offset(), COP, true, "Prefer single-quoted strings inside interpolations.");
                    if !c.contains(&b'\n') {
                        // Same fix logic as check_string_literals: double -> single
                        let mut runtime = Vec::new();
                        let mut i = 0;
                        while i < c.len() {
                            if c[i] == b'\\' && matches!(c.get(i + 1), Some(b'"') | Some(b'\\')) {
                                runtime.push(c[i + 1]);
                                i += 2;
                            } else {
                                runtime.push(c[i]);
                                i += 1;
                            }
                        }
                        let mut esc = Vec::new();
                        for b in &runtime {
                            if *b == b'\\' {
                                esc.extend_from_slice(b"\\\\");
                            } else {
                                esc.push(*b);
                            }
                        }
                        let mut rep = vec![b'\''];
                        let mut i = 0;
                        while i < esc.len() {
                            if esc[i] == b'\\' && esc.get(i + 1) == Some(&b'"') {
                                rep.push(b'"');
                                i += 2;
                            } else {
                                rep.push(esc[i]);
                                i += 1;
                            }
                        }
                        rep.push(b'\'');
                        self.fixes.push((l.start_offset(), l.end_offset(), rep));
                    }
                }
            }
            2 if open.as_slice() == b"'" => {
                // Prefer double quotes, but have single quotes
                if !single_quotes_required(src) {
                    self.push(l.start_offset(), COP, true, "Prefer double-quoted strings inside interpolations.");
                    // Single -> double fix
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

}
impl<'a> super::Cops<'a> {

    /// Style/CaseEquality — Avoid the use of the case equality operator `===`.
    /// Checks for === calls and suggests alternatives based on the receiver type.
    /// - For ranges: (1..10) === var → (1..10).include?(var)
    /// - For constants: Array === var → var.is_a?(Array)
    /// - For self.class: self.class === var → var.is_a?(self.class)
    /// Respects AllowOnConstant and AllowOnSelfClass configuration options.
    pub(crate) fn check_case_equality(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/CaseEquality";
        if !self.on(COP) {
            return;
        }

        // Only handle === operator
        if node.name().as_slice() != b"===" {
            return;
        }

        let Some(lhs) = node.receiver() else { return };
        let Some(args) = node.arguments() else { return };
        let Some(rhs_node) = args.arguments().iter().next() else { return };

        // Skip if receiver is a regexp
        if lhs.as_regular_expression_node().is_some() || lhs.as_interpolated_regular_expression_node().is_some() {
            return;
        }

        // `lhs.const_type? && !lhs.module_name?`: a const receiver whose
        // final segment isn't CamelCase (all-caps like URI::HTTPS — a
        // value-ish constant) is skipped by upstream regardless of config.
        let const_last_name: Option<&[u8]> = if let Some(c) = lhs.as_constant_read_node() {
            Some(c.name().as_slice())
        } else {
            lhs.as_constant_path_node().and_then(|p| p.name().map(|n| n.as_slice()))
        };
        if let Some(name) = const_last_name {
            let module_name = name.first().is_some_and(u8::is_ascii_uppercase)
                && name.iter().any(u8::is_ascii_lowercase);
            if !module_name {
                return;
            }
        }

        // Check AllowOnConstant config
        let allow_on_constant = self.cfg.get(COP, "AllowOnConstant") == Some("true");
        if (lhs.as_constant_read_node().is_some() || lhs.as_constant_path_node().is_some()) && allow_on_constant {
            return;
        }

        // Check AllowOnSelfClass config
        let allow_on_self_class = self.cfg.get(COP, "AllowOnSelfClass") == Some("true");
        if is_self_class(&lhs) && allow_on_self_class {
            return;
        }

        // Report offense at the === operator
        let Some(msg_loc) = node.message_loc() else { return };
        self.push(msg_loc.start_offset(), COP, true, "Avoid the use of the case equality operator `===`.");

        // Try to generate an autocorrect
        if let Some(replacement) = case_equality_replacement(&lhs, &rhs_node, self.src) {
            let loc = node.location();
            self.fixes.push((loc.start_offset(), loc.end_offset(), replacement));
        }
    }
}

/// Check if a node is `self.class`
fn is_self_class(node: &ruby_prism::Node) -> bool {
    if let Some(call) = node.as_call_node() {
        // Check if it's a send call to :class on self (receiver is Self)
        if call.name().as_slice() == b"class" {
            if let Some(receiver) = call.receiver() {
                if let Some(_) = receiver.as_self_node() {
                    return true;
                }
            }
        }
    }
    false
}

/// Generate replacement for a case equality call.
/// Returns the full replacement bytes, or None if no replacement can be generated.
fn case_equality_replacement(lhs: &ruby_prism::Node, rhs: &ruby_prism::Node, src: &[u8]) -> Option<Vec<u8>> {
    // Get source code for lhs and rhs
    let lhs_start = lhs.location().start_offset();
    let lhs_end = lhs.location().end_offset();
    let lhs_src = &src[lhs_start..lhs_end];

    let rhs_start = rhs.location().start_offset();
    let rhs_end = rhs.location().end_offset();
    let rhs_src = &src[rhs_start..rhs_end];

    if let Some(begin) = lhs.as_begin_node() {
        // Check if it's a Range inside begin
        if let Some(first_child) = begin.statements().and_then(|s| s.body().iter().next()) {
            if first_child.as_range_node().is_some() {
                // (1..10) === var → (1..10).include?(var)
                let mut replacement = lhs_src.to_vec();
                replacement.extend_from_slice(b".include?(");
                replacement.extend_from_slice(rhs_src);
                replacement.push(b')');
                return Some(replacement);
            }
        }
    } else if lhs.as_range_node().is_some() {
        // Range without begin: 1..10 === var → (1..10).include?(var)
        let mut replacement = b"(".to_vec();
        replacement.extend_from_slice(lhs_src);
        replacement.extend_from_slice(b").include?(");
        replacement.extend_from_slice(rhs_src);
        replacement.push(b')');
        return Some(replacement);
    } else if lhs.as_constant_read_node().is_some() || lhs.as_constant_path_node().is_some() {
        // Constant: Array === var → var.is_a?(Array)
        let rhs_needs_parens = needs_parentheses(rhs);
        let mut replacement = if rhs_needs_parens { b"(".to_vec() } else { Vec::new() };
        replacement.extend_from_slice(rhs_src);
        if rhs_needs_parens {
            replacement.push(b')');
        }
        replacement.extend_from_slice(b".is_a?(");
        replacement.extend_from_slice(lhs_src);
        replacement.push(b')');
        return Some(replacement);
    } else if is_self_class(lhs) {
        // self.class: self.class === var → var.is_a?(self.class)
        let rhs_needs_parens = needs_parentheses(rhs);
        let mut replacement = if rhs_needs_parens { b"(".to_vec() } else { Vec::new() };
        replacement.extend_from_slice(rhs_src);
        if rhs_needs_parens {
            replacement.push(b')');
        }
        replacement.extend_from_slice(b".is_a?(");
        replacement.extend_from_slice(lhs_src);
        replacement.push(b')');
        return Some(replacement);
    }

    None
}

/// Check if RHS needs parentheses when converting Array === a + b to (a + b).is_a?(Array)
fn needs_parentheses(node: &ruby_prism::Node) -> bool {
    // and/or nodes need parentheses
    if node.as_and_node().is_some() || node.as_or_node().is_some() {
        return true;
    }
    // if/unless nodes need parentheses
    if node.as_if_node().is_some() || node.as_unless_node().is_some() {
        return true;
    }
    // range nodes need parentheses
    if node.as_range_node().is_some() {
        return true;
    }
    // Assignment nodes need parentheses
    if node.as_local_variable_write_node().is_some()
        || node.as_instance_variable_write_node().is_some()
        || node.as_class_variable_write_node().is_some()
        || node.as_global_variable_write_node().is_some()
        || node.as_constant_write_node().is_some()
        || node.as_constant_path_write_node().is_some()
    {
        return true;
    }
    // Call nodes: operator methods and unary operations need parentheses
    if let Some(call) = node.as_call_node() {
        let name = call.name().as_slice();
        // Check for operator methods (including binary operators)
        if is_operator_method_name(name) {
            return true;
        }
    }

    false
}

/// Check if a method name is an operator method
fn is_operator_method_name(name: &[u8]) -> bool {
    matches!(
        name,
        b"|" | b"^"
            | b"&"
            | b"<=>"
            | b"=="
            | b"==="
            | b"=~"
            | b">"
            | b">="
            | b"<"
            | b"<="
            | b"<<"
            | b">>"
            | b"+"
            | b"-"
            | b"*"
            | b"/"
            | b"%"
            | b"**"
            | b"~"
            | b"+@"
            | b"-@"
            | b"!@"
            | b"~@"
            | b"[]"
            | b"[]="
            | b"!"
            | b"!="
            | b"!~"
            | b"`"
    )
}

impl<'a> super::Cops<'a> {
    /// Style/RedundantException — checks for `raise`/`fail` with explicit
    /// `RuntimeError` that can be simplified. Handles two patterns:
    /// 1. `raise RuntimeError, 'message'` → `raise 'message'`
    /// 2. `raise RuntimeError.new('message')` → `raise 'message'`
    ///
    /// Ported from rubocop's two node matchers: exploded (comma-separated) and
    /// compact (new call) forms.
    pub(crate) fn check_redundant_exception(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/RedundantException";
        if !self.on(COP) {
            return;
        }

        let method_name = node.name().as_slice();
        if !matches!(method_name, b"raise" | b"fail") {
            return;
        }

        // Try the compact form first (RuntimeError.new(message))
        if let Some(args_node) = node.arguments() {
            let args: Vec<ruby_prism::Node> = args_node.arguments().iter().collect();
            if args.len() == 1 {
                if let Some(new_call) = args[0].as_call_node() {
                    if new_call.name().as_slice() == b"new" {
                        if let Some(receiver) = new_call.receiver() {
                            if self.re_is_runtime_error_const(&receiver) {
                                if let Some(new_args_node) = new_call.arguments() {
                                    let new_args: Vec<ruby_prism::Node> = new_args_node.arguments().iter().collect();
                                    if new_args.len() == 1 {
                                        let message = &new_args[0];
                                        self.push(
                                            node.location().start_offset(),
                                            COP,
                                            true,
                                            "Redundant `RuntimeError.new` call can be replaced with just the message.",
                                        );
                                        let msg_src = self.node_src(message);
                                        let is_string = self.re_is_string(message);
                                        let replacement = if is_string {
                                            msg_src.to_vec()
                                        } else {
                                            let mut buf = msg_src.to_vec();
                                            buf.extend_from_slice(b".to_s");
                                            buf
                                        };
                                        self.fixes.push((new_call.location().start_offset(), new_call.location().end_offset(), replacement));
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try the exploded form (raise RuntimeError, message)
        if let Some(args_node) = node.arguments() {
            let args: Vec<ruby_prism::Node> = args_node.arguments().iter().collect();
            if args.len() == 2 {
                if self.re_is_runtime_error_const(&args[0]) {
                    let message = &args[1];
                    self.push(
                        node.location().start_offset(),
                        COP,
                        true,
                        "Redundant `RuntimeError` argument can be removed.",
                    );

                    let msg_src = self.node_src(message);
                    let is_string = self.re_is_string(message);

                    // Build replacement
                    let is_parenthesized = node.opening_loc().is_some();
                    let arg = if is_string {
                        msg_src.to_vec()
                    } else {
                        let mut buf = msg_src.to_vec();
                        buf.extend_from_slice(b".to_s");
                        buf
                    };

                    let mut replacement = Vec::new();
                    replacement.extend_from_slice(b"raise");
                    if is_parenthesized {
                        replacement.push(b'(');
                        replacement.extend_from_slice(&arg);
                        replacement.push(b')');
                    } else {
                        replacement.push(b' ');
                        replacement.extend_from_slice(&arg);
                    }

                    self.fixes.push((node.location().start_offset(), node.location().end_offset(), replacement));
                }
            }
        }
    }

    /// Check if a node is the RuntimeError constant (with or without :: prefix)
    fn re_is_runtime_error_const(&self, node: &ruby_prism::Node) -> bool {
        let const_node = match node.as_constant_read_node() {
            Some(c) => c,
            None => return false,
        };

        const_node.name().as_slice() == b"RuntimeError"
    }

    /// Check if a message node is a string type (including interpolated strings)
    fn re_is_string(&self, node: &ruby_prism::Node) -> bool {
        node.as_string_node().is_some()
            || node.as_interpolated_string_node().is_some()
            || node.as_x_string_node().is_some()
            || node.as_interpolated_x_string_node().is_some()
    }
}

impl<'a> super::Cops<'a> {
    /// Style/NestedModifier — nested modifier `if`/`unless`/`while`/`until`
    /// (`something if a if b`): a modifier conditional whose immediate
    /// syntactic PARENT is itself another modifier conditional. Ported from
    /// rubocop's `on_if`/`on_while`/`on_until` (all aliased to the same
    /// `check(node)`): `modifier?(node) && modifier?(node.parent)` where
    /// `modifier?` is `node&.basic_conditional? && node.modifier_form?`.
    ///
    /// rubocop's `node.parent` needs no tracking here: a modifier
    /// conditional's ONLY two AST children are its condition and its
    /// (single-statement) body, and — verified live against real rubocop —
    /// any parenthesized sub-expression wraps in an intervening `begin`
    /// node that breaks the direct parent/child edge, so the ONLY way a
    /// modifier node's true immediate parent can itself be a modifier
    /// conditional is if it IS that parent's condition or its sole body
    /// statement. Unparenthesized modifier chains are strictly
    /// left-associative (`a if b if c` parses as `(a if b) if c`), so in
    /// practice only the body slot ever matches — but this is called from
    /// every outer modifier node's own visit (pre-order, before recursing),
    /// inspecting its OWN body's sole statement for a qualifying inner, which
    /// is exactly equivalent to rubocop's parent-pointer check without
    /// needing one.
    ///
    /// Ported to prism: `node.body` (rubocop's whitequark AST, where `unless`
    /// is just an `:if` node with swapped branches, and a single-statement
    /// body is the statement itself, not wrapped) is
    /// `body_stmts.body().first()` here, matched against `IfNode`/
    /// `UnlessNode`/`WhileNode`/`UntilNode` via `nested_modifier_info`. A
    /// `begin...end while/until cond` post-condition loop is a DIFFERENT
    /// rubocop-ast node type (`:while_post`/`:until_post`, never
    /// `basic_conditional?`); prism instead flags it via
    /// `is_begin_modifier()` on the same `WhileNode`/`UntilNode` type, which
    /// `nested_modifier_info` excludes to match.
    ///
    /// Suppression: rubocop's `ignore_node`/`part_of_ignored_node?` means a
    /// long chain (`a until b while c unless d if e`) reports only ONE
    /// offense — the outermost qualifying pair — since flagging the inner of
    /// that pair marks its ENTIRE range (which, being a modifier node,
    /// starts at its own body and so contains every node nested beneath it)
    /// as ignored; any deeper candidate's start offset then falls inside
    /// that range and is skipped. `nested_modifier_ignored` reproduces this
    /// with plain byte-range containment instead of an ancestor walk.
    ///
    /// Autocorrect ports `autocorrect`/`new_expression`/`replacement_operator`/
    /// `left_hand_operand`/`right_hand_operand`/`add_parentheses_to_method_arguments`/
    /// `requires_parens?` verbatim, and only ever fires when BOTH the inner
    /// and outer are `if`/`unless` (rubocop's `node.if_type? &&
    /// node.parent.if_type?` — both compile to the same whitequark `:if`
    /// type; `while`/`until` never qualify, matching the "not correctable"
    /// spec examples). The corrector replaces from the inner's keyword
    /// through the OUTER's condition end (`range_between(node.loc.keyword
    /// .begin_pos, node.parent.condition.source_range.end_pos)`) with
    /// `"#{outer.keyword} #{lh} #{op} #{rh}"`.
    pub(crate) fn check_nested_modifier(
        &mut self,
        outer_keyword: &str,
        outer_cond: ruby_prism::Node,
        outer_body_stmts: Option<ruby_prism::StatementsNode>,
        outer_is_if_type: bool,
    ) {
        const COP: &str = "Style/NestedModifier";
        if !self.on(COP) {
            return;
        }
        let Some(body) = outer_body_stmts.and_then(|s| s.body().iter().next()) else { return };
        let Some((inner_keyword, inner_kw_loc, inner_cond, inner_is_if_type)) =
            nested_modifier_info(&body)
        else {
            return;
        };

        let body_loc = body.location();
        let (inner_start, inner_end) = (body_loc.start_offset(), body_loc.end_offset());
        if self.nested_modifier_ignored.iter().any(|&(s, e)| inner_start >= s && inner_start < e) {
            return;
        }

        // rubocop's CLI only shows `[Correctable]` when the corrector block
        // actually produces a change; since that's exactly the `if_type?`
        // pair condition `autocorrect` checks below, compute it up front.
        let correctable = inner_is_if_type && outer_is_if_type;
        self.push(inner_kw_loc.start_offset(), COP, correctable, "Avoid using nested modifiers.");
        self.nested_modifier_ignored.push((inner_start, inner_end));

        if !correctable {
            return; // `autocorrect`'s `return unless node.if_type? && node.parent.if_type?`
        }

        // `replacement_operator`
        let operator: &[u8] = if outer_keyword == "if" { b"&&" } else { b"||" };

        // `left_hand_operand`: outer's own condition, source verbatim,
        // parenthesized only if it's an `or`/`||` AND the operator is `&&`.
        let outer_cond_src = self.node_src(&outer_cond).to_vec();
        let lh = if outer_cond.as_or_node().is_some() && operator == b"&&" {
            let mut v = Vec::with_capacity(outer_cond_src.len() + 2);
            v.push(b'(');
            v.extend_from_slice(&outer_cond_src);
            v.push(b')');
            v
        } else {
            outer_cond_src
        };

        // `right_hand_operand`
        let mut rh = if let Some(call) = inner_cond.as_call_node().filter(|c| {
            c.arguments().is_some_and(|a| a.arguments().iter().next().is_some())
                && !nm_is_operator_method(c.name().as_slice())
        }) {
            nm_add_parens_to_method_args(self, &call)
        } else {
            self.node_src(&inner_cond).to_vec()
        };
        if nm_requires_parens(&inner_cond) {
            let mut v = Vec::with_capacity(rh.len() + 2);
            v.push(b'(');
            v.extend_from_slice(&rh);
            v.push(b')');
            rh = v;
        }
        if inner_keyword != outer_keyword {
            let mut v = Vec::with_capacity(rh.len() + 1);
            v.push(b'!');
            v.extend_from_slice(&rh);
            rh = v;
        }

        // `new_expression`
        let mut replacement = Vec::new();
        replacement.extend_from_slice(outer_keyword.as_bytes());
        replacement.push(b' ');
        replacement.extend_from_slice(&lh);
        replacement.push(b' ');
        replacement.extend_from_slice(operator);
        replacement.push(b' ');
        replacement.extend_from_slice(&rh);

        let range_start = inner_kw_loc.start_offset();
        let range_end = outer_cond.location().end_offset();
        self.fixes.push((range_start, range_end, replacement));
    }
}

/// Identifies whether `node` is a modifier-form `if`/`unless`/`while`/
/// `until` — the shapes `Style/NestedModifier` treats as a potential INNER
/// (or, from the caller's own guard, OUTER) half of a nested pair — and
/// returns its rubocop-visible `keyword`, the `Location` `add_offense`
/// anchors on, its condition node, and whether it's an `if_type?` node
/// (`if`/`unless`, both the same whitequark `:if` type — `while`/`until`
/// never satisfy `node.if_type?` and so never autocorrect).
fn nested_modifier_info<'pr>(
    node: &ruby_prism::Node<'pr>,
) -> Option<(&'static str, ruby_prism::Location<'pr>, ruby_prism::Node<'pr>, bool)> {
    if let Some(n) = node.as_if_node() {
        let kw = n.if_keyword_loc()?; // absent for ternaries
        if n.end_keyword_loc().is_some() {
            return None;
        }
        return Some(("if", kw, n.predicate(), true));
    }
    if let Some(n) = node.as_unless_node() {
        if n.end_keyword_loc().is_some() {
            return None;
        }
        return Some(("unless", n.keyword_loc(), n.predicate(), true));
    }
    if let Some(n) = node.as_while_node() {
        if n.is_begin_modifier() {
            return None;
        }
        let kw_start = n.keyword_loc().start_offset();
        if !n.statements().is_some_and(|s| s.location().start_offset() < kw_start) {
            return None;
        }
        return Some(("while", n.keyword_loc(), n.predicate(), false));
    }
    if let Some(n) = node.as_until_node() {
        if n.is_begin_modifier() {
            return None;
        }
        let kw_start = n.keyword_loc().start_offset();
        if !n.statements().is_some_and(|s| s.location().start_offset() < kw_start) {
            return None;
        }
        return Some(("until", n.keyword_loc(), n.predicate(), false));
    }
    None
}

/// `requires_parens?`: `node.or_type? || !(COMPARISON_OPERATORS &
/// node.children).empty?` — true for an `or`/`||` node, or a comparison
/// send (`==`, `===`, `!=`, `<=`, `>=`, `>`, `<`).
fn nm_requires_parens(node: &ruby_prism::Node) -> bool {
    if node.as_or_node().is_some() {
        return true;
    }
    node.as_call_node().is_some_and(|c| {
        matches!(c.name().as_slice(), b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<")
    })
}

/// `MethodIdentifierPredicates::OPERATOR_METHODS` (`operator_method?`).
fn nm_is_operator_method(name: &[u8]) -> bool {
    matches!(
        name,
        b"|" | b"^"
            | b"&"
            | b"<=>"
            | b"=="
            | b"==="
            | b"=~"
            | b">"
            | b">="
            | b"<"
            | b"<="
            | b"<<"
            | b">>"
            | b"+"
            | b"-"
            | b"*"
            | b"/"
            | b"%"
            | b"**"
            | b"~"
            | b"+@"
            | b"-@"
            | b"!@"
            | b"~@"
            | b"[]"
            | b"[]="
            | b"!"
            | b"!="
            | b"!~"
            | b"`"
    )
}

/// `add_parentheses_to_method_arguments`: rebuild `recv.method(args, ...)`
/// verbatim from a `send`'s parts (used when the condition is a
/// non-operator method call with arguments but no parens of its own, e.g.
/// `[1, 2].include? a` -> `[1, 2].include?(a)`).
fn nm_add_parens_to_method_args(cops: &super::Cops<'_>, call: &ruby_prism::CallNode) -> Vec<u8> {
    let mut expr = Vec::new();
    if let Some(recv) = call.receiver() {
        expr.extend_from_slice(cops.node_src(&recv));
        expr.push(b'.');
    }
    expr.extend_from_slice(call.name().as_slice());
    expr.push(b'(');
    if let Some(args) = call.arguments() {
        let items: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        for (i, arg) in items.iter().enumerate() {
            if i > 0 {
                expr.extend_from_slice(b", ");
            }
            expr.extend_from_slice(cops.node_src(arg));
        }
    }
    expr.push(b')');
    expr
}

impl<'a> super::Cops<'a> {
    /// Style/WhileUntilModifier — the mirror image of `MultilineIfModifier`:
    /// a FULL `while`/`until ... end` whose single-statement body would
    /// still fit `Layout/LineLength`'s `Max` once flattened into modifier
    /// form (`body while cond`). Ported from the `StatementModifier` mixin's
    /// `single_line_as_modifier?`, with `WhileUntilModifier#non_eligible_body?`
    /// adding the `body&.conditional?` guard on top of the mixin's own
    /// `super` checks.
    ///
    /// `node.modifier_form?` (`loc.end.nil?`) becomes prism's
    /// `closing_loc().is_none()` — a modifier-form `while`/`until` parses to
    /// the SAME `WhileNode`/`UntilNode` type, just without a `end` keyword
    /// location, so bail immediately when there's no closing to anchor on.
    ///
    /// `body.begin_type?` (whitequark's IMPLICIT multi-statement wrapper,
    /// used only when a loop body holds more than one top-level statement)
    /// has no prism counterpart node — prism never wraps a multi-statement
    /// body in an extra node, it just puts >1 entries in `statements().body()`
    /// directly. So that check becomes `body_list.len() != 1` here. This is
    /// NOT the same thing as an explicit `begin...end` used as the (single)
    /// loop body, which prism represents as a `BeginNode` occupying that one
    /// slot — whitequark calls that `kwbegin`, a different type that
    /// `begin_type?` does NOT match, so such a body stays eligible.
    ///
    /// `body&.conditional?` (`if`/`unless`/`while`/`until`/`case`/`case-in`)
    /// covers whitequark's unified `:if` type (which also represents
    /// `unless` and ternaries) by checking prism's `IfNode` AND `UnlessNode`
    /// separately.
    ///
    /// `condition.each_node.any?(&:lvasgn_type?)` (reject a condition that
    /// assigns a local variable anywhere in its subtree, e.g. `while (x = get)`)
    /// walks the predicate with a tiny `Visit` impl that only overrides the
    /// local-variable-write/target visitors — deliberately narrower than
    /// "any assignment": ivar/cvar/gvar/const assignment inside the
    /// condition is untouched by this check, matching `lvasgn_type?`'s
    /// specificity to LOCAL variables (the only kind whose modifier-form
    /// visibility actually changes).
    ///
    /// The disable-directive short-circuit in the mixin's
    /// `comment_disables_cop?` (used to decide whether a first-line comment
    /// counts as "real" text to preserve/reject on) is intentionally
    /// skipped: whether or not a first-line comment IS a
    /// `# rubocop:disable`/`:todo` for this cop (or `all`), the final
    /// visible offense list is identical either way — a real disable
    /// directive suppresses the offense downstream regardless of whether
    /// THIS cop's own eligibility math would have registered one. Treating
    /// every first-line comment as literal sidesteps re-parsing the
    /// directive regexp for a distinction that cannot change output.
    ///
    /// Autocorrect mirrors `to_modifier_form` (`body keyword cond`,
    /// parenthesized when the corrected expression would otherwise bind
    /// looser than its surrounding context, plus the preserved first-line
    /// comment) via `wum_parenthesize`'s best-effort backward source scan —
    /// see its doc comment for the caveat (no true AST-parent chain is
    /// available at this call site; this is UNEXERCISED by the fixture,
    /// which contains only `expect_no_offenses` examples).
    pub(crate) fn check_while_until_modifier(
        &mut self,
        node: &ruby_prism::Node,
        keyword_loc: ruby_prism::Location,
        predicate: ruby_prism::Node,
        statements: Option<ruby_prism::StatementsNode>,
        closing_loc: Option<ruby_prism::Location>,
        keyword: &'static str,
    ) {
        const COP: &str = "Style/WhileUntilModifier";
        if !self.on(COP) {
            return;
        }
        // `node.modifier_form?`
        let Some(closing) = closing_loc else { return };

        let node_loc = node.location();
        let node_start = node_loc.start_offset();
        let node_end = node_loc.end_offset();

        // ---- non_eligible_node? ----
        if wum_nonempty_line_count(&self.src[node_start..node_end]) > 3 {
            return;
        }
        let (first_line, _) = self.idx.loc(node_start);
        let (last_line, _) = self.idx.loc(node_end.saturating_sub(1));
        if self.wum_line_with_comment(last_line) {
            return;
        }
        let first_comment = self.wum_first_line_comment(first_line);
        let code_after = self.wum_code_after(closing);
        if first_comment.is_some() && code_after.is_some() {
            return;
        }

        // ---- non_eligible_body? (body.nil? / empty_source? / begin_type? /
        // contains_comment?), plus WhileUntilModifier's `conditional?` guard ----
        let Some(stmts) = statements else { return }; // body.nil?
        let body_list: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        if body_list.len() != 1 {
            return; // 0 statements (empty) or >1 (whitequark's implicit `begin`)
        }
        let body = &body_list[0];
        let body_loc = body.location();
        if body_loc.start_offset() == body_loc.end_offset() {
            return; // empty_source?
        }
        if wum_is_conditional(body) {
            return;
        }
        let (body_first_line, _) = self.idx.loc(body_loc.start_offset());
        let (body_last_line, _) = self.idx.loc(body_loc.end_offset().saturating_sub(1));
        if (body_first_line..=body_last_line).any(|l| self.wum_line_with_comment(l)) {
            return; // contains_comment?(body.source_range)
        }

        // ---- non_eligible_condition?: any local-variable assignment inside ----
        if wum_condition_has_lvasgn(&predicate) {
            return;
        }

        // ---- modifier_fits_on_single_line? ----
        let replacement =
            self.wum_to_modifier_form(body, &predicate, keyword, first_comment.as_deref(), node_start, node_end);
        let keyword_start = keyword_loc.start_offset();
        if let Some(max) = self.wum_max_line_length() {
            let len = self.wum_length_in_modifier_form(keyword_start, &replacement, code_after.as_deref());
            if len > max {
                return;
            }
        }

        // ---- offense + autocorrect ----
        self.push(
            keyword_start,
            COP,
            true,
            format!("Favor modifier `{keyword}` usage when having a single-line body."),
        );
        self.fixes.push((node_start, node_end, replacement.into_bytes()));
    }

    fn wum_line_with_comment(&self, line: usize) -> bool {
        self.comments.iter().any(|(l, _, _)| *l == line)
    }

    fn wum_first_line_comment(&self, line: usize) -> Option<&'a [u8]> {
        self.comments.iter().find(|(l, _, _)| *l == line).map(|(_, s, e)| &self.src[*s..*e])
    }

    /// `code_after`: whatever remains on the `end` keyword's own physical
    /// line, after the keyword — empty-string yields `None` (`unless
    /// code.empty?`), but a non-empty run of pure whitespace is still
    /// `Some` (rubocop never `.strip`s it).
    fn wum_code_after(&self, closing: ruby_prism::Location) -> Option<&'a [u8]> {
        let end_off = closing.end_offset();
        let (line, _) = self.idx.loc(closing.start_offset());
        let line_end = self.wum_line_end_offset(line);
        if end_off >= line_end {
            return None;
        }
        let code = &self.src[end_off..line_end];
        if code.is_empty() { None } else { Some(code) }
    }

    /// Byte offset one past the last non-newline character of `line`
    /// (1-based), i.e. excluding the trailing `\n`/`\r\n`.
    fn wum_line_end_offset(&self, line: usize) -> usize {
        if line < self.idx.starts.len() {
            let mut e = self.idx.starts[line] - 1;
            if e > 0 && self.src[e - 1] == b'\r' {
                e -= 1;
            }
            e
        } else {
            self.src.len()
        }
    }

    fn wum_to_modifier_form(
        &self,
        body: &ruby_prism::Node,
        predicate: &ruby_prism::Node,
        keyword: &str,
        first_comment: Option<&[u8]>,
        node_start: usize,
        node_end: usize,
    ) -> String {
        let body_src = String::from_utf8_lossy(self.node_src(body));
        let cond_src = String::from_utf8_lossy(self.node_src(predicate));
        let expr = format!("{body_src} {keyword} {cond_src}");
        let parenthesized =
            if self.wum_parenthesize(node_start, node_end) { format!("({expr})") } else { expr };
        match first_comment {
            Some(c) => format!("{parenthesized} {}", String::from_utf8_lossy(c)),
            None => parenthesized,
        }
    }

    /// `parenthesize?`: parenthesize the corrected modifier expression when
    /// dropping it in place, unparenthesized, would change the meaning of
    /// its surrounding expression (assignment RHS, `and`/`or`/`&&`/`||`
    /// operand, array/hash-literal element, bare method-call argument, or
    /// the receiver of a chained call like `end.freeze`) — all cases where
    /// modifier-`while`/`until`'s low precedence would otherwise swallow
    /// more than the original full-form statement did.
    ///
    /// Ported WITHOUT a real AST-parent chain (none is tracked by this
    /// visitor): a best-effort scan of the raw source immediately
    /// surrounding the node — backward from its start (skipping
    /// whitespace/newlines) for assignment/operator/argument contexts, and
    /// forward from its end for the `parent.send_type?` receiver case
    /// (`end.method` / `end&.method`, immediately adjacent with no
    /// intervening whitespace since Ruby doesn't allow a newline before a
    /// leading `.`/`&.`). This is coarser than `node.parent` (e.g. it
    /// cannot distinguish a `(` that opens a method call's argument list
    /// from one that opens a plain parenthesized group), but a full-form
    /// `while`/`until` used as an expression's operand/argument/RHS/receiver
    /// is already an unusual construct, and this path is UNEXERCISED by the
    /// fixture (see the cop-level doc comment).
    fn wum_parenthesize(&self, node_start: usize, node_end: usize) -> bool {
        if self.src[node_end..].starts_with(b".") || self.src[node_end..].starts_with(b"&.") {
            return true;
        }
        let mut i = node_start;
        while i > 0 && matches!(self.src[i - 1], b' ' | b'\t' | b'\r' | b'\n') {
            i -= 1;
        }
        if i == 0 {
            return false;
        }
        let before = &self.src[..i];
        for op in [
            &b"&&="[..], b"||=", b"**=", b"<<=", b">>=", b"+=", b"-=", b"*=", b"/=", b"%=",
            b"&=", b"|=", b"^=",
        ] {
            if before.ends_with(op) {
                return true;
            }
        }
        if before.ends_with(b"=")
            && !before.ends_with(b"==")
            && !before.ends_with(b"!=")
            && !before.ends_with(b"<=")
            && !before.ends_with(b">=")
            && !before.ends_with(b"=>")
        {
            return true;
        }
        if before.ends_with(b"&&") || before.ends_with(b"||") {
            return true;
        }
        if wum_ends_with_word(before, b"and") || wum_ends_with_word(before, b"or") {
            return true;
        }
        // Array-literal element, hash-pair value, or a `,`-separated slot in
        // some other list: `,`/`[` are unambiguous (an index target like
        // `a[while ...]` is itself a `send` argument, same verdict).
        if before.ends_with(b",") || before.ends_with(b"[") {
            return true;
        }
        // `(` is ambiguous: a method-call's argument-list opener (`foo(` —
        // `parent.send_type?`, true) vs. a bare grouping paren already
        // present in the source (`(while ...)` — parent is neither
        // assignment/operator/array/pair/send, false; re-parenthesizing
        // would be redundant). Distinguish by what touches the `(` itself:
        // a call's `(` is never preceded by whitespace or another opening
        // bracket/operator.
        if before.ends_with(b"(") {
            let paren_at = before.len() - 1;
            return paren_at > 0
                && matches!(before[paren_at - 1],
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b']' | b')' | b'?' | b'!');
        }
        false
    }

    /// `config.cop_enabled?('Layout/LineLength')` — deliberately `cfg`'s raw
    /// config-file enablement, NOT `self.on()`: the latter also folds in
    /// this RUN's `--only`/`--except` restriction, but real rubocop's own
    /// `max_line_length` reads `Layout/LineLength`'s enablement straight off
    /// the `Config` object regardless of which cops `--only` narrowed this
    /// invocation down to.
    fn wum_max_line_length(&self) -> Option<usize> {
        if !self.cfg.cop_config_enabled("Layout/LineLength") {
            return None;
        }
        Some(
            self.cfg
                .get("Layout/LineLength", "Max")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(120),
        )
    }

    /// `length_in_modifier_form`: the length (in rubocop's `line_length`
    /// sense — characters, plus a tab-indentation surcharge) of the
    /// keyword's own physical line with the `while`/`until ... end` block
    /// replaced in place by its modifier-form rendering, and any trailing
    /// `code_after` (text following the original `end` on its line) still
    /// appended.
    fn wum_length_in_modifier_form(
        &self,
        kw_start: usize,
        replacement: &str,
        code_after: Option<&[u8]>,
    ) -> usize {
        let (line, _) = self.idx.loc(kw_start);
        let line_start = self.idx.starts[line - 1];
        let mut full = self.src[line_start..kw_start].to_vec();
        full.extend_from_slice(replacement.as_bytes());
        if let Some(ca) = code_after {
            full.extend_from_slice(ca);
        }
        self.wum_line_length(&full)
    }

    fn wum_line_length(&self, line: &[u8]) -> usize {
        let nchars =
            if line.is_ascii() { line.len() } else { String::from_utf8_lossy(line).chars().count() };
        nchars + self.wum_indentation_difference(line)
    }

    /// `indentation_difference`: 0 unless the (simulated) line itself
    /// starts with a tab, in which case each leading tab bills at
    /// `tab_width` columns instead of 1 (tabs elsewhere on the line, or on
    /// a line that doesn't START with one, are never adjusted).
    fn wum_indentation_difference(&self, line: &[u8]) -> usize {
        if line.first() != Some(&b'\t') {
            return 0;
        }
        let tab_width = self.wum_tab_width();
        let leading_tabs = line.iter().take_while(|&&b| b == b'\t').count();
        leading_tabs * tab_width.saturating_sub(1)
    }

    /// `tab_indentation_width`: `Layout/IndentationStyle`'s `IndentationWidth`
    /// if configured, else `configured_indentation_width`
    /// (`Layout/IndentationWidth`'s `Width`, default 2).
    fn wum_tab_width(&self) -> usize {
        self.cfg
            .param("Layout/IndentationStyle", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2)
    }
}

/// `nonempty_line_count`: `source.lines.grep(/\S/).size` — count of the
/// node's own physical lines (its exact byte range, not the surrounding
/// full lines) containing at least one non-whitespace byte.
fn wum_nonempty_line_count(src: &[u8]) -> usize {
    src.split(|&b| b == b'\n').filter(|line| line.iter().any(|&b| !b.is_ascii_whitespace())).count()
}

/// `body&.conditional?` (`CONDITIONALS = if/while/until/case/case_match`),
/// split across prism's `IfNode` (covers whitequark's unified `if`/ternary)
/// and the separately-typed `UnlessNode`.
fn wum_is_conditional(node: &ruby_prism::Node) -> bool {
    node.as_if_node().is_some()
        || node.as_unless_node().is_some()
        || node.as_while_node().is_some()
        || node.as_until_node().is_some()
        || node.as_case_node().is_some()
        || node.as_case_match_node().is_some()
}

/// `condition.each_node.any?(&:lvasgn_type?)`: does the predicate's subtree
/// contain a local-variable write (plain, `op=`/`&&=`/`||=`) or a
/// local-variable target (an `mlhs` slot in multiple assignment, `for`
/// loops, or pattern-match binds)? These are the prism node shapes whose
/// whitequark translation surfaces (or contains, for the target-only forms)
/// an `lvasgn` node.
fn wum_condition_has_lvasgn(predicate: &ruby_prism::Node) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder {
        fn visit_local_variable_write_node(&mut self, _node: &ruby_prism::LocalVariableWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_local_variable_operator_write_node(
            &mut self,
            _node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>,
        ) {
            self.found = true;
        }
        fn visit_local_variable_and_write_node(
            &mut self,
            _node: &ruby_prism::LocalVariableAndWriteNode<'pr>,
        ) {
            self.found = true;
        }
        fn visit_local_variable_or_write_node(
            &mut self,
            _node: &ruby_prism::LocalVariableOrWriteNode<'pr>,
        ) {
            self.found = true;
        }
        fn visit_local_variable_target_node(&mut self, _node: &ruby_prism::LocalVariableTargetNode<'pr>) {
            self.found = true;
        }
    }
    let mut finder = Finder { found: false };
    use ruby_prism::Visit;
    finder.visit(predicate);
    finder.found
}

/// Does `before` end with word `w` at a word boundary (not itself preceded
/// by an identifier/digit character, so `"band"` doesn't match `"and"`)?
fn wum_ends_with_word(before: &[u8], w: &[u8]) -> bool {
    if !before.ends_with(w) {
        return false;
    }
    let start = before.len() - w.len();
    start == 0 || !matches!(before[start - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
}

/// Style/ExponentialNotation helpers, ported verbatim from rubocop's
/// `ExponentialNotation` cop. All three operate on the *mantissa* (and, for
/// `engineering`, the exponent) obtained by splitting the float literal's
/// raw source text on the literal byte `'e'` — matching the Ruby cop's
/// `node.source.split('e')`.
///
/// `scientific?` — mantissa must be `-?[1-9]` optionally followed by a `.`
/// and one-or-more digits (a trailing zero after the dot is fine — the
/// regex only requires *a* digit there, not a non-zero one).
fn exponential_notation_scientific(mantissa: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^-?[1-9](\.\d*[0-9])?$").unwrap()).is_match(mantissa)
}

/// `integral?` — mantissa must be a bare integer starting with `1`-`9` and,
/// if more digits follow, ending in a non-zero digit (no trailing zeroes).
fn exponential_notation_integral(mantissa: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^-?[1-9](\d*[1-9])?$").unwrap()).is_match(mantissa)
}

/// `engineering?` — exponent must be an integer divisible by 3, and the
/// mantissa must not have a 4+ digit integer part, must not start with `0`
/// immediately followed by another digit, and must not start with `0<any
/// char>0` (rubocop's `/^-?0.0/` — the middle `.` is an unescaped regex
/// wildcard, not a literal dot, so it also rejects e.g. `0x0`, though that
/// never arises for float-literal mantissas).
fn exponential_notation_engineering(mantissa: &str, exponent: &str) -> bool {
    static RE_EXP: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static RE_4DIGIT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static RE_0DIGIT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static RE_00: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

    let re_exp = RE_EXP.get_or_init(|| regex::Regex::new(r"^-?\d+$").unwrap());
    if !re_exp.is_match(exponent) {
        return false;
    }
    // Ruby's Integer#% follows floor-division semantics, but for a
    // known-good `-?\d+` string dividing by 3 the "is it exactly zero"
    // answer is sign-independent, so Rust's truncating `%` agrees here.
    let Ok(exp_val) = exponent.parse::<i64>() else { return false };
    if exp_val % 3 != 0 {
        return false;
    }
    let re_4digit = RE_4DIGIT.get_or_init(|| regex::Regex::new(r"^-?\d{4}").unwrap());
    if re_4digit.is_match(mantissa) {
        return false;
    }
    let re_0digit = RE_0DIGIT.get_or_init(|| regex::Regex::new(r"^-?0\d").unwrap());
    if re_0digit.is_match(mantissa) {
        return false;
    }
    let re_00 = RE_00.get_or_init(|| regex::Regex::new(r"^-?0.0").unwrap());
    if re_00.is_match(mantissa) {
        return false;
    }
    true
}

impl<'a> super::Cops<'a> {
    /// Style/ExponentialNotation — enforces a consistent style for
    /// exponential-notation float literals (`10e6`, `3.14e0`, ...) per
    /// `EnforcedStyle`: `scientific` (default), `engineering`, `integral`.
    ///
    /// Ported from rubocop's `ExponentialNotation` cop
    /// (`ConfigurableEnforcedStyle`). Every check works on `node.source` —
    /// the raw literal text, byte-identical to what's in the file — so no
    /// numeric parsing of the actual float value happens anywhere; it's
    /// pure source-text pattern matching, split on the literal byte `'e'`.
    ///
    /// Important corollary (verbatim from `offense?`'s
    /// `return false unless node.source['e']`, a case-sensitive substring
    /// check): a literal written with an uppercase `E` (e.g. `1.2E3`) has
    /// no lowercase `'e'` anywhere in its source, so this short-circuits to
    /// "not an offense" — in ANY style, including `scientific` — and such
    /// literals are silently never checked by this cop at all.
    ///
    /// Never correctable (the Ruby cop has no `AutoCorrector`/`autocorrect`
    /// method).
    pub(crate) fn check_exponential_notation(&mut self, node: &ruby_prism::FloatNode<'_>) {
        const COP: &str = "Style/ExponentialNotation";
        if !self.on(COP) {
            return;
        }
        let loc = node.location();
        let start = loc.start_offset();
        let end = loc.end_offset();
        let src = &self.src[start..end];
        if !src.contains(&b'e') {
            return;
        }
        let Ok(src_str) = std::str::from_utf8(src) else { return };

        // `ConfigurableEnforcedStyle` — default `scientific`.
        let style = self.cfg.get(COP, "EnforcedStyle").unwrap_or("scientific");

        let (offense, message): (bool, &'static str) = match style {
            "scientific" => {
                let mantissa = src_str.split('e').next().unwrap_or(src_str);
                (!exponential_notation_scientific(mantissa), "Use a mantissa >= 1 and < 10.")
            }
            "engineering" => {
                let mut parts = src_str.split('e');
                let mantissa = parts.next().unwrap_or(src_str);
                let exponent = parts.next().unwrap_or("");
                (
                    !exponential_notation_engineering(mantissa, exponent),
                    "Use an exponent divisible by 3 and a mantissa >= 0.1 and < 1000.",
                )
            }
            "integral" => {
                let mantissa = src_str.split('e').next().unwrap_or(src_str);
                (!exponential_notation_integral(mantissa), "Use an integer as mantissa, without trailing zero.")
            }
            _ => (false, ""),
        };

        if !offense {
            return;
        }
        self.push(start, COP, false, message);
    }
}
impl<'a> super::Cops<'a> {

    pub(crate) fn check_struct_inheritance(&mut self, node: &ruby_prism::ClassNode) {
        const COP: &str = "Style/StructInheritance";
        if !self.on(COP) {
            return;
        }
        let Some(parent_class) = node.superclass() else { return };

        // Check if parent_class matches the pattern for Struct.new (with or without a block)
        static STRUCT_PATTERN: OnceLock<Pat> = OnceLock::new();
        let pattern = matcher(&STRUCT_PATTERN,
            "{(send (const {nil? cbase} :Struct) :new ...) \
              (block (send (const {nil? cbase} :Struct) :new ...) ...)}");

        if nodepattern::matches(pattern, &parent_class, self.src).is_none() {
            return;
        }

        let parent_loc = parent_class.location();
        let msg = "Don't extend an instance initialized by `Struct.new`. Use a block to customize the struct.";
        self.push(parent_loc.start_offset(), COP, true, msg);

        // Fix 1: Remove the "class" keyword with surrounding space
        let keyword_loc = node.class_keyword_loc();
        let kw_start = keyword_loc.start_offset();
        let kw_end = keyword_loc.end_offset();
        // Find the space after "class"
        let mut space_end = kw_end;
        while space_end < self.src.len() && self.src[space_end] == b' ' {
            space_end += 1;
        }
        self.fixes.push((kw_start, space_end, vec![]));

        // Fix 2: Replace "<" with "="
        if let Some(op_loc) = node.inheritance_operator_loc() {
            self.fixes.push((op_loc.start_offset(), op_loc.end_offset(), b"=".to_vec()));
        }

        // Fix 3: Handle the parent class body transformation
        self.correct_struct_parent(node, &parent_class);
    }

    fn correct_struct_parent(&mut self, class_node: &ruby_prism::ClassNode, parent: &ruby_prism::Node) {
        // Check if parent is a CallNode with a block (do...end already present)
        if let Some(call_node) = parent.as_call_node() {
            if let Some(block_node) = call_node.block().and_then(|b| b.as_block_node()) {
                // Remove the " end" keyword with preceding space from the block
                let close_loc = block_node.closing_loc();
                let close_start = close_loc.start_offset();
                let close_end = close_loc.end_offset();
                // Find preceding space (not newlines per Ruby's range_with_surrounding_space)
                let mut space_start = close_start;
                if close_start > 0 && self.src[close_start - 1] == b' ' {
                    space_start = close_start - 1;
                }
                self.fixes.push((space_start, close_end, vec![]));
                return;
            }
        }

        if class_node.body().is_none() {
            // Class body is empty - remove from parent.end to class.end
            let parent_end = parent.location().end_offset();
            let class_end = class_node.location().end_offset();
            self.fixes.push((parent_end, class_end, vec![]));
        } else if let Some(call_node) = parent.as_call_node() {
            // Check if the call is unparenthesized by looking at the source code
            let has_args = call_node.arguments().is_some_and(|a| a.arguments().iter().next().is_some());

            // Check if unparenthesized: the source after "new" should not start with "("
            let is_unparenthesized = if let Some(msg_loc) = call_node.message_loc() {
                let after_msg = msg_loc.end_offset();
                let src_after = if after_msg < self.src.len() {
                    self.src[after_msg]
                } else {
                    b' '
                };
                src_after != b'('
            } else {
                false
            };

            if has_args && is_unparenthesized {
                // Wrap with parentheses and convert to "do"
                let args_src = call_node.arguments()
                    .map(|a| {
                        a.arguments().iter()
                            .map(|arg| String::from_utf8_lossy(&self.src[arg.location().start_offset()..arg.location().end_offset()]).to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let selector_end = call_node.message_loc()
                    .map(|loc| loc.end_offset())
                    .unwrap_or(parent.location().start_offset());
                let parent_end = parent.location().end_offset();
                let replacement = format!("({}) do", args_src);
                self.fixes.push((selector_end, parent_end, replacement.into_bytes()));
            } else {
                // Just insert " do" after parent
                let parent_end = parent.location().end_offset();
                self.fixes.push((parent_end, parent_end, b" do".to_vec()));
            }
        } else {
            // Fallback: insert " do" after parent
            let parent_end = parent.location().end_offset();
            self.fixes.push((parent_end, parent_end, b" do".to_vec()));
        }
    }
}

/// Style/ExpandPathArguments — `File.expand_path('..', __FILE__)` and the
/// `Pathname(__FILE__).parent.expand_path` / `Pathname.new(...)` families,
/// rewritten to their `__dir__`-based forms. Ported verbatim (message text,
/// depth-counting, autocorrect ranges) from rubocop's
/// `RuboCop::Cop::Style::ExpandPathArguments`.
impl<'a> super::Cops<'a> {
    pub(crate) fn check_expand_path_arguments(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/ExpandPathArguments";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"expand_path" {
            return;
        }
        if let Some((current_path, default_dir)) = expand_path_file_args(node) {
            self.expand_path_inspect_file(node, &current_path, &default_dir);
        } else if let Some((parent_call, default_dir)) = expand_path_pathname_parent(node) {
            if expand_path_is_file_literal(&default_dir, self.src) {
                let l = node.location();
                self.push(
                    l.start_offset(),
                    COP,
                    true,
                    "Use `Pathname(__dir__).expand_path` instead of \
                     `Pathname(__FILE__).parent.expand_path`.",
                );
                self.expand_path_fix_pathname(&default_dir, &parent_call);
            }
        } else if let Some((parent_call, default_dir)) = expand_path_pathname_new_parent(node) {
            if expand_path_is_file_literal(&default_dir, self.src) {
                let l = node.location();
                self.push(
                    l.start_offset(),
                    COP,
                    true,
                    "Use `Pathname.new(__dir__).expand_path` instead of \
                     `Pathname.new(__FILE__).parent.expand_path`.",
                );
                self.expand_path_fix_pathname(&default_dir, &parent_call);
            }
        }
    }

    /// Mirrors `inspect_offense_for_expand_path` + `autocorrect_expand_path`:
    /// only fires when `default_dir` is literally `__FILE__` and `current_path`
    /// is a plain (non-interpolated) string.
    fn expand_path_inspect_file(
        &mut self,
        node: &ruby_prism::CallNode,
        current_path: &ruby_prism::Node,
        default_dir: &ruby_prism::Node,
    ) {
        const COP: &str = "Style/ExpandPathArguments";
        if !expand_path_is_file_literal(default_dir, self.src) {
            return;
        }
        let Some(str_node) = current_path.as_string_node() else { return };
        let Some(sel) = node.message_loc() else { return };

        let current_path_str = String::from_utf8_lossy(str_node.content_loc().as_slice()).into_owned();
        let parent = expand_path_parent_path(&current_path_str);
        let depth = expand_path_depth(&current_path_str);

        let new_path = if parent.is_empty() { String::new() } else { format!("'{parent}', ") };
        let new_default_dir = if depth == 0 { "__FILE__" } else { "__dir__" };

        let message = format!(
            "Use `expand_path({new_path}{new_default_dir})` instead of \
             `expand_path('{current_path_str}', __FILE__)`."
        );
        self.push(sel.start_offset(), COP, true, message);

        let arg_start = current_path.location().start_offset();
        let arg_end = default_dir.location().end_offset();
        match depth {
            0 => self.fixes.push((arg_start, arg_end, b"__FILE__".to_vec())),
            1 => self.fixes.push((arg_start, arg_end, b"__dir__".to_vec())),
            _ => {
                let new_path_lit = format!("'{parent}'");
                let cp_l = current_path.location();
                let dd_l = default_dir.location();
                self.fixes.push((cp_l.start_offset(), cp_l.end_offset(), new_path_lit.into_bytes()));
                self.fixes.push((dd_l.start_offset(), dd_l.end_offset(), b"__dir__".to_vec()));
            }
        }
    }

    /// Mirrors the Pathname branch of `autocorrect` + `remove_parent_method`:
    /// replace `__FILE__` with `__dir__` and drop the `.parent` call.
    fn expand_path_fix_pathname(&mut self, default_dir: &ruby_prism::Node, parent_call: &ruby_prism::CallNode) {
        let dd_l = default_dir.location();
        self.fixes.push((dd_l.start_offset(), dd_l.end_offset(), b"__dir__".to_vec()));
        if let (Some(dot), Some(sel)) = (parent_call.call_operator_loc(), parent_call.message_loc()) {
            self.fixes.push((dot.start_offset(), dot.end_offset(), Vec::new()));
            self.fixes.push((sel.start_offset(), sel.end_offset(), Vec::new()));
        }
    }
}

/// `File`/`Pathname` receiver, bare (`File`) or top-level (`::File`) — mirrors
/// the `{nil? cbase} :Name` node-pattern slot.
fn expand_path_bare_const(n: &ruby_prism::Node, name: &[u8]) -> bool {
    if let Some(cr) = n.as_constant_read_node() {
        cr.name().as_slice() == name
    } else if let Some(cp) = n.as_constant_path_node() {
        cp.parent().is_none() && cp.name().is_some_and(|nm| nm.as_slice() == name)
    } else {
        false
    }
}

/// rubocop's `unrecommended_argument?`: the node's source is literally `__FILE__`.
fn expand_path_is_file_literal(n: &ruby_prism::Node, src: &[u8]) -> bool {
    let l = n.location();
    &src[l.start_offset()..l.end_offset()] == b"__FILE__"
}

fn expand_path_arg_count(node: &ruby_prism::CallNode) -> usize {
    node.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0)
}

/// `(send (const {nil? cbase} :File) :expand_path $_ $_)`
fn expand_path_file_args<'pr>(
    node: &ruby_prism::CallNode<'pr>,
) -> Option<(ruby_prism::Node<'pr>, ruby_prism::Node<'pr>)> {
    let recv = node.receiver()?;
    if !expand_path_bare_const(&recv, b"File") {
        return None;
    }
    let args: Vec<ruby_prism::Node> =
        node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
    if args.len() != 2 {
        return None;
    }
    let mut it = args.into_iter();
    let a0 = it.next().unwrap();
    let a1 = it.next().unwrap();
    Some((a0, a1))
}

/// `(send (send (send nil? :Pathname $_) :parent) :expand_path)` — `node` is
/// the outer `:expand_path` call itself; returns the `.parent` call (for
/// removal) and the captured argument to `Pathname(...)`.
fn expand_path_pathname_parent<'pr>(
    node: &ruby_prism::CallNode<'pr>,
) -> Option<(ruby_prism::CallNode<'pr>, ruby_prism::Node<'pr>)> {
    if expand_path_arg_count(node) != 0 {
        return None;
    }
    let parent_call = node.receiver()?.as_call_node()?;
    if parent_call.name().as_slice() != b"parent" || expand_path_arg_count(&parent_call) != 0 {
        return None;
    }
    let pathname_call = parent_call.receiver()?.as_call_node()?;
    if pathname_call.name().as_slice() != b"Pathname" || pathname_call.receiver().is_some() {
        return None;
    }
    let args: Vec<ruby_prism::Node> =
        pathname_call.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
    if args.len() != 1 {
        return None;
    }
    Some((parent_call, args.into_iter().next().unwrap()))
}

/// `(send (send (send (const {nil? cbase} :Pathname) :new $_) :parent) :expand_path)`
fn expand_path_pathname_new_parent<'pr>(
    node: &ruby_prism::CallNode<'pr>,
) -> Option<(ruby_prism::CallNode<'pr>, ruby_prism::Node<'pr>)> {
    if expand_path_arg_count(node) != 0 {
        return None;
    }
    let parent_call = node.receiver()?.as_call_node()?;
    if parent_call.name().as_slice() != b"parent" || expand_path_arg_count(&parent_call) != 0 {
        return None;
    }
    let new_call = parent_call.receiver()?.as_call_node()?;
    if new_call.name().as_slice() != b"new" {
        return None;
    }
    let recv = new_call.receiver()?;
    if !expand_path_bare_const(&recv, b"Pathname") {
        return None;
    }
    let args: Vec<ruby_prism::Node> =
        new_call.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
    if args.len() != 1 {
        return None;
    }
    Some((parent_call, args.into_iter().next().unwrap()))
}

/// rubocop's `depth`: split on `/`, count components that aren't `.`.
/// Ruby's String#split drops TRAILING empty segments ("../../".split('/')
/// == ["..", ".."]); Rust keeps them — mirror Ruby here.
fn expand_path_split(current_path: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = current_path.split('/').collect();
    while parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

fn expand_path_depth(current_path: &str) -> usize {
    expand_path_split(current_path).into_iter().filter(|p| *p != ".").count()
}

/// rubocop's `parent_path`: drop `.` components, then drop the FIRST `..`.
fn expand_path_parent_path(current_path: &str) -> String {
    let mut paths = expand_path_split(current_path);
    paths.retain(|p| *p != ".");
    if let Some(idx) = paths.iter().position(|p| *p == "..") {
        paths.remove(idx);
    }
    paths.join("/")
}
impl<'a> super::Cops<'a> {

    /// Style/RedundantSelfAssignment — detects assignments like `foo = foo.concat(ary)`
    /// where the method call returns self and modifies the receiver in place.
    pub(crate) fn check_redundant_self_assignment_lvar(
        &mut self,
        node: &ruby_prism::LocalVariableWriteNode,
    ) {
        const COP: &str = "Style/RedundantSelfAssignment";
        if !self.on(COP) {
            return;
        }
        let rhs = &node.value();
        if !self.check_redundant_self_assignment_impl(rhs, &RsaReceiver::Lvar(node.name().as_slice())) {
            return;
        }

        let call = match rhs.as_call_node() {
            Some(c) => c,
            _ => return,
        };
        let method_str = String::from_utf8_lossy(call.name().as_slice()).into_owned();
        let msg = format!(
            "Redundant self assignment detected. Method `{}` modifies its receiver in place.",
            method_str
        );
        self.push(node.operator_loc().start_offset(), COP, true, msg);

        // Fix: replace the entire assignment with just the RHS
        self.fixes.push((node.location().start_offset(), node.location().end_offset(), self.node_src(rhs).to_vec()));
    }

    /// Check for redundant self assignment on instance variables
    pub(crate) fn check_redundant_self_assignment_ivar(
        &mut self,
        node: &ruby_prism::InstanceVariableWriteNode,
    ) {
        const COP: &str = "Style/RedundantSelfAssignment";
        if !self.on(COP) {
            return;
        }
        let rhs = &node.value();
        if !self.check_redundant_self_assignment_impl(rhs, &RsaReceiver::Ivar(node.name().as_slice())) {
            return;
        }

        let call = match rhs.as_call_node() {
            Some(c) => c,
            _ => return,
        };
        let method_str = String::from_utf8_lossy(call.name().as_slice()).into_owned();
        let msg = format!(
            "Redundant self assignment detected. Method `{}` modifies its receiver in place.",
            method_str
        );
        self.push(node.operator_loc().start_offset(), COP, true, msg);

        // Fix: replace the entire assignment with just the RHS
        self.fixes.push((node.location().start_offset(), node.location().end_offset(), self.node_src(rhs).to_vec()));
    }

    /// Check for redundant self assignment on class variables
    pub(crate) fn check_redundant_self_assignment_cvar(
        &mut self,
        node: &ruby_prism::ClassVariableWriteNode,
    ) {
        const COP: &str = "Style/RedundantSelfAssignment";
        if !self.on(COP) {
            return;
        }
        let rhs = &node.value();
        if !self.check_redundant_self_assignment_impl(rhs, &RsaReceiver::Cvar(node.name().as_slice())) {
            return;
        }

        let call = match rhs.as_call_node() {
            Some(c) => c,
            _ => return,
        };
        let method_str = String::from_utf8_lossy(call.name().as_slice()).into_owned();
        let msg = format!(
            "Redundant self assignment detected. Method `{}` modifies its receiver in place.",
            method_str
        );
        self.push(node.operator_loc().start_offset(), COP, true, msg);

        // Fix: replace the entire assignment with just the RHS
        self.fixes.push((node.location().start_offset(), node.location().end_offset(), self.node_src(rhs).to_vec()));
    }

    /// Check for redundant self assignment on global variables
    pub(crate) fn check_redundant_self_assignment_gvar(
        &mut self,
        node: &ruby_prism::GlobalVariableWriteNode,
    ) {
        const COP: &str = "Style/RedundantSelfAssignment";
        if !self.on(COP) {
            return;
        }
        let rhs = &node.value();
        if !self.check_redundant_self_assignment_impl(rhs, &RsaReceiver::Gvar(node.name().as_slice())) {
            return;
        }

        let call = match rhs.as_call_node() {
            Some(c) => c,
            _ => return,
        };
        let method_str = String::from_utf8_lossy(call.name().as_slice()).into_owned();
        let msg = format!(
            "Redundant self assignment detected. Method `{}` modifies its receiver in place.",
            method_str
        );
        self.push(node.operator_loc().start_offset(), COP, true, msg);

        // Fix: replace the entire assignment with just the RHS
        self.fixes.push((node.location().start_offset(), node.location().end_offset(), self.node_src(rhs).to_vec()));
    }

    /// Check for redundant assignment via attribute setter (e.g., `other.foo = other.foo.concat(ary)`)
    pub(crate) fn check_redundant_self_assignment_call(
        &mut self,
        node: &ruby_prism::CallNode,
    ) {
        const COP: &str = "Style/RedundantSelfAssignment";
        if !self.on(COP) {
            return;
        }

        // Must be a method call ending with `=` (assignment method)
        let method_bytes = node.name().as_slice();
        if !method_bytes.ends_with(b"=") {
            return;
        }

        // Extract the attribute name (without the trailing `=`)
        let attr_name = &method_bytes[..method_bytes.len() - 1];

        let Some(receiver) = node.receiver() else { return };

        // Get the first argument (the RHS of the assignment)
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.len() != 1 {
            return;
        }
        let rhs = &args[0];

        // Check if the RHS is a call to a method that returns self
        let Some(rhs_call) = rhs.as_call_node() else { return };

        // The RHS receiver should be a call to the same attribute on the same object
        // E.g., for `other.foo = other.foo.concat(ary)`:
        // - receiver is `other` (CallNode for the simple identifier access)
        // - rhs_call.receiver() should also produce the same `other.foo` structure
        let Some(rhs_receiver) = rhs_call.receiver() else { return };

        // For the receivers to match, we need to check if accessing the same attribute
        // on the same base object. For simple cases like `other.foo`, the receiver
        // should be `other` and the method name in the RHS should match the attribute
        // Let me check if the RHS is `receiver.attr_name.*(...)`
        let Some(rhs_receiver_call) = rhs_receiver.as_call_node() else {
            return;
        };

        // The RHS receiver should be a call to the same method name on the same base receiver
        if rhs_receiver_call.name().as_slice() != attr_name {
            return;
        }

        // Check if the base receivers match
        let lhs_receiver_src = self.node_src(&receiver).to_vec();
        let rhs_base_receiver = rhs_receiver_call.receiver();
        let rhs_base_src = rhs_base_receiver.map(|r| self.node_src(&r).to_vec());

        if Some(lhs_receiver_src) != rhs_base_src {
            return;
        }

        // Check if the RHS method (the one being called on the attribute) returns self
        let rhs_method = rhs_call.name().as_slice();
        if !RSA_METHODS_RETURNING_SELF.contains(&rhs_method) {
            return;
        }

        let method_str = String::from_utf8_lossy(rhs_method).into_owned();
        let msg = format!(
            "Redundant self assignment detected. Method `{}` modifies its receiver in place.",
            method_str
        );

        // Find the `=` sign location for the error report
        // The method name for assignment includes the `=`, so we can find it by searching for it
        // in the source between the receiver end and the arguments start
        let node_start = node.location().start_offset();
        let node_end = node.location().end_offset();
        let src = &self.src[node_start..node_end];

        // Find the `=` in the source
        if let Some(eq_pos) = src.iter().position(|&b| b == b'=') {
            self.push(node_start + eq_pos, COP, true, msg);
        } else {
            // Fallback: use the start of the node
            self.push(node_start, COP, true, msg);
        }

        // Fix: remove the assignment part and keep just the method call
        // For `other.foo = other.foo.concat(ary)`, replace with `other.foo.concat(ary)`
        self.fixes.push((node.location().start_offset(), node.location().end_offset(), self.node_src(rhs).to_vec()));
    }

    /// Helper to check if RHS is calling a self-returning method on the same receiver
    fn check_redundant_self_assignment_impl(
        &self,
        rhs: &ruby_prism::Node,
        expected_receiver: &RsaReceiver,
    ) -> bool {
        let Some(call) = rhs.as_call_node() else { return false };

        // Check if method returns self
        let method = call.name();
        if !RSA_METHODS_RETURNING_SELF.contains(&method.as_slice()) {
            return false;
        }

        // Check if the receiver matches
        let Some(receiver) = call.receiver() else { return false };
        expected_receiver.matches(&receiver)
    }

}

/// Methods that return self (or equivalent) after modifying the receiver in place
/// From RuboCop::Cop::Style::RedundantSelfAssignment::METHODS_RETURNING_SELF
const RSA_METHODS_RETURNING_SELF: &[&[u8]] = &[
    b"append", b"clear", b"collect!", b"compare_by_identity", b"concat", b"delete_if",
    b"fill", b"initialize_copy", b"insert", b"keep_if", b"map!", b"merge!", b"prepend",
    b"push", b"rehash", b"replace", b"reverse!", b"rotate!", b"shuffle!", b"sort!",
    b"sort_by!", b"transform_keys!", b"transform_values!", b"unshift", b"update",
];

/// Helper enum for matching different types of receivers in redundant self assignment detection
#[derive(Debug)]
enum RsaReceiver<'a> {
    Lvar(&'a [u8]),
    Ivar(&'a [u8]),
    Cvar(&'a [u8]),
    Gvar(&'a [u8]),
}

impl<'a> RsaReceiver<'a> {
    /// Check if the given node matches this receiver
    fn matches(&self, node: &ruby_prism::Node) -> bool {
        match self {
            RsaReceiver::Lvar(name) => {
                node.as_local_variable_read_node()
                    .map(|n| n.name().as_slice() == *name)
                    .unwrap_or(false)
            }
            RsaReceiver::Ivar(name) => {
                node.as_instance_variable_read_node()
                    .map(|n| n.name().as_slice() == *name)
                    .unwrap_or(false)
            }
            RsaReceiver::Cvar(name) => {
                node.as_class_variable_read_node()
                    .map(|n| n.name().as_slice() == *name)
                    .unwrap_or(false)
            }
            RsaReceiver::Gvar(name) => {
                node.as_global_variable_read_node()
                    .map(|n| n.name().as_slice() == *name)
                    .unwrap_or(false)
            }
        }
    }
}

/// `Style::ModuleFunction#extend_self_node?`: `(send nil? :extend self)` — a
/// bare (no receiver, no block) call to `extend` with exactly one argument
/// that is the bare `self` keyword.
fn mf_extend_self_node(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    if call.receiver().is_some() || call.block().is_some() {
        return false;
    }
    if call.name().as_slice() != b"extend" {
        return false;
    }
    let Some(args) = call.arguments() else { return false };
    let list = args.arguments();
    list.len() == 1 && list.first().is_some_and(|n| n.as_self_node().is_some())
}

/// `Style::ModuleFunction#module_function_node?`: `(send nil? :module_function)`
/// — a bare (no receiver, no block, NO arguments) call to `module_function`.
fn mf_module_function_node(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    if call.receiver().is_some() || call.block().is_some() {
        return false;
    }
    call.name().as_slice() == b"module_function" && call.arguments().is_none()
}

/// `Style::ModuleFunction#private_directive?`: `(send nil? :private ...)` —
/// a bare (no receiver, no block) call to `private`, with any (including
/// zero) arguments — covers both the declarative `private` and the
/// argument form `private :foo`.
fn mf_private_directive_node(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    if call.receiver().is_some() || call.block().is_some() {
        return false;
    }
    call.name().as_slice() == b"private"
}

impl<'a> super::Cops<'a> {
    /// Style/ModuleFunction — checks for use of `extend self` or
    /// `module_function` in a module, per `EnforcedStyle`: `module_function`
    /// (default), `extend_self`, or `forbidden`.
    ///
    /// Ported from rubocop's `Style::ModuleFunction`
    /// (`include ConfigurableEnforcedStyle`, `extend AutoCorrector`).
    /// Upstream only activates when `node.body&.begin_type?` — whitequark
    /// only wraps a module's body in a `begin` node when it has 2+
    /// statements (a single-statement body is the bare statement node
    /// itself). Prism's `ModuleNode#body`, in contrast, ALWAYS wraps in a
    /// `StatementsNode` regardless of statement count — a prism-vs-whitequark
    /// trap — so this port explicitly requires >= 2 direct statements to
    /// match upstream's activation condition (verified live: a module
    /// containing only `extend self` produces no offense under real
    /// rubocop 1.88.0).
    ///
    /// Autocorrection (`extend AutoCorrector`) is unsafe and disabled by
    /// default; under `forbidden` style the offense is still reported but
    /// `next if style == :forbidden` in upstream's corrector block means no
    /// replacement ever happens — modeled here as `correctable = false` and
    /// no entry pushed to `self.fixes`, mirroring this file's existing
    /// `EmptyElse`-style `!forbidden` idiom.
    pub(crate) fn check_module_function(&mut self, node: &ruby_prism::ModuleNode) {
        const COP: &str = "Style/ModuleFunction";
        if !self.on(COP) {
            return;
        }
        let Some(body) = node.body() else { return };
        let Some(stmts) = body.as_statements_node() else { return };
        let children: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        // Mirrors `node.body&.begin_type?` — see doc comment above.
        if children.len() < 2 {
            return;
        }

        let style = self.cfg.get(COP, "EnforcedStyle").unwrap_or("module_function");
        let (msg, correctable): (&'static str, bool) = match style {
            "extend_self" => ("Use `extend self` instead of `module_function`.", true),
            "forbidden" => ("Do not use `module_function` or `extend self`.", false),
            _ => ("Use `module_function` instead of `extend self`.", true),
        };

        match style {
            "extend_self" => {
                for child in &children {
                    if mf_module_function_node(child) {
                        self.mf_offense(child, COP, msg, correctable, false);
                    }
                }
            }
            "forbidden" => {
                for child in &children {
                    if mf_extend_self_node(child) || mf_module_function_node(child) {
                        self.mf_offense(child, COP, msg, correctable, false);
                    }
                }
            }
            // "module_function" (default) and any unrecognized value
            // (the schema's `live()` gate already disables the cop
            // outright for an out-of-range `EnforcedStyle`).
            _ => {
                // `check_module_function`: skip entirely if ANY direct
                // statement is a `private` directive.
                if children.iter().any(mf_private_directive_node) {
                    return;
                }
                for child in &children {
                    if mf_extend_self_node(child) {
                        self.mf_offense(child, COP, msg, correctable, true);
                    }
                }
            }
        }
    }

    /// Pushes the offense for a matched `child` node and, when correctable,
    /// the replacement fix. `is_extend_self` records which literal source
    /// the matched node actually is (`extend self` vs `module_function`),
    /// since upstream's corrector picks the replacement text from the
    /// matched node's own shape (`if extend_self_node?(child_node) ...`),
    /// not from the configured style.
    fn mf_offense(
        &mut self,
        child: &ruby_prism::Node,
        cop: &'static str,
        msg: &'static str,
        correctable: bool,
        is_extend_self: bool,
    ) {
        let l = child.location();
        self.push(l.start_offset(), cop, correctable, msg);
        if correctable {
            let rep: &[u8] = if is_extend_self { b"module_function" } else { b"extend self" };
            self.fixes.push((l.start_offset(), l.end_offset(), rep.to_vec()));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/SingleArgumentDig — `x.dig(:a)` → `x[:a]`.
    pub(crate) fn check_single_argument_dig(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/SingleArgumentDig";
        if !self.hot.single_argument_dig || node.name().as_slice() != b"dig" {
            return;
        }

        // Must have a receiver
        let Some(receiver) = node.receiver() else { return };

        // Safe navigation operator (&.) should be ignored
        if node.call_operator_loc().is_some_and(|o| o.as_slice() == b"&.") {
            return;
        }

        // Block argument forwarding (&) should be ignored
        if node.block().is_some_and(|b| b.as_block_argument_node().is_some()) {
            return;
        }

        // Must have exactly one argument
        let args: Vec<ruby_prism::Node> = node
            .arguments()
            .map(|a| a.arguments().iter().collect())
            .unwrap_or_default();
        if args.len() != 1 {
            return;
        }

        let arg = &args[0];

        // Skip if argument is a ForwardingArgumentsNode (...), which represents ... forwarding
        if arg.as_forwarding_arguments_node().is_some() {
            return;
        }

        // Skip if argument is a SplatNode (any splat, with or without expression)
        if arg.as_splat_node().is_some() {
            return;
        }

        // Skip if argument is a KeywordHashNode with AssocSplatNode (** keyword forwarding)
        if let Some(hash) = arg.as_keyword_hash_node() {
            for elem in hash.elements().iter() {
                if elem.as_assoc_splat_node().is_some() {
                    return;
                }
            }
        }

        // Skip if argument is a block_pass (&:sym)
        if arg.as_block_argument_node().is_some() {
            return;
        }

        // Skip if argument is a hash
        if arg.as_hash_node().is_some() {
            return;
        }

        // When Style/DigChain is enabled, don't flag digs that are part of a
        // chain (the DigChain cop owns them). The OUTER dig of a chain is
        // visited first: it marks its dig-receiver's offset so the inner dig
        // also knows it's part of a chain when its own turn comes.
        if self.cfg.enabled("Style/DigChain") {
            if let Some(recv_call) = receiver.as_call_node() {
                if recv_call.name().as_slice() == b"dig" {
                    self.sad_chain_receivers.insert(recv_call.location().start_offset());
                    return;
                }
            }
            if self.sad_chain_receivers.contains(&node.location().start_offset()) {
                return;
            }
        }

        let receiver_src = String::from_utf8_lossy(self.node_src(&receiver)).into_owned();
        let argument_src = String::from_utf8_lossy(self.node_src(arg)).into_owned();
        let original_src = String::from_utf8_lossy(self.node_src(&node.as_node())).into_owned();

        let message = format!(
            "Use `{receiver_src}[{argument_src}]` instead of `{original_src}`."
        );

        let l = node.location();
        self.push(l.start_offset(), COP, true, message);

        // Generate the fix
        let fixed = format!("{receiver_src}[{argument_src}]");
        self.fixes.push((l.start_offset(), l.end_offset(), fixed.into_bytes()));
    }
}

// ---- Style/Encoding helpers: full `RuboCop::MagicComment` port ----
//
// Unlike `fsl_value` above (which only needs the frozen_string_literal
// setting), this cop needs `encoding_specified?`/`valid?` from ALL THREE
// magic-comment dialects (emacs `-*- k: v; ... -*-`, vim `# vim: k=v, ...`,
// and the simple `# key: value` form) — a leading comment that specifies
// some OTHER magic setting (frozen_string_literal, rbs_inline,
// shareable_constant_value, typed) still counts as "valid" and must not
// stop the scan, while a non-magic comment or code line does.
struct EncodingLine {
    /// The `coding`/`encoding`/`fileencoding` value, lowercased.
    encoding: Option<String>,
    /// The line rewritten with the encoding directive stripped out — `""`
    /// means the whole line should be deleted (mirrors `MagicComment
    /// #without`). Only meaningful when `encoding` is `Some`.
    without_encoding: String,
}

/// Mirrors `MagicComment.parse(line).valid?` (dialect-dispatched `any?`) plus
/// enough of each dialect's `#encoding`/`#without` to drive the cop. Returns
/// `None` for a line that is not a valid magic comment at all — the caller
/// (like rubocop's `comments` method) stops scanning as soon as this happens.
fn parse_encoding_line(text: &str) -> Option<EncodingLine> {
    if !text.starts_with('#') {
        return None;
    }

    static EMACS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if let Some(caps) = re(&EMACS, r"-\*-(.+)-\*-").captures(text) {
        let tokens: Vec<String> = caps[1].split(';').map(|t| t.trim().to_string()).collect();

        static ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static FSL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static SCV: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let enc_re = re(&ENC, r"^(?:en)?coding\s*:\s*([[:alnum:]_-]+)$");
        let fsl_re = re(&FSL, r"^frozen[_-]string[_-]literal\s*:\s*[[:alnum:]_-]+$");
        let scv_re = re(&SCV, r"^shareable[_-]constant[_-]value\s*:\s*[[:alnum:]_-]+$");

        let encoding = tokens.iter().find_map(|t| enc_re.captures(t).map(|c| c[1].to_lowercase()));
        let other = tokens.iter().any(|t| fsl_re.is_match(t) || scv_re.is_match(t));
        if encoding.is_none() && !other {
            return None;
        }

        let prefix_re = re(&PREFIX, r"^(?:en)?coding");
        let remaining: Vec<&str> = tokens.iter().filter(|t| !prefix_re.is_match(t)).map(String::as_str).collect();
        let without_encoding =
            if remaining.is_empty() { String::new() } else { format!("# -*- {} -*-", remaining.join(";")) };
        return Some(EncodingLine { encoding, without_encoding });
    }

    static VIM: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if let Some(caps) = re(&VIM, r"#\s*vim:\s*(.+)").captures(text) {
        let tokens: Vec<String> = caps[1].split(", ").map(|t| t.trim().to_string()).collect();

        static ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let enc_re = re(&ENC, r"^fileencoding\s*=\s*([[:alnum:]_-]+)$");
        // The `fileencoding` keyword only works when there's at least one
        // other token in the comment.
        let encoding = (tokens.len() > 1)
            .then(|| tokens.iter().find_map(|t| enc_re.captures(t).map(|c| c[1].to_lowercase())))
            .flatten();
        encoding.as_ref()?;

        let prefix_re = re(&PREFIX, r"^fileencoding");
        let remaining: Vec<&str> = tokens.iter().filter(|t| !prefix_re.is_match(t)).map(String::as_str).collect();
        let without_encoding =
            if remaining.is_empty() { String::new() } else { format!("# vim: {}", remaining.join(", ")) };
        return Some(EncodingLine { encoding, without_encoding });
    }

    // Simple `# key: value` form (case-insensitive).
    static ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static FSL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SCV: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static RBS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static TYPED: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static WITHOUT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let enc_re =
        re(&ENC, r"(?i)^\s*#\s*(?:frozen_string_literal:\s*(?:true|false))?\s*(?:en)?coding: ([[:alnum:]_-]+)");
    let fsl_re = re(&FSL, r"(?i)^\s*#\s*frozen[_-]string[_-]literal:\s*[[:alnum:]_-]+\s*$");
    let scv_re = re(&SCV, r"(?i)^\s*#\s*shareable[_-]constant[_-]value:\s*[[:alnum:]_-]+\s*$");
    let rbs_re = re(&RBS, r"(?i)^\s*#\s*rbs_inline:\s*([[:alnum:]_-]+)\s*$");
    let typed_re = re(&TYPED, r"(?i)^\s*#\s*typed:\s*[[:alnum:]_-]+\s*$");

    let encoding = enc_re.captures(text).map(|c| c[1].to_lowercase());
    let fsl = fsl_re.is_match(text);
    let scv = scv_re.is_match(text);
    // `valid_rbs_inline_value?` requires the un-downcased captured value to
    // literally be "enabled" or "disabled".
    let rbs = rbs_re.captures(text).is_some_and(|c| matches!(&c[1], "enabled" | "disabled"));
    let typed = typed_re.is_match(text);
    if encoding.is_none() && !fsl && !scv && !rbs && !typed {
        return None;
    }

    let without_re = re(&WITHOUT, r"(?i)^#\s*(?:en)?coding");
    let without_encoding = if without_re.is_match(text) { String::new() } else { text.to_string() };
    Some(EncodingLine { encoding, without_encoding })
}

impl<'a> super::Cops<'a> {
    /// Style/Encoding — a redundant `# encoding: utf-8` / `# coding: utf-8`
    /// (or emacs/vim equivalent) magic comment. Text-based: scans physical
    /// source lines from the top, exactly like rubocop's `comments` method —
    /// a shebang line is skipped, and the scan stops dead at the first line
    /// that isn't a valid magic comment of ANY kind (blank line, plain
    /// comment, or code).
    pub(crate) fn check_encoding(&mut self) {
        const COP: &str = "Style/Encoding";
        if !self.on(COP) {
            return;
        }
        if self.src.is_empty() {
            return;
        }

        let starts = &self.idx.starts;
        // `processed_source.lines` never yields a final phantom empty line
        // for a source that ends with a trailing newline.
        let num_lines = if *self.src.last().unwrap() == b'\n' { starts.len() - 1 } else { starts.len() };

        for line_no in 1..=num_lines {
            let start = starts[line_no - 1];
            let end = self.line_end(line_no);
            let bytes = &self.src[start..end];
            if bytes.starts_with(b"#!") {
                continue;
            }
            let text = String::from_utf8_lossy(bytes);
            let Some(parsed) = parse_encoding_line(&text) else {
                break;
            };
            let Some(encoding) = parsed.encoding else {
                continue;
            };
            if !encoding.eq_ignore_ascii_case("utf-8") {
                continue;
            }

            self.push(start, COP, true, "Unnecessary utf-8 encoding comment.");
            if parsed.without_encoding.is_empty() {
                // `range_with_surrounding_space(range, side: :right)`: eat the
                // line's own newline plus any further blank lines after it.
                let mut del_end = end;
                while del_end < self.src.len() && self.src[del_end] == b'\n' {
                    del_end += 1;
                }
                self.fixes.push((start, del_end, Vec::new()));
            } else {
                self.fixes.push((start, end, parsed.without_encoding.into_bytes()));
            }
        }
    }
}
impl<'a> super::Cops<'a> {

    /// Style/RedundantFetchBlock: detects fetch(key) { literal } patterns
    /// and suggests fetch(key, literal) instead.
    pub(crate) fn check_redundant_fetch_block(&mut self, call: &ruby_prism::CallNode) {
        const COP: &str = "Style/RedundantFetchBlock";
        if !self.on(COP) {
            return;
        }

        // Only calls carrying a literal block qualify
        let Some(node) = call.block().and_then(|b| b.as_block_node()) else { return };
        let node = &node;

        // Check if the method is 'fetch'
        if call.name().as_slice() != b"fetch" {
            return;
        }

        // Check if fetch already has an argument (should have exactly 1 argument for the key)
        let Some(args) = call.arguments() else { return };

        // fetch should have exactly one argument (the key)
        let args_count = args.arguments().iter().count();
        if args_count != 1 {
            return;
        }

        // Check if block has parameters - if it does, we don't match
        if let Some(params) = node.parameters() {
            if let Some(bp) = params.as_block_parameters_node() {
                if bp.parameters().is_some() {
                    return;
                }
            }
        }

        // Check if it's Rails.cache.fetch - skip if it is
        if self.is_rails_cache_fetch(&call) {
            return;
        }

        // Get the block body. An EMPTY block (`fetch(:key) {}`) matches
        // upstream's `${nil?}` body slot: report it and correct to
        // `fetch(key, nil)`.
        let Some(body) = node.body() else {
            let key_node = args.arguments().iter().next().unwrap();
            let key_src = String::from_utf8_lossy(self.node_src(&key_node)).into_owned();
            let msg = format!("Use `fetch({key_src}, nil)` instead of `fetch({key_src}) {{}}`.");
            let sel = call.message_loc().map(|m| m.start_offset()).unwrap_or_else(|| call.location().start_offset());
            self.push(sel, COP, true, msg);
            // replace from the selector through the block close
            let end = call.location().end_offset();
            self.fixes.push((sel, end, format!("fetch({key_src}, nil)").into_bytes()));
            return;
        };

        // Prism always wraps a block body in a StatementsNode — extract the
        // single statement (multi-statement bodies never match).
        let body_node = if let Some(stmts) = body.as_statements_node() {
            let mut it = stmts.body().iter();
            let Some(first) = it.next() else { return };
            if it.next().is_some() {
                return;
            }
            first
        } else {
            body
        };
        let body_node = &body_node;

        // Check for interpolated symbols (:"...#{...}")
        if let Some(sym) = body_node.as_interpolated_symbol_node() {
            if sym.parts().iter().any(|p| p.as_embedded_statements_node().is_some()) {
                return;
            }
        }

        // Determine if we should check for this literal type
        let should_report = if body_node.as_nil_node().is_some() {
            true
        } else if body_node.as_integer_node().is_some() {
            true
        } else if body_node.as_float_node().is_some() {
            true
        } else if body_node.as_symbol_node().is_some() {
            true
        } else if body_node.as_rational_node().is_some() {
            true
        } else if body_node.as_imaginary_node().is_some() {
            true
        } else if body_node.as_true_node().is_some() {
            true
        } else if body_node.as_false_node().is_some() {
            true
        } else if body_node.as_string_node().is_some() {
            self.frozen_string_literal_enabled()
        } else if body_node.as_constant_read_node().is_some() || body_node.as_constant_path_node().is_some() {
            self.cfg.get(COP, "SafeForConstants").map_or(false, |v| v == "true")
        } else {
            false
        };

        if !should_report {
            return;
        }

        // Build the message
        let key_node = args.arguments().iter().next().unwrap();
        let key_src = self.node_src(&key_node);
        let body_src = self.node_src(&body_node);

        let is_nil = body_node.as_nil_node().is_some();

        let default_src = if is_nil {
            "nil".to_string()
        } else {
            String::from_utf8_lossy(body_src).into_owned()
        };

        let good = format!("fetch({}, {})", String::from_utf8_lossy(key_src), default_src);

        // An explicit `{ nil }` body renders like any other body — only a
        // genuinely EMPTY block (handled above) prints `{}`.
        let bad_msg = format!(
            "Use `{}` instead of `fetch({}) {{ {} }}`.",
            good,
            String::from_utf8_lossy(key_src),
            String::from_utf8_lossy(body_src)
        );

        // Report the offense with the range from 'fetch' keyword to end of block
        if let Some(msg_loc) = call.message_loc() {
            let start = msg_loc.start_offset();
            let end = node.closing_loc().end_offset();

            self.push(start, COP, true, &bad_msg);

            // Add the fix
            let replacement = if is_nil {
                format!("fetch({}, nil)", String::from_utf8_lossy(key_src))
            } else {
                format!("fetch({}, {})", String::from_utf8_lossy(key_src), String::from_utf8_lossy(body_src))
            };

            self.fixes.push((start, end, replacement.into_bytes()));
        }
    }

    /// Helper to check if this is Rails.cache.fetch
    fn is_rails_cache_fetch(&self, call: &ruby_prism::CallNode) -> bool {
        let Some(receiver) = call.receiver() else { return false };

        // Check for Rails.cache pattern: (send (const _ :Rails) :cache)
        if let Some(call_recv) = receiver.as_call_node() {
            if call_recv.name().as_slice() != b"cache" {
                return false;
            }
            if let Some(inner_recv) = call_recv.receiver() {
                if inner_recv.as_constant_read_node().is_some() {
                    if let Some(const_node) = inner_recv.as_constant_read_node() {
                        return const_node.name().as_slice() == b"Rails";
                    }
                }
            }
        }

        false
    }

}

impl<'a> super::Cops<'a> {
    /// Style/KeywordParametersOrder. rubocop's `on_kwoptarg` fires once per
    /// `kwoptarg` (optional keyword parameter) that has ANY `kwarg`
    /// (required keyword parameter) among its `right_siblings` — an offense
    /// per misplaced optional. prism's `ParametersNode#keywords` already
    /// lists exactly the keyword-parameter nodes (mixing
    /// `OptionalKeywordParameterNode`/`RequiredKeywordParameterNode`) in
    /// written order — no other parameter kind can be interleaved among
    /// them by Ruby's grammar — so "right siblings that are `kwarg_type`"
    /// reduces to "later entries of this Vec that are required".
    ///
    /// Only the FIRST optional parameter in the whole list ever performs the
    /// reorder (upstream: `node.parent.find(&:kwoptarg_type?) == node`) —
    /// later matching offenses are registered but not corrected, since a
    /// single reorder already relocates every required parameter that
    /// follows an optional one.
    pub(crate) fn check_keyword_parameters_order_def(&mut self, node: &ruby_prism::DefNode) {
        if !self.on("Style/KeywordParametersOrder") {
            return;
        }
        let Some(params) = node.parameters() else { return };
        let has_parens = node.lparen_loc().is_some();
        self.kpo_check(&params, false, has_parens);
    }

    /// Same check for a block/lambda parameter list. Upstream's
    /// `parentheses?(arguments)` is ALWAYS false for a block/lambda's args
    /// node (its closing delimiter is `|` or, for a `->() {}` lambda, still
    /// not literally `)` in the sense that method checks), so the
    /// newline-after-reorder step is always attempted — but then
    /// unconditionally suppressed by `unless arguments.parent.block_type?`.
    /// Net effect: blocks/lambdas never get the trailing newline, whether or
    /// not they use parens/pipes — modeled here simply as "never insert".
    pub(crate) fn check_keyword_parameters_order_block(&mut self, params_holder: &ruby_prism::Node) {
        if !self.on("Style/KeywordParametersOrder") {
            return;
        }
        let Some(bp) = params_holder.as_block_parameters_node() else { return };
        let Some(params) = bp.parameters() else { return };
        self.kpo_check(&params, true, false);
    }

    fn kpo_check(&mut self, params: &ruby_prism::ParametersNode, is_block: bool, has_parens: bool) {
        const COP: &str = "Style/KeywordParametersOrder";
        const MSG: &str = "Place optional keyword parameters at the end of the parameters list.";

        let keywords: Vec<ruby_prism::Node<'_>> = params.keywords().iter().collect();
        if keywords.is_empty() {
            return;
        }
        let first_opt_idx = keywords.iter().position(|n| n.as_optional_keyword_parameter_node().is_some());

        for i in 0..keywords.len() {
            if keywords[i].as_optional_keyword_parameter_node().is_none() {
                continue;
            }
            let required_after: Vec<usize> = (i + 1..keywords.len())
                .filter(|&j| keywords[j].as_required_keyword_parameter_node().is_some())
                .collect();
            if required_after.is_empty() {
                continue;
            }

            self.push(keywords[i].location().start_offset(), COP, true, MSG);

            // Only the earliest offending optional parameter corrects.
            if first_opt_idx != Some(i) {
                continue;
            }

            // A comment anywhere across the WHOLE parameter list (every
            // kind, not just the keyword group) blocks the correction —
            // upstream's `contains_comment?(arguments_range(defining_node))`.
            let (span_start, span_end) = kpo_full_span(params);
            if self.comments.iter().any(|&(_, s, _)| s >= span_start && s < span_end) {
                continue;
            }

            // `corrector.insert_before(node, "#{kwarg_nodes.map(&:source).join(', ')}, ")`
            let insert_off = keywords[i].location().start_offset();
            let mut insert = Vec::new();
            for (pos, &j) in required_after.iter().enumerate() {
                if pos > 0 {
                    insert.extend_from_slice(b", ");
                }
                insert.extend_from_slice(self.node_src(&keywords[j]));
            }
            insert.extend_from_slice(b", ");
            self.fixes.push((insert_off, insert_off, insert));

            // Remove each relocated required parameter from its original
            // spot (with surrounding space/comma reconstruction) BEFORE
            // queuing the trailing-newline insert below: `apply_fixes`
            // breaks ties on identical start offsets by push order, and
            // when the last optional parameter is immediately followed by
            // one of these removals, the newline's insertion point and the
            // removal's (comma-trimmed) start coincide exactly — the
            // removal must be the one committed first so the newline lands
            // in the gap the removal leaves behind, not immediately undone
            // by `e <= last_start` rejecting the still-open removal.
            for &j in &required_after {
                let l = keywords[j].location();
                let (rs, re) = kpo_remove_range(self.src, l.start_offset(), l.end_offset());
                self.fixes.push((rs, re, Vec::new()));
            }

            // `append_newline_to_last_kwoptarg`: only for an unparenthesized
            // `def` (never blocks/lambdas — see doc comment above) whose
            // very last parameter isn't a `**rest`/`&block` (those already
            // sit at the line's end, so no break is needed).
            if !is_block && !has_parens {
                let last_is_rest_or_block = params.keyword_rest().is_some() || params.block().is_some();
                if !last_is_rest_or_block {
                    if let Some(last_opt) =
                        keywords.iter().rev().find(|n| n.as_optional_keyword_parameter_node().is_some())
                    {
                        let end = last_opt.location().end_offset();
                        self.fixes.push((end, end, b"\n".to_vec()));
                    }
                }
            }
        }
    }
}

/// The byte span from the first parameter (of any kind) to the last, in
/// prism's fixed grammar order — upstream's `arguments_range(defining_node)`
/// (`first_argument..last_argument`). Only called once at least one keyword
/// parameter is known to exist, so the final `keywords` fallbacks always
/// apply.
fn kpo_full_span(params: &ruby_prism::ParametersNode) -> (usize, usize) {
    let start = if let Some(n) = params.requireds().iter().next() {
        n.location().start_offset()
    } else if let Some(n) = params.optionals().iter().next() {
        n.location().start_offset()
    } else if let Some(n) = params.rest() {
        n.location().start_offset()
    } else if let Some(n) = params.posts().iter().next() {
        n.location().start_offset()
    } else {
        params.keywords().iter().next().unwrap().location().start_offset()
    };
    let end = if let Some(n) = params.block() {
        n.location().end_offset()
    } else if let Some(n) = params.keyword_rest() {
        n.location().end_offset()
    } else {
        params.keywords().iter().last().unwrap().location().end_offset()
    };
    (start, end)
}

/// `RangeHelp#range_with_surrounding_space` at its default (both sides,
/// horizontal whitespace then a run of newlines, no further generic
/// whitespace) followed by `range_with_surrounding_comma(range, :left)` —
/// deletes a required keyword parameter cleanly out of its original
/// position, consuming exactly one adjoining comma on the left.
fn kpo_remove_range(src: &[u8], start: usize, end: usize) -> (usize, usize) {
    let mut s = start;
    let mut e = end;
    while s > 0 && matches!(src[s - 1], b' ' | b'\t') {
        s -= 1;
    }
    while s > 0 && src[s - 1] == b'\n' {
        s -= 1;
    }
    while e < src.len() && matches!(src[e], b' ' | b'\t') {
        e += 1;
    }
    while e < src.len() && src[e] == b'\n' {
        e += 1;
    }
    while s > 0 && src[s - 1] == b',' {
        s -= 1;
    }
    (s, e)
}

impl<'a> super::Cops<'a> {
    /// Style/PerlBackrefs — Perl-style regexp match backreferences and their
    /// English versions ($1-$9, $&, $`, $', $+, $MATCH, $PREMATCH,
    /// $POSTMATCH, $LAST_PAREN_MATCH) should use Regexp.last_match forms.
    pub(crate) fn check_perl_backrefs_numbered(
        &mut self,
        node: &ruby_prism::NumberedReferenceReadNode,
    ) {
        const COP: &str = "Style/PerlBackrefs";
        if !self.on(COP) {
            return;
        }
        let offset = node.location().start_offset();

        // Get the number (1-9)
        let num = node.number();
        let original = format!("${}", num);
        let base_preferred = format!("Regexp.last_match({})", num);

        // Add :: prefix if inside class/module
        let preferred = self.add_constant_prefix(&base_preferred);

        let msg = format!(
            "Prefer `{}` over `{}`.",
            preferred, original
        );

        // Check if inside braceless interpolation
        let needs_braces = self.interpolated_node_depth > 0;

        let replacement = if needs_braces {
            let base = format!("Regexp.last_match({})", num);
            format!("{{{}}}", self.add_constant_prefix(&base))
        } else {
            preferred.clone()
        };

        self.push(offset, COP, true, &msg);
        self.fixes
            .push((offset, node.location().end_offset(), replacement.into_bytes()));
    }

    /// Style/PerlBackrefs for back references ($&, $`, $', $+)
    pub(crate) fn check_perl_backrefs_back_ref(
        &mut self,
        node: &ruby_prism::BackReferenceReadNode,
    ) {
        const COP: &str = "Style/PerlBackrefs";
        if !self.on(COP) {
            return;
        }
        let offset = node.location().start_offset();

        // Get the original source text for this node
        let src_text = String::from_utf8_lossy(
            self.node_src(&node.as_node()),
        );

        let (original, base_preferred) = match src_text.as_ref() {
            "$&" => ("$&".to_string(), "Regexp.last_match(0)".to_string()),
            "$`" => ("$`".to_string(), "Regexp.last_match.pre_match".to_string()),
            "$'" => ("$'".to_string(), "Regexp.last_match.post_match".to_string()),
            "$+" => ("$+".to_string(), "Regexp.last_match(-1)".to_string()),
            _ => return, // Unknown back reference
        };

        // Add :: prefix if inside class/module
        let preferred = self.add_constant_prefix(&base_preferred);

        let msg = format!(
            "Prefer `{}` over `{}`.",
            preferred, original
        );

        // Check if inside braceless interpolation
        let replacement = if self.interpolated_node_depth > 0 {
            format!("{{{}}}", preferred)
        } else {
            preferred.clone()
        };

        self.push(offset, COP, true, &msg);
        self.fixes.push((
            offset,
            node.location().end_offset(),
            replacement.into_bytes(),
        ));
    }

    /// Style/PerlBackrefs for global variable backrefs ($MATCH, $PREMATCH,
    /// $POSTMATCH, $LAST_PAREN_MATCH)
    pub(crate) fn check_perl_backrefs_gvar(
        &mut self,
        node: &ruby_prism::GlobalVariableReadNode,
    ) {
        const COP: &str = "Style/PerlBackrefs";
        if !self.on(COP) {
            return;
        }

        let name_bytes = node.name().as_slice();
        let (original, base_preferred) = match name_bytes {
            b"$MATCH" => ("$MATCH".to_string(), "Regexp.last_match(0)".to_string()),
            b"$PREMATCH" => (
                "$PREMATCH".to_string(),
                "Regexp.last_match.pre_match".to_string(),
            ),
            b"$POSTMATCH" => (
                "$POSTMATCH".to_string(),
                "Regexp.last_match.post_match".to_string(),
            ),
            b"$LAST_PAREN_MATCH" => (
                "$LAST_PAREN_MATCH".to_string(),
                "Regexp.last_match(-1)".to_string(),
            ),
            _ => return, // Not a perl backref global
        };

        // Add :: prefix if inside class/module
        let preferred = self.add_constant_prefix(&base_preferred);

        let offset = node.location().start_offset();
        let msg = format!(
            "Prefer `{}` over `{}`.",
            preferred, original
        );

        // Check if inside braceless interpolation
        let replacement = if self.interpolated_node_depth > 0 {
            format!("{{{}}}", preferred)
        } else {
            preferred.clone()
        };

        self.push(offset, COP, true, &msg);
        self.fixes.push((
            offset,
            node.location().end_offset(),
            replacement.into_bytes(),
        ));
    }

    /// Helper to add :: prefix if inside class/module
    fn add_constant_prefix(&self, expr: &str) -> String {
        if self.class_module_depth > 0 {
            format!("::{}", expr)
        } else {
            expr.to_string()
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/RedundantConditional — `if x == y then true else false` → `x == y`,
    /// and inverted form → `!(x == y)`.
    pub(crate) fn check_redundant_conditional(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/RedundantConditional";
        if !self.on(COP) {
            return;
        }

        // Don't trigger on modifier form (e.g., `true if x`)
        if node.if_keyword_loc().is_none() && node.end_keyword_loc().is_none() {
            // This is a ternary, which is fine to process
        } else if node.if_keyword_loc().is_some() && node.end_keyword_loc().is_none() {
            // This is a modifier if/unless, skip it
            return;
        }

        // Get the condition (predicate)
        let condition = node.predicate();

        // Check if condition is a send node with a comparison operator
        let call_node = match condition.as_call_node() {
            Some(c) => c,
            None => return,
        };

        let method_name = call_node.name().as_slice();
        let is_comparison = matches!(
            method_name,
            b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<" | b"<=>"
        );
        if !is_comparison {
            return;
        }

        // Get the then and else branches
        let then_stmts = match node.statements() {
            Some(s) => s,
            None => return,
        };

        let mut then_iter = then_stmts.body().iter();
        let then_stmt = match then_iter.next() {
            Some(s) if then_iter.next().is_none() => s,
            _ => return,
        };

        let else_clause = match node.subsequent() {
            Some(e) => e,
            None => return,
        };

        let else_node = match else_clause.as_else_node() {
            Some(e) => e,
            None => return,
        };

        let else_stmts = match else_node.statements() {
            Some(s) => s,
            None => return,
        };

        let mut else_iter = else_stmts.body().iter();
        let else_stmt = match else_iter.next() {
            Some(s) if else_iter.next().is_none() => s,
            _ => return,
        };

        // Check if then is true and else is false, or vice versa
        let is_true_then = then_stmt.as_true_node().is_some();
        let is_false_then = then_stmt.as_false_node().is_some();
        let is_true_else = else_stmt.as_true_node().is_some();
        let is_false_else = else_stmt.as_false_node().is_some();

        let (is_inverted, is_elsif) = if is_true_then && is_false_else {
            (false, node.if_keyword_loc().is_some_and(|kw| kw.as_slice() == b"elsif"))
        } else if is_false_then && is_true_else {
            (true, node.if_keyword_loc().is_some_and(|kw| kw.as_slice() == b"elsif"))
        } else {
            return;
        };

        // Generate the replacement message and fix
        let cond_src = self.node_src(&condition);
        let replacement = if is_inverted {
            format!("!({})", String::from_utf8_lossy(cond_src))
        } else {
            String::from_utf8_lossy(cond_src).to_string()
        };

        let msg = if is_elsif {
            format!("This conditional expression can just be replaced by [...].")
        } else {
            format!("This conditional expression can just be replaced by `{}`.", replacement)
        };

        let l = node.location();
        self.push(l.start_offset(), COP, true, msg);

        // Generate autocorrect
        let l_end = l.end_offset();
        if is_elsif {
            // For elsif, the body indentation should match the existing elsif body
            // Get the indentation from the elsif body
            let body_indent = if let Some(stmts) = node.statements() {
                if let Some(first_stmt) = stmts.body().iter().next() {
                    let (_, col) = self.idx.loc(first_stmt.location().start_offset());
                    col - 1 // Convert to 0-indexed
                } else {
                    0
                }
            } else {
                0
            };

            let mut fix_text = b"else\n".to_vec();
            fix_text.extend(std::iter::repeat(b' ').take(body_indent));
            fix_text.extend_from_slice(replacement.as_bytes());
            fix_text.push(b'\n');
            // Add the end keyword with proper indentation (at same level as elsif)
            let else_indent = self.idx.loc(l.start_offset()).1 - 1;
            fix_text.extend(std::iter::repeat(b' ').take(else_indent));
            fix_text.extend_from_slice(b"end");
            self.fixes.push((l.start_offset(), l_end, fix_text));
        } else {
            // For regular if or ternary, replace with the condition (or negated condition)
            self.fixes.push((l.start_offset(), l_end, replacement.into_bytes()));
        }
    }

    /// Style/RedundantConditional for unless statements.
    /// `unless x == y then true else false` → `!(x == y)` (then-clause is inverted)
    /// `unless x == y then false else true` → `x == y` (double negation cancels)
    pub(crate) fn check_redundant_conditional_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/RedundantConditional";
        if !self.on(COP) {
            return;
        }

        // Don't trigger on modifier form (e.g., `true unless x`)
        if node.end_keyword_loc().is_none() {
            return;
        }

        // Get the condition (predicate)
        let condition = node.predicate();

        // Check if condition is a send node with a comparison operator
        let call_node = match condition.as_call_node() {
            Some(c) => c,
            None => return,
        };

        let method_name = call_node.name().as_slice();
        let is_comparison = matches!(
            method_name,
            b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<" | b"<=>"
        );
        if !is_comparison {
            return;
        }

        // Get the then and else branches
        let then_stmts = match node.statements() {
            Some(s) => s,
            None => return,
        };

        let mut then_iter = then_stmts.body().iter();
        let then_stmt = match then_iter.next() {
            Some(s) if then_iter.next().is_none() => s,
            _ => return,
        };

        let else_clause = match node.else_clause() {
            Some(e) => e,
            None => return,
        };

        let else_stmts = match else_clause.statements() {
            Some(s) => s,
            None => return,
        };

        let mut else_iter = else_stmts.body().iter();
        let else_stmt = match else_iter.next() {
            Some(s) if else_iter.next().is_none() => s,
            _ => return,
        };

        // Check if then is true and else is false, or vice versa
        let is_true_then = then_stmt.as_true_node().is_some();
        let is_false_then = then_stmt.as_false_node().is_some();
        let is_true_else = else_stmt.as_true_node().is_some();
        let is_false_else = else_stmt.as_false_node().is_some();

        // For unless, the logic is inverted:
        // unless cond; true; else; false -> !(cond) (negation of condition)
        // unless cond; false; else; true -> cond (double negation cancels)
        let is_inverted = if is_true_then && is_false_else {
            true  // unless cond true else false → !(cond)
        } else if is_false_then && is_true_else {
            false // unless cond false else true → cond
        } else {
            return;
        };

        // Generate the replacement message and fix
        let cond_src = self.node_src(&condition);
        let replacement = if is_inverted {
            format!("!({})", String::from_utf8_lossy(cond_src))
        } else {
            String::from_utf8_lossy(cond_src).to_string()
        };

        let msg = format!("This conditional expression can just be replaced by `{}`.", replacement);

        let l = node.location();
        self.push(l.start_offset(), COP, true, msg);

        // Generate autocorrect
        self.fixes.push((l.start_offset(), l.end_offset(), replacement.into_bytes()));
    }
}


impl<'a> super::Cops<'a> {
    /// Style/MultilineMemoization: `foo ||= (...)` / `foo ||= begin ... end`
    /// spanning multiple lines must use whichever wrapper the
    /// `EnforcedStyle` prefers (`keyword`, the default, wants `begin`/`end`;
    /// `braces` wants `(`/`)`). Ported from rubocop's `on_or_asgn` +
    /// `bad_rhs?` + `message` + `keyword_autocorrect`.
    ///
    /// rubocop-ast unifies EVERY `||=` shape (lvar/ivar/cvar/gvar/const/
    /// const-path/attr-writer/index) into a single `or_asgn` node type;
    /// prism keeps them as 8 distinct node kinds (`LocalVariableOrWriteNode`
    /// &c.), so this is hooked from all 8 `visit_*_or_write_node` overrides
    /// in `mod.rs`, each passing its own node's start offset (matching
    /// upstream's `add_offense(node)` on the WHOLE `or_asgn`, never just the
    /// RHS — confirmed against the fixture: the offense's first-line carets
    /// always run from the assignment's own start through end-of-line) and
    /// its RHS value node.
    ///
    /// Verified live against rubocop 1.88.0 (see `ruby -rrubocop -e` probe
    /// in the branch notes) that whitequark's parser wraps ANY parenthesized
    /// `||=` RHS in a `:begin` node regardless of statement count — `(bar)`
    /// alone gets one just like `(bar; baz)` — so prism's `ParenthesesNode`
    /// (always emitted for explicit `(...)`) is a faithful 1:1 stand-in for
    /// `rhs.begin_type?`, and `BeginNode` (prism's `begin...end`,
    /// `rescue_clause`/`else_clause`/`ensure_clause` all optional) stands in
    /// for `rhs.kwbegin_type?`.
    pub(crate) fn check_multiline_memoization(&mut self, node_start: usize, rhs: &ruby_prism::Node) {
        const COP: &str = "Style/MultilineMemoization";
        if !self.on(COP) {
            return;
        }
        let loc = rhs.location();
        // `Node#multiline?`: the node's own first/last source line differ —
        // NOT the enclosed body's lines (an empty `()`/`begin end` can never
        // satisfy this since opening/closing then share a line).
        let start_line = self.idx.loc(loc.start_offset()).0;
        let end_line = self.idx.loc(loc.end_offset().saturating_sub(1)).0;
        if start_line == end_line {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        if style == "braces" {
            let Some(begin_node) = rhs.as_begin_node() else { return };
            let (Some(bk), Some(ek)) = (begin_node.begin_keyword_loc(), begin_node.end_keyword_loc()) else {
                return;
            };
            self.push(node_start, COP, true, "Wrap multiline memoization blocks in `(` and `)`.");
            self.fixes.push((bk.start_offset(), bk.end_offset(), b"(".to_vec()));
            self.fixes.push((ek.start_offset(), ek.end_offset(), b")".to_vec()));
        } else {
            let Some(paren) = rhs.as_parentheses_node() else { return };
            self.push(node_start, COP, true, "Wrap multiline memoization blocks in `begin` and `end`.");
            self.mm_keyword_autocorrect(&paren);
        }
    }

    /// `Alignment#configured_indentation_width`: the cop's own
    /// `IndentationWidth` param if a user set one (never a schema default —
    /// `Style/MultilineMemoization` has no such param in rubocop's
    /// `default.yml`), else `Layout/IndentationWidth`'s `Width` (schema
    /// default 2).
    fn mm_indentation_width(&self) -> usize {
        self.cfg
            .get("Style/MultilineMemoization", "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| self.cfg.int("Layout/IndentationWidth", "Width"))
    }

    /// The raw bytes of 1-based source `line`, line-terminator excluded —
    /// rubocop's `Source::Buffer#source_line`.
    fn mm_source_line(&self, line: usize) -> &'a [u8] {
        let start = self.idx.starts[line - 1];
        let end = self.idx.starts.get(line).map(|&s| s - 1).unwrap_or(self.src.len());
        &self.src[start..end]
    }

    /// `MultilineMemoization#keyword_autocorrect`/`keyword_begin_str`/
    /// `keyword_end_str`, ported verbatim: replaces just the `(`/`)` TOKENS
    /// (never the enclosed body) with `begin`/`end`, each conditionally
    /// carrying its own inserted newline + indentation depending on what
    /// already shares that token's line.
    fn mm_keyword_autocorrect(&mut self, paren: &ruby_prism::ParenthesesNode) {
        let open = paren.opening_loc();
        let close = paren.closing_loc();
        // `node.loc.column`: the RHS node's OWN start column (0-based) —
        // for a `ParenthesesNode` that's exactly the `(`'s column, since the
        // node's location starts there.
        let node_col = self.idx.loc(paren.location().start_offset()).1 - 1;
        let indent_width = self.mm_indentation_width();

        // keyword_begin_str: if a newline immediately follows the `(`,
        // just `begin` (the following line's own indentation is untouched);
        // otherwise `begin` needs its own newline + fresh indentation before
        // whatever content directly abutted the `(`.
        let begin_repl: Vec<u8> = if self.src.get(open.end_offset()) == Some(&b'\n') {
            b"begin".to_vec()
        } else {
            let mut v = b"begin\n".to_vec();
            v.extend(std::iter::repeat_n(b' ', node_col + indent_width));
            v
        };
        self.fixes.push((open.start_offset(), open.end_offset(), begin_repl));

        // keyword_end_str: if the `)`'s own line has any non-whitespace,
        // non-`)` content (i.e. the closing paren directly follows body
        // content on that line), `end` needs its own newline + the RHS
        // node's original indentation; otherwise the `)` sits alone (save
        // for leading whitespace) and `end` can just replace it in place.
        let end_line = self.idx.loc(close.start_offset()).0;
        let line_has_other_content =
            self.mm_source_line(end_line).iter().any(|&b| !b.is_ascii_whitespace() && b != b')');
        let end_repl: Vec<u8> = if line_has_other_content {
            let mut v = b"\n".to_vec();
            v.extend(std::iter::repeat_n(b' ', node_col));
            v.extend_from_slice(b"end");
            v
        } else {
            b"end".to_vec()
        };
        self.fixes.push((close.start_offset(), close.end_offset(), end_repl));
    }
}

impl<'a> super::Cops<'a> {
    /// Style/NegatedUnless — `unless !x` → `if x` and vice versa (mirror of NegatedIf).
    pub(crate) fn check_negated_unless(&mut self, node: &ruby_prism::UnlessNode) {
        if !self.hot.negated_unless {
            return;
        }
        const COP: &str = "Style/NegatedUnless";
        if node.else_clause().is_some() {
            return; // unless with else
        }
        let modifier = node.end_keyword_loc().is_none();
        match self.hot.negated_unless_style {
            1 if modifier => return,
            2 if !modifier => return,
            _ => {}
        }
        let Some((bang_start, recv_start)) = single_negative(node.predicate()) else { return };
        let l = node.location();
        let inverse = "if";
        let current = "unless";
        self.push(l.start_offset(), COP, true,
            format!("Favor `{inverse}` over `{current}` for negative conditions."));
        // fix: swap the keyword and drop the `!`
        let kw = node.keyword_loc();
        self.fixes.push((kw.start_offset(), kw.end_offset(), b"if".to_vec()));
        self.fixes.push((bang_start, recv_start, Vec::new()));
    }

}

impl<'a> super::Cops<'a> {
    /// Style/NonNilCheck — `on_def`/`on_defs` half: predicate methods
    /// (`foo?`) tolerate an explicit non-nil check as their trailing (or
    /// sole) body statement — upstream's `ignore_node(body.begin_type? ?
    /// body.children.last : body)`. Prism ALWAYS wraps a def body in a
    /// `StatementsNode` regardless of statement count (unlike whitequark,
    /// which only wraps 2+ statements in a `:begin`), so both branches
    /// collapse to one lookup: the last element of that `StatementsNode`.
    /// prism gives `def`/`defs` (singleton methods, e.g. `def Test.foo?`)
    /// the SAME node type, so this single hook covers both `on_def` and
    /// `on_defs`.
    pub(crate) fn check_non_nil_check_def(&mut self, node: &ruby_prism::DefNode) {
        if !node.name().as_slice().ends_with(b"?") {
            return;
        }
        let Some(body) = node.body() else { return };
        let last = if let Some(stmts) = body.as_statements_node() {
            stmts.body().iter().last()
        } else {
            Some(body)
        };
        if let Some(last) = last {
            self.non_nil_ignored
                .insert((last.location().start_offset(), last.location().end_offset()));
        }
    }

    /// Style/NonNilCheck — `on_send` half, minus `unless_and_nil_check?`
    /// (needs the parent `UnlessNode`; see `check_non_nil_check_unless`,
    /// called pre-order from `visit_unless_node`). Handles:
    /// - `not_equal_to_nil?` (`(send _ :!= nil)`): ALWAYS eligible — the only
    ///   form whose message/fix differs on `IncludeSemanticChanges`.
    /// - `not_and_nil_check?` (`(send (send _ :nil?) :!)`, i.e. `!x.nil?` /
    ///   `not x.nil?`, prism folds both to a `!`-named `CallNode`): eligible
    ///   only with `IncludeSemanticChanges: true`.
    pub(crate) fn check_non_nil_check(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/NonNilCheck";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"!=" | b"!") {
            return;
        }
        // `ignored_node?`: this exact node was marked by an enclosing
        // predicate `def` as its trailing/only body statement.
        if self
            .non_nil_ignored
            .contains(&(node.location().start_offset(), node.location().end_offset()))
        {
            return;
        }
        let semantic = self.non_nil_semantic_changes(COP);
        // `return if ... (!include_semantic_changes? && nil_comparison_style
        // == 'comparison')` — gates EVERY `RESTRICT_ON_SEND` method, not
        // just `!=`; harmless to check unconditionally here since the `!`
        // branch below already requires `semantic` to fire at all (and
        // `semantic` and `!semantic` can't both hold).
        if !semantic && self.non_nil_comparison_style_conflicts() {
            return;
        }
        let Some(receiver) = node.receiver() else { return };
        if name == b"!=" {
            // `(send _ :!= nil)` — any receiver, argument must be a literal
            // `nil` (excludes `x != 0`, `x != y`, …).
            let Some(args) = node.arguments() else { return };
            let mut it = args.arguments().iter();
            let Some(only) = it.next() else { return };
            if it.next().is_some() || only.as_nil_node().is_none() {
                return;
            }
            let l = node.location();
            let recv_src = self.node_src(&receiver).to_vec();
            let msg = if semantic {
                "Explicit non-nil checks are usually redundant.".to_string()
            } else {
                format!(
                    "Prefer `!{}.nil?` over `{}`.",
                    String::from_utf8_lossy(&recv_src),
                    String::from_utf8_lossy(self.node_src(&node.as_node())),
                )
            };
            self.push(l.start_offset(), COP, true, msg);
            let replacement: Vec<u8> = if semantic {
                recv_src
            } else {
                let mut r = b"!".to_vec();
                r.extend_from_slice(&recv_src);
                r.extend_from_slice(b".nil?");
                r
            };
            self.fixes.push((l.start_offset(), l.end_offset(), replacement));
        } else {
            // `!x.nil?` / `not x.nil?` — only with semantic changes, and
            // only this exact shape (a bare `!x` never matches: its
            // receiver isn't a `nil?` call).
            if !semantic || node.arguments().is_some() {
                return;
            }
            let Some(inner) = receiver.as_call_node() else { return };
            if inner.name().as_slice() != b"nil?" || inner.arguments().is_some() {
                return;
            }
            let l = node.location();
            self.push(l.start_offset(), COP, true, "Explicit non-nil checks are usually redundant.");
            // `inner_node.receiver ? inner_node.receiver.source : 'self'` —
            // an implicit receiver on the inner `nil?` (`!nil?`) corrects to
            // literal `self`.
            let replacement: Vec<u8> = match inner.receiver() {
                Some(inner_recv) => self.node_src(&inner_recv).to_vec(),
                None => b"self".to_vec(),
            };
            self.fixes.push((l.start_offset(), l.end_offset(), replacement));
        }
    }

    /// Style/NonNilCheck — `unless_and_nil_check?`: `unless x.nil?`, only
    /// with `IncludeSemanticChanges: true`. Corrects `unless x.nil? ... end`
    /// / `stmt unless x.nil?` to `if x ... end` / `if x stmt` by swapping the
    /// `unless` keyword to `if` and replacing the `.nil?` call with its
    /// receiver's source.
    pub(crate) fn check_non_nil_check_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/NonNilCheck";
        if !self.on(COP) || !self.non_nil_semantic_changes(COP) {
            return;
        }
        // `unless_check?`: `(if (send _ :nil?) ...)` matched against the
        // PARENT — i.e. this `nil?` call must be exactly the `unless`'s own
        // predicate, not merely nested somewhere inside it.
        let Some(call) = node.predicate().as_call_node() else { return };
        if call.name().as_slice() != b"nil?" || call.arguments().is_some() {
            return;
        }
        if self
            .non_nil_ignored
            .contains(&(call.location().start_offset(), call.location().end_offset()))
        {
            return;
        }
        // A receiver-less `nil?` (`unless nil?` — implicit `self.nil?`)
        // makes upstream's OWN autocorrect raise (`corrector.replace(node,
        // receiver.source)` where `receiver` is Ruby `nil`, not a node) —
        // verified live against rubocop 1.88.0: the file comes back
        // untouched and the run reports zero offenses for the whole file
        // (the exception aborts the cop's entire investigation of it).
        // Since no fixture example exercises this, and there is no sane
        // non-crashing offense to reproduce, treat it as "no offense" here.
        let Some(receiver) = call.receiver() else { return };
        let l = call.location();
        self.push(l.start_offset(), COP, true, "Explicit non-nil checks are usually redundant.");
        let kw = node.keyword_loc();
        self.fixes.push((kw.start_offset(), kw.end_offset(), b"if".to_vec()));
        self.fixes.push((l.start_offset(), l.end_offset(), self.node_src(&receiver).to_vec()));
    }

    fn non_nil_semantic_changes(&self, cop: &str) -> bool {
        self.cfg.get(cop, "IncludeSemanticChanges").is_some_and(|v| v == "true")
    }

    /// `nil_comparison_style == 'comparison'`: `Style/NilComparison`'s own
    /// `Enabled`/`EnforcedStyle`, read directly off its config section
    /// (`config.for_cop`). Deliberately `param()`, not `cop_config_enabled`:
    /// `Style/NilComparison` ships `Enabled: true` in real rubocop's
    /// default.yml, so a real `Config` object has that key set REGARDLESS of
    /// an `AllCops: DisabledByDefault` elsewhere — `all_disabled_by_default`
    /// only matters for cops with no baked-in default, which isn't this
    /// cop's situation. Only an EXPLICIT `Enabled: false` on `Style/
    /// NilComparison` itself should count as disabled here.
    fn non_nil_comparison_style_conflicts(&self) -> bool {
        self.cfg.param("Style/NilComparison", "Enabled") != Some("false")
            && self.cfg.get("Style/NilComparison", "EnforcedStyle") == Some("comparison")
    }
}

impl<'a> super::Cops<'a> {
    /// Style/MixinUsage: `include`/`extend`/`prepend` with exactly one
    /// constant argument, found where upstream's `in_top_level_scope?`
    /// node-pattern would be true. That pattern walks a `send` node's
    /// (whitequark) ancestors — `root?` (no parent at all) OR a parent
    /// that's one of `{kwbegin begin if def}` AND is *itself*
    /// `in_top_level_scope?` — all the way up to the file root. `ruby_prism`
    /// nodes have no back-pointer to their parent, so this is ported as a
    /// dedicated top-down walk from the program root instead of a bottom-up
    /// climb: once a node's real structural position falls outside that
    /// ancestor set, no offense is reachable anywhere beneath it (eligibility
    /// only ever flows downward from the root, never recovers), so ineligible
    /// subtrees are pruned rather than fully traversed. `StatementsNode` is
    /// whitequark-transparent unconditionally (a single statement is spliced
    /// in directly with no wrapper node at all; more than one becomes
    /// `:begin`, which is itself in the allow-list) — so it's walked the same
    /// way regardless of how many statements it holds.
    pub(crate) fn check_mixin_usage(&mut self, node: &ruby_prism::Node) {
        if !self.on("Style/MixinUsage") {
            return;
        }
        self.mixin_usage_walk(node);
    }

    fn mixin_usage_walk(&mut self, node: &ruby_prism::Node) {
        if let Some(stmts) = node.as_statements_node() {
            for stmt in stmts.body().iter() {
                self.mixin_usage_walk(&stmt);
            }
        } else if let Some(def) = node.as_def_node() {
            // `def self.foo` is whitequark's distinct `:defs` node type —
            // never in the allow-list, so it (and everything in its body) is
            // opaque regardless of position. Only a receiver-less `def`
            // (whitequark `:def`) is transparent, and only through its body
            // — parameters/defaults sit on a different (non-allow-listed)
            // branch and are never visited here.
            if def.receiver().is_none() {
                if let Some(body) = def.body() {
                    self.mixin_usage_walk(&body);
                }
            }
        } else if let Some(ifn) = node.as_if_node() {
            // Covers `if`, `elsif` (via `subsequent` recursing back into this
            // same arm) and ternaries alike — all one prism `IfNode` shape.
            if let Some(then_stmts) = ifn.statements() {
                self.mixin_usage_walk(&then_stmts.as_node());
            }
            if let Some(sub) = ifn.subsequent() {
                self.mixin_usage_walk(&sub);
            }
        } else if let Some(un) = node.as_unless_node() {
            if let Some(then_stmts) = un.statements() {
                self.mixin_usage_walk(&then_stmts.as_node());
            }
            if let Some(else_clause) = un.else_clause() {
                if let Some(else_stmts) = else_clause.statements() {
                    self.mixin_usage_walk(&else_stmts.as_node());
                }
            }
        } else if let Some(en) = node.as_else_node() {
            // Reached via `IfNode#subsequent`'s final `else` branch — in
            // whitequark that's just the enclosing `if`'s third child, not a
            // separate node type, so its statements inherit the same
            // transparency as the `if`/`unless` that owns it.
            if let Some(stmts) = en.statements() {
                self.mixin_usage_walk(&stmts.as_node());
            }
        } else if let Some(begin) = node.as_begin_node() {
            // A bare `begin...end` (no rescue/else/ensure) is whitequark's
            // `:kwbegin` wrapping its body directly — transparent. Any
            // rescue/else/ensure clause means the body's real whitequork
            // parent is a `:rescue`/`:ensure` node instead (`:kwbegin`, if
            // present at all, sits one level further out wrapping THAT node)
            // — never `:kwbegin` itself, so it's opaque. A keyword-less
            // `BeginNode` (a `def`'s implicit rescue/ensure body — see the
            // module's prism-vs-whitequark trap notes) only ever occurs
            // together with one of these clauses, so checking the three
            // clauses alone is sufficient.
            if begin.rescue_clause().is_none() && begin.else_clause().is_none() && begin.ensure_clause().is_none() {
                if let Some(stmts) = begin.statements() {
                    self.mixin_usage_walk(&stmts.as_node());
                }
            }
        } else if let Some(call) = node.as_call_node() {
            self.check_mixin_usage_call(&call);
            // A call's receiver/arguments/block are never allow-listed
            // types — no offense is reachable beneath them, so don't widen
            // the walk into them.
        }
        // Everything else (class/module/singleton-class bodies, block/
        // lambda bodies, while/until/case/case-in/for bodies, and any other
        // expression position) is opaque: no offense can occur underneath,
        // so it's simply left unwalked.
    }

    fn check_mixin_usage_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/MixinUsage";
        if node.receiver().is_some() {
            return;
        }
        let statement = match node.name().as_slice() {
            b"include" => "include",
            b"extend" => "extend",
            b"prepend" => "prepend",
            _ => return,
        };
        // A block turns the call into whitequark's `:block` wrapper node —
        // the `send` node's real parent becomes that (non-allow-listed) node,
        // so it's never top-level no matter how eligible its own position
        // would otherwise be.
        if node.block().is_some() {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let arg_list = args.arguments();
        if arg_list.iter().count() != 1 {
            return;
        }
        let arg = arg_list.iter().next().expect("count checked above");
        if arg.as_constant_read_node().is_none() && arg.as_constant_path_node().is_none() {
            return;
        }
        self.push(
            node.location().start_offset(),
            COP,
            false,
            format!("`{statement}` is used at the top level. Use inside `class` or `module`."),
        );
    }
}
impl<'a> super::Cops<'a> {

    /// Style/LambdaCall — checks for use of the lambda.(args) syntax.
    /// EnforcedStyle: call (default, `x.()` → `x.call`) / braces (`x.call` → `x.()`).
    pub(crate) fn check_lambda_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/LambdaCall";
        if !self.on(COP) {
            return;
        }
        // Only hook on "call" method
        if node.name().as_slice() != b"call" {
            return;
        }
        // Must have a receiver
        let Some(_) = node.receiver() else { return };

        // Determine current style: implicit is no message_loc, explicit has message_loc
        let is_implicit = node.message_loc().is_none();

        // Get enforced style from config: defaults to "call"
        let enforced_style = self.cfg.enforced_style(COP);

        // Determine if this is an offense
        let is_offense = if enforced_style == "braces" {
            !is_implicit   // prefer .(), so explicit is bad
        } else {
            is_implicit    // prefer .call (default), so implicit is bad
        };

        if !is_offense {
            return;
        }

        // Generate the preferred form
        let src = self.node_src(&node.as_node());
        let current = std::str::from_utf8(src).unwrap_or("<source>");

        let prefer = if let Some(receiver_node) = node.receiver() {
            let receiver_bytes = self.node_src(&receiver_node);
            let receiver = std::str::from_utf8(receiver_bytes).unwrap_or("");

            // Get the dot operator (. or &.)
            let dot = if let Some(dot_loc) = node.message_loc() {
                // For explicit calls, message_loc starts at the "c" in "call"
                // We need to get everything before it as the dot
                let msg_start = dot_loc.start_offset();
                let recv_end = receiver_node.location().end_offset();
                let dot_bytes = &self.src[recv_end..msg_start];
                std::str::from_utf8(dot_bytes).unwrap_or(".")
            } else {
                // For implicit calls, we need to find the dot from the source
                // x.() format - find the dot before the parens
                if let Some(paren_idx) = src.iter().position(|&b| b == b'(') {
                    let before_paren = &src[..paren_idx];
                    // The dot should be right before the opening paren
                    if before_paren.ends_with(b"&.") {
                        "&."
                    } else if before_paren.ends_with(b".") {
                        "."
                    } else {
                        "."
                    }
                } else {
                    "."
                }
            };

            // Extract arguments from the source
            let args_str = if let Some(args) = node.arguments() {
                let mut arg_parts = Vec::new();
                for arg in args.arguments().iter() {
                    let arg_bytes = self.node_src(&arg);
                    if let Ok(arg_str) = std::str::from_utf8(arg_bytes) {
                        arg_parts.push(arg_str.to_string());
                    }
                }
                if arg_parts.is_empty() {
                    String::new()
                } else {
                    format!("({})", arg_parts.join(", "))
                }
            } else {
                // No parenthesized arguments - check if there are space-separated args
                // by looking at the source between "call" and end
                if is_implicit {
                    String::new()
                } else {
                    // For explicit .call, we might have "x.call a, b" (no parens)
                    // We need to extract everything after "call" as arguments
                    let msg_loc = node.message_loc().unwrap();
                    let call_end = msg_loc.end_offset();
                    let node_end = node.location().end_offset();
                    if call_end < node_end {
                        let arg_bytes = &self.src[call_end..node_end];
                        if let Ok(arg_str) = std::str::from_utf8(arg_bytes) {
                            let trimmed = arg_str.trim_start();
                            if !trimmed.is_empty() {
                                format!("({})", trimmed)
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                }
            };

            if enforced_style == "braces" {
                // Convert x.call() to x.()
                let args_inner = args_str.trim_start_matches('(').trim_end_matches(')');
                format!("{}{}({})", receiver, dot, args_inner)
            } else {
                // Convert x.() to x.call()
                format!("{}{}{}{}", receiver, dot, "call", args_str)
            }
        } else {
            current.to_string()
        };

        let l = node.location();
        self.push(
            l.start_offset(),
            COP,
            true,
            format!("Prefer the use of `{}` over `{}`.", prefer, current),
        );

        let prefer_bytes = prefer.as_bytes().to_vec();
        self.fixes.push((l.start_offset(), l.end_offset(), prefer_bytes));
    }
}

/// Ruby's `String#capitalize`: upcase the first char, downcase the rest.
/// Used only for `CommentAnnotation`'s `just_keyword_of_sentence?` check
/// (`keyword == keyword.capitalize`).
fn ruby_capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(f) => f.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
        None => String::new(),
    }
}

impl<'a> super::Cops<'a> {
    /// Style/CommentAnnotation — flags annotation keywords (`TODO`, `FIXME`,
    /// ...) that aren't `KEYWORD: note` (or `KEYWORD note` under
    /// `RequireColon: false`). Ported from rubocop's `CommentAnnotation` cop
    /// + its `AnnotationComment` mixin, operating directly on the comment
    /// token list (`self.comments`) rather than any AST node — there's no
    /// single visit_* hook for this, so it runs once per file over ALL
    /// comments, mirroring `on_new_investigation`.
    ///
    /// Only two kinds of comment lines are checked (`first_comment_line? ||
    /// inline_comment?`): the first line of a run of consecutive own-line
    /// comments (a "paragraph" — later lines in that paragraph are exempt,
    /// per the cop's own doc comment, to avoid misfiring on prose), and any
    /// EOL/inline comment (code precedes the `#` on its line) regardless of
    /// what precedes or follows it.
    pub(crate) fn check_comment_annotation(&mut self) {
        const COP: &str = "Style/CommentAnnotation";
        if !self.on(COP) || self.comments.is_empty() {
            return;
        }
        // `Keywords` is an array-valued default absent from the generated
        // schema (only scalar defaults live there) — hardcode rubocop's
        // default.yml value as the fallback.
        let keywords: Vec<String> = match self.cfg.get(COP, "Keywords") {
            Some(v) => crate::config::parse_allowed_list(v),
            None => ["TODO", "FIXME", "OPTIMIZE", "HACK", "REVIEW", "NOTE"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        };
        if keywords.is_empty() {
            return;
        }
        let requires_colon = self.cfg.get(COP, "RequireColon") != Some("false");

        // `Regexp.union(keywords.sort_by { |w| -w.length })`: longer
        // keywords must be tried first so a phrase like `TODO LATER` wins
        // over a plain `TODO` prefix (Rust's regex crate, like Ruby's
        // Onigmo, picks the first alternative that matches at a position —
        // not the longest — so the ordering is load-bearing here).
        let mut sorted_kw = keywords.clone();
        sorted_kw.sort_by_key(|k| std::cmp::Reverse(k.len()));
        let alts = sorted_kw.iter().map(|k| regex::escape(k)).collect::<Vec<_>>().join("|");
        // Mirrors AnnotationComment's regex exactly:
        //   /^(# ?)(\b#{keywords_regex}\b)(\s*:)?(\s+)?(\S+)?/i
        let pattern = format!(r"(?i)^(# ?)(\b(?:{alts})\b)(\s*:)?(\s+)?(\S+)?");
        let Ok(re) = regex::Regex::new(&pattern) else { return };

        for i in 0..self.comments.len() {
            let (line, start, end) = self.comments[i];
            // `first_comment_line?`: this is the very first comment in the
            // file, or the previous comment sits on a non-adjacent line
            // (i.e. this comment opens a new paragraph).
            let first_comment_line = i == 0 || self.comments[i - 1].0 < line - 1;
            // `inline_comment?`: code precedes the `#` on this physical
            // line (the line as a whole isn't `^\s*#`).
            let line_start = self.idx.starts[line - 1];
            let inline_comment = self.src[line_start..start].iter().any(|b| !b.is_ascii_whitespace());
            if !(first_comment_line || inline_comment) {
                continue;
            }

            let Ok(text) = std::str::from_utf8(&self.src[start..end]) else { continue };
            let Some(caps) = re.captures(text) else { continue };
            let margin = caps.get(1).expect("group 1 required by pattern");
            let keyword_m = caps.get(2).expect("group 2 required alongside margin");
            let colon = caps.get(3);
            let space = caps.get(4);
            let note = caps.get(5);

            // `keyword_appearance?`: keyword && (colon || space).
            if colon.is_none() && space.is_none() {
                continue;
            }
            let keyword_str = keyword_m.as_str();
            // `just_keyword_of_sentence?`: a capitalized (not all-caps)
            // keyword, no colon, followed by space + note — reads as an
            // ordinary sentence ("Optimize if you want."), not an
            // annotation.
            if keyword_str == ruby_capitalize(keyword_str) && colon.is_none() && space.is_some() && note.is_some() {
                continue;
            }

            // `correct?(colon: requires_colon?)`.
            let is_correct = space.is_some()
                && note.is_some()
                && keyword_str == keyword_str.to_uppercase()
                && (colon.is_none() == !requires_colon);
            if is_correct {
                continue;
            }

            let bounds_start = start + margin.end();
            let bounds_len = keyword_str.len()
                + colon.map_or(0, |m| m.as_str().len())
                + space.map_or(0, |m| m.as_str().len());
            let bounds_end = bounds_start + bounds_len;

            let message = if note.is_some() {
                if requires_colon {
                    format!(
                        "Annotation keywords like `{keyword_str}` should be all upper case, followed by a colon, and a space, then a note describing the problem."
                    )
                } else {
                    format!(
                        "Annotation keywords like `{keyword_str}` should be all upper case, followed by a space, then a note describing the problem."
                    )
                }
            } else {
                format!("Annotation comment, with keyword `{keyword_str}`, is missing a note.")
            };

            // `next if annotation.note.nil?` inside the add_offense block:
            // a missing-note offense is registered but never autocorrected.
            let correctable = note.is_some();
            self.push(bounds_start, COP, correctable, message);
            if correctable {
                let replacement = if requires_colon {
                    format!("{}: ", keyword_str.to_uppercase())
                } else {
                    format!("{} ", keyword_str.to_uppercase())
                };
                self.fixes.push((bounds_start, bounds_end, replacement.into_bytes()));
            }
        }
    }
}


/// Style/TrailingUnderscoreVariable: a masgn LHS target's classification for
/// upstream's `DISALLOW = %i[lvasgn splat]` backward scan. Prism's masgn
/// targets (`MultiWriteNode#lefts`/`#rest`/`#rights`, and identically shaped
/// nested groups via `MultiTargetNode`) split what whitequark represents
/// uniformly as `(:lvasgn name)` / `(:splat inner)` / `(:mlhs ...)` children
/// of one `mlhs` node into distinct prism node types — this enum re-unifies
/// them for the port.
enum TuvSlot<'pr> {
    /// A plain local-variable target, or a splat wrapping one — carries the
    /// var name so the caller can check the underscore-prefix rule. Upstream
    /// derives this via a double `*variable` destructure (`var, = *variable`
    /// then `var, = *var`); a bare `*` (no inner expression) or a splat
    /// wrapping any non-local-variable target (ivar/cvar/gvar/const/attr/
    /// index) ends up with a `nil` or non-identifier symbol either way, which
    /// never satisfies `to_s.start_with?('_')` — represented here as `None`,
    /// which always fails `tuv_qualifies`.
    Candidate(Option<&'pr [u8]>),
    /// A nested `(...)` destructuring group (whitequark `:mlhs`) — never
    /// itself a DISALLOW-type candidate, so it stops the backward scan the
    /// same way a non-underscore name does. Walked separately (via
    /// `as_multi_target_node` directly) by `tuv_unneeded_ranges`'s
    /// `children_offenses` pass — this variant only needs to mark the stop.
    Nested,
    /// Any other assignment-target kind (ivar/cvar/gvar/const/attr/index) —
    /// not in `DISALLOW`, so it stops the scan without being a candidate.
    Other,
}

fn tuv_classify<'pr>(n: &ruby_prism::Node<'pr>) -> TuvSlot<'pr> {
    if let Some(lv) = n.as_local_variable_target_node() {
        return TuvSlot::Candidate(Some(lv.name().as_slice()));
    }
    if n.as_multi_target_node().is_some() {
        return TuvSlot::Nested;
    }
    if let Some(sp) = n.as_splat_node() {
        let name = sp
            .expression()
            .and_then(|e| e.as_local_variable_target_node())
            .map(|lv| lv.name().as_slice());
        return TuvSlot::Candidate(name);
    }
    TuvSlot::Other
}

/// `(allow_named_underscore_variables && var != :_) || !var.to_s.start_with?('_')`,
/// inverted to "does this name qualify as a trailing-underscore candidate".
fn tuv_qualifies(name: Option<&[u8]>, allow_named: bool) -> bool {
    match name {
        None => false,
        Some(n) if allow_named => n == b"_",
        Some(n) => n.starts_with(b"_"),
    }
}

/// Concatenates a masgn/mlhs target list in source order — prism splits what
/// whitequark gives as one flat `mlhs.children` array into `lefts` (before
/// any splat), an optional `rest` (the splat itself, if any), and `rights`
/// (after the splat).
fn tuv_collect_slots<'pr>(
    lefts: ruby_prism::NodeList<'pr>,
    rest: Option<ruby_prism::Node<'pr>>,
    rights: ruby_prism::NodeList<'pr>,
) -> Vec<ruby_prism::Node<'pr>> {
    let mut v: Vec<ruby_prism::Node<'pr>> = lefts.iter().collect();
    if let Some(r) = rest {
        v.push(r);
    }
    v.extend(rights.iter());
    v
}

/// Ported from `find_first_offense`/`find_first_possible_offense`: scans
/// `slots` from the end backward, extending the run for as long as each
/// slot is a DISALLOW-type candidate satisfying the underscore rule, and
/// stopping (keeping the previously accumulated index) at the first slot
/// that doesn't. Returns the run's leftmost index — or `None` if the very
/// last slot fails, or if `splat_variable_before?` cancels the run (a
/// `SplatNode` — qualifying or not — anywhere strictly before that index,
/// e.g. `_, *rest, _` or `a, *b, _`).
fn tuv_find_first_offense(slots: &[ruby_prism::Node], allow_named: bool) -> Option<usize> {
    let mut best: Option<usize> = None;
    for i in (0..slots.len()).rev() {
        match tuv_classify(&slots[i]) {
            TuvSlot::Candidate(name) if tuv_qualifies(name, allow_named) => best = Some(i),
            _ => break,
        }
    }
    let idx = best?;
    if slots[..idx].iter().any(|s| s.as_splat_node().is_some()) {
        return None;
    }
    Some(idx)
}

/// Which flavor of container `slots` belongs to — the top-level masgn
/// (`node.masgn_type?` true upstream) or a nested `(...)` group
/// (`node.masgn_type?` false, `node` == the mlhs node itself). Only the top
/// level carries an `=` operator and an RHS to fall back on.
enum TuvCtx {
    Top { operator_start: usize, rhs_start: usize },
    Nested,
}

/// Ported from `main_node_offense`: the offense range for the trailing run
/// found (if any) directly among `slots` — NOT including any nested groups'
/// own offenses, which `tuv_unneeded_ranges` collects separately.
fn tuv_main_offense(
    slots: &[ruby_prism::Node],
    rparen_end: Option<usize>,
    mlhs_start: usize,
    ctx: &TuvCtx,
    allow_named: bool,
) -> Option<(usize, usize)> {
    let idx = tuv_find_first_offense(slots, allow_named)?;
    let offense_start = slots[idx].location().start_offset();

    // `unused_variables_only?`: the run reaches all the way back to the
    // first slot, i.e. EVERY target at this level is a trailing underscore.
    if idx == 0 {
        return Some(match ctx {
            TuvCtx::Top { rhs_start, .. } => (mlhs_start, *rhs_start),
            TuvCtx::Nested => {
                let end = rparen_end.unwrap_or_else(|| slots[slots.len() - 1].location().end_offset());
                (mlhs_start, end)
            }
        });
    }

    // `range_for_parentheses`: a parenthesized group/LHS deletes from just
    // before the run's start through just before the closing paren — this
    // reaches past the run's own end to swallow any further trailing
    // targets and their commas (e.g. `(a, _, _,)` -> `(a,)` in one range).
    if let Some(rp_end) = rparen_end {
        return Some((offense_start - 1, rp_end - 1));
    }

    // Unparenthesized: only reachable at the top level (a nested group is
    // always written with literal parens in valid Ruby). Deletes from the
    // run's start through the `=` operator.
    match ctx {
        TuvCtx::Top { operator_start, .. } => Some((offense_start, *operator_start)),
        TuvCtx::Nested => {
            Some((offense_start, slots[slots.len() - 1].location().end_offset()))
        }
    }
}

/// Ported from `unneeded_ranges`: this level's own trailing-run offense (if
/// any), plus every nested group's own offenses (`children_offenses`,
/// recursed depth-first in source order).
fn tuv_unneeded_ranges(
    slots: &[ruby_prism::Node],
    rparen_end: Option<usize>,
    mlhs_start: usize,
    ctx: &TuvCtx,
    allow_named: bool,
    out: &mut Vec<(usize, usize)>,
) {
    for s in slots {
        if let Some(mt) = s.as_multi_target_node() {
            tuv_unneeded_ranges_group(&mt, allow_named, out);
        }
    }
    if let Some(main) = tuv_main_offense(slots, rparen_end, mlhs_start, ctx, allow_named) {
        out.push(main);
    }
}

fn tuv_unneeded_ranges_group(mt: &ruby_prism::MultiTargetNode, allow_named: bool, out: &mut Vec<(usize, usize)>) {
    let slots = tuv_collect_slots(mt.lefts(), mt.rest(), mt.rights());
    if slots.is_empty() {
        return;
    }
    // A nested destructuring group is always written with literal parens in
    // valid Ruby, but fall back to the slot span defensively.
    let lparen_start = mt.lparen_loc().map(|l| l.start_offset());
    let rparen_end = mt.rparen_loc().map(|l| l.end_offset());
    let mlhs_start = lparen_start.unwrap_or_else(|| slots[0].location().start_offset());
    tuv_unneeded_ranges(&slots, rparen_end, mlhs_start, &TuvCtx::Nested, allow_named, out);
}

impl<'a> super::Cops<'a> {
    /// Style/TrailingUnderscoreVariable (`on_masgn`): flags trailing `_`
    /// (or `_foo`-named, when `AllowNamedUnderscoreVariables: false`)
    /// targets in a multiple assignment, recursing into any nested `(...)`
    /// destructuring groups. See `tuv_main_offense`/`tuv_unneeded_ranges`
    /// for the range math ported from `main_node_offense`/`unneeded_ranges`.
    pub(crate) fn check_trailing_underscore_variable(&mut self, node: &ruby_prism::MultiWriteNode) {
        const COP: &str = "Style/TrailingUnderscoreVariable";
        if !self.on(COP) {
            return;
        }
        let allow_named = self.cfg.get(COP, "AllowNamedUnderscoreVariables") != Some("false");

        let slots = tuv_collect_slots(node.lefts(), node.rest(), node.rights());
        if slots.is_empty() {
            return;
        }
        let lparen_start = node.lparen_loc().map(|l| l.start_offset());
        let rparen_end = node.rparen_loc().map(|l| l.end_offset());
        let mlhs_start = lparen_start.unwrap_or_else(|| slots[0].location().start_offset());
        let ctx = TuvCtx::Top {
            operator_start: node.operator_loc().start_offset(),
            rhs_start: node.value().location().start_offset(),
        };

        let mut ranges = Vec::new();
        tuv_unneeded_ranges(&slots, rparen_end, mlhs_start, &ctx, allow_named, &mut ranges);
        if ranges.is_empty() {
            return;
        }

        // `good_code`: the message interpolates the WHOLE masgn's source
        // text with just this range excised — computed against the top
        // node's own source even for a nested group's offense, exactly as
        // upstream's `on_masgn` does for every range in the flattened list.
        let top_start = node.location().start_offset();
        let top_src = self.node_src(&node.as_node()).to_vec();

        for (start, end) in ranges {
            let offset = start - top_start;
            let size = end - start;
            let mut good_code = top_src.clone();
            good_code.drain(offset..offset + size);
            let good_code = String::from_utf8_lossy(&good_code);
            let msg = format!("Do not use trailing `_`s in parallel assignment. Prefer `{good_code}`.");
            self.push(start, COP, true, msg);
            self.fixes.push((start, end, Vec::new()));
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Style/EmptyCaseCondition: a `case` with no subject expression (`case`
    /// with no predicate — the "empty case" idiom, `case; when a; ...; end`)
    /// should be an `if`/`elsif` chain instead. Ports upstream's `on_case`
    /// guard-for-guard:
    ///
    /// - `case_node.condition` (prism: `predicate()`) must be absent.
    /// - `NOT_SUPPORTED_PARENT_TYPES` (`%i[return break next send csend]`,
    ///   i.e. `case_node.parent&.type`): the case must not be the value of an
    ///   enclosing `return`/`break`/`next`, nor the receiver/argument of a
    ///   method call. `self.ecc_no_offense` stands in for this — it's
    ///   populated eagerly (before the nested `case` node is itself
    ///   visited) by `visit_return_node`/`visit_break_node`/`visit_next_node`
    ///   and by `visit_call_node` in mod.rs, via `ecc_mark_not_supported_parent`
    ///   / `ecc_mark_not_supported_parent_call` below. Verified live against
    ///   real `rubocop` (`RuboCop::ProcessedSource`, `parser_engine:
    ///   parser_prism`) that `case_node.parent.type` is `:return` for
    ///   `return case...end` even though prism's own AST nests a transparent
    ///   `ArgumentsNode` in between — RuboCop's AST wrapping skips it, so a
    ///   direct "is this case the return/break/next's sole argument" check
    ///   (past that wrapper) matches upstream exactly. `break`/`next` before
    ///   an empty case are exercised by the fixture but tagged
    ///   `unsupported_on: :prism` (excluded from oracle scoring) — ported
    ///   anyway since live probing shows Prism's parent type still comes out
    ///   `:break`/`:next` (the tag is presumably about something else, e.g.
    ///   argument-parsing differences pre-Ruby-3.2, not this guard).
    /// - No `when`/`else` branch body may itself be a `return`, nor contain
    ///   one anywhere in its descendant tree (`ecc_contains_return`) —
    ///   upstream's `body.return_type? || body.each_descendant.any?
    ///   (&:return_type?)`. Verified live that this is a bare structural
    ///   check (traverses into nested `def`s/blocks unconditionally, no
    ///   scope-awareness) — a `return` inside a `def` nested in a `when`
    ///   branch still suppresses the offense.
    ///
    /// Autocorrect (`autocorrect` -> `correct_case_when` +
    /// `correct_when_conditions`) ports verbatim; see the per-step comments
    /// below.
    pub(crate) fn check_empty_case_condition(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Style/EmptyCaseCondition";
        if !self.on(COP) {
            return;
        }
        if node.predicate().is_some() {
            return;
        }
        let case_start = node.location().start_offset();
        if self.ecc_no_offense.contains(&case_start) {
            return;
        }

        let when_branches: Vec<ruby_prism::WhenNode> =
            node.conditions().iter().filter_map(|c| c.as_when_node()).collect();

        let mut branch_bodies: Vec<ruby_prism::StatementsNode> =
            when_branches.iter().filter_map(ruby_prism::WhenNode::statements).collect();
        if let Some(s) = node.else_clause().and_then(|e| e.statements()) {
            branch_bodies.push(s);
        }
        if branch_bodies.iter().any(|b| ecc_contains_return(&b.as_node())) {
            return;
        }

        let kw = node.case_keyword_loc();
        self.push(
            kw.start_offset(),
            COP,
            true,
            "Do not use empty `case` condition, instead use an `if` expression.",
        );

        // Autocorrect. A `case` with zero `when` branches can't legally
        // exist here (a bare `case`/`end` with no `when` is degenerate,
        // unexercised by the fixture, and upstream's own `when_nodes.first`
        // would itself blow up on it) — guard rather than panic.
        let Some(first_when) = when_branches.first() else { return };
        // `when_node.parent.parent` (== `case_node.parent`): whether this
        // `case` has ANY enclosing node at all, vs. being the sole top-level
        // statement in the whole file (`top_level_sole_stmt`, shared with
        // Lint/EmptyConditionalBody — see its definition).
        let case_has_parent = self.top_level_sole_stmt != Some(case_start);

        // `correct_case_when`: the `case`..first-`when`-KEYWORD span
        // collapses to the literal text `if` (swallowing everything between,
        // blank lines/comments included — `keep_first_when_comment` below
        // re-inserts any comments from that span ahead of it).
        let first_kw = first_when.keyword_loc();
        self.fixes.push((kw.start_offset(), first_kw.end_offset(), b"if".to_vec()));
        self.ecc_keep_first_when_comment(kw.start_offset(), first_kw.start_offset());
        for w in when_branches.iter().skip(1) {
            let wk = w.keyword_loc();
            self.fixes.push((wk.start_offset(), wk.end_offset(), b"elsif".to_vec()));
        }

        // `correct_when_conditions`.
        for w in &when_branches {
            let conditions: Vec<ruby_prism::Node> = w.conditions().iter().collect();
            // `replace_then_with_line_break`: swallow from the end of the
            // last condition through the end of the `then` keyword,
            // replacing with a newline — but only when the enclosing `case`
            // has some parent (see `case_has_parent` above); when the whole
            // file IS just this `case` expression, upstream's guard leaves
            // any `then` untouched (verified against the fixture's "with
            // when branches using then" example, whose corrected source
            // keeps every `then` literally).
            if case_has_parent {
                if let (Some(then_kw), Some(last_cond)) = (w.then_keyword_loc(), conditions.last()) {
                    self.fixes.push((last_cond.location().end_offset(), then_kw.end_offset(), b"\n".to_vec()));
                }
            }
            // Comma-delimited alternatives (`when a, b, c`) join with ` || `.
            if conditions.len() > 1 {
                let start = conditions.first().expect("len > 1").location().start_offset();
                let end = conditions.last().expect("len > 1").location().end_offset();
                let mut joined = Vec::new();
                for (i, c) in conditions.iter().enumerate() {
                    if i > 0 {
                        joined.extend_from_slice(b" || ");
                    }
                    joined.extend_from_slice(self.node_src(c));
                }
                self.fixes.push((start, end, joined));
            }
        }
    }

    /// Marks a `case`-with-no-predicate that is the sole argument of a
    /// `return`/`break`/`next` (past prism's transparent `ArgumentsNode`
    /// wrapper) so `check_empty_case_condition` skips it — see that method's
    /// doc comment. Called from `visit_return_node`/`visit_break_node`/
    /// `visit_next_node` in mod.rs, BEFORE they recurse into their argument
    /// (so the mark is already in place by the time `visit_case_node` fires
    /// on it).
    pub(crate) fn ecc_mark_not_supported_parent(&mut self, args: Option<ruby_prism::ArgumentsNode>) {
        if !self.on("Style/EmptyCaseCondition") {
            return;
        }
        let Some(a) = args else { return };
        for arg in a.arguments().iter() {
            if arg.as_case_node().is_some() {
                self.ecc_no_offense.insert(arg.location().start_offset());
            }
        }
    }

    /// Same marking for a `case` used as the RECEIVER or an ARGUMENT of a
    /// method call — `send`/`csend` in `NOT_SUPPORTED_PARENT_TYPES`. Prism
    /// represents both as `CallNode` (safe-navigation is just a flag), and
    /// upstream doesn't distinguish them for this guard either, so both
    /// receiver and argument positions mark unconditionally regardless of
    /// `is_safe_navigation`. Called from `visit_call_node` in mod.rs before
    /// it recurses into the receiver/arguments.
    pub(crate) fn ecc_mark_not_supported_parent_call(&mut self, node: &ruby_prism::CallNode) {
        if !self.on("Style/EmptyCaseCondition") {
            return;
        }
        if let Some(r) = node.receiver() {
            if r.as_case_node().is_some() {
                self.ecc_no_offense.insert(r.location().start_offset());
            }
        }
        if let Some(a) = node.arguments() {
            for arg in a.arguments().iter() {
                if arg.as_case_node().is_some() {
                    self.ecc_no_offense.insert(arg.location().start_offset());
                }
            }
        }
    }

    /// `keep_first_when_comment`: every comment on a line from the `case`
    /// keyword's own line (inclusive — this is how an inline `case #
    /// comment` gets hoisted onto its own line) through the line BEFORE the
    /// first `when` keyword's line (exclusive), reindented to the `case`
    /// keyword's column, inserted as whole lines immediately ahead of the
    /// `case`-keyword's line (i.e. ahead of where `if` ends up).
    fn ecc_keep_first_when_comment(&mut self, case_kw_start: usize, first_when_kw_start: usize) {
        let (case_line, case_col) = self.idx.loc(case_kw_start);
        let (when_line, _) = self.idx.loc(first_when_kw_start);
        let indent = vec![b' '; case_col - 1];
        let mut block = Vec::new();
        for &(line, start, end) in self.comments {
            if line >= case_line && line < when_line {
                block.extend_from_slice(&indent);
                block.extend_from_slice(&self.src[start..end]);
                block.push(b'\n');
            }
        }
        if block.is_empty() {
            return;
        }
        let line_start = self.idx.starts[case_line - 1];
        self.fixes.push((line_start, line_start, block));
    }
}

/// `body.return_type? || body.each_descendant.any?(&:return_type?)`: does
/// `node` itself, or anything beneath it — unconditionally, nested
/// `def`s/blocks included (verified live) — contain a `return`?
fn ecc_contains_return(node: &ruby_prism::Node) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder {
        fn visit_return_node(&mut self, node: &ruby_prism::ReturnNode<'pr>) {
            self.found = true;
            ruby_prism::visit_return_node(self, node);
        }
    }
    let mut f = Finder { found: false };
    f.visit(node);
    f.found
}


impl<'a> super::Cops<'a> {
    /// Style/OneLineConditional — single-line `if/then/else/end` and
    /// `unless/then/else/end` (NOT ternaries, NOT modifier forms, NOT
    /// `elsif` segments — `OnNormalIfUnless#on_if` guards those away before
    /// `on_normal_if_unless` ever runs). Corrects to a ternary (default) or
    /// to a genuine multi-line construct, per `AlwaysCorrectToMultiline` /
    /// `cannot_replace_to_ternary?`.
    ///
    /// Ternary is `condition, if_branch, else_branch = *node` in upstream —
    /// a RAW splat, not the `if_branch`/`else_branch` ACCESSOR methods. For
    /// `if`, raw children are already (cond, then-part, else-part); for
    /// `unless`, whitequark's builder stores raw children swapped by actual
    /// boolean truth (true-branch first), so the raw splat there yields
    /// (cond, else-part, then-part) — i.e. the ternary's true/false slots
    /// are SWAPPED relative to source order. `IfThenCorrector`'s multi-line
    /// correction instead uses the `if_branch`/`else_branch` ACCESSORS
    /// (which normalize back to source order for BOTH keywords), so no swap
    /// there — see the two builders below.
    pub(crate) fn check_one_line_conditional_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/OneLineConditional";
        if !self.on(COP) {
            return;
        }
        // `on_if`: ternary (`if_keyword_loc` absent) or modifier form
        // (`end_keyword_loc` absent) never reach `on_normal_if_unless`.
        let Some(kw) = node.if_keyword_loc() else { return };
        if node.end_keyword_loc().is_none() {
            return;
        }
        // `node.elsif?`: an elsif segment is visited independently (via the
        // outer if's `subsequent()` chain) but must not re-report — only
        // the chain's true head (`if_keyword_loc == "if"`) does.
        if kw.as_slice() != b"if" {
            return;
        }

        let loc = node.location();
        if !self.olc_single_line(&loc) {
            return;
        }

        let else_target = olc_else_target(node.subsequent());
        if !olc_else_present(&else_target) {
            return;
        }
        // `node.if_branch&.begin_type?`: >= 2 statements in the `then` body
        // disqualifies the offense entirely (not just forces multiline).
        if node.statements().is_some_and(|s| s.body().len() >= 2) {
            return;
        }

        let force_multiline = olc_cannot_replace_to_ternary(&else_target);
        let always_multiline = self.cfg.get(COP, "AlwaysCorrectToMultiline") == Some("true");
        let multiline = always_multiline || force_multiline;
        let msg = olc_message(b"if", multiline);

        let nested = self.olc_nested(loc.start_offset());
        self.push(loc.start_offset(), COP, !nested, msg);
        if nested {
            return;
        }
        self.one_line_cond_spans.push((loc.start_offset(), loc.end_offset()));

        let replacement = if multiline {
            let (indentation, body_indent) = self.olc_indents(loc.start_offset());
            olc_multiline_if(self, node, b"if", false, &indentation, &body_indent)
        } else {
            let cond_part = self.olc_wrap(&node.predicate());
            let then_stmt = node.statements().and_then(|s| s.body().first());
            let if_part = self.olc_wrap_opt(then_stmt);
            let else_part = match &else_target {
                OlcElse::Plain(e) => self.olc_wrap_opt(e.statements().and_then(|s| s.body().first())),
                OlcElse::Elsif(elsif) => self.olc_wrap(&elsif.as_node()),
                OlcElse::None => unreachable!("checked by olc_else_present above"),
            };
            let mut out = cond_part;
            out.extend_from_slice(b" ? ");
            out.extend_from_slice(&if_part);
            out.extend_from_slice(b" : ");
            out.extend_from_slice(&else_part);
            out
        };
        self.fixes.push((loc.start_offset(), loc.end_offset(), replacement));
    }

    /// Style/OneLineConditional for `unless ... else ... end` — prism's
    /// `UnlessNode` never chains into `elsif` (Ruby has no such syntax), so
    /// this is the single-level case; see `check_one_line_conditional_if`
    /// for the shared semantics and the `unless`-swap note.
    pub(crate) fn check_one_line_conditional_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/OneLineConditional";
        if !self.on(COP) {
            return;
        }
        if node.end_keyword_loc().is_none() {
            return; // modifier form
        }

        let loc = node.location();
        if !self.olc_single_line(&loc) {
            return;
        }

        let Some(else_node) = node.else_clause() else { return };
        if else_node.statements().is_none() {
            return;
        }
        if node.statements().is_some_and(|s| s.body().len() >= 2) {
            return;
        }

        let force_multiline = else_node.statements().is_some_and(|s| s.body().len() >= 2);
        let always_multiline = self.cfg.get(COP, "AlwaysCorrectToMultiline") == Some("true");
        let multiline = always_multiline || force_multiline;
        let msg = olc_message(b"unless", multiline);

        let nested = self.olc_nested(loc.start_offset());
        self.push(loc.start_offset(), COP, !nested, msg);
        if nested {
            return;
        }
        self.one_line_cond_spans.push((loc.start_offset(), loc.end_offset()));

        let replacement = if multiline {
            let (indentation, body_indent) = self.olc_indents(loc.start_offset());
            olc_multiline_unless(self, node, &indentation, &body_indent)
        } else {
            // Raw-splat order for `unless` swaps the ternary's true/false
            // slots relative to source order (see doc comment above).
            let cond_part = self.olc_wrap(&node.predicate());
            let then_stmt = node.statements().and_then(|s| s.body().first());
            let if_part = self.olc_wrap_opt(then_stmt);
            let else_part = self.olc_wrap_opt(else_node.statements().and_then(|s| s.body().first()));
            let mut out = cond_part;
            out.extend_from_slice(b" ? ");
            out.extend_from_slice(&else_part);
            out.extend_from_slice(b" : ");
            out.extend_from_slice(&if_part);
            out
        };
        self.fixes.push((loc.start_offset(), loc.end_offset(), replacement));
    }

    fn olc_single_line(&self, loc: &ruby_prism::Location) -> bool {
        let (start_line, _) = self.idx.loc(loc.start_offset());
        let (end_line, _) = self.idx.loc(loc.end_offset());
        start_line == end_line
    }

    /// `ignore_node`/`part_of_ignored_node?`: a one-line conditional fully
    /// nested inside an already-corrected outer one only gets an offense.
    fn olc_nested(&self, start_offset: usize) -> bool {
        self.one_line_cond_spans.iter().any(|(s, e)| start_offset >= *s && start_offset < *e)
    }

    /// `Alignment#configured_indentation_width` for this cop (schema has no
    /// `IndentationWidth` param of its own — only meaningful when a user
    /// sets it directly), then the base column of the node being corrected.
    fn olc_indents(&self, start_offset: usize) -> (String, String) {
        const COP: &str = "Style/OneLineConditional";
        let width = self
            .cfg
            .param(COP, "IndentationWidth")
            .and_then(|v| v.parse().ok())
            .or_else(|| self.cfg.get("Layout/IndentationWidth", "Width").and_then(|v| v.parse().ok()))
            .unwrap_or(2);
        let (_, col) = self.idx.loc(start_offset);
        (" ".repeat(col - 1), " ".repeat(width))
    }

    /// `expr_replacement(nil) => 'nil'`, else `requires_parentheses? ? "(#{src})" : src`.
    fn olc_wrap_opt(&self, node: Option<ruby_prism::Node>) -> Vec<u8> {
        match node {
            None => b"nil".to_vec(),
            Some(n) => self.olc_wrap(&n),
        }
    }

    fn olc_wrap(&self, node: &ruby_prism::Node) -> Vec<u8> {
        let src = self.node_src(node);
        if olc_requires_parentheses(node) {
            let mut v = Vec::with_capacity(src.len() + 2);
            v.push(b'(');
            v.extend_from_slice(src);
            v.push(b')');
            v
        } else {
            src.to_vec()
        }
    }
}

/// Normalized (textual) else-branch shape, independent of `if`/`unless`.
enum OlcElse<'pr> {
    None,
    Elsif(ruby_prism::IfNode<'pr>),
    Plain(ruby_prism::ElseNode<'pr>),
}

fn olc_else_target(subsequent: Option<ruby_prism::Node>) -> OlcElse {
    match subsequent {
        None => OlcElse::None,
        Some(sub) => match sub.as_if_node() {
            Some(elsif) => OlcElse::Elsif(elsif),
            None => OlcElse::Plain(sub.as_else_node().expect("if subsequent is else or elsif")),
        },
    }
}

/// `return unless node.else_branch`: nil only when there's no `else`
/// keyword at all, OR the `else` body is empty (`if x then y else end`).
/// An `elsif` continuation always counts as present.
fn olc_else_present(target: &OlcElse) -> bool {
    match target {
        OlcElse::None => false,
        OlcElse::Elsif(_) => true,
        OlcElse::Plain(e) => e.statements().is_some(),
    }
}

/// `cannot_replace_to_ternary?`: an `elsif` continuation always forces
/// multi-line; otherwise, >= 2 statements in the `else` body do.
fn olc_cannot_replace_to_ternary(target: &OlcElse) -> bool {
    match target {
        OlcElse::None => unreachable!("checked by olc_else_present before this is called"),
        OlcElse::Elsif(_) => true,
        OlcElse::Plain(e) => e.statements().is_some_and(|s| s.body().len() >= 2),
    }
}

/// `MSG_TERNARY`/`MSG_MULTILINE`, byte-for-byte.
fn olc_message(keyword: &[u8], multiline: bool) -> String {
    let kw = String::from_utf8_lossy(keyword);
    if multiline {
        format!("Favor multi-line `{kw}` over single-line `{kw}/then/else/end` constructs.")
    } else {
        format!("Favor the ternary operator (`?:`) over single-line `{kw}/then/else/end` constructs.")
    }
}

/// `IfThenCorrector#replacement`, recursing down an `elsif` chain. Uses the
/// `if_branch`/`else_branch` ACCESSOR semantics (source order, no `unless`
/// swap) — `node.keyword`/`root_keyword` carries the literal keyword text.
fn olc_multiline_if(
    cops: &super::Cops,
    node: &ruby_prism::IfNode,
    root_keyword: &[u8],
    is_elsif: bool,
    indentation: &str,
    body_indent: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    if is_elsif {
        out.extend_from_slice(indentation.as_bytes());
    }
    out.extend_from_slice(root_keyword);
    out.push(b' ');
    out.extend_from_slice(cops.node_src(&node.predicate()));
    out.push(b'\n');
    out.extend_from_slice(indentation.as_bytes());
    out.extend_from_slice(body_indent.as_bytes());
    let then_src = node.statements().map(|s| cops.node_src(&s.as_node()));
    out.extend_from_slice(then_src.unwrap_or(b"nil"));
    out.push(b'\n');
    match node.subsequent() {
        None => {
            out.extend_from_slice(indentation.as_bytes());
            out.extend_from_slice(b"end");
        }
        Some(sub) => {
            if let Some(elsif) = sub.as_if_node() {
                out.extend_from_slice(&olc_multiline_if(cops, &elsif, b"elsif", true, indentation, body_indent));
            } else if let Some(else_node) = sub.as_else_node() {
                out.extend_from_slice(indentation.as_bytes());
                out.extend_from_slice(b"else\n");
                out.extend_from_slice(indentation.as_bytes());
                out.extend_from_slice(body_indent.as_bytes());
                let else_src = else_node.statements().map(|s| cops.node_src(&s.as_node())).unwrap_or(b"");
                out.extend_from_slice(else_src);
                out.push(b'\n');
                out.extend_from_slice(indentation.as_bytes());
                out.extend_from_slice(b"end");
            }
        }
    }
    out
}

/// `IfThenCorrector#replacement` for `unless` — never chains.
fn olc_multiline_unless(
    cops: &super::Cops,
    node: &ruby_prism::UnlessNode,
    indentation: &str,
    body_indent: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"unless ");
    out.extend_from_slice(cops.node_src(&node.predicate()));
    out.push(b'\n');
    out.extend_from_slice(indentation.as_bytes());
    out.extend_from_slice(body_indent.as_bytes());
    let then_src = node.statements().map(|s| cops.node_src(&s.as_node()));
    out.extend_from_slice(then_src.unwrap_or(b"nil"));
    out.push(b'\n');
    out.extend_from_slice(indentation.as_bytes());
    match node.else_clause() {
        None => out.extend_from_slice(b"end"),
        Some(else_node) => {
            out.extend_from_slice(b"else\n");
            out.extend_from_slice(indentation.as_bytes());
            out.extend_from_slice(body_indent.as_bytes());
            let else_src = else_node.statements().map(|s| cops.node_src(&s.as_node())).unwrap_or(b"");
            out.extend_from_slice(else_src);
            out.push(b'\n');
            out.extend_from_slice(indentation.as_bytes());
            out.extend_from_slice(b"end");
        }
    }
    out
}

/// `OneLineConditional#requires_parentheses?`.
fn olc_requires_parentheses(node: &ruby_prism::Node) -> bool {
    if node.as_and_node().is_some()
        || node.as_or_node().is_some()
        || node.as_if_node().is_some()
        || node.as_unless_node().is_some()
        || clamp_is_assignment_like(node)
    {
        return true;
    }
    if olc_method_call_with_changed_precedence(node) {
        return true;
    }
    olc_keyword_with_changed_precedence(node)
}

/// `method_call_with_changed_precedence?`: an unparenthesized non-operator
/// method call WITH arguments (`check 1`) needs parens; a parenthesized one
/// (`a(0)`), a bare one (`cond`), or an operator call (`0 + 0`) doesn't.
fn olc_method_call_with_changed_precedence(node: &ruby_prism::Node) -> bool {
    let Some(call) = node.as_call_node() else { return false };
    let Some(args) = call.arguments() else { return false };
    if args.arguments().is_empty() {
        return false;
    }
    if call.opening_loc().is_some() {
        return false;
    }
    !CLAMP_OPERATOR_METHODS.contains(&call.name().as_slice())
}

/// `keyword_with_changed_precedence?`: `next`/`break`/`return` need parens
/// only when carrying a value (their `parenthesized_call?` is always false
/// upstream — whitequark tracks no `begin` loc for these — so args alone
/// decide); `yield`/`super`/`defined?` only when unparenthesized; `self`
/// and other keyword nodes without an `arguments?` concept never do.
fn olc_keyword_with_changed_precedence(node: &ruby_prism::Node) -> bool {
    if let Some(n) = node.as_next_node() {
        return n.arguments().is_some();
    }
    if let Some(n) = node.as_break_node() {
        return n.arguments().is_some();
    }
    if let Some(n) = node.as_return_node() {
        return n.arguments().is_some();
    }
    if let Some(n) = node.as_yield_node() {
        return n.arguments().is_some() && n.lparen_loc().is_none();
    }
    if let Some(n) = node.as_super_node() {
        return n.arguments().is_some() && n.lparen_loc().is_none();
    }
    if let Some(n) = node.as_defined_node() {
        return n.lparen_loc().is_none();
    }
    // `prefix_not?`: the literal `not` keyword form of `!` (not `!x`).
    if let Some(call) = node.as_call_node() {
        if call.receiver().is_some()
            && call.name().as_slice() == b"!"
            && call.message_loc().is_some_and(|m| m.as_slice() == b"not")
        {
            return true;
        }
    }
    false
}


/// Style/IfWithSemicolon — `if cond; body end` (and the `unless` form) is
/// flagged and rewritten as a ternary, a multi-line `if`, or (when the body
/// can't be squeezed onto one clause) just has its `;` swapped for a
/// newline. Ported from `OnNormalIfUnless#on_if` + `IfWithSemicolon`.
///
/// Two whitequark-specific quirks drive most of the plumbing below:
///
/// * `node.parent&.if_type?` — whitequark never wraps a single statement in
///   a synthetic `:begin`, so an `elsif` (itself stored as a nested `:if` in
///   the `else` slot) OR a manually-nested `if`/`unless` that happens to be
///   the SOLE statement of an enclosing if/unless's then/else body has that
///   enclosing node as its literal AST parent. Prism has no parent pointers
///   at all, so `if_semicolon_suppressed` reconstructs this by having every
///   visited if/unless node mark its own such children BEFORE checking
///   whether it itself is marked — this must run unconditionally (not
///   gated on whether the current node's own offense fires), because the
///   real whitequark check is purely structural.
/// * `ignore_node`/`part_of_ignored_node?` — once a node is flagged, its
///   entire range is exempt from ITS descendants firing independently (e.g.
///   a nested `if cond; ...; end` inside a block argument passed to the
///   flagged node's body). `if_semicolon_spans` replicates this the same
///   way `Style/UnlessElse`'s `unless_else_spans` does: range containment
///   instead of true ancestor walking (equivalent for a well-formed tree).
impl<'a> super::Cops<'a> {
    pub(crate) fn check_if_with_semicolon(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/IfWithSemicolon";
        if !self.on(COP) {
            return;
        }
        let src = self.src;
        let self_start = node.location().start_offset();
        // Structural bookkeeping (see doc comment) — unconditional.
        self.if_semicolon_mark_sole_child(node.statements());
        if let Some(sub) = node.subsequent() {
            if let Some(elsif) = sub.as_if_node() {
                self.if_semicolon_suppressed.insert(elsif.location().start_offset());
            } else if let Some(else_node) = sub.as_else_node() {
                self.if_semicolon_mark_sole_child(else_node.statements());
            }
        }
        if self.if_semicolon_suppressed.contains(&self_start) {
            return;
        }
        if self.if_semicolon_spans.iter().any(|(s, e)| self_start >= *s && self_start < *e) {
            return;
        }
        // `on_if`'s `return if node.modifier_form? || node.ternary?`.
        if node.if_keyword_loc().is_none() || node.end_keyword_loc().is_none() {
            return;
        }
        if node.then_keyword_loc().is_some() {
            return; // uses literal `then`, not `;`
        }
        let Some(semi) = if_semicolon_scan(src, node.predicate().location().end_offset()) else {
            return;
        };
        // Flatten if/elsif/.../else branches, exactly like `IfNode#branches`.
        let mut shapes = vec![if_branch_shape(node.statements())];
        let mut cur = node.subsequent();
        loop {
            match cur {
                None => break,
                Some(n) => {
                    if let Some(elsif) = n.as_if_node() {
                        shapes.push(if_branch_shape(elsif.statements()));
                        cur = elsif.subsequent();
                    } else if let Some(else_node) = n.as_else_node() {
                        shapes.push(if_branch_shape(else_node.statements()));
                        break;
                    } else {
                        break;
                    }
                }
            }
        }
        let require_newline =
            shapes.iter().any(if_shape_is_begin_like) || shapes.iter().any(if_shape_is_return_with_arg);
        let masgn_or_block = shapes.iter().any(if_shape_is_masgn_or_block);
        let top_else_is_if = if_top_else_is_iflike(node.subsequent());
        let cond_src = nsrc(&node.predicate(), src);
        let node_end = node.location().end_offset();
        self.if_semicolon_report(COP, "if", self_start, node_end, cond_src, require_newline, masgn_or_block, top_else_is_if);
        if require_newline || masgn_or_block {
            self.fixes.push((semi, semi + 1, b"\n".to_vec()));
        } else if top_else_is_if {
            let text = build_if_semicolon_chain_text(&node.as_node(), src);
            self.fixes.push((self_start, node_end, text));
        } else {
            let then_shape = if_branch_shape(node.statements());
            let else_shape = if_semicolon_top_else_shape(node.subsequent());
            let text = build_if_semicolon_ternary(src, cond_src, &then_shape, &else_shape, false);
            self.fixes.push((self_start, node_end, text));
        }
    }

    pub(crate) fn check_if_with_semicolon_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/IfWithSemicolon";
        if !self.on(COP) {
            return;
        }
        let src = self.src;
        let self_start = node.location().start_offset();
        self.if_semicolon_mark_sole_child(node.statements());
        if let Some(else_node) = node.else_clause() {
            self.if_semicolon_mark_sole_child(else_node.statements());
        }
        if self.if_semicolon_suppressed.contains(&self_start) {
            return;
        }
        if self.if_semicolon_spans.iter().any(|(s, e)| self_start >= *s && self_start < *e) {
            return;
        }
        if node.end_keyword_loc().is_none() {
            return; // modifier form
        }
        if node.then_keyword_loc().is_some() {
            return;
        }
        let Some(semi) = if_semicolon_scan(src, node.predicate().location().end_offset()) else {
            return;
        };
        // `ruby_prism` node types don't implement `Clone`, so the (cheap,
        // pointer-dereferencing) `else_clause()` accessor is just called
        // again everywhere a fresh `Option<Node>` is needed, rather than
        // stashing and reusing one value.
        //
        // NOTE: this uses `if_branch_shape` directly (not
        // `if_semicolon_top_else_shape`, which collapses a genuine
        // multi-statement else to `None` — safe there ONLY because that
        // helper is only ever consulted once `require_newline?` is already
        // known false). `require_newline?`/`masgn_or_block?` need the real
        // `Multi` shape preserved so a multi-statement else is detected.
        let shapes = [
            if_branch_shape(node.statements()),
            node.else_clause().map_or(IfShape::None, |e| if_branch_shape(e.statements())),
        ];
        let require_newline =
            shapes.iter().any(if_shape_is_begin_like) || shapes.iter().any(if_shape_is_return_with_arg);
        let masgn_or_block = shapes.iter().any(if_shape_is_masgn_or_block);
        let top_else_is_if = if_top_else_is_iflike(node.else_clause().map(|e| e.as_node()));
        let cond_src = nsrc(&node.predicate(), src);
        let node_end = node.location().end_offset();
        self.if_semicolon_report(COP, "unless", self_start, node_end, cond_src, require_newline, masgn_or_block, top_else_is_if);
        if require_newline || masgn_or_block {
            self.fixes.push((semi, semi + 1, b"\n".to_vec()));
        } else if top_else_is_if {
            let text = build_if_semicolon_chain_text(&node.as_node(), src);
            self.fixes.push((self_start, node_end, text));
        } else {
            let then_shape = if_branch_shape(node.statements());
            let else_shape = if_semicolon_top_else_shape(node.else_clause().map(|e| e.as_node()));
            let text = build_if_semicolon_ternary(src, cond_src, &then_shape, &else_shape, true);
            self.fixes.push((self_start, node_end, text));
        }
    }

    /// Marks `stmts`' sole statement (if it's an `if`/`unless`) as
    /// suppressed — see the impl-level doc comment.
    fn if_semicolon_mark_sole_child(&mut self, stmts: Option<ruby_prism::StatementsNode>) {
        if let IfShape::Single(n) = if_branch_shape(stmts) {
            if n.as_if_node().is_some() || n.as_unless_node().is_some() {
                self.if_semicolon_suppressed.insert(n.location().start_offset());
            }
        }
    }

    /// Shared message + offense push for both entry points above.
    fn if_semicolon_report(
        &mut self,
        cop: &'static str,
        keyword: &str,
        start: usize,
        end: usize,
        cond_src: &[u8],
        require_newline: bool,
        masgn_or_block: bool,
        top_else_is_if: bool,
    ) {
        let cond_str = String::from_utf8_lossy(cond_src);
        let suffix = if require_newline {
            "use a newline instead."
        } else if top_else_is_if || masgn_or_block {
            "use `if/else` instead."
        } else {
            "use a ternary operator instead."
        };
        self.push(start, cop, true, format!("Do not use `{keyword} {cond_str};` - {suffix}"));
        self.if_semicolon_spans.push((start, end));
    }
}

/// The whitequark-normalized shape of an if/unless branch body: absent, a
/// single statement (rubocop-ast's `if_branch`/`else_branch` — this CAN
/// itself be an explicit `begin ... end` (prism's `BeginNode`, whitequark's
/// `:kwbegin` — distinct from the `:begin` fold below), but a lone
/// `kwbegin` statement is still just one node), or more than one statement
/// (whitequark folds those into a synthetic `:begin`, which prism instead
/// keeps as a flat `StatementsNode` — there's no single node to point at).
enum IfShape<'pr> {
    None,
    Single(ruby_prism::Node<'pr>),
    Multi,
}

fn if_branch_shape<'pr>(stmts: Option<ruby_prism::StatementsNode<'pr>>) -> IfShape<'pr> {
    match stmts {
        None => IfShape::None,
        Some(s) => {
            let body = s.body();
            match body.len() {
                0 => IfShape::None,
                1 => IfShape::Single(body.first().expect("len == 1")),
                _ => IfShape::Multi,
            }
        }
    }
}

/// `branch.begin_type?` — true ONLY for a real multi-statement fold.
/// Whitequark uses TWO distinct types here: an implicit multi-statement
/// sequence is `:begin`, but an explicit `begin ... end` keyword block is
/// `:kwbegin` (prism's `BeginNode`) — verified against real rubocop:
/// `if cond; begin; a; b; end end` autocorrects to a TERNARY
/// (`cond ? begin; a; b; end : nil`), not a newline-insert, because a
/// single `kwbegin` statement does NOT satisfy `begin_type?`.
fn if_shape_is_begin_like(shape: &IfShape) -> bool {
    matches!(shape, IfShape::Multi)
}

/// `branch.type?(:masgn, :any_block)`.
fn if_shape_is_masgn_or_block(shape: &IfShape) -> bool {
    match shape {
        IfShape::Single(n) => n.as_multi_write_node().is_some() || n.as_call_node().is_some_and(|c| c.block().is_some()),
        _ => false,
    }
}

/// `branch.return_type? && branch.arguments.any?`.
fn if_shape_is_return_with_arg(shape: &IfShape) -> bool {
    match shape {
        IfShape::Single(n) => n
            .as_return_node()
            .is_some_and(|r| r.arguments().is_some_and(|a| !a.arguments().is_empty())),
        _ => false,
    }
}

/// The resolved next branch of an if/unless chain, mirroring
/// `node.else_branch` — collapsed the same way whitequark collapses an
/// EMPTY trailing `else` clause to the same `nil` as no `else` at all (both
/// leave the AST child slot empty; only `else?`'s location bookkeeping,
/// which this cop's logic never consults, can tell them apart).
enum IfSemicolonNext<'pr> {
    None,
    /// `subsequent()` was itself an `elsif` (`IfNode`), OR the resolved
    /// `else` clause's sole statement happens to be a manually-nested
    /// `if`/`unless` — rubocop's `else_branch&.if_type?` doesn't care which.
    IfLike(ruby_prism::Node<'pr>),
    /// A genuine terminal `else` with (at most) one statement.
    PlainElse(Option<ruby_prism::Node<'pr>>),
}

fn if_semicolon_resolve_next<'pr>(subsequent: Option<ruby_prism::Node<'pr>>) -> IfSemicolonNext<'pr> {
    let Some(n) = subsequent else { return IfSemicolonNext::None };
    if n.as_if_node().is_some() || n.as_unless_node().is_some() {
        return IfSemicolonNext::IfLike(n);
    }
    if let Some(else_node) = n.as_else_node() {
        return match if_branch_shape(else_node.statements()) {
            IfShape::None => IfSemicolonNext::None,
            IfShape::Single(inner) => {
                if inner.as_if_node().is_some() || inner.as_unless_node().is_some() {
                    IfSemicolonNext::IfLike(inner)
                } else {
                    IfSemicolonNext::PlainElse(Some(inner))
                }
            }
            // Unreachable via the only caller (`replacement`'s path is only
            // taken once `require_newline?` is confirmed false for every
            // branch in the chain, which already rules out a multi-statement
            // else) — kept total rather than panicking on malformed input.
            IfShape::Multi => IfSemicolonNext::PlainElse(None),
        };
    }
    IfSemicolonNext::None
}

fn if_top_else_is_iflike(subsequent: Option<ruby_prism::Node>) -> bool {
    matches!(if_semicolon_resolve_next(subsequent), IfSemicolonNext::IfLike(_))
}

/// The OUTER (flagged) node's own else-branch shape, for the ternary-build
/// path only (`top_else_is_if` is already known false whenever this is
/// called, so the `IfLike` case below is unreachable in practice).
fn if_semicolon_top_else_shape<'pr>(subsequent: Option<ruby_prism::Node<'pr>>) -> IfShape<'pr> {
    match if_semicolon_resolve_next(subsequent) {
        IfSemicolonNext::None | IfSemicolonNext::PlainElse(None) => IfShape::None,
        IfSemicolonNext::PlainElse(Some(n)) => IfShape::Single(n),
        IfSemicolonNext::IfLike(_) => IfShape::None,
    }
}

fn if_like_condition<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    if let Some(ifn) = n.as_if_node() {
        Some(ifn.predicate())
    } else if let Some(un) = n.as_unless_node() {
        Some(un.predicate())
    } else {
        None
    }
}

fn if_like_statements<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::StatementsNode<'pr>> {
    if let Some(ifn) = n.as_if_node() {
        ifn.statements()
    } else if let Some(un) = n.as_unless_node() {
        un.statements()
    } else {
        None
    }
}

fn if_like_subsequent<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    if let Some(ifn) = n.as_if_node() {
        ifn.subsequent()
    } else if let Some(un) = n.as_unless_node() {
        un.else_clause().map(|e| e.as_node())
    } else {
        None
    }
}

/// `IfWithSemicolon#correct_elsif` — rebuilds `if COND\n  BODY\nELSE\nend`
/// from scratch. `node` is the originally-flagged if/unless node itself
/// (never `elsif` — those are always suppressed); the "if"/"end" keywords
/// are ALWAYS literal, even when `node` is an `unless` (verified against
/// real rubocop: `unless cond; run else if x; y end end` autocorrects to a
/// literal `if`, not `unless`, and does NOT negate/swap the branches —
/// upstream's `correct_elsif`/`build_else_branch` never check `.unless?`,
/// only `replacement`'s OWN ternary-building does, once, for `node` itself).
fn build_if_semicolon_chain_text(node: &ruby_prism::Node, src: &[u8]) -> Vec<u8> {
    let cond = if_like_condition(node).expect("caller only passes an if/unless node");
    let cond_src = nsrc(&cond, src);
    let if_branch_src = if_semicolon_single_src(if_like_statements(node), src);
    let mut out = Vec::new();
    out.extend_from_slice(b"if ");
    out.extend_from_slice(cond_src);
    out.push(b'\n');
    out.extend_from_slice(b"  ");
    out.extend_from_slice(if_branch_src.unwrap_or(b""));
    out.push(b'\n');
    let next = if_semicolon_resolve_next(if_like_subsequent(node));
    let mut else_part = build_if_semicolon_else_branch(next, src);
    if else_part.last() == Some(&b'\n') {
        else_part.pop();
    }
    out.extend_from_slice(&else_part);
    out.push(b'\n');
    out.extend_from_slice(b"end");
    out
}

/// `IfWithSemicolon#build_else_branch` — always ends in `\n` unless `next`
/// is `None` (mirrors the ruby method never being called in that case).
fn build_if_semicolon_else_branch(next: IfSemicolonNext, src: &[u8]) -> Vec<u8> {
    match next {
        IfSemicolonNext::None => Vec::new(),
        IfSemicolonNext::PlainElse(body) => {
            let mut out = Vec::new();
            out.extend_from_slice(b"else\n  ");
            if let Some(n) = body {
                out.extend_from_slice(nsrc(&n, src));
            }
            out.push(b'\n');
            out
        }
        IfSemicolonNext::IfLike(n) => {
            let cond = if_like_condition(&n).expect("IfLike always wraps an if/unless node");
            let cond_src = nsrc(&cond, src);
            let if_branch_src = if_semicolon_single_src(if_like_statements(&n), src);
            let mut out = Vec::new();
            out.extend_from_slice(b"elsif ");
            out.extend_from_slice(cond_src);
            out.push(b'\n');
            out.extend_from_slice(b"  ");
            out.extend_from_slice(if_branch_src.unwrap_or(b""));
            out.push(b'\n');
            let deeper = if_semicolon_resolve_next(if_like_subsequent(&n));
            if !matches!(deeper, IfSemicolonNext::None) {
                out.extend_from_slice(&build_if_semicolon_else_branch(deeper, src));
            }
            out
        }
    }
}

fn if_semicolon_single_src<'pr>(stmts: Option<ruby_prism::StatementsNode<'pr>>, src: &'pr [u8]) -> Option<&'pr [u8]> {
    match if_branch_shape(stmts) {
        IfShape::Single(n) => Some(nsrc(&n, src)),
        _ => None,
    }
}

/// `IfWithSemicolon#replacement`'s ternary path: `COND ? THEN : ELSE`,
/// swapping THEN/ELSE for `unless` (rubocop-ast's `if_branch`/`else_branch`
/// accessors already normalize to SOURCE POSITION regardless of if/unless —
/// see the real `node_parts` swap for `unless` — so `then_shape`/
/// `else_shape` here are always "syntactically first"/"syntactically
/// second", and `swap` is the ONLY place `unless` semantics enter).
fn build_if_semicolon_ternary(src: &[u8], cond_src: &[u8], then_shape: &IfShape, else_shape: &IfShape, swap: bool) -> Vec<u8> {
    let then_src = if_semicolon_build_expr(then_shape, src);
    let else_src = if_semicolon_build_expr(else_shape, src);
    let (a, b) = if swap { (else_src, then_src) } else { (then_src, else_src) };
    let mut out = Vec::new();
    out.extend_from_slice(cond_src);
    out.extend_from_slice(b" ? ");
    out.extend_from_slice(&a);
    out.extend_from_slice(b" : ");
    out.extend_from_slice(&b);
    out
}

/// `IfWithSemicolon#build_expression`.
fn if_semicolon_build_expr(shape: &IfShape, src: &[u8]) -> Vec<u8> {
    match shape {
        IfShape::None => b"nil".to_vec(),
        // Unreachable: the ternary path only runs once every branch in the
        // chain is confirmed non-begin-like (`require_newline?` false).
        IfShape::Multi => Vec::new(),
        IfShape::Single(n) => {
            if let Some(call) = n.as_call_node() {
                if if_semicolon_requires_parens(&call) {
                    let msg_end = call.message_loc().map(|m| m.end_offset()).unwrap_or_else(|| call.location().end_offset());
                    let method_src = &src[call.location().start_offset()..msg_end];
                    let args = call.arguments().expect("checked by if_semicolon_requires_parens");
                    let first = args.arguments().first().expect("checked non-empty by if_semicolon_requires_parens");
                    let args_src = &src[first.location().start_offset()..call.location().end_offset()];
                    let mut out = Vec::with_capacity(method_src.len() + args_src.len() + 2);
                    out.extend_from_slice(method_src);
                    out.push(b'(');
                    out.extend_from_slice(args_src);
                    out.push(b')');
                    return out;
                }
            }
            nsrc(n, src).to_vec()
        }
    }
}

/// `IfWithSemicolon#require_argument_parentheses?`.
fn if_semicolon_requires_parens(call: &ruby_prism::CallNode) -> bool {
    const ARITH: [&[u8]; 6] = [b"+", b"-", b"*", b"/", b"%", b"**"];
    let name = call.name();
    let name_bytes = name.as_slice();
    if ARITH.iter().any(|a| *a == name_bytes) {
        return false;
    }
    if call.closing_loc().is_some_and(|c| c.as_slice() == b")") {
        return false;
    }
    if !call.arguments().is_some_and(|a| !a.arguments().is_empty()) {
        return false;
    }
    name_bytes != b"[]" && name_bytes != b"[]="
}

fn if_semicolon_scan(src: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < src.len() {
        match src[i] {
            b' ' | b'\t' => i += 1,
            b';' => return Some(i),
            _ => return None,
        }
    }
    None
}

fn nsrc<'pr>(n: &ruby_prism::Node, src: &'pr [u8]) -> &'pr [u8] {
    let l = n.location();
    &src[l.start_offset()..l.end_offset()]
}


impl<'a> super::Cops<'a> {
    /// Style/MultilineTernaryOperator — a `?:` ternary whose predicate/branches
    /// span more than one physical line. Correction depends on where the
    /// ternary sits (`use_assignment_method?`/`enforce_single_line_ternary_operator?`
    /// upstream, tracked via `mto_single_line`/`mto_parent_start` — see the
    /// visitor call sites in mod.rs that populate them before descending into
    /// a ternary):
    ///   - the sole argument of `return`, or the receiver/argument of a
    ///     non-assignment method call (`do_something cond ?\n a : b`) — the
    ///     fix collapses it to a single-line ternary (`MSG_SINGLE_LINE`);
    ///   - anything else (plain statement, RHS of an assignment, nested
    ///     inside another conditional, attribute/index-writer call like
    ///     `a.foo = .../a[:k] = ...`) — the fix expands to `if`/`else`/`end`
    ///     (`MSG_IF`).
    /// Comments strictly between the ternary's own first line and the line
    /// its else-branch starts on (upstream's `comments_in_range`, exclusive
    /// of that last line) would otherwise be silently dropped by the
    /// wholesale replace, so they're hoisted verbatim to just before the
    /// immediate parent statement (`mto_parent_start`) — matching upstream's
    /// `corrector.insert_before(parent, comments_in_condition)`. With no
    /// tracked parent (a bare top-level ternary statement) upstream skips the
    /// hoist entirely and those comments are lost; we mirror that.
    ///
    /// A single AST pass (one `visit_if_node` walk) processes ternaries
    /// top-down: when an outer multiline ternary gets its fix queued, its
    /// range is remembered in `mto_fixed_ranges` so any nested ternary
    /// visited afterward (`part_of_ignored_node?` upstream) still gets an
    /// offense, but no fix — the outer's replacement text already carries its
    /// original, unconverted source, and a fresh follow-up pass (the
    /// `--fix`/`-a` autocorrect loop, run by the harness, not this function)
    /// re-discovers and converts it, one level of nesting per pass.
    pub(crate) fn check_multiline_ternary_operator(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/MultilineTernaryOperator";
        const MSG_IF: &str = "Avoid multi-line ternary operators, use `if` or `unless` instead.";
        const MSG_SINGLE_LINE: &str = "Avoid multi-line ternary operators, use single-line instead.";
        if !self.on(COP) {
            return;
        }
        // `node.ternary?` upstream: a `?:` ternary never has an `if`/`unless`
        // keyword (only modifier/statement `if` does).
        if node.if_keyword_loc().is_some() {
            return;
        }
        let node_loc = node.location();
        let start = node_loc.start_offset();
        let end = node_loc.end_offset();
        let (start_line, _) = self.idx.loc(start);
        let (end_line, _) = self.idx.loc(end.saturating_sub(1).max(start));
        // `node.multiline?` upstream: more than one physical source line.
        if start_line == end_line {
            return;
        }
        let Some(stmts) = node.statements() else { return };
        let Some(else_node) = node.subsequent().and_then(|s| s.as_else_node()) else { return };
        let Some(else_stmts) = else_node.statements() else { return };

        let cond_src = self.node_src(&node.predicate());
        let if_src = self.node_src(&stmts.as_node());
        let else_src = self.node_src(&else_stmts.as_node());
        let enforce_single_line = self.mto_single_line.contains(&start);

        let mut replacement = Vec::new();
        if enforce_single_line {
            replacement.extend_from_slice(cond_src);
            replacement.extend_from_slice(b" ? ");
            replacement.extend_from_slice(if_src);
            replacement.extend_from_slice(b" : ");
            replacement.extend_from_slice(else_src);
        } else {
            replacement.extend_from_slice(b"if ");
            replacement.extend_from_slice(cond_src);
            replacement.push(b'\n');
            replacement.extend_from_slice(b"  ");
            replacement.extend_from_slice(if_src);
            replacement.extend_from_slice(b"\nelse\n");
            replacement.extend_from_slice(b"  ");
            replacement.extend_from_slice(else_src);
            replacement.extend_from_slice(b"\nend");
        }
        // `node.source != replacement(node)` upstream — e.g. a ternary whose
        // only multiline part is a receiver/predicate line-break already
        // reads identically once collapsed to the single-line template
        // (`do_something(arg\n  .foo ? bar : baz)`), so there's nothing to fix.
        let node_src_full = self.node_src(&node.as_node());
        if node_src_full == replacement.as_slice() {
            return;
        }

        let message = if enforce_single_line { MSG_SINGLE_LINE } else { MSG_IF };
        self.push(start, COP, true, message.to_string());

        // `part_of_ignored_node?` upstream — an ancestor ternary already
        // consumed this range with its own (unconverted-inner-text) fix this
        // pass; leave this one for the next pass.
        if self.mto_fixed_ranges.iter().any(|&(s, e)| s <= start && end <= e) {
            return;
        }
        self.fixes.push((start, end, replacement));
        self.mto_fixed_ranges.push((start, end));

        // `comments_in_range`: comments on lines [start_line, else_line) —
        // `find_end_line`'s `node.ternary?` branch uses the else-branch's
        // OWN start line as the exclusive upper bound, so a comment trailing
        // the else-branch value itself (same line) is left untouched (it's
        // outside the replaced byte range anyway).
        let (else_line, _) = self.idx.loc(else_stmts.location().start_offset());
        let mut hoist: Vec<u8> = Vec::new();
        for &(cline, cstart, cend) in self.comments {
            if cline >= start_line && cline < else_line {
                hoist.extend_from_slice(&self.src[cstart..cend]);
                hoist.push(b'\n');
            }
        }
        if !hoist.is_empty() {
            if let Some(&parent_start) = self.mto_parent_start.get(&start) {
                self.fixes.push((parent_start, parent_start, hoist));
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/CommentedKeyword — flags a trailing `#` comment sharing a
    /// physical line with `begin`/`class`/`def`/`end`/`module`. Ported
    /// verbatim from rubocop's `on_new_investigation`, which scans
    /// `processed_source.comments` directly (no AST node involved), hence
    /// the standalone (non-visit) hook call in `lint()` rather than a
    /// `visit_*` override.
    ///
    /// `offensive?` gates on three checks, in this exact order (rubocop
    /// short-circuits on the first two):
    ///   1. `rbs_inline_annotation?` — allowed on a `class X < Y` subclass
    ///      header (`#[...]`, requiring the closing bracket — an
    ///      unterminated `#[String` or a bare `#String]` is NOT exempt) or
    ///      on any `def`/`end` line (a bare `#:` prefix — RBS::Inline's
    ///      method-type annotation; note the classification is by LINE TEXT
    ///      shape only, so `end #: String` is exempt whether that `end`
    ///      closes a `def`, `class`, `module`, or `begin`).
    ///   2. `steep_annotation?` — `# steep:ignore` (a literal single space
    ///      between `#` and `steep`), optionally followed by more text as
    ///      long as a whitespace character (or end of comment) immediately
    ///      follows `ignore` itself (`#steep:ignore` with no leading space,
    ///      or `# steep:ignoreFoo` with no separator, are NOT valid).
    ///   3. `KEYWORD_REGEXES` (one of the five keywords, anchored at the
    ///      start of the line with a trailing space) must match, AND
    ///      `ALLOWED_COMMENT_REGEXES` (`:nodoc:`, `:yields:`, or a
    ///      `# rubocop:disable/enable/todo/push/pop` directive) must NOT.
    ///
    /// The reported `keyword` (and the correction's "hoist above the line"
    /// decision) comes from a separate regex — upstream's
    /// `/(?<keyword>\S+).*#/`, the line's first whitespace-delimited token —
    /// which happens to always coincide with whichever KEYWORD_REGEXES
    /// matched here (both anchor on the same leading run of non-space
    /// characters).
    ///
    /// Autocorrect (unsafe, like upstream): removes the comment plus
    /// surrounding horizontal whitespace only (spaces/tabs — rubocop's
    /// `range_with_surrounding_space(newlines: false)` never crosses a
    /// newline), and unless the matched keyword is literally `end`,
    /// re-inserts the original comment text as its own line directly above
    /// — at column 0 of the physical line, ignoring that line's own
    /// indentation (rubocop's `insert_before(buffer.line_range(...), ...)`).
    pub(crate) fn check_commented_keyword(&mut self) {
        const COP: &str = "Style/CommentedKeyword";
        if !self.on(COP) {
            return;
        }
        static KEYWORD_RES: OnceLock<[regex::Regex; 5]> = OnceLock::new();
        let keyword_res = KEYWORD_RES.get_or_init(|| {
            [
                regex::Regex::new(r"^\s*begin\s").unwrap(),
                regex::Regex::new(r"^\s*class\s").unwrap(),
                regex::Regex::new(r"^\s*def\s").unwrap(),
                regex::Regex::new(r"^\s*end\s").unwrap(),
                regex::Regex::new(r"^\s*module\s").unwrap(),
            ]
        });
        static NODOC_RE: OnceLock<regex::Regex> = OnceLock::new();
        let nodoc_re = NODOC_RE.get_or_init(|| regex::Regex::new(r"#\s*:nodoc:").unwrap());
        static YIELDS_RE: OnceLock<regex::Regex> = OnceLock::new();
        let yields_re = YIELDS_RE.get_or_init(|| regex::Regex::new(r"#\s*:yields:").unwrap());
        static DIRECTIVE_RE: OnceLock<regex::Regex> = OnceLock::new();
        let directive_re = DIRECTIVE_RE.get_or_init(|| {
            regex::Regex::new(r"#\s*rubocop\s*:\s*(?:disable|enable|todo|push|pop)\b").unwrap()
        });
        static SUBCLASS_RE: OnceLock<regex::Regex> = OnceLock::new();
        let subclass_re = SUBCLASS_RE
            .get_or_init(|| regex::Regex::new(r"^\s*class\s+(?:\w|::)+\s*<\s*(?:\w|::)+").unwrap());
        static METHOD_OR_END_RE: OnceLock<regex::Regex> = OnceLock::new();
        let method_or_end_re =
            METHOD_OR_END_RE.get_or_init(|| regex::Regex::new(r"^\s*(?:def\s|end)").unwrap());
        static RBS_BRACKET_RE: OnceLock<regex::Regex> = OnceLock::new();
        let rbs_bracket_re = RBS_BRACKET_RE.get_or_init(|| regex::Regex::new(r"^#\[.+\]").unwrap());
        static STEEP_RE: OnceLock<regex::Regex> = OnceLock::new();
        let steep_re =
            STEEP_RE.get_or_init(|| regex::Regex::new(r"#\ssteep:ignore(?:\s|\z)").unwrap());
        static EXTRACT_RE: OnceLock<regex::Regex> = OnceLock::new();
        let extract_re = EXTRACT_RE.get_or_init(|| regex::Regex::new(r"^\s*(\S+).*#").unwrap());

        for &(line, start, end) in self.comments {
            let line_start = self.idx.starts[line - 1];
            let line_end =
                if line < self.idx.starts.len() { self.idx.starts[line] - 1 } else { self.src.len() };
            let line_text = String::from_utf8_lossy(&self.src[line_start..line_end]);
            let comment_bytes = &self.src[start..end];
            let comment_str = String::from_utf8_lossy(comment_bytes);

            // rbs_inline_annotation?
            let rbs = if subclass_re.is_match(&line_text) {
                rbs_bracket_re.is_match(&comment_str)
            } else if method_or_end_re.is_match(&line_text) {
                comment_str.starts_with("#:")
            } else {
                false
            };
            if rbs || steep_re.is_match(&comment_str) {
                continue;
            }
            if !keyword_res.iter().any(|r| r.is_match(&line_text)) {
                continue;
            }
            if nodoc_re.is_match(&line_text)
                || yields_re.is_match(&line_text)
                || directive_re.is_match(&line_text)
            {
                continue;
            }
            let Some(caps) = extract_re.captures(&line_text) else { continue };
            let keyword = caps.get(1).unwrap().as_str().to_string();

            self.push(
                start,
                COP,
                true,
                format!("Do not place comments on the same line as the `{keyword}` keyword."),
            );

            // Autocorrect: remove the comment plus surrounding horizontal
            // whitespace (never crossing the newline either side).
            let mut remove_start = start;
            while remove_start > line_start && matches!(self.src[remove_start - 1], b' ' | b'\t') {
                remove_start -= 1;
            }
            let mut remove_end = end;
            while remove_end < self.src.len() && matches!(self.src[remove_end], b' ' | b'\t') {
                remove_end += 1;
            }
            self.fixes.push((remove_start, remove_end, Vec::new()));

            if keyword != "end" {
                let mut ins = comment_bytes.to_vec();
                ins.push(b'\n');
                self.fixes.push((line_start, line_start, ins));
            }
        }
    }
}


/// Method names for which RuboCop's `operator_method?` (rubocop-ast's
/// `MethodIdentifierPredicates::OPERATOR_METHODS`) returns true — used by
/// `Style/For`'s `ForToEachCorrector#requires_parentheses?` to decide
/// whether the collection expression needs wrapping in `(...)` before
/// `.each` is appended.
const FOR_OPERATOR_METHODS: &[&[u8]] = &[
    b"|", b"^", b"&", b"<=>", b"==", b"===", b"=~", b">", b">=", b"<", b"<=", b"<<", b">>", b"+",
    b"-", b"*", b"/", b"%", b"**", b"~", b"+@", b"-@", b"!@", b"~@", b"[]", b"[]=", b"!", b"!=",
    b"!~", b"`",
];

/// `ForToEachCorrector#requires_parentheses?` — true when the collection
/// expression would change meaning (or read ambiguously) if `.each` were
/// simply appended after it without wrapping parens: an unparenthesized
/// operator-method call (`a + b`, `a | b`, ...), a bare range literal
/// (`1...value`), or an `&&`/`||` expression. A collection that's ALREADY
/// wrapped in literal parens (prism's `ParenthesesNode`) is none of these
/// node types, so it's correctly left untouched (its `.source` already
/// includes the parens).
fn for_collection_requires_parens(node: &ruby_prism::Node) -> bool {
    if let Some(call) = node.as_call_node() {
        if !call.is_safe_navigation() && FOR_OPERATOR_METHODS.contains(&call.name().as_slice()) {
            return true;
        }
    }
    node.as_range_node().is_some() || node.as_and_node().is_some() || node.as_or_node().is_some()
}

/// `EachToForCorrector`'s pick of `argument_node.children.first` — the
/// leftmost declared block parameter (by written order: required, then
/// optional, then rest, then post, then keyword, then keyword-rest, then
/// block-pass), used verbatim (`.source`) as the `for` loop's variable
/// name/destructure target.
fn for_first_block_param<'pr>(params: &ruby_prism::ParametersNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    params
        .requireds()
        .iter()
        .next()
        .or_else(|| params.optionals().iter().next())
        .or_else(|| params.rest())
        .or_else(|| params.posts().iter().next())
        .or_else(|| params.keywords().iter().next())
        .or_else(|| params.keyword_rest())
        .or_else(|| params.block().map(|b| b.as_node()))
}

impl<'a> super::Cops<'a> {
    /// Style/For — enforces `for` vs `#each` per `EnforcedStyle` (`each`,
    /// the default, wants `.each`; `for` wants the `for` keyword). Ported
    /// from rubocop's `Style::For` (`ConfigurableEnforcedStyle` +
    /// `AutoCorrector`), which dispatches `on_for`/`on_block` (and its
    /// `on_numblock`/`on_itblock` aliases — prism collapses all three into
    /// one `BlockNode` shape, so `check_for_each` below covers all of
    /// them).
    ///
    /// `correct_style_detected`/`opposite_style_detected` are
    /// `ConfigurableEnforcedStyle` bookkeeping that only feeds
    /// `--auto-gen-config` output upstream — they never change whether an
    /// offense is reported or corrected, so they're dropped in this port.
    ///
    /// This half is the `each`-direction: every `for` loop is an offense
    /// when `EnforcedStyle` isn't `for`, autocorrected via
    /// `ForToEachCorrector`'s exact text surgery.
    pub(crate) fn check_for(&mut self, node: &ruby_prism::ForNode) {
        const COP: &str = "Style/For";
        if !self.on(COP) {
            return;
        }
        // `style == :each` — `EnforcedStyle` defaults to `each` per schema;
        // only an explicit `for` flips this cop into the opposite (no-op
        // here — see `check_for_each`) direction.
        if self.cfg.get(COP, "EnforcedStyle") == Some("for") {
            return;
        }

        let start = node.location().start_offset();
        self.push(start, COP, true, "Prefer `each` over `for`.");

        let index_src = self.node_src(&node.index());
        let collection = node.collection();
        let collection_src = self.node_src(&collection);

        // `collection_node.csend_type? ? '&.' : '.'`
        let dot: &[u8] = if collection.as_call_node().is_some_and(|c| c.is_safe_navigation()) {
            b"&."
        } else {
            b"."
        };

        let mut correction: Vec<u8> = Vec::with_capacity(collection_src.len() + index_src.len() + 12);
        if for_collection_requires_parens(&collection) {
            correction.push(b'(');
            correction.extend_from_slice(collection_src);
            correction.push(b')');
        } else {
            correction.extend_from_slice(collection_src);
        }
        correction.extend_from_slice(dot);
        correction.extend_from_slice(b"each do |");
        correction.extend_from_slice(index_src);
        correction.push(b'|');

        // `for_node.do?` — an explicit `do` keyword (not a bare newline or
        // `;`) replaces through its own end; otherwise the replacement ends
        // right after the collection expression (prism's node location
        // already spans the full, possibly-parenthesized, text either way).
        let end = match node.do_keyword_loc() {
            Some(do_loc) => do_loc.end_offset(),
            None => collection.location().end_offset(),
        };
        self.fixes.push((start, end, correction));
    }

    /// Style/For, `for`-direction — `on_block`/`on_numblock`/`on_itblock`:
    /// a multiline receiver-having `#each` call with no arguments passed to
    /// `each` itself (`suspect_enumerable?`) is corrected back to a `for`
    /// loop via `EachToForCorrector`, but only when `EnforcedStyle: for`
    /// (otherwise upstream just does `correct_style_detected` bookkeeping —
    /// no offense).
    pub(crate) fn check_for_each(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/For";
        if !self.on(COP) {
            return;
        }
        if self.cfg.get(COP, "EnforcedStyle") != Some("for") {
            return;
        }

        let Some(block) = node.block().and_then(|b| b.as_block_node()) else { return };

        // `suspect_enumerable?`: `node.multiline?` (`BlockNode#multiline?`
        // compares the OPENING/CLOSING delimiter lines — `do`/`{` vs
        // `end`/`}` — not the receiver-chain start), `node.method?(:each)`,
        // `!node.send_node.arguments?`.
        if node.name().as_slice() != b"each" {
            return;
        }
        if node.arguments().is_some() {
            return;
        }
        let open_line = self.idx.loc(block.opening_loc().start_offset()).0;
        let close_line = self.idx.loc(block.closing_loc().start_offset()).0;
        if open_line == close_line {
            return;
        }

        // `return unless node.receiver` — a bare `each do ... end` (implicit
        // self) is never corrected, regardless of style.
        let Some(receiver) = node.receiver() else { return };

        let start = node.location().start_offset();
        self.push(start, COP, true, "Prefer `for` over `each`.");

        let receiver_src = self.node_src(&receiver);

        // `block_node.arguments?` is hardcoded false for numblocks/itblocks
        // (numbered params / `it`) as well as a bare `do ... end` or an
        // empty `do || ... end` — all four fall back to the `_`
        // placeholder, matching `CORRECTION_WITHOUT_ARGUMENTS`.
        let bp = block.parameters().and_then(|p| p.as_block_parameters_node());
        let params = bp.as_ref().and_then(|bp| bp.parameters());

        let mut correction: Vec<u8> = b"for ".to_vec();
        let end = if let Some(params) = params {
            let var_src = for_first_block_param(&params)
                .map(|n| self.node_src(&n))
                .unwrap_or(b"_");
            correction.extend_from_slice(var_src);
            correction.extend_from_slice(b" in ");
            correction.extend_from_slice(receiver_src);
            correction.extend_from_slice(b" do");
            bp.expect("params implies bp").location().end_offset()
        } else {
            correction.extend_from_slice(b"_ in ");
            correction.extend_from_slice(receiver_src);
            correction.extend_from_slice(b" do");
            block.opening_loc().end_offset()
        };
        self.fixes.push((start, end, correction));
    }
}


// ---- Style/RedundantSort helpers ----

#[derive(Clone, Copy, PartialEq)]
enum RsSorter {
    Sort,
    SortBy,
}

/// Ports `redundant_sort?`'s node-pattern alternation, read from the
/// ACCESSOR call's point of view. Upstream's `on_send(:sort, :sort_by)` +
/// `node.parent`/`node.parent.parent` climb exists only because whitequark's
/// AST wraps a `sort { block }` receiver in a separate `block` node — prism
/// keeps a call's block on the SAME `CallNode` (`.block()`) regardless, so
/// the accessor's `.receiver()` is always, directly, the sort/sort_by call
/// (block or no block). That collapses all three of upstream's alternatives
/// (plain call, call-with-block-pass-arg, `any_block`-wrapped call) into one
/// shape here, read in a single visit of the outer accessor.
///
/// Returns `(sort_node, sorter, wants_min)` — `wants_min` is `first`/`[0]`/
/// `.at(0)`/`.slice(0)` (-> `min`/`min_by`) vs `last`/`[-1]`/`.at(-1)`/
/// `.slice(-1)` (-> `max`/`max_by`).
fn redundant_sort_match<'pr>(
    node: &ruby_prism::CallNode<'pr>,
) -> Option<(ruby_prism::CallNode<'pr>, RsSorter, bool)> {
    let name = node.name();
    let name = name.as_slice();
    let is_bracket = matches!(name, b"[]" | b"at" | b"slice");
    let wants_min = match name {
        b"first" => {
            // upstream's `(call $(call _ $:sort) ${:last :first})` etc. have
            // fixed arity (receiver + selector only) — `first`/`last` must
            // take NO arguments (`.first(1)` can't become `.min`: `min(1)`
            // isn't equivalent).
            if node.arguments().is_some() {
                return None;
            }
            true
        }
        b"last" => {
            if node.arguments().is_some() {
                return None;
            }
            false
        }
        b"[]" | b"at" | b"slice" => {
            // upstream's `{(int 0) (int -1)}` — exactly one argument, and it
            // must be the literal integer 0 or -1 (a variable, `[1]`, or a
            // negative-but-not-`-1` index all fall through unmatched).
            let args = node.arguments()?;
            let mut it = args.arguments().iter();
            let only = it.next()?;
            if it.next().is_some() {
                return None;
            }
            let int_node = only.as_integer_node()?;
            let v: i32 = int_node.value().try_into().ok()?;
            match v {
                0 => true,
                -1 => false,
                _ => return None,
            }
        }
        _ => return None,
    };

    let receiver = node.receiver()?;
    let sort_node = receiver.as_call_node()?;
    let sorter = match sort_node.name().as_slice() {
        b"sort" => RsSorter::Sort,
        b"sort_by" => RsSorter::SortBy,
        _ => return None,
    };
    // Neither `sort` nor `sort_by` ever takes a real positional argument in
    // any of upstream's alternatives (`mongo_client[...].sort(_id: 1)` has
    // one, and is correctly never matched).
    if sort_node.arguments().is_some() {
        return None;
    }
    let has_literal_block = sort_node.block().is_some_and(|b| b.as_block_node().is_some());
    let has_block_pass = sort_node.block().is_some_and(|b| b.as_block_argument_node().is_some());
    match sorter {
        RsSorter::Sort => {
            // `sort(&:foo)` (a block-PASS, no literal block) isn't covered by
            // any of upstream's `:sort` alternatives — only `:sort_by` has
            // the "one arg = block-pass" alt. A literal comparator block (or
            // no block at all) is fine either way.
            if has_block_pass {
                return None;
            }
        }
        RsSorter::SortBy => {
            // Bare `sort_by` (no block at all) never safely becomes
            // `min_by`/`max_by` — upstream requires either a block-pass arg
            // or a literal block.
            if !has_literal_block && !has_block_pass {
                return None;
            }
            // Upstream's node-pattern for the bracket/at/slice + block-pass
            // (no literal block) combo is written with a bare `send` type,
            // not `call` (the `{send csend}` alias) — so THAT ONE
            // alternative only matches when BOTH the accessor and the
            // sort_by call are plain (non-safe-navigation) sends. Every
            // other combo (first/last, or a literal block) uses `call` and
            // allows safe-navigation freely. Likely an upstream oversight,
            // but ported verbatim.
            if !has_literal_block
                && is_bracket
                && (node.is_safe_navigation() || sort_node.is_safe_navigation())
            {
                return None;
            }
        }
    }

    Some((sort_node, sorter, wants_min))
}

impl<'a> super::Cops<'a> {
    /// Style/RedundantSort — `x.sort.first`/`.last`/`[0]`/`[-1]`/`.at(0/-1)`/
    /// `.slice(0/-1)` -> `x.min`/`x.max`; likewise `sort_by` ->
    /// `min_by`/`max_by`. See `redundant_sort_match` above for why hooking
    /// the ACCESSOR call (instead of upstream's `on_send(:sort, :sort_by)` +
    /// parent climb) is sufficient here.
    pub(crate) fn check_redundant_sort(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/RedundantSort";
        if !self.on(COP) {
            return;
        }
        let Some((sort_node, sorter, wants_min)) = redundant_sort_match(node) else {
            return;
        };
        // `sort_node.loc.selector` — the bare `sort`/`sort_by` identifier,
        // excluding any receiver/dot/safe-nav-operator before it. Both the
        // offense anchor and the autocorrect's method-name replacement use
        // this same range.
        let Some(sel) = sort_node.message_loc() else { return };
        // The accessor's own `loc.selector` — for `.first`/`.last`/`.at(0)`/
        // `.slice(0)` this is just the bare name; for index syntax (`[0]`)
        // prism's `message_loc` already spans the whole `[0]`/`[-1]` text
        // (there's no separate identifier token to point at).
        let Some(accessor_sel) = node.message_loc() else { return };

        let sorter_text = match sorter {
            RsSorter::Sort => "sort",
            RsSorter::SortBy => "sort_by",
        };
        let suggestion = match (wants_min, sorter) {
            (true, RsSorter::Sort) => "min",
            (false, RsSorter::Sort) => "max",
            (true, RsSorter::SortBy) => "min_by",
            (false, RsSorter::SortBy) => "max_by",
        };
        let node_end = node.location().end_offset();
        let accessor_source = String::from_utf8_lossy(&self.src[accessor_sel.start_offset()..node_end]);
        let message = format!("Use `{suggestion}` instead of `{sorter_text}...{accessor_source}`.");

        self.push(sel.start_offset(), COP, true, message);

        // Autocorrect: remove the accessor (`.first`/`[0]`/etc, including its
        // dot or safe-nav operator when present — prism's `call_operator_loc`
        // covers both `.` and `&.`), replace the sort/sort_by identifier with
        // the suggested method name, then — when this whole expression is the
        // LEFT side of a `&&`/`||`/`and`/`or` — hoist the operator to sit
        // right after the (now-renamed) sort call instead of after the
        // removed accessor, matching upstream's
        // `replace_with_logical_operator`.
        let accessor_start = node
            .call_operator_loc()
            .map(|l| l.start_offset())
            .unwrap_or_else(|| accessor_sel.start_offset());
        self.fixes.push((accessor_start, node_end, Vec::new()));
        self.fixes.push((sel.start_offset(), sel.end_offset(), suggestion.as_bytes().to_vec()));

        if let Some(&(op_start, op_end)) = self.redundant_sort_logical_left.get(&node.location().start_offset()) {
            let receiver_end = sort_node.location().end_offset();
            let mut insert = vec![b' '];
            insert.extend_from_slice(&self.src[op_start..op_end]);
            self.fixes.push((receiver_end, receiver_end, insert));
            self.fixes.push((op_start, op_end, Vec::new()));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Style/FloatDivision — checks for division with integers coerced to floats
    pub(crate) fn check_float_division(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Style/FloatDivision";
        if !self.on(COP) || node.name().as_slice() != b"/" {
            return;
        }

        let Some(receiver) = node.receiver() else { return };
        let Some(args) = node.arguments() else { return };
        let args_vec: Vec<_> = args.arguments().iter().collect();
        if args_vec.len() != 1 {
            return;
        }
        let argument = &args_vec[0];

        // Helper to check if a node is a .to_f method call
        let is_to_f = |n: &ruby_prism::Node| {
            n.as_call_node().is_some_and(|c| {
                c.name().as_slice() == b"to_f" && c.receiver().is_some() && c.arguments().is_none()
            })
        };

        // Pattern for matching Regexp.last_match
        static REGEXP_MATCH_PAT: OnceLock<Pat> = OnceLock::new();
        let regexp_match_pat = matcher(
            &REGEXP_MATCH_PAT,
            "(send (const {nil? cbase} :Regexp) :last_match int)",
        );

        // Check if a node is Regexp.last_match or $n
        let is_regexp_match = |n: &ruby_prism::Node| {
            // Check for Regexp.last_match(n)
            if nodepattern::matches(regexp_match_pat, n, self.src).is_some() {
                return true;
            }
            // Check for $n (NumberedReferenceReadNode)
            if n.as_numbered_reference_read_node().is_some() {
                return true;
            }
            false
        };

        // Don't fire if either operand is Regexp.last_match or $n
        // For .to_f calls, check the receiver of the call
        let receiver_is_regexp = if let Some(call) = receiver.as_call_node() {
            if is_to_f(&receiver) {
                if let Some(r) = call.receiver() {
                    is_regexp_match(&r)
                } else {
                    false
                }
            } else {
                is_regexp_match(&receiver)
            }
        } else {
            is_regexp_match(&receiver)
        };

        let argument_is_regexp = if let Some(call) = argument.as_call_node() {
            if is_to_f(argument) {
                if let Some(a) = call.receiver() {
                    is_regexp_match(&a)
                } else {
                    false
                }
            } else {
                is_regexp_match(argument)
            }
        } else {
            is_regexp_match(argument)
        };

        if receiver_is_regexp || argument_is_regexp {
            return;
        }

        let receiver_has_to_f = is_to_f(&receiver);
        let argument_has_to_f = is_to_f(argument);

        let style = self.cfg.enforced_style(COP);
        let style_str = &style[..];

        // Determine if this is an offense based on style
        let should_fire = match style_str {
            "left_coerce" => argument_has_to_f, // fire if right has to_f
            "right_coerce" => receiver_has_to_f, // fire if left has to_f
            "single_coerce" => receiver_has_to_f && argument_has_to_f, // fire if both have to_f
            "fdiv" => receiver_has_to_f || argument_has_to_f, // fire if either has to_f
            _ => false,
        };

        if !should_fire {
            return;
        }

        let message = match style_str {
            "left_coerce" => "Prefer using `.to_f` on the left side.",
            "right_coerce" => "Prefer using `.to_f` on the right side.",
            "single_coerce" => "Prefer using `.to_f` on one side only.",
            "fdiv" => "Prefer using `fdiv` for float divisions.",
            _ => return,
        };

        let l = node.location();
        self.push(l.start_offset(), COP, true, message);

        // Create the fix based on style
        match style_str {
            "left_coerce" | "single_coerce" => {
                // left_coerce: add .to_f to receiver if needed, remove from argument
                // single_coerce: always keep on left, remove from right
                if !receiver_has_to_f {
                    // Add .to_f to receiver
                    let receiver_end = receiver.location().end_offset();
                    self.fixes.push((receiver_end, receiver_end, b".to_f".to_vec()));
                }
                if argument_has_to_f {
                    // Remove .to_f from argument
                    if let Some(call) = argument.as_call_node() {
                        if let Some(dot) = call.call_operator_loc() {
                            let msg_loc = call.message_loc().unwrap();
                            self.fixes.push((dot.start_offset(), msg_loc.end_offset(), Vec::new()));
                        }
                    }
                }
            }
            "right_coerce" => {
                // Remove .to_f from receiver, add .to_f to argument if needed
                if receiver_has_to_f {
                    // Remove .to_f from receiver
                    if let Some(call) = receiver.as_call_node() {
                        if let Some(dot) = call.call_operator_loc() {
                            let msg_loc = call.message_loc().unwrap();
                            self.fixes.push((dot.start_offset(), msg_loc.end_offset(), Vec::new()));
                        }
                    }
                }
                if !argument_has_to_f {
                    // Add .to_f to argument
                    let arg_end = argument.location().end_offset();
                    self.fixes.push((arg_end, arg_end, b".to_f".to_vec()));
                }
            }
            "fdiv" => {
                // Replace the entire division with fdiv
                let receiver_src = if receiver_has_to_f {
                    if let Some(call) = receiver.as_call_node() {
                        if let Some(recv) = call.receiver() {
                            self.node_src(&recv).to_vec()
                        } else {
                            self.node_src(&receiver).to_vec()
                        }
                    } else {
                        self.node_src(&receiver).to_vec()
                    }
                } else {
                    self.node_src(&receiver).to_vec()
                };

                let argument_src = if argument_has_to_f {
                    if let Some(call) = argument.as_call_node() {
                        if let Some(recv) = call.receiver() {
                            self.node_src(&recv).to_vec()
                        } else {
                            self.node_src(&argument).to_vec()
                        }
                    } else {
                        self.node_src(&argument).to_vec()
                    }
                } else {
                    self.node_src(&argument).to_vec()
                };

                // Check if argument needs parentheses
                let arg_src_str = String::from_utf8_lossy(&argument_src);
                let arg_needs_parens = !arg_src_str.starts_with('(') || !arg_src_str.ends_with(')');

                let mut replacement = format!(
                    "{}.fdiv",
                    String::from_utf8_lossy(&receiver_src)
                );
                if arg_needs_parens {
                    replacement.push('(');
                    replacement.push_str(&arg_src_str);
                    replacement.push(')');
                } else {
                    replacement.push_str(&arg_src_str);
                }

                self.fixes.push((l.start_offset(), l.end_offset(), replacement.into_bytes()));
            }
            _ => {}
        }
    }
}


// Style/EachWithObject -------------------------------------------------
//
// Ported from `on_block`/`on_itblock` (an alias of `on_block`) and
// `on_numblock`. Prism unifies whitequark's three block flavors (`:block`,
// `:itblock`, `:numblock`) into one `BlockNode`, distinguished only by the
// shape of `parameters()` — `BlockParametersNode` (named `|a, e|` params),
// `NumberedParametersNode` (`_1`/`_2`), or `ItParametersNode` (`it`). Since
// prism's `CallNode` (not `BlockNode`) owns the block via `.block()`, the
// whole check runs from `visit_call_node` instead of a block visitor —
// there is no need to thread call context through a "pending" field the
// way e.g. `NonLocalExitFromIterator` does, because `CallNode` already
// carries both the send AND the attached block directly.
//
// `each_with_object_block_candidate?`'s pattern requires the node's literal
// type to be `:block` — a `:itblock` (Ruby 3.4 `it`) node never matches,
// which is why `on_itblock` (aliased straight to `on_block`) never fires an
// offense for `it` blocks. We reproduce that by simply not handling
// `ItParametersNode` (or blocks with no `parameters()` at all, e.g. a block
// with no `|...|` delimiters) below — same "no offense" outcome.
impl<'a> Cops<'a> {
    /// Style/EachWithObject — `inject`/`reduce` calls whose block just
    /// accumulates into the (first) block param and returns it unchanged
    /// at the end can drop the explicit return and swap to
    /// `each_with_object`, which yields `(element, accumulator)` instead of
    /// `inject`'s `(accumulator, element)`.
    pub(crate) fn check_each_with_object(&mut self, call: &ruby_prism::CallNode) {
        const COP: &str = "Style/EachWithObject";
        if !self.on(COP) {
            return;
        }
        if !matches!(call.name().as_slice(), b"inject" | b"reduce") {
            return;
        }
        let Some(block) = call.block().and_then(|b| b.as_block_node()) else { return };
        // `(call _ {:inject :reduce} _)` — exactly one argument (the
        // initial accumulator value).
        let Some(args) = call.arguments() else { return };
        let arg_list: Vec<_> = args.arguments().iter().collect();
        if arg_list.len() != 1 {
            return;
        }
        // `simple_method_arg?`: a non-composite literal initial value (`0`,
        // `:sym`, a plain string, ...) can't meaningfully "accumulate", so
        // rubocop exempts it outright — checked BEFORE looking at the block
        // shape at all (matches `return if simple_method_arg?(...)` running
        // first in both `on_block` and `on_numblock`).
        if ewo_is_basic_literal(&arg_list[0]) {
            return;
        }
        let Some(msg_loc) = call.message_loc() else { return };
        let method_name = call.name();
        let Some(params) = block.parameters() else { return };

        if let Some(bp) = params.as_block_parameters_node() {
            self.check_each_with_object_block(&block, &bp, msg_loc.start_offset(), method_name.as_slice());
        } else if let Some(np) = params.as_numbered_parameters_node() {
            self.check_each_with_object_numblock(&block, &np, msg_loc.start_offset(), method_name.as_slice());
        }
    }

    /// `on_block`/`on_itblock` path — named `|accumulator, element|` params.
    fn check_each_with_object_block(
        &mut self,
        block: &ruby_prism::BlockNode,
        bp: &ruby_prism::BlockParametersNode,
        selector_off: usize,
        method_name: &[u8],
    ) {
        const COP: &str = "Style/EachWithObject";
        // `(args _ _)` — exactly two block parameters, of any kind.
        let Some(params) = bp.parameters() else { return };
        let param_nodes = ewo_ordered_params(&params);
        if param_nodes.len() != 2 {
            return;
        }
        let Some(accumulator_name) = ewo_simple_param_name(&param_nodes[0]) else { return };
        // Empty body (`{ |a, e| }`) — `return_value(body)` upstream returns
        // nil for a nil body, so no offense.
        let Some(body) = block.body() else { return };
        let Some(return_value) = ewo_return_value(&body) else { return };
        if return_value.name().as_slice() != accumulator_name.as_slice() {
            return;
        }
        if ewo_reassigns(&body, &accumulator_name) {
            return;
        }

        let message = format!("Use `each_with_object` instead of `{}`.", String::from_utf8_lossy(method_name));
        self.push(selector_off, COP, true, message);

        // autocorrect_block: rename the selector, swap the two block
        // params, and drop the trailing accumulator return (the whole line
        // if it occupies one on its own, else just the expression itself).
        self.fixes.push((selector_off, selector_off + method_name.len(), b"each_with_object".to_vec()));

        let (f_start, f_end) = ewo_span(&param_nodes[0]);
        let (s_start, s_end) = ewo_span(&param_nodes[1]);
        let f_src = self.src[f_start..f_end].to_vec();
        let s_src = self.src[s_start..s_end].to_vec();
        self.fixes.push((f_start, f_end, s_src));
        self.fixes.push((s_start, s_end, f_src));

        let rv_loc = return_value.location();
        let (rv_start, rv_end) = (rv_loc.start_offset(), rv_loc.end_offset());
        if ewo_occupies_whole_line(self.src, rv_start, rv_end) {
            let (line_start, _, line_end_incl) = ewo_line_bounds(self.src, rv_start, rv_end);
            self.fixes.push((line_start, line_end_incl, Vec::new()));
        } else {
            self.fixes.push((rv_start, rv_end, Vec::new()));
        }
    }

    /// `on_numblock` path — `_1`/`_2` numbered params (Ruby 2.7+, pre-3.4
    /// `it`). Unlike the named-param path, the trailing accumulator return
    /// is NOT removed (upstream: "We don't remove the return value to avoid
    /// a clobbering error") — instead every `_1`/`_2` local-variable read in
    /// the body is swapped, return statement included.
    fn check_each_with_object_numblock(
        &mut self,
        block: &ruby_prism::BlockNode,
        np: &ruby_prism::NumberedParametersNode,
        selector_off: usize,
        method_name: &[u8],
    ) {
        const COP: &str = "Style/EachWithObject";
        // `(numblock $(call _ {:inject :reduce} _) 2 $_)` — arity must be
        // exactly 2 (i.e. `_2` is referenced somewhere in the body).
        if np.maximum() != 2 {
            return;
        }
        let Some(body) = block.body() else { return };
        let Some(return_value) = ewo_return_value(&body) else { return };
        if return_value.name().as_slice() != b"_1" {
            return;
        }

        let message = format!("Use `each_with_object` instead of `{}`.", String::from_utf8_lossy(method_name));
        self.push(selector_off, COP, true, message);

        self.fixes.push((selector_off, selector_off + method_name.len(), b"each_with_object".to_vec()));
        let mut swapper = EwoNumSwap { fixes: Vec::new() };
        swapper.visit(&body);
        self.fixes.extend(swapper.fixes);
    }
}

/// rubocop-ast's (non-recursive) `basic_literal?`: `int`/`float`/`sym`/
/// `true`/`false`/`nil`/plain `str`/`rational`/`complex` — notably NOT
/// composite literals (`{}`, `[]`, interpolated strings/symbols, ranges,
/// regexps), which is exactly why `[].inject({}) { ... }` is never exempt
/// but `array.reduce(0) { ... }` is.
fn ewo_is_basic_literal(node: &ruby_prism::Node) -> bool {
    node.as_string_node().is_some()
        || node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
}

/// Block parameters in Ruby grammar order: required, optional, rest, post,
/// keyword, keyword-rest, block. Mirrors `rs_params_of`'s traversal but
/// keeps the nodes themselves (needed for `corrector.swap`'s source spans)
/// instead of just their names.
fn ewo_ordered_params<'pr>(params: &ruby_prism::ParametersNode<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    let mut out = Vec::new();
    for n in params.requireds().iter() {
        out.push(n);
    }
    for n in params.optionals().iter() {
        out.push(n);
    }
    if let Some(r) = params.rest() {
        out.push(r);
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
    out
}

/// A single parameter's name — deliberately NOT recursing into
/// `MultiTargetNode`/`SplatNode` (destructured `|(a, b), e|` params): rubocop
/// extracts the accumulator name via a flat `accumulator_var, = *first_arg`,
/// which for a destructured param yields the inner (m)lhs NODE, not a bare
/// symbol, so it can never equal a plain lvar's name — i.e. upstream itself
/// never treats a destructured first param as a trackable accumulator.
/// Returning `None` here reproduces that "never matches" outcome.
fn ewo_simple_param_name(node: &ruby_prism::Node) -> Option<Vec<u8>> {
    if let Some(p) = node.as_required_parameter_node() {
        return Some(p.name().as_slice().to_vec());
    }
    if let Some(p) = node.as_optional_parameter_node() {
        return Some(p.name().as_slice().to_vec());
    }
    if let Some(p) = node.as_rest_parameter_node() {
        return p.name().map(|n| n.as_slice().to_vec());
    }
    if let Some(p) = node.as_keyword_rest_parameter_node() {
        return p.name().map(|n| n.as_slice().to_vec());
    }
    if let Some(p) = node.as_required_keyword_parameter_node() {
        return Some(p.name().as_slice().to_vec());
    }
    if let Some(p) = node.as_optional_keyword_parameter_node() {
        return Some(p.name().as_slice().to_vec());
    }
    if let Some(p) = node.as_block_parameter_node() {
        return p.name().map(|n| n.as_slice().to_vec());
    }
    None
}

fn ewo_span(node: &ruby_prism::Node) -> (usize, usize) {
    let l = node.location();
    (l.start_offset(), l.end_offset())
}

/// `return_value(body)`: the block body's last statement (or the body
/// itself, for a single-expression body prism doesn't wrap in a
/// `StatementsNode`), but ONLY if it's a bare local-variable read —
/// anything else (a method call, a literal, ...) means there's nothing to
/// swap `each_with_object`'s implicit return onto.
fn ewo_return_value<'pr>(body: &ruby_prism::Node<'pr>) -> Option<ruby_prism::LocalVariableReadNode<'pr>> {
    if let Some(stmts) = body.as_statements_node() {
        let last = stmts.body().iter().last()?;
        last.as_local_variable_read_node()
    } else {
        body.as_local_variable_read_node()
    }
}

/// `accumulator_param_assigned_to?`: does ANY descendant of `body` write to
/// a local variable named `name` — a plain assignment, a compound
/// (`+=`/`||=`/`&&=`) assignment, or a multiple-assignment/pattern-match
/// target? Prism gives each of those its own flat node kind carrying the
/// name directly (unlike whitequark's `op_asgn`/`and_asgn`/`or_asgn`, which
/// wrap a nameless inner `(op_)asgn` node reached only by descending into
/// it) so checking each kind's own `.name()` field covers exactly the same
/// ground as upstream's `each_descendant`.
fn ewo_reassigns(body: &ruby_prism::Node, name: &[u8]) -> bool {
    let mut finder = EwoReassignFinder { name, found: false };
    finder.visit(body);
    finder.found
}

struct EwoReassignFinder<'n> {
    name: &'n [u8],
    found: bool,
}

impl<'pr, 'n> ruby_prism::Visit<'pr> for EwoReassignFinder<'n> {
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        if node.name().as_slice() == self.name {
            self.found = true;
        }
        ruby_prism::visit_local_variable_write_node(self, node);
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        if node.name().as_slice() == self.name {
            self.found = true;
        }
        ruby_prism::visit_local_variable_operator_write_node(self, node);
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        if node.name().as_slice() == self.name {
            self.found = true;
        }
        ruby_prism::visit_local_variable_and_write_node(self, node);
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        if node.name().as_slice() == self.name {
            self.found = true;
        }
        ruby_prism::visit_local_variable_or_write_node(self, node);
    }
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        if node.name().as_slice() == self.name {
            self.found = true;
        }
        ruby_prism::visit_local_variable_target_node(self, node);
    }
}

/// `autocorrect_numblock`: swap every `_1`/`_2` local-variable read in the
/// block body (the return statement included — see
/// `check_each_with_object_numblock`'s doc comment for why it's kept).
struct EwoNumSwap {
    fixes: Vec<super::Fix>,
}

impl<'pr> ruby_prism::Visit<'pr> for EwoNumSwap {
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        let repl: Option<&[u8]> = match node.name().as_slice() {
            b"_1" => Some(b"_2"),
            b"_2" => Some(b"_1"),
            _ => None,
        };
        if let Some(r) = repl {
            let l = node.location();
            self.fixes.push((l.start_offset(), l.end_offset(), r.to_vec()));
        }
        ruby_prism::visit_local_variable_read_node(self, node);
    }
}

/// Is `[start, end)` the only non-whitespace content on its (single) source
/// line? (`return_value_occupies_whole_line?`: `whole_line_expression(node)
/// .source.strip == node.source`.)
fn ewo_occupies_whole_line(src: &[u8], start: usize, end: usize) -> bool {
    let (line_start, line_end, _) = ewo_line_bounds(src, start, end);
    src[line_start..start].iter().all(|&b| b == b' ' || b == b'\t')
        && src[end..line_end].iter().all(|&b| b == b' ' || b == b'\t')
}

/// `range_by_whole_lines(range, include_final_newline: true)`: the full
/// source line(s) spanned by `[start, end)`. Returns
/// `(line_start, line_end_excl_newline, line_end_incl_newline)`.
fn ewo_line_bounds(src: &[u8], start: usize, end: usize) -> (usize, usize, usize) {
    let mut s = start;
    while s > 0 && src[s - 1] != b'\n' {
        s -= 1;
    }
    let mut e = end;
    while e < src.len() && src[e] != b'\n' {
        e += 1;
    }
    let e_incl = if e < src.len() { e + 1 } else { e };
    (s, e, e_incl)
}


impl<'a> super::Cops<'a> {
    /// Style/CaseLikeIf — an `if`/`elsif` chain where every branch condition
    /// compares the SAME target expression (`==`/`eql?`/`equal?` against a
    /// literal or SCREAMING_CASE constant, `===`, `is_a?`, `match?`/`match`/
    /// `=~` against a regexp, `include?`/`cover?` against a range literal —
    /// any of these OR'd together within a branch) is rewritten to
    /// `case`/`when`. Ports rubocop's `CaseLikeIf` + its `MinBranchesCount`
    /// mixin. Key pieces, transliterated from the Ruby source (comments
    /// below cite the corresponding private method name there):
    ///
    ///   - `should_check?`: a real `if` (not ternary/modifier-form), not
    ///     itself an `elsif` (only the HEAD of the chain fires — an `elsif`
    ///     IfNode is visited independently by the traversal, via its own
    ///     nested `visit_if_node` call, and must bail immediately, exactly
    ///     like upstream's `!node.elsif?` guard), has at least one `elsif`
    ///     (`elsif_conditional?`), and the if/elsif branch count meets
    ///     `MinBranchesCount` (default 3 — see `min_branches_count?`; a
    ///     trailing plain `else`, if present, never counts as a branch).
    ///     `unless` never reaches here at all: prism gives it a wholly
    ///     separate `UnlessNode` type that this cop never hooks.
    ///   - `find_target`: derives the "subject" expression from the FIRST
    ///     branch's condition only.
    ///   - `collect_conditions`/`condition_from_send_node` (run once per
    ///     branch condition, including every sub-condition OR'd together
    ///     within a single branch): rewrites each into the `when`-clause
    ///     fragment that would follow `target === `, or fails the WHOLE cop
    ///     (no offense at all, not just that branch) the moment any single
    ///     branch's condition isn't one of the recognized shapes.
    ///   - `regexp_with_working_captures?`: a `.match` call (not `match?`,
    ///     not `=~`) against a regexp with named captures on either side, OR
    ///     a literal-regexp-on-the-LHS `=~` with named captures (prism's
    ///     `MatchWriteNode`, upstream's `match_with_lvasgn`) blocks the
    ///     ENTIRE conversion outright — the auto-vivified local variable(s)
    ///     can't survive becoming a `case`/`when`.
    ///
    /// Node-equality (`lhs == target` etc. in the Ruby source — a structural
    /// `AST::Node#==` that ignores location) is approximated here as raw
    /// byte-source comparison of the two spans (`cli_node_eq`): exact for
    /// every fixture case (every repeat of the shared subject is spelled
    /// identically) but not a true structural comparator — see the final
    /// report's risk note for what that could miss on real-world code.
    ///
    /// Autocorrect folds rubocop's two same-start-boundary Corrector ops for
    /// the FIRST branch (`insert_before(node, "case TARGET\n<indent>")` +
    /// `replace(correction_range(first_branch), "when ...")`) into one
    /// replacement spanning their combined range, exactly like
    /// `check_comparable_clamp_if` above — our `Fix` model (a flat
    /// non-overlapping byte-range replace list) can't otherwise represent
    /// two edits that share a start offset.
    pub(crate) fn check_case_like_if<'pr>(&mut self, node: &ruby_prism::IfNode<'pr>) {
        const COP: &str = "Style/CaseLikeIf";
        if !self.on(COP) {
            return;
        }
        if !cli_should_check(node) {
            return;
        }
        let min_branches = self
            .cfg
            .get(COP, "MinBranchesCount")
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(3) as usize;
        let chain = cli_branch_chain(node);
        if chain.len() < min_branches {
            return;
        }

        let Some(target) = cli_find_target(&chain[0].0) else { return };

        let mut per_branch: Vec<Vec<ruby_prism::Node<'pr>>> = Vec::with_capacity(chain.len());
        for (cond, _kw_start) in &chain {
            if cli_regexp_with_working_captures(cond, self.src) {
                return;
            }
            let mut conds = Vec::new();
            if !cli_collect_conditions(cond, &target, self.src, &mut conds) {
                return;
            }
            per_branch.push(conds);
        }

        let start = node.location().start_offset();
        self.push(start, COP, true, "Convert `if-elsif` to `case-when`.");

        let target_src = self.node_src(&target).to_vec();
        let indent_n = self.idx.loc(start).1.saturating_sub(1);
        let indent = " ".repeat(indent_n);

        for (i, ((cond, kw_start), conds)) in chain.iter().zip(per_branch.iter()).enumerate() {
            let cond_end = cond.location().end_offset();
            let mut when_text = b"when ".to_vec();
            for (j, c) in conds.iter().enumerate() {
                if j > 0 {
                    when_text.extend_from_slice(b", ");
                }
                when_text.extend_from_slice(self.node_src(c));
            }
            if i == 0 {
                let mut rep = Vec::new();
                rep.extend_from_slice(b"case ");
                rep.extend_from_slice(&target_src);
                rep.push(b'\n');
                rep.extend_from_slice(indent.as_bytes());
                rep.extend_from_slice(&when_text);
                self.fixes.push((*kw_start, cond_end, rep));
            } else {
                self.fixes.push((*kw_start, cond_end, when_text));
            }
        }
    }
}

/// `should_check?`: real `if` (excludes ternary — no `if_keyword_loc` at
/// all), not a modifier-form (`end_keyword_loc` present), not itself an
/// `elsif` (keyword text must be exactly `if`), and `elsif_conditional?`
/// (its `subsequent` is itself an `elsif`-keyword IfNode).
fn cli_should_check(node: &ruby_prism::IfNode) -> bool {
    let Some(kw) = node.if_keyword_loc() else { return false };
    if kw.as_slice() != b"if" {
        return false;
    }
    if node.end_keyword_loc().is_none() {
        return false;
    }
    let Some(sub) = node.subsequent() else { return false };
    let Some(elsif) = sub.as_if_node() else { return false };
    elsif.if_keyword_loc().is_some_and(|k| k.as_slice() == b"elsif")
}

/// `branch_conditions`/`if_conditional_branches` combined: walks the
/// `if`/`elsif` chain (never descending into a trailing plain `else`),
/// pairing each level's own condition with the byte offset of ITS `if`/
/// `elsif` keyword — upstream's `node.parent.loc.keyword.begin_pos` in
/// `correction_range`, captured here instead of re-derived from a parent
/// pointer prism doesn't give us.
fn cli_branch_chain<'pr>(first: &ruby_prism::IfNode<'pr>) -> Vec<(ruby_prism::Node<'pr>, usize)> {
    let mut out = Vec::new();
    let Some(kw) = first.if_keyword_loc() else { return out };
    out.push((first.predicate(), kw.start_offset()));
    let mut cur = first.subsequent();
    while let Some(n) = cur {
        let Some(elsif) = n.as_if_node() else { break };
        let Some(kw) = elsif.if_keyword_loc() else { break };
        out.push((elsif.predicate(), kw.start_offset()));
        cur = elsif.subsequent();
    }
    out
}

/// `find_target`: derives the shared "subject" from the first branch's raw
/// condition node.
fn cli_find_target<'pr>(node: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    if let Some(p) = node.as_parentheses_node() {
        let first = p.body().and_then(|b| b.as_statements_node()).and_then(|s| s.body().iter().next())?;
        return cli_find_target(&first);
    }
    if let Some(o) = node.as_or_node() {
        let left = o.left();
        return cli_find_target(&left);
    }
    if let Some(mw) = node.as_match_write_node() {
        let call = mw.call();
        let lhs = call.receiver()?;
        let rhs = first_call_arg(&call)?;
        return if cli_is_regexp(&lhs) {
            Some(rhs)
        } else if cli_is_regexp(&rhs) {
            Some(lhs)
        } else {
            None
        };
    }
    if let Some(call) = node.as_call_node() {
        return cli_find_target_in_call(&call);
    }
    None
}

fn cli_find_target_in_call<'pr>(call: &ruby_prism::CallNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    match call.name().as_slice() {
        b"is_a?" => call.receiver(),
        b"==" | b"eql?" | b"equal?" => cli_find_target_in_equality(call),
        b"===" => first_call_arg(call),
        b"include?" | b"cover?" => cli_find_target_in_include_or_cover(call),
        b"match" | b"match?" | b"=~" => cli_find_target_in_match(call),
        _ => None,
    }
}

fn cli_find_target_in_equality<'pr>(call: &ruby_prism::CallNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let argument = first_call_arg(call)?;
    let receiver = call.receiver()?;
    if cli_is_literal(&argument) || cli_const_reference(&argument) {
        Some(receiver)
    } else if cli_is_literal(&receiver) || cli_const_reference(&receiver) {
        Some(argument)
    } else {
        None
    }
}

fn cli_find_target_in_include_or_cover<'pr>(call: &ruby_prism::CallNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let receiver = call.receiver()?;
    if cli_deparen(receiver).as_range_node().is_some() {
        first_call_arg(call)
    } else {
        None
    }
}

fn cli_find_target_in_match<'pr>(call: &ruby_prism::CallNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    let receiver = call.receiver()?;
    let argument = first_call_arg(call);
    if cli_is_regexp(&receiver) {
        argument
    } else if argument.as_ref().is_some_and(cli_is_regexp) {
        Some(receiver)
    } else {
        None
    }
}

/// `collect_conditions`: run per branch condition. Recurses through
/// parenthesized groups and `||`, pushing one rewritten `when`-fragment node
/// per leaf onto `out`; returns `false` (leaving `out` partially filled, same
/// as upstream — the caller always discards it on failure) the moment any
/// leaf isn't one of the recognized comparison shapes.
fn cli_collect_conditions<'pr>(
    node: &ruby_prism::Node<'pr>,
    target: &ruby_prism::Node<'pr>,
    src: &[u8],
    out: &mut Vec<ruby_prism::Node<'pr>>,
) -> bool {
    if let Some(p) = node.as_parentheses_node() {
        let Some(first) = p.body().and_then(|b| b.as_statements_node()).and_then(|s| s.body().iter().next())
        else {
            return false;
        };
        return cli_collect_conditions(&first, target, src, out);
    }
    if let Some(o) = node.as_or_node() {
        let left = o.left();
        let right = o.right();
        return cli_collect_conditions(&left, target, src, out) && cli_collect_conditions(&right, target, src, out);
    }
    let condition = if let Some(mw) = node.as_match_write_node() {
        let call = mw.call();
        match (call.receiver(), first_call_arg(&call)) {
            (Some(lhs), Some(rhs)) => cli_condition_from_binary_op(lhs, rhs, target, src),
            _ => None,
        }
    } else if let Some(call) = node.as_call_node() {
        cli_condition_from_call(&call, target, src)
    } else {
        None
    };
    match condition {
        Some(c) => {
            out.push(c);
            true
        }
        None => false,
    }
}

fn cli_condition_from_call<'pr>(
    call: &ruby_prism::CallNode<'pr>,
    target: &ruby_prism::Node<'pr>,
    src: &[u8],
) -> Option<ruby_prism::Node<'pr>> {
    match call.name().as_slice() {
        b"is_a?" => {
            let receiver = call.receiver()?;
            if cli_node_eq(&receiver, target, src) { first_call_arg(call) } else { None }
        }
        b"==" | b"eql?" | b"equal?" => cli_condition_from_equality(call, target, src),
        b"=~" | b"match" | b"match?" => cli_condition_from_match(call, target, src),
        b"===" => {
            let arg = first_call_arg(call)?;
            if cli_node_eq(&arg, target, src) { call.receiver() } else { None }
        }
        b"include?" | b"cover?" => cli_condition_from_include_or_cover(call, target, src),
        _ => None,
    }
}

fn cli_condition_from_equality<'pr>(
    call: &ruby_prism::CallNode<'pr>,
    target: &ruby_prism::Node<'pr>,
    src: &[u8],
) -> Option<ruby_prism::Node<'pr>> {
    let receiver = call.receiver()?;
    let argument = first_call_arg(call)?;
    let condition = cli_condition_from_binary_op(receiver, argument, target, src)?;
    if cli_class_reference(&condition) { None } else { Some(condition) }
}

fn cli_condition_from_match<'pr>(
    call: &ruby_prism::CallNode<'pr>,
    target: &ruby_prism::Node<'pr>,
    src: &[u8],
) -> Option<ruby_prism::Node<'pr>> {
    let receiver = call.receiver()?;
    let argument = first_call_arg(call)?;
    cli_condition_from_binary_op(receiver, argument, target, src)
}

fn cli_condition_from_include_or_cover<'pr>(
    call: &ruby_prism::CallNode<'pr>,
    target: &ruby_prism::Node<'pr>,
    src: &[u8],
) -> Option<ruby_prism::Node<'pr>> {
    let receiver = call.receiver()?;
    let deparenthesized = cli_deparen(receiver);
    let argument = first_call_arg(call)?;
    if deparenthesized.as_range_node().is_some() && cli_node_eq(&argument, target, src) {
        Some(deparenthesized)
    } else {
        None
    }
}

/// `condition_from_binary_op`: deparenthesize both operands, then return
/// whichever one ISN'T the target (the one that becomes a `when` value).
fn cli_condition_from_binary_op<'pr>(
    lhs: ruby_prism::Node<'pr>,
    rhs: ruby_prism::Node<'pr>,
    target: &ruby_prism::Node<'pr>,
    src: &[u8],
) -> Option<ruby_prism::Node<'pr>> {
    let lhs = cli_deparen(lhs);
    let rhs = cli_deparen(rhs);
    if cli_node_eq(&lhs, target, src) {
        Some(rhs)
    } else if cli_node_eq(&rhs, target, src) {
        Some(lhs)
    } else {
        None
    }
}

/// `deparenthesize`: unwrap nested parenthesized groups, taking the LAST
/// statement of each (matching upstream's `node.children.last`) — bails out
/// (returning what it has so far) on a syntactically-empty `()`, which
/// upstream can't reach here either (it would raise on a nil child).
fn cli_deparen(mut node: ruby_prism::Node) -> ruby_prism::Node {
    while let Some(p) = node.as_parentheses_node() {
        match p.body().and_then(|b| b.as_statements_node()).and_then(|s| s.body().iter().last()) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

/// Approximates upstream's structural `AST::Node#==` (ignores source
/// location) via raw byte-source comparison of the two nodes' own spans —
/// see the doc comment on `check_case_like_if` for the fidelity caveat.
fn cli_node_eq(a: &ruby_prism::Node, b: &ruby_prism::Node, src: &[u8]) -> bool {
    let al = a.location();
    let bl = b.location();
    src[al.start_offset()..al.end_offset()] == src[bl.start_offset()..bl.end_offset()]
}

fn cli_is_regexp(node: &ruby_prism::Node) -> bool {
    node.as_regular_expression_node().is_some() || node.as_interpolated_regular_expression_node().is_some()
}

/// `literal?` (rubocop-ast `Node::LITERALS`): str/dstr/xstr/int/float/sym/
/// dsym/array/hash/regexp/true/irange/erange/complex/rational/false/nil.
fn cli_is_literal(node: &ruby_prism::Node) -> bool {
    node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
        || node.as_string_node().is_some()
        || node.as_interpolated_string_node().is_some()
        || node.as_x_string_node().is_some()
        || node.as_interpolated_x_string_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_interpolated_symbol_node().is_some()
        || node.as_array_node().is_some()
        || node.as_hash_node().is_some()
        || node.as_range_node().is_some()
        || cli_is_regexp(node)
        || node.as_nil_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
}

/// The constant's own (last-segment, for a scoped `Foo::BAR`) name bytes,
/// for both a bare `ConstantReadNode` and a scoped `ConstantPathNode`.
fn cli_const_name<'pr>(node: &ruby_prism::Node<'pr>) -> Option<&'pr [u8]> {
    if let Some(c) = node.as_constant_read_node() {
        Some(c.name().as_slice())
    } else if let Some(c) = node.as_constant_path_node() {
        c.name().map(|n| n.as_slice())
    } else {
        None
    }
}

/// `const_reference?`: a constant whose name is more than one character and
/// entirely non-lowercase (upstream's `name.length > 1 && name == name.upcase`).
fn cli_const_reference(node: &ruby_prism::Node) -> bool {
    match cli_const_name(node) {
        Some(name) => name.len() > 1 && !name.iter().any(u8::is_ascii_lowercase),
        None => false,
    }
}

/// `class_reference?`: a constant whose name contains any lowercase letter
/// (a heuristic for "this reads as a class/module name", regardless of
/// length — unlike `const_reference?` above).
fn cli_class_reference(node: &ruby_prism::Node) -> bool {
    match cli_const_name(node) {
        Some(name) => name.iter().any(u8::is_ascii_lowercase),
        None => false,
    }
}

/// `regexp_with_working_captures?`: blocks the WHOLE conversion (called on
/// the raw, un-deparenthesized branch condition, matching upstream exactly —
/// a `(foo =~ /(?<n>x)/)` wrapped in parens, or one side of an `||`, is NOT
/// recognized here, same as upstream's plain `case node.type` dispatch).
fn cli_regexp_with_working_captures(node: &ruby_prism::Node, src: &[u8]) -> bool {
    if let Some(mw) = node.as_match_write_node() {
        let call = mw.call();
        if call.name().as_slice() != b"=~" {
            return false;
        }
        return call.receiver().is_some_and(|lhs| cli_regexp_has_named_captures(&lhs, src));
    }
    if let Some(call) = node.as_call_node() {
        if call.name().as_slice() != b"match" {
            return false;
        }
        let recv_named = call.receiver().is_some_and(|r| cli_regexp_has_named_captures(&r, src));
        let arg_named = first_call_arg(&call).is_some_and(|a| cli_regexp_has_named_captures(&a, src));
        return recv_named || arg_named;
    }
    false
}

/// `regexp_with_named_captures?`: `node.regexp_type? && node.each_capture(named:
/// true).any?`. Only a plain (non-interpolated) `RegularExpressionNode` is
/// handled — the fixture never exercises a named capture inside an
/// interpolated regexp literal here, and parsing one properly needs a real
/// regex-engine walk (see `scan_regexp_captures` in `lint_cops.rs` for the
/// numbered+named variant `Lint/MixedRegexpCaptureTypes` needs).
fn cli_regexp_has_named_captures(node: &ruby_prism::Node, src: &[u8]) -> bool {
    let Some(re) = node.as_regular_expression_node() else { return false };
    let content_loc = re.content_loc();
    let content = &src[content_loc.start_offset()..content_loc.end_offset()];
    cli_scan_named_capture(content)
}

/// Small purpose-built scanner (see `scan_regexp_captures` in
/// `lint_cops.rs` for the fuller sibling this is trimmed from) that only
/// needs to answer "does this pattern contain at least one named capturing
/// group" — `(?<name>...)` or `(?'name'...)`, excluding lookbehind
/// `(?<=`/`(?<!`. Skips backslash escapes and `[...]` character classes
/// (where `(`/`)` are literal) so it doesn't misfire inside them.
fn cli_scan_named_capture(src: &[u8]) -> bool {
    let n = src.len();
    let mut i = 0usize;
    let mut class_depth: u32 = 0;
    while i < n {
        let b = src[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if class_depth > 0 {
            match b {
                b'[' => class_depth += 1,
                b']' => class_depth -= 1,
                _ => {}
            }
            i += 1;
            continue;
        }
        if b == b'[' {
            class_depth = 1;
            i += 1;
            continue;
        }
        if b == b'(' && i + 1 < n && src[i + 1] == b'?' {
            match src.get(i + 2) {
                Some(b'<') if !matches!(src.get(i + 3), Some(b'=') | Some(b'!')) => return true,
                Some(b'\'') => return true,
                _ => {}
            }
        }
        i += 1;
    }
    false
}


/// rubocop-ast's `Node::TRUTHY_LITERALS` — the literal node types that make
/// a `while` condition unconditionally true for Style/InfiniteLoop's
/// `truthy_literal?` guard (`while 1`, `while [1]`, `while {}`, ...).
pub(crate) fn il_truthy_literal(n: &ruby_prism::Node) -> bool {
    n.as_string_node().is_some()
        || n.as_interpolated_string_node().is_some()
        || n.as_x_string_node().is_some()
        || n.as_interpolated_x_string_node().is_some()
        || n.as_integer_node().is_some()
        || n.as_float_node().is_some()
        || n.as_symbol_node().is_some()
        || n.as_interpolated_symbol_node().is_some()
        || n.as_array_node().is_some()
        || n.as_hash_node().is_some()
        || n.as_regular_expression_node().is_some()
        || n.as_interpolated_regular_expression_node().is_some()
        || n.as_true_node().is_some()
        || n.as_range_node().is_some()
        || n.as_imaginary_node().is_some()
        || n.as_rational_node().is_some()
}

/// rubocop-ast's `Node::FALSEY_LITERALS` — for Style/InfiniteLoop's
/// `falsey_literal?` guard on an `until` condition (`until false`,
/// `until nil`).
pub(crate) fn il_falsey_literal(n: &ruby_prism::Node) -> bool {
    n.as_false_node().is_some() || n.as_nil_node().is_some()
}

/// Style/InfiniteLoop's `VariableForce`-based scope guard, precomputed once
/// over the whole file (see `Cops::check_infinite_loop`'s doc comment for
/// why it can't be computed inline while visiting the loop node). Mirrors
/// `VariableForce::SCOPE_TYPES` (top level, `def`/`defs`, block, lambda,
/// `class`, `module`, `class << self`) — `while`/`until`/`for` are NOT
/// scope boundaries, so a loop's variables live in its enclosing method's
/// or the top-level scope. Within each scope, collects local variable
/// assignment ranges and reference (read) start offsets, then for every
/// `while true`/`until false` loop recorded in that scope (regardless of
/// nesting inside other loops), flags it for suppression when some
/// variable is: assigned somewhere inside the loop's own range, never
/// assigned anywhere before the loop starts, and read again somewhere
/// after the loop ends — the case where `loop do...end` would turn that
/// variable into a fresh block-scoped one and break the later read.
/// Instance/global/class variables are never tracked (matching
/// `VariableForce`, which only ever knows about `lvasgn`/`lvar`), so an
/// offense they'd otherwise gate is never suppressed by this pass.
pub(crate) fn infinite_loop_skips(root: &ruby_prism::Node) -> std::collections::HashSet<usize> {
    use std::collections::HashMap;
    use std::collections::HashSet;

    #[derive(Default)]
    struct Scope {
        assigns: HashMap<Vec<u8>, Vec<(usize, usize)>>,
        refs: HashMap<Vec<u8>, Vec<usize>>,
        loops: Vec<(usize, usize, usize)>, // (range_start, range_end, offense_anchor)
    }

    struct V {
        stack: Vec<Scope>,
        skip: HashSet<usize>,
    }

    impl V {
        fn assign(&mut self, name: &[u8], start: usize, end: usize) {
            self.stack.last_mut().unwrap().assigns.entry(name.to_vec()).or_default().push((start, end));
        }
        fn reference(&mut self, name: &[u8], pos: usize) {
            self.stack.last_mut().unwrap().refs.entry(name.to_vec()).or_default().push(pos);
        }
        fn record_loop(&mut self, start: usize, end: usize, anchor: usize) {
            self.stack.last_mut().unwrap().loops.push((start, end, anchor));
        }
        // Multiple-assignment target (`a, b = 1, 2` / `a, *b = arr`) —
        // only plain local-variable targets are `VariableForce`-tracked
        // assignments; splats/nested destructuring are unwrapped, anything
        // else (ivar/gvar/const/call/index targets) is just walked for any
        // nested loops/references it might still contain.
        fn masgn_target(&mut self, t: &ruby_prism::Node) {
            use ruby_prism::Visit;
            if let Some(lv) = t.as_local_variable_target_node() {
                let l = lv.location();
                self.assign(l.as_slice(), l.start_offset(), l.end_offset());
            } else if let Some(sp) = t.as_splat_node() {
                if let Some(e) = sp.expression() {
                    self.masgn_target(&e);
                }
            } else if let Some(mt) = t.as_multi_target_node() {
                for inner in mt.lefts().iter().chain(mt.rest()).chain(mt.rights().iter()) {
                    self.masgn_target(&inner);
                }
            } else {
                self.visit(t);
            }
        }
        fn finish_scope(&mut self) {
            let scope = self.stack.pop().expect("infinite_loop_skips: scope stack underflow");
            for &(rs, re, anchor) in &scope.loops {
                let hit = scope.assigns.iter().any(|(name, ranges)| {
                    if !ranges.iter().any(|&(s, e)| rs <= s && e <= re) {
                        return false; // not assigned_inside_loop?
                    }
                    if ranges.iter().any(|&(_, e)| e < rs) {
                        return false; // assigned_before_loop?
                    }
                    scope.refs.get(name).is_some_and(|pos| pos.iter().any(|&p| p > re))
                });
                if hit {
                    self.skip.insert(anchor);
                }
            }
        }
    }

    impl<'pr> ruby_prism::Visit<'pr> for V {
        fn visit_local_variable_read_node(&mut self, n: &ruby_prism::LocalVariableReadNode<'pr>) {
            let l = n.location();
            self.reference(l.as_slice(), l.start_offset());
        }
        fn visit_local_variable_write_node(&mut self, n: &ruby_prism::LocalVariableWriteNode<'pr>) {
            // rhs scanned before the assignment lands, matching
            // `process_variable_assignment` (`foo = foo + 1` sees the OLD
            // `foo` as a reference, not the one being created).
            self.visit(&n.value());
            let l = n.name_loc();
            self.assign(l.as_slice(), l.start_offset(), l.end_offset());
        }
        fn visit_local_variable_operator_write_node(
            &mut self,
            n: &ruby_prism::LocalVariableOperatorWriteNode<'pr>,
        ) {
            // `foo += 1` is a reference to the old `foo` AND an assignment
            // — matches `process_variable_operator_assignment`.
            let l = n.name_loc();
            self.reference(l.as_slice(), l.start_offset());
            self.visit(&n.value());
            self.assign(l.as_slice(), l.start_offset(), l.end_offset());
        }
        fn visit_local_variable_and_write_node(&mut self, n: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
            let l = n.name_loc();
            self.reference(l.as_slice(), l.start_offset());
            self.visit(&n.value());
            self.assign(l.as_slice(), l.start_offset(), l.end_offset());
        }
        fn visit_local_variable_or_write_node(&mut self, n: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
            let l = n.name_loc();
            self.reference(l.as_slice(), l.start_offset());
            self.visit(&n.value());
            self.assign(l.as_slice(), l.start_offset(), l.end_offset());
        }
        fn visit_multi_write_node(&mut self, n: &ruby_prism::MultiWriteNode<'pr>) {
            self.visit(&n.value());
            for t in n.lefts().iter().chain(n.rest()).chain(n.rights().iter()) {
                self.masgn_target(&t);
            }
        }
        fn visit_while_node(&mut self, n: &ruby_prism::WhileNode<'pr>) {
            if il_truthy_literal(&n.predicate()) {
                let l = n.location();
                self.record_loop(l.start_offset(), l.end_offset(), n.keyword_loc().start_offset());
            }
            ruby_prism::visit_while_node(self, n);
        }
        fn visit_until_node(&mut self, n: &ruby_prism::UntilNode<'pr>) {
            if il_falsey_literal(&n.predicate()) {
                let l = n.location();
                self.record_loop(l.start_offset(), l.end_offset(), n.keyword_loc().start_offset());
            }
            ruby_prism::visit_until_node(self, n);
        }
        // Scope boundaries (`VariableForce::SCOPE_TYPES`): a fresh
        // assignment/reference table, evaluated and popped once its body
        // has been fully walked (so it sees occurrences on either side of
        // any loop nested directly inside it).
        fn visit_def_node(&mut self, n: &ruby_prism::DefNode<'pr>) {
            // `defs`'s receiver (`def self.foo`) is evaluated in the OUTER
            // scope — rubocop-ast's `TWISTED_SCOPE_TYPES`.
            if let Some(r) = n.receiver() {
                self.visit(&r);
            }
            self.stack.push(Scope::default());
            if let Some(b) = n.body() {
                self.visit(&b);
            }
            self.finish_scope();
        }
        fn visit_block_node(&mut self, n: &ruby_prism::BlockNode<'pr>) {
            self.stack.push(Scope::default());
            if let Some(b) = n.body() {
                self.visit(&b);
            }
            self.finish_scope();
        }
        fn visit_lambda_node(&mut self, n: &ruby_prism::LambdaNode<'pr>) {
            self.stack.push(Scope::default());
            if let Some(b) = n.body() {
                self.visit(&b);
            }
            self.finish_scope();
        }
        fn visit_class_node(&mut self, n: &ruby_prism::ClassNode<'pr>) {
            if let Some(sc) = n.superclass() {
                self.visit(&sc);
            }
            self.stack.push(Scope::default());
            if let Some(b) = n.body() {
                self.visit(&b);
            }
            self.finish_scope();
        }
        fn visit_module_node(&mut self, n: &ruby_prism::ModuleNode<'pr>) {
            self.stack.push(Scope::default());
            if let Some(b) = n.body() {
                self.visit(&b);
            }
            self.finish_scope();
        }
        fn visit_singleton_class_node(&mut self, n: &ruby_prism::SingletonClassNode<'pr>) {
            // `class << expr`'s `expr` is evaluated in the OUTER scope.
            self.visit(&n.expression());
            self.stack.push(Scope::default());
            if let Some(b) = n.body() {
                self.visit(&b);
            }
            self.finish_scope();
        }
    }

    let mut v = V { stack: vec![Scope::default()], skip: HashSet::new() };
    use ruby_prism::Visit;
    v.visit(root);
    v.finish_scope();
    v.skip
}

impl<'a> super::Cops<'a> {
    /// Style/InfiniteLoop — `while true`/`until false`, in any of its
    /// shapes (full `while/until ... end`, single- or multi-line modifier
    /// form, or the post-condition `begin...end while/until`), should use
    /// `Kernel#loop` instead. `on_while`/`on_while_post` are literal
    /// aliases of the same handler upstream — prism gives both shapes
    /// (`while true; end` and `begin; end while true`) the SAME node type
    /// (distinguished only by `is_begin_modifier`), so one call site here
    /// covers both, unlike the `while`/`while_post` split in whitequark's
    /// AST.
    ///
    /// Before registering anything, this defers to the `VariableForce`
    /// scope guard precomputed in `infinite_loop_skips`: if a variable
    /// introduced inside the loop body is still read after the loop ends,
    /// wrapping it in `loop do...end` would make that variable
    /// block-scoped and break the later read, so upstream suppresses the
    /// offense ENTIRELY (not just the autocorrect). That check needs to
    /// see the whole enclosing scope — including code physically AFTER
    /// this loop — which a single forward visitor pass can't see yet at
    /// the point this node is reached, hence the whole-file precompute.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_infinite_loop(
        &mut self,
        is_infinite: bool,
        node_loc: ruby_prism::Location,
        keyword_loc: ruby_prism::Location,
        predicate: &ruby_prism::Node,
        statements: Option<ruby_prism::StatementsNode>,
        do_keyword_loc: Option<ruby_prism::Location>,
        closing_loc: Option<ruby_prism::Location>,
        is_begin_modifier: bool,
    ) {
        const COP: &str = "Style/InfiniteLoop";
        if !self.on(COP) || !is_infinite {
            return;
        }
        let kw_start = keyword_loc.start_offset();
        if self.il_no_offense.contains(&kw_start) {
            return;
        }
        self.push(kw_start, COP, true, "Use `Kernel#loop` for infinite loops.");

        if is_begin_modifier {
            // `begin ... end while/until cond` (a "post-condition loop"):
            // `begin` -> `loop do`; everything from the inner `end`
            // through the end of the WHOLE node (` while cond`/`
            // until cond` — never a trailing same-line comment, which
            // sits outside the node's own source range) is dropped.
            let Some(stmts) = statements else { return };
            let Some(begin_node) = stmts.body().iter().find_map(|n| n.as_begin_node()) else {
                return;
            };
            let (Some(begin_kw), Some(end_kw)) =
                (begin_node.begin_keyword_loc(), begin_node.end_keyword_loc())
            else {
                return;
            };
            self.fixes.push((begin_kw.start_offset(), begin_kw.end_offset(), b"loop do".to_vec()));
            self.fixes.push((end_kw.end_offset(), node_loc.end_offset(), Vec::new()));
        } else if closing_loc.is_none() {
            // Modifier form (`node.modifier_form?`: no `end` keyword at
            // all): `body while/until cond` -> `loop { body }` on one
            // line, or a fully reindented `loop do...end` block otherwise.
            let Some(stmts) = statements else { return };
            let node_start = node_loc.start_offset();
            let node_end = node_loc.end_offset();
            let (start_line, _) = self.idx.loc(node_start);
            let (end_line, _) = self.idx.loc(node_end.saturating_sub(1));
            let body_loc = stmts.location();
            let body_src = body_loc.as_slice();
            let replacement = if start_line == end_line {
                let mut r = b"loop { ".to_vec();
                r.extend_from_slice(body_src);
                r.extend_from_slice(b" }");
                r
            } else {
                // `Alignment#indentation(node)`: `node.loc.column`
                // synthetic spaces (always plain spaces, even over a
                // tab-indented original) plus the configured
                // `Layout/IndentationWidth`, reapplied to EVERY line of
                // the body (`body.source.gsub(/^/, indentation(node))`).
                let (_, node_col) = self.idx.loc(node_start); // 1-based
                let width = self.cfg.int("Layout/IndentationWidth", "Width");
                let synth_indent = " ".repeat((node_col - 1) + width);
                // The body's own source line's literal leading whitespace
                // (tabs and all) separates `loop do`/`end` from the
                // (already-reindented) body — the join separator in
                // `modifier_replacement`.
                let (body_line, _) = self.idx.loc(body_loc.start_offset());
                let line_start = self.idx.starts[body_line - 1];
                let mut ws_end = line_start;
                while ws_end < self.src.len() && matches!(self.src[ws_end], b' ' | b'\t') {
                    ws_end += 1;
                }
                let line_ws = &self.src[line_start..ws_end];

                let mut indented_body = Vec::new();
                for (i, line) in body_src.split(|&b| b == b'\n').enumerate() {
                    if i > 0 {
                        indented_body.push(b'\n');
                    }
                    indented_body.extend_from_slice(synth_indent.as_bytes());
                    indented_body.extend_from_slice(line);
                }

                let mut r = b"loop do\n".to_vec();
                r.extend_from_slice(line_ws);
                r.extend_from_slice(&indented_body);
                r.push(b'\n');
                r.extend_from_slice(line_ws);
                r.extend_from_slice(b"end");
                r
            };
            self.fixes.push((node_start, node_end, replacement));
        } else {
            // Regular `while cond [do] ... end` / `until cond [do] ... end`:
            // `while`/`until` through the `do` keyword (if any, else
            // through the condition) becomes `loop do`; the body and the
            // closing `end` are untouched.
            let end_off =
                do_keyword_loc.map(|d| d.end_offset()).unwrap_or_else(|| predicate.location().end_offset());
            self.fixes.push((kw_start, end_off, b"loop do".to_vec()));
        }
    }
}


/// `Style/OrAssignment`'s `{lvar ivar cvar gvar}` read-node whitelist —
/// prism's read-node `name()` already carries the sigil (`@foo`, `@@foo`,
/// `$foo`) exactly like whitequark's symbol, so a bare byte-slice comparison
/// across variable kinds can never collide (an ivar named `foo` reads as
/// `@foo`, never `foo`).
fn oa_read_name<'pr>(node: &ruby_prism::Node<'pr>) -> Option<&'pr [u8]> {
    if let Some(n) = node.as_local_variable_read_node() {
        return Some(n.name().as_slice());
    }
    if let Some(n) = node.as_instance_variable_read_node() {
        return Some(n.name().as_slice());
    }
    if let Some(n) = node.as_class_variable_read_node() {
        return Some(n.name().as_slice());
    }
    if let Some(n) = node.as_global_variable_read_node() {
        return Some(n.name().as_slice());
    }
    None
}

/// `Style/OrAssignment`'s `{lvasgn ivasgn cvasgn gvasgn}` write-node
/// whitelist, paired with the assigned value node
/// (`take_variable_and_default_from_unless`'s `node.if_branch`/
/// `node.else_branch` upstream).
fn oa_write_name_value<'pr>(node: &ruby_prism::Node<'pr>) -> Option<(&'pr [u8], ruby_prism::Node<'pr>)> {
    if let Some(n) = node.as_local_variable_write_node() {
        return Some((n.name().as_slice(), n.value()));
    }
    if let Some(n) = node.as_instance_variable_write_node() {
        return Some((n.name().as_slice(), n.value()));
    }
    if let Some(n) = node.as_class_variable_write_node() {
        return Some((n.name().as_slice(), n.value()));
    }
    if let Some(n) = node.as_global_variable_write_node() {
        return Some((n.name().as_slice(), n.value()));
    }
    None
}

/// `Style/OrAssignment` — checks for potential usage of the `||=` operator.
/// Upstream has two node matchers:
///
/// - `ternary_assignment?` + `on_lvasgn`/`on_ivasgn`/`on_cvasgn`/`on_gvasgn`:
///   `var = var ? var : default` and `var = if var; var; else; default; end`
///   — one shape in prism too, since a ternary is an `IfNode` with no
///   `if_keyword_loc` (see `check_or_assignment_write`, hooked from the four
///   `visit_*_variable_write_node`s).
/// - `unless_assignment?` + `on_if`: `unless var; var = default; end` and
///   `if var; else; var = default; end`. whitequark canonicalizes a real
///   `unless` into `(if cond nil body)`, so upstream's single `on_if` catches
///   both for free; prism gives `unless` its own dedicated `UnlessNode`, so
///   this needs two separate hooks below (`check_or_assignment_if` for the
///   `if`/empty-then/else shape, `check_or_assignment_unless` for the real
///   `unless` keyword AND modifier forms).
impl<'a> super::Cops<'a> {
    /// `ternary_assignment?` + `on_lvasgn` family: `write` is the whole
    /// write-node (`node.as_node()`), `name` its assigned variable (sigil
    /// included, e.g. `@foo`), `value` its RHS.
    pub(crate) fn check_or_assignment_write(
        &mut self,
        write: &ruby_prism::Node,
        name: &[u8],
        value: &ruby_prism::Node,
    ) {
        const COP: &str = "Style/OrAssignment";
        const MSG: &str = "Use the double pipe equals operator `||=` instead.";
        if !self.on(COP) {
            return;
        }
        let Some(iff) = value.as_if_node() else { return };
        if oa_read_name(&iff.predicate()) != Some(name) {
            return;
        }
        let Some(then_stmts) = iff.statements() else { return };
        let then_body = then_stmts.body();
        if then_body.len() != 1 || oa_read_name(&then_body.iter().next().unwrap()) != Some(name) {
            return;
        }
        // `return if else_branch.if_type?` — an `elsif` chain reuses this
        // position for another `IfNode` in prism's `subsequent()` too (no
        // `ElseNode` wrapper), so `as_else_node()` naturally excludes it.
        let Some(else_node) = iff.subsequent().and_then(|s| s.as_else_node()) else { return };
        let Some(else_stmts) = else_node.statements() else { return };

        let full = write.location();
        self.push(full.start_offset(), COP, true, MSG);

        let default_src = self.node_src(&else_stmts.as_node());
        let mut replacement = Vec::with_capacity(name.len() + 5 + default_src.len());
        replacement.extend_from_slice(name);
        replacement.extend_from_slice(b" ||= ");
        replacement.extend_from_slice(default_src);
        self.fixes.push((full.start_offset(), full.end_offset(), replacement));
    }

    /// `unless_assignment?` + `on_if`, the `if var; else; var = default; end`
    /// half — empty "then" branch (`nil?` on the if-branch position upstream)
    /// with a real `else`. The real `unless var; var = default; end` shape is
    /// `check_or_assignment_unless` below, since prism keeps `unless` as its
    /// own node type instead of canonicalizing into this `IfNode` shape.
    pub(crate) fn check_or_assignment_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Style/OrAssignment";
        const MSG: &str = "Use the double pipe equals operator `||=` instead.";
        if !self.on(COP) {
            return;
        }
        if node.statements().is_some() {
            return;
        }
        let predicate = node.predicate();
        let Some(pred_name) = oa_read_name(&predicate) else { return };
        // excludes `elsif` chains: those reuse this position for another
        // `IfNode`, not an `ElseNode`.
        let Some(else_node) = node.subsequent().and_then(|s| s.as_else_node()) else { return };
        let Some(else_stmts) = else_node.statements() else { return };
        let else_body = else_stmts.body();
        if else_body.len() != 1 {
            return;
        }
        let Some((wname, wvalue)) = oa_write_name_value(&else_body.iter().next().unwrap()) else {
            return;
        };
        if wname != pred_name {
            return;
        }

        let full = node.location();
        self.push(full.start_offset(), COP, true, MSG);

        let default_src = self.node_src(&wvalue);
        let mut replacement = Vec::with_capacity(pred_name.len() + 5 + default_src.len());
        replacement.extend_from_slice(pred_name);
        replacement.extend_from_slice(b" ||= ");
        replacement.extend_from_slice(default_src);
        self.fixes.push((full.start_offset(), full.end_offset(), replacement));
    }

    /// `unless_assignment?` + `on_if`, the real `unless var; var = default;
    /// end` half (keyword AND modifier forms — prism gives both a dedicated
    /// `UnlessNode`, unlike whitequark which canonicalizes them into the same
    /// `(if cond nil body)` shape `on_if` matches upstream). The assignment
    /// lives directly in `.statements()` (unless's primary/only body), NOT in
    /// an `else` slot — prism doesn't do whitequark's branch-flip
    /// canonicalization, so there is no `subsequent`/`else` lookup here.
    pub(crate) fn check_or_assignment_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Style/OrAssignment";
        const MSG: &str = "Use the double pipe equals operator `||=` instead.";
        if !self.on(COP) {
            return;
        }
        // a real `unless ... else ... end` flips which branch is nil in
        // whitequark's compiled `if` shape (the if-branch is no longer nil),
        // so upstream's pattern wouldn't match it either.
        if node.else_clause().is_some() {
            return;
        }
        let predicate = node.predicate();
        let Some(pred_name) = oa_read_name(&predicate) else { return };
        let Some(stmts) = node.statements() else { return };
        let body = stmts.body();
        if body.len() != 1 {
            return;
        }
        let Some((wname, wvalue)) = oa_write_name_value(&body.iter().next().unwrap()) else {
            return;
        };
        if wname != pred_name {
            return;
        }

        let full = node.location();
        self.push(full.start_offset(), COP, true, MSG);

        let default_src = self.node_src(&wvalue);
        let mut replacement = Vec::with_capacity(pred_name.len() + 5 + default_src.len());
        replacement.extend_from_slice(pred_name);
        replacement.extend_from_slice(b" ||= ");
        replacement.extend_from_slice(default_src);
        self.fixes.push((full.start_offset(), full.end_offset(), replacement));
    }
}


impl<'a> super::Cops<'a> {
    /// Style/EmptyMethod — port of rubocop's `EmptyMethod#on_def` (upstream
    /// aliases `on_defs` to the same handler; prism already unifies both
    /// into one `DefNode` with an optional `receiver`, so a single hook
    /// here covers both `def foo` and `def self.foo`). EnforcedStyle
    /// `compact` (default) wants an empty method collapsed onto one line;
    /// `expanded` wants the `end` pushed onto its own line. A def whose
    /// range covers a comment on any line is never "empty", even with an
    /// otherwise-nil body.
    pub(crate) fn check_empty_method(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/EmptyMethod";
        if !self.on(COP) {
            return;
        }
        if node.body().is_some() {
            return;
        }
        let loc = node.location();
        let start = loc.start_offset();
        let end = loc.end_offset();
        let (start_line, _) = self.idx.loc(start);
        let (end_line, _) = self.idx.loc(end.saturating_sub(1));
        // `processed_source.contains_comment?(node.source_range)`: any
        // comment on ANY line the node's range spans (not offset-precise —
        // a whole-line check), e.g. a blank-bodied def with `# baz` inside.
        if self.comments.iter().any(|&(l, _, _)| l >= start_line && l <= end_line) {
            return;
        }
        let compact_style = self.cfg.enforced_style(COP) != "expanded";
        let single_line = start_line == end_line;
        // `correct_style?`: `(compact? && single_line?) || (expanded? && multiline?)`
        // — already in the right shape, nothing to flag.
        if compact_style == single_line {
            return;
        }
        let message = if compact_style {
            "Put empty method definitions on a single line."
        } else {
            "Put the `end` of empty method definitions on the next line."
        };
        self.push(start, COP, true, message);

        let correction = em_corrected(self, node, compact_style, start);
        // `next if compact_style? && max_line_length && correction.size > max_line_length`
        // — offense still registered above, but the fix is withheld.
        if compact_style {
            if let Some(max) = self.em_max_line_length() {
                if correction.len() > max {
                    return;
                }
            }
        }
        self.fixes.push((start, end, correction));
    }

    /// `AutocorrectLogic#max_line_length`: `Layout/LineLength`'s raw
    /// config-file enablement (NOT this run's `--only`/`--except`-filtered
    /// `self.on`) gates whether a `Max` applies at all; when it does, an
    /// absent `Max` still defaults to 120. Same semantics as this file's
    /// `wum_max_line_length` (Style/WhileUntilModifier) — duplicated here
    /// since upstream's version lives on a cop-independent mixin, not
    /// something `EmptyMethod` itself owns.
    fn em_max_line_length(&self) -> Option<usize> {
        if !self.cfg.cop_config_enabled("Layout/LineLength") {
            return None;
        }
        Some(
            self.cfg
                .get("Layout/LineLength", "Max")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(120),
        )
    }
}

/// `corrected(node)` — `def #{scope}#{name}#{arguments}` then `joint(node)`
/// then `end`. `arguments` is rebuilt from each individual parameter node's
/// OWN source text joined with `, ` (rubocop's
/// `node.arguments.map(&:source).join(', ')`) — this deliberately does NOT
/// preserve the original parameter list's own line breaks/spacing even when
/// it spanned multiple physical lines; a live `rubocop -a` probe of
/// `def foo(abc: '10000',\n        def: '20000', ghi: '30000')\nend`
/// confirms the correction renormalizes to
/// `def foo(abc: '10000', def: '20000', ghi: '30000'); end`. Parameter
/// order follows Ruby's fixed grammar order (required, optional, rest,
/// post, keyword, keyword-rest, block), which is also prism's field layout
/// on `ParametersNode`, so walking the fields in that order reconstructs
/// the original written order. A totally empty parameter list — `def
/// foo()` — has NO `ParametersNode` at all in prism (unlike whitequark's
/// empty-but-present `args` node), so it naturally takes the "no
/// arguments" branch and its parens are dropped entirely, matching a live
/// probe of `def foo()\nend` -> `def foo; end`.
fn em_corrected(
    cops: &super::Cops,
    node: &ruby_prism::DefNode,
    compact_style: bool,
    def_start: usize,
) -> Vec<u8> {
    let mut out: Vec<u8> = b"def ".to_vec();
    if let Some(recv) = node.receiver() {
        out.extend_from_slice(cops.node_src(&recv));
        out.push(b'.');
    }
    out.extend_from_slice(node.name().as_slice());
    if let Some(params) = node.parameters() {
        let parts = em_ordered_params(&params);
        if !parts.is_empty() {
            let mut args: Vec<u8> = Vec::new();
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    args.extend_from_slice(b", ");
                }
                args.extend_from_slice(cops.node_src(p));
            }
            if node.lparen_loc().is_some() {
                out.push(b'(');
                out.extend_from_slice(&args);
                out.push(b')');
            } else {
                out.push(b' ');
                out.extend_from_slice(&args);
            }
        }
    }
    if compact_style {
        out.extend_from_slice(b"; end");
    } else {
        // `joint`: `"\n#{' ' * node.loc.column}"` — indent matches the
        // `def` keyword's own (0-based) column.
        out.push(b'\n');
        let col = cops.idx.loc(def_start).1 - 1;
        out.extend(std::iter::repeat(b' ').take(col));
        out.extend_from_slice(b"end");
    }
    out
}

/// Parameters in the order they were originally written. Ruby's grammar
/// fixes this order (required, optional, rest, post, keyword,
/// keyword-rest, block) — no other arrangement parses — and it's also the
/// field layout prism exposes on `ParametersNode`, so visiting the fields
/// in this order reproduces source order exactly.
fn em_ordered_params<'pr>(params: &ruby_prism::ParametersNode<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    let mut out = Vec::new();
    out.extend(params.requireds().iter());
    out.extend(params.optionals().iter());
    if let Some(r) = params.rest() {
        out.push(r);
    }
    out.extend(params.posts().iter());
    out.extend(params.keywords().iter());
    if let Some(kr) = params.keyword_rest() {
        out.push(kr);
    }
    if let Some(b) = params.block() {
        out.push(b.as_node());
    }
    out
}


impl<'a> super::Cops<'a> {
    /// Style/HashAsLastArrayItem — hooked from `visit_array_node` rather than
    /// mirroring upstream's `on_hash` (which walks EVERY hash node and asks
    /// "am I the containing array's last value?" via a `parent` back-link).
    /// Prism nodes carry no parent pointer, but the cop only ever fires on
    /// the array's OWN last element, so starting from the array and looking
    /// at `elements().last()` is behaviorally identical and needs no
    /// back-link at all.
    ///
    /// A second structural split: whitequark's parser gives both `{ a: 1 }`
    /// and a braceless `a: 1` the SAME `:hash` node type, distinguished only
    /// by `#braces?`. Prism instead uses two distinct node kinds —
    /// `HashNode` (always braced: `opening_loc`/`closing_loc` are
    /// non-optional fields) and `KeywordHashNode` (always braceless, no
    /// brace locations at all) — so `hali_braced` below stands in for
    /// upstream's `braces?` test across both.
    pub(crate) fn check_hash_as_last_array_item(&mut self, array: &ruby_prism::ArrayNode) {
        const COP: &str = "Style/HashAsLastArrayItem";
        if !self.on(COP) {
            return;
        }

        let elements: Vec<ruby_prism::Node> = array.elements().iter().collect();
        let Some(last) = elements.last() else { return };

        // Only a hash-like (braced or braceless) last element is ever in
        // play — anything else can't be an offense site.
        let Some(last_braced) = hali_braced(last) else { return };

        // `return if node.children.first&.kwsplat_type?` — a lone `**splat`
        // (or a `**splat` written first among pairs) is exempt regardless of
        // style, e.g. `[1, **options]`.
        let last_elements: Vec<ruby_prism::Node> = hali_elements(last);
        if last_elements.first().is_some_and(|e| e.as_assoc_splat_node().is_some()) {
            return;
        }

        // `explicit_array?` — an implicit array (e.g. the right-hand side of
        // a multiple assignment) can never have an "unbraced" hash flagged.
        if array.opening_loc().is_none() {
            return;
        }

        let braces_style = self.cfg.enforced_style(COP) != "no_braces";

        // `expected_braced_last_array_item?`: bail if the array is made ENTIRELY
        // of hashes already matching the enforced style (the cop's "ignore
        // arrays where multiple items are all hashes" note), or if the
        // second-to-last item is itself hash-like (only a non-hash
        // second-to-last item allows the last one to be judged at all).
        let all_already_conforming =
            elements.iter().all(|e| hali_braced(e).is_some_and(|b| b == braces_style));
        if all_already_conforming {
            return;
        }
        let n = elements.len();
        let second_last_is_hash = n >= 2 && hali_braced(&elements[n - 2]).is_some();
        if second_last_is_hash {
            return;
        }
        // `array.values.last.equal?(node)` is trivially true here since
        // `last` — by construction — IS `elements.last()`.

        let loc = last.location();
        let start = loc.start_offset();
        let end = loc.end_offset();

        if braces_style {
            if last_braced {
                return; // `return if node.braces?`
            }
            self.push(start, COP, true, "Wrap hash in `{` and `}`.");

            // `node.single_line? || same_line?(node, node.parent)`
            let last_char = if end > start { end - 1 } else { start };
            let single_line = self.idx.loc(start).0 == self.idx.loc(last_char).0;
            let same_line_as_array =
                self.idx.loc(start).0 == self.idx.loc(array.location().start_offset()).0;

            if single_line || same_line_as_array {
                self.fixes.push((start, start, b"{".to_vec()));
                self.fixes.push((end, end, b"}".to_vec()));
            } else {
                // `indent(node)` = `' ' * node.loc.column` (0-based).
                let col = self.idx.loc(start).1 - 1;
                let indent = " ".repeat(col);
                let mut open = b"{\n".to_vec();
                open.extend_from_slice(indent.as_bytes());
                let mut close = b"\n".to_vec();
                close.extend_from_slice(indent.as_bytes());
                close.push(b'}');
                self.fixes.push((start, start, open));
                self.fixes.push((end, end, close));
            }
        } else {
            if !last_braced {
                return; // `return unless node.braces?`
            }
            if last_elements.is_empty() {
                return; // "Empty hash cannot be unbraced"
            }
            self.push(start, COP, true, "Omit the braces around the hash.");

            // `remove_last_element_trailing_comma`: from the end of the hash
            // (== the array's last element), skip horizontal whitespace then
            // any run of newlines (`range_with_surrounding_space(...,
            // side: :right)`'s default `newlines: true`), and remove the
            // single byte landed on if it's a comma.
            let mut pos = end;
            while matches!(self.src.get(pos), Some(b' ' | b'\t')) {
                pos += 1;
            }
            while matches!(self.src.get(pos), Some(b'\n')) {
                pos += 1;
            }
            if self.src.get(pos) == Some(&b',') {
                self.fixes.push((pos, pos + 1, Vec::new()));
            }

            let hash_node = last.as_hash_node().expect("last_braced implies HashNode");
            let open = hash_node.opening_loc();
            let close = hash_node.closing_loc();
            self.fixes.push((open.start_offset(), open.end_offset(), Vec::new()));
            self.fixes.push((close.start_offset(), close.end_offset(), Vec::new()));
        }
    }
}

/// `node.hash_type? && braces?`-equivalent: `Some(true)` for an explicit
/// `{...}` `HashNode`, `Some(false)` for a braceless `KeywordHashNode`,
/// `None` for anything else.
fn hali_braced(node: &ruby_prism::Node) -> Option<bool> {
    if node.as_hash_node().is_some() {
        Some(true)
    } else if node.as_keyword_hash_node().is_some() {
        Some(false)
    } else {
        None
    }
}

/// The hash-like node's own pairs, uniformly across `HashNode` and
/// `KeywordHashNode` — empty (not a panic) for anything else, since callers
/// only ever invoke this after `hali_braced` already confirmed the kind.
fn hali_elements<'pr>(node: &ruby_prism::Node<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    if let Some(h) = node.as_hash_node() {
        h.elements().iter().collect()
    } else if let Some(h) = node.as_keyword_hash_node() {
        h.elements().iter().collect()
    } else {
        Vec::new()
    }
}


impl<'a> super::Cops<'a> {
    /// Style/RedundantAssignment — a def body (or one of its tail branches)
    /// whose last two statements are `x = expr` immediately followed by a
    /// bare read of `x`: the assignment is dead, since the method's return
    /// value would be `expr` either way. Ported from rubocop's
    /// `check_branch`, which recurses into begin/if-else/case/rescue/ensure
    /// tails of the def body — the last statement of any of those container
    /// types is itself a further tail position to check.
    pub(crate) fn check_redundant_assignment(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Style/RedundantAssignment";
        if !self.on(COP) {
            return;
        }
        if let Some(b) = node.body() {
            self.ra_branch(&b);
        }
    }

    /// Mirrors rubocop's `check_branch`/`check_*_node` family. Each of these
    /// node types is a "tail position container": whatever ends up last in
    /// one of its branches is, transitively, the def's own tail position.
    fn ra_branch(&mut self, node: &ruby_prism::Node) {
        if let Some(stmts) = node.as_statements_node() {
            self.ra_check_statements(&stmts);
        } else if let Some(c) = node.as_case_node() {
            for w in c.conditions().iter() {
                if let Some(w) = w.as_when_node() {
                    if let Some(s) = w.statements() {
                        self.ra_branch(&s.as_node());
                    }
                }
            }
            if let Some(s) = c.else_clause().and_then(|e| e.statements()) {
                self.ra_branch(&s.as_node());
            }
        } else if let Some(c) = node.as_case_match_node() {
            for i in c.conditions().iter() {
                if let Some(i) = i.as_in_node() {
                    if let Some(s) = i.statements() {
                        self.ra_branch(&s.as_node());
                    }
                }
            }
            if let Some(s) = c.else_clause().and_then(|e| e.statements()) {
                self.ra_branch(&s.as_node());
            }
        } else if let Some(i) = node.as_if_node() {
            // Skip ternaries (no `if` keyword) and modifier-form `if`/`elsif`
            // (no `end` keyword) — rubocop's `node.modifier_form? ||
            // node.ternary?`.
            if i.if_keyword_loc().is_none() || i.end_keyword_loc().is_none() {
                return;
            }
            if let Some(s) = i.statements() {
                self.ra_branch(&s.as_node());
            }
            if let Some(sub) = i.subsequent() {
                self.ra_branch(&sub); // ElseNode, or the elsif's IfNode
            }
        } else if let Some(u) = node.as_unless_node() {
            if u.end_keyword_loc().is_none() {
                return; // modifier-form `unless`
            }
            if let Some(s) = u.statements() {
                self.ra_branch(&s.as_node());
            }
            if let Some(s) = u.else_clause().and_then(|e| e.statements()) {
                self.ra_branch(&s.as_node());
            }
        } else if let Some(e) = node.as_else_node() {
            // Reached via an `if`/`unless`'s `subsequent()` — that's just a
            // bare `Node`, not routed through the case/case_match/if/unless
            // `else_clause()` accessors above.
            if let Some(s) = e.statements() {
                self.ra_branch(&s.as_node());
            }
        } else if let Some(b) = node.as_begin_node() {
            if let Some(ens) = b.ensure_clause() {
                // rubocop's `check_ensure_node` only descends into the
                // `ensure` branch itself — the protected body and any
                // rescue clauses are never visited when `ensure` is
                // present (verified live: `x = 2; x; ensure; 3; end`
                // reports no offense for the protected body).
                if let Some(s) = ens.statements() {
                    self.ra_branch(&s.as_node());
                }
            } else if let Some(r) = b.rescue_clause() {
                // rubocop's `check_rescue_node` walks ALL child nodes of
                // the `rescue` node unconditionally — the protected body,
                // every rescue clause, and an `else` clause if present —
                // even though the body isn't really a tail position when
                // there's a rescue-`else` (verified live).
                if let Some(s) = b.statements() {
                    self.ra_branch(&s.as_node());
                }
                let mut cur = Some(r);
                while let Some(rn) = cur {
                    if let Some(s) = rn.statements() {
                        self.ra_branch(&s.as_node());
                    }
                    cur = rn.subsequent();
                }
                if let Some(s) = b.else_clause().and_then(|e| e.statements()) {
                    self.ra_branch(&s.as_node());
                }
            } else if let Some(s) = b.statements() {
                // Bare `begin...end` grouping (rubocop's `:kwbegin`).
                self.ra_branch(&s.as_node());
            }
        }
    }

    /// The actual pattern check (rubocop's `check_begin_node`): if the last
    /// two statements are `lvasgn` then a same-named `lvar`, that's the
    /// offense; otherwise recurse into just the last statement, since only
    /// the tail position matters transitively.
    fn ra_check_statements(&mut self, stmts: &ruby_prism::StatementsNode) {
        const COP: &str = "Style/RedundantAssignment";
        let body: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        if body.len() >= 2 {
            if let (Some(asgn), Some(read)) = (
                body[body.len() - 2].as_local_variable_write_node(),
                body[body.len() - 1].as_local_variable_read_node(),
            ) {
                if asgn.name().as_slice() == read.name().as_slice() {
                    let al = asgn.location();
                    self.push(
                        al.start_offset(),
                        COP,
                        true,
                        "Redundant assignment before returning detected.",
                    );
                    let expr = asgn.value();
                    self.fixes.push((
                        al.start_offset(),
                        al.end_offset(),
                        self.node_src(&expr).to_vec(),
                    ));
                    let rl = read.location();
                    self.fixes.push((rl.start_offset(), rl.end_offset(), Vec::new()));
                    return;
                }
            }
        }
        if let Some(last) = body.last() {
            self.ra_branch(last);
        }
    }
}
