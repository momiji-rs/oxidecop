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

