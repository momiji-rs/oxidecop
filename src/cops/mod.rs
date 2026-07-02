//! The cop engine: the `Cops` visitor (shared state + cross-cutting helpers),
//! a THIN `Visit` impl that dispatches into per-department modules
//! (`style`/`naming`/`lint`/`layout`), and the `lint()` entry point.
mod layout;
mod lint_cops;
mod naming;
mod style;

use crate::config::{parse_allowed_list, Config, SCHEMA};
use crate::declarative::{render, Anchor, DECLARATIVE};
use crate::nodepattern::{self, Pat};
use ruby_prism::Visit;
use std::collections::{HashMap, HashSet};

pub struct Offense {
    pub line: usize,
    pub col: usize,
    pub cop: &'static str,
    pub correctable: bool,
    pub message: String,
}

pub struct LineIndex {
    pub(crate) starts: Vec<usize>,
}
impl LineIndex {
    pub fn new(src: &[u8]) -> Self {
        let mut starts = vec![0usize];
        for (i, &b) in src.iter().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineIndex { starts }
    }
    pub fn loc(&self, off: usize) -> (usize, usize) {
        let line = match self.starts.binary_search(&off) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (line + 1, off - self.starts[line] + 1)
    }
}

/// An autocorrect edit: (start_byte, end_byte, replacement).
pub type Fix = (usize, usize, Vec<u8>);

pub struct LintResult {
    pub offenses: Vec<Offense>,
    pub fixes: Vec<Fix>,
}

pub(crate) struct Cops<'a> {
    pub(crate) src: &'a [u8],
    pub(crate) idx: &'a LineIndex,
    pub(crate) cfg: &'a Config,
    pub(crate) comment_lines: HashSet<usize>,
    pub(crate) offenses: Vec<Offense>,
    // autocorrect edits: applied right-to-left so earlier offsets stay valid —
    // exactly how rubocop's Corrector composes source rewrites off the AST
    // source-ranges.
    pub(crate) fixes: Vec<Fix>,
    // DECLARATIVE cops: (parsed pattern, cop name, message). Built once from
    // the DECLARATIVE table — the cop "logic" is entirely in the pattern.
    pub(crate) decl: Vec<(Pat, &'static str, &'static str, Anchor, Option<&'static str>)>,
    // Cross-cutting exemptions, mirroring rubocop's `AllowedMethods` mixin: a cop
    // consults `allowed(cop, text)` to suppress an offense whose relevant string
    // (a method name, a source line, …) is either an exact `AllowedMethods` entry
    // or matches an `AllowedPatterns` regex.
    pub(crate) allowed_patterns: HashMap<String, Vec<regex::Regex>>,
    pub(crate) allowed_methods: HashMap<String, Vec<String>>,
    // Enclosing call/block method names (outermost first), maintained around the
    // manual recursion in `visit_call_node`. Lets cops consult ancestors (e.g.
    // Style/NumericPredicate's AllowedMethods on a wrapping `where(...)`, and its
    // `!x.zero?` negation) without a parent pointer.
    pub(crate) call_stack: Vec<Vec<u8>>,
    // Ancestor counters for Lint/NestedMethodDefinition: how many enclosing
    // `def`s, and how many enclosing "scoping" blocks/sclass (Class.new,
    // instance_eval, class << self, AllowedMethods, …). A nested def is an
    // offense iff def_depth >= 1 and scoping_depth == 0.
    pub(crate) def_depth: usize,
    pub(crate) scoping_depth: usize,
    // Inside a `#{...}` interpolation (rubocop's `inside_interpolation?`) —
    // string-literal style is not enforced there.
    pub(crate) interp_depth: usize,
    // Node spans claimed by a multiline string-concat check (rubocop's
    // `ignore_node`): individual strings inside are exempt from on_str.
    pub(crate) str_ignore: Vec<(usize, usize)>,
    // Numeric literals already checked as part of a folded `-@` call.
    pub(crate) num_ignore: Vec<usize>,
    // Heredoc BODIES as (first line, last line, delimiter) — terminator
    // excluded. Layout/TrailingWhitespace and Layout/LineLength consult these.
    pub(crate) heredoc_lines: Vec<(usize, usize, Vec<u8>)>,
    // The `__END__` line — nothing at or after it is lintable text.
    pub(crate) data_line: Option<usize>,
    // Per enclosing body (program/class/module/def), the names of classes
    // defined as its direct children — Naming/MethodName's "class emitter
    // method" exemption consults this.
    pub(crate) class_children_stack: Vec<Vec<Vec<u8>>>,
    // Every comment as (line, start_offset, text), in source order.
    pub(crate) comments: &'a [(usize, usize, Vec<u8>)],
    // Enclosing class/module names (their constant-path sources) — the
    // qualified identifier in Style/Documentation messages.
    pub(crate) mod_stack: Vec<String>,
    // Whether each enclosing class/module carried `#:nodoc: all`.
    pub(crate) nodoc_all_stack: Vec<bool>,
}
impl<'a> Cops<'a> {
    pub(crate) fn on(&self, cop: &str) -> bool {
        if !self.cfg.enabled(cop) {
            return false;
        }
        // rubocop raises on an EnforcedStyle outside SupportedStyles and the
        // file yields no offenses; the closest equivalent is disabling the cop.
        if let Some(v) = self.cfg.param(cop, "EnforcedStyle") {
            if let Some(s) = crate::config::schema(cop) {
                if !s.styles.is_empty() && !s.styles.contains(&v) {
                    return false;
                }
            }
        }
        true
    }
    /// Is `text` exempt for `cop` via AllowedMethods (exact) or AllowedPatterns?
    pub(crate) fn allowed(&self, cop: &str, text: &[u8]) -> bool {
        let s = String::from_utf8_lossy(text);
        let by_name = self
            .allowed_methods
            .get(cop)
            .is_some_and(|names| names.iter().any(|n| n.as_bytes() == text));
        let by_pattern = self
            .allowed_patterns
            .get(cop)
            .is_some_and(|pats| pats.iter().any(|re| re.is_match(&s)));
        by_name || by_pattern
    }
    pub(crate) fn push(&mut self, off: usize, cop: &'static str, correctable: bool, msg: impl Into<String>) {
        let (line, col) = self.idx.loc(off);
        self.offenses.push(Offense { line, col, cop, correctable, message: msg.into() });
    }
    pub(crate) fn node_src(&self, n: &ruby_prism::Node) -> &'a [u8] {
        let l = n.location();
        &self.src[l.start_offset()..l.end_offset()]
    }
    /// Names of `class` nodes that are direct children of `body`.
    fn direct_child_classes(body: &Option<ruby_prism::Node>) -> Vec<Vec<u8>> {
        body.as_ref()
            .and_then(|b| b.as_statements_node())
            .map(|stmts| {
                stmts
                    .body()
                    .iter()
                    .filter_map(|n| n.as_class_node().map(|c| c.name().as_slice().to_vec()))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// AllowComments guard: skip when enabled and a comment sits inside the block
    /// body (opening line through the line before the closer, so a trailing
    /// `end # comment` doesn't count).
    pub(crate) fn block_has_inner_comment(&self, open: usize, close: usize) -> bool {
        let l0 = self.idx.loc(open).0;
        let l1 = self.idx.loc(close).0;
        (l0..l1).any(|ln| self.comment_lines.contains(&ln))
    }
}

impl<'pr, 'a> Visit<'pr> for Cops<'a> {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        self.check_string_literals(node);
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        // `'a' \` line-continuation concatenation parses as this node with
        // quoted string parts — the ConsistentQuotesInMultiline check.
        self.check_string_concat(node);
        ruby_prism::visit_interpolated_string_node(self, node);
    }
    fn visit_embedded_statements_node(&mut self, node: &ruby_prism::EmbeddedStatementsNode<'pr>) {
        self.interp_depth += 1;
        ruby_prism::visit_embedded_statements_node(self, node);
        self.interp_depth -= 1;
    }
    fn visit_program_node(&mut self, node: &ruby_prism::ProgramNode<'pr>) {
        self.class_children_stack.push(Self::direct_child_classes(&Some(node.statements().as_node())));
        ruby_prism::visit_program_node(self, node);
        self.class_children_stack.pop();
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.check_documentation("class", node.location().start_offset(), &node.constant_path(), node.body());
        self.enter_namespace(node.location().start_offset(), &node.constant_path());
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        // Default walk — covers the superclass expression too, not just the body.
        ruby_prism::visit_class_node(self, node);
        self.class_children_stack.pop();
        self.leave_namespace();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.check_documentation("module", node.location().start_offset(), &node.constant_path(), node.body());
        self.enter_namespace(node.location().start_offset(), &node.constant_path());
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        ruby_prism::visit_module_node(self, node);
        self.class_children_stack.pop();
        self.leave_namespace();
    }
    fn visit_integer_node(&mut self, node: &ruby_prism::IntegerNode<'pr>) {
        if !self.num_ignore.contains(&node.location().start_offset()) {
            self.check_numeric_literals(&node.as_node());
        }
    }
    fn visit_float_node(&mut self, node: &ruby_prism::FloatNode<'pr>) {
        if !self.num_ignore.contains(&node.location().start_offset()) {
            self.check_numeric_literals(&node.as_node());
        }
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        self.check_method_name_def(node);
        self.check_nested_method_definition(node);
        self.check_redundant_return(node);
        // Default walk (receiver, params, body) one def level deeper — matches
        // rubocop's each_ancestor(:def) semantics, and covers offenses in
        // parameter default values, which a body-only walk silently skipped.
        self.def_depth += 1;
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        ruby_prism::visit_def_node(self, node);
        self.class_children_stack.pop();
        self.def_depth -= 1;
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        if let Some((off, msg)) = self.symbol_proc_lambda(node) {
            self.push(off, "Style/SymbolProc", true, msg);
        }
        // `->` is a lambda literal — rubocop reaches it via the `lambda` send.
        if self.on("Style/RedundantReturn") {
            if let Some(b) = node.body() {
                self.rr_branch(&b);
            }
        }
        ruby_prism::visit_lambda_node(self, node);
    }
    fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
        if let Some(b) = node.block() {
            let has_args = node.arguments().is_some_and(|a| a.arguments().iter().count() > 0);
            if let Some((off, msg)) = self.symbol_proc_super(&b, has_args) {
                self.push(off, "Style/SymbolProc", true, msg);
            }
        }
        ruby_prism::visit_super_node(self, node);
    }
    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        if let Some(b) = node.block() {
            if let Some((off, msg)) = self.symbol_proc_super(&b.as_node(), false) {
                self.push(off, "Style/SymbolProc", true, msg);
            }
        }
        ruby_prism::visit_forwarding_super_node(self, node);
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        // The expression (`class << HERE`) is outside the scoping context.
        self.visit(&node.expression());
        // `class << self` is a scoping context — nested defs inside are allowed.
        self.scoping_depth += 1;
        if let Some(b) = node.body() {
            self.visit(&b);
        }
        self.scoping_depth -= 1;
    }
    fn visit_alias_method_node(&mut self, node: &ruby_prism::AliasMethodNode<'pr>) {
        self.check_method_name_alias(node);
        ruby_prism::visit_alias_method_node(self, node);
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        // The parser gem folds unary minus into a numeric literal; prism keeps
        // the `-@` call when the sign is separated from the digits. Emulate
        // the fold so the offense span starts at the `-`.
        if node.name().as_slice() == b"-@" && node.arguments().is_none() {
            if let Some(r) = node.receiver() {
                if r.as_integer_node().is_some() || r.as_float_node().is_some() {
                    self.check_numeric_literals(&node.as_node());
                    self.num_ignore.push(r.location().start_offset());
                }
            }
        }
        self.check_method_name_macros(node);
        // Run every DECLARATIVE send-pattern against this call. The cop is data.
        let n = node.as_node();
        let node_off = node.location().start_offset();
        let op_off = node.message_loc().map(|l| l.start_offset()).unwrap_or(node_off);
        let recv_op_off = node
            .receiver()
            .and_then(|r| r.as_call_node().and_then(|c| c.message_loc()))
            .map(|l| l.start_offset())
            .unwrap_or(node_off);
        for i in 0..self.decl.len() {
            let (pat, cop, msg, anchor, style) = &self.decl[i];
            if !self.on(cop) {
                continue;
            }
            // EnforcedStyle gate: a style-specific row fires only under its style.
            if let Some(s) = style {
                if self.cfg.enforced_style(cop) != *s {
                    continue;
                }
            }
            if let Some(caps) = nodepattern::matches(pat, &n, self.src) {
                let (cop, msg) = (*cop, *msg);
                let off = match anchor {
                    Anchor::Op => op_off,
                    Anchor::Node => node_off,
                    Anchor::RecvOp => recv_op_off,
                };
                self.push(off, cop, false, render(msg, &caps));
            }
        }
        self.check_zero_length(node);
        // Style/RedundantReturn also fires for method-defining blocks
        // (rubocop's RESTRICT_ON_SEND: define_method & friends, lambda).
        if self.on("Style/RedundantReturn")
            && matches!(node.name().as_slice(), b"define_method" | b"define_singleton_method" | b"lambda")
        {
            if let Some(body) = node.block().and_then(|b| b.as_block_node()).and_then(|b| b.body()) {
                self.rr_branch(&body);
            }
        }
        // Style/NumericPredicate (imperative: message interpolates a constructed
        // suggestion). Uses call_stack for AllowedMethods-on-ancestor + negation.
        if let Some((off, msg)) = self.numeric_predicate(node) {
            self.push(off, "Style/NumericPredicate", true, msg);
        }
        if let Some((off, msg)) = self.symbol_proc(node) {
            self.push(off, "Style/SymbolProc", true, msg);
        }
        // recurse into children (we've overridden the default walk). Push this
        // call's name so descendants can see it as an ancestor.
        self.call_stack.push(node.name().as_slice().to_vec());
        if let Some(r) = node.receiver() {
            self.visit(&r);
        }
        if let Some(a) = node.arguments() {
            for arg in a.arguments().iter() {
                self.visit(&arg);
            }
        }
        if let Some(b) = node.block() {
            // A block is "scoping" (allows nested defs) if it's a class
            // constructor, an (instance|class|module)_(eval|exec), or its method
            // is in AllowedMethods.
            let scoping = self.on("Lint/NestedMethodDefinition")
                && (lint_cops::is_eval_exec(node)
                    || lint_cops::is_class_constructor(node, self.src)
                    || self.allowed("Lint/NestedMethodDefinition", node.name().as_slice()));
            if scoping {
                self.scoping_depth += 1;
            }
            self.visit(&b);
            if scoping {
                self.scoping_depth -= 1;
            }
        }
        self.call_stack.pop();
    }
}

/// Lint one file: run the text-based cops and the AST visitor, return sorted
/// offenses + autocorrect edits. Pure — no I/O; the caller owns file reading,
/// config discovery, and output formatting.
pub fn lint(src: &[u8], cfg: &Config) -> LintResult {
    let result = ruby_prism::parse(src);
    let idx = LineIndex::new(src);

    let mut comment_lines = HashSet::new();
    // Every comment as (line, start_offset, text) in source order — the
    // "comment tokens" FrozenStringLiteralComment reasons about.
    let mut comment_data: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for c in result.comments() {
        let l = c.location();
        let line = idx.loc(l.start_offset()).0;
        comment_lines.insert(line);
        comment_data.push((line, l.start_offset(), src[l.start_offset()..l.end_offset()].to_vec()));
    }
    // The line of the first real code token — comments before it are the
    // "leading comment lines" magic comments live in (rubocop's mixin).
    let first_code_line = result
        .node()
        .as_program_node()
        .and_then(|p| p.statements().body().iter().next().map(|n| idx.loc(n.location().start_offset()).0));

    let decl: Vec<(Pat, &'static str, &'static str, Anchor, Option<&'static str>)> = DECLARATIVE
        .iter()
        .map(|(p, cop, msg, a, style)| (nodepattern::parse(p), *cop, *msg, *a, *style))
        .collect();

    // Compile each cop's AllowedPatterns once (invalid regexes dropped); collect
    // AllowedMethods as exact-name lists. Both back `Cops::allowed`.
    let mut allowed_patterns: HashMap<String, Vec<regex::Regex>> = HashMap::new();
    let mut allowed_methods: HashMap<String, Vec<String>> = HashMap::new();
    for (sec, kv) in &cfg.sections {
        if let Some(v) = kv.get("AllowedPatterns") {
            let pats = parse_allowed_list(v)
                .into_iter()
                .filter_map(|p| regex::Regex::new(&p).ok())
                .collect();
            allowed_patterns.insert(sec.clone(), pats);
        }
        if let Some(v) = kv.get("AllowedMethods") {
            allowed_methods.insert(sec.clone(), parse_allowed_list(v));
        }
    }
    // Seed schema-default AllowedMethods for cops the config didn't set them on
    // (rubocop's config/default.yml ships some, e.g. Style/SymbolProc).
    for s in SCHEMA {
        if !s.allowed_methods.is_empty() && !allowed_methods.contains_key(s.cop) {
            allowed_methods.insert(s.cop.to_string(), s.allowed_methods.iter().map(|m| m.to_string()).collect());
        }
    }

    // Heredoc body line ranges, for Layout/TrailingWhitespace.
    let mut hd = HeredocFinder { idx: &idx, ranges: Vec::new() };
    hd.visit(&result.node());
    let heredoc_lines = hd.ranges;

    let mut cops = Cops {
        src,
        idx: &idx,
        cfg,
        comment_lines,
        offenses: Vec::new(),
        fixes: Vec::new(),
        decl,
        allowed_patterns,
        allowed_methods,
        call_stack: Vec::new(),
        def_depth: 0,
        scoping_depth: 0,
        interp_depth: 0,
        str_ignore: Vec::new(),
        num_ignore: Vec::new(),
        heredoc_lines,
        data_line: result.data_loc().map(|l| idx.loc(l.start_offset()).0),
        class_children_stack: Vec::new(),
        comments: &comment_data,
        mod_stack: Vec::new(),
        nodoc_all_stack: Vec::new(),
    };

    // ---- text-based cops ----
    cops.check_frozen_string_literal(first_code_line);
    cops.check_line_length();
    cops.check_trailing_whitespace();

    // ---- AST-based cops ----
    cops.visit(&result.node());

    let mut offenses = cops.offenses;
    apply_disable_directives(&mut offenses, &comment_data, src, &idx);
    offenses.sort_by(|a, b| (a.line, a.col, a.cop).cmp(&(b.line, b.col, b.cop)));
    LintResult { offenses, fixes: cops.fixes }
}

/// Collects the inclusive line ranges of heredoc bodies (terminator line
/// excluded), mirroring rubocop's `extract_heredocs`.
struct HeredocFinder<'a> {
    idx: &'a LineIndex,
    ranges: Vec<(usize, usize, Vec<u8>)>,
}
impl<'a> HeredocFinder<'a> {
    fn add_span(&mut self, start: usize, end: usize, closing: Option<ruby_prism::Location>) {
        let delim: Vec<u8> = closing
            .map(|c| {
                c.as_slice()
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect()
            })
            .unwrap_or_default();
        if start < end {
            self.ranges.push((self.idx.loc(start).0, self.idx.loc(end - 1).0, delim));
        }
    }
}
impl<'pr, 'a> Visit<'pr> for HeredocFinder<'a> {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        if node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) {
            let c = node.content_loc();
            self.add_span(c.start_offset(), c.end_offset(), node.closing_loc());
        }
    }
    fn visit_x_string_node(&mut self, node: &ruby_prism::XStringNode<'pr>) {
        if node.opening_loc().as_slice().starts_with(b"<<") {
            let c = node.content_loc();
            self.add_span(c.start_offset(), c.end_offset(), Some(node.closing_loc()));
        }
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        if node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<")) {
            if let (Some(first), Some(close)) = (node.parts().iter().next(), node.closing_loc()) {
                self.add_span(first.location().start_offset(), close.start_offset(), node.closing_loc());
            }
        }
        // keep walking — interpolations can nest further heredocs
        ruby_prism::visit_interpolated_string_node(self, node);
    }
}

/// Honor `# rubocop:disable Cop[, Cop…]` / `rubocop:todo` / `rubocop:enable`
/// comments: a trailing directive covers its own line; a standalone one opens
/// a range until the matching `enable` (inclusive) or EOF. `all` and bare
/// department names (`Style`) are supported.
fn apply_disable_directives(
    offenses: &mut Vec<Offense>,
    comments: &[(usize, usize, Vec<u8>)],
    src: &[u8],
    idx: &LineIndex,
) {
    let re = {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^#\s*rubocop\s*:\s*(disable|todo|enable)\s+(\S.*?)\s*$").unwrap())
    };
    // (cops: None = all, from, to)
    let mut ranges: Vec<(Option<Vec<String>>, usize, usize)> = Vec::new();
    let mut open: Vec<(Option<Vec<String>>, usize)> = Vec::new();
    let eof = idx.starts.len();
    for (line, off, text) in comments {
        let t = String::from_utf8_lossy(text);
        let Some(c) = re.captures(&t) else { continue };
        let list: Option<Vec<String>> = if c[2].trim() == "all" {
            None
        } else {
            Some(c[2].split(',').map(|s| s.trim().to_string()).collect())
        };
        let standalone = src[idx.starts[line - 1]..*off].iter().all(|b| b.is_ascii_whitespace());
        match &c[1] {
            "enable" => {
                // Close every open range this enable covers.
                let mut i = 0;
                while i < open.len() {
                    let covered = match (&list, &open[i].0) {
                        (None, _) => true,
                        (Some(en), None) => en.iter().any(|e| e == "all"),
                        (Some(en), Some(dis)) => dis.iter().all(|d| en.contains(d)),
                    };
                    if covered {
                        let (cops_list, from) = open.remove(i);
                        ranges.push((cops_list, from, *line));
                    } else {
                        i += 1;
                    }
                }
            }
            _ => {
                // disable | todo
                if standalone {
                    open.push((list, *line));
                } else {
                    ranges.push((list, *line, *line));
                }
            }
        }
    }
    for (list, from) in open {
        ranges.push((list, from, eof));
    }
    if ranges.is_empty() {
        return;
    }
    let covers = |entry: &str, cop: &str| entry == cop || cop.starts_with(&format!("{entry}/"));
    offenses.retain(|o| {
        !ranges.iter().any(|(cops_list, from, to)| {
            o.line >= *from
                && o.line <= *to
                && cops_list.as_ref().is_none_or(|cs| cs.iter().any(|c| covers(c, o.cop)))
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offenses(src: &str, cfg: &str) -> Vec<(usize, usize, &'static str)> {
        let cfg = Config::parse(cfg);
        lint(src.as_bytes(), &cfg)
            .offenses
            .iter()
            .map(|o| (o.line, o.col, o.cop))
            .collect()
    }

    const NUMERIC_ONLY: &str =
        "AllCops:\n  DisabledByDefault: true\nStyle/NumericLiterals:\n  Enabled: true\n";

    // Regression: manual recursion used to visit only `body`, silently skipping
    // parameter default values, superclass expressions, and lambda parameters.
    #[test]
    fn visits_def_parameter_defaults() {
        let got = offenses("def f(x = 1000000)\n  x\nend\n", NUMERIC_ONLY);
        assert_eq!(got, vec![(1, 11, "Style/NumericLiterals")]);
    }

    #[test]
    fn visits_class_superclass_expression() {
        let got = offenses("class Foo < Bar.make(2000000)\nend\n", NUMERIC_ONLY);
        assert_eq!(got, vec![(1, 22, "Style/NumericLiterals")]);
    }

    #[test]
    fn visits_lambda_parameter_defaults() {
        let got = offenses("f = ->(x = 1000000) { x }\n", NUMERIC_ONLY);
        assert_eq!(got, vec![(1, 12, "Style/NumericLiterals")]);
    }

    // nodepattern extensions: const/cbase scopes, `...` rest-args, csend.
    #[test]
    fn zero_length_non_polymorphic_guard_and_csend() {
        let cfg = "AllCops:\n  DisabledByDefault: true\nStyle/ZeroLengthPredicate:\n  Enabled: true\n";
        assert_eq!(offenses("File.stat(foo).size == 0\n", cfg), vec![]);
        assert_eq!(offenses("::File::Stat.new(foo).size.zero?\n", cfg), vec![]);
        assert_eq!(offenses("foo.size == 0\n", cfg), vec![(1, 1, "Style/ZeroLengthPredicate")]);
        // csend dispatch: zero-shapes flag, nonzero-shapes don't (on_send only)
        assert_eq!(offenses("x&.length == 0\n", cfg), vec![(1, 1, "Style/ZeroLengthPredicate")]);
        assert_eq!(offenses("x&.length > 0\n", cfg), vec![]);
    }
}
