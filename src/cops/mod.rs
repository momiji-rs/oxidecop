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
}
impl<'a> Cops<'a> {
    pub(crate) fn on(&self, cop: &str) -> bool {
        self.cfg.enabled(cop)
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
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.check_documentation(node.location().start_offset(), "class", &node.constant_path());
        // Default walk — covers the superclass expression too, not just the body.
        ruby_prism::visit_class_node(self, node);
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.check_documentation(node.location().start_offset(), "module", &node.constant_path());
        ruby_prism::visit_module_node(self, node);
    }
    fn visit_integer_node(&mut self, node: &ruby_prism::IntegerNode<'pr>) {
        self.check_numeric_literals(node);
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        self.check_method_name_def(node);
        self.check_nested_method_definition(node);
        self.check_redundant_return(node);
        // Default walk (receiver, params, body) one def level deeper — matches
        // rubocop's each_ancestor(:def) semantics, and covers offenses in
        // parameter default values, which a body-only walk silently skipped.
        self.def_depth += 1;
        ruby_prism::visit_def_node(self, node);
        self.def_depth -= 1;
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        if let Some((off, msg)) = self.symbol_proc_lambda(node) {
            self.push(off, "Style/SymbolProc", true, msg);
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
    };

    // ---- text-based cops ----
    cops.check_frozen_string_literal(&comment_data, first_code_line);
    cops.check_line_length();
    cops.check_trailing_whitespace();

    // ---- AST-based cops ----
    cops.visit(&result.node());

    cops.offenses.sort_by(|a, b| (a.line, a.col, a.cop).cmp(&(b.line, b.col, b.cop)));
    LintResult { offenses: cops.offenses, fixes: cops.fixes }
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
}
