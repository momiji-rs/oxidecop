//! Lint department. (Named `lint_cops` because `lint` is taken by the crate's
//! public entry point.)
use super::Cops;
use crate::nodepattern::{self, Pat};
use std::sync::OnceLock;

/// A rubocop `def_node_matcher` equivalent: the pattern string parses once.
fn matcher(cell: &'static OnceLock<Pat>, pattern: &str) -> &'static Pat {
    cell.get_or_init(|| nodepattern::parse(pattern))
}

impl<'a> Cops<'a> {
    /// Lint/NestedMethodDefinition: a def with an enclosing def and no
    /// intervening scoping block/sclass. `def recv.name` where recv is a
    /// var/const/call (not `self`) is exempt from being flagged itself.
    /// The `def_depth`/`scoping_depth` ancestor counters are maintained in
    /// `visit_def_node` / `visit_call_node` / `visit_singleton_class_node`.
    pub(crate) fn check_nested_method_definition(&mut self, node: &ruby_prism::DefNode) {
        if !self.on("Lint/NestedMethodDefinition") {
            return;
        }
        let exempt = node.receiver().is_some_and(|r| r.as_self_node().is_none());
        if !exempt && self.def_depth >= 1 && self.scoping_depth == 0 {
            self.push(node.location().start_offset(), "Lint/NestedMethodDefinition", false,
                "Method definitions must not be nested. Use `lambda` instead.");
        }
    }
}

impl<'a> Cops<'a> {
    /// Lint/UriRegexp — `URI.regexp(...)` is obsolete; prefer
    /// `URI::RFC2396_PARSER.make_regexp(...)` (the modern-ruby parser name).
    pub(crate) fn check_uri_regexp(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/UriRegexp";
        if !self.on(COP) || node.name().as_slice() != b"regexp" {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        let uri_const = matcher(&PAT, "(const {cbase nil?} :URI)");
        let Some(recv) = node.receiver() else { return };
        if nodepattern::matches(uri_const, &recv, self.src).is_none() {
            return;
        }
        let recv_src = String::from_utf8_lossy(self.node_src(&recv)).into_owned();
        let parser = if self.cfg.target_ruby() >= 3.4 { "RFC2396_PARSER" } else { "DEFAULT_PARSER" };
        let argument = node
            .arguments()
            .and_then(|a| a.arguments().iter().next())
            .map(|arg| format!("({})", String::from_utf8_lossy(self.node_src(&arg))))
            .unwrap_or_default();
        let preferred = format!("{recv_src}::{parser}.make_regexp{argument}");
        let current = String::from_utf8_lossy(self.node_src(&node.as_node())).into_owned();
        let Some(sel) = node.message_loc() else { return };
        let l = node.location();
        self.push(sel.start_offset(), COP, true,
            format!("`{current}` is obsolete and should not be used. Instead, use `{preferred}`."));
        self.fixes.push((l.start_offset(), l.end_offset(), preferred.into_bytes()));
    }
}

// ---- is this block "scoping" (its body may define methods)? ----
pub(crate) fn is_eval_exec(node: &ruby_prism::CallNode) -> bool {
    matches!(
        node.name().as_slice(),
        b"instance_eval" | b"class_eval" | b"module_eval" | b"instance_exec" | b"class_exec" | b"module_exec"
    )
}
/// `Class.new` / `Module.new` / `Struct.new` / `Data.define` (incl. `::`-prefixed).
pub(crate) fn is_class_constructor(node: &ruby_prism::CallNode, src: &[u8]) -> bool {
    let Some(r) = node.receiver() else { return false };
    let l = r.location();
    let recv = &src[l.start_offset()..l.end_offset()];
    match node.name().as_slice() {
        b"new" => matches!(recv, b"Class" | b"::Class" | b"Module" | b"::Module" | b"Struct" | b"::Struct"),
        b"define" => matches!(recv, b"Data" | b"::Data"),
        _ => false,
    }
}
