//! Lint department. (Named `lint_cops` because `lint` is taken by the crate's
//! public entry point.)
use super::Cops;
use crate::nodepattern::{self, Pat};
use std::collections::{HashMap, HashSet};
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
        if !self.hot.nested_method_definition {
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
    /// Lint/DuplicateRequire — the same `require`/`require_relative` twice
    /// within one statement list.
    pub(crate) fn check_duplicate_require(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/DuplicateRequire";
        let name = node.name().as_slice();
        if !matches!(name, b"require" | b"require_relative") || !self.on(COP) {
            return;
        }
        if let Some(r) = node.receiver() {
            let rs = self.node_src(&r);
            if !(matches!(rs, b"Kernel" | b"::Kernel")
                && (r.as_constant_read_node().is_some() || r.as_constant_path_node().is_some()))
            {
                return;
            }
        }
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.len() != 1 {
            return;
        }
        let scope = self.stmts_stack.last().copied().unwrap_or(0);
        let key = format!(
            "{}\u{0}{}\u{0}{}",
            scope,
            String::from_utf8_lossy(name),
            String::from_utf8_lossy(self.node_src(&args[0]))
        );
        if !self.requires_seen.insert(key) {
            let m = String::from_utf8_lossy(name);
            let l = node.location();
            self.push(l.start_offset(), COP, true, format!("Duplicate `{m}` detected."));
            // remove the whole line(s), final newline included
            let (line_s, _) = self.idx.loc(l.start_offset());
            let (line_e, _) = self.idx.loc(l.end_offset().saturating_sub(1));
            let start = self.idx.starts[line_s - 1];
            let end = self.idx.starts.get(line_e).copied().unwrap_or(self.src.len());
            self.fixes.push((start, end, Vec::new()));
        }
    }

    /// Lint/UriRegexp — `URI.regexp(...)` is obsolete; prefer
    /// `URI::RFC2396_PARSER.make_regexp(...)` (the modern-ruby parser name).
    pub(crate) fn check_uri_regexp(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/UriRegexp";
        if !self.hot.uri_regexp || node.name().as_slice() != b"regexp" {
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

    /// Lint/EmptyEnsure — an `ensure` with no body.
    pub(crate) fn check_empty_ensure(&mut self, node: &ruby_prism::EnsureNode) {
        if !self.on("Lint/EmptyEnsure") {
            return;
        }
        if node.statements().is_none() {
            let kw = node.ensure_keyword_loc();
            self.push(kw.start_offset(), "Lint/EmptyEnsure", true, "Empty `ensure` block detected.");
            self.fixes.push((kw.start_offset(), kw.end_offset(), Vec::new()));
        }
    }

    /// Lint/EmptyExpression — a bare `()`.
    pub(crate) fn check_empty_expression(&mut self, node: &ruby_prism::ParenthesesNode) {
        if !self.on("Lint/EmptyExpression") {
            return;
        }
        if node.body().is_none() {
            self.push(node.location().start_offset(), "Lint/EmptyExpression", false, "Avoid empty expressions.");
        }
    }

    /// Lint/Debugger — debugger entry points (`binding.pry`, `byebug`, …).
    /// The candidate name is the CHAINED dispatch (`Kernel.binding.irb`),
    /// matched against DebuggerMethods (default: rubocop's grouped list,
    /// flattened); `require 'debug/open'`-style entries via DebuggerRequires.
    pub(crate) fn check_debugger(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/Debugger";
        if !self.eng.debugger_on() {
            return;
        }
        // prefilter: the call's own name must be a possible FINAL segment of
        // a listed method — otherwise skip before any allocation
        if !self.eng.debugger_last_match(node.name().as_slice()) {
            return;
        }
        const DEFAULT_REQUIRES: &[&str] = &["debug/open", "debug/start"];
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        // rubocop's assumed_usage_context?: a bare no-arg call that is a
        // direct operand of another expression (or, outside any block/
        // kwbegin/lambda, merely has a call ancestor) is assumed to be a
        // normal method, not a breakpoint.
        let l = node.location();
        if args.is_empty()
            && !self.call_stack.is_empty()
            && (self.assumed_arg_offsets.contains(&l.start_offset()) || self.usage_block_depth == 0)
        {
            return;
        }
        let hit = if node.name().as_slice() == b"require" && args.len() == 1 {
            let requires = self.cfg.param(COP, "DebuggerRequires").map(crate::config::parse_allowed_list);
            args[0].as_string_node().is_some_and(|s| {
                let v = s.content_loc().as_slice();
                match &requires {
                    Some(list) => list.iter().any(|r| r.as_bytes() == v),
                    None => DEFAULT_REQUIRES.iter().any(|r| r.as_bytes() == v),
                }
            })
        } else {
            let chained = chained_method_name(node, self.src);
            match self.cfg.param(COP, "DebuggerMethods").map(crate::config::parse_allowed_list) {
                Some(list) => list.iter().any(|m| *m == chained),
                None => DEFAULT_DEBUGGER_METHODS.contains(&chained.as_str()),
            }
        };
        if hit {
            // the offense is the SEND — an attached block is not part of it
            let end = node
                .closing_loc()
                .map(|c| c.end_offset())
                .or_else(|| args.last().map(|a| a.location().end_offset()))
                .or_else(|| node.message_loc().map(|m| m.end_offset()))
                .unwrap_or(l.end_offset());
            let source = String::from_utf8_lossy(&self.src[l.start_offset()..end]);
            self.push(l.start_offset(), COP, false, format!("Remove debugger entry point `{source}`."));
        }
    }

    /// Lint/EmptyInterpolation — `"#{}"` (or interpolations of only nil /
    /// empty string literals), outside `%W[]`-style percent arrays.
    pub(crate) fn check_empty_interpolation(&mut self, node: &ruby_prism::EmbeddedStatementsNode) {
        const COP: &str = "Lint/EmptyInterpolation";
        if !self.on(COP) {
            return;
        }
        let l = node.location();
        if self.percent_arr_spans.iter().any(|(s, e)| l.start_offset() >= *s && l.start_offset() < *e) {
            return;
        }
        let empty = match node.statements() {
            None => true,
            Some(stmts) => stmts.body().iter().all(|n| {
                n.as_nil_node().is_some()
                    || n.as_string_node().is_some_and(|s| s.content_loc().as_slice().is_empty())
            }),
        };
        if empty {
            self.push(l.start_offset(), COP, true, "Empty interpolation detected.");
            self.fixes.push((l.start_offset(), l.end_offset(), Vec::new()));
        }
    }

    /// Lint/RescueException — `rescue Exception` (or `::Exception`) catches
    /// the root exception class; the offense anchors on the resbody's
    /// `rescue` keyword. Splats and namespaced/local-var paths never match
    /// `const_name_root`, so they're silently ignored (no crash).
    pub(crate) fn check_rescue_exception(&mut self, node: &ruby_prism::RescueNode) {
        const COP: &str = "Lint/RescueException";
        if !self.on(COP) {
            return;
        }
        let targets_exception = node
            .exceptions()
            .iter()
            .any(|e| const_name_root(&e).as_deref() == Some("Exception"));
        if !targets_exception {
            return;
        }
        self.push(node.keyword_loc().start_offset(), COP, false,
            "Avoid rescuing the `Exception` class. Perhaps you meant to rescue `StandardError`?");
    }

    /// Lint/EnsureReturn — a `return` inside an `ensure` body (not from an
    /// inner def/lambda scope).
    pub(crate) fn check_ensure_return(&mut self, node: &ruby_prism::EnsureNode) {
        const COP: &str = "Lint/EnsureReturn";
        if !self.on(COP) {
            return;
        }
        let Some(stmts) = node.statements() else { return };
        let mut returns = Vec::new();
        for n in stmts.body().iter() {
            collect_returns(&n, &mut returns);
        }
        for off in returns {
            self.push(off, COP, false, "Do not return from an `ensure` block.");
        }
    }

    /// Lint/UriEscapeUnescape — `URI.escape` & friends are obsolete; the
    /// message lists the case-specific replacements.
    pub(crate) fn check_uri_escape_unescape(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/UriEscapeUnescape";
        let name = node.name().as_slice();
        if !matches!(name, b"escape" | b"encode" | b"unescape" | b"decode") || !self.hot.uri_escape {
            return;
        }
        static PAT: OnceLock<Pat> = OnceLock::new();
        let uri_const = matcher(&PAT, "(const {cbase nil?} :URI)");
        let Some(recv) = node.receiver() else { return };
        if nodepattern::matches(uri_const, &recv, self.src).is_none() {
            return;
        }
        let replacements = if matches!(name, b"escape" | b"encode") {
            "`CGI.escape`, `URI.encode_www_form` or `URI.encode_www_form_component`"
        } else {
            "`CGI.unescape`, `URI.decode_www_form` or `URI.decode_www_form_component`"
        };
        let double_colon = if self.node_src(&recv).starts_with(b"::") { "::" } else { "" };
        let method = String::from_utf8_lossy(name);
        let l = node.location();
        self.push(l.start_offset(), COP, false, format!(
            "`{double_colon}URI.{method}` method is obsolete and should not be used. \
             Instead, use {replacements} depending on your specific use case."));
    }
}

/// rubocop's default DebuggerMethods (the grouped default.yml list, flattened).
pub(crate) const DEFAULT_DEBUGGER_METHODS: &[&str] = &[
    "binding.irb", "Kernel.binding.irb", "byebug", "remote_byebug", "Kernel.byebug",
    "Kernel.remote_byebug", "page.save_and_open_page", "page.save_and_open_screenshot",
    "page.save_page", "page.save_screenshot", "save_and_open_page",
    "save_and_open_screenshot", "save_page", "save_screenshot", "binding.b",
    "binding.break", "Kernel.binding.b", "Kernel.binding.break", "binding.pry",
    "binding.remote_pry", "binding.pry_remote", "Kernel.binding.pry",
    "Kernel.binding.remote_pry", "Kernel.binding.pry_remote", "Pry.rescue", "pry",
    "debugger", "Kernel.debugger", "jard", "binding.console",
];

/// rubocop's `chained_method_name`: the dispatch name prefixed by its
/// receiver chain of send/const names (`Kernel.binding.irb`).
fn chained_method_name(node: &ruby_prism::CallNode, src: &[u8]) -> String {
    let mut name = String::from_utf8_lossy(node.name().as_slice()).into_owned();
    let mut recv = node.receiver();
    while let Some(r) = recv {
        if let Some(c) = r.as_call_node() {
            name = format!("{}.{name}", String::from_utf8_lossy(c.name().as_slice()));
            recv = c.receiver();
        } else if let Some(c) = r.as_constant_read_node() {
            name = format!("{}.{name}", String::from_utf8_lossy(c.name().as_slice()));
            break;
        } else if r.as_constant_path_node().is_some() {
            let l = r.location();
            let text = String::from_utf8_lossy(&src[l.start_offset()..l.end_offset()]);
            // rubocop's const_name ignores the `::` cbase anchor
            name = format!("{}.{name}", text.trim_start_matches("::"));
            break;
        } else {
            // a non-send/const receiver can't produce a listed name
            return String::new();
        }
    }
    name
}

/// Find `return` nodes, not descending into inner defs or lambda scopes.
fn collect_returns(node: &ruby_prism::Node, out: &mut Vec<usize>) {
    struct Finder<'a> {
        out: &'a mut Vec<usize>,
    }
    impl<'pr, 'a> ruby_prism::Visit<'pr> for Finder<'a> {
        fn visit_return_node(&mut self, node: &ruby_prism::ReturnNode<'pr>) {
            self.out.push(node.location().start_offset());
            ruby_prism::visit_return_node(self, node);
        }
        fn visit_def_node(&mut self, _node: &ruby_prism::DefNode<'pr>) {}
        fn visit_lambda_node(&mut self, _node: &ruby_prism::LambdaNode<'pr>) {}
        fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
            // a `lambda { return }` block is its own scope; other blocks aren't
            if matches!(node.name().as_slice(), b"lambda" | b"proc") && node.block().is_some() {
                if let Some(r) = node.receiver() {
                    self.visit(&r);
                }
                return;
            }
            ruby_prism::visit_call_node(self, node);
        }
    }
    let mut f = Finder { out };
    use ruby_prism::Visit;
    f.visit(node);
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

impl<'a> super::Cops<'a> {
    /// Lint/EmptyClass — a class with no superclass and no body, or an empty
    /// metaclass. AllowComments accepts a comment inside the span as a body.
    pub(crate) fn check_empty_class(&mut self, node_start: usize, node_end: usize,
                                    has_body: bool, has_superclass: bool, metaclass: bool) {
        const COP: &str = "Lint/EmptyClass";
        if !self.on(COP) || has_body || (!metaclass && has_superclass) {
            return;
        }
        if self.cfg.get(COP, "AllowComments") == Some("true")
            && self.comments.iter().any(|(_, s, _)| *s >= node_start && *s < node_end)
        {
            return;
        }
        let msg = if metaclass { "Empty metaclass detected." } else { "Empty class detected." };
        self.push(node_start, COP, false, msg);
    }

    /// Lint/DeprecatedClassMethods — ENV.clone/dup/freeze, File/Dir.exists?,
    /// Socket.gethostby*, bare `attr name, bool`, bare `iterator?`.
    pub(crate) fn check_deprecated_class_methods(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/DeprecatedClassMethods";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        // receiver constant name (bare or ::-rooted), if any
        let recv_const = node.receiver().and_then(|r| const_name_root(&r));
        let l = node.location();
        let sel = node.message_loc().map(|m| (m.start_offset(), m.end_offset()));
        let argc = node.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0);
        enum Kind { DirEnvFile, Socket, Attr, Iterator }
        let kind = match (recv_const.as_deref(), name) {
            (Some("ENV"), b"clone" | b"dup" | b"freeze") if argc == 0 => Kind::DirEnvFile,
            (Some("File" | "Dir"), b"exists?") if argc == 1 => Kind::DirEnvFile,
            (Some("Socket"), b"gethostbyaddr" | b"gethostbyname") => Kind::Socket,
            (None, b"attr") if argc == 2 && node.receiver().is_none() => {
                let args: Vec<_> = node.arguments().unwrap().arguments().iter().collect();
                if args[1].as_true_node().is_some() || args[1].as_false_node().is_some() {
                    Kind::Attr
                } else {
                    return;
                }
            }
            (None, b"iterator?") if argc == 0 && node.receiver().is_none() => Kind::Iterator,
            _ => return,
        };
        let (rs, re) = match kind {
            Kind::DirEnvFile | Kind::Socket => (l.start_offset(), sel.map(|(_, e)| e).unwrap_or(l.end_offset())),
            Kind::Attr => (l.start_offset(), l.end_offset()),
            Kind::Iterator => sel.unwrap_or((l.start_offset(), l.end_offset())),
        };
        let current = String::from_utf8_lossy(&self.src[rs..re]).into_owned();
        let prefer = match kind {
            Kind::Attr => {
                let args: Vec<_> = node.arguments().unwrap().arguments().iter().collect();
                let attr_name = String::from_utf8_lossy(self.node_src(&args[0])).into_owned();
                let m = if args[1].as_true_node().is_some() { "attr_accessor" } else { "attr_reader" };
                format!("{m} {attr_name}")
            }
            Kind::DirEnvFile => {
                // rubocop interpolates the receiver SOURCE (`::File` keeps its `::`)
                let recv = node
                    .receiver()
                    .map(|r| String::from_utf8_lossy(self.node_src(&r)).into_owned())
                    .unwrap_or_default();
                match name {
                    b"clone" | b"dup" => format!("{recv}.to_h"),
                    b"exists?" => format!("{recv}.exist?"),
                    _ => "ENV".to_string(), // freeze has no method replacement
                }
            }
            Kind::Socket => {
                if name == b"gethostbyaddr" { "Addrinfo#getnameinfo".into() } else { "Addrinfo.getaddrinfo".into() }
            }
            Kind::Iterator => "block_given?".to_string(),
        };
        let correctable = !matches!(kind, Kind::Socket);
        if correctable {
            if name == b"freeze" {
                self.fixes.push((l.start_offset(), l.end_offset(), b"ENV".to_vec()));
            } else {
                self.fixes.push((rs, re, prefer.clone().into_bytes()));
            }
        }
        self.push(rs, COP, correctable,
            format!("`{current}` is deprecated in favor of `{prefer}`."));
    }

    /// Lint/FloatOutOfRange — float literals with magnitude exceeding Float range
    /// (they parse to Infinity or underflow to 0.0).
    pub(crate) fn check_float_out_of_range(&mut self, node: &ruby_prism::FloatNode) {
        const COP: &str = "Lint/FloatOutOfRange";
        if !self.on(COP) {
            return;
        }
        let value = node.value();
        // Overflow case: value is infinite
        if value.is_infinite() {
            self.push(node.location().start_offset(), COP, false, "Float out of range.");
            return;
        }
        // Underflow case: value is zero but source contains a non-zero digit
        if value == 0.0 {
            let src = self.node_src(&node.as_node());
            // Check if source contains any digit 1-9 (indicating an underflow)
            if src.iter().any(|&b| b >= b'1' && b <= b'9') {
                self.push(node.location().start_offset(), COP, false, "Float out of range.");
            }
        }
    }
}

/// The receiver as a root constant name: `Foo` or `::Foo` (nothing deeper).
fn const_name_root(node: &ruby_prism::Node) -> Option<String> {
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
    /// Lint/DuplicateHashKey — every hash-literal key after the first that
    /// duplicates an earlier one (by source text), among keys eligible per
    /// rubocop's `key.recursive_basic_literal? || key.const_type?`. `**splat`
    /// elements aren't keys and are skipped; duplicates only matter within
    /// this ONE hash node (nested hashes get their own `visit_hash_node` call).
    pub(crate) fn check_duplicate_hash_key(&mut self, node: &ruby_prism::HashNode) {
        const COP: &str = "Lint/DuplicateHashKey";
        if !self.on(COP) {
            return;
        }
        let mut seen: HashSet<&'a [u8]> = HashSet::new();
        for el in node.elements().iter() {
            let Some(assoc) = el.as_assoc_node() else { continue };
            let key = assoc.key();
            if !is_duplicate_hash_key_candidate(&key) {
                continue;
            }
            let src = self.node_src(&key);
            if !seen.insert(src) {
                self.push(key.location().start_offset(), COP, false, "Duplicated key in hash literal.");
            }
        }
    }
}

/// rubocop-ast's `recognized_key?`-style test for `Lint/DuplicateHashKey`:
/// `key.recursive_basic_literal? || key.const_type?`.
fn is_duplicate_hash_key_candidate(node: &ruby_prism::Node) -> bool {
    node.as_constant_read_node().is_some()
        || node.as_constant_path_node().is_some()
        || is_recursive_basic_literal(node)
}

/// rubocop-ast's `recursive_basic_literal?`: recurse through `and`/`or`,
/// parenthesized/interpolated bodies, comparison/`*`/`!`/`<=>` sends, and
/// composite literals (array/hash/pair/range/regexp/string/symbol/xstring),
/// bottoming out at non-composite basic literals (int/float/sym/true/false/
/// nil/str/rational/complex).
pub(crate) fn is_recursive_basic_literal(node: &ruby_prism::Node) -> bool {
    if let Some(call) = node.as_call_node() {
        const OPS: &[&[u8]] = &[b"==", b"===", b"!=", b"<=", b">=", b">", b"<", b"*", b"!", b"<=>"];
        let Some(recv) = call.receiver() else { return false };
        return OPS.contains(&call.name().as_slice())
            && is_recursive_basic_literal(&recv)
            && call
                .arguments()
                .is_none_or(|a| a.arguments().iter().all(|arg| is_recursive_basic_literal(&arg)));
    }
    if let Some(a) = node.as_and_node() {
        return is_recursive_basic_literal(&a.left()) && is_recursive_basic_literal(&a.right());
    }
    if let Some(o) = node.as_or_node() {
        return is_recursive_basic_literal(&o.left()) && is_recursive_basic_literal(&o.right());
    }
    if let Some(p) = node.as_parentheses_node() {
        return p.body().is_none_or(|b| is_recursive_basic_literal(&b));
    }
    if let Some(s) = node.as_statements_node() {
        return s.body().iter().all(|n| is_recursive_basic_literal(&n));
    }
    if let Some(arr) = node.as_array_node() {
        return arr.elements().iter().all(|e| is_recursive_basic_literal(&e));
    }
    if let Some(h) = node.as_hash_node() {
        return h.elements().iter().all(|e| is_recursive_basic_literal(&e));
    }
    if let Some(assoc) = node.as_assoc_node() {
        return is_recursive_basic_literal(&assoc.key()) && is_recursive_basic_literal(&assoc.value());
    }
    if let Some(splat) = node.as_assoc_splat_node() {
        return splat.value().is_none_or(|v| is_recursive_basic_literal(&v));
    }
    if let Some(r) = node.as_range_node() {
        return r.left().is_none_or(|l| is_recursive_basic_literal(&l))
            && r.right().is_none_or(|rr| is_recursive_basic_literal(&rr));
    }
    if node.as_regular_expression_node().is_some() || node.as_x_string_node().is_some() {
        return true;
    }
    if let Some(ire) = node.as_interpolated_regular_expression_node() {
        return ire.parts().iter().all(|p| is_recursive_basic_literal(&p));
    }
    if let Some(s) = node.as_interpolated_string_node() {
        return s.parts().iter().all(|p| is_recursive_basic_literal(&p));
    }
    if let Some(s) = node.as_interpolated_symbol_node() {
        return s.parts().iter().all(|p| is_recursive_basic_literal(&p));
    }
    if let Some(s) = node.as_interpolated_x_string_node() {
        return s.parts().iter().all(|p| is_recursive_basic_literal(&p));
    }
    if let Some(es) = node.as_embedded_statements_node() {
        return es.statements().is_none_or(|st| st.body().iter().all(|n| is_recursive_basic_literal(&n)));
    }
    node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_string_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
}

impl<'a> super::Cops<'a> {
    /// Lint/UnifiedInteger — bare or ::rooted Fixnum/Bignum constants
    /// should use Integer instead.
    pub(crate) fn check_unified_integer(&mut self, klass: &[u8], node_start: usize, node_end: usize) {
        const COP: &str = "Lint/UnifiedInteger";
        if !self.on(COP) {
            return;
        }
        let klass_str = String::from_utf8_lossy(klass);
        let msg = format!("Use `Integer` instead of `{klass_str}`.");
        let correctable = self.cfg.target_ruby() >= 2.4;
        self.push(node_start, COP, correctable, msg);
        if correctable {
            let src = &self.src[node_start..node_end];
            // Determine the replacement: preserve :: prefix if present
            let replacement = if src.starts_with(b"::") {
                b"::Integer".to_vec()
            } else {
                b"Integer".to_vec()
            };
            self.fixes.push((node_start, node_end, replacement));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Security/MarshalLoad — `Marshal.load` / `Marshal.restore` on a bare or
    /// ::-rooted Marshal receiver; the `Marshal.load(Marshal.dump(...))`
    /// deep-copy idiom is exempt.
    pub(crate) fn check_marshal_load(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Security/MarshalLoad";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"load" | b"restore") {
            return;
        }
        let recv_const = node.receiver().and_then(|r| const_name_root(&r));
        if recv_const.as_deref() != Some("Marshal") {
            return;
        }
        if let Some(args) = node.arguments() {
            if let Some(first_arg) = args.arguments().iter().next() {
                if let Some(call) = first_arg.as_call_node() {
                    if call.name().as_slice() == b"dump"
                        && call.receiver().and_then(|r| const_name_root(&r)).as_deref() == Some("Marshal")
                    {
                        return;
                    }
                }
            }
        }
        if let Some(sel) = node.message_loc() {
            let method = String::from_utf8_lossy(name);
            self.push(sel.start_offset(), COP, false, format!("Avoid using `Marshal.{method}`."));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/FlipFlop — prism represents `if a..b` / `if a...b` conditions
    /// directly as a `FlipFlopNode` (unlike whitequark's `iflipflop`/
    /// `eflipflop`, which had to be inferred from a `RangeNode` sitting in a
    /// boolean context). Both inclusive and exclusive flip-flops always
    /// offend — there's no config to gate.
    pub(crate) fn check_flip_flop(&mut self, node: &ruby_prism::FlipFlopNode) {
        const COP: &str = "Lint/FlipFlop";
        if !self.on(COP) {
            return;
        }
        self.push(node.location().start_offset(), COP, false, "Avoid the use of flip-flop operators.");
    }
}

    /// Lint/DuplicateCaseCondition: within a single `case`, each `when`
    /// condition is compared (by source text, standing in for rubocop's
    /// node equality) against every condition seen in earlier `when`
    /// branches of the same `case`; a repeat is flagged on each occurrence
    /// after the first.

impl<'a> super::Cops<'a> {
    pub(crate) fn check_duplicate_case_condition(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Lint/DuplicateCaseCondition";
        if !self.on(COP) {
            return;
        }
        let mut seen: HashSet<&'a [u8]> = HashSet::new();
        for branch in node.conditions().iter() {
            let Some(when_node) = branch.as_when_node() else { continue };
            for condition in when_node.conditions().iter() {
                let src = self.node_src(&condition);
                if !seen.insert(src) {
                    self.push(
                        condition.location().start_offset(),
                        COP,
                        false,
                        "Duplicate `when` condition detected.",
                    );
                }
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/DuplicateElsifCondition — an `elsif` whose condition repeats (by
    /// source text) an earlier condition in the same `if`/`elsif` chain.
    ///
    /// rubocop's `on_if` walks `while node.if? || node.elsif?`, starting
    /// fresh from whichever `if`-type node it's handed — including each
    /// nested elsif IfNode, since `elsif` is just `else_branch` chaining to
    /// another IfNode and the AST walker visits it too. rubocop doesn't guard
    /// against that double-visiting: `add_offense`'s same-range dedup quietly
    /// absorbs the redundant reports, and re-walking from partway through the
    /// chain can only ever re-find a duplicate that walking from the head
    /// already found (a mid-chain start only shrinks the `previous` list).
    /// We don't have that dedup, so instead we skip starting the walk at an
    /// elsif node's own visit — detected via `if_keyword_loc` reading
    /// `elsif` rather than `if` — and only ever walk once, from the head.
    pub(crate) fn check_duplicate_elsif_condition(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Lint/DuplicateElsifCondition";
        if !self.on(COP) {
            return;
        }
        if node.if_keyword_loc().is_some_and(|kw| kw.as_slice() == b"elsif") {
            return;
        }
        let mut previous: Vec<&'a [u8]> = vec![self.node_src(&node.predicate())];
        let mut next = node.subsequent();
        while let Some(n) = next {
            let Some(elsif) = n.as_if_node() else { break };
            let condition = elsif.predicate();
            let src = self.node_src(&condition);
            if previous.contains(&src) {
                self.push(
                    condition.location().start_offset(),
                    COP,
                    false,
                    "Duplicate `elsif` condition detected.",
                );
            }
            previous.push(src);
            next = elsif.subsequent();
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/TopLevelReturnWithArgument — a `return` with arguments at the top
    /// level (outside any def or block). The arguments are ignored by Ruby,
    /// so this is likely an error.
    pub(crate) fn check_top_level_return_with_argument(&mut self, node: &ruby_prism::ReturnNode) {
        const COP: &str = "Lint/TopLevelReturnWithArgument";
        if !self.on(COP) {
            return;
        }
        // Top-level return: not inside a def and not inside a block
        if self.def_depth > 0 || self.usage_block_depth > 0 {
            return;
        }
        // Check if return has arguments
        if node.arguments().is_none() {
            return;
        }
        let l = node.location();
        self.push(l.start_offset(), COP, true, "Top level return with argument detected.");
        // Autocorrect: replace entire return node with just "return"
        self.fixes.push((l.start_offset(), l.end_offset(), b"return".to_vec()));
    }
}

impl<'a> super::Cops<'a> {
    /// Security/Eval — `eval` and related calls with dynamic strings
    /// are flagged as a security risk. Literal strings and interpolated
    /// strings with only literal interpolations are exempt.
    pub(crate) fn check_security_eval(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Security/Eval";
        if !self.on(COP) {
            return;
        }

        // Check if method is "eval"
        if node.name().as_slice() != b"eval" {
            return;
        }

        // Check the receiver: nil (direct call), binding method, or Kernel constant
        let valid_receiver = if let Some(recv) = node.receiver() {
            // Check for Kernel constant (bare or ::rooted)
            if let Some("Kernel") = const_name_root(&recv).as_deref() {
                true
            } else if let Some(call) = recv.as_call_node() {
                // binding method call: binding.eval(...)
                call.name().as_slice() == b"binding" && call.receiver().is_none()
            } else {
                false
            }
        } else {
            // nil receiver (direct eval call)
            true
        };

        if !valid_receiver {
            return;
        }

        // Get the first argument
        let args: Vec<ruby_prism::Node> = node
            .arguments()
            .map(|a| a.arguments().iter().collect())
            .unwrap_or_default();

        if args.is_empty() {
            return;
        }

        let first_arg = &args[0];

        // Allow literal strings
        if first_arg.as_string_node().is_some() {
            return;
        }

        // Allow interpolated strings where all parts are recursive literals
        if let Some(istr) = first_arg.as_interpolated_string_node() {
            if istr.parts().iter().all(|p| is_recursive_basic_literal(&p)) {
                return;
            }
        }

        // Flag the offense at the method location
        if let Some(sel) = node.message_loc() {
            self.push(
                sel.start_offset(),
                COP,
                false,
                "The use of `eval` is a serious security risk.",
            );
        }
    }
}

/// rubocop-ast's `IMMUTABLE_LITERALS` (`LITERALS - MUTABLE_LITERALS`): the
/// literal node types that can never be mutated in place. Strings, dstr,
/// xstr, arrays, hashes, regexps, and ranges are excluded (mutable).
fn is_immutable_literal(node: &ruby_prism::Node) -> bool {
    node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_interpolated_symbol_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
}

impl<'a> super::Cops<'a> {
    /// Lint/EachWithObjectArgument — `each_with_object`'s argument is the
    /// object the block accumulates into; an immutable-literal argument
    /// (`0`, `:sym`, `nil`, ...) can never actually accumulate anything, so
    /// it's always a bug. rubocop's matcher: `(call _ :each_with_object $_)`
    /// — exactly one argument, any receiver (incl. safe-navigation `&.`).
    pub(crate) fn check_each_with_object_argument(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/EachWithObjectArgument";
        if !self.on(COP) || node.name().as_slice() != b"each_with_object" {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let args: Vec<_> = args.arguments().iter().collect();
        if args.len() != 1 || !is_immutable_literal(&args[0]) {
            return;
        }
        self.push(
            node.location().start_offset(),
            COP,
            false,
            "The argument to each_with_object cannot be immutable.",
        );
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/RegexpAsCondition — a regexp literal used directly as a boolean
    /// condition matches implicitly against `$_`. Prism represents this
    /// directly as a `MatchLastLineNode` (or `InterpolatedMatchLastLineNode`
    /// for `/#{x}/`-style interpolated ones) wherever a bare regexp literal
    /// sits as: (1) the predicate of an `if`/`unless`/`while`/`until` (which
    /// also covers ternaries — prism parses `cond ? a : b` as an `IfNode`
    /// too), or (2) the receiver of a `!`/`not` call, in EITHER case
    /// regardless of whether that call itself is inside a conditional. This
    /// mirrors whitequark's `match_current_line` node, but rubocop's own
    /// `on_match_current_line` re-derives "is this really a condition" via
    /// `node.ancestors.none?(&:conditional?)` — a real ancestor walk (any
    /// enclosing if/unless/while/until/case/case-in, not just "am I the
    /// predicate"). `cond_depth` (maintained around each conditional's
    /// visit in `visit_if_node`/`visit_unless_node`/`visit_while_node`/
    /// `visit_until_node`/`visit_case_node`/`visit_case_match_node`) plays
    /// that same role here.
    ///
    /// `visit_call_node` special-cases the `!`/`not`-wrapped form: since `!`
    /// binds tighter than `=~`, the fix must wrap the WHOLE `!` call
    /// (`!(/foo/ =~ $_)`) rather than just the regexp, so it calls this with
    /// `bang` set to that call's location and pre-marks the regexp's start
    /// offset in `regexp_bang_ignore` so the later direct visit of the
    /// literal (`visit_match_last_line_node` /
    /// `visit_interpolated_match_last_line_node`) doesn't double-flag it.
    pub(crate) fn check_regexp_as_condition(
        &mut self,
        node: &ruby_prism::Node,
        bang: Option<ruby_prism::Location>,
    ) {
        const COP: &str = "Lint/RegexpAsCondition";
        if !self.on(COP) || self.cond_depth == 0 {
            return;
        }
        let loc = node.location();
        self.push(
            loc.start_offset(),
            COP,
            true,
            "Do not use regexp literal as a condition. The regexp literal matches `$_` implicitly.",
        );
        let src = self.node_src(node);
        let mut text = Vec::with_capacity(src.len() + 8);
        if let Some(bl) = bang {
            text.extend_from_slice(b"!(");
            text.extend_from_slice(src);
            text.extend_from_slice(b" =~ $_)");
            self.fixes.push((bl.start_offset(), bl.end_offset(), text));
        } else {
            text.extend_from_slice(src);
            text.extend_from_slice(b" =~ $_");
            self.fixes.push((loc.start_offset(), loc.end_offset(), text));
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/DuplicateRescueException — the same exception class listed in
    /// more than one `rescue` clause of a single begin/rescue chain.
    ///
    /// Prism represents a rescue chain as a linked list of `RescueNode`s
    /// reachable via `.subsequent()`, whose head is a `BeginNode`'s
    /// `.rescue_clause()` — this covers both an explicit
    /// `begin ... rescue ... end` and an implicit `def`-body rescue, since
    /// prism wraps a rescuing method body in a `BeginNode` too. Hooking
    /// `visit_begin_node` (rather than `visit_rescue_node`, which the default
    /// walk also recurses into for every tail clause) means each chain is
    /// walked exactly once, from the head — mirroring rubocop's `on_rescue`,
    /// which fires once per begin/rescue and iterates all of its
    /// `resbody_branches`. Exceptions (including splats) are compared by
    /// source text standing in for rubocop's node equality, accumulating a
    /// `previous` set across the whole chain exactly like rubocop's
    /// `Set#add?`: the first occurrence of a given exception seeds the set,
    /// every later occurrence — whether in the same or a different clause —
    /// is flagged, anchored on the duplicate exception node itself.
    pub(crate) fn check_duplicate_rescue_exception(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Lint/DuplicateRescueException";
        if !self.on(COP) {
            return;
        }
        let Some(head) = node.rescue_clause() else { return };
        let mut previous: HashSet<&'a [u8]> = HashSet::new();
        let mut clause = Some(head);
        while let Some(resbody) = clause {
            for exception in resbody.exceptions().iter() {
                let src = self.node_src(&exception);
                if !previous.insert(src) {
                    self.push(
                        exception.location().start_offset(),
                        COP,
                        false,
                        "Duplicate `rescue` exception detected.",
                    );
                }
            }
            clause = resbody.subsequent();
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/SafeNavigationWithEmpty — `foo&.empty?` in a conditional
    /// (if/unless predicate) is unsafe because when foo is nil, the result
    /// is nil (falsy) instead of false, inverting the author's intent.
    /// The fix is to change `&.` to `&&` with explicit nil check.
    pub(crate) fn check_safe_navigation_with_empty(&mut self, node: &ruby_prism::Node) {
        const COP: &str = "Lint/SafeNavigationWithEmpty";
        if !self.on(COP) {
            return;
        }

        // Pattern match: a call node with method name "empty?" and safe navigation operator
        let Some(call) = node.as_call_node() else { return };

        // Check method name is "empty?"
        if call.name().as_slice() != b"empty?" {
            return;
        }

        // Check for safe navigation operator "&."
        let Some(op_loc) = call.call_operator_loc() else { return };
        if op_loc.as_slice() != b"&." {
            return;
        }

        // Check that receiver exists and is NOT itself a safe navigation call
        let Some(recv) = call.receiver() else { return };

        // If receiver is a call with safe navigation, don't flag it
        // (pattern says !csend - not a safe navigation call)
        if let Some(recv_call) = recv.as_call_node() {
            if recv_call.call_operator_loc().is_some_and(|rl| rl.as_slice() == b"&.") {
                return;
            }
        }

        let recv_src = String::from_utf8_lossy(self.node_src(&recv)).into_owned();
        let l = call.location();

        self.push(
            l.start_offset(),
            COP,
            true,
            "Avoid calling `empty?` with the safe navigation operator in conditionals.",
        );

        // Fix: replace the condition with "#{receiver} && #{receiver}.empty?"
        let replacement = format!("{} && {}.empty?", recv_src, recv_src);
        self.fixes.push((l.start_offset(), l.end_offset(), replacement.into_bytes()));
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/HashCompareByIdentity — a hash access/write keyed by an object's
    /// `object_id` (`hash[foo.object_id]`, `hash.key?(foo.object_id)`, …)
    /// rather than the object itself. Mirrors rubocop's node pattern
    /// `(call _ {:key? :has_key? :fetch :[] :[]=} (send _ :object_id) ...)`:
    /// any receiver, one of the five methods, whose FIRST argument is itself
    /// a no-arg call named `object_id` (any receiver, including implicit
    /// self, as in the bare `object_id` case). Fires on both `.` and `&.`
    /// calls (rubocop aliases `on_csend` to `on_send`), and offense is
    /// anchored at the whole call node's start, matching rubocop's default
    /// `add_offense(node)` behavior.
    pub(crate) fn check_hash_compare_by_identity(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/HashCompareByIdentity";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"key?" | b"has_key?" | b"fetch" | b"[]" | b"[]=") {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let Some(first_arg) = args.arguments().iter().next() else { return };
        let Some(call) = first_arg.as_call_node() else { return };
        if call.name().as_slice() != b"object_id" || call.arguments().is_some() {
            return;
        }
        // rubocop's pattern is `send`, not `call` — a `&.object_id` key
        // doesn't match there, so it doesn't here
        if call.call_operator_loc().is_some_and(|o| o.as_slice() == b"&.") {
            return;
        }
        self.push(
            node.location().start_offset(),
            COP,
            false,
            "Use `Hash#compare_by_identity` instead of using `object_id` for keys.",
        );
    }
}
/// Find bare `next` nodes (no arguments) in a reduce/inject block body,
/// not descending into nested blocks (which have their own scope).
fn collect_bare_next_in_reduce(node: &ruby_prism::Node, out: &mut Vec<usize>) {
    struct Finder<'a> {
        out: &'a mut Vec<usize>,
    }
    impl<'pr, 'a> ruby_prism::Visit<'pr> for Finder<'a> {
        fn visit_next_node(&mut self, node: &ruby_prism::NextNode<'pr>) {
            // Only collect if this next has no arguments (bare next)
            if node.arguments().is_none() {
                self.out.push(node.location().start_offset());
            }
            ruby_prism::visit_next_node(self, node);
        }
        fn visit_block_node(&mut self, _node: &ruby_prism::BlockNode<'pr>) {
            // Don't descend into nested blocks; they have their own scope
        }
    }
    let mut f = Finder { out };
    use ruby_prism::Visit;
    f.visit(node);
}


impl<'a> super::Cops<'a> {
    /// Lint/NextWithoutAccumulator — a bare `next` (no arguments) inside
    /// a `reduce` or `inject` block. The accumulator should be passed to
    /// `next` to preserve its value across iterations. This check looks for
    /// bare `next` statements in reduce/inject blocks and reports them,
    /// but correctly ignores `next` statements in nested blocks (which have
    /// their own scope).
    pub(crate) fn check_next_without_accumulator(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/NextWithoutAccumulator";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"reduce" | b"inject") {
            return;
        }
        let Some(block) = node.block() else { return };
        let Some(block) = block.as_block_node() else { return };
        let Some(body) = block.body() else { return };

        // Collect all bare next nodes in the block body, not descending into nested blocks
        let mut bare_nexts = Vec::new();
        collect_bare_next_in_reduce(&body, &mut bare_nexts);

        // Report each bare next
        for off in bare_nexts {
            self.push(off, COP, false, "Use `next` with an accumulator argument in a `reduce`.");
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/MultipleComparison — a chained mathematical comparison like
    /// `x < y < z`, which Ruby (unlike math or Python) does NOT parse as two
    /// comparisons ANDed together: it parses as `(x < y) < z`, comparing a
    /// boolean against `z`. Not a syntax error, just nonsense.
    ///
    /// Mirrors rubocop's node-matcher verbatim:
    ///   `(send (send _ {:< :> :<= :>=} $_) {:< :> :<= :>=} _)`
    /// i.e. an outer send whose METHOD is a comparison operator and whose
    /// RECEIVER is itself a send with a comparison-operator method; the
    /// capture is the INNER send's argument (the shared middle value, `y`
    /// in `x < y < z`) — not the inner send's receiver.
    ///
    /// rubocop allows chaining through the `&`/`|`/`^` set-operation
    /// operators (`x >= y & y < z`, which — because `&`/`|`/`^` bind TIGHTER
    /// than comparisons — actually parses as `x >= (y & y) < z`): if the
    /// captured middle value is itself a send whose method is one of those,
    /// it's exempted.
    ///
    /// Autocorrect duplicates the middle value with `&&`: `corrector.replace
    /// (center, "#{center.source} && #{center.source}")`, i.e. replace just
    /// the captured node's span with `"<src> && <src>"` — turning
    /// `x < y < z` into `x < y && y < z`.
    pub(crate) fn check_multiple_comparison(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/MultipleComparison";
        if !self.on(COP) {
            return;
        }
        const COMPARISON: &[&[u8]] = &[b"<", b">", b"<=", b">="];
        if !COMPARISON.contains(&node.name().as_slice()) {
            return;
        }
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.len() != 1 {
            return;
        }
        let Some(inner) = node.receiver().and_then(|r| r.as_call_node()) else { return };
        if !COMPARISON.contains(&inner.name().as_slice()) {
            return;
        }
        let inner_args: Vec<ruby_prism::Node> =
            inner.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if inner_args.len() != 1 {
            return;
        }
        let center = &inner_args[0];
        // "It allows multiple comparison using `&`, `|`, and `^` set
        // operation operators. e.g. `x >= y & y < z`"
        if let Some(c) = center.as_call_node() {
            if matches!(c.name().as_slice(), b"&" | b"|" | b"^") {
                return;
            }
        }
        let loc = node.location();
        self.push(
            loc.start_offset(),
            COP,
            true,
            "Use the `&&` operator to compare multiple values.",
        );
        let center_src = self.node_src(center);
        let mut text = Vec::with_capacity(center_src.len() * 2 + 4);
        text.extend_from_slice(center_src);
        text.extend_from_slice(b" && ");
        text.extend_from_slice(center_src);
        let cl = center.location();
        self.fixes.push((cl.start_offset(), cl.end_offset(), text));
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/IdentityComparison — `a.object_id == b.object_id` or
    /// `a.object_id != b.object_id` should use `equal?` instead.
    pub(crate) fn check_identity_comparison(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/IdentityComparison";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"==" | b"!=") {
            return;
        }

        // Get the receiver and check it's a call to object_id
        let Some(receiver) = node.receiver() else { return };
        let Some(lhs_call) = receiver.as_call_node() else { return };
        if lhs_call.name().as_slice() != b"object_id" {
            return;
        }
        if lhs_call.arguments().is_some() {
            return;
        }
        // The lhs receiver must be present (not bare object_id)
        let Some(_lhs_receiver) = lhs_call.receiver() else { return };

        // Get the first argument and check it's a call to object_id
        let Some(args) = node.arguments() else { return };
        let Some(first_arg) = args.arguments().iter().next() else { return };
        let Some(rhs_call) = first_arg.as_call_node() else { return };
        if rhs_call.name().as_slice() != b"object_id" {
            return;
        }
        if rhs_call.arguments().is_some() {
            return;
        }
        // The rhs receiver must be present (not bare object_id)
        let Some(_rhs_receiver) = rhs_call.receiver() else { return };

        // Build the message
        let comparison_method = String::from_utf8_lossy(name);
        let bang = if name == b"==" { "" } else { "!" };
        let message = format!(
            "Use `{bang}equal?` instead of `{comparison_method}` when comparing `object_id`."
        );

        self.push(node.location().start_offset(), COP, true, message);

        // Build the fix
        let lhs_src = self.node_src(&_lhs_receiver);
        let rhs_src = self.node_src(&_rhs_receiver);
        let mut replacement = Vec::new();
        if !bang.is_empty() {
            replacement.extend_from_slice(bang.as_bytes());
        }
        replacement.extend_from_slice(lhs_src);
        replacement.extend_from_slice(b".equal?(");
        replacement.extend_from_slice(rhs_src);
        replacement.extend_from_slice(b")");

        let l = node.location();
        self.fixes.push((l.start_offset(), l.end_offset(), replacement));
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/UselessElseWithoutRescue — `begin ... else ... end` with an
    /// `else` clause but no `rescue` clause. Without a `rescue`, `else` is
    /// dead code: it only ever runs when the `begin` body raised nothing,
    /// which is exactly when a bare `begin/end` would already fall through
    /// to run it anyway — so the `else` adds nothing but confusion.
    ///
    /// NOTE: this construct is a SYNTAX ERROR on Ruby 2.6+ (rubocop's own
    /// cop is capped via `maximum_target_ruby_version 2.5` and sources the
    /// offense from the legacy parser's `:useless_else` diagnostic reason).
    /// prism still parses it into a usable `BeginNode` — `else_clause` set,
    /// `rescue_clause` `None` — alongside a `begin_lonely_else` parse error
    /// we don't surface elsewhere, so we detect it directly off the AST
    /// shape instead of a diagnostic-reason lookup.
    pub(crate) fn check_useless_else_without_rescue(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Lint/UselessElseWithoutRescue";
        if !self.on(COP) {
            return;
        }
        if node.rescue_clause().is_some() {
            return;
        }
        let Some(else_clause) = node.else_clause() else { return };
        let kw = else_clause.else_keyword_loc();
        self.push(kw.start_offset(), COP, false, "`else` without `rescue` is useless.");
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/ReturnInVoidContext — a `return` WITH a value inside a
    /// void-context method: `initialize`, or a setter (`def foo=`) whose
    /// name isn't one of the comparison operators (`==`, `===`, `!=`,
    /// `<=`, `>=`) — mirrors rubocop-ast's `DefNode#void_context?`.
    ///
    /// The scan doesn't descend into nested `def`s (their own scope) nor
    /// into `lambda`/`define_method`/`define_singleton_method` blocks
    /// (rubocop's `SCOPE_CHANGING_METHODS` — "returning out of these
    /// methods only exits the block itself"). Plain blocks, numblocks,
    /// itblocks, and `proc` blocks are NOT scope-changing here, so returns
    /// inside them still count — this differs from `collect_returns`
    /// above (used by `Lint/EnsureReturn`), which treats `proc` as its own
    /// scope.
    pub(crate) fn check_return_in_void_context(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/ReturnInVoidContext";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        const COMPARISON_OPERATORS: &[&[u8]] = &[b"==", b"===", b"!=", b"<=", b">=", b">", b"<"];
        let is_setter = name.ends_with(b"=") && !COMPARISON_OPERATORS.contains(&name);
        // rubocop's `void_context?` requires plain `def_type?` (not `defs_type?`)
        // for the `initialize` branch — `def self.initialize` doesn't count —
        // but `assignment_method?` (the setter branch) doesn't check receiver.
        let is_initialize = name == b"initialize" && node.receiver().is_none();
        if !is_initialize && !is_setter {
            return;
        }
        let Some(body) = node.body() else { return };
        let mut returns = Vec::new();
        collect_void_context_returns(&body, &mut returns);
        let method = String::from_utf8_lossy(name).into_owned();
        for off in returns {
            self.push(off, COP, false, format!("Do not return a value in `{method}`."));
        }
    }
}

/// Find `return`-with-a-value keyword offsets, not descending into nested
/// `def`s or `lambda`/`define_method`/`define_singleton_method` blocks.
fn collect_void_context_returns(node: &ruby_prism::Node, out: &mut Vec<usize>) {
    struct Finder<'a> {
        out: &'a mut Vec<usize>,
    }
    impl<'pr, 'a> ruby_prism::Visit<'pr> for Finder<'a> {
        fn visit_return_node(&mut self, node: &ruby_prism::ReturnNode<'pr>) {
            if node.arguments().is_some() {
                self.out.push(node.keyword_loc().start_offset());
            }
            ruby_prism::visit_return_node(self, node);
        }
        fn visit_def_node(&mut self, _node: &ruby_prism::DefNode<'pr>) {}
        fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
            if let Some(r) = node.receiver() {
                self.visit(&r);
            }
            if let Some(a) = node.arguments() {
                self.visit_arguments_node(&a);
            }
            let scope_changing = node.block().is_some()
                && matches!(
                    node.name().as_slice(),
                    b"lambda" | b"define_method" | b"define_singleton_method"
                );
            if !scope_changing {
                if let Some(b) = node.block() {
                    self.visit(&b);
                }
            }
        }
    }
    let mut f = Finder { out };
    use ruby_prism::Visit;
    f.visit(node);
}

impl<'a> super::Cops<'a> {
    /// Lint/TrailingCommaInAttributeDeclaration — `attr_reader :foo,` swallows
    /// the following `def` as another argument (a bare `def` evaluates to its
    /// method name symbol), silently defining a getter that shadows it. Flags
    /// + strips the trailing comma between the last real attribute and the
    /// `def` argument.
    pub(crate) fn check_trailing_comma_in_attribute_declaration(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/TrailingCommaInAttributeDeclaration";
        if !self.on(COP) {
            return;
        }
        // rubocop's `attribute_accessor?` matcher: bare (nil receiver) send.
        if node.receiver().is_some() {
            return;
        }
        if !matches!(node.name().as_slice(), b"attr" | b"attr_reader" | b"attr_writer" | b"attr_accessor") {
            return;
        }
        let Some(args_node) = node.arguments() else { return };
        let args: Vec<ruby_prism::Node> = args_node.arguments().iter().collect();
        // A lone `def` argument (e.g. `attr_reader def foo; end`) has no
        // preceding attribute, so there is no trailing comma to flag.
        if args.len() <= 1 {
            return;
        }
        let Some(last) = args.last() else { return };
        if last.as_def_node().is_none() {
            return;
        }
        // `range_with_surrounding_space(..., side: :right).end.resize(1)`:
        // from the end of the last real attribute, skip horizontal
        // whitespace, and the next byte is the comma to remove.
        let prev_end = args[args.len() - 2].location().end_offset();
        let mut pos = prev_end;
        while matches!(self.src.get(pos), Some(b' ' | b'\t')) {
            pos += 1;
        }
        if self.src.get(pos) != Some(&b',') {
            return;
        }
        self.push(pos, COP, true, "Avoid leaving a trailing comma in attribute declarations.");
        self.fixes.push((pos, pos + 1, Vec::new()));
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/NestedPercentLiteral — a percent-literal array (`%i`, `%w`, `%I`,
    /// `%W`, `%q`, `%Q`, `%r`, `%s`, `%x`, or the bare `%`) whose elements'
    /// raw source *look* like the start of another percent literal (e.g.
    /// `%w[%w(a) b]`). Because `%i`/`%w`-family literals split their body on
    /// whitespace with no awareness of nested delimiters, such a nested
    /// literal is parsed as plain tokens rather than as a real nested array —
    /// almost certainly not what was intended. No autocorrect (rubocop's
    /// original has none either).
    pub(crate) fn check_nested_percent_literal(&mut self, node: &ruby_prism::ArrayNode<'_>) {
        const COP: &str = "Lint/NestedPercentLiteral";
        if !self.on(COP) {
            return;
        }
        // rubocop's `PercentLiteral#percent_literal?` + `type` check: only
        // arrays actually opened with a `%`-prefixed literal (`%i`, `%w`,
        // `%I`, `%W`, ...) are in scope — `[a, b]` or `%(a b)` (a *string*,
        // not an array) never reach here.
        let Some(opening) = node.opening_loc() else { return };
        if !opening.as_slice().starts_with(b"%") {
            return;
        }

        let re = {
            static RE: OnceLock<regex::Regex> = OnceLock::new();
            RE.get_or_init(|| {
                // PERCENT_LITERAL_TYPES = %w[% %i %I %q %Q %r %s %w %W %x];
                // REGEXES = types.map { |t| /\A#{t}\W/ } — any element whose
                // raw source starts with one of these percent-literal
                // openers immediately followed by a delimiter character.
                regex::Regex::new(r"^(?:%i|%I|%q|%Q|%r|%s|%w|%W|%x|%)\W").unwrap()
            })
        };

        let contains_nested = node.elements().iter().any(|el| {
            let src = self.node_src(&el);
            re.is_match(&String::from_utf8_lossy(src))
        });
        if !contains_nested {
            return;
        }

        let l = node.location();
        self.push(
            l.start_offset(),
            COP,
            false,
            "Within percent literals, nested percent literals do not function and may be unwanted in the result.",
        );
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/PercentSymbolArray — detects colons and commas in %i/%I arrays,
    /// which are likely unintended. For example, `%i(:foo, :bar)` should be
    /// `%i(foo bar)`.
    pub(crate) fn check_percent_symbol_array(&mut self, node: &ruby_prism::ArrayNode) {
        const COP: &str = "Lint/PercentSymbolArray";
        if !self.on(COP) {
            return;
        }

        // Check if this is a %i or %I array
        let Some(open_loc) = node.opening_loc() else { return };
        let open = open_loc.as_slice();
        if !open.starts_with(b"%i") && !open.starts_with(b"%I") {
            return;
        }

        // Check if any element has a leading : or trailing ,
        let mut has_issue = false;
        for element in node.elements().iter() {
            let src = self.node_src(&element);

            // Skip non-alphanumeric literals (like $, in %i{$,})
            if !src.iter().any(|&b| b.is_ascii_alphanumeric()) {
                continue;
            }

            if src.starts_with(b":") || src.ends_with(b",") {
                has_issue = true;
                break;
            }
        }

        if has_issue {
            let l = node.location();
            self.push(
                l.start_offset(),
                COP,
                true,
                "Within `%i`/`%I`, ':' and ',' are unnecessary and may be unwanted in the resulting symbols.",
            );

            // Add fixes: for each element, remove leading : and trailing ,
            for element in node.elements().iter() {
                let el = element.location();
                let src = self.node_src(&element);

                // Skip non-alphanumeric literals
                if !src.iter().any(|&b| b.is_ascii_alphanumeric()) {
                    continue;
                }

                // Remove trailing comma
                if src.ends_with(b",") {
                    self.fixes.push((el.end_offset() - 1, el.end_offset(), Vec::new()));
                }

                // Remove leading colon
                if src.starts_with(b":") {
                    self.fixes.push((el.start_offset(), el.start_offset() + 1, Vec::new()));
                }
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/CircularArgumentReference — detects circular argument references
    /// in optional keyword arguments and optional ordinal arguments.
    pub(crate) fn check_circular_argument_reference(
        &mut self,
        arg_name: &[u8],
        arg_value: &ruby_prism::Node,
    ) {
        const COP: &str = "Lint/CircularArgumentReference";
        if !self.on(COP) {
            return;
        }

        // Check for direct reference: arg_name = arg_name or kwarg: kwarg
        if let Some(lvar) = arg_value.as_local_variable_read_node() {
            if lvar.name().as_slice() == arg_name {
                let msg = format!("Circular argument reference - `{}`.", String::from_utf8_lossy(arg_name));
                self.push(arg_value.location().start_offset(), COP, false, msg);
                return;
            }
        }

        // Check for assignment chain: arg_name = x = y = arg_name
        self.check_assignment_chain(arg_name, arg_value);
    }

    fn check_assignment_chain(&mut self, arg_name: &[u8], node: &ruby_prism::Node) {
        const COP: &str = "Lint/CircularArgumentReference";

        // Only proceed if this is a local variable write node
        let Some(lv_write) = node.as_local_variable_write_node() else {
            return;
        };

        let mut seen_variables = std::collections::HashSet::new();
        let mut current_node = lv_write.value();
        seen_variables.insert(lv_write.name().as_slice().to_vec());

        // Traverse the assignment chain
        loop {
            if let Some(next_lv_write) = current_node.as_local_variable_write_node() {
                let var_name = next_lv_write.name().as_slice();
                seen_variables.insert(var_name.to_vec());
                current_node = next_lv_write.value();
            } else {
                break;
            }
        }

        // Check if we end up with a local variable read
        if let Some(lvar) = current_node.as_local_variable_read_node() {
            let var_name = lvar.name().as_slice();
            // Check if this variable is in the chain or if it's the original arg_name
            if seen_variables.iter().any(|v| v.as_slice() == var_name) || var_name == arg_name {
                let msg = format!("Circular argument reference - `{}`.", String::from_utf8_lossy(arg_name));
                self.push(current_node.location().start_offset(), COP, false, msg);
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/BinaryOperatorWithIdenticalOperands — checks for binary operators
    /// with identical operands (except for simple arithmetic: +, *, **, <<, >>).
    pub(crate) fn check_binary_operator_with_identical_operands(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/BinaryOperatorWithIdenticalOperands";
        if !self.on(COP) {
            return;
        }

        // Check if this is one of the operators we care about
        let op_bytes = node.name().as_slice();
        if !matches!(
            op_bytes,
            b"==" | b"!=" | b"===" | b"<=>" | b"=~" | b">" | b">=" | b"<" | b"<=" | b"|" | b"^"
        ) {
            return;
        }

        // Get the receiver
        let Some(receiver) = node.receiver() else { return };

        // Get the first argument
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.len() != 1 {
            return;
        }
        let arg = &args[0];

        // Compare source representations
        let recv_src = self.node_src(&receiver);
        let arg_src = self.node_src(arg);

        if recv_src == arg_src {
            let op_str = String::from_utf8_lossy(op_bytes);
            let l = node.location();
            self.push(
                l.start_offset(),
                COP,
                false,
                format!("Binary operator `{}` has identical operands.", op_str),
            );
        }
    }

    /// Lint/BinaryOperatorWithIdenticalOperands for && operator (and_node).
    pub(crate) fn check_and_with_identical_operands(&mut self, node: &ruby_prism::AndNode) {
        const COP: &str = "Lint/BinaryOperatorWithIdenticalOperands";
        if !self.on(COP) {
            return;
        }

        let left_src = self.node_src(&node.left());
        let right_src = self.node_src(&node.right());

        if left_src == right_src {
            let l = node.location();
            self.push(
                l.start_offset(),
                COP,
                false,
                "Binary operator `&&` has identical operands.".to_string(),
            );
        }
    }

    /// Lint/BinaryOperatorWithIdenticalOperands for || operator (or_node).
    pub(crate) fn check_or_with_identical_operands(&mut self, node: &ruby_prism::OrNode) {
        const COP: &str = "Lint/BinaryOperatorWithIdenticalOperands";
        if !self.on(COP) {
            return;
        }

        let left_src = self.node_src(&node.left());
        let right_src = self.node_src(&node.right());

        if left_src == right_src {
            let l = node.location();
            self.push(
                l.start_offset(),
                COP,
                false,
                "Binary operator `||` has identical operands.".to_string(),
            );
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/InterpolationCheck — detects interpolation in single-quoted strings.
    /// Single-quoted strings should not have interpolation; the correct approach
    /// is to use double quotes for interpolated strings.
    pub(crate) fn check_interpolation_check(&mut self, node: &ruby_prism::StringNode) {
        const COP: &str = "Lint/InterpolationCheck";
        if !self.on(COP) {
            return;
        }

        // Skip if this string is inside an interpolation context
        if self.interp_depth > 0 {
            return;
        }

        // Get opening and closing locations
        let Some(open_loc) = node.opening_loc() else { return };
        let Some(close_loc) = node.closing_loc() else { return };

        // Check if it's a single-quoted string
        if open_loc.as_slice() != b"'" {
            return;
        }

        // Skip heredocs
        if open_loc.as_slice().starts_with(b"<<") {
            return;
        }

        // Get the full source of the string
        let src = self.node_src(&node.as_node());

        // Check for unescaped interpolation
        let has_interpolation = self.has_unescaped_interpolation(src);
        if !has_interpolation {
            return;
        }

        // Check if the syntax would be valid if converted to double quotes
        if !self.would_be_valid_double_quoted(src) {
            return;
        }

        let l = node.location();
        self.push(
            l.start_offset(),
            COP,
            true,
            "Interpolation in single quoted string detected. Use double quoted strings if you need interpolation.",
        );

        // Add the fix
        self.add_interpolation_fix(open_loc.start_offset(), open_loc.end_offset(), close_loc.start_offset(), close_loc.end_offset(), src);
    }

    /// Check for interpolation in multiline single-quoted strings (dstr nodes)
    pub(crate) fn check_interpolation_check_dstr(&mut self, node: &ruby_prism::InterpolatedStringNode) {
        const COP: &str = "Lint/InterpolationCheck";
        if !self.on(COP) {
            return;
        }

        // Skip if this is not a single-quoted string
        let Some(open_loc) = node.opening_loc() else { return };
        if open_loc.as_slice() != b"'" {
            return;
        }

        // Skip heredocs
        if open_loc.as_slice().starts_with(b"<<") {
            return;
        }

        // Get the full source
        let src = self.node_src(&node.as_node());

        // Check for unescaped interpolation
        let has_interpolation = self.has_unescaped_interpolation(src);
        if !has_interpolation {
            return;
        }

        // Check if the syntax would be valid if converted to double quotes
        if !self.would_be_valid_double_quoted(src) {
            return;
        }

        let l = node.location();
        self.push(
            l.start_offset(),
            COP,
            true,
            "Interpolation in single quoted string detected. Use double quoted strings if you need interpolation.",
        );

        // Add the fix
        let Some(close_loc) = node.closing_loc() else { return };
        self.add_interpolation_fix(open_loc.start_offset(), open_loc.end_offset(), close_loc.start_offset(), close_loc.end_offset(), src);
    }

    /// Check if a byte string contains unescaped interpolation (#{ ... })
    fn has_unescaped_interpolation(&self, src: &[u8]) -> bool {
        let mut i = 0;
        while i < src.len() {
            if src[i] == b'#' && i + 1 < src.len() && src[i + 1] == b'{' {
                // Check if the # is escaped (preceded by odd number of backslashes)
                let mut backslash_count = 0;
                let mut j = i as i32 - 1;
                while j >= 0 && src[j as usize] == b'\\' {
                    backslash_count += 1;
                    j -= 1;
                }
                // If even number of backslashes (or zero), the # is not escaped.
                // Upstream matches /(?<!\\)#\{.*\}/ — `.` doesn't cross
                // newlines, so a `}` must close the braces on the same line
                // (`'#{'` alone is not an interpolation).
                if backslash_count % 2 == 0
                    && src[i + 2..]
                        .iter()
                        .take_while(|&&b| b != b'\n')
                        .any(|&b| b == b'}')
                {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    /// Check if converting to double quotes would result in valid syntax
    fn would_be_valid_double_quoted(&self, src: &[u8]) -> bool {
        // Skip if source contains patterns that would create invalid syntax

        // Skip if contains %<...>s pattern (format string syntax invalid in interpolation)
        if src.windows(2).any(|w| w == b"%<") {
            return false;
        }

        // Get the content (without quotes)
        let content = if src.len() > 2 {
            &src[1..src.len() - 1]
        } else {
            b""
        };

        // Skip if using %{...} format and content has unbalanced closing braces
        if src.contains(&b'"') {
            // Would use %{...} format
            // Check for } followed by #{, which would break the percent literal
            let mut i = 0;
            while i < content.len() {
                if content[i] == b'}' {
                    // Check if this is followed by unescaped #{
                    if i + 1 < content.len() {
                        if content[i + 1..].starts_with(b" #{")
                            || (i + 1 < content.len() && content[i + 1..].starts_with(b"#{")) {
                            return false;
                        }
                    }
                }
                i += 1;
            }
        }

        // Try to parse the converted string
        let double_quoted_string = if src.contains(&b'"') {
            // If the string contains double quotes, wrap with %{...}
            let mut result = Vec::with_capacity(src.len() + 4);
            result.extend_from_slice(b"%{");
            result.extend_from_slice(content);
            result.extend_from_slice(b"}");
            result
        } else {
            // Replace single quotes with double quotes
            let mut result = Vec::with_capacity(src.len());
            result.push(b'"');
            result.extend_from_slice(content);
            result.push(b'"');
            result
        };

        // Try to parse the converted string
        let parse_result = ruby_prism::parse(&double_quoted_string);
        let root_node = &parse_result.node();

        // The parsed result is a ProgramNode, get the first statement
        if let Some(program) = root_node.as_program_node() {
            if let Some(stmt) = program.statements().body().iter().next() {
                // Check if the statement is an interpolated string
                return stmt.as_interpolated_string_node().is_some();
            }
        }

        false
    }

    /// Add the autocorrect fix for interpolation check
    fn add_interpolation_fix(&mut self, open_start: usize, open_end: usize, close_start: usize, close_end: usize, src: &[u8]) {
        if src.contains(&b'"') {
            // Replace single quote with %{
            self.fixes.push((open_start, open_end, b"%{".to_vec()));
            // Replace closing single quote with }
            self.fixes.push((close_start, close_end, b"}".to_vec()));
        } else {
            // Replace single quotes with double quotes
            self.fixes.push((open_start, open_end, b"\"".to_vec()));
            self.fixes.push((close_start, close_end, b"\"".to_vec()));
        }
    }
}

impl<'a> Cops<'a> {
    /// Lint/FloatComparison — avoid direct comparison of floats for equality.
    pub(crate) fn check_float_comparison(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/FloatComparison";
        if !self.on(COP) {
            return;
        }

        let name = node.name().as_slice();
        if !matches!(name, b"==" | b"!=" | b"eql?" | b"equal?") {
            return;
        }

        // Must have exactly 1 argument
        let Some(args) = node.arguments() else { return };
        let mut args_iter = args.arguments().iter();
        let Some(rhs) = args_iter.next() else { return };
        if args_iter.next().is_some() {
            return; // More than one argument
        }

        let lhs = node.receiver();

        // Check if either side is "safe"
        let lhs_safe = lhs.as_ref().map_or(false, |n| self.literal_safe_node(&n));
        let rhs_safe = self.literal_safe_node(&rhs);
        if lhs_safe || rhs_safe {
            return;
        }

        // Check if either side is a float
        let lhs_float = lhs.as_ref().map_or(false, |n| self.is_float_node(&n));
        let rhs_float = self.is_float_node(&rhs);
        if !lhs_float && !rhs_float {
            return;
        }

        let message = if name == b"!=" {
            "Avoid inequality comparisons of floats as they are unreliable."
        } else {
            "Avoid equality comparisons of floats as they are unreliable."
        };

        self.push(node.location().start_offset(), COP, false, message);
    }

    /// Check case statement for float comparisons
    pub(crate) fn check_float_comparison_case(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Lint/FloatComparison";
        if !self.on(COP) {
            return;
        }

        for branch in node.conditions().iter() {
            let Some(when_node) = branch.as_when_node() else { continue };
            for condition in when_node.conditions().iter() {
                if !self.is_float_node(&condition) || self.literal_safe_node(&condition) {
                    continue;
                }
                self.push(
                    condition.location().start_offset(),
                    COP,
                    false,
                    "Avoid float literal comparisons in case statements as they are unreliable.",
                );
            }
        }
    }

    /// Check if a node represents a float value
    fn is_float_node(&self, node: &ruby_prism::Node) -> bool {
        // Direct float literal
        if node.as_float_node().is_some() {
            return true;
        }

        // Parentheses node - recurse on the first inner statement, like
        // upstream's `float?(node.children.first)` for :begin nodes.
        if let Some(paren) = node.as_parentheses_node() {
            if let Some(inner) = paren
                .body()
                .and_then(|b| b.as_statements_node().and_then(|st| st.body().iter().next()))
            {
                return self.is_float_node(&inner);
            }
            return false;
        }

        // Call node - check if it returns a float
        if let Some(call) = node.as_call_node() {
            return self.is_float_send(&call);
        }

        false
    }

    /// Check if a send node returns a float
    fn is_float_send(&self, node: &ruby_prism::CallNode) -> bool {
        let name = node.name().as_slice();

        // Float-returning methods: to_f, Float, fdiv
        if matches!(name, b"to_f" | b"Float" | b"fdiv") {
            return true;
        }

        // Check for arithmetic operations
        if self.is_arithmetic_operation(node) {
            if let Some(receiver) = node.receiver() {
                if self.is_float_node(&receiver) {
                    return true;
                }
            }
            if let Some(args) = node.arguments() {
                if let Some(first_arg) = args.arguments().iter().next() {
                    if self.is_float_node(&first_arg) {
                        return true;
                    }
                }
            }
            return false;
        }

        // Check for methods on float receivers
        if let Some(receiver) = node.receiver() {
            if receiver.as_float_node().is_some() {
                // FLOAT_INSTANCE_METHODS: @-, abs, magnitude, modulo, next_float, prev_float, quo
                if matches!(
                    name,
                    b"-@" | b"abs" | b"magnitude" | b"modulo" | b"next_float" | b"prev_float" | b"quo"
                ) {
                    return true;
                }

                // Check numeric-returning methods that can return floats
                if self.numeric_returning_method_returns_float(node) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a call node is an arithmetic operation
    fn is_arithmetic_operation(&self, node: &ruby_prism::CallNode) -> bool {
        matches!(
            node.name().as_slice(),
            b"+" | b"-" | b"*" | b"/" | b"%" | b"**"
        )
    }

    /// Check if a numeric-returning method returns float (has precision argument)
    fn numeric_returning_method_returns_float(&self, node: &ruby_prism::CallNode) -> bool {
        let name = node.name().as_slice();

        match name {
            b"angle" | b"arg" | b"phase" => {
                // These return float if receiver is negative
                if let Some(receiver) = node.receiver() {
                    if receiver.as_float_node().is_some() {
                        // Check if the float value is negative by looking at source
                        let src = self.node_src(&receiver);
                        let src_str = String::from_utf8_lossy(src);
                        // If source starts with -, it's negative
                        return src_str.starts_with('-');
                    }
                }
                false
            }
            b"ceil" | b"floor" | b"round" | b"truncate" => {
                // These return float only if they have a positive precision argument
                if let Some(args) = node.arguments() {
                    if let Some(first_arg) = args.arguments().iter().next() {
                        if first_arg.as_integer_node().is_some() {
                            let src = self.node_src(&first_arg);
                            let src_str = String::from_utf8_lossy(src);
                            // Try to parse as integer
                            if let Ok(precision) = src_str.parse::<i64>() {
                                return precision > 0;
                            }
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check if a node is "safe" for comparison (zero numeric or nil)
    fn literal_safe_node(&self, node: &ruby_prism::Node) -> bool {
        // Handle parentheses node - recurse on the first inner statement,
        // like upstream's `literal_safe?(node.children.first)` for :begin.
        if let Some(paren) = node.as_parentheses_node() {
            if let Some(inner) = paren
                .body()
                .and_then(|b| b.as_statements_node().and_then(|st| st.body().iter().next()))
            {
                return self.literal_safe_node(&inner);
            }
            return false;
        }

        // Check for nil
        if node.as_nil_node().is_some() {
            return true;
        }

        // Numeric zero, by value like upstream's `node.value.zero?` (so
        // `0.00`, `0_0`, `0x0` count) rather than by source spelling.
        if node.as_integer_node().is_some() || node.as_float_node().is_some() {
            let src = String::from_utf8_lossy(self.node_src(&node)).replace('_', "");
            let t = src.trim_start_matches(['-', '+']);
            let zero = if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                i128::from_str_radix(rest, 16) == Ok(0)
            } else if let Some(rest) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
                i128::from_str_radix(rest, 2) == Ok(0)
            } else if let Some(rest) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
                i128::from_str_radix(rest, 8) == Ok(0)
            } else {
                src.parse::<f64>() == Ok(0.0)
            };
            return zero;
        }

        false
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/EmptyWhen — a `when` branch with no body. Not autocorrectable
    /// (rubocop's cop defines no `autocorrect`).
    ///
    /// Offense anchor: `self.push` only carries a start offset (rubocop's
    /// line:col derive from it; range width isn't compared), so the anchor
    /// is simply the `when` keyword's start — verified against real
    /// `rubocop` output (`when :baz then # nothing` reports col 1, matching
    /// `keyword_loc.start`; whitequark's node range for this `when` node
    /// happens to run keyword..end-of-last-condition, i.e. it never extends
    /// through `then`, a comment, or the absent body, but that only matters
    /// for range *width*, which we don't need to reproduce).
    ///
    /// AllowComments (default true): rubocop's `CommentsHelp#contains_comments?`
    /// scans `processed_source.each_comment_in_lines(start_line...end_line)`
    /// where `start_line` is the `when` node's own line and `end_line` is
    /// `find_end_line` — for a plain (non-if/non-block) node that's the line
    /// of its `right_sibling` (the next `when`, or the `else` body's first
    /// statement) if one exists, else the enclosing node's `end` line (the
    /// `case`'s `end` keyword). `comments_contain_disables?` (a further gate
    /// on `rubocop:disable` comments inside the range) isn't replicated —
    /// not exercised by the fixture.
    pub(crate) fn check_empty_when(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Lint/EmptyWhen";
        if !self.on(COP) {
            return;
        }
        let allow_comments = self.cfg.get(COP, "AllowComments") == Some("true");
        let branches: Vec<_> = node.conditions().iter().collect();
        let n = branches.len();
        for (i, branch) in branches.iter().enumerate() {
            let Some(when_node) = branch.as_when_node() else { continue };
            if when_node.statements().is_some() {
                continue;
            }
            let start = when_node.keyword_loc().start_offset();

            if allow_comments {
                let start_line = self.idx.loc(start).0;
                let end_line = if i + 1 < n {
                    self.idx.loc(branches[i + 1].location().start_offset()).0
                } else if let Some(else_node) = node.else_clause() {
                    else_node
                        .statements()
                        .and_then(|s| {
                            s.body().iter().next().map(|s| self.idx.loc(s.location().start_offset()).0)
                        })
                        .unwrap_or_else(|| self.idx.loc(node.end_keyword_loc().start_offset()).0)
                } else {
                    self.idx.loc(node.end_keyword_loc().start_offset()).0
                };
                if self.comments.iter().any(|(line, _, _)| *line >= start_line && *line < end_line) {
                    continue;
                }
            }
            self.push(start, COP, false, "Avoid `when` branches without a body.");
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/InheritException — `class C < Exception` and `Class.new(Exception)`.
    /// `EnforcedStyle` picks the suggested replacement (`standard_error`
    /// default, or `runtime_error`). Autocorrect is unsafe upstream (bare
    /// `rescue` only catches `StandardError`, not `Exception`) but that only
    /// affects RuboCop's `--safe` gating, not this port's fix generation.
    ///
    /// The `class C < Exception` form is exempted when the bare (non-`::`)
    /// name `Exception` would actually resolve to a LOCAL class/module of
    /// that name defined earlier as a direct sibling statement — rubocop's
    /// `inherit_exception_class_with_omitted_namespace?`, ported here via
    /// `exception_siblings_stack` (see the `visit_*` hooks in `mod.rs` that
    /// push/pop it — mirrors the existing `class_children_stack` machinery
    /// but keeps start offsets so only EARLIER siblings count).
    pub(crate) fn check_inherit_exception_class(&mut self, node: &ruby_prism::ClassNode) {
        const COP: &str = "Lint/InheritException";
        if !self.on(COP) {
            return;
        }
        let Some(superclass) = node.superclass() else { return };
        let Some((name, is_cbase)) = inherit_exception_const_info(&superclass) else { return };
        if name != "Exception" {
            return;
        }
        if !is_cbase {
            let node_start = node.location().start_offset();
            let omitted = self.exception_siblings_stack.last().is_some_and(|sibs| {
                sibs.iter().any(|(pos, n)| *pos < node_start && n.as_slice() == b"Exception")
            });
            if omitted {
                return;
            }
        }
        let prefer = inherit_exception_preferred(self.cfg.enforced_style(COP));
        let sl = superclass.location();
        self.push(sl.start_offset(), COP, true, format!("Inherit from `{prefer}` instead of `Exception`."));
        self.fixes.push((sl.start_offset(), sl.end_offset(), prefer.as_bytes().to_vec()));
    }

    /// The `Class.new(Exception)` form of `Lint/InheritException`. Only a
    /// BARE (or `::`-prefixed) single-constant argument to a bare/`::Class`
    /// receiver's `new` qualifies (rubocop's `class_new_call?` node
    /// pattern) — a namespaced argument (`Class.new(Foo::Exception)`) never
    /// matches, same as `Foo::Exception` never matches on the `on_class`
    /// side (its `const_name` isn't bare `"Exception"`).
    pub(crate) fn check_inherit_exception_new(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/InheritException";
        if node.name().as_slice() != b"new" || node.is_safe_navigation() || !self.on(COP) {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if const_name_root(&recv).as_deref() != Some("Class") {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let arg_list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        let [arg] = arg_list.as_slice() else { return };
        if const_name_root(arg).as_deref() != Some("Exception") {
            return;
        }
        let prefer = inherit_exception_preferred(self.cfg.enforced_style(COP));
        let al = arg.location();
        self.push(al.start_offset(), COP, true, format!("Inherit from `{prefer}` instead of `Exception`."));
        self.fixes.push((al.start_offset(), al.end_offset(), prefer.as_bytes().to_vec()));
    }

    /// Names of `class`/`module` nodes that are direct children of `body`,
    /// paired with their start offset — `Lint/InheritException`'s sibling
    /// scan needs source ORDER (rubocop's `left_siblings`), unlike
    /// `direct_child_classes` which only needs the name set.
    pub(crate) fn direct_child_defs(body: &Option<ruby_prism::Node>) -> Vec<(usize, Vec<u8>)> {
        body.as_ref()
            .and_then(|b| b.as_statements_node())
            .map(|stmts| {
                stmts
                    .body()
                    .iter()
                    .filter_map(|n| {
                        if let Some(c) = n.as_class_node() {
                            Some((c.location().start_offset(), c.name().as_slice().to_vec()))
                        } else if let Some(m) = n.as_module_node() {
                            Some((m.location().start_offset(), m.name().as_slice().to_vec()))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn inherit_exception_preferred(style: &str) -> &'static str {
    if style == "runtime_error" {
        "RuntimeError"
    } else {
        "StandardError"
    }
}

/// Root const info as `(name, is_cbase)` for a bare `Foo` or explicit
/// top-level `::Foo` — mirrors `const_name_root` but also reports whether
/// the leading `::` (cbase) was present, since `Lint/InheritException`
/// treats `::Exception` as unambiguous (never an omitted-namespace local
/// reference) while bare `Exception` might resolve locally. Anything with a
/// real namespace segment (`A::Foo`) returns `None` — rubocop's `const_name`
/// would then read `"A::Foo"`, never bare `"Foo"`.
fn inherit_exception_const_info(node: &ruby_prism::Node) -> Option<(String, bool)> {
    if let Some(c) = node.as_constant_read_node() {
        return Some((String::from_utf8_lossy(c.name().as_slice()).into_owned(), false));
    }
    if let Some(p) = node.as_constant_path_node() {
        if p.parent().is_none() {
            return Some((String::from_utf8_lossy(p.name()?.as_slice()).into_owned(), true));
        }
    }
    None
}

impl<'a> super::Cops<'a> {
    /// Lint/ConstantDefinitionInBlock — a bare constant assignment
    /// (`FOO = 1`), or a `class`/`module` definition, that's a direct
    /// statement of a block's body (do..end/`{}`/numblock/itblock — prism
    /// represents all of these as one `BlockNode`).
    ///
    /// Ported from rubocop's two node-matchers:
    ///   constant_assigned_in_block?: ({^any_block [^begin ^^any_block]} nil? ...)
    ///   module_defined_in_block?:    ({^any_block [^begin ^^any_block]} ...)
    /// i.e. the node's parent is any_block, OR its parent is `begin` (a
    /// multi-statement body) and ITS parent is any_block; casgn additionally
    /// requires a nil scope (excludes `self::FOO`/`::FOO`/`Foo::BAR`).
    ///
    /// Prism always wraps a block's body in a `StatementsNode` — even a
    /// single-statement body — so both whitequark shapes above collapse into
    /// one check here: is this node a direct element of a `StatementsNode`
    /// whose own parent is a `BlockNode`? That's exactly what
    /// `block_owns_next_stmts` (set in `visit_block_node`, mod.rs) answers:
    /// it's only ever true for the StatementsNode reached immediately after
    /// a block (a rescue/ensure body inside a block is a `BeginNode`, not a
    /// `StatementsNode`, so the flag is never set for it — matching rubocop,
    /// which doesn't flag a casgn whose parent is `rescue`/`ensure` either).
    ///
    /// `self::FOO = 1` / `::FOO = 1` / `Foo::BAR = 1` (prism's
    /// ConstantPathWriteNode) always have a non-nil scope, so they can never
    /// match the upstream pattern — only plain ConstantWriteNode is checked.
    /// Compound constant assignment (`FOO ||= 1`, `FOO += 1`, ...) translates
    /// to `(op_asgn (casgn nil :FOO) ...)` upstream — the casgn's parent is
    /// the op-asgn node, never any_block/begin — so those never match either
    /// and prism's dedicated Or/And/Operator-write nodes are correctly never
    /// hooked into this check.
    pub(crate) fn check_constant_definition_in_block(&mut self, stmts: &ruby_prism::StatementsNode) {
        const COP: &str = "Lint/ConstantDefinitionInBlock";
        let parent_is_block = std::mem::take(&mut self.block_owns_next_stmts);
        if !parent_is_block || !self.on(COP) {
            return;
        }
        let Some(&(mstart, mend)) = self.call_stack.last() else { return };
        for stmt in stmts.body().iter() {
            if stmt.as_constant_write_node().is_none()
                && stmt.as_class_node().is_none()
                && stmt.as_module_node().is_none()
            {
                continue;
            }
            let method_name = &self.src[mstart..mend];
            if self.allowed(COP, method_name) {
                continue;
            }
            self.push(
                stmt.location().start_offset(),
                COP,
                false,
                "Do not define constants this way within a block.",
            );
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/ElseLayout — flags an `if`/`elsif`/`unless` whose `else` branch's
    /// first statement sits on the SAME source line as the `else` keyword
    /// itself (e.g. `else do_this`), since that's usually a mistake for
    /// `elsif`.
    ///
    /// Upstream's `on_if` (which also fires for `unless`, normalized to the
    /// same node shape) guards with `ternary?`, `then? && !else_branch
    /// .begin_type?`, and `single_line?`, then calls a private `check`
    /// that recurses ONE level, UNGUARDED, into an elsif's own
    /// `else_branch` — but only when the CURRENT node's own keyword is
    /// literally `if` (not `elsif`, not `unless`). Every node in an elsif
    /// chain is *also* visited independently by the normal AST walk (prism
    /// recurses into `subsequent()`, re-running this same guarded entry
    /// point), which is what actually handles chains of 2+ elsifs — the
    /// recursion only ever bridges exactly one level.
    ///
    /// Because the recursion bypasses the guards, it can surface an offense
    /// that the guarded entry for that SAME node would have suppressed:
    /// `if a; elsif b then y; else short; end` still offends on `short`
    /// even though `b`'s own `then?` + single-statement-else guard would
    /// block it if reached only via the normal walk (verified against a
    /// live `rubocop` run). Both paths can also converge on the very same
    /// `else` (one elsif directly followed by the real `else`); upstream
    /// dedups via `Base#add_offense`'s `current_offense_locations.add?`, so
    /// `else_layout_seen` (keyed by the offense's anchor offset) mirrors
    /// that here.
    pub(crate) fn check_else_layout_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Lint/ElseLayout";
        if !self.on(COP) {
            return;
        }
        // A `?:` ternary has no `if`/`elsif` keyword in prism.
        let Some(kw) = node.if_keyword_loc() else { return };
        let then_present = node.then_keyword_loc().is_some();
        let subsequent = node.subsequent();
        if then_present && !else_layout_begin_type(&subsequent) {
            return;
        }
        let l = node.location();
        if self.idx.loc(l.start_offset()).0 == self.idx.loc(l.end_offset().saturating_sub(1)).0 {
            return;
        }
        let is_if_kw = kw.as_slice() == b"if";
        self.else_layout_check(l.start_offset(), subsequent, is_if_kw);
    }

    /// Lint/ElseLayout for `unless ... else ...` — `unless` can't chain into
    /// an `elsif`, so there's no unguarded-recursion path here; only the
    /// guarded entry applies.
    pub(crate) fn check_else_layout_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Lint/ElseLayout";
        if !self.on(COP) {
            return;
        }
        let then_present = node.then_keyword_loc().is_some();
        let subsequent = node.else_clause().map(|e| e.as_node());
        if then_present && !else_layout_begin_type(&subsequent) {
            return;
        }
        let l = node.location();
        if self.idx.loc(l.start_offset()).0 == self.idx.loc(l.end_offset().saturating_sub(1)).0 {
            return;
        }
        self.else_layout_check(l.start_offset(), subsequent, false);
    }

    /// Upstream's private `check`: unconditional (no ternary/then/single_line
    /// guards — those only gate the entry points above). `node_start` is the
    /// start offset of whichever if/elsif node is "current" (its own column
    /// drives the autocorrect's indentation, matching `indentation(node)` on
    /// whatever node upstream's recursion last reassigned `node` to).
    fn else_layout_check(&mut self, node_start: usize, subsequent: Option<ruby_prism::Node>, is_if_kw: bool) {
        let Some(sub) = subsequent else { return };
        if let Some(else_node) = sub.as_else_node() {
            self.check_else_layout_body(node_start, &else_node);
        } else if is_if_kw {
            // `node.if?` — only a genuine `if` (not `elsif`/`unless`) recurses;
            // the recursed-into elsif's own keyword is always "elsif", so this
            // never continues past one level.
            if let Some(elsif) = sub.as_if_node() {
                self.else_layout_check(elsif.location().start_offset(), elsif.subsequent(), false);
            }
        }
    }

    /// Upstream's `check_else`: offense anchored on the else body's first
    /// statement when it shares a source line with the `else` keyword.
    fn check_else_layout_body(&mut self, node_start: usize, else_node: &ruby_prism::ElseNode) {
        const COP: &str = "Lint/ElseLayout";
        let Some(stmts) = else_node.statements() else { return };
        let Some(first) = stmts.body().iter().next() else { return };
        let first_start = first.location().start_offset();
        let else_kw = else_node.else_keyword_loc();
        if self.idx.loc(first_start).0 != self.idx.loc(else_kw.start_offset()).0 {
            return;
        }
        if !self.else_layout_seen.insert(first_start) {
            return;
        }
        self.push(first_start, COP, true, "Odd `else` layout detected. Did you mean to use `elsif`?");
        // `Alignment#indentation`: the owning node's own column, plus
        // `configured_indentation_width` (cop-local `IndentationWidth`, else
        // `Layout/IndentationWidth`'s `Width`, else 2).
        let width = self
            .cfg
            .param(COP, "IndentationWidth")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(|| self.cfg.int("Layout/IndentationWidth", "Width"));
        let (_, col) = self.idx.loc(node_start);
        let mut replacement = vec![b'\n'];
        replacement.extend(std::iter::repeat(b' ').take(col - 1 + width));
        // `corrector.insert_after(loc.else, "\n")` + replacing the blank gap
        // through the first statement with `indentation(node)` collapse into
        // one range replace: the gap only ever holds whitespace (`first` is
        // upstream's `first_else`, the immediate next token after `else`).
        self.fixes.push((else_kw.end_offset(), first_start, replacement));
    }
}

/// Upstream's `else_branch.begin_type?` (via `&.`, so `nil` counts as
/// not-begin too): true only when the falsy branch is a real `else` whose
/// body holds 2+ statements (a single statement, or an elsif chain link —
/// itself a lone `:if` node — is never wrapped in a `:begin`).
fn else_layout_begin_type(subsequent: &Option<ruby_prism::Node>) -> bool {
    subsequent.as_ref().is_some_and(|n| {
        n.as_else_node()
            .is_some_and(|e| e.statements().is_some_and(|s| s.body().iter().count() >= 2))
    })
}
impl<'a> Cops<'a> {
    /// Lint/DisjunctiveAssignmentInConstructor — checks for disjunctive
    /// assignment (||=) of instance variables in initialize methods.
    /// Since instance variables are nil by default, ||= is unnecessary.
    pub(crate) fn check_disjunctive_assignment_in_constructor(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/DisjunctiveAssignmentInConstructor";
        if !self.on(COP) {
            return;
        }
        // Only check initialize methods (plain def, not defs)
        if node.name().as_slice() != b"initialize" || node.receiver().is_some() {
            return;
        }
        let Some(body) = node.body() else { return };

        // Check statements until we hit something other than ||= on ivars
        if let Some(stmts) = body.as_statements_node() {
            // Multiple statements in the body
            for stmt in stmts.body().iter() {
                if let Some(or_write) = stmt.as_instance_variable_or_write_node() {
                    // Found ||= on instance variable - report offense
                    let op_loc = or_write.operator_loc();
                    self.push(op_loc.start_offset(), COP, true,
                        "Unnecessary disjunctive assignment. Use plain assignment.");
                    // Fix: replace ||= with =
                    self.fixes.push((op_loc.start_offset(), op_loc.end_offset(), b"=".to_vec()));
                } else {
                    // Stop checking - we found something other than ivar ||=
                    break;
                }
            }
        } else {
            // Single statement in the body
            if let Some(or_write) = body.as_instance_variable_or_write_node() {
                let op_loc = or_write.operator_loc();
                self.push(op_loc.start_offset(), COP, true,
                    "Unnecessary disjunctive assignment. Use plain assignment.");
                self.fixes.push((op_loc.start_offset(), op_loc.end_offset(), b"=".to_vec()));
            }
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Lint/IneffectiveAccessModifier — a bare `private`/`protected` inside a
    /// class/module body has no effect on `def self.foo` (a "defs", i.e. a
    /// method def with an explicit receiver) that follows it; only
    /// `private_class_method`, or `private`/`protected` inside a
    /// `class << self` block, actually restricts singleton methods.
    ///
    /// Ported from the upstream `ineffective_modifier` walk: only runs when
    /// the class/module body is a `begin_type?` (2+ statements — a
    /// single-statement body can never contain both a modifier and a defs).
    /// Walks the body's direct statements, tracking the most recently seen
    /// bare `public`/`private`/`protected` call (module_function is a bare
    /// access-modifier-shaped send too, but is excluded from consideration —
    /// it neither sets nor clears the tracked modifier) and recursing into
    /// bare `begin...end` blocks (no rescue/else/ensure — whitequark's
    /// `kwbegin`) with the modifier/ignore-list carried in, but changes made
    /// inside the nested block do NOT propagate back out (matching upstream's
    /// per-call local variable semantics).
    pub(crate) fn check_ineffective_access_modifier(&mut self, body: Option<ruby_prism::Node>) {
        const COP: &str = "Lint/IneffectiveAccessModifier";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body else { return };
        let Some(stmts) = body.as_statements_node() else { return };

        // `private_class_method_names`: upstream's `def_node_search` scans
        // the ENTIRE body subtree once (memoized on first use, but always
        // rooted at the top-level body node regardless of nesting depth) —
        // precomputing it eagerly here is equivalent.
        let mut ignored: HashSet<Vec<u8>> = HashSet::new();
        iam_collect_private_class_method_names(&stmts.as_node(), self.src, &mut ignored);

        self.iam_walk(&stmts, &ignored, None);
    }

    fn iam_walk(
        &mut self,
        stmts: &ruby_prism::StatementsNode,
        ignored: &HashSet<Vec<u8>>,
        mut modifier: Option<(usize, &'static str)>,
    ) {
        for child in stmts.body().iter() {
            if let Some(call) = child.as_call_node() {
                if call.receiver().is_none() && call.arguments().is_none() {
                    let off = call.location().start_offset();
                    match call.name().as_slice() {
                        b"public" => modifier = Some((off, "public")),
                        b"private" => modifier = Some((off, "private")),
                        b"protected" => modifier = Some((off, "protected")),
                        // `module_function` is structurally a bare access
                        // modifier too, but upstream's `access_modifier?`
                        // explicitly excludes it — leave `modifier` as-is.
                        _ => {}
                    }
                }
                continue;
            }
            if let Some(def) = child.as_def_node() {
                if def.receiver().is_some() {
                    self.iam_check_defs(&def, modifier, ignored);
                }
                continue;
            }
            if let Some(b) = child.as_begin_node() {
                if b.rescue_clause().is_none() && b.else_clause().is_none() && b.ensure_clause().is_none() {
                    if let Some(inner) = b.statements() {
                        self.iam_walk(&inner, ignored, modifier);
                    }
                }
            }
        }
    }

    fn iam_check_defs(
        &mut self,
        def: &ruby_prism::DefNode,
        modifier: Option<(usize, &'static str)>,
        ignored: &HashSet<Vec<u8>>,
    ) {
        const COP: &str = "Lint/IneffectiveAccessModifier";
        let Some((mod_off, visibility)) = modifier else { return };
        if visibility == "public" {
            return;
        }
        if ignored.contains(def.name().as_slice()) {
            return;
        }
        let alternative = if visibility == "private" {
            "`private_class_method` or `private` inside a `class << self` block"
        } else {
            "`protected` inside a `class << self` block"
        };
        let line = self.idx.loc(mod_off).0;
        let message = format!(
            "`{visibility}` (on line {line}) does not make singleton methods {visibility}. Use {alternative} instead."
        );
        self.push(def.def_keyword_loc().start_offset(), COP, false, message);
    }
}

/// Collects the symbol-literal arguments of every bare (no receiver)
/// `private_class_method` call anywhere in `node`'s subtree — upstream's
/// `private_class_methods` node search + `.select(&:basic_literal?)`.
///
/// Upstream's `$...` capture collects the call's direct argument nodes into a
/// plain Ruby array, and `.to_a.flatten` only flattens THAT array (multiple
/// args to one call, or across multiple calls) — it does NOT unpack an
/// `ArrayNode` passed as a single argument (`private_class_method [:a, :b]`):
/// `Array#flatten` doesn't descend into non-Array AST node objects, and an
/// array-literal *node* itself fails `basic_literal?` (arrays are a
/// `COMPOSITE_LITERAL`, excluded from `BASIC_LITERALS`) so it's filtered out
/// entirely — verified against real rubocop 1.88, which still flags every
/// singleton def when `private_class_method` is passed an array literal.
/// Only direct symbol-literal arguments are ever collected here; string/
/// numeric/etc. literal args are dropped too, since they can never satisfy
/// the `ignored_methods.include?` check upstream performs against a `defs`
/// node's (always-a-symbol) `method_name`.
fn iam_collect_private_class_method_names(node: &ruby_prism::Node, src: &[u8], out: &mut HashSet<Vec<u8>>) {
    struct Finder<'a> {
        src: &'a [u8],
        out: &'a mut HashSet<Vec<u8>>,
    }
    impl<'pr, 'a> ruby_prism::Visit<'pr> for Finder<'a> {
        fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
            if node.receiver().is_none() && node.name().as_slice() == b"private_class_method" {
                if let Some(args) = node.arguments() {
                    for arg in args.arguments().iter() {
                        if let Some(sym) = arg.as_symbol_node() {
                            if let Some(v) = sym.value_loc() {
                                self.out.insert(self.src[v.start_offset()..v.end_offset()].to_vec());
                            }
                        }
                    }
                }
            }
            ruby_prism::visit_call_node(self, node);
        }
    }
    let mut f = Finder { src, out };
    use ruby_prism::Visit;
    f.visit(node);
}

impl<'a> super::Cops<'a> {
    /// Lint/DeprecatedOpenSSLConstant — `OpenSSL::Cipher::ALGO.new(...)` /
    /// `OpenSSL::Digest::ALGO.{new,digest}(...)` where `ALGO` is a bare
    /// constant (algorithm-as-a-class-name) rather than a string argument.
    /// Ports rubocop's `algorithm_const` node-pattern (a three-deep constant
    /// path rooted at `OpenSSL`, with `Cipher`/`Digest` as the middle
    /// segment) plus its `replacement_args`/`build_cipher_arguments`
    /// algorithm-name-to-string transform, verbatim.
    pub(crate) fn check_deprecated_open_ssl_constant(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/DeprecatedOpenSSLConstant";
        if !self.on(COP) {
            return;
        }
        // RESTRICT_ON_SEND = %i[new digest]
        let name = node.name().as_slice();
        if name != b"new" && name != b"digest" {
            return;
        }
        // `return if node.arguments.any? { |arg| arg.variable? || arg.call_type? || arg.const_type? }`
        // variable? == ivar/gvar/cvar/lvar (read forms); call_type? also
        // covers safe-navigation (`&.`) since prism marks that as a flag on
        // the same `CallNode`, not a distinct node type.
        if let Some(args) = node.arguments() {
            for arg in args.arguments().iter() {
                if arg.as_local_variable_read_node().is_some()
                    || arg.as_instance_variable_read_node().is_some()
                    || arg.as_class_variable_read_node().is_some()
                    || arg.as_global_variable_read_node().is_some()
                    || arg.as_call_node().is_some()
                    || arg.as_constant_read_node().is_some()
                    || arg.as_constant_path_node().is_some()
                {
                    return;
                }
            }
        }
        let Some(receiver) = node.receiver() else { return };
        // `return if digest_const?(node.receiver)` — checked BEFORE
        // `algorithm_const`, so any receiver whose own outer name is
        // `Digest` (bare `OpenSSL::Digest`, or the doubled-up
        // `OpenSSL::Digest::Digest`) is exempted outright.
        if openssl_digest_const_name(&receiver) {
            return;
        }
        // `return unless algorithm_const(node)`
        let Some(algo) = openssl_algorithm_const(&receiver) else { return };
        let mid = algo.parent().expect("matched structure always has a middle segment");
        let openssl_class = String::from_utf8_lossy(self.node_src(&mid)).into_owned();
        let algo_full_src = String::from_utf8_lossy(self.node_src(&algo.as_node())).into_owned();
        let name_loc = algo.name_loc();
        let algo_name_src =
            String::from_utf8_lossy(&self.src[name_loc.start_offset()..name_loc.end_offset()]).into_owned();

        let arg_nodes: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();

        let replacement_args = if algo_full_src == "OpenSSL::Cipher::Cipher" {
            // `algorithm_constant.source == 'OpenSSL::Cipher::Cipher'` — keep
            // the original first argument's source verbatim.
            arg_nodes.first().map(|a| String::from_utf8_lossy(self.node_src(a)).into_owned()).unwrap_or_default()
        } else {
            let algorithm_name = openssl_algorithm_name(&algo_name_src, &openssl_class);
            if openssl_class == "OpenSSL::Cipher" {
                openssl_build_cipher_arguments(self.src, &arg_nodes, &algorithm_name)
            } else {
                let mut parts = vec![format!("'{algorithm_name}'")];
                for a in &arg_nodes {
                    parts.push(String::from_utf8_lossy(self.node_src(a)).into_owned());
                }
                parts.join(", ")
            }
        };

        let method = node
            .message_loc()
            .map(|l| String::from_utf8_lossy(&self.src[l.start_offset()..l.end_offset()]).into_owned())
            .unwrap_or_default();
        let original = String::from_utf8_lossy(self.node_src(&node.as_node())).into_owned();
        let message = format!("Use `{openssl_class}.{method}({replacement_args})` instead of `{original}`.");

        let l = node.location();
        self.push(l.start_offset(), COP, true, message);

        // `corrector.remove(algorithm_constant.loc.double_colon)` +
        // `corrector.remove(algorithm_constant.loc.name)` — strip `::ALGO`
        // off the receiver, leaving `OpenSSL::Cipher`/`OpenSSL::Digest`.
        let delim = algo.delimiter_loc();
        self.fixes.push((delim.start_offset(), delim.end_offset(), Vec::new()));
        self.fixes.push((name_loc.start_offset(), name_loc.end_offset(), Vec::new()));
        // `corrector.replace(correction_range(node), "#{selector}(#{replacement_args})")`
        if let Some(dot) = node.call_operator_loc() {
            let replacement = format!("{method}({replacement_args})").into_bytes();
            self.fixes.push((dot.end_offset(), l.end_offset(), replacement));
        }
    }
}

/// rubocop's `algorithm_const` node-pattern:
/// `(send $(const (const (const {nil? cbase} :OpenSSL) {:Cipher :Digest}) _) ...)`
/// — the receiver must be a three-deep constant path rooted at `OpenSSL`
/// (bare or `::`-prefixed), with `Cipher` or `Digest` as the middle segment.
/// Returns the innermost (algorithm-name) constant-path node.
fn openssl_algorithm_const<'pr>(recv: &ruby_prism::Node<'pr>) -> Option<ruby_prism::ConstantPathNode<'pr>> {
    let algo = recv.as_constant_path_node()?;
    let mid = algo.parent()?;
    let mid_path = mid.as_constant_path_node()?;
    let mid_name = mid_path.name()?;
    if mid_name.as_slice() != b"Cipher" && mid_name.as_slice() != b"Digest" {
        return None;
    }
    let root = mid_path.parent()?;
    let is_openssl_root = if let Some(cr) = root.as_constant_read_node() {
        cr.name().as_slice() == b"OpenSSL"
    } else if let Some(cp) = root.as_constant_path_node() {
        cp.parent().is_none() && cp.name().is_some_and(|n| n.as_slice() == b"OpenSSL")
    } else {
        false
    };
    is_openssl_root.then_some(algo)
}

/// rubocop's `digest_const?` node-pattern: `(const _ :Digest)` — true when
/// the receiver, at its OUTERMOST level (regardless of nesting), is itself a
/// constant named `Digest`.
fn openssl_digest_const_name(node: &ruby_prism::Node) -> bool {
    if let Some(p) = node.as_constant_path_node() {
        return p.name().is_some_and(|n| n.as_slice() == b"Digest");
    }
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == b"Digest";
    }
    false
}

const OPENSSL_NO_ARG_ALGORITHM: &[&str] = &["BF", "DES", "IDEA", "RC4"];

/// rubocop's `algorithm_name`: for `Cipher` (and not one of the no-argument
/// algorithms), chunk the raw constant name into 3-character groups
/// (`AES128` -> `AES-128`, trailing partial group dropped like `.scan`); for
/// `Digest` (or a no-arg `Cipher` algorithm), use the name verbatim.
fn openssl_algorithm_name(name: &str, openssl_class: &str) -> String {
    if openssl_class == "OpenSSL::Cipher" && !OPENSSL_NO_ARG_ALGORITHM.contains(&name) {
        name.as_bytes()
            .chunks(3)
            .filter(|c| c.len() == 3)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    } else {
        name.to_string()
    }
}

/// rubocop's `sanitize_arguments`: each original call argument becomes one
/// or more tokens — string literals contribute their unescaped VALUE, other
/// nodes (symbols, integers, ...) contribute raw source text; `:`/`'` are
/// stripped, then the result is split on `-` and downcased.
fn openssl_sanitize_arguments(src: &[u8], args: &[ruby_prism::Node]) -> Vec<String> {
    let mut out = Vec::new();
    for arg in args {
        let raw: String = if let Some(s) = arg.as_string_node() {
            String::from_utf8_lossy(s.unescaped()).into_owned()
        } else {
            let l = arg.location();
            String::from_utf8_lossy(&src[l.start_offset()..l.end_offset()]).into_owned()
        };
        let cleaned: String = raw.chars().filter(|&c| c != ':' && c != '\'').collect();
        for part in cleaned.split('-') {
            out.push(part.to_lowercase());
        }
    }
    out
}

/// rubocop's `build_cipher_arguments`: combine the (already `-`-split,
/// downcased) algorithm name with the sanitized call arguments — a bare
/// no-argument algorithm called with zero arguments returns just its own
/// name; otherwise append a `cbc` default mode only when no size/mode
/// arguments were given, then take the first three `-`-joined parts.
fn openssl_build_cipher_arguments(src: &[u8], args: &[ruby_prism::Node], algorithm_name: &str) -> String {
    let algorithm_parts: Vec<String> = algorithm_name.to_lowercase().split('-').map(str::to_string).collect();
    let no_arguments = args.is_empty();
    let size_and_mode = openssl_sanitize_arguments(src, args);
    if OPENSSL_NO_ARG_ALGORITHM.contains(&algorithm_parts[0].to_uppercase().as_str()) && no_arguments {
        return format!("'{}'", algorithm_parts[0]);
    }
    let mut combined = algorithm_parts;
    combined.extend(size_and_mode.iter().cloned());
    if size_and_mode.is_empty() {
        combined.push("cbc".to_string());
    }
    format!("'{}'", combined.into_iter().take(3).collect::<Vec<_>>().join("-"))
}

impl<'a> super::Cops<'a> {
    /// Lint/AssignmentInCondition — `if/while/until foo = bar` almost always
    /// means `==` was intended. Ported from upstream's `on_if` (aliased to
    /// `on_while`/`on_until`) + its private `traverse_node`/`SafeAssignment`
    /// mixin, walking the ENTIRE condition subtree (not just the top node):
    ///
    ///   - stop dead at a block literal (`return 1 if any_errors? { o = x }`
    ///     never flags the `o = x` inside — a whole call-with-block IS the
    ///     `BlockNode`'s enclosing `CallNode` here, so this only matters for
    ///     nested blocks reached WHILE descending, e.g. `foo { x if y = z }`'s
    ///     OUTER block doesn't stop the INNER `if`'s own on_if walk, since
    ///     that's a fresh top-level call from `visit_if_node`).
    ///   - a plain call/safe-call (`CallNode`) that ISN'T itself an
    ///     assignment method (`foo?`, `include?`, …) stops the walk outright
    ///     — this is what makes a block-call-as-condition inert without a
    ///     separate "is this a block" check: `any_errors? { ... }`'s outer
    ///     node is the `CallNode` (prism attaches the block as a field, not
    ///     an ancestor, unlike whitequark's `(block (send ...) ...)`), and a
    ///     non-assignment method name stops descent before ever reaching it.
    ///   - a parenthesized group (`ParenthesesNode`, upstream's `:begin`)
    ///     is transparent — never itself flagged — but `()` (empty) or (when
    ///     `AllowSafeAssignment`) a SOLE assignment/assignment-call child
    ///     stops the walk there (the "wrap it in parens to opt in" escape
    ///     hatch); any other content keeps descending, catching assignments
    ///     buried in `(foo == bar && baz = 1)`.
    ///   - every other node shape (`&&`, `||`, method args, …) is plain
    ///     structure: never flagged, always descended into.
    ///
    /// `AllowSafeAssignment` (default true) gates BOTH the parenthesized-
    /// escape-hatch above and whether the autocorrect (wrap the flagged
    /// expression in parens) ever fires — when false, offenses still fire
    /// (with a different message) but autocorrect never runs, matching
    /// upstream's `add_offense(...) { |c| next unless safe_assignment_allowed?; ... }`.
    pub(crate) fn check_assignment_in_condition(&mut self, predicate: &ruby_prism::Node) {
        const COP: &str = "Lint/AssignmentInCondition";
        if !self.on(COP) {
            return;
        }
        let allow_safe = self.cfg.get(COP, "AllowSafeAssignment") != Some("false");
        let mut hits: Vec<(usize, usize, usize)> = Vec::new(); // (operator_start, wrap_start, wrap_end)
        {
            struct Finder<'h> {
                allow_safe: bool,
                hits: &'h mut Vec<(usize, usize, usize)>,
            }
            impl<'pr, 'h> ruby_prism::Visit<'pr> for Finder<'h> {
                // A block literal is a dead end — upstream's `any_block_type?`
                // guard fires before anything else, so this never even checks
                // whether the block's underlying call was an assignment.
                fn visit_block_node(&mut self, _node: &ruby_prism::BlockNode<'pr>) {}

                fn visit_parentheses_node(&mut self, node: &ruby_prism::ParenthesesNode<'pr>) {
                    let stmts: Vec<ruby_prism::Node> = node
                        .body()
                        .and_then(|b| b.as_statements_node())
                        .map(|s| s.body().iter().collect())
                        .unwrap_or_default();
                    let empty_condition = stmts.is_empty();
                    let safe_assignment = stmts.len() == 1
                        && (is_equals_assignment(&stmts[0]) || is_assignment_call(&stmts[0]));
                    if empty_condition || (self.allow_safe && safe_assignment) {
                        return; // skip_children?: stop, no offense, no descent
                    }
                    // allowed_construct? (begin_type? is always true here): the
                    // group itself is never flagged, but descent continues.
                    ruby_prism::visit_parentheses_node(self, node);
                }

                fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
                    // skip_children?: `call_type? && !assignment_method?`.
                    if !is_assignment_method_name(node.name().as_slice()) {
                        return;
                    }
                    // allowed_construct? via `conditional_assignment?`
                    // (`!loc.operator`): a bracket/dot assignment ALWAYS has
                    // one in practice (`equal_loc`); the explicit-call form
                    // (`a.[]=(3, 10)`) doesn't, and is correctly left unflagged.
                    if let Some(op) = node.equal_loc() {
                        let l = node.location();
                        self.hits.push((op.start_offset(), l.start_offset(), l.end_offset()));
                    }
                    ruby_prism::visit_call_node(self, node);
                }

                fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_local_variable_write_node(self, node);
                }
                fn visit_instance_variable_write_node(&mut self, node: &ruby_prism::InstanceVariableWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_instance_variable_write_node(self, node);
                }
                fn visit_class_variable_write_node(&mut self, node: &ruby_prism::ClassVariableWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_class_variable_write_node(self, node);
                }
                fn visit_global_variable_write_node(&mut self, node: &ruby_prism::GlobalVariableWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_global_variable_write_node(self, node);
                }
                fn visit_constant_write_node(&mut self, node: &ruby_prism::ConstantWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_constant_write_node(self, node);
                }
                fn visit_constant_path_write_node(&mut self, node: &ruby_prism::ConstantPathWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_constant_path_write_node(self, node);
                }
                fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
                    self.report_write(node.operator_loc(), node.location());
                    ruby_prism::visit_multi_write_node(self, node);
                }
            }
            impl<'h> Finder<'h> {
                fn report_write(&mut self, op: ruby_prism::Location, whole: ruby_prism::Location) {
                    self.hits.push((op.start_offset(), whole.start_offset(), whole.end_offset()));
                }
            }
            let mut finder = Finder { allow_safe, hits: &mut hits };
            use ruby_prism::Visit;
            finder.visit(predicate);
        }
        if hits.is_empty() {
            return;
        }
        let msg = if allow_safe {
            "Use `==` if you meant to do a comparison or wrap the expression in parentheses to indicate you meant to assign in a condition."
        } else {
            "Use `==` if you meant to do a comparison or move the assignment up out of the condition."
        };
        for (op_start, wrap_start, wrap_end) in hits {
            self.push(op_start, COP, allow_safe, msg);
            if allow_safe {
                self.fixes.push((wrap_start, wrap_start, b"(".to_vec()));
                self.fixes.push((wrap_end, wrap_end, b")".to_vec()));
            }
        }
    }
}

/// Upstream's `AST::Node::EQUALS_ASSIGNMENTS` (`lvasgn`/`ivasgn`/`cvasgn`/
/// `gvasgn`/`casgn`/`masgn`) — the plain-`=` write node kinds, split across
/// several prism node types (`casgn` alone splits into `ConstantWriteNode`
/// and `ConstantPathWriteNode` depending on whether the constant is scoped).
fn is_equals_assignment(node: &ruby_prism::Node) -> bool {
    node.as_local_variable_write_node().is_some()
        || node.as_instance_variable_write_node().is_some()
        || node.as_class_variable_write_node().is_some()
        || node.as_global_variable_write_node().is_some()
        || node.as_constant_write_node().is_some()
        || node.as_constant_path_write_node().is_some()
        || node.as_multi_write_node().is_some()
}

/// Upstream's `SafeAssignment#setter_method?` (`[(call ...) setter_method?]`):
/// a call/safe-call node that is ITSELF an assignment (has an operator
/// location) — `test[0] = 10`'s `[]=` call, not a plain predicate call.
fn is_assignment_call(node: &ruby_prism::Node) -> bool {
    node.as_call_node().is_some_and(|c| c.equal_loc().is_some())
}

/// Upstream's `MethodDispatchNode#assignment_method?`: the method name ends
/// in `=` and isn't one of the comparison operators that also end in `=`
/// (`==`, `===`, `!=`, `<=`, `>=`).
fn is_assignment_method_name(name: &[u8]) -> bool {
    !matches!(name, b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<") && name.ends_with(b"=")
}

impl<'a> Cops<'a> {
    /// Lint/AmbiguousRegexpLiteral — a bare (paren-less) command call whose
    /// argument list starts with `/`, which the LEXER itself can't
    /// disambiguate from division. Upstream detects this off
    /// `processed_source.diagnostics` (`reason == :ambiguous_regexp`), which
    /// under rubocop's Prism translation is produced directly from prism's
    /// OWN `PM_WARN_AMBIGUOUS_SLASH` lex-level warning (see
    /// `Prism::Translation::Parser#warning_diagnostic`,
    /// `:ambiguous_slash => Diagnostic.new(:warning, :ambiguous_regexp, ...)`)
    /// — the message text and the 1-byte `/`-anchored location are passed
    /// through unchanged. Reimplementing prism's lex-state machine (`ARG`/
    /// `CMDARG` + `space_seen` + no-space-after) would be significant
    /// surface area for the exact same signal prism already computes and
    /// exposes via `ParseResult#warnings`; we ride that instead, matching
    /// upstream byte-for-byte since it rides the identical warning.
    ///
    /// Only the AUTOCORRECT target — which enclosing call to parenthesize —
    /// needs an AST walk, ported from `find_offense_node`/`first_argument_is_regexp?`/
    /// `method_chain_to_regexp_receiver?` (ambiguous_regexp_literal.rb) and
    /// `Util#add_parentheses` (util.rb).
    pub(crate) fn check_ambiguous_regexp_literal(&mut self, result: &ruby_prism::ParseResult) {
        const COP: &str = "Lint/AmbiguousRegexpLiteral";
        if !self.on(COP) {
            return;
        }
        const MSG: &str = "Ambiguous regexp literal. Parenthesize the method arguments if it's surely a regexp literal, or add a whitespace to the right of the `/` if it should be a division.";
        const WARN_TEXT: &str = "ambiguous `/`; wrap regexp in parentheses or add a space after `/` operator";

        let mut targets: Vec<usize> = Vec::new();
        for w in result.warnings() {
            if w.message() == WARN_TEXT {
                targets.push(w.location().start_offset());
            }
        }
        if targets.is_empty() {
            return;
        }
        let target_set: HashSet<usize> = targets.iter().copied().collect();
        let fixes = arl_find_fixes(&result.node(), &target_set);

        for off in targets {
            let fix = fixes.iter().find(|(o, _)| *o == off).map(|(_, f)| f);
            self.push(off, COP, fix.is_some(), MSG);
            match fix {
                Some(ArlFix::ArgsParen(msg_end, args_end)) => {
                    self.fixes.push((*msg_end, *msg_end + 1, b"(".to_vec()));
                    self.fixes.push((*args_end, *args_end, b")".to_vec()));
                }
                Some(ArlFix::WrapWhole(start, end)) => {
                    self.fixes.push((*start, *start, b"(".to_vec()));
                    self.fixes.push((*end, *end, b")".to_vec()));
                }
                Some(ArlFix::AppendParens(pos)) => {
                    self.fixes.push((*pos, *pos, b"()".to_vec()));
                }
                None => {}
            }
        }
    }
}

/// The autocorrect shape for one ambiguous-regexp offense, mirroring
/// `Util#add_parentheses`'s three live branches (the fourth, `args_type?`,
/// only applies to `...`-forwarding param lists and never to a call node):
/// - `ArgsParen(after_selector, after_last_arg)`: the found node HAS
///   arguments — replace the 1-byte gap right after the method name with
///   `(` and insert `)` right after the last argument (`args_begin`/
///   `args_end` in `util.rb`, ported without ever touching a possibly
///   block-swallowing `node.source_range` — see `ArlFrame::own_end`).
/// - `WrapWhole(start, end)`: the found node does NOT `respond_to?(:arguments)`
///   upstream — the `/regexp/ =~ var` "match-with-lvasgn" special case ONLY
///   (a plain `=~` call whose receiver is a literal regexp gets demoted out
///   of `:send` by whitequark's builder, so generic `Node#receiver` — a
///   node-pattern matcher — returns `nil` for it and the recursion stops
///   there). Plain `corrector.wrap`: parens go around the node's own source,
///   no whitespace surgery.
/// - `AppendParens(after_node)`: the found node has NO arguments at all
///   (`node.arguments.empty?`) — append a bare `()`. Structurally
///   unreachable from a real ambiguous-slash warning (there is always an
///   enclosing bare command call with at least the regexp as an argument),
///   kept only so the port is total over `add_parentheses`'s branches.
enum ArlFix {
    ArgsParen(usize, usize),
    WrapWhole(usize, usize),
    AppendParens(usize),
}

/// One enclosing `CallNode`'s shape, captured while descending into its
/// receiver/arguments — reconstructs exactly the parent-chain information
/// `find_offense_node`'s whitequark recursion reads off `node.parent`,
/// `node.receiver`, and `node.first_argument`, since prism nodes carry no
/// parent pointer.
struct ArlFrame {
    /// End of the method-name token — `args_begin` in `util.rb` is a 1-byte
    /// range starting here (the mandatory space `PM_WARN_AMBIGUOUS_SLASH`
    /// itself requires between the selector and `/`).
    message_end: usize,
    /// Start of the receiver's source, if any — used only for `WrapWhole`.
    receiver_start: Option<usize>,
    /// `first_argument_is_regexp?`: this call's OWN first argument (by
    /// TYPE, not identity — matching upstream exactly) is a regexp literal.
    args_first_is_regexp: bool,
    /// End of the argument list, if this call has any arguments at all —
    /// `None` here is upstream's `node.arguments.empty?`. Never includes an
    /// attached block: an `ArgumentsNode`'s own location never does.
    args_end: Option<usize>,
    /// End of this call's own content, ignoring any attached block — the
    /// prism-vs-whitequark block trap (a prism `CallNode`'s `location()`
    /// spans through `do...end`; the whitequark `:send` node's range never
    /// did). Falls back through arguments → explicit closing paren →
    /// message end.
    own_end: usize,
    /// Whitequark demotes a literal-regexp-receiver `=~` call out of
    /// `:send` (`Parser::Builders::Default#match_op`'s `static_regexp_node`
    /// branch), so generic `Node#receiver` (a node-pattern matcher scoped
    /// to `(send $_ ...)`) returns `nil` for it even though prism's own
    /// `CallNode` structurally has a receiver. This is that demotion.
    is_match_special: bool,
    /// `node.parent.send_type? && node.receiver` (the receiver-chain
    /// ascend condition), with `is_match_special` already folded in as the
    /// generic-`Node#receiver`-returns-`nil` case above.
    has_effective_receiver: bool,
}

impl ArlFrame {
    /// The fix upstream produces when THIS frame is where the recursion
    /// stops (`add_parentheses`'s dispatch on the resolved node).
    fn fix(&self) -> ArlFix {
        if self.is_match_special {
            ArlFix::WrapWhole(self.receiver_start.unwrap_or(self.message_end), self.own_end)
        } else if let Some(args_end) = self.args_end {
            ArlFix::ArgsParen(self.message_end, args_end)
        } else {
            ArlFix::AppendParens(self.own_end)
        }
    }
}

/// Walks `root` maintaining a stack of enclosing `ArlFrame`s (pushed/popped
/// around each `CallNode`'s receiver/arguments/block, i.e. exactly its
/// prism subtree), and for every regexp literal whose start offset is in
/// `targets`, replays `find_offense_node`'s ascend loop directly against the
/// stack from innermost outward — since a stack frame IS the enclosing
/// node's relevant state, ascending is just walking toward index 0.
fn arl_find_fixes(root: &ruby_prism::Node, targets: &HashSet<usize>) -> Vec<(usize, ArlFix)> {
    struct Walker<'t> {
        targets: &'t HashSet<usize>,
        stack: Vec<ArlFrame>,
        fixes: Vec<(usize, ArlFix)>,
    }
    impl<'t> Walker<'t> {
        fn resolve(&mut self, off: usize) {
            if !self.targets.contains(&off) {
                return;
            }
            let mut i = self.stack.len();
            while i > 0 {
                i -= 1;
                let ascend = {
                    let f = &self.stack[i];
                    if f.args_first_is_regexp {
                        self.fixes.push((off, f.fix()));
                        return;
                    }
                    if i == 0 {
                        self.fixes.push((off, f.fix()));
                        return;
                    }
                    f.has_effective_receiver
                };
                if !ascend {
                    self.fixes.push((off, self.stack[i].fix()));
                    return;
                }
            }
        }
    }
    impl<'pr, 't> ruby_prism::Visit<'pr> for Walker<'t> {
        fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
            let pushed = if let Some(msg) = node.message_loc() {
                let message_end = msg.end_offset();
                let receiver = node.receiver();
                let is_match_special = node.name().as_slice() == b"=~"
                    && receiver.as_ref().is_some_and(|r| r.as_regular_expression_node().is_some());
                let receiver_start = receiver.as_ref().map(|r| r.location().start_offset());
                let has_receiver = receiver.is_some();
                let args = node.arguments();
                let args_first_is_regexp = args
                    .as_ref()
                    .and_then(|a| a.arguments().first())
                    .is_some_and(|n| {
                        n.as_regular_expression_node().is_some()
                            || n.as_interpolated_regular_expression_node().is_some()
                    });
                let args_end = args.as_ref().map(|a| a.location().end_offset());
                let own_end = args_end
                    .or_else(|| node.closing_loc().map(|l| l.end_offset()))
                    .unwrap_or(message_end);
                self.stack.push(ArlFrame {
                    message_end,
                    receiver_start,
                    args_first_is_regexp,
                    args_end,
                    own_end,
                    is_match_special,
                    has_effective_receiver: has_receiver && !is_match_special,
                });
                true
            } else {
                false
            };
            ruby_prism::visit_call_node(self, node);
            if pushed {
                self.stack.pop();
            }
        }
        fn visit_regular_expression_node(&mut self, node: &ruby_prism::RegularExpressionNode<'pr>) {
            self.resolve(node.location().start_offset());
        }
        fn visit_interpolated_regular_expression_node(
            &mut self,
            node: &ruby_prism::InterpolatedRegularExpressionNode<'pr>,
        ) {
            self.resolve(node.location().start_offset());
            ruby_prism::visit_interpolated_regular_expression_node(self, node);
        }
    }
    let mut w = Walker { targets, stack: Vec::new(), fixes: Vec::new() };
    use ruby_prism::Visit;
    w.visit(root);
    w.fixes
}

impl<'a> Cops<'a> {
    /// Lint/AmbiguousBlockAssociation — `some_method a { |x| .. }`: a bare
    /// (unparenthesized) call whose LAST argument is itself a call taking a
    /// literal block. Reads like the block belongs to `some_method`, but it
    /// actually belongs to `a`. Ported verbatim from upstream's `on_send`
    /// (aliased `on_csend`) plus the `AllowedMethods`/`AllowedPattern` mixins.
    ///
    /// Prism attaches a literal block as a FIELD of the call it belongs to,
    /// not as a separate wrapping node the way whitequark's `(block (send
    /// ...) ...)` does. So upstream's `send_node.last_argument` (a `BlockNode`
    /// whose `#send_node` is the wrapped call) collapses here into ONE prism
    /// `CallNode`: the last element of `node`'s own arguments, IF its
    /// `.block()` is a `BlockNode` — a `&:sym`/`&blk` pass-through surfaces as
    /// a `BlockArgumentNode` there instead and correctly never matches
    /// `as_block_node()` (upstream's `any_block_type?` excludes it too).
    ///
    /// Because that inner call's own prism location already spans from its
    /// start THROUGH its block's closing delimiter (unlike the whitequark
    /// send node, whose `#source_range` stops before the block), anywhere
    /// upstream reads `last_argument.send_node.source`/`#method_name` for
    /// text OTHER than the full param dump, we must exclude the trailing
    /// block ourselves (`call_source_excluding_block`); anywhere it reads
    /// `last_argument.source`/`#source_range` wholesale (the offense param,
    /// and the autocorrect's `insert_after` point) the raw prism location is
    /// exactly right, block included, with no adjustment needed.
    pub(crate) fn check_ambiguous_block_association(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/AmbiguousBlockAssociation";
        if !self.on(COP) {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let Some(last) = args.arguments().last() else { return };
        // `ambiguous_block_association?`: last arg is itself a block-having
        // call (never a `&blk`/`&:sym` pass-through) whose OWN call has no
        // explicit arguments of its own.
        let Some(inner) = last.as_call_node() else { return };
        if inner.block().and_then(|b| b.as_block_node()).is_none() {
            return;
        }
        if inner.arguments().is_some() {
            return;
        }
        // `node.parenthesized?` — `loc.end.is?(')')`.
        if node.closing_loc().is_some_and(|c| c.as_slice() == b")") {
            return;
        }
        // `node.last_argument.lambda_or_proc?`
        if is_lambda_or_proc_call(&inner) {
            return;
        }
        // `allowed_method_pattern?`
        let outer_name = node.name().as_slice();
        if node.equal_loc().is_some()
            || is_operator_method_name(outer_name)
            || outer_name == b"[]"
            || self.allowed_method_name(COP, inner.name().as_slice())
        {
            return;
        }
        let method_src = call_source_excluding_block(&inner, self.src);
        if self.allowed_pattern_text(COP, method_src) {
            return;
        }
        let param = String::from_utf8_lossy(self.node_src(&last)).into_owned();
        let method = String::from_utf8_lossy(method_src).into_owned();
        let message = format!(
            "Parenthesize the param `{param}` to make sure that the block will be associated with the `{method}` method call."
        );
        self.push(node.location().start_offset(), COP, true, message);

        // `wrap_in_parentheses`: replace the whitespace between the selector
        // and the first argument with `(`, then close after the last one.
        if let (Some(sel), Some(first)) = (node.message_loc(), args.arguments().first()) {
            let (ws_start, ws_end) = (sel.end_offset(), first.location().start_offset());
            self.fixes.push((ws_start, ws_end, b"(".to_vec()));
            let end = last.location().end_offset();
            self.fixes.push((end, end, b")".to_vec()));
        }
    }

    /// Is `cop`'s configured `AllowedMethods` set (default `[]`) an exact
    /// match for `name`?
    fn allowed_method_name(&self, cop: &str, name: &[u8]) -> bool {
        self.eng.allowed_methods.get(cop).is_some_and(|names| names.iter().any(|n| n.as_bytes() == name))
    }

    /// Does any of `cop`'s configured `AllowedPatterns` (default `[]`) match
    /// `text`?
    fn allowed_pattern_text(&self, cop: &str, text: &[u8]) -> bool {
        self.eng.allowed_patterns.get(cop).is_some_and(|pats| {
            let s = String::from_utf8_lossy(text);
            pats.iter().any(|re| re.is_match(&s))
        })
    }
}

/// The text of `call`, EXCLUDING its own trailing block (and the whitespace
/// separating them) — upstream's whitequark `send_node#source_range`, which
/// never includes the block it's wrapped by, unlike prism's own `CallNode`
/// location.
fn call_source_excluding_block<'s>(call: &ruby_prism::CallNode, src: &'s [u8]) -> &'s [u8] {
    let l = call.location();
    let start = l.start_offset();
    let mut end = match call.block() {
        Some(b) => b.location().start_offset(),
        None => l.end_offset(),
    };
    while end > start && matches!(src[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
        end -= 1;
    }
    &src[start..end]
}

/// Upstream's `MethodIdentifierPredicates::OPERATOR_METHODS`.
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

/// Upstream's `Node#lambda_or_proc?` (`{lambda? proc?}`) applied to a call
/// that's already known to carry a literal block: `lambda { }`/`->() { }`
/// (bare `lambda`, no receiver) or `proc { }`/`Proc.new { }` (bare `proc`, or
/// `new` on the bare or fully-qualified `Proc` constant).
fn is_lambda_or_proc_call(call: &ruby_prism::CallNode) -> bool {
    let name = call.name().as_slice();
    if call.receiver().is_none() && matches!(name, b"lambda" | b"proc") {
        return true;
    }
    name == b"new" && call.receiver().is_some_and(|r| is_global_const_named(&r, b"Proc"))
}

/// Upstream's `Node#global_const?`: a bare constant, or one anchored at the
/// top level (`::Proc`), named `name`.
fn is_global_const_named(node: &ruby_prism::Node, name: &[u8]) -> bool {
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == name;
    }
    if let Some(c) = node.as_constant_path_node() {
        return c.parent().is_none() && c.name().is_some_and(|n| n.as_slice() == name);
    }
    false
}

/// Which half of `AmbiguousOperator`'s two diagnostic shapes a prism warning
/// maps to — mirrors the two ways upstream's `find_offense_node_by` looks
/// for the enclosing call:
/// - `Prefix`: the operator IS its own AST node (`*`/`&`/`**`), found by a
///   plain `each_node(:splat, :block_pass, :kwsplat)` scan with no
///   restriction on what encloses it (so `yield *a`/`super *a` count).
/// - `Unary`: `+`/`-` fold directly into the argument they prefix (an int
///   literal's own source starts at the sign, or a unary `send`'s
///   `message_loc` does) — found only via `each_node(:send).find`, which is
///   why `yield +1`/`super +1` register NO offense upstream even though
///   prism still emits the warning for them (verified against real
///   `rubocop` 1.88.0: `yield +42`/`super +42` produce zero offenses, while
///   `yield *array`/`super *array` DO).
#[derive(Clone, Copy, PartialEq, Eq)]
enum AmbOpKind {
    Prefix,
    Unary,
}

/// Parses a `ruby_prism` warning message back into the `(operator, kind)`
/// pair `Prism::Translation::Parser#warning_diagnostic` would have produced
/// as `Diagnostic.new(:warning, :ambiguous_prefix, { prefix: operator }, ...)`
/// — ported from the two lex-level message shapes prism 1.9 emits for
/// `PM_WARN_AMBIGUOUS_FIRST_ARGUMENT_{PLUS,MINUS}` and
/// `PM_WARN_AMBIGUOUS_PREFIX_{STAR,STAR_STAR,AMPERSAND}` (verified live via
/// `Prism.parse(...).warnings`, since the `ruby_prism` Rust crate exposes
/// only `message`/`location`, not the warning's own type enum).
fn ambop_operator_from_message(msg: &str) -> Option<(&'static str, AmbOpKind)> {
    const UNARY_PREFIX: &str = "ambiguous first argument; put parentheses or a space even after `";
    const UNARY_SUFFIX: &str = "` operator";
    const PREFIX_PREFIX: &str = "ambiguous `";
    const PREFIX_SUFFIX: &str = "` has been interpreted as an argument prefix";

    if let Some(rest) = msg.strip_prefix(UNARY_PREFIX) {
        if let Some(op) = rest.strip_suffix(UNARY_SUFFIX) {
            return match op {
                "+" => Some(("+", AmbOpKind::Unary)),
                "-" => Some(("-", AmbOpKind::Unary)),
                _ => None,
            };
        }
    }
    if let Some(rest) = msg.strip_prefix(PREFIX_PREFIX) {
        if let Some(op) = rest.strip_suffix(PREFIX_SUFFIX) {
            return match op {
                "*" => Some(("*", AmbOpKind::Prefix)),
                "&" => Some(("&", AmbOpKind::Prefix)),
                "**" => Some(("**", AmbOpKind::Prefix)),
                _ => None,
            };
        }
    }
    None
}

/// `AmbiguousOperator::AMBIGUITIES` + `MSG_FORMAT`, verbatim (including the
/// exact punctuation/backtick placement).
fn ambop_message(op: &str) -> String {
    let (actual, possible) = match op {
        "+" => ("positive number", "an addition"),
        "-" => ("negative number", "a subtraction"),
        "*" => ("splat", "a multiplication"),
        "&" => ("block", "a binary AND"),
        "**" => ("keyword splat", "an exponent"),
        _ => unreachable!("ambop_operator_from_message only yields known operators"),
    };
    format!(
        "Ambiguous {actual} operator. Parenthesize the method arguments if it's surely a {actual} operator, or add a whitespace to the right of the `{op}` if it should be {possible}."
    )
}

/// One enclosing argument-taking construct's shape (`CallNode`/`YieldNode`/
/// `SuperNode`) — reconstructs the two positions `Util#add_parentheses`'s
/// last branch (`args_begin`/`args_end`) needs, since prism nodes carry no
/// parent pointer. `AmbiguousOperator`'s `offense_node` is always this kind
/// of node with at least one argument (the ambiguous operator's own operand
/// IS that argument), so the `args_type?`/`arguments.empty?`/
/// `!respond_to?(:arguments)` branches of `add_parentheses` never fire here
/// (unlike `AmbiguousRegexpLiteral`, which needs all of them) — every hit
/// resolves to the `args_begin`/`args_end` shape.
struct AmbOpFrame {
    /// `args_begin(node)`: one byte right after the selector (`loc.keyword`
    /// for yield/super, `loc.selector`/prism's `message_loc` otherwise).
    message_end: usize,
    /// `args_end(node)`: `node.source_range.end` — a prism `CallNode`'s own
    /// `location()` already ends there (no parens/block to span past, since
    /// the warning only fires on a bare, paren-less call).
    own_end: usize,
    /// Gates the `Unary` (`+`/`-`) path to real `:send` nodes only, per
    /// `find_offense_node_by`'s second loop (`ast.each_node(:send)`) —
    /// `yield`/`super` frames are pushed only so `Prefix` hits inside them
    /// (from the unrestricted first loop) still resolve.
    is_call: bool,
    /// `unary_operator?`'s implicit gate: whitequark demotes `a&.b` to
    /// `:csend`, which `each_node(:send)` never visits, so a safe-nav call's
    /// own first argument can never be the `Unary` offense node.
    is_safe_nav: bool,
    /// This frame's first argument's own start offset, if it has one —
    /// `send_node.first_argument` in `find_offense_node_by`.
    first_argument_start: Option<usize>,
}

/// Walks `root` looking for prism warning offsets from `targets`, resolving
/// each to `(operator, autocorrect range)` exactly like
/// `AmbiguousOperator#find_offense_node_by` walks the whitequark AST:
/// `Prefix` operators (`*`/`&`/`**`) are their own node (`SplatNode`/
/// `BlockArgumentNode`/`AssocSplatNode`) found unconditionally; `Unary`
/// operators (`+`/`-`) are read off a `CallNode`'s first argument and gated
/// to non-safe-nav calls only.
fn ambop_find_fixes(
    root: &ruby_prism::Node,
    targets: &HashMap<usize, (&'static str, AmbOpKind)>,
) -> Vec<(usize, &'static str, usize, usize)> {
    struct Walker<'t> {
        targets: &'t HashMap<usize, (&'static str, AmbOpKind)>,
        stack: Vec<AmbOpFrame>,
        seen: HashSet<usize>,
        hits: Vec<(usize, &'static str, usize, usize)>,
    }
    impl<'t> Walker<'t> {
        fn resolve_prefix(&mut self, off: usize) {
            if self.seen.contains(&off) {
                return;
            }
            let Some(&(op, kind)) = self.targets.get(&off) else {
                return;
            };
            if kind != AmbOpKind::Prefix {
                return;
            }
            if let Some(frame) = self.stack.last() {
                self.seen.insert(off);
                self.hits.push((off, op, frame.message_end, frame.own_end));
            }
        }
        fn check_unary(&mut self, frame: &AmbOpFrame) {
            let Some(start) = frame.first_argument_start else {
                return;
            };
            if self.seen.contains(&start) {
                return;
            }
            let Some(&(op, kind)) = self.targets.get(&start) else {
                return;
            };
            if kind != AmbOpKind::Unary || !frame.is_call || frame.is_safe_nav {
                return;
            }
            self.seen.insert(start);
            self.hits.push((start, op, frame.message_end, frame.own_end));
        }
        fn push_keyword_frame(&mut self, keyword_end: usize, own_end: usize) {
            self.stack.push(AmbOpFrame {
                message_end: keyword_end,
                own_end,
                is_call: false,
                is_safe_nav: false,
                first_argument_start: None,
            });
        }
    }
    impl<'pr, 't> ruby_prism::Visit<'pr> for Walker<'t> {
        fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
            let pushed = if let Some(msg) = node.message_loc() {
                let frame = AmbOpFrame {
                    message_end: msg.end_offset(),
                    own_end: node.location().end_offset(),
                    is_call: true,
                    is_safe_nav: node.is_safe_navigation(),
                    first_argument_start: node
                        .arguments()
                        .and_then(|a| a.arguments().first())
                        .map(|n| n.location().start_offset()),
                };
                self.check_unary(&frame);
                self.stack.push(frame);
                true
            } else {
                false
            };
            ruby_prism::visit_call_node(self, node);
            if pushed {
                self.stack.pop();
            }
        }
        fn visit_yield_node(&mut self, node: &ruby_prism::YieldNode<'pr>) {
            self.push_keyword_frame(node.keyword_loc().end_offset(), node.location().end_offset());
            ruby_prism::visit_yield_node(self, node);
            self.stack.pop();
        }
        fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
            self.push_keyword_frame(node.keyword_loc().end_offset(), node.location().end_offset());
            ruby_prism::visit_super_node(self, node);
            self.stack.pop();
        }
        fn visit_splat_node(&mut self, node: &ruby_prism::SplatNode<'pr>) {
            self.resolve_prefix(node.location().start_offset());
            ruby_prism::visit_splat_node(self, node);
        }
        fn visit_block_argument_node(&mut self, node: &ruby_prism::BlockArgumentNode<'pr>) {
            self.resolve_prefix(node.location().start_offset());
            ruby_prism::visit_block_argument_node(self, node);
        }
        fn visit_assoc_splat_node(&mut self, node: &ruby_prism::AssocSplatNode<'pr>) {
            self.resolve_prefix(node.location().start_offset());
            ruby_prism::visit_assoc_splat_node(self, node);
        }
    }
    let mut w = Walker { targets, stack: Vec::new(), seen: HashSet::new(), hits: Vec::new() };
    use ruby_prism::Visit;
    w.visit(root);
    w.hits
}

impl<'a> Cops<'a> {
    /// Lint/AmbiguousOperator — a bare (paren-less) call/`yield`/`super`
    /// whose first argument opens with `+`/`-`/`*`/`&`/`**` and no space
    /// before the operand, which the LEXER can't disambiguate from a binary
    /// operator on the receiver/previous call. Like `AmbiguousRegexpLiteral`
    /// just above, upstream detects this off `processed_source.diagnostics`
    /// (`reason == :ambiguous_prefix`), which under rubocop's Prism
    /// translation comes straight from prism's own lex-level
    /// `PM_WARN_AMBIGUOUS_FIRST_ARGUMENT_{PLUS,MINUS}` and
    /// `PM_WARN_AMBIGUOUS_PREFIX_{STAR,STAR_STAR,AMPERSAND}` warnings (see
    /// `Prism::Translation::Parser#warning_diagnostic`) — we ride
    /// `ParseResult#warnings` directly rather than reimplementing prism's
    /// lex-state machine, matching upstream byte-for-byte since it rides the
    /// identical warning. The message text interpolates the operator itself
    /// (recovered from the warning message — the `ruby_prism` crate exposes
    /// no warning-type enum, only `message`/`location`).
    ///
    /// Only the AUTOCORRECT target needs an AST walk (`ambop_find_fixes`),
    /// ported from `find_offense_node_by`/`unary_operator?`
    /// (ambiguous_operator.rb) and `Util#add_parentheses`'s `args_begin`/
    /// `args_end` branch (util.rb) — the only branch reachable here, since
    /// `AmbiguousOperator`'s offense node always has at least one argument.
    pub(crate) fn check_ambiguous_operator(&mut self, result: &ruby_prism::ParseResult) {
        const COP: &str = "Lint/AmbiguousOperator";
        if !self.on(COP) {
            return;
        }

        let mut targets: HashMap<usize, (&'static str, AmbOpKind)> = HashMap::new();
        for w in result.warnings() {
            if let Some((op, kind)) = ambop_operator_from_message(w.message()) {
                targets.insert(w.location().start_offset(), (op, kind));
            }
        }
        if targets.is_empty() {
            return;
        }

        let hits = ambop_find_fixes(&result.node(), &targets);
        for (off, op, msg_end, args_end) in hits {
            self.push(off, COP, true, ambop_message(op));
            self.fixes.push((msg_end, msg_end + 1, b"(".to_vec()));
            self.fixes.push((args_end, args_end, b")".to_vec()));
        }
    }
}

// ---------------------------------------------------------------------
// Lint/UnreachableCode
// ---------------------------------------------------------------------
// Ports `flow_expression?` / `check_if` / `check_case` /
// `report_on_flow_command?` from rubocop's lint/unreachable_code.rb.
//
// The one structural wrinkle versus upstream's whitequark-based algorithm:
// prism always wraps a body in a `StatementsNode` (even a single
// statement), where whitequark leaves a lone statement bare and only
// introduces a `:begin` node for 2+ statements. That difference is benign
// here because `flow_expression?` on a compound node is an `any?` over its
// elements — checking a `StatementsNode` with exactly one element and
// recursing into that element are equivalent.
//
// The other wrinkle is real and was confirmed against live rubocop 1.88.0:
// an explicit `begin...end` is only "transparent" to this analysis (i.e.
// unwraps to its statements, so a `return` inside can make the whole
// `begin` block count as flow-of-control) when it carries NO rescue/else/
// ensure clause. `begin; return; rescue; ...; end` and `begin; return;
// ensure; ...; end` are both opaque — upstream's whitequark AST wraps
// those in `:kwbegin` around a `:rescue`/`:ensure` node that
// `flow_expression?` doesn't special-case, so it falls through to `false`
// regardless of what's inside. Probed via:
//   if cond
//     begin; return; rescue; return; end
//   else
//     return
//   end
//   bar   # NOT flagged (rubocop 1.88.0) — the begin/rescue is opaque
// versus a bare `begin; return; end` in the same position, which IS
// transparent and DOES make `bar` unreachable.

/// `redefinable_flow_method?` — only these six names are tracked as
/// possibly redefined by a `def`/`defs`.
fn uc_redefinable_flow_method(name: &[u8]) -> bool {
    matches!(name, b"raise" | b"fail" | b"throw" | b"exit" | b"exit!" | b"abort")
}

/// The `flow_command?` node-pattern's `send` alternative: a call to one of
/// the redefinable names, receiverless or explicitly on `Kernel`/`::Kernel`
/// (never e.g. `Dummy.raise`, which always calls the real class method).
fn uc_flow_command_call<'pr>(node: &ruby_prism::Node<'pr>) -> Option<ruby_prism::CallNode<'pr>> {
    let call = node.as_call_node()?;
    if !uc_redefinable_flow_method(call.name().as_slice()) {
        return None;
    }
    match call.receiver() {
        None => Some(call),
        Some(recv) => {
            let is_kernel = recv.as_constant_read_node().is_some_and(|c| c.name().as_slice() == b"Kernel")
                || recv
                    .as_constant_path_node()
                    .is_some_and(|c| c.parent().is_none() && c.name().is_some_and(|n| n.as_slice() == b"Kernel"));
            if is_kernel { Some(call) } else { None }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// `report_on_flow_command?`: keyword statements (return/next/break/
    /// retry/redo) always report. A `Kernel`-qualified call always reports
    /// (it can't have been shadowed). A bare call is suppressed entirely
    /// inside `instance_eval` (ambiguous `self`), else suppressed once a
    /// `def`/`defs` with that name has been seen.
    fn uc_report_on_flow_command(&self, call: &ruby_prism::CallNode) -> bool {
        if call.receiver().is_some() {
            return true;
        }
        if self.uc_instance_eval_depth > 0 {
            return false;
        }
        !self.uc_redefined.contains(call.name().as_slice())
    }

    /// `register_redefinition`: a `def`/`defs` shadowing one of the six
    /// tracked names disarms future bare calls to it.
    fn uc_register_redefinition(&mut self, name: &[u8]) {
        if uc_redefinable_flow_method(name) {
            self.uc_redefined.insert(name.to_vec());
        }
    }

    /// `flow_expression?` — does evaluating `node` unconditionally divert
    /// control flow away, making anything textually after it (in the same
    /// statement list) unreachable?
    fn uc_flow_expression(&mut self, node: &ruby_prism::Node) -> bool {
        if node.as_return_node().is_some()
            || node.as_next_node().is_some()
            || node.as_break_node().is_some()
            || node.as_retry_node().is_some()
            || node.as_redo_node().is_some()
        {
            return true;
        }
        if let Some(call) = uc_flow_command_call(node) {
            return self.uc_report_on_flow_command(&call);
        }
        if let Some(stmts) = node.as_statements_node() {
            for e in stmts.body().iter() {
                if self.uc_flow_expression(&e) {
                    return true;
                }
            }
            return false;
        }
        if let Some(begin) = node.as_begin_node() {
            // Opaque unless it's a BARE `begin...end` (see module doc comment).
            if begin.rescue_clause().is_some() || begin.else_clause().is_some() || begin.ensure_clause().is_some() {
                return false;
            }
            let Some(stmts) = begin.statements() else { return false };
            for e in stmts.body().iter() {
                if self.uc_flow_expression(&e) {
                    return true;
                }
            }
            return false;
        }
        if let Some(els) = node.as_else_node() {
            let Some(stmts) = els.statements() else { return false };
            for e in stmts.body().iter() {
                if self.uc_flow_expression(&e) {
                    return true;
                }
            }
            return false;
        }
        if let Some(iff) = node.as_if_node() {
            let Some(if_branch) = iff.statements() else { return false };
            let Some(else_branch) = iff.subsequent() else { return false };
            return self.uc_flow_expression(&if_branch.as_node()) && self.uc_flow_expression(&else_branch);
        }
        if let Some(unl) = node.as_unless_node() {
            // rubocop normalizes `unless`'s branches (node_parts swaps
            // true/false), but `check_if` only ANDs them together, so the
            // swap is a no-op here — both must be present and both flow.
            let Some(else_clause) = unl.else_clause() else { return false };
            let Some(main_stmts) = unl.statements() else { return false };
            return self.uc_flow_expression(&else_clause.as_node()) && self.uc_flow_expression(&main_stmts.as_node());
        }
        if let Some(c) = node.as_case_node() {
            let Some(else_branch) = c.else_clause() else { return false };
            if !self.uc_flow_expression(&else_branch.as_node()) {
                return false;
            }
            for w in c.conditions().iter() {
                let flows = match w.as_when_node().and_then(|w| w.statements()) {
                    Some(s) => self.uc_flow_expression(&s.as_node()),
                    None => false,
                };
                if !flows {
                    return false;
                }
            }
            return true;
        }
        if let Some(c) = node.as_case_match_node() {
            let Some(else_branch) = c.else_clause() else { return false };
            if !self.uc_flow_expression(&else_branch.as_node()) {
                return false;
            }
            for i in c.conditions().iter() {
                let flows = match i.as_in_node().and_then(|i| i.statements()) {
                    Some(s) => self.uc_flow_expression(&s.as_node()),
                    None => false,
                };
                if !flows {
                    return false;
                }
            }
            return true;
        }
        if let Some(d) = node.as_def_node() {
            self.uc_register_redefinition(d.name().as_slice());
            return false;
        }
        false
    }

    /// `on_begin`/`on_kwbegin`: within a straight-line statement list, any
    /// statement after one that always diverts control flow is unreachable.
    pub(crate) fn check_unreachable_code(&mut self, node: &ruby_prism::StatementsNode) {
        const COP: &str = "Lint/UnreachableCode";
        if !self.on(COP) {
            return;
        }
        let body: Vec<_> = node.body().iter().collect();
        for pair in body.windows(2) {
            if self.uc_flow_expression(&pair[0]) {
                self.push(pair[1].location().start_offset(), COP, false, "Unreachable code detected.");
            }
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/RedundantStringCoercion — checks for string conversion in string
    /// interpolation, `print`, `puts`, and `warn` arguments, which is redundant.
    pub(crate) fn check_redundant_string_coercion_in_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantStringCoercion";
        if !self.on(COP) {
            return;
        }

        let method_name = node.name().as_slice();
        // Check if this is one of the target methods: print, puts, warn
        if !matches!(method_name, b"print" | b"puts" | b"warn") {
            return;
        }

        // Must be a bare call (no receiver)
        if node.receiver().is_some() {
            return;
        }

        // Check arguments for .to_s calls
        if let Some(args) = node.arguments() {
            for arg in args.arguments().iter() {
                if let Some(call) = arg.as_call_node() {
                    if Self::is_redundant_to_s_call(&call) {
                        self.register_redundant_string_coercion_offense(
                            &call,
                            &format!("`{}`", String::from_utf8_lossy(method_name)),
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn check_redundant_string_coercion_in_interpolation(
        &mut self,
        node: &ruby_prism::EmbeddedStatementsNode,
    ) {
        const COP: &str = "Lint/RedundantStringCoercion";
        if !self.on(COP) {
            return;
        }

        // Get the last statement in the interpolation
        if let Some(stmts) = node.statements() {
            if let Some(final_node) = stmts.body().last() {
                if let Some(call) = final_node.as_call_node() {
                    if Self::is_redundant_to_s_call(&call) {
                        self.register_redundant_string_coercion_offense(&call, "interpolation");
                    }
                }
            }
        }
    }

    fn is_redundant_to_s_call(call: &ruby_prism::CallNode) -> bool {
        // Check if this is a .to_s call with no arguments
        call.name().as_slice() == b"to_s" && call.arguments().is_none()
    }

    fn register_redundant_string_coercion_offense(
        &mut self,
        call: &ruby_prism::CallNode,
        context: &str,
    ) {
        // Determine the message and replacement
        let (message, replacement) = if let Some(receiver) = call.receiver() {
            let recv_src = self.node_src(&receiver);
            (
                format!("Redundant use of `Object#to_s` in {}.", context),
                recv_src.to_vec(),
            )
        } else {
            (
                format!("Use `self` instead of `Object#to_s` in {}.", context),
                b"self".to_vec(),
            )
        };

        // Get the selector location (the "to_s" part)
        let sel_offset = call
            .message_loc()
            .map(|l| l.start_offset())
            .unwrap_or_else(|| call.location().start_offset());

        // Push the offense
        self.push(sel_offset, "Lint/RedundantStringCoercion", true, message);

        // Push the fix: replace the entire call with the replacement
        let l = call.location();
        self.fixes.push((l.start_offset(), l.end_offset(), replacement));
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/RedundantWithIndex — checks for redundant `with_index` in blocks
    /// where the index parameter is not used. Handles three block types:
    /// - Regular blocks with 0 or 1 parameters
    /// - Numblocks with 1 parameter (only _1, no _2)
    /// - Itblocks (implicit `it`)
    pub(crate) fn check_redundant_with_index(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantWithIndex";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"each_with_index" | b"with_index") {
            return;
        }

        // Mirrors ruby's check:
        // return unless node.receiver  (must have receiver)
        // return if node.method?(:with_index) && !node.receiver.receiver  (if with_index, receiver must have a receiver)
        let Some(recv) = node.receiver() else { return };
        if name == b"with_index" {
            // `node.receiver.receiver`: with_index's own receiver must itself
            // have a receiver (a genuine chain like ary.each.with_index) —
            // `ary.with_index` parses as a receiver-less call and is skipped.
            let has_inner_receiver = recv.as_call_node().and_then(|c| c.receiver()).is_some();
            if !has_inner_receiver {
                return;
            }
        }
        // Must have a block
        let Some(block_node) = node.block().and_then(|b| b.as_block_node()) else { return };

        // Determine the block type and check parameter count
        let should_flag = match block_node.parameters() {
            None => {
                // Block with no parameters: `{ }` — always flag
                true
            }
            Some(params_node) => {
                if let Some(np) = params_node.as_numbered_parameters_node() {
                    // Numblock with numbered parameters (_1, _2, ...)
                    // Only flag if it has exactly 1 parameter
                    np.maximum() == 1
                } else if params_node.as_it_parameters_node().is_some() {
                    // Itblock with implicit `it` parameter: always flag (1 parameter)
                    true
                } else if let Some(block_params) = params_node.as_block_parameters_node() {
                    // Regular block: check parameter count (req + opt + rest)
                    // BlockParametersNode wraps a ParametersNode
                    if let Some(params) = block_params.parameters() {
                        let req = params.requireds().iter().count();
                        let opt = params.optionals().iter().count();
                        let rest = if params.rest().is_some() { 1 } else { 0 };
                        (req + opt + rest) <= 1
                    } else {
                        // No parameters in the ParametersNode (shouldn't happen for BlockParametersNode)
                        true
                    }
                } else {
                    // Unknown parameter type, skip
                    false
                }
            }
        };
        if should_flag {
            self.push_redundant_with_index_offense(node);
        }
    }

    fn push_redundant_with_index_offense(&mut self, call: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantWithIndex";
        let name = call.name().as_slice();
        let (message, start) = if name == b"each_with_index" {
            // For each_with_index, the offense is at the selector and we replace it with "each"
            let sel = match call.message_loc() {
                Some(loc) => (loc.start_offset(), loc.end_offset()),
                None => return,
            };
            ("Use `each` instead of `each_with_index`.", sel.0)
        } else {
            // For with_index, the offense is at the method name
            let sel = match call.message_loc() {
                Some(loc) => loc.start_offset(),
                None => return,
            };
            ("Remove redundant `with_index`.", sel)
        };
        self.push(start, COP, true, message);

        // Build the fix
        if name == b"each_with_index" {
            // Replace selector with "each"
            let (sel_start, sel_end) = match call.message_loc() {
                Some(loc) => (loc.start_offset(), loc.end_offset()),
                None => return,
            };
            self.fixes.push((sel_start, sel_end, b"each".to_vec()));
        } else {
            // For .with_index, we need to remove the entire method call including arguments
            // but NOT the block
            let sel_start = match call.message_loc() {
                Some(loc) => loc.start_offset(),
                None => return,
            };

            // Find the dot before the selector
            if sel_start == 0 {
                return;
            }
            let dot_start = sel_start - 1;
            if self.src[dot_start] != b'.' {
                return;
            }

            // Determine the end: the end of the method call (including arguments, excluding block)
            // If there's a block node, we need to find where the call really ends (before the block)
            let call_end = if let Some(block_node) = call.block().and_then(|b| b.as_block_node()) {
                // Block exists, so find the end of the call (before the block and its space)
                let block_start = block_node.location().start_offset();
                // Walk backwards to find the end of the call, skipping whitespace
                let mut i = block_start;
                while i > dot_start && (self.src[i - 1] == b' ' || self.src[i - 1] == b'\t') {
                    i -= 1;
                }
                i
            } else {
                // No block, so use the call's full location
                call.location().end_offset()
            };

            self.fixes.push((dot_start, call_end, Vec::new()));
        }
    }
}

/// `body.begin_type? ? body.children : body` then `.last`: prism always
/// wraps a def body in a `StatementsNode` unless it's the bare form of an
/// implicit `rescue`/`ensure` directly on the `def` (a `BeginNode` with no
/// wrapping `StatementsNode`) — that `BeginNode` plays the role of
/// `last_expr` itself and can never match the setter-call shape below,
/// exactly mirroring whitequark's `:rescue`/`:ensure` (not `:begin`) body
/// types.
fn usc_last_expression(body: ruby_prism::Node) -> ruby_prism::Node {
    if let Some(stmts) = body.as_statements_node() {
        if let Some(last) = stmts.body().iter().last() {
            return last;
        }
    }
    body
}

/// rubocop-ast's `Node::VARIABLES` (`lvar`/`ivar`/`cvar`/`gvar` READS): the
/// node kinds `rhs_node.variable?` recognizes when copying a prior
/// assignment's tracked status across `x = y`. Names include prism's sigils
/// (`@foo`, `@@foo`, `$foo`) exactly like rubocop's symbol names, so they
/// can share one flat map with plain lvar names without colliding.
fn usc_variable_read_name<'pr>(node: &ruby_prism::Node<'pr>) -> Option<&'pr [u8]> {
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

/// rubocop-ast's `ASSIGNMENT_TYPES` (`lvasgn`/`ivasgn`/`cvasgn`/`gvasgn`) —
/// but as multiple-assignment TARGET nodes (masgn slots are prism's
/// `*TargetNode`s, not `*WriteNode`s). Nested destructuring
/// (`MultiTargetNode`) and splats (`SplatNode`) are deliberately excluded,
/// matching upstream's `next unless ASSIGNMENT_TYPES.include?(lhs_node.type)`.
fn usc_assignment_target_name<'pr>(node: &ruby_prism::Node<'pr>) -> Option<&'pr [u8]> {
    if let Some(n) = node.as_local_variable_target_node() {
        return Some(n.name().as_slice());
    }
    if let Some(n) = node.as_instance_variable_target_node() {
        return Some(n.name().as_slice());
    }
    if let Some(n) = node.as_class_variable_target_node() {
        return Some(n.name().as_slice());
    }
    if let Some(n) = node.as_global_variable_target_node() {
        return Some(n.name().as_slice());
    }
    None
}

/// rubocop-ast's `LITERALS` (`TRUTHY_LITERALS + FALSEY_LITERALS`) as used by
/// `constructor?`'s `node.literal?` check — every literal node shape prism
/// exposes, including both plain and interpolated string/symbol/regexp/xstr
/// variants (whitequark folds each pair into one node type; prism splits
/// them).
fn usc_is_literal(node: &ruby_prism::Node) -> bool {
    node.as_string_node().is_some()
        || node.as_interpolated_string_node().is_some()
        || node.as_x_string_node().is_some()
        || node.as_interpolated_x_string_node().is_some()
        || node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_interpolated_symbol_node().is_some()
        || node.as_array_node().is_some()
        || node.as_hash_node().is_some()
        || node.as_regular_expression_node().is_some()
        || node.as_interpolated_regular_expression_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_range_node().is_some()
        || node.as_imaginary_node().is_some()
        || node.as_rational_node().is_some()
}

/// rubocop-ast's `constructor?`: a literal, or a plain (non-safe-navigation)
/// `.new` call — `send_type?` is false for `csend` (`Top&.new`), so safe
/// navigation is deliberately excluded here too (verified live: rubocop
/// 1.88.0 does NOT flag `top = Top&.new; top.attr = 5`).
fn usc_constructor(node: &ruby_prism::Node) -> bool {
    if usc_is_literal(node) {
        return true;
    }
    node.as_call_node().is_some_and(|c| !c.is_safe_navigation() && c.name().as_slice() == b"new")
}

/// Ported from upstream's private `MethodVariableTracker`: walks the ENTIRE
/// method body tracking, per variable, whether its current value is a
/// locally-constructed object (a literal or `.new` call) as of each
/// assignment — so a later read (`y = x`) can copy `x`'s status, and a
/// setter call at the end can look up its receiver's final tracked status.
///
/// Mirrors upstream's `scan`/`throw :skip_children`: overridden `visit_*`
/// methods that DON'T call the generated `ruby_prism::visit_*_node` free
/// function stop descent into that node's children (matching `throw`); the
/// ones that DO call it keep descending (matching plain fallthrough in
/// `process_assignment_node`'s `case`). Node kinds with no override at all
/// (e.g. constant assignment, attribute/index `op_asgn`) aren't in
/// `ASSIGNMENT_TYPES` upstream either — they fall through to `return`
/// without a throw, so the `Visit` trait's own default recursion already
/// reproduces that "keep walking, do nothing here" behavior for free.
struct UscTracker<'pr> {
    local: HashMap<&'pr [u8], bool>,
}
impl<'pr> UscTracker<'pr> {
    fn set(&mut self, name: &'pr [u8], val: bool) {
        self.local.insert(name, val);
    }
    /// `process_assignment`: `rhs_node.variable?` copies the prior tracked
    /// status (or `false`/unset) across a plain read; anything else falls
    /// to `constructor?`.
    fn process_assignment(&mut self, name: &'pr [u8], rhs: &ruby_prism::Node<'pr>) {
        let val = match usc_variable_read_name(rhs) {
            Some(rn) => self.local.get(rn).copied().unwrap_or(false),
            None => usc_constructor(rhs),
        };
        self.set(name, val);
    }
}
impl<'pr> ruby_prism::Visit<'pr> for UscTracker<'pr> {
    /// `process_multiple_assignment`: iterate the top-level destructuring
    /// slots (`lefts` ++ optional `rest` ++ `rights` — prism's split of
    /// whitequark's flat `mlhs.children`) so each maps to the right-hand
    /// side element at the same position, but ONLY when the rhs is itself
    /// an array literal; any other rhs shape (e.g. a bare method call
    /// relying on an implicit `to_a`) blanket-marks every slot `true`,
    /// exactly like upstream. Always `throw :skip_children` (no
    /// default-traversal call).
    fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
        let mut slots: Vec<ruby_prism::Node> = node.lefts().iter().collect();
        if let Some(rest) = node.rest() {
            slots.push(rest);
        }
        slots.extend(node.rights().iter());

        let rhs = node.value();
        let rhs_elems: Option<Vec<ruby_prism::Node>> =
            rhs.as_array_node().map(|a| a.elements().iter().collect());

        for (i, lhs) in slots.iter().enumerate() {
            let Some(name) = usc_assignment_target_name(lhs) else { continue };
            match rhs_elems.as_ref().and_then(|elems| elems.get(i)) {
                Some(rhs_node) => self.process_assignment(name, rhs_node),
                None => self.set(name, true),
            }
        }
    }

    // `process_logical_operator_assignment` for a variable target: process
    // + `throw :skip_children` (no default-traversal call).
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_instance_variable_or_write_node(&mut self, node: &ruby_prism::InstanceVariableOrWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_instance_variable_and_write_node(&mut self, node: &ruby_prism::InstanceVariableAndWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_class_variable_or_write_node(&mut self, node: &ruby_prism::ClassVariableOrWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_class_variable_and_write_node(&mut self, node: &ruby_prism::ClassVariableAndWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_global_variable_or_write_node(&mut self, node: &ruby_prism::GlobalVariableOrWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }
    fn visit_global_variable_and_write_node(&mut self, node: &ruby_prism::GlobalVariableAndWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
    }

    // `process_binary_operator_assignment` for a variable target: ALWAYS
    // marks `true` regardless of the rhs (upstream never inspects it) +
    // `throw :skip_children`.
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        self.set(node.name().as_slice(), true);
    }
    fn visit_instance_variable_operator_write_node(
        &mut self,
        node: &ruby_prism::InstanceVariableOperatorWriteNode<'pr>,
    ) {
        self.set(node.name().as_slice(), true);
    }
    fn visit_class_variable_operator_write_node(&mut self, node: &ruby_prism::ClassVariableOperatorWriteNode<'pr>) {
        self.set(node.name().as_slice(), true);
    }
    fn visit_global_variable_operator_write_node(&mut self, node: &ruby_prism::GlobalVariableOperatorWriteNode<'pr>) {
        self.set(node.name().as_slice(), true);
    }

    // Plain `x = ...` (the `*ASSIGNMENT_TYPES` case in
    // `process_assignment_node`): process, but keep descending (upstream's
    // `case` doesn't throw here) — so a constructor buried inside the rhs
    // of a nested assignment is still found.
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
        ruby_prism::visit_local_variable_write_node(self, node);
    }
    fn visit_instance_variable_write_node(&mut self, node: &ruby_prism::InstanceVariableWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
        ruby_prism::visit_instance_variable_write_node(self, node);
    }
    fn visit_class_variable_write_node(&mut self, node: &ruby_prism::ClassVariableWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
        ruby_prism::visit_class_variable_write_node(self, node);
    }
    fn visit_global_variable_write_node(&mut self, node: &ruby_prism::GlobalVariableWriteNode<'pr>) {
        let rhs = node.value();
        self.process_assignment(node.name().as_slice(), &rhs);
        ruby_prism::visit_global_variable_write_node(self, node);
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/UselessSetterCall — a local var holding a freshly-built object
    /// whose setter call is the final expression of a method body is almost
    /// certainly a bug: the method's return value silently becomes the
    /// setter's result (e.g. `5`) instead of the object. Ported from
    /// upstream's `on_def` (aliased `on_defs` — prism's `DefNode` already
    /// covers both; a singleton def just has a receiver) plus its private
    /// `MethodVariableTracker` (see the free functions/`UscTracker` above).
    ///
    /// Always registered as correctable — this cop `extend`s `AutoCorrector`
    /// and every offense gets a correction (the safety caveats upstream
    /// documents are about false positives/return-value changes, not about
    /// whether a fix is offered).
    pub(crate) fn check_useless_setter_call(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/UselessSetterCall";
        if !self.on(COP) {
            return;
        }
        let Some(body) = node.body() else { return };
        let last_expr = usc_last_expression(body);

        // `[(send (lvar _) ...) setter_method?]` — a plain (non-safe-nav)
        // call whose receiver is a bare local-variable read, and which is
        // ITSELF an assignment: prism's `equal_loc` is `setter_method?`'s
        // `loc?(:operator)` (`x.attr = 5`, `x[:k] = 5`; never `x.attr == 5`).
        let Some(call) = last_expr.as_call_node() else { return };
        if call.is_safe_navigation() || call.equal_loc().is_none() {
            return;
        }
        let Some(receiver) = call.receiver() else { return };
        let Some(lvar) = receiver.as_local_variable_read_node() else { return };
        let var_name = lvar.name().as_slice();

        // `usc_last_expression` consumed the first `node.body()`; re-fetch
        // for the tracker's full-body scan (cheap — just re-reads a pointer).
        let Some(scan_body) = node.body() else { return };
        let mut tracker = UscTracker { local: HashMap::new() };
        {
            use ruby_prism::Visit;
            tracker.visit(&scan_body);
        }
        if !tracker.local.get(var_name).copied().unwrap_or(false) {
            return;
        }

        let recv_loc = receiver.location();
        let var_src = String::from_utf8_lossy(self.node_src(&receiver)).into_owned();
        self.push(
            recv_loc.start_offset(),
            COP,
            true,
            format!("Useless setter call to local variable `{var_src}`."),
        );

        // `corrector.insert_after(last_expr, "\n#{indent(last_expr)}#{loc_name.source}")`
        // — upstream's `indent` helper is `' ' * node.loc.column` (a
        // 0-based character count); `self.idx.loc` columns are 1-based.
        let call_loc = call.location();
        let (_, col) = self.idx.loc(call_loc.start_offset());
        let indent = " ".repeat(col.saturating_sub(1));
        let insertion = format!("\n{indent}{var_src}");
        self.fixes.push((call_loc.end_offset(), call_loc.end_offset(), insertion.into_bytes()));
    }
}

/// Given whatever immediately follows an if/elsif level (another `elsif`
/// IfNode, or a literal `else` ElseNode), the start offset of ITS OWN
/// keyword — this is what whitequark's `node.loc.else` (present on any
/// if/elsif node that has a subsequent branch) points at, regardless of
/// whether that branch is another `elsif` or the final `else`.
fn subsequent_keyword_start(sub: &ruby_prism::Node) -> usize {
    if let Some(elsif) = sub.as_if_node() {
        elsif.if_keyword_loc().map(|k| k.start_offset()).unwrap_or_else(|| elsif.location().start_offset())
    } else if let Some(else_node) = sub.as_else_node() {
        else_node.else_keyword_loc().start_offset()
    } else {
        sub.location().start_offset()
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/EmptyConditionalBody — an `if`/`elsif`/`unless` branch with no
    /// body. `AllowComments` (default true) suppresses the offense when a
    /// comment sits in the branch's own byte range (rubocop's
    /// `CommentsHelp#contains_comments?`/`find_end_line`, same family as
    /// `check_empty_when`'s port, but `find_end_line`'s `node.if_type?`
    /// branch needs its OWN translation here since it's if/elsif-specific).
    ///
    /// whitequark parses `if`/`elsif`/`unless` all as the SAME `:if` node
    /// type (an `elsif` is just the previous node's `else_branch` nesting
    /// another `:if`), so upstream's `on_if` fires once per level via the
    /// AST walk. Prism keeps `elsif` as IfNode#subsequent chaining (so it's
    /// visited again on its own — this function's caller in `mod.rs` skips
    /// re-entering when `if_keyword` reads `elsif`) but gives `unless` an
    /// entirely separate UnlessNode type, handled by the sibling function
    /// `check_empty_conditional_body_unless` below.
    ///
    /// Two traps drove the design (verified against live `rubocop`, see
    /// worker notes): (1) `node.loc.end` (whitequark) is set ONLY on the
    /// outermost if/unless — every nested `elsif` node has `loc.end == nil`
    /// — so the `same_line?(loc.begin, loc.end)` single-line skip (`if
    /// cond;end`, `if cond; else body end`) can only ever fire at the HEAD
    /// level, never on an `elsif` (matches the fixture: `elsif cond_b;end`
    /// DOES get flagged, even though textually it "fits on one line" up to
    /// the shared `end`). Prism's every level reports the SAME real
    /// `end_keyword_loc`, so that trap is replicated by gating the
    /// same-line check on `is_head`. (2) whitequark's `elsif` node's own
    /// `source_range` stops right before the (shared) `end`/next-keyword —
    /// but only its START offset is ever compared (the oracle rebuilds
    /// line:col purely from `self.push`'s single offset, never the
    /// message's range width), so the END-boundary discrepancy from prism
    /// giving `elsif` nodes a location that runs all the way through `end`
    /// never actually matters here.
    pub(crate) fn check_empty_conditional_body(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Lint/EmptyConditionalBody";
        if !self.on(COP) {
            return;
        }
        // Ternary `?:` has no if/elsif keyword and always has both branches
        // (mandatory syntax) — never reachable here. Only walk from the
        // HEAD of a chain; each nested `elsif` is a full IfNode of its own
        // and gets visited again by the normal traversal, which would
        // re-walk (and re-offend on) the same tail twice.
        let Some(head_kw) = node.if_keyword_loc() else { return };
        if head_kw.as_slice() == b"elsif" {
            return;
        }
        // A modifier `if`/`unless` (no `end`) always has a body (that's what
        // makes it a modifier), so this is unreachable in practice — guard
        // anyway rather than unwrap.
        let Some(end_kw) = node.end_keyword_loc() else { return };
        let end_kw_start = end_kw.start_offset();
        let end_kw_line = self.idx.loc(end_kw_start).0;
        let allow_comments = self.cfg.get(COP, "AllowComments") != Some("false");

        let mut level_start = head_kw.start_offset();
        let mut predicate = node.predicate();
        let mut statements = node.statements();
        let mut subsequent = node.subsequent();
        let mut prev_statements: Option<ruby_prism::StatementsNode> = None;
        let mut is_head = true;

        loop {
            let has_body = statements.is_some();
            // whitequark's `same_line?(node.loc.begin, node.loc.end)`: only
            // ever true at the head (see doc comment above) — `node.loc.end`
            // is this level's OWN end, which only the head genuinely has.
            let same_line_skip = is_head && {
                let cond_end = predicate.location().end_offset();
                self.idx.loc(cond_end).0 == end_kw_line
            };

            if !has_body && !same_line_skip {
                let start_line = self.idx.loc(level_start).0;
                let end_line = match &subsequent {
                    Some(sub) => self.idx.loc(subsequent_keyword_start(sub)).0,
                    None => end_kw_line,
                };
                let skip_via_comments = allow_comments
                    && self.comments.iter().any(|(line, _, _)| *line >= start_line && *line < end_line);

                if !skip_via_comments {
                    let keyword = if is_head { "if" } else { "elsif" };

                    // `can_simplify_conditional?`: an immediate, non-empty
                    // literal `else` (an `elsif` subsequent, or an empty
                    // `else`, never qualifies — matches
                    // `node.else_branch && node.loc.else.source == 'else'`).
                    let else_node = subsequent.as_ref().and_then(|s| s.as_else_node());
                    let can_simplify =
                        else_node.as_ref().is_some_and(|e| e.statements().is_some_and(|st| !st.body().is_empty()));

                    self.push(level_start, COP, can_simplify, format!("Avoid `{keyword}` branches without a body."));

                    if can_simplify {
                        let else_node = else_node.unwrap();
                        let ekw = else_node.else_keyword_loc();
                        // `node.inverse_keyword`: "unless" at the head (this
                        // branch is always literally `if` there), empty for
                        // an `elsif` (upstream's `case` has no `elsif` arm).
                        let inverse_kw = if is_head { "unless" } else { "" };
                        let cond_start = predicate.location().start_offset();
                        let cond_end = predicate.location().end_offset();
                        let mut replacement = Vec::new();
                        replacement.extend_from_slice(inverse_kw.as_bytes());
                        replacement.push(b' ');
                        replacement.extend_from_slice(&self.src[cond_start..cond_end]);
                        self.fixes.push((ekw.start_offset(), ekw.end_offset(), replacement));

                        // `empty_if_branch?`: at the head, true unless this
                        // if-statement is the SOLE top-level statement in
                        // the whole file (no def/class/module/block/etc.
                        // wraps it, no sibling statements needing a `begin`
                        // wrapper — the only case where whitequark's
                        // `node.parent` is genuinely nil). For an `elsif`
                        // level, it mirrors the PRECEDING level's own body:
                        // true when that body is empty, or is itself a
                        // single bodyless nested `if` (upstream's
                        // `if_branch.if_type? && !if_branch.body`).
                        let empty_if_branch = if is_head {
                            self.top_level_sole_stmt != Some(node.location().start_offset())
                        } else {
                            match &prev_statements {
                                None => true,
                                Some(stmts) => {
                                    stmts.body().len() == 1
                                        && stmts
                                            .body()
                                            .first()
                                            .and_then(|n| n.as_if_node())
                                            .is_some_and(|inner| inner.statements().is_none())
                                }
                            }
                        };

                        let remove_range = if empty_if_branch {
                            (level_start, ekw.start_offset())
                        } else {
                            (level_start, self.line_end_incl_newline(cond_end))
                        };
                        self.fixes.push((remove_range.0, remove_range.1, Vec::new()));
                    }
                }
            }

            let Some(sub) = subsequent.take() else { break };
            let Some(elsif) = sub.as_if_node() else { break };
            prev_statements = statements;
            level_start = elsif.if_keyword_loc().map(|k| k.start_offset()).unwrap_or_else(|| elsif.location().start_offset());
            predicate = elsif.predicate();
            statements = elsif.statements();
            subsequent = elsif.subsequent();
            is_head = false;
        }
    }

    /// Lint/EmptyConditionalBody for `unless` — prism's UnlessNode never
    /// chains (`unless` has no `elsif`), so this is a single-level version
    /// of `check_empty_conditional_body` above: the same-line skip and
    /// `empty_if_branch?`'s "sole top-level statement" check both always
    /// apply at "head" (there IS no other level).
    pub(crate) fn check_empty_conditional_body_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Lint/EmptyConditionalBody";
        if !self.on(COP) {
            return;
        }
        if node.statements().is_some() {
            return;
        }
        let Some(end_kw) = node.end_keyword_loc() else { return };
        let kw_start = node.keyword_loc().start_offset();
        let cond_end = node.predicate().location().end_offset();
        if self.idx.loc(cond_end).0 == self.idx.loc(end_kw.start_offset()).0 {
            return;
        }

        let allow_comments = self.cfg.get(COP, "AllowComments") != Some("false");
        if allow_comments {
            let start_line = self.idx.loc(kw_start).0;
            let end_line = match node.else_clause() {
                Some(ref e) => self.idx.loc(e.else_keyword_loc().start_offset()).0,
                None => self.idx.loc(end_kw.start_offset()).0,
            };
            if self.comments.iter().any(|(line, _, _)| *line >= start_line && *line < end_line) {
                return;
            }
        }

        let else_clause = node.else_clause();
        let can_simplify =
            else_clause.as_ref().is_some_and(|e| e.statements().is_some_and(|st| !st.body().is_empty()));

        self.push(kw_start, COP, can_simplify, "Avoid `unless` branches without a body.");

        if can_simplify {
            let else_node = else_clause.unwrap();
            let ekw = else_node.else_keyword_loc();
            let cond_start = node.predicate().location().start_offset();
            let mut replacement = b"if ".to_vec();
            replacement.extend_from_slice(&self.src[cond_start..cond_end]);
            self.fixes.push((ekw.start_offset(), ekw.end_offset(), replacement));

            let empty_if_branch = self.top_level_sole_stmt != Some(node.location().start_offset());
            let remove_range = if empty_if_branch {
                (kw_start, ekw.start_offset())
            } else {
                (kw_start, self.line_end_incl_newline(cond_end))
            };
            self.fixes.push((remove_range.0, remove_range.1, Vec::new()));
        }
    }

    /// `RangeHelp#range_by_whole_lines`-ish extension used by
    /// `deletion_range`: the offset one past the end of the line containing
    /// `pos` (i.e. including that line's own trailing newline), or the end
    /// of the buffer if `pos` is on the last, newline-less line.
    fn line_end_incl_newline(&self, pos: usize) -> usize {
        let line0 = self.idx.loc(pos).0 - 1;
        self.idx.starts.get(line0 + 1).copied().unwrap_or(self.src.len())
    }
}

// ---- Lint/LiteralInInterpolation helpers ----
//
// Ports `RuboCop::Cop::Lint::LiteralInInterpolation` (rubocop 1.88.0)
// verbatim, including its `autocorrected_value`/`autocorrected_value_in_hash`
// per-type dispatch and the regexp-slash backslash-rebalancing formula.

/// rubocop's `prints_as_self?`: basic literals print their own source when
/// stringified; composites (array/hash/range) do too iff every element does.
/// `__FILE__`/`__LINE__`/`__ENCODING__`/`__END__` need no special-casing
/// here (unlike upstream's whitequark-AST `special_keyword?`): prism gives
/// them their own node types (`SourceFileNode`/`SourceLineNode`/
/// `SourceEncodingNode`/a plain `CallNode`), none of which match below.
fn lii_prints_as_self(node: &ruby_prism::Node) -> bool {
    if node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_string_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
    {
        return true;
    }
    if let Some(arr) = node.as_array_node() {
        return arr.elements().iter().all(|e| lii_prints_as_self(&e));
    }
    if let Some(h) = node.as_hash_node() {
        return h.elements().iter().all(|e| {
            e.as_assoc_node()
                .is_some_and(|a| lii_prints_as_self(&a.key()) && lii_prints_as_self(&a.value()))
        });
    }
    if let Some(r) = node.as_range_node() {
        return r.left().map_or(true, |l| lii_prints_as_self(&l))
            && r.right().map_or(true, |rr| lii_prints_as_self(&rr));
    }
    false
}

/// `space_literal?`: an empty/whitespace-only plain string.
fn lii_is_space_literal(node: &ruby_prism::Node) -> bool {
    node.as_string_node()
        .is_some_and(|s| std::str::from_utf8(s.unescaped()).is_ok_and(|v| v.trim().is_empty()))
}

/// rubocop's `escape_string_content`: `/[\\"]|#(?=[@{$])/` -> backslash-
/// prefix the match. Operates on already-*decoded* string bytes.
fn lii_escape_string_content(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' || b == b'"' {
            out.push(b'\\');
            out.push(b);
        } else if b == b'#' && matches!(bytes.get(i + 1), Some(b'@') | Some(b'{') | Some(b'$')) {
            out.push(b'\\');
            out.push(b'#');
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}

/// The generic `node.source.gsub('"', '\"')` fallback used throughout the
/// upstream cop for composite/else cases: raw source text, quotes escaped.
fn lii_escape_quotes_raw(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        if b == b'"' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

/// `node.children.last.to_i.to_s` for an `int` node — decimal string,
/// underscores/base-prefixes stripped, sign preserved. Uses i128 (Ruby
/// Integer literals are arbitrary precision; ones exceeding i128 are not
/// handled — not exercised by the fixture).
fn lii_int_decimal(node: &ruby_prism::IntegerNode, src: &[u8]) -> String {
    let l = node.location();
    let raw = String::from_utf8_lossy(&src[l.start_offset()..l.end_offset()]).replace('_', "");
    let (neg, raw) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest.to_string()),
        None => (false, raw),
    };
    let (radix, digits): (u32, &str) = if node.is_hexadecimal() {
        (16, raw.trim_start_matches("0x").trim_start_matches("0X"))
    } else if node.is_binary() {
        (2, raw.trim_start_matches("0b").trim_start_matches("0B"))
    } else if node.is_octal() {
        let stripped = raw.trim_start_matches("0o").trim_start_matches("0O");
        if stripped.len() != raw.len() {
            (8, stripped)
        } else {
            // legacy `0377`-style octal (leading zero, no `o`)
            (8, raw.trim_start_matches('0'))
        }
    } else {
        (10, raw.as_str())
    };
    let digits = if digits.is_empty() { "0" } else { digits };
    let value = i128::from_str_radix(digits, radix).unwrap_or(0);
    if neg { (-value).to_string() } else { value.to_string() }
}

/// `node.children.last.to_f.to_s` for a `float` node — Ruby always keeps at
/// least one fractional digit (`2.0.to_s == "2.0"`).
fn lii_float_to_s(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
    }
    let s = format!("{value}");
    if s.contains('.') || s.contains('e') || s.contains('E') { s } else { format!("{s}.0") }
}

/// Is `name` (the *decoded* symbol content) a valid bare identifier that
/// `Symbol#inspect` prints without quotes? Approximates MRI's
/// `rb_str_symname_p` for the common cases the fixture exercises (plain
/// identifiers/ivars/cvars/gvars/operator method names) — exotic method
/// names (e.g. unusual operator combinations) are not exhaustively covered.
fn lii_is_plain_symbol_name(name: &[u8]) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"^(?:[A-Za-z_][A-Za-z0-9_]*[?!=]?|@[A-Za-z_][A-Za-z0-9_]*|@@[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*|\+@|-@|\+|-|\*\*|\*|/|%|==|===|!=|<=>|<<|>>|<=|>=|<|>|&|\||\^|~|!|=~|!~|\[\]=|\[\])$",
        )
        .unwrap()
    });
    std::str::from_utf8(name).is_ok_and(|s| re.is_match(s))
}

/// `node.value.inspect` for a `sym` node — bare `:name` for plain
/// identifiers, else a quoted `:"name"` form (minimal backslash/quote
/// escaping of the name itself; the caller re-escapes via
/// `lii_escape_string_content` for embedding, matching upstream's
/// `escape_string_content(node.value.inspect)`).
fn lii_symbol_inspect(name: &[u8]) -> Vec<u8> {
    if lii_is_plain_symbol_name(name) {
        let mut v = vec![b':'];
        v.extend_from_slice(name);
        v
    } else {
        let mut v = vec![b':', b'"'];
        for &b in name {
            if b == b'\\' || b == b'"' {
                v.push(b'\\');
            }
            v.push(b);
        }
        v.push(b'"');
        v
    }
}

/// `autocorrected_value_for_string`.
fn lii_value_for_string(node: &ruby_prism::StringNode, src: &[u8]) -> Vec<u8> {
    if std::str::from_utf8(node.unescaped()).is_err() {
        let l = node.location();
        let mut s = src[l.start_offset()..l.end_offset()].to_vec();
        if s.first() == Some(&b'"') {
            s.remove(0);
        }
        if s.last() == Some(&b'"') {
            s.pop();
        }
        return s;
    }
    lii_escape_string_content(node.unescaped())
}

/// `autocorrected_value_for_symbol` — prism's `value_loc` already gives the
/// exact content range (no `:`/quotes), so this is just raw-source
/// quote-escaping of that slice (matches upstream's begin/end-pos math).
fn lii_value_for_symbol(node: &ruby_prism::SymbolNode, src: &[u8]) -> Vec<u8> {
    let l = node.value_loc().unwrap_or_else(|| node.location());
    lii_escape_quotes_raw(&src[l.start_offset()..l.end_offset()])
}

/// `autocorrected_value_for_array` — non-percent arrays are replaced
/// verbatim (raw source, quotes escaped, NOT re-serialized element by
/// element); `%w`/`%W`/`%i`/`%I` arrays are re-rendered from their
/// whitespace-split *content* as a plain string array (rubocop does not
/// semantically distinguish `%i`/`%I` from `%w`/`%W` here — see fixture).
fn lii_value_for_array(node: &ruby_prism::ArrayNode, src: &[u8]) -> Vec<u8> {
    let is_percent = node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"%"));
    if !is_percent {
        let l = node.location();
        return lii_escape_quotes_raw(&src[l.start_offset()..l.end_offset()]);
    }
    let open = node.opening_loc().unwrap();
    let close = node.closing_loc().unwrap();
    let content = &src[open.end_offset()..close.start_offset()];
    let words: Vec<&[u8]> =
        content.split(|b: &u8| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
    let mut rendered = vec![b'['];
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            rendered.extend_from_slice(b", ");
        }
        rendered.push(b'"');
        rendered.extend_from_slice(w);
        rendered.push(b'"');
    }
    rendered.push(b']');
    lii_escape_quotes_raw(&rendered)
}

/// `autocorrected_value_for_hash`.
fn lii_value_for_hash(node: &ruby_prism::HashNode, src: &[u8]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (i, el) in node.elements().iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b", ");
        }
        let Some(assoc) = el.as_assoc_node() else { continue };
        out.extend(lii_value_in_hash(&assoc.key(), src));
        out.extend_from_slice(b"=>");
        out.extend(lii_value_in_hash(&assoc.value(), src));
    }
    out.push(b'}');
    out
}

/// `autocorrected_value_in_hash` — a *different* (more conservative)
/// per-type dispatch used for keys/values nested inside a hash; notably
/// `str` is escaped as `\"...\"` (each embedded `"` becomes `\\\"`) rather
/// than via `escape_string_content`.
fn lii_value_in_hash(node: &ruby_prism::Node, src: &[u8]) -> Vec<u8> {
    if let Some(n) = node.as_integer_node() {
        return lii_int_decimal(&n, src).into_bytes();
    }
    if let Some(n) = node.as_float_node() {
        return lii_float_to_s(n.value()).into_bytes();
    }
    if let Some(n) = node.as_string_node() {
        // `"\\\"#{value.gsub('"') { '\\\\\"' }}\\\""` — each embedded `"`
        // becomes THREE backslashes + a quote (verified against the actual
        // cop method, not hand-transcribed: a manual first pass here
        // under-escaped by one backslash and was caught by a live
        // rubocop-vs-oxidecop diff on the nested-hash fixture example).
        let mut out = vec![b'\\', b'"'];
        for &b in n.unescaped() {
            if b == b'"' {
                out.push(b'\\');
                out.push(b'\\');
                out.push(b'\\');
                out.push(b'"');
            } else {
                out.push(b);
            }
        }
        out.push(b'\\');
        out.push(b'"');
        return out;
    }
    if let Some(n) = node.as_symbol_node() {
        return lii_escape_string_content(&lii_symbol_inspect(n.unescaped()));
    }
    if let Some(n) = node.as_array_node() {
        return lii_value_for_array(&n, src);
    }
    if let Some(n) = node.as_hash_node() {
        return lii_value_for_hash(&n, src);
    }
    let l = node.location();
    lii_escape_quotes_raw(&src[l.start_offset()..l.end_offset()])
}

/// `autocorrected_value` — the top-level per-type dispatch for the offending
/// literal itself.
fn lii_autocorrected_value(node: &ruby_prism::Node, src: &[u8]) -> Vec<u8> {
    if let Some(n) = node.as_integer_node() {
        return lii_int_decimal(&n, src).into_bytes();
    }
    if let Some(n) = node.as_float_node() {
        return lii_float_to_s(n.value()).into_bytes();
    }
    if let Some(n) = node.as_string_node() {
        return lii_value_for_string(&n, src);
    }
    if let Some(n) = node.as_symbol_node() {
        return lii_value_for_symbol(&n, src);
    }
    if let Some(n) = node.as_array_node() {
        return lii_value_for_array(&n, src);
    }
    if let Some(n) = node.as_hash_node() {
        return lii_value_for_hash(&n, src);
    }
    if node.as_nil_node().is_some() {
        return Vec::new();
    }
    let l = node.location();
    lii_escape_quotes_raw(&src[l.start_offset()..l.end_offset()])
}

/// `handle_special_regexp_chars` — only invoked for `/../`-slash-delimited
/// regexps whose expanded value contains a `/`; re-balances backslash runs
/// immediately preceding a slash so the compiled `Regexp`'s behavior
/// survives removing the interpolation.
fn lii_handle_regexp_slashes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut backslashes = 0usize;
    for &b in value {
        if b == b'\\' {
            backslashes += 1;
        } else if b == b'/' {
            let needed = 2 * ((backslashes + 1) / 4) + 1;
            out.extend(std::iter::repeat(b'\\').take(needed));
            out.push(b'/');
            backslashes = 0;
        } else {
            out.extend(std::iter::repeat(b'\\').take(backslashes));
            backslashes = 0;
            out.push(b);
        }
    }
    out.extend(std::iter::repeat(b'\\').take(backslashes));
    out
}

impl<'a> super::Cops<'a> {
    /// Lint/LiteralInInterpolation — `"result is #{10}"` → `"result is 10"`.
    /// Hooked from each of the four interpolation-capable container types
    /// (dstr/dsym/xstr/regexp), mirroring the `Interpolation` mixin's
    /// `on_dstr`/`on_xstr`/`on_dsym`/`on_regexp` → `each_child_node(:begin)`:
    /// each container only inspects its OWN direct `#{...}` children —
    /// nested interpolations are handled independently when the walker
    /// separately reaches their own (nested) container node.
    fn check_lii(
        &mut self,
        es: &ruby_prism::EmbeddedStatementsNode,
        is_regexp: bool,
        regexp_slash: bool,
        ends_heredoc: bool,
    ) {
        const COP: &str = "Lint/LiteralInInterpolation";
        if !self.on(COP) {
            return;
        }
        let Some(stmts) = es.statements() else { return };
        let Some(final_node) = stmts.body().last() else { return };

        if !lii_prints_as_self(&final_node) {
            return;
        }
        // `array_in_regexp?`: arrays interpolated directly into a regexp are
        // handled by `Lint/ArrayLiteralInRegexp` instead.
        if is_regexp && final_node.as_array_node().is_some() {
            return;
        }
        // `space_literal? && ends_heredoc_line?`: an explicit space literal
        // at the very end of a heredoc line is left alone (interacts with
        // Layout/TrailingWhitespace instead).
        if ends_heredoc && lii_is_space_literal(&final_node) {
            return;
        }

        let mut expanded = lii_autocorrected_value(&final_node, self.src);
        if is_regexp && regexp_slash && expanded.contains(&b'/') {
            expanded = lii_handle_regexp_slashes(&expanded);
        }

        // `in_array_percent_literal?`: inside a `%W`/`%I` array element,
        // don't strip an interpolation whose expansion is empty or
        // contains whitespace (it would silently merge/split words).
        let es_l = es.location();
        let in_percent_array = self
            .percent_arr_spans
            .iter()
            .any(|(s, e)| es_l.start_offset() >= *s && es_l.start_offset() < *e);
        if in_percent_array && (expanded.is_empty() || expanded.iter().any(u8::is_ascii_whitespace)) {
            return;
        }

        let anchor = final_node.location().start_offset();
        self.push(anchor, COP, true, "Literal interpolation detected.");

        // nested dstr final node ("this is #{"#{1}"}"): upstream skips the
        // correction here — "fixed in next iteration".
        if final_node.as_interpolated_string_node().is_some() {
            return;
        }
        self.fixes.push((es_l.start_offset(), es_l.end_offset(), expanded));
    }

    pub(crate) fn check_lii_dstr(&mut self, node: &ruby_prism::InterpolatedStringNode) {
        let is_heredoc = node.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<"));
        let parts: Vec<ruby_prism::Node> = node.parts().iter().collect();
        for (i, p) in parts.iter().enumerate() {
            let Some(es) = p.as_embedded_statements_node() else { continue };
            // `ends_heredoc_line?`, reformulated in prism-native terms: for
            // squiggly/plain heredocs, a physical line's own newline shows
            // up as the very next `parts()` element (a bare `"\n"` string)
            // — this holds iff nothing else follows the `#{...}` on the
            // line.
            let ends_heredoc = is_heredoc
                && parts
                    .get(i + 1)
                    .and_then(|n| n.as_string_node())
                    .is_some_and(|s| s.unescaped().first() == Some(&b'\n'));
            self.check_lii(&es, false, false, ends_heredoc);
        }
    }

    pub(crate) fn check_lii_dsym(&mut self, node: &ruby_prism::InterpolatedSymbolNode) {
        for p in node.parts().iter() {
            let Some(es) = p.as_embedded_statements_node() else { continue };
            self.check_lii(&es, false, false, false);
        }
    }

    pub(crate) fn check_lii_ixstr(&mut self, node: &ruby_prism::InterpolatedXStringNode) {
        for p in node.parts().iter() {
            let Some(es) = p.as_embedded_statements_node() else { continue };
            self.check_lii(&es, false, false, false);
        }
    }

    pub(crate) fn check_lii_iregexp(&mut self, node: &ruby_prism::InterpolatedRegularExpressionNode) {
        let slash = node.opening_loc().as_slice() == b"/";
        for p in node.parts().iter() {
            let Some(es) = p.as_embedded_statements_node() else { continue };
            self.check_lii(&es, true, slash, false);
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/EmptyBlock — checks for blocks without a body.
    /// Handles both BlockNodes attached to calls and their parent calls.
    /// Empty lambdas/procs are allowed by default (AllowEmptyLambdas: true).
    /// Comments inside the block suppress the offense by default (AllowComments: true).
    pub(crate) fn check_empty_block_call(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/EmptyBlock";
        if !self.on(COP) {
            return;
        }

        let Some(block) = node.block().and_then(|b| b.as_block_node()) else { return };

        // Block has a body, skip
        if block.body().is_some() {
            return;
        }

        // Check if this is a lambda/proc call
        let allow_empty_lambdas = self.cfg.get(COP, "AllowEmptyLambdas") != Some("false");
        if allow_empty_lambdas && is_lambda_or_proc_call(node) {
            return;
        }

        // Check for comments in the block
        let allow_comments = self.cfg.get(COP, "AllowComments") != Some("false");
        if allow_comments {
            let start_line = self.idx.loc(block.location().start_offset()).0;
            let end_line = self.idx.loc(block.closing_loc().start_offset()).0 + 1;
            if self.comments.iter().any(|(line, _, _)| *line >= start_line && *line < end_line) {
                return;
            }
        }

        self.push(node.location().start_offset(), COP, false, "Empty block detected.");
    }

    /// Lint/EmptyBlock for LambdaNodes (`-> {}`).
    pub(crate) fn check_empty_block_lambda(&mut self, node: &ruby_prism::LambdaNode) {
        const COP: &str = "Lint/EmptyBlock";
        if !self.on(COP) {
            return;
        }
        // Lambda has a body, skip
        if node.body().is_some() {
            return;
        }

        // Check AllowEmptyLambdas
        let allow_empty_lambdas = self.cfg.get(COP, "AllowEmptyLambdas") != Some("false");
        if allow_empty_lambdas {
            return;
        }

        // Check for comments in the lambda
        let allow_comments = self.cfg.get(COP, "AllowComments") != Some("false");
        if allow_comments {
            let start_line = self.idx.loc(node.location().start_offset()).0;
            let end_line = self.idx.loc(node.closing_loc().start_offset()).0 + 1;
            if self.comments.iter().any(|(line, _, _)| *line >= start_line && *line < end_line) {
                return;
            }
        }

        self.push(node.location().start_offset(), COP, false, "Empty block detected.");
    }
}

impl<'a> Cops<'a> {
    /// Lint/DuplicateMagicComment — detect duplicate magic comments at the
    /// beginning of the file. Encoding and frozen_string_literal comments are
    /// tracked separately.
    pub(crate) fn check_duplicate_magic_comment(&mut self, first_code_line: Option<usize>) {
        const COP: &str = "Lint/DuplicateMagicComment";
        if !self.on(COP) {
            return;
        }

        // Collect leading magic comments: lines before the first code line
        let mut encoding_seen = false;
        let mut frozen_string_literal_seen = false;

        for (line, start, end) in self.comments {
            // Only process comments before the first code line
            if let Some(fcl) = first_code_line {
                if *line >= fcl {
                    break;
                }
            }

            let comment_text = String::from_utf8_lossy(&self.src[*start..*end]);

            // Determine if this is a magic comment and what type
            if is_encoding_magic_comment(&comment_text) {
                if encoding_seen {
                    // This is a duplicate encoding magic comment
                    self.push(*start, COP, true, "Duplicate magic comment detected.");
                    // Remove the entire line including newline
                    let (line_s, _) = self.idx.loc(*start);
                    let (line_e, _) = self.idx.loc(end.saturating_sub(1));
                    let fix_start = self.idx.starts[line_s - 1];
                    let fix_end = self.idx.starts.get(line_e).copied().unwrap_or(self.src.len());
                    self.fixes.push((fix_start, fix_end, Vec::new()));
                } else {
                    encoding_seen = true;
                }
            } else if is_frozen_string_literal_magic_comment(&comment_text) {
                if frozen_string_literal_seen {
                    // This is a duplicate frozen_string_literal magic comment
                    self.push(*start, COP, true, "Duplicate magic comment detected.");
                    // Remove the entire line including newline
                    let (line_s, _) = self.idx.loc(*start);
                    let (line_e, _) = self.idx.loc(end.saturating_sub(1));
                    let fix_start = self.idx.starts[line_s - 1];
                    let fix_end = self.idx.starts.get(line_e).copied().unwrap_or(self.src.len());
                    self.fixes.push((fix_start, fix_end, Vec::new()));
                } else {
                    frozen_string_literal_seen = true;
                }
            }
        }
    }
}

/// Check if a comment text is an encoding magic comment.
/// Patterns: `# encoding: value` or `# coding: value` (case-insensitive)
fn is_encoding_magic_comment(comment: &str) -> bool {
    // Simple pattern: # followed by optional whitespace, then encoding/coding, then colon
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?i)^\s*#\s*(?:en)?coding:\s*").unwrap()
    });
    re.is_match(comment)
}

/// Check if a comment text is a frozen_string_literal magic comment.
/// Patterns: `# frozen_string_literal: true/false` or similar variations (case-insensitive)
fn is_frozen_string_literal_magic_comment(comment: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?i)^\s*#\s*frozen[_-]string[_-]literal:\s*").unwrap()
    });
    re.is_match(comment)
}
impl<'a> super::Cops<'a> {

    /// Lint/UselessMethodDefinition — method whose body is just `super`
    /// (with matching args or bare).
    pub(crate) fn check_useless_method_definition(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/UselessMethodDefinition";
        if !self.on(COP) {
            return;
        }

        // `method_definition_with_modifier?`: skip when the def is a direct
        // argument of a call UNLESS that call is an access modifier
        // (private/protected/public/module_function) — `do_something def m`
        // is a generic macro whose semantics we can't see.
        if self.def_macro_args.contains(&node.location().start_offset()) {
            return;
        }

        // Skip if method has rest arguments (*args) or optional arguments (x = default)
        // or keyword arguments with defaults
        if let Some(params) = node.parameters() {
            // Check for rest arguments (`*args`); `...` sits in the same slot
            // as a ForwardingParameterNode but is NOT a whitequark restarg —
            // upstream still flags `def m(...)` + bare super.
            // `use_rest_or_optional_args?` lists exactly optarg/restarg/
            // kwoptarg: required keywords, **kwargs, &block, and `...`
            // (prism's keyword_rest ForwardingParameterNode) do NOT exempt.
            if params.rest().is_some_and(|r| r.as_forwarding_parameter_node().is_none()) {
                return;
            }
            if !params.optionals().is_empty() {
                return;
            }
            if params.keywords().iter().any(|k| k.as_optional_keyword_parameter_node().is_some()) {
                return;
            }
            if params
                .keyword_rest()
                .is_some_and(|kr| kr.as_forwarding_parameter_node().is_none() && kr.as_keyword_rest_parameter_node().is_none())
            {
                return;
            }
        }

        // Check if body is just `super` or `super(...)`
        if !self.is_delegating_to_super(node) {
            return;
        }

        let anchor = node.location().start_offset();
        self.push(anchor, COP, true, "Useless method definition detected.");

        // Fix: remove the entire method definition
        let loc = node.location();
        self.fixes.push((loc.start_offset(), loc.end_offset(), Vec::new()));
    }

    fn is_delegating_to_super(&self, def_node: &ruby_prism::DefNode) -> bool {
        let Some(body) = &def_node.body() else {
            return false;
        };

        // Try multiple ways to find a super node
        // First, check if body is directly a super. A super with an attached
        // literal block adds behavior — whitequark wraps it in a :block node
        // upstream's matcher never accepts.
        if let Some(super_node) = body.as_super_node() {
            if super_node.block().is_some() {
                return false;
            }
            return self.check_super_matches_params(&super_node, def_node);
        }

        // Check if body is a bare/forwarding super
        if let Some(fsuper) = body.as_forwarding_super_node() {
            // Forwarding super (bare super) always delegates — unless it
            // carries a block.
            return fsuper.block().is_none();
        }

        // Otherwise, check if it's wrapped in a StatementsNode
        if let Some(stmts) = body.as_statements_node() {
            let stmts_list: Vec<_> = stmts.body().iter().collect();

            // Only flag if ONLY statement is super
            if stmts_list.len() != 1 {
                return false;
            }

            if let Some(super_node) = stmts_list[0].as_super_node() {
                if super_node.block().is_some() {
                    return false;
                }
                return self.check_super_matches_params(&super_node, def_node);
            }

            // Also check for forwarding super in statements
            if let Some(fsuper) = stmts_list[0].as_forwarding_super_node() {
                return fsuper.block().is_none();
            }
        }

        false
    }

    fn check_super_matches_params(&self, super_node: &ruby_prism::SuperNode, def_node: &ruby_prism::DefNode) -> bool {
        // Get super arguments
        let super_args: Vec<&[u8]> = match super_node.arguments() {
            None => {
                // Bare super with no parentheses - delegates all args
                vec![]
            }
            Some(args_node) => {
                // Super with parentheses (even if empty) - extract arguments
                args_node
                    .arguments()
                    .iter()
                    .map(|arg| self.node_src(&arg))
                    .collect()
            }
        };

        // Get method parameters
        let method_args = self.get_method_args(def_node);

        // Check if delegating:
        // Super with same args count and matching source matches the method signature
        method_args.len() == super_args.len()
            && method_args
                .iter()
                .zip(super_args.iter())
                .all(|(m, s)| *m == *s)
    }

    fn get_method_args(&self, def_node: &ruby_prism::DefNode) -> Vec<&[u8]> {
        let mut args = Vec::new();

        if let Some(params) = def_node.parameters() {
            // Only required arguments count for matching with super(args)
            for param in params.requireds().iter() {
                args.push(self.node_src(&param));
            }
        }

        args
    }
}

/// Lint/SelfAssignment — `x = x` (and every shape rubocop recognizes: `||=`/
/// `&&=`, multiple assignment, attribute writers, `[]=`). Ported from
/// `RuboCop::Cop::Lint::SelfAssignment`; the cop never autocorrects, so every
/// offense here is `self.push(..., false, ...)`.
///
/// Node-shape notes (prism vs whitequark):
///   - whitequark folds a plain var write, `||=`, and `&&=` into `lvasgn`/
///     `or-asgn`/`and-asgn` with a UNIFORM lhs/rhs shape per var kind; prism
///     instead gives each combination (kind × operator) its own struct
///     (`LocalVariableWriteNode`/`OrWriteNode`/`AndWriteNode`, ditto for
///     ivar/cvar/gvar/const) — hence one thin per-kind wrapper below, all
///     sharing `self_assignment_var_check`.
///   - `obj.attr {=,||=,&&=}` and `hash[k] {=,||=,&&=}` are, in whitequark,
///     ALL "send" nodes (`[]=`/`attr=` for plain writes; `or-asgn`/`and-asgn`
///     wrapping a `[]`/`attr` READ node for the shorthand forms) — one
///     `reader_self_assignment?` handles both attribute and index shapes.
///     Prism instead has SEPARATE node types per shape: `CallNode` (plain
///     `obj.attr =` / `hash[k] =` / the explicit-call form `obj.[]=(...)`),
///     and — with NO relation to `CallNode` at all — `CallAndWriteNode`/
///     `CallOrWriteNode` (attribute `||=`/`&&=`) and `IndexAndWriteNode`/
///     `IndexOrWriteNode` (index `||=`/`&&=`). Each needs its own `visit_*`
///     override (see `mod.rs`) feeding the same `sa_reader_match` core.
impl<'a> super::Cops<'a> {
    /// `AllowRBSInlineAnnotation` (default false), resolved via `cfg.get` so
    /// the schema default applies when unset.
    fn self_assignment_allow_rbs(&self) -> bool {
        self.cfg.get("Lint/SelfAssignment", "AllowRBSInlineAnnotation") == Some("true")
    }

    /// Upstream's `rbs_inline_annotation?` asks whether a trailing `#: ...`
    /// RBS comment is associated (via `ast_with_comments`) with a specific
    /// sub-node (the rhs for `on_lvasgn`, the first mlhs target for
    /// `on_masgn`, the lhs reader for `on_or_asgn`/`on_and_asgn`, the
    /// receiver for `on_send`). Every spec fixture keeps the whole offending
    /// statement — and its trailing annotation, if any — on one physical
    /// line, so "does a `#:`-comment sit on THIS line" is behaviorally
    /// equivalent here and sidesteps reimplementing comment/node association.
    fn self_assignment_rbs_annotated(&self, offset: usize) -> bool {
        let line = self.idx.loc(offset).0;
        self.comments.iter().any(|&(l, s, e)| l == line && self.src[s..e].starts_with(b"#:"))
    }

    /// Structural-equality shortcut for the node comparisons this cop makes
    /// (`node.receiver == value_node.receiver`, `lhs.arguments == rhs.arguments`,
    /// `rhs.children.first == lhs.children.first`, ...): every comparison
    /// this cop needs is between two sub-expressions that, when equal, are
    /// spelled identically (same variable name, same literal) — so byte-for-
    /// byte source comparison stands in for whitequark's structural node
    /// `==` without needing a general AST-equality routine.
    fn sa_opt_recv_eq(&self, a: Option<&ruby_prism::Node>, b: Option<&ruby_prism::Node>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(x), Some(y)) => self.node_src(x) == self.node_src(y),
            _ => false,
        }
    }
    fn sa_args_eq(&self, a: &[ruby_prism::Node], b: &[ruby_prism::Node]) -> bool {
        a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| self.node_src(x) == self.node_src(y))
    }

    /// Shared core for the four simple-var kinds (local/instance/class/global):
    /// gate on enablement + RBS annotation, then let the caller's `matches`
    /// closure decide (by rhs node type + name) whether this is a self-write.
    fn self_assignment_var_check(
        &mut self,
        whole_start: usize,
        rhs: &ruby_prism::Node,
        matches: impl FnOnce(&ruby_prism::Node) -> bool,
    ) {
        const COP: &str = "Lint/SelfAssignment";
        if !self.on(COP) {
            return;
        }
        if self.self_assignment_allow_rbs() && self.self_assignment_rbs_annotated(whole_start) {
            return;
        }
        if matches(rhs) {
            self.push(whole_start, COP, false, "Self-assignment detected.");
        }
    }

    /// `on_lvasgn`/`on_ivasgn`/`on_cvasgn`/`on_gvasgn` (`ASSIGNMENT_TYPE_TO_RHS_TYPE`):
    /// `foo = foo`, `foo ||= foo`, `foo &&= foo`.
    pub(crate) fn check_self_assignment_lvar(&mut self, whole_start: usize, name: &[u8], rhs: &ruby_prism::Node) {
        self.self_assignment_var_check(whole_start, rhs, |r| {
            r.as_local_variable_read_node().is_some_and(|v| v.name().as_slice() == name)
        });
    }
    pub(crate) fn check_self_assignment_ivar(&mut self, whole_start: usize, name: &[u8], rhs: &ruby_prism::Node) {
        self.self_assignment_var_check(whole_start, rhs, |r| {
            r.as_instance_variable_read_node().is_some_and(|v| v.name().as_slice() == name)
        });
    }
    pub(crate) fn check_self_assignment_cvar(&mut self, whole_start: usize, name: &[u8], rhs: &ruby_prism::Node) {
        self.self_assignment_var_check(whole_start, rhs, |r| {
            r.as_class_variable_read_node().is_some_and(|v| v.name().as_slice() == name)
        });
    }
    pub(crate) fn check_self_assignment_gvar(&mut self, whole_start: usize, name: &[u8], rhs: &ruby_prism::Node) {
        self.self_assignment_var_check(whole_start, rhs, |r| {
            r.as_global_variable_read_node().is_some_and(|v| v.name().as_slice() == name)
        });
    }
    /// `on_casgn`: only the bare-constant shape (`Foo = Foo`) is checked —
    /// upstream compares `node.namespace == node.rhs.namespace` too, which is
    /// why `Foo = ::Foo`/`Foo ||= ::Foo` (rhs scoped to top-level, namespace
    /// `cbase` vs lhs's `nil`) never match; requiring the rhs to be a bare
    /// `ConstantReadNode` (rather than a `ConstantPathNode`) reproduces that
    /// for every namespace shape without modeling namespaces explicitly.
    pub(crate) fn check_self_assignment_const(&mut self, whole_start: usize, name: &[u8], rhs: &ruby_prism::Node) {
        self.self_assignment_var_check(whole_start, rhs, |r| {
            r.as_constant_read_node().is_some_and(|v| v.name().as_slice() == name)
        });
    }

    /// `on_masgn` / `multiple_self_assignment?`: `foo, bar = foo, bar` (and
    /// the explicit-array form `foo, bar = [foo, bar]`). Only local/instance/
    /// class/global-var targets ever match (`ASSIGNMENT_TYPE_TO_RHS_TYPE`
    /// excludes `casgn`/`send`/`splat`), so a target of any other shape
    /// anywhere in the list makes the whole `masgn` unflagged — ported via
    /// `sa_masgn_pair_matches` returning `false` for those shapes.
    pub(crate) fn check_self_assignment_masgn(&mut self, node: &ruby_prism::MultiWriteNode) {
        const COP: &str = "Lint/SelfAssignment";
        if !self.on(COP) {
            return;
        }
        let whole_start = node.location().start_offset();
        if self.self_assignment_allow_rbs() && self.self_assignment_rbs_annotated(whole_start) {
            return;
        }
        // rhs must be an explicit array — `foo, bar = *something` (splat) and
        // `foo, bar = something` (a bare method-call rhs) are never arrays.
        let Some(arr) = node.value().as_array_node() else { return };
        let elems: Vec<ruby_prism::Node> = arr.elements().iter().collect();

        let lefts: Vec<ruby_prism::Node> = node.lefts().iter().collect();
        let rights: Vec<ruby_prism::Node> = node.rights().iter().collect();
        let mut targets: Vec<ruby_prism::Node> = Vec::with_capacity(lefts.len() + rights.len() + 1);
        targets.extend(lefts);
        if let Some(rest) = node.rest() {
            targets.push(rest);
        }
        targets.extend(rights);

        if targets.is_empty() || targets.len() != elems.len() {
            return;
        }
        let all_match = targets.iter().zip(elems.iter()).all(|(t, r)| sa_masgn_pair_matches(t, r));
        if all_match {
            self.push(whole_start, COP, false, "Self-assignment detected.");
        }
    }

    /// `reader_self_assignment?`: does `rhs` read the exact same
    /// `receiver.method_name(*key_args)` expression being written? Shared by
    /// every "call/index write vs call/index READ" shape: plain `obj.attr =
    /// obj.attr` / `hash[k] = hash[k]` (`on_send`'s `handle_attribute_assignment`/
    /// `handle_key_assignment`, `method_name`/`key_args` taken from the LHS
    /// write) and their `||=`/`&&=` counterparts (`CallOrWriteNode` &c., with
    /// `key_args` empty for the attribute shape). A method-call key
    /// (`hash[foo] ||= hash[foo]`) is deliberately never a match, since it
    /// may return a different value each call.
    fn sa_reader_match(
        &self,
        receiver: Option<&ruby_prism::Node>,
        method_name: &[u8],
        key_args: &[ruby_prism::Node],
        rhs: &ruby_prism::Node,
    ) -> bool {
        let Some(rc) = rhs.as_call_node() else { return false };
        if rc.name().as_slice() != method_name {
            return false;
        }
        if !self.sa_opt_recv_eq(receiver, rc.receiver().as_ref()) {
            return false;
        }
        if key_args.iter().any(|a| a.as_call_node().is_some()) {
            return false;
        }
        let rc_args: Vec<ruby_prism::Node> =
            rc.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        self.sa_args_eq(key_args, &rc_args)
    }

    /// `CallAndWriteNode`/`CallOrWriteNode` (attribute `foo.bar {||=,&&=} foo.bar`)
    /// and `IndexAndWriteNode`/`IndexOrWriteNode` (`hash[k] {||=,&&=} hash[k]`) —
    /// `or_and_asgn_self_assignment?`'s `:send`/`:csend` branch.
    pub(crate) fn check_self_assignment_reader_write(
        &mut self,
        whole_start: usize,
        receiver: Option<ruby_prism::Node>,
        method_name: &[u8],
        key_args: &[ruby_prism::Node],
        rhs: &ruby_prism::Node,
    ) {
        const COP: &str = "Lint/SelfAssignment";
        if !self.on(COP) {
            return;
        }
        if self.self_assignment_allow_rbs() && self.self_assignment_rbs_annotated(whole_start) {
            return;
        }
        if self.sa_reader_match(receiver.as_ref(), method_name, key_args, rhs) {
            self.push(whole_start, COP, false, "Self-assignment detected.");
        }
    }

    /// `on_send`/`on_csend`: plain `obj.attr = obj.attr` (`handle_attribute_assignment`)
    /// and `hash[k] = hash[k]` / the explicit-call `obj.[]=(k, obj[k])` /
    /// `obj&.[]=(k, obj[k])` forms (`handle_key_assignment`, dispatched off
    /// `method?(:[]=)` — which also matches the explicit-call spelling, since
    /// it has the exact same method name).
    pub(crate) fn check_self_assignment_send(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/SelfAssignment";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        let is_key = name == b"[]=";
        if !is_key && !is_assignment_method_name(name) {
            return;
        }
        if self.self_assignment_allow_rbs() && self.self_assignment_rbs_annotated(node.location().start_offset()) {
            return;
        }
        let arg_list: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        let offends = if is_key {
            // `node.last_argument` / `node.arguments[0...-1]`: the trailing
            // arg is the value being written, everything before it is the
            // index's own key arguments.
            match arg_list.split_last() {
                Some((value_node, key_args)) => {
                    self.sa_reader_match(node.receiver().as_ref(), b"[]", key_args, value_node)
                }
                None => false,
            }
        } else if arg_list.len() == 1 {
            // `first_argument.method_name.to_s == node.method_name.to_s.delete_suffix('=')`
            match name.strip_suffix(b"=") {
                Some(base) => self.sa_reader_match(node.receiver().as_ref(), base, &[], &arg_list[0]),
                None => false,
            }
        } else {
            false
        };
        if offends {
            self.push(node.location().start_offset(), COP, false, "Self-assignment detected.");
        }
    }
}

/// `rhs_matches_lhs?` restricted to the shapes `ASSIGNMENT_TYPE_TO_RHS_TYPE`
/// covers (local/instance/class/global-var targets only — a `casgn`, `send`
/// (attribute/index), or `splat` target never matches, matching upstream's
/// `Hash#[]` miss on those types).
fn sa_masgn_pair_matches(target: &ruby_prism::Node, rhs_elem: &ruby_prism::Node) -> bool {
    if let Some(t) = target.as_local_variable_target_node() {
        return rhs_elem.as_local_variable_read_node().is_some_and(|r| r.name().as_slice() == t.name().as_slice());
    }
    if let Some(t) = target.as_instance_variable_target_node() {
        return rhs_elem
            .as_instance_variable_read_node()
            .is_some_and(|r| r.name().as_slice() == t.name().as_slice());
    }
    if let Some(t) = target.as_class_variable_target_node() {
        return rhs_elem.as_class_variable_read_node().is_some_and(|r| r.name().as_slice() == t.name().as_slice());
    }
    if let Some(t) = target.as_global_variable_target_node() {
        return rhs_elem.as_global_variable_read_node().is_some_and(|r| r.name().as_slice() == t.name().as_slice());
    }
    false
}

impl<'a> super::Cops<'a> {
    /// Lint/UselessTimes — `0.times { }` / negative `.times` never yield;
    /// `1.times { }` yields exactly once, so the call adds nothing but noise.
    /// Ported from `lib/rubocop/cop/lint/useless_times.rb` (rubocop 1.88.0).
    ///
    /// `times_call?` (`(send (int $_) :times (block-pass (sym $_))?)`) is
    /// reproduced directly: plain (non safe-nav) `send`, integer-literal
    /// receiver, no positional args, and — if a block-pass is present — it
    /// must be a literal `&:sym` (anything else, e.g. `&some_proc`, means the
    /// whole pattern fails to match and there is NO offense at all, not just
    /// no autocorrect).
    pub(crate) fn check_useless_times<'pr>(&mut self, node: &ruby_prism::CallNode<'pr>) {
        const COP: &str = "Lint/UselessTimes";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"times" || node.is_safe_navigation() {
            return;
        }
        let Some(receiver) = node.receiver() else { return };
        let Some(int_node) = receiver.as_integer_node() else { return };
        // An extra positional arg (`1.times(2)`, `1.times(2, &:foo)`) breaks
        // the node-pattern match entirely — no offense, not even LOC.
        if node.arguments().is_some() {
            return;
        }

        // Owned, not borrowed: `SymbolNode::unescaped()` ties its return to
        // `&self`, and the local `sym`/`expr` bindings don't outlive this
        // block — a `Vec` sidesteps that without changing behavior (this is
        // a short-lived label, not a hot path).
        let mut proc_name: Option<Vec<u8>> = None;
        let mut literal_block: Option<ruby_prism::BlockNode<'pr>> = None;
        if let Some(b) = node.block() {
            if let Some(bn) = b.as_block_node() {
                literal_block = Some(bn);
            } else if let Some(bp) = b.as_block_argument_node() {
                // `(block-pass (sym $_))` — a non-literal block-pass
                // (`&some_proc`, bare `&`) doesn't match at all.
                let Some(expr) = bp.expression() else { return };
                let Some(sym) = expr.as_symbol_node() else { return };
                proc_name = Some(sym.unescaped().to_vec());
            } else {
                return;
            }
        }

        // `return if count > 1` — huge (bignum) receivers overflow i32; they
        // are never `<= 1` in practice, so treat conversion failure the same
        // as "count > 1" (no offense). This is a deliberate, harmless
        // deviation for a receiver no real program writes.
        let count: i32 = match int_node.value().try_into() {
            Ok(v) => v,
            Err(_) => return,
        };
        if count > 1 {
            return;
        }

        let node_loc = node.location();
        let start = node_loc.start_offset();

        // `next if !own_line?(node) || node.parent&.send_type?` — both guards
        // live inside the corrector block upstream: tripping either one still
        // registers the offense, just with no fix attached (not "Correctable").
        let guards_ok = self.ut_own_line(start) && !self.ut_call_child.contains(&start);
        let fix: Option<(usize, usize, Vec<u8>)> = if !guards_ok {
            None
        } else {
            let empty_block_body = literal_block.as_ref().is_some_and(|b| b.body().is_none());
            if count < 1 || empty_block_body {
                Some(self.ut_remove_whole_lines(node_loc))
            } else if let Some(name) = &proc_name {
                Some((start, node_loc.end_offset(), name.clone()))
            } else if let Some(bn) = &literal_block {
                self.ut_autocorrect_block(&node_loc, bn).map(|body| (start, node_loc.end_offset(), body))
            } else {
                None
            }
        };

        self.push(start, COP, fix.is_some(), format!("Useless call to `{count}.times` detected."));
        if let Some(f) = fix {
            self.fixes.push(f);
        }
    }

    /// `own_line?`: nothing but whitespace precedes `offset` on its line.
    fn ut_own_line(&self, offset: usize) -> bool {
        let (line, _) = self.idx.loc(offset);
        let line_start = self.idx.starts[line - 1];
        self.src[line_start..offset].iter().all(u8::is_ascii_whitespace)
    }

    /// `remove_node`: `range_by_whole_lines(node.source_range,
    /// include_final_newline: true)` — extend to the start of the node's
    /// first line and through the newline ending its last line (or EOF, if
    /// that line has none).
    fn ut_remove_whole_lines(&self, node_loc: ruby_prism::Location<'_>) -> (usize, usize, Vec<u8>) {
        let start_off = node_loc.start_offset();
        let end_off = node_loc.end_offset();
        let start_line = self.idx.loc(start_off).0;
        let end_line = self.idx.loc(end_off.saturating_sub(1).max(start_off)).0;
        let range_start = self.idx.starts[start_line - 1];
        let range_end =
            if end_line < self.idx.starts.len() { self.idx.starts[end_line] } else { self.src.len() };
        (range_start, range_end, Vec::new())
    }

    /// `autocorrect_block`: splice the block's body out in place of the whole
    /// `N.times do ... end` node, substituting the (sole, simple) block
    /// argument's occurrences with `0` and re-indenting continuation lines so
    /// they land where the receiver used to start. Returns `None` for any of
    /// upstream's `reducible_to_body?` disqualifiers (never autocorrect).
    fn ut_autocorrect_block(
        &self,
        node_loc: &ruby_prism::Location<'_>,
        block: &ruby_prism::BlockNode<'_>,
    ) -> Option<Vec<u8>> {
        use ruby_prism::Visit;
        let body = block.body()?;

        let block_arg = match ut_param_shape(block) {
            UtParamShape::NotReducible => return None,
            UtParamShape::Zero => None,
            UtParamShape::Simple(name) => Some(name),
        };

        let mut scan = UtBodyScan {
            target: block_arg,
            reassigned: false,
            shield_depth: 0,
            orphan: false,
            in_pattern: false,
        };
        scan.visit(&body);
        if scan.orphan || scan.reassigned {
            return None;
        }

        let body_loc = body.location();
        let body_text = &self.src[body_loc.start_offset()..body_loc.end_offset()];
        let text = match block_arg {
            Some(name) => ut_word_replace(body_text, name, b"0"),
            None => body_text.to_vec(),
        };

        let node_col = self.ut_column(node_loc.start_offset());
        let body_col = self.ut_column(body_loc.start_offset());
        Some(ut_fix_indentation(&text, node_col, body_col))
    }

    fn ut_column(&self, offset: usize) -> usize {
        let (line, _) = self.idx.loc(offset);
        offset - self.idx.starts[line - 1]
    }
}

/// The shape of a block's formal parameters, for `reducible_to_body?`.
enum UtParamShape<'a> {
    /// No declared params (including `it`/numbered-parameter blocks, which
    /// prism represents without a `BlockParametersNode` — matching upstream's
    /// incidental behavior of never substituting `it`/`_1` either).
    Zero,
    /// Exactly one plain required identifier (`|i|`) — substitutable.
    Simple(&'a [u8]),
    /// Anything else (>1 param of any kind; or a lone destructured/splat/
    /// optional/keyword/block param) — never autocorrect.
    NotReducible,
}

fn ut_param_shape<'a>(block: &ruby_prism::BlockNode<'a>) -> UtParamShape<'a> {
    let Some(params) = block.parameters() else { return UtParamShape::Zero };
    let Some(bp) = params.as_block_parameters_node() else { return UtParamShape::Zero };
    let Some(p) = bp.parameters() else { return UtParamShape::Zero };
    let requireds = p.requireds();
    let total = requireds.iter().count()
        + p.optionals().iter().count()
        + usize::from(p.rest().is_some())
        + p.posts().iter().count()
        + p.keywords().iter().count()
        + usize::from(p.keyword_rest().is_some())
        + usize::from(p.block().is_some());
    if total == 0 {
        return UtParamShape::Zero;
    }
    if total == 1 {
        if let Some(req) = requireds.iter().next().and_then(|n| n.as_required_parameter_node()) {
            return UtParamShape::Simple(req.name().as_slice());
        }
    }
    UtParamShape::NotReducible
}

/// `\b#{name}\b` gsub, byte-for-byte (this is what upstream does — a naive
/// textual substitution over the body's raw source, not an AST rewrite, so
/// it would also (incorrectly) touch an identical identifier inside a string
/// literal; that quirk is intentionally preserved).
fn ut_word_replace(text: &[u8], name: &[u8], replacement: &[u8]) -> Vec<u8> {
    fn is_word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i..].starts_with(name)
            && !name.is_empty()
            && (i == 0 || !is_word_byte(text[i - 1]))
            && (i + name.len() == text.len() || !is_word_byte(text[i + name.len()]))
        {
            out.extend_from_slice(replacement);
            i += name.len();
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

/// `fix_indentation`: for every line but the first, delete the byte-column
/// range `[node_col, body_col)` (NOT "the first `body_col - node_col`
/// bytes" — the range is anchored at `node_col`, which only coincides with
/// the line start when the offending call itself starts at column 0).
/// Blank lines are left alone; a line too short to reach `node_col` is left
/// alone too (upstream would raise; this is a harmless, safer deviation).
fn ut_fix_indentation(text: &[u8], node_col: usize, body_col: usize) -> Vec<u8> {
    if body_col <= node_col {
        return text.to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    for (i, line) in text.split(|&b| b == b'\n').enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        if i == 0 || line.is_empty() || line.len() <= node_col {
            out.extend_from_slice(line);
        } else {
            let cut_end = body_col.min(line.len());
            out.extend_from_slice(&line[..node_col]);
            out.extend_from_slice(&line[cut_end..]);
        }
    }
    out
}

/// One recursive pass over a `1.times { |arg| BODY }`'s body computing BOTH
/// `reducible_to_body?` disqualifiers that require walking the tree:
///   - `orphans_loop_control_keyword?`: a `next`/`break`/`redo` not shielded
///     by an intervening block/while/until/for (relative to the outer
///     `times` block, which is about to be removed).
///   - `block_reassigns_arg?`: any `lvasgn`-shaped write to `arg` anywhere in
///     the subtree (whitequark represents op-assign targets, multiple-
///     assignment targets, for-loop index vars and rescue vars all as plain
///     `lvasgn` — matched here via prism's `LocalVariable*WriteNode` and
///     `LocalVariableTargetNode`). A `case/in` or one-line `=>`/`in` pattern
///     capture reuses `LocalVariableTargetNode` too, but whitequark parses
///     those as `match_var` (never `lvasgn`) — `in_pattern` excludes them.
struct UtBodyScan<'a> {
    target: Option<&'a [u8]>,
    reassigned: bool,
    shield_depth: u32,
    orphan: bool,
    in_pattern: bool,
}
impl<'pr> ruby_prism::Visit<'pr> for UtBodyScan<'pr> {
    fn visit_block_node(&mut self, node: &ruby_prism::BlockNode<'pr>) {
        self.shield_depth += 1;
        ruby_prism::visit_block_node(self, node);
        self.shield_depth -= 1;
    }
    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        self.shield_depth += 1;
        ruby_prism::visit_while_node(self, node);
        self.shield_depth -= 1;
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        self.shield_depth += 1;
        ruby_prism::visit_until_node(self, node);
        self.shield_depth -= 1;
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        self.shield_depth += 1;
        ruby_prism::visit_for_node(self, node);
        self.shield_depth -= 1;
    }
    fn visit_next_node(&mut self, node: &ruby_prism::NextNode<'pr>) {
        if self.shield_depth == 0 {
            self.orphan = true;
        }
        ruby_prism::visit_next_node(self, node);
    }
    fn visit_break_node(&mut self, node: &ruby_prism::BreakNode<'pr>) {
        if self.shield_depth == 0 {
            self.orphan = true;
        }
        ruby_prism::visit_break_node(self, node);
    }
    fn visit_redo_node(&mut self, node: &ruby_prism::RedoNode<'pr>) {
        if self.shield_depth == 0 {
            self.orphan = true;
        }
        ruby_prism::visit_redo_node(self, node);
    }
    fn visit_in_node(&mut self, node: &ruby_prism::InNode<'pr>) {
        let prev = self.in_pattern;
        self.in_pattern = true;
        self.visit(&node.pattern());
        self.in_pattern = prev;
        if let Some(s) = node.statements() {
            self.visit_statements_node(&s);
        }
    }
    fn visit_match_required_node(&mut self, node: &ruby_prism::MatchRequiredNode<'pr>) {
        self.visit(&node.value());
        let prev = self.in_pattern;
        self.in_pattern = true;
        self.visit(&node.pattern());
        self.in_pattern = prev;
    }
    fn visit_match_predicate_node(&mut self, node: &ruby_prism::MatchPredicateNode<'pr>) {
        self.visit(&node.value());
        let prev = self.in_pattern;
        self.in_pattern = true;
        self.visit(&node.pattern());
        self.in_pattern = prev;
    }
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        if self.target == Some(node.name().as_slice()) {
            self.reassigned = true;
        }
        ruby_prism::visit_local_variable_write_node(self, node);
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        if self.target == Some(node.name().as_slice()) {
            self.reassigned = true;
        }
        ruby_prism::visit_local_variable_and_write_node(self, node);
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        if self.target == Some(node.name().as_slice()) {
            self.reassigned = true;
        }
        ruby_prism::visit_local_variable_or_write_node(self, node);
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        if self.target == Some(node.name().as_slice()) {
            self.reassigned = true;
        }
        ruby_prism::visit_local_variable_operator_write_node(self, node);
    }
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        if !self.in_pattern && self.target == Some(node.name().as_slice()) {
            self.reassigned = true;
        }
    }
}
impl<'a> Cops<'a> {
    /// Lint/ToJSON — checks that `#to_json` includes an optional argument
    /// to be parsable via JSON.generate(obj).
    pub(crate) fn check_to_json(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/ToJSON";
        if !self.on(COP) {
            return;
        }

        // Check if this is a `to_json` method with no arguments
        if node.name().as_slice() != b"to_json" {
            return;
        }

        // Check if arguments are empty
        let has_params = node
            .parameters()
            .is_some_and(|p| !p.requireds().is_empty() || !p.optionals().is_empty()
                || p.rest().is_some() || !p.posts().is_empty()
                || !p.keywords().is_empty() || p.keyword_rest().is_some()
                || p.block().is_some());

        if has_params {
            return;
        }

        let anchor = node.location().start_offset();
        self.push(anchor, COP, true, "`#to_json` requires an optional argument to be parsable via JSON.generate(obj).");

        // Autocorrect: insert `(*_args)` after the method name
        let name_loc = node.name_loc();
        let insert_pos = name_loc.end_offset();
        self.fixes.push((insert_pos, insert_pos, b"(*_args)".to_vec()));
    }
}


impl<'a> super::Cops<'a> {
    /// Security/YAMLLoad — `YAML.load` without `permitted_classes` is unsafe
    /// in Ruby 3.0 and below. In Ruby 3.1+ (Psych 4), `YAML.load` is safe by default.
    pub(crate) fn check_yaml_load(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Security/YAMLLoad";
        if !self.on(COP) || self.cfg.target_ruby() > 3.0 {
            return;
        }
        let name = node.name().as_slice();
        if name != b"load" {
            return;
        }
        let recv_const = node.receiver().and_then(|r| const_name_root(&r));
        if recv_const.as_deref() != Some("YAML") {
            return;
        }
        if let Some(sel) = node.message_loc() {
            self.push(sel.start_offset(), COP, true,
                "Prefer using `YAML.safe_load` over `YAML.load`.");
            self.fixes.push((sel.start_offset(), sel.end_offset(), b"safe_load".to_vec()));
        }
    }
}

/// `Struct.instance_methods.sort` under Ruby 4.0.0 — rubocop's
/// `STRUCT_METHOD_NAMES`, ported verbatim (same order, same entries) so any
/// future upstream table refresh is a straight diff against this list.
const STRUCT_METHOD_NAMES: &[&[u8]] = &[
    b"!", b"!=", b"!~", b"<=>", b"==", b"===", b"[]", b"[]=", b"__id__", b"__send__", b"all?",
    b"any?", b"chain", b"chunk", b"chunk_while", b"class", b"clone", b"collect", b"collect_concat",
    b"compact", b"count", b"cycle", b"deconstruct", b"deconstruct_keys",
    b"define_singleton_method", b"detect", b"dig", b"display", b"drop", b"drop_while", b"dup",
    b"each", b"each_cons", b"each_entry", b"each_pair", b"each_slice", b"each_with_index",
    b"each_with_object", b"entries", b"enum_for", b"eql?", b"equal?", b"extend", b"filter",
    b"filter_map", b"find", b"find_all", b"find_index", b"first", b"flat_map", b"freeze",
    b"frozen?", b"grep", b"grep_v", b"group_by", b"hash", b"include?", b"inject", b"inspect",
    b"instance_eval", b"instance_exec", b"instance_of?", b"instance_variable_defined?",
    b"instance_variable_get", b"instance_variable_set", b"instance_variables", b"is_a?",
    b"itself", b"kind_of?", b"lazy", b"length", b"map", b"max", b"max_by", b"member?", b"members",
    b"method", b"methods", b"min", b"min_by", b"minmax", b"minmax_by", b"nil?", b"none?",
    b"object_id", b"one?", b"partition", b"private_methods", b"protected_methods",
    b"public_method", b"public_methods", b"public_send", b"reduce", b"reject",
    b"remove_instance_variable", b"respond_to?", b"reverse_each", b"select", b"send",
    b"singleton_class", b"singleton_method", b"singleton_methods", b"size", b"slice_after",
    b"slice_before", b"slice_when", b"sort", b"sort_by", b"sum", b"take", b"take_while", b"tally",
    b"tap", b"then", b"to_a", b"to_enum", b"to_h", b"to_s", b"to_set", b"uniq", b"values",
    b"values_at", b"yield_self", b"zip",
];

impl<'a> super::Cops<'a> {
    /// Lint/StructNewOverride — a `Struct.new(:member, ...)` (bare or
    /// `::`-prefixed receiver) member name that shadows a built-in `Struct`
    /// instance method is easy to do by accident and produces surprising
    /// results. Mirrors rubocop's `on_send`: RESTRICT_ON_SEND is `:new`, the
    /// receiver must be a bare/`::`-rooted `Struct` (the `struct_new`
    /// node-matcher), and EVERY argument is walked — the first is exempt
    /// only when it's a string (the optional explicit class name); any
    /// argument that isn't a symbol or string literal is silently skipped
    /// (this is how the trailing `keyword_init: true` hash is ignored).
    pub(crate) fn check_struct_new_override(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/StructNewOverride";
        if node.name().as_slice() != b"new" || node.is_safe_navigation() || !self.on(COP) {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if const_name_root(&recv).as_deref() != Some("Struct") {
            return;
        }
        let Some(args) = node.arguments() else { return };
        for (index, arg) in args.arguments().iter().enumerate() {
            // Ignore if the first argument is a class name (a string).
            if index == 0 && arg.as_string_node().is_some() {
                continue;
            }
            // `member_name.inspect` / `member_name.to_s` — for both symbol
            // and string nodes here the raw (unescaped) bytes ARE the
            // member name; only the `.inspect` quoting differs by type.
            // Safe to build unquoted since every name that reaches the
            // format! below is a member of STRUCT_METHOD_NAMES, and none of
            // those tokens need escaping when symbol- or string-quoted.
            let (name, inspected): (Vec<u8>, String) = if let Some(s) = arg.as_symbol_node() {
                let n = s.unescaped().to_vec();
                let inspected = format!(":{}", String::from_utf8_lossy(&n));
                (n, inspected)
            } else if let Some(s) = arg.as_string_node() {
                let n = s.unescaped().to_vec();
                let inspected = format!("\"{}\"", String::from_utf8_lossy(&n));
                (n, inspected)
            } else {
                continue;
            };
            if !STRUCT_METHOD_NAMES.contains(&name.as_slice()) {
                continue;
            }
            let method_name = String::from_utf8_lossy(&name);
            self.push(
                arg.location().start_offset(),
                COP,
                false,
                format!("`{inspected}` member overrides `Struct#{method_name}` and it may be unexpected."),
            );
        }
    }
}
impl<'a> super::Cops<'a> {
    /// Lint/Loop — `begin ... end while/until condition` should be replaced
    /// with `loop do ... break [unless|if] condition ... end`.
    pub(crate) fn check_loop_while(&mut self, node: &ruby_prism::WhileNode) {
        const COP: &str = "Lint/Loop";
        if !self.on(COP) || !node.is_begin_modifier() {
            return;
        }

        let statements = match node.statements() {
            Some(s) => s,
            None => return,
        };
        // Find the BeginNode in statements
        let Some(begin_node) = statements.body().iter().find_map(|n| n.as_begin_node()) else {
            return;
        };
        let Some(begin_keyword_loc) = begin_node.begin_keyword_loc() else { return };
        let Some(end_keyword_loc) = begin_node.end_keyword_loc() else { return };

        let keyword_loc = node.keyword_loc();
        let condition = &node.predicate();
        let location = node.location();

        const MSG: &str = "Use `Kernel#loop` with `break` rather than `begin/end/until`(or `while`).";

        // Register the offense at the keyword location
        self.push(keyword_loc.start_offset(), COP, true, MSG);

        // Build the break statement
        let break_keyword = "unless";
        let condition_src = String::from_utf8_lossy(self.node_src(condition));

        // Calculate indentation for the break line (same as 'end' keyword)
        let (_, col) = self.idx.loc(end_keyword_loc.start_offset());
        let indent = " ".repeat(col.saturating_sub(1));
        let break_line = format!("break {break_keyword} {condition_src}\n{indent}");

        // Fix 1: Replace 'begin' with 'loop do'
        self.fixes.push((
            begin_keyword_loc.start_offset(),
            begin_keyword_loc.end_offset(),
            b"loop do".to_vec(),
        ));

        // Fix 2: Insert break statement before 'end'
        self.fixes.push((
            end_keyword_loc.start_offset(),
            end_keyword_loc.start_offset(),
            break_line.into_bytes(),
        ));

        // Fix 3: Remove from after 'end' to the end of the whole statement
        self.fixes.push((
            end_keyword_loc.end_offset(),
            location.end_offset(),
            Vec::new(),
        ));
    }

    pub(crate) fn check_loop_until(&mut self, node: &ruby_prism::UntilNode) {
        const COP: &str = "Lint/Loop";
        if !self.on(COP) || !node.is_begin_modifier() {
            return;
        }

        let statements = match node.statements() {
            Some(s) => s,
            None => return,
        };
        // Find the BeginNode in statements
        let Some(begin_node) = statements.body().iter().find_map(|n| n.as_begin_node()) else {
            return;
        };
        let Some(begin_keyword_loc) = begin_node.begin_keyword_loc() else { return };
        let Some(end_keyword_loc) = begin_node.end_keyword_loc() else { return };

        let keyword_loc = node.keyword_loc();
        let condition = &node.predicate();
        let location = node.location();

        const MSG: &str = "Use `Kernel#loop` with `break` rather than `begin/end/until`(or `while`).";

        // Register the offense at the keyword location
        self.push(keyword_loc.start_offset(), COP, true, MSG);

        // Build the break statement
        let break_keyword = "if";
        let condition_src = String::from_utf8_lossy(self.node_src(condition));

        // Calculate indentation for the break line (same as 'end' keyword)
        let (_, col) = self.idx.loc(end_keyword_loc.start_offset());
        let indent = " ".repeat(col.saturating_sub(1));
        let break_line = format!("break {break_keyword} {condition_src}\n{indent}");

        // Fix 1: Replace 'begin' with 'loop do'
        self.fixes.push((
            begin_keyword_loc.start_offset(),
            begin_keyword_loc.end_offset(),
            b"loop do".to_vec(),
        ));

        // Fix 2: Insert break statement before 'end'
        self.fixes.push((
            end_keyword_loc.start_offset(),
            end_keyword_loc.start_offset(),
            break_line.into_bytes(),
        ));

        // Fix 3: Remove from after 'end' to the end of the whole statement
        self.fixes.push((
            end_keyword_loc.end_offset(),
            location.end_offset(),
            Vec::new(),
        ));
    }
}

impl<'a> super::Cops<'a> {
    /// Security/Open — `Kernel#open` and `URI.open` enable not only file
    /// access but also process invocation by prefixing a pipe symbol.
    /// Flags calls with non-safe first arguments (non-literal strings,
    /// or literals starting with `|`).
    pub(crate) fn check_open(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Security/Open";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"open" {
            return;
        }

        // Check receiver: must be nil (Kernel#open) or URI constant
        let receiver = node.receiver();
        let receiver_name = receiver.as_ref().and_then(const_name_root);
        let is_kernel = receiver.is_none();
        let is_uri = receiver_name.as_deref() == Some("URI");

        if !is_uri && !is_kernel {
            return;
        }

        // Get the first argument
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.is_empty() {
            return;
        }

        let first_arg = &args[0];

        // Check if the argument is safe
        if self.is_safe_open_arg(first_arg) {
            return;
        }

        // Report offense at the method selector
        if let Some(sel) = node.message_loc() {
            let receiver_str = if is_uri {
                let recv_src = String::from_utf8_lossy(self.node_src(receiver.as_ref().unwrap())).into_owned();
                format!("{recv_src}.")
            } else {
                "Kernel#".to_string()
            };
            let msg = format!("The use of `{receiver_str}open` is a serious security risk.");
            self.push(sel.start_offset(), COP, false, msg);
        }
    }

    /// Check if a first argument to `open` is safe:
    /// - Simple string: safe if not empty and doesn't start with `|`
    /// - Interpolated string: safe if the first part is safe
    /// - Concatenated string: safe if the first part (before the +) is safe
    /// - Anything else: unsafe
    fn is_safe_open_arg(&self, node: &ruby_prism::Node) -> bool {
        match node {
            // Simple string literal
            n if n.as_string_node().is_some() => {
                let s = n.as_string_node().unwrap();
                let content = s.content_loc().as_slice();
                !content.is_empty() && !content.starts_with(b"|")
            }
            // Interpolated string: check the first part
            n if n.as_interpolated_string_node().is_some() => {
                let dstr = n.as_interpolated_string_node().unwrap();
                let parts = dstr.parts();
                if parts.is_empty() {
                    return false;
                }
                // Check the first part
                match parts.iter().next().unwrap() {
                    part_n if part_n.as_string_node().is_some() => {
                        let s = part_n.as_string_node().unwrap();
                        let content = s.content_loc().as_slice();
                        !content.starts_with(b"|")
                    }
                    _ => false, // starts with interpolation
                }
            }
            // Concatenated string (string + something)
            n if n.as_call_node().is_some() => {
                let call = n.as_call_node().unwrap();
                if call.name().as_slice() == b"+" {
                    if let Some(receiver) = call.receiver() {
                        return self.is_safe_open_arg(&receiver);
                    }
                }
                false
            }
            _ => false,
        }
    }
}

impl<'a> super::Cops<'a> {
    /// Security/JSONLoad — `JSON.load` and `JSON.restore` allow deserialization
    /// of arbitrary Ruby objects, which is unsafe for untrusted input. Unless
    /// `create_additions` is explicitly passed, we should use `JSON.parse` instead.
    pub(crate) fn check_json_load(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Security/JSONLoad";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"load" | b"restore") {
            return;
        }
        let recv_const = node.receiver().and_then(|r| const_name_root(&r));
        if recv_const.as_deref() != Some("JSON") {
            return;
        }

        // Check if `create_additions` keyword argument is present
        let has_create_additions = node
            .arguments()
            .map(|args| {
                args.arguments()
                    .iter()
                    .any(|arg| has_create_additions_key(&arg))
            })
            .unwrap_or(false);

        if !has_create_additions {
            if let Some(sel) = node.message_loc() {
                let method_name = String::from_utf8_lossy(name);
                self.push(sel.start_offset(), COP, true,
                    format!("Prefer `JSON.parse` over `JSON.{}`.", method_name));
                self.fixes.push((sel.start_offset(), sel.end_offset(), b"parse".to_vec()));
            }
        }
    }
}

/// Check if a node or its nested hash contains the `create_additions` key
fn has_create_additions_key(node: &ruby_prism::Node) -> bool {
    // Hash argument containing create_additions: value
    if let Some(hash) = node.as_hash_node() {
        for el in hash.elements().iter() {
            if let Some(assoc) = el.as_assoc_node() {
                if let Some(key_sym) = assoc.key().as_symbol_node() {
                    if key_sym.unescaped() == b"create_additions" {
                        return true;
                    }
                }
            }
        }
    }

    // Keyword hash (keyword arguments wrapped in KeywordHashNode)
    if let Some(kw_hash) = node.as_keyword_hash_node() {
        for el in kw_hash.elements().iter() {
            if let Some(assoc) = el.as_assoc_node() {
                if let Some(key_sym) = assoc.key().as_symbol_node() {
                    if key_sym.unescaped() == b"create_additions" {
                        return true;
                    }
                }
            }
        }
    }

    false
}

impl<'a> super::Cops<'a> {
    /// Lint/PercentStringArray — detects quotes and commas in %w/%W arrays,
    /// e.g. `%w('foo', "bar")`, which are likely unintended (a mistranslated
    /// array of string literals) rather than meant to be part of the
    /// resulting strings.
    ///
    /// rubocop's detection operates on each element's *unescaped* (cooked)
    /// value — e.g. for `%W("a\255\255")` the escape `\255` is interpreted
    /// to a raw byte before the quote/comma regexes run — while correction
    /// trims the *raw source* of every element (interpolated or not) once
    /// any element triggers an offense. See `psa_contains_quotes_or_commas`
    /// for the quote/comma heuristic (mirrors rubocop's `QUOTES_AND_COMMAS`).
    ///
    /// Elements containing real interpolation (`InterpolatedStringNode`)
    /// never contribute to detection: rubocop's own implementation derives
    /// the "literal" for such nodes from `child.children.first.to_s`, which
    /// for a `dstr` node is a debug s-expression of the first child node
    /// (not its text), so it practically never matches. Live-probed against
    /// rubocop 1.88.0: `%W("#{a}")`, `%W(#{a},)`, `%W("#{a}",)` all yield no
    /// offense in isolation, but such elements still get their surrounding
    /// quotes stripped by the corrector once another element triggers the
    /// offense (e.g. `%W('foo', "#{a}")` corrects to `%W(foo #{a})`).
    pub(crate) fn check_percent_string_array(&mut self, node: &ruby_prism::ArrayNode) {
        const COP: &str = "Lint/PercentStringArray";
        if !self.on(COP) {
            return;
        }

        // Check if this is a %w or %W array.
        let Some(open_loc) = node.opening_loc() else { return };
        let open = open_loc.as_slice();
        if !open.starts_with(b"%w") && !open.starts_with(b"%W") {
            return;
        }

        let elements: Vec<_> = node.elements().iter().collect();

        // Detection: only plain (non-interpolated) string elements
        // contribute, using their unescaped (cooked) value.
        let has_issue = elements.iter().any(|element| {
            element
                .as_string_node()
                .is_some_and(|s| psa_contains_quotes_or_commas(s.unescaped()))
        });

        if !has_issue {
            return;
        }

        let l = node.location();
        self.push(
            l.start_offset(),
            COP,
            true,
            "Within `%w`/`%W`, quotes and ',' are unnecessary and may be \
             unwanted in the resulting strings.",
        );

        // Correction: applies to every element's raw source (quotes/escapes
        // uninterpreted), regardless of whether it triggered detection.
        for element in &elements {
            let el = element.location();
            let raw = self.node_src(element);

            // Trailing: an optional quote followed by an optional comma,
            // matched greedily from the right (mirrors `/['"]?,?$/`).
            let trailing_len = if raw.len() >= 2
                && matches!(raw[raw.len() - 2], b'\'' | b'"')
                && raw[raw.len() - 1] == b','
            {
                2
            } else if matches!(raw.last(), Some(&b',') | Some(&b'\'') | Some(&b'"')) {
                1
            } else {
                0
            };
            if trailing_len > 0 {
                self.fixes.push((el.end_offset() - trailing_len, el.end_offset(), Vec::new()));
            }

            // Leading: a single leading quote char (mirrors `/^['"]/`).
            if matches!(raw.first(), Some(&b'\'') | Some(&b'"')) {
                self.fixes.push((el.start_offset(), el.start_offset() + 1, Vec::new()));
            }
        }
    }
}

/// Mirrors rubocop's `QUOTES_AND_COMMAS` patterns: a value's cooked content
/// is suspicious if it ends with ',', or is entirely wrapped in matching
/// single or double quotes. Values with no alphanumeric content at all
/// (e.g. a lone quote or comma) are treated as likely false positives
/// (`%w(' " ! = # ,)` etc.) and ignored, matching rubocop's alnum guard.
fn psa_contains_quotes_or_commas(literal: &[u8]) -> bool {
    if !literal.iter().any(u8::is_ascii_alphanumeric) {
        return false;
    }
    if literal.last() == Some(&b',') {
        return true;
    }
    if literal.len() >= 2 {
        let first = literal[0];
        let last = literal[literal.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return true;
        }
    }
    false
}

impl<'a> super::Cops<'a> {
    /// Lint/MixedRegexpCaptureTypes — a `Regexp` literal that mixes named
    /// `(?<name>...)` captures with plain numbered `(...)` captures (the
    /// numbered ones are silently ignored by Ruby's `Regexp` engine once a
    /// named one is present, which is almost never what the author wants).
    ///
    /// Upstream (`RuboCop::Ext::RegexpNode#each_capture`) hands the regexp's
    /// *un-interpolated* source off to the `regexp_parser` gem and walks the
    /// resulting expression tree counting named vs. numbered capture groups.
    /// `RegularExpressionNode` (the plain `/.../ ` / `%r{...}` literal, as
    /// opposed to `InterpolatedRegularExpressionNode`) never contains
    /// interpolation, so it always satisfies rubocop's
    /// `return if node.interpolation?` guard — we only need to hook the
    /// non-interpolated node type at all.
    ///
    /// Rather than pull in a full regex-parsing dependency, `scan_regexp_captures`
    /// below is a small purpose-built scanner over the pattern's raw source
    /// bytes that tracks just enough state (character-class depth, escapes,
    /// `(?...)` group-type dispatch, extended-mode `#` comments) to tell
    /// whether the pattern contains a named capture and/or a numbered one —
    /// mirroring `Regexp::Expression`'s capturing-group semantics for that
    /// one purpose, without being a general regex parser.
    pub(crate) fn check_mixed_regexp_capture_types(&mut self, node: &ruby_prism::RegularExpressionNode) {
        const COP: &str = "Lint/MixedRegexpCaptureTypes";
        if !self.on(COP) {
            return;
        }
        let content_loc = node.content_loc();
        let src = &self.src[content_loc.start_offset()..content_loc.end_offset()];
        let (has_named, has_numbered) = scan_regexp_captures(src, node.is_extended());
        if !has_named || !has_numbered {
            return;
        }
        const MSG: &str = "Do not mix named captures and numbered captures in a Regexp literal.";
        self.push(node.location().start_offset(), COP, false, MSG);
    }
}

/// Scans a regexp pattern's raw source bytes (already excluding the
/// delimiters and trailing option letters) and reports whether it contains
/// at least one named capturing group (`(?<name>...)` / `(?'name'...)`,
/// excluding lookbehind `(?<=`/`(?<!`) and/or at least one plain numbered
/// capturing group (a `(` not followed by `?`).
///
/// This purposefully does not build a full parse tree — it only needs to
/// classify each top-level `(` it meets, which can be done by looking at
/// the handful of bytes immediately following it. Contents unrelated to
/// group/class delimiters (backslash escapes, character classes, `(?#...)`
/// comments, `x`-mode `#...` comments, non-capturing/lookaround/atomic
/// groups, inline-option groups, and numbered subexpression calls) are
/// skipped over without recursing, since none of them can themselves
/// introduce a capture.
///
/// Every group *with a body* (plain capture, named capture, non-capturing,
/// lookaround, atomic, absent, and colon-bodied inline-option groups) is
/// tallied in `depth`, decremented by the literal `)` that later closes it;
/// `(?#...)` comments and bodyless directives/subexpression-calls (`(?i)`,
/// `(?1)`) are fully self-contained and never touch `depth`. If `depth` is
/// ever driven negative (a stray close-paren, as literally happens with
/// `(?#comment (with parens))...` — the comment eats only up to the first
/// `)`, leaving the next `)` unmatched) or ends up non-zero, real rubocop's
/// `regexp_parser` backend fails to parse the pattern at all and — since
/// `each_capture` then yields nothing for either type — no offense is ever
/// raised; we mirror that by returning `(false, false)` in that case
/// (mirroring: https://github.com/rubocop/rubocop/issues/8083).
fn scan_regexp_captures(src: &[u8], extended: bool) -> (bool, bool) {
    let mut has_named = false;
    let mut has_numbered = false;
    let n = src.len();
    let mut i = 0usize;
    // Depth of nested `[...]` character classes (Onigmo allows nesting via
    // `&&` set intersection); parens/brackets inside a class are literal.
    let mut class_depth: u32 = 0;
    // Count of currently-open groups-with-a-body, used purely to detect
    // whether the pattern is well-formed (balanced parens); see doc above.
    let mut depth: i64 = 0;

    while i < n {
        let b = src[i];

        // A backslash escapes the next byte everywhere, including inside a
        // character class — it can never itself open/close a group or class.
        if b == b'\\' {
            i += 2;
            continue;
        }

        if class_depth > 0 {
            // POSIX bracket subexpressions (`[:alpha:]`, `[.ch.]`, `[=e=]`)
            // are literal spans inside a class; skip to their own closer so
            // their embedded `]` can't be mistaken for the class's closer.
            if b == b'[' && i + 1 < n && matches!(src[i + 1], b':' | b'.' | b'=') {
                let closer = [src[i + 1], b']'];
                match find_bytes(&src[i + 2..], &closer) {
                    Some(rel) => i += 2 + rel + 2,
                    None => i += 2,
                }
                continue;
            }
            if b == b'[' {
                class_depth += 1;
                i += 1;
                continue;
            }
            if b == b']' {
                class_depth -= 1;
                i += 1;
                continue;
            }
            i += 1;
            continue;
        }

        // Outside any character class.
        if b == b'[' {
            class_depth = 1;
            i += 1;
            // Negation and a then-immediately-following `]` don't close the
            // class: `]` is only a literal-first-character allowance.
            if i < n && src[i] == b'^' {
                i += 1;
            }
            if i < n && src[i] == b']' {
                i += 1;
            }
            continue;
        }

        if extended && b == b'#' {
            // Free-spacing mode: `#` starts a comment that runs to EOL.
            while i < n && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if b == b')' {
            // Closes the innermost open group-with-a-body. A `)` with
            // nothing open is a syntax error real rubocop can't parse past.
            if depth == 0 {
                return (false, false);
            }
            depth -= 1;
            i += 1;
            continue;
        }

        if b != b'(' {
            i += 1;
            continue;
        }

        // `b == b'('`.
        if i + 1 >= n || src[i + 1] != b'?' {
            // A plain, non-`?`-prefixed `(` is always a numbered capture.
            has_numbered = true;
            depth += 1;
            i += 1;
            continue;
        }

        // `(?...` — a special group; classify by what follows `?`.
        let j = i + 2;
        if j >= n {
            i = j;
            continue;
        }
        match src[j] {
            b'#' => {
                // `(?#comment)` — raw text up to the next `)`; no escaping.
                // Self-contained: does not touch `depth`.
                i = match find_bytes(&src[j + 1..], b")") {
                    Some(rel) => j + 1 + rel + 1,
                    None => n,
                };
            }
            b'<' if j + 1 < n && matches!(src[j + 1], b'=' | b'!') => {
                // Lookbehind `(?<=...)` / `(?<!...)` — not a capture, but
                // still has a body that a later `)` must close.
                depth += 1;
                i = j + 2;
            }
            b'<' => {
                // Named capture `(?<name>...)`.
                has_named = true;
                depth += 1;
                i = match find_bytes(&src[j + 1..], b">") {
                    Some(rel) => j + 1 + rel + 1,
                    None => n,
                };
            }
            b'\'' => {
                // Named capture using quote delimiters: `(?'name'...)`.
                has_named = true;
                depth += 1;
                i = match find_bytes(&src[j + 1..], b"'") {
                    Some(rel) => j + 1 + rel + 1,
                    None => n,
                };
            }
            b':' | b'=' | b'!' | b'>' | b'~' => {
                // Non-capturing group / lookahead / negative lookahead /
                // atomic group / absent-expression group — all have bodies.
                depth += 1;
                i = j + 1;
            }
            _ => {
                // An inline-option group (`(?imx-ix:...)`), a bodyless
                // option directive (`(?imx)`), or a numbered/relative
                // subexpression call (`(?1)`, `(?+1)`, `(?R)`) — none of
                // these are captures. None of them contain a nested `(`
                // before their own `:` (body-opener) or `)`
                // (bodyless-closer, already fully self-contained), so a
                // flat scan for whichever comes first is exact.
                let mut k = j;
                while k < n && src[k] != b':' && src[k] != b')' {
                    k += 1;
                }
                if k < n && src[k] == b':' {
                    depth += 1;
                    i = k + 1;
                } else if k < n {
                    i = k + 1;
                } else {
                    i = n;
                }
            }
        }
    }

    if depth != 0 || class_depth != 0 {
        // Unbalanced groups or an unterminated character class: real
        // rubocop's regexp_parser backend fails to parse this pattern, so
        // `each_capture` (of either kind) comes up empty and no offense is
        // ever raised — regardless of what we tallied above.
        return (false, false);
    }

    (has_named, has_numbered)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl<'a> super::Cops<'a> {

    /// Lint/RequireParentheses: checks for method calls without parentheses
    /// where the last argument is a && or || expression (for predicate methods)
    /// or the first argument is a ternary with && or || in its condition.
    pub(crate) fn check_require_parentheses(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RequireParentheses";
        if !self.on(COP) {
            return;
        }

        // Skip if parenthesized or no arguments
        if node.closing_loc().is_some_and(|c| c.as_slice() == b")") {
            return;
        }
        let Some(args) = node.arguments() else {
            return;
        };
        let arguments = args.arguments();
        if arguments.is_empty() {
            return;
        }

        let method_name = node.name().as_slice();

        // Skip if it's a [] or assignment method
        if method_name == b"[]" {
            return;
        }
        if node.equal_loc().is_some() {
            // This is an assignment method like `foo = bar`
            return;
        }

        // Check if first argument is a ternary with && or || in condition
        if let Some(first) = arguments.first() {
            if let Some(if_node) = first.as_if_node() {
                // Check if it's a ternary (no if_keyword_loc means it's a `?:` ternary)
                if if_node.if_keyword_loc().is_none() {
                    // It's a ternary. Check if condition is && or ||
                    let condition = &if_node.predicate();
                    if Self::is_operator_keyword_and_or(&condition) {
                        // Check if method is not [] or assignment
                        if method_name != b"[]" && node.equal_loc().is_none() {
                            // Report: range from call start to condition end
                            self.push(node.location().start_offset(), COP, false,
                                "Use parentheses in the method call to avoid confusion about precedence.");
                            return;
                        }
                    }
                }
            }
        }

        // Check if it's a predicate method with && or || in last argument
        if method_name.ends_with(b"?") {
            if let Some(last) = arguments.last() {
                if Self::is_operator_keyword_and_or(&last) {
                    self.push(node.location().start_offset(), COP, false,
                        "Use parentheses in the method call to avoid confusion about precedence.");
                }
            }
        }
    }

    /// Helper: check if a node is an AndNode or OrNode using && or || (not and/or).
    fn is_operator_keyword_and_or(node: &ruby_prism::Node) -> bool {
        if let Some(and_node) = node.as_and_node() {
            // In Prism, the operator field contains the operator text.
            // We want to flag when it's && (operator keyword), not and
            return and_node.operator_loc().as_slice() == b"&&";
        }
        if let Some(or_node) = node.as_or_node() {
            // Check if it's || (operator keyword), not or
            return or_node.operator_loc().as_slice() == b"||";
        }
        false
    }
}
/// True for both an explicit `{...}` hash literal and a bare/braceless
/// keyword-argument list (`foo(bar: 1)`) — rubocop-ast's prism translation
/// normalizes both to a `:hash`-type node, which is what
/// `argument.hash_type?` tests against in the original cop.
fn erb_new_is_hash_like(node: &ruby_prism::Node) -> bool {
    node.as_hash_node().is_some() || node.as_keyword_hash_node().is_some()
}

/// The (possibly braceless) hash's `key: value` pairs, uniformly across
/// `HashNode` and `KeywordHashNode` — both just wrap `AssocNode` elements
/// (a `**splat` element isn't an `AssocNode` and is silently skipped, same
/// as rubocop's `pairs` helper only iterating true pairs).
fn erb_new_hash_pairs<'a>(node: &ruby_prism::Node<'a>) -> Vec<ruby_prism::AssocNode<'a>> {
    let elements: Vec<ruby_prism::Node<'a>> = if let Some(h) = node.as_hash_node() {
        h.elements().iter().collect()
    } else if let Some(h) = node.as_keyword_hash_node() {
        h.elements().iter().collect()
    } else {
        Vec::new()
    };
    elements.into_iter().filter_map(|e| e.as_assoc_node()).collect()
}

/// `build_kwargs` — `[trim_mode_arg, eoutvar_arg]`, each `Some("trim_mode:
/// <value source>")`/`Some("eoutvar: <value source>")` when the trailing
/// hash-like argument carries that key (bare-label form only: the key node's
/// `unescaped` symbol name, matching rubocop's `pair.key.source == 'trim_mode'`
/// string compare — a `:trim_mode => x` explicit-arrow key has a `source` of
/// `":trim_mode"` in the original and so never matches either; ported
/// faithfully rather than "fixed"). Any OTHER keys in that hash are dropped
/// from the correction, same as upstream.
fn erb_new_build_kwargs(last_argument: &ruby_prism::Node, src: &[u8]) -> [Option<String>; 2] {
    let mut trim_mode = None;
    let mut eoutvar = None;
    if erb_new_is_hash_like(last_argument) {
        for pair in erb_new_hash_pairs(last_argument) {
            let Some(key_sym) = pair.key().as_symbol_node() else { continue };
            let value_src = String::from_utf8_lossy(&src[pair.value().location().start_offset()..pair.value().location().end_offset()]).into_owned();
            match key_sym.unescaped() {
                b"trim_mode" => trim_mode = Some(format!("trim_mode: {value_src}")),
                b"eoutvar" => eoutvar = Some(format!("eoutvar: {value_src}")),
                _ => {}
            }
        }
    }
    [trim_mode, eoutvar]
}

/// `override_by_legacy_args` — the raw positional 3rd/4th arguments
/// (`arguments[2]`/`arguments[3]`), when present and not themselves
/// hash-like, take precedence over anything `build_kwargs` produced.
fn erb_new_override_by_legacy_args(
    mut kwargs: [Option<String>; 2],
    arguments: &[ruby_prism::Node],
    src: &[u8],
) -> [Option<String>; 2] {
    if let Some(a2) = arguments.get(2) {
        if !erb_new_is_hash_like(a2) {
            let s = String::from_utf8_lossy(&src[a2.location().start_offset()..a2.location().end_offset()]).into_owned();
            kwargs[0] = Some(format!("trim_mode: {s}"));
        }
    }
    if let Some(a3) = arguments.get(3) {
        if !erb_new_is_hash_like(a3) {
            let s = String::from_utf8_lossy(&src[a3.location().start_offset()..a3.location().end_offset()]).into_owned();
            kwargs[1] = Some(format!("eoutvar: {s}"));
        }
    }
    kwargs
}

impl<'a> super::Cops<'a> {
    /// Lint/ErbNewArguments — `ERB.new` positional 2nd/3rd/4th arguments
    /// (safe_level/trim_mode/eoutvar) are deprecated since Ruby 2.6;
    /// safe_level has no keyword replacement (just flagged), trim_mode and
    /// eoutvar get rewritten to `trim_mode:`/`eoutvar:` keyword arguments.
    /// `minimum_target_ruby_version 2.6` gates the whole cop.
    ///
    /// Matches `(send (const {nil? cbase} :ERB) :new $...)` — bare `ERB` or
    /// top-level `::ERB`, via the shared `const_name_root` helper (it
    /// already treats a parent-less `ConstantPathNode`, i.e. `::ERB`, the
    /// same as a bare `ConstantReadNode`).
    ///
    /// Offense anchor: the offending positional argument node's own start
    /// offset (rubocop's `add_offense(argument, ...)` default location is
    /// `argument.loc.expression`). Message text is chosen purely by
    /// POSITION within the 2nd..4th argument slice (index 0/1/2), not by
    /// what the argument actually is — mirrors rubocop's
    /// `arguments[1..3].each_with_index`.
    ///
    /// Autocorrect always rewrites the FULL argument list (first argument's
    /// start through the last argument's end) to `str[, trim_mode: ...][,
    /// eoutvar: ...]`, recomputed fresh for every qualifying offense (the
    /// original attaches the identical `corrector.replace` block to each
    /// `add_offense` call); pushing the same byte-identical fix multiple
    /// times is harmless — `apply_fixes` applies the first one it processes
    /// for a given range and then skips the rest as overlapping, and since
    /// every copy has identical bytes the result is the same either way.
    pub(crate) fn check_erb_new_arguments(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/ErbNewArguments";
        if !self.on(COP) || self.cfg.target_ruby() < 2.6 {
            return;
        }
        if node.name().as_slice() != b"new" {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if const_name_root(&recv).as_deref() != Some("ERB") {
            return;
        }
        let Some(args_node) = node.arguments() else { return };
        let arguments: Vec<ruby_prism::Node> = args_node.arguments().iter().collect();
        if arguments.is_empty() {
            return;
        }
        // correct_arguments?: a single argument, or exactly 2 where the
        // 2nd is already hash-like (all keyword args).
        if arguments.len() == 1 || (arguments.len() == 2 && erb_new_is_hash_like(&arguments[1])) {
            return;
        }

        let hi = arguments.len().min(4);
        let offending: Vec<(usize, &ruby_prism::Node)> = arguments[1..hi]
            .iter()
            .enumerate()
            .filter(|(_, a)| !erb_new_is_hash_like(a))
            .collect();
        if offending.is_empty() {
            return;
        }

        // Shared correction: recomputed once, pushed per offending argument.
        let str_src = String::from_utf8_lossy(self.node_src(&arguments[0])).into_owned();
        let last_argument = arguments.last().unwrap();
        let kwargs = erb_new_build_kwargs(last_argument, self.src);
        let overridden = erb_new_override_by_legacy_args(kwargs, &arguments, self.src);
        let mut parts = vec![str_src];
        parts.extend(overridden.into_iter().flatten());
        let good_arguments = parts.join(", ");
        let range_start = arguments[0].location().start_offset();
        let range_end = last_argument.location().end_offset();

        for (i, argument) in offending {
            let arg_value = String::from_utf8_lossy(self.node_src(argument)).into_owned();
            let message = match i {
                0 => "Passing safe_level with the 2nd argument of `ERB.new` is deprecated. \
                      Do not use it, and specify other arguments as keyword arguments."
                    .to_string(),
                1 => format!(
                    "Passing trim_mode with the 3rd argument of `ERB.new` is deprecated. Use \
                     keyword argument like `ERB.new(str, trim_mode: {arg_value})` instead."
                ),
                2 => format!(
                    "Passing eoutvar with the 4th argument of `ERB.new` is deprecated. Use \
                     keyword argument like `ERB.new(str, eoutvar: {arg_value})` instead."
                ),
                _ => unreachable!(),
            };
            self.push(argument.location().start_offset(), COP, true, message);
            self.fixes.push((range_start, range_end, good_arguments.clone().into_bytes()));
        }
    }
}

/// Mirrors `RuboCop::MagicComment#encoding_specified?` and, in the branch
/// where that's false, `#valid?` (i.e. any *other* magic setting specified) —
/// for one physical leading-comment line. Three comment dialects, tried in
/// `MagicComment.parse`'s priority order: emacs (`-*- k: v; ... -*-`), vim
/// (`# vim: k=v, ...` — can only ever specify `encoding`), then the simple
/// `# key: value` form. Returns `(encoding_specified, other_magic_valid)`.
fn ordered_magic_comment_kind(text: &str) -> (bool, bool) {
    static EMACS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let emacs_re = EMACS.get_or_init(|| regex::Regex::new(r"-\*-(.+)-\*-").unwrap());

    if let Some(caps) = emacs_re.captures(text) {
        static EMACS_ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static EMACS_FSL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static EMACS_SCV: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let enc_re = EMACS_ENC
            .get_or_init(|| regex::Regex::new(r"^(?:en)?coding\s*:\s*[A-Za-z0-9_-]+$").unwrap());
        let fsl_re = EMACS_FSL.get_or_init(|| {
            regex::Regex::new(r"^frozen[_-]string[_-]literal\s*:\s*[A-Za-z0-9_-]+$").unwrap()
        });
        let scv_re = EMACS_SCV.get_or_init(|| {
            regex::Regex::new(r"^shareable[_-]constant[_-]value\s*:\s*[A-Za-z0-9_-]+$").unwrap()
        });

        let tokens: Vec<&str> = caps[1].split(';').map(|t| t.trim()).collect();
        let encoding = tokens.iter().any(|t| enc_re.is_match(t));
        // rbs_inline / typed can never be specified via an emacs comment.
        let other = tokens.iter().any(|t| fsl_re.is_match(t) || scv_re.is_match(t));
        return (encoding, !encoding && other);
    }

    static VIM: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let vim_re = VIM.get_or_init(|| regex::Regex::new(r"#\s*vim:\s*(.+)").unwrap());
    if let Some(caps) = vim_re.captures(text) {
        static VIM_ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let enc_re = VIM_ENC
            .get_or_init(|| regex::Regex::new(r"^fileencoding\s*=\s*[A-Za-z0-9_-]+$").unwrap());
        let tokens: Vec<&str> = caps[1].split(", ").map(|t| t.trim()).collect();
        // The `fileencoding` keyword is only honored when >= 2 tokens are
        // present; a vim comment can never specify any other magic setting.
        let encoding = tokens.len() > 1 && tokens.iter().any(|t| enc_re.is_match(t));
        return (encoding, false);
    }

    static SIMPLE_ENC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SIMPLE_FSL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SIMPLE_SCV: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SIMPLE_RBS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static SIMPLE_TYPED: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

    let enc_re = SIMPLE_ENC.get_or_init(|| {
        regex::Regex::new(r"(?i)^\s*#\s*(?:frozen_string_literal:\s*(?:true|false))?\s*(?:en)?coding: [A-Za-z0-9_-]+").unwrap()
    });
    let fsl_re = SIMPLE_FSL.get_or_init(|| {
        regex::Regex::new(r"(?i)^\s*#\s*frozen[_-]string[_-]literal:\s*[A-Za-z0-9_-]+\s*$").unwrap()
    });
    let scv_re = SIMPLE_SCV.get_or_init(|| {
        regex::Regex::new(r"(?i)^\s*#\s*shareable[_-]constant[_-]value:\s*[A-Za-z0-9_-]+\s*$").unwrap()
    });
    let rbs_re = SIMPLE_RBS
        .get_or_init(|| regex::Regex::new(r"(?i)^\s*#\s*rbs_inline:\s*([A-Za-z0-9_-]+)\s*$").unwrap());
    let typed_re = SIMPLE_TYPED
        .get_or_init(|| regex::Regex::new(r"(?i)^\s*#\s*typed:\s*[A-Za-z0-9_-]+\s*$").unwrap());

    let encoding = enc_re.is_match(text);
    // `valid_rbs_inline_value?` requires the (case-sensitive, un-downcased)
    // captured value to literally be "enabled" or "disabled".
    let rbs = rbs_re
        .captures(text)
        .is_some_and(|c| matches!(&c[1], "enabled" | "disabled"));
    let other = fsl_re.is_match(text) || scv_re.is_match(text) || rbs || typed_re.is_match(text);
    (encoding, !encoding && other)
}

impl<'a> super::Cops<'a> {
    /// Lint/OrderedMagicComments — the encoding magic comment (`# encoding:
    /// ...` / `# coding: ...` / emacs / vim forms) must precede every other
    /// leading magic comment (`frozen_string_literal`, `shareable_constant_value`,
    /// `rbs_inline`, `typed`). Comment/text-based, like
    /// `check_duplicate_magic_comment`.
    pub(crate) fn check_ordered_magic_comments(&mut self, first_code_line: Option<usize>) {
        const COP: &str = "Lint/OrderedMagicComments";
        if !self.on(COP) {
            return;
        }
        if self.src.is_empty() {
            return;
        }

        // rubocop's `magic_comment_lines`: scan leading comments in order,
        // remembering the latest encoding-specified line (`lines[0]`) and the
        // latest "other magic" line (`lines[1]`) seen so far, stopping as
        // soon as both are set.
        let mut encoding_line: Option<usize> = None;
        let mut other_line: Option<usize> = None;
        for (line, start, end) in self.comments {
            if let Some(fcl) = first_code_line {
                if *line >= fcl {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&self.src[*start..*end]);
            let (enc, other) = ordered_magic_comment_kind(&text);
            if enc {
                encoding_line = Some(*line);
            } else if other {
                other_line = Some(*line);
            }
            if encoding_line.is_some() && other_line.is_some() {
                break;
            }
        }

        let (Some(enc_line), Some(oth_line)) = (encoding_line, other_line) else {
            return;
        };
        if enc_line < oth_line {
            return;
        }

        let enc_start = self.idx.starts[enc_line - 1];
        let enc_end = self.line_end(enc_line);
        let oth_start = self.idx.starts[oth_line - 1];
        let oth_end = self.line_end(oth_line);

        self.push(
            enc_start,
            COP,
            true,
            "The encoding magic comment should precede all other magic comments.",
        );

        let enc_text = self.src[enc_start..enc_end].to_vec();
        let oth_text = self.src[oth_start..oth_end].to_vec();
        self.fixes.push((enc_start, enc_end, oth_text));
        self.fixes.push((oth_start, oth_end, enc_text));
    }
}

/// `Struct.new` / `Data.define` (incl. `::`-prefixed) — subset of is_class_constructor.
pub(crate) fn is_struct_data_constructor(node: &ruby_prism::CallNode, src: &[u8]) -> bool {
    let Some(r) = node.receiver() else { return false };
    let l = r.location();
    let recv = &src[l.start_offset()..l.end_offset()];
    match node.name().as_slice() {
        b"new" => matches!(recv, b"Struct" | b"::Struct"),
        b"define" => matches!(recv, b"Data" | b"::Data"),
        _ => false,
    }
}

impl<'a> super::Cops<'a> {
    /// Lint/ImplicitStringConcatenation — adjacent string literals on the
    /// same line (`'a' 'b'`), which prism (like whitequark) folds into a
    /// single `InterpolatedStringNode` whose `parts` are the individual
    /// quoted pieces. Ported from `on_dstr`'s `each_bad_cons`: every
    /// consecutive pair of parts that are BOTH themselves string literals
    /// (`StringNode` or a further-nested `InterpolatedStringNode` — i.e. a
    /// part with its OWN quotes, whether plain or containing real `#{}`
    /// interpolation) and sit on the same source line is an offense.
    ///
    /// Unlike whitequark, prism never splits a single multi-line plain
    /// string literal into synthetic `str`/`str` parts — a bare `'abc\ndef'`
    /// stays one `StringNode` and never even reaches this visitor — so
    /// upstream's `ending_delimiter` guard (worked around whitequark's
    /// quirk) has no prism equivalent and is intentionally not ported.
    ///
    /// The message suffix (`FOR_ARRAY`/`FOR_METHOD`) mirrors upstream's
    /// `node.parent&.array_type?` / `node.parent&.send_type?`: computed once
    /// per container node from `isc_array_child`/`isc_send_child` (populated
    /// eagerly by `visit_array_node`/`visit_call_node`), then reused for
    /// every offense the container produces.
    ///
    /// Autocorrect: `corrector.replace(lhs.end.join(rhs.begin), ' + ')`,
    /// except when either side's own string VALUE (recursively, like
    /// upstream's `str_content`) is empty — then that side is deleted
    /// outright (the triple-quote `"""string"""` case).
    pub(crate) fn check_implicit_string_concatenation(&mut self, node: &ruby_prism::InterpolatedStringNode) {
        const COP: &str = "Lint/ImplicitStringConcatenation";
        if !self.on(COP) {
            return;
        }
        let parts: Vec<ruby_prism::Node> = node.parts().iter().collect();
        if parts.len() < 2 {
            return;
        }
        let node_start = node.location().start_offset();
        let suffix: &str = if self.isc_array_child.contains(&node_start) {
            " Or, if they were intended to be separate array elements, separate them with a comma."
        } else if self.isc_send_child.contains(&node_start) {
            " Or, if they were intended to be separate method arguments, separate them with a comma."
        } else {
            ""
        };
        for pair in parts.windows(2) {
            let lhs = &pair[0];
            let rhs = &pair[1];
            if !isc_is_string_part(lhs) || !isc_is_string_part(rhs) {
                continue;
            }
            let ll = lhs.location();
            let rl = rhs.location();
            let lhs_last_line = self.idx.loc(ll.end_offset().saturating_sub(1)).0;
            let rhs_first_line = self.idx.loc(rl.start_offset()).0;
            if lhs_last_line != rhs_first_line {
                continue;
            }
            let lhs_disp = String::from_utf8_lossy(&self.isc_display_str(lhs)).into_owned();
            let rhs_disp = String::from_utf8_lossy(&self.isc_display_str(rhs)).into_owned();
            let message = format!(
                "Combine {lhs_disp} and {rhs_disp} into a single string literal, rather than using implicit string concatenation.{suffix}"
            );
            self.push(ll.start_offset(), COP, true, message);

            if self.isc_value(lhs).is_empty() {
                self.fixes.push((ll.start_offset(), ll.end_offset(), Vec::new()));
            } else if self.isc_value(rhs).is_empty() {
                self.fixes.push((rl.start_offset(), rl.end_offset(), Vec::new()));
            } else {
                self.fixes.push((ll.end_offset(), rl.start_offset(), b" + ".to_vec()));
            }
        }
    }

    /// `Node#value` (`StrNode#value` / rubocop-ast's `DstrNode#value`) — the
    /// string's own semantic VALUE: a plain `StringNode` contributes its
    /// unescaped content; a nested `InterpolatedStringNode` recurses over its
    /// own parts using each part's OWN value when it has one (another
    /// str/dstr-like part), else falls back to that part's raw source
    /// (`DstrNode#value`'s `child.respond_to?(:value) ? child.value :
    /// child.source`) — covers a part that's real `#{}` interpolation. Used
    /// only for the autocorrect empty-value check (`lhs_node.value == ''`).
    fn isc_value(&self, part: &ruby_prism::Node) -> Vec<u8> {
        if let Some(s) = part.as_string_node() {
            s.unescaped().to_vec()
        } else if let Some(d) = part.as_interpolated_string_node() {
            d.parts().iter().flat_map(|p| self.isc_value(&p)).collect()
        } else {
            self.node_src(part).to_vec()
        }
    }

    /// The cop's own private `str_content` helper — DIFFERENT from
    /// `Node#value` above despite the similar recursion shape. A plain
    /// `StringNode` contributes its unescaped content; a nested
    /// `InterpolatedStringNode` recurses over its own parts; any other part
    /// (real `#{}` interpolation) contributes NOTHING, mirroring upstream's
    /// `return unless node.respond_to?(:str_type?)` guard, which — walking a
    /// non-str/dstr node's OWN children generically — bottoms out at bare
    /// `nil`/`Symbol` leaves (a call's receiver-less receiver, its selector)
    /// that don't respond to `str_type?` either, so a `#{...}` part with no
    /// string literal nested inside it collapses to `''` rather than its
    /// source text. Used only by `display_str`'s inspect fallback.
    fn isc_str_content(&self, part: &ruby_prism::Node) -> Vec<u8> {
        if let Some(s) = part.as_string_node() {
            s.unescaped().to_vec()
        } else if let Some(d) = part.as_interpolated_string_node() {
            d.parts().iter().flat_map(|p| self.isc_str_content(&p)).collect()
        } else {
            Vec::new()
        }
    }

    /// `display_str` — the part's raw source UNLESS it spans multiple lines,
    /// in which case upstream substitutes `str_content(node).inspect` (its
    /// semantic value, Ruby-`String#inspect`-quoted) so the message doesn't
    /// spill a literal newline into the offense text.
    fn isc_display_str(&self, part: &ruby_prism::Node) -> Vec<u8> {
        let src = self.node_src(part);
        if src.contains(&b'\n') {
            isc_ruby_inspect(&self.isc_str_content(part))
        } else {
            src.to_vec()
        }
    }
}

/// `string_literal?` — a part counts as a string literal (safe to pair up
/// for implicit-concatenation detection) whether it's a plain quoted piece
/// or itself a quoted piece with real `#{}` interpolation inside; only a
/// bare embedded-expression part (no quotes of its own) fails this.
fn isc_is_string_part(part: &ruby_prism::Node) -> bool {
    part.as_string_node().is_some() || part.as_interpolated_string_node().is_some()
}

/// A close approximation of Ruby's `String#inspect` for the common escapes
/// (backslash/quote/whitespace control chars, `#{`/`#@`/`#$` sigils, other
/// control bytes as `\xHH`); valid UTF-8 multibyte text passes through
/// unescaped, matching MRI's behavior for printable characters.
fn isc_ruby_inspect(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(b'"');
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\r' => out.extend_from_slice(b"\\r"),
            0x1b => out.extend_from_slice(b"\\e"),
            0x07 => out.extend_from_slice(b"\\a"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0b => out.extend_from_slice(b"\\v"),
            b'#' if matches!(bytes.get(i + 1), Some(b'{') | Some(b'@') | Some(b'$')) => {
                out.push(b'\\');
                out.push(b'#');
            }
            0x00..=0x1f | 0x7f => out.extend_from_slice(format!("\\x{b:02X}").as_bytes()),
            _ => out.push(b),
        }
        i += 1;
    }
    out.push(b'"');
    out
}

impl<'a> Cops<'a> {
    /// Lint/RaiseException — `raise` or `fail` statements that raise `Exception`
    /// or `Exception.new`. Should use `StandardError` or a specific exception class instead.
    /// Allows configurable implicit namespaces (default: ['Gem']).
    pub(crate) fn check_raise_exception(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RaiseException";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"raise" | b"fail") {
            return;
        }

        // Pattern 1: raise Exception / raise ::Exception
        if let Some((offset, end_offset, has_cbase)) = self.check_raise_exception_direct(node) {
            if self.should_report_raise_exception(has_cbase) {
                self.register_raise_exception_offense_direct(offset, end_offset, has_cbase);
            }
            return;
        }

        // Pattern 2: raise Exception.new(...) / raise ::Exception.new(...)
        if let Some((offset, end_offset, has_cbase)) = self.check_raise_exception_new(node) {
            if self.should_report_raise_exception(has_cbase) {
                self.register_raise_exception_offense_direct(offset, end_offset, has_cbase);
            }
        }
    }

    /// Check for the pattern: raise Exception or raise ::Exception
    /// Returns (start_offset, end_offset, has_explicit_namespace) if matches
    fn check_raise_exception_direct(&self, node: &ruby_prism::CallNode) -> Option<(usize, usize, bool)> {
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.is_empty() {
            return None;
        }
        let first_arg = &args[0];
        // Check if it's a constant (Exception or ::Exception)
        if let Some(c) = first_arg.as_constant_read_node() {
            if c.name().as_slice() == b"Exception" {
                let loc = first_arg.location();
                return Some((loc.start_offset(), loc.end_offset(), false));
            }
        } else if let Some(p) = first_arg.as_constant_path_node() {
            // Check for ::Exception pattern (explicit namespace)
            if p.parent().is_none() && p.name().as_ref().is_some_and(|n| n.as_slice() == b"Exception") {
                let loc = first_arg.location();
                return Some((loc.start_offset(), loc.end_offset(), true));
            }
        }
        None
    }

    /// Check for the pattern: raise Exception.new(...) or raise ::Exception.new(...)
    /// Returns (start_offset, end_offset, has_explicit_namespace) if matches
    fn check_raise_exception_new(&self, node: &ruby_prism::CallNode) -> Option<(usize, usize, bool)> {
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        if args.is_empty() {
            return None;
        }
        let first_arg = &args[0];
        // Check if it's a call to .new
        if let Some(call) = first_arg.as_call_node() {
            if call.name().as_slice() != b"new" {
                return None;
            }
            let receiver = call.receiver()?;
            // Check if the receiver is Exception or ::Exception
            if let Some(c) = receiver.as_constant_read_node() {
                if c.name().as_slice() == b"Exception" {
                    let loc = receiver.location();
                    return Some((loc.start_offset(), loc.end_offset(), false));
                }
            } else if let Some(p) = receiver.as_constant_path_node() {
                // Check for ::Exception pattern (explicit namespace)
                if p.parent().is_none() && p.name().as_ref().is_some_and(|n| n.as_slice() == b"Exception") {
                    let loc = receiver.location();
                    return Some((loc.start_offset(), loc.end_offset(), true));
                }
            }
        }
        None
    }

    /// Check if we should report an offense for this raise/fail Exception
    fn should_report_raise_exception(&self, has_cbase: bool) -> bool {
        // If it has an explicit namespace (::Exception), always report
        if has_cbase {
            return true;
        }
        // Otherwise, check if we're in an allowed implicit namespace
        !self.is_in_allowed_namespace()
    }

    /// Check if we're currently inside an allowed namespace
    fn is_in_allowed_namespace(&self) -> bool {
        let allowed = self.allowed_implicit_namespaces();
        // Check the top-level module in the stack against allowed list
        for module_path in self.mod_stack.iter().rev() {
            // Get the first component of the module name (e.g., "Gem" from "Gem::Inner")
            let first_component = module_path.split("::").next().unwrap_or("");
            if allowed.iter().any(|a| a == first_component) {
                return true;
            }
        }
        false
    }

    /// Get the list of allowed implicit namespaces from config, default to ['Gem']
    fn allowed_implicit_namespaces(&self) -> Vec<String> {
        const COP: &str = "Lint/RaiseException";
        match self.cfg.get(COP, "AllowedImplicitNamespaces") {
            Some(val) => {
                // Parse the config value as a list
                crate::config::parse_allowed_list(val)
            }
            None => {
                // Default to ['Gem']
                vec!["Gem".to_string()]
            }
        }
    }

    /// Register the offense and add autocorrect
    fn register_raise_exception_offense_direct(&mut self, start_offset: usize, end_offset: usize, _has_cbase: bool) {
        const COP: &str = "Lint/RaiseException";
        let exception_src = &self.src[start_offset..end_offset];

        // Determine the replacement
        let replacement = if exception_src.starts_with(b"::") {
            b"::StandardError".to_vec()
        } else {
            b"StandardError".to_vec()
        };

        self.push(start_offset, COP, true, "Use `StandardError` over `Exception`.");
        self.fixes.push((start_offset, end_offset, replacement));
    }
}

impl<'a> Cops<'a> {
    /// Lint/RedundantWithObject — checks for redundant `with_object` in blocks
    /// where the accumulator parameter is not used. Handles three block types:
    /// - Regular blocks with only 1 parameter
    /// - Numblocks with only 1 parameter (_1, no _2)
    /// - Itblocks (implicit `it` - always 1 parameter)
    pub(crate) fn check_redundant_with_object(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantWithObject";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !matches!(name, b"each_with_object" | b"with_object") {
            return;
        }

        // Mirrors ruby's check:
        // return unless node.receiver  (must have receiver)
        // return if node.method?(:with_object) && !node.receiver.receiver  (if with_object, receiver must have a receiver)
        let Some(recv) = node.receiver() else { return };
        if name == b"with_object" {
            // `node.receiver.receiver`: with_object's own receiver must itself
            // have a receiver (a genuine chain like ary.each.with_object) —
            // `ary.with_object` parses as a receiver-less call and is skipped.
            let has_inner_receiver = recv.as_call_node().and_then(|c| c.receiver()).is_some();
            if !has_inner_receiver {
                return;
            }
        }
        // For each_with_object, must have an explicit argument to the method
        if name == b"each_with_object" && node.arguments().is_none() {
            return;
        }
        // Must have a block
        let Some(block_node) = node.block().and_then(|b| b.as_block_node()) else { return };

        // Determine the block type and check parameter count
        // For each_with_object/with_object, we flag if there's only 1 block parameter
        // (meaning the accumulator parameter is not used)
        let should_flag = match block_node.parameters() {
            None => {
                // Block with no parameters: `{ }` — always flag
                true
            }
            Some(params_node) => {
                if let Some(np) = params_node.as_numbered_parameters_node() {
                    // Numblock with numbered parameters (_1, _2, ...)
                    // Only flag if it has exactly 1 parameter
                    np.maximum() == 1
                } else if params_node.as_it_parameters_node().is_some() {
                    // Itblock with implicit `it` parameter: always flag (1 parameter)
                    true
                } else if let Some(block_params) = params_node.as_block_parameters_node() {
                    // Regular block: check parameter count (req + opt + rest)
                    // BlockParametersNode wraps a ParametersNode
                    if let Some(params) = block_params.parameters() {
                        let req = params.requireds().iter().count();
                        let opt = params.optionals().iter().count();
                        let rest = if params.rest().is_some() { 1 } else { 0 };
                        (req + opt + rest) <= 1
                    } else {
                        // No parameters in the ParametersNode (shouldn't happen for BlockParametersNode)
                        true
                    }
                } else {
                    // Unknown parameter type, skip
                    false
                }
            }
        };
        if should_flag {
            self.push_redundant_with_object_offense(node);
        }
    }

    fn push_redundant_with_object_offense(&mut self, call: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantWithObject";
        let name = call.name().as_slice();
        let (message, start) = if name == b"each_with_object" {
            // For each_with_object, the offense is at the selector and we replace it with "each"
            let sel = match call.message_loc() {
                Some(loc) => (loc.start_offset(), loc.end_offset()),
                None => return,
            };
            ("Use `each` instead of `each_with_object`.", sel.0)
        } else {
            // For with_object, the offense is at the method name
            let sel = match call.message_loc() {
                Some(loc) => loc.start_offset(),
                None => return,
            };
            ("Remove redundant `with_object`.", sel)
        };
        self.push(start, COP, true, message);

        // Build the fix
        if name == b"each_with_object" {
            // Replace from selector start to end of arguments (before block)
            // For `ary.each_with_object([]) { |v| v }`, we replace `each_with_object([])` with `each`
            let sel_start = match call.message_loc() {
                Some(loc) => loc.start_offset(),
                None => return,
            };
            // Find where to stop: either at the start of the block (if present) or at call end
            let replacement_end = call.block()
                .and_then(|b| b.as_block_node())
                .map(|b| {
                    let block_start = b.location().start_offset();
                    // Walk backwards to skip whitespace before the block
                    let mut i = block_start;
                    while i > sel_start && (self.src[i - 1] == b' ' || self.src[i - 1] == b'\t' || self.src[i - 1] == b'\n' || self.src[i - 1] == b'\r') {
                        i -= 1;
                    }
                    i
                })
                .unwrap_or_else(|| call.location().end_offset());
            self.fixes.push((sel_start, replacement_end, b"each".to_vec()));
        } else {
            // For .with_object, we need to remove the entire method call including arguments
            // but NOT the block
            let sel_start = match call.message_loc() {
                Some(loc) => loc.start_offset(),
                None => return,
            };

            // Find the dot before the selector
            if sel_start == 0 {
                return;
            }
            let dot_start = sel_start - 1;
            if self.src[dot_start] != b'.' {
                return;
            }

            // Determine the end: the end of the method call (including arguments, excluding block)
            // If there's a block node, we need to find where the call really ends (before the block)
            let call_end = if let Some(block_node) = call.block().and_then(|b| b.as_block_node()) {
                // Block exists, so find the end of the call (before the block and its space)
                let block_start = block_node.location().start_offset();
                // Walk backwards to find the end of the call, skipping whitespace
                let mut i = block_start;
                while i > dot_start && (self.src[i - 1] == b' ' || self.src[i - 1] == b'\t') {
                    i -= 1;
                }
                i
            } else {
                // No block, so use the call's full location
                call.location().end_offset()
            };

            self.fixes.push((dot_start, call_end, Vec::new()));
        }
    }
}


// Lint/UnderscorePrefixedVariableName ---------------------------------------
//
// Upstream rides `VariableForce` (`after_leaving_scope`): for every local
// variable whose name starts with `_`, if it has at least one EXPLICIT
// reference (a real `lvar` read — NOT the implicit "everything's in scope"
// reference a zero-arity `super` or bare `binding` call produces) and isn't
// an allowed block keyword argument, offend at the variable's declaration.
//
// This repo has no shared variable-tracking force, so this ports a
// standalone, scoped local-variable walk (precedent: Style/RedundantSelf's
// `rs_scope` machinery in style.rs, though that only tracks NAMES, not
// per-variable usage). One frame per active def/class/module/sclass/
// block/lambda/top-level scope — exactly the node kinds Ruby itself treats
// as a fresh local-variable namespace. `LocalVariableReadNode`,
// `LocalVariableWriteNode`, and `LocalVariableTargetNode` all carry a
// `depth` field that prism resolves at PARSE time using Ruby's own scoping
// rules, so looking up which frame a name belongs to is just
// `frames[frames.len() - 1 - depth]` — prism can never emit a depth that
// would need to cross a hard (def/class/module/sclass) scope boundary,
// since that isn't legal Ruby (confirmed by probing `Prism.parse` directly:
// a `def` nested inside another method always resets `depth` to 0 for its
// own locals), so one flat stack is sufficient; no separate bookkeeping is
// needed to keep block-chains from leaking across a `def`.
//
// `super`/`binding` implicit references (upstream's `process_zero_arity_
// super`/`process_send`) need no special-casing at all: neither ever
// produces a `LocalVariableReadNode`, and only explicit reads count toward
// `references.none?(&:explicit?)` — so simply never creating a reference
// for them already matches upstream's semantics for free. A `super(*_)` or
// `binding(*_)` DOES pick up `_` as an ordinary argument, which prism gives
// us as a ordinary `LocalVariableReadNode` inside the call's `ArgumentsNode`
// — caught by the plain read-node handling with no extra plumbing.
impl<'a> super::Cops<'a> {
    /// `after_leaving_scope`: runs the whole-file scope walk once (from
    /// `visit_program_node` in mod.rs) and reports every `_`-prefixed local
    /// that has an explicit reference, skipping ones exempted by
    /// `AllowKeywordBlockArguments`. Not `extend AutoCorrector` upstream —
    /// detection only, no autocorrect.
    pub(crate) fn check_underscore_prefixed_variable_name(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Lint/UnderscorePrefixedVariableName";
        if !self.on(COP) {
            return;
        }
        let allow_kw_block = self.cfg.get(COP, "AllowKeywordBlockArguments") == Some("true");
        let mut c = UpvCollector { frames: vec![HashMap::new()], is_block: vec![false], vars: Vec::new() };
        use ruby_prism::Visit;
        c.visit(&node.as_node());
        for v in &c.vars {
            if !v.used || !v.name.starts_with(b"_") {
                continue;
            }
            if v.allow_kw_block && allow_kw_block {
                continue;
            }
            self.push(v.decl_offset, COP, false, "Do not use prefix `_` for a variable that is used.");
        }
    }
}

/// One declared local: its name, the offset of its FIRST declaration in its
/// scope (upstream anchors the offense there even after reassignment), and
/// whether it was ever read explicitly.
struct UpvVar {
    name: Vec<u8>,
    decl_offset: usize,
    used: bool,
    /// `variable.block_argument? && variable.keyword_argument?` — a keyword
    /// parameter (required or optional) declared directly in a block's OR
    /// lambda's own parameter list (never a `def`'s).
    allow_kw_block: bool,
}

/// Lint/UnderscorePrefixedVariableName: the scope walk. `frames`/`is_block`
/// are parallel stacks (one entry per currently-open def/class/module/
/// sclass/block/lambda/top-level scope); `vars` is the flat storage all
/// frames index into by name.
struct UpvCollector {
    frames: Vec<HashMap<Vec<u8>, usize>>,
    is_block: Vec<bool>,
    vars: Vec<UpvVar>,
}

impl UpvCollector {
    fn frame_for_depth(&self, depth: u32) -> usize {
        self.frames.len().saturating_sub(1).saturating_sub(depth as usize)
    }
    /// `variable_table.declare_variable(name, node) unless variable_exist?
    /// (name)` — a subsequent write/param with the same name in the SAME
    /// target frame is a no-op (the offense always anchors on the original
    /// declaration, not a reassignment).
    fn declare(&mut self, name: &[u8], depth: u32, anchor: usize, allow_kw_block: bool) {
        let idx = self.frame_for_depth(depth);
        self.declare_in(idx, name, anchor, allow_kw_block);
    }
    /// Parameters/shadow-locals always declare into the CURRENT (innermost)
    /// frame — there's no `depth` field for them, they can only ever
    /// introduce a name in their own parameter list's scope.
    fn declare_here(&mut self, name: &[u8], anchor: usize, allow_kw_block: bool) {
        let here = self.frames.len() - 1;
        self.declare_in(here, name, anchor, allow_kw_block);
    }
    fn declare_in(&mut self, idx: usize, name: &[u8], anchor: usize, allow_kw_block: bool) {
        if self.frames[idx].contains_key(name) {
            return;
        }
        let var_idx = self.vars.len();
        self.vars.push(UpvVar { name: name.to_vec(), decl_offset: anchor, used: false, allow_kw_block });
        self.frames[idx].insert(name.to_vec(), var_idx);
    }
    /// `variable.reference!(node)` for a plain `lvar` read — the only kind
    /// of reference this cop ever sees, since `super`/`binding`'s implicit
    /// references are never materialized here (see the module comment).
    fn reference(&mut self, name: &[u8], depth: u32) {
        let idx = self.frame_for_depth(depth);
        if let Some(&var_idx) = self.frames[idx].get(name) {
            self.vars[var_idx].used = true;
        }
    }
}

impl<'pr> ruby_prism::Visit<'pr> for UpvCollector {
    // `def`/`class`/`module`/`sclass` are hard scope boundaries: the parts
    // evaluated in the ENCLOSING scope (a `defs` receiver, a class's
    // superclass/constant path, `class << expr`'s `expr`) are visited
    // BEFORE the new frame is pushed; only the params/body run inside it.
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let Some(recv) = node.receiver() {
            self.visit(&recv);
        }
        self.frames.push(HashMap::new());
        self.is_block.push(false);
        if let Some(params) = node.parameters() {
            self.visit_parameters_node(&params);
        }
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
        self.is_block.pop();
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.visit(&node.constant_path());
        if let Some(sup) = node.superclass() {
            self.visit(&sup);
        }
        self.frames.push(HashMap::new());
        self.is_block.push(false);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
        self.is_block.pop();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.visit(&node.constant_path());
        self.frames.push(HashMap::new());
        self.is_block.push(false);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
        self.is_block.pop();
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        self.visit(&node.expression());
        self.frames.push(HashMap::new());
        self.is_block.push(false);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
        self.is_block.pop();
    }
    // Blocks and lambdas are SOFT scopes: they may close over an enclosing
    // frame (via `depth`), so they get their own frame but are marked
    // `is_block` for the `AllowKeywordBlockArguments` gate. Default
    // traversal (params, then body) is otherwise exactly what we want.
    fn visit_block_node(&mut self, node: &ruby_prism::BlockNode<'pr>) {
        self.frames.push(HashMap::new());
        self.is_block.push(true);
        ruby_prism::visit_block_node(self, node);
        self.frames.pop();
        self.is_block.pop();
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        self.frames.push(HashMap::new());
        self.is_block.push(true);
        ruby_prism::visit_lambda_node(self, node);
        self.frames.pop();
        self.is_block.pop();
    }
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        self.declare(node.name().as_slice(), node.depth(), node.name_loc().start_offset(), false);
        self.visit(&node.value());
    }
    // `masgn` targets (`foo, bar = baz`), `case/in` pattern bindings, and
    // `foo => bar` rightward assignment all reuse this one node type —
    // upstream's PATTERN_MATCH_VARIABLE_TYPE (`:match_var`) and masgn's
    // plain `lvasgn` targets are BOTH just declarations here; either way the
    // anchor is `node.loc.name` (this node's own span, no separate name_loc).
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        self.declare(node.name().as_slice(), node.depth(), node.location().start_offset(), false);
    }
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
    }
    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        self.declare_here(node.name().as_slice(), node.location().start_offset(), false);
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        self.declare_here(node.name().as_slice(), node.name_loc().start_offset(), false);
        self.visit(&node.value());
    }
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        // anonymous `*` (no name) declares nothing — `process_variable_
        // declaration`'s `return unless variable_name` upstream.
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.declare_here(name.as_slice(), loc.start_offset(), false);
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        let is_block = *self.is_block.last().unwrap_or(&false);
        self.declare_here(node.name().as_slice(), node.name_loc().start_offset(), is_block);
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        let is_block = *self.is_block.last().unwrap_or(&false);
        self.declare_here(node.name().as_slice(), node.name_loc().start_offset(), is_block);
        self.visit(&node.value());
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.declare_here(name.as_slice(), loc.start_offset(), false);
        }
    }
    // `&block` — a method/block's block-PASS parameter, not a block node.
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.declare_here(name.as_slice(), loc.start_offset(), false);
        }
    }
    // `shadowarg` — a block-local variable (`obj.each { |arg; this| }`).
    fn visit_block_local_variable_node(&mut self, node: &ruby_prism::BlockLocalVariableNode<'pr>) {
        self.declare_here(node.name().as_slice(), node.location().start_offset(), false);
    }
    // Regexp named captures (`/(?<_foo>\w+)/ =~ str`) — upstream's
    // `match_with_lvasgn`. Location = the REGEXP node's own range (`node.
    // children.first.source_range`), shared by every name this match
    // declares — NOT each target's own span. Handled directly (not via the
    // generic `visit_local_variable_target_node` dispatch) so an ordinary
    // masgn/pattern target's anchor logic doesn't get reused here.
    fn visit_match_write_node(&mut self, node: &ruby_prism::MatchWriteNode<'pr>) {
        let call = node.call();
        let anchor = call.receiver().map(|r| r.location().start_offset());
        ruby_prism::visit_call_node(self, &call);
        if let Some(anchor) = anchor {
            for t in node.targets().iter() {
                if let Some(tgt) = t.as_local_variable_target_node() {
                    self.declare(tgt.name().as_slice(), tgt.depth(), anchor, false);
                }
            }
        }
    }
}




/// Upstream DirectiveComment#initialize rejects a directive whose pre-match
/// is exactly `#` + whitespace — a commented-OUT directive
/// (`#   # rubocop:disable X` in doc examples) is no directive at all.
fn directive_commented_out(pre: &str) -> bool {
    let mut chars = pre.chars();
    chars.next() == Some('#') && chars.all(|c| c.is_whitespace())
}

/// Upstream COPS_PATTERN prefix parse over a directive tail: the literal
/// `all`, or comma-separated cop names (`(?:[A-Za-z]\w*/)*[A-Za-z]\w*`),
/// matched from the START of the tail. Space-separated junk after the valid
/// prefix (malformed directives, embedded second directives, prose) is NOT
/// part of the list; a tail with no leading valid name yields None and the
/// whole directive is ignored (upstream's nil `cop_names`).
fn directive_cops_prefix(s: &str) -> Option<&str> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"^(?:all\b|(?:[A-Za-z]\w*/)*[A-Za-z]\w*(?:\s*,\s*(?:[A-Za-z]\w*/)*[A-Za-z]\w*)*)",
        )
        .unwrap()
    });
    re.find(s).map(|m| m.as_str())
}

/// Per-cop tracking state for `Lint/MissingCopEnableDirective`, mirroring
/// rubocop's `CommentConfig::CopAnalysis` (`line_ranges`, `start_line_number`).
/// Line numbers are `f64` so `-Infinity`/`Infinity` (config-disabled cops /
/// still-open-at-EOF ranges) fold into the same arithmetic as real line
/// numbers, exactly like Ruby's `Range` over `Float::INFINITY` endpoints.
#[derive(Clone, Default)]
struct MissingEnableAnalysis {
    ranges: Vec<(f64, f64)>,
    start: Option<f64>,
}

/// `RuboCop::Config#enable_cop?` for an arbitrary (possibly-not-this-run's)
/// cop name, DELIBERATELY ignoring `AllCops: DisabledByDefault`.
///
/// The oracle harness always injects `AllCops: DisabledByDefault: true` into
/// the generated `.rubocop.yml` (to keep this multi-cop engine's other
/// native cop implementations from also firing during a single-cop oracle
/// run) — but rubocop's own RSpec `:config` shared context builds its
/// `Config` WITHOUT that flag, so a cop named only inside a `# rubocop:...`
/// comment (never the cop under test) is enabled-by-default there. Reading
/// `Config::cop_config_enabled`/`Config::enabled` here would fold in the
/// harness's isolation flag as if it were real project config and wrongly
/// treat every unlisted cop as "already disabled, no need to ever
/// re-enable". This helper reads only the cop's own explicit `Enabled: false`
/// (matching a real `other_cops` override in the spec), defaulting to
/// enabled otherwise — i.e. what the actual rubocop test config would see.
fn mced_cop_enabled(cfg: &crate::config::Config, key: &str) -> bool {
    cfg.sections.get(key).and_then(|s| s.get("Enabled")).map(|v| v != "false").unwrap_or(true)
}

/// `cop_config['MaxRangeSize']` as a number: rubocop's default.yml ships
/// `.inf`, our SCHEMA renders that as the string `"Infinity"`, and the
/// oracle's static spec-config extractor (which can't evaluate Ruby) emits
/// the literal, non-numeric text `Float::INFINITY` for `let(:cop_config) {
/// { 'MaxRangeSize' => Float::INFINITY } }`. None of those parse as an f64,
/// so — like a real infinite `MaxRangeSize` — they all fall back to
/// `f64::INFINITY`, which is the only sensible default for unparseable text.
fn mced_max_range(v: &str) -> f64 {
    v.trim().parse::<f64>().unwrap_or(f64::INFINITY)
}

/// Finds (or lazily creates) `key`'s slot in the ordered analysis list. A new
/// slot seeds `start = -Infinity` when the cop is disabled in the effective
/// config — `CommentConfig#inject_disabled_cops_directives` primes every
/// config-disabled cop with a synthetic `disable` directive at
/// `CONFIG_DISABLED_LINE_RANGE_MIN` (`-Infinity`) before any real comment is
/// read, so that its true first `disable`/`enable` directive in the source
/// extends (rather than starts) that already-open range.
fn mced_slot(analyses: &mut Vec<(String, MissingEnableAnalysis)>, cfg: &crate::config::Config, key: &str) -> usize {
    if let Some(i) = analyses.iter().position(|(k, _)| k == key) {
        return i;
    }
    let seeded = if mced_cop_enabled(cfg, key) {
        MissingEnableAnalysis::default()
    } else {
        MissingEnableAnalysis { ranges: Vec::new(), start: Some(f64::NEG_INFINITY) }
    };
    analyses.push((key.to_string(), seeded));
    analyses.len() - 1
}

/// `CommentConfig#analyze_disabled`/`#analyze_rest`: a STANDALONE (comment-
/// only-line) directive. Both branches extend any already-open range to this
/// line; they differ only in what the range's next start becomes — a
/// `disable`/`todo` opens (or re-opens) it, an `enable` closes it for good.
fn mced_analyze_standalone(a: &mut MissingEnableAnalysis, line: f64, disabling: bool) {
    if let Some(start) = a.start {
        a.ranges.push((start, line));
    }
    a.start = if disabling { Some(line) } else { None };
}

/// `CommentConfig#apply_cop_op` — a `# rubocop:push +Cop`/`-Cop` argument
/// applied immediately (push/pop bypass the standalone/single-line dispatch
/// entirely). `-` opens (only if not already open); `+` closes (only if
/// open).
fn mced_apply_op(analyses: &mut Vec<(String, MissingEnableAnalysis)>, cfg: &crate::config::Config, op: char, cop: &str, line: f64) {
    let i = mced_slot(analyses, cfg, cop);
    let a = &analyses[i].1;
    if op == '-' && a.start.is_none() {
        analyses[i].1.start = Some(line);
    } else if op == '+' {
        if let Some(start) = a.start {
            analyses[i].1.ranges.push((start, line));
            analyses[i].1.start = None;
        }
    }
}

/// `CommentConfig#pop_state`: restores the stack frame saved at the matching
/// `push`, closing (as of `line - 1`) whatever got opened since, and
/// reopening (as of `line`) whatever was open when the `push` ran but got
/// closed inside the pushed scope.
fn mced_pop(
    analyses: &mut Vec<(String, MissingEnableAnalysis)>,
    cfg: &crate::config::Config,
    restore: &[(String, MissingEnableAnalysis)],
    line: f64,
) {
    let mut keys: Vec<String> = analyses.iter().map(|(k, _)| k.clone()).collect();
    for (k, _) in restore {
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }
    for key in keys {
        let i = mced_slot(analyses, cfg, &key);
        let current = analyses[i].1.clone();
        let mut ranges = current.ranges;
        if let Some(start) = current.start {
            ranges.push((start, line - 1.0));
        }
        let restore_open = restore.iter().find(|(k, _)| *k == key).is_some_and(|(_, a)| a.start.is_some());
        analyses[i].1 = MissingEnableAnalysis { ranges, start: restore_open.then_some(line) };
    }
}

impl<'a> Cops<'a> {
    /// Lint/MissingCopEnableDirective — a `# rubocop:disable`/`# rubocop:todo`
    /// that never gets a matching `# rubocop:enable` (within `MaxRangeSize`
    /// lines, `.inf` by default) leaves cops silently off for the rest of the
    /// file, unnoticed by later contributors. Ported from rubocop's
    /// `CommentConfig#analyze` (the very machinery `processed_source
    /// .disabled_line_ranges` runs on) plus `MissingCopEnableDirective
    /// #each_missing_enable`/`#acceptable_range?`/`#message`.
    ///
    /// This is a whole-file, comment-driven check — not tied to any AST node
    /// — so like `check_double_cop_disable_directive` it's called once
    /// directly, walking `self.comments`.
    ///
    /// Two deliberate simplifications versus the real cop, neither exercised
    /// by the spec fixture and both needing rubocop's full ~600-cop registry
    /// (which this engine doesn't carry):
    ///  - A bare department name (`# rubocop:disable Layout`) is tracked as
    ///    ONE pseudo-entry keyed by the department name itself, instead of
    ///    being expanded into every individual cop in that department. This
    ///    is observably IDENTICAL: real rubocop's `message` collapses every
    ///    expanded cop's rendering to the same "department" text
    ///    (`department_enabled?` fires for all of them alike), and
    ///    `Cop::Base#add_offense`'s per-location dedup
    ///    (`current_offense_locations.add?`) means only the FIRST of those
    ///    identical offenses at that comment is ever actually reported.
    ///  - `# rubocop:disable all`/`# rubocop:todo all` is not tracked at all
    ///    (never offends). Real rubocop would name ONE specific
    ///    un-reenabled cop chosen by registry hash-iteration order — not
    ///    reproducible without the real registry, and reproducing it wrong
    ///    would be worse than not reporting. `# rubocop:enable all` still
    ///    closes every currently-open entry (its real effect on everything
    ///    else this cop tracks).
    pub(crate) fn check_missing_cop_enable_directive(&mut self) {
        const COP: &str = "Lint/MissingCopEnableDirective";
        if !self.on(COP) {
            return;
        }
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            // UNANCHORED like upstream's DIRECTIVE_COMMENT_REGEXP: the marker may
            // sit mid-comment (even inside doc-example text), and such a match
            // REALLY toggles the cop — rubocop-src's own files rely on it.
            regex::Regex::new(r"#\s*rubocop\s*:\s*(disable|todo|enable|push|pop)\b\s*(.*)$").unwrap()
        });

        // Ruby Hashes preserve insertion order; a handful of entries at most
        // ever exist, so a linear-scan-backed ordered map is plenty.
        let mut analyses: Vec<(String, MissingEnableAnalysis)> = Vec::new();
        let mut stack: Vec<Vec<(String, MissingEnableAnalysis)>> = Vec::new();

        for &(line, start, end) in self.comments {
            let text = String::from_utf8_lossy(&self.src[start..end]);
            let Some(caps) = re.captures(&text) else { continue };
            if directive_commented_out(&text[..caps.get(0).unwrap().start()]) {
                continue;
            }
            let mode = caps.get(1).unwrap().as_str();
            let rest = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            let line_f = line as f64;
            // `comment_only_line?`: nothing but whitespace precedes the `#`
            // on this physical line, AND the directive marker sits at the
            // very start of the comment (upstream's `single_line?` treats a
            // mid-comment marker — doc-example text, `#   # rubocop:...` —
            // as a trailing single-line directive that never opens a range).
            let standalone = caps.get(0).unwrap().start() == 0
                && self.src[self.idx.starts[line - 1]..start].iter().all(u8::is_ascii_whitespace);

            match mode {
                "push" => {
                    // upstream's PUSH_POP_ARGS_PATTERN: a prefix of valid
                    // `[+-]Cop/Name` tokens; none valid => the directive has
                    // no cop list and is ignored entirely (no restore point).
                    let toks: Vec<(char, String)> = rest
                        .split_whitespace()
                        .map_while(|tok| {
                            let mut chars = tok.chars();
                            let op = chars.next().filter(|c| matches!(c, '+' | '-'))?;
                            let name: String = chars.collect();
                            let valid = !name.is_empty()
                                && name.split('/').all(|seg| {
                                    let mut cs = seg.chars();
                                    cs.next().is_some_and(|c| c.is_ascii_alphabetic())
                                        && cs.all(|c| c.is_alphanumeric() || c == '_')
                                });
                            valid.then(|| (op, name))
                        })
                        .collect();
                    // a BARE `# rubocop:push` (no args) is valid; only a
                    // push WITH args where none parse is ignored.
                    if toks.is_empty() && !rest.trim().is_empty() {
                        continue;
                    }
                    stack.push(analyses.clone());
                    for (op, cop_name) in toks {
                        {
                            mced_apply_op(&mut analyses, self.cfg, op, &cop_name, line_f);
                        }
                    }
                }
                "pop" => {
                    if let Some(restore) = stack.pop() {
                        mced_pop(&mut analyses, self.cfg, &restore, line_f);
                    }
                }
                "disable" | "todo" | "enable" => {
                    let disabling = mode != "enable";
                    // a ` -- reason` trailer is prose, not part of the cop list
                    let cops_part = rest.split(" -- ").next().unwrap_or(rest).trim();
                    let Some(cops_part) = directive_cops_prefix(cops_part) else { continue };
                    if cops_part == "all" {
                        if !disabling && standalone {
                            // `# rubocop:enable all`: close every open entry.
                            for (_, a) in analyses.iter_mut() {
                                if let Some(s) = a.start.take() {
                                    a.ranges.push((s, line_f));
                                }
                            }
                        }
                        // `disable`/`todo all` isn't tracked — see doc comment.
                        continue;
                    }
                    for raw in cops_part.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        let i = mced_slot(&mut analyses, self.cfg, raw);
                        if standalone {
                            mced_analyze_standalone(&mut analyses[i].1, line_f, disabling);
                        } else if disabling {
                            // `analyze_single_line`: a trailing disable/todo
                            // only ever covers its own line; a trailing
                            // `enable` has no effect at all.
                            analyses[i].1.ranges.push((line_f, line_f));
                        }
                    }
                }
                _ => {}
            }
        }

        // `CommentConfig#cop_line_ranges`: a still-open range at EOF extends
        // through `Float::INFINITY`.
        for (_, a) in analyses.iter_mut() {
            if let Some(s) = a.start.take() {
                a.ranges.push((s, f64::INFINITY));
            }
        }

        let max_range_str = self.cfg.get(COP, "MaxRangeSize").unwrap_or("Infinity");
        let max_range = mced_max_range(max_range_str);

        // `Cop::Base#add_offense`'s `current_offense_locations.add?` dedup:
        // only the first offense at a given comment survives.
        let mut emitted: HashSet<usize> = HashSet::new();
        for (key, analysis) in &analyses {
            for &(min, max) in &analysis.ranges {
                // `acceptable_range?`
                if max - min < max_range + 2.0 {
                    continue;
                }
                if min == f64::NEG_INFINITY {
                    continue;
                }
                if key.contains('/') && max.is_infinite() && max > 0.0 && !mced_cop_enabled(self.cfg, key) {
                    continue;
                }
                let line = min as usize;
                let Some(&(_, cstart, _)) = self.comments.iter().find(|&&(l, _, _)| l == line) else {
                    continue;
                };
                if !emitted.insert(cstart) {
                    continue;
                }
                // A bare department key (no `/`) renders as `department`
                // with just the department name; a full `Dept/Cop` key
                // renders as `cop` — see `DirectiveComment#in_directive_department?`.
                let type_word = if key.contains('/') { "cop" } else { "department" };
                let msg = if max_range.is_infinite() {
                    format!("Re-enable {key} {type_word} with `# rubocop:enable` after disabling it.")
                } else {
                    format!(
                        "Re-enable {key} {type_word} within {max_range_str} lines after disabling it."
                    )
                };
                self.push(cstart, COP, false, msg);
            }
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Lint/RescueType — rescuing from non-constant literals (symbols, strings,
    /// numbers, arrays, hashes, etc.) will raise a `TypeError` instead of catching
    /// the actual exception.
    pub(crate) fn check_rescue_type(&mut self, node: &ruby_prism::RescueNode) {
        const COP: &str = "Lint/RescueType";
        if !self.on(COP) {
            return;
        }
        let exceptions: Vec<ruby_prism::Node> = node.exceptions().iter().collect();
        if exceptions.is_empty() {
            return;
        }

        let invalid: Vec<&ruby_prism::Node> = exceptions
            .iter()
            .filter(|e| is_invalid_rescue_type(e))
            .collect();

        if invalid.is_empty() {
            return;
        }

        let kw_loc = node.keyword_loc();
        let last_exc = exceptions.last().unwrap();
        let end_offset = last_exc.location().end_offset();

        let invalid_str = invalid.iter()
            .map(|e| String::from_utf8_lossy(self.node_src(e)).into_owned())
            .collect::<Vec<_>>()
            .join(", ");

        self.push(kw_loc.start_offset(), COP, true,
            format!("Rescuing from `{invalid_str}` will raise a `TypeError` instead of catching the actual exception."));

        // Autocorrect: replace from end of keyword to end of all exceptions
        let repl_start = kw_loc.end_offset();
        let valid_exceptions: Vec<&ruby_prism::Node> = exceptions
            .iter()
            .filter(|e| !is_invalid_rescue_type(e))
            .collect();

        let replacement = if valid_exceptions.is_empty() {
            Vec::new()
        } else {
            let valid_str = valid_exceptions.iter()
                .map(|e| String::from_utf8_lossy(self.node_src(e)).into_owned())
                .collect::<Vec<_>>()
                .join(", ");
            format!(" {valid_str}").into_bytes()
        };

        self.fixes.push((repl_start, end_offset, replacement));
    }
}

/// Helper function to check if a node is an invalid rescue type (non-constant literal).
/// Invalid types: nil, true, false, int, float, rational, complex, str, dstr, sym, array, hash
fn is_invalid_rescue_type(node: &ruby_prism::Node) -> bool {
    node.as_nil_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
        || node.as_string_node().is_some()
        || node.as_interpolated_string_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_interpolated_symbol_node().is_some()
        || node.as_array_node().is_some()
        || node.as_hash_node().is_some()
}

// Lint/SuppressedException: `rescue` clauses with an effectively-empty body.
//
// Upstream's `on_resbody` fires once per `:resbody` AST node. Both the
// clause form (`begin ... rescue ... end`, `def ... rescue ... end`,
// `foo do ... rescue ... end`) and the modifier form (`expr rescue expr2`)
// translate to that SAME node shape upstream (prism's `Prism::Translation::
// Parser` maps both `RescueNode` and `RescueModifierNode` onto `:resbody`),
// so the three guards below (real body / AllowComments / AllowNil) apply
// identically to both — we just have two entry points, one per prism node
// type, sharing the guard logic inline since their "body" shapes differ
// (`RescueNode#statements` is an optional `StatementsNode`; a modifier's
// `rescue_expression` is a single, always-present node).
impl<'a> super::Cops<'a> {
    /// `RescueNode` — the clause form (`rescue` inside `begin`/`def`/a block).
    /// The offense anchors on the `rescue` keyword, matching upstream (whose
    /// `:resbody` node's own source range always starts there).
    pub(crate) fn check_suppressed_exception(&mut self, node: &ruby_prism::RescueNode) {
        const COP: &str = "Lint/SuppressedException";
        if !self.on(COP) {
            return;
        }
        let nil_body = Self::se_nil_statements(&node.statements());
        // `return if node.body && !nil_body?(node)` — a present, non-nil
        // body means this clause isn't suppressing anything.
        if node.statements().is_some() && !nil_body {
            return;
        }
        self.se_finish(node.keyword_loc().start_offset(), nil_body);
    }

    /// `RescueModifierNode` — `expr rescue fallback`. Its body
    /// (`rescue_expression`) is a mandatory field, so upstream's `node.body`
    /// guard can never trigger here; only the nil-body shape matters.
    pub(crate) fn check_suppressed_exception_modifier(&mut self, node: &ruby_prism::RescueModifierNode) {
        const COP: &str = "Lint/SuppressedException";
        if !self.on(COP) {
            return;
        }
        let nil_body = node.rescue_expression().as_nil_node().is_some();
        if !nil_body {
            return;
        }
        self.se_finish(node.keyword_loc().start_offset(), nil_body);
    }

    /// Shared tail of `on_resbody`: the AllowComments / AllowNil guards, then
    /// `add_offense`. `start` is always the `rescue` keyword's offset.
    fn se_finish(&mut self, start: usize, nil_body: bool) {
        const COP: &str = "Lint/SuppressedException";
        let first_line = self.idx.loc(start).0;
        if self.cfg.get(COP, "AllowComments") == Some("true") && self.se_comment_between(first_line) {
            return;
        }
        if self.cfg.get(COP, "AllowNil") == Some("true") && nil_body {
            return;
        }
        self.push(start, COP, false, "Do not suppress exceptions.");
    }

    /// `nil_body?`: is the resbody's body exactly a single `nil` literal
    /// (not present at all doesn't count as "nil", and neither does a
    /// `nil`-then-something-else multi-statement body).
    fn se_nil_statements(statements: &Option<ruby_prism::StatementsNode>) -> bool {
        match statements {
            None => false,
            Some(stmts) => {
                let body = stmts.body();
                body.len() == 1 && body.iter().next().is_some_and(|n| n.as_nil_node().is_some())
            }
        }
    }

    /// `comment_between_rescue_and_end?`: does any actual source line from
    /// `first_line + 1` through the nearest enclosing `kwbegin`/`any_def`/
    /// `any_block` ancestor's closing line (tracked in `se_ancestor_end_lines`
    /// by `visit_begin_node`/`visit_def_node`/`visit_block_node`) consist of
    /// nothing but a comment? No such ancestor (e.g. a bare top-level `x
    /// rescue nil`) means upstream's `each_ancestor(...).first` is nil, so
    /// this short-circuits to false.
    fn se_comment_between(&self, first_line: usize) -> bool {
        let Some(&end_line) = self.se_ancestor_end_lines.last() else { return false };
        (first_line + 1..=end_line).any(|ln| self.se_line_is_comment_only(ln))
    }

    /// `Util#comment_line?`: the RAW source line (not comment-token spans)
    /// matches `/^\s*#/` — a trailing `code # comment` line does NOT count.
    fn se_line_is_comment_only(&self, line: usize) -> bool {
        let Some(&start) = self.idx.starts.get(line.wrapping_sub(1)) else { return false };
        let end = self.idx.starts.get(line).copied().unwrap_or(self.src.len());
        let text = &self.src[start..end];
        text.iter()
            .find(|&&b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .is_some_and(|&b| b == b'#')
    }
}


impl<'a> super::Cops<'a> {
    /// Lint/NonLocalExitFromIterator (detection only, no autocorrect).
    ///
    /// Ports `on_return` by walking `self.nle_stack` — the innermost active
    /// def/block/lambda ancestors, pushed/popped by `visit_def_node` /
    /// `visit_lambda_node` / `visit_block_node` in `mod.rs` (prism has no
    /// parent pointers, so this stack stands in for upstream's
    /// `each_ancestor(:any_block, :any_def)`). Walking it innermost-first
    /// mirrors that climb exactly:
    ///
    /// * `Def`/`Lambda` -> `scoped_node?` was true upstream: stop, no offense.
    /// * `Block { is_define_method: true, .. }` -> upstream's
    ///   `define_method?(node.send_node)` breaks the climb outright, even
    ///   when the block itself has no params.
    /// * `Block { has_args: false, .. }` -> upstream's
    ///   `next if node.argument_list.empty?`: skip this frame, keep climbing.
    /// * `Block { chained: true, .. }` -> upstream's `chained_send?`: offense
    ///   at the `return` keyword, then stop.
    /// * `Block { chained: false, .. }` -> no match, keep climbing (upstream's
    ///   implicit `next` when the `if chained_send?` guard is false).
    pub(crate) fn check_non_local_exit_from_iterator(&mut self, node: &ruby_prism::ReturnNode) {
        const COP: &str = "Lint/NonLocalExitFromIterator";
        const MSG: &str = "Non-local exit from iterator, without return value. \
            `next`, `break`, `Array#find`, `Array#any?`, etc. is preferred.";
        if !self.on(COP) {
            return;
        }
        // `return_value?`: `return` with an explicit value is always allowed.
        if node.arguments().is_some() {
            return;
        }
        for frame in self.nle_stack.iter().rev() {
            match frame {
                super::NleFrame::Def | super::NleFrame::Lambda => break,
                super::NleFrame::Block { is_define_method: true, .. } => break,
                super::NleFrame::Block { has_args: false, .. } => continue,
                super::NleFrame::Block { chained: true, .. } => {
                    self.push(node.keyword_loc().start_offset(), COP, false, MSG);
                    break;
                }
                super::NleFrame::Block { .. } => continue,
            }
        }
    }
}


/// Lint/UnreachableLoop — a loop (`while`/`until`/`for`, or a block attached
/// to an `Enumerable`/enumerator method or `Kernel#loop`) whose body ALWAYS
/// breaks out on the very first iteration: every control-flow path through
/// it ends in `break`/`return`/`raise`/etc, so the loop can run at most once.
///
/// Ports upstream's `statements`/`break_statement?`/`check_if`/`check_case`/
/// `preceded_by_continue_statement?`/`conditional_continue_keyword?` verbatim
/// (see rubocop's `lib/rubocop/cop/lint/unreachable_loop.rb`), adapted to
/// prism's node shapes:
///
/// * Upstream's dual "a bare single statement OR a `:begin`/`:kwbegin`-
///   wrapped list" representation collapses in prism, which ALWAYS wraps a
///   body in a `StatementsNode` regardless of statement count. Since
///   `preceded_by_continue_statement?`'s "left siblings" reduce to an empty
///   slice for a one-element list anyway (no earlier statements to scan), a
///   single find-plus-preceding-scan over the flattened list reproduces
///   upstream's behavior for every case this cop's fixture exercises — the
///   one place this simplification could theoretically diverge is a
///   single-statement loop body whose TRUE upstream left-siblings would come
///   from OUTSIDE the body (e.g. the `while`'s own condition, or a block's
///   call/args), which is not something any real check here would find
///   containing `next`/`redo` in practice (see final-report residual risks).
/// * A bare `begin...end` grouping (no `rescue`/`else`/`ensure`) is treated
///   the same way — flattened one level — mirroring upstream's shared
///   `:begin`/`:kwbegin` case; one WITH exception-handling clauses attached
///   is opaque (upstream's `case node.type` has no `:rescue` branch either).
/// * Prism has no back-pointer from a block to its owning call (unlike
///   whitequark, where the block node OWNS its `send_node` child) — so
///   `loop_method?`/`on_block` is implemented from `visit_call_node` instead
///   of `visit_block_node`, where the owning `CallNode` is directly at hand.
///   Empirically (verified against real `rubocop`), a `CallNode`'s own
///   `location()` already spans from the start of its full receiver chain
///   through its trailing block's closing delimiter, matching upstream's
///   block-node offense anchor exactly with no extra adjustment needed.
/// * `unless` is folded into the same `if`-branch handling as upstream (the
///   `parser` gem normalizes `unless` into a swapped-branch `:if` node,
///   which is why `break_statement?`'s `:if` case silently also covers it).
impl<'a> super::Cops<'a> {
    pub(crate) fn check_unreachable_loop_while(&mut self, node: &ruby_prism::WhileNode) {
        if !self.on(UL_COP) {
            return;
        }
        self.ul_check(node.location().start_offset(), node.statements().map(|s| s.as_node()));
    }

    pub(crate) fn check_unreachable_loop_until(&mut self, node: &ruby_prism::UntilNode) {
        if !self.on(UL_COP) {
            return;
        }
        self.ul_check(node.location().start_offset(), node.statements().map(|s| s.as_node()));
    }

    pub(crate) fn check_unreachable_loop_for(&mut self, node: &ruby_prism::ForNode) {
        if !self.on(UL_COP) {
            return;
        }
        self.ul_check(node.location().start_offset(), node.statements().map(|s| s.as_node()));
    }

    /// `on_block` — reached from `visit_call_node`, since prism gives us the
    /// call a block is attached to directly (unlike whitequark's block node,
    /// which owns a `send_node` child pointing the other way).
    pub(crate) fn check_unreachable_loop_call<'pr>(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if !self.on(UL_COP) {
            return;
        }
        let Some(block) = node.block() else { return };
        // `&:sym`/bare `&blk` block-passes are `BlockArgumentNode`s, never a
        // real block — `any_block_type?` upstream.
        let Some(block) = block.as_block_node() else { return };
        if !ul_loopable_call(node) {
            return;
        }
        let src = call_source_excluding_block(node, self.src);
        if self.ul_matches_allowed_pattern(src) {
            return;
        }
        self.ul_check(node.location().start_offset(), block.body());
    }

    /// Shared `check(node)` body: find the first top-level statement that
    /// always breaks, then gate on `preceded_by_continue_statement?` (did an
    /// earlier statement in the SAME list run `next`/`redo`?) and
    /// `conditional_continue_keyword?` (does the found statement itself end
    /// in `... || next`/`... || redo`?).
    fn ul_check(&mut self, anchor: usize, body: Option<ruby_prism::Node>) {
        const MSG: &str = "This loop will have at most one iteration.";
        let list = ul_flatten_group(body);
        let Some(idx) = list.iter().position(|n| self.ul_break_statement(n)) else { return };
        if self.ul_preceded_by_continue(&list[..idx]) {
            return;
        }
        if ul_conditional_continue_keyword(&list[idx]) {
            return;
        }
        self.push(anchor, UL_COP, false, MSG);
    }

    /// `loop_method?` — is `node` itself a call+block pair over an
    /// `Enumerable`/enumerator method or `Kernel#loop`, not exempted by
    /// `AllowedPatterns`? Used both to gate the top-level `on_block` entry
    /// AND (per upstream) to exclude a nested loop from
    /// `preceded_by_continue_statement?`'s scan — a `next`/`redo` belonging
    /// to an INNER loop doesn't "continue" the outer one.
    fn ul_loop_method(&self, node: &ruby_prism::Node) -> bool {
        let Some(call) = node.as_call_node() else { return false };
        let Some(block) = call.block() else { return false };
        if block.as_block_node().is_none() {
            return false;
        }
        if !ul_loopable_call(&call) {
            return false;
        }
        let src = call_source_excluding_block(&call, self.src);
        !self.ul_matches_allowed_pattern(src)
    }

    /// `matches_allowed_pattern?` with upstream's schema-default
    /// `AllowedPatterns: ['(exactly|at_least|at_most)\(\d+\)\.times']`
    /// hard-coded as the fallback for when the (array-typed, so
    /// schema-absent) config key isn't user-overridden — `cfg.param` only
    /// ever surfaces USER config, never schema defaults, for array params.
    fn ul_matches_allowed_pattern(&self, text: &[u8]) -> bool {
        match self.eng.allowed_patterns.get(UL_COP) {
            Some(pats) => {
                let s = String::from_utf8_lossy(text);
                pats.iter().any(|re| re.is_match(&s))
            }
            None => {
                static DEFAULT: OnceLock<regex::Regex> = OnceLock::new();
                let re = DEFAULT
                    .get_or_init(|| regex::Regex::new(r"(exactly|at_least|at_most)\(\d+\)\.times").unwrap());
                re.is_match(&String::from_utf8_lossy(text))
            }
        }
    }

    /// The shared "find the first statement that always breaks, then check
    /// no EARLIER one in the same list ran `next`/`redo`" scan — used both
    /// for a genuinely grouped `:begin`/`:kwbegin`, and for any
    /// `StatementsNode` (which, per `ul_break_statement`'s comment, always
    /// gets this treatment regardless of its element count).
    fn ul_group_break(&self, list: &[ruby_prism::Node]) -> bool {
        match list.iter().position(|n| self.ul_break_statement(n)) {
            None => false,
            Some(idx) => !self.ul_preceded_by_continue(&list[..idx]),
        }
    }

    /// `break_statement?` applied to a single node.
    fn ul_break_statement(&self, node: &ruby_prism::Node) -> bool {
        if ul_break_command(node) {
            return true;
        }
        // Prism always wraps a branch's body in a `StatementsNode`, even for
        // a single statement — unlike whitequark, which hands `break_statement?`
        // either a lone node OR a `:begin`-wrapped list depending on count.
        // Since a one-element grouped scan trivially reduces to just
        // `ul_break_statement` on that lone element (its "preceding slice"
        // is empty either way), treating EVERY `StatementsNode` as a group
        // reproduces upstream's dual representation exactly.
        if let Some(stmts) = node.as_statements_node() {
            return self.ul_group_break(&stmts.body().iter().collect::<Vec<_>>());
        }
        // `case node.type when :begin, :kwbegin` — a bare `begin...end`
        // grouping (no exception-handling clauses) used as a single
        // statement; flatten one level and recurse the same find-plus-
        // preceding-scan used for any other grouped list.
        if let Some(begin) = node.as_begin_node() {
            if begin.rescue_clause().is_some() || begin.else_clause().is_some() || begin.ensure_clause().is_some() {
                return false;
            }
            let list = ul_flatten_group(begin.statements().map(|s| s.as_node()));
            return self.ul_group_break(&list);
        }
        if let Some(iff) = node.as_if_node() {
            return self.ul_check_if(&iff);
        }
        if let Some(unl) = node.as_unless_node() {
            return self.ul_check_unless(&unl);
        }
        if let Some(c) = node.as_case_node() {
            return self.ul_check_case(&c);
        }
        if let Some(c) = node.as_case_match_node() {
            return self.ul_check_case_match(&c);
        }
        false
    }

    /// `branch.body && break_statement?(branch.body)` for a branch resolved
    /// via prism's `.statements()` (`None` when the branch is absent or has
    /// an empty body).
    fn ul_branch_break(&self, branch: Option<ruby_prism::StatementsNode>) -> bool {
        match branch {
            None => false,
            Some(s) => self.ul_break_statement(&s.as_node()),
        }
    }

    /// `check_if` — `if_branch && else_branch && break_statement?(if_branch)
    /// && break_statement?(else_branch)`. An `elsif` is a nested `IfNode`
    /// reachable via `.subsequent()`, exactly like upstream's `else_branch`
    /// holding the nested `(if ...)` node for a chain — recursing through
    /// `ul_break_statement` (which dispatches back into `ul_check_if`)
    /// reproduces upstream's own recursive `check_if` calls.
    fn ul_check_if(&self, node: &ruby_prism::IfNode) -> bool {
        if !self.ul_branch_break(node.statements()) {
            return false;
        }
        match node.subsequent() {
            None => false,
            Some(sub) => match sub.as_else_node() {
                Some(els) => self.ul_branch_break(els.statements()),
                None => self.ul_break_statement(&sub),
            },
        }
    }

    /// `check_if` on an `unless` — the `parser` gem normalizes `unless` into
    /// a swapped-branch `:if` node (`node_parts` swaps true/false), which is
    /// why upstream's `:if` case transparently also covers it; prism keeps a
    /// distinct `UnlessNode`, so replicate the swap explicitly: `.statements
    /// ()` is the negated ("else"-position) body, `.else_clause()` the
    /// ("if"-position) body. `&&` is symmetric, so the swap direction is
    /// otherwise inconsequential.
    fn ul_check_unless(&self, node: &ruby_prism::UnlessNode) -> bool {
        let Some(else_clause) = node.else_clause() else { return false };
        self.ul_branch_break(else_clause.statements()) && self.ul_branch_break(node.statements())
    }

    /// `check_case` for `case`/`when` — an `else` that always breaks, AND
    /// every `when` branch does too.
    fn ul_check_case(&self, node: &ruby_prism::CaseNode) -> bool {
        let Some(else_clause) = node.else_clause() else { return false };
        if !self.ul_branch_break(else_clause.statements()) {
            return false;
        }
        node.conditions().iter().all(|w| match w.as_when_node() {
            Some(w) => self.ul_branch_break(w.statements()),
            None => false,
        })
    }

    /// `check_case` for `case`/`in` (pattern matching) — same shape as
    /// `ul_check_case`, over `in` branches instead of `when` branches.
    fn ul_check_case_match(&self, node: &ruby_prism::CaseMatchNode) -> bool {
        let Some(else_clause) = node.else_clause() else { return false };
        if !self.ul_branch_break(else_clause.statements()) {
            return false;
        }
        node.conditions().iter().all(|i| match i.as_in_node() {
            Some(i) => self.ul_branch_break(i.statements()),
            None => false,
        })
    }

    /// `preceded_by_continue_statement?` — did an EARLIER statement in the
    /// same list run `next`/`redo` anywhere in its subtree? A sibling that's
    /// itself a loop (a `while`/`until`/`for` keyword, or another
    /// `loop_method?` call+block) is skipped: a `next`/`redo` belonging to
    /// that INNER loop doesn't continue the outer one being checked here.
    fn ul_preceded_by_continue(&self, siblings: &[ruby_prism::Node]) -> bool {
        siblings.iter().any(|sib| {
            if ul_loop_keyword(sib) || self.ul_loop_method(sib) {
                return false;
            }
            ul_contains_next_or_redo(sib)
        })
    }
}

const UL_COP: &str = "Lint/UnreachableLoop";

/// `statements(node)` — the flattened list of top-level statements making up
/// `n`: empty when there's no body, the un-wrapped children of a
/// `StatementsNode` or a bare (no `rescue`/`else`/`ensure`) grouping
/// `BeginNode`, or a one-element list holding `n` itself otherwise.
fn ul_flatten_group<'pr>(n: Option<ruby_prism::Node<'pr>>) -> Vec<ruby_prism::Node<'pr>> {
    let Some(n) = n else { return Vec::new() };
    if let Some(s) = n.as_statements_node() {
        return s.body().iter().collect();
    }
    if let Some(b) = n.as_begin_node() {
        if b.rescue_clause().is_some() || b.else_clause().is_some() || b.ensure_clause().is_some() {
            return Vec::new();
        }
        return match b.statements() {
            Some(s) => s.body().iter().collect(),
            None => Vec::new(),
        };
    }
    vec![n]
}

/// `break_command?` — a bare `return`/`break` (regardless of arguments), or
/// a call to one of `raise`/`fail`/`throw`/`exit`/`exit!`/`abort` with a nil
/// or `(::)Kernel` receiver, over a plain (non-safe-navigation) `send`.
fn ul_break_command(node: &ruby_prism::Node) -> bool {
    if node.as_return_node().is_some() || node.as_break_node().is_some() {
        return true;
    }
    let Some(call) = node.as_call_node() else { return false };
    if call.is_safe_navigation() {
        return false;
    }
    if !matches!(call.name().as_slice(), b"raise" | b"fail" | b"throw" | b"exit" | b"exit!" | b"abort") {
        return false;
    }
    match call.receiver() {
        None => true,
        Some(recv) => ul_is_kernel_const(&recv),
    }
}

/// `(const {nil? cbase} :Kernel)` — bare `Kernel` or top-level `::Kernel`
/// (NOT `Foo::Kernel`, which would have a non-nil, non-cbase first child).
fn ul_is_kernel_const(node: &ruby_prism::Node) -> bool {
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == b"Kernel";
    }
    if let Some(c) = node.as_constant_path_node() {
        return c.parent().is_none() && c.name().is_some_and(|n| n.as_slice() == b"Kernel");
    }
    false
}

/// `node.loop_keyword?` — a `while`/`until`/`for`, pre- or post-condition
/// alike (the post-condition distinction doesn't matter for this cop, which
/// only ever inspects the node's TYPE here, never whether it's a modifier).
fn ul_loop_keyword(node: &ruby_prism::Node) -> bool {
    node.as_while_node().is_some() || node.as_until_node().is_some() || node.as_for_node().is_some()
}

/// `send_node.enumerable_method? || send_node.enumerator_method? ||
/// send_node.method?(:loop)` for the CALL a block is attached to — prism
/// gives us this directly as the `CallNode` itself (its `.block()` is the
/// block), unlike whitequark where the block node owns a `send_node` child.
fn ul_loopable_call(call: &ruby_prism::CallNode) -> bool {
    let name = call.name().as_slice();
    name == b"loop" || ul_is_enumerator_method(name) || ul_is_enumerable_method(name)
}

/// `MethodIdentifierPredicates::ENUMERATOR_METHODS` plus the `each_*` prefix
/// rule.
fn ul_is_enumerator_method(name: &[u8]) -> bool {
    if name.starts_with(b"each_") {
        return true;
    }
    matches!(
        name,
        b"collect"
            | b"collect_concat"
            | b"detect"
            | b"downto"
            | b"each"
            | b"find"
            | b"find_all"
            | b"find_index"
            | b"inject"
            | b"loop"
            | b"map!"
            | b"map"
            | b"reduce"
            | b"reject"
            | b"reject!"
            | b"reverse_each"
            | b"select"
            | b"select!"
            | b"times"
            | b"upto"
    )
}

/// `MethodIdentifierPredicates::ENUMERABLE_METHODS` — `Enumerable.
/// instance_methods + [:each]` (Ruby 3.4.1's `Enumerable`, matching the
/// rubocop-ast version this cop is pinned to).
fn ul_is_enumerable_method(name: &[u8]) -> bool {
    matches!(
        name,
        b"all?"
            | b"any?"
            | b"chain"
            | b"chunk"
            | b"chunk_while"
            | b"collect"
            | b"collect_concat"
            | b"compact"
            | b"count"
            | b"cycle"
            | b"detect"
            | b"drop"
            | b"drop_while"
            | b"each"
            | b"each_cons"
            | b"each_entry"
            | b"each_slice"
            | b"each_with_index"
            | b"each_with_object"
            | b"entries"
            | b"filter"
            | b"filter_map"
            | b"find"
            | b"find_all"
            | b"find_index"
            | b"first"
            | b"flat_map"
            | b"grep"
            | b"grep_v"
            | b"group_by"
            | b"include?"
            | b"inject"
            | b"lazy"
            | b"map"
            | b"max"
            | b"max_by"
            | b"member?"
            | b"min"
            | b"min_by"
            | b"minmax"
            | b"minmax_by"
            | b"none?"
            | b"one?"
            | b"partition"
            | b"reduce"
            | b"reject"
            | b"reverse_each"
            | b"select"
            | b"slice_after"
            | b"slice_before"
            | b"slice_when"
            | b"sort"
            | b"sort_by"
            | b"sum"
            | b"take"
            | b"take_while"
            | b"tally"
            | b"to_a"
            | b"to_h"
            | b"to_set"
            | b"uniq"
            | b"zip"
    )
}

/// `each_descendant(*CONTINUE_KEYWORDS).any?` — does `node`'s subtree
/// contain a `next` or `redo` ANYWHERE, with no scope boundary (this walks
/// into nested blocks/defs too, exactly like upstream's raw AST descent).
fn ul_contains_next_or_redo(node: &ruby_prism::Node) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder {
        fn visit_next_node(&mut self, node: &ruby_prism::NextNode<'pr>) {
            self.found = true;
            ruby_prism::visit_next_node(self, node);
        }
        fn visit_redo_node(&mut self, node: &ruby_prism::RedoNode<'pr>) {
            self.found = true;
            ruby_prism::visit_redo_node(self, node);
        }
    }
    let mut f = Finder { found: false };
    use ruby_prism::Visit;
    f.visit(node);
    f.found
}

/// `conditional_continue_keyword?` — does the LAST (in depth-first, pre-
/// order traversal — matching `each_descendant`) `or`-node anywhere in
/// `node`'s subtree have a `next`/`redo` right-hand side, e.g. `return
/// do_something(value) || next`?
fn ul_conditional_continue_keyword(node: &ruby_prism::Node) -> bool {
    struct Finder {
        last_matches: Option<bool>,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder {
        fn visit_or_node(&mut self, node: &ruby_prism::OrNode<'pr>) {
            let rhs = node.right();
            self.last_matches = Some(rhs.as_next_node().is_some() || rhs.as_redo_node().is_some());
            ruby_prism::visit_or_node(self, node);
        }
    }
    let mut f = Finder { last_matches: None };
    use ruby_prism::Visit;
    f.visit(node);
    f.last_matches.unwrap_or(false)
}


impl<'a> super::Cops<'a> {
    /// Lint/RedundantRequireStatement — `require` of a feature already
    /// loaded by the target Ruby version. Mirrors upstream's
    /// `redundant_require_statement?` node matcher: `(send nil? :require
    /// (str #redundant_feature?))` — a bare, receiver-less `require` call
    /// with exactly one plain (non-interpolated) string literal argument
    /// naming a feature `rrs_redundant_feature` recognizes for the active
    /// `target_ruby_version`.
    ///
    /// Offense anchor: the `require` call node's own start offset
    /// (rubocop's `add_offense(node)` default location is the whole send
    /// node's source range).
    ///
    /// Autocorrect has two shapes, both ported from the single
    /// `corrector` block in the Ruby source:
    ///   - Ordinary statement (the overwhelming common case): remove the
    ///     WHOLE line(s) the call's own source range spans, final newline
    ///     included (`range_by_whole_lines(node.source_range,
    ///     include_final_newline: true)`).
    ///   - The call is the SOLE statement of a modifier-form `if`/`unless`/
    ///     `while`/`until` (`node.parent.modifier_form?`, flagged ahead of
    ///     time by `rrs_note_modifier_body` since prism gives no parent
    ///     pointers — see that field's doc on `rrs_modifier_end` in
    ///     `mod.rs`): remove the call plus any immediately adjacent
    ///     trailing horizontal whitespace then newlines
    ///     (`range_with_surrounding_space(node.source_range, side:
    ///     :right)`), and separately insert `"\nend"` right after the
    ///     conditional's own end (a modifier form has no `end` keyword, so
    ///     its own source range already ends at the predicate) — turning
    ///     `require 'x' if cond` into `if cond\nend`.
    pub(crate) fn check_redundant_require_statement(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantRequireStatement";
        if !self.on(COP) {
            return;
        }
        let call_start = node.location().start_offset();
        // Consume the modifier-body note if it belongs to exactly this call
        // node. It was set unconditionally for any bare-call modifier body
        // (see `rrs_note_modifier_body`), so it must be cleared here even
        // when this call turns out not to be a qualifying `require` — it
        // can never be relevant to any OTHER node either way.
        let modifier_end = match self.rrs_modifier_end.take() {
            Some((s, e)) if s == call_start => Some(e),
            other => {
                self.rrs_modifier_end = other;
                None
            }
        };
        if node.name().as_slice() != b"require" || node.receiver().is_some() {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let items: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        if items.len() != 1 {
            return;
        }
        let Some(str_node) = items[0].as_string_node() else { return };
        if !rrs_redundant_feature(str_node.content_loc().as_slice(), self.cfg.target_ruby()) {
            return;
        }
        self.push(call_start, COP, true, "Remove unnecessary `require` statement.");
        if let Some(parent_end) = modifier_end {
            let right_end = rrs_space_right(self.src, node.location().end_offset());
            self.fixes.push((call_start, right_end, Vec::new()));
            self.fixes.push((parent_end, parent_end, b"\nend".to_vec()));
        } else {
            let (line_s, _) = self.idx.loc(call_start);
            let (line_e, _) = self.idx.loc(node.location().end_offset().saturating_sub(1));
            let start = self.idx.starts[line_s - 1];
            let end = self.idx.starts.get(line_e).copied().unwrap_or(self.src.len());
            self.fixes.push((start, end, Vec::new()));
        }
    }

    /// Called pre-recursion by `visit_if_node`/`visit_unless_node`/
    /// `visit_while_node`/`visit_until_node` (see each call site) once
    /// they've established the node is a genuine modifier-form conditional
    /// (has a keyword, has no `end` keyword; `while`/`until` additionally
    /// require the body to precede the keyword, ruling out the
    /// `begin...end while` post-condition-loop shape). If the sole body
    /// statement is a bare call node, record it — matching value — so
    /// `check_redundant_require_statement` can recognize its parent as
    /// modifier-form once traversal reaches that exact call.
    pub(crate) fn rrs_note_modifier_body(
        &mut self,
        stmts: Option<ruby_prism::StatementsNode>,
        parent_end: usize,
    ) {
        if !self.on("Lint/RedundantRequireStatement") {
            return;
        }
        let Some(stmts) = stmts else { return };
        let items: Vec<ruby_prism::Node> = stmts.body().iter().collect();
        if items.len() != 1 {
            return;
        }
        if let Some(call) = items[0].as_call_node() {
            self.rrs_modifier_end = Some((call.location().start_offset(), parent_end));
        }
    }
}

/// Upstream's `RUBY_22_LOADED_FEATURES` plus every other version-gated
/// feature named in `redundant_feature?`'s doc comment: `enumerator`
/// unconditionally; `thread` at 2.1+; `rational`/`complex` at 2.2+;
/// `ruby2_keywords` at 2.7+; `fiber` at 3.1+; `set` at 3.2+; `pathname` at
/// 4.0+.
fn rrs_redundant_feature(feature: &[u8], target_ruby: f64) -> bool {
    match feature {
        b"enumerator" => true,
        b"thread" => target_ruby >= 2.1,
        b"rational" | b"complex" => target_ruby >= 2.2,
        b"ruby2_keywords" => target_ruby >= 2.7,
        b"fiber" => target_ruby >= 3.1,
        b"set" => target_ruby >= 3.2,
        b"pathname" => target_ruby >= 4.0,
        _ => false,
    }
}

/// The END position only of `RangeHelp#range_with_surrounding_space(range,
/// side: :right)` (the start is left untouched by callers) — extend
/// rightward over immediately adjacent horizontal whitespace, then over
/// newlines.
fn rrs_space_right(src: &[u8], mut end: usize) -> usize {
    while end < src.len() && matches!(src[end], b' ' | b'\t') {
        end += 1;
    }
    while end < src.len() && src[end] == b'\n' {
        end += 1;
    }
    end
}


/// A `(const _ _)` node-pattern match at ANY nesting depth — both a bare
/// `Foo` (`ConstantReadNode`) and a namespaced `A::B` / top-level `::Foo`
/// (`ConstantPathNode`) satisfy it, since prism's `const` node type covers
/// both and the pattern's `_ _` wildcards accept any namespace/name shape.
fn swma_is_const(n: &ruby_prism::Node) -> bool {
    n.as_constant_read_node().is_some() || n.as_constant_path_node().is_some()
}

impl<'a> super::Cops<'a> {
    /// Lint/SendWithMixinArgument — `Foo.send(:include, Bar)` (also
    /// `public_send`/`__send__`, symbol or string method name) should be
    /// `Foo.include Bar`. Mirrors rubocop's `send_with_mixin_argument?`
    /// node-matcher verbatim:
    ///   (send
    ///     {nil? self (const _ _)} {:send :public_send :__send__}
    ///     ({sym str} $#mixin_method?)
    ///       $(const _ _)+)
    /// — receiver must be implicit, `self`, or a const (any nesting);
    /// safe-navigation sends never match (rubocop's `(send ...)` pattern
    /// excludes `csend`); the first argument must be a *literal* symbol or
    /// string (no interpolation) naming `include`/`prepend`/`extend`; every
    /// remaining argument must be a const (any nesting) and there must be at
    /// least one. The offense range and the autocorrect both span from the
    /// `send`/`public_send`/`__send__` selector through the end of the whole
    /// call (rubocop's `range_between(loc.selector.begin_pos,
    /// loc.expression.end_pos)`), so the receiver itself is never touched.
    pub(crate) fn check_send_with_mixin_argument(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/SendWithMixinArgument";
        if !self.on(COP) || node.is_safe_navigation() {
            return;
        }
        let name = node.name();
        let name = name.as_slice();
        if name != b"send" && name != b"public_send" && name != b"__send__" {
            return;
        }
        match node.receiver() {
            None => {}
            Some(r) => {
                if r.as_self_node().is_none() && !swma_is_const(&r) {
                    return;
                }
            }
        }
        let Some(args) = node.arguments() else { return };
        let args: Vec<_> = args.arguments().iter().collect();
        let Some((first, rest)) = args.split_first() else { return };
        if rest.is_empty() {
            return;
        }
        let method_bytes: Vec<u8> = if let Some(sym) = first.as_symbol_node() {
            sym.unescaped().to_vec()
        } else if let Some(st) = first.as_string_node() {
            st.unescaped().to_vec()
        } else {
            return;
        };
        if method_bytes != b"include" && method_bytes != b"prepend" && method_bytes != b"extend" {
            return;
        }
        if !rest.iter().all(swma_is_const) {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        let bad_start = sel.start_offset();
        let bad_end = node.location().end_offset();
        let method_str = String::from_utf8_lossy(&method_bytes);
        let module_names_source = rest
            .iter()
            .map(|m| String::from_utf8_lossy(self.node_src(m)).into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        let bad_method = String::from_utf8_lossy(&self.src[bad_start..bad_end]).into_owned();
        let message = format!(
            "Use `{method_str} {module_names_source}` instead of `{bad_method}`."
        );
        self.push(bad_start, COP, true, message);
        self.fixes.push((
            bad_start,
            bad_end,
            format!("{method_str} {module_names_source}").into_bytes(),
        ));
    }
}


impl<'a> super::Cops<'a> {
    /// `Lint/ParenthesesAsGroupedExpression` — `method (arg)` with a space
    /// before a parenthesized SOLE argument is ambiguous: Ruby parses it as
    /// `method(the_whole_parenthesized_expr)`, not as call-parens around
    /// `arg`. Upstream's whitequark-oriented `valid_context?` guards
    /// (`any_block_type?`/`hash_type?`/`ternary_expression?`/
    /// `compound_range?`/`chained_calls?`) all test `node.first_argument`
    /// itself — which, whenever `parenthesized_call?` holds, is ALWAYS the
    /// synthetic wrapper node (whitequark's `:begin`, prism's
    /// `ParenthesesNode`), never the unwrapped inner expression. So those
    /// predicates are unreachable in practice (verified against real
    /// `rubocop` 1.88: a parenthesized block/hash/ternary body still
    /// offends). The two guards that DO matter are `operator_method?` and
    /// `setter_method?`, plus the two structural gates below. Ported to
    /// prism terms:
    ///   - `node.arguments.one?` -> exactly one call argument.
    ///   - `first_argument.parenthesized_call?` (own `loc.begin == '('`) ->
    ///     that sole argument is ITSELF a `ParenthesesNode` (the entire
    ///     argument is one explicit `(...)` group) — this is the ONLY shape
    ///     that structurally corresponds to the ambiguous surface syntax;
    ///     any other node type (a plain call with its own args-parens like
    ///     `b(c)`, `yield(c)`/`super(c)`/`defined?(c)` with their own
    ///     keyword-parens, a chain `(x).foo.bar`, a compound range
    ///     `(a-b)..(c-d)`, a multi-arg hash-pattern key, etc.) is NOT a
    ///     `ParenthesesNode` and is excluded for free, matching upstream's
    ///     early-exit `return true unless ...` AND its independent
    ///     `spaces_before_left_parenthesis` string-prefix check in one shot.
    ///   - `node.parenthesized?` (`loc.end.is?(')')`, the CALL's own parens)
    ///     -> `node.opening_loc().is_some()`.
    pub(crate) fn check_parentheses_as_grouped_expression(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/ParenthesesAsGroupedExpression";
        if !self.on(COP) {
            return;
        }

        // `node.parenthesized?` — the call itself already has real parens
        // around its arguments; nothing ambiguous here.
        if node.opening_loc().is_some() {
            return;
        }

        let Some(args) = node.arguments() else { return };
        let arg_list = args.arguments();
        if arg_list.len() != 1 {
            return;
        }

        // `first_argument.parenthesized_call?` — the sole argument must
        // itself be a full `(...)` group (a prism `ParenthesesNode`), not
        // merely have a `(` appear somewhere inside it.
        let Some(paren) = arg_list.iter().next().unwrap().as_parentheses_node() else {
            return;
        };

        // `node.operator_method? || node.setter_method?`
        let name = node.name().as_slice();
        if is_operator_method_name(name) || node.equal_loc().is_some() {
            return;
        }

        let Some(selector) = node.message_loc() else { return };
        let sel_end = selector.end_offset();
        let paren_loc = paren.location();
        let paren_start = paren_loc.start_offset();

        // `spaces_before_left_parenthesis` / `space_length.positive?` — the
        // offense range is exactly the (possibly multi-byte) gap between the
        // selector and the opening paren.
        if paren_start <= sel_end {
            return;
        }

        let argument_src = String::from_utf8_lossy(&self.src[paren_start..paren_loc.end_offset()]);
        let message = format!("`{argument_src}` interpreted as grouped expression.");
        self.push(sel_end, COP, true, message);
        self.fixes.push((sel_end, paren_start, Vec::new()));
    }
}


impl<'a> super::Cops<'a> {
    /// Lint/MissingSuper — a bare `def initialize` inside a class (or
    /// `Class.new` block) with a "stateful" parent (anything but
    /// `Object`/`BasicObject`/`AllowedParentClasses`) that never calls
    /// `super`, OR a lifecycle-callback method (`MS_CALLBACKS` below)
    /// defined anywhere inside a class/module/`sclass` body without
    /// `super`. See the `ms_scope_depth`/`ms_class_stack`/`ms_block_stack`
    /// field docs in `mod.rs` for how the three ancestor lookups this needs
    /// (`each_ancestor(:class, :sclass, :module)`, `each_ancestor
    /// (:any_block)`, `each_ancestor(:class)`) are tracked without real
    /// parent pointers. `method_missing`/`respond_to_missing?` are
    /// deliberately excluded from `MS_CALLBACKS` — upstream's own doc
    /// comment: "this cop does not consider `method_missing`...". No
    /// autocorrector — upstream's own doc comment: "the position of `super`
    /// cannot be determined automatically."
    pub(crate) fn check_missing_super(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/MissingSuper";
        const CONSTRUCTOR_MSG: &str = "Call `super` to initialize state of the parent class.";
        const CALLBACK_MSG: &str = "Call `super` to invoke callback defined in the parent class.";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        // `callback_method_def?`: `CALLBACKS.include?(node.method_name)` and
        // `node.each_ancestor(:class, :sclass, :module).first` — the LATTER
        // is a pure existence check (any such ancestor at all, wherever it
        // is), so `ms_scope_depth > 0` suffices.
        let is_callback = MS_CALLBACKS.contains(&name) && self.ms_scope_depth > 0;
        let start = node.location().start_offset();
        if node.receiver().is_some() {
            // `on_defs` — upstream never looks at `method?(:initialize)`
            // here, so only the callback branch ever applies.
            if is_callback && !ms_contains_super(&node.as_node()) {
                self.push(start, COP, false, CALLBACK_MSG);
            }
            return;
        }
        // `on_def`'s `offender?`: (`initialize` or callback) and no `super`
        // anywhere in the def's subtree (verified live against the real gem:
        // a `super` inside a NESTED `def`, several levels down, still counts
        // — `each_descendant(:super, :zsuper)` has no def/block scope
        // awareness here, unlike some of this cop's siblings).
        let is_initialize = name == b"initialize";
        if !(is_initialize || is_callback) || ms_contains_super(&node.as_node()) {
            return;
        }
        if is_initialize {
            if self.ms_inside_stateful_parent() {
                self.push(start, COP, false, CONSTRUCTOR_MSG);
            }
        } else {
            self.push(start, COP, false, CALLBACK_MSG);
        }
    }

    /// `inside_class_with_stateful_parent?` — the nearest `any_block`
    /// ancestor (however far out) takes priority over any `class` ancestor:
    /// only a `Class.new(x)`-shaped one with a disallowed `x` counts, and
    /// any OTHER kind of block always means "no offense", full stop (a
    /// live-verified upstream quirk: a plain block between the def and an
    /// otherwise-stateful outer class suppresses the offense entirely).
    /// With no block ancestor at all, fall back to the nearest REAL `class`
    /// ancestor's own superclass verdict (`false` with no `class` ancestor
    /// either — e.g. a bare `def initialize` inside a `module`).
    fn ms_inside_stateful_parent(&self) -> bool {
        match self.ms_block_stack.last() {
            Some(frame) => frame.unwrap_or(false),
            None => self.ms_class_stack.last().copied().unwrap_or(false),
        }
    }

    /// A `class` node's own "stateful parent" verdict, for `ms_class_stack`:
    /// `class_node.parent_class && !allowed_class?(class_node.parent_class)`.
    pub(crate) fn ms_has_stateful_parent(&self, superclass: Option<&ruby_prism::Node>) -> bool {
        let Some(sc) = superclass else { return false };
        match ms_const_name(sc) {
            Some(n) => !self.ms_allowed_classes().contains(&n),
            None => true,
        }
    }

    /// `class_new_block`'s node-pattern verdict for the CALL a block is
    /// attached to — `(any_block (send (const {nil? cbase} :Class) :new
    /// $_) ...)`: `Some(b)` when `call` is `Class.new(x)`/`::Class.new(x)`
    /// with EXACTLY one argument `x` (the pattern's `$_` capture requires
    /// arity 1 — zero args, as in a bare `Class.new do...end`, never
    /// matches), `b` being whether `x` is disallowed; `None` otherwise
    /// (a non-`Class` receiver, safe-navigation, or the wrong arg count).
    pub(crate) fn ms_class_new_pending(&self, call: &ruby_prism::CallNode) -> Option<bool> {
        if call.name().as_slice() != b"new" || call.is_safe_navigation() {
            return None;
        }
        let recv = call.receiver()?;
        if const_name_root(&recv).as_deref() != Some("Class") {
            return None;
        }
        let args = call.arguments()?;
        let arg_list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
        let [arg] = arg_list.as_slice() else { return None };
        Some(match ms_const_name(arg) {
            Some(n) => !self.ms_allowed_classes().contains(&n),
            None => true,
        })
    }

    /// `STATELESS_CLASSES + cop_config.fetch('AllowedParentClasses', [])` —
    /// `AllowedParentClasses` has no schema entry (array-valued defaults
    /// are omitted by the schema generator), so its upstream default
    /// (`[]`) is hardcoded here as the `None` fallback.
    fn ms_allowed_classes(&self) -> Vec<String> {
        let mut allowed = vec!["BasicObject".to_string(), "Object".to_string()];
        if let Some(v) = self.cfg.get("Lint/MissingSuper", "AllowedParentClasses") {
            allowed.extend(crate::config::parse_allowed_list(v));
        }
        allowed
    }
}

/// `CALLBACKS = (CLASS_LIFECYCLE_CALLBACKS + METHOD_LIFECYCLE_CALLBACKS)` —
/// deliberately excludes `method_missing`/`respond_to_missing?` (see the doc
/// comment on `check_missing_super`).
const MS_CALLBACKS: &[&[u8]] = &[
    b"inherited",
    b"method_added",
    b"method_removed",
    b"method_undefined",
    b"singleton_method_added",
    b"singleton_method_removed",
    b"singleton_method_undefined",
];

/// rubocop-ast's `Node#const_name`: the full dotted name of a constant
/// expression (`ConstantReadNode`/`ConstantPathNode`), with a leading `::`
/// (cbase) anchor stripped — `None` for anything else, exactly like
/// upstream (`return unless const_type? || casgn_type?`).
fn ms_const_name(node: &ruby_prism::Node) -> Option<String> {
    if let Some(c) = node.as_constant_read_node() {
        return Some(String::from_utf8_lossy(c.name().as_slice()).into_owned());
    }
    if let Some(p) = node.as_constant_path_node() {
        let name = String::from_utf8_lossy(p.name()?.as_slice()).into_owned();
        return match p.parent() {
            None => Some(name),
            Some(parent) => Some(format!("{}::{name}", ms_const_name(&parent)?)),
        };
    }
    None
}

/// `contains_super?`: `node.each_descendant(:super, :zsuper).any?` — a
/// plain, unbounded descendant walk.
fn ms_contains_super(node: &ruby_prism::Node) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder {
        fn visit_super_node(&mut self, _node: &ruby_prism::SuperNode<'pr>) {
            self.found = true;
        }
        fn visit_forwarding_super_node(&mut self, _node: &ruby_prism::ForwardingSuperNode<'pr>) {
            self.found = true;
        }
    }
    let mut f = Finder { found: false };
    use ruby_prism::Visit;
    f.visit(node);
    f.found
}


// ---- Lint/SafeNavigationConsistency ----
//
// Upstream (`lib/rubocop/cop/lint/safe_navigation_consistency.rb`): inside an
// `&&`/`||` condition, every method call on the SAME receiver must use safe
// navigation (`&.`) consistently. `on_and`/`on_or` (aliased) fire for EVERY
// `and`/`or` node in the file, not just the topmost of a chain — nested
// `and`/`or` nodes get their own independent pass. Each pass:
//   1. walks its own `left`/`right` (recursing through nested `and`/`or`,
//      dropping anything else — in particular a parenthesized group, which
//      is neither `call_type?` nor `operator_keyword?` — see
//      `operand_nodes`) collecting every call-type "operand" reached, tagged
//      with which side (`&&` vs `||`) of whichever `and`/`or` node it came
//      from directly (never through a dropped parenthesized wrapper — see
//      the module doc below for why that case never arises here);
//   2. groups those operands by receiver source text (`""` for a bare,
//      receiver-less call — upstream's `receiver_name_as_key`, whose
//      `method.parent.call_type?` branch is dead code for operands reached
//      this way: an operand's immediate parent is always the `and`/`or`
//      node it was `left`/`right` of, never another call);
//   3. per group, `find_consistent_parts` picks a target navigation style
//      (`.` or `&.`) and a start index into the group from the leftmost
//      safe/unsafe calls found — see `snc_find_consistent_parts` for the
//      literal port of its branching;
//   4. every operand from that index onward that doesn't already match the
//      target style gets flagged (and, unless it's an operator-method call
//      like `foo + 1` with no dot to rewrite, corrected).
//
// Upstream's `Base#add_offense` silently drops a second offense registered
// at a RANGE already claimed earlier in the SAME file (`current_offense_
// locations.add?`) — since the commissioner dispatches pre-order (outer
// `and`/`or` before the nested ones inside it), an outer pass can already
// claim a range that an inner pass's own independent pass would also want to
// flag; only the first (outer) registration counts. `Cops::snc_offended`
// (keyed by the offense's own start offset — no two distinct candidate
// offenses for this cop ever share a start offset) reproduces that.
impl<'a> Cops<'a> {
    pub(crate) fn check_safe_navigation_consistency(
        &mut self,
        left: ruby_prism::Node,
        right: ruby_prism::Node,
        is_and: bool,
    ) {
        const COP: &str = "Lint/SafeNavigationConsistency";
        if !self.on(COP) {
            return;
        }

        let mut operands: Vec<SncOperand<'a>> = Vec::new();
        self.snc_collect(&left, is_and, &mut operands);
        self.snc_collect(&right, is_and, &mut operands);

        // `group_by` — preserve first-seen key order, and within each group
        // the operands' original (left-to-right, depth-first) order.
        let mut groups: Vec<(&'a [u8], Vec<usize>)> = Vec::new();
        for (i, op) in operands.iter().enumerate() {
            if let Some(g) = groups.iter_mut().find(|(k, _)| *k == op.receiver_key) {
                g.1.push(i);
            } else {
                groups.push((op.receiver_key, vec![i]));
            }
        }

        for (_, idxs) in &groups {
            let Some((dot_is_period, begin)) = snc_find_consistent_parts(&operands, idxs) else {
                continue;
            };
            for &i in &idxs[begin..] {
                let op = &operands[i];
                if snc_already_appropriate(op, dot_is_period) {
                    continue;
                }
                self.snc_register_offense(op, dot_is_period);
            }
        }
    }

    /// `collect_operands`/`operand_nodes`: walk `node` (one side of an
    /// `and`/`or` node), recursing through nested `and`/`or` nodes (their own
    /// `left`/`right`, re-tagged with THEIR OWN kind — `parent_is_and` is
    /// only consulted at the leaf) and collecting every call-type leaf
    /// reached. Anything else (in particular a parenthesized group, which
    /// upstream's whitequark `begin_type?`/prism `ParenthesesNode` is
    /// neither `operator_keyword?` nor `call_type?`) is dropped — the whole
    /// subtree underneath it, even if it's itself an `and`/`or` chain, is
    /// invisible to THIS pass (it gets its own independent pass when the
    /// visitor reaches that nested `and`/`or` node directly).
    fn snc_collect(&self, node: &ruby_prism::Node, parent_is_and: bool, out: &mut Vec<SncOperand<'a>>) {
        if let Some(and) = node.as_and_node() {
            self.snc_collect(&and.left(), true, out);
            self.snc_collect(&and.right(), true, out);
        } else if let Some(or) = node.as_or_node() {
            self.snc_collect(&or.left(), false, out);
            self.snc_collect(&or.right(), false, out);
        } else if let Some(call) = node.as_call_node() {
            out.push(self.snc_make_operand(&call, parent_is_and));
        }
    }

    fn snc_make_operand(&self, call: &ruby_prism::CallNode, in_and: bool) -> SncOperand<'a> {
        const COP: &str = "Lint/SafeNavigationConsistency";
        let name_bytes = call.name().as_slice();
        let is_csend = call.is_safe_navigation();
        let dot_range = call.call_operator_loc().map(|l| (l.start_offset(), l.end_offset()));
        let is_dot = call.call_operator_loc().is_some_and(|l| l.as_slice() == b".");
        let is_operator_method = snc_is_operator_method(name_bytes);
        // `nilable?`: a safe-navigated call always is; otherwise a method
        // nil itself responds to (upstream's `NilMethods` mixin — nil's own
        // instance methods, plus `to_d`, plus the cop's configured
        // `AllowedMethods`, default `present?`/`blank?`/`presence`/`try`/
        // `try!` per the schema).
        let is_nilable = is_csend || snc_is_builtin_nil_method(name_bytes) || self.allowed(COP, name_bytes);
        let receiver_key: &'a [u8] = call.receiver().map(|r| self.node_src(&r)).unwrap_or(b"");
        SncOperand {
            node_start: call.location().start_offset(),
            dot_range,
            is_csend,
            is_dot,
            is_operator_method,
            is_nilable,
            receiver_key,
            in_and,
        }
    }

    /// `register_offense`: `offense_range` is the whole call for an
    /// operator-method operand (no dot to anchor on, e.g. `foo + 1`),
    /// otherwise the call-operator (`.`/`&.`) token. The corrector only
    /// fires (and only then is the offense actually `[Correctable]`, per
    /// upstream) for the latter case.
    fn snc_register_offense(&mut self, op: &SncOperand, dot_is_period: bool) {
        const COP: &str = "Lint/SafeNavigationConsistency";
        let offense_start = if op.is_operator_method {
            op.node_start
        } else {
            let Some((s, _)) = op.dot_range else { return };
            s
        };
        // Upstream's range-identity offense dedup (see module doc above).
        if !self.snc_offended.insert(offense_start) {
            return;
        }
        let message = if dot_is_period {
            "Use `.` instead of unnecessary `&.`."
        } else {
            "Use `&.` for consistency with safe navigation."
        };
        self.push(offense_start, COP, !op.is_operator_method, message);
        if !op.is_operator_method {
            if let Some((s, e)) = op.dot_range {
                let replacement: &[u8] = if dot_is_period { b"." } else { b"&." };
                self.fixes.push((s, e, replacement.to_vec()));
            }
        }
    }
}

/// One call-type operand collected from an `&&`/`||` chain, tagged with
/// which side (`in_and` = `&&`, else `||`) of its immediate `and`/`or`
/// parent it came from — upstream's `operand_in_and?`/`operand_in_or?`,
/// specialized: an operand's immediate parent, reached the way `snc_collect`
/// reaches it, is ALWAYS the `and`/`or` node it was `left`/`right` of
/// (never a parenthesized wrapper — see `snc_collect`'s doc), so upstream's
/// defensive walk up through `begin_type?` ancestors never actually fires,
/// and `operand_in_and?`/`operand_in_or?` collapse to this one bool.
struct SncOperand<'a> {
    /// The call's own start offset — the offense anchor for an
    /// operator-method operand (`register_offense`'s `operand` branch).
    node_start: usize,
    /// The call-operator (`.`/`&.`) token's (start, end), if any.
    dot_range: Option<(usize, usize)>,
    is_csend: bool,
    /// `dot?` — the call-operator token is exactly `.` (as opposed to
    /// `&.`, `::`, or absent for a receiver-less call).
    is_dot: bool,
    is_operator_method: bool,
    is_nilable: bool,
    /// Receiver's own source text (`""` for a receiver-less call) — the
    /// `group_by` key.
    receiver_key: &'a [u8],
    in_and: bool,
}

/// `most_left_indices`, inlined into `find_consistent_parts`: the leftmost
/// index (within `idxs`, i.e. within ONE receiver-group) of, respectively, a
/// safe-navigated (`csend`) operand on the `&&` side / the `||` side, and a
/// non-nilable (`send`) operand on the `&&` side / the `||` side.
fn snc_most_left_indices(
    operands: &[SncOperand],
    idxs: &[usize],
) -> (Option<usize>, Option<usize>, Option<usize>, Option<usize>) {
    let mut csend_in_and = None;
    let mut csend_in_or = None;
    let mut send_in_and = None;
    let mut send_in_or = None;
    for (idx, &oi) in idxs.iter().enumerate() {
        let op = &operands[oi];
        if op.in_and {
            if op.is_csend && csend_in_and.is_none() {
                csend_in_and = Some(idx);
            }
            if !op.is_nilable && send_in_and.is_none() {
                send_in_and = Some(idx);
            }
        } else {
            if op.is_csend && csend_in_or.is_none() {
                csend_in_or = Some(idx);
            }
            if !op.is_nilable && send_in_or.is_none() {
                send_in_or = Some(idx);
            }
        }
    }
    (csend_in_and, csend_in_or, send_in_and, send_in_or)
}

/// `find_consistent_parts`, ported literally (branch order matters — these
/// are `elsif`s, not independent conditions): returns the target navigation
/// style (`true` = `.`, `false` = `&.`) and the index INTO `idxs` (a single
/// receiver-group) where flagging starts, or `None` if this group has
/// nothing to reconcile (or is unreconcilable — a safe-navigated `&&` operand
/// to the left of a safe-navigated `||` operand can never be made
/// consistent by adding/removing navigation on the operands after it).
fn snc_find_consistent_parts(operands: &[SncOperand], idxs: &[usize]) -> Option<(bool, usize)> {
    let (csend_in_and, csend_in_or, send_in_and, send_in_or) = snc_most_left_indices(operands, idxs);

    if let (Some(ca), Some(co)) = (csend_in_and, csend_in_or) {
        if ca < co {
            return None;
        }
    }

    if let Some(ca) = csend_in_and {
        let begin = match send_in_and {
            Some(sa) => sa.min(ca),
            None => ca,
        };
        return Some((true, begin + 1));
    }
    if let (Some(so), Some(co)) = (send_in_or, csend_in_or) {
        return if so < co { Some((true, so + 1)) } else { Some((false, co + 1)) };
    }
    if let (Some(sa), Some(co)) = (send_in_and, csend_in_or) {
        if sa < co {
            return Some((true, co));
        }
    }
    None
}

/// `already_appropriate_call?`.
fn snc_already_appropriate(op: &SncOperand, dot_is_period: bool) -> bool {
    if op.is_csend && !dot_is_period {
        return true;
    }
    (op.is_dot || op.is_operator_method) && dot_is_period
}

/// `RuboCop::AST::Node::OPERATOR_METHODS`.
fn snc_is_operator_method(name: &[u8]) -> bool {
    const OPS: &[&[u8]] = &[
        b"|", b"^", b"&", b"<=>", b"==", b"===", b"=~", b">", b">=", b"<", b"<=", b"<<", b">>", b"+", b"-", b"*",
        b"/", b"%", b"**", b"~", b"+@", b"-@", b"!@", b"~@", b"[]", b"[]=", b"!", b"!=", b"!~", b"`",
    ];
    OPS.iter().any(|&op| op == name)
}

/// `NilMethods#nil_methods`, minus the cop-config `AllowedMethods` part
/// (checked separately via `self.allowed`, so config overrides — like the
/// fixture's own — apply): `nil.methods` (Ruby 3.4) plus `to_d`.
fn snc_is_builtin_nil_method(name: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"!", b"!=", b"!~", b"&", b"<=>", b"==", b"===", b"=~", b"^", b"__id__", b"__send__", b"class", b"clone",
        b"define_singleton_method", b"display", b"dup", b"enum_for", b"eql?", b"equal?", b"extend", b"freeze",
        b"frozen?", b"hash", b"inspect", b"instance_eval", b"instance_exec", b"instance_of?",
        b"instance_variable_defined?", b"instance_variable_get", b"instance_variable_set", b"instance_variables",
        b"is_a?", b"itself", b"kind_of?", b"method", b"methods", b"nil?", b"object_id", b"private_methods",
        b"protected_methods", b"public_method", b"public_methods", b"public_send", b"rationalize",
        b"remove_instance_variable", b"respond_to?", b"send", b"singleton_class", b"singleton_method",
        b"singleton_methods", b"tap", b"then", b"to_a", b"to_c", b"to_d", b"to_enum", b"to_f", b"to_h", b"to_i",
        b"to_r", b"to_s", b"yield_self", b"|",
    ];
    METHODS.iter().any(|&m| m == name)
}


/// Finds (or lazily creates) `key`'s slot in an ordered `names` map mirroring
/// rubocop's `Hash.new(0)` (`CommentConfig#extra_enabled_comments`'
/// `disable_count`). A cop-specific key (has a `/`) that is `Enabled: false`
/// in the effective config is seeded at count 1 — mirroring
/// `registry.disabled(config).each { |cop| disable_count[cop.cop_name] += 1
/// }`, which runs BEFORE any directive is read. A bare department key (no
/// `/`) is never config-pre-disabled this way in real rubocop (that hash is
/// built from actual Cop classes, never department names), so it always
/// starts at 0. Reuses `mced_cop_enabled` (defined above for
/// `Lint/MissingCopEnableDirective`) for the same "ignore the oracle
/// harness's injected `AllCops: DisabledByDefault`" reasoning documented
/// there.
fn rce_slot(names: &mut Vec<(String, i32)>, cfg: &crate::config::Config, key: &str) -> usize {
    if let Some(i) = names.iter().position(|(k, _)| k == key) {
        return i;
    }
    let seed = if key.contains('/') && !mced_cop_enabled(cfg, key) { 1 } else { 0 };
    names.push((key.to_string(), seed));
    names.len() - 1
}

/// `DirectiveComment#cop_name_indention`'s Rust equivalent:
/// `comment.text.index(/#{Regexp.escape(name)}(?!\w)/)`. Finds the first
/// occurrence of `name` in `text` that isn't immediately followed by a
/// word character — so a shorter name isn't matched inside a longer one
/// that shares its PREFIX (`Layout/EmptyLines` inside
/// `Layout/EmptyLinesAfterModuleInclusion`). No leading-boundary check is
/// made, matching upstream (a name that's a SUFFIX of another isn't
/// guarded against either — not exercised by the fixture).
fn rce_find_name(text: &[u8], name: &str) -> Option<usize> {
    let needle = name.as_bytes();
    if needle.is_empty() {
        return None;
    }
    (0..=text.len().saturating_sub(needle.len())).find(|&i| {
        &text[i..i + needle.len()] == needle
            && !text.get(i + needle.len()).is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_')
    })
}

/// `SurroundingSpace#reposition`/`RangeHelp#range_with_comma`'s comma-aware
/// removal range for ONE redundant name inside a multi-name directive
/// (`register_offense`'s `range_with_comma` branch, reached when
/// `directive.match?(cop_names)` is false — i.e. some OTHER name in the same
/// comment is still necessary). Widens `name`'s own span over adjacent
/// spaces/tabs (never newlines) in both directions, then removes through
/// whichever comma sits on either side of that widened span — trimming the
/// leading space too UNLESS the list has no space after that comma (so a
/// single separating space survives either way). Returns byte offsets
/// relative to `text` (the comment's own source slice, offset 0 == its `#`).
fn rce_remove_with_comma(text: &[u8], name: &str) -> Option<(usize, usize)> {
    let mut begin_pos = rce_find_name(text, name)?;
    let mut end_pos = begin_pos + name.len();
    while begin_pos > 0 && matches!(text[begin_pos - 1], b' ' | b'\t') {
        begin_pos -= 1;
    }
    while end_pos < text.len() && matches!(text[end_pos], b' ' | b'\t') {
        end_pos += 1;
    }
    if begin_pos > 0 && text[begin_pos - 1] == b',' {
        // `range_with_comma_before`: comma through the (trimmed) name end.
        Some((begin_pos - 1, end_pos))
    } else if end_pos < text.len() && text[end_pos] == b',' {
        // `range_with_comma_after`: (trimmed) name start through the comma,
        // keeping the leading space when there's no space after the comma
        // either (so exactly one separating space survives either way).
        let mut bp = begin_pos;
        if !matches!(text.get(end_pos + 1), Some(b' ')) {
            bp += 1;
        }
        Some((bp, end_pos + 1))
    } else {
        // `range_between(start, comment.source_range.end_pos)`: no comma
        // neighbor at all, i.e. `name` had no other item alongside it in
        // the directive's OWN written text. Removes only the comment's own
        // text (not the trailing newline) — reached for a bare department
        // token that's the directive's sole written item but ISN'T fully
        // redundant once a same-department specific cop (never repeated in
        // this directive) is still legitimately open (see `full_match`'s
        // department-sibling check above), leaving a blank line behind.
        Some((0, text.len()))
    }
}

/// `SurroundingSpace#range_with_surrounding_space(directive.range, side:
/// :right)`: the whole-directive removal used when EVERY name in the
/// comment is redundant (`directive.match?(cop_names)`). `directive.range`
/// is approximated as the whole comment span (true whenever the comment is
/// nothing but the directive itself, as in every fixture example — no
/// trailing `-- reason` prose). Expands rightward over spaces/tabs, then
/// over ALL consecutive newlines (upstream's `final_pos` loops one `\n` at
/// a time but doesn't stop after the first).
fn rce_remove_whole(src: &[u8], start: usize, end: usize) -> (usize, usize) {
    let mut e = end;
    while e < src.len() && matches!(src[e], b' ' | b'\t') {
        e += 1;
    }
    while e < src.len() && src[e] == b'\n' {
        e += 1;
    }
    (start, e)
}

impl<'a> Cops<'a> {
    /// Lint/RedundantCopEnableDirective — a `# rubocop:enable` naming a cop
    /// (or department, or `all`) that ISN'T currently disabled at that point
    /// is dead text. Ported from `CommentConfig#extra_enabled_comments`
    /// (`handle_switch`/`handle_enable_all`) + the cop's own
    /// `register_offense`/`range_of_offense`/`range_with_comma`.
    ///
    /// Unlike `Lint/MissingCopEnableDirective` above, this check is
    /// independent of the push/pop stack machinery entirely — upstream's
    /// `extra_enabled_comments` walks `each_directive` with a single flat
    /// `names` counter, skipping `push`/`pop` outright.
    ///
    /// Deliberate simplification (same category as `MissingEnableAnalysis`'s
    /// department handling above, and just as observably invisible): a bare
    /// department name (`# rubocop:disable Layout`) is tracked as ONE
    /// pseudo-entry keyed by the department name itself, instead of being
    /// expanded into every individual cop in that department (this engine
    /// doesn't carry the full ~500-cop registry needed to do that). This is
    /// observably IDENTICAL for every case the fixture exercises: whenever
    /// upstream's per-cop expansion would flag SOME (not all) of a
    /// department's cops as extra, EVERY one of those offenses collapses via
    /// `register_offense`'s `department?`-triggered shortening (`name =
    /// name.split('/').first`) to the SAME message at the SAME location
    /// (the literal department text in the comment) — and `Cop::Base
    /// #add_offense`'s location dedup then collapses them to the one offense
    /// our coarser model reports directly. The one scenario this can't
    /// reproduce (not in the fixture): a department fully covered by
    /// disabling EVERY individual cop in it one-by-one (rather than via one
    /// bare `# rubocop:disable Layout`) would upstream-correctly treat a
    /// later `# rubocop:enable Layout` as non-redundant; this simplified
    /// model, never having set the bare "Layout" key, would flag it as
    /// redundant. (The mirror-image interaction — a bare-department enable
    /// where ONE specific same-department cop is still legitimately open —
    /// IS handled: see the `full_match` department-sibling check below,
    /// needed because it changes which CORRECTION range applies even though
    /// the reported offense itself is identical either way.)
    ///
    /// `# rubocop:disable all` / `# rubocop:todo all` are also not tracked
    /// (upstream expands `all` into literally every registry cop even for a
    /// *disable*, via `directive.cop_names`, which isn't reproducible here).
    /// This can only under-report (missing a "was genuinely still open"
    /// case for a later specific-cop enable) — not exercised by the fixture,
    /// which never disables via bare `all`.
    pub(crate) fn check_redundant_cop_enable_directive(&mut self) {
        const COP: &str = "Lint/RedundantCopEnableDirective";
        if !self.on(COP) {
            return;
        }
        // `!processed_source.raw_source.include?('enable')` fast-path.
        if !self.src.windows(6).any(|w| w == b"enable") {
            return;
        }

        static RE: OnceLock<regex::Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            // unanchored — see the twin regex in check_missing_cop_enable_directive
            regex::Regex::new(r"#\s*rubocop\s*:\s*(disable|todo|enable|push|pop)\b\s*(.*)$")
                .unwrap()
        });

        // `Hash.new(0)`, insertion-ordered (only a handful of entries ever
        // exist, so a linear-scan-backed vec is plenty — same idiom as
        // `MissingEnableAnalysis`'s `analyses` above).
        let mut names: Vec<(String, i32)> = Vec::new();

        // One record per comment that ends up with at least one redundant
        // name: its own span, every name it lists (written order, for the
        // `directive.match?` all-redundant check), and the subset that's
        // redundant (written order).
        struct Rec {
            start: usize,
            end: usize,
            extra: Vec<String>,
            full_match: bool,
        }
        let mut recs: Vec<Rec> = Vec::new();

        for &(line, start, end) in self.comments {
            let text = String::from_utf8_lossy(&self.src[start..end]);
            let Some(caps) = re.captures(&text) else { continue };
            if directive_commented_out(&text[..caps.get(0).unwrap().start()]) {
                continue;
            }
            let mode = caps.get(1).unwrap().as_str();
            if mode == "push" || mode == "pop" {
                continue;
            }
            // `comment_only_line?`: nothing but whitespace precedes the `#`
            // on this physical line — a directive sharing its line with
            // real code doesn't participate in this check at all (unlike
            // `Lint/MissingCopEnableDirective`, which still tracks a
            // trailing single-line disable).
            let standalone =
                self.src[self.idx.starts[line - 1]..start].iter().all(u8::is_ascii_whitespace);
            if !standalone {
                continue;
            }
            let rest = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            // a ` -- reason` trailer is prose, not part of the cop list
            let cops_part = rest.split(" -- ").next().unwrap_or(rest).trim();
            let Some(cops_part) = directive_cops_prefix(cops_part) else { continue };
            let disabling = mode == "disable" || mode == "todo";

            if cops_part == "all" {
                if disabling {
                    // `disable all`/`todo all` — see doc comment: not tracked.
                    continue;
                }
                // `handle_enable_all`: close every currently-open name;
                // redundant only if NONE were open.
                let mut enabled_cops = 0;
                for (_, count) in names.iter_mut() {
                    if *count > 0 {
                        *count -= 1;
                        enabled_cops += 1;
                    }
                }
                if enabled_cops == 0 {
                    // `directive.match?(["all"])`: `parsed_cop_names` for an
                    // `all` directive is `["all"]` too (`"all"` isn't itself
                    // a registered department) — always a full match.
                    recs.push(Rec { start, end, extra: vec!["all".to_string()], full_match: true });
                }
                continue;
            }

            let raw_tokens: Vec<String> = cops_part
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if disabling {
                for tok in &raw_tokens {
                    let i = rce_slot(&mut names, self.cfg, tok);
                    names[i].1 += 1;
                }
            } else {
                let mut extra = Vec::new();
                for tok in &raw_tokens {
                    let i = rce_slot(&mut names, self.cfg, tok);
                    if names[i].1 > 0 {
                        names[i].1 -= 1;
                    } else {
                        extra.push(tok.clone());
                    }
                }
                if !extra.is_empty() {
                    // `directive.match?(cop_names)`: true only when EVERY
                    // cop the directive really covers (after upstream's
                    // department expansion, which this engine's coarser
                    // per-token model doesn't replicate) ended up extra. A
                    // bare department token collapses ~90 individual cops
                    // into one pseudo-entry (see the doc comment above) —
                    // but if some OTHER already-tracked specific cop in that
                    // same department is STILL currently disabled (its own
                    // count > 0, meaning upstream's expansion would have
                    // silently consumed it as the one legitimately-needed
                    // enable), the directive only PARTIALLY matches even
                    // though this token's own pseudo-entry looks fully
                    // redundant — downgrade to the per-name removal path.
                    let mut a = raw_tokens.clone();
                    a.sort();
                    a.dedup();
                    let mut b = extra.clone();
                    b.sort();
                    b.dedup();
                    let mut full_match = a == b;
                    if full_match {
                        for tok in &raw_tokens {
                            if tok.contains('/') {
                                continue;
                            }
                            let prefix = format!("{tok}/");
                            if names.iter().any(|(k, c)| *c > 0 && k.starts_with(&prefix)) {
                                full_match = false;
                                break;
                            }
                        }
                    }
                    recs.push(Rec { start, end, extra, full_match });
                }
            }
        }

        // `Cop::Base#add_offense`'s `current_offense_locations.add?` dedup.
        let mut emitted: HashSet<usize> = HashSet::new();
        for rec in &recs {
            let comment_text = &self.src[rec.start..rec.end];
            for name in &rec.extra {
                let Some(rel) = rce_find_name(comment_text, name) else { continue };
                let abs_start = rec.start + rel;
                if !emitted.insert(abs_start) {
                    continue;
                }
                let display = if name == "all" { "all cops".to_string() } else { name.clone() };
                self.push(abs_start, COP, true, format!("Unnecessary enabling of {display}."));
            }

            if rec.full_match {
                let (fstart, fend) = rce_remove_whole(self.src, rec.start, rec.end);
                self.fixes.push((fstart, fend, Vec::new()));
            } else {
                for name in &rec.extra {
                    if let Some((rs, re_)) = rce_remove_with_comma(comment_text, name) {
                        self.fixes.push((rec.start + rs, rec.start + re_, Vec::new()));
                    }
                }
            }
        }
    }
}


/// `Dir.glob(...)`/`Dir[...]` — a bare `Dir` or root `::Dir` receiver, per
/// `def_node_matcher`'s `{nil? cbase}` (bare constant or `::`-rooted, never a
/// namespaced one like `Foo::Dir`).
fn ndro_dir_recv(node: &ruby_prism::Node) -> bool {
    const_name_root(node).as_deref() == Some("Dir")
}

/// `unsorted_dir_block?` — the call ITSELF is `Dir.glob(...)`; a block or
/// block-pass attaches directly, with no intervening `.each`.
fn ndro_dir_glob_call(call: &ruby_prism::CallNode) -> bool {
    call.name().as_slice() == b"glob" && call.receiver().is_some_and(|r| ndro_dir_recv(&r))
}

/// `unsorted_dir_each?` — the call is `.each` chained onto `Dir[...]` or
/// `Dir.glob(...)`.
fn ndro_dir_each_call(call: &ruby_prism::CallNode) -> bool {
    if call.name().as_slice() != b"each" {
        return false;
    }
    let Some(recv) = call.receiver() else { return false };
    let Some(recv_call) = recv.as_call_node() else { return false };
    matches!(recv_call.name().as_slice(), b"[]" | b"glob")
        && recv_call.receiver().is_some_and(|r| ndro_dir_recv(&r))
}

/// `method_require?` — a block-pass (`&expr`) wrapping `method(:require)` or
/// `method(:require_relative)`.
fn ndro_method_require_pass(barg: &ruby_prism::BlockArgumentNode) -> bool {
    let Some(expr) = barg.expression() else { return false };
    let Some(inner) = expr.as_call_node() else { return false };
    if inner.receiver().is_some() || inner.name().as_slice() != b"method" {
        return false;
    }
    let Some(args) = inner.arguments() else { return false };
    let items: Vec<_> = args.arguments().iter().collect();
    items.len() == 1
        && items[0]
            .as_symbol_node()
            .is_some_and(|s| matches!(s.unescaped(), b"require" | b"require_relative"))
}

/// The block's loop-variable candidate names. An explicit `|var|` — exactly
/// one plain required param, nothing else, matching upstream's
/// `def_node_matcher :loop_variable, "(args (arg $_))"` — yields that one
/// name. Numbered params (`_1`, `_2`, ...) yield every numbered name up to
/// the block's `maximum`, mirroring `on_numblock`'s
/// `node.argument_list.filter { ... }` (each candidate checked
/// independently; any one being required is enough). Anything else (zero
/// params, splat/optional/keyword/destructured args) yields no candidates,
/// same as upstream's silent non-match — `it`-params are never reached here
/// since they require Ruby 3.4+ and this cop is gated to `<= 2.7`.
fn ndro_loop_var_names(params: Option<ruby_prism::Node>) -> Vec<Vec<u8>> {
    let Some(p) = params else { return Vec::new() };
    if let Some(np) = p.as_numbered_parameters_node() {
        return (1..=np.maximum()).map(|i| format!("_{i}").into_bytes()).collect();
    }
    let Some(bp) = p.as_block_parameters_node() else { return Vec::new() };
    let Some(pp) = bp.parameters() else { return Vec::new() };
    if pp.requireds().len() != 1
        || pp.optionals().len() != 0
        || pp.rest().is_some()
        || pp.posts().len() != 0
        || pp.keywords().len() != 0
        || pp.keyword_rest().is_some()
        || pp.block().is_some()
    {
        return Vec::new();
    }
    pp.requireds()
        .iter()
        .next()
        .and_then(|n| n.as_required_parameter_node())
        .map(|rp| vec![rp.name().as_slice().to_vec()])
        .unwrap_or_default()
}

/// `var_is_required?` — recursively searches `body` (if/else nesting and
/// deeper included, like upstream's `def_node_search`) for
/// `require(var)`/`require_relative(var)` where `var` is a bare local-
/// variable read matching `var` by name.
fn ndro_var_is_required(body: &ruby_prism::Node, var: &[u8]) -> bool {
    struct Finder<'h> {
        var: &'h [u8],
        found: bool,
    }
    impl<'pr, 'h> ruby_prism::Visit<'pr> for Finder<'h> {
        fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
            if self.found {
                return;
            }
            if node.receiver().is_none() && matches!(node.name().as_slice(), b"require" | b"require_relative") {
                if let Some(args) = node.arguments() {
                    let items: Vec<_> = args.arguments().iter().collect();
                    if items.len() == 1 {
                        if let Some(lvar) = items[0].as_local_variable_read_node() {
                            if lvar.name().as_slice() == self.var {
                                self.found = true;
                                return;
                            }
                        }
                    }
                }
            }
            ruby_prism::visit_call_node(self, node);
        }
    }
    let mut finder = Finder { var, found: false };
    use ruby_prism::Visit;
    finder.visit(body);
    finder.found
}

/// The "logical send" range — receiver through the end of the call's own
/// arguments/parens, EXCLUDING any attached `do...end`/`{}` block (whose
/// prism `CallNode::location` otherwise extends through the block's `end`).
/// A block-pass (`&expr`) never extends `location()` past the closing paren,
/// so this only matters for the real-block case.
fn ndro_call_range_no_block(call: &ruby_prism::CallNode) -> (usize, usize) {
    let start = call.location().start_offset();
    let end = if let Some(closing) = call.closing_loc() {
        closing.end_offset()
    } else if let Some(args) = call.arguments() {
        args.location().end_offset()
    } else if let Some(m) = call.message_loc() {
        m.end_offset()
    } else {
        call.location().end_offset()
    };
    (start, end)
}

impl<'a> super::Cops<'a> {
    /// Lint/NonDeterministicRequireOrder — `Dir[...]`/`Dir.glob(...)` make no
    /// ordering guarantee; requiring the results without `.sort` first can
    /// load files in a different order (and fail differently) across
    /// operating systems/filesystems. `Dir.glob`/`Dir[]` sort by default
    /// starting in Ruby 3.0, so upstream disables the ENTIRE cop above that
    /// (`maximum_target_ruby_version 2.7`) — nothing below ever runs once
    /// `TargetRubyVersion > 2.7`.
    pub(crate) fn check_non_deterministic_require_order(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/NonDeterministicRequireOrder";
        if !self.on(COP) || self.cfg.target_ruby() > 2.7 {
            return;
        }
        let Some(b) = node.block() else { return };
        if let Some(block) = b.as_block_node() {
            self.ndro_check_block(node, &block);
        } else if let Some(barg) = b.as_block_argument_node() {
            self.ndro_check_block_pass(node, &barg);
        }
    }

    /// `on_block`/`on_numblock` — offense anchors on the call the block
    /// attaches to (`Dir.glob(...)` itself, or the `.each` chained onto
    /// `Dir[...]`/`Dir.glob(...)`); `correct_block`'s two branches replace
    /// that same span with either its own source or its receiver's source,
    /// plus `.sort.each`.
    fn ndro_check_block(&mut self, call: &ruby_prism::CallNode, block: &ruby_prism::BlockNode) {
        const COP: &str = "Lint/NonDeterministicRequireOrder";
        let is_glob_block = ndro_dir_glob_call(call);
        let is_each = ndro_dir_each_call(call);
        if !is_glob_block && !is_each {
            return;
        }
        let Some(body) = block.body() else { return };
        let names = ndro_loop_var_names(block.parameters());
        if names.is_empty() || !names.iter().any(|n| ndro_var_is_required(&body, n)) {
            return;
        }
        let anchor = call.location().start_offset();
        self.push(anchor, COP, true, "Sort files before requiring them.");
        let (start, end) = ndro_call_range_no_block(call);
        let mut repl = Vec::new();
        if is_glob_block {
            repl.extend_from_slice(&self.src[start..end]);
        } else {
            // `unsorted_dir_each?` matched, so a receiver is guaranteed.
            let rl = call.receiver().expect("each-chain has a receiver").location();
            repl.extend_from_slice(&self.src[rl.start_offset()..rl.end_offset()]);
        }
        repl.extend_from_slice(b".sort.each");
        self.fixes.push((start, end, repl));
    }

    /// `on_block_pass` — offense anchors on the whole call carrying the
    /// block-pass (`Dir.glob(pattern, &method(:require))` or
    /// `Dir[...].each(&method(:require))`). `correct_block_pass`'s two
    /// branches: the direct-glob form moves `&method(...)` out past a new
    /// `.sort.each(...)`; the `.each`-chain form just renames the selector.
    fn ndro_check_block_pass(&mut self, call: &ruby_prism::CallNode, barg: &ruby_prism::BlockArgumentNode) {
        const COP: &str = "Lint/NonDeterministicRequireOrder";
        if !ndro_method_require_pass(barg) {
            return;
        }
        let is_glob_pass = ndro_dir_glob_call(call);
        let is_each_pass = ndro_dir_each_call(call);
        if !is_glob_pass && !is_each_pass {
            return;
        }
        let anchor = call.location().start_offset();
        self.push(anchor, COP, true, "Sort files before requiring them.");
        if is_glob_pass {
            let barg_loc = barg.location();
            let prev_end = call
                .arguments()
                .and_then(|a| a.arguments().iter().last())
                .map(|n| n.location().end_offset())
                .unwrap_or_else(|| barg_loc.start_offset());
            self.fixes.push((prev_end, barg_loc.end_offset(), Vec::new()));
            let call_end = call.location().end_offset();
            let mut ins = b".sort.each(".to_vec();
            ins.extend_from_slice(&self.src[barg_loc.start_offset()..barg_loc.end_offset()]);
            ins.push(b')');
            self.fixes.push((call_end, call_end, ins));
        } else if let Some(sel) = call.message_loc() {
            self.fixes.push((sel.start_offset(), sel.end_offset(), b"sort.each".to_vec()));
        }
    }
}


// Lint/FormatParameterMismatch: mirrors `RuboCop::Cop::Utils::FormatString`
// (a hand-rolled port of its `SEQUENCE` regex — Rust's `regex` crate rejects
// duplicate named capture groups across alternation branches and has no
// lookbehind, both of which the original pattern relies on) plus the cop's
// own `count_matches`/`offending_node?` bookkeeping. No autocorrector.

/// One match of `RuboCop::Cop::Utils::FormatString::SEQUENCE` — byte offsets
/// into the format-string's own RAW source slice (quotes/interpolation
/// markers included, matching Ruby's `node.source`, since dstr nodes must
/// see their literal `#{...}` text rather than an evaluated/unescaped value).
struct CfpmSeq {
    start: usize,
    end: usize,
    has_name: bool,
    is_percent: bool,
}

fn cfpm_is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `FLAG = /[ #0+-]|(?<arg_number>\d+)\$/` repeated (`FLAG*`), returned as
/// every prefix-length end position (0 reps first) so callers can backtrack
/// from the greedy (longest) match down to shorter ones, exactly as Onigmo
/// would when a longer flags run leads to an overall match failure (e.g.
/// `%#{padding}s`, where the bare `#` must NOT be swallowed as a flag so the
/// `#{...}` interpolation can be recognized as a dynamic WIDTH instead).
fn cfpm_flag_positions(s: &[u8], start: usize) -> Vec<usize> {
    let mut positions = vec![start];
    let mut pos = start;
    loop {
        if pos < s.len() && matches!(s[pos], b' ' | b'#' | b'0' | b'+' | b'-') {
            pos += 1;
            positions.push(pos);
            continue;
        }
        if pos < s.len() && s[pos].is_ascii_digit() {
            let mut j = pos;
            while j < s.len() && s[j].is_ascii_digit() {
                j += 1;
            }
            if j < s.len() && s[j] == b'$' {
                pos = j + 1;
                positions.push(pos);
                continue;
            }
        }
        break;
    }
    positions
}

/// `NUMBER = /\d+|\*(?:\d+\$)?|\#\{.*?\}/` — used for both WIDTH and (after
/// the leading `.`) PRECISION.
fn cfpm_parse_number(s: &[u8], pos: usize) -> Option<usize> {
    if pos >= s.len() {
        return None;
    }
    if s[pos].is_ascii_digit() {
        let mut j = pos;
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        return Some(j);
    }
    if s[pos] == b'*' {
        let mut j = pos + 1;
        if j < s.len() && s[j].is_ascii_digit() {
            let mut k = j;
            while k < s.len() && s[k].is_ascii_digit() {
                k += 1;
            }
            if k < s.len() && s[k] == b'$' {
                j = k + 1;
            }
        }
        return Some(j);
    }
    if s[pos] == b'#' && pos + 1 < s.len() && s[pos + 1] == b'{' {
        // Non-greedy `.*?` up to the first `}`.
        return s[pos + 2..].iter().position(|&b| b == b'}').map(|rel| pos + 2 + rel + 1);
    }
    None
}

/// `PRECISION = /\.(?<precision>NUMBER?)/` — the leading `.` is mandatory,
/// the NUMBER after it is not (`%.d` is a valid, empty-precision sequence).
fn cfpm_parse_precision(s: &[u8], pos: usize) -> Option<usize> {
    if pos < s.len() && s[pos] == b'.' {
        let after = pos + 1;
        return Some(cfpm_parse_number(s, after).unwrap_or(after));
    }
    None
}

/// `NAME = /<(?<name>\w+)>/` (the annotated `%<name>s` form).
fn cfpm_parse_name_angle(s: &[u8], pos: usize) -> Option<usize> {
    if pos < s.len() && s[pos] == b'<' {
        let mut j = pos + 1;
        let word_start = j;
        while j < s.len() && cfpm_is_word_byte(s[j]) {
            j += 1;
        }
        if j > word_start && j < s.len() && s[j] == b'>' {
            return Some(j + 1);
        }
    }
    None
}

/// `TEMPLATE_NAME = /(?<!\#)\{(?<name>\w+)\}/` (the `%{name}` form) — the
/// negative lookbehind keeps a preceding `#{` interpolation opener from
/// being mistaken for one.
fn cfpm_parse_template_name(s: &[u8], pos: usize) -> Option<usize> {
    if pos < s.len() && s[pos] == b'{' {
        if pos > 0 && s[pos - 1] == b'#' {
            return None;
        }
        let mut j = pos + 1;
        let word_start = j;
        while j < s.len() && cfpm_is_word_byte(s[j]) {
            j += 1;
        }
        if j > word_start && j < s.len() && s[j] == b'}' {
            return Some(j + 1);
        }
    }
    None
}

/// `TYPE = /(?<type>[bBdiouxXeEfgGaAcps])/`.
fn cfpm_parse_type(s: &[u8], pos: usize) -> Option<usize> {
    if pos < s.len()
        && matches!(
            s[pos],
            b'b' | b'B'
                | b'd'
                | b'i'
                | b'o'
                | b'u'
                | b'x'
                | b'X'
                | b'e'
                | b'E'
                | b'f'
                | b'g'
                | b'G'
                | b'a'
                | b'A'
                | b'c'
                | b'p'
                | b's'
        )
    {
        Some(pos + 1)
    } else {
        None
    }
}

/// The part of `SEQUENCE` after `% flags` — tries, in the source pattern's
/// alternation order:
///   1. `WIDTH? PRECISION? NAME? TYPE` (falling back to no-NAME if consuming
///      one leaves no valid TYPE, since NAME is optional here and the regex
///      would backtrack it away)
///   2. `WIDTH? NAME PRECISION? TYPE`
///   3. `NAME (more_flags=FLAG*) WIDTH? PRECISION? TYPE`
///   4. `WIDTH? PRECISION? TEMPLATE_NAME` (the `%{name}` sibling alternative,
///      which needs no TYPE)
/// Returns `(end_offset, has_name)`.
fn cfpm_match_after_flags(s: &[u8], pos: usize) -> Option<(usize, bool)> {
    {
        let mut p = pos;
        if let Some(e) = cfpm_parse_number(s, p) {
            p = e;
        }
        if let Some(e) = cfpm_parse_precision(s, p) {
            p = e;
        }
        let mut with_name = p;
        let mut has_name = false;
        if let Some(e) = cfpm_parse_name_angle(s, p) {
            with_name = e;
            has_name = true;
        }
        if has_name {
            if let Some(e) = cfpm_parse_type(s, with_name) {
                return Some((e, true));
            }
        }
        if let Some(e) = cfpm_parse_type(s, p) {
            return Some((e, false));
        }
    }
    {
        let mut p = pos;
        if let Some(e) = cfpm_parse_number(s, p) {
            p = e;
        }
        if let Some(e) = cfpm_parse_name_angle(s, p) {
            let mut p2 = e;
            if let Some(e2) = cfpm_parse_precision(s, p2) {
                p2 = e2;
            }
            if let Some(e3) = cfpm_parse_type(s, p2) {
                return Some((e3, true));
            }
        }
    }
    if let Some(e) = cfpm_parse_name_angle(s, pos) {
        for &fe in cfpm_flag_positions(s, e).iter().rev() {
            let mut p = fe;
            if let Some(w) = cfpm_parse_number(s, p) {
                p = w;
            }
            if let Some(pr) = cfpm_parse_precision(s, p) {
                p = pr;
            }
            if let Some(t) = cfpm_parse_type(s, p) {
                return Some((t, true));
            }
        }
    }
    {
        let mut p = pos;
        if let Some(e) = cfpm_parse_number(s, p) {
            p = e;
        }
        if let Some(e) = cfpm_parse_precision(s, p) {
            p = e;
        }
        if let Some(e) = cfpm_parse_template_name(s, p) {
            return Some((e, true));
        }
    }
    None
}

/// Tries `SEQUENCE` anchored at `pos` (`s[pos]` must be `%`). Returns
/// `(end_offset, has_name, is_percent)`.
fn cfpm_match_sequence_at(s: &[u8], pos: usize) -> Option<(usize, bool, bool)> {
    if pos + 1 < s.len() && s[pos + 1] == b'%' {
        return Some((pos + 2, false, true));
    }
    for &fe in cfpm_flag_positions(s, pos + 1).iter().rev() {
        if let Some((end, has_name)) = cfpm_match_after_flags(s, fe) {
            return Some((end, has_name, false));
        }
    }
    None
}

/// `@source.scan(SEQUENCE)` — every non-overlapping match, left to right.
fn cfpm_scan_sequences(s: &[u8]) -> Vec<CfpmSeq> {
    let mut i = 0;
    let mut out = Vec::new();
    while i < s.len() {
        if s[i] == b'%' {
            if let Some((end, has_name, is_percent)) = cfpm_match_sequence_at(s, i) {
                out.push(CfpmSeq { start: i, end, has_name, is_percent });
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// `FormatSequence#max_digit_dollar_num`: re-scans the SEQUENCE's own raw
/// text for `\d+\$` occurrences and returns the max (or `None`, matching
/// Ruby's `nil` for "no digit-dollar refs in this sequence").
fn cfpm_seq_max_digit_dollar(s: &[u8], seq: &CfpmSeq) -> Option<u64> {
    let text = &s[seq.start..seq.end];
    let mut max_val: Option<u64> = None;
    let mut i = 0;
    while i < text.len() {
        if text[i].is_ascii_digit() {
            let start = i;
            while i < text.len() && text[i].is_ascii_digit() {
                i += 1;
            }
            if i < text.len() && text[i] == b'$' {
                if let Ok(v) = std::str::from_utf8(&text[start..i]).unwrap_or("").parse::<u64>() {
                    max_val = Some(max_val.map_or(v, |m| m.max(v)));
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    max_val
}

/// `FormatSequence#arity`: `@source.scan('*').count + 1`.
fn cfpm_seq_arity(s: &[u8], seq: &CfpmSeq) -> i64 {
    s[seq.start..seq.end].iter().filter(|&&b| b == b'*').count() as i64 + 1
}

fn cfpm_is_str_or_dstr(node: &ruby_prism::Node) -> bool {
    node.as_string_node().is_some() || node.as_interpolated_string_node().is_some()
}

fn cfpm_is_const(node: &ruby_prism::Node) -> bool {
    node.as_constant_read_node().is_some() || node.as_constant_path_node().is_some()
}

fn cfpm_is_kernel_receiver(node: &ruby_prism::Node) -> bool {
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == b"Kernel";
    }
    if let Some(c) = node.as_constant_path_node() {
        return c.name().is_some_and(|n| n.as_slice() == b"Kernel");
    }
    false
}

fn cfpm_first_argument<'pr>(call: &ruby_prism::CallNode<'pr>) -> Option<ruby_prism::Node<'pr>> {
    call.arguments().and_then(|a| a.arguments().iter().next())
}

/// `called_on_string?`: `{(send {nil? const_type?} _ {str dstr} ...) (send
/// {str dstr} ...)}` — either the receiver is absent/a constant and the
/// FIRST ARGUMENT is a string, or the receiver itself is a string.
fn cfpm_called_on_string(call: &ruby_prism::CallNode) -> bool {
    let first_is_str = cfpm_first_argument(call).is_some_and(|n| cfpm_is_str_or_dstr(&n));
    match call.receiver() {
        None => first_is_str,
        Some(r) => {
            if cfpm_is_const(&r) {
                first_is_str
            } else {
                cfpm_is_str_or_dstr(&r)
            }
        }
    }
}

/// `format_method?`: shared by `format?`/`sprintf?`.
fn cfpm_format_method_named(call: &ruby_prism::CallNode, name: &[u8]) -> bool {
    if let Some(r) = call.receiver() {
        if cfpm_is_const(&r) && !cfpm_is_kernel_receiver(&r) {
            return false;
        }
    }
    if call.name().as_slice() != name {
        return false;
    }
    let Some(args) = call.arguments() else { return false };
    let list = args.arguments();
    if list.iter().count() <= 1 {
        return false;
    }
    let first = list.iter().next().unwrap();
    cfpm_is_str_or_dstr(&first)
}

fn cfpm_is_format(call: &ruby_prism::CallNode) -> bool {
    cfpm_format_method_named(call, b"format")
}

fn cfpm_is_sprintf(call: &ruby_prism::CallNode) -> bool {
    cfpm_format_method_named(call, b"sprintf")
}

/// `heredoc?(node)`: `node.first_argument.source[0, 2] == '<<'` — a plain
/// string/dstr checks its OPENING token (never `<<` unless it's a real
/// heredoc); any other node type falls back to its raw source slice (never
/// heredoc-shaped either, so this is just a defensive fallback).
fn cfpm_starts_with_shovel(node: &ruby_prism::Node) -> bool {
    if let Some(s) = node.as_string_node() {
        return s.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<"));
    }
    if let Some(d) = node.as_interpolated_string_node() {
        return d.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<"));
    }
    node.location().as_slice().starts_with(b"<<")
}

/// `percent?`.
fn cfpm_is_percent(call: &ruby_prism::CallNode) -> bool {
    if call.name().as_slice() != b"%" {
        return false;
    }
    let recv = call.receiver();
    let recv_is_str = recv.as_ref().is_some_and(cfpm_is_str_or_dstr);
    let first_arg_is_array = cfpm_first_argument(call).is_some_and(|n| n.as_array_node().is_some());
    if !(recv_is_str || first_arg_is_array) {
        return false;
    }
    if recv_is_str {
        if let Some(first) = cfpm_first_argument(call) {
            if cfpm_starts_with_shovel(&first) {
                return false;
            }
        }
    }
    true
}

fn cfpm_method_with_format_args(call: &ruby_prism::CallNode) -> bool {
    cfpm_is_sprintf(call) || cfpm_is_format(call) || cfpm_is_percent(call)
}

fn cfpm_format_string_applicable(call: &ruby_prism::CallNode) -> bool {
    cfpm_called_on_string(call) && cfpm_method_with_format_args(call)
}

/// `countable_format?`.
fn cfpm_countable_format(call: &ruby_prism::CallNode) -> bool {
    (cfpm_is_sprintf(call) || cfpm_is_format(call))
        && !cfpm_first_argument(call).is_some_and(|n| cfpm_starts_with_shovel(&n))
}

/// `countable_percent?`.
fn cfpm_countable_percent(call: &ruby_prism::CallNode) -> bool {
    cfpm_is_percent(call) && cfpm_first_argument(call).is_some_and(|n| n.as_array_node().is_some())
}

/// `expected_fields_count`.
fn cfpm_expected_fields_count(node: &ruby_prism::Node) -> Option<i64> {
    if !cfpm_is_str_or_dstr(node) {
        return None;
    }
    let src = node.location().as_slice();
    let seqs = cfpm_scan_sequences(src);
    if seqs.iter().any(|q| q.has_name) {
        return Some(1);
    }
    if let Some(m) = seqs.iter().filter_map(|q| cfpm_seq_max_digit_dollar(src, q)).max() {
        if m != 0 {
            return Some(m as i64);
        }
    }
    Some(seqs.iter().filter(|q| !q.is_percent).map(|q| cfpm_seq_arity(src, q)).sum())
}

/// `mixed_formats?` (via `FormatString#valid?`/`invalid_format_string?`).
fn cfpm_mixed_formats(src: &[u8], seqs: &[CfpmSeq]) -> bool {
    let mut kinds: Vec<u8> = Vec::new();
    for seq in seqs.iter().filter(|q| !q.is_percent) {
        let kind = if seq.has_name {
            0u8
        } else if cfpm_seq_max_digit_dollar(src, seq).is_some() {
            1u8
        } else {
            2u8
        };
        kinds.push(kind);
    }
    kinds.sort_unstable();
    kinds.dedup();
    kinds.len() > 1
}

/// `count_matches` — `(num_of_format_args, num_of_expected_fields)`, `None`
/// standing in for Ruby's `:unknown`.
fn cfpm_count_matches(call: &ruby_prism::CallNode) -> (Option<i64>, Option<i64>) {
    if cfpm_countable_format(call) {
        let args = call.arguments().expect("countable_format implies arguments");
        let list = args.arguments();
        let n = list.iter().count() as i64;
        let first = list.iter().next().expect("countable_format implies a first argument");
        (Some(n - 1), cfpm_expected_fields_count(&first))
    } else if cfpm_countable_percent(call) {
        let first = cfpm_first_argument(call).expect("countable_percent implies a first argument");
        let arr = first.as_array_node().expect("countable_percent implies an array first argument");
        let n = arr.elements().iter().count() as i64;
        let expected = call.receiver().as_ref().and_then(cfpm_expected_fields_count);
        (Some(n), expected)
    } else {
        (None, None)
    }
}

/// `splat_args?` — only applies to `format`/`sprintf` (the `%` operator's
/// own array literal is scanned as-is, splats included, by
/// `count_percent_matches`).
fn cfpm_splat_args(call: &ruby_prism::CallNode) -> bool {
    if cfpm_is_percent(call) {
        return false;
    }
    let Some(args) = call.arguments() else { return false };
    args.arguments().iter().skip(1).any(|a| a.as_splat_node().is_some())
}

/// `matched_arguments_count?`.
fn cfpm_matched_arguments_count(expected: i64, passed: i64) -> bool {
    if passed.is_negative() {
        expected < passed.abs()
    } else {
        expected != passed
    }
}

/// `offending_node?`.
fn cfpm_offending_node(call: &ruby_prism::CallNode) -> bool {
    if cfpm_splat_args(call) {
        return false;
    }
    let (num_args_opt, num_fields_opt) = cfpm_count_matches(call);
    let Some(num_args) = num_args_opt else { return false };
    let num_fields = num_fields_opt.unwrap_or(0);
    if num_fields == 0 {
        if let Some(first) = cfpm_first_argument(call) {
            if first.as_interpolated_string_node().is_some() || first.as_array_node().is_some() {
                return false;
            }
        }
    }
    cfpm_matched_arguments_count(num_fields, num_args)
}

/// `message`.
fn cfpm_message_text(call: &ruby_prism::CallNode) -> String {
    let (num_args, num_fields) = cfpm_count_matches(call);
    let method_name = if call.name().as_slice() == b"%" {
        "String#%".to_string()
    } else {
        String::from_utf8_lossy(call.name().as_slice()).into_owned()
    };
    format!(
        "Number of arguments ({}) to `{}` doesn't match the number of fields ({}).",
        num_args.unwrap_or(0),
        method_name,
        num_fields.unwrap_or(0)
    )
}

impl<'a> Cops<'a> {
    /// Lint/FormatParameterMismatch: `format`/`sprintf`/`String#%` where the
    /// number of passed arguments doesn't match the format string's field
    /// count — or where the format string itself mixes numbered, named and
    /// unnumbered sequences. No autocorrector.
    pub(crate) fn check_format_parameter_mismatch(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/FormatParameterMismatch";
        if !self.on(COP) {
            return;
        }
        // `on_send` never fires for `csend` (`&.`) unless a cop aliases
        // `on_csend`, which this one doesn't.
        if node.is_safe_navigation() {
            return;
        }
        if !cfpm_format_string_applicable(node) {
            return;
        }
        let Some(sel) = node.message_loc() else { return };

        let format_node = if cfpm_is_percent(node) {
            node.receiver().expect("percent? implies a receiver")
        } else {
            cfpm_first_argument(node).expect("format?/sprintf? implies a first argument")
        };
        let src = format_node.location().as_slice();
        let seqs = cfpm_scan_sequences(src);
        if cfpm_mixed_formats(src, &seqs) {
            self.push(
                sel.start_offset(),
                COP,
                false,
                "Format string is invalid because formatting sequence types (numbered, named or unnumbered) are mixed.",
            );
            return;
        }

        if !cfpm_offending_node(node) {
            return;
        }
        self.push(sel.start_offset(), COP, false, cfpm_message_text(node));
    }
}


// ---- Lint/OutOfRangeRegexpRef ---------------------------------------------
//
// Upstream tracks a single `@valid_ref` ivar (here: `Cops::oorr_valid_ref`,
// `Option<u32>` — `None` standing in for whitequark's `nil`) that gets
// updated every time a regexp literal is "matched" against something, and
// consulted every time a `$1`..`$9` numbered-backref read (prism's
// `NumberedReferenceReadNode`) is encountered. Node-processing ORDER is
// everything here — see the doc comments on each hook below for exactly
// when in the traversal it must fire, mirroring upstream's
// `on_send`/`after_send`/`on_when`/`on_in_pattern`/`on_nth_ref` callback
// timing (a "pre" callback fires at node-enter, before children are
// visited; an "after" callback fires once the node's own children have
// been fully visited).
//
// `on_match_with_lvasgn` (upstream's callback for `/regex/ =~ str` where
// `regex` has a named capture — whitequark elides the `=~` into a
// dedicated `match_with_lvasgn` node with NO nested `:send` node at all)
// has no dedicated hook here: prism instead wraps an ordinary `CallNode`
// (name `=~`, receiver the regexp) in a `MatchWriteNode`, and
// `ruby_prism::visit_match_write_node`'s default body dispatches straight
// into `visit_call_node` — so the `after_send`-equivalent hook below
// reproduces `check_regexp(node.children.first)` for free, calling
// `check_regexp` on the exact same regexp node upstream would.

const OORR_REGEXP_RECEIVER_METHODS: &[&[u8]] = &[b"=~", b"===", b"match"];
const OORR_REGEXP_ARGUMENT_METHODS: &[&[u8]] = &[
    b"=~",
    b"match",
    b"grep",
    b"gsub",
    b"gsub!",
    b"sub",
    b"sub!",
    b"[]",
    b"slice",
    b"slice!",
    b"index",
    b"rindex",
    b"scan",
    b"partition",
    b"rpartition",
    b"start_with?",
    b"end_with?",
];
// RESTRICT_ON_SEND: the union of the two method sets above — every such
// call resets `@valid_ref`, whether or not a regexp literal is actually
// involved.
const OORR_RESTRICT_ON_SEND: &[&[u8]] = &[
    b"=~",
    b"===",
    b"match",
    b"grep",
    b"gsub",
    b"gsub!",
    b"sub",
    b"sub!",
    b"[]",
    b"slice",
    b"slice!",
    b"index",
    b"rindex",
    b"scan",
    b"partition",
    b"rpartition",
    b"start_with?",
    b"end_with?",
];

fn oorr_is_regexp_node(node: &ruby_prism::Node) -> bool {
    node.as_regular_expression_node().is_some() || node.as_interpolated_regular_expression_node().is_some()
}

/// `pattern.each_descendant(:regexp).to_a` — every regexp literal anywhere
/// in `node`'s subtree (array/hash/alternative/pin `case/in` patterns can
/// nest a regexp arbitrarily deep), regardless of depth. Both prism regexp
/// node types stand in for whitequark's single `:regexp` node type (see the
/// module doc above for why `Lint/OutOfRangeRegexpRef` needs both).
fn oorr_regexp_descendants<'pr>(node: &ruby_prism::Node<'pr>) -> Vec<ruby_prism::Node<'pr>> {
    struct Finder<'pr> {
        found: Vec<ruby_prism::Node<'pr>>,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder<'pr> {
        fn visit_regular_expression_node(&mut self, node: &ruby_prism::RegularExpressionNode<'pr>) {
            self.found.push(node.as_node());
            ruby_prism::visit_regular_expression_node(self, node);
        }
        fn visit_interpolated_regular_expression_node(
            &mut self,
            node: &ruby_prism::InterpolatedRegularExpressionNode<'pr>,
        ) {
            self.found.push(node.as_node());
            ruby_prism::visit_interpolated_regular_expression_node(self, node);
        }
    }
    let mut f = Finder { found: Vec::new() };
    use ruby_prism::Visit;
    f.visit(node);
    f.found
}

/// Counts named vs. plain numbered capturing groups in a regexp pattern's
/// raw source bytes, mirroring the presence-scanning algorithm documented
/// on `scan_regexp_captures` above (`Lint/MixedRegexpCaptureTypes`) but
/// tallying group COUNTS rather than a mere presence bit — `check_regexp`
/// needs the exact number of named captures, since Onigmo semantics say
/// that once ANY named group exists in a pattern, the plain numbered groups
/// no longer participate in `$1`.."$9"` numbering at all (the named groups
/// alone are numbered, in order of appearance). A malformed/unbalanced
/// pattern (real rubocop's `regexp_parser` backend fails to parse it, so
/// `each_capture` yields nothing for either kind) reports `(0, 0)`, same as
/// `scan_regexp_captures`'s `(false, false)`.
fn oorr_count_captures(src: &[u8], extended: bool) -> (u32, u32) {
    let mut named_count: u32 = 0;
    let mut numbered_count: u32 = 0;
    let n = src.len();
    let mut i = 0usize;
    let mut class_depth: u32 = 0;
    let mut depth: i64 = 0;

    while i < n {
        let b = src[i];

        if b == b'\\' {
            i += 2;
            continue;
        }

        if class_depth > 0 {
            if b == b'[' && i + 1 < n && matches!(src[i + 1], b':' | b'.' | b'=') {
                let closer = [src[i + 1], b']'];
                match find_bytes(&src[i + 2..], &closer) {
                    Some(rel) => i += 2 + rel + 2,
                    None => i += 2,
                }
                continue;
            }
            if b == b'[' {
                class_depth += 1;
                i += 1;
                continue;
            }
            if b == b']' {
                class_depth -= 1;
                i += 1;
                continue;
            }
            i += 1;
            continue;
        }

        if b == b'[' {
            class_depth = 1;
            i += 1;
            if i < n && src[i] == b'^' {
                i += 1;
            }
            if i < n && src[i] == b']' {
                i += 1;
            }
            continue;
        }

        if extended && b == b'#' {
            while i < n && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if b == b')' {
            if depth == 0 {
                return (0, 0);
            }
            depth -= 1;
            i += 1;
            continue;
        }

        if b != b'(' {
            i += 1;
            continue;
        }

        if i + 1 >= n || src[i + 1] != b'?' {
            numbered_count += 1;
            depth += 1;
            i += 1;
            continue;
        }

        let j = i + 2;
        if j >= n {
            i = j;
            continue;
        }
        match src[j] {
            b'#' => {
                i = match find_bytes(&src[j + 1..], b")") {
                    Some(rel) => j + 1 + rel + 1,
                    None => n,
                };
            }
            b'<' if j + 1 < n && matches!(src[j + 1], b'=' | b'!') => {
                depth += 1;
                i = j + 2;
            }
            b'<' => {
                named_count += 1;
                depth += 1;
                i = match find_bytes(&src[j + 1..], b">") {
                    Some(rel) => j + 1 + rel + 1,
                    None => n,
                };
            }
            b'\'' => {
                named_count += 1;
                depth += 1;
                i = match find_bytes(&src[j + 1..], b"'") {
                    Some(rel) => j + 1 + rel + 1,
                    None => n,
                };
            }
            b':' | b'=' | b'!' | b'>' | b'~' => {
                depth += 1;
                i = j + 1;
            }
            _ => {
                let mut k = j;
                while k < n && src[k] != b':' && src[k] != b')' {
                    k += 1;
                }
                if k < n && src[k] == b':' {
                    depth += 1;
                    i = k + 1;
                } else if k < n {
                    i = k + 1;
                } else {
                    i = n;
                }
            }
        }
    }

    if depth != 0 || class_depth != 0 {
        return (0, 0);
    }

    (named_count, numbered_count)
}

impl<'a> super::Cops<'a> {
    /// `check_regexp`: `Some(count)` for a non-interpolated regexp literal
    /// (the named-capture count if positive, else the numbered-capture
    /// count), `None` for an interpolated one (`return if node.interpolation?`
    /// upstream — a `None` here always gets ASSIGNED into `@valid_ref`
    /// as-is by every caller, same as upstream leaving `@valid_ref` at
    /// whatever `check_regexp`'s early `return` (i.e. `nil`) produced).
    fn oorr_capture_count(&self, node: &ruby_prism::Node) -> Option<u32> {
        if node.as_interpolated_regular_expression_node().is_some() {
            return None;
        }
        let regex = node.as_regular_expression_node()?;
        let content_loc = regex.content_loc();
        let src = &self.src[content_loc.start_offset()..content_loc.end_offset()];
        let (named, numbered) = oorr_count_captures(src, regex.is_extended());
        Some(if named > 0 { named } else { numbered })
    }

    /// `after_send`/`after_csend` (aliased in upstream to the same method):
    /// fires for every `RESTRICT_ON_SEND` call (the union of
    /// `OORR_REGEXP_RECEIVER_METHODS` and `OORR_REGEXP_ARGUMENT_METHODS|)
    /// REGARDLESS of whether it turns out to touch a regexp literal —
    /// `@valid_ref` is unconditionally reset to `None` first, so an
    /// intervening non-regexp call (e.g. `foo.match(some_regexp_variable)`)
    /// invalidates any earlier regexp's capture count, then re-derived from
    /// THIS call's own regexp-literal first-argument/receiver if it has
    /// one (first-argument takes priority, matching upstream's
    /// `if regexp_first_argument? ... elsif regexp_receiver?`).
    ///
    /// Must be called from `visit_call_node` AFTER the receiver and
    /// arguments have been visited but BEFORE any attached block — see the
    /// call site's own comment for why.
    pub(crate) fn check_out_of_range_regexp_ref_after_send(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/OutOfRangeRegexpRef";
        if !self.on(COP) {
            return;
        }
        let name = node.name().as_slice();
        if !OORR_RESTRICT_ON_SEND.contains(&name) {
            return;
        }
        self.oorr_valid_ref = None;
        let first_argument = node.arguments().and_then(|a| a.arguments().iter().next());
        if let Some(arg) = &first_argument {
            if OORR_REGEXP_ARGUMENT_METHODS.contains(&name) && oorr_is_regexp_node(arg) {
                self.oorr_valid_ref = self.oorr_capture_count(arg);
                return;
            }
        }
        if let Some(recv) = node.receiver() {
            if OORR_REGEXP_RECEIVER_METHODS.contains(&name) && oorr_is_regexp_node(&recv) {
                self.oorr_valid_ref = self.oorr_capture_count(&recv);
            }
        }
    }

    /// `on_when`: the max capture-count across every REGEXP-LITERAL
    /// condition of a `when` clause (non-regexp conditions, e.g. a plain
    /// variable, are ignored entirely — they don't even reset the state).
    /// Must run BEFORE the clause's conditions/body are visited. An
    /// interpolated regexp condition contributes nothing (`oorr_capture_count`
    /// returns `None`, filtered out); if NO condition ends up contributing
    /// (including "there were no regexp conditions at all"), `@valid_ref`
    /// becomes `None` (an empty iterator's `.max()` is `None`) — NOT `0`.
    pub(crate) fn check_out_of_range_regexp_ref_when(&mut self, node: &ruby_prism::WhenNode) {
        const COP: &str = "Lint/OutOfRangeRegexpRef";
        if !self.on(COP) {
            return;
        }
        let conditions: Vec<ruby_prism::Node> = node.conditions().iter().collect();
        let max_count = conditions
            .iter()
            .filter(|c| oorr_is_regexp_node(c))
            .filter_map(|c| self.oorr_capture_count(c))
            .max();
        self.oorr_valid_ref = max_count;
    }

    /// `on_in_pattern`: same "max across contributing regexps" shape as
    /// `on_when`, but the regexp(s) come from `regexp_patterns` — either the
    /// `in` pattern itself (if it's a bare regexp literal) or every regexp
    /// anywhere in its subtree (array/hash/alternative/pin patterns etc.).
    /// Must run BEFORE the pattern/statements are visited.
    pub(crate) fn check_out_of_range_regexp_ref_in_pattern(&mut self, node: &ruby_prism::InNode) {
        const COP: &str = "Lint/OutOfRangeRegexpRef";
        if !self.on(COP) {
            return;
        }
        let pattern = node.pattern();
        let patterns: Vec<ruby_prism::Node> = if oorr_is_regexp_node(&pattern) {
            vec![pattern]
        } else {
            oorr_regexp_descendants(&pattern)
        };
        let max_count = patterns.iter().filter_map(|p| self.oorr_capture_count(p)).max();
        self.oorr_valid_ref = max_count;
    }

    /// `on_nth_ref`: `$1`..`$9` (and beyond) read against the capture count
    /// left by the most recently seen regexp. `None` means "no verdict —
    /// never offend" (upstream's `return if @valid_ref.nil?`); otherwise
    /// offend only if the backref number EXCEEDS the valid count (`$1`
    /// against a 1-capture regexp is fine; `$2` against it is not).
    pub(crate) fn check_out_of_range_regexp_ref_nth_ref(&mut self, node: &ruby_prism::NumberedReferenceReadNode) {
        const COP: &str = "Lint/OutOfRangeRegexpRef";
        if !self.on(COP) {
            return;
        }
        let Some(valid) = self.oorr_valid_ref else {
            return;
        };
        let backref = node.number();
        if backref <= valid {
            return;
        }
        let count = if valid == 0 { "no".to_string() } else { valid.to_string() };
        let group = if valid == 1 { "group" } else { "groups" };
        let msg = format!("${backref} is out of range ({count} regexp capture {group} detected).");
        self.push(node.location().start_offset(), COP, false, msg);
    }
}


/// Lint/RedundantSplatExpansion: which kind of node directly holds a given
/// splat — prism has no parent pointers, so `visit_array_node`/
/// `visit_call_node`/`visit_when_node`/`visit_rescue_node` mark this eagerly
/// (keyed by the splat's own start offset in `Cops::rse_ctx`) while they're
/// visiting the actual container, for `check_redundant_splat_expansion` to
/// read back once it reaches the splat itself.
#[derive(Clone, Copy)]
pub(crate) enum RseContainer {
    /// A real `[...]` or percent (`%w`/`%W`/`%i`/`%I`) array literal —
    /// upstream's `parent.array_type? && parent.loc.begin && parent.loc.end`
    /// (`part_of_an_array?`)/`bracketed?`.
    ArrayBracketed,
    /// The bracket-less `array` node prism (like the legacy parser gem)
    /// synthesizes around a bare splat used as the WHOLE value of a simple or
    /// multiple assignment RHS (`a = *x`, `a, b = *x`) — same `ArrayNode`
    /// shape as the real-literal case, just with no `opening_loc`.
    ArrayImplicit,
    /// A direct positional argument of a method call — upstream's
    /// `parent.call_type?` (`method_argument?`), true for both a plain call
    /// and a safe-navigation one.
    CallArg,
    /// A `when` clause condition — upstream's `parent.when_type?`.
    When,
    /// A `rescue` exception-class-list entry — upstream's
    /// `grandparent&.resbody_type?` (see `visit_rescue_node`'s doc: prism's
    /// flat `exceptions()` collapses that extra indirection away).
    Rescue,
}

/// See `RseContainer`'s doc.
#[derive(Clone, Copy)]
pub(crate) struct RseCtx {
    pub(crate) container: RseContainer,
    /// The container's own start offset — for `ArrayBracketed`/`ArrayImplicit`
    /// this is the array's `location()`; for the others, the container
    /// node's own `location()`. Compared against `top_level_sole_stmt` and
    /// looked up in `rse_assignment_value` to emulate upstream's `grandparent
    /// = node.parent.parent` gate on a splatted `Array.new(...)` call.
    pub(crate) container_start: usize,
    pub(crate) container_end: usize,
    /// Only meaningful when `container` is one of the two Array variants:
    /// the array's own element count, for upstream's
    /// `array_new_inside_array_literal?` sibling check.
    pub(crate) array_len: usize,
}

/// Lint/RedundantSplatExpansion's `array_new?`/`Array.new`-detector: a bare
/// (unqualified, `nil?`) or top-level-qualified (`::Array`, `cbase`)
/// `Array.new(...)` call, with or without a block attached (both shapes are
/// the SAME prism `CallNode`, unlike upstream's whitequark tree which wraps
/// the block-attached form in a separate `:block` node around an identical
/// `:send`).
fn rse_is_array_new_call(call: &ruby_prism::CallNode) -> bool {
    if call.name().as_slice() != b"new" {
        return false;
    }
    let Some(recv) = call.receiver() else { return false };
    recv.as_constant_read_node().is_some_and(|c| c.location().as_slice() == b"Array")
        || recv
            .as_constant_path_node()
            .is_some_and(|cp| cp.parent().is_none() && cp.name_loc().as_slice() == b"Array")
}

/// Lint/RedundantSplatExpansion's `remove_brackets`: renders a splatted
/// array literal's ELEMENTS as a bare comma-separated list, verbatim (byte
/// range) for a plain `[...]` array, or re-quoted for a percent literal
/// (`%w`/`%W`/`%i`/`%I`) whose elements carry no delimiter of their own.
fn rse_remove_brackets(cops: &Cops, arr: &ruby_prism::ArrayNode) -> Vec<u8> {
    let elements: Vec<&[u8]> = arr.elements().iter().map(|e| cops.node_src(&e)).collect();
    let opening = arr.opening_loc().map(|l| l.as_slice()).unwrap_or(b"[");
    let mut out = Vec::new();
    if opening.starts_with(b"%w") {
        out.push(b'\'');
        for (i, el) in elements.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b"', '");
            }
            out.extend_from_slice(el);
        }
        out.push(b'\'');
    } else if opening.starts_with(b"%W") {
        out.push(b'"');
        for (i, el) in elements.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b"\", \"");
            }
            out.extend_from_slice(el);
        }
        out.push(b'"');
    } else if opening.starts_with(b"%i") {
        out.push(b':');
        for (i, el) in elements.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b", :");
            }
            out.extend_from_slice(el);
        }
    } else if opening.starts_with(b"%I") {
        out.extend_from_slice(b":\"");
        for (i, el) in elements.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b"\", :\"");
            }
            out.extend_from_slice(el);
        }
        out.push(b'"');
    } else {
        for (i, el) in elements.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(el);
        }
    }
    out
}

impl<'a> Cops<'a> {
    /// Lint/RedundantSplatExpansion's `replacement_range_and_content`: given
    /// the splat and its (already-classified) expression, work out the
    /// autocorrect `(start, end, replacement)`. `expr` is one of the three
    /// shapes `check_redundant_splat_expansion` has already confirmed
    /// `literal_expansion` matches: an `Array.new(...)` call, a (non-empty)
    /// array literal, or a str/dstr/int/float scalar.
    fn rse_replacement(
        &self,
        node: &ruby_prism::SplatNode,
        expr: &ruby_prism::Node,
        ctx: Option<RseCtx>,
    ) -> (usize, usize, Vec<u8>) {
        let splat_range = node.location();

        if let Some(call) = expr.as_call_node().filter(rse_is_array_new_call) {
            // `expression = node.parent.source_range if node.parent.array_type?`
            // — widen the replace-range to swallow the enclosing array
            // (real brackets or the implicit assignment-RHS wrapper) too.
            let (start, end) = match ctx {
                Some(c @ RseCtx { container: RseContainer::ArrayBracketed, .. })
                | Some(c @ RseCtx { container: RseContainer::ArrayImplicit, .. }) => {
                    (c.container_start, c.container_end)
                }
                _ => (splat_range.start_offset(), splat_range.end_offset()),
            };
            return (start, end, self.node_src(&call.as_node()).to_vec());
        }

        if let Some(arr) = expr.as_array_node() {
            // `redundant_brackets?`: `parent.when_type? || method_argument? ||
            // part_of_an_array? || grandparent&.resbody_type?`.
            let redundant_brackets = matches!(
                ctx.map(|c| c.container),
                Some(RseContainer::When)
                    | Some(RseContainer::CallArg)
                    | Some(RseContainer::ArrayBracketed)
                    | Some(RseContainer::Rescue)
            );
            if redundant_brackets {
                let content = rse_remove_brackets(self, &arr);
                return (splat_range.start_offset(), splat_range.end_offset(), content);
            }
            // `[node.loc.operator, '']` — just the bare `*`, leaving the
            // array literal (or bracket-less implicit-assignment wrapper)
            // itself intact.
            let op = node.operator_loc();
            return (op.start_offset(), op.end_offset(), Vec::new());
        }

        // Scalar literal (str/dstr/int/float): `replacement = variable.source;
        // replacement = "[#{replacement}]" if wrap_in_brackets?(node)` —
        // `wrap_in_brackets?` = `node.parent.array_type? &&
        // !node.parent.bracketed?`, i.e. specifically the bracket-less
        // implicit-assignment wrapper (a REAL bracketed array never reaches
        // here un-wrapped, since it already has its own delimiters).
        let mut replacement = self.node_src(expr).to_vec();
        if matches!(ctx.map(|c| c.container), Some(RseContainer::ArrayImplicit)) {
            let mut wrapped = Vec::with_capacity(replacement.len() + 2);
            wrapped.push(b'[');
            wrapped.append(&mut replacement);
            wrapped.push(b']');
            replacement = wrapped;
        }
        (splat_range.start_offset(), splat_range.end_offset(), replacement)
    }

    /// Lint/RedundantSplatExpansion: flags `*expr` where `expr` is a literal
    /// whose splat is provably pointless — an array/percent-literal, a bare
    /// scalar (str/dstr/int/float), or an `Array.new(...)` call/block sitting
    /// somewhere upstream's `ASSIGNMENT_TYPES` grandparent check allows.
    ///
    /// Ported from `on_splat` + `redundant_splat_expansion` +
    /// `replacement_range_and_content` — see `RseContainer`'s doc for how the
    /// "parent"/"grandparent" AST-walk this cop relies on (impossible to do
    /// directly over prism's parent-less tree) is reconstructed from the
    /// eager `rse_ctx`/`rse_assignment_value` marks left by the container
    /// node's own visitor.
    pub(crate) fn check_redundant_splat_expansion(&mut self, node: &ruby_prism::SplatNode) {
        const COP: &str = "Lint/RedundantSplatExpansion";
        if !self.on(COP) {
            return;
        }
        let Some(expr) = node.expression() else { return };
        let splat_start = node.location().start_offset();
        let ctx = self.rse_ctx.get(&splat_start).copied();

        let array_expr = expr.as_array_node();
        let call_expr = expr.as_call_node().filter(|c| rse_is_array_new_call(c));
        let is_scalar_literal = expr.as_string_node().is_some()
            || expr.as_interpolated_string_node().is_some()
            || expr.as_integer_node().is_some()
            || expr.as_float_node().is_some();

        // `literal_expansion` didn't match at all (a plain variable/call
        // read, a range, a hash, ...) — nothing to say.
        if !is_scalar_literal && array_expr.is_none() && call_expr.is_none() {
            return;
        }

        // An empty array/percent literal (`*[]`, `*%w()`, ...) expands to
        // nothing, so removing the splat would change semantics.
        if let Some(arr) = &array_expr {
            if arr.elements().iter().count() == 0 {
                return;
            }
        }

        // The `expanded_item.send_type?` branch — ONLY reachable for an
        // `Array.new(...)` call/block, never for a plain literal.
        if call_expr.is_some() {
            // `array_new_inside_array_literal?`: `Array.new(...)` sitting
            // alongside 2+ siblings inside an array literal (bracketed OR
            // the implicit assignment/masgn-RHS wrapper) is accepted
            // outright, no matter what encloses that array.
            if let Some(c) = ctx {
                if matches!(c.container, RseContainer::ArrayBracketed | RseContainer::ArrayImplicit)
                    && c.array_len > 1
                {
                    return;
                }
            }
            // `grandparent = node.parent.parent; return if grandparent &&
            // !ASSIGNMENT_TYPES.include?(grandparent.type)` — fires only when
            // the splat's container is EITHER the whole top-level program (no
            // grandparent at all) or itself the direct value of a plain
            // single-variable assignment (masgn excluded, matching upstream).
            let grandparent_ok = match ctx {
                Some(c) => {
                    self.top_level_sole_stmt == Some(c.container_start)
                        || self.rse_assignment_value.contains(&c.container_start)
                }
                // No tracked container at all (e.g. a `return`/`yield`
                // argument list, which prism never array-wraps) — upstream's
                // grandparent there is never `nil` (always at least the
                // enclosing keyword node) and never an assignment type
                // either, so this always skips; the sole miss is the
                // vanishingly rare bare top-level `return *Array.new(...)`
                // with nothing else in the file.
                None => false,
            };
            if !grandparent_ok {
                return;
            }
        }

        let is_call_arg = matches!(ctx.map(|c| c.container), Some(RseContainer::CallArg));
        let is_bracketed_array = matches!(ctx.map(|c| c.container), Some(RseContainer::ArrayBracketed));
        // `array_splat?(node) = node.children.first.array_type?` — true only
        // when the splatted expression is ITSELF an array (not an
        // `Array.new` call, not a scalar).
        let array_splat = array_expr.is_some();

        if array_splat && (is_call_arg || is_bracketed_array) {
            // `use_percent_literal_array_argument?`: `method_argument?(node)
            // && (argument.percent_literal?(:string) ||
            // argument.percent_literal?(:symbol))` — deliberately
            // `method_argument?` only, NOT `part_of_an_array?`, so a percent
            // literal splatted as a sibling inside a real array literal is
            // never exempted by `AllowPercentLiteralArrayArgument`.
            if is_call_arg && self.cfg.get(COP, "AllowPercentLiteralArrayArgument") != Some("false") {
                if let Some(arr) = array_expr {
                    let is_percent_str_or_sym = arr.opening_loc().is_some_and(|l| {
                        let s = l.as_slice();
                        s.starts_with(b"%w") || s.starts_with(b"%W") || s.starts_with(b"%i") || s.starts_with(b"%I")
                    });
                    if is_percent_str_or_sym {
                        return;
                    }
                }
            }
            let (start, end, content) = self.rse_replacement(node, &expr, ctx);
            self.push(splat_start, COP, true, "Pass array contents as separate arguments.");
            self.fixes.push((start, end, content));
            return;
        }

        let (start, end, content) = self.rse_replacement(node, &expr, ctx);
        self.push(splat_start, COP, true, "Replace splat expansion with comma separated values.");
        self.fixes.push((start, end, content));
    }
}


// Lint/ShadowedException: a `rescue` clause that can never fire because a
// less-specific exception was already rescued earlier in the same chain, or
// because a single `rescue` clause lists two exceptions where one is an
// ancestor of the other (`rescue Exception, StandardError` behaves exactly
// like `rescue Exception` alone). Ported from rubocop's `ShadowedException`
// (`include RescueNode, RangeHelp`).
//
// Upstream's `on_rescue(node)` fires once per `:rescue` AST node — the WHOLE
// begin/def/block rescue chain (whitequark flattens every `resbody` sibling
// under one `:rescue` parent; prism instead links each clause via
// `RescueNode#subsequent`). We hook `visit_begin_node` (`BeginNode`, whose
// `rescue_clause()` is the head of that linked list) exactly like
// `Lint/DuplicateRescueException` does — NOT `visit_rescue_node`, which the
// default walk re-enters once per LINK and would score each chain multiple
// times. `BeginNode` also covers a `def`'s implicit rescue/ensure body,
// which prism wraps in a `BeginNode` even without an explicit `begin`
// keyword.
//
// The modifier form (`foo rescue nil`) upstream translates to the SAME
// `:rescue`/`:resbody` shape, so its `on_rescue` fires too — but a modifier
// rescue is always exactly one resbody with no exception class (implicit
// `StandardError`), so `rescue_group_rescues_multiple_levels` is always
// false and `sorted?` is trivially true (a single-group list has no
// `each_cons(2)` pairs): it can never produce an offense. There's no
// `RescueModifierNode` visitor hook here at all — that's the same outcome
// as replicating upstream's always-true-for-this-shape `rescue_modifier?`
// guard, without the dead code.
//
// Exception resolution: upstream calls `Kernel.const_get(exception.source)`
// to resolve each rescued name's RAW SOURCE TEXT to a live Ruby class,
// falling back to `nil` on `NameError` (undefined/custom names, method
// calls, splats, array literals — anything whose source text isn't a real
// top-level constant path). We can't load Ruby at lint time, so `shx_chain`
// hardcodes the static parent-chain table for every core Ruby exception
// class (`Class#superclass`, verbatim from a stock `ruby -e
// 'ObjectSpace.each_object(Class){|k| ... }'` dump — see table comment)
// plus a generic `Errno::<NAME>` rule (every `Errno::X` is a direct
// `SystemCallError` subclass, matching Ruby's dynamically-generated `Errno`
// namespace). Anything else resolves to `None`, exactly like a rescued
// `NameError`.
impl<'a> super::Cops<'a> {
    pub(crate) fn check_shadowed_exception(&mut self, node: &ruby_prism::BeginNode) {
        const COP: &str = "Lint/ShadowedException";
        if !self.on(COP) {
            return;
        }
        let Some(head) = node.rescue_clause() else { return };
        let mut rescues: Vec<ruby_prism::RescueNode> = Vec::new();
        let mut cur = Some(head);
        while let Some(r) = cur {
            cur = r.subsequent();
            rescues.push(r);
        }
        let groups: Vec<Vec<Option<&'a [u8]>>> =
            rescues.iter().map(|r| self.shx_evaluate_exceptions(r)).collect();

        let rescue_group_rescues_multiple_levels =
            groups.iter().any(|g| shx_contains_multiple_levels(g));
        if !rescue_group_rescues_multiple_levels && shx_sorted(&groups) {
            return;
        }
        if let Some(idx) = shx_find_shadowing(&groups) {
            let start = rescues[idx].keyword_loc().start_offset();
            self.push(start, COP, false, "Do not shadow rescued Exceptions.");
        }
    }

    /// `evaluate_exceptions`: a bare `rescue` (no exception list) behaves
    /// like `rescue StandardError`; otherwise resolve each listed
    /// exception's raw source text.
    fn shx_evaluate_exceptions(&self, resbody: &ruby_prism::RescueNode) -> Vec<Option<&'a [u8]>> {
        let list: Vec<ruby_prism::Node> = resbody.exceptions().iter().collect();
        if list.is_empty() {
            return vec![Some(&b"StandardError"[..])];
        }
        list.iter()
            .map(|n| {
                let src = self.node_src(n);
                if shx_chain(src).is_some() { Some(src) } else { None }
            })
            .collect()
    }
}

/// Is `name` a direct `SystemCallError` subclass, i.e. an `Errno::<NAME>`
/// path? (`system_call_err?`: `error.ancestors[1] == SystemCallError`.)
/// Ruby generates an `Errno` class for every platform errno code at boot, so
/// this is a name-shape rule rather than a fixed list.
fn shx_is_errno(name: &[u8]) -> bool {
    match name.strip_prefix(b"Errno::") {
        Some(rest) if !rest.is_empty() => {
            rest[0].is_ascii_uppercase()
                && rest.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        }
        _ => false,
    }
}

/// The numeric-errno-code group an `Errno::X` name belongs to, for
/// `exception.const_get(:Errno) != other.const_get(:Errno)`. Real errno
/// values are platform-dependent (rubocop's own spec exercises this exact
/// ambiguity with `stub_const('Errno::EAGAIN::Errno', ...)`  precisely to
/// pin it down); `EAGAIN`/`EWOULDBLOCK` sharing a code is the portable,
/// nearly-universal case the spec models, so it's the one alias hardcoded
/// here. Every other name is its own group.
fn shx_errno_group(name: &[u8]) -> &[u8] {
    let rest = name.strip_prefix(b"Errno::").unwrap_or(name);
    if rest == b"EWOULDBLOCK" { b"EAGAIN" } else { rest }
}

/// `(child, parent)` — the core Ruby `Exception` hierarchy's `superclass`
/// chain (stock Ruby 3.4, `ObjectSpace.each_object(Class)` filtered to `<=
/// Exception`, gem-defined classes excluded). `Exception` itself is the
/// implicit root and has no entry.
static SHX_PARENT: &[(&[u8], &[u8])] = &[
    (b"NoMemoryError", b"Exception"),
    (b"ScriptError", b"Exception"),
    (b"LoadError", b"ScriptError"),
    (b"NotImplementedError", b"ScriptError"),
    (b"SyntaxError", b"ScriptError"),
    (b"SecurityError", b"Exception"),
    (b"SignalException", b"Exception"),
    (b"Interrupt", b"SignalException"),
    (b"SystemExit", b"Exception"),
    (b"SystemStackError", b"Exception"),
    (b"StandardError", b"Exception"),
    (b"ArgumentError", b"StandardError"),
    (b"UncaughtThrowError", b"ArgumentError"),
    (b"EncodingError", b"StandardError"),
    (b"FiberError", b"StandardError"),
    (b"IOError", b"StandardError"),
    (b"EOFError", b"IOError"),
    (b"IO::TimeoutError", b"IOError"),
    (b"IndexError", b"StandardError"),
    (b"KeyError", b"IndexError"),
    (b"StopIteration", b"IndexError"),
    (b"ClosedQueueError", b"StopIteration"),
    (b"LocalJumpError", b"StandardError"),
    (b"NameError", b"StandardError"),
    (b"NoMethodError", b"NameError"),
    (b"RangeError", b"StandardError"),
    (b"FloatDomainError", b"RangeError"),
    (b"RegexpError", b"StandardError"),
    (b"Regexp::TimeoutError", b"RegexpError"),
    (b"RuntimeError", b"StandardError"),
    (b"FrozenError", b"RuntimeError"),
    // `TimeoutError` is a deprecated top-level alias for `Timeout::Error`
    // (from the `timeout` stdlib); resolving it prints a runtime deprecation
    // warning upstream silences via `RuboCop::Util.silence_warnings` — we
    // emit no such warning at all, so there's nothing to suppress, but the
    // name still needs to resolve (not raise `NameError`) to match upstream
    // behavior for `rescue TimeoutError`.
    (b"TimeoutError", b"RuntimeError"),
    (b"Timeout::Error", b"RuntimeError"),
    (b"SystemCallError", b"StandardError"),
    (b"ThreadError", b"StandardError"),
    (b"TypeError", b"StandardError"),
    (b"ZeroDivisionError", b"StandardError"),
    (b"NoMatchingPatternError", b"StandardError"),
    (b"NoMatchingPatternKeyError", b"NoMatchingPatternError"),
    (b"Math::DomainError", b"StandardError"),
];

/// The ancestor chain from `name` up to (and including) `Exception`, or
/// `None` if `name` isn't a known core exception class / valid `Errno::X`
/// path — mirrors `Kernel.const_get(name)` raising `NameError` for anything
/// else (custom classes, typos, method-call/splat/array-literal source
/// text, ...).
fn shx_chain(name: &[u8]) -> Option<Vec<&[u8]>> {
    if name == b"Exception" {
        return Some(vec![b"Exception"]);
    }
    if shx_is_errno(name) {
        return Some(vec![name, b"SystemCallError", b"StandardError", b"Exception"]);
    }
    let mut chain: Vec<&[u8]> = vec![name];
    let mut cur = name;
    loop {
        match SHX_PARENT.iter().find(|(child, _)| *child == cur) {
            Some((_, parent)) => {
                chain.push(parent);
                if *parent == b"Exception" {
                    return Some(chain);
                }
                cur = parent;
            }
            None => return None,
        }
    }
}

/// `Module#<=>`: `Some(0)` same class, `Some(-1)` `a` is a subclass of `b`,
/// `Some(1)` `a` is a superclass of `b`, `None` if unrelated. Both
/// `compare_exceptions` and `sorted?`'s raw array comparison reduce to this.
fn shx_cmp(a: &[u8], b: &[u8]) -> Option<i32> {
    if a == b {
        // still validate `a` resolves at all (an unresolved/`None` element
        // never reaches this far — callers guard that — but keep it total).
        shx_chain(a)?;
        return Some(0);
    }
    let ca = shx_chain(a)?;
    let cb = shx_chain(b)?;
    if ca[1..].contains(&b) {
        return Some(-1);
    }
    if cb[1..].contains(&a) {
        return Some(1);
    }
    None
}

/// `compare_exceptions`: truthy (in Ruby's sense — anything but `nil`/
/// `false`) iff the pair "shadows" within the same `rescue` clause. `Some(0)`
/// (identical classes, e.g. `rescue NameError, NameError`) counts as truthy
/// here exactly like upstream, since `0` is truthy in Ruby.
fn shx_shadow_pair(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    let (Some(a), Some(b)) = (a, b) else { return false };
    if shx_is_errno(a) && shx_is_errno(b) {
        if shx_errno_group(a) == shx_errno_group(b) {
            return false;
        }
        shx_cmp(a, b).is_some()
    } else {
        shx_cmp(a, b).is_some()
    }
}

/// `contains_multiple_levels_of_exceptions?`: `Exception` alongside anything
/// else in the same clause always counts (`Exception` is always treated as
/// the top level); otherwise any shadowing pair within the group counts.
fn shx_contains_multiple_levels(group: &[Option<&[u8]>]) -> bool {
    if group.len() > 1 && group.iter().any(|e| *e == Some(&b"Exception"[..])) {
        return true;
    }
    for i in 0..group.len() {
        for j in (i + 1)..group.len() {
            if shx_shadow_pair(group[i], group[j]) {
                return true;
            }
        }
    }
    false
}

/// `Array#<=>` over two exception-name lists: element-wise via `shx_cmp`
/// (with `nil <=> nil` = `0`, any other `nil` pairing = unrelated/`None`,
/// short-circuiting the whole comparison exactly like Ruby's `Array#<=>`);
/// a common all-equal prefix falls through to comparing lengths.
fn shx_group_cmp(x: &[Option<&[u8]>], y: &[Option<&[u8]>]) -> Option<i32> {
    let n = x.len().min(y.len());
    for i in 0..n {
        let c = match (x[i], y[i]) {
            (None, None) => Some(0),
            (Some(a), Some(b)) => shx_cmp(a, b),
            _ => None,
        };
        match c {
            None => return None,
            Some(0) => continue,
            Some(v) => return Some(v),
        }
    }
    Some((x.len() as i64 - y.len() as i64).signum() as i32)
}

/// `sorted?`'s single-pair body (reused directly by `find_shadowing_rescue`,
/// which calls it on one `each_cons(2)` pair at a time): `Exception` in the
/// earlier group always breaks order; `Exception` in the later group (or
/// either group being empty/all-`nil`) is vacuously fine; otherwise fall
/// back to the raw array comparison, treating `nil` (unrelated ancestry) as
/// "not backwards" — `(x <=> y || 0) <= 0`.
fn shx_pair_sorted(x: &[Option<&[u8]>], y: &[Option<&[u8]>]) -> bool {
    let has_exception = |g: &[Option<&[u8]>]| g.iter().any(|e| *e == Some(&b"Exception"[..]));
    if has_exception(x) {
        return false;
    }
    if has_exception(y) {
        return true;
    }
    let all_none = |g: &[Option<&[u8]>]| g.iter().all(|e| e.is_none());
    if all_none(x) || all_none(y) {
        return true;
    }
    match shx_group_cmp(x, y) {
        Some(v) => v <= 0,
        None => true,
    }
}

/// `sorted?` over the whole chain: every consecutive pair must be in order.
fn shx_sorted(groups: &[Vec<Option<&[u8]>>]) -> bool {
    groups.windows(2).all(|w| shx_pair_sorted(&w[0], &w[1]))
}

/// `find_shadowing_rescue`: an internally-shadowing group (checked across
/// ALL groups first, regardless of position) wins over an out-of-order
/// adjacent pair; the offense anchors on the EARLIER clause of a violating
/// pair (`rescues[i]`, not `rescues[i+1]`) — the one whose overly-broad
/// rescue shadows what follows it.
fn shx_find_shadowing(groups: &[Vec<Option<&[u8]>>]) -> Option<usize> {
    for (i, g) in groups.iter().enumerate() {
        if shx_contains_multiple_levels(g) {
            return Some(i);
        }
    }
    for i in 0..groups.len().saturating_sub(1) {
        if !shx_pair_sorted(&groups[i], &groups[i + 1]) {
            return Some(i);
        }
    }
    None
}


// ---- Lint/SafeNavigationChain ----
//
// Upstream (`lib/rubocop/cop/lint/safe_navigation_chain.rb` + the `NilMethods`
// mixin): flags an ORDINARY (non safe-nav) method call chained directly onto
// a safe-navigated (`&.`) receiver — `x&.foo.bar` raises `NoMethodError`
// whenever `x` is nil, since `x&.foo` short-circuits to `nil` and the
// trailing `.bar` isn't itself guarded.
//
// `on_send` fires for every plain `send` node (never `csend` — this cop has
// no `alias on_csend on_send`). Per node:
//   1. `bad_method?`: this call's receiver must be, directly, a safe-nav
//      (`csend`) call — OR a `(csend ...)` parenthesized single-statement
//      group (prism: `ParenthesesNode` wrapping a one-statement
//      `StatementsNode`). A call-WITH-BLOCK collapses into the plain-csend
//      case in prism (the block lives on the very same `CallNode` — unlike
//      whitequark's separate wrapping `block` node), so upstream's third
//      pattern alternative (`send $(any_block (csend ...) ...) $_`) needs no
//      separate handling here: `x&.select { ... }.bar`'s receiver IS the
//      csend `CallNode`, block and all.
//   2. `nil_methods.include?(method) || PLUS_MINUS_METHODS.include?(method)`:
//      exempt when the OUTER call's own method is one nil itself responds to
//      (`snc_is_builtin_nil_method`, shared with the sibling
//      SafeNavigationConsistency cop above), the cop's configured
//      `AllowedMethods` (default `present?`/`blank?`/`presence`/`try`/
//      `try!`/`in?`, via `self.allowed`), or unary `+@`/`-@` — prism parses
//      `+str&.to_i` as `(+@ (csend str to_i))` (unary +/- binds LOOSER than
//      the safe-nav call), so unary +/- is always the OUTER node checked
//      here, never something nested inside the receiver.
//   3. `ternary_safe_navigation?`: exempt when this call is the THEN-branch
//      of a ternary (`?:` — a real `if`/`unless` statement's branch is a
//      `StatementsNode`, never a bare expression, so this can only be a
//      ternary) whose CONDITION has the same source text as the captured
//      safe-nav receiver (`foo&.bar ? foo&.bar - 1 : baz` — the true branch
//      is instead `Lint/RedundantSafeNavigation`'s territory).
//   4. `require_safe_navigation?`: upstream's one PARENT-aware guard —
//      exempts a call that is the RHS of an `&&`/`and` (`and_type?`, which
//      covers BOTH surface spellings identically) node whose LHS's receiver
//      has the SAME source text as this call's own receiver
//      (`x&.foo&.bar && x&.foo.baz`: the `.baz` call is exempt, having
//      already been "guarded" by the `&&`'s LHS). `||`/`or` never gets this
//      exemption — only `and_type?` is checked upstream. Source-text
//      equality (rather than true structural AST equality, which upstream
//      actually uses) mirrors the same simplification the sibling
//      SafeNavigationConsistency cop's `receiver_key` already makes; not
//      exercised differently by the fixture.
//
// None of these 4 checks can see rubocop's `node.parent` directly (prism
// nodes carry no parent pointer). `snav_parent` (see its own doc, and the
// `visit_and_node`/`visit_or_node`/`visit_if_node`/`visit_array_node`/
// `visit_assoc_node`/`visit_call_node` populators in `mod.rs`) reconstructs
// exactly the parent facts steps 3-4 (and, further below, autocorrection's
// `require_parentheses?`) need, keyed by the candidate node's own start
// offset.
//
// The offense range starts at this call's own dot (`.` — never `&.`, since a
// safe-nav receiver was already ruled out for THIS call itself) if it has
// one, else at the end of the safe-nav receiver (an operator-method call or
// `[]`/`[]=` has no dot), and always ends at this call's own end (its
// arguments/block included, so e.g. `.bar(y)` or `{ |x| ... }` extend the
// range).
//
// `ternary_else_branch?` (the ELSE-branch symmetric case to step 3) still
// registers the offense but WITHOUT autocorrection ("the receiver in the
// else branch may be nil... autocorrection is not possible as the intent is
// ambiguous") — ported as `push(.., correctable: false, ..)` with no
// `self.fixes` entry, same idiom SafeNavigationConsistency uses for its own
// uncorrectable (operator-method) case.
//
// Autocorrection (`add_safe_navigation_operator`): replaces the offense
// range with `&` prepended (plus a `.` too, unless the range's own text
// already starts with one) to itself — EXCEPT a `[]`/`[]=` call, rewritten
// as `&.[](args)`/`&.[]=(args)` (bracket syntax has no dot to turn into
// `&.`). `require_parentheses?` additionally wraps the WHOLE outer call in
// `(...)` when: it's an element/key/value of an array or hash-pair literal
// AND has no dot of its own (`operator_inside_collection_literal?`); or its
// own method is a comparison operator (`==`/`===`/`!=`/`<=`/`>=`/`>`/`<`)
// AND its immediate parent is either an `&&`/`||` — NOT the `and`/`or`
// keyword spelling; `logical_operator?` checks the actual OPERATOR TOKEN,
// unlike `require_safe_navigation?`'s `and_type?` which doesn't care — or
// another comparison-method call (as one of ITS arguments).
impl<'a> super::Cops<'a> {
    pub(crate) fn check_safe_navigation_chain(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/SafeNavigationChain";
        if !self.on(COP) {
            return;
        }
        if node.is_safe_navigation() {
            return; // upstream's `on_send`, never `on_csend`
        }
        let Some(receiver) = node.receiver() else { return };
        let safe_nav = if let Some(c) = receiver.as_call_node() {
            if !c.is_safe_navigation() {
                return;
            }
            c
        } else if let Some(p) = receiver.as_parentheses_node() {
            // `(begin (csend ...))`: exactly one statement, itself a csend.
            let Some(body) = p.body() else { return };
            let Some(stmts) = body.as_statements_node() else { return };
            let mut it = stmts.body().iter();
            let Some(only) = it.next() else { return };
            if it.next().is_some() {
                return;
            }
            let Some(c) = only.as_call_node() else { return };
            if !c.is_safe_navigation() {
                return;
            }
            c
        } else {
            return;
        };

        let method = node.name().as_slice();
        if snc_is_builtin_nil_method(method) || self.allowed(COP, method) {
            return;
        }
        if method == b"+@" || method == b"-@" {
            return;
        }

        let node_start = node.location().start_offset();
        let parent = self.snav_parent.get(&node_start).copied();

        // `ternary_safe_navigation?`
        if let Some(SnavParent::TernaryBranch { is_then: true, condition }) = parent {
            if condition == self.node_src(&safe_nav.as_node()) {
                return;
            }
        }

        // `require_safe_navigation?`
        if let Some(SnavParent::LogicalOperand { is_and: true, is_rhs: true, lhs_receiver, .. }) = parent {
            let rhs_receiver = node.receiver().map(|r| self.node_src(&r));
            if lhs_receiver == rhs_receiver {
                return;
            }
        }

        let is_ternary_else = matches!(
            parent,
            Some(SnavParent::TernaryBranch { is_then: false, condition })
                if condition == self.node_src(&safe_nav.as_node())
        );

        let node_end = node.location().end_offset();
        let (offense_start, has_dot) = match node.call_operator_loc() {
            Some(d) => (d.start_offset(), true),
            None => (safe_nav.location().end_offset(), false),
        };

        const MSG: &str = "Do not chain ordinary method call after safe navigation operator.";
        if is_ternary_else {
            self.push(offense_start, COP, false, MSG);
            return;
        }
        self.push(offense_start, COP, true, MSG);

        // ---- autocorrect ----
        let is_brackets = method == b"[]" || method == b"[]=";
        let replacement: Vec<u8> = if is_brackets {
            let mut inner = Vec::new();
            inner.extend_from_slice(method);
            inner.push(b'(');
            if let Some(args) = node.arguments() {
                for (i, a) in args.arguments().iter().enumerate() {
                    if i > 0 {
                        inner.extend_from_slice(b", ");
                    }
                    inner.extend_from_slice(self.node_src(&a));
                }
            }
            inner.push(b')');
            let mut out = Vec::with_capacity(inner.len() + 2);
            out.push(b'&');
            out.push(b'.');
            out.extend_from_slice(&inner);
            out
        } else {
            let text = &self.src[offense_start..node_end];
            let mut out = Vec::with_capacity(text.len() + 2);
            out.push(b'&');
            if !text.starts_with(b".") {
                out.push(b'.');
            }
            out.extend_from_slice(text);
            out
        };
        self.fixes.push((offense_start, node_end, replacement));

        if self.snav_requires_parens(node, has_dot, parent) {
            self.fixes.push((node_start, node_start, b"(".to_vec()));
            self.fixes.push((node_end, node_end, b")".to_vec()));
        }
    }

    /// `require_parentheses?`.
    fn snav_requires_parens(&self, node: &ruby_prism::CallNode, has_dot: bool, parent: Option<SnavParent>) -> bool {
        // `operator_inside_collection_literal?`
        if !has_dot && matches!(parent, Some(SnavParent::CollectionLiteral)) {
            return true;
        }
        const COMPARISON: &[&[u8]] = &[b"==", b"===", b"!=", b"<=", b">=", b">", b"<"];
        if !COMPARISON.contains(&node.name().as_slice()) {
            return false;
        }
        match parent {
            Some(SnavParent::LogicalOperand { is_symbol_op, .. }) => is_symbol_op,
            Some(SnavParent::ComparisonCallArg) => true,
            _ => false,
        }
    }
}

/// Lint/SafeNavigationChain: immediate-parent context for a candidate node,
/// keyed by that node's own start offset in `Cops::snav_parent` — see
/// `check_safe_navigation_chain`'s doc comment for the full mapping to
/// upstream's `node.parent`-based predicates, and `mod.rs`'s
/// `visit_and_node`/`visit_or_node`/`visit_if_node`/`visit_array_node`/
/// `visit_assoc_node`/`visit_call_node` for where each variant is populated.
#[derive(Clone, Copy)]
pub(crate) enum SnavParent<'a> {
    /// Immediate parent is an `and`/`or` node. `is_and` distinguishes an
    /// `and`/`&&`-node parent (relevant to `require_safe_navigation?`) from
    /// an `or`/`||`-node one (never exempted there); `is_symbol_op` is the
    /// operator TOKEN actually used (`&&`/`||` vs the `and`/`or` keyword) —
    /// feeds `require_parentheses?`'s `logical_operator?`, which checks the
    /// token, not the node type. `lhs_receiver` is only meaningful when
    /// `is_and && is_rhs`: the LHS's receiver's own source text (`None` = a
    /// receiver-less/bare call, or the LHS isn't itself a call at all).
    LogicalOperand { is_and: bool, is_rhs: bool, is_symbol_op: bool, lhs_receiver: Option<&'a [u8]> },
    /// Immediate parent is a ternary (`?:`) `if` node's then/else branch.
    /// `is_then` picks `ternary_safe_navigation?` (the if-branch, exempted
    /// entirely) vs `ternary_else_branch?` (the else-branch: offense
    /// registered, but never corrected). `condition` is the ternary's own
    /// predicate's source text, compared against the candidate's captured
    /// safe-nav receiver's source text.
    TernaryBranch { is_then: bool, condition: &'a [u8] },
    /// Immediate parent is an array or hash-pair literal (element, or pair
    /// key/value) — `operator_inside_collection_literal?`.
    CollectionLiteral,
    /// Immediate parent is a `send`/`csend` node (as one of its arguments)
    /// whose OWN method is a comparison operator — the second
    /// `require_parentheses?` disjunct.
    ComparisonCallArg,
}


// =====================================================================
// Lint/LiteralAsCondition
//
// Ported from rubocop's `Lint::LiteralAsCondition` (`include RangeHelp`,
// `extend AutoCorrector`). Flags a literal used as (or as an and/or operand
// feeding) the condition of `if`/`unless`/`while`/`until`/ternary/`case`/
// `case-in`, plus a literal that's the operand of a `!`/`not`.
//
// whitequark folds `unless` into the very same `:if` node type (condition/
// true-branch/false-branch just swapped — see `IfNode#node_parts` in
// rubocop-ast), so upstream's single `on_if` handles real `if`, `unless`,
// AND ternaries all at once. Prism gives `unless` its own `UnlessNode`, so
// this port splits that one upstream method into
// `check_literal_as_condition_if` (real `if`/elsif/ternary — all the same
// prism `IfNode`) and `check_literal_as_condition_unless`.
//
// Two prism-vs-whitequark traps drive most of the complexity below:
//
// 1. `node.source` for a nested `elsif`'s own `IfNode`: whitequark's
//    `SourceMap` for an elsif clause spans from the `elsif` keyword through
//    the END OF ITS OWN CONTENT (the deepest branch in its chain), NEVER
//    reaching the shared closing `end` keyword — that `end` belongs only to
//    the outermost `if`. Prism's `IfNode#location`, in contrast, gives EVERY
//    level of the chain (including every nested elsif) the SAME range,
//    reaching all the way to that shared `end`. Verified live against both
//    `Prism.parse` and `RuboCop::ProcessedSource`. `lac_elsif_content_end`
//    computes the whitequark-accurate stopping point; `lac_if_wq_range`
//    applies it only to a genuine elsif level (`if_keyword_loc` reading
//    `elsif`), leaving the outermost `if`/ternary/modifier-`if`'s own
//    `location().end_offset()` (already correct) alone.
// 2. `IgnoredNode#part_of_ignored_node?` compares byte ranges computed with
//    trap #1 already applied — an offense on a nested elsif/ternary whose
//    enclosing `if` was already rewritten this pass is reported but never
//    autocorrected (avoids emitting two overlapping edits). Modeled here by
//    `Cops::lac_ignored`, a running list of (start, end) ranges already
//    corrected this file, checked/extended by both
//    `lac_correct_if_node`/`lac_correct_unless_node`.
//
// `on_while`/`on_until` vs. `on_while_post`/`on_until_post`: whitequark gives
// the post-condition `begin...end while/until cond` loop shape its own
// `:while_post`/`:until_post` node type (still built into the same
// `RuboCop::AST::WhileNode`/`UntilNode` class — see rubocop-ast's
// `builder.rb`); prism folds it into the ordinary `WhileNode`/`UntilNode`
// with `is_begin_modifier?` true. `lac_loop_regular`/`lac_loop_post` take a
// `guard_kw` (`"true"`/`"false"`) plus `is_while` so one pair of functions
// serves both `while` and `until`.
impl<'a> super::Cops<'a> {
    /// `on_send`'s `RESTRICT_ON_SEND = [:!]` + `negation_method?` guard,
    /// then `check_for_literal`: unlike `handle_node` (below), the operand
    /// checked HERE gets no `parent.and_type?` suppression — that guard only
    /// matters for literals found via the `check_node`/`handle_node`
    /// recursion this falls into when the operand isn't itself a literal.
    pub(crate) fn check_literal_as_condition_send(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"!" {
            return;
        }
        let Some(cond) = node.receiver() else { return };
        if lac_literal(&cond) {
            self.push(cond.location().start_offset(), COP, false, lac_msg(self.node_src(&cond)));
        } else {
            lac_check_node(self, &cond);
        }
    }

    /// `on_and`: `node.lhs.truthy_literal?` — the WHOLE `and` node is
    /// replaced with the right-hand side's source, unless that rhs is a bare
    /// `return`/`break`/`next` (would-be void-value syntax error once it's
    /// promoted to the leftmost expression).
    pub(crate) fn check_literal_as_condition_and(&mut self, node: &ruby_prism::AndNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        let lhs = node.left();
        if !style::il_truthy_literal(&lhs) {
            return;
        }
        let rhs = node.right();
        let correctable = !lac_is_return_break_next(&rhs);
        self.push(lhs.location().start_offset(), COP, correctable, lac_msg(self.node_src(&lhs)));
        if correctable {
            let repl = self.node_src(&rhs).to_vec();
            let l = node.location();
            self.fixes.push((l.start_offset(), l.end_offset(), repl));
        }
    }

    /// `on_or`: `node.lhs.falsey_literal?`, otherwise the mirror of
    /// `check_literal_as_condition_and`.
    pub(crate) fn check_literal_as_condition_or(&mut self, node: &ruby_prism::OrNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        let lhs = node.left();
        if !style::il_falsey_literal(&lhs) {
            return;
        }
        let rhs = node.right();
        let correctable = !lac_is_return_break_next(&rhs);
        self.push(lhs.location().start_offset(), COP, correctable, lac_msg(self.node_src(&lhs)));
        if correctable {
            let repl = self.node_src(&rhs).to_vec();
            let l = node.location();
            self.fixes.push((l.start_offset(), l.end_offset(), repl));
        }
    }

    /// Shared body for `on_while`/`on_until` (the ordinary, non-post-loop
    /// shape — block form `while cond ... end` AND bare modifier form `body
    /// while cond`, both whitequark's plain `:while`/`:until`). `guard_kw` is
    /// the literal text that short-circuits entirely (`"true"` for while,
    /// `"false"` for until: the canonical "intentional infinite loop"
    /// idiom); `is_while` selects which literal set is the "self" (replace
    /// the condition with `guard_kw`) vs. "opposite" (drop the whole loop —
    /// it would never run even once) case.
    fn lac_loop_regular(&mut self, cond: &ruby_prism::Node, node_loc: ruby_prism::Location, guard_kw: &'static [u8], is_while: bool) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        if self.node_src(cond) == guard_kw {
            return;
        }
        let (is_self, is_opposite) = if is_while {
            (style::il_truthy_literal(cond), style::il_falsey_literal(cond))
        } else {
            (style::il_falsey_literal(cond), style::il_truthy_literal(cond))
        };
        if is_self {
            self.push(cond.location().start_offset(), COP, true, lac_msg(self.node_src(cond)));
            self.fixes.push((cond.location().start_offset(), cond.location().end_offset(), guard_kw.to_vec()));
        } else if is_opposite {
            self.push(cond.location().start_offset(), COP, true, lac_msg(self.node_src(cond)));
            self.fixes.push((node_loc.start_offset(), node_loc.end_offset(), Vec::new()));
        }
    }

    pub(crate) fn check_literal_as_condition_while(&mut self, node: &ruby_prism::WhileNode) {
        self.lac_loop_regular(&node.predicate(), node.location(), b"true", true);
    }

    pub(crate) fn check_literal_as_condition_until(&mut self, node: &ruby_prism::UntilNode) {
        self.lac_loop_regular(&node.predicate(), node.location(), b"false", false);
    }

    /// Shared body for `on_while_post`/`on_until_post` (the `begin ... end
    /// while/until cond` post-condition loop; prism: ordinary `WhileNode`/
    /// `UntilNode` with `is_begin_modifier() == true`). The "self" case does
    /// a raw FIRST-OCCURRENCE substring replace of the condition's own
    /// source text with `guard_kw` across the whole node's source (mirrors
    /// upstream's `node.source.sub(node.condition.source, 'true')` literally
    /// — a real quirk: it's textual, not AST-aware). The "opposite" case
    /// replaces the whole node with its `begin` body's statements, each
    /// re-emitted verbatim and joined with a bare `"\n"` (upstream
    /// `node.body.child_nodes.map(&:source).join("\n")` — original
    /// indentation between statements is NOT preserved).
    fn lac_loop_post(
        &mut self,
        cond: &ruby_prism::Node,
        statements: Option<ruby_prism::StatementsNode>,
        node_loc: ruby_prism::Location,
        guard_kw: &'static [u8],
        is_while: bool,
    ) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        if self.node_src(cond) == guard_kw {
            return;
        }
        let (is_self, is_opposite) = if is_while {
            (style::il_truthy_literal(cond), style::il_falsey_literal(cond))
        } else {
            (style::il_falsey_literal(cond), style::il_truthy_literal(cond))
        };
        if is_self {
            self.push(cond.location().start_offset(), COP, true, lac_msg(self.node_src(cond)));
            let whole = self.src[node_loc.start_offset()..node_loc.end_offset()].to_vec();
            let cond_src = self.node_src(cond).to_vec();
            let replacement = lac_sub_first(&whole, &cond_src, guard_kw);
            self.fixes.push((node_loc.start_offset(), node_loc.end_offset(), replacement));
        } else if is_opposite {
            self.push(cond.location().start_offset(), COP, true, lac_msg(self.node_src(cond)));
            let begin_node = statements.and_then(|s| s.body().iter().find_map(|n| n.as_begin_node()));
            let replacement = begin_node
                .and_then(|b| b.statements())
                .map(|s| {
                    s.body().iter().map(|n| self.node_src(&n).to_vec()).collect::<Vec<_>>().join(&b"\n"[..])
                })
                .unwrap_or_default();
            self.fixes.push((node_loc.start_offset(), node_loc.end_offset(), replacement));
        }
    }

    pub(crate) fn check_literal_as_condition_while_post(&mut self, node: &ruby_prism::WhileNode) {
        self.lac_loop_post(&node.predicate(), node.statements(), node.location(), b"true", true);
    }

    pub(crate) fn check_literal_as_condition_until_post(&mut self, node: &ruby_prism::UntilNode) {
        self.lac_loop_post(&node.predicate(), node.statements(), node.location(), b"false", false);
    }

    /// `on_case`: a subject present (`case cond ... end`) delegates to
    /// `lac_check_case_common`; a subject-LESS `case` (`case\nwhen a then
    /// ...\nend`) instead flags any `when` clause every one of whose
    /// (possibly multiple, comma-separated) conditions is itself a literal —
    /// the offense spans the first condition's start through the last's end.
    pub(crate) fn check_literal_as_condition_case(&mut self, node: &ruby_prism::CaseNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        if let Some(cond) = node.predicate() {
            if !style::il_falsey_literal(&cond) && !style::il_truthy_literal(&cond) {
                return;
            }
            self.lac_check_case_common(&cond, &node.as_node());
        } else {
            for branch in node.conditions().iter() {
                let Some(when_node) = branch.as_when_node() else { continue };
                let conds: Vec<ruby_prism::Node> = when_node.conditions().iter().collect();
                if conds.is_empty() || !conds.iter().all(lac_literal) {
                    continue;
                }
                let start = conds.first().unwrap().location().start_offset();
                let end = conds.last().unwrap().location().end_offset();
                self.push(start, COP, false, lac_msg(&self.src[start..end]));
            }
        }
    }

    /// `on_case_match`: a `case-in` ALWAYS has a subject (prism's
    /// `CaseMatchNode#predicate` is never absent — the subject-less branch
    /// upstream guards for is unreachable pattern-matching syntax and is not
    /// ported). `descendants.any?(&:match_var_type?)` (any pattern anywhere
    /// in the `in` branches binds a NEW local — `in x`, `in [*rest]`, `in a:
    /// Integer => m`, ...) is scoped to just the `in` PATTERNS themselves
    /// (`lac_has_match_var`), not their guard/body statements: whitequark's
    /// `:match_var` node type is exclusive to pattern captures, but prism
    /// represents both a pattern capture AND an ordinary multiple-assignment
    /// target (`a, b = 1, 2`) with the SAME `LocalVariableTargetNode` — a
    /// body statement doing the latter must not be mistaken for the former.
    pub(crate) fn check_literal_as_condition_case_match(&mut self, node: &ruby_prism::CaseMatchNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        let Some(cond) = node.predicate() else { return };
        if lac_has_match_var(node) {
            return;
        }
        if !style::il_falsey_literal(&cond) && !style::il_truthy_literal(&cond) {
            return;
        }
        self.lac_check_case_common(&cond, &node.as_node());
    }

    /// `check_case`: an array subject is only followed through when every
    /// element is (recursively) a `basic_literal?` (`primitive_array?`); a
    /// `dstr` (interpolated string) subject is never followed at all. Falls
    /// into the same `check_node`/`handle_node` recursion `on_send` uses,
    /// with `parent` = the `case`/`case-in` node itself (never `and_type?`,
    /// so the `handle_node` suppression there never fires from this path).
    fn lac_check_case_common(&mut self, cond: &ruby_prism::Node, parent: &ruby_prism::Node) {
        if let Some(arr) = cond.as_array_node() {
            if !lac_primitive_array(&arr) {
                return;
            }
        }
        if cond.as_interpolated_string_node().is_some() {
            return;
        }
        lac_handle_node(self, cond, parent);
    }

    /// `on_if`: real `if`/`elsif` (prism `IfNode` with an `if_keyword_loc`)
    /// AND ternaries (no keyword at all) share this one upstream method —
    /// see the module doc for why `unless` needs its own,
    /// `check_literal_as_condition_unless`.
    pub(crate) fn check_literal_as_condition_if(&mut self, node: &ruby_prism::IfNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        let cond = node.predicate();
        if !style::il_falsey_literal(&cond) && !style::il_truthy_literal(&cond) {
            return;
        }
        self.lac_correct_if_node(node, &cond);
    }

    pub(crate) fn check_literal_as_condition_unless(&mut self, node: &ruby_prism::UnlessNode) {
        const COP: &str = "Lint/LiteralAsCondition";
        if !self.on(COP) {
            return;
        }
        let cond = node.predicate();
        if !style::il_falsey_literal(&cond) && !style::il_truthy_literal(&cond) {
            return;
        }
        self.lac_correct_unless_node(node, &cond);
    }

    /// `correct_if_node`, specialized to a real `if`/elsif/ternary
    /// (`condition_evaluation?` always takes the non-`unless?` branch:
    /// `cond.truthy_literal?`). See the module doc for the two
    /// prism-vs-whitequark traps this leans on.
    fn lac_correct_if_node(&mut self, node: &ruby_prism::IfNode, cond: &ruby_prism::Node) {
        const COP: &str = "Lint/LiteralAsCondition";
        let result = style::il_truthy_literal(cond);
        let (start, end) = lac_if_wq_range(node);
        let ignored = self.lac_ignored.iter().any(|&(is, ie)| is <= start && ie >= end);
        self.push(cond.location().start_offset(), COP, !ignored, lac_msg(self.node_src(cond)));
        if ignored {
            return;
        }

        let is_elsif = node.if_keyword_loc().is_some_and(|k| k.as_slice() == b"elsif");
        let is_ternary = node.if_keyword_loc().is_none();
        let elsif_conditional = node.subsequent().is_some_and(|s| s.as_if_node().is_some());
        let has_else = node.subsequent().is_some_and(|s| s.as_else_node().is_some());

        let new_node: Vec<u8> = if is_elsif && result {
            // "else\n  #{range_with_comments(node.if_branch).source}"
            let mut out = b"else\n  ".to_vec();
            if let Some(stmts) = node.statements() {
                let lower = node.predicate().location().end_offset();
                let (s, e) = lac_range_with_comments(self, stmts.location().start_offset(), stmts.location().end_offset(), lower);
                out.extend_from_slice(&self.src[s..e]);
            }
            out
        } else if is_elsif && !result {
            // "else\n  #{node.else_branch.source}"
            let mut out = b"else\n  ".to_vec();
            match node.subsequent() {
                Some(sub) => {
                    if let Some(else_node) = sub.as_else_node() {
                        if let Some(stmts) = else_node.statements() {
                            out.extend_from_slice(self.node_src(&stmts.as_node()));
                        }
                    } else if let Some(nested) = sub.as_if_node() {
                        let ns = nested.location().start_offset();
                        let ne = lac_elsif_content_end(&nested);
                        out.extend_from_slice(&self.src[ns..ne]);
                    }
                }
                None => {}
            }
            out
        } else if node.statements().is_some() && result {
            // node.if_branch.source
            self.node_src(&node.statements().unwrap().as_node()).to_vec()
        } else if elsif_conditional {
            // "#{node.else_branch.source.sub('elsif', 'if')}\nend"
            let nested = node.subsequent().unwrap().as_if_node().unwrap();
            let ns = nested.location().start_offset();
            let ne = lac_elsif_content_end(&nested);
            let nested_src = self.src[ns..ne].to_vec();
            let mut out = lac_sub_first(&nested_src, b"elsif", b"if");
            out.extend_from_slice(b"\nend");
            out
        } else if has_else || is_ternary {
            // node.else_branch.source
            node.subsequent()
                .and_then(|s| s.as_else_node())
                .and_then(|e| e.statements())
                .map(|s| self.node_src(&s.as_node()).to_vec())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        self.fixes.push((start, end, new_node));
        self.lac_ignored.push((start, end));
    }

    /// `correct_if_node` for `unless` (`condition_evaluation?`'s `unless?`
    /// branch: `cond.falsey_literal?`). `unless` never chains an elsif and
    /// is never a ternary, so only 2 of the upstream `new_node` cases are
    /// reachable: the (normalized) if-branch when `result`, else the
    /// `else`-clause body (or `''` with neither).
    fn lac_correct_unless_node(&mut self, node: &ruby_prism::UnlessNode, cond: &ruby_prism::Node) {
        const COP: &str = "Lint/LiteralAsCondition";
        let result = style::il_falsey_literal(cond);
        let start = node.location().start_offset();
        let end = node.location().end_offset();
        let ignored = self.lac_ignored.iter().any(|&(is, ie)| is <= start && ie >= end);
        self.push(cond.location().start_offset(), COP, !ignored, lac_msg(self.node_src(cond)));
        if ignored {
            return;
        }

        let new_node: Vec<u8> = if node.statements().is_some() && result {
            self.node_src(&node.statements().unwrap().as_node()).to_vec()
        } else if let Some(else_clause) = node.else_clause() {
            else_clause.statements().map(|s| self.node_src(&s.as_node()).to_vec()).unwrap_or_default()
        } else {
            Vec::new()
        };

        self.fixes.push((start, end, new_node));
        self.lac_ignored.push((start, end));
    }
}

use super::style;

/// `Node::LITERALS` (`TRUTHY_LITERALS ∪ FALSEY_LITERALS`) — rubocop-ast's
/// generic `literal?`.
fn lac_literal(n: &ruby_prism::Node) -> bool {
    style::il_truthy_literal(n) || style::il_falsey_literal(n)
}

/// `Node::BASIC_LITERALS` (`LITERALS` minus the composite/interpolated
/// types: `dstr`, `xstr`, `dsym`, `array`, `hash`, `irange`, `erange`,
/// `regexp`) — rubocop-ast's generic `basic_literal?`, called
/// `lac_basic_literal` below once arrays get their `primitive_array?`
/// override layered on top.
fn lac_ast_basic_literal(n: &ruby_prism::Node) -> bool {
    n.as_string_node().is_some()
        || n.as_integer_node().is_some()
        || n.as_float_node().is_some()
        || n.as_symbol_node().is_some()
        || n.as_true_node().is_some()
        || n.as_false_node().is_some()
        || n.as_nil_node().is_some()
        || n.as_imaginary_node().is_some()
        || n.as_rational_node().is_some()
}

/// `LiteralAsCondition#basic_literal?`: same as the AST's own
/// `basic_literal?`, except an array recurses into `primitive_array?`
/// instead of being blanket-composite (`false`).
fn lac_basic_literal(n: &ruby_prism::Node) -> bool {
    if let Some(arr) = n.as_array_node() { lac_primitive_array(&arr) } else { lac_ast_basic_literal(n) }
}

/// `primitive_array?`: every element is (recursively) `basic_literal?`.
fn lac_primitive_array(arr: &ruby_prism::ArrayNode) -> bool {
    arr.elements().iter().all(|el| lac_basic_literal(&el))
}

/// `return`/`break`/`next` — `rhs.type?(:return, :break, :next)`, guarding
/// `on_and`/`on_or`'s autocorrect (promoting one of these to the leftmost
/// expression of the resulting `&&`/`||`-free code would be a void-value
/// syntax error).
fn lac_is_return_break_next(n: &ruby_prism::Node) -> bool {
    n.as_return_node().is_some() || n.as_break_node().is_some() || n.as_next_node().is_some()
}

/// `descendants.any?(&:match_var_type?)`, scoped to every `in` branch's own
/// PATTERN (never its guard or body) — see
/// `check_literal_as_condition_case_match`'s doc for why the scoping
/// matters. `LocalVariableTargetNode` is prism's stand-in for whitequark's
/// `:match_var` here (a bare `in x`, an array/find pattern's splat capture,
/// a hash pattern's shorthand/`=>` capture, ...).
fn lac_has_match_var(node: &ruby_prism::CaseMatchNode) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Finder {
        fn visit_local_variable_target_node(&mut self, _node: &ruby_prism::LocalVariableTargetNode<'pr>) {
            self.found = true;
        }
    }
    use ruby_prism::Visit;
    let mut f = Finder { found: false };
    for cond in node.conditions().iter() {
        if let Some(in_node) = cond.as_in_node() {
            f.visit(&in_node.pattern());
        }
    }
    f.found
}

/// `check_node`/`handle_node`'s mutual recursion. `parent` is `node`'s
/// immediate AST parent (prism gives no parent pointers, so every recursive
/// call threads it through explicitly instead of upstream's `node.parent`).
/// A literal found here is suppressed when its immediate parent is an `and`
/// node — already independently flagged (on its OWN lhs) by
/// `check_literal_as_condition_and`, so this avoids a double report for
/// exactly that shape.
fn lac_handle_node(cops: &mut Cops, node: &ruby_prism::Node, parent: &ruby_prism::Node) {
    if lac_literal(node) {
        if parent.as_and_node().is_some() {
            return;
        }
        cops.push(node.location().start_offset(), "Lint/LiteralAsCondition", false, lac_msg(cops.node_src(node)));
    } else if node.as_call_node().is_some() || node.as_and_node().is_some() || node.as_or_node().is_some() || node.as_parentheses_node().is_some() {
        lac_check_node(cops, node);
    }
}

/// `check_node`: unwraps a `!`/`not` call (bang-spelled ONLY —
/// `prefix_bang?` requires the literal `!` selector, so a nested `not` is a
/// dead end here, matching upstream), an `and`/`or` node's own two operands,
/// or a single-statement parenthesized group (prism `ParenthesesNode`,
/// whitequark's `:begin` — `kwbegin`/`begin...end` is a DIFFERENT node type
/// in both and is never unwrapped here), each further into `handle_node`.
fn lac_check_node(cops: &mut Cops, node: &ruby_prism::Node) {
    if let Some(call) = node.as_call_node() {
        if call.receiver().is_some()
            && call.name().as_slice() == b"!"
            && call.message_loc().is_some_and(|m| m.as_slice() == b"!")
        {
            let recv = call.receiver().unwrap();
            lac_handle_node(cops, &recv, node);
        }
    } else if let Some(and) = node.as_and_node() {
        let l = and.left();
        let r = and.right();
        lac_handle_node(cops, &l, node);
        lac_handle_node(cops, &r, node);
    } else if let Some(or) = node.as_or_node() {
        let l = or.left();
        let r = or.right();
        lac_handle_node(cops, &l, node);
        lac_handle_node(cops, &r, node);
    } else if let Some(paren) = node.as_parentheses_node() {
        if let Some(body) = paren.body() {
            if let Some(stmts) = body.as_statements_node() {
                let items: Vec<ruby_prism::Node> = stmts.body().iter().collect();
                if items.len() == 1 {
                    lac_handle_node(cops, &items[0], node);
                }
            }
        }
    }
}

/// `range_with_comments(if_branch)`: extend `[start, end)` to also cover a
/// same-last-line trailing ("decorating") comment and a directly-preceding
/// comment run down to `lower_bound` (the elsif/if's own condition end) —
/// see `lac_correct_if_node`'s `is_elsif && result` branch, the one case
/// where a comment attached to the content being spliced INTO `new_node`
/// would otherwise be silently dropped (every other branch's comments
/// survive for free as untouched bytes outside the replaced range).
fn lac_range_with_comments(cops: &Cops, start: usize, end: usize, lower_bound: usize) -> (usize, usize) {
    let mut lo = start;
    let mut hi = end;
    let last_line = cops.idx.loc(end.saturating_sub(1)).0;
    for &(line, s, e) in cops.comments {
        if s > lower_bound && e <= start {
            lo = lo.min(s);
        }
        if s >= end && line == last_line {
            hi = hi.max(e);
        }
    }
    (lo, hi)
}

/// The whitequark-accurate stopping point for an elsif-chain `IfNode`'s own
/// content: recurses through `subsequent` (another elsif, or a terminal
/// `else`) to the deepest branch's last statement — see the module doc's
/// trap #1. Invariant under WHICH level of the chain it's called from: every
/// non-outermost node's own whitequark range stops at this exact same
/// offset, since none of them (unlike the outermost) reach the shared
/// closing `end`.
fn lac_elsif_content_end(node: &ruby_prism::IfNode) -> usize {
    match node.subsequent() {
        Some(sub) => {
            if let Some(else_node) = sub.as_else_node() {
                else_node
                    .statements()
                    .map(|s| s.location().end_offset())
                    .unwrap_or_else(|| else_node.else_keyword_loc().end_offset())
            } else if let Some(elsif) = sub.as_if_node() {
                lac_elsif_content_end(&elsif)
            } else {
                node.location().end_offset()
            }
        }
        None => node
            .statements()
            .map(|s| s.location().end_offset())
            .unwrap_or_else(|| node.predicate().location().end_offset()),
    }
}

/// The whitequark-accurate `(start, end)` byte range of ANY level of an
/// `if`/elsif/ternary chain: the outermost `if`/ternary/modifier-`if`'s own
/// `location().end_offset()` is already correct (it owns whatever `end`
/// keyword — or lack thereof — the construct has); only a genuine nested
/// `elsif` needs `lac_elsif_content_end`'s adjustment.
fn lac_if_wq_range(node: &ruby_prism::IfNode) -> (usize, usize) {
    let start = node.location().start_offset();
    let is_elsif = node.if_keyword_loc().is_some_and(|k| k.as_slice() == b"elsif");
    let end = if is_elsif { lac_elsif_content_end(node) } else { node.location().end_offset() };
    (start, end)
}

/// `String#sub(needle, repl)` semantics: replace the FIRST byte-occurrence
/// of `needle`, or return `haystack` unchanged if it doesn't occur.
fn lac_sub_first(haystack: &[u8], needle: &[u8], repl: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        let mut out = repl.to_vec();
        out.extend_from_slice(haystack);
        return out;
    }
    match haystack.windows(needle.len()).position(|w| w == needle) {
        Some(pos) => {
            let mut out = Vec::with_capacity(haystack.len() - needle.len() + repl.len());
            out.extend_from_slice(&haystack[..pos]);
            out.extend_from_slice(repl);
            out.extend_from_slice(&haystack[pos + needle.len()..]);
            out
        }
        None => haystack.to_vec(),
    }
}

/// `format(MSG, literal: node.source)`.
fn lac_msg(src: &[u8]) -> String {
    format!("Literal `{}` appeared as a condition.", String::from_utf8_lossy(src))
}


/// Lint/ShadowedArgument. Upstream builds this on `VariableForce` (a full
/// variable-lifecycle tracker: scopes, `Variable`/`Assignment`/`Reference`
/// objects, and a `Branch`/`Branchable` system for reasoning about which
/// conditional arm an assignment/reference sits in). We hand-roll a
/// deliberately narrower model that's sufficient for `ShadowedArgument`'s own
/// algorithm (`check_argument`/`shadowing_assignment`/
/// `assignment_without_argument_usage`/`conditional_assignment?` in
/// `rubocop/cop/lint/shadowed_argument.rb`), leaning hard on two facts:
///
/// 1. Prism already resolves local-variable scoping for us: every
///    `LocalVariable{Read,Write,Target,Operator/Or/AndWrite}Node` carries a
///    `depth` (how many enclosing lexical scopes to walk up), computed by
///    prism using the exact same rules `VariableTable#find_variable`
///    manually re-derives upstream (blocks/lambdas are "soft" scopes a name
///    can resolve through; `def`/`class`/`module`/`sclass` are hard resets).
///    So `SaCollector` just keeps a flat stack of frames (one per lexical
///    scope, pushed for EVERY def/class/module/sclass/block/lambda) and
///    indexes `frames[frames.len() - 1 - depth]` — no re-implementation of
///    scope resolution needed.
/// 2. `check_argument` only ever cares about variables declared as method or
///    block PARAMETERS (`argument.method_argument? || argument.block_argument?`,
///    and `explicit_block_local_variable?` — a `;shadow` block-local — bails
///    out immediately). So `SaCollector` only ever creates a tracked `SaVar`
///    for a real parameter declaration; plain local writes, and any
///    `;shadow`/pattern-match/`case/in` capture bindings, are simply never
///    registered as trackable names at all (mirroring
///    `process_pattern_match_variable`'s declare-but-never-assign-or-
///    reference behavior for `case/in`, and `explicit_block_local_variable?`
///    for `;shadow` locals) — a write/read that resolves (via depth) to an
///    untracked name is silently a no-op for us, exactly as it is a no-op
///    for this cop upstream.
///
/// What upstream's `Branch`/`Branchable` machinery is used for, replicated
/// more narrowly here:
///  - `conditional_assignment?` (is an assignment inside an `if`/`while`/
///    `until`(pre-condition only)/`case`/`case_match`/`block`/`lambda`/
///    `rescue`-region relative to the variable's OWN scope node): tracked via
///    `counters`, a stack parallel to `frames` where EVERY currently-open
///    frame's counter gets incremented while visiting one of those
///    constructs (decremented on exit). A variable's assignment records
///    `counters[owning_frame] > 0` at the moment it's visited — exactly
///    "is there such a construct between here and that scope's own node",
///    without needing real ancestor pointers.
///  - The `argument_references`/`assignment.references` backward-marking
///    used to exclude "this reference is really evaluating a LATER
///    reassignment's value, not a genuine use of the original argument" is
///    approximated (see `sa_check_argument`) as: an explicit (non-`super`/
///    `binding`) reference only counts as "used before shadowing" if no
///    assignment to the variable happened before it — i.e. it's reading the
///    variable's very first (original-argument) value. This is exact for
///    every fixture example and any straight-line code; it can only diverge
///    from upstream's fuller branch-aware bookkeeping in contrived
///    multi-branch/loop reassignment interleavings not exercised here (see
///    the residual-risk note in the final report).
///
/// Not modeled at all (upstream's `process_pattern_match_variable`/regexp
/// named captures never produce an assignment or reference either, so this
/// is a no-op both ways): `case/in` pattern captures, `/(?<name>)/ =~ str`
/// named captures. `for`-loop index variables get minimal best-effort
/// handling (rare for a `for`-variable to coincide with a pre-existing
/// argument name, since `for` doesn't open its own scope).
impl<'a> Cops<'a> {
    pub(crate) fn check_shadowed_argument(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Lint/ShadowedArgument";
        if !self.on(COP) {
            return;
        }
        let ignore_implicit = self.cfg.get(COP, "IgnoreImplicitReferences") == Some("true");
        let mut c = SaCollector {
            frames: vec![SaFrame { kind: SaKind::Other, names: HashMap::new() }],
            counters: vec![0],
            vars: Vec::new(),
            masgn_value_clamp: None,
        };
        use ruby_prism::Visit;
        c.visit(&node.as_node());
        for v in &mut c.vars {
            v.assignments.sort_by_key(|a| a.node_start);
            v.references.sort_by_key(|r| r.pos);
        }
        let mut offenses: Vec<(usize, Vec<u8>)> = Vec::new();
        for v in &c.vars {
            if let Some(start) = sa_check_argument(v, ignore_implicit) {
                offenses.push((start, v.name.clone()));
            }
        }
        offenses.sort_by_key(|(start, _)| *start);
        for (start, name) in offenses {
            let msg = format!(
                "Argument `{}` was shadowed by a local variable before it was used.",
                String::from_utf8_lossy(&name)
            );
            self.push(start, COP, false, msg);
        }
    }
}

/// One tracked method/block-parameter variable. `decl_start` is the
/// parameter's own name-span start offset — used as the offense anchor when
/// `check_argument` can't pin down a precise reassignment location
/// (`argument.declaration_node` upstream).
struct SaVar {
    name: Vec<u8>,
    decl_start: usize,
    assignments: Vec<SaAssignment>,
    references: Vec<SaReference>,
}

/// One assignment to a tracked variable. `node_start` is the assignment's
/// OWN node's start offset (never the `meta_assignment_node`'s — matches
/// `assignment.node.source_range.begin_pos`, e.g. for a masgn splat target
/// this is just `items`'s own span, not `*items, ... = ...`'s). `shorthand`
/// is true for `||=`/`&&=`/`+=`-shaped writes (upstream's
/// `assignment_node.shorthand_asgn?` — always skipped, never a shadowing
/// candidate, since they inherently read the old value). `uses_var` is
/// upstream's `uses_var?` def_node_search: does this assignment's effective
/// node (its RHS value, for a masgn also every sibling target/the RHS)
/// contain a read of this same variable NAME (purely syntactic, exactly
/// like upstream's `def_node_search` — not scope-aware). `conditional` is
/// `conditional_assignment?`: was there an `if`/`while`/`until`/`case`/
/// `case_match`/block/lambda/rescue-region ancestor between this assignment
/// and the variable's own scope node.
struct SaAssignment {
    node_start: usize,
    shorthand: bool,
    uses_var: bool,
    conditional: bool,
}

/// One reference (read) of a tracked variable. `explicit` is false only for
/// the two implicit-reference sources upstream recognizes: a zero-arity
/// `super` (references the nearest enclosing `def`'s own parameters only)
/// and a bare, argument-less `binding` call (references every parameter
/// reachable from its own scope, walking outward through block/lambda
/// scopes).
struct SaReference {
    pos: usize,
    explicit: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum SaKind {
    /// A `def`/`defs` scope — the only kind whose vars are ever
    /// `method_argument?` (relevant to zero-arity `super`'s implicit
    /// reference, which only ever touches a `def`'s own parameters).
    Def,
    /// A `block`/`lambda` scope — "soft": zero-arity `super` and `binding`
    /// both walk straight through it to reach an enclosing scope; entering
    /// one also increments every OPEN frame's conditional counter (it's a
    /// `:block`-type ancestor for anything outside it).
    Block,
    /// `class`/`module`/`sclass`, or the file's top level: a hard scope
    /// boundary that owns no trackable parameters, but still needs its own
    /// frame so nested defs/blocks compute the right depth-relative index,
    /// and still stops an outward `super`/`binding` walk once reached.
    Other,
}

struct SaFrame {
    kind: SaKind,
    /// Declared parameter name -> index into the collector's flat `vars`.
    names: HashMap<Vec<u8>, usize>,
}

/// The scope-tracking visitor described in the module comment above
/// `check_shadowed_argument`.
struct SaCollector {
    frames: Vec<SaFrame>,
    /// While traversing a masgn's VALUE: the masgn's own start offset.
    /// Ruby evaluates the RHS before any target is assigned, so an implicit
    /// (`super`/`binding`) reference arising there must count as happening
    /// AT the assignment, not after it (`index, algorithm, arg = super` —
    /// rails mysql adapter false positive); position-clamping the recorded
    /// reference to the masgn start reproduces VariableForce's event order.
    masgn_value_clamp: Option<usize>,
    /// Parallel to `frames`: `counters[i]` counts how many currently-open
    /// `if`/`while`/`until`/`case`/`case_match`/block/lambda/rescue-region
    /// constructs sit between the CURRENT traversal position and
    /// `frames[i]`'s own scope node — i.e. exactly `conditional_assignment?`
    /// for a variable owned by frame `i`, without needing ancestor pointers.
    counters: Vec<u32>,
    vars: Vec<SaVar>,
}

impl SaCollector {
    fn resolve(&self, name: &[u8], depth: u32) -> Option<(usize, usize)> {
        let top = self.frames.len().checked_sub(1)?;
        let f = top.checked_sub(depth as usize)?;
        self.frames[f].names.get(name).map(|&idx| (idx, f))
    }

    fn declare_arg(&mut self, name: &[u8], decl_start: usize) {
        let frame = self.frames.last_mut().unwrap();
        if frame.names.contains_key(name) {
            return;
        }
        let idx = self.vars.len();
        self.vars.push(SaVar { name: name.to_vec(), decl_start, assignments: Vec::new(), references: Vec::new() });
        self.frames.last_mut().unwrap().names.insert(name.to_vec(), idx);
    }

    fn record_write(&mut self, name: &[u8], depth: u32, pos: usize, shorthand: bool, uses_var: bool) {
        if let Some((idx, f)) = self.resolve(name, depth) {
            let conditional = self.counters[f] > 0;
            self.vars[idx].assignments.push(SaAssignment { node_start: pos, shorthand, uses_var, conditional });
        }
    }

    fn record_reference(&mut self, name: &[u8], depth: u32, pos: usize, explicit: bool) {
        if let Some((idx, _)) = self.resolve(name, depth) {
            self.vars[idx].references.push(SaReference { pos, explicit });
        }
    }

    fn enter_conditional(&mut self) {
        for c in &mut self.counters {
            *c += 1;
        }
    }
    fn exit_conditional(&mut self) {
        for c in &mut self.counters {
            *c -= 1;
        }
    }
    fn enter_frame(&mut self, kind: SaKind) {
        self.frames.push(SaFrame { kind, names: HashMap::new() });
        self.counters.push(0);
    }
    fn exit_frame(&mut self) {
        self.frames.pop();
        self.counters.pop();
    }
    fn enter_block_frame(&mut self) {
        self.enter_conditional();
        self.enter_frame(SaKind::Block);
    }
    fn exit_block_frame(&mut self) {
        self.exit_frame();
        self.exit_conditional();
    }

    /// Zero-arity `super`: `process_zero_arity_super` — walks from the
    /// CURRENT scope outward, referencing a `Def` frame's own vars (the only
    /// kind that's ever `method_argument?`) and STOPPING there; a `Block`
    /// frame contributes nothing (its vars are `block_argument?`, filtered
    /// out upstream too) but doesn't stop the walk; any other (hard,
    /// non-`Def`) frame stops the walk without marking anything.
    fn mark_zsuper(&mut self, pos: usize) {
        let pos = self.masgn_value_clamp.map_or(pos, |c| c.min(pos));
        for i in (0..self.frames.len()).rev() {
            match self.frames[i].kind {
                SaKind::Def => {
                    let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
                    for idx in idxs {
                        self.vars[idx].references.push(SaReference { pos, explicit: false });
                    }
                    break;
                }
                SaKind::Block => continue,
                SaKind::Other => break,
            }
        }
    }

    /// Bare `binding` call: `VariableTable#accessible_variables` — marks the
    /// current scope's own vars, and keeps walking (and marking) outward
    /// through `Block` frames, stopping right after including the first
    /// non-`Block` frame.
    fn mark_binding(&mut self, pos: usize) {
        let pos = self.masgn_value_clamp.map_or(pos, |c| c.min(pos));
        let mut i = self.frames.len();
        while i > 0 {
            i -= 1;
            let is_block = self.frames[i].kind == SaKind::Block;
            let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
            for idx in idxs {
                self.vars[idx].references.push(SaReference { pos, explicit: false });
            }
            if !is_block {
                break;
            }
        }
    }

    /// `Assignment#meta_assignment_node`'s `multiple_assignment_node`/
    /// `rest_assignment_node` case, recursively: a masgn target is either a
    /// splat (unwrap one level), a nested `(a, b)` sub-mlhs (flatten into its
    /// own lefts/rest/rights), a local-variable target (record the write —
    /// `uses_var?`'s `def_node_search` is purely syntactic over the WHOLE
    /// masgn node, so e.g. `x, arr[x] = 1, 2` counts as a use of `x` even
    /// though that read sits in a sibling target, not the RHS `value`), or
    /// anything else (index/attr/ivar/etc targets — just visit normally so
    /// nested reads inside e.g. `arr[i]` still get picked up).
    fn process_masgn_target<'pr>(&mut self, t: &ruby_prism::Node<'pr>, whole: &ruby_prism::Node<'pr>)
    where
        Self: ruby_prism::Visit<'pr>,
    {
        use ruby_prism::Visit;
        if let Some(splat) = t.as_splat_node() {
            if let Some(expr) = splat.expression() {
                self.process_masgn_target(&expr, whole);
            }
            return;
        }
        if let Some(mt) = t.as_multi_target_node() {
            let mut inner: Vec<ruby_prism::Node<'pr>> = mt.lefts().iter().collect();
            if let Some(r) = mt.rest() {
                inner.push(r);
            }
            inner.extend(mt.rights().iter());
            for it in &inner {
                self.process_masgn_target(it, whole);
            }
            return;
        }
        if let Some(lvt) = t.as_local_variable_target_node() {
            let name = lvt.name();
            let name = name.as_slice();
            let uses_var = sa_contains_lvar_read(whole, name);
            self.record_write(name, lvt.depth(), lvt.location().start_offset(), false, uses_var);
            return;
        }
        self.visit(t);
    }
}

/// `def_node_search :uses_var?, '(lvar %)'` — a purely syntactic (NOT
/// scope-aware) search for any `lvar`-equivalent read of `name` anywhere in
/// `node`'s subtree, matching upstream's naive `def_node_search` exactly
/// (including nested blocks/scopes, which upstream's search doesn't skip
/// either).
fn sa_contains_lvar_read(node: &ruby_prism::Node, name: &[u8]) -> bool {
    struct Search<'n> {
        name: &'n [u8],
        found: bool,
    }
    impl<'pr, 'n> ruby_prism::Visit<'pr> for Search<'n> {
        fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
            if node.name().as_slice() == self.name {
                self.found = true;
            }
        }
    }
    let mut s = Search { name, found: false };
    use ruby_prism::Visit;
    s.visit(node);
    s.found
}

/// Port of `ShadowedArgument#check_argument` /
/// `#shadowing_assignment` / `#assignment_without_argument_usage`. Returns
/// the offense anchor (byte offset) if `v` is shadowed.
fn sa_check_argument(v: &SaVar, ignore_implicit: bool) -> Option<usize> {
    // `return unless argument.referenced?`
    if v.references.is_empty() {
        return None;
    }

    // `assignment_without_argument_usage`: find the first assignment that
    // doesn't reference the variable's own old value, skipping (and
    // propagating `location_known = false` for) ones that are themselves
    // shorthand (`||=` etc, always "use" their argument) or inside a
    // conditional/block/rescue region (their execution isn't guaranteed, so
    // the precise shadowing location becomes undecidable even once a later,
    // unconditional overwrite is found).
    let mut location_known = true;
    let mut found: Option<&SaAssignment> = None;
    for a in &v.assignments {
        if a.shorthand {
            location_known = false;
            continue;
        }
        if !a.uses_var {
            if a.conditional {
                location_known = false;
                continue;
            }
            found = Some(a);
            break;
        }
        // uses its own old value: not a shadowing candidate, but doesn't
        // affect `location_known` either — keep scanning.
    }
    let assignment = found?;
    let threshold = assignment.node_start;

    // `shadowing_assignment`: was the variable genuinely used (its ORIGINAL
    // argument value read) at or before the shadowing assignment? An
    // explicit reference only counts if no assignment preceded it — once any
    // assignment has happened, a later explicit read reflects the
    // REASSIGNED value, not the original argument (upstream's
    // `argument_references` excludes exactly these via `assignment.
    // references`' backward marking). An implicit (`super`/`binding`)
    // reference is never excluded this way, and additionally short-circuits
    // entirely when `IgnoreImplicitReferences` is on, regardless of
    // position.
    let first_assignment_pos = v.assignments.first().map(|a| a.node_start);
    for r in &v.references {
        if !r.explicit {
            if ignore_implicit {
                return None;
            }
            if r.pos <= threshold {
                return None;
            }
            continue;
        }
        let excluded_as_post_reassignment_read = first_assignment_pos.is_some_and(|p| p < r.pos);
        if excluded_as_post_reassignment_read {
            continue;
        }
        if r.pos <= threshold {
            return None;
        }
    }

    Some(if location_known { assignment.node_start } else { v.decl_start })
}

impl<'pr> ruby_prism::Visit<'pr> for SaCollector {
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let Some(recv) = node.receiver() {
            self.visit(&recv);
        }
        self.enter_frame(SaKind::Def);
        if let Some(params) = node.parameters() {
            self.visit_parameters_node(&params);
        }
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.visit(&node.constant_path());
        if let Some(sup) = node.superclass() {
            self.visit(&sup);
        }
        self.enter_frame(SaKind::Other);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.visit(&node.constant_path());
        self.enter_frame(SaKind::Other);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        self.visit(&node.expression());
        self.enter_frame(SaKind::Other);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_block_node(&mut self, node: &ruby_prism::BlockNode<'pr>) {
        self.enter_block_frame();
        ruby_prism::visit_block_node(self, node);
        self.exit_block_frame();
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        self.enter_block_frame();
        ruby_prism::visit_lambda_node(self, node);
        self.exit_block_frame();
    }
    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice(), node.name_loc().start_offset());
        self.visit(&node.value());
    }
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.declare_arg(name.as_slice(), loc.start_offset());
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice(), node.name_loc().start_offset());
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice(), node.name_loc().start_offset());
        self.visit(&node.value());
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.declare_arg(name.as_slice(), loc.start_offset());
        }
    }
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.declare_arg(name.as_slice(), loc.start_offset());
        }
    }
    // `;shadow` block-locals (`explicit_block_local_variable?`) are
    // deliberately never registered — see the module doc comment.
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        let name = node.name();
        let name = name.as_slice();
        let uses_var = sa_contains_lvar_read(&node.value(), name);
        self.record_write(name, node.depth(), node.location().start_offset(), false, uses_var);
        self.visit(&node.value());
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        let name = node.name();
        let name = name.as_slice();
        let pos = node.location().start_offset();
        self.record_reference(name, node.depth(), pos, true);
        self.record_write(name, node.depth(), pos, true, true);
        self.visit(&node.value());
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        let name = node.name();
        let name = name.as_slice();
        let pos = node.location().start_offset();
        self.record_reference(name, node.depth(), pos, true);
        self.record_write(name, node.depth(), pos, true, true);
        self.visit(&node.value());
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        let name = node.name();
        let name = name.as_slice();
        let pos = node.location().start_offset();
        self.record_reference(name, node.depth(), pos, true);
        self.record_write(name, node.depth(), pos, true, true);
        self.visit(&node.value());
    }
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        let name = node.name();
        self.record_reference(name.as_slice(), node.depth(), node.location().start_offset(), true);
    }
    fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
        let whole = node.as_node();
        let mut targets: Vec<ruby_prism::Node> = node.lefts().iter().collect();
        if let Some(r) = node.rest() {
            targets.push(r);
        }
        targets.extend(node.rights().iter());
        for t in &targets {
            self.process_masgn_target(t, &whole);
        }
        let saved = self.masgn_value_clamp;
        self.masgn_value_clamp = Some(whole.location().start_offset());
        self.visit(&node.value());
        self.masgn_value_clamp = saved;
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        self.visit(&node.collection());
        let idx = node.index();
        if let Some(lvt) = idx.as_local_variable_target_node() {
            let name = lvt.name();
            let name = name.as_slice();
            // `for_assignment_node`'s meta node is the WHOLE `ForNode`
            // (index + collection + body): `uses_var?`'s `def_node_search`
            // therefore also sees reads inside the loop BODY, not just the
            // collection expression — almost always true for a real `for`
            // loop, which is why reassigning a `for`'s own iteration
            // variable essentially never registers as a shadowing
            // candidate in practice.
            let uses_var = sa_contains_lvar_read(&node.collection(), name)
                || node.statements().is_some_and(|st| sa_contains_lvar_read(&st.as_node(), name));
            self.record_write(name, lvt.depth(), lvt.location().start_offset(), false, uses_var);
        } else {
            self.visit(&idx);
        }
        if let Some(st) = node.statements() {
            self.visit(&st.as_node());
        }
    }
    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        self.mark_zsuper(node.location().start_offset());
        if let Some(block) = node.block() {
            self.visit_block_node(&block);
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if node.name().as_slice() == b"binding" {
            let empty_args =
                node.arguments().map(|a| a.arguments().iter().next().is_none()).unwrap_or(true);
            if empty_args {
                self.mark_binding(node.location().start_offset());
            }
        }
        ruby_prism::visit_call_node(self, node);
    }
    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        self.enter_conditional();
        ruby_prism::visit_if_node(self, node);
        self.exit_conditional();
    }
    fn visit_unless_node(&mut self, node: &ruby_prism::UnlessNode<'pr>) {
        self.enter_conditional();
        ruby_prism::visit_unless_node(self, node);
        self.exit_conditional();
    }
    fn visit_case_node(&mut self, node: &ruby_prism::CaseNode<'pr>) {
        self.enter_conditional();
        ruby_prism::visit_case_node(self, node);
        self.exit_conditional();
    }
    fn visit_case_match_node(&mut self, node: &ruby_prism::CaseMatchNode<'pr>) {
        self.enter_conditional();
        ruby_prism::visit_case_match_node(self, node);
        self.exit_conditional();
    }
    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        if node.is_begin_modifier() {
            ruby_prism::visit_while_node(self, node);
        } else {
            self.enter_conditional();
            ruby_prism::visit_while_node(self, node);
            self.exit_conditional();
        }
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        if node.is_begin_modifier() {
            ruby_prism::visit_until_node(self, node);
        } else {
            self.enter_conditional();
            ruby_prism::visit_until_node(self, node);
            self.exit_conditional();
        }
    }
    fn visit_rescue_modifier_node(&mut self, node: &ruby_prism::RescueModifierNode<'pr>) {
        self.enter_conditional();
        self.visit(&node.expression());
        self.visit(&node.rescue_expression());
        self.exit_conditional();
    }
    // `begin ... rescue ... else ... ensure ... end` — upstream's SINGLE
    // `:rescue` node type (spanning main body + rescue clauses + else body,
    // but NOT the separate `:ensure` wrapper) maps to prism's `BeginNode`
    // only when `rescue_clause` is present; the main body, every chained
    // `rescue_clause`, and the `else_clause` all sit "inside" it (ancestor-
    // wise) for `conditional_assignment?`'s purposes, but `ensure_clause`
    // does not (`type?(:block, :rescue)` never matches `:ensure`).
    fn visit_begin_node(&mut self, node: &ruby_prism::BeginNode<'pr>) {
        if node.rescue_clause().is_some() {
            self.enter_conditional();
            if let Some(st) = node.statements() {
                self.visit(&st.as_node());
            }
            if let Some(rc) = node.rescue_clause() {
                self.visit_rescue_node(&rc);
            }
            if let Some(ec) = node.else_clause() {
                self.visit(&ec.as_node());
            }
            self.exit_conditional();
        } else if let Some(st) = node.statements() {
            self.visit(&st.as_node());
        }
        if let Some(en) = node.ensure_clause() {
            self.visit(&en.as_node());
        }
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        for exc in node.exceptions().iter() {
            self.visit(&exc);
        }
        if let Some(reference) = node.reference() {
            if let Some(lvt) = reference.as_local_variable_target_node() {
                let name = lvt.name();
                self.record_write(name.as_slice(), lvt.depth(), lvt.location().start_offset(), false, false);
            } else {
                self.visit(&reference);
            }
        }
        if let Some(st) = node.statements() {
            self.visit(&st.as_node());
        }
        if let Some(sub) = node.subsequent() {
            self.visit(&sub.as_node());
        }
    }
}


// ---------------------------------------------------------------------
// Lint/Void
//
// Architecture note: upstream's `on_begin`/`on_kwbegin` fires for EVERY
// whitequark `:begin`/`:kwbegin` node found ANYWHERE in the tree (rubocop's
// generic per-node-type dispatch, independent of `check_begin`'s own
// internal recursion). A whitequark `:begin` node is exactly one of:
//   - an implicit 2+-statement sequence (def/block/for/ensure/if/case/
//     when/in/rescue/top-level bodies) — prism: a `StatementsNode` with
//     `body().len() >= 2` (a single statement is NEVER wrapped upstream,
//     matching this codebase's established `StatementsNode` convention —
//     see `DnFrame::BeginGroup`'s doc in mod.rs).
//   - an explicit parenthesized grouping `(...)` — prism: `ParenthesesNode`
//     — which whitequark represents as `:begin` regardless of how many
//     statements it holds (0, 1, or many).
// An explicit `begin...end`/`:kwbegin` is a DIFFERENT whitequark type and
// is only reached via `EnsureNode`'s clause / `EnsureNode`'s statements
// via the generic `StatementsNode` path above; `check_void_op`'s own
// `node.children.first while node&.begin_type?` unwrap loop ONLY unwraps
// `:begin` (i.e. `ParenthesesNode` here), never `:kwbegin`.
//
// `void_context?` (whether the LAST child of a 2+-statement group is ALSO
// checked, not just popped) is `true` upstream only for: `EnsureNode`
// (always), `ForNode` (always), `DefNode`/`DefNode` w/ receiver (only
// `initialize` or an assignment-method `foo=`), and `BlockNode` (only
// `each`/`tap`). EVERY other container (top-level program, `if`/`unless`/
// `when`/`in`/`case`-`else` branches, a plain `begin...end`, a `rescue`/
// `resbody`'s own main body) never responds to `void_context?` at all, so
// it defaults to `false`. This is threaded top-down via `void_pending_ctx`
// (see its field doc in mod.rs), which the FOUR special containers set
// right before descending into a body that is DIRECTLY a `StatementsNode`
// (never set for an implicit rescue/else/ensure-wrapping `BeginNode`
// instead — matching upstream's main-body-under-rescue/ensure never being
// the LAST child of its real `:rescue`/`:ensure` parent, hence never void,
// exactly the same as the "unset" default) — see `visit_statements_node`,
// `visit_def_node`, `visit_block_node`, `visit_for_node`,
// `visit_ensure_node` in mod.rs.
//
// `inside_each_block` (`each_ancestor(:any_block).first&.method?(:each)`)
// is tracked as a genuine ancestor stack (`void_each_stack`, pushed/popped
// by `visit_block_node`/`visit_lambda_node` for EVERY block/`->` literal —
// prism's translator rewrites `->(){}` into the same "block whose send is
// `lambda`" shape) so a nested `.each` block correctly shadows/un-shadows
// through arbitrarily deep if/case/def nesting, matching `each_ancestor`
// finding only the NEAREST block ancestor.
impl<'a> super::Cops<'a> {
    const COP: &'static str = "Lint/Void";

    /// `check_begin`: the whitequark `:begin`/`:kwbegin` handler, applied
    /// to any 2+-statement group (see the module doc above for how prism
    /// nodes map onto this). `void_ctx` is this group's own
    /// `void_context?` verdict (always `false` unless the caller threaded
    /// one in via `void_pending_ctx`).
    pub(crate) fn check_void_begin_group(&mut self, items: &[ruby_prism::Node], void_ctx: bool) {
        if !self.on(Self::COP) {
            return;
        }
        let inside_each = self.void_each_stack.last().copied().unwrap_or(false);
        let n = items.len();
        // `expressions.pop if !in_void_context?(node) || inside_each_block`
        let take_n = if !void_ctx || inside_each { n.saturating_sub(1) } else { n };
        for expr in &items[..take_n] {
            // `check_void_op(expr) { inside_each_block }` — a block is
            // ALWAYS given here, so `return if block && yield(node)`
            // reduces to `return if inside_each_block`.
            self.check_void_op(expr, inside_each);
            self.check_void_expr(expr, false);
        }
    }

    /// `check_void_op`: unwraps parenthesized grouping(s), then flags a
    /// `BINARY_OPERATORS`/`UNARY_OPERATORS` call whose return value is
    /// discarded. `suppress` is upstream's `block && yield(node)` — `true`
    /// only when called from `check_begin`'s per-statement loop while
    /// `inside_each_block`; the `on_block`/`on_ensure` single-statement
    /// callers below never suppress (upstream never passes a block there).
    pub(crate) fn check_void_op(&mut self, node: &ruby_prism::Node, suppress: bool) {
        if !self.on(Self::COP) {
            return;
        }
        // `node = node.children.first while node&.begin_type?` — ONLY a
        // parenthesized grouping maps to whitequark's `:begin` here (an
        // explicit `begin...end`/`:kwbegin` is a distinct type, never
        // unwrapped by this loop upstream either).
        if let Some(p) = node.as_parentheses_node() {
            let Some(inner) = p.body() else { return };
            if let Some(s) = inner.as_statements_node() {
                let Some(first) = s.body().iter().next() else { return };
                self.check_void_op(&first, suppress);
                return;
            }
            self.check_void_op(&inner, suppress);
            return;
        }
        let Some(call) = node.as_call_node() else { return };
        let name_id = call.name();
        let name = name_id.as_slice();
        const UNARY: &[&[u8]] = &[b"+@", b"-@", b"~", b"!"];
        const BINARY: &[&[u8]] = &[b"*", b"/", b"%", b"+", b"-", b"==", b"===", b"!=", b"<", b">", b"<=", b">=", b"<=>"];
        let is_unary = UNARY.contains(&name);
        if !is_unary && !BINARY.contains(&name) {
            return;
        }
        // `if !UNARY_OPERATORS.include?(...) && node.loc.dot && node.arguments.none?; return; end`
        if !is_unary && call.call_operator_loc().is_some() && void_call_args_empty(&call) {
            return;
        }
        if suppress {
            return;
        }
        let Some(sel) = call.message_loc() else { return };
        let msg = format!("Operator `{}` used in void context.", String::from_utf8_lossy(name));
        self.push(sel.start_offset(), Self::COP, true, msg);
        self.autocorrect_void_op(&call);
    }

    fn autocorrect_void_op(&mut self, call: &ruby_prism::CallNode) {
        if void_call_args_empty(call) {
            // `corrector.replace(node, node.receiver.source)` — always
            // present: every operator call reaching here (unary, or a
            // dot-call with zero args already excluded above) has a receiver.
            let Some(recv) = call.receiver() else { return };
            let recv_src = self.node_src(&recv).to_vec();
            let loc = call.location();
            self.fixes.push((loc.start_offset(), loc.end_offset(), recv_src));
        } else {
            if let Some(dot) = call.call_operator_loc() {
                self.fixes.push((dot.start_offset(), dot.end_offset(), Vec::new()));
            }
            let Some(sel) = call.message_loc() else { return };
            // `range_with_surrounding_space(range: node.loc.selector, side: :both, newlines: false)`
            let (s, e) = void_expand_both_horizontal_ws(self.src, sel.start_offset(), sel.end_offset());
            self.fixes.push((s, e, b"\n".to_vec()));
        }
    }

    /// `check_expression`: dispatches to the `if`/`case`/`case...in`
    /// single-branch-value checkers, else falls through to
    /// `check_void_expression_nodes`. `no_autocorrect` mirrors upstream's
    /// `node.parent.type?(:if, :case, :when, :case_match, :in_pattern)`
    /// guard in `autocorrect_void_expression` — always `true` once we've
    /// entered ANY branch-value recursion below (an `if`/`case` node's own
    /// non-branch value never reaches here directly as a "parent" in that
    /// sense, so passing it straight through matches exactly).
    pub(crate) fn check_void_expr(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        if !self.on(Self::COP) {
            return;
        }
        if let Some(if_node) = node.as_if_node() {
            // `check_if_expression`: ONLY the truthy/then branch — upstream
            // never looks at `else_branch` at all (a real asymmetry, kept
            // byte-for-byte).
            self.check_void_branch_value(if_node.statements());
            return;
        }
        if let Some(u) = node.as_unless_node() {
            self.check_void_branch_value(u.statements());
            return;
        }
        if let Some(c) = node.as_case_node() {
            for cond in c.conditions().iter() {
                if let Some(w) = cond.as_when_node() {
                    self.check_void_branch_value(w.statements());
                }
            }
            if let Some(e) = c.else_clause() {
                self.check_void_branch_value(e.statements());
            }
            return;
        }
        if let Some(c) = node.as_case_match_node() {
            for cond in c.conditions().iter() {
                if let Some(inp) = cond.as_in_node() {
                    self.check_void_branch_value(inp.statements());
                }
            }
            if let Some(e) = c.else_clause() {
                self.check_void_branch_value(e.statements());
            }
            return;
        }
        self.check_void_expression_nodes(node, no_autocorrect);
    }

    /// A `when`/`in`/`else` branch's body is only a checkable "value" when
    /// it's EXACTLY one statement — 0 statements means no body (upstream's
    /// `if when_node.body`/`if in_pattern_node.body` guard); 2+ statements
    /// is instead separately flagged (non-last members only, `void_ctx:
    /// false`) via the generic `StatementsNode` handling in
    /// `visit_statements_node`, matching upstream's independent `on_begin`
    /// dispatch for that nested `:begin` node.
    fn check_void_branch_value(&mut self, stmts: Option<ruby_prism::StatementsNode>) {
        let Some(stmts) = stmts else { return };
        let list = stmts.body();
        if list.iter().count() != 1 {
            return;
        }
        if let Some(only) = list.iter().next() {
            self.check_void_expr(&only, true);
        }
    }

    /// `check_void_expression_nodes`: literal / variable-or-constant /
    /// `self` / `defined?`-or-lambda-or-proc, then (only when
    /// `CheckForMethodsWithNoSideEffects`) a nonmutating method call.
    fn check_void_expression_nodes(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        self.check_void_literal(node, no_autocorrect);
        self.check_void_var(node, no_autocorrect);
        self.check_void_self(node, no_autocorrect);
        self.check_defined_or_lambda(node, no_autocorrect);
        if self.cfg.get(Self::COP, "CheckForMethodsWithNoSideEffects") == Some("true") {
            self.check_void_nonmutating(node);
        }
    }

    fn check_void_literal(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        if !void_entirely_literal(node) {
            return;
        }
        // `|| node.xstr_type? || node.range_type? || node.nil_type?`
        if node.as_x_string_node().is_some() || node.as_interpolated_x_string_node().is_some() {
            return;
        }
        if node.as_range_node().is_some() {
            return;
        }
        if node.as_nil_node().is_some() {
            return;
        }
        let src = self.node_src(node);
        let msg = format!("Literal `{}` used in void context.", String::from_utf8_lossy(src));
        self.push(node.location().start_offset(), Self::COP, true, msg);
        self.autocorrect_void_expression(node, no_autocorrect);
    }

    fn check_void_var(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        // `__ENCODING__`: a nested-constant-path shape upstream
        // (`Encoding::UTF_8`) whose `.source` reads literally
        // `"__ENCODING__"`, matching `SPECIAL_KEYWORDS` — always VAR_MSG
        // over the full node. Prism gives a dedicated `SourceEncodingNode`
        // instead of a real constant path, so it's special-cased directly;
        // `__FILE__`/`__LINE__` are plain literal types upstream (`str`/
        // `int`), handled by `check_void_literal` via `SourceFileNode`/
        // `SourceLineNode` in `void_is_literal_leaf`, never here.
        if node.as_source_encoding_node().is_some() {
            let src = self.node_src(node);
            let msg = format!("Variable `{}` used in void context.", String::from_utf8_lossy(src));
            self.push(node.location().start_offset(), Self::COP, true, msg);
            self.autocorrect_void_expression(node, no_autocorrect);
            return;
        }
        let is_var = node.as_local_variable_read_node().is_some()
            || node.as_instance_variable_read_node().is_some()
            || node.as_class_variable_read_node().is_some()
            || node.as_global_variable_read_node().is_some();
        if is_var {
            // `offense_range = node.loc.name; message = ... node.loc.name.source`
            // — for every variable-read type, `loc.name` spans the exact
            // same range as the whole node (no separate sigil-less name
            // sub-location), so the full node source/range serve directly.
            let src = self.node_src(node);
            let msg = format!("Variable `{}` used in void context.", String::from_utf8_lossy(src));
            self.push(node.location().start_offset(), Self::COP, true, msg);
            self.autocorrect_void_expression(node, no_autocorrect);
            return;
        }
        if node.as_constant_read_node().is_some() || node.as_constant_path_node().is_some() {
            let src = self.node_src(node);
            let msg = format!("Constant `{}` used in void context.", String::from_utf8_lossy(src));
            self.push(node.location().start_offset(), Self::COP, true, msg);
            self.autocorrect_void_expression(node, no_autocorrect);
        }
    }

    fn check_void_self(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        if node.as_self_node().is_none() {
            return;
        }
        self.push(node.location().start_offset(), Self::COP, true, "`self` used in void context.");
        self.autocorrect_void_expression(node, no_autocorrect);
    }

    fn check_defined_or_lambda(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        if node.as_defined_node().is_none() && !void_lambda_or_proc(node) {
            return;
        }
        let src = self.node_src(node);
        let msg = format!("`{}` used in void context.", String::from_utf8_lossy(src));
        self.push(node.location().start_offset(), Self::COP, true, msg);
        self.autocorrect_void_expression(node, no_autocorrect);
    }

    fn check_void_nonmutating(&mut self, node: &ruby_prism::Node) {
        // Both `node.type?(:send, :any_block)` alternatives collapse to a
        // plain `CallNode` in prism — a block, if any, is a FIELD of the
        // call, never a separate wrapping node (`autocorrect_nonmutating_
        // send`'s `node.send_type? ? node : node.send_node` is therefore
        // always just `node` itself here too).
        let Some(call) = node.as_call_node() else { return };
        const WITH_BANG: &[&[u8]] = &[
            b"capitalize", b"chomp", b"chop", b"compact", b"delete_prefix", b"delete_suffix",
            b"downcase", b"encode", b"flatten", b"gsub", b"lstrip", b"merge", b"next", b"reject",
            b"reverse", b"rotate", b"rstrip", b"scrub", b"select", b"shuffle", b"slice", b"sort",
            b"sort_by", b"squeeze", b"strip", b"sub", b"succ", b"swapcase", b"tr", b"tr_s",
            b"transform_values", b"unicode_normalize", b"uniq", b"upcase",
        ];
        const REPLACEABLE_BY_EACH: &[&[u8]] = &[b"collect", b"map"];
        let name_id = call.name();
        let name = name_id.as_slice();
        let suggestion: Vec<u8> = if REPLACEABLE_BY_EACH.contains(&name) {
            b"each".to_vec()
        } else if WITH_BANG.contains(&name) {
            let mut s = name.to_vec();
            s.push(b'!');
            s
        } else {
            return;
        };
        let msg = format!(
            "Method `#{}` used in void context. Did you mean `#{}`?",
            String::from_utf8_lossy(name),
            String::from_utf8_lossy(&suggestion)
        );
        self.push(node.location().start_offset(), Self::COP, true, msg);
        // `autocorrect_nonmutating_send`: unconditional (no parent-type or
        // assignment-method exclusion, unlike `autocorrect_void_expression`).
        if let Some(sel) = call.message_loc() {
            self.fixes.push((sel.start_offset(), sel.end_offset(), suggestion));
        }
    }

    /// `autocorrect_void_expression`: skipped entirely when reached via an
    /// `if`/`case`/`case...in` branch-value (`no_autocorrect`) or when the
    /// nearest enclosing `def`/`defs` (any depth, through blocks/ifs — see
    /// `def_name_stack`) is an assignment method (`foo=`); otherwise
    /// removes the node plus its leading horizontal whitespace and ONE
    /// run of newlines.
    fn autocorrect_void_expression(&mut self, node: &ruby_prism::Node, no_autocorrect: bool) {
        if no_autocorrect {
            return;
        }
        if self.def_name_stack.last().is_some_and(|n| void_is_assignment_method_name(n)) {
            return;
        }
        let loc = node.location();
        let start = void_expand_left_ws_and_newlines(self.src, loc.start_offset());
        self.fixes.push((start, loc.end_offset(), Vec::new()));
    }
}

/// `each_value`/`each_key`-recursive `entirely_literal?`. `AssocSplatNode`
/// (`**kwsplat`) is silently ignored (contributes nothing, matching
/// upstream's `each_key`/`each_value` skipping kwsplats outright — an
/// empty-after-filtering hash's `.all?` is vacuously `true`).
fn void_entirely_literal(node: &ruby_prism::Node) -> bool {
    if let Some(arr) = node.as_array_node() {
        return arr.elements().iter().all(|e| void_entirely_literal(&e));
    }
    if let Some(h) = node.as_hash_node() {
        return h.elements().iter().all(|e| match e.as_assoc_node() {
            Some(pair) => void_entirely_literal(&pair.key()) && void_entirely_literal(&pair.value()),
            None => true,
        });
    }
    if let Some(call) = node.as_call_node() {
        return call.name().as_slice() == b"freeze" && call.receiver().is_some_and(|r| void_entirely_literal(&r));
    }
    void_is_literal_leaf(node)
}

/// `node.literal?` (`LITERALS` minus the composite array/hash types
/// already handled above) — `xstr`/`range`/`nil` are included here (they
/// ARE `literal?` upstream) but excluded one level up by `check_void_
/// literal`'s explicit `xstr_type?`/`range_type?`/`nil_type?` guards, not
/// here, matching upstream's own `entirely_literal?` vs `check_literal`
/// split exactly. `__FILE__`/`__LINE__` are plain `str`/`int` literals
/// upstream (whitequark folds them at parse time); prism instead gives
/// dedicated `SourceFileNode`/`SourceLineNode` types, included here as
/// their literal equivalents.
fn void_is_literal_leaf(node: &ruby_prism::Node) -> bool {
    node.as_string_node().is_some()
        || node.as_interpolated_string_node().is_some()
        || node.as_x_string_node().is_some()
        || node.as_interpolated_x_string_node().is_some()
        || node.as_integer_node().is_some()
        || node.as_float_node().is_some()
        || node.as_symbol_node().is_some()
        || node.as_interpolated_symbol_node().is_some()
        || node.as_regular_expression_node().is_some()
        || node.as_interpolated_regular_expression_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_range_node().is_some()
        || node.as_rational_node().is_some()
        || node.as_imaginary_node().is_some()
        || node.as_source_file_node().is_some()
        || node.as_source_line_node().is_some()
}

/// `node.arguments.empty?` / `.none?` (both spellings used upstream) —
/// `None` (no parens/args at all) or an empty argument list either count.
fn void_call_args_empty(call: &ruby_prism::CallNode) -> bool {
    call.arguments().is_none_or(|a| a.arguments().iter().count() == 0)
}

/// `Node#lambda_or_proc?`: `{lambda? proc?}`.
/// - `lambda?`: `(any_block (send nil? :lambda) ...)` — a stabby `->(){}`
///   (prism: dedicated `LambdaNode`, always a match) OR a real `lambda {
///   }`/`lambda do end` call (prism: `CallNode` named `lambda`, no
///   receiver, WITH a literal block).
/// - `proc?`: `(block (send nil? :proc) ...)` (a `proc { }` call, same
///   shape) OR `(block (send #global_const?(:Proc) :new) ...)` (`Proc.new
///   { }`) OR the blockless `(send #global_const?(:Proc) :new)` (a bare
///   `Proc.new` with no block or args at all).
fn void_lambda_or_proc(node: &ruby_prism::Node) -> bool {
    if node.as_lambda_node().is_some() {
        return true;
    }
    let Some(call) = node.as_call_node() else { return false };
    let name_id = call.name();
    let name = name_id.as_slice();
    let has_literal_block = call.block().is_some_and(|b| b.as_block_node().is_some());
    if has_literal_block {
        if call.receiver().is_none() && (name == b"lambda" || name == b"proc") {
            return true;
        }
        return name == b"new" && call.receiver().is_some_and(|r| void_is_proc_const(&r));
    }
    name == b"new"
        && call.receiver().is_some_and(|r| void_is_proc_const(&r))
        && call.arguments().is_none_or(|a| a.arguments().iter().count() == 0)
}

/// `global_const?(:Proc)`: a bare top-level `Proc` (`ConstantReadNode`) or
/// `::Proc` (`ConstantPathNode` with no parent, i.e. the `::` root).
fn void_is_proc_const(node: &ruby_prism::Node) -> bool {
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == b"Proc";
    }
    if let Some(c) = node.as_constant_path_node() {
        return c.parent().is_none() && c.name().is_some_and(|n| n.as_slice() == b"Proc");
    }
    false
}

/// `DefNode#assignment_method?`: `!comparison_method? && method_name.to_s.
/// end_with?('=')`.
pub(crate) fn void_is_assignment_method_name(name: &[u8]) -> bool {
    const COMPARISON: &[&[u8]] = &[b"==", b"===", b"!=", b"<=", b">=", b">", b"<"];
    !COMPARISON.contains(&name) && name.ends_with(b"=")
}

/// `RangeHelp#range_with_surrounding_space(range: node.loc.selector, side:
/// :both, newlines: false)` — horizontal whitespace only, both sides,
/// never crossing a newline.
fn void_expand_both_horizontal_ws(src: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {
    while start > 0 && matches!(src[start - 1], b' ' | b'\t') {
        start -= 1;
    }
    while end < src.len() && matches!(src[end], b' ' | b'\t') {
        end += 1;
    }
    (start, end)
}

/// `RangeHelp#range_with_surrounding_space(range: node.source_range, side:
/// :left)` (`newlines: true` by default) — horizontal whitespace THEN one
/// run of newlines, left side only (matches `RangeHelp#final_pos` exactly:
/// it never loops back to re-consume spaces/tabs after crossing a
/// newline, so an earlier line's own indentation is left untouched).
fn void_expand_left_ws_and_newlines(src: &[u8], mut start: usize) -> usize {
    while start > 0 && matches!(src[start - 1], b' ' | b'\t') {
        start -= 1;
    }
    while start > 0 && src[start - 1] == b'\n' {
        start -= 1;
    }
    start
}


// Lint/UnusedBlockArgument ---------------------------------------------------
//
// Upstream (`UnusedBlockArgument` including the shared `UnusedArgument`
// mixin) rides `VariableForce`'s `after_leaving_scope`: for every parameter
// (or explicit `;shadow` block-local) declared in a BLOCK's or LAMBDA's own
// parameter list, offend at the name's own location unless it's already
// `_`-prefixed, has at least one explicit reference, or is exempted by
// `allowed_block?` (not actually a block/lambda parameter, or an empty
// block body under `IgnoreEmptyBlocks`), `allowed_keyword_argument?`
// (`AllowUnusedKeywordArguments`), or (`;shadow` locals only)
// `used_block_local?` — reassigned at least once, regardless of whether
// it's ever READ.
//
// Ported as a standalone scope-tracking walk, the same shape as
// `Lint/UnderscorePrefixedVariableName`'s `UpvCollector` above (see its
// module comment for the full argument for why a single flat frame stack,
// indexed by prism's own `depth` field, is sufficient — a `def`/`class`/
// `module`/`sclass` boundary can never be crossed by a `depth`). The
// difference here: only BLOCK/LAMBDA frames ever declare a trackable name
// (their own parameters/shadow-locals, since this cop only ever cares about
// `block_argument?` variables); `Def`/`Other` frames are still pushed
// (empty) purely to keep the depth arithmetic correct for reads that occur
// after they close.
//
// Two upstream `VariableForce` special cases matter here (unlike
// `UnderscorePrefixedVariableName`, which only ever cares about EXPLICIT
// references): a bare, argument-less `binding` call (`process_send` — note
// upstream never actually checks for an absent receiver, just the method
// name and zero args) marks every variable in `VariableTable
// #accessible_variables` as referenced: the current scope's own vars, then
// each enclosing scope's own vars in turn AS LONG AS the scope just
// finished is itself block/lambda-typed, stopping right after the first
// non-block one is included. Zero-arity `super` (`process_zero_arity_
// super`) is a documented no-op for this cop: it only ever marks `method_
// argument?` variables (a `def`'s own params), never `block_argument?`
// ones, so it needs no handling at all.
impl<'a> super::Cops<'a> {
    /// `after_leaving_scope` + `check_argument`/`message`/`autocorrect`: runs
    /// the whole-file scope walk once (from `visit_program_node` in mod.rs),
    /// then re-derives each unused parameter's message/correction exactly as
    /// `UnusedArgument#check_argument` + `UnusedBlockArgument#message` +
    /// `UnusedArgCorrector.correct` would.
    pub(crate) fn check_unused_block_argument(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Lint/UnusedBlockArgument";
        if !self.on(COP) {
            return;
        }
        let ignore_empty_blocks = self.cfg.get(COP, "IgnoreEmptyBlocks") == Some("true");
        let allow_unused_kwargs = self.cfg.get(COP, "AllowUnusedKeywordArguments") == Some("true");

        let mut c = UbaCollector {
            frames: vec![UbaFrame { is_block: false, scope_idx: None, names: HashMap::new() }],
            vars: Vec::new(),
            scopes: Vec::new(),
        };
        use ruby_prism::Visit;
        c.visit(&node.as_node());

        for scope in &c.scopes {
            // `allowed_block?`'s `ignore_empty_blocks? && empty_block?`
            // disjunct — applies uniformly to every variable in the scope
            // (shadow-locals included, since `block_argument?` is true for
            // those too).
            if scope.is_empty && ignore_empty_blocks {
                continue;
            }
            let all_referenced_none = scope.var_indices.iter().all(|&i| !c.vars[i].referenced);
            let arg_count = scope.var_indices.len();
            for &i in &scope.var_indices {
                let v = &c.vars[i];
                if v.kind == UbaKind::ShadowArg {
                    // `used_block_local?`: reassigned at least once is
                    // allowed outright, regardless of read status.
                    if v.assigned {
                        continue;
                    }
                    if v.name.starts_with(b"_") || v.referenced {
                        continue;
                    }
                    let msg =
                        format!("Unused block local variable - `{}`.", String::from_utf8_lossy(&v.name));
                    self.push(v.name_start, COP, true, msg);
                    let mut repl = Vec::with_capacity(v.name.len() + 1);
                    repl.push(b'_');
                    repl.extend_from_slice(&v.name);
                    self.fixes.push((v.name_start, v.name_start + v.name.len(), repl));
                    continue;
                }
                let is_kw = matches!(v.kind, UbaKind::ReqKwArg | UbaKind::OptKwArg);
                if is_kw && allow_unused_kwargs {
                    continue;
                }
                if v.name.starts_with(b"_") || v.referenced {
                    continue;
                }
                let base = format!("Unused block argument - `{}`.", String::from_utf8_lossy(&v.name));
                let augmentation = if scope.is_lambda {
                    let mut m = uba_underscore_message(&v.name);
                    if all_referenced_none {
                        m.push_str(
                            " Also consider using a proc without arguments instead of a lambda \
                             if you want it to accept any arguments but don't care about them.",
                        );
                    }
                    m
                } else if all_referenced_none && !scope.is_define_method {
                    if arg_count > 1 {
                        "You can omit all the arguments if you don't care about them.".to_string()
                    } else {
                        "You can omit the argument if you don't care about it.".to_string()
                    }
                } else {
                    uba_underscore_message(&v.name)
                };
                let msg = format!("{base} {augmentation}");
                // `UnusedArgCorrector.correct`: `kwarg`/`kwoptarg` never get
                // a correction block's worth of actual edits (RuboCop still
                // reports them, just not as `[Correctable]`).
                let correctable = !is_kw;
                self.push(v.name_start, COP, correctable, msg);
                if correctable {
                    if v.kind == UbaKind::BlockArg {
                        let (start, end) = uba_blockarg_removal_range(self.src, v.full_start, v.full_end);
                        self.fixes.push((start, end, Vec::new()));
                    } else {
                        let mut repl = Vec::with_capacity(v.name.len() + 1);
                        repl.push(b'_');
                        repl.extend_from_slice(&v.name);
                        self.fixes.push((v.name_start, v.name_start + v.name.len(), repl));
                    }
                }
            }
        }
    }
}

/// `message_for_underscore_prefix`: shared by both the lambda and
/// normal-block augmentation paths.
fn uba_underscore_message(name: &[u8]) -> String {
    format!(
        "If it's necessary, use `_` or `_{}` as an argument name to indicate that it won't be used.",
        String::from_utf8_lossy(name)
    )
}

/// `UnusedArgCorrector.correct_for_blockarg_type`: an unused `&block`
/// parameter is REMOVED entirely (never `_`-prefixed) — `range_with_
/// surrounding_space(side: :left)` (eat trailing `[ \t]*`, then `\n*`) then
/// `range_with_surrounding_comma(:left)` (eat one further preceding `,`).
fn uba_blockarg_removal_range(src: &[u8], mut start: usize, end: usize) -> (usize, usize) {
    while start > 0 && matches!(src[start - 1], b' ' | b'\t') {
        start -= 1;
    }
    while start > 0 && src[start - 1] == b'\n' {
        start -= 1;
    }
    while start > 0 && src[start - 1] == b',' {
        start -= 1;
    }
    (start, end)
}

#[derive(Clone, Copy, PartialEq)]
enum UbaKind {
    Arg,
    OptArg,
    RestArg,
    ReqKwArg,
    OptKwArg,
    KwRestArg,
    BlockArg,
    ShadowArg,
}

/// One declared block/lambda parameter (or `;shadow` block-local). `name_start`
/// is the anchor for both the offense and (for every kind but `BlockArg`) the
/// autocorrect rename range (`name_start .. name_start + name.len()`).
/// `full_start`/`full_end` are the declaring node's OWN full span — only
/// consulted for `BlockArg` (the whole `&block` gets removed, not renamed).
struct UbaVar {
    name: Vec<u8>,
    name_start: usize,
    full_start: usize,
    full_end: usize,
    kind: UbaKind,
    referenced: bool,
    assigned: bool,
}

/// Upstream's `all_arguments = scope.variables.each_value.select(&:block_
/// argument?)` plus the two `scope.node`-level predicates `message_for_
/// normal_block`/`message_for_lambda` need: `lambda?` (was this block's own
/// call named `lambda`, or a `->(){}` literal) and `define_method_call?`
/// (was it `define_method`). `is_empty` is `empty_block?` (a `do...end`/`{}`
/// with no body at all).
struct UbaScope {
    var_indices: Vec<usize>,
    is_lambda: bool,
    is_define_method: bool,
    is_empty: bool,
}

struct UbaFrame {
    /// Block/lambda scopes are "soft": a `binding` call's implicit
    /// reference walk continues on outward through them (see `mark_
    /// binding`); `def`/`class`/`module`/`sclass` are hard stops.
    is_block: bool,
    /// `Some` (indexing into the collector's `scopes`) iff `is_block` — the
    /// only kind of frame that ever declares a trackable name.
    scope_idx: Option<usize>,
    names: HashMap<Vec<u8>, usize>,
}

/// The scope-tracking visitor described in the module comment above
/// `check_unused_block_argument`.
struct UbaCollector {
    frames: Vec<UbaFrame>,
    vars: Vec<UbaVar>,
    scopes: Vec<UbaScope>,
}

impl UbaCollector {
    fn frame_for_depth(&self, depth: u32) -> usize {
        self.frames.len().saturating_sub(1).saturating_sub(depth as usize)
    }

    fn declare_here(&mut self, name: &[u8], name_start: usize, full_start: usize, full_end: usize, kind: UbaKind) {
        let fi = self.frames.len() - 1;
        if self.frames[fi].names.contains_key(name) {
            return;
        }
        let idx = self.vars.len();
        self.vars.push(UbaVar {
            name: name.to_vec(),
            name_start,
            full_start,
            full_end,
            kind,
            referenced: false,
            assigned: false,
        });
        self.frames[fi].names.insert(name.to_vec(), idx);
        if let Some(si) = self.frames[fi].scope_idx {
            self.scopes[si].var_indices.push(idx);
        }
    }

    fn reference(&mut self, name: &[u8], depth: u32) {
        let fi = self.frame_for_depth(depth);
        if let Some(&idx) = self.frames[fi].names.get(name) {
            self.vars[idx].referenced = true;
        }
    }

    fn assign(&mut self, name: &[u8], depth: u32) {
        let fi = self.frame_for_depth(depth);
        if let Some(&idx) = self.frames[fi].names.get(name) {
            self.vars[idx].assigned = true;
        }
    }

    /// `VariableTable#accessible_variables`: the current (innermost) scope's
    /// own vars, then each enclosing scope's own vars in turn as long as the
    /// scope just included was itself block/lambda-typed.
    fn mark_binding(&mut self) {
        let mut i = self.frames.len();
        while i > 0 {
            i -= 1;
            let is_block = self.frames[i].is_block;
            let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
            for idx in idxs {
                self.vars[idx].referenced = true;
            }
            if !is_block {
                break;
            }
        }
    }

    fn enter_block_scope(&mut self, is_lambda: bool, is_define_method: bool, has_body: bool) {
        let scope_idx = self.scopes.len();
        self.scopes.push(UbaScope { var_indices: Vec::new(), is_lambda, is_define_method, is_empty: !has_body });
        self.frames.push(UbaFrame { is_block: true, scope_idx: Some(scope_idx), names: HashMap::new() });
    }

    fn exit_block_scope(&mut self) {
        self.frames.pop();
    }
}

impl<'pr> ruby_prism::Visit<'pr> for UbaCollector {
    // `def`/`class`/`module`/`sclass` are hard scope boundaries: parts
    // evaluated in the ENCLOSING scope (a `defs` receiver, a class's
    // superclass/constant path, `class << expr`'s `expr`) are visited
    // BEFORE the new (empty, non-block) frame is pushed.
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let Some(recv) = node.receiver() {
            self.visit(&recv);
        }
        self.frames.push(UbaFrame { is_block: false, scope_idx: None, names: HashMap::new() });
        if let Some(params) = node.parameters() {
            self.visit_parameters_node(&params);
        }
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.visit(&node.constant_path());
        if let Some(sup) = node.superclass() {
            self.visit(&sup);
        }
        self.frames.push(UbaFrame { is_block: false, scope_idx: None, names: HashMap::new() });
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.visit(&node.constant_path());
        self.frames.push(UbaFrame { is_block: false, scope_idx: None, names: HashMap::new() });
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        self.visit(&node.expression());
        self.frames.push(UbaFrame { is_block: false, scope_idx: None, names: HashMap::new() });
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.frames.pop();
    }
    // A `do...end`/`{}` block attached to this call: `lambda?`/`define_
    // method_call?` are both keyed off the CALL's own method name (upstream
    // never checks for an absent receiver on either), never the block node
    // itself — so both are computed right here, before descending into the
    // block's own params/body as a fresh scope. `&:sym`/bare `&var` block-
    // PASS arguments (`BlockArgumentNode`) aren't block nodes at all and are
    // just visited generically.
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if let Some(recv) = node.receiver() {
            self.visit(&recv);
        }
        if let Some(args) = node.arguments() {
            self.visit_arguments_node(&args);
        }
        let name = node.name();
        let name = name.as_slice();
        // `process_send`: a bare, argument-less `binding` call (receiver
        // irrelevant) marks every currently-accessible variable referenced.
        if name == b"binding" && node.arguments().is_none_or(|a| a.arguments().is_empty()) {
            self.mark_binding();
        }
        if let Some(block) = node.block() {
            if let Some(bn) = block.as_block_node() {
                let is_lambda = name == b"lambda";
                let is_define_method = name == b"define_method";
                self.enter_block_scope(is_lambda, is_define_method, bn.body().is_some());
                if let Some(params) = bn.parameters() {
                    self.visit(&params);
                }
                if let Some(body) = bn.body() {
                    self.visit(&body);
                }
                self.exit_block_scope();
            } else {
                self.visit(&block);
            }
        }
    }
    // `super(...) { }` (explicit args) / bare `super { }` (`zsuper`, all
    // args implicitly forwarded) can each carry their own block too — never
    // a lambda, never `define_method`.
    fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
        if let Some(args) = node.arguments() {
            self.visit_arguments_node(&args);
        }
        if let Some(block) = node.block() {
            if let Some(bn) = block.as_block_node() {
                self.enter_block_scope(false, false, bn.body().is_some());
                if let Some(params) = bn.parameters() {
                    self.visit(&params);
                }
                if let Some(body) = bn.body() {
                    self.visit(&body);
                }
                self.exit_block_scope();
            } else {
                self.visit(&block);
            }
        }
    }
    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        if let Some(bn) = node.block() {
            self.enter_block_scope(false, false, bn.body().is_some());
            if let Some(params) = bn.parameters() {
                self.visit(&params);
            }
            if let Some(body) = bn.body() {
                self.visit(&body);
            }
            self.exit_block_scope();
        }
    }
    // `->(){}` literal: always a lambda, never attached via `CallNode::
    // block()`.
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        self.enter_block_scope(true, false, node.body().is_some());
        if let Some(params) = node.parameters() {
            self.visit(&params);
        }
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_block_scope();
    }
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
    }
    // Plain `x = value` never references `x` itself (only assigns it) —
    // `process_variable_assignment` processes the RHS BEFORE recording the
    // assignment, so `x = x + 1` still counts as a genuine prior read.
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        self.visit(&node.value());
        self.assign(node.name().as_slice(), node.depth());
    }
    // A masgn (`a, b = ...`)/pattern-match target: a write, never a read —
    // matches `process_variable_assignment`'s non-referencing behavior
    // exactly (any read of the same name in the whole masgn's RHS or a
    // sibling target is a SEPARATE `LocalVariableReadNode`, picked up on its
    // own).
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        self.assign(node.name().as_slice(), node.depth());
    }
    // `+=`/`-=`/etc: `process_variable_operator_assignment` ALWAYS
    // references the variable's old value before evaluating the RHS, then
    // assigns — regardless of whether the old value's read is used to
    // suppress an offense downstream, this exactly matches upstream's
    // unconditional `variable_table.reference_variable(name, node)`.
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
        self.visit(&node.value());
        self.assign(node.name().as_slice(), node.depth());
    }
    // `&&=`/`||=`: upstream treats `and_asgn`/`or_asgn` identically to
    // `op_asgn` in `OPERATOR_ASSIGNMENT_TYPES` — always references first.
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
        self.visit(&node.value());
        self.assign(node.name().as_slice(), node.depth());
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
        self.visit(&node.value());
        self.assign(node.name().as_slice(), node.depth());
    }
    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        let loc = node.location();
        self.declare_here(node.name().as_slice(), loc.start_offset(), loc.start_offset(), loc.end_offset(), UbaKind::Arg);
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        let nloc = node.name_loc();
        let floc = node.location();
        self.declare_here(
            node.name().as_slice(),
            nloc.start_offset(),
            floc.start_offset(),
            floc.end_offset(),
            UbaKind::OptArg,
        );
        self.visit(&node.value());
    }
    // Anonymous `*` (no name) declares nothing trackable — matches upstream
    // `process_variable_declaration`'s `return unless variable_name`.
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        if let (Some(name), Some(nloc)) = (node.name(), node.name_loc()) {
            let floc = node.location();
            self.declare_here(name.as_slice(), nloc.start_offset(), floc.start_offset(), floc.end_offset(), UbaKind::RestArg);
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        let nloc = node.name_loc();
        let floc = node.location();
        self.declare_here(
            node.name().as_slice(),
            nloc.start_offset(),
            floc.start_offset(),
            floc.end_offset(),
            UbaKind::ReqKwArg,
        );
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        let nloc = node.name_loc();
        let floc = node.location();
        self.declare_here(
            node.name().as_slice(),
            nloc.start_offset(),
            floc.start_offset(),
            floc.end_offset(),
            UbaKind::OptKwArg,
        );
        self.visit(&node.value());
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        if let (Some(name), Some(nloc)) = (node.name(), node.name_loc()) {
            let floc = node.location();
            self.declare_here(name.as_slice(), nloc.start_offset(), floc.start_offset(), floc.end_offset(), UbaKind::KwRestArg);
        }
    }
    // `&block` — a method/block's block-PASS parameter, not a block node.
    // Anonymous `&` (no name) declares nothing trackable.
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        if let (Some(name), Some(nloc)) = (node.name(), node.name_loc()) {
            let floc = node.location();
            self.declare_here(name.as_slice(), nloc.start_offset(), floc.start_offset(), floc.end_offset(), UbaKind::BlockArg);
        }
    }
    // `shadowarg` — a block-local variable (`obj.each { |arg; this| }`).
    fn visit_block_local_variable_node(&mut self, node: &ruby_prism::BlockLocalVariableNode<'pr>) {
        let loc = node.location();
        self.declare_here(node.name().as_slice(), loc.start_offset(), loc.start_offset(), loc.end_offset(), UbaKind::ShadowArg);
    }
}


// ---------------------------------------------------------------------
// Lint/UnusedMethodArgument
//
// Upstream layers `Lint::UnusedArgument` (shared with `UnusedBlockArgument`)
// on top of `VariableForce`'s generic `after_leaving_scope`/`Variable#
// referenced?` machinery, then narrows to `variable.method_argument?` (a
// parameter declared directly in a `def`/`defs`'s own parameter list) and
// adds its own `ignored_method?`/`block_argument_with_yield?`/message-
// building logic on top.
//
// Like `Lint/ShadowedArgument`'s `SaCollector` (see its doc comment above),
// we hand-roll a narrow scope/reference walk instead of a full
// `VariableForce` port, leaning on the same fact: prism's `depth` field on
// every local-variable read/write already encodes exactly the scope-
// resolution rule `VariableTable#find_variable` re-derives upstream. But
// this cop needs dramatically LESS bookkeeping than `ShadowedArgument`:
//
// `Variable#referenced?` is simply `!@references.empty?` — `reference!`
// unconditionally appends to `@references` before doing any of its
// branch/assignment bookkeeping (that bookkeeping only feeds OTHER
// consumers, like `Assignment#used?` for `UselessAssignment`). So for THIS
// cop, "was the argument ever referenced" reduces to "does prism ever
// resolve a local-variable READ (or an implicit zero-arity-`super`/bare-
// `binding` reference) back to this parameter's own declaration frame" —
// no ordering, branch, or reassignment-tracking logic needed at all. In
// particular a masgn's LHS targets (`a, b = b, a`) are pure writes (no
// `reference!` call upstream either), so leaving `LocalVariableTargetNode`
// unhandled (falls through to the `Visit` trait's no-op default — it has no
// child nodes of its own) already gives the right answer: `a, b = b, a`
// references both `a` and `b` (read on the RHS, evaluated before the
// targets are written), while `a, b = b, 42` references only `b`.
//
// Only method-argument declarations (`UmaCollector` only ever calls
// `declare` while `frames.last().kind == Def`) are ever tracked; a block's
// own parameters are silently ignored (not even declared), matching
// `method_argument?`'s `scope.node.any_def_type?` gate — a block frame's
// `names` map simply stays empty, so a `depth`-resolved read that lands on
// it is a harmless no-op (correctly NOT counting as a reference to an
// outer, same-named method argument, since prism's depth already reflects
// real Ruby shadowing rules).
impl<'a> Cops<'a> {
    /// `after_leaving_scope` + `UnusedMethodArgument#check_argument`/
    /// `#message`/`#ignored_method?`/`#block_argument_with_yield?`, run once
    /// (from `visit_program_node` in mod.rs) over the whole file.
    pub(crate) fn check_unused_method_argument(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Lint/UnusedMethodArgument";
        if !self.on(COP) {
            return;
        }
        let allow_unused_kw = self.cfg.get(COP, "AllowUnusedKeywordArguments") == Some("true");
        let ignore_empty = self.cfg.get(COP, "IgnoreEmptyMethods") != Some("false");
        let ignore_not_impl = self.cfg.get(COP, "IgnoreNotImplementedMethods") != Some("false");
        // `NotImplementedExceptions` is an Array default, absent from the
        // generated SCHEMA (see the dept-file convention noted in the brief)
        // — hardcode rubocop's default.yml value (`['NotImplementedError']`)
        // as the fallback when unset.
        let allowed_exceptions: Vec<Vec<u8>> = match self.cfg.get(COP, "NotImplementedExceptions") {
            Some(raw) => {
                let list = crate::config::parse_allowed_list(raw);
                if list.is_empty() { vec![b"NotImplementedError".to_vec()] } else { list.into_iter().map(String::into_bytes).collect() }
            }
            None => vec![b"NotImplementedError".to_vec()],
        };

        let mut c = UmaCollector {
            frames: vec![UmaFrame { kind: UmaKind::Other, names: HashMap::new() }],
            vars: Vec::new(),
            results: Vec::new(),
            allowed_exceptions,
        };
        use ruby_prism::Visit;
        c.visit(&node.as_node());

        struct Pending {
            start: usize,
            msg: String,
            fix: Option<(usize, usize, Vec<u8>)>,
        }
        let mut pending: Vec<Pending> = Vec::new();

        for result in &c.results {
            // `ignored_method?`: an empty body or a lone `raise <allowed>`/
            // `fail` body suppresses EVERY argument of this method, not just
            // the currently-checked one.
            let ignored = (ignore_empty && result.empty_body) || (ignore_not_impl && result.not_implemented);
            if ignored {
                continue;
            }
            // `message`'s `all_arguments.none?(&:referenced?)` — computed
            // once per method, over ALL its declared parameters (including
            // `_`-prefixed/keyword/etc ones), not just the offending one.
            let any_referenced = result.param_idxs.iter().any(|&i| c.vars[i].referenced);
            for &i in &result.param_idxs {
                let p = &c.vars[i];
                // `should_be_unused?`
                if p.name.starts_with(b"_") {
                    continue;
                }
                // `referenced?`
                if p.referenced {
                    continue;
                }
                let is_kw = matches!(p.kind, UmaParamKind::Kwarg | UmaParamKind::Kwoptarg);
                // `keyword_argument? && cop_config['AllowUnusedKeywordArguments']`
                if is_kw && allow_unused_kw {
                    continue;
                }
                // `block_argument_with_yield?`
                if matches!(p.kind, UmaParamKind::Blockarg) && result.has_yield {
                    continue;
                }

                let mut msg = format!("Unused method argument - `{}`.", String::from_utf8_lossy(&p.name));
                if !is_kw {
                    msg.push_str(&format!(
                        " If it's necessary, use `_` or `_{}` as an argument name to indicate that it won't be used. If it's unnecessary, remove it.",
                        String::from_utf8_lossy(&p.name)
                    ));
                }
                if !any_referenced {
                    msg.push_str(&format!(
                        " You can also write as `{}(*)` if you want the method to accept any arguments but don't care about them.",
                        String::from_utf8_lossy(&result.scope_name)
                    ));
                }

                // `UnusedArgCorrector.correct`: kwarg/kwoptarg never
                // correct; a block-pass param is removed entirely (with its
                // surrounding space + comma); everything else gets a `_`
                // prefix inserted onto its bare name.
                let fix = match p.kind {
                    UmaParamKind::Kwarg | UmaParamKind::Kwoptarg => None,
                    UmaParamKind::Blockarg => {
                        let (rs, re) = uma_blockarg_removal_range(self.src, p.node_start, p.node_end);
                        Some((rs, re, Vec::new()))
                    }
                    _ => {
                        let mut repl = Vec::with_capacity(p.name.len() + 1);
                        repl.push(b'_');
                        repl.extend_from_slice(&p.name);
                        Some((p.name_start, p.name_end, repl))
                    }
                };
                pending.push(Pending { start: p.name_start, msg, fix });
            }
        }
        pending.sort_by_key(|p| p.start);
        for p in pending {
            let correctable = p.fix.is_some();
            self.push(p.start, COP, correctable, p.msg);
            if let Some(f) = p.fix {
                self.fixes.push(f);
            }
        }
    }
}

/// `RangeHelp#range_with_surrounding_space(node.source_range, side: :left)`
/// (spaces/tabs, then newlines) followed by `range_with_surrounding_comma
/// (range, :left)` (a run of commas) — `UnusedArgCorrector.
/// correct_for_blockarg_type`'s removal range for an unused `&block` param,
/// e.g. turning `foo, bar, &block` into `foo, bar`.
fn uma_blockarg_removal_range(src: &[u8], node_start: usize, node_end: usize) -> (usize, usize) {
    let mut start = node_start;
    while start > 0 && matches!(src[start - 1], b' ' | b'\t') {
        start -= 1;
    }
    while start > 0 && src[start - 1] == b'\n' {
        start -= 1;
    }
    while start > 0 && src[start - 1] == b',' {
        start -= 1;
    }
    (start, node_end)
}

/// `Node#const_name` (rubocop-ast): the fully-qualified name of a `const`
/// node, dropping a leading top-level `::` qualifier (`cbase`) — e.g.
/// `::Foo` and `Foo` both yield `"Foo"`; `::Lib::Error` and `Lib::Error`
/// both yield `"Lib::Error"`. Returns `None` for any non-const node
/// (`allowed_exception_class?`'s `return false unless node.const_type?`).
fn uma_const_full_name(node: &ruby_prism::Node) -> Option<Vec<u8>> {
    if let Some(c) = node.as_constant_read_node() {
        return Some(c.name().as_slice().to_vec());
    }
    if let Some(p) = node.as_constant_path_node() {
        let short = p.name()?.as_slice().to_vec();
        return match p.parent() {
            None => Some(short),
            Some(parent) => {
                let mut full = uma_const_full_name(&parent)?;
                full.extend_from_slice(b"::");
                full.extend_from_slice(&short);
                Some(full)
            }
        };
    }
    None
}

/// `not_implemented?` def_node_matcher: `{(send nil? :raise
/// #allowed_exception_class? ...) (send nil? :fail ...)}`, applied to a
/// method's body. Prism always wraps a `def`'s body in a `StatementsNode`
/// (even a single statement — unlike whitequark, which leaves a lone
/// statement unwrapped), so the whitequark pattern's "body IS directly this
/// one send node" becomes "body has EXACTLY one statement, and it's this
/// send node".
fn uma_not_implemented(body: &ruby_prism::Node, allowed: &[Vec<u8>]) -> bool {
    let Some(stmts) = body.as_statements_node() else { return false };
    let items: Vec<_> = stmts.body().iter().collect();
    let [only] = items.as_slice() else { return false };
    let Some(call) = only.as_call_node() else { return false };
    if call.receiver().is_some() {
        return false;
    }
    match call.name().as_slice() {
        b"fail" => true,
        b"raise" => {
            let Some(args) = call.arguments() else { return false };
            let Some(first) = args.arguments().iter().next() else { return false };
            uma_const_full_name(&first).is_some_and(|full| allowed.iter().any(|a| a.as_slice() == full.as_slice()))
        }
        _ => false,
    }
}

/// `block_argument_with_yield?`'s `method_body.yield_type? ||
/// method_body.each_descendant(:yield).any?` — both disjuncts collapse into
/// one search here: prism's `StatementsNode` wrapper means a lone `yield`
/// statement is a DESCENDANT of `body` (never `body` itself), so a single
/// scope-oblivious search (matching upstream's `each_descendant`, which
/// also doesn't stop at nested def/block boundaries) covers both.
fn uma_contains_yield(node: &ruby_prism::Node) -> bool {
    struct Search {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for Search {
        fn visit_yield_node(&mut self, _node: &ruby_prism::YieldNode<'pr>) {
            self.found = true;
        }
    }
    let mut s = Search { found: false };
    use ruby_prism::Visit;
    s.visit(node);
    s.found
}

/// One method (`def`/`defs`) parameter kind — mirrors the
/// `ARGUMENT_DECLARATION_TYPES` subset that can ever appear in a `def`'s own
/// parameter list (`shadowarg` is block-local-only, never a method param).
#[derive(Clone, Copy, PartialEq)]
enum UmaParamKind {
    Required,
    Optional,
    Rest,
    Kwarg,
    Kwoptarg,
    Kwrest,
    Blockarg,
}

/// One tracked method-parameter declaration. `name_start`/`name_end` is the
/// bare identifier's own span (`declaration_node.loc.name` — the offense
/// anchor, and the `_`-prefix insertion point for every non-block-arg,
/// non-keyword kind). `node_start`/`node_end` is the FULL parameter span
/// (including a leading `&`) — only actually used by `Blockarg`'s removal
/// range; identical to the name span for every other kind.
struct UmaParam {
    name: Vec<u8>,
    kind: UmaParamKind,
    name_start: usize,
    name_end: usize,
    node_start: usize,
    node_end: usize,
    referenced: bool,
}

/// One finished `def`/`defs` scope: its own declared parameters (by index
/// into the collector's flat `vars`), enough about its body to replicate
/// `ignored_method?`/`block_argument_with_yield?`, and its bare method name
/// (`Scope#name` — `variable.scope.name`, used in the "write as `foo(*)`"
/// message suffix).
struct UmaDefResult {
    param_idxs: Vec<usize>,
    empty_body: bool,
    not_implemented: bool,
    has_yield: bool,
    scope_name: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq)]
enum UmaKind {
    /// A `def`/`defs` scope — the only kind that ever declares a trackable
    /// (`method_argument?`) parameter.
    Def,
    /// A `block`/`lambda` scope — "soft": zero-arity `super` and bare
    /// `binding` both walk straight through it to reach an enclosing scope.
    /// Its own parameters are never declared here at all (this cop doesn't
    /// care about block-argument usage), so a depth-resolved read landing
    /// on one is always a harmless no-op.
    Block,
    /// `class`/`module`/`sclass`, or the file's top level: a hard scope
    /// boundary that owns no trackable parameters, but still needs its own
    /// frame so nested defs/blocks compute the right depth-relative index,
    /// and still stops an outward `super`/`binding` walk once reached.
    Other,
}

struct UmaFrame {
    kind: UmaKind,
    /// Declared parameter name -> index into the collector's flat `vars`.
    /// Only ever populated for a `Def`-kind frame.
    names: HashMap<Vec<u8>, usize>,
}

/// The scope-tracking visitor described in the module comment above
/// `check_unused_method_argument`.
struct UmaCollector {
    frames: Vec<UmaFrame>,
    vars: Vec<UmaParam>,
    results: Vec<UmaDefResult>,
    allowed_exceptions: Vec<Vec<u8>>,
}

impl UmaCollector {
    fn in_def(&self) -> bool {
        self.frames.last().is_some_and(|f| f.kind == UmaKind::Def)
    }

    fn declare(&mut self, name: &[u8], kind: UmaParamKind, name_start: usize, name_end: usize, node_start: usize, node_end: usize) {
        let frame = self.frames.last_mut().unwrap();
        if frame.names.contains_key(name) {
            return;
        }
        let idx = self.vars.len();
        self.vars.push(UmaParam { name: name.to_vec(), kind, name_start, name_end, node_start, node_end, referenced: false });
        frame.names.insert(name.to_vec(), idx);
    }

    fn resolve(&self, name: &[u8], depth: u32) -> Option<usize> {
        let top = self.frames.len().checked_sub(1)?;
        let f = top.checked_sub(depth as usize)?;
        self.frames[f].names.get(name).copied()
    }

    fn reference(&mut self, name: &[u8], depth: u32) {
        if let Some(idx) = self.resolve(name, depth) {
            self.vars[idx].referenced = true;
        }
    }

    fn enter_frame(&mut self, kind: UmaKind) {
        self.frames.push(UmaFrame { kind, names: HashMap::new() });
    }
    fn exit_frame(&mut self) -> UmaFrame {
        self.frames.pop().unwrap()
    }

    /// Zero-arity `super` (`process_zero_arity_super`): walks from the
    /// CURRENT scope outward, referencing the nearest `Def` frame's own
    /// params and STOPPING there; a `Block` frame contributes nothing but
    /// doesn't stop the walk; any other (hard, non-`Def`) frame stops the
    /// walk without marking anything.
    fn mark_zsuper(&mut self) {
        for i in (0..self.frames.len()).rev() {
            match self.frames[i].kind {
                UmaKind::Def => {
                    let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
                    for idx in idxs {
                        self.vars[idx].referenced = true;
                    }
                    break;
                }
                UmaKind::Block => continue,
                UmaKind::Other => break,
            }
        }
    }

    /// Bare `binding` call (`VariableTable#accessible_variables`): marks the
    /// current scope's own vars, and keeps walking (and marking) outward
    /// through `Block` frames, stopping right after including the first
    /// non-`Block` frame.
    fn mark_binding(&mut self) {
        let mut i = self.frames.len();
        while i > 0 {
            i -= 1;
            let is_block = self.frames[i].kind == UmaKind::Block;
            let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
            for idx in idxs {
                self.vars[idx].referenced = true;
            }
            if !is_block {
                break;
            }
        }
    }
}

impl<'pr> ruby_prism::Visit<'pr> for UmaCollector {
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let Some(recv) = node.receiver() {
            self.visit(&recv);
        }
        self.enter_frame(UmaKind::Def);
        if let Some(params) = node.parameters() {
            self.visit_parameters_node(&params);
        }
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        let frame = self.exit_frame();
        if !frame.names.is_empty() {
            let body = node.body();
            let empty_body = body.is_none();
            let not_implemented = body.as_ref().is_some_and(|b| uma_not_implemented(b, &self.allowed_exceptions));
            let has_yield = body.as_ref().is_some_and(uma_contains_yield);
            self.results.push(UmaDefResult {
                param_idxs: frame.names.into_values().collect(),
                empty_body,
                not_implemented,
                has_yield,
                scope_name: node.name().as_slice().to_vec(),
            });
        }
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.visit(&node.constant_path());
        if let Some(sup) = node.superclass() {
            self.visit(&sup);
        }
        self.enter_frame(UmaKind::Other);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.visit(&node.constant_path());
        self.enter_frame(UmaKind::Other);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        self.visit(&node.expression());
        self.enter_frame(UmaKind::Other);
        if let Some(body) = node.body() {
            self.visit(&body);
        }
        self.exit_frame();
    }
    fn visit_block_node(&mut self, node: &ruby_prism::BlockNode<'pr>) {
        self.enter_frame(UmaKind::Block);
        ruby_prism::visit_block_node(self, node);
        self.exit_frame();
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        self.enter_frame(UmaKind::Block);
        ruby_prism::visit_lambda_node(self, node);
        self.exit_frame();
    }
    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        if self.in_def() {
            let l = node.location();
            self.declare(node.name().as_slice(), UmaParamKind::Required, l.start_offset(), l.end_offset(), l.start_offset(), l.end_offset());
        }
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        if self.in_def() {
            let nl = node.name_loc();
            self.declare(node.name().as_slice(), UmaParamKind::Optional, nl.start_offset(), nl.end_offset(), nl.start_offset(), nl.end_offset());
        }
        self.visit(&node.value());
    }
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        if self.in_def() {
            if let (Some(name), Some(nl)) = (node.name(), node.name_loc()) {
                self.declare(name.as_slice(), UmaParamKind::Rest, nl.start_offset(), nl.end_offset(), nl.start_offset(), nl.end_offset());
            }
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        if self.in_def() {
            let nl = node.name_loc();
            self.declare(node.name().as_slice(), UmaParamKind::Kwarg, nl.start_offset(), nl.end_offset(), nl.start_offset(), nl.end_offset());
        }
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        if self.in_def() {
            let nl = node.name_loc();
            self.declare(node.name().as_slice(), UmaParamKind::Kwoptarg, nl.start_offset(), nl.end_offset(), nl.start_offset(), nl.end_offset());
        }
        self.visit(&node.value());
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        if self.in_def() {
            if let (Some(name), Some(nl)) = (node.name(), node.name_loc()) {
                self.declare(name.as_slice(), UmaParamKind::Kwrest, nl.start_offset(), nl.end_offset(), nl.start_offset(), nl.end_offset());
            }
        }
    }
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        if self.in_def() {
            if let (Some(name), Some(nl)) = (node.name(), node.name_loc()) {
                let full = node.location();
                self.declare(name.as_slice(), UmaParamKind::Blockarg, nl.start_offset(), nl.end_offset(), full.start_offset(), full.end_offset());
            }
        }
    }
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
    }
    // `+=`/`||=`/`&&=`-shaped writes implicitly read the OLD value first
    // (`process_variable_operator_assignment`'s `reference_variable` call
    // before processing the RHS) — a plain `=` write (`LocalVariableWriteNode`,
    // left to the default traversal) never does.
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
        self.visit(&node.value());
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
        self.visit(&node.value());
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        self.reference(node.name().as_slice(), node.depth());
        self.visit(&node.value());
    }
    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        self.mark_zsuper();
        if let Some(block) = node.block() {
            self.visit_block_node(&block);
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if node.name().as_slice() == b"binding" {
            let empty_args = node.arguments().map(|a| a.arguments().iter().next().is_none()).unwrap_or(true);
            if empty_args {
                self.mark_binding();
            }
        }
        ruby_prism::visit_call_node(self, node);
    }
}

use ruby_prism::Visit;

/// Lint/UselessAccessModifier — a bare `public`/`private`/`protected`/
/// `module_function` (or a no-arg `private_class_method`) that has no
/// effect: repeated, leading-and-unused, top-level, or followed by nothing
/// that actually defines a method.
///
/// Upstream's algorithm threads a `(cur_vis, unused)` pair through a
/// recursive `child_nodes` walk of a class/module/sclass/qualifying-block
/// body, where `unused` is the most recent modifier not yet known to guard a
/// real method def. Three shapes are ported separately here because prism's
/// tree shape differs from whitequark's in ways that change which branch of
/// upstream's `check_node`/`on_begin` actually fires:
///
/// 1. **Top level** (`check_useless_access_modifier_top_level`) — upstream's
///    `on_begin` fires ONLY for whitequark's implicit multi-statement
///    `:begin` (2+ raw top-level statements; a single top-level statement is
///    never wrapped, so `on_begin` never runs for it). It does a SHALLOW,
///    unconditional scan: every direct-child bare modifier or no-arg
///    `private_class_method` is flagged, full stop — no def-tracking, no
///    recursion. Since prism's `ProgramNode` always wraps in a
///    `StatementsNode` even for a single statement, we gate on
///    `body.len() >= 2` ourselves to reproduce the "never wraps a lone
///    statement" cutoff.
///
/// 2. **Single-statement scope body** — for the SAME reason (prism always
///    wraps a class/module/sclass/block body in a `StatementsNode`, even
///    with exactly one statement, where whitequark would hand `check_node`
///    the bare inner node directly), a body with exactly one statement gets
///    upstream's OTHER `check_node` branch: flag it if-and-only-if it is
///    itself a bare modifier (`node.send_type? && node.bare_access_modifier?`
///    — deliberately NOT `access_modifier?`, so a lone `private_class_method`
///    with nothing else in the body is never flagged; confirmed against the
///    real cop). Nothing else about a single-statement body is inspected —
///    not method defs, not nested scopes — matching upstream's `check_node`
///    being a strict `begin_type? || bare_access_modifier?` dispatch with no
///    third branch for a single statement that only "kind of" contains a
///    modifier (e.g. `class A; begin; private; end; end` is NEVER flagged
///    upstream even though the `private` has nothing after it, because the
///    class's only statement is a bare `kwbegin`, which is neither
///    `begin_type?` nor `bare_access_modifier?`).
///
/// 3. **Multi-statement scope body** (`UamFold`, `>= 2` statements) —
///    upstream's real `check_child_nodes` fold. Ported as a dedicated
///    `ruby_prism::Visit` walker (not the shared `Cops` visitor) so that
///    "recurse generically into whatever this arbitrary node is" falls out
///    of the crate's own default per-type descent — we only need to override
///    the handful of node kinds upstream special-cases (`def`, `class`,
///    `module`, `sclass`, and — the bulk of the logic — `call`, since a
///    call's optional attached block is a FIELD in prism rather than an
///    outer wrapper node like whitequark's `:block`).
///
/// `check_useless_access_modifier_scope` is shared by cases 2 and 3, and is
/// called from `on_class`/`on_module`/`on_sclass`'s single top-level dispatch
/// point in `mod.rs`, plus `check_useless_access_modifier_block` for
/// qualifying blocks (`eval_call?`/`included_block?`).
impl<'a> Cops<'a> {
    /// `on_begin`: only the OUTERMOST top-level statement list, and only when
    /// it has 2+ statements (see the module-level doc for why). Every direct
    /// child that is a bare modifier or no-arg `private_class_method` is
    /// flagged unconditionally — this deliberately does NOT recurse or track
    /// def-usage; upstream's `on_begin` doesn't either.
    pub(crate) fn check_useless_access_modifier_top_level(&mut self, stmts: &ruby_prism::StatementsNode) {
        const COP: &str = "Lint/UselessAccessModifier";
        if !self.on(COP) {
            return;
        }
        let body = stmts.body();
        if body.len() < 2 {
            return;
        }
        for child in body.iter() {
            let Some(call) = child.as_call_node() else { continue };
            // A block-attached call is never `send_type?` in whitequark, so
            // `on_begin`'s direct `child_nodes` scan would never reach it.
            if call.block().is_some() {
                continue;
            }
            if let Some(vis) = uam_bare_modifier_name(&call) {
                let l = call.location();
                self.uam_emit(l.start_offset(), l.end_offset(), vis);
            } else if call.name().as_slice() == b"private_class_method" && call.arguments().is_none() {
                let l = call.location();
                self.uam_emit(l.start_offset(), l.end_offset(), "private_class_method");
            }
        }
    }

    /// `on_block`: `eval_call?(node) || included_block?(node)` — called from
    /// `visit_call_node` for every call that has an attached block. Only
    /// `class_eval`/`instance_eval` (any receiver), a `Class`/`Module`/
    /// `Struct.new`/`Data.define` block, a configured `ContextCreatingMethods`
    /// block (receiver nil or a constant), or (when
    /// `ActiveSupportExtensionsEnabled`) an `included` block qualify.
    pub(crate) fn check_useless_access_modifier_block(
        &mut self,
        call: &ruby_prism::CallNode,
        block: &ruby_prism::BlockNode,
    ) {
        const COP: &str = "Lint/UselessAccessModifier";
        if !self.on(COP) {
            return;
        }
        let name = call.name().as_slice();
        let eligible = (self.cfg.active_support() && name == b"included")
            || matches!(name, b"class_eval" | b"instance_eval")
            || is_class_constructor(call, self.src)
            || (uam_recv_nil_or_const(call) && self.uam_ctx_creating_methods().iter().any(|m| m.as_slice() == name));
        if !eligible {
            return;
        }
        self.check_useless_access_modifier_scope(block.body());
    }

    /// `on_class`/`on_module`/`on_sclass`'s shared `check_node(node.body)`,
    /// plus the body of a qualifying block reached via
    /// `check_useless_access_modifier_block`. See the module-level doc for
    /// why the single-statement and 2+-statement cases are handled
    /// differently.
    pub(crate) fn check_useless_access_modifier_scope(&mut self, body: Option<ruby_prism::Node>) {
        const COP: &str = "Lint/UselessAccessModifier";
        if !self.on(COP) {
            return;
        }
        let Some(body) = body else { return };
        // A body that reduces to a bare `BeginNode` (an explicit `begin..end`
        // with no other sibling statements, or a class/module/sclass with a
        // directly-attached `rescue`/`ensure`) is whitequark's `kwbegin` —
        // neither `begin_type?` nor `bare_access_modifier?` — so upstream's
        // `check_node` does nothing at all (verified against the real cop).
        let Some(stmts) = body.as_statements_node() else { return };
        let elems = stmts.body();
        if elems.len() < 2 {
            // Exactly one statement: upstream hands `check_node` that bare
            // node directly (prism always wraps in a `StatementsNode`, even
            // for one statement) — only its OWN bare-modifier-ness matters;
            // nothing else is inspected, no matter what it is.
            if let Some(call) = elems.iter().next().and_then(|n| n.as_call_node()) {
                if let Some(vis) = uam_bare_modifier_name(&call) {
                    let l = call.location();
                    self.uam_emit(l.start_offset(), l.end_offset(), vis);
                }
            }
            return;
        }
        let mut fold = UamFold {
            src: self.src,
            ctx_methods: self.uam_ctx_creating_methods(),
            method_methods: self.uam_method_creating_methods(),
            active_support: self.cfg.active_support(),
            cur_vis: Some("public"),
            unused: None,
            out: Vec::new(),
        };
        fold.visit(&stmts.as_node());
        // `check_scope`'s final `return unless unused; add_offense(unused, ...)`
        // — a modifier still pending at the end of the scope is useless too.
        if let Some((us, ue, un)) = fold.unused {
            fold.out.push((us, ue, un));
        }
        for (start, end, name) in fold.out {
            self.uam_emit(start, end, name);
        }
    }

    /// `cop_config.fetch('ContextCreatingMethods', [])`, with `"included"`
    /// pre-filtered out (upstream skips it in the loop to avoid redefining
    /// its own `included_block?` matcher). Absent from the generated schema
    /// since its default is the array `[]`.
    fn uam_ctx_creating_methods(&self) -> Vec<Vec<u8>> {
        self.cfg
            .get("Lint/UselessAccessModifier", "ContextCreatingMethods")
            .map(crate::config::parse_allowed_list)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m != "included")
            .map(String::into_bytes)
            .collect()
    }
    /// `cop_config.fetch('MethodCreatingMethods', [])`, same "included"
    /// pre-filter and same absent-array-default reasoning as above.
    fn uam_method_creating_methods(&self) -> Vec<Vec<u8>> {
        self.cfg
            .get("Lint/UselessAccessModifier", "MethodCreatingMethods")
            .map(crate::config::parse_allowed_list)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m != "included")
            .map(String::into_bytes)
            .collect()
    }

    /// Shared offense+autocorrect emission: `add_offense(node, message:
    /// format(MSG, current: name))` with `autocorrect` = `range_by_whole_lines
    /// (node.source_range, include_final_newline: true)` then `corrector.remove`.
    fn uam_emit(&mut self, start: usize, end: usize, name: &str) {
        const COP: &str = "Lint/UselessAccessModifier";
        self.push(start, COP, true, format!("Useless `{name}` access modifier."));
        let (rs, re) = uam_whole_lines(self.src, start, end);
        self.fixes.push((rs, re, Vec::new()));
    }
}

/// `bare_access_modifier?`, restricted to the exact 4 macro names upstream's
/// `bare_access_modifier_declaration?` matches (`public`/`private`/
/// `protected`/`module_function`) — deliberately excludes
/// `private_class_method`, which is a separate check
/// (`access_modifier?`'s OTHER disjunct) with different call-site rules.
/// Callers are responsible for confirming there's no attached block first
/// (a block-attached call is never whitequark's bare `:send` shape).
fn uam_bare_modifier_name(call: &ruby_prism::CallNode) -> Option<&'static str> {
    if call.receiver().is_some() || call.arguments().is_some() {
        return None;
    }
    match call.name().as_slice() {
        b"public" => Some("public"),
        b"private" => Some("private"),
        b"protected" => Some("protected"),
        b"module_function" => Some("module_function"),
        _ => None,
    }
}

/// `{nil? const}` — used by `any_context_creating_methods?`'s receiver guard.
/// Prism splits whitequark's single `:const` type into `ConstantReadNode`
/// (`Foo`) and `ConstantPathNode` (`Foo::Bar`, `::Foo`); both count.
fn uam_recv_nil_or_const(call: &ruby_prism::CallNode) -> bool {
    match call.receiver() {
        None => true,
        Some(r) => r.as_constant_read_node().is_some() || r.as_constant_path_node().is_some(),
    }
}

/// `RangeHelp#range_by_whole_lines(range, include_final_newline: true)`.
fn uam_whole_lines(src: &[u8], start: usize, end: usize) -> (usize, usize) {
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

/// The outcome of classifying a call node's own name/receiver/arguments,
/// deliberately IGNORING any attached block — see `UamFold::classify_bare`'s
/// doc for why this "as if bare" view is exactly what upstream's recursion
/// into an unmatched block's wrapped inner `send` amounts to.
enum UamBare {
    /// A bare `public`/`private`/`protected`/`module_function` macro call.
    Modifier(&'static str),
    /// A no-arg `private_class_method` — always an immediate offense.
    PcmImmediate,
    /// `private_class_method` WITH arguments — upstream's `check_send_node`
    /// falls through neither branch and (being called via Ruby multiple
    /// assignment on a `nil` return) resets `cur_vis`/`unused` to `nil` as a
    /// side effect. Reproduced faithfully; see `UamFold::apply_bare`.
    PcmCorrupt,
    /// `static_method_definition?` (`attr`/`attr_reader`/`attr_writer`/
    /// `attr_accessor`, or a bare `def`, handled separately in
    /// `UamFold::visit_def_node`), `dynamic_method_definition?`'s bare
    /// `define_method` alt, or a configured `MethodCreatingMethods` name.
    MethodDef,
    /// `class_constructor?`'s bare-send alt (`Class.new` etc. with no
    /// block) — inert in practice (no body to scan) but still a boundary.
    ScopeBoundary,
    /// None of the above: upstream's generic
    /// `check_child_nodes(child, unused, cur_vis)` recursion into whatever
    /// this node's own children are.
    Nothing,
}

/// Lint/UselessAccessModifier's `check_child_nodes` fold for a 2+-statement
/// scope body, as a standalone `ruby_prism::Visit` walker — see the
/// module-level doc above `check_useless_access_modifier_top_level` for why
/// this is a separate visitor rather than hooking the shared `Cops` one.
struct UamFold<'s> {
    src: &'s [u8],
    /// `ContextCreatingMethods`, "included" pre-filtered out.
    ctx_methods: Vec<Vec<u8>>,
    /// `MethodCreatingMethods`, "included" pre-filtered out.
    method_methods: Vec<Vec<u8>>,
    active_support: bool,
    /// `cur_vis` — `None` only ever means upstream's `nil`-corruption case
    /// (see `UamBare::PcmCorrupt`), never a real "no visibility yet" state
    /// (the fold always starts at `Some("public")`).
    cur_vis: Option<&'static str>,
    /// `unused` — the most recent modifier not yet known to guard a def,
    /// as `(start_offset, end_offset, name)` of its own `source_range`.
    unused: Option<(usize, usize, &'static str)>,
    /// Offenses found so far, as `(start, end, name)` — `start`/`end` double
    /// as both the offense anchor and the autocorrect's own node range.
    out: Vec<(usize, usize, &'static str)>,
}

impl<'s> UamFold<'s> {
    fn flag(&mut self, start: usize, end: usize, name: &'static str) {
        self.out.push((start, end, name));
    }

    /// `check_new_visibility`: a NEW distinct modifier flushes the
    /// previously-pending one (if any) as useless; a REPEATED modifier
    /// (same as `cur_vis`) is immediately useless itself, and does NOT
    /// disturb whatever was already pending.
    fn note_new_vis(&mut self, name: &'static str, start: usize, end: usize) {
        if self.cur_vis == Some(name) {
            self.flag(start, end, name);
        } else {
            if let Some((us, ue, un)) = self.unused.take() {
                self.flag(us, ue, un);
            }
            self.cur_vis = Some(name);
            self.unused = Some((start, end, name));
        }
    }

    /// `access_modifier?`/`method_definition?`/`start_of_new_scope?`
    /// classification of `call`'s own name/receiver/arguments, ignoring any
    /// attached block entirely. This is exactly what upstream's generic
    /// recursion into an unmatched with-block child (whitequark's outer
    /// `:block` node) finds when it reaches that block's wrapped inner
    /// `send` as one of ITS children — the block was already peeled away
    /// structurally by that point. Prism keeps the block as a field on the
    /// same `CallNode` rather than wrapping it as a separate outer node, so
    /// `UamFold::handle_call` re-derives the same "as if bare" view directly
    /// instead of relying on a second, differently-shaped node to recurse
    /// into.
    fn classify_bare(&self, call: &ruby_prism::CallNode) -> UamBare {
        let name = call.name().as_slice();
        let no_recv = call.receiver().is_none();
        if no_recv && call.arguments().is_none() {
            match name {
                b"public" => return UamBare::Modifier("public"),
                b"private" => return UamBare::Modifier("private"),
                b"protected" => return UamBare::Modifier("protected"),
                b"module_function" => return UamBare::Modifier("module_function"),
                _ => {}
            }
        }
        if name == b"private_class_method" {
            return if call.arguments().is_none() { UamBare::PcmImmediate } else { UamBare::PcmCorrupt };
        }
        if no_recv && matches!(name, b"attr" | b"attr_reader" | b"attr_writer" | b"attr_accessor") {
            return UamBare::MethodDef;
        }
        if no_recv && name == b"define_method" {
            return UamBare::MethodDef;
        }
        if no_recv && self.method_methods.iter().any(|m| m.as_slice() == name) {
            return UamBare::MethodDef;
        }
        if is_class_constructor(call, self.src) {
            return UamBare::ScopeBoundary;
        }
        UamBare::Nothing
    }

    /// Applies `classify_bare`'s verdict: a matched leaf never recurses
    /// further (matching upstream, where a matched `child` never falls to
    /// the generic-recursion `elsif`); only `Nothing` recurses into the
    /// call's own receiver/arguments.
    fn apply_bare(&mut self, call: &ruby_prism::CallNode) {
        match self.classify_bare(call) {
            UamBare::Modifier(vis) => {
                let l = call.location();
                self.note_new_vis(vis, l.start_offset(), l.end_offset());
            }
            UamBare::PcmImmediate => {
                let l = call.location();
                self.flag(l.start_offset(), l.end_offset(), "private_class_method");
            }
            UamBare::PcmCorrupt => {
                self.cur_vis = None;
                self.unused = None;
            }
            UamBare::MethodDef => {
                self.unused = None;
            }
            UamBare::ScopeBoundary => {}
            UamBare::Nothing => {
                if let Some(r) = call.receiver() {
                    self.visit(&r);
                }
                if let Some(a) = call.arguments() {
                    for arg in a.arguments().iter() {
                        self.visit(&arg);
                    }
                }
            }
        }
    }

    /// `child.send_type? && access_modifier?(child)` /
    /// `child.block_type? && included_block?(child)` / `method_definition?`
    /// (`any_block` define_method alt) / `start_of_new_scope?`'s `eval_call?`
    /// disjuncts that require a block (`class_or_instance_eval?`,
    /// `class_constructor?`'s any_block alt, `any_context_creating_methods?`)
    /// — checked FIRST, since these consume the whole call+block as one
    /// indivisible leaf with no further recursion at all. Anything else
    /// falls through to `apply_bare` (the "as if bare" retry) plus a
    /// separate, unconditional scan of the block's own body — matching
    /// upstream's generic recursion into the wrapping `:block` node's
    /// [inner-send, params, body] children.
    fn handle_call(&mut self, call: &ruby_prism::CallNode) {
        if let Some(block_arg) = call.block() {
            if let Some(bn) = block_arg.as_block_node() {
                let name = call.name().as_slice();
                if self.active_support && name == b"included" {
                    return;
                }
                if call.receiver().is_none() && name == b"define_method" {
                    self.unused = None;
                    return;
                }
                if matches!(name, b"class_eval" | b"instance_eval") {
                    return;
                }
                if is_class_constructor(call, self.src) {
                    return;
                }
                if uam_recv_nil_or_const(call) && self.ctx_methods.iter().any(|m| m.as_slice() == name) {
                    return;
                }
                self.apply_bare(call);
                if let Some(body) = bn.body() {
                    self.visit(&body);
                }
                return;
            }
            // `&:sym` block-pass args aren't block nodes — treat as bare.
        }
        self.apply_bare(call);
    }
}

impl<'pr, 's> ruby_prism::Visit<'pr> for UamFold<'s> {
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        // `static_method_definition?`'s bare `def` alt matches ANY `def`
        // type (i.e. whitequark's receiver-less `:def`, never `:defs`) —
        // `node.receiver()` is prism's equivalent of that type distinction.
        // Either way, a def's body is never recursed into (a method body is
        // its own visibility scope), and a `defs` (explicit receiver) is a
        // complete no-op, exactly like upstream's `!child.defs_type?` guard.
        if node.receiver().is_none() {
            self.unused = None;
        }
    }
    fn visit_class_node(&mut self, _node: &ruby_prism::ClassNode<'pr>) {
        // `start_of_new_scope?`: a boundary, handled independently by its
        // own top-level `visit_class_node` dispatch in `mod.rs` — recursing
        // here too would be upstream's own redundant-but-deduped
        // `check_scope(child)` double-visit (`add_offense` dedupes by exact
        // range), so we simply don't bother.
    }
    fn visit_module_node(&mut self, _node: &ruby_prism::ModuleNode<'pr>) {}
    fn visit_singleton_class_node(&mut self, _node: &ruby_prism::SingletonClassNode<'pr>) {}
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        self.handle_call(node);
    }
}


/// `nil.methods` on Ruby 3.4 (hand-copied — no runtime to query from a
/// static-schema Rust port), the set upstream computes ONCE at cop-class
/// load time as `RedundantSafeNavigation::NIL_METHODS` (used by
/// `respond_to_nil_method?`) and again — identically, `:!` is already a
/// member — as `Lint::Utils::NilReceiverChecker::NIL_METHODS` (used by
/// `non_nil_method?`). One shared list backs both ports below.
const RSN_NIL_METHODS: &[&[u8]] = &[
    b"!", b"!=", b"!~", b"&", b"<=>", b"==", b"===", b"=~", b"^", b"__id__", b"__send__", b"class",
    b"clone", b"define_singleton_method", b"display", b"dup", b"enum_for", b"eql?", b"equal?",
    b"extend", b"freeze", b"frozen?", b"hash", b"inspect", b"instance_eval", b"instance_exec",
    b"instance_of?", b"instance_variable_defined?", b"instance_variable_get",
    b"instance_variable_set", b"instance_variables", b"is_a?", b"itself", b"kind_of?", b"method",
    b"methods", b"nil?", b"object_id", b"private_methods", b"protected_methods", b"public_method",
    b"public_methods", b"public_send", b"rationalize", b"remove_instance_variable", b"respond_to?",
    b"send", b"singleton_class", b"singleton_method", b"singleton_methods", b"tap", b"then",
    b"to_a", b"to_c", b"to_enum", b"to_f", b"to_h", b"to_i", b"to_r", b"to_s", b"yield_self", b"|",
];

impl<'a> super::Cops<'a> {
    /// Lint/RedundantSafeNavigation — `on_csend`. Ported verbatim from
    /// upstream's method of the same name: MSG_NON_NIL (gated behind the
    /// `InferNonNilReceiver` config flag, and only when `rsn_scan_scope`
    /// already proved this exact call's receiver can't be nil — see that
    /// function's doc) takes priority; otherwise falls through to the
    /// "plain" `guarded_by_nil_receiver?` port (`rsn_guarded_by_nil_receiver`)
    /// for the default MSG. Anchor for both is `node.loc.dot` (prism:
    /// `call_operator_loc()`) — just the `&.` text — and so is the
    /// autocorrect (`replace(range, '.')`).
    pub(crate) fn check_redundant_safe_navigation(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/RedundantSafeNavigation";
        if !self.on(COP) || !node.is_safe_navigation() {
            return;
        }
        let Some(op) = node.call_operator_loc() else { return };
        let anchor = op.start_offset();
        if self.cfg.get(COP, "InferNonNilReceiver") == Some("true")
            && self.rsn_infer_nonnil.contains(&node.location().start_offset())
        {
            self.push(
                anchor,
                COP,
                true,
                "Redundant safe navigation on non-nil receiver (detected by analyzing previous code/method invocations).",
            );
            self.fixes.push((anchor, op.end_offset(), b".".to_vec()));
            return;
        }
        if self.rsn_guarded_by_nil_receiver(node) {
            return;
        }
        self.push(anchor, COP, true, "Redundant safe navigation detected, use `.` instead.");
        self.fixes.push((anchor, op.end_offset(), b".".to_vec()));
    }

    /// `guarded_by_nil_receiver?`: is the `&.` actually load-bearing?
    fn rsn_guarded_by_nil_receiver(&self, node: &ruby_prism::CallNode) -> bool {
        let Some(receiver) = node.receiver() else { return false };
        if rsn_assume_receiver_instance_exists(&receiver) {
            return false;
        }
        let guaranteed_instance = rsn_guaranteed_instance(&receiver);
        if !guaranteed_instance && !self.rsn_check(node) {
            return true;
        }
        self.rsn_respond_to_nil_method(node) && !guaranteed_instance
    }

    /// `check?`: the method must be one of `AllowedMethods`, AND this exact
    /// `csend` call must sit directly in a "condition-ish" position — see
    /// `Cops::rsn_cond_pos`'s doc for exactly which positions qualify and
    /// where they're populated (prism gives no parent pointer).
    fn rsn_check(&self, node: &ruby_prism::CallNode) -> bool {
        const COP: &str = "Lint/RedundantSafeNavigation";
        if !self.allowed_method_name(COP, node.name().as_slice()) {
            return false;
        }
        self.rsn_cond_pos.contains(&node.location().start_offset())
    }

    /// `respond_to_nil_method?`: `(csend _ :respond_to? (sym %NIL_METHODS))`
    /// — a `&.respond_to?(:sym)` call whose sole argument names a method
    /// `nil` itself implements (so dropping `&.` would silently swap a
    /// `nil` result for a real `true`/`false`, changing the truthiness of
    /// unrelated-looking code).
    fn rsn_respond_to_nil_method(&self, node: &ruby_prism::CallNode) -> bool {
        if node.name().as_slice() != b"respond_to?" {
            return false;
        }
        let Some(args) = node.arguments() else { return false };
        let arglist = args.arguments();
        let mut iter = arglist.iter();
        let Some(first) = iter.next() else { return false };
        if iter.next().is_some() {
            return false;
        }
        let Some(sym) = first.as_symbol_node() else { return false };
        RSN_NIL_METHODS.contains(&sym.unescaped())
    }

    /// Lint/RedundantSafeNavigation — `on_or`: `foo&.to_h || {}`-shaped
    /// "conversion with default" redundancy (`conversion_with_default?`'s
    /// six-way node-pattern `or`, ported as a per-method-name match since
    /// prism's `CallNode` already carries an optional trailing `.block()`
    /// as a plain field — unlike whitequark's separate wrapping `:block`
    /// node type, so there's no separate "any_block" case to detect: a
    /// `to_h` call's own `.block()` being present or absent is orthogonal
    /// to whether it's the target of this pattern at all).
    pub(crate) fn check_redundant_safe_navigation_or(&mut self, node: &ruby_prism::OrNode) {
        const COP: &str = "Lint/RedundantSafeNavigation";
        if !self.on(COP) {
            return;
        }
        let lhs = node.left();
        let Some(call) = lhs.as_call_node() else { return };
        if !call.is_safe_navigation() || call.arguments().is_some() {
            return;
        }
        let rhs = node.right();
        let matches_default = match call.name().as_slice() {
            b"to_h" => rhs.as_hash_node().is_some_and(|h| h.elements().iter().next().is_none()),
            b"to_a" => {
                call.block().is_none()
                    && rhs.as_array_node().is_some_and(|a| a.elements().iter().next().is_none())
            }
            b"to_i" => call.block().is_none() && rsn_is_int_zero(&rhs),
            b"to_f" => call.block().is_none() && rsn_is_float_zero(&rhs),
            b"to_s" => {
                call.block().is_none()
                    && rhs.as_string_node().is_some_and(|s| s.unescaped().is_empty())
            }
            _ => false,
        };
        if !matches_default {
            return;
        }
        let Some(op) = call.call_operator_loc() else { return };
        self.push(
            op.start_offset(),
            COP,
            true,
            "Redundant safe navigation with default literal detected.",
        );
        self.fixes.push((op.start_offset(), op.end_offset(), b".".to_vec()));
        self.fixes.push((lhs.location().end_offset(), node.location().end_offset(), Vec::new()));
    }

    /// Lint/RedundantSafeNavigation's `InferNonNilReceiver`: scan one
    /// analysis scope (a `def`/`defs` body, or the top-level program body —
    /// upstream's `NilReceiverChecker` stops climbing at `:def`/`:defs`/
    /// `:class`/`:module`/`:sclass`, so those are exactly the scope
    /// boundaries) and populate `self.rsn_infer_nonnil` with the start
    /// offset of every `csend` call inside whose receiver is ALREADY
    /// PROVEN non-nil by a real dereference (or, for an `if`'s own true
    /// branch, by the condition itself) reachable along every path to it.
    ///
    /// Upstream computes this by climbing UP from each `csend`'s receiver
    /// through `node.parent`/`node.left_siblings` (rubocop-ast gives real
    /// parent pointers; prism gives none). This instead walks DOWN through
    /// the scope exactly ONCE, threading a growing set of receiver-
    /// expression SOURCE TEXTS already known non-nil ("evidence") — see
    /// `rsn_scan`'s doc for why the two are equivalent and how each upstream
    /// node-type case (`_cant_be_nil?`'s `case node.type`) maps to a branch
    /// there, and `rsn_sole_condition_root` for the `sole_condition_of_parent_if?`
    /// bonus. Guarded behind the config flag (default off) since it's an
    /// O(scope size) walk of literally every scope in the file.
    pub(crate) fn rsn_scan_scope(&mut self, body: &ruby_prism::Node) {
        const COP: &str = "Lint/RedundantSafeNavigation";
        if !self.on(COP) || self.cfg.get(COP, "InferNonNilReceiver") != Some("true") {
            return;
        }
        let additional_owned = self
            .cfg
            .get(COP, "AdditionalNilMethods")
            .map(crate::config::parse_allowed_list)
            .unwrap_or_else(|| vec!["present?".to_string(), "blank?".to_string()]);
        let additional: Vec<&[u8]> = additional_owned.iter().map(|s| s.as_bytes()).collect();
        rsn_scan(body, &[], &additional, &mut self.rsn_infer_nonnil);
    }
}

/// See `rsn_scan_scope`'s doc for the overall algorithm. Returns the
/// evidence GUARANTEED to hold immediately after `node` finishes executing
/// (used to fold across a sequential list by callers); flags every
/// `InferNonNilReceiver`-redundant `csend` found ANYWHERE in `node`'s
/// subtree into `out` (keyed by that call's own start offset) as a side
/// effect, including inside non-guaranteed positions (a block body, an
/// `and`/`or` RHS, an `if`/`case`/`when` branch, a `rescue`/`ensure`/`else`
/// clause) — those are scanned with whatever evidence is available AT THAT
/// POINT, but their OWN findings are discarded by the caller (never folded
/// into the returned evidence), exactly mirroring upstream's per-node-type
/// `case` in `_cant_be_nil?`: only a `:send`/`:begin`/`:if`/`:case`/`:and`/
/// `:or`/`:pair`/`:when`/`*asgn` node's specific "always-runs-first" child
/// contributes evidence that survives past it; a `def`/`class`/`module`/
/// `sclass` found here is a scope boundary (stops immediately, contributing
/// nothing) — its OWN interior gets scanned separately, fresh, when the
/// main traversal's `visit_def_node`/etc. reaches it directly.
fn rsn_scan(
    node: &ruby_prism::Node,
    evidence: &[Vec<u8>],
    additional_nil: &[&[u8]],
    out: &mut HashSet<usize>,
) -> Vec<Vec<u8>> {
    if node.as_def_node().is_some()
        || node.as_class_node().is_some()
        || node.as_module_node().is_some()
        || node.as_singleton_class_node().is_some()
    {
        return evidence.to_vec();
    }
    if let Some(call) = node.as_call_node() {
        let mut ev = evidence.to_vec();
        if let Some(r) = call.receiver() {
            ev = rsn_scan(&r, &ev, additional_nil, out);
        }
        if let Some(args) = call.arguments() {
            for a in args.arguments().iter() {
                ev = rsn_scan(&a, &ev, additional_nil, out);
            }
        }
        if let Some(blk) = call.block() {
            if let Some(b) = blk.as_block_node() {
                if let Some(body) = b.body() {
                    let _ = rsn_scan(&body, &ev, additional_nil, out);
                }
            }
        }
        if call.is_safe_navigation() {
            if let Some(r) = call.receiver() {
                if evidence_contains(&ev, r.location().as_slice()) {
                    out.insert(call.location().start_offset());
                }
            }
            return ev;
        }
        if let Some(r) = call.receiver() {
            if rsn_non_nil_method(call.name().as_slice(), additional_nil) {
                ev.push(r.location().as_slice().to_vec());
            }
        }
        return ev;
    }
    if let Some(s) = node.as_statements_node() {
        let mut ev = evidence.to_vec();
        for stmt in s.body().iter() {
            ev = rsn_scan(&stmt, &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(a) = node.as_array_node() {
        let mut ev = evidence.to_vec();
        for e in a.elements().iter() {
            ev = rsn_scan(&e, &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(h) = node.as_hash_node() {
        let mut ev = evidence.to_vec();
        for e in h.elements().iter() {
            ev = rsn_scan(&e, &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(a) = node.as_assoc_node() {
        let ev = rsn_scan(&a.key(), evidence, additional_nil, out);
        return rsn_scan(&a.value(), &ev, additional_nil, out);
    }
    if let Some(a) = node.as_assoc_splat_node() {
        if let Some(v) = a.value() {
            return rsn_scan(&v, evidence, additional_nil, out);
        }
        return evidence.to_vec();
    }
    if let Some(a) = node.as_arguments_node() {
        let mut ev = evidence.to_vec();
        for e in a.arguments().iter() {
            ev = rsn_scan(&e, &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(a) = node.as_and_node() {
        let ev_after_lhs = rsn_scan(&a.left(), evidence, additional_nil, out);
        let _ = rsn_scan(&a.right(), &ev_after_lhs, additional_nil, out);
        return ev_after_lhs;
    }
    if let Some(o) = node.as_or_node() {
        let ev_after_lhs = rsn_scan(&o.left(), evidence, additional_nil, out);
        let _ = rsn_scan(&o.right(), &ev_after_lhs, additional_nil, out);
        return ev_after_lhs;
    }
    if let Some(i) = node.as_if_node() {
        let cond = i.predicate();
        let ev_after_cond = rsn_scan(&cond, evidence, additional_nil, out);
        let mut ev_then = ev_after_cond.clone();
        if let Some(root) = rsn_sole_condition_root(&cond) {
            ev_then.push(root.to_vec());
        }
        if let Some(stmts) = i.statements() {
            let _ = rsn_scan(&stmts.as_node(), &ev_then, additional_nil, out);
        }
        if let Some(sub) = i.subsequent() {
            let _ = rsn_scan(&sub, &ev_after_cond, additional_nil, out);
        }
        return ev_after_cond;
    }
    if let Some(u) = node.as_unless_node() {
        let cond = u.predicate();
        let ev_after_cond = rsn_scan(&cond, evidence, additional_nil, out);
        if let Some(stmts) = u.statements() {
            let _ = rsn_scan(&stmts.as_node(), &ev_after_cond, additional_nil, out);
        }
        if let Some(e) = u.else_clause() {
            let _ = rsn_scan(&e.as_node(), &ev_after_cond, additional_nil, out);
        }
        return ev_after_cond;
    }
    if let Some(e) = node.as_else_node() {
        if let Some(stmts) = e.statements() {
            return rsn_scan(&stmts.as_node(), evidence, additional_nil, out);
        }
        return evidence.to_vec();
    }
    if let Some(w) = node.as_when_node() {
        let mut ev = evidence.to_vec();
        for c in w.conditions().iter() {
            ev = rsn_scan(&c, &ev, additional_nil, out);
        }
        if let Some(stmts) = w.statements() {
            let _ = rsn_scan(&stmts.as_node(), &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(i) = node.as_in_node() {
        let _ = rsn_scan(&i.pattern(), evidence, additional_nil, out);
        if let Some(stmts) = i.statements() {
            let _ = rsn_scan(&stmts.as_node(), evidence, additional_nil, out);
        }
        return evidence.to_vec();
    }
    if let Some(c) = node.as_case_node() {
        let mut ev = match c.predicate() {
            Some(p) => rsn_scan(&p, evidence, additional_nil, out),
            None => evidence.to_vec(),
        };
        for w in c.conditions().iter() {
            ev = rsn_scan(&w, &ev, additional_nil, out);
        }
        if let Some(e) = c.else_clause() {
            let _ = rsn_scan(&e.as_node(), &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(c) = node.as_case_match_node() {
        let ev = match c.predicate() {
            Some(p) => rsn_scan(&p, evidence, additional_nil, out),
            None => evidence.to_vec(),
        };
        for i in c.conditions().iter() {
            let _ = rsn_scan(&i, &ev, additional_nil, out);
        }
        if let Some(e) = c.else_clause() {
            let _ = rsn_scan(&e.as_node(), &ev, additional_nil, out);
        }
        return ev;
    }
    if let Some(w) = node.as_local_variable_write_node() {
        return rsn_scan(&w.value(), evidence, additional_nil, out);
    }
    if let Some(w) = node.as_instance_variable_write_node() {
        return rsn_scan(&w.value(), evidence, additional_nil, out);
    }
    if let Some(w) = node.as_class_variable_write_node() {
        return rsn_scan(&w.value(), evidence, additional_nil, out);
    }
    if let Some(w) = node.as_global_variable_write_node() {
        return rsn_scan(&w.value(), evidence, additional_nil, out);
    }
    if let Some(w) = node.as_constant_write_node() {
        return rsn_scan(&w.value(), evidence, additional_nil, out);
    }
    if let Some(w) = node.as_constant_path_write_node() {
        return rsn_scan(&w.value(), evidence, additional_nil, out);
    }
    if let Some(p) = node.as_parentheses_node() {
        if let Some(b) = p.body() {
            return rsn_scan(&b, evidence, additional_nil, out);
        }
        return evidence.to_vec();
    }
    if let Some(w) = node.as_while_node() {
        let ev_after_cond = rsn_scan(&w.predicate(), evidence, additional_nil, out);
        if let Some(stmts) = w.statements() {
            let _ = rsn_scan(&stmts.as_node(), &ev_after_cond, additional_nil, out);
        }
        return ev_after_cond;
    }
    if let Some(w) = node.as_until_node() {
        let ev_after_cond = rsn_scan(&w.predicate(), evidence, additional_nil, out);
        if let Some(stmts) = w.statements() {
            let _ = rsn_scan(&stmts.as_node(), &ev_after_cond, additional_nil, out);
        }
        return ev_after_cond;
    }
    if let Some(b) = node.as_begin_node() {
        let mut ev = match b.statements() {
            Some(s) => rsn_scan(&s.as_node(), evidence, additional_nil, out),
            None => evidence.to_vec(),
        };
        if let Some(resc) = b.rescue_clause() {
            let mut r = Some(resc);
            while let Some(rn) = r {
                if let Some(stmts) = rn.statements() {
                    let _ = rsn_scan(&stmts.as_node(), evidence, additional_nil, out);
                }
                r = rn.subsequent();
            }
        }
        if let Some(e) = b.else_clause() {
            ev = rsn_scan(&e.as_node(), &ev, additional_nil, out);
        }
        if let Some(ens) = b.ensure_clause() {
            if let Some(stmts) = ens.statements() {
                ev = rsn_scan(&stmts.as_node(), evidence, additional_nil, out);
            }
        }
        return ev;
    }
    if let Some(r) = node.as_rescue_modifier_node() {
        let _ = rsn_scan(&r.expression(), evidence, additional_nil, out);
        let _ = rsn_scan(&r.rescue_expression(), evidence, additional_nil, out);
        return evidence.to_vec();
    }
    if let Some(r) = node.as_return_node() {
        if let Some(args) = r.arguments() {
            for a in args.arguments().iter() {
                let _ = rsn_scan(&a, evidence, additional_nil, out);
            }
        }
        return evidence.to_vec();
    }
    if let Some(b) = node.as_break_node() {
        if let Some(args) = b.arguments() {
            for a in args.arguments().iter() {
                let _ = rsn_scan(&a, evidence, additional_nil, out);
            }
        }
        return evidence.to_vec();
    }
    if let Some(n) = node.as_next_node() {
        if let Some(args) = n.arguments() {
            for a in args.arguments().iter() {
                let _ = rsn_scan(&a, evidence, additional_nil, out);
            }
        }
        return evidence.to_vec();
    }
    if let Some(y) = node.as_yield_node() {
        if let Some(args) = y.arguments() {
            for a in args.arguments().iter() {
                let _ = rsn_scan(&a, evidence, additional_nil, out);
            }
        }
        return evidence.to_vec();
    }
    if let Some(s) = node.as_splat_node() {
        if let Some(e) = s.expression() {
            let _ = rsn_scan(&e, evidence, additional_nil, out);
        }
        return evidence.to_vec();
    }
    if let Some(b) = node.as_block_argument_node() {
        if let Some(e) = b.expression() {
            let _ = rsn_scan(&e, evidence, additional_nil, out);
        }
        return evidence.to_vec();
    }
    if let Some(d) = node.as_defined_node() {
        let _ = rsn_scan(&d.value(), evidence, additional_nil, out);
        return evidence.to_vec();
    }
    // Anything else (literals, bare variable reads, pattern-match nodes,
    // parameter lists, ...) has no "guaranteed-first" child upstream's
    // `_cant_be_nil?` would recurse into either — matches its `case`
    // falling through to the generic sibling/parent climb with nothing
    // found, i.e. a no-op here.
    evidence.to_vec()
}

fn evidence_contains(evidence: &[Vec<u8>], text: &[u8]) -> bool {
    evidence.iter().any(|e| e.as_slice() == text)
}

/// `non_nil_method?`: not one of `nil`'s own methods, and not configured
/// via `AdditionalNilMethods` (default `present?`/`blank?`).
fn rsn_non_nil_method(name: &[u8], additional_nil: &[&[u8]]) -> bool {
    if additional_nil.iter().any(|m| *m == name) {
        return false;
    }
    !RSN_NIL_METHODS.contains(&name)
}

/// `sole_condition_of_parent_if?`'s per-branch bonus, restricted to the
/// (single) case that matters here: `condition` is the enclosing `if`'s
/// OWN, WHOLE predicate (never a sub-part of a compound one — callers only
/// ever pass an `if`'s direct `predicate()`). If it's a bare reference
/// (`if foo`) or a `csend` chain of any depth (`if foo&.bar&.baz`), entering
/// the TRUE branch proves the chain's ROOT receiver truthy, hence non-nil.
/// Callers never apply this to `unless` (a falsy condition there could
/// still mean `nil`, so upstream's `unless parent.unless?` guard excludes
/// it entirely).
fn rsn_sole_condition_root<'x>(condition: &ruby_prism::Node<'x>) -> Option<&'x [u8]> {
    if condition.as_local_variable_read_node().is_some() {
        return Some(condition.location().as_slice());
    }
    let call = condition.as_call_node()?;
    if call.is_safe_navigation() {
        return Some(rsn_csend_root_receiver(&call));
    }
    if call.receiver().is_none() {
        return Some(condition.location().as_slice());
    }
    None
}

/// `csend_root_receiver`: walk down a (possibly mixed send/csend) call
/// chain's receivers to the innermost one that isn't itself a call with a
/// receiver of its own.
fn rsn_csend_root_receiver<'x>(call: &ruby_prism::CallNode<'x>) -> &'x [u8] {
    let mut recv = match call.receiver() {
        Some(r) => r,
        None => return call.location().as_slice(),
    };
    loop {
        let Some(inner) = recv.as_call_node() else { break };
        match inner.receiver() {
            Some(r) => recv = r,
            None => break,
        }
    }
    recv.location().as_slice()
}

/// `assume_receiver_instance_exists?`: a camelCase-named constant, `self`,
/// or any non-`nil` literal is assumed to never actually be `nil` at
/// runtime, so `&.` on one is unconditionally redundant.
fn rsn_assume_receiver_instance_exists(receiver: &ruby_prism::Node) -> bool {
    if rsn_is_camel_case_const(receiver) {
        return true;
    }
    receiver.as_self_node().is_some() || (rsn_is_literal(receiver) && receiver.as_nil_node().is_none())
}

/// `receiver.const_type? && !receiver.short_name.match?(SNAKE_CASE)` — a
/// constant (bare or namespaced) whose LAST segment isn't
/// `SCREAMING_SNAKE_CASE` reads as a class/module name (rubocop's own
/// `Naming/ConstantName` heuristic), which is never realistically `nil`.
fn rsn_is_camel_case_const(receiver: &ruby_prism::Node) -> bool {
    let short_name: Option<&[u8]> = if let Some(c) = receiver.as_constant_read_node() {
        Some(c.name().as_slice())
    } else if let Some(c) = receiver.as_constant_path_node() {
        c.name().map(|n| n.as_slice())
    } else {
        None
    };
    let Some(name) = short_name else { return false };
    !rsn_snake_case(name)
}

/// `SNAKE_CASE = /\A[[:digit:][:upper:]_]+\z/` — every byte is an ASCII
/// digit, ASCII uppercase letter, or underscore.
fn rsn_snake_case(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&b| b.is_ascii_digit() || b.is_ascii_uppercase() || b == b'_')
}

/// `receiver.literal? && !receiver.nil_type?` — a basic literal OTHER than
/// the `nil` literal itself.
fn rsn_is_literal(node: &ruby_prism::Node) -> bool {
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
        || node.as_regular_expression_node().is_some()
        || node.as_interpolated_regular_expression_node().is_some()
        || node.as_array_node().is_some()
        || node.as_hash_node().is_some()
        || node.as_true_node().is_some()
        || node.as_false_node().is_some()
        || node.as_nil_node().is_some()
        || node.as_range_node().is_some()
}

/// `guaranteed_instance?`: a plain (non-safe-nav) `.to_s`/`.to_i`/`.to_f`/
/// `.to_a`/`.to_h` call's RESULT can never be `nil` (each always returns a
/// real instance of its type), so a further `&.` on it is redundant
/// regardless of the method that follows. A SAFE-NAV predecessor doesn't
/// count (`foo&.to_s&.strip`'s first `&.` might itself short-circuit to
/// `nil` without ever calling `to_s` at all) — mirrored here by requiring
/// `!is_safe_navigation()`, matching upstream's `receiver.send_type?`
/// (`false` for a whitequark `csend`). Prism represents an attached block
/// as a plain optional field on the SAME `CallNode` (unlike whitequark's
/// separate wrapping `:block` node), so there's no separate "any_block"
/// unwrap needed — `foo.to_h { ... }` already IS the `CallNode` this
/// matches directly.
fn rsn_guaranteed_instance(receiver: &ruby_prism::Node) -> bool {
    let Some(call) = receiver.as_call_node() else { return false };
    if call.is_safe_navigation() {
        return false;
    }
    matches!(call.name().as_slice(), b"to_s" | b"to_i" | b"to_f" | b"to_a" | b"to_h")
}

fn rsn_is_int_zero(node: &ruby_prism::Node) -> bool {
    node.as_integer_node().is_some_and(|n| TryInto::<i32>::try_into(n.value()) == Ok(0))
}

fn rsn_is_float_zero(node: &ruby_prism::Node) -> bool {
    node.as_float_node().is_some_and(|n| n.value() == 0.0)
}


// ============================================================================
// Lint/DuplicateMethods
// ============================================================================
//
// Ported from `RuboCop::Cop::Lint::DuplicateMethods`. Tracks every method
// definition (plain `def`, `def self.x`/`def CONST.x`, `alias`, `alias_method`,
// `attr`/`attr_reader`/`attr_writer`/`attr_accessor`, `delegate` (only when
// `AllCops: ActiveSupportExtensionsEnabled`), and `def_delegator(s)`/
// `def_instance_delegator(s)`) under a QUALIFIED key (its enclosing class/
// module/sclass/casgn/block "scope", à la rubocop-ast's `parent_module_name`,
// plus the nearest enclosing `def`'s name for a nested definition) and flags
// the SECOND (and later) definition under the same key, referencing the
// file:line of the ORIGINAL. Definitions inside an `if`/`unless`/ternary are
// ignored entirely (upstream: "a different definition is used depending on
// platform, etc."), and a lone re-definition inside an `ensure`/`rescue`
// clause is silently accepted ONCE per clause-kind (a common idiom: define,
// then restore in `ensure`) — see `Cops::dm_found_method`'s doc.
//
// Prism has no parent pointers, so upstream's `node.parent_module_name`
// (an ancestor walk over `:class`/`:module`/`:sclass`/`:casgn`/`:block`
// nodes) is replicated as a STACK (`Cops::dm_ns_stack`) pushed/popped by the
// relevant `visit_*` hooks in `mod.rs`, walked nearest-to-farthest by
// `Cops::dm_pmn`. `anonymous_class_block` (the fallback for a `def`/alias/
// attr sitting in an unassigned `Class.new`/`Module.new do...end` block) is
// replicated the same way via `Cops::dm_anon_stack` + `Cops::dm_sclass_stack`.

/// Nearest enclosing `rescue`/`ensure` "scope" — see `Cops::dm_rescue_scope`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DmScope {
    Rescue,
    Ensure,
}

/// A `Class.new`/`Module.new do...end` block's identity for
/// `anon_block_scope_id` purposes — see `Cops::dm_anon_stack`'s doc. Unlike
/// upstream's literal `"#{receiver.source}.#{method}"` / file:line text,
/// only EQUALITY matters here (it's never rendered), so the block's own
/// start offset stands in for upstream's `source_location(anon_block)`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum DmScopeId {
    Pos(usize),
    Recv(Vec<u8>, Vec<u8>),
}

/// A definition's dedup key: the fully-qualified display name (prefixed by
/// the nearest enclosing `def`'s name for a nested definition — upstream's
/// `method_key`), plus an optional `anon_block_scope_id` suffix.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct DmKey {
    base: String,
    scope_id: Option<DmScopeId>,
}

/// One frame of `Cops::dm_ns_stack` — see `Cops::dm_pmn`'s doc.
pub(crate) enum DmNsFrame {
    /// Contributes this literal text segment to the joined scope name.
    Frag(String),
    /// This ancestor can't be resolved (upstream's `return nil` from deep
    /// inside `parent_module_name`'s block) — the WHOLE walk fails (`None`),
    /// matching Ruby's non-local return semantics.
    Abort,
    /// Transparent: contributes nothing, but doesn't fail the walk (a bare
    /// `class_eval do...end` with an implicit receiver, or a `Class.new`/
    /// `Module.new do...end` block directly assigned to a constant — the
    /// casgn ancestor already contributes the name).
    Skip,
}

pub(crate) struct DmNsEntry {
    pub(crate) frame: DmNsFrame,
    /// For a `class`/`module` frame only: its simple (last-segment)
    /// declared name — backs `Cops::dm_lookup_constant`.
    pub(crate) simple_name: Option<Vec<u8>>,
}

/// The subject shape of an enclosing `class << subject` — backs
/// `Cops::dm_found_instance_method`'s `found_sclass_method` fallback and
/// `anonymous_class_block`'s "any non-self sclass ancestor" exclusion.
pub(crate) enum DmSclass {
    SelfKind,
    ConstKind,
    /// A bare/method-call subject (`class << blah`) — holds its method name.
    SendKind(Vec<u8>),
    OtherKind,
}

/// One frame of `Cops::dm_anon_stack`, pushed for EVERY block (any kind) —
/// mirrors `node.each_ancestor(:block).first` for `anonymous_class_block`.
#[derive(Clone)]
pub(crate) struct DmAnonFrame {
    pub(crate) is_new_block: bool,
    pub(crate) parent_lvasgn: bool,
    pub(crate) scope_id: DmScopeId,
    /// `Cops::dm_ns_stack`'s length just BEFORE this block's own frame was
    /// pushed — i.e. the ancestor chain for `anon_block.parent_module_name`
    /// itself (which does not include the block's own frame).
    pub(crate) ns_len_at_entry: usize,
}

/// A bare (symbol or string) literal's content, or `None` for anything else
/// — upstream's `sym_name`/`{sym str}` node-pattern fragments.
fn dm_sym_or_str(n: &ruby_prism::Node) -> Option<Vec<u8>> {
    if let Some(s) = n.as_symbol_node() {
        return Some(s.unescaped().to_vec());
    }
    if let Some(s) = n.as_string_node() {
        return Some(s.unescaped().to_vec());
    }
    None
}

/// `class_or_module_new_block?`'s call-shape half: `(send (const _ {:Class
/// :Module}) :new ...)` — a plain (non-safe-nav) `new` call whose receiver's
/// SOURCE TEXT is exactly `Class`/`::Class`/`Module`/`::Module`.
pub(crate) fn dm_new_block_call(call: &ruby_prism::CallNode, src: &[u8]) -> bool {
    if call.name().as_slice() != b"new" || call.is_safe_navigation() {
        return false;
    }
    let Some(r) = call.receiver() else { return false };
    let l = r.location();
    matches!(&src[l.start_offset()..l.end_offset()], b"Class" | b"::Class" | b"Module" | b"::Module")
}

/// The simple (last-segment) name of a constant reference — `Foo` -> "Foo",
/// `Foo::Bar` -> "Bar" (namespace ignored, matching upstream's `_, const_name
/// = *node.receiver` destructure).
fn dm_const_last_name(node: &ruby_prism::Node) -> Option<Vec<u8>> {
    if let Some(c) = node.as_constant_read_node() {
        return Some(c.name().as_slice().to_vec());
    }
    if let Some(p) = node.as_constant_path_node() {
        return p.name().map(|n| n.as_slice().to_vec());
    }
    None
}

/// `smart_path`'s effective behavior for this port: the oracle always stages
/// upstream's `smart_path` — relative to the working directory when the
/// file sits under it, else the path as given. The engine's `rel_path` is
/// already the CLI-supplied (cwd-relative during corpus runs) path, so this
/// only trims a cosmetic leading "./"; the oracle harness normalizes its
/// absolute temp paths back to `(string)` itself.
fn dm_smart_path(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

/// `humanize_scope`: `scope.sub(/(?:(?<name>.*)::)#<Class:\k<name>>|
/// #<Class:(?<name>.*)>(?:::)?/, '\k<name>.')`, then `#` appended unless it
/// already ends in `.`. Hand-rolled (no backreference support in the `regex`
/// crate) — safe for OUR OWN generated fragments, which only ever nest an
/// `#<Class:...>` segment as the LAST (nearest) one.
fn dm_humanize_scope(scope: &str) -> String {
    let marker = "::#<Class:";
    let mut replaced: Option<String> = None;
    let mut search_from = 0;
    while let Some(rel) = scope[search_from..].find(marker) {
        let i = search_from + rel;
        let name = &scope[..i];
        let expect_suffix = format!("{marker}{name}>");
        if scope[i..] == expect_suffix {
            replaced = Some(format!("{name}."));
            break;
        }
        search_from = i + 1;
    }
    if replaced.is_none() {
        if let Some(idx) = scope.find("#<Class:") {
            if let Some(close_rel) = scope[idx..].find('>') {
                let close = idx + close_rel;
                let name2 = &scope[idx + 8..close];
                let mut after = close + 1;
                if scope[after..].starts_with("::") {
                    after += 2;
                }
                replaced = Some(format!("{}{}.{}", &scope[..idx], name2, &scope[after..]));
            }
        }
    }
    let out = replaced.unwrap_or_else(|| scope.to_string());
    if out.ends_with('.') {
        out
    } else {
        format!("{out}#")
    }
}

/// `qualified_name(enclosing, namespace: nil, mod_name)`: the `namespace`
/// argument is always `nil` at both of upstream's call sites this port
/// exercises (the anon-block "Object" case, and `lookup_constant`'s simple
/// single-segment class/module names).
fn dm_qualified_name(enclosing: Option<&str>, mod_name: &str) -> String {
    match enclosing {
        Some("Object") => mod_name.to_string(),
        Some(e) => format!("{e}::{mod_name}"),
        None => format!("::{mod_name}"),
    }
}

/// AssocNode elements of a `HashNode`/`KeywordHashNode` (an `AssocSplatNode`
/// among them — `**opts` — simply isn't an `AssocNode` and is dropped, same
/// as upstream's node-pattern only matching literal `pair`s).
fn dm_hash_pairs<'pr>(node: &ruby_prism::Node<'pr>) -> Option<Vec<ruby_prism::AssocNode<'pr>>> {
    let elements = if let Some(h) = node.as_hash_node() {
        h.elements()
    } else if let Some(h) = node.as_keyword_hash_node() {
        h.elements()
    } else {
        return None;
    };
    Some(elements.iter().filter_map(|e| e.as_assoc_node()).collect())
}

fn dm_pair_value<'pr>(pairs: &[ruby_prism::AssocNode<'pr>], key: &[u8]) -> Option<ruby_prism::Node<'pr>> {
    pairs
        .iter()
        .find(|p| p.key().as_symbol_node().is_some_and(|s| s.unescaped() == key))
        .map(|p| p.value())
}

/// `alias_method?`: `(send nil? :alias_method (sym $_name) (sym $_original_name))`
/// — BOTH arguments must be symbol literals (a string, or a dynamic
/// expression, doesn't match at all).
fn dm_match_alias_method(call: &ruby_prism::CallNode) -> Option<(Vec<u8>, Vec<u8>)> {
    if call.receiver().is_some() || call.name().as_slice() != b"alias_method" {
        return None;
    }
    let args = call.arguments()?;
    let list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
    if list.len() != 2 {
        return None;
    }
    let name = list[0].as_symbol_node()?.unescaped().to_vec();
    let orig = list[1].as_symbol_node()?.unescaped().to_vec();
    Some((name, orig))
}

/// `attribute_accessor?`: `(send nil? {:attr_reader :attr_writer
/// :attr_accessor :attr} $...)` — captures EVERY remaining argument
/// (any type; `sym_name` filters non-symbols out later).
fn dm_match_attribute_accessor<'pr>(
    call: &ruby_prism::CallNode<'pr>,
) -> Option<(&'static str, Vec<ruby_prism::Node<'pr>>)> {
    if call.receiver().is_some() {
        return None;
    }
    let kind = match call.name().as_slice() {
        b"attr_reader" => "attr_reader",
        b"attr_writer" => "attr_writer",
        b"attr_accessor" => "attr_accessor",
        b"attr" => "attr",
        _ => return None,
    };
    let args: Vec<ruby_prism::Node> = call.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
    Some((kind, args))
}

/// `delegate_method?`: `(send nil? :delegate ({sym str} $_)+ (hash <(pair
/// (sym :to) {sym str}) ...>))` — one-or-more leading sym/str names, then
/// EXACTLY a trailing hash argument that contains a `to:` pair with a
/// sym/str value (any other keys, `**splat`, or a missing/dynamic `to:`,
/// fail the whole match).
fn dm_match_delegate(call: &ruby_prism::CallNode) -> Option<Vec<Vec<u8>>> {
    if call.receiver().is_some() || call.name().as_slice() != b"delegate" {
        return None;
    }
    let args = call.arguments()?;
    let list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
    if list.len() < 2 {
        return None;
    }
    let (last, rest) = list.split_last()?;
    let pairs = dm_hash_pairs(last)?;
    let has_to = pairs
        .iter()
        .any(|p| p.key().as_symbol_node().is_some_and(|s| s.unescaped() == b"to") && dm_sym_or_str(&p.value()).is_some());
    if !has_to {
        return None;
    }
    let mut names = Vec::with_capacity(rest.len());
    for a in rest {
        names.push(dm_sym_or_str(a)?);
    }
    if names.is_empty() {
        return None;
    }
    Some(names)
}

/// `delegate_prefix`: `nil` unless the trailing hash has a `prefix:` pair;
/// `true` uses the `to:` value's text, a literal sym/str uses its own text,
/// anything else (a dynamic expression, `false`, ...) means no prefix.
fn dm_delegate_prefix(call: &ruby_prism::CallNode) -> Option<Vec<u8>> {
    let args = call.arguments()?;
    let list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
    let last = list.last()?;
    let pairs = dm_hash_pairs(last)?;
    let prefix_val = dm_pair_value(&pairs, b"prefix")?;
    if prefix_val.as_true_node().is_some() {
        let to_val = dm_pair_value(&pairs, b"to")?;
        dm_sym_or_str(&to_val)
    } else {
        dm_sym_or_str(&prefix_val)
    }
}

/// `delegator?`: `(send nil? {:def_delegator :def_instance_delegator}
/// {{sym str} ({sym str} $_) | {sym str} {sym str} ({sym str} $_)})` —
/// EXACTLY 2 or 3 positional sym/str args; captures the LAST one (the
/// alias, when a 3rd argument is given).
fn dm_match_delegator(call: &ruby_prism::CallNode) -> Option<Vec<u8>> {
    if call.receiver().is_some() || !matches!(call.name().as_slice(), b"def_delegator" | b"def_instance_delegator") {
        return None;
    }
    let args = call.arguments()?;
    let list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
    if list.len() != 2 && list.len() != 3 {
        return None;
    }
    let mut last = None;
    for a in &list {
        last = Some(dm_sym_or_str(a)?);
    }
    last
}

/// `delegators?`: `(send nil? {:def_delegators :def_instance_delegators}
/// {sym str} ({sym str} $_)+)` — first arg (target, uncaptured) plus
/// one-or-more captured names, all sym/str.
fn dm_match_delegators(call: &ruby_prism::CallNode) -> Option<Vec<Vec<u8>>> {
    if call.receiver().is_some() || !matches!(call.name().as_slice(), b"def_delegators" | b"def_instance_delegators") {
        return None;
    }
    let args = call.arguments()?;
    let list: Vec<ruby_prism::Node> = args.arguments().iter().collect();
    if list.len() < 2 {
        return None;
    }
    dm_sym_or_str(&list[0])?;
    let mut names = Vec::with_capacity(list.len() - 1);
    for a in &list[1..] {
        names.push(dm_sym_or_str(a)?);
    }
    Some(names)
}

impl<'a> super::Cops<'a> {
    /// `on_def`/`on_defs` — prism unifies both into one `DefNode` (`defs` <=>
    /// `receiver().is_some()`). A plain `def` always goes through
    /// `found_instance_method`; `def self.x`/`def CONST.x` go through the
    /// separate (simpler, no `found_sclass_method` fallback) `check_self_
    /// receiver`/`check_const_receiver` paths; any OTHER receiver kind
    /// (`def obj.x` for an arbitrary expression) is never checked at all,
    /// matching upstream's `on_defs` having no `else` branch.
    pub(crate) fn check_duplicate_methods_def(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Lint/DuplicateMethods";
        if !self.on(COP) {
            return;
        }
        if self.dm_if_depth > 0 {
            return;
        }
        let anchor = node.def_keyword_loc().start_offset();
        let name = node.name().as_slice().to_vec();
        match node.receiver() {
            None => self.dm_found_instance_method(anchor, &name),
            Some(recv) => {
                if let Some(const_name) = dm_const_last_name(&recv) {
                    self.dm_check_const_receiver(anchor, &name, &const_name);
                } else if recv.as_self_node().is_some() {
                    self.dm_check_self_receiver(anchor, &name);
                }
            }
        }
    }

    /// `on_alias`: `alias new old` — self-alias (`alias foo foo`) is always
    /// allowed (suppresses Ruby's redefinition warning), and both sides
    /// must be plain symbols (a `$gvar` alias uses different children and
    /// never matches at all).
    pub(crate) fn check_duplicate_methods_alias(&mut self, node: &ruby_prism::AliasMethodNode) {
        const COP: &str = "Lint/DuplicateMethods";
        if !self.on(COP) {
            return;
        }
        let Some(new_sym) = node.new_name().as_symbol_node() else { return };
        let Some(old_sym) = node.old_name().as_symbol_node() else { return };
        let name = new_sym.unescaped().to_vec();
        let original = old_sym.unescaped().to_vec();
        if name == original {
            return;
        }
        if self.dm_if_depth > 0 {
            return;
        }
        let anchor = node.location().start_offset();
        self.dm_found_instance_method(anchor, &name);
    }

    /// `on_send` — `alias_method`/`attr*`/`delegate`/`def_delegator(s)`.
    /// Restricted to those 9 method names (`RESTRICT_ON_SEND`), same as
    /// upstream. NOTE: unlike the other four branches, `attr*` does NOT get
    /// the `inside_condition?` exemption upstream — ported verbatim.
    pub(crate) fn check_duplicate_methods_send(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Lint/DuplicateMethods";
        if !self.on(COP) {
            return;
        }
        if !matches!(
            node.name().as_slice(),
            b"alias_method"
                | b"attr_reader"
                | b"attr_writer"
                | b"attr_accessor"
                | b"attr"
                | b"delegate"
                | b"def_delegator"
                | b"def_instance_delegator"
                | b"def_delegators"
                | b"def_instance_delegators"
        ) {
            return;
        }
        let anchor = node.location().start_offset();
        if let Some((name, original)) = dm_match_alias_method(node) {
            if name == original || self.dm_if_depth > 0 {
                return;
            }
            self.dm_found_instance_method(anchor, &name);
            return;
        }
        if let Some((kind, args)) = dm_match_attribute_accessor(node) {
            self.dm_on_attr(anchor, kind, &args);
            return;
        }
        if self.hot.active_support {
            if let Some(names) = dm_match_delegate(node) {
                if self.dm_if_depth > 0 {
                    return;
                }
                self.dm_on_delegate(anchor, node, &names);
                return;
            }
        }
        if let Some(name) = dm_match_delegator(node) {
            if self.dm_if_depth > 0 {
                return;
            }
            self.dm_found_instance_method(anchor, &name);
            return;
        }
        if let Some(names) = dm_match_delegators(node) {
            if self.dm_if_depth > 0 {
                return;
            }
            for name in names {
                self.dm_found_instance_method(anchor, &name);
            }
        }
    }

    fn dm_on_attr(&mut self, anchor: usize, kind: &str, args: &[ruby_prism::Node]) {
        match kind {
            "attr" => {
                let writable = args.len() == 2 && args[1].as_true_node().is_some();
                if let Some(first) = args.first() {
                    self.dm_found_attr_arg(anchor, first, true, writable);
                }
            }
            "attr_reader" => {
                for a in args {
                    self.dm_found_attr_arg(anchor, a, true, false);
                }
            }
            "attr_writer" => {
                for a in args {
                    self.dm_found_attr_arg(anchor, a, false, true);
                }
            }
            "attr_accessor" => {
                for a in args {
                    self.dm_found_attr_arg(anchor, a, true, true);
                }
            }
            _ => {}
        }
    }

    fn dm_found_attr_arg(&mut self, anchor: usize, arg: &ruby_prism::Node, readable: bool, writable: bool) {
        let Some(sym) = arg.as_symbol_node() else { return };
        let name = sym.unescaped().to_vec();
        if readable {
            self.dm_found_instance_method(anchor, &name);
        }
        if writable {
            let mut w = name;
            w.push(b'=');
            self.dm_found_instance_method(anchor, &w);
        }
    }

    fn dm_on_delegate(&mut self, anchor: usize, node: &ruby_prism::CallNode, names: &[Vec<u8>]) {
        let prefix = dm_delegate_prefix(node);
        for name in names {
            let full = if let Some(ref p) = prefix {
                let mut v = p.clone();
                v.push(b'_');
                v.extend_from_slice(name);
                v
            } else {
                name.clone()
            };
            self.dm_found_instance_method(anchor, &full);
        }
    }

    /// `found_instance_method`: `parent_module_name` (a real enclosing class/
    /// module/sclass/casgn/block chain) first; else `anonymous_class_block`
    /// (an unassigned `Class.new`/`Module.new do...end` block); else
    /// `found_sclass_method` (a `class << subject` whose subject is a bare
    /// method call, e.g. `class << blah`).
    fn dm_found_instance_method(&mut self, anchor: usize, name: &[u8]) {
        let name_str = String::from_utf8_lossy(name).into_owned();
        if let Some(scope) = self.dm_pmn(self.dm_ns_stack.len()) {
            let display = format!("{}{}", dm_humanize_scope(&scope), name_str);
            self.dm_found_method(anchor, display, None);
            return;
        }
        if let Some(anon) = self.dm_anonymous_class_block() {
            let anon_pmn = self.dm_pmn(anon.ns_len_at_entry);
            let base = dm_qualified_name(anon_pmn.as_deref(), "Object");
            let scope_txt = if self.dm_sclass_stack.is_empty() { base } else { format!("#<Class:{base}>") };
            let display = format!("{}{}", dm_humanize_scope(&scope_txt), name_str);
            self.dm_found_method(anchor, display, Some(anon.scope_id.clone()));
            return;
        }
        if let Some(DmSclass::SendKind(subj)) = self.dm_sclass_stack.last() {
            let display = format!("{}.{}", String::from_utf8_lossy(subj), name_str);
            self.dm_found_method(anchor, display, None);
        }
    }

    /// `check_const_receiver`: `def CONST.x` — resolve `CONST`'s simple name
    /// against an enclosing `class`/`module` ancestor (compound casgn/
    /// dotted-declaration matching isn't replicated — not exercised by the
    /// fixture; see the final report).
    fn dm_check_const_receiver(&mut self, anchor: usize, name: &[u8], const_name: &[u8]) {
        let Some(qualified) = self.dm_lookup_constant(const_name) else { return };
        let display = format!("{qualified}.{}", String::from_utf8_lossy(name));
        self.dm_found_method(anchor, display, None);
    }

    /// `check_self_receiver`: `def self.x` — NOTE no `found_sclass_method`
    /// fallback here (upstream has none either): if neither `parent_module_
    /// name` nor `anonymous_class_block` resolves, nothing happens.
    fn dm_check_self_receiver(&mut self, anchor: usize, name: &[u8]) {
        let name_str = String::from_utf8_lossy(name).into_owned();
        if let Some(enclosing) = self.dm_pmn(self.dm_ns_stack.len()) {
            let display = format!("{enclosing}.{name_str}");
            self.dm_found_method(anchor, display, None);
            return;
        }
        if let Some(anon) = self.dm_anonymous_class_block() {
            let anon_pmn = self.dm_pmn(anon.ns_len_at_entry);
            let scope = dm_qualified_name(anon_pmn.as_deref(), "Object");
            let display = format!("{scope}.{name_str}");
            self.dm_found_method(anchor, display, Some(anon.scope_id.clone()));
        }
    }

    /// `lookup_constant`: nearest-first walk over `dm_ns_stack`'s class/
    /// module frames, matching by simple declared name.
    fn dm_lookup_constant(&self, const_name: &[u8]) -> Option<String> {
        for (idx, entry) in self.dm_ns_stack.iter().enumerate().rev() {
            if entry.simple_name.as_deref() == Some(const_name) {
                let enc = self.dm_pmn(idx);
                return Some(dm_qualified_name(enc.as_deref(), &String::from_utf8_lossy(const_name)));
            }
        }
        None
    }

    /// `parent_module_name`: walk `dm_ns_stack[..upto]` nearest-to-farthest,
    /// collecting each frame's fragment (aborting the WHOLE walk — returns
    /// `None` — the moment an `Abort` frame is hit, matching upstream's
    /// non-local `return nil`), then reverse (farthest-to-nearest) and join
    /// with `::`; an empty result is `"Object"` (upstream's fallback for "no
    /// qualifying ancestors at all", DISTINCT from an abort).
    fn dm_pmn(&self, upto: usize) -> Option<String> {
        let mut parts = Vec::new();
        for entry in self.dm_ns_stack[..upto].iter().rev() {
            match &entry.frame {
                DmNsFrame::Frag(s) => parts.push(s.clone()),
                DmNsFrame::Abort => return None,
                DmNsFrame::Skip => {}
            }
        }
        parts.reverse();
        Some(if parts.is_empty() { "Object".to_string() } else { parts.join("::") })
    }

    /// `anonymous_class_block`: the nearest enclosing block of ANY kind must
    /// itself be a `Class.new`/`Module.new do...end` (`is_new_block`), not
    /// assigned to a local variable (`parent_lvasgn`), and no enclosing
    /// `sclass` may have a non-`self` subject.
    fn dm_anonymous_class_block(&self) -> Option<DmAnonFrame> {
        let top = self.dm_anon_stack.last()?;
        if !top.is_new_block || top.parent_lvasgn {
            return None;
        }
        if self.dm_sclass_stack.iter().any(|s| !matches!(s, DmSclass::SelfKind)) {
            return None;
        }
        Some(top.clone())
    }

    /// Pushed/popped by `visit_class_node`/`visit_module_node` right after/
    /// before `enter_namespace`/`leave_namespace` — see `dm_ns_stack`'s doc.
    pub(crate) fn dm_enter_namespace(&mut self, constant_path: &ruby_prism::Node) {
        let frag = String::from_utf8_lossy(self.node_src(constant_path)).into_owned();
        let simple = dm_const_last_name(constant_path);
        self.dm_ns_stack.push(DmNsEntry { frame: DmNsFrame::Frag(frag), simple_name: simple });
    }
    pub(crate) fn dm_leave_namespace(&mut self) {
        self.dm_ns_stack.pop();
    }

    /// Pushed/popped by `visit_singleton_class_node` around its body —
    /// `parent_module_name_for_sclass`: `class << self` recurses into the
    /// ALREADY-established ancestor chain (computed BEFORE this frame is
    /// pushed, matching upstream's `sclass_node.parent_module_name` never
    /// including the sclass node itself); `class << CONST` wraps the
    /// constant's own source text; anything else (a bare/method-call
    /// subject, e.g. `class << blah`) aborts `parent_module_name` but is
    /// still tracked (as a `SendKind`) for `found_sclass_method`.
    pub(crate) fn dm_enter_sclass(&mut self, subject: &ruby_prism::Node) {
        let (frame, kind) = if subject.as_self_node().is_some() {
            let rec = self.dm_pmn(self.dm_ns_stack.len());
            (DmNsFrame::Frag(format!("#<Class:{}>", rec.unwrap_or_default())), DmSclass::SelfKind)
        } else if subject.as_constant_read_node().is_some() || subject.as_constant_path_node().is_some() {
            let text = String::from_utf8_lossy(self.node_src(subject)).into_owned();
            (DmNsFrame::Frag(format!("#<Class:{text}>")), DmSclass::ConstKind)
        } else if let Some(call) = subject.as_call_node() {
            (DmNsFrame::Abort, DmSclass::SendKind(call.name().as_slice().to_vec()))
        } else {
            (DmNsFrame::Abort, DmSclass::OtherKind)
        };
        self.dm_ns_stack.push(DmNsEntry { frame, simple_name: None });
        self.dm_sclass_stack.push(kind);
    }
    pub(crate) fn dm_leave_sclass(&mut self) {
        self.dm_ns_stack.pop();
        self.dm_sclass_stack.pop();
    }

    /// `visit_call_node`'s `(is_new_block, ns_frame)` classification for a
    /// block it's about to descend into — `parent_module_name_for_block`:
    /// `class_eval` (implicit receiver contributes nothing; a const receiver
    /// contributes its text; anything else aborts) takes priority; else a
    /// `Class.new`/`Module.new` block DIRECTLY assigned to a constant
    /// (`dm_pending_casgn_new_block`, set by `dm_check_casgn_value`)
    /// contributes nothing (the casgn ancestor already does); any other
    /// block aborts (`new_class_or_module_block?`'s catch-all `yield`).
    pub(crate) fn dm_classify_block(&mut self, call: &ruby_prism::CallNode) -> (bool, DmNsFrame) {
        let is_new = dm_new_block_call(call, self.src);
        let is_casgn_assigned = std::mem::take(&mut self.dm_pending_casgn_new_block);
        if call.name().as_slice() == b"class_eval" {
            let frame = match call.receiver() {
                None => DmNsFrame::Skip,
                Some(recv) => {
                    if recv.as_constant_read_node().is_some() || recv.as_constant_path_node().is_some() {
                        DmNsFrame::Frag(String::from_utf8_lossy(self.node_src(&recv)).into_owned())
                    } else {
                        DmNsFrame::Abort
                    }
                }
            };
            (is_new, frame)
        } else if is_new && is_casgn_assigned {
            (is_new, DmNsFrame::Skip)
        } else {
            (is_new, DmNsFrame::Abort)
        }
    }

    /// `visit_constant_write_node`/`visit_constant_path_write_node`: if
    /// `value` is directly a `Class.new`/`Module.new do...end` call, push
    /// this casgn's own `parent_module_name` fragment (`frag`) and arm
    /// `dm_pending_casgn_new_block` so the upcoming block visit knows to
    /// contribute nothing of its own — returns whether a frame was pushed
    /// (the caller pops it back off after visiting the value).
    pub(crate) fn dm_check_casgn_value(&mut self, value: &ruby_prism::Node, frag: String) -> bool {
        let Some(c) = value.as_call_node() else { return false };
        if !dm_new_block_call(&c, self.src) || c.block().is_none() {
            return false;
        }
        self.dm_pending_casgn_new_block = true;
        self.dm_ns_stack.push(DmNsEntry { frame: DmNsFrame::Frag(frag), simple_name: None });
        true
    }

    /// `found_method`: the funnel every path above goes through. A
    /// re-definition under an already-seen key is normally an offense,
    /// EXCEPT the first time it happens while inside a `rescue`/`ensure`
    /// clause of a given kind (`dm_scope_seen`) — a common idiom (define,
    /// then restore in `ensure`) that upstream treats as re-baselining
    /// rather than flagging; a SECOND redefinition within the SAME clause
    /// kind (or one outside any rescue/ensure at all) still offends.
    fn dm_found_method(&mut self, anchor: usize, display_name: String, scope_id: Option<DmScopeId>) {
        const COP: &str = "Lint/DuplicateMethods";
        let key_base = match self.def_name_stack.last() {
            Some(encl) => format!("{}.{}", String::from_utf8_lossy(encl), display_name),
            None => display_name.clone(),
        };
        let key = DmKey { base: key_base, scope_id };
        let scope = self.dm_rescue_scope.last().copied();
        if let Some(&prev_anchor) = self.dm_definitions.get(&key) {
            if let Some(sc) = scope {
                let seen = self.dm_scope_seen.entry(sc).or_default();
                if !seen.contains(&key) {
                    seen.insert(key.clone());
                    self.dm_definitions.insert(key, anchor);
                    return;
                }
            }
            let prev_line = self.idx.loc(prev_anchor).0;
            let cur_line = self.idx.loc(anchor).0;
            let base = dm_smart_path(self.rel_path);
            let msg = format!("Method `{display_name}` is defined at both {base}:{prev_line} and {base}:{cur_line}.");
            self.push(anchor, COP, false, msg);
        } else {
            self.dm_definitions.insert(key, anchor);
        }
    }
}


// =====================================================================
// Lint/UselessAssignment
//
// A from-scratch, narrowed port of `RuboCop::Cop::VariableForce` (the
// ~450-line `variable_force.rb` plus its `Scope`/`Variable`/`Assignment`/
// `Reference`/`Branch`/`Branchable` support classes) specialized to exactly
// what `Lint::UselessAssignment` consumes. This is the heaviest VariableForce
// consumer in the cop set: unlike `ShadowedArgument`/`Unused*Argument`
// (which only need a used/unused boolean per parameter), this cop needs
// real per-assignment liveness — which of several sequential/branching
// assignments to the same name are "live" (could still be observed by a
// later read) versus "dead" (unconditionally overwritten before any read).
//
// Architecture, mapped onto prism:
//
// 1. SCOPES (`UaKind`/`UaFrame`): one frame per `def`/`defs`, `class`,
//    `module`, `sclass`, and every `block`/`lambda` literal, plus one for
//    the top level — exactly upstream's `SCOPE_TYPES`. Variable
//    declaration/resolution is delegated to prism's own `depth` field on
//    every `LocalVariable{Read,Write,Target,OperatorWrite,OrWrite,
//    AndWrite}Node` (see the `ShadowedArgument`/`SaCollector` doc comment
//    above for why this is exact): `frames[frames.len()-1-depth]` is the
//    variable's home frame. A block's frame is "soft" — `depth` can walk
//    outward through it — so `captured_by_block` is just `depth > 0`
//    evaluated while the CURRENT frame is a block (mirrors
//    `VariableTable#mark_variable_as_captured_by_block_if_so`).
//
// 2. BRANCHES (`UaBranch` = `Option<Rc<UaBranchNode>>`, a persistent/shared
//    linked list): upstream's `Branch.of`/`Branchable` compute a node's
//    "nearest branching ancestor" lazily via real parent pointers, which
//    prism doesn't give us. Since branches never cross a scope boundary
//    (`Branch.of` stops once `!scope.include?(node)`), and since we already
//    do a real recursive-descent traversal (not the generic auto-visit used
//    by simpler cops), we thread the "current branch" downward exactly like
//    a reader parameter: entering a branched CHILD position (an `if`/
//    `unless` truthy/falsey body, a `case`/`case/in` `when`/`in`/`else`
//    clause, a `rescue`/`rescue-clause`/`else` region of a "protected"
//    `begin`, the right-hand side of `&&`/`||`/`op_asgn`/`or_asgn`/
//    `and_asgn`) pushes a new `Rc<UaBranchNode>` (parent = the branch active
//    just before entering); an ALWAYS-RUN position (an `if`'s condition, a
//    `case`'s target, a loop's condition, a `for`'s element/collection, the
//    left side of `&&`/`||`/op-assign, an `ensure` body) is transparent
//    (inherits the surrounding branch unchanged — matches `always_run?`
//    causing `Branch.of` to skip that ancestor entirely). Entering any new
//    SCOPE resets the current branch to `None` (matches branches never
//    escaping their scope). `UaBranchNode.may_jump` is upstream's
//    `ExceptionHandler#may_jump_to_other_branch?`/`#may_run_incompletely?`
//    (always equal for our two users, `Rescue`/`Ensure`'s `main_body?`
//    slot): true only for the PROTECTED body of a `begin` that has a
//    `rescue` and/or `ensure` clause, since an exception can transfer
//    control out of it at any statement boundary.
//
// 3. REFERENCE CASCADE (`ua_reference_cascade`): a direct port of
//    `Variable#reference!`'s reverse walk over a variable's assignments,
//    marking every assignment "referenced" unless it's proven to have
//    already been unconditionally overwritten by a later one (a `None`
//    branch, or a branch identical to the read's own). `ua_exclusive_with`
//    ports `Branch#exclusive_with?`; `in_modifier_conditional` ports the
//    `foo = 1 unless foo`-shaped special case verbatim.
//
// 4. LOOP-COMPLETION MARKING (`ua_mark_loop_completions`): a direct port of
//    `mark_assignments_as_referenced_in_loop`/`find_variables_in_loop` — a
//    purely SYNTACTIC (scope-unaware, exactly like upstream's
//    `each_descendant`) post-scan of a loop's (or a `retry`-containing
//    `begin/rescue`'s) full subtree once its normal traversal finishes,
//    marking assignments to any variable also READ somewhere in that same
//    subtree: unconditionally for the last such assignment, and for every
//    other one that also sits under an `if`/`unless`/`case`/`case/in`/
//    `begin-with-rescue` region (`in_branch_node`, upstream's
//    `each_ancestor(*BRANCH_NODES)` — deliberately NOT the same predicate as
//    `may_jump`/branch-push above: loops/`&&`/`||`/op-assigns/`ensure`
//    don't count here).
//
// 5. `variable_in_loop_condition?` (`UaAssignment.in_loop_condition`): a
//    narrower, ADDITIONAL suppression computed at record time from
//    `loop_stack` (innermost currently-open `while`/`until`/`for`), guarded
//    by `no_loop_condition_check` (any enclosing `def` — upstream's
//    `each_ancestor(:any_def).any?` — since `each_ancestor` is a raw,
//    scope-unaware walk that must not let an OUTER loop's condition
//    suppress a same-named but semantically distinct variable declared
//    inside a nested `def`).
//
// 6. IGNORE-CASCADE (`chained_assignment?`/`ignore_node`): `foo = bar = x`
//    is two independent `Variable`s (`foo`, `bar`) whose assignment nodes
//    NEST (bar's node is foo's `.value()`). Once `foo`'s assignment is
//    reported useless, upstream `ignore_node`s it, which transparently
//    suppresses any OTHER assignment (any variable) physically nested
//    inside it — otherwise `bar` would ALSO get an independent (and, after
//    autocorrecting away "foo = ", spatially conflicting) offense. Modeled
//    here as a per-scope list of "ignored" byte ranges accumulated in the
//    same order upstream processes variables (declaration order per scope,
//    each variable's assignments newest-first) — see `ua_finish_scope`.
//
// Not modeled / simplified (none exercised by the fixture — see the task's
// final report for the exhaustive list): `rest_assignment?`'s message-text
// fork for a masgn splat with NO sibling targets (`*a = 1, 2, 3` — always
// treated as the far-more-common `multiple_assignment?` message/autocorrect
// here); `chained_assignment?`/sequential-assignment detection is only
// evaluated for a plain (`LocalVariableWriteNode`) assignment's OWN value,
// never for a regexp named-capture's right-hand side; `collect_variable_like_names`
// (the "Did you mean" candidate pool) treats every nested scope as fully
// opaque rather than also harvesting its "twisted" (receiver/superclass/
// block-invocation) outer-scope-owned pieces.
// =====================================================================
use std::rc::Rc;

#[derive(Clone)]
struct UaBranchNode {
    parent: Option<Rc<UaBranchNode>>,
    control_id: usize,
    child_id: usize,
    may_jump: bool,
}
type UaBranch = Option<Rc<UaBranchNode>>;

fn ua_new_branch(parent: &UaBranch, control_id: usize, child_id: usize, may_jump: bool) -> UaBranch {
    Some(Rc::new(UaBranchNode { parent: parent.clone(), control_id, child_id, may_jump }))
}

fn ua_branches_eq(a: &UaBranch, b: &UaBranch) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.control_id == y.control_id && x.child_id == y.child_id,
        (None, None) => true,
        _ => false,
    }
}

/// `Branch#exclusive_with?`.
fn ua_exclusive_with(a: &Rc<UaBranchNode>, b: &UaBranch) -> bool {
    if a.may_jump {
        return false;
    }
    let Some(mut cur) = b.clone() else { return false };
    loop {
        if cur.control_id == a.control_id {
            return cur.child_id != a.child_id;
        }
        match cur.parent.clone() {
            Some(p) => cur = p,
            None => break,
        }
    }
    match &a.parent {
        Some(p) => ua_exclusive_with(p, b),
        None => false,
    }
}

/// `Assignment#run_exclusively_with?` / `Branchable#run_exclusively_with?`.
fn ua_run_exclusively_with(a: &UaBranch, b: &UaBranch) -> bool {
    match a {
        Some(ab) => ua_exclusive_with(ab, b),
        None => false,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum UaKind {
    Def,
    Block,
    Other,
}

struct UaFrame {
    kind: UaKind,
    names: HashMap<Vec<u8>, usize>,
    decl_order: Vec<usize>,
    /// `return_value_node_of_scope`'s range for THIS scope, precomputed at
    /// push time from its (about-to-be-visited) body.
    return_range: Option<(usize, usize)>,
}

/// `Assignment#meta_assignment_node`'s effective classification, narrowed to
/// what affects our message text and autocorrect strategy.
#[derive(Clone, Copy, PartialEq)]
enum UaMeta {
    /// Plain `x = value` (`assignment.node` IS the whole thing).
    Plain,
    /// A masgn target, or a masgn splat target with sibling targets
    /// (`multiple_assignment?`).
    MultipleAssign,
    /// A standalone masgn splat target with NO sibling targets
    /// (`rest_assignment?` — message falls back to `similar_name_message`,
    /// but autocorrect still renames to `_`).
    RestAssign,
    /// A `for x in ...` loop variable (`for_assignment?`).
    ForAssign,
    /// `x += value` / `x -= value` / etc (autocorrectable: `remove_trailing_character_from_operator`).
    OperatorAssign,
    /// `x ||= value` (message shows "Use `||`..."; never autocorrected).
    OrAssign,
    /// `x &&= value` (message shows "Use `&&`..."; never autocorrected).
    AndAssign,
    /// `/(?<name>...)/ =~ str` named capture.
    RegexpNamedCapture,
    /// `rescue Foo => name` / `rescue => name`.
    ExceptionVar,
}

struct UaAssignment {
    meta: UaMeta,
    node_start: usize,
    node_end: usize,
    /// Offense anchor: `assignment.node.loc.name` (or, for a regexp named
    /// capture, the regexp literal's own start).
    anchor: usize,
    branch: UaBranch,
    referenced: bool,
    reassigned: bool,
    in_branch_node: bool,
    no_loop_condition_check: bool,
    in_loop_condition: bool,
    /// Start offset of `.value()`, for the plain-assignment autocorrect
    /// (`node.loc.name.begin.join(node.expression.source_range.begin)`).
    value_start: Option<usize>,
    /// `chained_assignment?`'s two conditions, evaluated ONLY for `Plain`.
    value_is_send: bool,
    value_is_lvasgn: bool,
    /// For `OperatorAssign`: the bare operator text (`"+"`, `"-"`, ...,
    /// straight from prism's own `binary_operator`) — used for the message
    /// ("Use `+` instead of `+=`.").
    op_text: Vec<u8>,
    /// For `OperatorAssign`: end offset of `binary_operator_loc` (which
    /// spans the FULL combined token, e.g. `"+="`) — the
    /// `remove_trailing_character_from_operator` autocorrect drops just
    /// the trailing `=` (`[operator_end-1, operator_end)`).
    operator_end: usize,
    /// For `Or`/`AndAssign`: whether this assignment is the scope's own
    /// final statement (`operator_assignment_message`'s
    /// `return_value_node_of_scope` check) — only then does the message
    /// show "Use `||`/`&&` instead of...".
    is_scope_return_value: bool,
    /// `in_modifier_conditional?`: this assignment's own node is (modulo
    /// one layer of parenthesization) a direct child of a modifier-form
    /// `if`/`unless`/`while`/`until`.
    is_modifier_child: bool,
    /// `sequential_assignment?`: `x = 1, y = 2` (parsed as `x = [1, y = 2]`)
    /// — disables autocorrect for every assignment in the chain.
    sequential: bool,
}

struct UaVar {
    name: Vec<u8>,
    captured_by_block: bool,
    assignments: Vec<UaAssignment>,
    /// `method_argument?`: declared as a `def`/`defs` parameter — the only
    /// kind zero-arity `super` implicitly references.
    is_arg: bool,
}

/// `Variable#reference!`: walk `assignments` newest-first, marking each
/// referenced unless proven unconditionally overwritten by a later one,
/// exactly matching upstream's `consumed_branches`/`in_modifier_conditional?`
/// bookkeeping. `modifier: &[bool]` is parallel to `assignments`: whether
/// that assignment's own node sits directly under a modifier-form
/// `if`/`unless`/`while`/`until` (see `in_modifier_conditional?`).
fn ua_reference_cascade(assignments: &mut [UaAssignment], modifier: &[bool], ref_branch: &UaBranch) {
    let mut consumed: HashSet<(usize, usize)> = HashSet::new();
    for i in (0..assignments.len()).rev() {
        if let Some(b) = &assignments[i].branch {
            if consumed.contains(&(b.control_id, b.child_id)) {
                continue;
            }
        }
        if !ua_run_exclusively_with(&assignments[i].branch, ref_branch) {
            assignments[i].referenced = true;
        }
        if modifier[i] {
            continue;
        }
        let branch_none = assignments[i].branch.is_none();
        let branch_eq = ua_branches_eq(&assignments[i].branch, ref_branch);
        if branch_none || branch_eq {
            break;
        }
        // `may_run_incompletely?` == `may_jump` for our two users.
        let may_run_incompletely = assignments[i].branch.as_ref().is_some_and(|b| b.may_jump);
        if !may_run_incompletely {
            if let Some(b) = &assignments[i].branch {
                consumed.insert((b.control_id, b.child_id));
            }
        }
    }
}

struct UaOffense {
    anchor: usize,
    correctable: bool,
    message: String,
}

/// The scope-tracking, branch-tracking recursive-descent visitor described
/// in the module doc comment above.
struct UaCollector<'s> {
    src: &'s [u8],
    frames: Vec<UaFrame>,
    vars: Vec<UaVar>,
    current_branch: UaBranch,
    /// `each_ancestor(*BRANCH_NODES).any?` — raw, scope-unaware nesting
    /// count of `if`/`unless`/`case`/`case/in`/protected-`begin` regions.
    branch_node_depth: u32,
    /// Innermost currently-open `while`/`until` (its condition's referenced
    /// local-variable names) or `for` (`None`, meaning "has no usable
    /// condition, don't look further out either" — matches
    /// `each_ancestor.find` stopping at the nearest loop-type ancestor).
    loop_stack: Vec<Option<HashSet<Vec<u8>>>>,
    /// `in_modifier_conditional?`: set true just before visiting the ONE
    /// direct child (predicate, or sole body statement) of a modifier-form
    /// `if`/`unless`/`while`/`until`; consumed (read then cleared) by the
    /// very next assignment-recording visitor entered.
    modifier_ctx: bool,
    /// `sequential_assignment?`: true while traversing the VALUE subtree of
    /// a plain assignment whose own value is an array literal containing
    /// an assignment descendant (`x = 1, y = 2`) — every assignment
    /// recorded anywhere within (at any nesting depth, e.g. `x = 1, (y = 2,
    /// z = 3)`) inherits it, matching upstream's ancestor-climbing check.
    force_sequential: bool,
    offenses: Vec<UaOffense>,
    fixes: Vec<(usize, usize, Vec<u8>)>,
}

impl<'s> UaCollector<'s> {
    fn new(src: &'s [u8]) -> Self {
        UaCollector {
            src,
            frames: Vec::new(),
            vars: Vec::new(),
            current_branch: None,
            branch_node_depth: 0,
            loop_stack: Vec::new(),
            modifier_ctx: false,
            force_sequential: false,
            offenses: Vec::new(),
            fixes: Vec::new(),
        }
    }

    fn take_modifier_ctx(&mut self) -> bool {
        std::mem::take(&mut self.modifier_ctx)
    }

    /// Visits the ONE direct child of a modifier-form conditional
    /// (predicate, or sole body statement), propagating `modifier_ctx`
    /// through at most one layer of `(...)` parenthesization — matches
    /// `in_modifier_conditional?`'s `parent = parent.parent if
    /// parent&.begin_type?`.
    fn visit_modifier_child<'pr>(&mut self, node: &ruby_prism::Node<'pr>)
    where
        Self: ruby_prism::Visit<'pr>,
    {
        use ruby_prism::Visit;
        self.modifier_ctx = true;
        if let Some(p) = node.as_parentheses_node() {
            if let Some(body) = p.body() {
                if let Some(st) = body.as_statements_node() {
                    if let Some(first) = st.body().iter().next() {
                        self.visit(&first);
                        self.modifier_ctx = false;
                        return;
                    }
                }
                self.visit(&body);
                self.modifier_ctx = false;
                return;
            }
        }
        self.visit(node);
        self.modifier_ctx = false;
    }

    fn resolve(&self, name: &[u8], depth: u32) -> Option<usize> {
        let top = self.frames.len().checked_sub(1)?;
        let f = top.checked_sub(depth as usize)?;
        self.frames[f].names.get(name).copied()
    }

    /// `process_variable_declaration` / the `declare_variable unless
    /// variable_exist?` half of `process_variable_assignment`.
    fn ensure_declared(&mut self, name: &[u8], depth: u32) -> usize {
        if let Some(idx) = self.resolve(name, depth) {
            return idx;
        }
        let top = self.frames.len() - 1;
        let f = top.saturating_sub(depth as usize);
        let idx = self.vars.len();
        self.vars.push(UaVar { name: name.to_vec(), captured_by_block: false, assignments: Vec::new(), is_arg: false });
        self.frames[f].names.insert(name.to_vec(), idx);
        self.frames[f].decl_order.push(idx);
        idx
    }

    /// A parameter declaration (`def`/`defs` OR block/lambda) — always at
    /// depth 0 (a parameter belongs to its own scope). `is_arg`
    /// (`method_argument?`, the only kind zero-arity `super` implicitly
    /// references) is true only when the CURRENT (innermost) frame is a
    /// `def`'s own — a block's own parameters are `block_argument?`, not
    /// `method_argument?`.
    fn declare_arg(&mut self, name: &[u8]) {
        if self.resolve(name, 0).is_some() {
            return;
        }
        let top = self.frames.len() - 1;
        let is_arg = self.frames[top].kind == UaKind::Def;
        let idx = self.vars.len();
        self.vars.push(UaVar { name: name.to_vec(), captured_by_block: false, assignments: Vec::new(), is_arg });
        self.frames[top].names.insert(name.to_vec(), idx);
        self.frames[top].decl_order.push(idx);
    }

    /// `VariableTable#push_scope` + resetting the branch (branches never
    /// cross a scope boundary — see the module doc comment). Returns the
    /// saved outer branch, to be restored by the caller after finishing
    /// this scope (see `pop_scope_and_finish`).
    fn push_scope<'n>(&mut self, kind: UaKind, body: &Option<ruby_prism::Node<'n>>) -> UaBranch {
        self.frames.push(UaFrame {
            kind,
            names: HashMap::new(),
            decl_order: Vec::new(),
            return_range: ua_scope_return_range(body),
        });
        std::mem::take(&mut self.current_branch)
    }

    fn pop_scope_and_finish<'n>(&mut self, saved_branch: UaBranch, body: &Option<ruby_prism::Node<'n>>) {
        self.finish_scope(body);
        self.current_branch = saved_branch;
    }

    /// `process_pattern_match_variable`: declare (searching outward through
    /// block scopes like a real reference would, but never assign) — see
    /// the `visit_match_predicate_node`/`visit_match_required_node`/
    /// `visit_case_match_node` call sites.
    fn declare_pattern_var(&mut self, name: &[u8]) {
        if self.find_by_name(name).is_some() {
            return;
        }
        let idx = self.vars.len();
        self.vars.push(UaVar { name: name.to_vec(), captured_by_block: false, assignments: Vec::new(), is_arg: false });
        let top = self.frames.len() - 1;
        self.frames[top].names.insert(name.to_vec(), idx);
        self.frames[top].decl_order.push(idx);
    }

    /// `Assignment#meta_assignment_node`'s `multiple_assignment_node`/
    /// `rest_assignment_node`, recursively: a masgn target is either a
    /// splat (unwrap once, remembering `is_rest`), a nested `(a, b)`
    /// sub-mlhs (flatten into its own lefts/rest/rights — sibling count is
    /// recomputed fresh at THIS nesting level), a local-variable target
    /// (record the write), or anything else (index/attr/ivar targets —
    /// just visit normally so nested reads are still picked up).
    fn process_masgn_target_list<'pr>(&mut self, targets: &[ruby_prism::Node<'pr>])
    where
        Self: ruby_prism::Visit<'pr>,
    {
        let has_siblings = targets.len() > 1;
        for t in targets {
            self.process_masgn_target(t, false, has_siblings);
        }
    }

    fn process_masgn_target<'pr>(&mut self, t: &ruby_prism::Node<'pr>, is_rest: bool, has_siblings: bool)
    where
        Self: ruby_prism::Visit<'pr>,
    {
        use ruby_prism::Visit;
        if let Some(splat) = t.as_splat_node() {
            if let Some(expr) = splat.expression() {
                self.process_masgn_target(&expr, true, has_siblings);
            }
            return;
        }
        if let Some(mt) = t.as_multi_target_node() {
            let mut inner: Vec<ruby_prism::Node<'pr>> = mt.lefts().iter().collect();
            if let Some(r) = mt.rest() {
                inner.push(r);
            }
            inner.extend(mt.rights().iter());
            self.process_masgn_target_list(&inner);
            return;
        }
        if let Some(lvt) = t.as_local_variable_target_node() {
            let is_mod = self.take_modifier_ctx();
            let name = lvt.name();
            let name = name.as_slice();
            let depth = lvt.depth();
            let loc = lvt.location();
            let meta = if is_rest && !has_siblings { UaMeta::RestAssign } else { UaMeta::MultipleAssign };
            let mut a = self.base_assignment(meta, loc.start_offset(), loc.end_offset(), loc.start_offset(), name);
            a.is_modifier_child = is_mod;
            self.record_assignment(name, depth, a);
            return;
        }
        self.visit(t);
    }

    /// `for_assignment_node`: EVERY element of a `for` loop's index — plain,
    /// splat, or nested — is `for_assignment?` uniformly (never
    /// `multiple_assignment?`, since a `for`'s mlhs-wrapped index is never a
    /// masgn's grandparent).
    fn process_for_target<'pr>(&mut self, t: &ruby_prism::Node<'pr>)
    where
        Self: ruby_prism::Visit<'pr>,
    {
        use ruby_prism::Visit;
        if let Some(splat) = t.as_splat_node() {
            if let Some(expr) = splat.expression() {
                self.process_for_target(&expr);
            }
            return;
        }
        if let Some(mt) = t.as_multi_target_node() {
            let mut inner: Vec<ruby_prism::Node<'pr>> = mt.lefts().iter().collect();
            if let Some(r) = mt.rest() {
                inner.push(r);
            }
            inner.extend(mt.rights().iter());
            for it in &inner {
                self.process_for_target(it);
            }
            return;
        }
        if let Some(lvt) = t.as_local_variable_target_node() {
            let is_mod = self.take_modifier_ctx();
            let name = lvt.name();
            let name = name.as_slice();
            let depth = lvt.depth();
            let loc = lvt.location();
            let mut a = self.base_assignment(UaMeta::ForAssign, loc.start_offset(), loc.end_offset(), loc.start_offset(), name);
            a.is_modifier_child = is_mod;
            self.record_assignment(name, depth, a);
            return;
        }
        self.visit(t);
    }

    /// `exception_assignment?`'s target: `rescue Foo => name` / `rescue =>
    /// name`. `exceptions_first_end`/`keyword_end` are
    /// `remove_exception_assignment_part`'s `range` start candidates
    /// (the exception-type list's own end, else the `rescue` keyword's end).
    fn record_rescue_reference<'pr>(
        &mut self,
        reference: &ruby_prism::Node<'pr>,
        exceptions_first_end: Option<usize>,
        keyword_end: usize,
    ) where
        Self: ruby_prism::Visit<'pr>,
    {
        if let Some(lvt) = reference.as_local_variable_target_node() {
            let is_mod = self.take_modifier_ctx();
            let name = lvt.name();
            let name = name.as_slice();
            let depth = lvt.depth();
            let loc = lvt.location();
            let start = exceptions_first_end.unwrap_or(keyword_end);
            let mut a = self.base_assignment(UaMeta::ExceptionVar, loc.start_offset(), loc.end_offset(), loc.start_offset(), name);
            a.is_modifier_child = is_mod;
            a.value_start = Some(start);
            self.record_assignment(name, depth, a);
        } else {
            use ruby_prism::Visit;
            self.visit(reference);
        }
    }

    /// `VariableTable#mark_variable_as_captured_by_block_if_so`.
    fn mark_captured(&mut self, idx: usize, depth: u32) {
        if depth > 0 && self.frames.last().is_some_and(|f| f.kind == UaKind::Block) {
            self.vars[idx].captured_by_block = true;
        }
    }

    fn in_loop_condition_now(&self, name: &[u8]) -> bool {
        match self.loop_stack.last() {
            Some(Some(names)) => names.contains(name),
            _ => false,
        }
    }

    fn has_def_ancestor(&self) -> bool {
        self.frames.iter().any(|f| f.kind == UaKind::Def)
    }

    /// Record an assignment to `name` (already-resolved `depth`). Returns
    /// the assignment's index within its variable for later mutation
    /// (op/or/and-assign need to record the pre-value reference first, then
    /// come back and finish the assignment fields after visiting `.value()`).
    fn record_assignment(&mut self, name: &[u8], depth: u32, spec: UaAssignment) {
        let idx = self.ensure_declared(name, depth);
        self.mark_captured(idx, depth);
        let reassigned = {
            let last = self.vars[idx].assignments.last();
            match last {
                Some(prev) if !self.vars[idx].captured_by_block && ua_branches_eq(&prev.branch, &spec.branch) => true,
                _ => false,
            }
        };
        if reassigned {
            if let Some(prev) = self.vars[idx].assignments.last_mut() {
                if !prev.referenced {
                    prev.reassigned = true;
                }
            }
        }
        self.vars[idx].assignments.push(spec);
    }

    /// `VariableTable#reference_variable` + `Variable#reference!`.
    fn reference(&mut self, name: &[u8], depth: u32) {
        let Some(idx) = self.resolve(name, depth) else { return };
        self.mark_captured(idx, depth);
        let branch = self.current_branch.clone();
        let modifier: Vec<bool> = self.vars[idx].assignments.iter().map(|a| a.is_modifier_child).collect();
        ua_reference_cascade(&mut self.vars[idx].assignments, &modifier, &branch);
    }

    /// Zero-arity `super`: reference every `method_argument?` variable
    /// reachable by walking outward from the current scope through
    /// consecutive block frames (stopping at, and including, the first
    /// non-block frame) — see the `SaCollector::mark_zsuper` doc comment
    /// for why this exactly matches `VariableTable#accessible_variables`
    /// filtered to `method_argument?` for this cop's purposes.
    fn mark_zsuper(&mut self) {
        let branch = self.current_branch.clone();
        for i in (0..self.frames.len()).rev() {
            let kind = self.frames[i].kind;
            if kind == UaKind::Def {
                let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
                for idx in idxs {
                    if !self.vars[idx].is_arg {
                        continue;
                    }
                    let modifier: Vec<bool> = self.vars[idx].assignments.iter().map(|a| a.is_modifier_child).collect();
                    ua_reference_cascade(&mut self.vars[idx].assignments, &modifier, &branch);
                }
                break;
            } else if kind == UaKind::Block {
                continue;
            } else {
                break;
            }
        }
    }

    /// Bare `binding`: `VariableTable#accessible_variables` — reference the
    /// current scope's own vars, and keep going (and referencing) outward
    /// through block frames, stopping right after including the first
    /// non-block frame.
    fn mark_binding(&mut self) {
        let branch = self.current_branch.clone();
        let mut i = self.frames.len();
        while i > 0 {
            i -= 1;
            let is_block = self.frames[i].kind == UaKind::Block;
            let idxs: Vec<usize> = self.frames[i].names.values().copied().collect();
            for idx in idxs {
                let modifier: Vec<bool> = self.vars[idx].assignments.iter().map(|a| a.is_modifier_child).collect();
                ua_reference_cascade(&mut self.vars[idx].assignments, &modifier, &branch);
            }
            if !is_block {
                break;
            }
        }
    }
}

// --- UaAssignment / UaCollector: construction, scope-finish, messages ---

impl UaAssignment {
    fn new(meta: UaMeta, node_start: usize, node_end: usize, anchor: usize, branch: UaBranch) -> Self {
        UaAssignment {
            meta,
            node_start,
            node_end,
            anchor,
            branch,
            referenced: false,
            reassigned: false,
            in_branch_node: false,
            no_loop_condition_check: false,
            in_loop_condition: false,
            value_start: None,
            value_is_send: false,
            value_is_lvasgn: false,
            op_text: Vec::new(),
            operator_end: 0,
            is_scope_return_value: false,
            is_modifier_child: false,
            sequential: false,
        }
    }
}

impl<'s> UaCollector<'s> {
    /// Fills in the fields that come uniformly from collector state
    /// (branch, `in_branch_node`, the loop-condition/def-ancestor guard).
    /// `is_modifier_child` is NOT set here — callers must capture
    /// `take_modifier_ctx()` as the very first thing they do (before
    /// recursing into any child, e.g. an operator-assignment's `.value()`)
    /// and set it on the returned assignment afterwards.
    fn base_assignment(&self, meta: UaMeta, node_start: usize, node_end: usize, anchor: usize, name: &[u8]) -> UaAssignment {
        let mut a = UaAssignment::new(meta, node_start, node_end, anchor, self.current_branch.clone());
        a.in_branch_node = self.branch_node_depth > 0;
        a.no_loop_condition_check = self.has_def_ancestor();
        a.in_loop_condition = !a.no_loop_condition_check && self.in_loop_condition_now(name);
        a.sequential = self.force_sequential;
        a
    }

    /// `VariableTable#find_variable` (name-only, no explicit depth) — used
    /// only by the loop-completion pass, matching upstream's own
    /// name-resolved-via-VariableTable lookup for
    /// `mark_assignments_as_referenced_in_loop`.
    fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        let mut i = self.frames.len();
        while i > 0 {
            i -= 1;
            if let Some(&idx) = self.frames[i].names.get(name) {
                return Some(idx);
            }
            if self.frames[i].kind != UaKind::Block {
                return None;
            }
        }
        None
    }

    /// `mark_assignments_as_referenced_in_loop`.
    fn mark_loop_completions(&mut self, scan: &UaLoopScan) {
        for name in &scan.read_names {
            let Some(idx) = self.find_by_name(name) else { continue };
            let in_loop: Vec<usize> = self.vars[idx]
                .assignments
                .iter()
                .enumerate()
                .filter(|(_, a)| scan.assign_positions.contains(&a.node_start))
                .map(|(i, _)| i)
                .collect();
            if in_loop.is_empty() {
                continue;
            }
            for &ai in &in_loop {
                if self.vars[idx].assignments[ai].in_branch_node {
                    self.vars[idx].assignments[ai].referenced = true;
                }
            }
            if let Some(&last) = in_loop.last() {
                self.vars[idx].assignments[last].referenced = true;
            }
        }
    }

    /// `after_leaving_scope` → `check_for_unused_assignments` for every
    /// variable declared directly in this (just-finished) scope, in
    /// declaration order (needed for the ignore-cascade — see the module
    /// doc comment). `scope_body` is the scope's own body node, reused for
    /// the similar-name candidate scan.
    fn finish_scope<'n>(&mut self, scope_body: &Option<ruby_prism::Node<'n>>) {
        let frame = self.frames.pop().expect("frame stack underflow");
        if frame.decl_order.iter().all(|&i| self.vars[i].name.starts_with(b"_")) {
            return;
        }
        let send_names = ua_collect_variable_like_sends(scope_body);
        let mut ignored: Vec<(usize, usize)> = Vec::new();
        for &vidx in &frame.decl_order {
            if self.vars[vidx].name.starts_with(b"_") {
                continue;
            }
            let n = self.vars[vidx].assignments.len();
            for i in (0..n).rev() {
                let (used, skip_ignored, skip_loop_cond, node_start, node_end) = {
                    let a = &self.vars[vidx].assignments[i];
                    let captured = self.vars[vidx].captured_by_block;
                    let used = (!a.reassigned && captured) || a.referenced;
                    let skip_ignored = ignored.iter().any(|&(s, e)| a.node_start >= s && a.node_start < e);
                    (used, skip_ignored, a.in_loop_condition, a.node_start, a.node_end)
                };
                if used || skip_ignored || skip_loop_cond {
                    continue;
                }
                let (correctable, message, fix) = self.ua_offense_for(vidx, i, &frame, &send_names);
                let anchor = self.vars[vidx].assignments[i].anchor;
                self.offenses.push(UaOffense { anchor, correctable, message });
                if let Some(f) = fix {
                    self.fixes.push(f);
                }
                if self.vars[vidx].assignments[i].meta == UaMeta::Plain
                    && (self.vars[vidx].assignments[i].value_is_send || self.vars[vidx].assignments[i].value_is_lvasgn)
                {
                    ignored.push((node_start, node_end));
                }
            }
        }
    }

    /// `message_for_useless_assignment` + `autocorrect`. Returns
    /// (correctable, full message, optional fix).
    fn ua_offense_for(
        &self,
        vidx: usize,
        aidx: usize,
        frame: &UaFrame,
        send_names: &HashSet<Vec<u8>>,
    ) -> (bool, String, Option<(usize, usize, Vec<u8>)>) {
        let name = self.vars[vidx].name.clone();
        let name_str = String::from_utf8_lossy(&name).into_owned();
        let a_meta = self.vars[vidx].assignments[aidx].meta;
        let base = format!("Useless assignment to variable - `{name_str}`.");
        let suffix = match a_meta {
            UaMeta::MultipleAssign => {
                format!(" Use `_` or `_{name_str}` as a variable name to indicate that it won't be used.")
            }
            UaMeta::OperatorAssign | UaMeta::OrAssign | UaMeta::AndAssign => {
                let a = &self.vars[vidx].assignments[aidx];
                if a.is_scope_return_value {
                    let (short, full) = match a_meta {
                        UaMeta::OrAssign => ("||".to_string(), "||=".to_string()),
                        UaMeta::AndAssign => ("&&".to_string(), "&&=".to_string()),
                        _ => {
                            let op = String::from_utf8_lossy(&a.op_text).into_owned();
                            (op.clone(), format!("{op}="))
                        }
                    };
                    format!(" Use `{short}` instead of `{full}`.")
                } else {
                    String::new()
                }
            }
            _ => {
                let mut candidates: HashSet<Vec<u8>> = send_names.clone();
                for &vi in &frame.decl_order {
                    candidates.insert(self.vars[vi].name.clone());
                }
                ua_similar_name_suffix(&name, candidates)
            }
        };
        let message = format!("{base}{suffix}");

        let a = &self.vars[vidx].assignments[aidx];
        let uncorrectable = a.sequential || a_meta == UaMeta::OrAssign || a_meta == UaMeta::AndAssign;
        let correctable = !uncorrectable;
        let fix = if uncorrectable { None } else { self.ua_autocorrect_for(vidx, aidx) };
        (correctable, message, fix)
    }

    fn ua_autocorrect_for(&self, vidx: usize, aidx: usize) -> Option<(usize, usize, Vec<u8>)> {
        let a = &self.vars[vidx].assignments[aidx];
        match a.meta {
            UaMeta::MultipleAssign | UaMeta::RestAssign | UaMeta::ForAssign => {
                Some((a.node_start, a.node_end, b"_".to_vec()))
            }
            UaMeta::OperatorAssign => Some((a.operator_end - 1, a.operator_end, Vec::new())),
            UaMeta::OrAssign | UaMeta::AndAssign => None,
            UaMeta::ExceptionVar => {
                let start = a.value_start?;
                Some((start, a.node_end, Vec::new()))
            }
            UaMeta::RegexpNamedCapture => {
                // `replace_named_capture_group_with_non_capturing_group`:
                // `node.children.first.source.sub(/\(\?<#{name}>/, '(?:')`
                // — `node_start..node_end` is the regexp literal's own
                // range (see `visit_match_write_node`).
                let name = &self.vars[vidx].name;
                let regex_src = &self.src[a.node_start..a.node_end];
                let pattern = format!("(?<{}>", String::from_utf8_lossy(name));
                let pos = ua_find_bytes(regex_src, pattern.as_bytes())?;
                let abs_start = a.node_start + pos;
                let abs_end = abs_start + pattern.len();
                Some((abs_start, abs_end, b"(?:".to_vec()))
            }
            UaMeta::Plain => {
                let value_start = a.value_start?;
                Some((a.anchor, value_start, Vec::new()))
            }
        }
    }
}

fn ua_find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Result of the purely-syntactic (scope-unaware) descendant scan over a
/// loop's (or a `retry`-containing `begin/rescue`'s) full subtree —
/// `find_variables_in_loop`.
struct UaLoopScan {
    read_names: HashSet<Vec<u8>>,
    assign_positions: HashSet<usize>,
}

impl<'pr> ruby_prism::Visit<'pr> for UaLoopScan {
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        self.read_names.insert(node.name().as_slice().to_vec());
    }
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        self.assign_positions.insert(node.location().start_offset());
        ruby_prism::visit_local_variable_write_node(self, node);
    }
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        self.assign_positions.insert(node.location().start_offset());
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        self.read_names.insert(node.name().as_slice().to_vec());
        self.assign_positions.insert(node.location().start_offset());
        ruby_prism::visit_local_variable_operator_write_node(self, node);
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        self.read_names.insert(node.name().as_slice().to_vec());
        self.assign_positions.insert(node.location().start_offset());
        ruby_prism::visit_local_variable_or_write_node(self, node);
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        self.read_names.insert(node.name().as_slice().to_vec());
        self.assign_positions.insert(node.location().start_offset());
        ruby_prism::visit_local_variable_and_write_node(self, node);
    }
}

fn ua_scan_loop(node: &ruby_prism::Node) -> UaLoopScan {
    let mut s = UaLoopScan { read_names: HashSet::new(), assign_positions: HashSet::new() };
    use ruby_prism::Visit;
    s.visit(node);
    s
}

/// `sequential_assignment?`'s base case: does `node`'s subtree contain any
/// assignment-shaped node at all (purely syntactic, matching upstream's
/// naive `each_descendant.any?(&:assignment?)`)?
fn ua_contains_any_assignment(node: &ruby_prism::Node) -> bool {
    struct S {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for S {
        fn visit_local_variable_write_node(&mut self, _n: &ruby_prism::LocalVariableWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_local_variable_target_node(&mut self, _n: &ruby_prism::LocalVariableTargetNode<'pr>) {
            self.found = true;
        }
        fn visit_local_variable_operator_write_node(&mut self, _n: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_local_variable_or_write_node(&mut self, _n: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_local_variable_and_write_node(&mut self, _n: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_multi_write_node(&mut self, _n: &ruby_prism::MultiWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_instance_variable_write_node(&mut self, _n: &ruby_prism::InstanceVariableWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_global_variable_write_node(&mut self, _n: &ruby_prism::GlobalVariableWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_class_variable_write_node(&mut self, _n: &ruby_prism::ClassVariableWriteNode<'pr>) {
            self.found = true;
        }
        fn visit_constant_write_node(&mut self, _n: &ruby_prism::ConstantWriteNode<'pr>) {
            self.found = true;
        }
    }
    let mut s = S { found: false };
    use ruby_prism::Visit;
    s.visit(node);
    s.found
}

/// `collect_variable_like_names`'s method-invocation half:
/// receiverless, argument-less sends, scanned with every nested
/// `def`/`class`/`module`/`sclass`/`block`/`lambda` treated as fully
/// opaque (a simplification of upstream's `Scope#each_node`, which also
/// harvests a nested scope's own "twisted" outer-owned pieces — see the
/// module doc comment's residual-risk note).
struct UaSendNames {
    names: HashSet<Vec<u8>>,
}
impl<'pr> ruby_prism::Visit<'pr> for UaSendNames {
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        let has_args = node.arguments().is_some_and(|a| a.arguments().iter().next().is_some());
        if node.receiver().is_none() && !has_args {
            self.names.insert(node.name().as_slice().to_vec());
        }
        ruby_prism::visit_call_node(self, node);
    }
    fn visit_def_node(&mut self, _n: &ruby_prism::DefNode<'pr>) {}
    fn visit_class_node(&mut self, _n: &ruby_prism::ClassNode<'pr>) {}
    fn visit_module_node(&mut self, _n: &ruby_prism::ModuleNode<'pr>) {}
    fn visit_singleton_class_node(&mut self, _n: &ruby_prism::SingletonClassNode<'pr>) {}
    fn visit_block_node(&mut self, _n: &ruby_prism::BlockNode<'pr>) {}
    fn visit_lambda_node(&mut self, _n: &ruby_prism::LambdaNode<'pr>) {}
}

fn ua_collect_variable_like_sends(scope_body: &Option<ruby_prism::Node>) -> HashSet<Vec<u8>> {
    let mut s = UaSendNames { names: HashSet::new() };
    if let Some(b) = scope_body {
        use ruby_prism::Visit;
        s.visit(b);
    }
    s.names
}

/// `process_pattern_match_variable`: pattern-match capture names (`in`/`=>`
/// destructuring, and `case/in`) are declared but NEVER get an `Assignment`
/// record at all — so this collector only needs their NAMES (to declare
/// them, making later reads resolve) and never touches `record_assignment`.
struct UaPatternVars {
    names: Vec<Vec<u8>>,
}
impl<'pr> ruby_prism::Visit<'pr> for UaPatternVars {
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        self.names.push(node.name().as_slice().to_vec());
    }
}
fn ua_collect_pattern_vars(node: &ruby_prism::Node) -> Vec<Vec<u8>> {
    let mut s = UaPatternVars { names: Vec::new() };
    use ruby_prism::Visit;
    s.visit(node);
    s.names
}

/// `return_value_node_of_scope`: the scope's own final directly-executed
/// statement's byte range (or the whole body's range, for a non-`begin`
/// single-expression body) — used only to decide whether an operator
/// assignment's message gets the "Use `||`/`&&`/... instead" suffix.
fn ua_scope_return_range(body: &Option<ruby_prism::Node>) -> Option<(usize, usize)> {
    let body = body.as_ref()?;
    if let Some(st) = body.as_statements_node() {
        let last = st.body().iter().last()?;
        let l = last.location();
        Some((l.start_offset(), l.end_offset()))
    } else {
        let l = body.location();
        Some((l.start_offset(), l.end_offset()))
    }
}

// --- DidYouMean::SpellChecker port (Jaro/Jaro-Winkler/Levenshtein) ---

fn ua_normalize(s: &[u8]) -> Vec<char> {
    String::from_utf8_lossy(s).chars().filter(|&c| c != '@').flat_map(|c| c.to_lowercase()).collect()
}
fn ua_chars(s: &[u8]) -> Vec<char> {
    String::from_utf8_lossy(s).chars().collect()
}

fn ua_jaro(a: &[char], b: &[char]) -> f64 {
    let (s1, s2) = if a.len() > b.len() { (b, a) } else { (a, b) };
    let len1 = s1.len();
    let len2 = s2.len();
    if len1 == 0 {
        return if len2 == 0 { 0.0 } else { 0.0 };
    }
    let range = if len2 > 3 { len2 / 2 - 1 } else { 0 };
    let mut flags1 = vec![false; len1];
    let mut flags2 = vec![false; len2];
    let mut m: i64 = 0;
    for i in 0..len1 {
        let last = i + range;
        let start = if i >= range { i - range } else { 0 };
        let mut j = start;
        while j <= last && j < len2 {
            if !flags2[j] && s1[i] == s2[j] {
                flags2[j] = true;
                flags1[i] = true;
                m += 1;
                break;
            }
            j += 1;
        }
    }
    if m == 0 {
        return 0.0;
    }
    let mut k = 0usize;
    let mut t: i64 = 0;
    for i in 0..len1 {
        if !flags1[i] {
            continue;
        }
        let mut index = k;
        let mut j = k;
        while j < len2 {
            index = j;
            if flags2[j] {
                j += 1;
                break;
            }
            j += 1;
        }
        k = j;
        if s1[i] != s2[index] {
            t += 1;
        }
    }
    let t = (t as f64 / 2.0).floor();
    let mf = m as f64;
    let l1 = len1 as f64;
    let l2 = len2 as f64;
    (mf / l1 + mf / l2 + (mf - t) / mf) / 3.0
}

fn ua_jaro_winkler(word: &[char], input: &[char]) -> f64 {
    let jaro = ua_jaro(word, input);
    if jaro > 0.7 {
        let mut prefix = 0usize;
        for (i, &c1) in word.iter().enumerate() {
            if i >= 4 {
                break;
            }
            if input.get(i) == Some(&c1) {
                prefix += 1;
            } else {
                break;
            }
        }
        jaro + (prefix as f64) * 0.1 * (1.0 - jaro)
    } else {
        jaro
    }
}

fn ua_levenshtein(a: &[char], b: &[char]) -> i64 {
    let n = a.len();
    let m = b.len();
    if n == 0 {
        return m as i64;
    }
    if m == 0 {
        return n as i64;
    }
    let mut d: Vec<i64> = (0..=m as i64).collect();
    for i in 1..=n {
        let mut prev_diag = d[0];
        d[0] = i as i64;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let tmp = d[j];
            d[j] = (d[j] + 1).min(d[j - 1] + 1).min(prev_diag + cost);
            prev_diag = tmp;
        }
    }
    d[m]
}

/// `DidYouMean::SpellChecker#correct`.
fn ua_spellcheck_correct(input: &[u8], dictionary: &HashSet<Vec<u8>>) -> Option<Vec<u8>> {
    let norm_input = ua_normalize(input);
    let threshold = if norm_input.len() > 3 { 0.834 } else { 0.77 };
    let mut words: Vec<Vec<u8>> = dictionary
        .iter()
        .filter(|w| w.as_slice() != input)
        .filter(|w| ua_jaro_winkler(&ua_normalize(w), &norm_input) >= threshold)
        .cloned()
        .collect();
    words.sort_by(|a, b| {
        let da = ua_jaro_winkler(&ua_chars(a), &norm_input);
        let db = ua_jaro_winkler(&ua_chars(b), &norm_input);
        da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
    });
    words.reverse();
    let lev_threshold = (norm_input.len() as f64 * 0.25).ceil() as i64;
    let mut corrections: Vec<Vec<u8>> =
        words.iter().filter(|w| ua_levenshtein(&ua_normalize(w), &norm_input) <= lev_threshold).cloned().collect();
    if corrections.is_empty() {
        corrections = words
            .iter()
            .filter(|w| {
                let wn = ua_normalize(w);
                let len = norm_input.len().min(wn.len());
                ua_levenshtein(&wn, &norm_input) < len as i64
            })
            .take(1)
            .cloned()
            .collect();
    }
    corrections.into_iter().next()
}

fn ua_similar_name_suffix(target: &[u8], mut candidates: HashSet<Vec<u8>>) -> String {
    candidates.remove(target);
    match ua_spellcheck_correct(target, &candidates) {
        Some(name) => format!(" Did you mean `{}`?", String::from_utf8_lossy(&name)),
        None => String::new(),
    }
}

fn ua_scan_names(node: &ruby_prism::Node) -> HashSet<Vec<u8>> {
    struct S {
        names: HashSet<Vec<u8>>,
    }
    impl<'pr> ruby_prism::Visit<'pr> for S {
        fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
            self.names.insert(node.name().as_slice().to_vec());
        }
    }
    let mut s = S { names: HashSet::new() };
    use ruby_prism::Visit;
    s.visit(node);
    s.names
}

fn ua_contains_retry(first_rescue: &ruby_prism::RescueNode) -> bool {
    struct S {
        found: bool,
    }
    impl<'pr> ruby_prism::Visit<'pr> for S {
        fn visit_retry_node(&mut self, _n: &ruby_prism::RetryNode<'pr>) {
            self.found = true;
        }
    }
    let mut s = S { found: false };
    use ruby_prism::Visit;
    s.visit(&first_rescue.as_node());
    s.found
}

/// `find_variables_in_loop` scoped to a `begin/rescue`'s protected region
/// (main body + every chained rescue clause + `else`) — deliberately
/// EXCLUDING `ensure` (upstream's `:rescue` node never includes it either).
fn ua_scan_loop_begin_no_ensure(node: &ruby_prism::BeginNode) -> UaLoopScan {
    let mut s = UaLoopScan { read_names: HashSet::new(), assign_positions: HashSet::new() };
    use ruby_prism::Visit;
    if let Some(st) = node.statements() {
        s.visit(&st.as_node());
    }
    let mut rc = node.rescue_clause();
    while let Some(r) = rc {
        for exc in r.exceptions().iter() {
            s.visit(&exc);
        }
        if let Some(reference) = r.reference() {
            s.visit(&reference);
        }
        if let Some(st) = r.statements() {
            s.visit(&st.as_node());
        }
        rc = r.subsequent();
    }
    if let Some(e) = node.else_clause() {
        if let Some(st) = e.statements() {
            s.visit(&st.as_node());
        }
    }
    s
}

// --- The traversal itself ---

impl<'pr, 's> ruby_prism::Visit<'pr> for UaCollector<'s> {
    // -- Scopes --

    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if let Some(recv) = node.receiver() {
            self.visit(&recv);
        }
        let body = node.body();
        let saved = self.push_scope(UaKind::Def, &body);
        if let Some(params) = node.parameters() {
            self.visit_parameters_node(&params);
        }
        if let Some(b) = &body {
            self.visit(b);
        }
        self.pop_scope_and_finish(saved, &body);
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.visit(&node.constant_path());
        if let Some(sup) = node.superclass() {
            self.visit(&sup);
        }
        let body = node.body();
        let saved = self.push_scope(UaKind::Other, &body);
        if let Some(b) = &body {
            self.visit(b);
        }
        self.pop_scope_and_finish(saved, &body);
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.visit(&node.constant_path());
        let body = node.body();
        let saved = self.push_scope(UaKind::Other, &body);
        if let Some(b) = &body {
            self.visit(b);
        }
        self.pop_scope_and_finish(saved, &body);
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        self.visit(&node.expression());
        let body = node.body();
        let saved = self.push_scope(UaKind::Other, &body);
        if let Some(b) = &body {
            self.visit(b);
        }
        self.pop_scope_and_finish(saved, &body);
    }
    fn visit_block_node(&mut self, node: &ruby_prism::BlockNode<'pr>) {
        let body = node.body();
        let saved = self.push_scope(UaKind::Block, &body);
        if let Some(params) = node.parameters() {
            self.visit(&params);
        }
        if let Some(b) = &body {
            self.visit(b);
        }
        self.pop_scope_and_finish(saved, &body);
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        let body = node.body();
        let saved = self.push_scope(UaKind::Block, &body);
        if let Some(params) = node.parameters() {
            self.visit(&params);
        }
        if let Some(b) = &body {
            self.visit(b);
        }
        self.pop_scope_and_finish(saved, &body);
    }

    // -- Parameter declarations (declare-only, never assigned) --

    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice());
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice());
        self.visit(&node.value());
    }
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        if let Some(name) = node.name() {
            self.declare_arg(name.as_slice());
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice());
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        self.declare_arg(node.name().as_slice());
        self.visit(&node.value());
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        if let Some(name) = node.name() {
            self.declare_arg(name.as_slice());
        }
    }
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        if let Some(name) = node.name() {
            self.declare_arg(name.as_slice());
        }
    }
    fn visit_block_local_variable_node(&mut self, node: &ruby_prism::BlockLocalVariableNode<'pr>) {
        self.ensure_declared(node.name().as_slice(), 0);
    }

    // -- Plain / multiple / rest / for / operator / regexp assignments --

    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        let is_mod = self.take_modifier_ctx();
        let inherited_sequential = self.force_sequential;
        let name = node.name();
        let name = name.as_slice();
        let depth = node.depth();
        self.ensure_declared(name, depth);
        let value = node.value();
        let is_sequential_array = value.as_array_node().is_some_and(|arr| ua_contains_any_assignment(&arr.as_node()));
        if is_sequential_array {
            self.force_sequential = true;
        }
        self.visit(&value);
        self.force_sequential = inherited_sequential;
        let loc = node.location();
        let value_loc = value.location();
        let mut a = self.base_assignment(UaMeta::Plain, loc.start_offset(), loc.end_offset(), node.name_loc().start_offset(), name);
        a.is_modifier_child = is_mod;
        a.value_start = Some(value_loc.start_offset());
        a.value_is_send = value.as_call_node().is_some();
        a.value_is_lvasgn = value.as_local_variable_write_node().is_some();
        a.sequential = inherited_sequential || is_sequential_array;
        self.record_assignment(name, depth, a);
    }

    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        let is_mod = self.take_modifier_ctx();
        let name = node.name();
        let name = name.as_slice();
        let depth = node.depth();
        self.ensure_declared(name, depth);
        self.reference(name, depth);
        let op_loc = node.binary_operator_loc();
        let control_id = node.location().start_offset();
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, false);
        self.visit(&node.value());
        self.current_branch = saved;
        let loc = node.location();
        let mut a = self.base_assignment(UaMeta::OperatorAssign, loc.start_offset(), loc.end_offset(), loc.start_offset(), name);
        a.is_modifier_child = is_mod;
        a.op_text = node.binary_operator().as_slice().to_vec();
        a.operator_end = op_loc.end_offset();
        a.is_scope_return_value = self.frames.last().and_then(|f| f.return_range) == Some((loc.start_offset(), loc.end_offset()));
        self.record_assignment(name, depth, a);
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        let is_mod = self.take_modifier_ctx();
        let name = node.name();
        let name = name.as_slice();
        let depth = node.depth();
        self.ensure_declared(name, depth);
        self.reference(name, depth);
        let control_id = node.location().start_offset();
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, false);
        self.visit(&node.value());
        self.current_branch = saved;
        let loc = node.location();
        let mut a = self.base_assignment(UaMeta::OrAssign, loc.start_offset(), loc.end_offset(), loc.start_offset(), name);
        a.is_modifier_child = is_mod;
        a.is_scope_return_value = self.frames.last().and_then(|f| f.return_range) == Some((loc.start_offset(), loc.end_offset()));
        self.record_assignment(name, depth, a);
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        let is_mod = self.take_modifier_ctx();
        let name = node.name();
        let name = name.as_slice();
        let depth = node.depth();
        self.ensure_declared(name, depth);
        self.reference(name, depth);
        let control_id = node.location().start_offset();
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, false);
        self.visit(&node.value());
        self.current_branch = saved;
        let loc = node.location();
        let mut a = self.base_assignment(UaMeta::AndAssign, loc.start_offset(), loc.end_offset(), loc.start_offset(), name);
        a.is_modifier_child = is_mod;
        a.is_scope_return_value = self.frames.last().and_then(|f| f.return_range) == Some((loc.start_offset(), loc.end_offset()));
        self.record_assignment(name, depth, a);
    }

    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        self.take_modifier_ctx();
        let name = node.name();
        self.reference(name.as_slice(), node.depth());
    }

    fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
        self.take_modifier_ctx();
        self.visit(&node.value());
        let mut targets: Vec<ruby_prism::Node> = node.lefts().iter().collect();
        if let Some(r) = node.rest() {
            targets.push(r);
        }
        targets.extend(node.rights().iter());
        self.process_masgn_target_list(&targets);
    }

    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        self.take_modifier_ctx();
        self.visit(&node.collection());
        let idx = node.index();
        self.process_for_target(&idx);
        let control_id = node.location().start_offset();
        self.loop_stack.push(None);
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, false);
        if let Some(st) = node.statements() {
            self.visit(&st.as_node());
        }
        self.current_branch = saved;
        self.loop_stack.pop();
        let scan = ua_scan_loop(&node.as_node());
        self.mark_loop_completions(&scan);
    }

    fn visit_match_write_node(&mut self, node: &ruby_prism::MatchWriteNode<'pr>) {
        let is_mod = self.take_modifier_ctx();
        let call = node.call();
        let regex_opt = call.receiver();
        let targets: Vec<ruby_prism::LocalVariableTargetNode> =
            node.targets().iter().filter_map(|t| t.as_local_variable_target_node()).collect();
        for t in &targets {
            self.ensure_declared(t.name().as_slice(), t.depth());
        }
        if let Some(args) = call.arguments() {
            for a in args.arguments().iter() {
                self.visit(&a);
            }
        }
        if let Some(regex) = &regex_opt {
            self.visit(regex);
        }
        let regex_range = regex_opt.as_ref().map(|r| r.location()).unwrap_or_else(|| node.location());
        let anchor = regex_range.start_offset();
        for t in &targets {
            let name = t.name();
            let name = name.as_slice();
            let mut a = self.base_assignment(
                UaMeta::RegexpNamedCapture,
                regex_range.start_offset(),
                regex_range.end_offset(),
                anchor,
                name,
            );
            a.is_modifier_child = is_mod;
            self.record_assignment(name, t.depth(), a);
        }
    }

    // -- Pattern matching (`in`/`=>`): declare-only captures --

    fn visit_match_predicate_node(&mut self, node: &ruby_prism::MatchPredicateNode<'pr>) {
        self.take_modifier_ctx();
        self.visit(&node.value());
        for name in ua_collect_pattern_vars(&node.pattern()) {
            self.declare_pattern_var(&name);
        }
    }
    fn visit_match_required_node(&mut self, node: &ruby_prism::MatchRequiredNode<'pr>) {
        self.take_modifier_ctx();
        self.visit(&node.value());
        for name in ua_collect_pattern_vars(&node.pattern()) {
            self.declare_pattern_var(&name);
        }
    }

    // -- Conditionals / branches --

    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        self.branch_node_depth += 1;
        let is_modifier = node.if_keyword_loc().is_some() && node.end_keyword_loc().is_none();
        if is_modifier {
            self.visit_modifier_child(&node.predicate());
        } else {
            self.visit(&node.predicate());
        }
        let control_id = node.location().start_offset();
        if let Some(st) = node.statements() {
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 1, false);
            if is_modifier {
                if let Some(first) = st.body().iter().next() {
                    self.visit_modifier_child(&first);
                }
            } else {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
        }
        if let Some(sub) = node.subsequent() {
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 2, false);
            self.visit(&sub);
            self.current_branch = saved;
        }
        self.branch_node_depth -= 1;
    }
    fn visit_unless_node(&mut self, node: &ruby_prism::UnlessNode<'pr>) {
        self.branch_node_depth += 1;
        let is_modifier = node.end_keyword_loc().is_none();
        if is_modifier {
            self.visit_modifier_child(&node.predicate());
        } else {
            self.visit(&node.predicate());
        }
        let control_id = node.location().start_offset();
        if let Some(st) = node.statements() {
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 1, false);
            if is_modifier {
                if let Some(first) = st.body().iter().next() {
                    self.visit_modifier_child(&first);
                }
            } else {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
        }
        if let Some(e) = node.else_clause() {
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 2, false);
            if let Some(st) = e.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
        }
        self.branch_node_depth -= 1;
    }
    fn visit_case_node(&mut self, node: &ruby_prism::CaseNode<'pr>) {
        self.branch_node_depth += 1;
        if let Some(p) = node.predicate() {
            self.visit(&p);
        }
        let control_id = node.location().start_offset();
        for cond in node.conditions().iter() {
            if let Some(w) = cond.as_when_node() {
                let child_id = w.location().start_offset();
                let saved = self.current_branch.clone();
                self.current_branch = ua_new_branch(&saved, control_id, child_id, false);
                for c in w.conditions().iter() {
                    self.visit(&c);
                }
                if let Some(st) = w.statements() {
                    self.visit(&st.as_node());
                }
                self.current_branch = saved;
            }
        }
        if let Some(e) = node.else_clause() {
            let child_id = e.location().start_offset();
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, child_id, false);
            if let Some(st) = e.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
        }
        self.branch_node_depth -= 1;
    }
    fn visit_case_match_node(&mut self, node: &ruby_prism::CaseMatchNode<'pr>) {
        self.branch_node_depth += 1;
        if let Some(p) = node.predicate() {
            self.visit(&p);
        }
        let control_id = node.location().start_offset();
        for cond in node.conditions().iter() {
            if let Some(inn) = cond.as_in_node() {
                let child_id = inn.location().start_offset();
                let saved = self.current_branch.clone();
                self.current_branch = ua_new_branch(&saved, control_id, child_id, false);
                for name in ua_collect_pattern_vars(&inn.pattern()) {
                    self.declare_pattern_var(&name);
                }
                if let Some(st) = inn.statements() {
                    self.visit(&st.as_node());
                }
                self.current_branch = saved;
            }
        }
        if let Some(e) = node.else_clause() {
            let child_id = e.location().start_offset();
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, child_id, false);
            if let Some(st) = e.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
        }
        self.branch_node_depth -= 1;
    }

    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        let predicate = node.predicate();
        let cond_names = ua_scan_names(&predicate);
        let control_id = node.location().start_offset();
        // `modifier_form?` (`loc.end.nil?`) — but a post-condition loop
        // (`begin...end while cond`) is a DIFFERENT whitequark type
        // (`:while_post`, not in `BASIC_CONDITIONALS`), so it never counts
        // as a modifier conditional for `in_modifier_conditional?` even
        // though it ALSO lacks its own closing keyword.
        let is_modifier = !node.is_begin_modifier() && node.closing_loc().is_none();
        if node.is_begin_modifier() {
            self.loop_stack.push(Some(cond_names));
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 1, false);
            if let Some(st) = node.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
            self.loop_stack.pop();
            self.visit(&predicate);
        } else {
            if is_modifier {
                self.visit_modifier_child(&predicate);
            } else {
                self.visit(&predicate);
            }
            self.loop_stack.push(Some(cond_names));
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 1, false);
            if let Some(st) = node.statements() {
                if is_modifier {
                    if let Some(first) = st.body().iter().next() {
                        self.visit_modifier_child(&first);
                    }
                } else {
                    self.visit(&st.as_node());
                }
            }
            self.current_branch = saved;
            self.loop_stack.pop();
        }
        let scan = ua_scan_loop(&node.as_node());
        self.mark_loop_completions(&scan);
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        let predicate = node.predicate();
        let cond_names = ua_scan_names(&predicate);
        let control_id = node.location().start_offset();
        let is_modifier = !node.is_begin_modifier() && node.closing_loc().is_none();
        if node.is_begin_modifier() {
            self.loop_stack.push(Some(cond_names));
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 1, false);
            if let Some(st) = node.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved;
            self.loop_stack.pop();
            self.visit(&predicate);
        } else {
            if is_modifier {
                self.visit_modifier_child(&predicate);
            } else {
                self.visit(&predicate);
            }
            self.loop_stack.push(Some(cond_names));
            let saved = self.current_branch.clone();
            self.current_branch = ua_new_branch(&saved, control_id, 1, false);
            if let Some(st) = node.statements() {
                if is_modifier {
                    if let Some(first) = st.body().iter().next() {
                        self.visit_modifier_child(&first);
                    }
                } else {
                    self.visit(&st.as_node());
                }
            }
            self.current_branch = saved;
            self.loop_stack.pop();
        }
        let scan = ua_scan_loop(&node.as_node());
        self.mark_loop_completions(&scan);
    }

    fn visit_and_node(&mut self, node: &ruby_prism::AndNode<'pr>) {
        self.take_modifier_ctx();
        self.visit(&node.left());
        let control_id = node.location().start_offset();
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, false);
        self.visit(&node.right());
        self.current_branch = saved;
    }
    fn visit_or_node(&mut self, node: &ruby_prism::OrNode<'pr>) {
        self.take_modifier_ctx();
        self.visit(&node.left());
        let control_id = node.location().start_offset();
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, false);
        self.visit(&node.right());
        self.current_branch = saved;
    }

    fn visit_rescue_modifier_node(&mut self, node: &ruby_prism::RescueModifierNode<'pr>) {
        self.take_modifier_ctx();
        self.branch_node_depth += 1;
        let control_id = node.location().start_offset();
        let saved = self.current_branch.clone();
        self.current_branch = ua_new_branch(&saved, control_id, 1, true);
        self.visit(&node.expression());
        self.current_branch = ua_new_branch(&saved, control_id, 2, false);
        self.visit(&node.rescue_expression());
        self.current_branch = saved;
        self.branch_node_depth -= 1;
    }

    fn visit_begin_node(&mut self, node: &ruby_prism::BeginNode<'pr>) {
        self.take_modifier_ctx();
        let control_id = node.location().start_offset();
        let has_rescue = node.rescue_clause().is_some();
        let has_ensure = node.ensure_clause().is_some();
        let may_jump = has_rescue || has_ensure;
        if has_rescue {
            self.branch_node_depth += 1;
        }
        let saved = self.current_branch.clone();
        if may_jump {
            self.current_branch = ua_new_branch(&saved, control_id, 1, true);
        }
        if let Some(st) = node.statements() {
            self.visit(&st.as_node());
        }
        self.current_branch = saved.clone();

        let mut rc = node.rescue_clause();
        while let Some(r) = rc {
            let child_id = r.location().start_offset();
            self.current_branch = ua_new_branch(&saved, control_id, child_id, false);
            for exc in r.exceptions().iter() {
                self.visit(&exc);
            }
            if let Some(reference) = r.reference() {
                let exceptions_first_end = r.exceptions().iter().next().map(|e| e.location().end_offset());
                let keyword_end = r.keyword_loc().end_offset();
                self.record_rescue_reference(&reference, exceptions_first_end, keyword_end);
            }
            if let Some(st) = r.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved.clone();
            rc = r.subsequent();
        }
        if let Some(e) = node.else_clause() {
            let child_id = e.location().start_offset();
            self.current_branch = ua_new_branch(&saved, control_id, child_id, false);
            if let Some(st) = e.statements() {
                self.visit(&st.as_node());
            }
            self.current_branch = saved.clone();
        }
        if has_rescue {
            self.branch_node_depth -= 1;
        }

        if let Some(first_rescue) = node.rescue_clause() {
            if ua_contains_retry(&first_rescue) {
                let scan = ua_scan_loop_begin_no_ensure(node);
                self.mark_loop_completions(&scan);
            }
        }

        if let Some(en) = node.ensure_clause() {
            if let Some(st) = en.statements() {
                self.visit(&st.as_node());
            }
        }
    }

    // -- Implicit references --

    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        self.take_modifier_ctx();
        self.mark_zsuper();
        if let Some(block) = node.block() {
            self.visit_block_node(&block);
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if node.name().as_slice() == b"binding" {
            let empty_args = node.arguments().map(|a| a.arguments().iter().next().is_none()).unwrap_or(true);
            if empty_args {
                self.mark_binding();
            }
        }
        ruby_prism::visit_call_node(self, node);
    }
}

impl<'a> Cops<'a> {
    pub(crate) fn check_useless_assignment(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Lint/UselessAssignment";
        if !self.on(COP) {
            return;
        }
        let mut c = UaCollector::new(self.src);
        let body = Some(node.statements().as_node());
        let saved = c.push_scope(UaKind::Other, &body);
        use ruby_prism::Visit;
        c.visit(&node.statements().as_node());
        c.pop_scope_and_finish(saved, &body);
        for off in c.offenses {
            self.push(off.anchor, COP, off.correctable, off.message);
        }
        for f in c.fixes {
            self.fixes.push(f);
        }
    }
}
