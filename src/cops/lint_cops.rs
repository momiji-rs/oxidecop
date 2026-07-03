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
fn is_recursive_basic_literal(node: &ruby_prism::Node) -> bool {
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
            if params.rest().is_some_and(|r| r.as_forwarding_parameter_node().is_none()) {
                return;
            }
            // Check for optional arguments
            if !params.optionals().is_empty() {
                return;
            }
            // Check for keyword rest arguments
            if params.keyword_rest().is_some() {
                return;
            }
            // Check for keyword arguments (any keywords mean there are defaults or **kwargs)
            if !params.keywords().is_empty() {
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
