//! Lint department. (Named `lint_cops` because `lint` is taken by the crate's
//! public entry point.)
use super::Cops;
use crate::nodepattern::{self, Pat};
use std::collections::HashSet;
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
