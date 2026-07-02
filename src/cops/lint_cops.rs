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
