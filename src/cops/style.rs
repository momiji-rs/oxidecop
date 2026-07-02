//! Style department: imperative cop logic too stateful for the DECLARATIVE
//! table (constructed suggestions, block-shape analysis, text-level checks).
use super::Cops;

impl<'a> Cops<'a> {
    /// Style/StringLiterals — dispatch on the active EnforcedStyle, resolved
    /// once from the config SCHEMA (see `Config::enforced_style`). Heredocs /
    /// %-literals have other openings and fall through untouched.
    pub(crate) fn check_string_literals(&mut self, node: &ruby_prism::StringNode) {
        if !self.on("Style/StringLiterals") {
            return;
        }
        let Some(open) = node.opening_loc() else { return };
        let c = node.content_loc().as_slice();
        let l = node.location();
        match self.cfg.enforced_style("Style/StringLiterals") {
            // Prefer single quotes: a double-quoted string with no `'` and
            // no `\` in its content could be single-quoted losslessly.
            "single_quotes" if open.as_slice() == b"\"" => {
                if !c.contains(&b'\'') && !c.contains(&b'\\') {
                    self.push(l.start_offset(), "Style/StringLiterals", true,
                        "Prefer single-quoted strings when you don't need string interpolation or special symbols.");
                    // fix: `"c"` -> `'c'`
                    let mut rep = vec![b'\''];
                    rep.extend_from_slice(c);
                    rep.push(b'\'');
                    self.fixes.push((l.start_offset(), l.end_offset(), rep));
                }
            }
            // Prefer double quotes: a single-quoted string is an offense
            // UNLESS it needs the single quotes — i.e. it contains a `\`
            // that is NOT part of `\\` or `\'` (those are the only escapes
            // single quotes interpret; a bare `\x` is a literal backslash
            // that double quotes would have to escape as `\\x`).
            "double_quotes" if open.as_slice() == b"'" => {
                let mut needs_single = false;
                let mut i = 0;
                while i < c.len() {
                    if c[i] == b'\\' {
                        match c.get(i + 1) {
                            Some(b'\\') | Some(b'\'') => { i += 2; continue; }
                            _ => { needs_single = true; break; }
                        }
                    }
                    i += 1;
                }
                if !needs_single {
                    self.push(l.start_offset(), "Style/StringLiterals", true,
                        "Prefer double-quoted strings unless you need single quotes to avoid extra backslashes for escaping.");
                    // fix: `'c'` -> `"c"`, unescaping `\'` -> `'` (`\\` stays)
                    let mut inner = Vec::new();
                    let mut i = 0;
                    while i < c.len() {
                        if c[i] == b'\\' && c.get(i + 1) == Some(&b'\'') {
                            inner.push(b'\'');
                            i += 2;
                        } else {
                            inner.push(c[i]);
                            i += 1;
                        }
                    }
                    let mut rep = vec![b'"'];
                    rep.extend_from_slice(&inner);
                    rep.push(b'"');
                    self.fixes.push((l.start_offset(), l.end_offset(), rep));
                }
            }
            _ => {}
        }
    }

    /// Style/NumericLiterals — decimal literals over MinDigits want `_` grouping.
    pub(crate) fn check_numeric_literals(&mut self, node: &ruby_prism::IntegerNode) {
        if !self.on("Style/NumericLiterals") {
            return;
        }
        let s = self.node_src(&node.as_node());
        // decimal only, no existing underscore, > configured digit count
        let digits = s.iter().filter(|c| c.is_ascii_digit()).count();
        let min = self.cfg.int("Style/NumericLiterals", "MinDigits");
        if !s.contains(&b'_') && !s.starts_with(b"0x") && !s.starts_with(b"0b") && !s.starts_with(b"0o") && digits >= min {
            self.push(node.location().start_offset(), "Style/NumericLiterals", true,
                "Use underscores(_) as thousands separator and separate every 3 digits with them.".to_string());
            // fix: group digits in threes from the right (`1000000` -> `1_000_000`)
            let ds: Vec<u8> = s.to_vec();
            let mut grouped = Vec::new();
            for (i, c) in ds.iter().enumerate() {
                if i > 0 && (ds.len() - i) % 3 == 0 {
                    grouped.push(b'_');
                }
                grouped.push(*c);
            }
            let l = node.location();
            self.fixes.push((l.start_offset(), l.end_offset(), grouped));
        }
    }

    /// Style/Documentation — a class/module wants a comment on the line above.
    pub(crate) fn check_documentation(&mut self, start_off: usize, kind: &str, name: &ruby_prism::Node) {
        if !self.on("Style/Documentation") {
            return;
        }
        let (line, _) = self.idx.loc(start_off);
        if !self.comment_lines.contains(&(line.wrapping_sub(1))) {
            let nm = String::from_utf8_lossy(self.node_src(name)).to_string();
            self.push(start_off, "Style/Documentation", false,
                format!("Missing top-level documentation comment for `{kind} {nm}`."));
        }
    }

    /// Style/FrozenStringLiteralComment — text-based, runs once per file.
    pub(crate) fn check_frozen_string_literal(&mut self, has_frozen: bool) {
        if self.on("Style/FrozenStringLiteralComment") && !has_frozen {
            self.push(0, "Style/FrozenStringLiteralComment", true, "Missing frozen string literal comment.");
            self.fixes.push((0, 0, b"# frozen_string_literal: true\n\n".to_vec()));
        }
    }

    /// Style/RedundantReturn — the def body's last statement is a bare `return x`.
    pub(crate) fn check_redundant_return(&mut self, node: &ruby_prism::DefNode) {
        if !self.on("Style/RedundantReturn") {
            return;
        }
        if let Some(stmts) = node.body().and_then(|b| b.as_statements_node()) {
            if let Some(last) = stmts.body().iter().last() {
                if let Some(ret) = last.as_return_node() {
                    self.push(ret.location().start_offset(), "Style/RedundantReturn", true,
                        "Redundant `return` detected.");
                }
            }
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
