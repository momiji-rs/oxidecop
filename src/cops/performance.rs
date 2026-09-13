//! Performance department — ports of rubocop-performance v1.27.0.
//! Cops are off unless `plugins: rubocop-performance` (or `require:`) is set,
//! matching RuboCop; `--only Performance/X` still force-enables for the oracle.
use super::Cops;
use regex::Regex;
use std::sync::OnceLock;

impl<'a> Cops<'a> {
    fn value_used(&self, node: &ruby_prism::CallNode) -> bool {
        self.value_used_offsets.contains(&node.location().start_offset())
    }
    fn block_tail(&self, node: &ruby_prism::CallNode) -> bool {
        self.block_tail_offsets.contains(&node.location().start_offset())
    }
    fn receiver_is_ewo_accum(&self, recv: &ruby_prism::Node) -> bool {
        let Some(want) = self.ewo_accum.last().and_then(|n| n.as_ref()) else {
            return false;
        };
        let mut owned: Option<ruby_prism::Node> = None;
        loop {
            let n = owned.as_ref().unwrap_or(recv);
            match n.as_call_node().and_then(|c| c.receiver()) {
                Some(r) => owned = Some(r),
                None => break,
            }
        }
        owned.as_ref().unwrap_or(recv).as_local_variable_read_node().is_some_and(|l| l.name().as_slice() == want)
    }

    /// Performance/ReverseEach — `recv.reverse.each` → `recv.reverse_each`,
    /// unless the result is used (assignment, outer send, return/break/next).
    pub(crate) fn check_reverse_each(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/ReverseEach";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"each" {
            return;
        }
        // Prism wraps `each()` in an empty ArgumentsNode; count children so
        // empty parens match the upstream no-argument `(call _ :each)`.
        if arg_count(node) != 0 {
            return;
        }
        // `use_return_value?` walks ancestors for assignment/send/return.
        // `perf_send_depth` includes this call, so > 1 means an outer send
        // (including the owner of an enclosing block).
        if self.perf_send_depth > 1 {
            return;
        }
        if self.value_used(node) {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let Some(rev) = recv.as_call_node() else { return };
        if rev.name().as_slice() != b"reverse" {
            return;
        }
        if arg_count(&rev) != 0 || rev.block().is_some() {
            return;
        }
        let Some(rev_sel) = rev.message_loc() else { return };
        let Some(each_sel) = node.message_loc() else { return };
        let start = rev_sel.start_offset();
        let end = each_sel.end_offset();
        self.push(start, COP, true, "Use `reverse_each` instead of `reverse.each`.");
        self.fixes.push((start, end, b"reverse_each".to_vec()));
    }

    /// Performance/Size — `array_or_hash.count` (no args, no block) → `size`.
    pub(crate) fn check_size(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/Size";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"count" {
            return;
        }
        if arg_count(node) != 0 || node.block().is_some() {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if !size_array_receiver(&recv) && !size_hash_receiver(&recv) {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        self.push(sel.start_offset(), COP, true, "Use `size` instead of `count`.");
        self.fixes.push((sel.start_offset(), sel.end_offset(), b"size".to_vec()));
    }

    /// Performance/RangeInclude — `(a..b).include?` / `member?` → `cover?`.
    pub(crate) fn check_range_include(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/RangeInclude";
        if !self.on(COP) {
            return;
        }
        let name = node.name();
        if name.as_slice() != b"include?" && name.as_slice() != b"member?" {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        if !is_range_like(&recv) {
            return;
        }
        let Some(sel) = node.message_loc() else { return };
        let bad = std::str::from_utf8(name.as_slice()).unwrap_or("include?");
        self.push(
            sel.start_offset(),
            COP,
            true,
            format!("Use `Range#cover?` instead of `Range#{bad}`."),
        );
        self.fixes.push((sel.start_offset(), sel.end_offset(), b"cover?".to_vec()));
    }

    /// Performance/FlatMap — `map/collect { }.flatten(1)` → `flat_map`.
    pub(crate) fn check_flat_map(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/FlatMap";
        if !self.on(COP) {
            return;
        }
        let flatten_name = node.name();
        if flatten_name.as_slice() != b"flatten" && flatten_name.as_slice() != b"flatten!" {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let Some(map_call) = recv.as_call_node() else { return };
        let map_name = map_call.name();
        if map_name.as_slice() != b"map" && map_name.as_slice() != b"collect" {
            return;
        }
        if !map_collect_shape(&map_call) {
            return;
        }
        let flatten_level = flatten_arg_int(node, self.src);
        let warn_bare = self.cfg.get(COP, "EnabledForFlattenWithoutParams") == Some("true");
        // `flatten_arg_int` is None both for a bare `flatten` and for a
        // non-literal depth (`flatten(depth)`). The bare-flatten warning
        // only applies when no argument is supplied.
        let has_flatten_arg = positional_args(node) != 0;
        let (ok, extra) = match flatten_level {
            Some(1) => (true, false),
            None if warn_bare && !has_flatten_arg => (true, true),
            _ => (false, false),
        };
        if !ok {
            return;
        }
        let Some(map_sel) = map_call.message_loc() else { return };
        let end = node.location().end_offset();
        // Exclude a trailing chained call on flatten (`.flatten(1).size`): the
        // CallNode location for flatten does not include `.size`.
        let method = std::str::from_utf8(map_name.as_slice()).unwrap_or("map");
        let flatten = std::str::from_utf8(flatten_name.as_slice()).unwrap_or("flatten");
        let mut msg = format!("Use `flat_map` instead of `{method}...{flatten}`.");
        if extra {
            msg.push_str(
                " Beware, `flat_map` only flattens 1 level and `flatten` can be used to flatten multiple levels.",
            );
        }
        self.push(map_sel.start_offset(), COP, flatten_level == Some(1), msg);
        if flatten_level == Some(1) {
            // Drop `.flatten(1)` and rename map/collect. The flatten call's
            // location includes its own args; map_call location includes its
            // block. Join from end of map_call through end of flatten.
            let drop_from = map_call.location().end_offset();
            self.fixes.push((map_sel.start_offset(), map_sel.end_offset(), b"flat_map".to_vec()));
            self.fixes.push((drop_from, end, Vec::new()));
        }
        let _ = extra;
    }

    /// Performance/Detect — `select/find_all/filter.first/last/[0]/[-1]` → detect.
    pub(crate) fn check_detect(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/Detect";
        if !self.on(COP) {
            return;
        }
        let second = node.name();
        let is_index = second.as_slice() == b"[]";
        if second.as_slice() != b"first" && second.as_slice() != b"last" && !is_index {
            return;
        }
        // Upstream matcher is `(send ...)`, not `(call ...)`. Rewriting
        // `select { ... }&.first` would drop `&.`.
        if node.is_safe_navigation() {
            return;
        }
        if !is_index {
            if node.arguments().is_some_and(|a| a.arguments().iter().count() > 0) {
                return;
            }
        }
        let index = if is_index { index_arg(node, self.src) } else { None };
        if is_index && index != Some(0) && index != Some(-1) {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let Some(sel_call) = recv.as_call_node() else { return };
        let first_method = sel_call.name();
        if !matches!(first_method.as_slice(), b"select" | b"find_all" | b"filter") {
            return;
        }
        if !select_shape(&sel_call) {
            return;
        }
        if lazy_receiver(&sel_call) {
            return;
        }
        let prefer = self.preferred_detect();
        let first = std::str::from_utf8(first_method.as_slice()).unwrap_or("select");
        let reverse = second.as_slice() == b"last" || index == Some(-1);
        let msg = if is_index {
            let i = index.unwrap_or(0);
            if reverse {
                format!("Use `reverse.{prefer}` instead of `{first}[{i}]`.")
            } else {
                format!("Use `{prefer}` instead of `{first}[{i}]`.")
            }
        } else if reverse {
            let sm = std::str::from_utf8(second.as_slice()).unwrap_or("last");
            format!("Use `reverse.{prefer}` instead of `{first}.{sm}`.")
        } else {
            let sm = std::str::from_utf8(second.as_slice()).unwrap_or("first");
            format!("Use `{prefer}` instead of `{first}.{sm}`.")
        };
        let Some(sel_loc) = sel_call.message_loc() else { return };
        let Some(second_sel) = node.message_loc() else { return };
        self.push(sel_loc.start_offset(), COP, true, msg);
        let replacement = if reverse {
            format!("reverse.{prefer}")
        } else {
            prefer
        };
        self.fixes.push((sel_loc.start_offset(), sel_loc.end_offset(), replacement.into_bytes()));
        // Drop `.first` / `.last` / `[0]` including the operator.
        self.fixes.push((sel_call.location().end_offset(), second_sel.end_offset(), Vec::new()));
        // For `[]` the closing `]` is past the selector; node.location covers it.
        if is_index {
            // replace the previous drop with one that includes `]`.
            self.fixes.pop();
            self.fixes.push((sel_call.location().end_offset(), node.location().end_offset(), Vec::new()));
        }
    }

    fn preferred_detect(&self) -> String {
        // Style/CollectionMethods PreferredMethods['detect'] defaults to
        // `find` in RuboCop's default.yml. Nested hashes never reach SCHEMA,
        // so an absent key uses that default; a flat `detect:` override (the
        // oracle's replacement config) still wins.
        match self.cfg.get("Style/CollectionMethods", "detect") {
            Some(s) if !s.is_empty() && s != "nil" => s.to_string(),
            _ => "find".to_string(),
        }
    }

    /// Performance/StringReplacement — single-char `gsub`/`gsub!` → `tr`/`delete`.
    pub(crate) fn check_string_replacement(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/StringReplacement";
        if !self.on(COP) {
            return;
        }
        let bang = match node.name().as_slice() {
            b"gsub" => false,
            b"gsub!" => true,
            _ => return,
        };
        if node.block().is_some() {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let mut it = args.arguments().iter();
        let Some(first) = it.next() else { return };
        let Some(second) = it.next() else { return };
        if it.next().is_some() {
            return;
        }
        let Some(second_s) = string_unescaped(&second) else { return };
        if second_s.chars().count() > 1 {
            return;
        }
        let Some((first_src, from_regex)) = first_pattern_source(&first, self.src) else { return };
        if from_regex.1 {
            return; // regexp options
        }
        let raw = first_src;
        if from_regex.0 && !deterministic_regex(&raw) {
            return;
        }
        let interpreted = if from_regex.0 {
            interpret_escapes(&raw)
        } else {
            raw.clone().into_bytes()
        };
        if interpreted_len(&interpreted) != 1 {
            return;
        }
        let delete = second_s.is_empty();
        let method = if delete { "delete" } else { "tr" };
        let current = if bang { if delete { "gsub!" } else { "gsub!" } } else { "gsub" };
        let prefer = format!("{method}{}", if bang { "!" } else { "" });
        let Some(sel) = node.message_loc() else { return };
        let end = node.location().end_offset();
        self.push(
            sel.start_offset(),
            COP,
            true,
            format!("Use `{prefer}` instead of `{current}`."),
        );
        self.fixes.push((sel.start_offset(), sel.end_offset(), prefer.into_bytes()));
        if from_regex.0 {
            let lit = to_string_literal_bytes(&interpreted);
            self.fixes.push((first.location().start_offset(), first.location().end_offset(), lit.into_bytes()));
        }
        if delete {
            // Drop the second argument. Keep `)` if the call was parenthesized.
            let first_end = first.location().end_offset();
            let close = node.closing_loc().map(|l| l.as_slice().to_vec()).unwrap_or_default();
            self.fixes.push((first_end, end, close));
        }
        let _ = current;
    }

    /// Performance/RedundantMerge — `h.merge!(k: v)` → `h[k] = v`.
    pub(crate) fn check_redundant_merge(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Performance/RedundantMerge";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"merge!" {
            return;
        }
        // Upstream matcher is `(send ...)`. `hash&.merge!(a: 1)` must keep `&.`.
        if node.is_safe_navigation() {
            return;
        }
        if node.block().is_some() {
            return;
        }
        let Some(recv) = node.receiver() else { return };
        let Some(args) = node.arguments() else { return };
        let mut ait = args.arguments().iter();
        let Some(hash_arg) = ait.next() else { return };
        if ait.next().is_some() {
            return;
        }
        let Some(pairs) = hash_pairs(&hash_arg) else { return };
        if pairs.is_empty() {
            return;
        }
        if pairs.iter().any(|p| p.splat) {
            return;
        }
        let max = self.cfg.get(COP, "MaxKeyValuePairs").and_then(|s| {
            if s == "nil" {
                Some(2)
            } else {
                s.parse().ok()
            }
        }).unwrap_or(2);
        if pairs.len() > max {
            return;
        }
        if pairs.len() > 1 && !receiver_pure(&recv) {
            return;
        }
        if self.value_used(node) {
            return;
        }
        // Block tails are value-used except `each_with_object` when the
        // receiver unwinds to that block's accumulator.
        if self.block_tail(node) && !self.receiver_is_ewo_accum(&recv) {
            return;
        }
        let recv_src = String::from_utf8_lossy(self.node_src(&recv)).into_owned();
        let assigns: Vec<String> = pairs
            .iter()
            .map(|p| {
                let key = format_hash_key(self, &p.key, p.colon);
                let val = String::from_utf8_lossy(self.node_src(&p.value));
                format!("{recv_src}[{key}] = {val}")
            })
            .collect();
        let prefer = assigns.join("; ");
        let current = String::from_utf8_lossy(self.node_src(&node.as_node()));
        let msg = format!("Use `{prefer}` instead of `{current}`.");
        let postfix = self.hs_modifier_depth > 0 && pairs.len() > 1;
        self.push(node.location().start_offset(), COP, !postfix, msg);
        if postfix {
            return;
        }
        let joined = if pairs.len() == 1 {
            assigns[0].clone()
        } else {
            let pad = leading_spaces(self.src, node.location().start_offset());
            assigns.join(&format!("\n{pad}"))
        };
        self.fixes.push((node.location().start_offset(), node.location().end_offset(), joined.into_bytes()));
    }
}

struct HashPair<'pr> {
    key: ruby_prism::Node<'pr>,
    value: ruby_prism::Node<'pr>,
    colon: bool,
    splat: bool,
}

fn hash_pairs<'pr>(node: &ruby_prism::Node<'pr>) -> Option<Vec<HashPair<'pr>>> {
    let elements = if let Some(h) = node.as_hash_node() {
        h.elements()
    } else if let Some(h) = node.as_keyword_hash_node() {
        h.elements()
    } else {
        return None;
    };
    if elements.iter().any(|n| n.as_assoc_splat_node().is_some()) {
        return None;
    }
    Some(collect_assocs(elements))
}

fn collect_assocs<'pr>(elements: ruby_prism::NodeList<'pr>) -> Vec<HashPair<'pr>> {
    elements
        .iter()
        .filter_map(|n| {
            if n.as_assoc_splat_node().is_some() {
                return None;
            }
            let a = n.as_assoc_node()?;
            let colon = a.operator_loc().is_none_or(|l| l.as_slice() != b"=>");
            Some(HashPair { key: a.key(), value: a.value(), colon, splat: false })
        })
        .collect()
}

fn format_hash_key(cops: &Cops, key: &ruby_prism::Node, colon: bool) -> String {
    if key.as_symbol_node().is_some() && colon {
        let src = cops.node_src(key);
        let t = std::str::from_utf8(src).unwrap_or("").trim_end_matches(':');
        if t.starts_with(':') {
            t.to_string()
        } else {
            format!(":{t}")
        }
    } else {
        String::from_utf8_lossy(cops.node_src(key)).into_owned()
    }
}

fn receiver_pure(recv: &ruby_prism::Node) -> bool {
    if recv.as_local_variable_read_node().is_some()
        || recv.as_instance_variable_read_node().is_some()
        || recv.as_class_variable_read_node().is_some()
        || recv.as_global_variable_read_node().is_some()
        || recv.as_constant_read_node().is_some()
        || recv.as_self_node().is_some()
        || recv.as_nil_node().is_some()
        || recv.as_true_node().is_some()
        || recv.as_false_node().is_some()
        || recv.as_integer_node().is_some()
        || recv.as_float_node().is_some()
        || recv.as_string_node().is_some()
        || recv.as_symbol_node().is_some()
    {
        return true;
    }
    if let Some(h) = recv.as_hash_node() {
        return h.elements().iter().all(|e| assoc_pure(&e));
    }
    if let Some(a) = recv.as_array_node() {
        return a.elements().iter().all(|e| receiver_pure(&e));
    }
    if let Some(r) = recv.as_range_node() {
        let left = r.left().is_none_or(|n| receiver_pure(&n));
        let right = r.right().is_none_or(|n| receiver_pure(&n));
        return left && right;
    }
    if let Some(p) = recv.as_parentheses_node() {
        let Some(body) = p.body() else { return false };
        if let Some(stmts) = body.as_statements_node() {
            let mut it = stmts.body().iter();
            let Some(first) = it.next() else { return false };
            return it.next().is_none() && receiver_pure(&first);
        }
        return receiver_pure(&body);
    }
    false
}

fn assoc_pure(n: &ruby_prism::Node) -> bool {
    if let Some(a) = n.as_assoc_node() {
        return receiver_pure(&a.key()) && receiver_pure(&a.value());
    }
    false
}

fn leading_spaces(src: &[u8], off: usize) -> String {
    let line_start = src[..off].iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
    src[line_start..off].iter().take_while(|&&b| b == b' ' || b == b'\t').map(|&b| b as char).collect()
}

fn size_array_receiver(n: &ruby_prism::Node) -> bool {
    if n.as_array_node().is_some() {
        return true;
    }
    let Some(c) = n.as_call_node() else { return false };
    if c.name().as_slice() == b"to_a" {
        // `(call _ :to_a)` accepts `to_a()`; Prism stores empty parens as a wrapper.
        return arg_count(&c) == 0 && c.block().is_none();
    }
    if c.name().as_slice() == b"[]" {
        // `(send (const nil? :Array) :[] _)` — exactly one argument.
        return const_named(c.receiver().as_ref(), b"Array") && arg_count(&c) == 1;
    }
    c.receiver().is_none() && c.name().as_slice() == b"Array" && arg_count(&c) == 1
}

fn size_hash_receiver(n: &ruby_prism::Node) -> bool {
    if n.as_hash_node().is_some() {
        return true;
    }
    let Some(c) = n.as_call_node() else { return false };
    if c.name().as_slice() == b"to_h" {
        return arg_count(&c) == 0 && c.block().is_none();
    }
    if c.name().as_slice() == b"[]" {
        return const_named(c.receiver().as_ref(), b"Hash") && arg_count(&c) == 1;
    }
    c.receiver().is_none() && c.name().as_slice() == b"Hash" && arg_count(&c) == 1
}

fn const_named(recv: Option<&ruby_prism::Node>, name: &[u8]) -> bool {
    recv.and_then(|r| r.as_constant_read_node())
        .is_some_and(|c| c.name().as_slice() == name)
}

fn is_range_like(n: &ruby_prism::Node) -> bool {
    if n.as_range_node().is_some() {
        return true;
    }
    if let Some(pn) = n.as_parentheses_node() {
        let Some(body) = pn.body() else { return false };
        let Some(stmts) = body.as_statements_node() else {
            return body.as_range_node().is_some();
        };
        let mut it = stmts.body().iter();
        let Some(first) = it.next() else { return false };
        return it.next().is_none() && first.as_range_node().is_some();
    }
    false
}

fn flatten_arg_int(node: &ruby_prism::CallNode, src: &[u8]) -> Option<i32> {
    let args = node.arguments()?;
    let mut it = args.arguments().iter();
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    int_value(&first, src)
}

fn index_arg(node: &ruby_prism::CallNode, src: &[u8]) -> Option<i32> {
    let args = node.arguments()?;
    let mut it = args.arguments().iter();
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    int_value(&first, src)
}

fn int_value(n: &ruby_prism::Node, src: &[u8]) -> Option<i32> {
    if let Some(i) = n.as_integer_node() {
        let l = i.location();
        let t = std::str::from_utf8(&src[l.start_offset()..l.end_offset()]).ok()?;
        return t.parse().ok();
    }
    if let Some(c) = n.as_call_node() {
        if c.name().as_slice() == b"-@" {
            let r = c.receiver()?;
            let v = int_value(&r, src)?;
            return Some(-v);
        }
    }
    None
}

fn arg_count(c: &ruby_prism::CallNode) -> usize {
    c.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0)
}

fn positional_args(c: &ruby_prism::CallNode) -> usize {
    c.arguments()
        .map(|a| a.arguments().iter().filter(|n| n.as_block_argument_node().is_none()).count())
        .unwrap_or(0)
}

fn map_collect_shape(c: &ruby_prism::CallNode) -> bool {
    if positional_args(c) != 0 {
        return false;
    }
    c.block().is_some()
        || c.arguments()
            .is_some_and(|a| a.arguments().iter().any(|n| n.as_block_argument_node().is_some()))
}

fn select_shape(c: &ruby_prism::CallNode) -> bool {
    map_collect_shape(c)
}

fn lazy_receiver(sel: &ruby_prism::CallNode) -> bool {
    sel.receiver()
        .and_then(|r| r.as_call_node())
        .is_some_and(|c| c.name().as_slice() == b"lazy" && c.receiver().is_some())
}

fn string_unescaped(n: &ruby_prism::Node) -> Option<String> {
    let s = n.as_string_node()?;
    Some(String::from_utf8_lossy(&s.unescaped()).into_owned())
}

/// (source, (is_regex, has_options))
fn first_pattern_source(n: &ruby_prism::Node, src: &[u8]) -> Option<(String, (bool, bool))> {
    if let Some(s) = n.as_string_node() {
        return Some((String::from_utf8_lossy(&s.unescaped()).into_owned(), (false, false)));
    }
    if let Some(re) = n.as_regular_expression_node() {
        let content = String::from_utf8_lossy(&re.unescaped()).into_owned();
        let opts = re.closing_loc().as_slice().len() > 1; // `/a/i` closing is `/i`
        return Some((content, (true, opts)));
    }
    if n.as_interpolated_regular_expression_node().is_some() {
        return None;
    }
    let c = n.as_call_node()?;
    if c.name().as_slice() != b"new" && c.name().as_slice() != b"compile" {
        return None;
    }
    let recv_ok = c
        .receiver()
        .and_then(|r| r.as_constant_read_node())
        .is_some_and(|k| k.name().as_slice() == b"Regexp");
    if !recv_ok {
        let _ = src;
        return None;
    }
    let args = c.arguments()?;
    let mut it = args.arguments().iter();
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    // Recurse for the pattern text/options, but the constructor itself is a
    // regexp source so autocorrect can replace `Regexp.new('a')` with `'a'`.
    let (src_text, (_inner_regex, has_options)) = first_pattern_source(&first, src)?;
    Some((src_text, (true, has_options)))
}

fn deterministic_regex(src: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"\A(?:[\w\s\-,"'!#%&<>=;:`~/]|\\[^AbBdDgGhHkpPRwWXsSzZ0-9])+\z"#).unwrap()
    });
    re.is_match(src)
}

fn push_char(out: &mut Vec<u8>, c: char) {
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// Interpret Ruby string/regexp escapes as bytes so `\xNN` above 0x7F stays
/// a single 8-bit value instead of a UTF-8 Unicode scalar.
fn interpret_escapes(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            push_char(&mut out, c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('r') => out.push(b'\r'),
            Some('f') => out.push(0x0c),
            Some('v') => out.push(0x0b),
            Some('b') => out.push(0x08),
            Some('a') => out.push(0x07),
            Some('e') => out.push(0x1b),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                // Ruby accepts one or two hex digits after `\x`.
                let mut hex = String::new();
                if chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                    hex.push(chars.next().unwrap());
                    if chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                        hex.push(chars.next().unwrap());
                    }
                }
                if let Ok(v) = u8::from_str_radix(&hex, 16) {
                    out.push(v);
                    continue;
                }
                out.push(b'x');
            }
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                if let Ok(v) = u32::from_str_radix(&hex, 16) {
                    if let Some(ch) = char::from_u32(v) {
                        push_char(&mut out, ch);
                        continue;
                    }
                }
            }
            Some(other) => push_char(&mut out, other),
            None => out.push(b'\\'),
        }
    }
    out
}

fn interpreted_len(bytes: &[u8]) -> usize {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.chars().count(),
        Err(_) => bytes.len(),
    }
}

fn to_string_literal_bytes(s: &[u8]) -> String {
    match std::str::from_utf8(s) {
        Ok(text) => to_string_literal(text),
        Err(_) => ruby_inspect_bytes(s),
    }
}

fn to_string_literal(s: &str) -> String {
    if s.contains('\'') || s.chars().any(|c| c.is_control() || c == '\\') {
        ruby_inspect(s)
    } else {
        format!("'{s}'")
    }
}

/// Ruby `String#inspect` spellings for the escapes StringReplacement emits.
fn ruby_inspect(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\u{1b}' => out.push_str("\\e"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\x{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Inspect a non-UTF-8 byte string the way Ruby does for ASCII-8BIT:
/// high bytes stay `\\xNN` rather than becoming Unicode scalars.
fn ruby_inspect_bytes(s: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in s {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            0x07 => out.push_str("\\a"),
            0x08 => out.push_str("\\b"),
            0x0b => out.push_str("\\v"),
            0x0c => out.push_str("\\f"),
            0x1b => out.push_str("\\e"),
            b if b < 0x20 || b >= 0x7f => out.push_str(&format!("\\x{b:02X}")),
            b => out.push(b as char),
        }
    }
    out.push('"');
    out
}
