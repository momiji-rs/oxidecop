//! Metrics department: `Metrics/CyclomaticComplexity`, `Metrics/PerceivedComplexity`
//! and `Metrics/AbcSize` — three cops sharing rubocop's `MethodComplexity` mixin
//! (`on_def`/`on_defs`/`on_block` dispatch, `Max`/`AllowedMethods`/`AllowedPatterns`
//! config, message format) plus small utility mixins it pulls in:
//!  - `RepeatedCsendDiscount`: repeated `&.` sends on the same untouched local
//!    variable count once (reset when the variable is reassigned).
//!  - `IteratingBlock`: a block/block-pass attached to a "known iterating"
//!    method (`each`, `map`, `each_with_object`, ...) counts; other blocks
//!    don't.
//!  - `Utils::AbcSizeCalculator` (+`RepeatedAttributeDiscount`): assignment/
//!    branch/condition vectors, `Math.sqrt(a**2+b**2+c**2).round(2)`.
//!
//! Both `CyclomaticComplexity`/`PerceivedComplexity` compute their score with
//! a single filtered walk (rubocop's `body.each_node(:lvasgn, *COUNTED_NODES)`)
//! — `ComplexityCounter` below. `AbcSize` needs branch/condition/assignment
//! counts for EVERY node (rubocop's `visit_depth_last`, a plain post-order
//! walk) — `AbcCounter` below scores AFTER recursing into children to match
//! that order.
//!
//! Known gaps (none exercised by the spec fixture): `RepeatedAttributeDiscount`'s
//! invalidation on reassignment (`update_repeated_attribute`) is not
//! replicated — our attribute trie only grows, it never forgets an attribute
//! after `self.foo = x`. This only matters under `CountRepeatedAttributes:
//! false`. Also not replicated: `AbcSizeCalculator`'s attribute-repetition
//! discount for the *target* of a compound assignment (`obj.attr ||= x`
//! under `CountRepeatedAttributes: false` doesn't discount the implicit
//! `obj.attr` read) — a narrower version of the same gap.
//!
//! Fixed traps worth flagging for the next person poking at this file:
//!  - rubocop's `:rescue` node is ONE node per `begin`/`rescue` construct no
//!    matter how many `rescue` clauses it has (each clause is a `:resbody`
//!    child, which ISN'T in `COUNTED_NODES`) — prism instead chains one
//!    `RescueNode` per clause via `.subsequent()`, so scoring every node the
//!    default traversal reaches double/triple-counts multi-clause rescues.
//!    We score once per chain and walk the rest unscored.
//!  - `expr rescue fallback` (modifier rescue) is prism's own
//!    `RescueModifierNode` — a different node type than `RescueNode`, easy
//!    to silently miss entirely.
//!  - a block using numbered parameters (`_1`) or `it` is rubocop's
//!    `:numblock`/`:itblock` node type, NOT `:block` — since `COUNTED_NODES`
//!    only lists `:block`, such blocks (even ones on a known-iterating
//!    method) never earn a complexity/condition point. Prism keeps the same
//!    `BlockNode` type for all three; the distinction only shows up in
//!    `block.parameters()` being a `NumberedParametersNode`/`ItParametersNode`.
//!  - `->{ }` is prism's own `LambdaNode`, with no underlying call node —
//!    rubocop's parser desugars it to `(block (send nil :lambda) ...)`, so
//!    `AbcSize` picks up a `branch` point from the hidden `send`.
use super::Cops;
use ruby_prism::Visit;
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// `RuboCop::Cop::Metrics::Utils::IteratingBlock::KNOWN_ITERATING_METHODS`.
fn is_known_iterating_method(name: &[u8]) -> bool {
    const NAMES: &[&[u8]] = &[
        // enumerable
        b"all?", b"any?", b"chain", b"chunk", b"chunk_while", b"collect", b"collect_concat",
        b"count", b"cycle", b"detect", b"drop", b"drop_while", b"each", b"each_cons",
        b"each_entry", b"each_slice", b"each_with_index", b"each_with_object", b"entries",
        b"filter", b"filter_map", b"find", b"find_all", b"find_index", b"flat_map", b"grep",
        b"grep_v", b"group_by", b"inject", b"lazy", b"map", b"max", b"max_by", b"min", b"min_by",
        b"minmax", b"minmax_by", b"none?", b"one?", b"partition", b"reduce", b"reject",
        b"reverse_each", b"select", b"slice_after", b"slice_before", b"slice_when", b"sort",
        b"sort_by", b"sum", b"take", b"take_while", b"tally", b"to_h", b"uniq", b"zip",
        // enumerator
        b"with_index", b"with_object",
        // array
        b"bsearch", b"bsearch_index", b"collect!", b"combination", b"d_permutation",
        b"delete_if", b"each_index", b"keep_if", b"map!", b"permutation", b"product",
        b"reject!", b"repeat", b"repeated_combination", b"select!", b"sort!",
        // hash
        b"each_key", b"each_pair", b"each_value", b"fetch", b"fetch_values", b"has_key?",
        b"merge", b"merge!", b"transform_keys", b"transform_keys!", b"transform_values",
        b"transform_values!",
    ];
    NAMES.contains(&name)
}

/// `RuboCop::AST::Node::COMPARISON_OPERATORS`.
fn is_comparison_method(name: &[u8]) -> bool {
    matches!(name, b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<")
}

/// `AbcSizeCalculator#compound_assignment`'s `will_be_miscounted` check,
/// generalized to a *value* position: `respond_to?(:setter_method?) &&
/// !setter_method?` is true for any node shaped like a plain (non-setter)
/// dispatch — a bare/attribute call, `yield`, or `super` — PROVIDED it
/// doesn't carry its own block (a call/`super` WITH a block is rubocop's
/// `:block` node, which doesn't respond to `setter_method?` at all; `->{}`
/// is the same `:block` shape under the hood, so it never qualifies either).
/// rubocop's `compound_assignment` runs this same check against BOTH the
/// (possibly synthetic, in prism) assignment target AND the RHS value —
/// this only covers the value side; the target side is baked directly into
/// each `visit_*_write_node` override below (attribute/index targets are
/// always send-shaped, so they always qualify; local/ivar/etc. targets
/// never do).
fn is_readonly_dispatch(node: &ruby_prism::Node) -> bool {
    // A literal block (`{ }`/`do...end`) wraps the call into rubocop's
    // `:block` node type instead of `:send`/`:zsuper`/`:super` —
    // disqualifying (see `is_countable_block`'s doc comment for the same
    // trap in reverse). A block-PASS (`&:sym`/`&block_var`) stays a plain
    // `:send` with the pass as just another argument — still qualifies.
    fn has_literal_block(block: Option<ruby_prism::Node>) -> bool {
        block.is_some_and(|b| b.as_block_node().is_some())
    }
    if let Some(c) = node.as_call_node() {
        !has_literal_block(c.block())
    } else if node.as_yield_node().is_some() {
        true
    } else if let Some(s) = node.as_super_node() {
        !has_literal_block(s.block())
    } else if let Some(s) = node.as_forwarding_super_node() {
        s.block().is_none()
    } else {
        node.as_defined_node().is_some()
    }
}

/// A call's `.block()` counts toward complexity/condition only when it's a
/// rubocop `:block` node — `:numblock` (numbered params, `_1`) and
/// `:itblock` (`it`) are distinct COUNTED_NODES-excluded types in rubocop's
/// AST even though prism keeps them all as one `BlockNode` shape.
fn is_countable_block(block: &ruby_prism::Node) -> bool {
    if let Some(b) = block.as_block_node() {
        !b.parameters().is_some_and(|p| {
            p.as_numbered_parameters_node().is_some() || p.as_it_parameters_node().is_some()
        })
    } else {
        block.as_block_argument_node().is_some()
    }
}

/// rubocop's `capturing_variable?`: a name that isn't `_`-prefixed.
fn is_capturing_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.starts_with(b"_")
}

/// Ruby's `format("%.<prec>g", value)` — general float format: `prec`
/// significant digits, fixed-point with trailing zeros/point stripped for
/// every exponent range this cop's messages hit (complexity/Max values here
/// are never negative, subnormal, or huge enough to force scientific
/// notation, but the fallback is implemented for completeness).
fn format_g(value: f64, prec: usize) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    let prec = prec.max(1);
    let neg = value.is_sign_negative();

    // Ruby's `sprintf("%g", ...)` rounds from the SHORTEST round-trip
    // decimal digit string for the float (the same digits `Float#to_s`
    // would print), not from the float's full binary-exact decimal
    // expansion. The two disagree exactly at representable ties — e.g. the
    // nearest `f64` to `173.35` is truly `173.34999999999999431...`, which
    // "%.4g"-rounds to `173.3` if you round the exact value but to `173.4`
    // if you round the shortest digit string `"173.35"` (a genuine halfway
    // case, rounded up) — and Ruby does the latter. Rust's `{}` Display
    // impl for `f64` already computes that same shortest digit string, so
    // we round THAT instead of a `{:e}`-formatted exact expansion.
    let shortest = format!("{}", value.abs());
    let (int_part, frac_part) = shortest.split_once('.').unwrap_or((shortest.as_str(), ""));
    let mut digits: Vec<u8> = int_part.bytes().chain(frac_part.bytes()).map(|b| b - b'0').collect();
    let mut exp: i32 = int_part.len() as i32 - 1;
    while digits.len() > 1 && digits[0] == 0 {
        digits.remove(0);
        exp -= 1;
    }

    // Round the digit string to `prec` significant digits — but ONLY if it
    // actually has more than `prec` digits to begin with. This matters for
    // trailing zeros: rubocop's `format("%.4g", ...)` strips trailing
    // fractional zeros for a value that already fit in fewer digits
    // (`8.0` → `"8"`), but KEEPS a trailing zero produced by rounding down
    // to exactly `prec` digits (`8.05` at `%.2g` → `"8.0"`, not `"8"`) —
    // i.e. it never pads short digit strings, and never strips digits it
    // was asked to show. An exact tie (the digit immediately after position
    // `prec` is `5` with nothing nonzero beyond) rounds HALF TO EVEN,
    // matching the dtoa-style rounding underneath Ruby's `sprintf` —
    // everything else rounds the ordinary way (up from 5, down otherwise).
    if digits.len() > prec {
        let exact_half = digits[prec] == 5 && digits[prec + 1..].iter().all(|&d| d == 0);
        let round_up = if exact_half { digits[prec - 1] % 2 == 1 } else { digits[prec] >= 5 };
        digits.truncate(prec);
        if round_up {
            let mut i = prec;
            loop {
                if i == 0 {
                    digits.insert(0, 1);
                    exp += 1;
                    digits.truncate(prec);
                    break;
                }
                i -= 1;
                if digits[i] == 9 {
                    digits[i] = 0;
                } else {
                    digits[i] += 1;
                    break;
                }
            }
        }
    }

    let sign = if neg { "-" } else { "" };
    if exp < -4 || exp >= prec as i32 {
        let mantissa_digits: String = digits.iter().map(|d| (d + b'0') as char).collect();
        let (first, rest) = mantissa_digits.split_at(1);
        let mantissa = if rest.is_empty() { first.to_string() } else { format!("{first}.{rest}") };
        format!("{sign}{mantissa}e{}{:02}", if exp >= 0 { "+" } else { "-" }, exp.abs())
    } else if exp < 0 {
        let mut out = String::from("0.");
        for _ in 0..(-exp - 1) {
            out.push('0');
        }
        for d in &digits {
            out.push((d + b'0') as char);
        }
        format!("{sign}{}", out.trim_end_matches('0').trim_end_matches('.'))
    } else {
        let int_len = (exp + 1) as usize;
        let mut out = String::new();
        for (i, d) in digits.iter().enumerate() {
            if i == int_len {
                out.push('.');
            }
            out.push((d + b'0') as char);
        }
        for _ in digits.len()..int_len {
            out.push('0');
        }
        let out = if out.contains('.') {
            out.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            out
        };
        format!("{sign}{out}")
    }
}

/// rubocop's `define_method?` node pattern: a bare, receiverless
/// `define_method`/`define_singleton_method`-shaped call is NOT what's
/// matched here — only literally `define_method(:name)`/`("name")` with a
/// single symbol/string literal argument, no receiver.
fn define_method_name(call: &ruby_prism::CallNode) -> Option<Vec<u8>> {
    if call.receiver().is_some() || call.name().as_slice() != b"define_method" {
        return None;
    }
    let args = call.arguments()?;
    let items: Vec<_> = args.arguments().iter().collect();
    let [arg] = items.as_slice() else { return None };
    if let Some(sym) = arg.as_symbol_node() {
        let v = sym.value_loc()?;
        Some(v.as_slice().to_vec())
    } else if let Some(s) = arg.as_string_node() {
        Some(s.content_loc().as_slice().to_vec())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// CyclomaticComplexity / PerceivedComplexity: a single filtered walk
// ---------------------------------------------------------------------------

/// Scores `body.each_node(:lvasgn, *COUNTED_NODES)` for both cops — they
/// differ only in the `:if`/`:case`/`:when` handling (`perceived`) and
/// PerceivedComplexity swaps individual `:when` scoring for one aggregate
/// `:case` computation.
struct ComplexityCounter<'pr> {
    perceived: bool,
    score: i64,
    repeated_csend: HashSet<&'pr [u8]>,
}

impl<'pr> ComplexityCounter<'pr> {
    fn new(perceived: bool) -> Self {
        ComplexityCounter { perceived, score: 1, repeated_csend: HashSet::new() }
    }

    /// `discount_for_repeated_csend?` — only a bare-local-variable receiver
    /// is trackable; every other receiver shape always counts.
    fn discount_csend(&mut self, node: &ruby_prism::CallNode<'pr>) -> bool {
        let Some(lv) = node.receiver().and_then(|r| r.as_local_variable_read_node()) else {
            return false;
        };
        let name = lv.name().as_slice();
        if self.repeated_csend.contains(name) {
            true
        } else {
            self.repeated_csend.insert(name);
            false
        }
    }

    /// Walks a `rescue`/`.subsequent()` chain WITHOUT re-scoring each link
    /// (that's `visit_rescue_node`'s job, done once for the whole chain) —
    /// mirrors prism's own `visit_rescue_node` default traversal.
    fn visit_rescue_chain(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        for exc in node.exceptions().iter() {
            self.visit(&exc);
        }
        if let Some(r) = node.reference() {
            self.visit(&r);
        }
        if let Some(s) = node.statements() {
            self.visit_statements_node(&s);
        }
        if let Some(sub) = node.subsequent() {
            self.visit_rescue_chain(&sub);
        }
    }
}

impl<'pr> Visit<'pr> for ComplexityCounter<'pr> {
    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        if self.perceived {
            // Ternary (`?:`) never has a `loc.else` — its `:` isn't `else?`.
            let ternary = node.if_keyword_loc().is_none();
            let is_elsif = node.if_keyword_loc().is_some_and(|l| l.as_slice() == b"elsif");
            let has_else = !ternary && node.subsequent().is_some();
            self.score += if has_else && !is_elsif { 2 } else { 1 };
        } else {
            self.score += 1;
        }
        ruby_prism::visit_if_node(self, node);
    }
    fn visit_unless_node(&mut self, node: &ruby_prism::UnlessNode<'pr>) {
        self.score += if self.perceived && node.else_clause().is_some() { 2 } else { 1 };
        ruby_prism::visit_unless_node(self, node);
    }
    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        // `begin ... end while cond` (a post-condition/do-while loop) is
        // rubocop's distinct `while_post` node type — NOT `while` — and
        // isn't itself in COUNTED_NODES either way.
        if !node.is_begin_modifier() {
            self.score += 1;
        }
        ruby_prism::visit_while_node(self, node);
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        // See `visit_while_node` — `begin ... end until cond` is `until_post`.
        if !node.is_begin_modifier() {
            self.score += 1;
        }
        ruby_prism::visit_until_node(self, node);
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_for_node(self, node);
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        // One `+1` for the whole chain (rubocop's single `:rescue` node),
        // not one per `.subsequent()` link (rubocop's per-clause `:resbody`,
        // which ISN'T itself in COUNTED_NODES) — see module doc comment.
        self.score += 1;
        self.visit_rescue_chain(node);
    }
    fn visit_rescue_modifier_node(&mut self, node: &ruby_prism::RescueModifierNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_rescue_modifier_node(self, node);
    }
    fn visit_and_node(&mut self, node: &ruby_prism::AndNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_and_node(self, node);
    }
    fn visit_or_node(&mut self, node: &ruby_prism::OrNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_or_node(self, node);
    }
    fn visit_when_node(&mut self, node: &ruby_prism::WhenNode<'pr>) {
        if !self.perceived {
            self.score += 1;
        }
        ruby_prism::visit_when_node(self, node);
    }
    fn visit_case_node(&mut self, node: &ruby_prism::CaseNode<'pr>) {
        if self.perceived {
            let nb_branches = node.conditions().iter().count() as f64
                + if node.else_clause().is_some() { 1.0 } else { 0.0 };
            let add = if node.predicate().is_none() { nb_branches } else { (nb_branches * 0.2 + 0.8).round() };
            self.score += add as i64;
        }
        ruby_prism::visit_case_node(self, node);
    }
    fn visit_in_node(&mut self, node: &ruby_prism::InNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_in_node(self, node);
    }
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        self.repeated_csend.remove(node.name().as_slice());
        ruby_prism::visit_local_variable_write_node(self, node);
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if node.is_safe_navigation() && !self.discount_csend(node) {
            self.score += 1;
        }
        if let Some(b) = node.block() {
            if is_countable_block(&b) && is_known_iterating_method(node.name().as_slice()) {
                self.score += 1;
            }
        }
        ruby_prism::visit_call_node(self, node);
    }
    // `or_asgn`/`and_asgn` (rubocop-ast unifies 8 write-target shapes each
    // into one node type per operator; prism keeps them apart) — uniform +1.
    fn visit_call_and_write_node(&mut self, node: &ruby_prism::CallAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_call_and_write_node(self, node);
    }
    fn visit_call_or_write_node(&mut self, node: &ruby_prism::CallOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_call_or_write_node(self, node);
    }
    fn visit_class_variable_and_write_node(&mut self, node: &ruby_prism::ClassVariableAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_class_variable_and_write_node(self, node);
    }
    fn visit_class_variable_or_write_node(&mut self, node: &ruby_prism::ClassVariableOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_class_variable_or_write_node(self, node);
    }
    fn visit_constant_and_write_node(&mut self, node: &ruby_prism::ConstantAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_constant_and_write_node(self, node);
    }
    fn visit_constant_or_write_node(&mut self, node: &ruby_prism::ConstantOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_constant_or_write_node(self, node);
    }
    fn visit_constant_path_and_write_node(&mut self, node: &ruby_prism::ConstantPathAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_constant_path_and_write_node(self, node);
    }
    fn visit_constant_path_or_write_node(&mut self, node: &ruby_prism::ConstantPathOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_constant_path_or_write_node(self, node);
    }
    fn visit_global_variable_and_write_node(&mut self, node: &ruby_prism::GlobalVariableAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_global_variable_and_write_node(self, node);
    }
    fn visit_global_variable_or_write_node(&mut self, node: &ruby_prism::GlobalVariableOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_global_variable_or_write_node(self, node);
    }
    fn visit_index_and_write_node(&mut self, node: &ruby_prism::IndexAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_index_and_write_node(self, node);
    }
    fn visit_index_or_write_node(&mut self, node: &ruby_prism::IndexOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_index_or_write_node(self, node);
    }
    fn visit_instance_variable_and_write_node(&mut self, node: &ruby_prism::InstanceVariableAndWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_instance_variable_and_write_node(self, node);
    }
    fn visit_instance_variable_or_write_node(&mut self, node: &ruby_prism::InstanceVariableOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_instance_variable_or_write_node(self, node);
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        self.repeated_csend.remove(node.name().as_slice());
        self.score += 1;
        ruby_prism::visit_local_variable_and_write_node(self, node);
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        self.repeated_csend.remove(node.name().as_slice());
        self.score += 1;
        ruby_prism::visit_local_variable_or_write_node(self, node);
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        self.repeated_csend.remove(node.name().as_slice());
        ruby_prism::visit_local_variable_operator_write_node(self, node);
    }
}

// ---------------------------------------------------------------------------
// AbcSize: a full post-order walk (assignment/branch/condition vectors)
// ---------------------------------------------------------------------------

/// `RepeatedAttributeDiscount`'s `@known_attributes` tree — one trie per
/// receiver root, each level keyed by the 0-arg method name.
#[derive(Default)]
struct AttrTrie<'pr> {
    children: HashMap<&'pr [u8], AttrTrie<'pr>>,
}

#[derive(PartialEq, Eq, Hash)]
enum AttrRoot<'pr> {
    /// `nil` (bare receiverless call) and `self` share one bucket (rubocop
    /// seeds `@known_attributes` with both keys pointing at the same hash).
    NilSelf,
    Lvar(&'pr [u8]),
    Ivar(&'pr [u8]),
    Cvar(&'pr [u8]),
    Gvar(&'pr [u8]),
    Const(&'pr [u8]),
}

struct AbcCounter<'pr> {
    assignment: i64,
    branch: i64,
    condition: i64,
    repeated_csend: HashSet<&'pr [u8]>,
    discount_attrs: bool,
    attr_roots: HashMap<AttrRoot<'pr>, AttrTrie<'pr>>,
    /// Set while walking an `in`/`=>`/`in` (`InNode`/`MatchRequiredNode`/
    /// `MatchPredicateNode`) pattern: rubocop's parser binds pattern
    /// captures (`in [a, b]`, `in {name:}`) via its own `match_var` node
    /// type, never `lvasgn` — so unlike a real local-variable target
    /// (masgn/for-loop), a capture earns no `assignment` point. Prism
    /// reuses the very same `LocalVariableTargetNode` for both, so this
    /// flag is how `visit_local_variable_target_node` tells them apart.
    in_pattern: bool,
}

impl<'pr> AbcCounter<'pr> {
    fn new(discount_attrs: bool) -> Self {
        AbcCounter {
            assignment: 0,
            branch: 0,
            condition: 0,
            in_pattern: false,
            repeated_csend: HashSet::new(),
            discount_attrs,
            attr_roots: HashMap::new(),
        }
    }

    fn discount_csend(&mut self, node: &ruby_prism::CallNode<'pr>) -> bool {
        self.discount_csend_receiver(node.receiver())
    }

    /// Shared by every csend-shaped node (`CallNode` and the `&.`-flavored
    /// compound-write nodes: `CallAndWriteNode`/`CallOrWriteNode`/
    /// `CallOperatorWriteNode`) — only a bare-local-variable receiver is
    /// trackable; every other receiver shape always counts.
    fn discount_csend_receiver(&mut self, receiver: Option<ruby_prism::Node<'pr>>) -> bool {
        let Some(lv) = receiver.and_then(|r| r.as_local_variable_read_node()) else {
            return false;
        };
        let name = lv.name().as_slice();
        if self.repeated_csend.contains(name) {
            true
        } else {
            self.repeated_csend.insert(name);
            false
        }
    }

    /// Walks a `rescue`/`.subsequent()` chain WITHOUT re-scoring each link
    /// — see `visit_rescue_node` and the module doc comment.
    fn visit_rescue_chain(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        for exc in node.exceptions().iter() {
            self.visit(&exc);
        }
        if let Some(r) = node.reference() {
            self.visit(&r);
        }
        if let Some(s) = node.statements() {
            self.visit_statements_node(&s);
        }
        if let Some(sub) = node.subsequent() {
            self.visit_rescue_chain(&sub);
        }
    }

    /// `discount_repeated_attribute?`/`find_attributes`: walk the 0-arg call
    /// chain down to its root, registering every not-yet-seen level. Bails
    /// to "not discounted" (`false`) the instant a receiver along the chain
    /// isn't itself a root or a further 0-arg call — matching rubocop's
    /// `find_attributes` `else: return yield nil` short-circuit.
    fn discount_attribute(&mut self, call: &ruby_prism::CallNode<'pr>) -> bool {
        let mut names: Vec<&'pr [u8]> = Vec::new();
        let mut cur = call.as_node();
        let root = loop {
            let Some(c) = cur.as_call_node() else { return false };
            if c.arguments().is_some() {
                return false;
            }
            names.push(c.name().as_slice());
            match c.receiver() {
                None => break AttrRoot::NilSelf,
                Some(r) if r.as_self_node().is_some() => break AttrRoot::NilSelf,
                Some(r) => {
                    if let Some(lv) = r.as_local_variable_read_node() {
                        break AttrRoot::Lvar(lv.name().as_slice());
                    } else if let Some(iv) = r.as_instance_variable_read_node() {
                        break AttrRoot::Ivar(iv.name().as_slice());
                    } else if let Some(cv) = r.as_class_variable_read_node() {
                        break AttrRoot::Cvar(cv.name().as_slice());
                    } else if let Some(gv) = r.as_global_variable_read_node() {
                        break AttrRoot::Gvar(gv.name().as_slice());
                    } else if r.as_constant_read_node().is_some() || r.as_constant_path_node().is_some() {
                        break AttrRoot::Const(r.location().as_slice());
                    } else if r.as_call_node().is_some() {
                        cur = r;
                    } else {
                        return false;
                    }
                }
            }
        };
        names.reverse();
        let mut node = self.attr_roots.entry(root).or_default();
        let mut any_new = false;
        for name in names {
            if !node.children.contains_key(name) {
                any_new = true;
            }
            node = node.children.entry(name).or_default();
        }
        !any_new
    }
}

impl<'pr> Visit<'pr> for AbcCounter<'pr> {
    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        ruby_prism::visit_if_node(self, node);
        let ternary = node.if_keyword_loc().is_none();
        let has_real_else = !ternary && node.subsequent().is_some_and(|s| s.as_else_node().is_some());
        self.condition += if has_real_else { 2 } else { 1 };
    }
    fn visit_unless_node(&mut self, node: &ruby_prism::UnlessNode<'pr>) {
        ruby_prism::visit_unless_node(self, node);
        self.condition += if node.else_clause().is_some() { 2 } else { 1 };
    }
    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        ruby_prism::visit_while_node(self, node);
        // `begin ... end while cond` is rubocop's `while_post`, not `while`
        // — not in CONDITION_NODES either way.
        if !node.is_begin_modifier() {
            self.condition += 1;
        }
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        ruby_prism::visit_until_node(self, node);
        if !node.is_begin_modifier() {
            self.condition += 1;
        }
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        ruby_prism::visit_for_node(self, node);
        self.condition += 1;
        self.assignment += 1; // `node.for_type?` short-circuits `assignment?`
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        // One point per chain, not per `.subsequent()` link — see
        // `visit_rescue_chain` and the module doc comment.
        self.visit_rescue_chain(node);
        self.condition += 1;
    }
    fn visit_rescue_modifier_node(&mut self, node: &ruby_prism::RescueModifierNode<'pr>) {
        ruby_prism::visit_rescue_modifier_node(self, node);
        self.condition += 1;
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        ruby_prism::visit_lambda_node(self, node);
        // `->{ }` desugars to `(block (send nil :lambda) ...)` in rubocop's
        // parser — no such node exists in prism, so the implicit `send`'s
        // `branch` point has no home except here.
        self.branch += 1;
    }
    fn visit_when_node(&mut self, node: &ruby_prism::WhenNode<'pr>) {
        ruby_prism::visit_when_node(self, node);
        self.condition += 1;
    }
    fn visit_in_node(&mut self, node: &ruby_prism::InNode<'pr>) {
        let prev = self.in_pattern;
        self.in_pattern = true;
        self.visit(&node.pattern());
        self.in_pattern = prev;
        if let Some(s) = node.statements() {
            self.visit_statements_node(&s);
        }
        self.condition += 1;
    }
    // `data => {name:}` / `data in {name:}` — one-line pattern matching,
    // same `match_var`-not-`lvasgn` capture semantics as `in_node`'s pattern.
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
    fn visit_and_node(&mut self, node: &ruby_prism::AndNode<'pr>) {
        ruby_prism::visit_and_node(self, node);
        self.condition += 1;
    }
    fn visit_or_node(&mut self, node: &ruby_prism::OrNode<'pr>) {
        ruby_prism::visit_or_node(self, node);
        self.condition += 1;
    }
    // Compound assignment (`or_asgn`/`and_asgn`/`op_asgn` in rubocop-ast):
    // upstream's `assignment?` special-cases these via `compound_assignment`,
    // which re-derives the assignment point that visiting the LHS as its OWN
    // node (an equals-assignment shape, in rubocop's parser) would otherwise
    // have earned. Prism instead fuses LHS+operator+RHS into one node per
    // shape with no such nested target to visit independently, so each of
    // these pays the assignment (and, for the call/index-setter shapes,
    // branch) point explicitly here — see module doc comment.
    fn visit_call_and_write_node(&mut self, node: &ruby_prism::CallAndWriteNode<'pr>) {
        ruby_prism::visit_call_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.branch += 1;
        if node.is_safe_navigation() && !self.discount_csend_receiver(node.receiver()) {
            self.condition += 1;
        }
        self.condition += 1;
    }
    fn visit_call_or_write_node(&mut self, node: &ruby_prism::CallOrWriteNode<'pr>) {
        ruby_prism::visit_call_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.branch += 1;
        if node.is_safe_navigation() && !self.discount_csend_receiver(node.receiver()) {
            self.condition += 1;
        }
        self.condition += 1;
    }
    fn visit_call_operator_write_node(&mut self, node: &ruby_prism::CallOperatorWriteNode<'pr>) {
        ruby_prism::visit_call_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.branch += 1;
        if node.is_safe_navigation() && !self.discount_csend_receiver(node.receiver()) {
            self.condition += 1;
        }
    }
    fn visit_class_variable_and_write_node(&mut self, node: &ruby_prism::ClassVariableAndWriteNode<'pr>) {
        ruby_prism::visit_class_variable_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_class_variable_or_write_node(&mut self, node: &ruby_prism::ClassVariableOrWriteNode<'pr>) {
        ruby_prism::visit_class_variable_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_class_variable_operator_write_node(&mut self, node: &ruby_prism::ClassVariableOperatorWriteNode<'pr>) {
        ruby_prism::visit_class_variable_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
    }
    fn visit_constant_and_write_node(&mut self, node: &ruby_prism::ConstantAndWriteNode<'pr>) {
        ruby_prism::visit_constant_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_constant_or_write_node(&mut self, node: &ruby_prism::ConstantOrWriteNode<'pr>) {
        ruby_prism::visit_constant_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_constant_operator_write_node(&mut self, node: &ruby_prism::ConstantOperatorWriteNode<'pr>) {
        ruby_prism::visit_constant_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
    }
    fn visit_constant_path_and_write_node(&mut self, node: &ruby_prism::ConstantPathAndWriteNode<'pr>) {
        ruby_prism::visit_constant_path_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_constant_path_or_write_node(&mut self, node: &ruby_prism::ConstantPathOrWriteNode<'pr>) {
        ruby_prism::visit_constant_path_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_constant_path_operator_write_node(&mut self, node: &ruby_prism::ConstantPathOperatorWriteNode<'pr>) {
        ruby_prism::visit_constant_path_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
    }
    fn visit_global_variable_and_write_node(&mut self, node: &ruby_prism::GlobalVariableAndWriteNode<'pr>) {
        ruby_prism::visit_global_variable_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_global_variable_or_write_node(&mut self, node: &ruby_prism::GlobalVariableOrWriteNode<'pr>) {
        ruby_prism::visit_global_variable_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_global_variable_operator_write_node(&mut self, node: &ruby_prism::GlobalVariableOperatorWriteNode<'pr>) {
        ruby_prism::visit_global_variable_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
    }
    // Index targets (`arr[i] ||= x`) are, like attribute targets, a
    // send-shaped fragment when isolated (`arr[i]`'s getter form) — prism
    // fuses the implicit `[]` call away entirely, so its `branch` point (and
    // the unconditional assignment compensation) has no other home.
    fn visit_index_and_write_node(&mut self, node: &ruby_prism::IndexAndWriteNode<'pr>) {
        ruby_prism::visit_index_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.branch += 1;
        self.condition += 1;
    }
    fn visit_index_or_write_node(&mut self, node: &ruby_prism::IndexOrWriteNode<'pr>) {
        ruby_prism::visit_index_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.branch += 1;
        self.condition += 1;
    }
    fn visit_index_operator_write_node(&mut self, node: &ruby_prism::IndexOperatorWriteNode<'pr>) {
        ruby_prism::visit_index_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.branch += 1;
    }
    fn visit_instance_variable_and_write_node(&mut self, node: &ruby_prism::InstanceVariableAndWriteNode<'pr>) {
        ruby_prism::visit_instance_variable_and_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_instance_variable_or_write_node(&mut self, node: &ruby_prism::InstanceVariableOrWriteNode<'pr>) {
        ruby_prism::visit_instance_variable_or_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_instance_variable_operator_write_node(
        &mut self,
        node: &ruby_prism::InstanceVariableOperatorWriteNode<'pr>,
    ) {
        ruby_prism::visit_instance_variable_operator_write_node(self, node);
        self.assignment += 1;
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        ruby_prism::visit_local_variable_and_write_node(self, node);
        self.repeated_csend.remove(node.name().as_slice());
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        ruby_prism::visit_local_variable_or_write_node(self, node);
        self.repeated_csend.remove(node.name().as_slice());
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
        self.condition += 1;
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        ruby_prism::visit_local_variable_operator_write_node(self, node);
        self.repeated_csend.remove(node.name().as_slice());
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
        if is_readonly_dispatch(&node.value()) {
            self.assignment += 1;
        }
    }
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        ruby_prism::visit_local_variable_write_node(self, node);
        self.repeated_csend.remove(node.name().as_slice());
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        ruby_prism::visit_local_variable_target_node(self, node);
        // A pattern-matching capture (`match_var` in rubocop's parser, not
        // `lvasgn`) earns nothing — see `in_pattern`'s doc comment.
        if self.in_pattern {
            return;
        }
        self.repeated_csend.remove(node.name().as_slice());
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_instance_variable_write_node(&mut self, node: &ruby_prism::InstanceVariableWriteNode<'pr>) {
        ruby_prism::visit_instance_variable_write_node(self, node);
        self.assignment += 1;
    }
    fn visit_instance_variable_target_node(&mut self, node: &ruby_prism::InstanceVariableTargetNode<'pr>) {
        ruby_prism::visit_instance_variable_target_node(self, node);
        self.assignment += 1;
    }
    fn visit_class_variable_write_node(&mut self, node: &ruby_prism::ClassVariableWriteNode<'pr>) {
        ruby_prism::visit_class_variable_write_node(self, node);
        self.assignment += 1;
    }
    fn visit_class_variable_target_node(&mut self, node: &ruby_prism::ClassVariableTargetNode<'pr>) {
        ruby_prism::visit_class_variable_target_node(self, node);
        self.assignment += 1;
    }
    fn visit_global_variable_write_node(&mut self, node: &ruby_prism::GlobalVariableWriteNode<'pr>) {
        ruby_prism::visit_global_variable_write_node(self, node);
        self.assignment += 1;
    }
    fn visit_global_variable_target_node(&mut self, node: &ruby_prism::GlobalVariableTargetNode<'pr>) {
        ruby_prism::visit_global_variable_target_node(self, node);
        self.assignment += 1;
    }
    fn visit_constant_write_node(&mut self, node: &ruby_prism::ConstantWriteNode<'pr>) {
        ruby_prism::visit_constant_write_node(self, node);
        self.assignment += 1;
    }
    fn visit_constant_path_write_node(&mut self, node: &ruby_prism::ConstantPathWriteNode<'pr>) {
        ruby_prism::visit_constant_path_write_node(self, node);
        self.assignment += 1;
    }
    // Masgn (`a, b = 1, 2`) targets: unlike `or_asgn`/`and_asgn`/`op_asgn`,
    // prism keeps a genuinely separate, visitable target node per LHS
    // element here (matching rubocop's parser) rather than fusing everything
    // into one node — so these need no RHS-bonus (masgn's own
    // `compound_assignment` only ever inspects `node.assignments`, i.e. the
    // targets) but otherwise follow the same rules as their write-node
    // counterparts above.
    fn visit_constant_target_node(&mut self, node: &ruby_prism::ConstantTargetNode<'pr>) {
        ruby_prism::visit_constant_target_node(self, node);
        self.assignment += 1;
    }
    fn visit_constant_path_target_node(&mut self, node: &ruby_prism::ConstantPathTargetNode<'pr>) {
        ruby_prism::visit_constant_path_target_node(self, node);
        self.assignment += 1;
    }
    fn visit_call_target_node(&mut self, node: &ruby_prism::CallTargetNode<'pr>) {
        ruby_prism::visit_call_target_node(self, node);
        self.assignment += 1;
        self.branch += 1;
        if node.is_safe_navigation() && !self.discount_csend_receiver(Some(node.receiver())) {
            self.condition += 1;
        }
    }
    fn visit_index_target_node(&mut self, node: &ruby_prism::IndexTargetNode<'pr>) {
        ruby_prism::visit_index_target_node(self, node);
        self.assignment += 1;
        self.branch += 1;
        if node.is_safe_navigation() && !self.discount_csend_receiver(Some(node.receiver())) {
            self.condition += 1;
        }
    }
    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        ruby_prism::visit_required_parameter_node(self, node);
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        ruby_prism::visit_optional_parameter_node(self, node);
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        ruby_prism::visit_rest_parameter_node(self, node);
        if node.name().is_some_and(|n| is_capturing_name(n.as_slice())) {
            self.assignment += 1;
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        ruby_prism::visit_required_keyword_parameter_node(self, node);
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        ruby_prism::visit_optional_keyword_parameter_node(self, node);
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        ruby_prism::visit_keyword_rest_parameter_node(self, node);
        if node.name().is_some_and(|n| is_capturing_name(n.as_slice())) {
            self.assignment += 1;
        }
    }
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        ruby_prism::visit_block_parameter_node(self, node);
        if node.name().is_some_and(|n| is_capturing_name(n.as_slice())) {
            self.assignment += 1;
        }
    }
    fn visit_block_local_variable_node(&mut self, node: &ruby_prism::BlockLocalVariableNode<'pr>) {
        ruby_prism::visit_block_local_variable_node(self, node);
        if is_capturing_name(node.name().as_slice()) {
            self.assignment += 1;
        }
    }
    fn visit_yield_node(&mut self, node: &ruby_prism::YieldNode<'pr>) {
        ruby_prism::visit_yield_node(self, node);
        self.branch += 1;
    }
    // `/regexp/ =~ expr` with named captures (`(?<name>...)`) auto-vivifies
    // locals for each name — rubocop's parser fuses the whole thing into one
    // `match_with_lvasgn` node that ISN'T itself send/csend/yield (no
    // `branch`), isn't a COUNTED_NODES/CONDITION_NODES member (no
    // `condition`), and doesn't expose the captures as separately-visitable
    // `lvasgn` targets either (no `assignment`) — it's entirely uncounted
    // except for whatever's nested inside the matched expression itself.
    // Prism's `MatchWriteNode` keeps a real (visitable, scorable) `CallNode`
    // for the `=~` and real `LocalVariableTargetNode`s for the captures, so
    // we walk around both rather than through `visit_call_node`/the targets.
    fn visit_match_write_node(&mut self, node: &ruby_prism::MatchWriteNode<'pr>) {
        let call = node.call();
        if let Some(r) = call.receiver() {
            self.visit(&r);
        }
        if let Some(args) = call.arguments() {
            for a in args.arguments().iter() {
                self.visit(&a);
            }
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        ruby_prism::visit_call_node(self, node);
        // Setter-shaped calls (`obj.attr = x`, `x[0] = 1`) — `equal_loc` is
        // prism's signal for rubocop's `setter_method?` (`loc?(:operator)`).
        if node.equal_loc().is_some() {
            self.assignment += 1;
        }
        let discounted = self.discount_attrs && self.discount_attribute(node);
        if !discounted {
            if is_comparison_method(node.name().as_slice()) {
                self.condition += 1;
            } else {
                self.branch += 1;
                if node.is_safe_navigation() && !self.discount_csend(node) {
                    self.condition += 1;
                }
            }
        }
        // A block/block-pass on a KNOWN ITERATING method is its own
        // `condition` point — never discounted by the attribute tracking.
        if let Some(b) = node.block() {
            if is_countable_block(&b) && is_known_iterating_method(node.name().as_slice()) {
                self.condition += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// hooks + cop entry points
// ---------------------------------------------------------------------------

impl<'a> Cops<'a> {
    /// `on_def`/`on_defs`: prism doesn't distinguish `def foo` from
    /// `def self.foo` (both are `DefNode`, `on_defs` was a whitequark-only
    /// split) — same anchor/name/body for all three cops.
    pub(crate) fn check_metrics_complexity_def(&mut self, node: &ruby_prism::DefNode) {
        let anchor = node.location().start_offset();
        let name = node.name().as_slice();
        let body = node.body();
        self.check_cyclomatic_complexity(anchor, name, body.as_ref());
        self.check_perceived_complexity(anchor, name, body.as_ref());
        self.check_abc_size(anchor, name, body.as_ref());
    }

    /// `on_block`/`on_numblock`/`on_itblock` (rubocop's `define_method?`
    /// node-pattern guard): only a bare `define_method(:name) { ... }` block
    /// is treated as its own "method" for complexity purposes.
    pub(crate) fn check_metrics_complexity_define_method(
        &mut self,
        call: &ruby_prism::CallNode,
        block: &ruby_prism::BlockNode,
    ) {
        let Some(name) = define_method_name(call) else { return };
        // rubocop's whitequark `:block` node range spans from the CALL's own
        // start through the block's `end`/`}` — prism's own `BlockNode`
        // location starts at the block's opening keyword/brace instead (a
        // documented prism-vs-whitequark trap), so anchor on the call.
        let anchor = call.location().start_offset();
        let body = block.body();
        self.check_cyclomatic_complexity(anchor, &name, body.as_ref());
        self.check_perceived_complexity(anchor, &name, body.as_ref());
        self.check_abc_size(anchor, &name, body.as_ref());
    }

    fn check_cyclomatic_complexity(&mut self, anchor: usize, name: &[u8], body: Option<&ruby_prism::Node>) {
        const COP: &str = "Metrics/CyclomaticComplexity";
        if !self.on(COP) || self.allowed(COP, name) {
            return;
        }
        let Some(body) = body else { return };
        let max: f64 = self.cfg.get(COP, "Max").and_then(|v| v.parse().ok()).unwrap_or(7.0);
        let mut counter = ComplexityCounter::new(false);
        counter.visit(body);
        if (counter.score as f64) > max {
            let msg = format!(
                "Cyclomatic complexity for `{}` is too high. [{}/{}]",
                String::from_utf8_lossy(name),
                counter.score,
                max as i64
            );
            self.push(anchor, COP, false, msg);
        }
    }

    fn check_perceived_complexity(&mut self, anchor: usize, name: &[u8], body: Option<&ruby_prism::Node>) {
        const COP: &str = "Metrics/PerceivedComplexity";
        if !self.on(COP) || self.allowed(COP, name) {
            return;
        }
        let Some(body) = body else { return };
        let max: f64 = self.cfg.get(COP, "Max").and_then(|v| v.parse().ok()).unwrap_or(8.0);
        let mut counter = ComplexityCounter::new(true);
        counter.visit(body);
        if (counter.score as f64) > max {
            let msg = format!(
                "Perceived complexity for `{}` is too high. [{}/{}]",
                String::from_utf8_lossy(name),
                counter.score,
                max as i64
            );
            self.push(anchor, COP, false, msg);
        }
    }

    fn check_abc_size(&mut self, anchor: usize, name: &[u8], body: Option<&ruby_prism::Node>) {
        const COP: &str = "Metrics/AbcSize";
        if !self.on(COP) || self.allowed(COP, name) {
            return;
        }
        let Some(body) = body else { return };
        let max: f64 = self.cfg.get(COP, "Max").and_then(|v| v.parse().ok()).unwrap_or(17.0);
        let discount_attrs = self.cfg.get(COP, "CountRepeatedAttributes") == Some("false");
        let mut counter = AbcCounter::new(discount_attrs);
        counter.visit(body);
        let complexity = ((counter.assignment.pow(2) + counter.branch.pow(2) + counter.condition.pow(2)) as f64)
            .sqrt();
        let complexity = (complexity * 100.0).round() / 100.0;
        if complexity > max {
            let msg = format!(
                "Assignment Branch Condition size for `{}` is too high. [<{}, {}, {}> {}/{}]",
                String::from_utf8_lossy(name),
                counter.assignment,
                counter.branch,
                counter.condition,
                format_g(complexity, 4),
                format_g(max, 4)
            );
            self.push(anchor, COP, false, msg);
        }
    }
}
impl<'a> super::Cops<'a> {

    pub(crate) fn check_metrics_parameter_lists(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Metrics/ParameterLists";
        if !self.on(COP) {
            return;
        }

        let Some(params) = node.parameters() else { return };

        // Check if this is an initialize method inside a Struct.new/Data.define block
        let in_struct_data_block = self.metrics_in_struct_data_define_block.last().copied().unwrap_or(false);
        if node.name().as_slice() == b"initialize" && in_struct_data_block {
            return;
        }

        // Check for too many parameters overall
        // Default is true, so count keyword args by default
        let count_keyword_args = self.cfg.get(COP, "CountKeywordArgs")
            .map(|v| v != "false")
            .unwrap_or(true);

        let param_count = if count_keyword_args {
            // Count all parameters except block parameters
            params.requireds().iter().count()
                + params.optionals().iter().count()
                + params.rest().is_some() as usize
                + params.posts().iter().count()
                + params.keywords().iter().count()
                + params.keyword_rest().is_some() as usize
        } else {
            // Don't count keyword parameters
            params.requireds().iter().count()
                + params.optionals().iter().count()
                + params.rest().is_some() as usize
                + params.posts().iter().count()
        };

        let max_params = self.cfg.get(COP, "Max")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(5);

        if param_count > max_params {
            let msg = format!(
                "Avoid parameter lists longer than {} parameters. [{}/{}]",
                max_params,
                param_count,
                max_params
            );
            // Upstream anchors at node.arguments.source_range, whose span
            // INCLUDES the parens — use the def's lparen when present (the
            // params may start on a later line), else the first param.
            let offset = node
                .lparen_loc()
                .map(|l| l.start_offset())
                .unwrap_or_else(|| params.location().start_offset());
            self.push(offset, COP, false, msg);
        }

        // Check for too many optional parameters
        let optionals: Vec<_> = params.optionals().iter().collect();
        let max_optional = self.cfg.get(COP, "MaxOptionalParameters")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);

        if optionals.len() > max_optional {
            let msg = format!(
                "Method has too many optional parameters. [{}/{}]",
                optionals.len(),
                max_optional
            );
            // Report on the def node location
            self.push(node.location().start_offset(), COP, false, msg);
        }
    }
}

use super::LineIndex;

// ---------------------------------------------------------------------------
// Metrics/ModuleLength — ports rubocop's `CodeLength` mixin (shared with the
// not-yet-implemented Metrics/ClassLength) restricted to what a `module`
// definition needs: a real `module ... end` node, and the `Foo = Module.new
// do ... end`/`Foo = ::Module.new do ... end` casgn form (`module_definition?`
// node-pattern). Extending this to Metrics/ClassLength later mainly means
// adding a `class`-node entry point that reuses `ml_classlike_length`
// (already generic over module/class) and a casgn matcher for
// `Class.new(...) do ... end`.
//
// Known gaps (none exercised by the spec fixture):
//  - `omit_length` (the hash-without-braces/parenthesized-call correction to
//    a folded `method_call`) isn't replicated — folding a bare-hash-argument
//    method call under `CountAsOne: [method_call]` may be off by 1-2 lines.
//  - `source_from_node_with_heredoc` (the casgn/`Module.new` body-length
//    special case for a body that CONTAINS a heredoc, where the body node's
//    own `source` text doesn't reach through the heredoc's closing
//    delimiter) isn't replicated — we just use the body node's own text
//    span. rubocop's whitequark AST needs this because a heredoc node's own
//    `source_range` stops at the opening line; if prism's heredoc node
//    ranges already extend through the closing delimiter (unverified here),
//    this gap is moot in practice.
// ---------------------------------------------------------------------------

/// `CodeLengthCalculator::FOLDABLE_TYPES` as a config-resolved bitset —
/// `CountAsOne`'s default is `[]` (NOT the four-way list; that's just the
/// menu of valid values), so folding is opt-in per cop config.
#[derive(Default, Clone, Copy)]
struct MlFoldableTypes {
    array: bool,
    hash: bool,
    heredoc: bool,
    method_call: bool,
}

impl MlFoldableTypes {
    fn from_list(list: &[String]) -> Self {
        let mut f = MlFoldableTypes::default();
        for s in list {
            match s.as_str() {
                "array" => f.array = true,
                "hash" => f.hash = true,
                "heredoc" => f.heredoc = true,
                "method_call" => f.method_call = true,
                _ => {}
            }
        }
        f
    }
    fn any(&self) -> bool {
        self.array || self.hash || self.heredoc || self.method_call
    }
}

fn ml_is_classlike(node: &ruby_prism::Node) -> bool {
    node.as_module_node().is_some() || node.as_class_node().is_some()
}

/// rubocop's `String#blank?` (empty OR whitespace-only — NOT the strict
/// `String#empty?` some other cops' "blank line" helpers use) combined with
/// `comment_line?` (entire line, ignoring leading whitespace, starts with
/// `#`) — `CodeLength#irrelevant_line`.
fn ml_irrelevant_line_text(bytes: &[u8], count_comments: bool) -> bool {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return true;
    }
    if count_comments {
        return false;
    }
    bytes.iter().find(|b| !b.is_ascii_whitespace()).is_some_and(|&b| b == b'#')
}

/// Ruby's `String#lines` split (keep-newline semantics, but we only need the
/// segment COUNT/content so the `\n` itself is dropped) applied to an
/// arbitrary byte slice — a plain string never yields a synthetic trailing
/// empty element the way a naive `split('\n')` would.
fn ml_count_text_fragment(bytes: &[u8], count_comments: bool) -> i64 {
    let mut count = 0i64;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            if !ml_irrelevant_line_text(&bytes[start..i], count_comments) {
                count += 1;
            }
            start = i + 1;
        }
    }
    if start < bytes.len() && !ml_irrelevant_line_text(&bytes[start..], count_comments) {
        count += 1;
    }
    count
}

/// `(any_block (send (const {nil? cbase} :Module) :new) ...)` —
/// `module_definition?`. Matches bare `Module.new`/`::Module.new` (no
/// arguments) followed by a literal block (do/end or `{}`; a block-PASS
/// doesn't produce this shape at all in rubocop's AST).
fn ml_module_new_block<'pr>(value: &ruby_prism::Node<'pr>) -> Option<ruby_prism::BlockNode<'pr>> {
    let call = value.as_call_node()?;
    if call.name().as_slice() != b"new" {
        return None;
    }
    if call.arguments().is_some_and(|a| a.arguments().iter().count() > 0) {
        return None;
    }
    let recv = call.receiver()?;
    let is_module = recv.as_constant_read_node().is_some_and(|c| c.location().as_slice() == b"Module")
        || recv
            .as_constant_path_node()
            .is_some_and(|cp| cp.parent().is_none() && cp.name_loc().as_slice() == b"Module");
    if !is_module {
        return None;
    }
    call.block()?.as_block_node()
}

/// Records the full (inclusive) line range of every `module`/`class`
/// descendant reached from a classlike node's body — `classlike_code_length`
/// excludes ALL of a nested module/class's lines wholesale (its own length
/// was/will be scored separately when `on_module`/`on_class` visits it).
struct MlInnerClasslikeCollector<'a> {
    idx: &'a LineIndex,
    lines: HashSet<usize>,
}
impl<'a, 'pr> Visit<'pr> for MlInnerClasslikeCollector<'a> {
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.record(&node.as_node());
        ruby_prism::visit_module_node(self, node);
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.record(&node.as_node());
        ruby_prism::visit_class_node(self, node);
    }
}
impl<'a> MlInnerClasslikeCollector<'a> {
    fn record(&mut self, node: &ruby_prism::Node) {
        let l = node.location();
        let first = self.idx.loc(l.start_offset()).0;
        let last = self.idx.loc(l.end_offset().saturating_sub(1)).0;
        for line in first..=last {
            self.lines.insert(line);
        }
    }
}

/// `each_top_level_descendant`: walks every child reached from a node,
/// stopping at (and never descending into) a classlike node OR a node
/// matching one of the configured foldable types — the matched node itself
/// is recorded but not explored further (its own nested foldables are
/// irrelevant; it folds to a single line as a whole).
struct MlFoldWalker<'pr> {
    foldable: MlFoldableTypes,
    matches: Vec<ruby_prism::Node<'pr>>,
}
impl<'pr> Visit<'pr> for MlFoldWalker<'pr> {
    fn visit_module_node(&mut self, _node: &ruby_prism::ModuleNode<'pr>) {}
    fn visit_class_node(&mut self, _node: &ruby_prism::ClassNode<'pr>) {}
    fn visit_array_node(&mut self, node: &ruby_prism::ArrayNode<'pr>) {
        if self.foldable.array {
            self.matches.push(node.as_node());
        } else {
            ruby_prism::visit_array_node(self, node);
        }
    }
    fn visit_hash_node(&mut self, node: &ruby_prism::HashNode<'pr>) {
        if self.foldable.hash {
            self.matches.push(node.as_node());
        } else {
            ruby_prism::visit_hash_node(self, node);
        }
    }
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        if self.foldable.heredoc && super::breakable::is_heredoc_node(&node.as_node()) {
            self.matches.push(node.as_node());
        }
        // A plain `StringNode` has no child nodes to recurse into either way.
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        if self.foldable.heredoc && super::breakable::is_heredoc_node(&node.as_node()) {
            self.matches.push(node.as_node());
        } else {
            ruby_prism::visit_interpolated_string_node(self, node);
        }
    }
    fn visit_x_string_node(&mut self, node: &ruby_prism::XStringNode<'pr>) {
        if self.foldable.heredoc && super::breakable::is_heredoc_node(&node.as_node()) {
            self.matches.push(node.as_node());
        }
    }
    fn visit_interpolated_x_string_node(&mut self, node: &ruby_prism::InterpolatedXStringNode<'pr>) {
        if self.foldable.heredoc && super::breakable::is_heredoc_node(&node.as_node()) {
            self.matches.push(node.as_node());
        } else {
            ruby_prism::visit_interpolated_x_string_node(self, node);
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if self.foldable.method_call {
            self.matches.push(node.as_node());
        } else {
            ruby_prism::visit_call_node(self, node);
        }
    }
}

impl<'a> Cops<'a> {
    fn ml_irrelevant_file_line(&self, line: usize, count_comments: bool) -> bool {
        let s = self.idx.starts[line - 1];
        let e = self.line_end(line);
        ml_irrelevant_line_text(&self.src[s..e], count_comments)
    }

    /// `code_length` for an arbitrary node via its OWN literal source text
    /// (the `else` branch's default `extract_body(node) == node` case) —
    /// used both for the casgn/`Module.new` body and for a folded
    /// array/hash/method-call descendant.
    fn ml_node_own_length(&self, node: &ruby_prism::Node, count_comments: bool) -> i64 {
        let l = node.location();
        ml_count_text_fragment(&self.src[l.start_offset()..l.end_offset()], count_comments)
    }

    /// `heredoc_length`: the heredoc's own body content (between the opener
    /// and the closing delimiter line), non-irrelevant lines, `+ 2` for the
    /// (unconditionally counted) opener/closer lines themselves.
    fn ml_heredoc_length(&self, node: &ruby_prism::Node, count_comments: bool) -> i64 {
        let range = if let Some(n) = node.as_string_node() {
            let c = n.content_loc();
            Some((c.start_offset(), c.end_offset()))
        } else if let Some(n) = node.as_interpolated_string_node() {
            n.opening_loc().map(|o| o.end_offset()).zip(n.closing_loc().map(|c| c.start_offset()))
        } else if let Some(n) = node.as_x_string_node() {
            let c = n.content_loc();
            Some((c.start_offset(), c.end_offset()))
        } else if let Some(n) = node.as_interpolated_x_string_node() {
            Some((n.opening_loc().end_offset(), n.closing_loc().start_offset()))
        } else {
            None
        };
        let body_count = match range {
            Some((s, e)) if e > s => ml_count_text_fragment(&self.src[s..e], count_comments),
            _ => 0,
        };
        body_count + 2
    }

    /// `classlike_code_length` — real `module`/`class` node form.
    fn ml_classlike_length(&self, node: &ruby_prism::Node, count_comments: bool) -> i64 {
        let body = match node.as_module_node() {
            Some(m) => m.body(),
            None => node.as_class_node().and_then(|c| c.body()),
        };
        // `namespace_module?`: a module/class whose ENTIRE body is a single
        // nested module/class definition scores 0 (pure namespace).
        if body.as_ref().is_some_and(ml_is_classlike) {
            return 0;
        }
        let l = node.location();
        let first = self.idx.loc(l.start_offset()).0;
        let last = self.idx.loc(l.end_offset().saturating_sub(1)).0;
        let mut excluded = MlInnerClasslikeCollector { idx: self.idx, lines: HashSet::new() };
        if let Some(b) = &body {
            excluded.visit(b);
        }
        let mut length = 0i64;
        // Interior lines only — excludes the node's own first (`module Foo`)
        // and last (`end`) line. An empty `(first+1)..=(last-1)` range (e.g.
        // `module Foo\nend`) simply iterates zero times.
        for line in (first + 1)..=last.saturating_sub(1) {
            if excluded.lines.contains(&line) {
                continue;
            }
            // Upstream bug replicated verbatim: `classlike_code_length`
            // indexes `@processed_source[line_number]` with the 1-BASED line
            // number into the 0-based lines array, so the blank/comment
            // relevance test actually inspects the FOLLOWING line (rails
            // xml_mini.rb counts 153, not 152, because of this).
            if !self.ml_irrelevant_file_line(line + 1, count_comments) {
                length += 1;
            }
        }
        length
    }

    /// Applies `CountAsOne` folding to a base length, walking `start`'s
    /// children (NOT `start` itself — `each_top_level_descendant` never
    /// tests the top node for classlike-ness/type membership, only its
    /// descendants) via `walk`, which must invoke the matching
    /// `ruby_prism::visit_*_node` default-traversal free function for
    /// `start`'s own node type so the walker sees exactly `start`'s direct
    /// children.
    fn ml_apply_folding(&self, mut length: i64, matches: Vec<ruby_prism::Node>, count_comments: bool) -> i64 {
        for m in matches {
            let descendant_length = if super::breakable::is_heredoc_node(&m) {
                self.ml_heredoc_length(&m, count_comments)
            } else {
                self.ml_node_own_length(&m, count_comments)
            };
            length = length - descendant_length + 1;
        }
        length
    }

    fn ml_config(&self, cop: &'static str) -> (i64, bool, MlFoldableTypes) {
        let max = self.cfg.get(cop, "Max").and_then(|v| v.parse().ok()).unwrap_or(100);
        let count_comments = self.cfg.get(cop, "CountComments") == Some("true");
        let count_as_one =
            self.cfg.get(cop, "CountAsOne").map(crate::config::parse_allowed_list).unwrap_or_default();
        (max, count_comments, MlFoldableTypes::from_list(&count_as_one))
    }

    /// `on_module` — a real `module Foo ... end` definition.
    pub(crate) fn check_module_length_module(&mut self, node: &ruby_prism::ModuleNode) {
        const COP: &str = "Metrics/ModuleLength";
        if !self.on(COP) {
            return;
        }
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = self.ml_classlike_length(&node.as_node(), count_comments);
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_module_node(&mut walker, node);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Module has too many lines. [{length}/{max}]");
            self.push(node.location().start_offset(), COP, false, msg);
        }
    }

    /// `on_casgn` guarded by `module_definition?` — `Foo = Module.new do
    /// ... end` / `Foo = ::Module.new do ... end`. Anchored at `node.loc.name`
    /// (just `Foo`), matching `CodeLength#location`'s casgn branch.
    pub(crate) fn check_module_length_casgn(&mut self, node: &ruby_prism::ConstantWriteNode) {
        const COP: &str = "Metrics/ModuleLength";
        if !self.on(COP) {
            return;
        }
        let Some(block) = ml_module_new_block(&node.value()) else { return };
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = match block.body() {
            Some(b) => self.ml_method_body_length(&b, count_comments),
            None => 0,
        };
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_constant_write_node(&mut walker, node);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Module has too many lines. [{length}/{max}]");
            self.push(node.name_loc().start_offset(), COP, false, msg);
        }
    }
}


// ---------------------------------------------------------------------------
// Metrics/BlockLength — reuses the same `CodeLength`-mixin machinery as
// Metrics/ModuleLength above (`ml_config`/`ml_node_own_length`/
// `ml_apply_folding`/`MlFoldWalker`), applied to `on_block` (aliased
// `on_numblock`/`on_itblock` upstream — prism collapses all three shapes,
// `do...end`, `{}`, numbered-param `_1`, and `it`-param, into ONE
// `ruby_prism::BlockNode`, so a single hook covers every alias). Adds:
//  - `AllowedMethods`/`AllowedPatterns` (+ the deprecated `IgnoredMethods`/
//    `ExcludedMethods` aliases the `AllowedMethods` mixin still honors).
//  - `method_receiver_excluded?`: a `Receiver.method`-shaped config entry
//    requires an exact (whitespace-stripped) receiver-source match; a bare
//    entry matches the method name against ANY receiver.
//  - `class_constructor?`: `Class.new`/`Module.new`/`Struct.new`/
//    `Data.define` (any args, `::`-qualified or not) are exempt — the first
//    two are scored by Metrics/ClassLength/ModuleLength instead, and
//    Struct/Data blocks are never scored by any Metrics length cop (the
//    cop's own "NOTE: does not apply for Struct definitions").
//
// Known gaps (none exercised by the spec fixture):
//  - `source_from_node_with_heredoc` (see the ModuleLength note above) isn't
//    replicated for a block body containing a heredoc.
//  - The deprecated `IgnoredMethods`/`ExcludedMethods` aliases are folded
//    into the very same plain-string list `AllowedMethods` uses, rather than
//    rubocop's real type-sniffing (an array holding a `Regexp` moves the
//    WHOLE deprecated array into `AllowedPattern`'s regex matching instead of
//    `AllowedMethods`'s exact-name matching). This is indistinguishable from
//    upstream's actual behavior for the fixture: the oracle's static spec
//    parser flattens a Ruby `/regex/` literal to its bare source text before
//    it ever reaches our config file, and a bare (dot-less) list entry
//    already matches a method name against ANY receiver under
//    `method_receiver_excluded?` — the exact same effect `AllowedPattern`'s
//    regex matching has on a plain (non-metacharacter) pattern.
// ---------------------------------------------------------------------------

impl<'a> Cops<'a> {
    /// `AllowedMethods` (config override, else schema default `['refine']`,
    /// via `self.eng.allowed_methods` — `self.cfg.get` can't see this default
    /// since it's an ARRAY, absent from the scalar `SCHEMA.params` table)
    /// plus the deprecated `IgnoredMethods`/`ExcludedMethods` aliases
    /// (default `[]` each, read straight off `self.cfg` since neither has a
    /// schema default to miss) — see the module doc above for why these
    /// don't need real regex-vs-string type sniffing here.
    fn bl_allowed_methods(&self, cop: &'static str) -> Vec<String> {
        let mut list = self.eng.allowed_methods.get(cop).cloned().unwrap_or_default();
        for key in ["IgnoredMethods", "ExcludedMethods"] {
            if let Some(v) = self.cfg.get(cop, key) {
                list.extend(crate::config::parse_allowed_list(v));
            }
        }
        list
    }

    /// `matches_allowed_pattern?(node.method_name)` — the real `AllowedPatterns`
    /// key only (default `[]`).
    fn bl_matches_pattern(&self, cop: &'static str, method: &[u8]) -> bool {
        self.eng.allowed_patterns.get(cop).is_some_and(|pats| {
            let s = String::from_utf8_lossy(method);
            pats.iter().any(|re| re.is_match(&s))
        })
    }

    /// `allowed_method?(node.method_name) || method_receiver_excluded?(node)`
    /// collapsed into one pass over the combined list: a bare (dot-less)
    /// entry behaves exactly like `allowed_method?` (matches the method name
    /// against ANY receiver, including none — `method_receiver_excluded?`'s
    /// own fallback assignment, `method = receiver; receiver =
    /// node_receiver`, makes the two upstream checks literally the same code
    /// path once an entry has no dot), while a `Receiver.method` entry
    /// requires an exact (whitespace-stripped) receiver-source match. Only
    /// the FIRST two dot-split segments matter, matching Ruby's `receiver,
    /// method = config.split('.')` parallel assignment (extra segments, if
    /// any, are silently dropped upstream too).
    fn bl_method_or_receiver_excluded(&self, call: &ruby_prism::CallNode, combined: &[String]) -> bool {
        let node_method = call.name().as_slice();
        let node_receiver: Option<Vec<u8>> = call.receiver().map(|r| {
            let l = r.location();
            self.src[l.start_offset()..l.end_offset()].iter().copied().filter(|b| !b.is_ascii_whitespace()).collect()
        });
        combined.iter().any(|config| {
            let parts: Vec<&str> = config.split('.').collect();
            if parts.len() >= 2 {
                node_method == parts[1].as_bytes() && node_receiver.as_deref() == Some(parts[0].as_bytes())
            } else {
                node_method == config.as_bytes()
            }
        })
    }

    /// `Metrics/BlockLength#on_block` (aliased `on_numblock`/`on_itblock`).
    /// `call` is the `CallNode` this block is attached to — never reached for
    /// a `&:sym` block-PASS argument, which prism never turns into a
    /// `BlockNode` at all (so no `check_block_length` call site ever sees
    /// one; nothing to guard against here).
    pub(crate) fn check_block_length(&mut self, call: &ruby_prism::CallNode, block: &ruby_prism::BlockNode) {
        const COP: &str = "Metrics/BlockLength";
        if !self.on(COP) {
            return;
        }
        if self.bl_matches_pattern(COP, call.name().as_slice()) {
            return;
        }
        let combined = self.bl_allowed_methods(COP);
        if self.bl_method_or_receiver_excluded(call, &combined) {
            return;
        }
        // `node.class_constructor?`: checking the underlying `send` shape
        // (receiver + method name, any args) is equivalent to checking it on
        // the wrapping `any_block` node upstream — the block-node alternative
        // of that node-pattern is satisfied by exactly the same send shape,
        // regardless of the block's own contents.
        if super::lint_cops::is_class_constructor(call, self.src) {
            return;
        }
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = match block.body() {
            Some(b) => self.ml_method_body_length(&b, count_comments),
            None => 0,
        };
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_block_node(&mut walker, block);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Block has too many lines. [{length}/{max}]");
            // `CodeLength#location`'s non-LSP branch is the node's full
            // `source_range` — for a block, that starts at the RECEIVER
            // (verified live against rubocop: `Foo::Bar.bar do ... end`
            // anchors at column 1, the `F` of `Foo`, not the `bar` selector),
            // falling back to the selector itself when there's no receiver.
            let anchor = call
                .receiver()
                .map(|r| r.location().start_offset())
                .or_else(|| call.message_loc().map(|m| m.start_offset()))
                .unwrap_or_else(|| call.location().start_offset());
            self.push(anchor, COP, false, msg);
        }
    }
}


// ---------------------------------------------------------------------------
// Metrics/ClassLength — reuses the `ml_*` `CodeLengthCalculator` port above
// (already generic over `class`/`module`) plus a real `class`/`class << self`
// entry point and the `Foo = Class.new do ... end` / `Foo = Struct.new(...)
// do ... end` casgn form (`class_definition?`'s `any_block` branch).
//
// Unlike `Metrics::ModuleLength#on_casgn` (which node-matches only a plain,
// unnested `(casgn nil? _ (any_block (send Module :new) ...))` and calls
// `check_code_length` on the CASGN node itself, anchoring at `node.loc.name`),
// `ClassLength#on_casgn` re-derives the block via `find_expression_within_
// parent` and calls `check_code_length` on the BLOCK itself — so it reaches
// (and anchors on the block's own full source range, not the constant name)
// through every constant-assignment SHAPE: plain `=` (including chained
// `Foo = Bar = Class.new do ... end`, resolved via recursion into the
// INNERMOST link — the outer link's own value is another assignment node,
// never a block, so only the innermost one matches), `||=`/`&&=`, `Foo::Bar
// = ...`, and multiple assignment (`Foo, Bar = Struct.new(...) do ... end`,
// upstream re-derives the SAME block once per mlhs target and relies on
// `add_offense` deduplicating identical location+message; we just check the
// masgn's value once directly for the same result).
//
// Also unlike `module_definition?` (Module.new, no args, per this file's
// `ml_module_new_block`), `class_definition?` allows ANY argument count on
// the `.new` call — required for `Struct.new(:foo, :bar) do ... end`.
//
// Known gaps (none exercised by the spec fixture):
//  - `Data.define do ... end` is NOT part of `class_definition?` (verified
//    against rubocop-ast 1.49.1's own node pattern: only `Struct`/`Class`) —
//    `Foo = Data.define do ... end` is correctly never checked, matching
//    upstream.
//  - Same `omit_length`/heredoc-body gaps as `Metrics/ModuleLength` (see
//    that section's doc comment) apply identically here.
// ---------------------------------------------------------------------------

/// `class_definition?`'s `any_block` branch: `(any_block (send
/// #global_const?({:Struct :Class}) :new ...) _ $_)` — bare or
/// `::`-qualified `Class`/`Struct` receiver, `new` message, ANY argument
/// count, followed by a literal block (do/end or `{}`; a block-PASS isn't
/// this shape at all, matching `ml_module_new_block`'s same distinction).
/// Returns the CALL node alongside the block: rubocop's whitequark `:block`
/// node (what `class_definition?` actually matches and what `check_code_
/// length`'s `else`-branch `node.source_range` anchors on) spans from the
/// call's own start — prism's own `BlockNode::location` starts at the
/// opening `do`/`{` instead (the documented prism-vs-whitequark block-range
/// trap), so the anchor must come from the call, not the block.
fn cl_class_new_block<'pr>(
    value: &ruby_prism::Node<'pr>,
) -> Option<(ruby_prism::CallNode<'pr>, ruby_prism::BlockNode<'pr>)> {
    let call = value.as_call_node()?;
    if call.name().as_slice() != b"new" {
        return None;
    }
    let recv = call.receiver()?;
    let is_class_or_struct = |name: &[u8]| name == b"Class" || name == b"Struct";
    let ok = recv.as_constant_read_node().is_some_and(|c| is_class_or_struct(c.location().as_slice()))
        || recv
            .as_constant_path_node()
            .is_some_and(|cp| cp.parent().is_none() && is_class_or_struct(cp.name_loc().as_slice()));
    if !ok {
        return None;
    }
    let block = call.block()?.as_block_node()?;
    Some((call, block))
}

impl<'a> Cops<'a> {
    /// `on_class` — a real `class Foo ... end` definition. `ml_classlike_length`
    /// is already generic over `class`/`module` (the `namespace_module?`/
    /// inner-classlike-exclusion logic keys on either type).
    pub(crate) fn check_class_length_class(&mut self, node: &ruby_prism::ClassNode) {
        const COP: &str = "Metrics/ClassLength";
        if !self.on(COP) {
            return;
        }
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = self.ml_classlike_length(&node.as_node(), count_comments);
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_class_node(&mut walker, node);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Class has too many lines. [{length}/{max}]");
            self.push(node.location().start_offset(), COP, false, msg);
        }
    }

    /// `on_sclass`, guarded by `node.each_ancestor(:class).any?` (skip when
    /// already nested inside a REAL `class` — its lines are already counted
    /// as part of that enclosing class's own length via the plain interior-
    /// line walk; see `cl_class_depth`'s field doc). Unlike `class`/`module`,
    /// `sclass` is NOT one of `CodeLengthCalculator::CLASSLIKE_TYPES`
    /// (`class`/`module` only) — upstream's `code_length` takes the plain
    /// `extract_body` branch for it (`body.source.lines`, counted as-is, with
    /// NO nested-class-line exclusion — verified against real rubocop 1.88:
    /// a top-level `class << self` containing a nested `class` counts that
    /// nested class's lines for BOTH the outer sclass's total and the inner
    /// class's own separate offense). Matches `ml_node_own_length` on the
    /// sclass's own body node, exactly like the casgn/`Class.new` form below.
    pub(crate) fn check_class_length_sclass(&mut self, node: &ruby_prism::SingletonClassNode) {
        const COP: &str = "Metrics/ClassLength";
        if !self.on(COP) || self.cl_class_depth > 0 {
            return;
        }
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = match node.body() {
            Some(b) => self.ml_method_body_length(&b, count_comments),
            None => 0,
        };
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_singleton_class_node(&mut walker, node);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Class has too many lines. [{length}/{max}]");
            self.push(node.location().start_offset(), COP, false, msg);
        }
    }

    /// `on_casgn`'s `class_definition?`-guarded branch, called from every
    /// constant-assignment write-node hook in `mod.rs` with that node's own
    /// RHS `value()` — see this section's module doc comment for how that
    /// covers every shape upstream's `find_expression_within_parent` chases
    /// down manually. Anchored on the BLOCK's own full source range
    /// (`CodeLength#location`'s non-casgn `else` branch — the node actually
    /// passed to `check_code_length` upstream is the `any_block`, which is
    /// never casgn-shaped, so it never takes the `node.loc.name` branch).
    pub(crate) fn check_class_length_casgn(&mut self, value: &ruby_prism::Node) {
        const COP: &str = "Metrics/ClassLength";
        if !self.on(COP) {
            return;
        }
        let Some((call, block)) = cl_class_new_block(value) else { return };
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = match block.body() {
            Some(b) => self.ml_method_body_length(&b, count_comments),
            None => 0,
        };
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_block_node(&mut walker, &block);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Class has too many lines. [{length}/{max}]");
            self.push(call.location().start_offset(), COP, false, msg);
        }
    }
}


// ---------------------------------------------------------------------------
// Metrics/BlockNesting: a full-file recursive walk from `on_new_investigation`
// ---------------------------------------------------------------------------
//
// Unlike the per-`def` cops above, rubocop's `check_nesting_level` walks the
// ENTIRE file once from `processed_source.ast`, threading a `current_level`
// counter through EVERY node — defs/classes DON'T reset it, so nesting depth
// is continuous across method/class boundaries. Only `NESTING_BLOCKS` types
// increment the level: `if`/`unless`/ternary (whitequark's unified `:if`
// type), `case`, `case`/`in`, `while`/`until` (including the post-condition
// `begin...end while`/`until` form — always counted, unlike
// `CyclomaticComplexity`'s COUNTED_NODES which excludes it), `for`, and each
// INDIVIDUAL `rescue` clause (`:resbody` — never the whole `:rescue`/`begin`
// construct). When `CountBlocks` is set, any literal block (`do...end`/`{}`,
// including numbered-param/`it`-param and lambda-literal forms — but NOT a
// `&:sym`/`&blk` block-PASS argument) also increments.
//
// `elsif` nodes "consider" (they still match `:if`) but never themselves
// increment (`count_if_block?`'s `node.elsif?` guard) — detected the same way
// `ComplexityCounter` distinguishes ternaries above: `if_keyword_loc`'s slice.
// Modifier `if`/`unless` only increment when `CountModifierForms` is set;
// modifier `while`/`until`/ternary `if` always increment regardless (only
// `if`/`unless` STATEMENT forms are gated by `count_if_block?`).
//
// Once a node is flagged, rubocop's `ignore_node` suppresses any FURTHER
// offense whose source range is CONTAINED WITHIN it (`part_of_ignored_node?`)
// — a violating outer node swallows violations nested inside it, but never a
// sibling at the same depth. Multiple `rescue` clauses in one chain are true
// AST siblings (evaluated at the SAME level) in rubocop's whitequark AST —
// `visit_rescue_node` below threads the pre-increment `saved` level to
// `.subsequent()`, not the incremented one used for THIS clause's own body,
// to replicate that sibling (not nested) relationship.
struct BlockNestingWalker {
    level: i32,
    max: i32,
    count_blocks: bool,
    count_modifier_forms: bool,
    ignored: Vec<(usize, usize)>,
    offenses: Vec<usize>,
}

impl BlockNestingWalker {
    fn new(max: i32, count_blocks: bool, count_modifier_forms: bool) -> Self {
        BlockNestingWalker { level: 0, max, count_blocks, count_modifier_forms, ignored: Vec::new(), offenses: Vec::new() }
    }

    /// `part_of_ignored_node?`: is `[start, end)` contained within a range
    /// already flagged (and hence `ignore_node`-registered)?
    fn part_of_ignored(&self, start: usize, end: usize) -> bool {
        self.ignored.iter().any(|&(b, e)| b <= start && e >= end)
    }

    fn check(&mut self, start: usize, end: usize) {
        if self.level > self.max && !self.part_of_ignored(start, end) {
            self.offenses.push(start);
            self.ignored.push((start, end));
        }
    }
}

impl<'pr> Visit<'pr> for BlockNestingWalker {
    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        let is_ternary = node.if_keyword_loc().is_none();
        let is_elsif = node.if_keyword_loc().is_some_and(|l| l.as_slice() == b"elsif");
        let is_modifier = !is_ternary && !is_elsif && node.end_keyword_loc().is_none();
        let increment = if is_elsif { false } else if is_modifier { self.count_modifier_forms } else { true };
        let saved = self.level;
        if increment {
            self.level += 1;
        }
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_if_node(self, node);
        self.level = saved;
    }

    fn visit_unless_node(&mut self, node: &ruby_prism::UnlessNode<'pr>) {
        let is_modifier = node.end_keyword_loc().is_none();
        let increment = if is_modifier { self.count_modifier_forms } else { true };
        let saved = self.level;
        if increment {
            self.level += 1;
        }
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_unless_node(self, node);
        self.level = saved;
    }

    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        let saved = self.level;
        self.level += 1;
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_while_node(self, node);
        self.level = saved;
    }

    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        let saved = self.level;
        self.level += 1;
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_until_node(self, node);
        self.level = saved;
    }

    fn visit_case_node(&mut self, node: &ruby_prism::CaseNode<'pr>) {
        let saved = self.level;
        self.level += 1;
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_case_node(self, node);
        self.level = saved;
    }

    fn visit_case_match_node(&mut self, node: &ruby_prism::CaseMatchNode<'pr>) {
        let saved = self.level;
        self.level += 1;
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_case_match_node(self, node);
        self.level = saved;
    }

    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        let saved = self.level;
        self.level += 1;
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        ruby_prism::visit_for_node(self, node);
        self.level = saved;
    }

    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        let saved = self.level;
        self.level = saved + 1;
        let loc = node.location();
        self.check(loc.start_offset(), loc.end_offset());
        for exc in node.exceptions().iter() {
            self.visit(&exc);
        }
        if let Some(r) = node.reference() {
            self.visit(&r);
        }
        if let Some(s) = node.statements() {
            self.visit_statements_node(&s);
        }
        self.level = saved;
        // Sibling `rescue` clauses share the SAME ambient level — recurse at
        // `saved`, not the incremented level used for this clause's own body.
        if let Some(sub) = node.subsequent() {
            self.visit_rescue_node(&sub);
        }
    }

    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        let literal_block = self.count_blocks && node.block().is_some_and(|b| b.as_block_node().is_some());
        if literal_block {
            let saved = self.level;
            self.level += 1;
            let loc = node.location();
            self.check(loc.start_offset(), loc.end_offset());
            ruby_prism::visit_call_node(self, node);
            self.level = saved;
        } else {
            ruby_prism::visit_call_node(self, node);
        }
    }

    fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
        let literal_block = self.count_blocks && node.block().is_some_and(|b| b.as_block_node().is_some());
        if literal_block {
            let saved = self.level;
            self.level += 1;
            let loc = node.location();
            self.check(loc.start_offset(), loc.end_offset());
            ruby_prism::visit_super_node(self, node);
            self.level = saved;
        } else {
            ruby_prism::visit_super_node(self, node);
        }
    }

    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        if self.count_blocks && node.block().is_some() {
            let saved = self.level;
            self.level += 1;
            let loc = node.location();
            self.check(loc.start_offset(), loc.end_offset());
            ruby_prism::visit_forwarding_super_node(self, node);
            self.level = saved;
        } else {
            ruby_prism::visit_forwarding_super_node(self, node);
        }
    }

    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        if self.count_blocks {
            let saved = self.level;
            self.level += 1;
            let loc = node.location();
            self.check(loc.start_offset(), loc.end_offset());
            ruby_prism::visit_lambda_node(self, node);
            self.level = saved;
        } else {
            ruby_prism::visit_lambda_node(self, node);
        }
    }
}

impl<'a> Cops<'a> {
    /// `on_new_investigation`: one whole-file walk from `processed_source.ast`
    /// (see `BlockNestingWalker`'s doc comment above for the full model).
    pub(crate) fn check_block_nesting(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Metrics/BlockNesting";
        if !self.on(COP) {
            return;
        }
        let max: i32 = self.cfg.get(COP, "Max").and_then(|v| v.parse().ok()).unwrap_or(3);
        let count_blocks = self.cfg.get(COP, "CountBlocks") == Some("true");
        let count_modifier_forms = self.cfg.get(COP, "CountModifierForms") == Some("true");
        let mut walker = BlockNestingWalker::new(max, count_blocks, count_modifier_forms);
        walker.visit_statements_node(&node.statements());
        let msg = format!("Avoid more than {max} levels of block nesting.");
        for start in walker.offenses {
            self.push(start, COP, false, msg.clone());
        }
    }
}


// ---------------------------------------------------------------------------
// Metrics/MethodLength — reuses the same `CodeLength`-mixin port as
// `Metrics/ModuleLength` above (`ml_*` helpers, `MlFoldableTypes`,
// `MlFoldWalker`, `ml_apply_folding`, `ml_irrelevant_file_line`), but hits
// `CodeLengthCalculator#code_length`'s NON-classlike branch: `def`/`defs`
// (one `DefNode` type either way in prism) and `define_method(...) do ...
// end` blocks (`on_block`/`on_numblock`/`on_itblock` — numbered-parameter
// and `it`-parameter blocks stay the same `BlockNode` shape in prism).
//
// Known gaps (none exercised by the spec fixture):
//  - `omit_length` (bare-hash-argument method-call folding correction) isn't
//    replicated — same gap as noted above `Metrics::ModuleLength`.
//  - An endless `def`/block whose ENTIRE body is one bare heredoc (no
//    wrapping `StatementsNode` for `node_with_heredoc?`'s
//    `each_descendant` — which never tests `node` itself — to find) falls
//    through to the plain `body.source.lines` branch and undercounts,
//    mirroring `ModuleLength`'s equivalent unreplicated
//    `source_from_node_with_heredoc` gap for a classlike/casgn body.
//  - `MlFoldWalker` (shared, unmodified, with `Metrics::ModuleLength` above)
//    folds a call THAT HAS ITS OWN LITERAL BLOCK attached (`foo(...) do
//    ... end`) as one unit spanning through that block's `end`/`}` when
//    `CountAsOne` includes `method_call` — verified directly against real
//    rubocop to be WRONG whenever the call's own head (receiver/args, i.e.
//    what whitequark treats as the separate `send_node` child of its own
//    composite `:block` node) spans a different line count than prism's
//    block-inclusive `CallNode::location()`. Upstream independently
//    re-tests/re-folds the send head AND the block's body as two unrelated
//    top-level children; prism's single fused `CallNode` (whose own
//    `location()` already reaches through the block) has no clean
//    equivalent split without a bespoke helper, so this is left as a
//    latent gap shared with `ModuleLength` rather than patched here. Only
//    matters for `CountAsOne: [method_call]` combined with a call-with-block
//    appearing anywhere in the measured span; harmless (no-op) whenever
//    that call's own head is single-line, which is the overwhelmingly
//    common case (e.g. plain `define_method(:m) do ... end`).
// ---------------------------------------------------------------------------

/// `CodeLengthCalculator#node_with_heredoc?`'s own narrow
/// `each_descendant(:str, :dstr)` filter — a heredoc `xstr`/`` `cmd` ``
/// node alone does NOT gate this branch, even though it's still
/// `heredoc_node?` true once inside it (see `MlHeredocEndScanner`, which
/// upstream's own `each_descendant` walk — no type filter there — would
/// also pick up). Never tests the root node itself (`each_descendant`
/// excludes self).
struct MlPlainHeredocGate {
    is_root: bool,
    found: bool,
}
impl<'pr> Visit<'pr> for MlPlainHeredocGate {
    fn visit_branch_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.check(&node);
    }
    fn visit_leaf_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.check(&node);
    }
}
impl MlPlainHeredocGate {
    fn check(&mut self, node: &ruby_prism::Node) {
        if std::mem::replace(&mut self.is_root, false) || self.found {
            return;
        }
        let is_plain_str = node.as_string_node().is_some() || node.as_interpolated_string_node().is_some();
        if is_plain_str && super::breakable::is_heredoc_node(node) {
            self.found = true;
        }
    }
}

/// `CodeLengthCalculator#source_from_node_with_heredoc`'s
/// `node.each_descendant { |d| ... }` max-last-line scan — driven by the
/// generic `visit_branch_node_enter`/`visit_leaf_node_enter` hooks (fired
/// for literally every node, branch or leaf, ahead of the type-specific
/// dispatch) so no per-type override list is needed. `each_descendant`
/// excludes the root itself, and that exclusion is NOT just pedantry here:
/// when `body` is the implicit rescue/ensure `BeginNode`, its own
/// `location()` extends through the enclosing `def`'s/block's own `end`
/// keyword (see `ml_begin_node_content_start`'s doc comment) — a bogus
/// candidate that would inflate, not just harmlessly duplicate, the max.
struct MlHeredocEndScanner<'i> {
    idx: &'i LineIndex,
    is_root: bool,
    max_line: usize,
}
impl<'i, 'pr> Visit<'pr> for MlHeredocEndScanner<'i> {
    fn visit_branch_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.record(&node);
    }
    fn visit_leaf_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.record(&node);
    }
}
impl<'i> MlHeredocEndScanner<'i> {
    fn record(&mut self, node: &ruby_prism::Node) {
        if std::mem::replace(&mut self.is_root, false) {
            return;
        }
        // A prism BlockNode spans through its `end`, but its whitequark
        // counterparts (the block's args + body, visited as children) stop
        // earlier — the enclosing CallNode already carries the full span
        // when the block-call is itself a descendant, so recording the
        // BlockNode would leak the `end` line when the block-call is the
        // (excluded) root.
        if node.as_block_node().is_some() {
            return;
        }
        // An `elsif` IfNode (and an ElseNode) in prism spans through the
        // chain's SHARED `end` keyword; the whitequark counterparts stop at
        // their branch content. Skip them — their children (predicate,
        // statements, deeper elsifs) are visited normally and cover exactly
        // the whitequark extent. A standalone `if` still records its own
        // span (whitequark includes its `end` there too).
        if node
            .as_if_node()
            .is_some_and(|n| n.if_keyword_loc().is_some_and(|k| k.as_slice() == b"elsif"))
            || node.as_else_node().is_some()
        {
            return;
        }
        // Same trap as def-with-rescue: prism's implicit BeginNode spans
        // through the OWNING construct's `end` keyword; whitequark's
        // rescue/ensure wrappers stop at their content. Record the content
        // end instead (children still visited normally).
        if let Some(b) = node.as_begin_node() {
            // Only the IMPLICIT wrapper (no `begin` keyword) needs the
            // content-end treatment; an explicit kwbegin spans through its
            // own `end` in whitequark too.
            if b.begin_keyword_loc().is_none() {
                let line = self.idx.loc(ml_begin_node_content_end(&b).saturating_sub(1)).0;
                if line > self.max_line {
                    self.max_line = line;
                }
                return;
            }
        }
        let line = if super::breakable::is_heredoc_node(node) {
            let closing = if let Some(n) = node.as_string_node() {
                n.closing_loc()
            } else if let Some(n) = node.as_interpolated_string_node() {
                n.closing_loc()
            } else if let Some(n) = node.as_x_string_node() {
                Some(n.closing_loc())
            } else if let Some(n) = node.as_interpolated_x_string_node() {
                Some(n.closing_loc())
            } else {
                None
            };
            match closing {
                Some(c) => self.idx.loc(c.start_offset()).0,
                None => self.idx.loc(node.location().end_offset().saturating_sub(1)).0,
            }
        } else {
            self.idx.loc(node.location().end_offset().saturating_sub(1)).0
        };
        if line > self.max_line {
            self.max_line = line;
        }
    }
}

/// Where a `def`/block body's implicit rescue/ensure `BeginNode` content
/// ends — mirrors whitequark's rescue/ensure wrapper ranges (ensure body,
/// else else-body, else last rescue clause, else plain statements) instead
/// of prism's own `BeginNode::location()`, which extends through the
/// enclosing `def`'s/block's own `end` keyword (a documented
/// prism-vs-whitequark trap: never use a def-with-rescue/ensure body's
/// location END as "content end"). A near-duplicate of
/// `style::begin_node_content_end` kept local to this dept file rather than
/// shared across dept files.
fn ml_begin_node_content_end(b: &ruby_prism::BeginNode) -> usize {
    if let Some(ens) = b.ensure_clause() {
        return match ens.statements() {
            Some(stmts) => stmts.location().end_offset(),
            None => ens.ensure_keyword_loc().end_offset(),
        };
    }
    if let Some(els) = b.else_clause() {
        return match els.statements() {
            Some(stmts) => stmts.location().end_offset(),
            None => els.else_keyword_loc().end_offset(),
        };
    }
    if let Some(mut resc) = b.rescue_clause() {
        while let Some(next) = resc.subsequent() {
            resc = next;
        }
        return match resc.statements() {
            Some(stmts) => stmts.location().end_offset(),
            None => resc.location().end_offset(),
        };
    }
    match b.statements() {
        Some(stmts) => stmts.location().end_offset(),
        None => b.location().end_offset(),
    }
}

/// Where a `def`/block body's implicit rescue/ensure `BeginNode` content
/// STARTS — the symmetric counterpart to `ml_begin_node_content_end`, and
/// just as necessary: prism gives this synthetic (no explicit `begin`
/// keyword) `BeginNode` the exact SAME `location()` as the enclosing
/// `def`/block itself (verified directly against `ruby-prism`: for `def
/// foo\n  a = 1\nrescue\n  a = 2\nend`, the body `BeginNode`'s `location()`
/// starts at byte 0 — the `def` keyword — not at `a = 1`), so its start
/// offset is exactly as unusable as its end offset. Whitequark's own
/// rescue/ensure-wrapper node instead starts at the first REAL clause: the
/// leading (pre-rescue) statements if any, else the first `rescue`, else
/// (only reachable if a rescue-less body somehow still parses an `else`)
/// the `else`, else `ensure` alone.
fn ml_begin_node_content_start(b: &ruby_prism::BeginNode) -> usize {
    if let Some(stmts) = b.statements() {
        return stmts.location().start_offset();
    }
    if let Some(resc) = b.rescue_clause() {
        return resc.location().start_offset();
    }
    if let Some(els) = b.else_clause() {
        return els.location().start_offset();
    }
    if let Some(ens) = b.ensure_clause() {
        return ens.location().start_offset();
    }
    b.location().start_offset()
}

/// Resolves a `def`/block body's true content start, correcting for the
/// implicit-`BeginNode` trap `ml_begin_node_content_start` documents.
fn ml_body_content_start(body: &ruby_prism::Node) -> usize {
    match body.as_begin_node() {
        Some(b) => ml_begin_node_content_start(&b),
        None => body.location().start_offset(),
    }
}

/// `method_name.basic_literal?`'s extraction of `method_name.value`,
/// restricted to what `define_method`'s first argument realistically is: a
/// plain (non-interpolated) `:sym` or `str` literal. `basic_literal?` is
/// FALSE for `dsym`/`dstr` (any real `#{}` interpolation) and everything
/// else, so those never consult the allow-list at all — `None` here means
/// exactly that "always proceed to check_code_length" case.
fn ml_basic_literal_value(node: &ruby_prism::Node) -> Option<Vec<u8>> {
    if let Some(sym) = node.as_symbol_node() {
        Some(sym.unescaped().to_vec())
    } else if let Some(s) = node.as_string_node() {
        Some(s.unescaped().to_vec())
    } else {
        None
    }
}

impl<'a> Cops<'a> {
    /// `CodeLengthCalculator#code_length`'s non-classlike/non-heredoc `else`
    /// branch, restricted to what a `def`/`defs`/`block`/`numblock`/
    /// `itblock`'s OWN body (`extract_body` already unwrapped `node` down to
    /// `body` before this runs) can be: `body.source.lines` counted via
    /// `irrelevant_line?`, EXCEPT when `body` contains a plain `str`/`dstr`
    /// heredoc descendant — then rubocop widens the counted range to raw
    /// file lines from `body`'s own first line through the true max end
    /// line (`source_from_node_with_heredoc`), since a heredoc node's own
    /// `source_range`/`location()` stops at its opener token and would
    /// otherwise silently drop the heredoc's body/closing-delimiter lines.
    fn ml_method_body_length(&self, body: &ruby_prism::Node, count_comments: bool) -> i64 {
        let mut gate = MlPlainHeredocGate { is_root: true, found: false };
        gate.visit(body);
        let start = ml_body_content_start(body);
        if gate.found {
            let first_line = self.idx.loc(start).0;
            let mut scanner = MlHeredocEndScanner { idx: self.idx, is_root: true, max_line: first_line };
            // `source_from_node_with_heredoc` takes the max over DESCENDANTS
            // only — the body node itself never contributes its own last
            // line. Whitequark's unwrapped single-statement body (a do-block
            // spanning the whole def) is therefore excluded, so a prism
            // StatementsNode with ONE child must scan from that child as the
            // root, or the block's own `end` line leaks into the count
            // (rails releaser_test.rb: 20 vs upstream's 19).
            let sole = body
                .as_statements_node()
                .and_then(|st| {
                    let mut it = st.body().iter();
                    let first = it.next();
                    if it.next().is_none() { first } else { None }
                });
            match sole {
                Some(child) => scanner.visit(&child),
                None => scanner.visit(body),
            }
            let mut length = 0i64;
            for line in first_line..=scanner.max_line {
                if !self.ml_irrelevant_file_line(line, count_comments) {
                    length += 1;
                }
            }
            length
        } else {
            let end = match body.as_begin_node() {
                Some(b) => ml_begin_node_content_end(&b),
                None => body.location().end_offset(),
            };
            if end > start { ml_count_text_fragment(&self.src[start..end], count_comments) } else { 0 }
        }
    }

    /// `on_def`/`on_defs` — prism gives both the same `DefNode` shape, so
    /// there's nothing to distinguish; `allowed?(node.method_name)` is
    /// `AllowedMethods`/`AllowedPatterns`, already generalized as `self.allowed`.
    pub(crate) fn check_method_length_def(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Metrics/MethodLength";
        if !self.on(COP) {
            return;
        }
        if self.allowed(COP, node.name().as_slice()) {
            return;
        }
        let Some(body) = node.body() else { return };
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = self.ml_method_body_length(&body, count_comments);
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            ruby_prism::visit_def_node(&mut walker, node);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Method has too many lines. [{length}/{max}]");
            self.push(node.location().start_offset(), COP, false, msg);
        }
    }

    /// `on_block`/`on_numblock`/`on_itblock` guarded by
    /// `node.method?(:define_method)` — rubocop-ast's `method?` only
    /// compares `method_name`, so (unlike
    /// `check_metrics_complexity_define_method`'s stricter receiverless
    /// `define_method?` node-pattern) this fires for ANY call literally
    /// named `define_method`, receiver or not.
    pub(crate) fn check_method_length_block(&mut self, call: &ruby_prism::CallNode, block: &ruby_prism::BlockNode) {
        const COP: &str = "Metrics/MethodLength";
        if !self.on(COP) {
            return;
        }
        if call.name().as_slice() != b"define_method" {
            return;
        }
        // `method_name = node.send_node.first_argument; return if
        // method_name.basic_literal? && allowed?(method_name.value)`.
        if let Some(arg) = call.arguments().and_then(|a| a.arguments().iter().next()) {
            if let Some(value) = ml_basic_literal_value(&arg) {
                if self.allowed(COP, &value) {
                    return;
                }
            }
        }
        let Some(body) = block.body() else { return };
        let (max, count_comments, foldable) = self.ml_config(COP);
        let mut length = self.ml_method_body_length(&body, count_comments);
        if foldable.any() {
            let mut walker = MlFoldWalker { foldable, matches: Vec::new() };
            // Walk from the CALL, not just the block — whitequark's `:block`
            // node has THREE direct children (send, args, body), and
            // `each_top_level_descendant` starts from all of them; anchoring
            // the fold-walk on `call` (via `visit_call_node`'s default walk:
            // receiver, arguments, then the block itself) reaches all three
            // — correctly for array/hash/heredoc folds found among the
            // call's own arguments, but see the module-level doc comment
            // for the `method_call`-folds-the-whole-call-plus-block gap this
            // shares with `ModuleLength`.
            ruby_prism::visit_call_node(&mut walker, call);
            length = self.ml_apply_folding(length, walker.matches, count_comments);
        }
        if length > max {
            let msg = format!("Method has too many lines. [{length}/{max}]");
            // rubocop's own `:block` node range spans from the CALL's start
            // through the block's `end`/`}` (see `ModuleLength`'s sibling
            // comment on the same prism-vs-whitequark trap for
            // `check_metrics_complexity_define_method`) — anchor on the call.
            self.push(call.location().start_offset(), COP, false, msg);
        }
    }
}
