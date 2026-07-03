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
