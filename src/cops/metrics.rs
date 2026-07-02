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
//! Known gaps (none exercised by the spec fixture): `AbcSize`'s "compound
//! assignment" bean-counting for `masgn`/`op_asgn`/`or_asgn`/`and_asgn` LHS
//! shapes (rubocop's `compound_assignment`) is not replicated — those nodes
//! still contribute their `or`/`and`-family COUNTED_NODES condition point,
//! but never an assignment point. `RepeatedAttributeDiscount`'s invalidation
//! on reassignment (`update_repeated_attribute`) is not replicated either —
//! our attribute trie only grows, it never forgets an attribute after
//! `self.foo = x`.
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
    let sci = format!("{:.*e}", prec - 1, value);
    let epos = sci.find('e').expect("scientific notation always has an exponent");
    let exp: i32 = sci[epos + 1..].parse().expect("valid exponent digits");
    if exp < -4 || exp >= prec as i32 {
        let mantissa = sci[..epos].trim_end_matches('0').trim_end_matches('.');
        format!("{mantissa}e{}{:02}", if exp >= 0 { "+" } else { "-" }, exp.abs())
    } else {
        let decimals = (prec as i32 - 1 - exp).max(0) as usize;
        let fixed = format!("{value:.decimals$}");
        if fixed.contains('.') {
            fixed.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            fixed
        }
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
        self.score += 1;
        ruby_prism::visit_while_node(self, node);
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_until_node(self, node);
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_for_node(self, node);
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_rescue_node(self, node);
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
            let is_block = b.as_block_node().is_some() || b.as_block_argument_node().is_some();
            if is_block && is_known_iterating_method(node.name().as_slice()) {
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
        self.score += 1;
        ruby_prism::visit_local_variable_and_write_node(self, node);
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        self.score += 1;
        ruby_prism::visit_local_variable_or_write_node(self, node);
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
}

impl<'pr> AbcCounter<'pr> {
    fn new(discount_attrs: bool) -> Self {
        AbcCounter {
            assignment: 0,
            branch: 0,
            condition: 0,
            repeated_csend: HashSet::new(),
            discount_attrs,
            attr_roots: HashMap::new(),
        }
    }

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
        self.condition += 1;
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        ruby_prism::visit_until_node(self, node);
        self.condition += 1;
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        ruby_prism::visit_for_node(self, node);
        self.condition += 1;
        self.assignment += 1; // `node.for_type?` short-circuits `assignment?`
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        ruby_prism::visit_rescue_node(self, node);
        self.condition += 1;
    }
    fn visit_when_node(&mut self, node: &ruby_prism::WhenNode<'pr>) {
        ruby_prism::visit_when_node(self, node);
        self.condition += 1;
    }
    fn visit_in_node(&mut self, node: &ruby_prism::InNode<'pr>) {
        ruby_prism::visit_in_node(self, node);
        self.condition += 1;
    }
    fn visit_and_node(&mut self, node: &ruby_prism::AndNode<'pr>) {
        ruby_prism::visit_and_node(self, node);
        self.condition += 1;
    }
    fn visit_or_node(&mut self, node: &ruby_prism::OrNode<'pr>) {
        ruby_prism::visit_or_node(self, node);
        self.condition += 1;
    }
    fn visit_call_and_write_node(&mut self, node: &ruby_prism::CallAndWriteNode<'pr>) {
        ruby_prism::visit_call_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_call_or_write_node(&mut self, node: &ruby_prism::CallOrWriteNode<'pr>) {
        ruby_prism::visit_call_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_class_variable_and_write_node(&mut self, node: &ruby_prism::ClassVariableAndWriteNode<'pr>) {
        ruby_prism::visit_class_variable_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_class_variable_or_write_node(&mut self, node: &ruby_prism::ClassVariableOrWriteNode<'pr>) {
        ruby_prism::visit_class_variable_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_constant_and_write_node(&mut self, node: &ruby_prism::ConstantAndWriteNode<'pr>) {
        ruby_prism::visit_constant_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_constant_or_write_node(&mut self, node: &ruby_prism::ConstantOrWriteNode<'pr>) {
        ruby_prism::visit_constant_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_constant_path_and_write_node(&mut self, node: &ruby_prism::ConstantPathAndWriteNode<'pr>) {
        ruby_prism::visit_constant_path_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_constant_path_or_write_node(&mut self, node: &ruby_prism::ConstantPathOrWriteNode<'pr>) {
        ruby_prism::visit_constant_path_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_global_variable_and_write_node(&mut self, node: &ruby_prism::GlobalVariableAndWriteNode<'pr>) {
        ruby_prism::visit_global_variable_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_global_variable_or_write_node(&mut self, node: &ruby_prism::GlobalVariableOrWriteNode<'pr>) {
        ruby_prism::visit_global_variable_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_index_and_write_node(&mut self, node: &ruby_prism::IndexAndWriteNode<'pr>) {
        ruby_prism::visit_index_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_index_or_write_node(&mut self, node: &ruby_prism::IndexOrWriteNode<'pr>) {
        ruby_prism::visit_index_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_instance_variable_and_write_node(&mut self, node: &ruby_prism::InstanceVariableAndWriteNode<'pr>) {
        ruby_prism::visit_instance_variable_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_instance_variable_or_write_node(&mut self, node: &ruby_prism::InstanceVariableOrWriteNode<'pr>) {
        ruby_prism::visit_instance_variable_or_write_node(self, node);
        self.condition += 1;
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        ruby_prism::visit_local_variable_and_write_node(self, node);
        self.condition += 1;
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        ruby_prism::visit_local_variable_or_write_node(self, node);
        self.condition += 1;
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
            let is_block = b.as_block_node().is_some() || b.as_block_argument_node().is_some();
            if is_block && is_known_iterating_method(node.name().as_slice()) {
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
