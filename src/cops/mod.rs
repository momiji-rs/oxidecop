//! The cop engine: the `Cops` visitor (shared state + cross-cutting helpers),
//! a THIN `Visit` impl that dispatches into per-department modules
//! (`style`/`naming`/`lint`/`layout`), and the `lint()` entry point.
mod breakable;
mod bundler;
mod gemspec;
mod layout;
mod lint_cops;
mod metrics;
mod naming;
mod style;

use crate::config::{parse_allowed_list, Config, SCHEMA};
use crate::declarative::{render, Anchor, DECLARATIVE};
use crate::nodepattern::{self, Pat};
use ruby_prism::Visit;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// Nanosecond tallies per phase, summed across threads — printed by the
/// runner when OXIDECOP_TIMING is set. Loads/stores are relaxed; this is
/// diagnostics, not synchronization.
pub static T_PARSE: AtomicU64 = AtomicU64::new(0);
pub static T_PREP: AtomicU64 = AtomicU64::new(0);
pub static T_TEXT: AtomicU64 = AtomicU64::new(0);
pub static T_VISIT: AtomicU64 = AtomicU64::new(0);
pub static T_POST: AtomicU64 = AtomicU64::new(0);

fn tick(slot: &AtomicU64, since: std::time::Instant) -> std::time::Instant {
    let now = std::time::Instant::now();
    slot.fetch_add(now.duration_since(since).as_nanos() as u64, Ordering::Relaxed);
    now
}

pub struct Offense {
    pub line: usize,
    pub col: usize,
    pub cop: &'static str,
    pub correctable: bool,
    pub message: String,
}

pub struct LineIndex {
    pub(crate) starts: Vec<usize>,
}
impl LineIndex {
    pub fn new(src: &[u8]) -> Self {
        let mut starts = vec![0usize];
        for (i, &b) in src.iter().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineIndex { starts }
    }
    pub fn loc(&self, off: usize) -> (usize, usize) {
        let line = match self.starts.binary_search(&off) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (line + 1, off - self.starts[line] + 1)
    }
}

/// An autocorrect edit: (start_byte, end_byte, replacement).
pub type Fix = (usize, usize, Vec<u8>);

/// Lint/NonLocalExitFromIterator: a single frame of `nle_stack` — see the
/// field doc on `Cops::nle_stack` for what each variant means.
pub(crate) enum NleFrame {
    Def,
    Lambda,
    Block { has_args: bool, is_define_method: bool, chained: bool },
}

/// Style/ExplicitBlockArgument: the shape of a `yield`-only block's owning
/// call/super/zsuper site (the only three grammar positions a block can hang
/// off of), used to build the `add_block_argument` autocorrect at the call
/// site — see `Cops::eba_pending`'s doc.
pub(crate) enum EbaKind {
    /// Existing explicit argument(s) — `last_arg_end` is the last one's own
    /// end offset (extended rightward over a directly-adjacent trailing
    /// comma at use time, matching `range_with_surrounding_comma(:right)`).
    HasArgs { last_arg_end: usize },
    /// Explicit-but-empty parens, e.g. `foo()` / `super()` — `start`/`end`
    /// bracket the `(...)` text to be replaced outright.
    EmptyParens { start: usize, end: usize },
    /// No parens, no arguments at all: `foo { }`, bare `super { }`, or the
    /// bare zsuper `super { }` (flagged separately via `EbaOwner::is_zsuper`).
    Bare,
}
/// Style/ExplicitBlockArgument: everything `check_explicit_block_argument`
/// needs about the block's owning node, computed once (by
/// `style::eba_call_owner`/`eba_super_owner`/`eba_zsuper_owner`) right before
/// that owner's `self.visit(&block)` call.
pub(crate) struct EbaOwner {
    /// The offense anchor AND the block-removal's own highlighted start —
    /// prism's `CallNode`/`SuperNode#location` already spans receiver
    /// through the trailing block (unlike whitequark's `send_node`, which
    /// stops short of it), so this is simply the owner's own
    /// `location().start_offset()`.
    pub(crate) anchor: usize,
    /// This owner's own end offset EXCLUDING the block — where the block's
    /// source text (`block_body_range`) starts being removed, and (for
    /// `Bare`) also where the replacement `(&block)` text is inserted.
    pub(crate) call_end: usize,
    pub(crate) kind: EbaKind,
    /// Whether this owner is a bare zsuper (`super` with no parens/args at
    /// all) — its replacement must additionally forward the enclosing def's
    /// own parameters (`build_new_arguments_for_zsuper`).
    pub(crate) is_zsuper: bool,
}
/// Style/ExplicitBlockArgument: precomputed per-`def` facts, pushed on
/// `visit_def_node` entry and popped on exit — stands in for upstream's
/// parent-pointer `each_ancestor(:any_def).first` (prism gives none), whose
/// innermost frame is always `.last()`.
pub(crate) struct EbaDefInfo {
    /// This def's own start offset — the `@def_nodes.add?` compare-by-identity
    /// key (unique per lexical `def`, even for two textually-identical ones).
    pub(crate) start_offset: usize,
    /// `extract_block_name`: the existing `&block` param's name if the def
    /// already declares one (empty for an anonymous bare `&`), else the
    /// literal `block`.
    pub(crate) block_name: Vec<u8>,
    /// Whether the signature itself still needs a `(&block)`-shaped edit —
    /// false when the def already declares an explicit block parameter.
    pub(crate) needs_sig_edit: bool,
    /// The (start, end, replacement) signature edit; only meaningful when
    /// `needs_sig_edit`.
    pub(crate) sig_edit: (usize, usize, Vec<u8>),
    /// `build_new_arguments_for_zsuper`: each of this def's own parameters,
    /// source text verbatim except a bare positional optional (`y = 42`),
    /// which contributes just its name (`y`) — in declaration order.
    pub(crate) zsuper_arg_texts: Vec<Vec<u8>>,
}

/// Style/DoubleNegation: rubocop's `find_last_child`, precomputed once (it
/// only depends on a `def`/`define_method` call's OWN static shape, never on
/// where the checked `!!` sits) into just the two facts `end_of_method_
/// definition?` actually reads off it:
/// - `is_pair_or_hash` mirrors `last_child.type?(:pair, :hash)`,
/// - `is_array_parent` mirrors `last_child.parent.array_type?`
///
/// Both, if either is true, mean "never a return position" outright,
/// regardless of the checked node's own line. Otherwise
/// `first_line`/`last_line` (of `last_child` itself) feed the two remaining
/// upstream comparisons (`last_child.first_line <= node.first_line` and
/// `last_child.last_line <= conditional_node.last_line`).
#[derive(Clone, Copy)]
pub(crate) struct DnLastChild {
    pub(crate) is_pair_or_hash: bool,
    pub(crate) is_array_parent: bool,
    pub(crate) first_line: usize,
    pub(crate) last_line: usize,
}

/// Style/DoubleNegation: one entry per ancestor level that upstream's
/// `allowed_in_returns?` climb (via rubocop-ast's real `node.parent`, which
/// prism doesn't provide) actually cares about. Every OTHER node kind is
/// transparently absent from the stack — `find_def_node_from_ascendant` and
/// `find_conditional_node_from_ascendant` never match on them, so skipping
/// them is equivalent to including them as inert frames.
/// `find_parent_not_enumerable`, however, stops at the true IMMEDIATE
/// parent unconditionally (continuing only across `pair`/`hash`/`array`),
/// so the `Enumerable`/`BeginGroup` frames carry their direct children's
/// start offsets: the climb in `dn_end_of_method_definition` only crosses a
/// frame when the current node really is one of its direct children —
/// otherwise some unframed node (e.g. a plain method call) sits in between
/// and upstream would have stopped there (rails corpus:
/// `wr.write Marshal.dump [!!x, ...]` inside a def inside `unless`).
pub(crate) enum DnFrame {
    /// A real `def`/`defs`. Carries the enclosing method's own
    /// `find_last_child(def_node.body)`, or `None` when it couldn't be
    /// computed (e.g. an empty body).
    Def(Option<DnLastChild>),
    /// A `define_method`/`define_singleton_method` block, standing in for
    /// upstream's `def_node = the SEND node` special case. Carries
    /// `find_last_child(def_node)` — the call's own last argument.
    DefineMethodCall(Option<DnLastChild>),
    /// An `if`/`unless`/`while`/`until`/`case`/`case/in` — `conditional?`.
    /// Carries the node's own `last_line`.
    Conditional(usize),
    /// A `hash`, `array`, or hash-pair (`assoc`) literal — skipped over by
    /// `find_parent_not_enumerable` (only when actually the direct parent).
    Enumerable { start: usize, child_starts: Vec<usize> },
    /// A `StatementsNode` that groups 2+ statements — upstream's `:begin`
    /// node. Carries the group's own `last_line` (for `node.loc.line ==
    /// parent.loc.last_line`).
    BeginGroup { last_line: usize, child_starts: Vec<usize> },
}

/// Per-RUN state derived from the Config once — parsed patterns, resolved
/// enablement, compiled exemption maps. lint() is called per file; nothing
/// here should be rebuilt per file.
pub struct Engine {
    // DECLARATIVE rows that are enabled AND match their style gate, patterns
    // parsed — the per-node loop touches nothing else.
    decl: Vec<(Pat, &'static str, &'static str, Anchor)>,
    // (cop, enabled) sorted by cop — on() binary-searches instead of hashing.
    enabled: Vec<(&'static str, bool)>,
    allowed_patterns: HashMap<String, Vec<regex::Regex>>,
    allowed_methods: HashMap<String, Vec<String>>,
    // Lint/Debugger: is the cop live, and the FINAL segments of its method
    // list (`irb` for `Kernel.binding.irb`) — a cheap prefilter that avoids
    // building the chained name for every call node.
    debugger_on: bool,
    debugger_last: Vec<Vec<u8>>,
    // Direct enablement bits + hot per-cop config, resolved once — the
    // per-node checks read fields instead of hashing strings.
    pub(crate) hot: Hot,
    // AllCops: DisplayStyleGuide — append " (url)" to messages.
    display_style_guide: bool,
    style_guide_base: String,
    // Per-cop Exclude patterns (cop name, matchers) — applied per file.
    cop_excludes: Vec<(&'static str, Vec<regex::Regex>)>,
    // per-cop Include (filename-scoped cops): the cop runs ONLY on matching
    // paths — rubocop's TargetFinder-level gating, applied per file here.
    cop_includes: Vec<(&'static str, Vec<regex::Regex>)>,
}

/// Enablement + configuration the per-NODE checks consult. Everything here is
/// a plain field read in the hot loop.
#[derive(Default, Clone)]
pub(crate) struct Hot {
    pub(crate) semicolon: bool,
    pub(crate) empty_literal: bool,
    pub(crate) string_literals: bool,
    /// 1 = single_quotes, 2 = double_quotes, 0 = anything else
    pub(crate) string_style: u8,
    pub(crate) consistent_quotes: bool,
    pub(crate) string_literals_in_interpolation: bool,
    /// 1 = single_quotes, 2 = double_quotes, 0 = anything else
    pub(crate) string_interp_style: u8,
    pub(crate) numeric_literals: bool,
    pub(crate) min_digits: usize,
    pub(crate) numeric_strict: bool,
    pub(crate) method_name: bool,
    pub(crate) method_name_style: String,
    pub(crate) numeric_predicate: bool,
    pub(crate) numeric_pred_comparison: bool,
    pub(crate) symbol_proc: bool,
    pub(crate) symbol_proc_allow_args: bool,
    pub(crate) symbol_proc_allow_comments: bool,
    pub(crate) active_support: bool,
    pub(crate) zero_length: bool,
    pub(crate) even_odd: bool,
    pub(crate) dir: bool,
    pub(crate) string_chars: bool,
    pub(crate) nested_file_dirname: bool,
    pub(crate) uri_regexp: bool,
    pub(crate) uri_escape: bool,
    pub(crate) random_with_offset: bool,
    pub(crate) boolean_symbol: bool,
    pub(crate) redundant_return: bool,
    pub(crate) nested_method_definition: bool,
    pub(crate) negated_if: bool,
    /// 0 = both, 1 = prefix, 2 = postfix
    pub(crate) negated_if_style: u8,
    pub(crate) negated_unless: bool,
    /// 0 = both, 1 = prefix, 2 = postfix
    pub(crate) negated_unless_style: u8,
    pub(crate) sample: bool,
    pub(crate) single_argument_dig: bool,
}

/// Resolve a cop name string to its &'static form (cache deserialization).
pub fn intern_cop(name: &str) -> Option<&'static str> {
    IMPLEMENTED.iter().find(|c| **c == name).copied()
}

/// Every cop name the engine implements — enablement resolves once per run.
const IMPLEMENTED: &[&str] = &[
    "Lint/DuplicateRequire", "Naming/AsciiIdentifiers", "Naming/BinaryOperatorParameterName",
    "Naming/ClassAndModuleCamelCase", "Naming/ConstantName", "Style/MultilineIfThen", "Style/Not",
    "Style/StderrPuts", "Style/WhileUntilDo", "Style/ColonMethodCall", "Style/Attr",
    "Lint/EmptyClass", "Lint/DeprecatedClassMethods", "Layout/EmptyLineAfterMagicComment",
    "Layout/EmptyLines", "Style/EmptyLiteral", "Style/Semicolon", "Style/GlobalVars",
    "Layout/SpaceAfterComma", "Layout/SpaceBeforeSemicolon", "Layout/SpaceBeforeComma",
    "Layout/SpaceBeforeComment", "Lint/FloatOutOfRange", "Style/SymbolLiteral",
    "Lint/RescueException", "Lint/RescueType", "Style/WhenThen", "Lint/DuplicateHashKey",
    "Security/MarshalLoad", "Layout/SpaceAfterMethodName", "Layout/SpaceAfterSemicolon",
    "Layout/SpaceAfterNot", "Lint/UnifiedInteger", "Lint/FlipFlop", "Style/Proc",
    "Lint/DuplicateCaseCondition", "Lint/DuplicateElsifCondition", "Style/ColonMethodDefinition",
    "Layout/LeadingEmptyLines", "Style/Strip", "Lint/TopLevelReturnWithArgument", "Security/Eval",
    "Style/VariableInterpolation", "Lint/EachWithObjectArgument", "Style/TrailingBodyOnModule",
    "Lint/DuplicateRescueException", "Style/TrailingBodyOnClass", "Lint/SafeNavigationWithEmpty",
    "Style/RedundantCapitalW", "Lint/HashCompareByIdentity", "Lint/NextWithoutAccumulator",
    "Layout/SpaceAfterColon", "Lint/MultipleComparison", "Style/EmptyLambdaParameter",
    "Layout/SpaceInsideArrayPercentLiteral", "Style/IfUnlessModifierOfIfUnless",
    "Style/EmptyBlockParameter", "Lint/IdentityComparison", "Layout/SpaceInsideRangeLiteral",
    "Style/DoubleCopDisableDirective", "Style/ClassCheck", "Naming/BlockParameterName",
    "Style/ClassMethods", "Style/TrailingBodyOnMethodDefinition", "Lint/UselessElseWithoutRescue",
    "Lint/ReturnInVoidContext", "Style/MultilineBlockChain", "Style/OptionalArguments",
    "Style/RedundantFileExtensionInRequire", "Lint/TrailingCommaInAttributeDeclaration",
    "Layout/ConditionPosition", "Naming/HeredocDelimiterNaming", "Naming/HeredocDelimiterCase",
    "Style/MultilineWhenThen", "Naming/MethodParameterName", "Layout/EmptyLinesAroundBeginBody",
    "Layout/EmptyLinesAroundBlockBody", "Style/ClassVars", "Lint/NestedPercentLiteral",
    "Lint/PercentSymbolArray", "Style/MinMax", "Style/TrailingMethodEndStatement",
    "Style/OptionalBooleanParameter", "Layout/SpaceInsideStringInterpolation",
    "Layout/EmptyLinesAroundMethodBody", "Style/NestedTernaryOperator",
    "Layout/AssignmentIndentation", "Lint/CircularArgumentReference",
    "Lint/BinaryOperatorWithIdenticalOperands", "Lint/InterpolationCheck", "Lint/FloatComparison",
    "Layout/SpaceInsidePercentLiteralDelimiters", "Lint/EmptyWhen", "Lint/InheritException",
    "Lint/ConstantDefinitionInBlock", "Lint/ElseLayout", "Layout/EmptyLinesAroundModuleBody",
    "Lint/DisjunctiveAssignmentInConstructor", "Lint/IneffectiveAccessModifier",
    "Layout/LeadingCommentSpace", "Lint/DeprecatedOpenSSLConstant", "Lint/AssignmentInCondition",
    "Layout/EmptyLinesAroundClassBody", "Lint/AmbiguousRegexpLiteral", "Layout/BlockEndNewline",
    "Metrics/CyclomaticComplexity", "Metrics/PerceivedComplexity", "Metrics/AbcSize",
    "Metrics/ParameterLists", "Layout/EmptyLinesAroundAttributeAccessor", "Style/RedundantSortBy",
    "Layout/SpaceInLambdaLiteral", "Layout/SpaceAroundEqualsInParameterDefault", "Layout/EndOfLine",
    "Lint/AmbiguousBlockAssociation", "Lint/AmbiguousOperator",
    "Layout/EmptyLinesAroundExceptionHandlingKeywords", "Style/RedundantPercentQ",
    "Layout/SpaceBeforeFirstArg", "Lint/UnreachableCode", "Lint/RedundantStringCoercion",
    "Style/EachForSimpleLoop", "Lint/RedundantWithIndex", "Layout/CommentIndentation",
    "Layout/DotPosition", "Lint/UselessSetterCall", "Lint/EmptyConditionalBody",
    "Style/ComparableClamp", "Style/RedundantFreeze", "Lint/LiteralInInterpolation",
    "Lint/EmptyBlock", "Lint/DuplicateMagicComment", "Style/NilLambda",
    "Lint/UselessMethodDefinition", "Lint/SelfAssignment", "Layout/AccessModifierIndentation",
    "Layout/CaseIndentation", "Style/RedundantSelf", "Lint/UselessTimes",
    "Layout/EmptyLinesAroundAccessModifier", "Lint/ToJSON", "Security/YAMLLoad",
    "Style/StabbyLambdaParentheses", "Lint/StructNewOverride", "Lint/Loop", "Style/BlockComments",
    "Layout/BeginEndAlignment", "Style/EmptyElse", "Layout/EmptyLineBetweenDefs",
    "Style/SelfAssignment", "Style/SingleLineMethods", "Style/PreferredHashMethods",
    "Style/NumericLiteralPrefix", "Security/Open", "Security/JSONLoad", "Style/Sample",
    "Style/HashLikeCase", "Style/PercentQLiterals", "Lint/PercentStringArray",
    "Lint/MixedRegexpCaptureTypes", "Style/NestedParenthesizedCalls", "Style/BarePercentLiterals",
    "Lint/RequireParentheses", "Style/CaseEquality", "Style/RedundantException",
    "Lint/ErbNewArguments", "Lint/OrderedMagicComments", "Layout/DefEndAlignment",
    "Style/ExponentialNotation", "Style/StructInheritance", "Style/ExpandPathArguments",
    "Style/ModuleFunction", "Style/Encoding", "Style/RedundantFetchBlock",
    "Layout/ClosingHeredocIndentation", "Lint/ImplicitStringConcatenation",
    "Style/KeywordParametersOrder", "Naming/AccessorMethodName", "Style/PerlBackrefs",
    "Lint/RaiseException", "Lint/RedundantWithObject", "Style/RedundantConditional",
    "Style/MultilineMemoization", "Style/RedundantSelfAssignment", "Style/DefWithParentheses",
    "Layout/InitialIndentation", "Layout/TrailingEmptyLines", "Lint/EmptyFile",
    "Lint/EmptyInterpolation", "Lint/EnsureReturn", "Style/BeginBlock", "Style/CharacterLiteral",
    "Style/EndBlock", "Style/NegatedWhile", "Style/UnlessElse", "Layout/LineLength",
    "Layout/TrailingWhitespace", "Lint/BigDecimalNew", "Lint/BooleanSymbol", "Lint/Debugger",
    "Lint/EmptyEnsure", "Lint/EmptyExpression", "Lint/NestedMethodDefinition", "Lint/RandOne",
    "Lint/UriEscapeUnescape", "Lint/UriRegexp", "Naming/MethodName", "Style/ArrayJoin", "Style/Dir",
    "Style/Documentation", "Style/EvenOdd", "Style/FloatDivision", "Style/FrozenStringLiteralComment", "Style/LambdaCall",
    "Style/NegatedIf", "Style/NegatedUnless", "Style/NestedFileDirname", "Style/NilComparison",
    "Style/NumericLiterals", "Style/NumericPredicate", "Style/RandomWithOffset",
    "Style/RedundantReturn", "Style/StringChars", "Style/StringLiterals",
    "Style/StringLiteralsInInterpolation", "Style/SymbolProc", "Style/UnpackFirst",
    "Style/ZeroLengthPredicate", "Lint/RegexpAsCondition", "Style/MultilineIfModifier",
    "Style/GlobalStdStream", "Style/MissingRespondToMissing", "Style/NestedModifier",
    "Layout/MultilineArrayBraceLayout", "Layout/MultilineHashBraceLayout",
    "Layout/MultilineMethodDefinitionBraceLayout", "Style/WhileUntilModifier",
    "Style/SingleArgumentDig", "Style/NonNilCheck", "Style/MixinUsage",
    "Lint/UnderscorePrefixedVariableName", "Lint/MissingCopEnableDirective",
    "Layout/MultilineMethodCallBraceLayout", "Style/CommentAnnotation", "Lint/SuppressedException",
    "Style/TrailingUnderscoreVariable", "Lint/NonLocalExitFromIterator", "Layout/EmptyComment",
    "Style/EmptyCaseCondition", "Style/OneLineConditional", "Style/IfWithSemicolon",
    "Style/MultilineTernaryOperator", "Style/CommentedKeyword", "Style/For", "Style/RedundantSort", "Style/EachWithObject", "Style/CaseLikeIf", "Naming/VariableName", "Naming/RescuedExceptionsVariableName",
    "Lint/UnreachableLoop", "Style/InfiniteLoop", "Style/OrAssignment", "Style/EmptyMethod",
    "Lint/RedundantRequireStatement", "Lint/SendWithMixinArgument", "Style/HashAsLastArrayItem", "Lint/ParenthesesAsGroupedExpression",
    "Naming/PredicatePrefix", "Bundler/InsecureProtocolSource", "Bundler/DuplicatedGem", "Bundler/GemFilename",
    "Gemspec/RubyVersionGlobalsUsage", "Gemspec/DuplicatedAssignment", "Gemspec/RequiredRubyVersion", "Gemspec/OrderedDependencies",
    "Layout/IndentationStyle", "Layout/ParameterAlignment", "Style/RedundantAssignment", "Bundler/OrderedGems", "Layout/SpaceBeforeBlockBraces",
    "Lint/MissingSuper", "Style/LineEndConcatenation", "Style/CombinableLoops", "Style/SlicingWithRange",
    "Style/RedundantInterpolation", "Style/BisectedAttrAccessor",
    "Layout/SpaceAroundKeyword", "Style/MixinGrouping", "Style/ClassEqualityComparison", "Style/ParenthesesAroundCondition", "Layout/SpaceInsideParens",
    "Style/ExplicitBlockArgument",
    "Style/RescueModifier", "Layout/FirstParameterIndentation", "Bundler/DuplicatedGroup", "Layout/EmptyLinesAroundArguments", "Style/EvalWithLocation",
    "Style/MethodCallWithoutArgsParentheses", "Style/Alias", "Style/RaiseArgs", "Style/MethodDefParentheses",
    "Lint/SafeNavigationConsistency", "Style/HashTransformKeys", "Style/SymbolArray", "Style/HashTransformValues",
    "Layout/ArrayAlignment", "Lint/RedundantCopEnableDirective", "Style/TrailingCommaInHashLiteral", "Metrics/ModuleLength",
    "Style/SpecialGlobalVars",
    "Style/StringConcatenation", "Metrics/BlockLength", "Metrics/ClassLength", "Lint/NonDeterministicRequireOrder", "Metrics/BlockNesting", "Lint/FormatParameterMismatch", "Style/TrailingCommaInArrayLiteral", "Metrics/MethodLength", "Layout/SpaceAroundMethodCallOperator", "Style/WordArray", "Layout/SpaceAroundBlockParameters", "Style/TrailingCommaInArguments",
    "Layout/HeredocIndentation", "Style/RescueStandardError", "Naming/MemoizedInstanceVariableName", "Lint/OutOfRangeRegexpRef", "Style/PercentLiteralDelimiters", "Lint/RedundantSplatExpansion", "Style/DoubleNegation", "Naming/VariableNumber", "Style/CommandLiteral", "Style/AccessorGrouping", "Style/IfInsideElse", "Style/AndOr", "Style/IdenticalConditionalBranches",
    "Style/YodaCondition", "Style/TernaryParentheses", "Style/SignalException", "Style/RedundantBegin", "Style/SoleNestedConditional", "Style/Next", "Style/RegexpLiteral", "Lint/ShadowedException", "Lint/SafeNavigationChain", "Style/MultipleComparison", "Style/TrivialAccessors", "Naming/FileName",
    "Style/Lambda", "Style/GuardClause", "Lint/LiteralAsCondition", "Lint/ShadowedArgument", "Lint/Void", "Style/HashSyntax", "Lint/UnusedBlockArgument", "Lint/UnusedMethodArgument", "Lint/UselessAccessModifier", "Style/HashEachMethods", "Style/MutableConstant",
];

impl Engine {
    pub fn new(cfg: &Config) -> Engine {
        // rubocop raises on an EnforcedStyle outside SupportedStyles and the
        // file yields no offenses; the closest equivalent is disabling the cop.
        let live = |c: &str| {
            if !cfg.enabled(c) {
                return false;
            }
            if let Some(v) = cfg.param(c, "EnforcedStyle") {
                if let Some(sch) = crate::config::schema(c) {
                    if !sch.styles.is_empty() && !sch.styles.contains(&v) {
                        return false;
                    }
                }
            }
            true
        };
        let mut enabled: Vec<(&'static str, bool)> =
            IMPLEMENTED.iter().map(|c| (*c, live(c))).collect();
        enabled.sort_by_key(|(c, _)| *c);
        let is_on = |cop: &str| {
            enabled
                .binary_search_by(|(c, _)| (*c).cmp(cop))
                .map(|i| enabled[i].1)
                .unwrap_or(false)
        };
        // style-gate + enablement resolved NOW; the visitor loop just matches
        let decl = DECLARATIVE
            .iter()
            .filter(|(_, cop, _, _, style)| {
                is_on(cop) && style.is_none_or(|st| cfg.enforced_style(cop) == st)
            })
            .map(|(p, cop, msg, a, _)| (nodepattern::parse(p), *cop, *msg, *a))
            .collect();

        let mut allowed_patterns: HashMap<String, Vec<regex::Regex>> = HashMap::new();
        let mut allowed_methods: HashMap<String, Vec<String>> = HashMap::new();
        for (sec, kv) in &cfg.sections {
            if let Some(v) = kv.get("AllowedPatterns") {
                let pats = parse_allowed_list(v)
                    .into_iter()
                    .filter_map(|p| {
                        // `!ruby/regexp /.../ ` wraps an explicit regexp;
                        // plain strings are already regexps to rubocop
                        let body = p
                            .strip_prefix("!ruby/regexp")
                            .map(|r| r.trim())
                            .and_then(|r| r.strip_prefix('/'))
                            .and_then(|r| r.rsplit_once('/').map(|(b, _)| b.to_string()))
                            .unwrap_or(p);
                        regex::Regex::new(&body).ok()
                    })
                    .collect();
                allowed_patterns.insert(sec.clone(), pats);
            }
            if let Some(v) = kv.get("AllowedMethods") {
                allowed_methods.insert(sec.clone(), parse_allowed_list(v));
            }
        }
        // Seed schema-default AllowedMethods for cops the config didn't set
        // them on — unless the section replaces defaults outright.
        for s in SCHEMA {
            if !s.allowed_methods.is_empty()
                && !allowed_methods.contains_key(s.cop)
                && !cfg.replaces_defaults(s.cop)
            {
                allowed_methods
                    .insert(s.cop.to_string(), s.allowed_methods.iter().map(|m| m.to_string()).collect());
            }
        }

        let debugger_on = is_on("Lint/Debugger");
        let debugger_last = if debugger_on {
            let listed = cfg.param("Lint/Debugger", "DebuggerMethods").map(parse_allowed_list);
            let names: Vec<String> = match listed {
                Some(l) => l,
                None => crate::cops::lint_cops::DEFAULT_DEBUGGER_METHODS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            let mut last: Vec<Vec<u8>> = names
                .iter()
                .map(|n| n.rsplit('.').next().unwrap_or(n).as_bytes().to_vec())
                .collect();
            last.push(b"require".to_vec());
            last.sort();
            last.dedup();
            last
        } else {
            Vec::new()
        };

        let hot = Hot {
            semicolon: is_on("Style/Semicolon"),
            empty_literal: is_on("Style/EmptyLiteral"),
            string_literals: is_on("Style/StringLiterals"),
            string_style: match cfg.enforced_style("Style/StringLiterals") {
                "single_quotes" => 1,
                "double_quotes" => 2,
                _ => 0,
            },
            consistent_quotes: cfg.param("Style/StringLiterals", "ConsistentQuotesInMultiline")
                == Some("true"),
            string_literals_in_interpolation: is_on("Style/StringLiteralsInInterpolation"),
            string_interp_style: match cfg.enforced_style("Style/StringLiteralsInInterpolation") {
                "single_quotes" => 1,
                "double_quotes" => 2,
                _ => 0,
            },
            numeric_literals: is_on("Style/NumericLiterals"),
            min_digits: cfg.int("Style/NumericLiterals", "MinDigits"),
            numeric_strict: cfg.param("Style/NumericLiterals", "Strict") == Some("true"),
            method_name: is_on("Naming/MethodName"),
            method_name_style: cfg.enforced_style("Naming/MethodName").to_string(),
            numeric_predicate: is_on("Style/NumericPredicate"),
            numeric_pred_comparison: cfg.enforced_style("Style/NumericPredicate") == "comparison",
            symbol_proc: is_on("Style/SymbolProc"),
            symbol_proc_allow_args: cfg.param("Style/SymbolProc", "AllowMethodsWithArguments")
                == Some("true"),
            symbol_proc_allow_comments: cfg.param("Style/SymbolProc", "AllowComments") == Some("true"),
            active_support: cfg.active_support(),
            zero_length: is_on("Style/ZeroLengthPredicate"),
            even_odd: is_on("Style/EvenOdd"),
            dir: is_on("Style/Dir"),
            string_chars: is_on("Style/StringChars"),
            nested_file_dirname: is_on("Style/NestedFileDirname") && cfg.target_ruby() >= 3.1,
            uri_regexp: is_on("Lint/UriRegexp"),
            uri_escape: is_on("Lint/UriEscapeUnescape"),
            random_with_offset: is_on("Style/RandomWithOffset"),
            boolean_symbol: is_on("Lint/BooleanSymbol"),
            redundant_return: is_on("Style/RedundantReturn"),
            nested_method_definition: is_on("Lint/NestedMethodDefinition"),
            negated_if: is_on("Style/NegatedIf"),
            negated_if_style: match cfg.enforced_style("Style/NegatedIf") {
                "prefix" => 1,
                "postfix" => 2,
                _ => 0,
            },
            negated_unless: is_on("Style/NegatedUnless"),
            negated_unless_style: match cfg.enforced_style("Style/NegatedUnless") {
                "prefix" => 1,
                "postfix" => 2,
                _ => 0,
            },
            sample: is_on("Style/Sample"),
            single_argument_dig: is_on("Style/SingleArgumentDig"),
        };
        let display_style_guide = cfg.param("AllCops", "DisplayStyleGuide") == Some("true");
        let style_guide_base = cfg
            .param("AllCops", "StyleGuideBaseURL")
            .unwrap_or("https://rubystyle.guide")
            .to_string();
        let cop_excludes: Vec<(&'static str, Vec<regex::Regex>)> = IMPLEMENTED
            .iter()
            .filter_map(|c| {
                let m = cfg.section_exclude_matchers(c);
                (!m.is_empty()).then_some((*c, m))
            })
            .collect();
        let cop_includes: Vec<(&'static str, Vec<regex::Regex>)> = IMPLEMENTED
            .iter()
            .filter_map(|c| {
                let m = cfg.section_include_matchers(c);
                (!m.is_empty()).then_some((*c, m))
            })
            .collect();
        Engine {
            decl, enabled, allowed_patterns, allowed_methods, debugger_on, debugger_last, hot,
            cop_excludes, cop_includes, display_style_guide, style_guide_base,
        }
    }
    /// The " (https://...)" message suffix for a cop, when configured —
    /// upstream MessageAnnotator's `(style_guide_url, *reference_urls)`,
    /// shown under AllCops: DisplayStyleGuide when any URL exists.
    pub(crate) fn style_guide_suffix(&self, cop: &str) -> Option<String> {
        if !self.display_style_guide {
            return None;
        }
        let schema = crate::config::schema(cop)?;
        let mut urls: Vec<String> = Vec::new();
        if let Some(sg) = schema.style_guide {
            urls.push(if sg.starts_with('#') {
                format!("{}{sg}", self.style_guide_base)
            } else {
                sg.to_string()
            });
        }
        urls.extend(schema.references.iter().map(|r| r.to_string()));
        if urls.is_empty() {
            return None;
        }
        Some(format!(" ({})", urls.join(", ")))
    }
    /// The hot flags for one file: the base view with per-cop Excludes for
    /// matching cops switched off. Returns the excluded non-hot cop names too.
    pub fn file_view(&self, rel_path: &str) -> (Hot, Vec<&'static str>) {
        let mut hot = self.hot.clone();
        let mut disabled = Vec::new();
        for (cop, matchers) in &self.cop_includes {
            if !matchers.iter().any(|re| re.is_match(rel_path)) {
                disabled.push(*cop);
            }
        }
        for (cop, matchers) in &self.cop_excludes {
            if matchers.iter().any(|re| re.is_match(rel_path)) {
                disabled.push(*cop);
                match *cop {
                    "Style/StringLiterals" => hot.string_literals = false,
                    "Style/NumericLiterals" => hot.numeric_literals = false,
                    "Naming/MethodName" => hot.method_name = false,
                    "Style/NumericPredicate" => hot.numeric_predicate = false,
                    "Style/SymbolProc" => hot.symbol_proc = false,
                    "Style/ZeroLengthPredicate" => hot.zero_length = false,
                    "Style/EvenOdd" => hot.even_odd = false,
                    "Style/Dir" => hot.dir = false,
                    "Style/StringChars" => hot.string_chars = false,
                    "Style/NestedFileDirname" => hot.nested_file_dirname = false,
                    "Lint/UriRegexp" => hot.uri_regexp = false,
                    "Lint/UriEscapeUnescape" => hot.uri_escape = false,
                    "Style/RandomWithOffset" => hot.random_with_offset = false,
                    "Lint/BooleanSymbol" => hot.boolean_symbol = false,
                    "Style/RedundantReturn" => hot.redundant_return = false,
                    "Lint/NestedMethodDefinition" => hot.nested_method_definition = false,
                    "Style/NegatedIf" => hot.negated_if = false,
                    "Style/NegatedUnless" => hot.negated_unless = false,
                    "Style/Sample" => hot.sample = false,
                    "Style/SingleArgumentDig" => hot.single_argument_dig = false,
                    _ => {}
                }
            }
        }
        (hot, disabled)
    }
    pub(crate) fn debugger_on(&self) -> bool {
        self.debugger_on
    }
    /// Could `name` be the final segment of a listed debugger method (or
    /// `require`)? Sorted-list binary search.
    pub(crate) fn debugger_last_match(&self, name: &[u8]) -> bool {
        self.debugger_last.binary_search_by(|x| x.as_slice().cmp(name)).is_ok()
    }
}

pub struct LintResult {
    pub offenses: Vec<Offense>,
    pub fixes: Vec<Fix>,
}

pub(crate) struct Cops<'a> {
    pub(crate) src: &'a [u8],
    pub(crate) idx: &'a LineIndex,
    pub(crate) cfg: &'a Config,
    pub(crate) comment_lines: HashSet<usize>,
    pub(crate) offenses: Vec<Offense>,
    // autocorrect edits: applied right-to-left so earlier offsets stay valid —
    // exactly how rubocop's Corrector composes source rewrites off the AST
    // source-ranges.
    pub(crate) fixes: Vec<Fix>,
    // Per-run engine state: parsed+prefiltered patterns, resolved enablement,
    // compiled exemption maps.
    pub(crate) eng: &'a Engine,
    // Per-FILE view of the hot flags (per-cop Exclude may switch cops off for
    // this file) + the excluded non-hot cops.
    pub(crate) hot: Hot,
    pub(crate) file_disabled: Vec<&'static str>,
    // Enclosing call/block method-name SPANS (outermost first), maintained
    // around the manual recursion in `visit_call_node`. Lets cops consult
    // ancestors (e.g. Style/NumericPredicate's AllowedMethods on a wrapping
    // `where(...)`, and its `!x.zero?` negation) without a parent pointer.
    // Spans index into src — no per-node allocation.
    pub(crate) call_stack: Vec<(usize, usize)>,
    // Ancestor counters for Lint/NestedMethodDefinition: how many enclosing
    // `def`s, and how many enclosing "scoping" blocks/sclass (Class.new,
    // instance_eval, class << self, AllowedMethods, …). A nested def is an
    // offense iff def_depth >= 1 and scoping_depth == 0.
    pub(crate) def_depth: usize,
    pub(crate) scoping_depth: usize,
    // Style/ClassEqualityComparison: enclosing `def`/`defs` method names
    // (innermost last), mirroring `node.each_ancestor(:any_def).first` —
    // `AllowedMethods`/`AllowedPatterns` exempt the NEAREST enclosing def.
    pub(crate) def_name_stack: Vec<Vec<u8>>,
    // Inside a `#{...}` interpolation (rubocop's `inside_interpolation?`) —
    // string-literal style is not enforced there.
    pub(crate) interp_depth: usize,
    // interp_depth snapshots taken on entering each interpolated-xstring:
    // upstream's inside_interpolation? only counts dstr/dsym/regexp parents,
    // so a string whose NEAREST #{} belongs to an xstr (interp_depth ==
    // last snapshot + 1) is exempt for Style/StringLiteralsInInterpolation.
    pub(crate) xstr_interp_base: Vec<usize>,
    // Node spans claimed by a multiline string-concat check (rubocop's
    // `ignore_node`): individual strings inside are exempt from on_str.
    pub(crate) str_ignore: Vec<(usize, usize)>,
    // Numeric literals already checked as part of a folded `-@` call.
    pub(crate) num_ignore: Vec<usize>,
    // Spans of `%i[...]`/`%I[...]` arrays — Lint/BooleanSymbol skips those.
    pub(crate) percent_sym_spans: Vec<(usize, usize)>,
    // Spans of ANY percent-literal array — Lint/EmptyInterpolation skips those.
    pub(crate) percent_arr_spans: Vec<(usize, usize)>,
    // Style/WordArray: one entry per currently-open `ArrayNode` (pushed on
    // entry, popped on exit) — `true` when THAT array is a "matrix" (all of
    // its own elements are arrays, and at least one sub-array has complex
    // content per `WordRegex`), mirroring `matrix_of_complex_content?`. A
    // child array's own check peeks at the top (its immediate parent) to
    // answer `within_matrix_of_complex_content?` in O(1), no real parent
    // pointers needed. (Approximation: this is the nearest ENCLOSING array
    // node, not necessarily the strict AST parent if a non-array node sits
    // between them — not exercised by the fixture.)
    pub(crate) wa_matrix_stack: Vec<bool>,
    // PercentArray#invalid_percent_array_context?: start offsets of array
    // literals that are arguments of an UNPARENTHESIZED call carrying a
    // literal block (`foo ["a", "b"] do ... end`) — converting to %w/%i
    // there is ambiguous, so the brackets->percent direction never offends.
    pub(crate) pa_invalid_ctx: HashSet<usize>,
    // Style/RegexpLiteral's `allowed_omit_parentheses_with_percent_r_literal?`
    // needs `node.parent&.call_type?` — prism gives no parent pointer, so
    // `visit_call_node` marks the start offsets of its receiver and each
    // argument (before descending) when they are regexp literals; a `%r`
    // node found in this set was a direct receiver/argument of SOME `send`/
    // `csend` call (parens or not — matches whitequark's `call_type?`, which
    // doesn't care whether the call itself is parenthesized).
    pub(crate) rl_call_child: HashSet<usize>,
    // Style/Lambda's `arg_to_unparenthesized_call?`: start offsets of nodes
    // that are a DIRECT argument (never the receiver) of an unparenthesized
    // `send`/`csend` call — for a hash-pair argument (`foo key: value`), the
    // PAIR'S VALUE offset is stored (mirroring upstream's climb through a
    // `pair_type?` parent to its grandparent send before checking
    // `sibling_index`). A multiline arrow-lambda literal found in this set,
    // when converted lambda-literal->method, gets its `do`/`end` delimiters
    // swapped to `{`/`}` (unparenthesized `do...end` block arguments other
    // than a call's receiver are syntactically ambiguous).
    pub(crate) lambda_unparen_arg: HashSet<usize>,
    // Inner `File.dirname` calls claimed by an outer chain (NestedFileDirname).
    pub(crate) dirname_ignore: Vec<usize>,
    // Innermost statement-list span starts — Lint/DuplicateRequire scopes by it.
    pub(crate) stmts_stack: Vec<usize>,
    // unless/else nodes already corrected — nested ones only get offenses.
    pub(crate) unless_else_spans: Vec<(usize, usize)>,
    // Style/OneLineConditional spans already corrected — a nested one-line
    // conditional fully inside an outer one's replaced range only gets an
    // offense (rubocop's `ignore_node`/`part_of_ignored_node?`).
    pub(crate) one_line_cond_spans: Vec<(usize, usize)>,
    // Style/IfInsideElse: spans of outer `if` nodes already autocorrected —
    // a further nested if/else structure fully inside one of these ranges
    // only gets an offense, never a second (conflicting) autocorrect
    // (rubocop's `ignore_node`/`part_of_ignored_node?`).
    pub(crate) if_inside_else_ignored: Vec<(usize, usize)>,
    // Style/IfWithSemicolon: spans of already-flagged if/unless nodes
    // (rubocop's `ignore_node`) — a node whose start falls inside one is
    // `part_of_ignored_node?` and skipped entirely (no offense at all).
    pub(crate) if_semicolon_spans: Vec<(usize, usize)>,
    // Style/IfWithSemicolon: start offsets of if/unless nodes whose
    // whitequark "parent" would be another if/unless node — an `elsif`
    // (prism's `subsequent()` chain) or the sole statement of an enclosing
    // if/unless's then/else body (whitequark doesn't wrap a single
    // statement in `:begin`, so it becomes a direct AST child of the outer
    // `:if` node). `on_normal_if_unless`'s `return if node.parent&.if_type?`
    // guard is purely structural (independent of whether the outer node
    // itself gets flagged), so this is populated for EVERY if/unless node
    // visited, not just ones that end up with an offense.
    pub(crate) if_semicolon_suppressed: HashSet<usize>,
    // multi-line plain-string line spans (Layout/EmptyLines token lines)
    pub(crate) multiline_str_lines: Vec<(usize, usize)>,
    // the file's frozen_string_literal magic-comment value, if any
    pub(crate) fsl_enabled: Option<bool>,
    // sorted literal content spans + already-flagged semicolon offsets
    pub(crate) lit_spans: Vec<(usize, usize)>,
    pub(crate) semi_flagged: HashSet<usize>,
    // range-literal spans and value-omission kwarg spans (Style/Semicolon fixes)
    pub(crate) range_spans: Vec<(usize, usize)>,
    pub(crate) vo_kwargs: Vec<(usize, usize, usize)>,
    // spans of unparenthesized call argument lists being visited
    // (first arg start, all arg spans) — Style/EmptyLiteral's Hash fix
    pub(crate) bare_arg_frames: Vec<(usize, Vec<(usize, usize)>)>,
    // ---- Layout/LineLength breakable machinery (see breakable.rs) ----
    pub(crate) ll_active: bool,
    pub(crate) ll_max: usize,
    pub(crate) ll_split: bool,
    pub(crate) ll_long: Vec<bool>,
    pub(crate) ll_break: std::collections::HashMap<usize, (usize, Option<u8>)>,
    pub(crate) ll_semi: std::collections::HashMap<usize, usize>,
    pub(crate) ll_block: std::collections::HashMap<usize, usize>,
    pub(crate) ll_coll_stack: Vec<breakable::LlFrame>,
    pub(crate) ll_str_skip: HashSet<usize>,
    pub(crate) ll_dstr_delim: Vec<u8>,
    pub(crate) requires_seen: HashSet<String>,
    // Depth of enclosing blocks / kwbegin / lambdas — Lint/Debugger's
    // assumed-usage heuristic consults this.
    pub(crate) usage_block_depth: usize,
    // Start offsets of nodes that are a DIRECT operand of a call / array /
    // hash pair — rubocop's `assumed_argument?` parent check.
    pub(crate) assumed_arg_offsets: HashSet<usize>,
    // Heredoc BODIES as (first line, last line, delimiter, static) —
    // terminator excluded; `static` marks the `<<~'X'` uninterpolated form.
    pub(crate) heredoc_lines: Vec<(usize, usize, Vec<u8>, bool)>,
    // The `__END__` line — nothing at or after it is lintable text.
    pub(crate) data_line: Option<usize>,
    // Per enclosing body (program/class/module/def), the names of classes
    // defined as its direct children — Naming/MethodName's "class emitter
    // method" exemption consults this.
    pub(crate) class_children_stack: Vec<Vec<Vec<u8>>>,
    // Lint/InheritException: per enclosing body (program/class/module), the
    // direct-child `class`/`module` statements as (start_offset, name) —
    // rubocop's `class_node.left_siblings` (siblings with an earlier start
    // offset than the node being checked, since prism visits in source order).
    pub(crate) exception_siblings_stack: Vec<Vec<(usize, Vec<u8>)>>,
    // Style/MissingRespondToMissing: per enclosing class/module/sclass body,
    // whether a `respond_to_missing?` (plain `def`) and/or a `self.
    // respond_to_missing?` (`def self.`) exist ANYWHERE in that body's
    // subtree — rubocop's `grand_parent.each_descendant(node.type)` scan,
    // which does not stop at nested class/module boundaries. `(has_def,
    // has_defs)`; an empty stack (no enclosing class/module/sclass) means
    // rubocop's `node.parent.parent` scan target is unreachable, so the cop
    // always fires (see `check_missing_respond_to_missing`'s doc comment).
    pub(crate) respond_to_missing_stack: Vec<(bool, bool)>,
    // Every comment as (line, start_offset, end_offset) spans into src.
    pub(crate) comments: &'a [(usize, usize, usize)],
    // Enclosing class/module names (their constant-path sources) — the
    // qualified identifier in Style/Documentation messages.
    pub(crate) mod_stack: Vec<String>,
    // Whether each enclosing class/module carried `#:nodoc: all`.
    pub(crate) nodoc_all_stack: Vec<bool>,
    // Depth of enclosing if/unless/while/until/case/case-in nodes —
    // Lint/RegexpAsCondition's `node.ancestors.none?(&:conditional?)` guard
    // (a real ancestor walk, not just "am I the predicate") ported as a
    // counter maintained around each conditional's visit.
    pub(crate) cond_depth: usize,
    // Style/AndOr (EnforcedStyle: always): start offsets of `or`/`||` nodes
    // whose DIRECT AST parent is an `and`/`&&` node — rubocop-ast's
    // `node.parent&.and_type?` in `keep_operator_precedence`. Populated in
    // `check_and_or_and` (visited pre-order, so a parent AndNode is always
    // seen before its child) and consulted in `check_and_or_or`.
    pub(crate) andor_or_parent_and: std::collections::HashSet<usize>,
    // Start offsets of MatchLastLineNode/InterpolatedMatchLastLineNode
    // literals already offended-on as the receiver of an enclosing `!`/`not`
    // call — the later direct visit of the literal skips these so it isn't
    // double-flagged (rubocop's `ignore_node`).
    pub(crate) regexp_bang_ignore: Vec<usize>,
    // Style/MultilineIfModifier: start offsets of modifier if/unless nodes
    // already offended-on — a nested chain (`body if inner if outer`) shares
    // ONE start offset across every level (a modifier node's location begins
    // at its body, not its keyword), so only the first (outermost, visited
    // pre-order) one gets an offense (rubocop's `ignore_node`/
    // `part_of_ignored_node?`). Every eligible level still gets a FIX pushed.
    pub(crate) multiline_if_mod_seen: HashSet<usize>,
    // Style/NestedTernaryOperator: start offsets of nested ternaries already
    // reported — avoids duplicate offenses when the same nested ternary appears
    // in multiple outer ternaries.
    pub(crate) nested_ternary_reported: HashSet<usize>,
    // Style/MultilineTernaryOperator: parent-context lookup, keyed by a
    // ternary if-node's own start offset (prism has no parent pointers, so
    // whichever node visits the ternary as a direct child registers itself
    // here BEFORE recursing — mirrors `ut_call_child`'s idiom). `mto_parent_start`
    // holds the immediate parent's own start offset (used to position hoisted
    // comments, upstream's `corrector.insert_before(parent, ...)`);
    // `mto_single_line` holds ternaries whose parent is `return`/`break`/`next`
    // or a non-assignment `send`/`csend` call (upstream's
    // `enforce_single_line_ternary_operator?`), which corrects to a single-line
    // ternary instead of expanding to `if`/`else`.
    pub(crate) mto_parent_start: HashMap<usize, usize>,
    pub(crate) mto_single_line: HashSet<usize>,
    // Style/IdenticalConditionalBranches: mirrors `mto_parent_start` above —
    // keyed by an `if`/`case`/`case_match` node's own start offset, holding
    // the start offset of an ENCLOSING plain/compound assignment node when
    // that conditional is directly the assignment's value (`x = if foo ...
    // end`). Stands in for rubocop-ast's `node.parent&.assignment?` (prism
    // has no parent pointers), populated by the `assignment_write!`-family
    // macros before they recurse into the value.
    pub(crate) icb_assign_start: HashMap<usize, usize>,
    // Style/GuardClause: mirrors `icb_assign_start` — start offsets of
    // `if`/`unless` nodes that sit directly as the VALUE of an assignment
    // (`result = if something ... end`), populated by the same
    // `assignment_write!`-family macros. Stands in for rubocop-ast's
    // `node.parent&.assignment?` (prism has no parent pointers). A plain
    // `HashSet` suffices — unlike `icb_assign_start`, `accepted_form?` only
    // ever needs the yes/no fact, never the enclosing assignment's location.
    pub(crate) gc_assignment_value_starts: HashSet<usize>,
    // Style/MultilineTernaryOperator: byte ranges of ternaries already
    // corrected in THIS pass — a nested ternary whose range falls inside one
    // of these is `part_of_ignored_node?` upstream: still gets an offense, but
    // no fix is queued (the outer replacement already consumed its source; a
    // later autocorrect pass will re-discover and fix it fresh).
    pub(crate) mto_fixed_ranges: Vec<(usize, usize)>,
    // Style/NestedModifier: byte ranges (start, end) of modifier if/unless/
    // while/until nodes already flagged as the INNER half of a nested-modifier
    // pair — rubocop's `ignore_node`/`part_of_ignored_node?`. A candidate
    // node whose start offset falls inside one of these ranges is skipped;
    // since an ignored node's own range spans everything nested beneath it
    // (body-wise), this transitively suppresses deeper pairs in a long
    // modifier chain, matching upstream's ancestor-walking `part_of_ignored_node?`.
    pub(crate) nested_modifier_ignored: Vec<(usize, usize)>,
    // Style/SoleNestedConditional: mirrors upstream's `ignore_node`/
    // `ignored_node?` — once an outer conditional's nested branch has been
    // folded into it, that branch's own start offset is recorded here so
    // that, when the SAME traversal pass later visits it in its own right
    // (it's still a proper `if`/`unless` node with possibly its own further
    // nested offense), its correction is skipped for THIS pass (the offense
    // itself still fires) rather than emitting edits that would overlap the
    // enclosing correction's — `apply_fixes`'s per-edit overlap skip is too
    // coarse-grained to keep such a correction's several edits atomic, so
    // without this a partial application can drop only SOME of a
    // correction's edits and desync the source (e.g. removing an outer
    // `end` without the matching condition merge). Reset per `lint()` call,
    // so `apply_fixes_iter`'s next pass (fresh parse) picks the deferred
    // fold up cleanly, matching upstream's own multi-pass convergence.
    pub(crate) snc_ignored: Vec<usize>,
    // Layout/AssignmentIndentation: maps a chained assignment's own start
    // offset (`bar` in `foo = bar = baz`) to the start offset of its
    // immediate same-line enclosing assignment (`foo`) — see
    // `assignment_indentation_hook` in layout.rs for why this is only ever
    // ONE level, matching upstream's `leftmost_multiple_assignment` bug.
    pub(crate) assignment_leftmost: HashMap<usize, usize>,
    // Lint/ConstantDefinitionInBlock: set by `visit_block_node` right before
    // descending into a block's body when that body is a `StatementsNode` —
    // the very next `visit_statements_node` call consumes (takes) it, so it's
    // true iff THAT statements list is literally the block's own body (not
    // some deeper def/if/class statements list reached along the way).
    pub(crate) block_owns_next_stmts: bool,
    // Relative file path for cops that need to check the filename (e.g., Gemfile)
    pub(crate) rel_path: &'a str,
    // Lint/UnreachableCode: method names redefined by a `def`/`defs` seen so
    // far in the file (rubocop's `@redefined`) — only the six
    // `redefinable_flow_method?` names are ever inserted.
    pub(crate) uc_redefined: HashSet<Vec<u8>>,
    // Lint/UnreachableCode: depth of enclosing `instance_eval` blocks
    // (rubocop's `@instance_eval_count`) — inside one, a bare redefinable
    // call's target `self` is unknown, so the warning is suppressed.
    pub(crate) uc_instance_eval_depth: usize,
    // Style/Attr: stack of whether each enclosing class/module has a custom
    // `attr` method defined — used to skip the cop when a custom implementation
    // is present (rubocop's `define_attr_method?`).
    pub(crate) style_attr_custom_method_stack: Vec<bool>,
    // Layout/EmptyLinesAroundClassBody / EmptyLinesAroundModuleBody:
    // (cop, start-offset) pairs already offended-on — `check_beginning` and
    // `check_ending` collapse onto the exact same physical line when a
    // class/module/sclass body is nothing but a single blank line (e.g.
    // `class << self\n\nend`), and upstream's `Base#add_offense` silently
    // drops the second `add_offense` call for an identical range
    // (`current_offense_locations.add?(range)`), so only the "beginning"
    // message survives.
    pub(crate) el_offended: HashSet<(&'static str, usize)>,
    // Lint/ElseLayout: start offsets of else-body first-statements already
    // reported — upstream's unguarded one-level elsif recursion can revisit
    // the same else branch; Base#add_offense dedups by range there.
    pub(crate) else_layout_seen: HashSet<usize>,
    // Lint/EmptyConditionalBody: the start offset of the SOLE top-level
    // program statement, when there is exactly one — rubocop's
    // `empty_if_branch?` treats a totally parent-less if/unless (the only
    // statement in the whole file, nothing wrapping it: no def/class/module/
    // block/begin/assignment/etc.) differently from every other case, which
    // this lets us test with a single offset comparison instead of tracking
    // "am I inside any container" via a pile of depth counters.
    pub(crate) top_level_sole_stmt: Option<usize>,
    // Lint/UselessMethodDefinition: start offsets of DefNodes that are a
    // direct argument of a NON-access-modifier call (`do_something def m`) —
    // upstream's method_definition_with_modifier? skip.
    pub(crate) def_macro_args: HashSet<usize>,
    // Style/SingleArgumentDig: start offsets of dig calls known to be the
    // receiver of an outer dig (chain members, ceded to Style/DigChain).
    pub(crate) sad_chain_receivers: HashSet<usize>,
    // Style/StringConcatenation: start offsets of `+` CallNodes already
    // accounted for as an interior link of an ancestor's chain (so we don't
    // re-process them as their own topmost when the default traversal
    // descends into them).
    pub(crate) sc_handled: HashSet<usize>,
    // Style/RedundantSelf: per-active def/block scope, the set of local
    // variable / parameter names known to disambiguate `self.x` from a bare
    // `x` — rubocop's `@local_variables_scopes` aliases ONE mutable Array
    // across every descendant of a def/block (`add_scope`), so a name pushed
    // anywhere is visible scope-wide from that point on; a nested `block`
    // literally reuses (shares) the enclosing scope's Rc (closures see outer
    // locals — even ones only a nested block itself defines, matching
    // upstream's heuristic), while a nested `def` always gets a fresh one
    // (methods don't close over outer locals).
    pub(crate) rs_scope_stack: Vec<std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>>>,
    // Style/RedundantSelf: TOP-LEVEL (no enclosing def/block) exemptions —
    // upstream's identity-keyed hash gives each un-scoped node its own
    // private entry; a (span, name) pair stands in for "is the candidate
    // node an each_ancestor of the node that entry belongs to" via byte-range
    // containment, which holds for any well-formed AST nesting.
    pub(crate) rs_narrow: Vec<(usize, usize, Vec<u8>)>,
    // Style/RedundantSelf: enclosing block ancestors, outermost first — (is
    // this a PLAIN block, i.e. not `_1`/`it` numbered-param sugar; does it
    // have NO `|...|` delimiters at all) — `it_method_in_block?`'s
    // `each_ancestor(:block).first` (type-filtered!) +
    // `empty_and_without_delimiters?`.
    pub(crate) rs_block_stack: Vec<(bool, bool)>,
    // Style/MethodCallWithoutArgsParentheses's `same_name_assignment?`: one
    // frame per enclosing local-variable write/masgn ancestor, each holding
    // the name(s) it assigns (a masgn frame can hold several). Only LOCAL
    // variable writes are tracked — ivar/cvar/gvar/casgn writes carry sigils
    // or start uppercase, so their name can never equal a bare method name
    // (and camelCase methods are excluded earlier anyway), making them dead
    // code here. `obj.method ||= x` / index writes are separate node kinds
    // in prism (CallOrWriteNode &c.) that are simply never pushed here,
    // which is exactly upstream's `asgn_node.lhs.call_type?` exclusion.
    pub(crate) mcwap_assign_stack: Vec<Vec<Vec<u8>>>,
    // Style/MethodCallWithoutArgsParentheses's `default_argument?`
    // (`node.parent&.optarg_type?`): start offsets of call nodes that are the
    // DIRECT `value` of a `def`/block optional parameter (`def foo(test =
    // test())`) — set once, up front, in `visit_optional_parameter_node`.
    pub(crate) mcwap_optarg_default: HashSet<usize>,
    // Lint/NonLocalExitFromIterator: one entry per active def/block/lambda
    // ancestor, innermost last — mirrors upstream's
    // `each_ancestor(:any_block, :any_def)` climb from a `return` node.
    // `Def` and `Lambda` are the two frame kinds that make `scoped_node?`
    // true and stop the climb outright (a `def`/`defs`, or a block whose
    // `send_node` is literally named `lambda` — prism represents a stabby
    // `->(){}` as its own `LambdaNode`, which RuboCop's own Prism translator
    // rewrites into that same "block whose send is `lambda`" shape, so both
    // collapse to the same frame here). `Block` carries what upstream reads
    // off the block's owning `send_node`: whether it has an explicit
    // receiver (`chained_send?`), whether it's a bare `define_method`/
    // `define_singleton_method` call (breaks the climb without offending),
    // and whether the block itself declares any parameters
    // (`argument_list.empty?`).
    pub(crate) nle_stack: Vec<NleFrame>,
    // One-shot: `(is_lambda_call, has_receiver, is_define_method)` for the
    // block a `visit_call_node` is about to descend into — set right before
    // that descent, consumed by the immediately following `visit_block_node`
    // call. `None` when a block is reached some other way (e.g. owned by a
    // `super`/`zsuper` call): upstream's `chained_send?`/`define_method?`
    // patterns only ever match a `send`/`csend` node, so those default to
    // "no receiver, not define_method" — never scoped, never chained.
    pub(crate) nle_pending: Option<(bool, bool, bool)>,
    // Naming/MemoizedInstanceVariableName: the enclosing `define_method`/
    // `define_singleton_method` call's method-name argument — rubocop's
    // `method_definition?` pattern `(block (send _ %DYNAMIC_DEFINE_METHODS
    // ({sym str} $_)) ...)` (any receiver, exactly one literal symbol/string
    // arg). Stashed by `visit_call_node` right before descending into a
    // block, consumed by the immediately following `visit_block_node`.
    // `Some(None)` when the call has a block but doesn't qualify (wrong
    // name/arity/arg shape); plain `None` when unset (non-block calls).
    pub(crate) mivn_pending_method_name: Option<Option<Vec<u8>>>,
    // Lint/UselessTimes: start offsets of nodes that are the RECEIVER of, or a
    // direct positional ARGUMENT to, an enclosing (non-safe-navigation) call —
    // rubocop's `node.parent&.send_type?` guard (whitequark's `:block`/`:send`
    // node for a call wraps its receiver/args as direct children; a hash pair
    // or array element does NOT count, matching whitequark's `:pair`/`:array`
    // parent types). Populated eagerly in `visit_call_node` before descending,
    // so it's already complete by the time a nested `send` is visited.
    pub(crate) ut_call_child: HashSet<usize>,
    // Style/EmptyCaseCondition: start offsets of empty-condition `case` nodes
    // found in a structural position upstream's `NOT_SUPPORTED_PARENT_TYPES`
    // forbids (`case_node.parent&.type` in `%i[return break next send csend]`)
    // — a `case` that's the value of a `return`/`break`/`next`, or the
    // receiver/argument of a method call (`send`/`csend` are both prism
    // `CallNode`, so both track here regardless of safe-navigation).
    // Populated eagerly, before the nested `case` node is itself visited, by
    // `visit_return_node`/`visit_break_node`/`visit_next_node` (the case is
    // the return/break/next's sole argument, past the transparent
    // `ArgumentsNode` wrapper) and by `visit_call_node`'s existing
    // receiver/argument loops.
    pub(crate) ecc_no_offense: HashSet<usize>,
    // Layout/EmptyLinesAroundAccessModifier: whether the bare access
    // modifier currently under consideration sits somewhere that traces
    // back — through class/module/sclass/block/kwbegin/if branches — to a
    // class-like or top-level context (rubocop-ast's `in_macro_scope?`).
    // Pushed/popped around class/module/sclass (always TRUE) and `def`
    // (always FALSE); a `Class.new`/`Module.new`/`Struct.new`/`Data.define`
    // block ALSO pushes TRUE unconditionally. Every other construct (any
    // other block, an explicit `begin...end`, an `if`/`unless` branch) is
    // transparent — it doesn't touch the stack at all, which is exactly
    // upstream's `kwbegin begin any_block (if _condition <%0 _>)
    // #in_macro_scope?` recursion (prism gives every branch/body its own
    // `StatementsNode`, so there's no whitequark "sole statement" to chase
    // up through `parent.parent` for). An empty stack means "top-level
    // program" (root), which is always TRUE.
    pub(crate) el_am_scope: Vec<bool>,
    // rubocop's `@class_or_module_def_first_line`/`@class_or_module_def_last_line`
    // ivars — NOT a stack: plain fields overwritten (never restored) every
    // time a class/module/sclass node is entered, exactly mirroring
    // upstream's non-nesting-aware ivar bug-for-bug.
    pub(crate) el_am_class_first_line: Option<usize>,
    pub(crate) el_am_class_last_line: Option<usize>,
    // rubocop's `@block_line` ivar — same non-restoring overwrite semantics,
    // updated on every block (any flavor: `do`/`end`, `{}`, numbered params,
    // `it`).
    pub(crate) el_am_block_line: Option<usize>,
    // One-shot flag consumed by the very next `visit_statements_node` call —
    // mirrors `block_owns_next_stmts` (Lint/ConstantDefinitionInBlock) but
    // kept separate so the two cops don't fight over the same flag.
    pub(crate) el_am_block_owns_next_stmts: bool,
    // One-shot flag set by `visit_call_node` right before descending into a
    // block it owns, when that block is a `Class.new`/`Module.new`/
    // `Struct.new`/`Data.define` constructor — consumed by the immediately
    // following `visit_block_node` call.
    pub(crate) el_am_ctor_block: bool,
    // One-shot flag set by `visit_call_node` right before descending into a
    // block it owns, when that block is specifically a `Struct.new`/`Data.define`
    // constructor (NOT Class.new or Module.new) — consumed by the immediately
    // following `visit_block_node` call.
    pub(crate) metrics_ctor_block: bool,
    // Metrics/ParameterLists: stack tracking whether we're inside a
    // Struct.new/Data.define block (true) or not (false). Pushed when
    // visiting such a block, popped when leaving.
    pub(crate) metrics_in_struct_data_define_block: Vec<bool>,
    // Style/GlobalStdStream: start offsets of bare `STDIN`/`STDOUT`/`STDERR`
    // ConstantReadNode values already known to be the RHS of a matching
    // `$stdin`/`$stdout`/`$stderr` plain global-var assignment (rubocop's
    // `const_to_gvar_assignment?` node-pattern) — populated eagerly in
    // `visit_global_variable_write_node` before descending into the value,
    // so it's already complete by the time the constant itself is visited.
    // A `::STDIN`-style ConstantPathNode value never qualifies (its
    // whitequark namespace child is a non-nil `cbase`, not `nil?`), so only
    // ConstantReadNode offsets are ever inserted here.
    pub(crate) gss_gvasgn_skip: HashSet<usize>,
    // Gemspec/RubyVersionGlobalsUsage: (start, end) byte ranges of
    // ConstantPathNodes that are the assignment TARGET of an enclosing
    // constant-path write (`Ruby::VERSION = x`, `+=`, `||=`, `&&=`) —
    // whitequark folds the whole target into a `casgn`, so upstream's
    // `on_const` never sees it, while prism traversal visits it as a plain
    // ConstantPathNode. Populated eagerly in the visit_constant_path_*write
    // overrides before descending. Keyed by (start, end), NOT just start,
    // because the target's own namespace segments share its start offset
    // (`Ruby::VERSION::FOO = 1` — the inner `Ruby::VERSION` scope IS still
    // flagged by upstream) and must not be swallowed by the skip.
    pub(crate) rvgu_write_target_skip: HashSet<(usize, usize)>,
    // Gemspec/RequiredRubyVersion: has a `xxx.required_ruby_version = ...`
    // send been seen anywhere in the file? Set while visiting call nodes;
    // consulted once at the end of `visit_program_node` (rubocop's
    // `def_node_search` existence scan over the whole AST).
    pub(crate) grrv_seen: bool,
    // Layout/MultilineArrayBraceLayout / MultilineHashBraceLayout: start
    // offsets of array/hash LITERALS that are either the RECEIVER of an
    // enclosing call (any flavor, incl. safe-navigation — rubocop's
    // `chained?`) or a direct positional ARGUMENT of an enclosing
    // NON-safe-navigation call (`argument?`) — populated eagerly in
    // `visit_call_node` before descending. Method-definition brace layout
    // never needs this: its "node" is the parameters list, whose parent is
    // always the `def`/`defs`, never a call.
    pub(crate) mlbl_call_child: HashSet<usize>,
    // Layout/DefEndAlignment: def-node start offsets already handled (either
    // via an enclosing `def`-modifier chain's `on_send`, or via `on_def`
    // itself) — rubocop's `ignore_node`/`ignored_node?`. A def-modifier chain
    // (`foo bar def m; end`) fires `on_send` once per qualifying call in the
    // chain (outermost visited first); only the first actually checks/offends
    // — every other visit (including the def's own `on_def`) short-circuits.
    pub(crate) dea_ignored: HashSet<usize>,
    // Layout/DefEndAlignment: def-node start offset -> the start offset of
    // the immediate (single-level) wrapping call, when the def is the
    // resolved target of a `def`-modifier chain — rubocop's
    // `node.parent&.send_type?` used by the cop's OWN `autocorrect` override,
    // which anchors the `end` correction to the immediate parent even when
    // the offense message (computed from the outermost call in a multi-level
    // chain) reports a different column.
    pub(crate) dea_parent: HashMap<usize, usize>,
    // Layout/ClosingHeredocIndentation: a CallNode's own start offset -> the
    // climbed-chain root it inherits from an ENCLOSING call that found it as
    // its receiver or a (non-safe-nav) argument — `find_node_used_heredoc_
    // argument`'s `node.parent&.send_type?` climb, computed top-down in
    // `visit_call_node` (outer calls are visited, and populate this, before
    // the inner call they wrap is ever reached).
    pub(crate) chi_call_root: HashMap<usize, usize>,
    // Layout/ClosingHeredocIndentation: a heredoc's opening-token start
    // offset -> (resolved root call's own start offset, is_argument) once
    // the heredoc is found to be that call's receiver (`chained?`, `false`)
    // or a direct positional argument (`argument?`, `true`) — the only two
    // cases `argument_indentation_correct?` special-cases; everything else
    // falls back to the plain opening-vs-closing-line comparison.
    pub(crate) chi_heredoc_ctx: HashMap<usize, (usize, bool)>,
    // Layout/HeredocIndentation: opening-token start offsets of heredocs that
    // are the receiver of a zero-argument `.squish`/`.squish!` call —
    // `squish_method?`'s `(send _ {:squish :squish!})` pattern, precomputed
    // top-down in `visit_call_node` the same way `chi_heredoc_ctx` is (the
    // receiver is visited AFTER this call registers it).
    pub(crate) squish_heredoc: HashSet<usize>,
    // Lint/ImplicitStringConcatenation: start offsets of nodes that are a
    // direct ELEMENT of an array literal — rubocop's `node.parent&.array_type?`
    // guard, consulted only to pick the "separate array elements" message
    // suffix. Populated eagerly in `visit_array_node` before descending.
    pub(crate) isc_array_child: HashSet<usize>,
    // Lint/ImplicitStringConcatenation: start offsets of nodes that are the
    // RECEIVER of, or a direct positional ARGUMENT to, an enclosing
    // (non-safe-navigation) call — rubocop's `node.parent&.send_type?` guard,
    // consulted only to pick the "separate method arguments" message suffix.
    // Mirrors `ut_call_child`/`mlbl_call_child`; kept as its own field per
    // this file's one-field-per-cop convention.
    pub(crate) isc_send_child: HashSet<usize>,
    // Style/Alias: nearest-enclosing-scope stack for `scope_type` (rubocop's
    // ancestor walk stopping at the first `class`/`module` (0 = :lexical),
    // `def`/`defs`/block-or-lambda-not-instance_eval (1 = :dynamic), or an
    // `instance_eval` block (2 = :instance_eval)). Pushed by
    // `visit_class_node`/`visit_module_node` (0), `visit_def_node` (1,
    // regardless of receiver — defs counts as :dynamic same as def),
    // `visit_lambda_node` (1 — a stabby lambda is a "block whose send is
    // `lambda`", never instance_eval), and `visit_block_node` (1 or 2, from
    // `alias_pending_instance_eval`). Nodes that don't match any of these
    // (if/begin/`class << self`/...) push nothing, so the climb transparently
    // passes through them — mirrors rubocop's `case parent.type` falling
    // through unmatched types. Empty stack == top level == :lexical.
    pub(crate) alias_scope_stack: Vec<u8>,
    // Style/Alias: nearest-enclosing class-or-module stack for
    // `lexical_scope_type` (rubocop's `node.each_ancestor(:class,
    // :module).first` — unlike `scope_type` above, this ancestor search
    // passes straight through `def`/block/lambda frames, only stopping at an
    // actual `class`/`module`). `true` = class, `false` = module; empty ==
    // top level. Pushed only by `visit_class_node`/`visit_module_node`.
    pub(crate) alias_cm_stack: Vec<bool>,
    // Style/TrivialAccessors: nearest-enclosing "barrier" ancestor for
    // `in_module_or_instance_eval?` (rubocop's `node.each_ancestor(:any_block,
    // :class, :sclass, :module)` walk, stopping at the FIRST ancestor of one
    // of those types: `class`/`sclass` -> not exempt (0), `module` -> exempt
    // (1), a block whose owning call is `instance_eval` -> exempt (2)). A
    // non-instance_eval block/lambda is transparent — mirrors upstream's
    // `else` branch falling through to the NEXT ancestor without returning —
    // so it pushes nothing; `last()` is always the nearest real barrier, if
    // any (empty stack == top level == not exempt, same as `class`/`sclass`).
    pub(crate) ta_barrier: Vec<u8>,
    // Style/TrivialAccessors: start offsets of DefNodes that are a direct
    // argument of ANY call (`private def foo; end`, …) — rubocop's
    // `autocorrect` guard `node.parent&.send_type?`, which (unlike
    // `def_macro_args` below) does NOT exempt access modifiers: the offense
    // still fires, only the correction is suppressed.
    pub(crate) ta_call_arg_defs: HashSet<usize>,
    // Style/Alias: count of enclosing PLAIN `def` nodes (receiver-less —
    // whitequark's `:def`, NOT `:defs`) — rubocop's `each_ancestor(:def)`
    // guard in `alias_method_possible?`. Only a regular instance-method body
    // blocks the `alias` -> `alias_method` correction (self would be the
    // instance, not the class, at runtime); a singleton `def self.foo`/`def
    // obj.foo` body does not increment this.
    pub(crate) alias_def_depth: usize,
    // Style/Alias: set by `visit_call_node` right before descending into a
    // block it owns (`self.visit(&b)`) — whether THIS call's method name is
    // `instance_eval`, for the immediately following `visit_block_node` to
    // push the right `alias_scope_stack` entry. `None` when the descent
    // wasn't reached that way (mirrors `nle_pending`/`ms_pending_block`).
    pub(crate) alias_pending_instance_eval: Option<bool>,
    // Style/Alias: start offsets of nodes that are a direct positional
    // ARGUMENT of an enclosing NON-safe-navigation call — rubocop's
    // `node.argument?` (`parent&.send_type? && parent.arguments.include?
    // (self)`). Used by `alias_method_value_used?` to skip `alias_method`
    // calls whose return value feeds another call (`public alias_method
    // :a, :b`). Populated eagerly in `visit_call_node`'s argument loop.
    pub(crate) alias_arg_offsets: HashSet<usize>,
    // Style/Alias: start offsets of `ConstantWriteNode` RHS values — rubocop's
    // `node.parent&.assignment?` guard in `alias_method_value_used?`
    // (`NAME = alias_method :a, :b`). Populated eagerly in
    // `visit_constant_write_node` before descending. Other assignment
    // flavors (ivar/cvar/gvar/lvar, op-assign, multiple-assignment) as the
    // direct RHS of an `alias_method` call aren't covered — untested by the
    // fixture and vanishingly rare (`alias_method`'s return value is a
    // symbol, not normally something worth assigning).
    pub(crate) alias_value_offsets: HashSet<usize>,
    // Style/RedundantInterpolation: start offsets of `InterpolatedStringNode`s
    // that are a direct PART of an implicit-concatenation wrapper (an outer
    // `InterpolatedStringNode` with no opening/closing quotes of its own,
    // e.g. `"#{sparta}" ' this is'`) — rubocop's `implicit_concatenation?`
    // (`node.parent&.dstr_type?`) guard. Populated eagerly in
    // `visit_interpolated_string_node` before descending.
    pub(crate) ri_concat_child: HashSet<usize>,
    // Style/RedundantInterpolation: start offsets of `InterpolatedStringNode`s
    // that are a direct ELEMENT of a percent-literal array (`%W(#{@var} foo)`)
    // — rubocop's `embedded_in_percent_array?` guard. Populated eagerly in
    // `visit_array_node` before descending.
    pub(crate) ri_percent_array_child: HashSet<usize>,
    // Style/PerlBackrefs: depth of enclosing interpolated string/regexp/xstring
    // nodes (InterpolatedStringNode, InterpolatedRegularExpressionNode,
    // InterpolatedXStringNode) — used to determine if backrefs need to be
    // wrapped in braces.
    pub(crate) interpolated_node_depth: usize,
    // Style/PerlBackrefs: depth of enclosing class/module nodes — used to
    // determine if Regexp constant needs :: prefix.
    pub(crate) class_module_depth: usize,
    // Metrics/ClassLength's `on_sclass` guard (`node.each_ancestor(:class)
    // .any?`): count of REAL `class` node ancestors currently open (module/
    // sclass/block nesting doesn't reset or contribute — only `class` does).
    pub(crate) cl_class_depth: usize,
    // Style/NonNilCheck: (start, end) offset spans of nodes marked via
    // `ignore_node` —
    // the trailing (or sole) statement of a predicate method's (`foo?`)
    // body, which prism always wraps in a `StatementsNode` regardless of
    // statement count. A later `on_send`-equivalent visit on the EXACT same
    // node is skipped, mirroring rubocop's node-identity `ignored_node?`.
    pub(crate) non_nil_ignored: HashSet<(usize, usize)>,
    // Layout/MultilineMethodCallBraceLayout: a CallNode's own start offset ->
    // (dot start offset, enclosing call's own end offset) when that call is
    // itself the DOT-CHAINED RECEIVER of an outer call (`X.method_name`) AND
    // its own first (positional) argument is a plain, non-interpolated
    // heredoc-opened string — `MultilineLiteralBraceCorrector#
    // use_heredoc_argument_method_chain?`/`#correct_heredoc_argument_method_
    // chain`. Populated top-down in `visit_call_node` (the outer chained call
    // is visited, and populates this for its receiver, before the receiver
    // itself is ever reached).
    pub(crate) mmcbl_heredoc_chain: HashMap<usize, (usize, usize)>,
    // Lint/SuppressedException: enclosing `kwbegin`/`any_def`/`any_block`
    // ancestor closing lines (outermost first) — `each_ancestor(:kwbegin,
    // :any_def, :any_block).first` needs only the NEAREST one's closing
    // line, so a simple stack (pushed on entry, popped on exit) suffices.
    pub(crate) se_ancestor_end_lines: Vec<usize>,
    // Style/RedundantSort: start offset of the LEFT operand of every `and`/
    // `or`/`&&`/`||` node in the file -> that logical node's operator
    // location (start, end) — rubocop's `node.parent&.operator_keyword?`
    // check needs the accessor node's PARENT, but prism gives no parent
    // pointers; populated eagerly in `visit_and_node`/`visit_or_node` before
    // descending into `left`, mirroring this file's established
    // "populate ahead of time, keyed by the child's own start offset" idiom
    // (see `ut_call_child` etc. above).
    pub(crate) redundant_sort_logical_left: HashMap<usize, (usize, usize)>,
    // Style/RaiseArgs: start offsets of a call node that is the immediate
    // LEFT/RIGHT operand of an `and`/`or` node, or the immediate then/else
    // branch of a ternary `IfNode` — matching upstream's `requires_parens?`
    // (`node.parent.operator_keyword? || (node.parent.if_type? &&
    // node.parent.ternary?)`), needed only when the parent turns out to BE
    // the `raise`/`fail` call this cop corrects. `operator_keyword?` is true
    // for AndNode/OrNode regardless of `&&`/`and` spelling, so both operands
    // of every logical node are registered unconditionally; populated
    // eagerly in `visit_and_node`/`visit_or_node`/`visit_if_node` before
    // descending, mirroring `redundant_sort_logical_left`'s "populate ahead
    // of time, keyed by the child's own start offset" idiom (prism gives no
    // parent pointers).
    pub(crate) ra_needs_parens: HashSet<usize>,
    // Naming/VariableName: depth of enclosing pattern-match PATTERN subtrees
    // (an `InNode`/`MatchRequiredNode`/`MatchPredicateNode`'s `.pattern()`,
    // not its `.statements()`/guard) — prism represents a plain pattern bind
    // (`in fooBar`) with the very same `LocalVariableTargetNode` used for
    // masgn/rescue/for-loop targets, but upstream's `on_lvasgn` is never
    // aliased from `on_match_var` (a DIFFERENT whitequark node type), so a
    // bare pattern binding itself is never checked — only a later READ of it
    // (an ordinary `lvar`) is. Non-zero while visiting such a `.pattern()`
    // suppresses the WRITE-side check on any `LocalVariableTargetNode`
    // reached along the way.
    pub(crate) pattern_depth: usize,
    // Naming/RescuedExceptionsVariableName: depth of "inside a resbody's own
    // statements" (NOT its `subsequent` sibling chain) — mirrors rubocop's
    // `node.each_ancestor(:resbody).any?` nested-rescue guard.
    pub(crate) renv_resbody_depth: usize,
    // Stack of per-kwbegin accumulators: (offending_name, preferred_name)
    // byte-string pairs for every offense found inside the currently-open
    // kwbegin (explicit `begin...end`) block — rubocop's autocorrect also
    // renames references in `kwbegin_node.right_siblings`. Byte strings
    // only (never a borrowed `Node`) so these don't need to track the
    // parse-tree lifetime. Popped into `renv_just_closed_kwbegin_renames`
    // when the kwbegin's own traversal finishes, consumed right after by
    // the loop in `visit_statements_node`.
    pub(crate) renv_pending_kwbegin_stack: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
    pub(crate) renv_just_closed_kwbegin_renames: Vec<(Vec<u8>, Vec<u8>)>,
    // Style/InfiniteLoop: `while`/`until` node start-offsets for which
    // upstream's `VariableForce`-based scope analysis would suppress the
    // offense entirely (a variable is introduced inside the loop body and
    // still referenced after it, so wrapping in `loop do...end` would change
    // scoping semantics). Precomputed once over the whole file before the
    // main visitor runs, since the check needs assignments/references that
    // occur textually AFTER the loop too — see `infinite_loop_skips`.
    pub(crate) il_no_offense: HashSet<usize>,
    // Lint/RedundantRequireStatement: (call's own start offset, enclosing
    // modifier-form conditional's own end offset) set right before recursing
    // into a modifier `if`/`unless`/`while`/`until` node's SOLE statement
    // when that statement is itself a bare call (any call — validity as a
    // redundant `require` is checked later) — rubocop's `node.parent&.
    // modifier_form?`, since prism gives no parent pointers. Consumed
    // (taken) the moment that exact call node is visited, whichever call it
    // turns out to be, so it never leaks to an unrelated node.
    pub(crate) rrs_modifier_end: Option<(usize, usize)>,
    // Naming/PredicatePrefix (UseSorbetSigs config only): start offsets of
    // `def`/`defs` nodes immediately preceded, in their enclosing
    // StatementsNode's body list, by a `sig { returns(T::Boolean) }` (or
    // `sig do...end`) call — rubocop's `node.left_sibling`-based
    // `sorbet_sig?(node, return_type: 'T::Boolean')`. Precomputed per
    // StatementsNode in `check_predicate_prefix_sig_scan` before its
    // children are visited.
    pub(crate) pp_sig_ok: HashSet<usize>,
    // Lint/MissingSuper: depth of enclosing `class`/`module`/`class << self`
    // ancestors — upstream's `node.each_ancestor(:class, :sclass,
    // :module).first` for `callback_method_def?` only needs to know ONE
    // exists (whichever it is), so a plain counter suffices.
    pub(crate) ms_scope_depth: usize,
    // Lint/MissingSuper: one entry per REAL `class` node ancestor (not
    // `module`/`sclass` — those don't push here, so a nested one is
    // transparently skipped, matching `each_ancestor(:class).first`):
    // whether that class's own superclass is "stateful" (present and not
    // `Object`/`BasicObject`/`AllowedParentClasses`). Consulted only when
    // `ms_block_stack` is empty (a block ancestor always takes priority —
    // see `ms_block_stack`'s doc).
    pub(crate) ms_class_stack: Vec<bool>,
    // Lint/MissingSuper: one entry per `any_block` ancestor (an ordinary
    // `do...end`/`{}` `BlockNode`, OR a stabby-lambda `LambdaNode` — both
    // translate to rubocop's `:block` type, so both count) — upstream's
    // `node.each_ancestor(:any_block).first` takes priority over any
    // `class` ancestor whenever one exists at all, however far out. `None`
    // = this nearest block isn't a `Class.new(x)`-with-exactly-one-arg
    // shape (`class_new_block`); `Some(b)` = it is, and `b` says whether
    // `x` is "stateful" (not an allowed class name).
    pub(crate) ms_block_stack: Vec<Option<bool>>,
    // Lint/MissingSuper: the `Some`/`None` `visit_block_node` should push
    // onto `ms_block_stack` for the block about to be visited — set by
    // `visit_call_node` right before its `self.visit(&b)` call (mirrors the
    // established `nle_pending` idiom) and consumed (`.take()`) at the top
    // of `visit_block_node`. Never sees a stabby lambda (those aren't
    // reached through a call's `.block()`), which always pushes `None`
    // directly instead.
    pub(crate) ms_pending_block: Option<bool>,
    // Layout/SpaceAroundKeyword: ancestor-kind stack maintained by
    // `visit_branch_node_enter`/`_leave` for EVERY branch node in the tree
    // (rubocop's `preceded_by_operator?` needs the real ancestor chain, and
    // prism gives no parent pointers) — see `Cops::sak_classify` in
    // layout.rs for the encoding. The TOP entry is always the node currently
    // being visited (pushed on entry), so a lookup climbs from index
    // `len - 2` downward.
    pub(crate) sak_ancestors: Vec<u8>,
    // Layout/SpaceAroundKeyword: start offsets of `end` keywords already
    // checked — an `elsif` chain's nested `IfNode`s (and `UnlessNode`'s
    // `else_clause` chain) all report the SAME `end_keyword_loc` in prism;
    // rubocop's `Base#add_offense` collapses those onto one offense via
    // range-identity, which this reproduces explicitly.
    pub(crate) sak_end_seen: HashSet<usize>,
    // Style/ExplicitBlockArgument: the owning call/super/zsuper site's shape
    // for the block about to be visited — set by `visit_call_node`/
    // `visit_super_node`/`visit_forwarding_super_node` right before their
    // `self.visit(&b)` (the established `nle_pending` idiom), consumed at
    // the top of `visit_block_node`. Always `Some` in practice: every
    // `BlockNode` is reached through exactly one of those three call sites.
    pub(crate) eba_pending: Option<EbaOwner>,
    // Style/ExplicitBlockArgument: one entry per active `def`/`defs`
    // ancestor, innermost last — see `EbaDefInfo`'s doc.
    pub(crate) eba_def_stack: Vec<EbaDefInfo>,
    // Style/ExplicitBlockArgument: start offsets of defs whose signature has
    // already received its `(&block)` edit this run — `@def_nodes.add?`.
    pub(crate) eba_def_fixed: HashSet<usize>,
    // Style/RescueModifier: `parenthesized?(node)` needs the enclosing
    // `(...)`'s own delimiter locations, but prism carries no parent
    // pointers. `visit_parentheses_node` records each of its DIRECT
    // statement children that is a `RescueModifierNode`, keyed by that
    // child's own start offset, BEFORE recursing — mirrors rubocop's
    // `node.parent && parentheses?(node.parent)` (only a rescue-modifier
    // that is itself a top-level statement of the enclosing parens counts,
    // not one nested deeper inside). Value: (open_start, open_end,
    // close_start, close_end) of the parens' own `(`/`)` delimiters.
    pub(crate) rescue_mod_parens: HashMap<usize, (usize, usize, usize, usize)>,
    // Lint/SafeNavigationConsistency: start offsets of offense ranges
    // already registered by an OUTER `and`/`or` node's pass over this same
    // chain — since `on_and`/`on_or` fires for EVERY `and`/`or` node in the
    // file (not just the topmost of a chain), a nested node's own pass can
    // recompute the very same candidate offense. Upstream's
    // `Base#add_offense` silently drops any later call whose range was
    // already claimed (`current_offense_locations.add?`); this reproduces
    // that dedup explicitly. Two distinct candidate ranges for this cop
    // never share a start offset, so keying on the start offset alone
    // (mirroring `sak_end_seen` above) is equivalent to upstream's
    // full-range identity check.
    pub(crate) snc_offended: HashSet<usize>,
    // Lint/SafeNavigationChain: immediate-parent context for a node, keyed
    // by that node's own start offset — populated pre-order in the handful
    // of visit_* overrides whose children can be the cop's candidate
    // "ordinary send after safe-navigation" node, since prism nodes carry
    // no parent pointer (unlike whitequark's `node.parent`). Consumed (and
    // left in place — a start offset is only ever queried once) by
    // `check_safe_navigation_chain`. See that function's doc comment for
    // the full mapping to upstream's `parent`-based predicates.
    pub(crate) snav_parent: HashMap<usize, lint_cops::SnavParent<'a>>,
    // Layout/ArrayAlignment: start offsets of bracketless `ArrayNode`s that
    // are the `value` of a `MultiWriteNode` — rubocop's `node.parent&
    // .masgn_type?` early return in `on_array` (a mass-assignment's bare
    // RHS list, e.g. `a, b =\n  1, 2`, is never itself alignment-checked).
    // Populated by `visit_multi_write_node` before descending.
    pub(crate) aa_masgn_rhs: HashSet<usize>,
    // Layout/ArrayAlignment: start offset of a bracketless `ArrayNode` that
    // is the `value` of an ordinary (non-masgn) assignment -> that write
    // node's own start offset, standing in for rubocop's `node.parent.loc
    // .line` (`target_method_lineno`'s non-`bracketed?` branch, needed only
    // under `EnforcedStyle: with_fixed_indentation`). Populated by the
    // `assignment_write!`/`assignment_operator_write!` macros before
    // descending into the value.
    pub(crate) aa_unbracketed_rhs_parent: HashMap<usize, usize>,
    // Layout/ArrayAlignment: byte ranges of every offense node registered so
    // far THIS RUN, in traversal order — rubocop's cop-instance-wide
    // `@current_offenses` (populated by `Base#add_offense` across the whole
    // file, not just the current array's own siblings), consulted by
    // `Alignment#check_alignment`'s overlap guard: a nested array's own
    // bad-alignment node that falls entirely inside an already-registered
    // (enclosing) offense is still reported, but its correction is skipped
    // (`register_offense(expr, nil)` -> `AlignmentCorrector.correct` no-ops
    // on a nil node) so the two rewrites don't collide in one pass.
    pub(crate) aa_registered_ranges: Vec<(usize, usize)>,
    // Style/SpecialGlobalVars: per-file `@required_english` flag — once a
    // `require 'English'` has been inserted (or was already present at the
    // relevant top-level position) for one offense, later offenses in the
    // same file must not insert a second one.
    pub(crate) sgv_required_english: bool,
    // Style/SpecialGlobalVars: `(start_offset, end_offset, is_require_english)`
    // for each of the Program's own top-level statements, computed once in
    // `visit_program_node` — mirrors rubocop's `RequireLibrary#ensure_required`
    // climbing every ancestor up to the root and consulting `@required_libs`/
    // `right_siblings`, which prism's parent-less nodes can't do directly.
    pub(crate) sgv_top_stmts: Vec<(usize, usize, bool)>,
    // Style/SpecialGlobalVars: true while visiting the `variable` of an
    // `EmbeddedVariableNode` (prism's dedicated node for the braceless
    // `"#$gvar"`/`"#@ivar"` interpolation shorthand) — upstream's
    // `node.parent&.type` being `:dstr`/`:xstr`/`:regexp` (only true for
    // THIS braceless form, never for a braced `"#{$gvar}"`, whose gvar's
    // parent is an intervening statements node) decides whether the
    // autocorrect replacement needs its own `{}` added.
    pub(crate) sgv_in_embedded_var: bool,
    // Style/SpecialGlobalVars: whether the CURRENT innermost interpolated
    // literal (set right before descending into its `parts()`) is one of
    // upstream's brace-eligible parent types (`:dstr`/`:xstr`/`:regexp` —
    // ordinary/x/regexp string literals) as opposed to `:dsym` (interpolated
    // symbol, e.g. `:"#$:"`), which upstream's own `%i[dstr xstr
    // regexp].include?` deliberately excludes: a braceless `#$var` inside a
    // dsym is autocorrected WITHOUT adding braces (arguably a rubocop
    // oddity, but this ports it verbatim).
    pub(crate) sgv_brace_eligible: bool,
    // Style/SpecialGlobalVars: gvar start offset -> (embedded-statements
    // node's own start/end offsets, outer-literal brace eligibility) — see
    // `visit_embedded_statements_node`'s doc.
    pub(crate) sgv_climb: HashMap<usize, (usize, usize, bool)>,
    // Lint/OutOfRangeRegexpRef: capture-count "the most recently seen
    // regexp gives `$1..$9` this many valid refs" state — mirrors
    // upstream's `@valid_ref` ivar. `Some(0)` at the start of every file
    // (matching `on_new_investigation`'s `@valid_ref = 0`, NOT `None` —
    // `$1` before any regexp at all is still a confident "0 captures"
    // verdict, not an unknown one). Becomes `None` whenever a
    // `RESTRICT_ON_SEND` call is seen that doesn't pan out (no regexp
    // literal receiver/argument) or an interpolated regexp is checked —
    // `None` means "never offend" (upstream's `return if @valid_ref.nil?`).
    pub(crate) oorr_valid_ref: Option<u32>,
    // Lint/RedundantSplatExpansion: per-splat container context, keyed by the
    // splat node's own start offset and populated EAGERLY while visiting
    // whichever node type can hold it directly (array literal element —
    // including the bracket-less array prism synthesizes for a bare splat
    // used as the WHOLE value of a simple/multiple assignment RHS — call
    // argument, `when` condition, `rescue` exception) since prism gives us no
    // parent pointers to look this up from the splat itself. Mirrors
    // upstream's `node.parent` (`method_argument?`/`part_of_an_array?`/
    // `redundant_brackets?`) and the `array_new_inside_array_literal?`
    // sibling check (`array_len`).
    pub(crate) rse_ctx: HashMap<usize, lint_cops::RseCtx>,
    // Lint/RedundantSplatExpansion: start offsets of nodes that are the
    // DIRECT `.value()` of a plain single-variable assignment (`lvasgn`/
    // `ivasgn`/`cvasgn`/`gvasgn`/`casgn` in upstream's whitequark terms —
    // deliberately NOT multiple assignment or any `+=`/`||=`/`&&=` compound
    // form) — mirrors upstream's `ASSIGNMENT_TYPES` grandparent check that
    // gates whether a splatted bare `Array.new(...)` call (with or without a
    // block) is flagged: `redundant_splat_expansion`'s `grandparent =
    // node.parent.parent` is exactly this node's parent whenever the splat's
    // immediate container equals that value outright.
    pub(crate) rse_assignment_value: HashSet<usize>,
    // Style/DoubleNegation: a hand-rolled "ancestor stack" mirroring exactly
    // the node kinds `allowed_in_returns?` climbs through (prism gives no
    // parent pointers) — pushed/popped by `visit_def_node`, `visit_block_node`
    // (only for a `define_method`/`define_singleton_method` block, via
    // `dn_pending_define_method`), `visit_if_node`/`visit_unless_node`/
    // `visit_while_node`/`visit_until_node`/`visit_case_node`/
    // `visit_case_match_node` (conditionals), `visit_array_node`/
    // `visit_hash_node`/`visit_assoc_node` (enumerable literals), and
    // `visit_statements_node` (a "begin"-equivalent, only when it actually
    // groups more than one statement — a single-statement body is
    // transparent in whitequark's tree, so no frame is pushed for it). See
    // `DnFrame`'s doc and `style::check_double_negation`.
    pub(crate) dn_ancestors: Vec<DnFrame>,
    // Style/DoubleNegation: start offsets of nodes that are a DIRECT argument
    // of a `return` — `visit_return_node` populates this (skipping the
    // `ArgumentsNode` wrapper prism interposes) BEFORE recursing, mirroring
    // `node.parent&.return_type?`, which only ever looks at the true
    // immediate parent (never a deeper descendant).
    pub(crate) dn_return_arg_offsets: HashSet<usize>,
    // Style/DoubleNegation: the `define_method`/`define_singleton_method`
    // call's own precomputed "last child" — set by `visit_call_node` right
    // before `self.visit(&b)` descends into that call's block (the
    // established `nle_pending` idiom), consumed at the top of
    // `visit_block_node`. `None` for an ordinary block.
    // Outer `None` = not a `define_method`/`define_singleton_method` call
    // (no frame pushed at all, matching upstream's `define_method?(parent)`
    // staying false); `Some(inner)` = it is one, `inner` being the call's own
    // `find_last_child` (which can itself be `None`, e.g. an argument-less
    // call — still a real `def_node` upstream, just with a `nil` last_child).
    pub(crate) dn_pending_define_method: Option<Option<DnLastChild>>,
    // Style/SignalException (`semantic` style): `raise`/`fail` CallNode
    // start offsets already classified by `on_rescue`'s scoped scans
    // (`check_scope`/`allow`, upstream's `ignore_node`/`ignored_node?`) so
    // the generic `on_send` handler never double-reports or misclassifies
    // them (a `raise` legitimately rethrown inside a `rescue` handler, or a
    // `raise`/`fail` already scored via a `begin`/`resbody` scope walk).
    pub(crate) sigex_ignored: HashSet<usize>,
    // Style/SignalException (`only_raise` style): memoized
    // `custom_fail_defined?` — true iff the file defines a `fail` instance
    // or singleton method anywhere (`def_node_search` over the whole AST,
    // computed once up front in `visit_program_node` rather than lazily on
    // first use, since our single-pass traversal has no per-cop memoized
    // accessor to hang the laziness off of).
    pub(crate) sigex_custom_fail_defined: bool,
    // Style/Next's `@reindented_lines` (`Hash.new(0)`, reset per
    // `on_new_investigation` i.e. once per file — matched here by simply
    // being a fresh field on each per-file `Cops` instance): cumulative
    // dedent already queued for a given 1-based line by an EARLIER (outer)
    // `next` correction in this SAME file, keyed by line number, so a
    // nested correction's own reindent widens the existing removal instead
    // of emitting a second, byte-identical-or-conflicting edit the apply
    // step would just drop. Maps line -> (index into `fixes` of that line's
    // current removal edit if one's been pushed yet, cumulative delta).
    pub(crate) nx_reindented: HashMap<usize, (Option<usize>, i64)>,
    // Style/MultipleComparison: (start, end) spans of `OrNode`s that are the
    // immediate `left`/`right` child of ANOTHER `OrNode` — mirrors
    // `root_of_or_node`'s parent-walk (prism gives no parent pointers). Keyed
    // by the FULL span, not just the start offset: a left-associative `||`
    // chain's outer node and its nested left child share the very same start
    // offset (both begin at the chain's leftmost token), so start-offset-only
    // keying (this file's usual "populate ahead of time" idiom) would
    // conflate them and wrongly skip the true root too. `visit_or_node` marks
    // both children (if they're themselves `OrNode`s) BEFORE descending, so
    // by the time traversal reaches a nested one, this is already populated;
    // `check_style_multiple_comparison` only ever processes the OUTERMOST
    // `or` of a chain (`node == root_of_or_node(node)`), i.e. one whose own
    // (start, end) is NOT in this set.
    pub(crate) mc_nested_or: HashSet<(usize, usize)>,
    // Lint/LiteralAsCondition: `IgnoredNode#ignore_node`/`part_of_ignored_node?`
    // for `correct_if_node`'s corrector block — (start, "whitequark-accurate"
    // end) byte ranges of every `if`/`elsif`/ternary node whose autocorrect
    // has already been applied THIS FILE, in traversal (i.e. outer-before-
    // inner) order. Before applying a further `if`-chain correction, the
    // candidate node's own (start, end) is checked against every range here;
    // if it falls inside one, only the offense (never the fix) is recorded —
    // mirrors upstream skipping autocorrection for a nested elsif/ternary
    // whose enclosing if/elsif was already rewritten (rewriting both would
    // double-edit overlapping text). See `lac_elsif_content_end`'s doc for
    // why a nested `elsif` node's own end here is NOT its raw prism
    // `location().end_offset()`.
    pub(crate) lac_ignored: Vec<(usize, usize)>,
    // Lint/Void: `each_ancestor(:any_block).first&.method?(:each)` — a
    // stack of "is this open block/`->` lambda ancestor a `.each` call",
    // pushed/popped by `visit_block_node`/`visit_lambda_node` for EVERY
    // block (prism's Prism-translator rewrites `->(){}` into the same
    // "block whose send is `lambda`" shape, so it's `false` there). Reading
    // `.last()` gives the NEAREST enclosing block regardless of how many
    // non-block nodes (if/case/def/...) sit in between — matches
    // `each_ancestor` walking straight up the parent chain.
    pub(crate) void_each_stack: Vec<bool>,
    // Lint/Void: the owning call's method name for the block about to be
    // visited, stashed by `visit_call_node` right before descending into a
    // LITERAL block (never for a `&:sym`/`&blk` block-PASS argument, which
    // never triggers `visit_block_node` at all) — consumed by
    // `visit_block_node` to compute `void_each_stack`'s top and
    // `BlockNode#void_context?` (`VOID_CONTEXT_METHODS = [:each, :tap]`).
    pub(crate) void_pending_block_name: Option<Vec<u8>>,
    // Lint/Void's `in_void_context?`: the void-context verdict for the
    // StatementsNode about to be visited, stashed by whichever caller
    // KNOWS it (`visit_def_node`/`visit_block_node`/`visit_for_node`/
    // `visit_ensure_node`, right before descending into a body that is
    // DIRECTLY a `StatementsNode` — never set when it's an implicit
    // rescue/ensure-wrapping `BeginNode` instead, matching upstream's
    // `parent.respond_to?(:void_context?)` being false for a `:rescue`/
    // `:ensure`-nested main body that isn't the LAST child). Consumed
    // (taken) unconditionally at the top of `visit_statements_node`, so it
    // can never leak into an unrelated, later-visited `StatementsNode`.
    // Absent (`None`) defaults to `false` — every other container type
    // (top-level program, `if`/`unless`/`when`/`in`/`rescue`/plain
    // `begin...end`) never responds to `void_context?` upstream either.
    pub(crate) void_pending_ctx: Option<bool>,
    // Style/HashSyntax (EnforcedShorthandSyntax parenthesization): for a
    // braceless keyword-hash argument's start offset, the call/super/yield
    // node that directly owns it (`find_ancestor_method_dispatch_node`) —
    // see `style::HsDispatch`'s doc.
    pub(crate) hs_call_ctx: HashMap<usize, style::HsDispatch>,
    // Style/HashSyntax: start offsets whose immediate parent is a
    // call/if/super/until/while/yield node (`requires_parentheses_context?`
    // — receiver/argument/predicate position, always forces added parens).
    pub(crate) hs_call_like_ctx: HashSet<usize>,
    // Style/HashSyntax: a node's start offset -> the start offset of the
    // assignment node it's the VALUE of (`last_expression?`'s assignment
    // climb, one hop per entry — chained assignments recurse through
    // multiple entries).
    pub(crate) hs_assign_parent: HashMap<usize, usize>,
    // Style/HashSyntax: start offsets that have a following statement in
    // their enclosing statements-list (`node.right_sibling`, restricted to
    // the "plain statement" case this cop's fixtures actually exercise).
    pub(crate) hs_stmt_next: HashSet<usize>,
    // Style/HashSyntax: start offsets whose immediate parent (after
    // transparently skipping a single-statement `StatementsNode` wrapper,
    // like whitequark does) is a `(...)` grouping (`parentheses?`).
    pub(crate) hs_paren_parent: HashSet<usize>,
    // Style/HashSyntax: live nesting depth of "modifier-form if/while/until"
    // ancestors at the current point of traversal
    // (`use_modifier_form_without_parenthesized_method_call?`'s
    // `ancestor.ancestors.any? { modifier_form? }` climb) — valid to read
    // only while still nested inside those ancestors, which on_pair/on_hash
    // always are (single-pass traversal, checked in pre-order).
    pub(crate) hs_modifier_depth: u32,
    // Style/HashSyntax: a pair's start offset -> the shared context of its
    // containing hash-like node (bounds, braced?, last-pair key==value) —
    // populated once per hash before its pairs are visited, so `on_pair`'s
    // per-pair check (which prism gives no parent pointer for) can look it
    // up. See `style::HsPairCtx`'s doc.
    pub(crate) hs_pair_ctx: HashMap<usize, style::HsPairCtx>,
    // Style/HashSyntax: braceless-keyword-hash start offsets already given
    // a `return`-wrapping `{`/`}` fix — a hash with 2+ shorthand-eligible
    // pairs would otherwise queue the identical wrap edit once per pair.
    pub(crate) hs_wrapped_return: HashSet<usize>,
}
impl<'a> Cops<'a> {
    /// Resolved once per run in Engine::new — this is a binary search over a
    /// short static list, called on every node for every check.
    pub(crate) fn on(&self, cop: &str) -> bool {
        if !self.file_disabled.is_empty() && self.file_disabled.iter().any(|c| *c == cop) {
            return false;
        }
        self.eng
            .enabled
            .binary_search_by(|(c, _)| (*c).cmp(cop))
            .map(|i| self.eng.enabled[i].1)
            .unwrap_or(false)
    }
    /// Is `text` exempt for `cop` via AllowedMethods (exact) or AllowedPatterns?
    pub(crate) fn allowed(&self, cop: &str, text: &[u8]) -> bool {
        let by_name = self
            .eng
            .allowed_methods
            .get(cop)
            .is_some_and(|names| names.iter().any(|n| n.as_bytes() == text));
        if by_name {
            return true;
        }
        self.eng
            .allowed_patterns
            .get(cop)
            .is_some_and(|pats| {
                let s = String::from_utf8_lossy(text);
                pats.iter().any(|re| re.is_match(&s))
            })
    }
    pub(crate) fn push(&mut self, off: usize, cop: &'static str, correctable: bool, msg: impl Into<String>) {
        let (line, mut col) = self.idx.loc(off);
        // rubocop columns count CHARACTERS; recount when the prefix has
        // multi-byte text (the ASCII case is byte == char).
        let prefix = &self.src[self.idx.starts[line - 1]..off];
        if !prefix.is_ascii() {
            col = String::from_utf8_lossy(prefix).chars().count() + 1;
        }
        let mut message = msg.into();
        if let Some(sfx) = self.eng.style_guide_suffix(cop) {
            message.push_str(&sfx);
        }
        self.offenses.push(Offense { line, col, cop, correctable, message });
    }
    pub(crate) fn node_src(&self, n: &ruby_prism::Node) -> &'a [u8] {
        let l = n.location();
        &self.src[l.start_offset()..l.end_offset()]
    }
    /// Style/MultilineTernaryOperator parent-tracking: `child` is a direct
    /// AST child of a node starting at `parent_start` (a plain assignment's
    /// RHS, `return`'s argument, a call's receiver/argument, ...). If `child`
    /// is a `?:` ternary, remember `parent_start` for comment hoisting, and
    /// (when `single_line_eligible`) mark it as one whose correction collapses
    /// to a single-line ternary instead of expanding to `if`/`else`.
    pub(crate) fn mto_note_child(&mut self, child: &ruby_prism::Node, parent_start: usize, single_line_eligible: bool) {
        if !self.on("Style/MultilineTernaryOperator") {
            return;
        }
        let Some(iff) = child.as_if_node() else { return };
        if iff.if_keyword_loc().is_some() {
            return;
        }
        let off = iff.location().start_offset();
        self.mto_parent_start.insert(off, parent_start);
        if single_line_eligible {
            self.mto_single_line.insert(off);
        }
    }
    /// Style/IdenticalConditionalBranches parent-tracking (see the
    /// `icb_assign_start` field doc comment): if `value` is directly an
    /// `if`/`case`/`case_match` node, remember that its enclosing assignment
    /// starts at `lhs_start`.
    pub(crate) fn icb_note_assignment_value(&mut self, lhs_start: usize, value: &ruby_prism::Node) {
        if value.as_if_node().is_some() || value.as_case_node().is_some() || value.as_case_match_node().is_some() {
            self.icb_assign_start.insert(value.location().start_offset(), lhs_start);
        }
    }
    /// Style/GuardClause parent-tracking (see the `gc_assignment_value_starts`
    /// field doc comment): if `value` is directly an `if`/`unless` node,
    /// remember that it sits as an assignment's RHS — `accepted_form?`'s
    /// `node.parent&.assignment?` guard.
    pub(crate) fn gc_note_assignment_value(&mut self, value: &ruby_prism::Node) {
        if value.as_if_node().is_some() || value.as_unless_node().is_some() {
            self.gc_assignment_value_starts.insert(value.location().start_offset());
        }
    }
    /// Autocorrects for DECLARATIVE-table cops (the one thing a pattern row
    /// can't express). Returns whether a fix was produced.
    fn decl_fix(&mut self, cop: &str, node: &ruby_prism::CallNode) -> bool {
        let l = node.location();
        match cop {
            "Style/NilComparison" => {
                let Some(recv) = node.receiver() else { return false };
                if node.name().as_slice() == b"nil?" {
                    // `.nil?` -> ` == nil` (dot through selector end)
                    let (Some(dot), Some(sel)) = (node.call_operator_loc(), node.message_loc()) else {
                        return false;
                    };
                    self.fixes.push((dot.start_offset(), sel.end_offset(), b" == nil".to_vec()));
                } else {
                    // `x == nil` -> `x.nil?` (receiver end through node end)
                    let re = recv.location().end_offset();
                    self.fixes.push((re, l.end_offset(), b".nil?".to_vec()));
                }
                // parenthesize when the parent is a `!` call
                if self
                    .call_stack
                    .last()
                    .is_some_and(|sp| &self.src[sp.0..sp.1] == b"!")
                {
                    self.fixes.push((l.start_offset(), l.start_offset(), b"(".to_vec()));
                    self.fixes.push((l.end_offset(), l.end_offset(), b")".to_vec()));
                }
                true
            }
            "Lint/BigDecimalNew" => {
                // `BigDecimal.new(x)` -> `BigDecimal(x)`; a `::` anchor drops
                if let (Some(dotish), Some(sel)) = (node.call_operator_loc(), node.message_loc()) {
                    self.fixes.push((dotish.start_offset(), sel.end_offset(), Vec::new()));
                    if let Some(r) = node.receiver() {
                        if self.node_src(&r).starts_with(b"::") {
                            let rs = r.location().start_offset();
                            self.fixes.push((rs, rs + 2, Vec::new()));
                        }
                    }
                    return true;
                }
                false
            }
            "Style/ArrayJoin" => {
                let (Some(recv), Some(arg)) = (
                    node.receiver(),
                    node.arguments().and_then(|a| a.arguments().iter().next()),
                ) else {
                    return false;
                };
                let rep = format!(
                    "{}.join({})",
                    String::from_utf8_lossy(self.node_src(&recv)),
                    String::from_utf8_lossy(self.node_src(&arg))
                );
                self.fixes.push((l.start_offset(), l.end_offset(), rep.into_bytes()));
                true
            }
            _ => false,
        }
    }

    /// Lint/NonLocalExitFromIterator: whether a block's `parameters()` yields
    /// a non-empty `argument_list` — upstream's `BlockNode#argument_list`.
    /// A numbered-param (`_1`) or `it`-param block ALWAYS counts (prism only
    /// produces those node kinds when the block body actually uses `_1..._9`
    /// / bare `it`); an explicit `|...|` block counts only if it actually
    /// declares a required/optional/rest/keyword/keyword-rest/post/block
    /// param (matches `each_descendant(:argument)` — an empty `|| `
    /// delimiter pair has none).
    fn nle_block_has_args(params: &Option<ruby_prism::Node>) -> bool {
        let Some(p) = params else { return false };
        if p.as_numbered_parameters_node().is_some() || p.as_it_parameters_node().is_some() {
            return true;
        }
        let Some(bp) = p.as_block_parameters_node() else { return false };
        let Some(inner) = bp.parameters() else { return false };
        inner.requireds().iter().count() > 0
            || inner.optionals().iter().count() > 0
            || inner.rest().is_some()
            || inner.posts().iter().count() > 0
            || inner.keywords().iter().count() > 0
            || inner.keyword_rest().is_some()
            || inner.block().is_some()
    }
    /// Names of `class` nodes that are direct children of `body`.
    fn direct_child_classes(body: &Option<ruby_prism::Node>) -> Vec<Vec<u8>> {
        body.as_ref()
            .and_then(|b| b.as_statements_node())
            .map(|stmts| {
                stmts
                    .body()
                    .iter()
                    .filter_map(|n| n.as_class_node().map(|c| c.name().as_slice().to_vec()))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Check if the body of a class/module contains a custom `attr` method definition.
    fn has_custom_attr_method_in_body(body: &Option<ruby_prism::Node>) -> bool {
        body.as_ref()
            .and_then(|b| b.as_statements_node())
            .map(|stmts| {
                stmts
                    .body()
                    .iter()
                    .any(|n| {
                        if let Some(def) = n.as_def_node() {
                            def.name().as_slice() == b"attr"
                        } else {
                            false
                        }
                    })
            })
            .unwrap_or(false)
    }
    /// AllowComments guard: skip when enabled and a comment sits inside the block
    /// body (opening line through the line before the closer, so a trailing
    /// `end # comment` doesn't count).
    pub(crate) fn block_has_inner_comment(&self, open: usize, close: usize) -> bool {
        let l0 = self.idx.loc(open).0;
        let l1 = self.idx.loc(close).0;
        (l0..l1).any(|ln| self.comment_lines.contains(&ln))
    }
}

// Layout/AssignmentIndentation: the four write-node shapes share these field
// layouts (see `layout.rs` for the actual check). Plain/`||=`/`&&=` writes
// expose `name_loc`+`operator_loc`; compound (`+=` etc) writes expose
// `name_loc`+`binary_operator_loc`; `Foo::Bar = x` path writes expose
// `target()` (a `ConstantPathNode`) instead of `name_loc`.
macro_rules! assignment_write {
    ($self:expr, $node:expr) => {{
        let lhs_start = $node.name_loc().start_offset();
        let op_end = $node.operator_loc().end_offset();
        $self.aa_note_unbracketed_rhs(lhs_start, &$node.value());
        $self.assignment_indentation_hook(lhs_start, op_end, $node.value());
        $self.icb_note_assignment_value(lhs_start, &$node.value());
        $self.gc_note_assignment_value(&$node.value());
    }};
}
macro_rules! assignment_operator_write {
    ($self:expr, $node:expr) => {{
        let lhs_start = $node.name_loc().start_offset();
        let op_end = $node.binary_operator_loc().end_offset();
        $self.aa_note_unbracketed_rhs(lhs_start, &$node.value());
        $self.assignment_indentation_hook(lhs_start, op_end, $node.value());
        $self.icb_note_assignment_value(lhs_start, &$node.value());
        $self.gc_note_assignment_value(&$node.value());
    }};
}
macro_rules! assignment_path_write {
    ($self:expr, $node:expr) => {{
        let lhs_start = $node.target().location().start_offset();
        let op_end = $node.operator_loc().end_offset();
        $self.assignment_indentation_hook(lhs_start, op_end, $node.value());
        $self.icb_note_assignment_value(lhs_start, &$node.value());
        $self.gc_note_assignment_value(&$node.value());
    }};
}
macro_rules! assignment_path_operator_write {
    ($self:expr, $node:expr) => {{
        let lhs_start = $node.target().location().start_offset();
        let op_end = $node.binary_operator_loc().end_offset();
        $self.assignment_indentation_hook(lhs_start, op_end, $node.value());
        $self.icb_note_assignment_value(lhs_start, &$node.value());
        $self.gc_note_assignment_value(&$node.value());
    }};
}

impl<'pr, 'a> Visit<'pr> for Cops<'a> {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        self.check_string_literals(node);
        self.check_string_literals_in_interpolation(node);
        self.check_character_literal(node);
        self.check_gvar_artifact(node);
        self.check_heredoc_delimiter_naming(node.opening_loc(), node.closing_loc());
        self.check_heredoc_delimiter_case(node.opening_loc(), node.closing_loc());
        self.check_closing_heredoc_indentation(node.opening_loc(), node.closing_loc());
        {
            let c = node.content_loc();
            self.check_heredoc_indentation(node.opening_loc(), node.closing_loc(), c.start_offset(), c.end_offset());
        }
        self.check_interpolation_check(node);
        self.check_redundant_percent_q_str(node);
        self.check_percent_q_literals(node);
        self.check_bare_percent_literals_str(node);
        self.check_percent_literal_delimiters_str(node);
        self.ll_check_str(node);
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        // `'a' \` line-continuation concatenation parses as this node with
        // quoted string parts — the ConsistentQuotesInMultiline check.
        self.check_string_concat(node);
        self.check_implicit_string_concatenation(node);
        self.check_heredoc_delimiter_naming(node.opening_loc(), node.closing_loc());
        self.check_heredoc_delimiter_case(node.opening_loc(), node.closing_loc());
        self.check_closing_heredoc_indentation(node.opening_loc(), node.closing_loc());
        // `on_dstr` (Heredoc mixin aliases it to `on_str`): the body location
        // isn't a single `content_loc` for an interpolated node — mirror
        // `HeredocFinder`'s own span (first part's start through the closing
        // delimiter's start).
        if let (Some(first), Some(close)) = (node.parts().iter().next(), node.closing_loc()) {
            self.check_heredoc_indentation(
                node.opening_loc(),
                node.closing_loc(),
                first.location().start_offset(),
                close.start_offset(),
            );
        }
        self.check_interpolation_check_dstr(node);
        self.check_redundant_percent_q_dstr(node);
        self.check_lii_dstr(node);
        self.check_bare_percent_literals_dstr(node);
        self.check_percent_literal_delimiters_dstr(node);
        self.ll_check_dstr(node);
        self.check_redundant_interpolation(node);
        // Mark direct parts of an implicit-concatenation wrapper (an outer
        // `InterpolatedStringNode` with no quotes of its own gluing 2+
        // adjacent literals, e.g. `"#{sparta}" ' this is'`) before
        // descending, so `check_redundant_interpolation` can recognize a
        // nested single-interpolation part as excluded (rubocop's
        // `implicit_concatenation?`).
        if self.on("Style/RedundantInterpolation") && node.opening_loc().is_none() {
            let parts: Vec<ruby_prism::Node> = node.parts().iter().collect();
            if parts.len() >= 2 {
                for p in &parts {
                    self.ri_concat_child.insert(p.location().start_offset());
                }
            }
        }
        let delim = node.opening_loc().and_then(|o| match o.as_slice() {
            b"'" | b"\"" => Some(o.as_slice()[0]),
            _ => None,
        });
        if let Some(d) = delim {
            self.ll_dstr_delim.push(d);
        }
        self.interpolated_node_depth += 1;
        let prev_brace_eligible = self.sgv_brace_eligible;
        self.sgv_brace_eligible = true;
        ruby_prism::visit_interpolated_string_node(self, node);
        self.sgv_brace_eligible = prev_brace_eligible;
        self.interpolated_node_depth -= 1;
        if delim.is_some() {
            self.ll_dstr_delim.pop();
        }
    }
    fn visit_symbol_node(&mut self, node: &ruby_prism::SymbolNode<'pr>) {
        self.check_boolean_symbol(node);
        self.check_symbol_literal(node);
        self.check_percent_literal_delimiters_sym(node);
        self.check_variable_number_sym(node);
    }
    fn visit_interpolated_symbol_node(&mut self, node: &ruby_prism::InterpolatedSymbolNode<'pr>) {
        self.check_lii_dsym(node);
        let prev_brace_eligible = self.sgv_brace_eligible;
        self.sgv_brace_eligible = false;
        ruby_prism::visit_interpolated_symbol_node(self, node);
        self.sgv_brace_eligible = prev_brace_eligible;
    }
    fn visit_interpolated_regular_expression_node(
        &mut self,
        node: &ruby_prism::InterpolatedRegularExpressionNode<'pr>,
    ) {
        self.check_lii_iregexp(node);
        self.check_percent_literal_delimiters_iregexp(node);
        self.check_regexp_literal_interpolated(node);
        self.interpolated_node_depth += 1;
        let prev_brace_eligible = self.sgv_brace_eligible;
        self.sgv_brace_eligible = true;
        ruby_prism::visit_interpolated_regular_expression_node(self, node);
        self.sgv_brace_eligible = prev_brace_eligible;
        self.interpolated_node_depth -= 1;
    }
    fn visit_interpolated_x_string_node(&mut self, node: &ruby_prism::InterpolatedXStringNode<'pr>) {
        self.check_command_literal_ixstr(node);
        self.check_space_inside_percent_literal_delimiters_ixstr(node);
        self.check_percent_literal_delimiters_ixstr(node);
        self.check_lii_ixstr(node);
        self.check_heredoc_delimiter_case(Some(node.opening_loc()), Some(node.closing_loc()));
        self.check_closing_heredoc_indentation(Some(node.opening_loc()), Some(node.closing_loc()));
        // whitequark's `xstring_compose` always builds a plain `:xstr` node
        // (interpolated or not — there is no `:dxstr`), so `Heredoc#on_xstr`
        // (aliased to `#on_str`) covers THIS node too; body span mirrors the
        // `InterpolatedStringNode` case (first part's start through the
        // closing delimiter's own start).
        if let Some(first) = node.parts().iter().next() {
            self.check_heredoc_indentation(
                Some(node.opening_loc()),
                Some(node.closing_loc()),
                first.location().start_offset(),
                node.closing_loc().start_offset(),
            );
        }
        self.xstr_interp_base.push(self.interp_depth);
        self.interpolated_node_depth += 1;
        let prev_brace_eligible = self.sgv_brace_eligible;
        self.sgv_brace_eligible = true;
        ruby_prism::visit_interpolated_x_string_node(self, node);
        self.sgv_brace_eligible = prev_brace_eligible;
        self.interpolated_node_depth -= 1;
        self.xstr_interp_base.pop();
    }
    fn visit_x_string_node(&mut self, node: &ruby_prism::XStringNode<'pr>) {
        self.check_command_literal_xstr(node);
        self.check_heredoc_delimiter_naming(Some(node.opening_loc()), Some(node.closing_loc()));
        self.check_heredoc_delimiter_case(Some(node.opening_loc()), Some(node.closing_loc()));
        self.check_closing_heredoc_indentation(Some(node.opening_loc()), Some(node.closing_loc()));
        {
            let c = node.content_loc();
            self.check_heredoc_indentation(
                Some(node.opening_loc()),
                Some(node.closing_loc()),
                c.start_offset(),
                c.end_offset(),
            );
        }
        self.check_space_inside_percent_literal_delimiters_xstr(node);
        self.check_percent_literal_delimiters_xstr(node);
        ruby_prism::visit_x_string_node(self, node);
    }
    fn visit_hash_node(&mut self, node: &ruby_prism::HashNode<'pr>) {
        self.check_hash_syntax_hash(node);
        self.check_duplicate_hash_key(node);
        self.check_multiline_hash_brace_layout(node);
        self.check_trailing_comma_in_hash_literal(node);
        if self.ll_active {
            let l = node.location();
            self.ll_enter_collection(
                l.start_offset(),
                l.end_offset(),
                node.elements().iter().count(),
                || node
                    .elements()
                    .iter()
                    .map(|e| (e.location().start_offset(), e.location().end_offset()))
                    .collect(),
                breakable::LlKind::Hash,
                breakable::LlCallInfo::default(),
            );
        }
        // Style/DoubleNegation: `find_parent_not_enumerable`'s `hash_type?`.
        self.dn_ancestors.push(DnFrame::Enumerable {
            start: node.location().start_offset(),
            child_starts: node.elements().iter().map(|e| e.location().start_offset()).collect(),
        });
        ruby_prism::visit_hash_node(self, node);
        self.dn_ancestors.pop();
        self.ll_exit_collection();
    }
    fn visit_keyword_hash_node(&mut self, node: &ruby_prism::KeywordHashNode<'pr>) {
        self.check_hash_syntax_keyword_hash(node);
        ruby_prism::visit_keyword_hash_node(self, node);
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        if self.ll_active {
            self.ll_str_skip.insert(node.value().location().start_offset());
        }
        self.check_space_after_colon_kwoptarg(node);
        self.check_circular_argument_reference(node.name().as_slice(), &node.value());
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_optional_keyword_parameter_node(self, node);
    }
    fn visit_optional_parameter_node(&mut self, node: &ruby_prism::OptionalParameterNode<'pr>) {
        self.check_space_around_equals_in_parameter_default(node);
        self.check_circular_argument_reference(node.name().as_slice(), &node.value());
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        // Style/MethodCallWithoutArgsParentheses's `default_argument?`:
        // `node.parent&.optarg_type?` — only the DIRECT value counts, not any
        // deeper descendant, so this is recorded here rather than via a stack.
        if let Some(call) = node.value().as_call_node() {
            self.mcwap_optarg_default.insert(call.location().start_offset());
        }
        ruby_prism::visit_optional_parameter_node(self, node);
    }
    fn visit_required_parameter_node(&mut self, node: &ruby_prism::RequiredParameterNode<'pr>) {
        // no `name_loc` — a required parameter IS just its identifier, so
        // `location()` is already the exact name range.
        self.check_variable_name(node.name().as_slice(), node.location().start_offset());
        self.check_variable_number(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_rest_parameter_node(&mut self, node: &ruby_prism::RestParameterNode<'pr>) {
        // anonymous `*` carries no name — nothing to check.
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.check_variable_name(name.as_slice(), loc.start_offset());
        }
    }
    fn visit_required_keyword_parameter_node(&mut self, node: &ruby_prism::RequiredKeywordParameterNode<'pr>) {
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
    }
    fn visit_keyword_rest_parameter_node(&mut self, node: &ruby_prism::KeywordRestParameterNode<'pr>) {
        // anonymous `**` carries no name — nothing to check.
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.check_variable_name(name.as_slice(), loc.start_offset());
        }
    }
    fn visit_block_parameter_node(&mut self, node: &ruby_prism::BlockParameterNode<'pr>) {
        // anonymous `&` (def or block) carries no name — nothing to check.
        // Covers BOTH `def foo(&blk)` and `foo { |&blk| }` — prism (like
        // whitequark) uses the identical node shape for both.
        if let (Some(name), Some(loc)) = (node.name(), node.name_loc()) {
            self.check_variable_name(name.as_slice(), loc.start_offset());
        }
    }
    fn visit_constant_write_node(&mut self, node: &ruby_prism::ConstantWriteNode<'pr>) {
        let v = node.value();
        self.check_module_length_casgn(node);
        self.check_class_length_casgn(&v);
        // Style/Alias's `alias_method_value_used?`: `node.parent&.assignment?`
        // — `NAME = alias_method :a, :b`.
        self.alias_value_offsets.insert(v.location().start_offset());
        self.check_ascii_constant_write(node);
        self.check_constant_name(node.name().as_slice(), node.name_loc().start_offset(), Some(&v));
        self.check_self_assignment_const(node.location().start_offset(), node.name().as_slice(), &v);
        self.mto_note_child(&v, node.location().start_offset(), false);
        // Lint/RedundantSplatExpansion's `ASSIGNMENT_TYPES` (`casgn` here) —
        // see `rse_assignment_value`'s doc on `Cops`.
        self.rse_assignment_value.insert(v.location().start_offset());
        self.check_mutable_constant(node.value());
        assignment_write!(self, node);
        ruby_prism::visit_constant_write_node(self, node);
    }
    fn visit_constant_or_write_node(&mut self, node: &ruby_prism::ConstantOrWriteNode<'pr>) {
        let v = node.value();
        self.check_constant_name(node.name().as_slice(), node.name_loc().start_offset(), Some(&v));
        self.check_self_assignment_const(node.location().start_offset(), node.name().as_slice(), &v);
        self.check_multiline_memoization(node.location().start_offset(), &v);
        self.check_class_length_casgn(&v);
        self.check_mutable_constant(node.value());
        assignment_write!(self, node);
        ruby_prism::visit_constant_or_write_node(self, node);
    }
    fn visit_constant_target_node(&mut self, node: &ruby_prism::ConstantTargetNode<'pr>) {
        // a constant target in a multiple assignment (`A, B = 1, 2`)
        self.check_constant_name(node.name().as_slice(), node.location().start_offset(), None);
    }
    fn visit_constant_path_write_node(&mut self, node: &ruby_prism::ConstantPathWriteNode<'pr>) {
        self.check_ascii_constant_path_write(node);
        let t = node.target();
        if let Some(name) = t.name() {
            let v = node.value();
            self.check_constant_name(name.as_slice(), t.name_loc().start_offset(), Some(&v));
        }
        self.mto_note_child(&node.value(), node.location().start_offset(), false);
        self.check_class_length_casgn(&node.value());
        // Lint/RedundantSplatExpansion's `ASSIGNMENT_TYPES` (`casgn` here,
        // namespaced form) — see `rse_assignment_value`'s doc on `Cops`.
        self.rse_assignment_value.insert(node.value().location().start_offset());
        self.check_mutable_constant(node.value());
        assignment_path_write!(self, node);
        self.rvgu_mark_write_target(&node.target());
        ruby_prism::visit_constant_path_write_node(self, node);
    }
    fn visit_constant_and_write_node(&mut self, node: &ruby_prism::ConstantAndWriteNode<'pr>) {
        self.check_self_assignment_const(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_class_length_casgn(&node.value());
        assignment_write!(self, node);
        ruby_prism::visit_constant_and_write_node(self, node);
    }
    fn visit_constant_operator_write_node(&mut self, node: &ruby_prism::ConstantOperatorWriteNode<'pr>) {
        self.check_class_length_casgn(&node.value());
        assignment_operator_write!(self, node);
        ruby_prism::visit_constant_operator_write_node(self, node);
    }
    fn visit_constant_path_operator_write_node(&mut self, node: &ruby_prism::ConstantPathOperatorWriteNode<'pr>) {
        self.check_class_length_casgn(&node.value());
        assignment_path_operator_write!(self, node);
        self.rvgu_mark_write_target(&node.target());
        ruby_prism::visit_constant_path_operator_write_node(self, node);
    }
    fn visit_constant_path_or_write_node(&mut self, node: &ruby_prism::ConstantPathOrWriteNode<'pr>) {
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        self.check_class_length_casgn(&node.value());
        self.check_mutable_constant(node.value());
        assignment_path_write!(self, node);
        self.rvgu_mark_write_target(&node.target());
        ruby_prism::visit_constant_path_or_write_node(self, node);
    }
    fn visit_constant_path_and_write_node(&mut self, node: &ruby_prism::ConstantPathAndWriteNode<'pr>) {
        self.check_class_length_casgn(&node.value());
        assignment_path_write!(self, node);
        self.rvgu_mark_write_target(&node.target());
        ruby_prism::visit_constant_path_and_write_node(self, node);
    }
    fn visit_regular_expression_node(&mut self, node: &ruby_prism::RegularExpressionNode<'pr>) {
        self.check_mixed_regexp_capture_types(node);
        self.check_percent_literal_delimiters_regexp(node);
        self.check_regexp_literal(node);
        ruby_prism::visit_regular_expression_node(self, node);
    }
    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        self.rs_scan_conditional(&node.as_node(), &node.predicate());
        self.check_and_or_conditional(&node.predicate());
        self.check_nested_ternary_operator(node);
        // pre-order, before recursion: register THIS ternary's branches as
        // having it for a parent (a nested ternary in the else-branch, e.g.
        // `cond_a? ? foo : cond_b? ? bar : baz`), then check this node itself.
        if node.if_keyword_loc().is_none() {
            // Lint/SafeNavigationChain: `ternary_safe_navigation?`/
            // `ternary_else_branch?` — a REAL if/unless statement's branch is
            // a `StatementsNode`, never a bare expression, so only a ternary
            // `?:` (no `if`/`then`/`end` keywords) can put a candidate call
            // node directly in this position.
            let snc_condition = if self.on("Lint/SafeNavigationChain") {
                Some(self.node_src(&node.predicate()))
            } else {
                None
            };
            if let Some(stmts) = node.statements() {
                if let Some(only) = stmts.body().iter().next() {
                    self.mto_note_child(&only, node.location().start_offset(), false);
                    self.ra_needs_parens.insert(only.location().start_offset());
                    if let Some(condition) = snc_condition {
                        self.snav_parent.insert(
                            only.location().start_offset(),
                            lint_cops::SnavParent::TernaryBranch { is_then: true, condition },
                        );
                    }
                }
            }
            if let Some(else_stmts) =
                node.subsequent().and_then(|s| s.as_else_node()).and_then(|e| e.statements())
            {
                if let Some(only) = else_stmts.body().iter().next() {
                    self.mto_note_child(&only, node.location().start_offset(), false);
                    self.ra_needs_parens.insert(only.location().start_offset());
                    if let Some(condition) = snc_condition {
                        self.snav_parent.insert(
                            only.location().start_offset(),
                            lint_cops::SnavParent::TernaryBranch { is_then: false, condition },
                        );
                    }
                }
            }
        }
        self.check_multiline_ternary_operator(node);
        self.check_ternary_parentheses(node);
        self.check_else_layout_if(node);
        self.check_assignment_in_condition(&node.predicate());
        self.check_negated_if(node);
        self.check_redundant_conditional(node);
        self.check_duplicate_elsif_condition(node);
        self.check_empty_conditional_body(node);
        self.check_comparable_clamp_if(node);
        self.check_case_like_if(node);
        self.check_empty_else_if(node);
        self.check_if_inside_else(node);
        self.check_one_line_conditional_if(node);
        self.check_if_with_semicolon(node);
        self.check_safe_navigation_with_empty(&node.predicate());
        self.check_or_assignment_if(node);
        self.check_identical_conditional_branches_if(node);
        self.check_sole_nested_conditional(&node.as_node());
        self.check_guard_clause_if(node);
        self.check_literal_as_condition_if(node);
        if let Some(kw) = node.if_keyword_loc() {
            if matches!(kw.as_slice(), b"if" | b"elsif") {
                let kw_text = if kw.as_slice() == b"elsif" { "elsif" } else { "if" };
                self.check_multiline_if_then(
                    node.then_keyword_loc(),
                    node.end_keyword_loc(),
                    node.statements().map(|s| s.location().start_offset()),
                    kw_text,
                );
                self.check_parens_around_condition(kw_text, false, &node.predicate());
                // ternaries have no keyword; modifiers have no end keyword
                if node.end_keyword_loc().is_some() {
                    self.check_condition_position(kw.as_slice(), kw.start_offset(), &node.predicate());
                }
            }
        }
        // Layout/SpaceAroundKeyword's `on_if`: `keyword` (`if`/`elsif` — a
        // whitequark `:if` node covers both, and prism's nested `subsequent`
        // `IfNode` chain mirrors that), `then` (`begin_keyword`), `end`, and
        // the trailing `else` (when `subsequent` resolves to an `ElseNode`
        // rather than another `elsif` `IfNode`).
        if let Some(kw) = node.if_keyword_loc() {
            self.sak_check(kw.start_offset(), kw.end_offset(), kw.as_slice());
        }
        if let Some(then_kw) = node.then_keyword_loc() {
            if then_kw.as_slice() == b"then" {
                self.sak_check(then_kw.start_offset(), then_kw.end_offset(), b"then");
            }
        }
        if let Some(end_kw) = node.end_keyword_loc() {
            self.sak_check_end(end_kw.start_offset(), b"end");
        }
        if let Some(else_node) = node.subsequent().and_then(|s| s.as_else_node()) {
            let e = else_node.else_keyword_loc();
            self.sak_check(e.start_offset(), e.end_offset(), b"else");
        }
        // pre-order (before recursion): a nested modifier chain
        // (`body if inner if outer`) needs the OUTER node checked first, so
        // it claims the shared start offset before the inner one is visited
        // (see check_multiline_if_modifier's doc comment).
        if node.end_keyword_loc().is_none() && node.if_keyword_loc().is_some() {
            self.check_multiline_if_modifier("if", node.location(), node.predicate(), node.statements());
            self.check_nested_modifier("if", node.predicate(), node.statements(), true);
            self.rrs_note_modifier_body(node.statements(), node.location().end_offset());
        }
        self.cond_depth += 1;
        // Style/DoubleNegation: `conditional?` (`CONDITIONALS` includes
        // `:if`, which whitequark also uses for a ternary — this pushes for
        // those too, matching upstream making no such distinction).
        self.dn_ancestors.push(DnFrame::Conditional(self.idx.loc(node.location().end_offset().saturating_sub(1)).0));
        // Style/HashSyntax: the predicate is a `requires_parentheses_context?`
        // position; a genuine (non-ternary) modifier `if`/`unless` widens
        // `hs_modifier_depth` for its whole subtree (predicate + body) — see
        // the field docs.
        self.hs_call_like_ctx.insert(node.predicate().location().start_offset());
        let hs_modifier = node.if_keyword_loc().is_some() && node.end_keyword_loc().is_none();
        if hs_modifier {
            self.hs_modifier_depth += 1;
        }
        ruby_prism::visit_if_node(self, node);
        if hs_modifier {
            self.hs_modifier_depth -= 1;
        }
        self.dn_ancestors.pop();
        self.cond_depth -= 1;
        // post-order (after recursion): nested-modifier autocorrect needs the
        // inner node's fixes registered first (TreeRewriter insert order)
        if node.end_keyword_loc().is_none() {
            if let Some(kw) = node.if_keyword_loc() {
                self.check_if_unless_modifier_of_if_unless("if", kw, node.predicate(), node.statements());
            }
        }
    }
    fn visit_unless_node(&mut self, node: &ruby_prism::UnlessNode<'pr>) {
        self.rs_scan_conditional(&node.as_node(), &node.predicate());
        self.check_else_layout_unless(node);
        // whitequark's parser has no distinct `unless` node type — `unless
        // cond` compiles to `(if cond nil body)`, so upstream's `on_if` (which
        // Lint/AssignmentInCondition aliases to `on_while`/`on_until`, but
        // never separately defines `on_unless`) already covers it for free.
        // Prism DOES give `unless` its own `UnlessNode`, so it needs its own
        // hook here to match.
        self.check_assignment_in_condition(&node.predicate());
        self.check_parens_around_condition("unless", false, &node.predicate());
        self.check_redundant_conditional_unless(node);
        self.check_safe_navigation_with_empty(&node.predicate());
        self.check_negated_unless(node);
        self.check_unless_else(node);
        self.check_one_line_conditional_unless(node);
        self.check_empty_conditional_body_unless(node);
        self.check_empty_else_unless(node);
        self.check_non_nil_check_unless(node);
        self.check_if_with_semicolon_unless(node);
        self.check_or_assignment_unless(node);
        self.check_sole_nested_conditional(&node.as_node());
        self.check_guard_clause_unless(node);
        self.check_literal_as_condition_unless(node);
        self.check_multiline_if_then(
            node.then_keyword_loc(),
            node.end_keyword_loc(),
            node.statements().map(|s| s.location().start_offset()),
            "unless",
        );
        if node.end_keyword_loc().is_some() {
            self.check_condition_position(b"unless", node.keyword_loc().start_offset(), &node.predicate());
        }
        // Layout/SpaceAroundKeyword: whitequark folds `unless` into an `:if`
        // node too (same reasoning as the comment above), so on_if's
        // keyword/then/end/else checks apply here verbatim.
        {
            let kw = node.keyword_loc();
            self.sak_check(kw.start_offset(), kw.end_offset(), b"unless");
        }
        if let Some(then_kw) = node.then_keyword_loc() {
            if then_kw.as_slice() == b"then" {
                self.sak_check(then_kw.start_offset(), then_kw.end_offset(), b"then");
            }
        }
        if let Some(end_kw) = node.end_keyword_loc() {
            self.sak_check_end(end_kw.start_offset(), b"end");
        }
        if let Some(else_node) = node.else_clause() {
            let e = else_node.else_keyword_loc();
            self.sak_check(e.start_offset(), e.end_offset(), b"else");
        }
        // pre-order: nested modifiers dedup via multiline_if_mod_seen.
        if node.end_keyword_loc().is_none() {
            self.check_multiline_if_modifier("unless", node.location(), node.predicate(), node.statements());
            self.check_nested_modifier("unless", node.predicate(), node.statements(), true);
            self.rrs_note_modifier_body(node.statements(), node.location().end_offset());
        }
        self.cond_depth += 1;
        self.dn_ancestors.push(DnFrame::Conditional(self.idx.loc(node.location().end_offset().saturating_sub(1)).0));
        self.hs_call_like_ctx.insert(node.predicate().location().start_offset());
        let hs_modifier = node.end_keyword_loc().is_none();
        if hs_modifier {
            self.hs_modifier_depth += 1;
        }
        ruby_prism::visit_unless_node(self, node);
        if hs_modifier {
            self.hs_modifier_depth -= 1;
        }
        self.dn_ancestors.pop();
        self.cond_depth -= 1;
        // post-order: see the if-visitor note.
        if node.end_keyword_loc().is_none() {
            self.check_if_unless_modifier_of_if_unless("unless", node.keyword_loc(), node.predicate(), node.statements());
        }
    }
    fn visit_class_variable_write_node(&mut self, node: &ruby_prism::ClassVariableWriteNode<'pr>) {
        self.check_class_vars(node.name().as_slice(), node.name_loc().start_offset());
        self.check_self_assignment_shorthand_cvar(node);
        self.check_self_assignment_cvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_redundant_self_assignment_cvar(node);
        self.mto_note_child(&node.value(), node.location().start_offset(), false);
        self.check_or_assignment_write(&node.as_node(), node.name().as_slice(), &node.value());
        // Lint/RedundantSplatExpansion's `ASSIGNMENT_TYPES` (`cvasgn` here) —
        // see `rse_assignment_value`'s doc on `Cops`.
        self.rse_assignment_value.insert(node.value().location().start_offset());
        assignment_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_class_variable_write_node(self, node);
    }
    fn visit_class_variable_operator_write_node(&mut self, node: &ruby_prism::ClassVariableOperatorWriteNode<'pr>) {
        self.check_class_vars(node.name().as_slice(), node.name_loc().start_offset());
        assignment_operator_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_class_variable_operator_write_node(self, node);
    }
    fn visit_class_variable_or_write_node(&mut self, node: &ruby_prism::ClassVariableOrWriteNode<'pr>) {
        self.check_class_vars(node.name().as_slice(), node.name_loc().start_offset());
        self.check_self_assignment_cvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        assignment_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_class_variable_or_write_node(self, node);
    }
    fn visit_class_variable_and_write_node(&mut self, node: &ruby_prism::ClassVariableAndWriteNode<'pr>) {
        self.check_class_vars(node.name().as_slice(), node.name_loc().start_offset());
        self.check_self_assignment_cvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        assignment_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_class_variable_and_write_node(self, node);
    }
    fn visit_class_variable_target_node(&mut self, node: &ruby_prism::ClassVariableTargetNode<'pr>) {
        // a class var target in a multiple assignment (`@@a, @@b = 1, 2`) is a
        // cvasgn in whitequark, so upstream's on_cvasgn fires per target
        self.check_class_vars(node.name().as_slice(), node.location().start_offset());
        self.check_variable_name(node.name().as_slice(), node.location().start_offset());
        self.check_variable_number(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_global_variable_read_node(&mut self, node: &ruby_prism::GlobalVariableReadNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.location().start_offset());
        self.check_perl_backrefs_gvar(node);
        self.check_special_global_vars(node);
    }
    fn visit_global_variable_write_node(&mut self, node: &ruby_prism::GlobalVariableWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        self.check_self_assignment_gvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_redundant_self_assignment_gvar(node);
        self.check_global_std_stream_gvasgn(node.name().as_slice(), &node.value());
        self.mto_note_child(&node.value(), node.location().start_offset(), false);
        self.check_or_assignment_write(&node.as_node(), node.name().as_slice(), &node.value());
        // Lint/RedundantSplatExpansion's `ASSIGNMENT_TYPES` (`gvasgn` here) —
        // see `rse_assignment_value`'s doc on `Cops`.
        self.rse_assignment_value.insert(node.value().location().start_offset());
        assignment_write!(self, node);
        self.check_variable_name_gvasgn(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_write_node(self, node);
    }
    fn visit_global_variable_operator_write_node(&mut self, node: &ruby_prism::GlobalVariableOperatorWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        assignment_operator_write!(self, node);
        self.check_variable_name_gvasgn(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_operator_write_node(self, node);
    }
    fn visit_global_variable_or_write_node(&mut self, node: &ruby_prism::GlobalVariableOrWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        self.check_self_assignment_gvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        assignment_write!(self, node);
        self.check_variable_name_gvasgn(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_or_write_node(self, node);
    }
    fn visit_global_variable_and_write_node(&mut self, node: &ruby_prism::GlobalVariableAndWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        self.check_self_assignment_gvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        assignment_write!(self, node);
        self.check_variable_name_gvasgn(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_and_write_node(self, node);
    }
    fn visit_global_variable_target_node(&mut self, node: &ruby_prism::GlobalVariableTargetNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.location().start_offset());
        self.check_variable_name_gvasgn(node.name().as_slice(), node.location().start_offset());
        self.check_variable_number(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_numbered_reference_read_node(&mut self, node: &ruby_prism::NumberedReferenceReadNode<'pr>) {
        self.check_perl_backrefs_numbered(node);
        self.check_out_of_range_regexp_ref_nth_ref(node);
    }
    fn visit_back_reference_read_node(&mut self, node: &ruby_prism::BackReferenceReadNode<'pr>) {
        self.check_perl_backrefs_back_ref(node);
    }
    fn visit_local_variable_read_node(&mut self, node: &ruby_prism::LocalVariableReadNode<'pr>) {
        self.check_ascii_identifiers_in_name(node.name().as_slice(), node.location().start_offset(), false);
        // Naming/VariableName's `on_lvar` alias — a READ is checked
        // unconditionally, even one reached from inside a pattern-match guard
        // or a pin (`^x`) expression (rubocop's own AST has no such
        // exception either: an `lvar` node is an `lvar` node).
        self.check_variable_name(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_local_variable_write_node(&mut self, node: &ruby_prism::LocalVariableWriteNode<'pr>) {
        self.check_ascii_local_variable_write(node);
        self.check_self_assignment_shorthand_lvar(node);
        self.check_self_assignment_lvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_redundant_self_assignment_lvar(node);
        self.mto_note_child(&node.value(), node.location().start_offset(), false);
        self.check_or_assignment_write(&node.as_node(), node.name().as_slice(), &node.value());
        // Lint/RedundantSplatExpansion's `ASSIGNMENT_TYPES` (`lvasgn` here) —
        // see `rse_assignment_value`'s doc on `Cops`.
        self.rse_assignment_value.insert(node.value().location().start_offset());
        assignment_write!(self, node);
        self.rs_lvar_write(node.name().as_slice(), &node.value());
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        // Style/HashSyntax: `last_expression?`'s assignment climb — the
        // value is this write's "assignment_node" hop.
        self.hs_assign_parent
            .insert(node.value().location().start_offset(), node.location().start_offset());
        // Style/MethodCallWithoutArgsParentheses's `same_name_assignment?`:
        // this name is a live "ancestor assignment" for the whole `value`
        // subtree — see the `mcwap_assign_stack` field doc.
        self.mcwap_assign_stack.push(vec![node.name().as_slice().to_vec()]);
        ruby_prism::visit_local_variable_write_node(self, node);
        self.mcwap_assign_stack.pop();
    }
    fn visit_local_variable_operator_write_node(&mut self, node: &ruby_prism::LocalVariableOperatorWriteNode<'pr>) {
        assignment_operator_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        self.mcwap_assign_stack.push(vec![node.name().as_slice().to_vec()]);
        ruby_prism::visit_local_variable_operator_write_node(self, node);
        self.mcwap_assign_stack.pop();
    }
    fn visit_local_variable_or_write_node(&mut self, node: &ruby_prism::LocalVariableOrWriteNode<'pr>) {
        self.check_self_assignment_lvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        assignment_write!(self, node);
        self.rs_lvar_write(node.name().as_slice(), &node.value());
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        self.mcwap_assign_stack.push(vec![node.name().as_slice().to_vec()]);
        ruby_prism::visit_local_variable_or_write_node(self, node);
        self.mcwap_assign_stack.pop();
    }
    fn visit_local_variable_and_write_node(&mut self, node: &ruby_prism::LocalVariableAndWriteNode<'pr>) {
        self.check_self_assignment_lvar(node.location().start_offset(), node.name().as_slice(), &node.value());
        assignment_write!(self, node);
        self.rs_lvar_write(node.name().as_slice(), &node.value());
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        self.mcwap_assign_stack.push(vec![node.name().as_slice().to_vec()]);
        ruby_prism::visit_local_variable_and_write_node(self, node);
        self.mcwap_assign_stack.pop();
    }
    fn visit_local_variable_target_node(&mut self, node: &ruby_prism::LocalVariableTargetNode<'pr>) {
        // masgn/rescue/for-loop targets are lvasgn in whitequark (checked);
        // a bare pattern-match binding (`in fooBar`) is NOT (see
        // `pattern_depth`'s doc comment).
        if self.pattern_depth == 0 {
            self.check_variable_name(node.name().as_slice(), node.location().start_offset());
            self.check_variable_number(node.name().as_slice(), node.location().start_offset());
        }
    }
    fn visit_instance_variable_write_node(&mut self, node: &ruby_prism::InstanceVariableWriteNode<'pr>) {
        self.check_self_assignment_shorthand_ivar(node);
        self.check_self_assignment_ivar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_redundant_self_assignment_ivar(node);
        self.mto_note_child(&node.value(), node.location().start_offset(), false);
        self.check_or_assignment_write(&node.as_node(), node.name().as_slice(), &node.value());
        // Lint/RedundantSplatExpansion's `ASSIGNMENT_TYPES` (`ivasgn` here) —
        // see `rse_assignment_value`'s doc on `Cops`.
        self.rse_assignment_value.insert(node.value().location().start_offset());
        assignment_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_instance_variable_write_node(self, node);
    }
    fn visit_instance_variable_operator_write_node(
        &mut self,
        node: &ruby_prism::InstanceVariableOperatorWriteNode<'pr>,
    ) {
        assignment_operator_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_instance_variable_operator_write_node(self, node);
    }
    fn visit_instance_variable_or_write_node(&mut self, node: &ruby_prism::InstanceVariableOrWriteNode<'pr>) {
        self.check_self_assignment_ivar(node.location().start_offset(), node.name().as_slice(), &node.value());
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        assignment_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_instance_variable_or_write_node(self, node);
    }
    fn visit_instance_variable_and_write_node(&mut self, node: &ruby_prism::InstanceVariableAndWriteNode<'pr>) {
        self.check_self_assignment_ivar(node.location().start_offset(), node.name().as_slice(), &node.value());
        assignment_write!(self, node);
        self.check_variable_name(node.name().as_slice(), node.name_loc().start_offset());
        self.check_variable_number(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_instance_variable_and_write_node(self, node);
    }
    fn visit_instance_variable_target_node(&mut self, node: &ruby_prism::InstanceVariableTargetNode<'pr>) {
        // an ivar target in a multiple assignment (`@a, @b = 1, 2`) or a
        // `rescue => @e` is an ivasgn in whitequark, so upstream's
        // on_ivasgn fires per target (ivars can never appear in a pattern).
        self.check_variable_name(node.name().as_slice(), node.location().start_offset());
        self.check_variable_number(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_multi_write_node(&mut self, node: &ruby_prism::MultiWriteNode<'pr>) {
        self.check_class_length_casgn(&node.value());
        let lhs_start = node.location().start_offset();
        let op_end = node.operator_loc().end_offset();
        // Layout/ArrayAlignment's `node.parent&.masgn_type?` guard — the
        // bare comma-list value of a mass assignment is never itself
        // alignment-checked (prism represents it as a bracketless
        // `ArrayNode`, same shape as a single-target `a = 1, 2`, whose
        // exclusion is keyed on parentage alone).
        if node.value().as_array_node().is_some() {
            self.aa_masgn_rhs.insert(node.value().location().start_offset());
        }
        self.assignment_indentation_hook(lhs_start, op_end, node.value());
        self.check_self_assignment_masgn(node);
        self.check_trailing_underscore_variable(node);
        // Style/RedundantSelf: only plain local-var masgn targets carry a
        // usable name upstream (`child.to_a.first` on a non-lvasgn target —
        // e.g. an attr-writer or splat — yields a NODE, not a symbol, so it
        // can never match a `method_name` and is effectively a no-op there).
        for t in node.lefts().iter().chain(node.rights().iter()) {
            if let Some(lv) = t.as_local_variable_target_node() {
                let name = lv.name().as_slice().to_vec();
                self.rs_lvar_write(&name, &node.value());
            }
        }
        // Style/MethodCallWithoutArgsParentheses's `variable_in_mass_assignment?`
        // (`node.assignments.reject(&:send_type?).any? { |n| n.name == ... }`):
        // collect every plain local-variable target's name — `lefts`, an
        // optional `*rest`, and `rights` — recursing through nested
        // destructuring (`(a, *b), c = ...`) and unwrapping `*splat`.
        // `IndexTargetNode`/`CallTargetNode` (index/attribute writes — the
        // upstream `send_type?` rejects) are skipped for free by only
        // matching `LocalVariableTargetNode`/`MultiTargetNode`/`SplatNode`.
        let mut mcwap_names = Vec::new();
        for t in node.lefts().iter() {
            Self::mcwap_collect_lvar_target_names(&t, &mut mcwap_names);
        }
        if let Some(r) = node.rest() {
            Self::mcwap_collect_lvar_target_names(&r, &mut mcwap_names);
        }
        for t in node.rights().iter() {
            Self::mcwap_collect_lvar_target_names(&t, &mut mcwap_names);
        }
        self.mcwap_assign_stack.push(mcwap_names);
        ruby_prism::visit_multi_write_node(self, node);
        self.mcwap_assign_stack.pop();
    }
    fn visit_call_and_write_node(&mut self, node: &ruby_prism::CallAndWriteNode<'pr>) {
        self.check_self_assignment_reader_write(
            node.location().start_offset(),
            node.receiver(),
            node.read_name().as_slice(),
            &[],
            &node.value(),
        );
        ruby_prism::visit_call_and_write_node(self, node);
    }
    fn visit_call_or_write_node(&mut self, node: &ruby_prism::CallOrWriteNode<'pr>) {
        self.check_self_assignment_reader_write(
            node.location().start_offset(),
            node.receiver(),
            node.read_name().as_slice(),
            &[],
            &node.value(),
        );
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        ruby_prism::visit_call_or_write_node(self, node);
    }
    fn visit_index_and_write_node(&mut self, node: &ruby_prism::IndexAndWriteNode<'pr>) {
        let key_args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        self.check_self_assignment_reader_write(
            node.location().start_offset(),
            node.receiver(),
            b"[]",
            &key_args,
            &node.value(),
        );
        ruby_prism::visit_index_and_write_node(self, node);
    }
    fn visit_index_or_write_node(&mut self, node: &ruby_prism::IndexOrWriteNode<'pr>) {
        let key_args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        self.check_self_assignment_reader_write(
            node.location().start_offset(),
            node.receiver(),
            b"[]",
            &key_args,
            &node.value(),
        );
        self.check_multiline_memoization(node.location().start_offset(), &node.value());
        ruby_prism::visit_index_or_write_node(self, node);
    }
    fn visit_case_node(&mut self, node: &ruby_prism::CaseNode<'pr>) {
        self.check_duplicate_case_condition(node);
        self.check_float_comparison_case(node);
        self.check_empty_when(node);
        self.check_case_indentation(node);
        self.check_empty_else_case(node);
        self.check_hash_like_case(node);
        self.check_empty_case_condition(node);
        self.check_identical_conditional_branches_case(node);
        self.check_literal_as_condition_case(node);
        {
            let kw = node.case_keyword_loc();
            self.sak_check(kw.start_offset(), kw.end_offset(), b"case");
        }
        if let Some(else_node) = node.else_clause() {
            let e = else_node.else_keyword_loc();
            self.sak_check(e.start_offset(), e.end_offset(), b"else");
        }
        self.cond_depth += 1;
        self.dn_ancestors.push(DnFrame::Conditional(self.idx.loc(node.location().end_offset().saturating_sub(1)).0));
        ruby_prism::visit_case_node(self, node);
        self.dn_ancestors.pop();
        self.cond_depth -= 1;
    }
    fn visit_case_match_node(&mut self, node: &ruby_prism::CaseMatchNode<'pr>) {
        self.check_case_match_indentation(node);
        self.check_identical_conditional_branches_case_match(node);
        self.check_literal_as_condition_case_match(node);
        {
            let kw = node.case_keyword_loc();
            self.sak_check(kw.start_offset(), kw.end_offset(), b"case");
        }
        if let Some(else_node) = node.else_clause() {
            let e = else_node.else_keyword_loc();
            self.sak_check(e.start_offset(), e.end_offset(), b"else");
        }
        self.cond_depth += 1;
        self.dn_ancestors.push(DnFrame::Conditional(self.idx.loc(node.location().end_offset().saturating_sub(1)).0));
        ruby_prism::visit_case_match_node(self, node);
        self.dn_ancestors.pop();
        self.cond_depth -= 1;
    }
    fn visit_when_node(&mut self, node: &ruby_prism::WhenNode<'pr>) {
        self.check_when_then(node);
        self.check_multiline_when_then(node);
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"when");
        // Lint/OutOfRangeRegexpRef's `on_when`: must run BEFORE descending
        // into the clause's conditions/body so nth-refs inside see the
        // updated state (mirrors upstream's node-enter callback timing).
        self.check_out_of_range_regexp_ref_when(node);
        // Lint/RedundantSplatExpansion: a `when *expr` condition is never
        // array-wrapped by prism (unlike an assignment RHS) — the splat's
        // real parent is this `WhenNode` directly.
        if self.on("Lint/RedundantSplatExpansion") {
            let l = node.location();
            for c in node.conditions().iter() {
                if c.as_splat_node().is_some() {
                    self.rse_ctx.insert(
                        c.location().start_offset(),
                        lint_cops::RseCtx {
                            container: lint_cops::RseContainer::When,
                            container_start: l.start_offset(),
                            container_end: l.end_offset(),
                            array_len: 0,
                        },
                    );
                }
            }
        }
        ruby_prism::visit_when_node(self, node);
    }
    fn visit_in_node(&mut self, node: &ruby_prism::InNode<'pr>) {
        self.check_redundant_self_in_pattern(node);
        let kw = node.in_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"in");
        // Lint/OutOfRangeRegexpRef's `on_in_pattern`: node-enter timing,
        // same as `on_when` above — must run before the pattern/statements
        // are visited.
        self.check_out_of_range_regexp_ref_in_pattern(node);
        // Inlines `ruby_prism::visit_in_node`'s own default body (visit
        // pattern, then statements) so only the PATTERN half runs under
        // `pattern_depth` — see that field's doc comment on `Cops`.
        self.pattern_depth += 1;
        self.visit(&node.pattern());
        self.pattern_depth -= 1;
        if let Some(s) = node.statements() {
            self.visit_statements_node(&s);
        }
    }
    fn visit_match_required_node(&mut self, node: &ruby_prism::MatchRequiredNode<'pr>) {
        // `expr => pattern` (rightward assignment) — same pattern-binding
        // shape as `case/in`, so the same `pattern_depth` exemption applies.
        // rubocop's `on_match_pattern` (which would check the `=>` operator)
        // only fires when `target_ruby_version < 3.0`; oxidecop always
        // targets >= 3.0, so this is unconditionally unchecked (matches the
        // fixture's unconditional 'accepts before/after `=>`' examples).
        self.visit(&node.value());
        self.pattern_depth += 1;
        self.visit(&node.pattern());
        self.pattern_depth -= 1;
    }
    fn visit_match_predicate_node(&mut self, node: &ruby_prism::MatchPredicateNode<'pr>) {
        // `expr in pattern` (boolean pattern match) — same as above.
        let op = node.operator_loc();
        self.sak_check(op.start_offset(), op.end_offset(), b"in");
        self.visit(&node.value());
        self.pattern_depth += 1;
        self.visit(&node.pattern());
        self.pattern_depth -= 1;
    }
    fn visit_constant_read_node(&mut self, node: &ruby_prism::ConstantReadNode<'pr>) {
        let klass = node.name().as_slice();
        if matches!(klass, b"Fixnum" | b"Bignum") {
            let l = node.location();
            self.check_unified_integer(klass, l.start_offset(), l.end_offset());
        }
        let l = node.location();
        self.check_global_std_stream(klass, l.start_offset(), l.end_offset());
        self.check_ruby_version_globals_usage_read(node);
    }
    fn visit_constant_path_node(&mut self, node: &ruby_prism::ConstantPathNode<'pr>) {
        // only a bare ::-rooted constant counts, not a namespaced one
        if node.parent().is_none() {
            if let Some(name) = node.name() {
                let klass = name.as_slice();
                if matches!(klass, b"Fixnum" | b"Bignum") {
                    let l = node.location();
                    self.check_unified_integer(klass, l.start_offset(), l.end_offset());
                }
                let l = node.location();
                self.check_global_std_stream(klass, l.start_offset(), l.end_offset());
            }
        }
        self.check_ruby_version_globals_usage_path(node);
        self.check_space_after_double_colon(node);
        ruby_prism::visit_constant_path_node(self, node);
    }
    fn visit_return_node(&mut self, node: &ruby_prism::ReturnNode<'pr>) {
        self.check_min_max_return(node);
        self.check_top_level_return_with_argument(node);
        self.check_non_local_exit_from_iterator(node);
        self.ecc_mark_not_supported_parent(node.arguments());
        // Style/DoubleNegation's `node.parent&.return_type?` — only the
        // return's own DIRECT argument(s) count (prism interposes an
        // `ArgumentsNode` wrapper whitequark doesn't have; skip straight
        // through it), never a deeper descendant.
        if let Some(args) = node.arguments() {
            for a in args.arguments().iter() {
                self.dn_return_arg_offsets.insert(a.location().start_offset());
            }
        }
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"return");
        // Style/MultilineTernaryOperator: `return cond ? a : b` — a single
        // return value that's a ternary corrects to single-line, mirroring
        // upstream's `SINGLE_LINE_TYPES` including `:return`.
        if let Some(args) = node.arguments() {
            let list = args.arguments();
            if list.iter().count() == 1 {
                if let Some(only) = list.iter().next() {
                    self.mto_note_child(&only, node.location().start_offset(), true);
                }
            }
        }
        ruby_prism::visit_return_node(self, node);
    }
    fn visit_break_node(&mut self, node: &ruby_prism::BreakNode<'pr>) {
        self.ecc_mark_not_supported_parent(node.arguments());
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"break");
        ruby_prism::visit_break_node(self, node);
    }
    fn visit_next_node(&mut self, node: &ruby_prism::NextNode<'pr>) {
        self.ecc_mark_not_supported_parent(node.arguments());
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"next");
        ruby_prism::visit_next_node(self, node);
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        self.check_rescue_exception(node);
        self.check_rescue_type(node);
        self.check_suppressed_exception(node);
        self.check_rescue_standard_error(node);
        {
            let kw = node.keyword_loc();
            self.sak_check(kw.start_offset(), kw.end_offset(), b"rescue");
        }
        self.check_rescued_exceptions_variable_name(node);
        // Lint/RedundantSplatExpansion: `rescue *expr` — upstream's
        // whitequark/parser-gem translation wraps a multi-exception rescue
        // list (splat included) in a synthetic bracket-less `array` node, so
        // a splatted exception list's `grandparent` is the `resbody`
        // (`RescueNode`) itself; prism's own `exceptions()` is already flat
        // (no such wrapper), so the splat's real parent IS this `RescueNode`
        // directly — one less level of indirection to replicate.
        if self.on("Lint/RedundantSplatExpansion") {
            let l = node.location();
            for ex in &node.exceptions() {
                if ex.as_splat_node().is_some() {
                    self.rse_ctx.insert(
                        ex.location().start_offset(),
                        lint_cops::RseCtx {
                            container: lint_cops::RseContainer::Rescue,
                            container_start: l.start_offset(),
                            container_end: l.end_offset(),
                            array_len: 0,
                        },
                    );
                }
            }
        }
        // Hand-rolled (rather than a plain `ruby_prism::visit_rescue_node`
        // call) ONLY so `renv_resbody_depth` can bracket exactly the
        // `.statements()` visit — traversal order/coverage is identical to
        // the generated default (exceptions, reference, statements, then
        // `subsequent`); see Naming/RescuedExceptionsVariableName's nested-
        // rescue guard (`each_ancestor(:resbody)`), which must NOT treat a
        // `subsequent` (sibling `elsif`-style rescue branch) as nesting.
        for ex in &node.exceptions() {
            self.visit(&ex);
        }
        if let Some(r) = node.reference() {
            self.visit(&r);
        }
        if let Some(st) = node.statements() {
            self.renv_resbody_depth += 1;
            self.visit_statements_node(&st);
            self.renv_resbody_depth -= 1;
        }
        if let Some(sub) = node.subsequent() {
            self.visit_rescue_node(&sub);
        }
    }
    fn visit_rescue_modifier_node(&mut self, node: &ruby_prism::RescueModifierNode<'pr>) {
        self.check_signal_exception_rescue_modifier(node);
        self.check_suppressed_exception_modifier(node);
        self.check_rescue_modifier(node);
        // Layout/SpaceAroundKeyword's `on_resbody`: whitequark parses a
        // modifier `expr rescue handler` as a `:rescue` node wrapping ONE
        // `:resbody` child (nil exception classes/variable) — same
        // `on_resbody` hook prism's dedicated `RescueModifierNode` maps to.
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"rescue");
        ruby_prism::visit_rescue_modifier_node(self, node);
    }
    fn visit_flip_flop_node(&mut self, node: &ruby_prism::FlipFlopNode<'pr>) {
        self.check_flip_flop(node);
        ruby_prism::visit_flip_flop_node(self, node);
    }
    fn visit_match_last_line_node(&mut self, node: &ruby_prism::MatchLastLineNode<'pr>) {
        if !self.regexp_bang_ignore.contains(&node.location().start_offset()) {
            self.check_regexp_as_condition(&node.as_node(), None);
        }
        // leaf node — ruby_prism::visit_match_last_line_node is a no-op.
    }
    fn visit_interpolated_match_last_line_node(&mut self, node: &ruby_prism::InterpolatedMatchLastLineNode<'pr>) {
        if !self.regexp_bang_ignore.contains(&node.location().start_offset()) {
            self.check_regexp_as_condition(&node.as_node(), None);
        }
        ruby_prism::visit_interpolated_match_last_line_node(self, node);
    }
    fn visit_range_node(&mut self, node: &ruby_prism::RangeNode<'pr>) {
        self.check_space_inside_range_literal(node);
        if self.hot.semicolon {
            let l = node.location();
            self.range_spans.push((l.start_offset(), l.end_offset()));
        }
        ruby_prism::visit_range_node(self, node);
    }
    fn visit_statements_node(&mut self, node: &ruby_prism::StatementsNode<'pr>) {
        // Lint/Void's `on_begin`/`on_kwbegin`: fires for EVERY implicit
        // whitequark `:begin` node, which is exactly a `StatementsNode` with
        // 2+ statements (a single statement is transparently unwrapped —
        // no `:begin` node exists at all upstream — see `void_each_stack`'s
        // doc for how the void-context verdict is threaded down here).
        let void_pending = self.void_pending_ctx.take();
        if self.on("Lint/Void") {
            let list: Vec<ruby_prism::Node> = node.body().iter().collect();
            if list.len() >= 2 {
                self.check_void_begin_group(&list, void_pending.unwrap_or(false));
            }
        }
        // Style/HashSyntax: `node.right_sibling` for any statement that
        // isn't the last one in this list — see `hs_stmt_next`'s doc.
        if self.on("Style/HashSyntax") {
            let body: Vec<ruby_prism::Node> = node.body().iter().collect();
            if let Some((_, rest)) = body.split_last() {
                for s in rest {
                    self.hs_stmt_next.insert(s.location().start_offset());
                }
            }
        }
        self.check_semicolon_separators(node);
        self.ll_check_semicolons(node);
        self.check_constant_definition_in_block(node);
        self.check_empty_lines_around_attribute_accessor(node);
        self.check_empty_lines_around_access_modifier(node);
        self.check_unreachable_code(node);
        self.check_empty_line_between_defs(node);
        self.check_predicate_prefix_sig_scan(node);
        self.check_combinable_loops(node);
        self.stmts_stack.push(node.location().start_offset());
        // Style/DoubleNegation: upstream's `:begin` node only ever exists
        // when whitequark groups 2+ statements — a single-statement body is
        // transparently unwrapped to that one statement directly, unlike
        // prism's `StatementsNode`, which wraps unconditionally. Pushing a
        // frame only when there's more than one statement reproduces that.
        let dn_pushed_begin = node.body().iter().count() > 1;
        if dn_pushed_begin {
            let last_line = self.idx.loc(node.location().end_offset().saturating_sub(1)).0;
            self.dn_ancestors.push(DnFrame::BeginGroup {
                last_line,
                child_starts: node.body().iter().map(|s| s.location().start_offset()).collect(),
            });
        }
        if self.on("Naming/RescuedExceptionsVariableName") {
            // Hand-rolled (rather than the plain default-visitor call) so
            // that right after visiting a direct `kwbegin` (explicit
            // `begin...end`) child, any rename requests it queued up (from
            // offenses found anywhere inside it) can be immediately applied
            // to the STATEMENTS THAT FOLLOW IT IN THIS SAME LIST — rubocop's
            // `kwbegin_node.right_siblings` autocorrect step. Traversal
            // order/coverage is identical to `ruby_prism::
            // visit_statements_node`'s default (visit each child in order).
            let list = node.body();
            for (i, child) in list.iter().enumerate() {
                self.visit(&child);
                let is_kwbegin = child
                    .as_begin_node()
                    .is_some_and(|b| b.begin_keyword_loc().is_some());
                if is_kwbegin {
                    let renames = std::mem::take(&mut self.renv_just_closed_kwbegin_renames);
                    for (name, preferred) in &renames {
                        for sib in list.iter().skip(i + 1) {
                            naming::correct_rescue_refs(&sib, name, preferred, &mut self.fixes);
                        }
                    }
                }
            }
        } else {
            ruby_prism::visit_statements_node(self, node);
        }
        if dn_pushed_begin {
            self.dn_ancestors.pop();
        }
        self.stmts_stack.pop();
    }
    // Lint/ConstantDefinitionInBlock: no other cop needs a general "what's my
    // parent" answer, so rather than a full ancestor stack this hand-rolls
    // the default BlockNode walk (params, then body — see
    // `ruby_prism::visit_block_node`) to flag "the body about to be visited
    // IS this block's own StatementsNode" right before descending into it.
    fn visit_block_node(&mut self, node: &ruby_prism::BlockNode<'pr>) {
        // Lint/Void: consume the owning call's method name (see
        // `void_pending_block_name`'s doc); `None` only if somehow reached
        // without that stash (never happens in practice — every `BlockNode`
        // has an owning call), treated as neither `each` nor `tap`.
        let void_method_name = self.void_pending_block_name.take();
        let void_is_each = void_method_name.as_deref() == Some(&b"each"[..]);
        let void_is_tap = void_method_name.as_deref() == Some(&b"tap"[..]);
        self.void_each_stack.push(void_is_each);
        self.check_space_before_block_braces(&node.opening_loc(), &node.closing_loc());
        self.check_block_end_newline(node);
        self.check_access_modifier_indentation_block(node);
        self.check_space_around_block_parameters(node);
        // Layout/SpaceAroundKeyword: `do`/`end` — a numbered-param (`_1`) or
        // `it`-param block is still a plain `BlockNode` in prism (same as an
        // ordinary block), so this one hook covers `on_block`/`on_numblock`/
        // `on_itblock` alike. `{`/`}` delimiters aren't checked here at all
        // (that's Layout/SpaceBeforeBlockBraces/SpaceInsideBlockBraces turf).
        let opening = node.opening_loc();
        let is_do = opening.as_slice() == b"do";
        if is_do {
            self.sak_check(opening.start_offset(), opening.end_offset(), b"do");
        }
        if is_do {
            let closing = node.closing_loc();
            self.sak_check_end(closing.start_offset(), b"end");
        }
        // Style/RedundantSelf: a block CONTINUES (shares) the enclosing
        // scope's name set when one is active — a real Ruby closure sees
        // outer locals, and upstream's `add_scope(node,
        // @local_variables_scopes[node])` reuses the SAME Array object, not a
        // copy. At top level (no enclosing def/block) it starts fresh.
        let is_plain = !matches!(&node.parameters(),
            Some(p) if p.as_numbered_parameters_node().is_some() || p.as_it_parameters_node().is_some());
        let no_delims = node.parameters().is_none();
        if let Some(p) = node.parameters() {
            self.check_keyword_parameters_order_block(&p);
        }
        self.rs_block_stack.push((is_plain, no_delims));
        // Lint/MissingSuper: consume the `Class.new(x)`-shape verdict
        // `visit_call_node` set right before descending into us — see the
        // `ms_pending_block` field doc.
        self.ms_block_stack.push(self.ms_pending_block.take());
        // Lint/NonLocalExitFromIterator: consume the pending call-context
        // `visit_call_node` set right before descending into us (`None`
        // when we weren't reached that way, e.g. a `super`/`zsuper` block —
        // see the `nle_pending` field doc).
        let has_args = Self::nle_block_has_args(&node.parameters());
        let nle_frame = match self.nle_pending.take() {
            Some((true, _, _)) => NleFrame::Lambda,
            Some((false, chained, is_define_method)) => NleFrame::Block { has_args, is_define_method, chained },
            None => NleFrame::Block { has_args, is_define_method: false, chained: false },
        };
        self.nle_stack.push(nle_frame);
        // Naming/MemoizedInstanceVariableName: consume the dynamic-define
        // method name `visit_call_node` stashed right before this visit —
        // see the `mivn_pending_method_name` field doc.
        if let Some(mivn_name) = self.mivn_pending_method_name.take().flatten() {
            self.check_memoized_ivar_block(&mivn_name, node);
        }
        // Style/ExplicitBlockArgument: consume the owning call/super/zsuper
        // shape set right before this visit — see the `eba_pending` doc.
        if let Some(owner) = self.eba_pending.take() {
            self.check_explicit_block_argument(node, owner);
        }
        let rs_names = node
            .parameters()
            .and_then(|p| p.as_block_parameters_node())
            .and_then(|bp| bp.parameters())
            .map(|pp| style::rs_params_of(&pp))
            .unwrap_or_default();
        match self.rs_scope_stack.last() {
            Some(top) => {
                if !rs_names.is_empty() {
                    top.borrow_mut().extend(rs_names);
                }
                let shared = top.clone();
                self.rs_scope_stack.push(shared);
            }
            None => self.rs_scope_stack.push(std::rc::Rc::new(std::cell::RefCell::new(rs_names))),
        }
        // Layout/EmptyLinesAroundAccessModifier's `@block_line` — updated for
        // EVERY block flavor (do/end, {}, numbered params, `it`), regardless
        // of whether it's a class-constructor block.
        self.el_am_block_line = Some(self.idx.loc(node.location().start_offset()).0);
        // Consume the ctor flag `visit_call_node` set right before calling
        // into us — a `Class.new`/`Module.new`/`Struct.new`/`Data.define`
        // block is unconditionally "in macro scope" (see `el_am_scope` docs).
        let is_ctor_block = std::mem::take(&mut self.el_am_ctor_block);
        if is_ctor_block {
            self.el_am_scope.push(true);
        }
        // Consume the metrics_ctor_block flag for Struct.new/Data.define blocks
        let is_metrics_ctor_block = std::mem::take(&mut self.metrics_ctor_block);
        if is_metrics_ctor_block {
            self.metrics_in_struct_data_define_block.push(true);
        }
        // Lint/SuppressedException's ancestor search: `:any_block` — closing
        // line is the block's own delimiter (`end` or `}`).
        let block_end_line = self.idx.loc(node.closing_loc().start_offset()).0;
        self.se_ancestor_end_lines.push(block_end_line);
        // Style/Alias's `scope_type`: this block is `:instance_eval` iff the
        // owning call (set right before `visit_call_node` descended into us)
        // is named `instance_eval`; otherwise it's `:dynamic` like any other
        // block. `None` (unreached via that path) defaults to `:dynamic`.
        let alias_instance_eval = self.alias_pending_instance_eval.take().unwrap_or(false);
        self.alias_scope_stack.push(if alias_instance_eval { 2 } else { 1 });
        // Style/TrivialAccessors: an `instance_eval` block is a barrier (see
        // `ta_barrier`'s doc); any other block/lambda is transparent, so
        // nothing is pushed and the ancestor walk passes straight through.
        if alias_instance_eval {
            self.ta_barrier.push(2);
        }
        // Style/DoubleNegation: consume the `define_method`/
        // `define_singleton_method` verdict `visit_call_node` set right
        // before descending into us — see the `dn_pending_define_method`
        // field doc. `None` for an ordinary block (never pushed at all,
        // exactly like upstream's `define_method?(parent)` staying false).
        let dn_define_method = self.dn_pending_define_method.take();
        if let Some(last_child) = dn_define_method {
            self.dn_ancestors.push(DnFrame::DefineMethodCall(last_child));
        }
        if let Some(params) = node.parameters() {
            self.visit(&params);
        }
        if let Some(body) = node.body() {
            if body.as_statements_node().is_some() {
                self.block_owns_next_stmts = true;
                self.el_am_block_owns_next_stmts = true;
                // Lint/Void's `on_block`/`on_numblock`/`on_itblock`: a
                // SINGLE-statement, non-`begin` body is checked directly
                // (`check_void_op`/`check_expression`, no group/pop logic)
                // when `in_void_context?` (this block's own `void_context?`
                // — `each`/`tap`) — but `each` is excluded right after, so
                // only a bare `tap { single_stmt }` ever reaches this. A
                // 2+-statement body instead goes through
                // `visit_statements_node`'s generic group handling below via
                // `void_pending_ctx`.
                let stmts = body.as_statements_node().unwrap();
                let count = stmts.body().iter().count();
                if count == 1 {
                    if void_is_tap {
                        if let Some(only) = stmts.body().iter().next() {
                            self.check_void_op(&only, false);
                            self.check_void_expr(&only, false);
                        }
                    }
                } else if count >= 2 {
                    self.void_pending_ctx = Some(void_is_each || void_is_tap);
                }
            }
            self.visit(&body);
        }
        self.void_each_stack.pop();
        if dn_define_method.is_some() {
            self.dn_ancestors.pop();
        }
        if alias_instance_eval {
            self.ta_barrier.pop();
        }
        self.alias_scope_stack.pop();
        self.se_ancestor_end_lines.pop();
        self.rs_scope_stack.pop();
        self.rs_block_stack.pop();
        self.nle_stack.pop();
        self.ms_block_stack.pop();
        if is_ctor_block {
            self.el_am_scope.pop();
        }
        if is_metrics_ctor_block {
            self.metrics_in_struct_data_define_block.pop();
        }
    }
    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        self.check_next_while(node);
        self.check_loop_while(node);
        self.check_unreachable_loop_while(node);
        if node.is_begin_modifier() {
            self.check_literal_as_condition_while_post(node);
        } else {
            self.check_literal_as_condition_while(node);
        }
        self.check_infinite_loop(
            style::il_truthy_literal(&node.predicate()),
            node.location(),
            node.keyword_loc(),
            &node.predicate(),
            node.statements(),
            node.do_keyword_loc(),
            node.closing_loc(),
            node.is_begin_modifier(),
        );
        self.rs_scan_conditional(&node.as_node(), &node.predicate());
        self.check_and_or_conditional(&node.predicate());
        self.check_assignment_in_condition(&node.predicate());
        // `on_while` is never invoked upstream for the `begin...end while`
        // post-condition-loop shape (a distinct whitequark node type), so
        // skip it here too.
        if !node.is_begin_modifier() {
            self.check_parens_around_condition("while", true, &node.predicate());
        }
        self.check_negated_while(node.predicate(), node.location().start_offset(), node.keyword_loc(), false);
        if !node.statements().is_some_and(|st| st.location().start_offset() < node.keyword_loc().start_offset()) {
            self.check_condition_position(b"while", node.keyword_loc().start_offset(), &node.predicate());
        }
        self.check_while_until_do(&node.predicate(), node.do_keyword_loc(), node.location(),
            node.statements().map(|s| s.location().start_offset()), "while");
        // pre-order: a genuine modifier `while` (not the `begin...end while`
        // post-condition-loop shape, which prism flags via `is_begin_modifier`
        // and rubocop-ast gives a distinct `:while_post` type that's never
        // `basic_conditional?`) has its body before its keyword.
        if !node.is_begin_modifier()
            && node.statements().is_some_and(|st| st.location().start_offset() < node.keyword_loc().start_offset())
        {
            self.check_nested_modifier("while", node.predicate(), node.statements(), false);
            self.rrs_note_modifier_body(node.statements(), node.location().end_offset());
        }
        self.check_while_until_modifier(
            &node.as_node(),
            node.keyword_loc(),
            node.predicate(),
            node.statements(),
            node.closing_loc(),
            "while",
        );
        self.sak_check(node.keyword_loc().start_offset(), node.keyword_loc().end_offset(), b"while");
        if let Some(do_kw) = node.do_keyword_loc() {
            self.sak_check(do_kw.start_offset(), do_kw.end_offset(), b"do");
        }
        if let Some(closing) = node.closing_loc() {
            if node.do_keyword_loc().is_some() {
                self.sak_check_end(closing.start_offset(), b"end");
            }
        }
        self.cond_depth += 1;
        // Style/DoubleNegation: `conditional?`'s `CONDITIONALS` set includes
        // `:while` but NOT `:while_post` — the `begin...end while` shape
        // whitequark gives a distinct type, matching `is_begin_modifier()`.
        let dn_pushed = !node.is_begin_modifier();
        if dn_pushed {
            self.dn_ancestors.push(DnFrame::Conditional(self.idx.loc(node.location().end_offset().saturating_sub(1)).0));
        }
        self.hs_call_like_ctx.insert(node.predicate().location().start_offset());
        let hs_modifier = node.closing_loc().is_none();
        if hs_modifier {
            self.hs_modifier_depth += 1;
        }
        ruby_prism::visit_while_node(self, node);
        if hs_modifier {
            self.hs_modifier_depth -= 1;
        }
        if dn_pushed {
            self.dn_ancestors.pop();
        }
        self.cond_depth -= 1;
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        self.check_next_until(node);
        self.check_loop_until(node);
        self.check_unreachable_loop_until(node);
        if node.is_begin_modifier() {
            self.check_literal_as_condition_until_post(node);
        } else {
            self.check_literal_as_condition_until(node);
        }
        self.check_infinite_loop(
            style::il_falsey_literal(&node.predicate()),
            node.location(),
            node.keyword_loc(),
            &node.predicate(),
            node.statements(),
            node.do_keyword_loc(),
            node.closing_loc(),
            node.is_begin_modifier(),
        );
        self.rs_scan_conditional(&node.as_node(), &node.predicate());
        self.check_and_or_conditional(&node.predicate());
        self.check_assignment_in_condition(&node.predicate());
        // `on_until` (aliased to `on_while` upstream) is never invoked for
        // the `begin...end until` post-condition-loop shape either.
        if !node.is_begin_modifier() {
            self.check_parens_around_condition("until", true, &node.predicate());
        }
        self.check_negated_while(node.predicate(), node.location().start_offset(), node.keyword_loc(), true);
        if !node.statements().is_some_and(|st| st.location().start_offset() < node.keyword_loc().start_offset()) {
            self.check_condition_position(b"until", node.keyword_loc().start_offset(), &node.predicate());
        }
        self.check_while_until_do(&node.predicate(), node.do_keyword_loc(), node.location(),
            node.statements().map(|s| s.location().start_offset()), "until");
        // pre-order: see visit_while_node's note on `is_begin_modifier`.
        if !node.is_begin_modifier()
            && node.statements().is_some_and(|st| st.location().start_offset() < node.keyword_loc().start_offset())
        {
            self.check_nested_modifier("until", node.predicate(), node.statements(), false);
            self.rrs_note_modifier_body(node.statements(), node.location().end_offset());
        }
        self.check_while_until_modifier(
            &node.as_node(),
            node.keyword_loc(),
            node.predicate(),
            node.statements(),
            node.closing_loc(),
            "until",
        );
        self.sak_check(node.keyword_loc().start_offset(), node.keyword_loc().end_offset(), b"until");
        if let Some(do_kw) = node.do_keyword_loc() {
            self.sak_check(do_kw.start_offset(), do_kw.end_offset(), b"do");
        }
        if let Some(closing) = node.closing_loc() {
            if node.do_keyword_loc().is_some() {
                self.sak_check_end(closing.start_offset(), b"end");
            }
        }
        self.cond_depth += 1;
        let dn_pushed = !node.is_begin_modifier();
        if dn_pushed {
            self.dn_ancestors.push(DnFrame::Conditional(self.idx.loc(node.location().end_offset().saturating_sub(1)).0));
        }
        self.hs_call_like_ctx.insert(node.predicate().location().start_offset());
        let hs_modifier = node.closing_loc().is_none();
        if hs_modifier {
            self.hs_modifier_depth += 1;
        }
        ruby_prism::visit_until_node(self, node);
        if hs_modifier {
            self.hs_modifier_depth -= 1;
        }
        if dn_pushed {
            self.dn_ancestors.pop();
        }
        self.cond_depth -= 1;
    }
    fn visit_for_node(&mut self, node: &ruby_prism::ForNode<'pr>) {
        self.check_next_for(node);
        self.check_for(node);
        self.check_unreachable_loop_for(node);
        if let Some(do_kw) = node.do_keyword_loc() {
            self.sak_check(do_kw.start_offset(), do_kw.end_offset(), b"do");
            self.sak_check_end(node.end_keyword_loc().start_offset(), b"end");
        }
        // Manual (rather than the default `ruby_prism::visit_for_node`) so
        // `void_pending_ctx` is set immediately before (and only before) the
        // STATEMENTS child specifically — `ForNode#void_context?` is always
        // `true` upstream (see `void_pending_ctx`'s field doc).
        self.visit(&node.index());
        self.visit(&node.collection());
        if let Some(stmts) = node.statements() {
            self.void_pending_ctx = Some(true);
            self.visit_statements_node(&stmts);
        }
    }
    fn visit_pre_execution_node(&mut self, node: &ruby_prism::PreExecutionNode<'pr>) {
        if self.on("Style/BeginBlock") {
            self.push(node.keyword_loc().start_offset(), "Style/BeginBlock", false,
                "Avoid the use of `BEGIN` blocks.");
        }
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"BEGIN");
        ruby_prism::visit_pre_execution_node(self, node);
    }
    fn visit_post_execution_node(&mut self, node: &ruby_prism::PostExecutionNode<'pr>) {
        if self.on("Style/EndBlock") {
            let kw = node.keyword_loc();
            self.push(kw.start_offset(), "Style/EndBlock", true,
                "Avoid the use of `END` blocks. Use `Kernel#at_exit` instead.");
            self.fixes.push((kw.start_offset(), kw.end_offset(), b"at_exit".to_vec()));
        }
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"END");
        ruby_prism::visit_post_execution_node(self, node);
    }
    fn visit_begin_node(&mut self, node: &ruby_prism::BeginNode<'pr>) {
        self.check_signal_exception_rescue(node);
        self.check_duplicate_rescue_exception(node);
        self.check_shadowed_exception(node);
        self.check_useless_else_without_rescue(node);
        self.check_empty_lines_around_begin_body(node);
        self.check_empty_lines_around_exception_handling_keywords_kwbegin(node);
        self.check_begin_end_alignment(node);
        let kwbegin = node.begin_keyword_loc().is_some();
        // Layout/SpaceAroundKeyword: `on_kwbegin`'s `begin`/`end` (explicit
        // `begin...end` only — the IMPLICIT BeginNode wrapping a def's
        // rescue/ensure body has no `begin_keyword_loc` and isn't checked)
        // plus `on_rescue`'s `else` (the `else` after a rescue clause, which
        // DOES apply to both the explicit-kwbegin and implicit-def shapes).
        if let Some(begin_kw) = node.begin_keyword_loc() {
            self.sak_check(begin_kw.start_offset(), begin_kw.end_offset(), b"begin");
        }
        if let Some(end_kw) = node.end_keyword_loc() {
            if kwbegin {
                self.sak_check_end(end_kw.start_offset(), b"end");
            }
        }
        if let Some(else_node) = node.else_clause() {
            let e = else_node.else_keyword_loc();
            self.sak_check(e.start_offset(), e.end_offset(), b"else");
        }
        if kwbegin {
            self.usage_block_depth += 1;
            // Lint/SuppressedException's ancestor search: an explicit
            // `begin...end` is a `:kwbegin` ancestor; the closing line is
            // its `end` keyword (always present when `begin_keyword_loc` is).
            let end_line = node
                .end_keyword_loc()
                .map(|l| self.idx.loc(l.start_offset()).0)
                .unwrap_or_else(|| self.idx.loc(node.location().end_offset()).0);
            self.se_ancestor_end_lines.push(end_line);
            // Naming/RescuedExceptionsVariableName: open a fresh accumulator
            // for offenses found anywhere inside this kwbegin — rubocop's
            // autocorrect additionally renames references in
            // `kwbegin_node.right_siblings`.
            self.renv_pending_kwbegin_stack.push(Vec::new());
        }
        ruby_prism::visit_begin_node(self, node);
        if kwbegin {
            self.usage_block_depth -= 1;
            self.se_ancestor_end_lines.pop();
            self.renv_just_closed_kwbegin_renames =
                self.renv_pending_kwbegin_stack.pop().unwrap_or_default();
        }
    }
    fn visit_ensure_node(&mut self, node: &ruby_prism::EnsureNode<'pr>) {
        self.check_empty_ensure(node);
        self.check_ensure_return(node);
        let kw = node.ensure_keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"ensure");
        // Lint/Void's `on_ensure`/`check_ensure`: `EnsureNode#void_context?`
        // is unconditionally `true` upstream. A single-statement clause body
        // (`node.branch` not `begin_type?`) is checked DIRECTLY — never
        // gated on `in_void_context?` at all — matching `check_ensure`'s
        // early bypass; a 2+-statement body instead goes through
        // `visit_statements_node`'s generic group handling via
        // `void_pending_ctx` (an empty clause, `node.statements() ==
        // None`, mirrors `check_ensure`'s `return unless (body = node.
        // branch)` guard: nothing to check).
        if let Some(stmts) = node.statements() {
            let count = stmts.body().iter().count();
            if count == 1 {
                if let Some(only) = stmts.body().iter().next() {
                    self.check_void_expr(&only, false);
                }
            } else if count >= 2 {
                self.void_pending_ctx = Some(true);
            }
            self.visit_statements_node(&stmts);
        }
    }
    fn visit_parentheses_node(&mut self, node: &ruby_prism::ParenthesesNode<'pr>) {
        self.check_empty_expression(node);
        self.record_rescue_modifier_parens(node);
        // Style/HashSyntax: `parentheses?(dispatch.parent)` — whitequark
        // transparently unwraps a single-statement `StatementsNode` body, so
        // a lone statement inside `(...)` has the parens node itself, not
        // the statements wrapper, as its "parent".
        if let Some(body) = node.body() {
            if let Some(stmts) = body.as_statements_node() {
                let items: Vec<ruby_prism::Node> = stmts.body().iter().collect();
                if items.len() == 1 {
                    self.hs_paren_parent.insert(items[0].location().start_offset());
                }
            }
        }
        ruby_prism::visit_parentheses_node(self, node);
    }
    fn visit_array_node(&mut self, node: &ruby_prism::ArrayNode<'pr>) {
        self.check_trailing_comma_in_array_literal(node);
        self.check_hash_as_last_array_item(node);
        self.check_multiline_array_brace_layout(node);
        self.check_nested_percent_literal(node);
        self.check_percent_symbol_array(node);
        self.check_percent_string_array(node);
        self.check_symbol_array(node);
        self.check_word_array(node);
        self.check_min_max_array(node);
        self.check_space_inside_percent_literal_delimiters_array(node);
        self.check_percent_literal_delimiters_array(node);
        if self.ll_active {
            let heredoc_arg_index = node
                .elements()
                .iter()
                .position(|e| breakable::is_heredoc_node(&e));
            if self.ll_split {
                for e in node.elements().iter() {
                    self.ll_str_skip.insert(e.location().start_offset());
                }
            }
            let l = node.location();
            self.ll_enter_collection(
                l.start_offset(),
                l.end_offset(),
                node.elements().iter().count(),
                || node
                    .elements()
                    .iter()
                    .map(|e| (e.location().start_offset(), e.location().end_offset()))
                    .collect(),
                breakable::LlKind::Array,
                breakable::LlCallInfo { heredoc_arg_index, ..Default::default() },
            );
        }
        if let Some(o) = node.opening_loc() {
            let o = o.as_slice();
            if o.starts_with(b"%i") || o.starts_with(b"%I") {
                let l = node.location();
                self.percent_sym_spans.push((l.start_offset(), l.end_offset()));
            }
            if o.starts_with(b"%") {
                let l = node.location();
                self.percent_arr_spans.push((l.start_offset(), l.end_offset()));
                // Style/RedundantInterpolation's `embedded_in_percent_array?`
                // guard: an interpolated element with no quotes of its own
                // directly inside ANY percent-literal array (`%W(#{@var}
                // foo)`), mirroring upstream's generic `percent_literal?`
                // (any `%`-prefixed array opening).
                if self.on("Style/RedundantInterpolation") {
                    for e in node.elements().iter() {
                        self.ri_percent_array_child.insert(e.location().start_offset());
                    }
                }
            }
        }
        self.check_redundant_capital_w(node);
        self.check_space_inside_array_percent_literal(node);
        if self.eng.debugger_on {
            for e in node.elements().iter() {
                self.assumed_arg_offsets.insert(e.location().start_offset());
            }
        }
        if self.on("Lint/ImplicitStringConcatenation") {
            for e in node.elements().iter() {
                self.isc_array_child.insert(e.location().start_offset());
            }
        }
        self.check_array_alignment(node);
        // Lint/SafeNavigationChain: `operator_inside_collection_literal?`'s
        // `type?(:array, :pair)` — the array-literal half.
        if self.on("Lint/SafeNavigationChain") {
            for e in node.elements().iter() {
                self.snav_parent.insert(e.location().start_offset(), lint_cops::SnavParent::CollectionLiteral);
            }
        }
        let wa_matrix = self.wa_matrix_complex(node);
        self.wa_matrix_stack.push(wa_matrix);
        // Lint/RedundantSplatExpansion: covers BOTH a real `[...]`/percent
        // literal AND the bracket-less array prism synthesizes around a bare
        // splat used as the WHOLE value of a simple/multiple-assignment RHS
        // (`opening_loc` is `None` for that synthetic wrapper) — the same
        // `ArrayNode` shape either way, distinguished only by `opening_loc`.
        if self.on("Lint/RedundantSplatExpansion") {
            let bracketed = node.opening_loc().is_some();
            let l = node.location();
            let len = node.elements().iter().count();
            for e in node.elements().iter() {
                if e.as_splat_node().is_some() {
                    self.rse_ctx.insert(
                        e.location().start_offset(),
                        lint_cops::RseCtx {
                            container: if bracketed {
                                lint_cops::RseContainer::ArrayBracketed
                            } else {
                                lint_cops::RseContainer::ArrayImplicit
                            },
                            container_start: l.start_offset(),
                            container_end: l.end_offset(),
                            array_len: len,
                        },
                    );
                }
            }
        }
        // Style/DoubleNegation: `find_parent_not_enumerable`'s `array_type?`.
        self.dn_ancestors.push(DnFrame::Enumerable {
            start: node.location().start_offset(),
            child_starts: node.elements().iter().map(|e| e.location().start_offset()).collect(),
        });
        ruby_prism::visit_array_node(self, node);
        self.dn_ancestors.pop();
        self.wa_matrix_stack.pop();
        self.ll_exit_collection();
    }
    fn visit_assoc_node(&mut self, node: &ruby_prism::AssocNode<'pr>) {
        self.check_hash_syntax_pair(node);
        // both sides of a hash pair are "assumed arguments"
        if self.eng.debugger_on {
            self.assumed_arg_offsets.insert(node.key().location().start_offset());
            self.assumed_arg_offsets.insert(node.value().location().start_offset());
        }
        if self.ll_active {
            // strings under a pair are not split-candidates (rubocop's
            // breakable_string? parent check)
            self.ll_str_skip.insert(node.key().location().start_offset());
            self.ll_str_skip.insert(node.value().location().start_offset());
        }
        self.check_space_after_colon_pair(node);
        // Lint/SafeNavigationChain: `operator_inside_collection_literal?`'s
        // `type?(:array, :pair)` — the hash-pair half (key and value alike,
        // for symmetry; only a value ever appears in the fixture).
        if self.on("Lint/SafeNavigationChain") {
            self.snav_parent.insert(node.key().location().start_offset(), lint_cops::SnavParent::CollectionLiteral);
            self.snav_parent.insert(node.value().location().start_offset(), lint_cops::SnavParent::CollectionLiteral);
        }
        // Style/DoubleNegation: `find_parent_not_enumerable`'s `pair_type?`.
        self.dn_ancestors.push(DnFrame::Enumerable {
            start: node.location().start_offset(),
            child_starts: vec![
                node.key().location().start_offset(),
                node.value().location().start_offset(),
            ],
        });
        ruby_prism::visit_assoc_node(self, node);
        self.dn_ancestors.pop();
    }
    fn visit_embedded_variable_node(&mut self, node: &ruby_prism::EmbeddedVariableNode<'pr>) {
        self.check_variable_interpolation(node);
        let prev = self.sgv_in_embedded_var;
        self.sgv_in_embedded_var = true;
        ruby_prism::visit_embedded_variable_node(self, node);
        self.sgv_in_embedded_var = prev;
    }
    fn visit_embedded_statements_node(&mut self, node: &ruby_prism::EmbeddedStatementsNode<'pr>) {
        self.check_space_inside_string_interpolation(node);
        self.check_redundant_string_coercion_in_interpolation(node);
        self.check_empty_interpolation(node);
        // Style/SpecialGlobalVars: `"#{$var}"` with NOTHING but the gvar
        // inside the braces is upstream's `node.parent&.begin_type? &&
        // node.parent.children.one?` climb target — the translated
        // "begin" node there is really THIS embedded-statements node
        // itself, whose own `loc.expression` (rubocop-ast's prism
        // translation) spans the WHOLE `#{...}` including its own `#{`/`}`
        // delimiters. Recorded here (keyed by the sole gvar's own start
        // offset) so the offense side doesn't need parent pointers.
        if let Some(stmts) = node.statements() {
            let body: Vec<ruby_prism::Node> = stmts.body().iter().collect();
            if body.len() == 1 {
                if let Some(gvar) = body[0].as_global_variable_read_node() {
                    let eloc = node.location();
                    self.sgv_climb.insert(
                        gvar.location().start_offset(),
                        (eloc.start_offset(), eloc.end_offset(), self.sgv_brace_eligible),
                    );
                }
            }
        }
        self.interp_depth += 1;
        ruby_prism::visit_embedded_statements_node(self, node);
        self.interp_depth -= 1;
    }
    fn visit_program_node(&mut self, node: &ruby_prism::ProgramNode<'pr>) {
        self.check_signal_exception_prescan(node);
        self.check_redundant_begin(node);
        self.check_block_nesting(node);
        self.check_duplicated_gem(node);
        self.check_duplicated_group(node);
        self.check_mixin_usage(&node.statements().as_node());
        self.class_children_stack.push(Self::direct_child_classes(&Some(node.statements().as_node())));
        self.exception_siblings_stack.push(Self::direct_child_defs(&Some(node.statements().as_node())));
        let top_body = node.statements().body();
        self.sgv_top_stmts = top_body
            .iter()
            .map(|n| {
                let loc = n.location();
                (loc.start_offset(), loc.end_offset(), self.sgv_is_require_english(&n))
            })
            .collect();
        self.top_level_sole_stmt = if top_body.len() == 1 {
            top_body.first().map(|n| n.location().start_offset())
        } else {
            None
        };
        self.check_underscore_prefixed_variable_name(node);
        self.check_shadowed_argument(node);
        self.check_unused_block_argument(node);
        self.check_unused_method_argument(node);
        self.check_space_inside_parens(node);
        self.check_useless_access_modifier_top_level(&node.statements());
        ruby_prism::visit_program_node(self, node);
        self.exception_siblings_stack.pop();
        self.class_children_stack.pop();
        // Gemspec/RequiredRubyVersion's `on_new_investigation`: after the
        // whole file has been walked (populating `grrv_seen` via any
        // `required_ruby_version=` send visited above), fire the
        // missing-version offense if none was ever seen; blank sources
        // mirror rubocop's `processed_source.ast` nil-check.
        let has_code = node.statements().body().iter().next().is_some();
        self.check_required_ruby_version_missing(has_code);
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.check_class_length_class(node);
        self.check_ascii_class(node);
        let l = node.location();
        self.check_empty_class(l.start_offset(), l.end_offset(),
            node.body().is_some(), node.superclass().is_some(), false);
        self.check_trailing_body_on_class(node.class_keyword_loc().start_offset(), l.end_offset(), node.body());
        self.check_class_methods(&node.constant_path(), node.body());
        self.check_documentation("class", node.location().start_offset(), &node.constant_path(), node.body());
        self.check_camel_case_name(&node.constant_path());
        self.check_inherit_exception_class(node);
        self.check_ineffective_access_modifier(node.body());
        self.check_useless_access_modifier_scope(node.body());
        self.check_bisected_attr_accessor(node.body());
        self.check_mixin_grouping(node.body());
        self.check_accessor_grouping(node.body());
        self.check_empty_lines_around_class_body(node);
        self.check_access_modifier_indentation_class(node);
        self.check_struct_inheritance(node);
        self.enter_namespace(node.location().start_offset(), &node.constant_path());
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        self.exception_siblings_stack.push(Self::direct_child_defs(&node.body()));
        self.respond_to_missing_stack.push(Self::scan_respond_to_missing(&node.body()));
        // Layout/EmptyLinesAroundAccessModifier's `@class_or_module_def_first_line`/
        // `@class_or_module_def_last_line` — `parent_class.first_line` (the
        // superclass expression) when there is one, else the class node's own
        // first line (its `class` keyword).
        self.el_am_class_first_line = Some(self.idx.loc(
            node.superclass().map(|s| s.location().start_offset()).unwrap_or(l.start_offset()),
        ).0);
        self.el_am_class_last_line = Some(self.idx.loc(l.end_offset().saturating_sub(1)).0);
        self.el_am_scope.push(true);
        // Style/Attr: check if this class has a custom `attr` method
        let has_custom_attr = Self::has_custom_attr_method_in_body(&node.body());
        self.style_attr_custom_method_stack.push(has_custom_attr);
        // Lint/MissingSuper: this REAL `class` node's own "stateful parent"
        // verdict — see the `ms_class_stack` field doc.
        self.ms_class_stack.push(self.ms_has_stateful_parent(node.superclass().as_ref()));
        self.ms_scope_depth += 1;
        // Default walk — covers the superclass expression too, not just the body.
        self.class_module_depth += 1;
        self.cl_class_depth += 1;
        self.alias_scope_stack.push(0);
        self.alias_cm_stack.push(true);
        self.ta_barrier.push(0);
        ruby_prism::visit_class_node(self, node);
        self.ta_barrier.pop();
        self.alias_cm_stack.pop();
        self.alias_scope_stack.pop();
        self.cl_class_depth -= 1;
        self.class_module_depth -= 1;
        self.ms_scope_depth -= 1;
        self.ms_class_stack.pop();
        self.style_attr_custom_method_stack.pop();
        self.el_am_scope.pop();
        self.respond_to_missing_stack.pop();
        self.exception_siblings_stack.pop();
        self.class_children_stack.pop();
        self.leave_namespace();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.check_module_length_module(node);
        self.check_ascii_module(node);
        self.check_trailing_body_on_module(node);
        self.check_class_methods(&node.constant_path(), node.body());
        self.check_documentation("module", node.location().start_offset(), &node.constant_path(), node.body());
        self.check_camel_case_name(&node.constant_path());
        self.check_module_function(node);
        self.check_empty_lines_around_module_body(node);
        self.check_ineffective_access_modifier(node.body());
        self.check_useless_access_modifier_scope(node.body());
        self.check_bisected_attr_accessor(node.body());
        self.check_mixin_grouping(node.body());
        self.check_accessor_grouping(node.body());
        self.check_access_modifier_indentation_module(node);
        self.enter_namespace(node.location().start_offset(), &node.constant_path());
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        self.exception_siblings_stack.push(Self::direct_child_defs(&node.body()));
        self.respond_to_missing_stack.push(Self::scan_respond_to_missing(&node.body()));
        let ml = node.location();
        self.el_am_class_first_line = Some(self.idx.loc(ml.start_offset()).0);
        self.el_am_class_last_line = Some(self.idx.loc(ml.end_offset().saturating_sub(1)).0);
        self.el_am_scope.push(true);
        // Style/Attr: check if this module has a custom `attr` method
        let has_custom_attr = Self::has_custom_attr_method_in_body(&node.body());
        self.style_attr_custom_method_stack.push(has_custom_attr);
        self.class_module_depth += 1;
        self.ms_scope_depth += 1;
        self.alias_scope_stack.push(0);
        self.alias_cm_stack.push(false);
        self.ta_barrier.push(1);
        ruby_prism::visit_module_node(self, node);
        self.ta_barrier.pop();
        self.alias_cm_stack.pop();
        self.alias_scope_stack.pop();
        self.ms_scope_depth -= 1;
        self.class_module_depth -= 1;
        self.style_attr_custom_method_stack.pop();
        self.el_am_scope.pop();
        self.respond_to_missing_stack.pop();
        self.exception_siblings_stack.pop();
        self.class_children_stack.pop();
        self.leave_namespace();
    }
    fn visit_integer_node(&mut self, node: &ruby_prism::IntegerNode<'pr>) {
        if !self.num_ignore.contains(&node.location().start_offset()) {
            self.check_numeric_literals(&node.as_node());
            self.check_numeric_literal_prefix(node);
        }
    }
    fn visit_float_node(&mut self, node: &ruby_prism::FloatNode<'pr>) {
        self.check_float_out_of_range(node);
        self.check_exponential_notation(node);
        if !self.num_ignore.contains(&node.location().start_offset()) {
            self.check_numeric_literals(&node.as_node());
        }
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        self.check_trivial_accessors(node);
        self.check_ascii_def(node);
        self.check_multiline_method_definition_brace_layout(node);
        self.check_def_end_alignment(node);
        self.check_missing_respond_to_missing(node);
        self.check_trailing_method_end_statement(node);
        self.check_optional_boolean_parameter(node);
        self.check_empty_lines_around_method_body(node);
        self.check_empty_lines_around_exception_handling_keywords_def(node);
        self.check_disjunctive_assignment_in_constructor(node);
        self.check_useless_setter_call(node);
        self.check_useless_method_definition(node);
        self.check_to_json(node);
        self.check_single_line_methods(node);
        self.check_empty_method(node);
        self.check_accessor_method_name(node);
        self.check_metrics_complexity_def(node);
        self.check_metrics_parameter_lists(node);
        self.check_method_length_def(node);
        self.check_def_with_parentheses(node);
        self.check_space_after_method_name(node);
        self.check_colon_method_definition(node);
        if node.equal_loc().is_none() {
            self.check_trailing_body_on_method_definition(node);
        }
        self.check_method_name_def(node);
        self.check_variable_number_def(node);
        self.check_predicate_prefix_def(node);
        self.check_binary_operator_parameter(node);
        self.check_nested_method_definition(node);
        self.check_redundant_return(node);
        self.check_redundant_assignment(node);
        self.check_return_in_void_context(node);
        self.check_optional_arguments(node);
        self.check_method_parameter_name(node);
        self.check_keyword_parameters_order_def(node);
        self.check_non_nil_check_def(node);
        self.check_parameter_alignment(node);
        self.check_first_parameter_indentation(node);
        self.check_missing_super(node);
        self.check_method_def_parentheses(node);
        self.check_memoized_ivar_def(node);
        self.check_guard_clause_def(node.body());
        // Default walk (receiver, params, body) one def level deeper — matches
        // rubocop's each_ancestor(:def) semantics, and covers offenses in
        // parameter default values, which a body-only walk silently skipped.
        if self.ll_active {
            let l = node.location();
            let count = node.parameters().map(|p| breakable::param_count(&p)).unwrap_or(0);
            self.ll_enter_collection(
                l.start_offset(),
                l.end_offset(),
                count,
                || breakable::def_param_spans(node),
                breakable::LlKind::Def,
                breakable::LlCallInfo::default(),
            );
        }
        self.def_depth += 1;
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        // Style/RedundantSelf: a `def` ALWAYS starts a brand-new scope (even
        // nested inside a block/def) — methods don't see enclosing locals.
        let rs_names = node.parameters().map(|p| style::rs_params_of(&p)).unwrap_or_default();
        self.rs_scope_stack.push(std::rc::Rc::new(std::cell::RefCell::new(rs_names)));
        // A `def` is never a `in_macro_scope?` wrapper — any bare
        // public/private/protected/module_function inside one (however
        // deeply, through transparent if/begin/block wrappers) is just a
        // regular method call, not an access-modifier declaration.
        self.el_am_scope.push(false);
        // Lint/SuppressedException's ancestor search: `:any_def` — closing
        // line is the `end` keyword, or (endless def) the node's own last line.
        let def_end_line = node
            .end_keyword_loc()
            .map(|l| self.idx.loc(l.start_offset()).0)
            .unwrap_or_else(|| self.idx.loc(node.location().end_offset()).0);
        self.se_ancestor_end_lines.push(def_end_line);
        // Lint/NonLocalExitFromIterator: a `def`/`defs` always stops
        // upstream's ancestor climb (`scoped_node?`'s `any_def_type?`).
        self.nle_stack.push(NleFrame::Def);
        self.def_name_stack.push(node.name().as_slice().to_vec());
        // Style/ExplicitBlockArgument: this def's precomputed facts (block
        // name, signature edit, zsuper arg texts) — see `EbaDefInfo`'s doc.
        self.eba_def_stack.push(style::eba_build_def_info(self.src, node));
        self.alias_scope_stack.push(1);
        let alias_plain_def = node.receiver().is_none();
        if alias_plain_def {
            self.alias_def_depth += 1;
        }
        // Style/DoubleNegation: `find_def_node_from_ascendant`'s `any_def_type?`
        // stop, with `find_last_child(def_node.body)` precomputed eagerly —
        // it only depends on this def's own static shape.
        self.dn_ancestors.push(DnFrame::Def(self.dn_compute_def_last_child(node)));
        // Lint/Void's `DefNode#void_context?`: `(def_type? && method?
        // (:initialize)) || assignment_method?` — `def_type?` is false for
        // a `defs` (`def self.foo`, prism: `receiver().is_some()`), so only
        // `assignment_method?` can apply there. Only set when the body is
        // DIRECTLY a `StatementsNode` (no rescue/else/ensure wrapping it in
        // an implicit `BeginNode` — see `void_pending_ctx`'s doc).
        if node.body().is_some_and(|b| b.as_statements_node().is_some()) {
            let is_defs = node.receiver().is_some();
            let name = node.name();
            let void_ctx = (!is_defs && name.as_slice() == b"initialize")
                || lint_cops::void_is_assignment_method_name(name.as_slice());
            self.void_pending_ctx = Some(void_ctx);
        }
        ruby_prism::visit_def_node(self, node);
        self.dn_ancestors.pop();
        if alias_plain_def {
            self.alias_def_depth -= 1;
        }
        self.alias_scope_stack.pop();
        self.eba_def_stack.pop();
        self.def_name_stack.pop();
        self.nle_stack.pop();
        self.se_ancestor_end_lines.pop();
        self.el_am_scope.pop();
        self.rs_scope_stack.pop();
        self.class_children_stack.pop();
        self.def_depth -= 1;
        self.ll_exit_collection();
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        self.check_space_before_block_braces(&node.opening_loc(), &node.closing_loc());
        self.check_block_end_newline_lambda(node);
        self.check_space_around_block_parameters_lambda(node);
        self.check_space_in_lambda_literal(node);
        self.check_empty_block_lambda(node);
        self.check_nil_lambda_stabby(node);
        self.check_stabby_lambda_parentheses(node);
        self.check_empty_lambda_parameter(node);
        self.check_lambda_literal(node);
        if let Some(p) = node.parameters() {
            self.check_keyword_parameters_order_block(&p);
        }
        self.ll_check_lambda(node);
        if let Some((off, msg)) = self.symbol_proc_lambda(node) {
            self.push(off, "Style/SymbolProc", true, msg);
        }
        // `->` is a lambda literal — rubocop reaches it via the `lambda` send.
        if self.hot.redundant_return {
            if let Some(b) = node.body() {
                self.rr_branch(&b);
            }
        }
        self.usage_block_depth += 1;
        // Lint/NonLocalExitFromIterator: a stabby `->(){}` always stops
        // upstream's ancestor climb (`scoped_node?`'s `node.lambda?` —
        // RuboCop's Prism translator rewrites `LambdaNode` into the same
        // "block whose send is `lambda`" shape it uses for `lambda do...end`).
        self.nle_stack.push(NleFrame::Lambda);
        // Lint/MissingSuper: a stabby lambda is an `any_block` ancestor too
        // (same rewrite noted above) but is never `Class.new(x)`-shaped.
        self.ms_block_stack.push(None);
        // Style/Alias's `scope_type`: same rewrite as above — a stabby lambda
        // is a `:block` whose method is `lambda`, never `instance_eval`.
        self.alias_scope_stack.push(1);
        // Lint/Void: a stabby `->(){}` is an `each_ancestor(:any_block)`
        // stop too (same rewrite noted above), but never `each`/`tap` —
        // see `void_each_stack`'s doc.
        self.void_each_stack.push(false);
        ruby_prism::visit_lambda_node(self, node);
        self.void_each_stack.pop();
        self.alias_scope_stack.pop();
        self.ms_block_stack.pop();
        self.nle_stack.pop();
        self.usage_block_depth -= 1;
    }
    fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
        {
            let kw = node.keyword_loc();
            self.sak_check(kw.start_offset(), kw.end_offset(), b"super");
        }
        self.hs_register_dispatch(
            node.location().start_offset(),
            Some(node.keyword_loc().end_offset()),
            node.rparen_loc().is_some(),
            false,
            false,
            None,
            node.arguments().as_ref(),
        );
        let framed = node.lparen_loc().is_none() && self.hot.empty_literal && node.arguments().is_some();
        if framed {
            let spans: Vec<(usize, usize)> = node
                .arguments()
                .unwrap()
                .arguments()
                .iter()
                .map(|x| (x.location().start_offset(), x.location().end_offset()))
                .collect();
            let first = spans.first().map(|(s, _)| *s).unwrap_or(0);
            self.bare_arg_frames.push((first, spans));
        }
        if let Some(b) = node.block() {
            if let Some(bn) = b.as_block_node() {
                self.check_empty_block_parameter(&bn);
                self.check_block_parameter_name(&bn);
                let owner_line = self.idx.loc(node.keyword_loc().start_offset()).0;
                let end_line = self.idx.loc(bn.closing_loc().start_offset()).0;
                self.check_empty_lines_around_exception_handling_keywords(bn.body(), owner_line, end_line);
                // Style/ExplicitBlockArgument: this `super(...)`'s own
                // shape — see the `eba_pending` field doc.
                self.eba_pending = Some(style::eba_super_owner(node));
            }
            let has_args = node.arguments().is_some_and(|a| a.arguments().iter().count() > 0);
            let last_end = if node.lparen_loc().is_some() {
                node.arguments().and_then(|a| a.arguments().iter().last().map(|n| n.location().end_offset()))
            } else {
                None
            };
            if let Some((off, msg)) = self.symbol_proc_super(&b, has_args, last_end) {
                self.push(off, "Style/SymbolProc", true, msg);
            }
        }
        ruby_prism::visit_super_node(self, node);
        if framed {
            self.bare_arg_frames.pop();
        }
    }
    fn visit_forwarding_super_node(&mut self, node: &ruby_prism::ForwardingSuperNode<'pr>) {
        {
            // `ForwardingSuperNode` (bare `super`, no parens/args) has no
            // dedicated `keyword_loc` — its OWN `location()` spans through a
            // trailing block (`super {}`'s location is `"super {}"`), so the
            // keyword itself is always exactly the first 5 bytes (`super`
            // is a fixed literal for this node — there's no other spelling).
            let start = node.location().start_offset();
            self.sak_check(start, start + 5, b"super");
        }
        if let Some(b) = node.block() {
            self.check_empty_block_parameter(&b);
            self.check_block_parameter_name(&b);
            if let Some((off, msg)) = self.symbol_proc_super(&b.as_node(), false, None) {
                self.push(off, "Style/SymbolProc", true, msg);
            }
            let owner_line = self.idx.loc(node.location().start_offset()).0;
            let end_line = self.idx.loc(b.closing_loc().start_offset()).0;
            self.check_empty_lines_around_exception_handling_keywords(b.body(), owner_line, end_line);
            // Style/ExplicitBlockArgument: bare zsuper's own shape — see
            // the `eba_pending` field doc.
            self.eba_pending = Some(style::eba_zsuper_owner(node));
        }
        ruby_prism::visit_forwarding_super_node(self, node);
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        self.check_class_length_sclass(node);
        self.check_empty_lines_around_sclass_body(node);
        self.check_access_modifier_indentation_sclass(node);
        let l = node.location();
        self.check_empty_class(l.start_offset(), l.end_offset(), node.body().is_some(), false, true);
        self.check_trailing_body_on_class(node.class_keyword_loc().start_offset(), l.end_offset(), node.body());
        self.check_useless_access_modifier_scope(node.body());
        self.check_bisected_attr_accessor(node.body());
        self.check_accessor_grouping(node.body());
        // Layout/EmptyLinesAroundAccessModifier's `@class_or_module_def_first_line`
        // uses `node.identifier.source_range.first_line` — the `<<` expression
        // (usually `self`), not the `class` keyword.
        self.el_am_class_first_line = Some(self.idx.loc(node.expression().location().start_offset()).0);
        self.el_am_class_last_line = Some(self.idx.loc(l.end_offset().saturating_sub(1)).0);
        // The expression (`class << HERE`) is outside the scoping context.
        self.visit(&node.expression());
        // `class << self` is a scoping context — nested defs inside are allowed.
        self.scoping_depth += 1;
        // Lint/MissingSuper: `sclass` counts as a `class`/`sclass`/`module`
        // ancestor for `callback_method_def?`'s existence check.
        self.ms_scope_depth += 1;
        self.el_am_scope.push(true);
        self.respond_to_missing_stack.push(Self::scan_respond_to_missing(&node.body()));
        // Style/TrivialAccessors: `sclass` is a `class`/`sclass` barrier too
        // (see `ta_barrier`'s doc) — a nested def's ancestor walk stops here,
        // returning "not exempt", even under an outer `instance_eval`.
        self.ta_barrier.push(0);
        if let Some(b) = node.body() {
            self.visit(&b);
        }
        self.ta_barrier.pop();
        self.respond_to_missing_stack.pop();
        self.el_am_scope.pop();
        self.ms_scope_depth -= 1;
        self.scoping_depth -= 1;
    }
    fn visit_alias_method_node(&mut self, node: &ruby_prism::AliasMethodNode<'pr>) {
        self.check_method_name_alias(node);
        self.check_alias(node);
        ruby_prism::visit_alias_method_node(self, node);
    }
    fn visit_and_node(&mut self, node: &ruby_prism::AndNode<'pr>) {
        self.check_and_or_and(node);
        self.check_and_with_identical_operands(node);
        self.check_literal_as_condition_and(node);
        self.check_safe_navigation_consistency(node.left(), node.right(), true);
        let op = node.operator_loc();
        self.redundant_sort_logical_left.insert(node.left().location().start_offset(), (op.start_offset(), op.end_offset()));
        self.ra_needs_parens.insert(node.left().location().start_offset());
        self.ra_needs_parens.insert(node.right().location().start_offset());
        if op.as_slice() == b"and" {
            self.sak_check(op.start_offset(), op.end_offset(), b"and");
        }
        if self.on("Lint/SafeNavigationChain") {
            let is_symbol_op = op.as_slice() == b"&&";
            let left = node.left();
            let right = node.right();
            let lhs_receiver = left.as_call_node().and_then(|c| c.receiver()).map(|r| self.node_src(&r));
            self.snav_parent.insert(
                left.location().start_offset(),
                lint_cops::SnavParent::LogicalOperand { is_and: true, is_rhs: false, is_symbol_op, lhs_receiver: None },
            );
            self.snav_parent.insert(
                right.location().start_offset(),
                lint_cops::SnavParent::LogicalOperand { is_and: true, is_rhs: true, is_symbol_op, lhs_receiver },
            );
        }
        ruby_prism::visit_and_node(self, node);
    }
    fn visit_or_node(&mut self, node: &ruby_prism::OrNode<'pr>) {
        self.check_and_or_or(node);
        self.check_or_with_identical_operands(node);
        self.check_literal_as_condition_or(node);
        self.check_safe_navigation_consistency(node.left(), node.right(), false);
        let op = node.operator_loc();
        self.redundant_sort_logical_left.insert(node.left().location().start_offset(), (op.start_offset(), op.end_offset()));
        self.ra_needs_parens.insert(node.left().location().start_offset());
        self.ra_needs_parens.insert(node.right().location().start_offset());
        if op.as_slice() == b"or" {
            self.sak_check(op.start_offset(), op.end_offset(), b"or");
        }
        if self.on("Lint/SafeNavigationChain") {
            let is_symbol_op = op.as_slice() == b"||";
            self.snav_parent.insert(
                node.left().location().start_offset(),
                lint_cops::SnavParent::LogicalOperand { is_and: false, is_rhs: false, is_symbol_op, lhs_receiver: None },
            );
            self.snav_parent.insert(
                node.right().location().start_offset(),
                lint_cops::SnavParent::LogicalOperand { is_and: false, is_rhs: true, is_symbol_op, lhs_receiver: None },
            );
        }
        if node.left().as_or_node().is_some() {
            let l = node.left().location();
            self.mc_nested_or.insert((l.start_offset(), l.end_offset()));
        }
        if node.right().as_or_node().is_some() {
            let l = node.right().location();
            self.mc_nested_or.insert((l.start_offset(), l.end_offset()));
        }
        self.check_style_multiple_comparison(node);
        ruby_prism::visit_or_node(self, node);
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        self.hs_register_dispatch(
            node.location().start_offset(),
            node.message_loc().map(|l| l.end_offset()),
            node.closing_loc().is_some_and(|l| l.as_slice() == b")"),
            matches!(node.name().as_slice(), b"[]" | b"[]="),
            {
                let n = node.name().as_slice();
                n.ends_with(b"=") && !matches!(n, b"==" | b"===" | b"!=" | b"<=" | b">=")
            },
            node.receiver().as_ref(),
            node.arguments().as_ref(),
        );
        // Style/RegexpLiteral: mark a receiver/argument regexp literal as a
        // direct child of THIS call (`node.parent&.call_type?`), before
        // descending — see `rl_call_child`'s doc.
        if let Some(r) = node.receiver() {
            if r.as_regular_expression_node().is_some()
                || r.as_interpolated_regular_expression_node().is_some()
            {
                self.rl_call_child.insert(r.location().start_offset());
            }
        }
        if let Some(args) = node.arguments() {
            for a in args.arguments().iter() {
                if a.as_regular_expression_node().is_some()
                    || a.as_interpolated_regular_expression_node().is_some()
                {
                    self.rl_call_child.insert(a.location().start_offset());
                }
            }
        }
        // PercentArray#invalid_percent_array_context?: mark array-literal
        // arguments of an unparenthesized call with a literal block BEFORE
        // descending — see `pa_invalid_ctx`'s doc.
        if node.opening_loc().is_none()
            && node.block().is_some_and(|b| b.as_block_node().is_some())
        {
            if let Some(args) = node.arguments() {
                for a in args.arguments().iter() {
                    if a.as_array_node().is_some() {
                        self.pa_invalid_ctx.insert(a.location().start_offset());
                    }
                }
            }
        }
        // Style/Lambda's `arg_to_unparenthesized_call?` — see
        // `lambda_unparen_arg`'s doc. Runs for every unparenthesized call
        // with arguments (not just ones with a literal block) since the
        // qualifying node here is an ARGUMENT of THIS call, not necessarily
        // this call's own block.
        if node.opening_loc().is_none() {
            if let Some(args) = node.arguments() {
                for a in args.arguments().iter() {
                    if let Some(kw) = a.as_keyword_hash_node() {
                        for elem in kw.elements().iter() {
                            if let Some(assoc) = elem.as_assoc_node() {
                                self.lambda_unparen_arg.insert(assoc.value().location().start_offset());
                            }
                        }
                    } else {
                        self.lambda_unparen_arg.insert(a.location().start_offset());
                    }
                }
            }
        }
        // Layout/SpaceAroundKeyword's `on_send`: `prefix_not?` — a `not x`
        // call (name `!`, but SPELLED `not`, distinct from `!x`'s bare `!`
        // selector, which this cop never checks).
        if node.name().as_slice() == b"!" {
            if let Some(sel) = node.message_loc() {
                if sel.as_slice() == b"not" {
                    self.sak_check(sel.start_offset(), sel.end_offset(), b"not");
                }
            }
        }
        self.check_double_negation(node);
        self.check_signal_exception_send(node);
        self.check_literal_as_condition_send(node);
        // Lint/UselessMethodDefinition: register def-arguments of generic
        // macro calls (anything but a receiver-less access modifier).
        if let Some(args) = node.arguments() {
            let is_access_modifier = node.receiver().is_none()
                && matches!(node.name().as_slice(), b"private" | b"protected" | b"public" | b"module_function");
            if !is_access_modifier {
                for a in args.arguments().iter() {
                    if a.as_def_node().is_some() {
                        self.def_macro_args.insert(a.location().start_offset());
                    }
                }
            }
            // Style/TrivialAccessors: unlike the set above, this one is NOT
            // exempted for access modifiers — see `ta_call_arg_defs`'s doc.
            for a in args.arguments().iter() {
                if a.as_def_node().is_some() {
                    self.ta_call_arg_defs.insert(a.location().start_offset());
                }
            }
        }
        self.ecc_mark_not_supported_parent_call(node);
        self.check_def_end_alignment_send(node);
        self.check_redundant_self(node);
        self.check_binary_operator_with_identical_operands(node);
        self.check_float_comparison(node);
        self.check_line_end_concatenation(node);
        self.check_string_concatenation(node);
        self.check_hash_each_methods(node);
        if self.ll_active {
            let (count, info) = breakable::call_break_facts(node);
            let l = node.location();
            self.ll_enter_collection(l.start_offset(), l.end_offset(), count,
                || breakable::call_elements(node), breakable::LlKind::Call, info);
            if let Some(b) = node.block().and_then(|b| b.as_block_node()) {
                self.ll_check_block(node, &b);
            }
        }
        // The parser gem folds unary minus into a numeric literal; prism keeps
        // the `-@` call when the sign is separated from the digits. Emulate
        // the fold so the offense span starts at the `-`.
        if node.name().as_slice() == b"-@" && node.arguments().is_none() {
            if let Some(r) = node.receiver() {
                if r.as_integer_node().is_some() || r.as_float_node().is_some() {
                    self.check_numeric_literals(&node.as_node());
                    self.num_ignore.push(r.location().start_offset());
                }
            }
        }
        // `!/foo/` / `not /foo/` — rubocop's fix wraps the WHOLE `!` call
        // (`!(/foo/ =~ $_)`), not just the regexp, since `!` binds tighter
        // than `=~`. Only the immediate `!` wrapping the literal matters —
        // `!!/foo/` corrects to `!!(/foo/ =~ $_)`, wrapping the inner `!`.
        if node.name().as_slice() == b"!" && node.arguments().is_none() {
            if let Some(r) = node.receiver() {
                let regexp_loc = r
                    .as_match_last_line_node()
                    .map(|m| m.location())
                    .or_else(|| r.as_interpolated_match_last_line_node().map(|m| m.location()));
                if let Some(rl) = regexp_loc {
                    self.regexp_bang_ignore.push(rl.start_offset());
                    self.check_regexp_as_condition(&r, Some(node.location()));
                }
            }
        }
        self.check_method_name_macros(node);
        self.check_predicate_prefix_dynamic(node);
        self.check_alias_method(node);
        self.check_colon_method_call(node);
        self.check_deprecated_class_methods(node);
        self.check_marshal_load(node);
        self.check_security_eval(node);
        self.check_eval_with_location(node);
        self.check_redundant_self_assignment_call(node);
        self.check_each_with_object_argument(node);
        self.check_each_with_object(node);
        self.check_hash_transform_keys(node);
        self.check_hash_transform_values(node);
        self.check_trailing_comma_in_attribute_declaration(node);
        self.check_trailing_comma_in_arguments(node);
        self.check_class_variable_set(node);
        self.check_hash_compare_by_identity(node);
        self.check_next_without_accumulator(node);
        self.check_multiple_comparison(node);
        self.check_identity_comparison(node);
        self.check_yoda_condition(node);
        self.check_class_check(node);
        self.check_class_equality_comparison(node);
        self.check_redundant_file_extension_in_require(node);
        self.check_proc_new(node);
        self.check_strip(node);
        self.check_space_after_not(node);
        self.check_empty_literal(node);
        self.check_inherit_exception_new(node);
        self.check_struct_new_override(node);
        self.check_deprecated_open_ssl_constant(node);
        self.check_yaml_load(node);
        self.check_open(node);
        self.check_json_load(node);
        self.check_erb_new_arguments(node);
        self.check_expand_path_arguments(node);
        self.check_redundant_sort_by(node);
        self.check_redundant_sort(node);
        self.check_ambiguous_block_association(node);
        self.check_send_with_mixin_argument(node);
        self.check_space_before_first_arg(node);
        self.check_redundant_string_coercion_in_call(node);
        self.check_each_for_simple_loop(node);
        self.check_for_each(node);
        self.check_redundant_with_index(node);
        self.check_redundant_with_object(node);
        self.check_dot_position(node);
        self.check_space_around_method_call_operator(node);
        self.check_comparable_clamp_min_max(node);
        self.check_redundant_freeze(node);
        self.check_nil_lambda_call(node);
        self.check_lambda_method(node);
        self.check_preferred_hash_methods(node);
        self.check_sample(node);
        self.check_single_argument_dig(node);
        self.check_nested_parenthesized_calls(node);
        self.check_require_parentheses(node);
        self.check_parentheses_as_grouped_expression(node);
        self.check_non_nil_check(node);
        self.check_multiline_method_call_brace_layout(node);
        // Naming/AsciiIdentifiers scans tIDENTIFIER tokens — method call
        // selectors included (weird.なまえ); operators/[] have no message_loc
        // worth checking and setters end in =, both ASCII-guarded anyway.
        if let Some(ml) = node.message_loc() {
            self.check_ascii_identifiers_in_name(node.name().as_slice(), ml.start_offset(), false);
        }
        self.check_case_equality(node);
        self.check_redundant_exception(node);
        self.check_raise_exception(node);
        self.check_raise_args(node);
        self.check_self_assignment_send(node);
        self.check_useless_times(node);
        self.check_attr(node);
        self.check_lambda_call(node);
        self.check_method_call_without_args_parentheses(node);
        self.check_unreachable_loop_call(node);
        self.check_insecure_protocol_source(node);
        self.check_required_ruby_version(node);
        self.check_non_deterministic_require_order(node);
        // Run every ACTIVE declarative pattern against this call (enablement
        // and style gates were resolved when the Engine was built).
        let n = node.as_node();
        let node_off = node.location().start_offset();
        for i in 0..self.eng.decl.len() {
            let (pat, cop, msg, anchor) = &self.eng.decl[i];
            if let Some(caps) = nodepattern::matches(pat, &n, self.src) {
                let (cop, msg) = (*cop, *msg);
                let off = match anchor {
                    Anchor::Op => node.message_loc().map(|l| l.start_offset()).unwrap_or(node_off),
                    Anchor::Node => node_off,
                    Anchor::RecvOp => node
                        .receiver()
                        .and_then(|r| r.as_call_node().and_then(|c| c.message_loc()))
                        .map(|l| l.start_offset())
                        .unwrap_or(node_off),
                };
                let correctable = self.decl_fix(cop, node);
                self.push(off, cop, correctable, render(msg, &caps));
            }
        }
        self.check_zero_length(node);
        self.check_even_odd(node);
        self.check_dir(node);
        self.check_string_chars(node);
        self.check_float_division(node);
        self.check_nested_file_dirname(node);
        self.check_uri_regexp(node);
        self.check_uri_escape_unescape(node);
        self.check_unpack_first(node);
        self.check_random_with_offset(node);
        self.check_debugger(node);
        self.check_stderr_puts(node);
        self.check_not(node);
        self.check_duplicate_require(node);
        self.check_redundant_require_statement(node);
        // Style/RedundantReturn also fires for method-defining blocks
        // (rubocop's RESTRICT_ON_SEND: define_method & friends, lambda).
        if self.hot.redundant_return
            && matches!(node.name().as_slice(), b"define_method" | b"define_singleton_method" | b"lambda")
        {
            if let Some(body) = node.block().and_then(|b| b.as_block_node()).and_then(|b| b.body()) {
                self.rr_branch(&body);
            }
        }
        // Style/NumericPredicate (imperative: message interpolates a constructed
        // suggestion). Uses call_stack for AllowedMethods-on-ancestor + negation.
        if let Some((off, msg)) = self.numeric_predicate(node) {
            // the message quotes the replacement — reuse it as the fix
            if let (Some(s), Some(e)) = (msg.find('`'), msg.rfind("` instead")) {
                let l = node.location();
                self.fixes.push((l.start_offset(), l.end_offset(), msg[s + 1..e].as_bytes().to_vec()));
            }
            self.push(off, "Style/NumericPredicate", true, msg);
        }
        if let Some((off, msg)) = self.symbol_proc(node) {
            self.symbol_proc_fix(node, &msg);
            self.push(off, "Style/SymbolProc", true, msg);
        }
        self.check_slicing_with_range(node);
        self.check_empty_lines_around_arguments(node);
        self.check_format_parameter_mismatch(node);
        // Lint/SafeNavigationChain: the main per-node check (see its doc
        // comment for why this must run BEFORE this call's own arguments are
        // visited below, and how it reads `snav_parent` entries left by
        // ANCESTOR nodes already visited on the way down here).
        self.check_safe_navigation_chain(node);
        // Lint/SafeNavigationChain's `require_parentheses?` 2nd disjunct:
        // mark this call's own arguments when THIS call's method is itself a
        // comparison operator, BEFORE they're visited below.
        if self.on("Lint/SafeNavigationChain")
            && matches!(node.name().as_slice(), b"==" | b"===" | b"!=" | b"<=" | b">=" | b">" | b"<")
        {
            if let Some(args) = node.arguments() {
                for a in args.arguments().iter() {
                    self.snav_parent.insert(a.location().start_offset(), lint_cops::SnavParent::ComparisonCallArg);
                }
            }
        }
        // recurse into children (we've overridden the default walk). Push this
        // call's name SPAN so descendants can see it as an ancestor.
        let name_span = node
            .message_loc()
            .map(|l| (l.start_offset(), l.end_offset()))
            .unwrap_or((node_off, node_off));
        self.call_stack.push(name_span);
        let track_args = self.eng.debugger_on;
        // Lint/UselessTimes: a safe-navigation call's receiver/args don't
        // count as "parent is :send" (whitequark's `:csend` != `:send`).
        let ut_track = !node.is_safe_navigation() && self.on("Lint/UselessTimes");
        // Layout/Multiline{Array,Hash,MethodCall}BraceLayout: `chained?`
        // (receiver of ANY call, safe-nav included) / `argument?` (positional
        // argument of a non-safe-nav call only) — see `mlbl_call_child`. The
        // method-call cop additionally needs this to know whether the CALL
        // NODE ITSELF (checked via `check_multiline_method_call_brace_layout`
        // below) is chained onto / an argument of an outer call.
        let mlbl_track = self.on("Layout/MultilineArrayBraceLayout")
            || self.on("Layout/MultilineHashBraceLayout")
            || self.on("Layout/MultilineMethodCallBraceLayout");
        // Layout/ClosingHeredocIndentation: this call's own climbed-chain
        // root — inherited from an enclosing call that already claimed THIS
        // call as its receiver/argument, or (the common case) itself when
        // there is no such enclosing call. `None` when the cop is off.
        let chi_root = self
            .on("Layout/ClosingHeredocIndentation")
            .then(|| self.chi_call_root.get(&node_off).copied().unwrap_or(node_off));
        // Lint/ImplicitStringConcatenation: same `parent&.send_type?` guard as
        // `ut_track` — see `isc_send_child`.
        let isc_track = !node.is_safe_navigation() && self.on("Lint/ImplicitStringConcatenation");
        // Style/Alias's `alias_method_value_used?`: `node.argument?` — same
        // `parent&.send_type?` (non-safe-nav) guard as `isc_track` above.
        let alias_track = !node.is_safe_navigation() && self.on("Style/Alias");
        // Style/MultilineTernaryOperator: a ternary that's this call's
        // receiver or (positional) argument has a `:send`/`:csend` parent —
        // `SINGLE_LINE_TYPES`, unless the call itself is an assignment method
        // (`foo=`, `[]=`, but not a comparison operator like `==`).
        let mto_name = node.name();
        let mto_is_assign_method = mto_name.as_slice().ends_with(b"=")
            && !matches!(mto_name.as_slice(), b"==" | b"===" | b"!=" | b"<=" | b">=");
        let mto_call_start = node.location().start_offset();
        // Layout/HeredocIndentation's `heredoc_squish?`: `squish_method?`
        // needs `active_support_extensions_enabled?` too, and only a plain
        // `send` (not `&.`) with no arguments matches `(send _ {:squish
        // :squish!})`.
        let hi_squish_track = !node.is_safe_navigation()
            && node.arguments().is_none()
            && self.hot.active_support
            && matches!(node.name().as_slice(), b"squish" | b"squish!")
            && self.on("Layout/HeredocIndentation");
        if let Some(r) = node.receiver() {
            if hi_squish_track {
                if let Some(hoff) = layout::chi_heredoc_offset(&r) {
                    self.squish_heredoc.insert(hoff);
                }
            }
            if track_args {
                self.assumed_arg_offsets.insert(r.location().start_offset());
            }
            if ut_track {
                self.ut_call_child.insert(r.location().start_offset());
            }
            self.mto_note_child(&r, mto_call_start, !mto_is_assign_method);
            if mlbl_track {
                self.mlbl_call_child.insert(r.location().start_offset());
            }
            // Layout/MultilineMethodCallBraceLayout's
            // `use_heredoc_argument_method_chain?`: THIS call (`node`) must
            // have an actual dot (`X.foo`/`X&.foo` — a synthetic operator
            // call like `X + 1` has no `call_operator_loc` and can't be a
            // dot-chain at all), and the RECEIVER `r` must itself be a call
            // whose first positional argument is a plain (non-interpolated)
            // heredoc-opened string.
            if self.on("Layout/MultilineMethodCallBraceLayout") {
                if let (Some(rc), Some(dot)) = (r.as_call_node(), node.call_operator_loc()) {
                    let heredoc_first_arg = rc
                        .arguments()
                        .and_then(|a| a.arguments().iter().next())
                        .and_then(|first| first.as_string_node())
                        .is_some_and(|s| {
                            s.opening_loc().is_some_and(|o| o.as_slice().starts_with(b"<<"))
                        });
                    if heredoc_first_arg {
                        self.mmcbl_heredoc_chain.insert(
                            r.location().start_offset(),
                            (dot.start_offset(), node.location().end_offset()),
                        );
                    }
                }
            }
            if let Some(root) = chi_root {
                // `chained?`: heredoc-as-receiver counts regardless of THIS
                // call's own safe-navigation (`parent.call_type?` is true for
                // both `send` and `csend`); climbing PAST a further-nested
                // call in receiver position still requires plain `send`.
                if let Some(hoff) = layout::chi_heredoc_offset(&r) {
                    self.chi_heredoc_ctx.insert(hoff, (root, false));
                } else if !node.is_safe_navigation() && r.as_call_node().is_some() {
                    self.chi_call_root.insert(r.location().start_offset(), root);
                }
            }
            if isc_track {
                self.isc_send_child.insert(r.location().start_offset());
            }
            self.visit(&r);
        }
        if self.hot.semicolon {
            if let (Some(a), Some(sel)) = (node.arguments(), node.message_loc()) {
                if let Some(kw) = a.arguments().iter().last().and_then(|x| x.as_keyword_hash_node()) {
                    let omission = kw.elements().iter().any(|e| {
                        e.as_assoc_node().is_some_and(|p| p.value().as_implicit_node().is_some())
                    });
                    if omission {
                        let kl = kw.location();
                        self.vo_kwargs.push((kl.start_offset(), kl.end_offset(), sel.end_offset()));
                    }
                }
            }
        }
        if let Some(a) = node.arguments() {
            // Style/EmptyLiteral's Hash fix needs the enclosing bare arg list
            let framed = node.opening_loc().is_none() && self.hot.empty_literal;
            if framed {
                let spans: Vec<(usize, usize)> = a
                    .arguments()
                    .iter()
                    .map(|x| (x.location().start_offset(), x.location().end_offset()))
                    .collect();
                let first = spans.first().map(|(s, _)| *s).unwrap_or(0);
                self.bare_arg_frames.push((first, spans));
            }
            // Lint/RedundantSplatExpansion's `method_argument?`: a splat that
            // is a direct positional argument — prism attaches no wrapper
            // node here (same flat shape as upstream's translated tree), so
            // the splat's real parent IS this `CallNode` (receiver chain and
            // all — safe-navigation included, matching upstream's
            // `call_type?` covering both `send` and `csend`).
            let rse_track = self.on("Lint/RedundantSplatExpansion");
            let rse_call_range = node.location();
            for arg in a.arguments().iter() {
                if track_args {
                    self.assumed_arg_offsets.insert(arg.location().start_offset());
                }
                if ut_track {
                    self.ut_call_child.insert(arg.location().start_offset());
                }
                if rse_track && arg.as_splat_node().is_some() {
                    self.rse_ctx.insert(
                        arg.location().start_offset(),
                        lint_cops::RseCtx {
                            container: lint_cops::RseContainer::CallArg,
                            container_start: rse_call_range.start_offset(),
                            container_end: rse_call_range.end_offset(),
                            array_len: 0,
                        },
                    );
                }
                if mlbl_track && !node.is_safe_navigation() {
                    self.mlbl_call_child.insert(arg.location().start_offset());
                }
                // `argument?`: requires THIS call to be plain `send` (not
                // `csend`) — a safe-nav call's arguments are never
                // `argument?` true, and climbing never passes through one.
                if let (Some(root), false) = (chi_root, node.is_safe_navigation()) {
                    if let Some(hoff) = layout::chi_heredoc_offset(&arg) {
                        self.chi_heredoc_ctx.insert(hoff, (root, true));
                    } else if arg.as_call_node().is_some() {
                        self.chi_call_root.insert(arg.location().start_offset(), root);
                    }
                }
                if isc_track {
                    self.isc_send_child.insert(arg.location().start_offset());
                }
                if alias_track {
                    self.alias_arg_offsets.insert(arg.location().start_offset());
                }
                self.mto_note_child(&arg, mto_call_start, !mto_is_assign_method);
                self.visit(&arg);
            }
            if framed {
                self.bare_arg_frames.pop();
            }
        }
        // Lint/OutOfRangeRegexpRef's `after_send`/`after_csend`: fires after
        // the receiver and arguments are visited but BEFORE any attached
        // block — see that function's doc comment for why this exact spot
        // matters (mirrors whitequark's node shape, where a block's body is
        // never a child of the `:send` node itself).
        self.check_out_of_range_regexp_ref_after_send(node);
        if let Some(b) = node.block() {
            if let Some(bn) = b.as_block_node() {
                self.check_empty_block_parameter(&bn);
                self.check_block_parameter_name(&bn);
                self.check_empty_lines_around_block_body(&bn);
                self.check_metrics_complexity_define_method(node, &bn);
                self.check_method_length_block(node, &bn);
                self.check_empty_lines_around_exception_handling_keywords_block(node, &bn);
                self.check_block_length(node, &bn);
                self.check_next_block(node, &bn);
                self.check_guard_clause_block(node, &bn);
                self.check_useless_access_modifier_block(node, &bn);
            }
            // Lint/NonLocalExitFromIterator: stash this call's shape
            // (`send_node.method?(:lambda)`, `define_method?`,
            // `chained_send?`) for the `visit_block_node` call
            // `self.visit(&b)` triggers below — see the `nle_pending` field
            // doc. Left `None` for `&:sym` block-pass args, which never
            // trigger `visit_block_node`.
            if b.as_block_node().is_some() {
                // Lint/Void: see `void_pending_block_name`'s field doc.
                self.void_pending_block_name = Some(node.name().as_slice().to_vec());
                let is_lambda_call = node.name().as_slice() == b"lambda";
                let is_define_method =
                    matches!(node.name().as_slice(), b"define_method" | b"define_singleton_method")
                        && node.arguments().is_some_and(|a| a.arguments().iter().count() == 1);
                self.nle_pending = Some((is_lambda_call, node.receiver().is_some(), is_define_method));
                // Naming/MemoizedInstanceVariableName: this call's dynamic-
                // define method-name argument, if it qualifies — see the
                // `mivn_pending_method_name` field doc.
                self.mivn_pending_method_name = Some(naming::mivn_dynamic_define_name(node));
                // Style/DoubleNegation: `define_method?(parent)` (no arg-count
                // restriction, unlike `is_define_method` above — this cop's
                // own upstream check is just `child.method?(:define_method)
                // || child.method?(:define_singleton_method)`) — see the
                // `dn_pending_define_method` field doc.
                self.dn_pending_define_method = if matches!(
                    node.name().as_slice(),
                    b"define_method" | b"define_singleton_method"
                ) {
                    Some(self.dn_compute_call_last_child(node))
                } else {
                    None
                };
                // Lint/MissingSuper: this block's `class_new_block` verdict —
                // see the `ms_pending_block` field doc.
                self.ms_pending_block = self.ms_class_new_pending(node);
                // Style/ExplicitBlockArgument: this call's own shape — see
                // the `eba_pending` field doc.
                self.eba_pending = Some(style::eba_call_owner(node));
                // Style/Alias's `scope_type`: `parent.method?(:instance_eval)`
                // for the block we're about to descend into.
                self.alias_pending_instance_eval = Some(node.name().as_slice() == b"instance_eval");
            }
            // Consumed by the `visit_block_node` call this triggers below
            // (`&:sym` block-pass args aren't block nodes, so this is false
            // whenever `b` isn't one — no visit_block_node ever fires for it).
            self.el_am_ctor_block = b.as_block_node().is_some() && lint_cops::is_class_constructor(node, self.src);
            self.metrics_ctor_block = b.as_block_node().is_some() && lint_cops::is_struct_data_constructor(node, self.src);
            self.check_multiline_block_chain(node);
            self.check_redundant_fetch_block(node);
            self.check_empty_block_call(node);
            // A block is "scoping" (allows nested defs) if it's a class
            // constructor, an (instance|class|module)_(eval|exec), or its method
            // is in AllowedMethods.
            let scoping = self.hot.nested_method_definition
                && (lint_cops::is_eval_exec(node)
                    || lint_cops::is_class_constructor(node, self.src)
                    || self.allowed("Lint/NestedMethodDefinition", node.name().as_slice()));
            if scoping {
                self.scoping_depth += 1;
            }
            // Lint/UnreachableCode: `on_block`/`after_block` around any
            // `instance_eval` block (numbered/`it`/ordinary params all
            // collapse to one prism `BlockNode`) — inside it, a bare
            // redefinable-flow call's `self` is unknown.
            let uc_instance_eval = self.on("Lint/UnreachableCode")
                && node.name().as_slice() == b"instance_eval"
                && b.as_block_node().is_some();
            if uc_instance_eval {
                self.uc_instance_eval_depth += 1;
            }
            self.usage_block_depth += 1;
            self.visit(&b);
            self.usage_block_depth -= 1;
            if uc_instance_eval {
                self.uc_instance_eval_depth -= 1;
            }
            if scoping {
                self.scoping_depth -= 1;
            }
        }
        self.call_stack.pop();
        self.ll_exit_collection();
    }
    fn visit_splat_node(&mut self, node: &ruby_prism::SplatNode<'pr>) {
        self.check_redundant_splat_expansion(node);
        ruby_prism::visit_splat_node(self, node);
    }
    fn visit_yield_node(&mut self, node: &ruby_prism::YieldNode<'pr>) {
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"yield");
        self.hs_register_dispatch(
            node.location().start_offset(),
            Some(kw.end_offset()),
            node.rparen_loc().is_some(),
            false,
            false,
            None,
            node.arguments().as_ref(),
        );
        ruby_prism::visit_yield_node(self, node);
    }
    fn visit_defined_node(&mut self, node: &ruby_prism::DefinedNode<'pr>) {
        let kw = node.keyword_loc();
        self.sak_check(kw.start_offset(), kw.end_offset(), b"defined?");
        ruby_prism::visit_defined_node(self, node);
    }
    // Layout/SpaceAroundKeyword's `preceded_by_operator?` needs a real
    // ancestor chain, which prism doesn't provide (no parent pointers).
    // `visit()`'s generated dispatcher (see the `Visit` trait) calls these
    // around EVERY node — branch or leaf — regardless of which concrete
    // `visit_xxx_node` override (if any) handles it, so this is the one hook
    // guaranteed to see every ancestor level. See `Cops::sak_classify` /
    // `Cops::sak_preceded_by_operator` in layout.rs.
    fn visit_branch_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.sak_ancestors.push(Self::sak_classify(&node));
    }
    fn visit_branch_node_leave(&mut self) {
        self.sak_ancestors.pop();
    }
    fn visit_leaf_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.sak_ancestors.push(Self::sak_classify(&node));
    }
    fn visit_leaf_node_leave(&mut self) {
        self.sak_ancestors.pop();
    }
}

/// Lint one file: run the text-based cops and the AST visitor, return sorted
/// offenses + autocorrect edits. Pure — no I/O; the caller owns file reading,
/// config discovery, and output formatting.
pub fn lint(src: &[u8], cfg: &Config, eng: &Engine, rel_path: &str) -> LintResult {
    let t0 = std::time::Instant::now();
    let result = ruby_prism::parse(src);
    let t = tick(&T_PARSE, t0);
    let idx = LineIndex::new(src);

    let mut comment_lines = HashSet::new();
    // Every comment as (line, start, end) spans — the "comment tokens"
    // FrozenStringLiteralComment reasons about. No text copies.
    let mut comment_data: Vec<(usize, usize, usize)> = Vec::new();
    for c in result.comments() {
        let l = c.location();
        let line = idx.loc(l.start_offset()).0;
        comment_lines.insert(line);
        comment_data.push((line, l.start_offset(), l.end_offset()));
    }
    // The line of the first real code token — comments before it are the
    // "leading comment lines" magic comments live in (rubocop's mixin).
    let first_code_line = result
        .node()
        .as_program_node()
        .and_then(|p| p.statements().body().iter().next().map(|n| idx.loc(n.location().start_offset()).0));

    // The file-level frozen_string_literal magic comment (leading comments).
    let fsl_enabled = comment_data
        .iter()
        .take_while(|(line, _, _)| first_code_line.is_none_or(|fc| *line < fc))
        .find_map(|(_, s, e)| crate::cops::style::fsl_value(&String::from_utf8_lossy(&src[*s..*e])))
        .map(|v| v == "true");

    // Heredoc body line ranges, for Layout/TrailingWhitespace; multi-line
    // plain strings ride along (Layout/EmptyLines treats them as tokens).
    let mut hd = HeredocFinder { idx: &idx, ranges: Vec::new(), str_lines: Vec::new(), lit_spans: Vec::new() };
    hd.visit(&result.node());
    let heredoc_lines = hd.ranges;
    let multiline_str_lines = hd.str_lines;
    let mut lit_spans = hd.lit_spans;
    lit_spans.sort_unstable();

    let (hot, file_disabled) = eng.file_view(rel_path);
    let mut cops = Cops {
        src,
        idx: &idx,
        cfg,
        hot,
        file_disabled,
        comment_lines,
        offenses: Vec::new(),
        fixes: Vec::new(),
        eng,
        call_stack: Vec::new(),
        def_depth: 0,
        scoping_depth: 0,
        def_name_stack: Vec::new(),
        interp_depth: 0,
        xstr_interp_base: Vec::new(),
        str_ignore: Vec::new(),
        num_ignore: Vec::new(),
        percent_sym_spans: Vec::new(),
        percent_arr_spans: Vec::new(),
        wa_matrix_stack: Vec::new(),
        pa_invalid_ctx: HashSet::new(),
        rl_call_child: HashSet::new(),
        lambda_unparen_arg: HashSet::new(),
        dirname_ignore: Vec::new(),
        stmts_stack: Vec::new(),
        unless_else_spans: Vec::new(),
        one_line_cond_spans: Vec::new(),
        if_inside_else_ignored: Vec::new(),
        if_semicolon_spans: Vec::new(),
        if_semicolon_suppressed: HashSet::new(),
        ll_active: false,
        ll_max: 0,
        ll_split: false,
        ll_long: Vec::new(),
        ll_break: std::collections::HashMap::new(),
        ll_semi: std::collections::HashMap::new(),
        ll_block: std::collections::HashMap::new(),
        ll_coll_stack: Vec::new(),
        ll_str_skip: HashSet::new(),
        ll_dstr_delim: Vec::new(),
        requires_seen: HashSet::new(),
        usage_block_depth: 0,
        assumed_arg_offsets: HashSet::new(),
        heredoc_lines,
        multiline_str_lines,
        fsl_enabled,
        lit_spans,
        semi_flagged: HashSet::new(),
        range_spans: Vec::new(),
        vo_kwargs: Vec::new(),
        bare_arg_frames: Vec::new(),
        data_line: result.data_loc().map(|l| idx.loc(l.start_offset()).0),
        class_children_stack: Vec::new(),
        exception_siblings_stack: Vec::new(),
        respond_to_missing_stack: Vec::new(),
        comments: &comment_data,
        mod_stack: Vec::new(),
        nodoc_all_stack: Vec::new(),
        cond_depth: 0,
        andor_or_parent_and: HashSet::new(),
        regexp_bang_ignore: Vec::new(),
        multiline_if_mod_seen: HashSet::new(),
        nested_ternary_reported: HashSet::new(),
        mto_parent_start: HashMap::new(),
        mto_single_line: HashSet::new(),
        icb_assign_start: HashMap::new(),
        gc_assignment_value_starts: HashSet::new(),
        mto_fixed_ranges: Vec::new(),
        nested_modifier_ignored: Vec::new(),
        snc_ignored: Vec::new(),
        assignment_leftmost: HashMap::new(),
        block_owns_next_stmts: false,
        rel_path,
        uc_redefined: HashSet::new(),
        uc_instance_eval_depth: 0,
        style_attr_custom_method_stack: Vec::new(),
        el_offended: HashSet::new(),
        else_layout_seen: HashSet::new(),
        top_level_sole_stmt: None,
        sgv_required_english: false,
        sgv_top_stmts: Vec::new(),
        sgv_in_embedded_var: false,
        sgv_brace_eligible: false,
        sgv_climb: HashMap::new(),
        rse_ctx: HashMap::new(),
        rse_assignment_value: HashSet::new(),
        dn_ancestors: Vec::new(),
        dn_return_arg_offsets: HashSet::new(),
        dn_pending_define_method: None,
        nx_reindented: HashMap::new(),
        mc_nested_or: HashSet::new(),
        lac_ignored: Vec::new(),
        void_each_stack: Vec::new(),
        void_pending_block_name: None,
        void_pending_ctx: None,
        hs_call_ctx: HashMap::new(),
        hs_call_like_ctx: HashSet::new(),
        hs_assign_parent: HashMap::new(),
        hs_stmt_next: HashSet::new(),
        hs_paren_parent: HashSet::new(),
        hs_modifier_depth: 0,
        hs_pair_ctx: HashMap::new(),
        hs_wrapped_return: HashSet::new(),
        def_macro_args: HashSet::new(),
        sad_chain_receivers: HashSet::new(),
        sc_handled: HashSet::new(),
        rs_scope_stack: Vec::new(),
        rs_narrow: Vec::new(),
        rs_block_stack: Vec::new(),
        mcwap_assign_stack: Vec::new(),
        mcwap_optarg_default: HashSet::new(),
        nle_stack: Vec::new(),
        nle_pending: None,
        mivn_pending_method_name: None,
        ut_call_child: HashSet::new(),
        ecc_no_offense: HashSet::new(),
        el_am_scope: Vec::new(),
        el_am_class_first_line: None,
        el_am_class_last_line: None,
        el_am_block_line: None,
        el_am_block_owns_next_stmts: false,
        el_am_ctor_block: false,
        metrics_ctor_block: false,
        metrics_in_struct_data_define_block: Vec::new(),
        gss_gvasgn_skip: HashSet::new(),
        rvgu_write_target_skip: HashSet::new(),
        grrv_seen: false,
        mlbl_call_child: HashSet::new(),
        dea_ignored: HashSet::new(),
        dea_parent: HashMap::new(),
        chi_call_root: HashMap::new(),
        chi_heredoc_ctx: HashMap::new(),
        squish_heredoc: HashSet::new(),
        isc_array_child: HashSet::new(),
        isc_send_child: HashSet::new(),
        alias_scope_stack: Vec::new(),
        alias_cm_stack: Vec::new(),
        ta_barrier: Vec::new(),
        ta_call_arg_defs: HashSet::new(),
        alias_def_depth: 0,
        alias_pending_instance_eval: None,
        alias_arg_offsets: HashSet::new(),
        alias_value_offsets: HashSet::new(),
        ri_concat_child: HashSet::new(),
        ri_percent_array_child: HashSet::new(),
        interpolated_node_depth: 0,
        class_module_depth: 0,
        cl_class_depth: 0,
        non_nil_ignored: HashSet::new(),
        mmcbl_heredoc_chain: HashMap::new(),
        se_ancestor_end_lines: Vec::new(),
        redundant_sort_logical_left: HashMap::new(),
        ra_needs_parens: HashSet::new(),
        pattern_depth: 0,
        renv_resbody_depth: 0,
        renv_pending_kwbegin_stack: Vec::new(),
        renv_just_closed_kwbegin_renames: Vec::new(),
        il_no_offense: HashSet::new(),
        rrs_modifier_end: None,
        pp_sig_ok: HashSet::new(),
        ms_scope_depth: 0,
        ms_class_stack: Vec::new(),
        ms_block_stack: Vec::new(),
        ms_pending_block: None,
        sak_ancestors: Vec::new(),
        sak_end_seen: HashSet::new(),
        eba_pending: None,
        eba_def_stack: Vec::new(),
        eba_def_fixed: HashSet::new(),
        rescue_mod_parens: HashMap::new(),
        snc_offended: HashSet::new(),
        snav_parent: HashMap::new(),
        aa_masgn_rhs: HashSet::new(),
        aa_unbracketed_rhs_parent: HashMap::new(),
        aa_registered_ranges: Vec::new(),
        oorr_valid_ref: Some(0),
        sigex_ignored: HashSet::new(),
        sigex_custom_fail_defined: false,
    };

    let t = tick(&T_PREP, t);

    // ---- text-based cops ----
    let first_code_off = result
        .node()
        .as_program_node()
        .and_then(|p| p.statements().body().iter().next().map(|n| n.location().start_offset()));
    cops.check_gem_filename();
    cops.check_file_name(&result.node());
    cops.check_frozen_string_literal(first_code_line);
    cops.check_empty_line_after_magic_comment(first_code_line);
    cops.check_duplicate_magic_comment(first_code_line);
    cops.check_ordered_magic_comments(first_code_line);
    cops.check_encoding();
    cops.check_empty_lines();
    cops.check_trailing_whitespace();
    cops.check_empty_file();
    cops.check_trailing_empty_lines();
    cops.check_initial_indentation(first_code_off);
    cops.check_leading_empty_lines(first_code_off);
    cops.check_indentation_style();
    let t = tick(&T_TEXT, t);

    // ---- AST-based cops ----
    cops.ll_prepare();
    if cops.on("Style/InfiniteLoop") {
        cops.il_no_offense = style::infinite_loop_skips(&result.node());
    }
    cops.visit(&result.node());
    // Gemspec/OrderedDependencies: a whole-file scan (collect every
    // `add_dependency`-family call, then compare consecutive pairs) rather
    // than a per-node hook — see gemspec.rs's doc comment.
    cops.check_ordered_dependencies(&result.node());
    // Bundler/OrderedGems: same whole-file-scan shape (see gemspec.rs's
    // check_ordered_dependencies doc comment) — collect every `gem 'name'`
    // declaration, then compare consecutive pairs.
    cops.check_ordered_gems(&result.node());
    // needs the breakable nominations the walk collected
    cops.check_line_length();
    cops.check_semicolon_lines();
    cops.check_space_after_comma();
    cops.check_space_before_semicolon();
    cops.check_space_before_comma();
    cops.check_space_before_comment();
    cops.check_leading_comment_space();
    cops.check_comment_indentation();
    cops.check_empty_comment();
    cops.check_block_comments();
    cops.check_comment_annotation();
    // Lint/AmbiguousRegexpLiteral: rides prism's own lex-level
    // PM_WARN_AMBIGUOUS_SLASH warnings (result.warnings()), not a specific
    // node type — there's no single visit_* hook to attach this to.
    cops.check_ambiguous_regexp_literal(&result);
    cops.check_ambiguous_operator(&result);
    cops.check_end_of_line();
    cops.check_space_after_semicolon();
    cops.check_double_cop_disable_directive();
    cops.check_missing_cop_enable_directive();
    cops.check_redundant_cop_enable_directive();
    cops.check_commented_keyword();
    cops.check_duplicated_assignment(&result.node());
    let t = tick(&T_VISIT, t);

    let mut offenses = cops.offenses;
    apply_disable_directives(&mut offenses, &comment_data, src, &idx);
    offenses.sort_by(|a, b| (a.line, a.col, a.cop).cmp(&(b.line, b.col, b.cop)));
    tick(&T_POST, t);
    LintResult { offenses, fixes: cops.fixes }
}

/// Collects the inclusive line ranges of heredoc bodies (terminator line
/// excluded), mirroring rubocop's `extract_heredocs`.
struct HeredocFinder<'a> {
    idx: &'a LineIndex,
    ranges: Vec<(usize, usize, Vec<u8>, bool)>,
    // multi-line NON-heredoc string spans (start line, end line)
    str_lines: Vec<(usize, usize)>,
    // every literal CONTENT byte span (string/regex/symbol text) — semicolons
    // inside are data, not statement separators
    lit_spans: Vec<(usize, usize)>,
}
impl<'a> HeredocFinder<'a> {
    fn add_span(&mut self, start: usize, end: usize, closing: Option<ruby_prism::Location>, stat: bool) {
        let delim: Vec<u8> = closing
            .map(|c| {
                c.as_slice()
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect()
            })
            .unwrap_or_default();
        if start < end {
            self.ranges.push((self.idx.loc(start).0, self.idx.loc(end - 1).0, delim, stat));
        }
    }
}
impl<'a> HeredocFinder<'a> {
    fn note_multiline(&mut self, l: ruby_prism::Location) {
        let (s, e) = (self.idx.loc(l.start_offset()).0, self.idx.loc(l.end_offset().saturating_sub(1)).0);
        if e > s {
            self.str_lines.push((s, e));
        }
    }
}
impl<'pr, 'a> Visit<'pr> for HeredocFinder<'a> {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        // delimiters included: `%q;...;` uses `;` as its fence, and token-
        // aware text cops must not read fences as punctuation. A heredoc's
        // location() is just its opener — the body is content_loc.
        match node.opening_loc() {
            Some(o) if !o.as_slice().starts_with(b"<<") => {
                let l = node.location();
                self.lit_spans.push((l.start_offset(), l.end_offset()));
            }
            _ => {
                let c = node.content_loc();
                self.lit_spans.push((c.start_offset(), c.end_offset()));
            }
        }
        if let Some(o) = node.opening_loc() {
            if o.as_slice().starts_with(b"<<") {
                let stat = o.as_slice().contains(&b'\'');
                let c = node.content_loc();
                self.add_span(c.start_offset(), c.end_offset(), node.closing_loc(), stat);
            } else {
                self.note_multiline(node.location());
            }
        }
    }
    fn visit_symbol_node(&mut self, node: &ruby_prism::SymbolNode<'pr>) {
        let l = node.location();
        self.lit_spans.push((l.start_offset(), l.end_offset()));
    }
    fn visit_regular_expression_node(&mut self, node: &ruby_prism::RegularExpressionNode<'pr>) {
        let l = node.location();
        self.lit_spans.push((l.start_offset(), l.end_offset()));
    }
    fn visit_x_string_node(&mut self, node: &ruby_prism::XStringNode<'pr>) {
        let l = node.location();
        self.lit_spans.push((l.start_offset(), l.end_offset()));
        let c = node.content_loc();
        self.lit_spans.push((c.start_offset(), c.end_offset()));
        if node.opening_loc().as_slice().starts_with(b"<<") {
            let c = node.content_loc();
            self.add_span(c.start_offset(), c.end_offset(), Some(node.closing_loc()), false);
        }
    }
    fn visit_interpolated_regular_expression_node(&mut self, node: &ruby_prism::InterpolatedRegularExpressionNode<'pr>) {
        let o = node.opening_loc();
        self.lit_spans.push((o.start_offset(), o.end_offset()));
        let c = node.closing_loc();
        self.lit_spans.push((c.start_offset(), c.end_offset()));
        ruby_prism::visit_interpolated_regular_expression_node(self, node);
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        if let Some(o) = node.opening_loc() {
            if !o.as_slice().starts_with(b"<<") {
                self.lit_spans.push((o.start_offset(), o.end_offset()));
                if let Some(cl) = node.closing_loc() {
                    self.lit_spans.push((cl.start_offset(), cl.end_offset()));
                }
            }
        }
        // prism represents MULTI-LINE heredocs as interpolated containers even
        // when they're pure text — the single-quote form is still static.
        if let Some(o) = node.opening_loc() {
            if o.as_slice().starts_with(b"<<") {
                let stat = o.as_slice().contains(&b'\'');
                if let (Some(first), Some(close)) = (node.parts().iter().next(), node.closing_loc()) {
                    self.add_span(first.location().start_offset(), close.start_offset(), node.closing_loc(), stat);
                }
            } else {
                self.note_multiline(node.location());
            }
        }
        // keep walking — interpolations can nest further heredocs
        ruby_prism::visit_interpolated_string_node(self, node);
    }
}

/// Honor `# rubocop:disable Cop[, Cop…]` / `rubocop:todo` / `rubocop:enable`
/// comments: a trailing directive covers its own line; a standalone one opens
/// a range until the matching `enable` (inclusive) or EOF. `all` and bare
/// department names (`Style`) are supported.
fn apply_disable_directives(
    offenses: &mut Vec<Offense>,
    comments: &[(usize, usize, usize)],
    src: &[u8],
    idx: &LineIndex,
) {
    let re = {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^#\s*rubocop\s*:\s*(disable|todo|enable)\s+(\S.*?)\s*$").unwrap())
    };
    // (cops: None = all, from, to)
    let mut ranges: Vec<(Option<Vec<String>>, usize, usize)> = Vec::new();
    let mut open: Vec<(Option<Vec<String>>, usize)> = Vec::new();
    let eof = idx.starts.len();
    for (line, off, end) in comments {
        let t = String::from_utf8_lossy(&src[*off..*end]);
        let Some(c) = re.captures(&t) else { continue };
        // a ` -- reason` trailer is a comment, not part of the cop list
        let cops_part = c[2].split(" -- ").next().unwrap_or(&c[2]).trim();
        let list: Option<Vec<String>> = if cops_part == "all" {
            None
        } else {
            Some(cops_part.split(',').map(|s| s.trim().to_string()).collect())
        };
        let standalone = src[idx.starts[line - 1]..*off].iter().all(|b| b.is_ascii_whitespace());
        match &c[1] {
            "enable" => {
                // Close every open range this enable covers.
                let mut i = 0;
                while i < open.len() {
                    let covered = match (&list, &open[i].0) {
                        (None, _) => true,
                        (Some(en), None) => en.iter().any(|e| e == "all"),
                        (Some(en), Some(dis)) => dis.iter().all(|d| en.contains(d)),
                    };
                    if covered {
                        let (cops_list, from) = open.remove(i);
                        ranges.push((cops_list, from, *line));
                    } else {
                        i += 1;
                    }
                }
            }
            _ => {
                // disable | todo
                if standalone {
                    open.push((list, *line));
                } else {
                    ranges.push((list, *line, *line));
                }
            }
        }
    }
    for (list, from) in open {
        ranges.push((list, from, eof));
    }
    if ranges.is_empty() {
        return;
    }
    let covers = |entry: &str, cop: &str| entry == cop || cop.starts_with(&format!("{entry}/"));
    offenses.retain(|o| {
        !ranges.iter().any(|(cops_list, from, to)| {
            o.line >= *from
                && o.line <= *to
                && cops_list.as_ref().is_none_or(|cs| cs.iter().any(|c| covers(c, o.cop)))
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offenses(src: &str, cfg: &str) -> Vec<(usize, usize, &'static str)> {
        let cfg = Config::parse(cfg);
        let eng = Engine::new(&cfg);
        lint(src.as_bytes(), &cfg, &eng, "test.rb")
            .offenses
            .iter()
            .map(|o| (o.line, o.col, o.cop))
            .collect()
    }

    const NUMERIC_ONLY: &str =
        "AllCops:\n  DisabledByDefault: true\nStyle/NumericLiterals:\n  Enabled: true\n";

    // Regression: manual recursion used to visit only `body`, silently skipping
    // parameter default values, superclass expressions, and lambda parameters.
    #[test]
    fn visits_def_parameter_defaults() {
        let got = offenses("def f(x = 1000000)\n  x\nend\n", NUMERIC_ONLY);
        assert_eq!(got, vec![(1, 11, "Style/NumericLiterals")]);
    }

    #[test]
    fn visits_class_superclass_expression() {
        let got = offenses("class Foo < Bar.make(2000000)\nend\n", NUMERIC_ONLY);
        assert_eq!(got, vec![(1, 22, "Style/NumericLiterals")]);
    }

    #[test]
    fn visits_lambda_parameter_defaults() {
        let got = offenses("f = ->(x = 1000000) { x }\n", NUMERIC_ONLY);
        assert_eq!(got, vec![(1, 12, "Style/NumericLiterals")]);
    }

    // Found linting rubocop's own source: `map { |a| a&.name }` must NOT
    // suggest `&:name` (safe navigation differs from a plain call on nil).
    #[test]
    fn symbol_proc_rejects_safe_navigation() {
        let cfg = "AllCops:\n  DisabledByDefault: true\nStyle/SymbolProc:\n  Enabled: true\n";
        assert_eq!(offenses("x.map { |a| a&.name }\n", cfg), vec![]);
        assert_eq!(offenses("x.map { |a| a.name }\n", cfg), vec![(1, 7, "Style/SymbolProc")]);
    }

    // Lint/RandOne's spec is entirely parameterized shared_examples (the
    // oracle skips it); these are its it_behaves_like cases verbatim.
    #[test]
    fn rand_one_cases() {
        let cfg = "AllCops:\n  DisabledByDefault: true\nLint/RandOne:\n  Enabled: true\n";
        for src in ["rand 1\n", "rand(-1)\n", "rand(1.0)\n", "rand(-1.0)\n",
                    "Kernel.rand(1)\n", "Kernel.rand 1.0\n", "::Kernel.rand(-1.0)\n"] {
            assert_eq!(offenses(src, cfg).len(), 1, "expected offense for {src:?}");
        }
        for src in ["rand\n", "rand(2)\n", "rand(-1..1)\n", "Kernel.rand 2\n",
                    "::Kernel.rand\n", "x.rand(1)\n"] {
            assert_eq!(offenses(src, cfg), vec![], "expected clean for {src:?}");
        }
    }

    // nodepattern extensions: const/cbase scopes, `...` rest-args, csend.
    #[test]
    fn zero_length_non_polymorphic_guard_and_csend() {
        let cfg = "AllCops:\n  DisabledByDefault: true\nStyle/ZeroLengthPredicate:\n  Enabled: true\n";
        assert_eq!(offenses("File.stat(foo).size == 0\n", cfg), vec![]);
        assert_eq!(offenses("::File::Stat.new(foo).size.zero?\n", cfg), vec![]);
        assert_eq!(offenses("foo.size == 0\n", cfg), vec![(1, 1, "Style/ZeroLengthPredicate")]);
        // csend dispatch: zero-shapes flag, nonzero-shapes don't (on_send only)
        assert_eq!(offenses("x&.length == 0\n", cfg), vec![(1, 1, "Style/ZeroLengthPredicate")]);
        assert_eq!(offenses("x&.length > 0\n", cfg), vec![]);
    }
}
