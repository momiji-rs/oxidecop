//! The cop engine: the `Cops` visitor (shared state + cross-cutting helpers),
//! a THIN `Visit` impl that dispatches into per-department modules
//! (`style`/`naming`/`lint`/`layout`), and the `lint()` entry point.
mod breakable;
mod layout;
mod lint_cops;
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
}

/// Resolve a cop name string to its &'static form (cache deserialization).
pub fn intern_cop(name: &str) -> Option<&'static str> {
    IMPLEMENTED.iter().find(|c| **c == name).copied()
}

/// Every cop name the engine implements — enablement resolves once per run.
const IMPLEMENTED: &[&str] = &[
    "Lint/DuplicateRequire", "Naming/BinaryOperatorParameterName",
    "Naming/ClassAndModuleCamelCase", "Naming/ConstantName", "Style/MultilineIfThen",
    "Style/Not", "Style/StderrPuts", "Style/WhileUntilDo", "Style/ColonMethodCall",
    "Lint/EmptyClass", "Lint/DeprecatedClassMethods", "Layout/EmptyLineAfterMagicComment",
    "Layout/EmptyLines", "Style/EmptyLiteral", "Style/Semicolon", "Style/GlobalVars",
    "Layout/SpaceAfterComma", "Layout/SpaceBeforeSemicolon", "Layout/SpaceBeforeComma",
    "Layout/SpaceBeforeComment", "Lint/FloatOutOfRange", "Style/SymbolLiteral",
    "Lint/RescueException", "Style/WhenThen", "Lint/DuplicateHashKey",
    "Security/MarshalLoad", "Layout/SpaceAfterMethodName", "Layout/SpaceAfterSemicolon", "Layout/SpaceAfterNot", "Lint/UnifiedInteger", "Lint/FlipFlop", "Style/Proc", "Lint/DuplicateCaseCondition", "Lint/DuplicateElsifCondition", "Style/ColonMethodDefinition",
    "Layout/LeadingEmptyLines", "Style/Strip", "Lint/TopLevelReturnWithArgument", "Security/Eval", "Style/VariableInterpolation", "Lint/EachWithObjectArgument", "Style/TrailingBodyOnModule", "Lint/DuplicateRescueException", "Style/TrailingBodyOnClass", "Lint/SafeNavigationWithEmpty", "Style/RedundantCapitalW", "Lint/HashCompareByIdentity", "Lint/NextWithoutAccumulator", "Layout/SpaceAfterColon", "Lint/MultipleComparison", "Style/EmptyLambdaParameter", "Layout/SpaceInsideArrayPercentLiteral", "Style/IfUnlessModifierOfIfUnless", "Style/EmptyBlockParameter", "Lint/IdentityComparison", "Layout/SpaceInsideRangeLiteral", "Style/DoubleCopDisableDirective", "Style/ClassCheck", "Naming/BlockParameterName", "Style/ClassMethods", "Style/TrailingBodyOnMethodDefinition", "Lint/UselessElseWithoutRescue", "Lint/ReturnInVoidContext", "Style/MultilineBlockChain", "Style/OptionalArguments",
    "Style/DefWithParentheses",
    "Layout/InitialIndentation", "Layout/TrailingEmptyLines", "Lint/EmptyFile",
    "Lint/EmptyInterpolation", "Lint/EnsureReturn", "Style/BeginBlock",
    "Style/CharacterLiteral", "Style/EndBlock", "Style/NegatedWhile", "Style/UnlessElse",
    "Layout/LineLength", "Layout/TrailingWhitespace", "Lint/BigDecimalNew",
    "Lint/BooleanSymbol", "Lint/Debugger", "Lint/EmptyEnsure", "Lint/EmptyExpression",
    "Lint/NestedMethodDefinition", "Lint/RandOne", "Lint/UriEscapeUnescape",
    "Lint/UriRegexp", "Lint/UnifiedInteger", "Naming/MethodName", "Style/ArrayJoin", "Style/Dir",
    "Style/Documentation", "Style/EvenOdd", "Style/FrozenStringLiteralComment",
    "Style/NegatedIf", "Style/NestedFileDirname", "Style/NilComparison",
    "Style/NumericLiterals", "Style/NumericPredicate", "Style/RandomWithOffset",
    "Style/RedundantReturn", "Style/StringChars", "Style/StringLiterals",
    "Style/SymbolProc", "Style/UnpackFirst", "Style/ZeroLengthPredicate",
    "Lint/RegexpAsCondition",
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
        Engine {
            decl, enabled, allowed_patterns, allowed_methods, debugger_on, debugger_last, hot,
            cop_excludes, display_style_guide, style_guide_base,
        }
    }
    /// The " (https://...)" message suffix for a cop, when configured.
    pub(crate) fn style_guide_suffix(&self, cop: &str) -> Option<String> {
        if !self.display_style_guide {
            return None;
        }
        let sg = crate::config::schema(cop)?.style_guide?;
        Some(if sg.starts_with('#') {
            format!(" ({}{sg})", self.style_guide_base)
        } else {
            format!(" ({sg})")
        })
    }
    /// The hot flags for one file: the base view with per-cop Excludes for
    /// matching cops switched off. Returns the excluded non-hot cop names too.
    pub fn file_view(&self, rel_path: &str) -> (Hot, Vec<&'static str>) {
        let mut hot = self.hot.clone();
        let mut disabled = Vec::new();
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
    // Inside a `#{...}` interpolation (rubocop's `inside_interpolation?`) —
    // string-literal style is not enforced there.
    pub(crate) interp_depth: usize,
    // Node spans claimed by a multiline string-concat check (rubocop's
    // `ignore_node`): individual strings inside are exempt from on_str.
    pub(crate) str_ignore: Vec<(usize, usize)>,
    // Numeric literals already checked as part of a folded `-@` call.
    pub(crate) num_ignore: Vec<usize>,
    // Spans of `%i[...]`/`%I[...]` arrays — Lint/BooleanSymbol skips those.
    pub(crate) percent_sym_spans: Vec<(usize, usize)>,
    // Spans of ANY percent-literal array — Lint/EmptyInterpolation skips those.
    pub(crate) percent_arr_spans: Vec<(usize, usize)>,
    // Inner `File.dirname` calls claimed by an outer chain (NestedFileDirname).
    pub(crate) dirname_ignore: Vec<usize>,
    // Innermost statement-list span starts — Lint/DuplicateRequire scopes by it.
    pub(crate) stmts_stack: Vec<usize>,
    // unless/else nodes already corrected — nested ones only get offenses.
    pub(crate) unless_else_spans: Vec<(usize, usize)>,
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
    // Start offsets of MatchLastLineNode/InterpolatedMatchLastLineNode
    // literals already offended-on as the receiver of an enclosing `!`/`not`
    // call — the later direct visit of the literal skips these so it isn't
    // double-flagged (rubocop's `ignore_node`).
    pub(crate) regexp_bang_ignore: Vec<usize>,
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
    /// AllowComments guard: skip when enabled and a comment sits inside the block
    /// body (opening line through the line before the closer, so a trailing
    /// `end # comment` doesn't count).
    pub(crate) fn block_has_inner_comment(&self, open: usize, close: usize) -> bool {
        let l0 = self.idx.loc(open).0;
        let l1 = self.idx.loc(close).0;
        (l0..l1).any(|ln| self.comment_lines.contains(&ln))
    }
}

impl<'pr, 'a> Visit<'pr> for Cops<'a> {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        self.check_string_literals(node);
        self.check_character_literal(node);
        self.check_gvar_artifact(node);
        self.ll_check_str(node);
    }
    fn visit_interpolated_string_node(&mut self, node: &ruby_prism::InterpolatedStringNode<'pr>) {
        // `'a' \` line-continuation concatenation parses as this node with
        // quoted string parts — the ConsistentQuotesInMultiline check.
        self.check_string_concat(node);
        self.ll_check_dstr(node);
        let delim = node.opening_loc().and_then(|o| match o.as_slice() {
            b"'" | b"\"" => Some(o.as_slice()[0]),
            _ => None,
        });
        if let Some(d) = delim {
            self.ll_dstr_delim.push(d);
        }
        ruby_prism::visit_interpolated_string_node(self, node);
        if delim.is_some() {
            self.ll_dstr_delim.pop();
        }
    }
    fn visit_symbol_node(&mut self, node: &ruby_prism::SymbolNode<'pr>) {
        self.check_boolean_symbol(node);
        self.check_symbol_literal(node);
    }
    fn visit_hash_node(&mut self, node: &ruby_prism::HashNode<'pr>) {
        self.check_duplicate_hash_key(node);
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
        ruby_prism::visit_hash_node(self, node);
        self.ll_exit_collection();
    }
    fn visit_optional_keyword_parameter_node(&mut self, node: &ruby_prism::OptionalKeywordParameterNode<'pr>) {
        if self.ll_active {
            self.ll_str_skip.insert(node.value().location().start_offset());
        }
        self.check_space_after_colon_kwoptarg(node);
        ruby_prism::visit_optional_keyword_parameter_node(self, node);
    }
    fn visit_constant_write_node(&mut self, node: &ruby_prism::ConstantWriteNode<'pr>) {
        let v = node.value();
        self.check_constant_name(node.name().as_slice(), node.name_loc().start_offset(), Some(&v));
        ruby_prism::visit_constant_write_node(self, node);
    }
    fn visit_constant_or_write_node(&mut self, node: &ruby_prism::ConstantOrWriteNode<'pr>) {
        let v = node.value();
        self.check_constant_name(node.name().as_slice(), node.name_loc().start_offset(), Some(&v));
        ruby_prism::visit_constant_or_write_node(self, node);
    }
    fn visit_constant_target_node(&mut self, node: &ruby_prism::ConstantTargetNode<'pr>) {
        // a constant target in a multiple assignment (`A, B = 1, 2`)
        self.check_constant_name(node.name().as_slice(), node.location().start_offset(), None);
    }
    fn visit_constant_path_write_node(&mut self, node: &ruby_prism::ConstantPathWriteNode<'pr>) {
        let t = node.target();
        if let Some(name) = t.name() {
            let v = node.value();
            self.check_constant_name(name.as_slice(), t.name_loc().start_offset(), Some(&v));
        }
        ruby_prism::visit_constant_path_write_node(self, node);
    }
    fn visit_if_node(&mut self, node: &ruby_prism::IfNode<'pr>) {
        self.check_negated_if(node);
        self.check_duplicate_elsif_condition(node);
        self.check_safe_navigation_with_empty(&node.predicate());
        if let Some(kw) = node.if_keyword_loc() {
            if matches!(kw.as_slice(), b"if" | b"elsif") {
                let kw_text = if kw.as_slice() == b"elsif" { "elsif" } else { "if" };
                self.check_multiline_if_then(
                    node.then_keyword_loc(),
                    node.end_keyword_loc(),
                    node.statements().map(|s| s.location().start_offset()),
                    kw_text,
                );
            }
        }
        self.cond_depth += 1;
        ruby_prism::visit_if_node(self, node);
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
        self.check_safe_navigation_with_empty(&node.predicate());
        self.check_unless_else(node);
        self.check_multiline_if_then(
            node.then_keyword_loc(),
            node.end_keyword_loc(),
            node.statements().map(|s| s.location().start_offset()),
            "unless",
        );
        self.cond_depth += 1;
        ruby_prism::visit_unless_node(self, node);
        self.cond_depth -= 1;
        // post-order: see the if-visitor note.
        if node.end_keyword_loc().is_none() {
            self.check_if_unless_modifier_of_if_unless("unless", node.keyword_loc(), node.predicate(), node.statements());
        }
    }
    fn visit_global_variable_read_node(&mut self, node: &ruby_prism::GlobalVariableReadNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_global_variable_write_node(&mut self, node: &ruby_prism::GlobalVariableWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_write_node(self, node);
    }
    fn visit_global_variable_operator_write_node(&mut self, node: &ruby_prism::GlobalVariableOperatorWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_operator_write_node(self, node);
    }
    fn visit_global_variable_or_write_node(&mut self, node: &ruby_prism::GlobalVariableOrWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_or_write_node(self, node);
    }
    fn visit_global_variable_and_write_node(&mut self, node: &ruby_prism::GlobalVariableAndWriteNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.name_loc().start_offset());
        ruby_prism::visit_global_variable_and_write_node(self, node);
    }
    fn visit_global_variable_target_node(&mut self, node: &ruby_prism::GlobalVariableTargetNode<'pr>) {
        self.check_global_var(node.name().as_slice(), node.location().start_offset());
    }
    fn visit_case_node(&mut self, node: &ruby_prism::CaseNode<'pr>) {
        self.check_duplicate_case_condition(node);
        self.cond_depth += 1;
        ruby_prism::visit_case_node(self, node);
        self.cond_depth -= 1;
    }
    fn visit_case_match_node(&mut self, node: &ruby_prism::CaseMatchNode<'pr>) {
        self.cond_depth += 1;
        ruby_prism::visit_case_match_node(self, node);
        self.cond_depth -= 1;
    }
    fn visit_when_node(&mut self, node: &ruby_prism::WhenNode<'pr>) {
        self.check_when_then(node);
        ruby_prism::visit_when_node(self, node);
    }
    fn visit_constant_read_node(&mut self, node: &ruby_prism::ConstantReadNode<'pr>) {
        let klass = node.name().as_slice();
        if matches!(klass, b"Fixnum" | b"Bignum") {
            let l = node.location();
            self.check_unified_integer(klass, l.start_offset(), l.end_offset());
        }
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
            }
        }
        ruby_prism::visit_constant_path_node(self, node);
    }
    fn visit_return_node(&mut self, node: &ruby_prism::ReturnNode<'pr>) {
        self.check_top_level_return_with_argument(node);
        ruby_prism::visit_return_node(self, node);
    }
    fn visit_rescue_node(&mut self, node: &ruby_prism::RescueNode<'pr>) {
        self.check_rescue_exception(node);
        ruby_prism::visit_rescue_node(self, node);
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
        self.check_semicolon_separators(node);
        self.ll_check_semicolons(node);
        self.stmts_stack.push(node.location().start_offset());
        ruby_prism::visit_statements_node(self, node);
        self.stmts_stack.pop();
    }
    fn visit_while_node(&mut self, node: &ruby_prism::WhileNode<'pr>) {
        self.check_negated_while(node.predicate(), node.location().start_offset(), node.keyword_loc(), false);
        self.check_while_until_do(&node.predicate(), node.do_keyword_loc(), node.location(),
            node.statements().map(|s| s.location().start_offset()), "while");
        self.cond_depth += 1;
        ruby_prism::visit_while_node(self, node);
        self.cond_depth -= 1;
    }
    fn visit_until_node(&mut self, node: &ruby_prism::UntilNode<'pr>) {
        self.check_negated_while(node.predicate(), node.location().start_offset(), node.keyword_loc(), true);
        self.check_while_until_do(&node.predicate(), node.do_keyword_loc(), node.location(),
            node.statements().map(|s| s.location().start_offset()), "until");
        self.cond_depth += 1;
        ruby_prism::visit_until_node(self, node);
        self.cond_depth -= 1;
    }
    fn visit_pre_execution_node(&mut self, node: &ruby_prism::PreExecutionNode<'pr>) {
        if self.on("Style/BeginBlock") {
            self.push(node.keyword_loc().start_offset(), "Style/BeginBlock", false,
                "Avoid the use of `BEGIN` blocks.");
        }
        ruby_prism::visit_pre_execution_node(self, node);
    }
    fn visit_post_execution_node(&mut self, node: &ruby_prism::PostExecutionNode<'pr>) {
        if self.on("Style/EndBlock") {
            let kw = node.keyword_loc();
            self.push(kw.start_offset(), "Style/EndBlock", true,
                "Avoid the use of `END` blocks. Use `Kernel#at_exit` instead.");
            self.fixes.push((kw.start_offset(), kw.end_offset(), b"at_exit".to_vec()));
        }
        ruby_prism::visit_post_execution_node(self, node);
    }
    fn visit_begin_node(&mut self, node: &ruby_prism::BeginNode<'pr>) {
        self.check_duplicate_rescue_exception(node);
        self.check_useless_else_without_rescue(node);
        let kwbegin = node.begin_keyword_loc().is_some();
        if kwbegin {
            self.usage_block_depth += 1;
        }
        ruby_prism::visit_begin_node(self, node);
        if kwbegin {
            self.usage_block_depth -= 1;
        }
    }
    fn visit_ensure_node(&mut self, node: &ruby_prism::EnsureNode<'pr>) {
        self.check_empty_ensure(node);
        self.check_ensure_return(node);
        ruby_prism::visit_ensure_node(self, node);
    }
    fn visit_parentheses_node(&mut self, node: &ruby_prism::ParenthesesNode<'pr>) {
        self.check_empty_expression(node);
        ruby_prism::visit_parentheses_node(self, node);
    }
    fn visit_array_node(&mut self, node: &ruby_prism::ArrayNode<'pr>) {
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
            }
        }
        self.check_redundant_capital_w(node);
        self.check_space_inside_array_percent_literal(node);
        if self.eng.debugger_on {
            for e in node.elements().iter() {
                self.assumed_arg_offsets.insert(e.location().start_offset());
            }
        }
        ruby_prism::visit_array_node(self, node);
        self.ll_exit_collection();
    }
    fn visit_assoc_node(&mut self, node: &ruby_prism::AssocNode<'pr>) {
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
        ruby_prism::visit_assoc_node(self, node);
    }
    fn visit_embedded_variable_node(&mut self, node: &ruby_prism::EmbeddedVariableNode<'pr>) {
        self.check_variable_interpolation(node);
        ruby_prism::visit_embedded_variable_node(self, node);
    }
    fn visit_embedded_statements_node(&mut self, node: &ruby_prism::EmbeddedStatementsNode<'pr>) {
        self.check_empty_interpolation(node);
        self.interp_depth += 1;
        ruby_prism::visit_embedded_statements_node(self, node);
        self.interp_depth -= 1;
    }
    fn visit_program_node(&mut self, node: &ruby_prism::ProgramNode<'pr>) {
        self.class_children_stack.push(Self::direct_child_classes(&Some(node.statements().as_node())));
        ruby_prism::visit_program_node(self, node);
        self.class_children_stack.pop();
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        let l = node.location();
        self.check_empty_class(l.start_offset(), l.end_offset(),
            node.body().is_some(), node.superclass().is_some(), false);
        self.check_trailing_body_on_class(node.class_keyword_loc().start_offset(), l.end_offset(), node.body());
        self.check_class_methods(&node.constant_path(), node.body());
        self.check_documentation("class", node.location().start_offset(), &node.constant_path(), node.body());
        self.check_camel_case_name(&node.constant_path());
        self.enter_namespace(node.location().start_offset(), &node.constant_path());
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        // Default walk — covers the superclass expression too, not just the body.
        ruby_prism::visit_class_node(self, node);
        self.class_children_stack.pop();
        self.leave_namespace();
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.check_trailing_body_on_module(node);
        self.check_class_methods(&node.constant_path(), node.body());
        self.check_documentation("module", node.location().start_offset(), &node.constant_path(), node.body());
        self.check_camel_case_name(&node.constant_path());
        self.enter_namespace(node.location().start_offset(), &node.constant_path());
        self.class_children_stack.push(Self::direct_child_classes(&node.body()));
        ruby_prism::visit_module_node(self, node);
        self.class_children_stack.pop();
        self.leave_namespace();
    }
    fn visit_integer_node(&mut self, node: &ruby_prism::IntegerNode<'pr>) {
        if !self.num_ignore.contains(&node.location().start_offset()) {
            self.check_numeric_literals(&node.as_node());
        }
    }
    fn visit_float_node(&mut self, node: &ruby_prism::FloatNode<'pr>) {
        self.check_float_out_of_range(node);
        if !self.num_ignore.contains(&node.location().start_offset()) {
            self.check_numeric_literals(&node.as_node());
        }
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        self.check_def_with_parentheses(node);
        self.check_space_after_method_name(node);
        self.check_colon_method_definition(node);
        if node.equal_loc().is_none() {
            self.check_trailing_body_on_method_definition(node);
        }
        self.check_method_name_def(node);
        self.check_binary_operator_parameter(node);
        self.check_nested_method_definition(node);
        self.check_redundant_return(node);
        self.check_return_in_void_context(node);
        self.check_optional_arguments(node);
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
        ruby_prism::visit_def_node(self, node);
        self.class_children_stack.pop();
        self.def_depth -= 1;
        self.ll_exit_collection();
    }
    fn visit_lambda_node(&mut self, node: &ruby_prism::LambdaNode<'pr>) {
        self.check_empty_lambda_parameter(node);
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
        ruby_prism::visit_lambda_node(self, node);
        self.usage_block_depth -= 1;
    }
    fn visit_super_node(&mut self, node: &ruby_prism::SuperNode<'pr>) {
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
        if let Some(b) = node.block() {
            self.check_empty_block_parameter(&b);
            self.check_block_parameter_name(&b);
            if let Some((off, msg)) = self.symbol_proc_super(&b.as_node(), false, None) {
                self.push(off, "Style/SymbolProc", true, msg);
            }
        }
        ruby_prism::visit_forwarding_super_node(self, node);
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        let l = node.location();
        self.check_empty_class(l.start_offset(), l.end_offset(), node.body().is_some(), false, true);
        self.check_trailing_body_on_class(node.class_keyword_loc().start_offset(), l.end_offset(), node.body());
        // The expression (`class << HERE`) is outside the scoping context.
        self.visit(&node.expression());
        // `class << self` is a scoping context — nested defs inside are allowed.
        self.scoping_depth += 1;
        if let Some(b) = node.body() {
            self.visit(&b);
        }
        self.scoping_depth -= 1;
    }
    fn visit_alias_method_node(&mut self, node: &ruby_prism::AliasMethodNode<'pr>) {
        self.check_method_name_alias(node);
        ruby_prism::visit_alias_method_node(self, node);
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
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
        self.check_colon_method_call(node);
        self.check_deprecated_class_methods(node);
        self.check_marshal_load(node);
        self.check_security_eval(node);
        self.check_each_with_object_argument(node);
        self.check_hash_compare_by_identity(node);
        self.check_next_without_accumulator(node);
        self.check_multiple_comparison(node);
        self.check_identity_comparison(node);
        self.check_class_check(node);
        self.check_proc_new(node);
        self.check_strip(node);
        self.check_space_after_not(node);
        self.check_empty_literal(node);
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
        self.check_nested_file_dirname(node);
        self.check_uri_regexp(node);
        self.check_uri_escape_unescape(node);
        self.check_unpack_first(node);
        self.check_random_with_offset(node);
        self.check_debugger(node);
        self.check_stderr_puts(node);
        self.check_not(node);
        self.check_duplicate_require(node);
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
        // recurse into children (we've overridden the default walk). Push this
        // call's name SPAN so descendants can see it as an ancestor.
        let name_span = node
            .message_loc()
            .map(|l| (l.start_offset(), l.end_offset()))
            .unwrap_or((node_off, node_off));
        self.call_stack.push(name_span);
        let track_args = self.eng.debugger_on;
        if let Some(r) = node.receiver() {
            if track_args {
                self.assumed_arg_offsets.insert(r.location().start_offset());
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
            for arg in a.arguments().iter() {
                if track_args {
                    self.assumed_arg_offsets.insert(arg.location().start_offset());
                }
                self.visit(&arg);
            }
            if framed {
                self.bare_arg_frames.pop();
            }
        }
        if let Some(b) = node.block() {
            if let Some(bn) = b.as_block_node() {
                self.check_empty_block_parameter(&bn);
                self.check_block_parameter_name(&bn);
            }
            self.check_multiline_block_chain(node);
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
            self.usage_block_depth += 1;
            self.visit(&b);
            self.usage_block_depth -= 1;
            if scoping {
                self.scoping_depth -= 1;
            }
        }
        self.call_stack.pop();
        self.ll_exit_collection();
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
        interp_depth: 0,
        str_ignore: Vec::new(),
        num_ignore: Vec::new(),
        percent_sym_spans: Vec::new(),
        percent_arr_spans: Vec::new(),
        dirname_ignore: Vec::new(),
        stmts_stack: Vec::new(),
        unless_else_spans: Vec::new(),
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
        comments: &comment_data,
        mod_stack: Vec::new(),
        nodoc_all_stack: Vec::new(),
        cond_depth: 0,
        regexp_bang_ignore: Vec::new(),
    };

    let t = tick(&T_PREP, t);

    // ---- text-based cops ----
    let first_code_off = result
        .node()
        .as_program_node()
        .and_then(|p| p.statements().body().iter().next().map(|n| n.location().start_offset()));
    cops.check_frozen_string_literal(first_code_line);
    cops.check_empty_line_after_magic_comment(first_code_line);
    cops.check_empty_lines();
    cops.check_trailing_whitespace();
    cops.check_empty_file();
    cops.check_trailing_empty_lines();
    cops.check_initial_indentation(first_code_off);
    cops.check_leading_empty_lines(first_code_off);
    let t = tick(&T_TEXT, t);

    // ---- AST-based cops ----
    cops.ll_prepare();
    cops.visit(&result.node());
    // needs the breakable nominations the walk collected
    cops.check_line_length();
    cops.check_semicolon_lines();
    cops.check_space_after_comma();
    cops.check_space_before_semicolon();
    cops.check_space_before_comma();
    cops.check_space_before_comment();
    cops.check_space_after_semicolon();
    cops.check_double_cop_disable_directive();
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
