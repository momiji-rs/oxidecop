//! Bundler department.
use super::Cops;
use std::collections::{HashMap, HashSet};

impl<'a> Cops<'a> {
    /// Bundler/InsecureProtocolSource — `source :gemcutter`/`:rubygems`/
    /// `:rubyforge` (rubygems.org mirrors that default to plain HTTP) or the
    /// literal string `'http://rubygems.org'`. Mirrors the cop's single
    /// `def_node_matcher` pattern `(send nil? :source ${(sym :gemcutter)
    /// (sym :rubygems) (sym :rubyforge) (:str "http://rubygems.org")})`: a
    /// bare `source` call (no receiver) with EXACTLY one argument that is one
    /// of those four literals. Anchors on the ARGUMENT node (not the whole
    /// call) since upstream's `add_offense(source_node, ...)` highlights only
    /// the captured `${...}` — matches the fixture's caret placement.
    ///
    /// Upstream's `Include` (`**/*.gemfile`, `**/Gemfile`, `**/gems.rb`) is a
    /// file-discovery-time filter applied by `RuboCop::Runner`/`TargetFinder`,
    /// not logic inside `on_send`. The RSpec fixture drives the cop directly
    /// via `RuboCop::Cop::Team.new([cop], ...).investigate(processed_source)`
    /// (see `rubocop/rspec/cop_helper.rb`), which never consults `Include` —
    /// confirmed live (`ruby -rrubocop`: `Team#investigate` fires on a
    /// `ProcessedSource` named "ex.rb" with no Gemfile-shaped path). oxidecop
    /// likewise has no general per-cop `Include` gate (only `AllCops:
    /// Include`/per-cop `Exclude` are wired into `file_view`), so this checks
    /// purely on AST shape, matching what the fixture actually exercises.
    pub(crate) fn check_insecure_protocol_source(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Bundler/InsecureProtocolSource";
        if !self.on(COP) {
            return;
        }
        if node.receiver().is_some() || node.name().as_slice() != b"source" {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let arg_list = args.arguments();
        if arg_list.iter().count() != 1 {
            return;
        }
        let arg = arg_list.iter().next().unwrap();

        let (source_text, use_http_protocol): (Vec<u8>, bool) =
            if let Some(sym) = arg.as_symbol_node() {
                let v = sym.unescaped();
                if !matches!(v, b"gemcutter" | b"rubygems" | b"rubyforge") {
                    return;
                }
                (v.to_vec(), false)
            } else if let Some(s) = arg.as_string_node() {
                if s.unescaped() != b"http://rubygems.org" {
                    return;
                }
                (s.unescaped().to_vec(), true)
            } else {
                return;
            };

        // `allow_http_protocol?` — `cop_config.fetch('AllowHttpProtocol',
        // true)`; the schema default is "true" so an absent config key falls
        // back to allowed (no offense).
        if use_http_protocol && self.cfg.get(COP, "AllowHttpProtocol") != Some("false") {
            return;
        }

        let l = arg.location();
        let message = if use_http_protocol {
            "Use `https://rubygems.org` instead of `http://rubygems.org`.".to_string()
        } else {
            format!(
                "The source `:{}` is deprecated because HTTP requests are insecure. Please change \
                 your source to 'https://rubygems.org' if possible, or 'http://rubygems.org' if not.",
                String::from_utf8_lossy(&source_text)
            )
        };
        self.push(l.start_offset(), COP, true, message);
        self.fixes.push((l.start_offset(), l.end_offset(), b"'https://rubygems.org'".to_vec()));
    }
}


impl<'a> Cops<'a> {
    /// Bundler/DuplicatedGem — a `gem 'name'` declaration repeated in the
    /// same Gemfile, unless every occurrence lives in a mutually exclusive
    /// branch of the SAME `if`/`elsif`/`else`/`unless`/`case`-`when` chain.
    ///
    /// rubocop's `on_new_investigation` runs a `def_node_search` for
    /// `(send nil? :gem str ...)` over the WHOLE file (inside defs/blocks/
    /// classes too), groups the matches by their (structurally-equal)
    /// first-argument string node, and for any group with more than one
    /// member, checks `conditional_declaration?`:
    ///
    ///   parent = nodes[0].each_ancestor.find { |a| !a.begin_type? }
    ///   return false unless parent&.type?(:if, :when)
    ///   root = parent.if_type? ? parent : parent.parent
    ///   nodes.all? { |n| root.branches.compact.any? { |b| b == n || b.child_nodes.include?(n) } }
    ///
    /// Prism has no parent pointers, so this walks a real ancestor stack
    /// built via `visit_branch_node_enter`/`_leave` (pushed/popped around
    /// EVERY branch node in the tree by prism's own dispatcher, not just the
    /// ones we care about — the cheapest way to get an `each_ancestor`
    /// equivalent here). Two prism-only wrapper shapes get skipped like
    /// rubocop's `begin_type?` skips whitequark's implicit multi-statement
    /// `:begin`: `StatementsNode` (prism wraps EVERY body, even a single
    /// statement, unlike whitequark, which only wraps 2+ statements) and
    /// `ElseNode` (whitequark has no wrapper for `else` at all — its body is
    /// a direct child slot of the `:if`/`:case` node, so `each_ancestor`
    /// never sees it).
    pub(crate) fn check_duplicated_gem(&mut self, node: &ruby_prism::ProgramNode) {
        const COP: &str = "Bundler/DuplicatedGem";
        if !self.on(COP) {
            return;
        }
        if !dg_is_gemfile(self.rel_path) {
            return;
        }
        let mut finder = DgFinder { stack: Vec::new(), matches: Vec::new() };
        use ruby_prism::Visit;
        finder.visit(&node.as_node());
        if finder.matches.len() < 2 {
            return;
        }
        // Group by the (unescaped) string content of the first argument —
        // `group_by(&:first_argument)` upstream, where Node#== is
        // structural. Insertion order is irrelevant for the final output
        // (offenses are sorted by line/col downstream) but kept stable
        // anyway.
        let mut order: Vec<Vec<u8>> = Vec::new();
        let mut groups: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        for (i, m) in finder.matches.iter().enumerate() {
            groups
                .entry(m.gem_name.clone())
                .or_insert_with(|| {
                    order.push(m.gem_name.clone());
                    Vec::new()
                })
                .push(i);
        }
        for key in &order {
            let idxs = &groups[key];
            if idxs.len() < 2 {
                continue;
            }
            let first = &finder.matches[idxs[0]];
            if dg_conditional_declaration(&finder.matches, idxs, first) {
                continue;
            }
            let (first_line, _) = self.idx.loc(first.call_start);
            let gem_name = String::from_utf8_lossy(key);
            for &i in &idxs[1..] {
                let start = finder.matches[i].call_start;
                let message = format!(
                    "Gem `{gem_name}` requirements already given on line {first_line} of the Gemfile."
                );
                self.push(start, COP, false, message);
            }
        }
    }
}

/// Only Gemfile-shaped files: rubocop's default `Include` for this cop
/// (`**/*.gemfile`, `**/Gemfile`, `**/gems.rb`) approximated on the
/// basename, since the harness has no generic per-cop `Include` gate.
fn dg_is_gemfile(rel_path: &str) -> bool {
    let name = std::path::Path::new(rel_path).file_name().and_then(|f| f.to_str()).unwrap_or("");
    name == "Gemfile" || name == "gems.rb" || name.ends_with(".gemfile")
}

struct DgMatch<'pr> {
    call_start: usize,
    gem_name: Vec<u8>,
    // The flattened branch bodies of the nearest enclosing if/unless/case
    // conditional that DIRECTLY contains this call (skipping only
    // StatementsNode/ElseNode/BeginNode wrappers) — None when no such
    // ancestor exists (unconditional, or nested under something else first,
    // e.g. a `def`/block/class).
    branches: Option<Vec<Option<ruby_prism::Node<'pr>>>>,
}

struct DgFinder<'pr> {
    stack: Vec<ruby_prism::Node<'pr>>,
    matches: Vec<DgMatch<'pr>>,
}

impl<'pr> ruby_prism::Visit<'pr> for DgFinder<'pr> {
    fn visit_branch_node_enter(&mut self, node: ruby_prism::Node<'pr>) {
        self.stack.push(node);
    }
    fn visit_branch_node_leave(&mut self) {
        self.stack.pop();
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if node.receiver().is_none() && node.name().as_slice() == b"gem" {
            if let Some(first) = node.arguments().and_then(|a| a.arguments().iter().next()) {
                if let Some(s) = first.as_string_node() {
                    // self.stack.last() is this very call node (pushed by
                    // visit_branch_node_enter right before we were
                    // dispatched to) — ancestors start one below it.
                    let branches = dg_ancestor_branches(&self.stack);
                    self.matches.push(DgMatch {
                        call_start: node.location().start_offset(),
                        gem_name: s.unescaped().to_vec(),
                        branches,
                    });
                }
            }
        }
        ruby_prism::visit_call_node(self, node);
    }
}

/// `nodes[0].each_ancestor.find { |a| !a.begin_type? }` then its
/// `.branches` (flattened through the whole if/elsif/else or
/// case/when/else) — or `None` when the nearest real ancestor isn't
/// `if`/`unless`/`when`.
fn dg_ancestor_branches<'pr>(
    stack: &[ruby_prism::Node<'pr>],
) -> Option<Vec<Option<ruby_prism::Node<'pr>>>> {
    if stack.len() < 2 {
        return None;
    }
    let mut idx = stack.len() - 2;
    loop {
        let anc = &stack[idx];
        if anc.as_statements_node().is_some() || anc.as_begin_node().is_some() || anc.as_else_node().is_some() {
            if idx == 0 {
                return None;
            }
            idx -= 1;
            continue;
        }
        if let Some(iff) = anc.as_if_node() {
            return Some(dg_if_chain_branches(&iff));
        }
        if let Some(unl) = anc.as_unless_node() {
            return Some(vec![
                unl.statements().map(|s| s.as_node()),
                unl.else_clause().and_then(|e| e.statements()).map(|s| s.as_node()),
            ]);
        }
        if anc.as_when_node().is_some() {
            if idx == 0 {
                return None;
            }
            return stack[idx - 1].as_case_node().map(dg_case_branches);
        }
        return None;
    }
}

/// Flattens an `if`/`elsif`/`else` chain into its branch bodies, in source
/// order — rubocop-ast's `IfNode#branches` recursing through `elsif`s.
fn dg_if_chain_branches<'pr>(node: &ruby_prism::IfNode<'pr>) -> Vec<Option<ruby_prism::Node<'pr>>> {
    let mut out = vec![node.statements().map(|s| s.as_node())];
    let mut cur = node.subsequent();
    while let Some(n) = cur {
        if let Some(elsif) = n.as_if_node() {
            out.push(elsif.statements().map(|s| s.as_node()));
            cur = elsif.subsequent();
        } else if let Some(els) = n.as_else_node() {
            out.push(els.statements().map(|s| s.as_node()));
            cur = None;
        } else {
            cur = None;
        }
    }
    out
}

/// `CaseNode#branches`: every `when`'s body plus the `else` body, in order.
fn dg_case_branches<'pr>(node: ruby_prism::CaseNode<'pr>) -> Vec<Option<ruby_prism::Node<'pr>>> {
    let mut out: Vec<Option<ruby_prism::Node<'pr>>> = node
        .conditions()
        .iter()
        .filter_map(|c| c.as_when_node())
        .map(|w| w.statements().map(|s| s.as_node()))
        .collect();
    if let Some(els) = node.else_clause() {
        out.push(els.statements().map(|s| s.as_node()));
    }
    out
}

/// `conditional_declaration?`: true iff EVERY node in the group lives inside
/// one of `first`'s conditional branches (rubocop's `within_conditional?`:
/// `branch == node || branch.child_nodes.include?(node)` — collapsed here to
/// one check since prism always wraps bodies in a `StatementsNode`, so "is
/// `node` a direct child of `branch`'s statement list" and "is `branch`
/// itself the (unwrapped) node" are the same test against `branch`'s two
/// possible shapes).
fn dg_conditional_declaration(matches: &[DgMatch], idxs: &[usize], first: &DgMatch) -> bool {
    let Some(branches) = &first.branches else { return false };
    idxs.iter().all(|&i| {
        let start = matches[i].call_start;
        branches.iter().any(|b| dg_branch_contains(b, start))
    })
}

fn dg_branch_contains(branch: &Option<ruby_prism::Node>, target: usize) -> bool {
    let Some(b) = branch else { return false };
    if let Some(st) = b.as_statements_node() {
        st.body().iter().any(|n| n.location().start_offset() == target)
    } else {
        b.location().start_offset() == target
    }
}


impl<'a> Cops<'a> {
    /// Bundler/GemFilename — rubocop's `on_new_investigation` runs this once
    /// per file, independent of its contents. With EnforcedStyle: Gemfile
    /// (default) a `gems.rb`/`gems.locked` basename is flagged; with
    /// `gems.rb`, a `Gemfile`/`Gemfile.lock` basename is flagged. No
    /// autocorrector. `add_global_offense` anchors at file start (byte 0 ->
    /// 1:1, same as Lint/EmptyFile's global offense).
    pub(crate) fn check_gem_filename(&mut self) {
        const COP: &str = "Bundler/GemFilename";
        if !self.on(COP) {
            return;
        }
        // rubocop's `processed_source.file_path` is the EXPANDED (absolute)
        // path — `File.expand_path` against the working directory (live
        // probe: `rubocop gems.rb` reports `file path: /private/tmp/.../gems.rb`).
        let file_path = if self.rel_path.starts_with('/') {
            self.rel_path.to_string()
        } else {
            std::env::current_dir()
                .map(|d| d.join(self.rel_path).to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| self.rel_path.to_string())
        };
        let file_path = file_path.as_str();
        let basename = file_path.rsplit('/').next().unwrap_or(file_path);
        let gemfile_required = self.cfg.enforced_style(COP) != "gems.rb";

        let message = if gemfile_required {
            match basename {
                "gems.rb" => Some(format!(
                    "`gems.rb` file was found but `Gemfile` is required (file path: {file_path})."
                )),
                "gems.locked" => Some(format!(
                    "Expected a `Gemfile.lock` with `Gemfile` but found `gems.locked` file (file path: {file_path})."
                )),
                _ => None,
            }
        } else {
            match basename {
                "Gemfile" => Some(format!(
                    "`Gemfile` was found but `gems.rb` file is required (file path: {file_path})."
                )),
                "Gemfile.lock" => Some(format!(
                    "Expected a `gems.locked` file with `gems.rb` but found `Gemfile.lock` (file path: {file_path})."
                )),
                _ => None,
            }
        };

        if let Some(message) = message {
            self.push(0, COP, false, message);
        }
    }
}


/// One `gem 'name'` declaration matching rubocop's node pattern `(:send
/// nil? :gem str ...)` — a bare `gem` call (no receiver) whose FIRST
/// argument is literally a string node (any further args/trailing block are
/// irrelevant to the match). Since the pattern already requires the first
/// argument to be a `str` node, `OrderedGemNode#find_gem_name`'s recursive
/// "peel through `.receiver()` chains" branch is dead code here (it only
/// matters for cops like Gemspec/OrderedDependencies whose pattern doesn't
/// pin the argument's node type) — the string's own content is always what
/// gets used.
struct GemDecl {
    // The call node's own span (`gem` through its last argument) — rubocop's
    // `node.source_range`: both the offense anchor and the "own line" bound
    // `declaration_with_comment` swaps up to.
    start: usize,
    first_line: usize,
    last_line: usize,
    name: Vec<u8>,
}

/// Collects every `gem_declarations` match in the whole file, in source
/// order — rubocop's `def_node_search` walks the full tree (including
/// inside `group do ... end` blocks), and for this narrow, non-nesting node
/// shape, preorder traversal order is the same as source order.
struct GemDeclCollector<'a> {
    idx: &'a super::LineIndex,
    decls: Vec<GemDecl>,
}
impl<'pr, 'a> ruby_prism::Visit<'pr> for GemDeclCollector<'a> {
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        if node.receiver().is_none() && node.name().as_slice() == b"gem" {
            if let Some(first) = node.arguments().and_then(|a| a.arguments().iter().next()) {
                if let Some(s) = first.as_string_node() {
                    let l = node.location();
                    let start = l.start_offset();
                    let end = l.end_offset();
                    self.decls.push(GemDecl {
                        start,
                        first_line: self.idx.loc(start).0,
                        last_line: self.idx.loc(end.saturating_sub(1).max(start)).0,
                        name: s.unescaped().to_vec(),
                    });
                }
            }
        }
        ruby_prism::visit_call_node(self, node);
    }
}

impl<'a> Cops<'a> {
    /// Bundler/OrderedGems — `gem` declarations must be alphabetically
    /// sorted within their "section" (a maximal run of declarations on
    /// consecutive lines, where a leading comment block directly touching a
    /// declaration counts as part of it unless `TreatCommentsAsGroupSeparators`
    /// says otherwise).
    ///
    /// Ported from `RuboCop::Cop::Bundler::OrderedGems` +
    /// `OrderedGemNode` (mixin) + `OrderedGemCorrector` — the very same
    /// mixin/corrector `Gemspec::OrderedDependencies` uses (see
    /// `check_ordered_dependencies` in gemspec.rs, whose structure this
    /// mirrors closely). Two differences from that port: (1) there's only
    /// ONE method name (`gem`), so no grouping-by-method-name step exists;
    /// (2) the node pattern here pins the first argument to `str` directly,
    /// so `gem_name` never needs the receiver-chain-peeling fallback.
    ///
    /// Run once over the whole parsed tree (like `check_ordered_dependencies`),
    /// not from a `visit_*` hook — the upstream check is fundamentally a
    /// whole-file `def_node_search` + `each_cons(2)`, not a single-node
    /// predicate. This cop's per-cop `Include` (`**/*.gemfile`, `**/Gemfile`,
    /// `**/gems.rb`) is handled by the engine's DEFAULT_COP_INCLUDES
    /// machinery upstream of this function, per the task brief — no gating
    /// here.
    pub(crate) fn check_ordered_gems(&mut self, root: &ruby_prism::Node) {
        const COP: &str = "Bundler/OrderedGems";
        if !self.on(COP) {
            return;
        }
        let mut collector = GemDeclCollector { idx: self.idx, decls: Vec::new() };
        ruby_prism::Visit::visit(&mut collector, root);
        let decls = collector.decls;
        if decls.len() < 2 {
            return;
        }

        // TreatCommentsAsGroupSeparators default true, ConsiderPunctuation
        // default false — both ARRAY-absent-from-schema-safe here since
        // they're plain booleans, but honor the same self.cfg.get +
        // schema-default-fallback idiom as the sibling port for consistency.
        let treat_as_sep = self.cfg.get(COP, "TreatCommentsAsGroupSeparators") != Some("false");
        let consider_punct = self.cfg.get(COP, "ConsiderPunctuation") == Some("true");

        // Lines whose ENTIRE content (up to the `#`) is whitespace — a
        // "leading comment" line eligible to be swapped along with the
        // declaration under it (rubocop's `Parser::Source::Comment::
        // Associator`: a same-line TRAILING comment never counts as a
        // preceding one).
        let mut own_line_comment: HashSet<usize> = HashSet::new();
        for &(line, start, _end) in self.comments {
            let ls = self.idx.starts[line - 1];
            if self.src[ls..start].iter().all(u8::is_ascii_whitespace) {
                own_line_comment.insert(line);
            }
        }
        // Whole-line-is-whitespace check (blank line).
        let blank_line = |line: usize| -> bool {
            let ls = self.idx.starts[line - 1];
            let le = self.idx.starts.get(line).copied().unwrap_or(self.src.len());
            self.src[ls..le].iter().all(u8::is_ascii_whitespace)
        };
        // The EARLIEST comment `Parser::Source::Comment::Associator` attaches
        // to a node starting on `first_line` — `get_source_range`'s
        // `ast_with_comments[node].first`. Walk upward through blank and
        // comment-only lines; the topmost comment-only line seen is the
        // first attached comment.
        let leading_top = |first_line: usize| -> Option<usize> {
            let mut top = None;
            let mut line = first_line;
            while line > 1 {
                let above = line - 1;
                if own_line_comment.contains(&above) {
                    top = Some(above);
                } else if !blank_line(above) {
                    break;
                }
                line = above;
            }
            top
        };
        // `get_source_range(node, treat_as_sep).first_line`: with
        // TreatCommentsAsGroupSeparators, comments are never folded in.
        let source_range_first_line =
            |first_line: usize| if treat_as_sep { first_line } else { leading_top(first_line).unwrap_or(first_line) };

        let canon = |name: &[u8]| -> Vec<u8> {
            let mut v: Vec<u8> = if consider_punct {
                name.to_vec()
            } else {
                name.iter().copied().filter(|&b| b != b'-' && b != b'_').collect()
            };
            v.make_ascii_lowercase();
            v
        };

        // Byte ranges already claimed by an earlier swap THIS pass — when a
        // declaration is the `current` of one offense and the `previous` of
        // the next (`c, b, a`), the second `corrector.swap` clobbers the
        // first; rubocop drops the whole clobbering corrector (Parser::
        // ClobberingError suppression) and re-converges over autocorrect
        // passes. Both halves of a swap must stay atomic — applying one half
        // alone would corrupt the source.
        let mut claimed: Vec<(usize, usize)> = Vec::new();

        for w in decls.windows(2) {
            let (prev, curr) = (&w[0], &w[1]);
            // consecutive_lines?
            let curr_top = source_range_first_line(curr.first_line);
            if prev.last_line != curr_top.saturating_sub(1) {
                continue;
            }
            // case_insensitive_out_of_order?(gem_name(current), gem_name(previous))
            if canon(&curr.name) >= canon(&prev.name) {
                continue;
            }

            let prev_name = String::from_utf8_lossy(&prev.name).into_owned();
            let curr_name = String::from_utf8_lossy(&curr.name).into_owned();
            let msg = format!(
                "Gems should be sorted in an alphabetical order within their section of the Gemfile. Gem `{curr_name}` should appear before `{prev_name}`."
            );
            self.push(curr.start, COP, true, msg);

            // OrderedGemCorrector#declaration_with_comment for each side:
            // begin = start of the topmost attached-comment line (or the
            // node's own line when there's none / comments are separators);
            // end = end of the node's OWN last line, newline included.
            let prev_top = source_range_first_line(prev.first_line);
            let curr_range = (self.idx.starts[curr_top - 1], og_line_end_incl_nl(self.idx, self.src, curr.last_line));
            let prev_range = (self.idx.starts[prev_top - 1], og_line_end_incl_nl(self.idx, self.src, prev.last_line));

            let overlaps = |a: (usize, usize), b: &(usize, usize)| a.0 < b.1 && b.0 < a.1;
            if claimed.iter().any(|c| overlaps(curr_range, c) || overlaps(prev_range, c)) {
                continue; // offense stands; the clobbering correction is dropped
            }
            claimed.push(curr_range);
            claimed.push(prev_range);

            let curr_text = self.src[curr_range.0..curr_range.1].to_vec();
            let prev_text = self.src[prev_range.0..prev_range.1].to_vec();
            // corrector.swap(current_range, previous_range)
            self.fixes.push((curr_range.0, curr_range.1, prev_text));
            self.fixes.push((prev_range.0, prev_range.1, curr_text));
        }
    }
}

/// End offset of `line`, including its trailing newline — the start of the
/// next line, or end-of-buffer for the last line. (Free function, not a
/// `Cops` method, to avoid an inherent-method name collision with
/// gemspec.rs's identically-shaped `line_end_incl_nl` helper — inherent
/// impls share one method namespace per type across the whole crate.)
fn og_line_end_incl_nl(idx: &super::LineIndex, src: &[u8], line: usize) -> usize {
    idx.starts.get(line).copied().unwrap_or(src.len())
}
