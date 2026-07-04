//! Gemspec department: cops that flag risky patterns inside `.gemspec` files.
use super::Cops;

impl<'a> Cops<'a> {
    /// Gemspec/RubyVersionGlobalsUsage — bare `RUBY_VERSION` / `::RUBY_VERSION`.
    /// Ported verbatim from upstream's node pattern:
    ///   `{ (const {cbase nil?} :RUBY_VERSION) (const (const {cbase nil?} :Ruby) :VERSION) }`
    ///
    /// Upstream additionally gates on
    /// `gem_specification(processed_source.ast) && ruby_version?(node)`, where
    /// `gem_specification` is a `GemspecHelp#def_node_search` invoked WITHOUT a
    /// block. Per `RuboCop::AST::NodePattern::MethodDefiner#emit_node_search`,
    /// a no-block call to a `def_node_search`-defined method just returns
    /// `enum_for(...)` — a lazy `Enumerator` that is always truthy (Ruby's
    /// `&&` only cares about `nil`/`false`) and is never actually iterated.
    /// So `gem_specification(processed_source.ast) && ruby_version?(node)`
    /// reduces to plain `ruby_version?(node)`: the "is there a
    /// `Gem::Specification.new do |x| ... end` block anywhere in the file"
    /// check is a no-op in the real cop. Confirmed live against rubocop
    /// 1.88.0: `RUBY_VERSION` on a line by itself, with NO
    /// `Gem::Specification` block anywhere in the source, still registers
    /// the offense (`ruby -rrubocop` probe via `RuboCop::Cop::Team#investigate`).
    ///
    /// The cop is really scoped to gemspec files purely through the config's
    /// `Include: ['**/*.gemspec']`, which is a file-selection concern the
    /// runner applies before invoking any cop at all — `on_const` itself
    /// never inspects the filename. This engine has no per-cop Include-glob
    /// dispatch mechanism (only a whole-run `AllCops: Include` exists), and
    /// the authoritative spec fixture's `expect_offense` calls don't pass a
    /// filename either (so the harness always feeds a plain `ex.rb`) —
    /// matching the literal ported method body, this check does not
    /// re-derive an Include restriction from `rel_path`.
    pub(crate) fn check_ruby_version_globals_usage_read(&mut self, node: &ruby_prism::ConstantReadNode) {
        const COP: &str = "Gemspec/RubyVersionGlobalsUsage";
        if !self.on(COP) {
            return;
        }
        if node.name().as_slice() != b"RUBY_VERSION" {
            return;
        }
        let l = node.location();
        self.push_ruby_version_globals_usage(l.start_offset(), l.end_offset());
    }

    /// Gemspec/RubyVersionGlobalsUsage — `::RUBY_VERSION`, `Ruby::VERSION`,
    /// and `::Ruby::VERSION`. See `check_ruby_version_globals_usage_read` for
    /// the full rationale (no filename/Include gating, no
    /// `Gem::Specification` block requirement).
    pub(crate) fn check_ruby_version_globals_usage_path(&mut self, node: &ruby_prism::ConstantPathNode) {
        const COP: &str = "Gemspec/RubyVersionGlobalsUsage";
        if !self.on(COP) {
            return;
        }
        let Some(name) = node.name() else { return };
        let matches = match name.as_slice() {
            b"RUBY_VERSION" => node.parent().is_none(),
            b"VERSION" => node.parent().is_some_and(|p| is_bare_or_top_level_ruby(&p)),
            _ => false,
        };
        if !matches {
            return;
        }
        let l = node.location();
        // The exact target of a constant-path write (`Ruby::VERSION = x`,
        // `::RUBY_VERSION ||= x`, `+=`, `&&=`) is a whitequark `casgn`
        // upstream — `on_const` never fires for it (confirmed live: rubocop
        // 1.88.0 registers ZERO offenses on `Ruby::VERSION = '3'`). Its
        // namespace segments are still plain consts there and DO flag
        // (`Ruby::VERSION::FOO = 1` flags the inner `Ruby::VERSION`), which
        // the (start, end)-keyed skip preserves — the inner segment shares
        // the target's start offset but not its end.
        if self.rvgu_write_target_skip.contains(&(l.start_offset(), l.end_offset())) {
            return;
        }
        self.push_ruby_version_globals_usage(l.start_offset(), l.end_offset());
    }

    /// Mark `target` (the assignment target of an enclosing constant-path
    /// write) as exempt from Gemspec/RubyVersionGlobalsUsage — called from
    /// the `visit_constant_path_*write_node` overrides BEFORE traversal
    /// descends into the target. See `rvgu_write_target_skip` in mod.rs.
    pub(crate) fn rvgu_mark_write_target(&mut self, target: &ruby_prism::ConstantPathNode) {
        let l = target.location();
        self.rvgu_write_target_skip.insert((l.start_offset(), l.end_offset()));
    }

    fn push_ruby_version_globals_usage(&mut self, start: usize, end: usize) {
        const COP: &str = "Gemspec/RubyVersionGlobalsUsage";
        let text = String::from_utf8_lossy(&self.src[start..end]);
        self.push(start, COP, false, format!("Do not use `{text}` in gemspec file."));
    }
}

/// Is `node` a reference to the bare `Ruby` module — either a plain
/// `ConstantReadNode` named `Ruby`, or a top-level `::Ruby`
/// (a parent-less `ConstantPathNode` named `Ruby`)?
fn is_bare_or_top_level_ruby(node: &ruby_prism::Node) -> bool {
    if let Some(c) = node.as_constant_read_node() {
        return c.name().as_slice() == b"Ruby";
    }
    if let Some(c) = node.as_constant_path_node() {
        return c.parent().is_none() && c.name().is_some_and(|n| n.as_slice() == b"Ruby");
    }
    false
}
