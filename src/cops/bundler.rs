//! Bundler department.
use super::Cops;

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
