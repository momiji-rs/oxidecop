//! Config: the `.rubocop.yml` subset we parse, and the per-cop SCHEMA that is
//! the single source of truth for parameter defaults / SupportedStyles.
use std::collections::HashMap;

/// Per-cop config schema: parameter defaults and (for style cops) the supported
/// `EnforcedStyle`s + default. This is the ONE place defaults live — no default
/// literals scattered at call sites, EnforcedStyle resolution/validation in one
/// spot. The table itself (`SCHEMA`, all 606 cops) is GENERATED from rubocop's
/// own `config/default.yml` by `tools/gen_schema.rb` — see `src/schema_gen.rs`.
pub struct Schema {
    pub cop: &'static str,
    /// (param, default-as-string). For style cops, includes `EnforcedStyle`.
    pub params: &'static [(&'static str, &'static str)],
    /// SupportedStyles — used to validate a configured `EnforcedStyle`.
    pub styles: &'static [&'static str],
    /// Default `AllowedMethods` when the config doesn't set one (e.g. rubocop
    /// ships `Style/SymbolProc` with `AllowedMethods: [define_method]`).
    pub allowed_methods: &'static [&'static str],
    /// The style-guide anchor/URL (default.yml `StyleGuide:`) — appended to
    /// messages under `AllCops: DisplayStyleGuide`.
    pub style_guide: Option<&'static str>,
}
pub use crate::schema_gen::SCHEMA;
pub fn schema(cop: &str) -> Option<&'static Schema> {
    // SCHEMA is generated sorted by cop name.
    SCHEMA.binary_search_by(|s| s.cop.cmp(cop)).ok().map(|i| &SCHEMA[i])
}
pub fn schema_default(cop: &str, key: &str) -> Option<&'static str> {
    schema(cop).and_then(|s| s.params.iter().find(|(k, _)| *k == key).map(|(_, v)| *v))
}

/// Parse a YAML flow sequence of patterns (`['\Afoo\z', '^\s*bar']`) into their
/// raw regex sources. Quote-aware so commas inside quotes aren't split points.
/// This backs the cross-cutting `AllowedPatterns` config (see `Cops::allowed`).
pub fn parse_allowed_list(s: &str) -> Vec<String> {
    let s = s.trim();
    if !s.starts_with('[') {
        return Vec::new(); // `nil` / absent / scalar → no patterns
    }
    let inner = &s[1..s.len().saturating_sub(1)];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in inner.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                ',' => {
                    let t = cur.trim().to_string();
                    if !t.is_empty() {
                        out.push(t);
                    }
                    cur.clear();
                }
                _ => cur.push(c),
            },
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() {
        out.push(t);
    }
    out
}

// ---------------- config (.rubocop.yml, minimal subset) ----------------
pub struct Config {
    // cop/section name -> { key -> value }
    pub(crate) sections: HashMap<String, HashMap<String, String>>,
    all_disabled_by_default: bool,
    // `--only Cop1,Cop2` — when set, ONLY these cops (or departments) run,
    // regardless of Enabled flags, like rubocop's flag.
    pub only: Option<Vec<String>>,
    // `--except Cop1,Cop2` — never run these, whatever else says so.
    pub except: Option<Vec<String>>,
    // `inherit_from:` targets, in order (base-most first), relative to the
    // config file's directory. The runner resolves and merges them.
    pub inherits: Vec<String>,
}
impl Config {
    pub fn parse(text: &str) -> Self {
        let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut cur: Option<String> = None;
        let mut cur_list_key: Option<String> = None;
        let mut inherits: Vec<String> = Vec::new();
        let mut in_inherit_list = false;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or(""); // strip comments
            if line.trim().is_empty() {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let t = line.trim();
            if !indented {
                cur_list_key = None;
                in_inherit_list = false;
                // `inherit_from:` — scalar or block list of config paths
                if t == "inherit_from:" {
                    in_inherit_list = true;
                    cur = None;
                    continue;
                }
                if let Some(v) = t.strip_prefix("inherit_from:") {
                    inherits.push(v.trim().trim_matches(|c| c == '\'' || c == '"').to_string());
                    cur = None;
                    continue;
                }
                // top-level "Section:" (may also be "Section: value" — ignore value)
                if let Some(name) = t.strip_suffix(':') {
                    cur = Some(name.to_string());
                    sections.entry(name.to_string()).or_default();
                } else if let Some((k, _)) = t.split_once(':') {
                    cur = Some(k.trim().to_string());
                    sections.entry(k.trim().to_string()).or_default();
                }
            } else if in_inherit_list {
                if let Some(item) = t.strip_prefix("- ") {
                    inherits.push(item.trim().trim_matches(|c| c == '\'' || c == '"').to_string());
                }
            } else if let Some(item) = t.strip_prefix("- ") {
                // a block-list item under the last seen key: accumulate into
                // the flow form (`['a', 'b']`) that parse_allowed_list reads.
                if let (Some(sec), Some(key)) = (&cur, &cur_list_key) {
                    let map = sections.get_mut(sec).unwrap();
                    let item = item.trim().trim_matches(|c| c == '\'' || c == '"');
                    let entry = map.entry(key.clone()).or_default();
                    if entry.is_empty() || entry == "[]" {
                        *entry = format!("['{item}']");
                    } else if entry.ends_with(']') {
                        entry.truncate(entry.len() - 1);
                        entry.push_str(&format!(", '{item}']"));
                    }
                }
            } else if let (Some(sec), Some((k, v))) = (&cur, t.split_once(':')) {
                let (k, v) = (k.trim().to_string(), v.trim().to_string());
                cur_list_key = v.is_empty().then(|| k.clone());
                sections.get_mut(sec).unwrap().insert(k, v);
            }
        }
        let all_disabled_by_default = sections
            .get("AllCops")
            .and_then(|s| s.get("DisabledByDefault"))
            .map(|v| v == "true")
            .unwrap_or(false);
        Config { sections, all_disabled_by_default, only: None, except: None, inherits }
    }
    /// Overlay `child` on top of self (self is the inherited base). Scalar
    /// keys override; `Exclude` lists MERGE (union), matching rubocop's
    /// default inherit_mode.
    pub fn merge_child(&mut self, child: Config) {
        for (sec, kv) in child.sections {
            let base = self.sections.entry(sec).or_default();
            for (k, v) in kv {
                if k == "Exclude" {
                    let entry = base.entry(k).or_default();
                    if entry.is_empty() || entry == "[]" {
                        *entry = v;
                    } else if !v.is_empty() && v != "[]" && entry.ends_with(']') && v.starts_with('[') {
                        entry.truncate(entry.len() - 1);
                        entry.push_str(", ");
                        entry.push_str(v.trim_start_matches('['));
                    }
                } else {
                    base.insert(k, v);
                }
            }
        }
        self.all_disabled_by_default = self
            .sections
            .get("AllCops")
            .and_then(|s| s.get("DisabledByDefault"))
            .map(|v| v == "true")
            .unwrap_or(false);
        self.inherits = Vec::new();
    }
    pub fn enabled(&self, cop: &str) -> bool {
        if let Some(except) = &self.except {
            if except.iter().any(|o| o == cop || cop.starts_with(&format!("{o}/"))) {
                return false;
            }
        }
        if let Some(only) = &self.only {
            return only.iter().any(|o| o == cop || cop.starts_with(&format!("{o}/")));
        }
        match self.sections.get(cop).and_then(|s| s.get("Enabled")) {
            Some(v) => v != "false",
            None => !self.all_disabled_by_default,
        }
    }
    pub fn param(&self, cop: &str, key: &str) -> Option<&str> {
        self.sections.get(cop).and_then(|s| s.get(key)).map(|s| s.as_str())
    }
    /// The cop's section carries `__replace_defaults__` — it REPLACES the
    /// defaults instead of merging over them (a spec whose `let(:config)`
    /// rebuilt the whole RuboCop::Config; unspecified params are nil there).
    pub fn replaces_defaults(&self, cop: &str) -> bool {
        self.param(cop, "__replace_defaults__") == Some("true")
    }
    /// Resolved value: user config if present, else the SCHEMA default —
    /// unless the section replaces defaults outright.
    pub fn get(&self, cop: &str, key: &str) -> Option<&str> {
        self.param(cop, key).or_else(|| {
            if self.replaces_defaults(cop) {
                None
            } else {
                schema_default(cop, key)
            }
        })
    }
    pub fn int(&self, cop: &str, key: &str) -> usize {
        self.get(cop, key).and_then(|v| v.parse().ok()).unwrap_or(0)
    }
    /// The active `EnforcedStyle`: the configured value if it's a supported
    /// style, otherwise the schema default. One place for style resolution.
    pub fn enforced_style(&self, cop: &str) -> &str {
        let default = schema_default(cop, "EnforcedStyle").unwrap_or("");
        match self.param(cop, "EnforcedStyle") {
            Some(v) if schema(cop).map(|s| s.styles.contains(&v)).unwrap_or(false) => v,
            _ => default,
        }
    }
    /// A deterministic serialization of the resolved config — the cache key
    /// component that captures "same effective configuration".
    pub fn identity(&self) -> String {
        let mut secs: Vec<_> = self.sections.iter().collect();
        secs.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = String::new();
        for (sec, kv) in secs {
            let mut kvs: Vec<_> = kv.iter().collect();
            kvs.sort_by(|a, b| a.0.cmp(b.0));
            out.push_str(sec);
            out.push('\u{1}');
            for (k, v) in kvs {
                out.push_str(k);
                out.push('\u{2}');
                out.push_str(v);
                out.push('\u{2}');
            }
        }
        out
    }
    /// AllCops/TargetRubyVersion — rubocop's DEFAULT_VERSION (2.7) when unset.
    /// Version-gated cop behavior (parser names, minimum_target_ruby_version)
    /// dispatches on this.
    pub fn target_ruby(&self) -> f64 {
        self.sections
            .get("AllCops")
            .and_then(|s| s.get("TargetRubyVersion"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(2.7)
    }
    /// The AllCops Exclude patterns, compiled once. Patterns are
    /// rubocop-style globs (`**` spans directories, `*` doesn't) or
    /// `!ruby/regexp /.../` literals.
    pub fn exclude_matchers(&self) -> Vec<regex::Regex> {
        self.section_exclude_matchers("AllCops")
    }
    /// A section's Exclude patterns (per-cop Exclude), compiled.
    pub fn section_exclude_matchers(&self, section: &str) -> Vec<regex::Regex> {
        let Some(v) = self.sections.get(section).and_then(|s| s.get("Exclude")) else {
            return Vec::new();
        };
        parse_allowed_list(v).iter().filter_map(|p| exclude_regex(p)).collect()
    }
    /// AllCops/ActiveSupportExtensionsEnabled (default false). Gates whether
    /// `proc`/`lambda`/`Proc.new` blocks are candidates for Style/SymbolProc.
    pub fn active_support(&self) -> bool {
        self.sections
            .get("AllCops")
            .and_then(|s| s.get("ActiveSupportExtensionsEnabled"))
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

/// Minimal rubocop-glob compiler: `**` crosses directory separators, `*` and
/// `?` don't. Anchored to the whole path.
pub fn glob_regex(pat: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                // `**/` may match nothing at all
                if chars.peek() == Some(&'/') {
                    chars.next();
                    re.push_str("(?:.*/)?");
                } else {
                    re.push_str(".*");
                }
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    regex::Regex::new(&re).ok()
}

/// Compile one Exclude entry: a `!ruby/regexp /.../` literal or a glob.
pub fn exclude_regex(pat: &str) -> Option<regex::Regex> {
    if let Some(rest) = pat.strip_prefix("!ruby/regexp") {
        let rest = rest.trim();
        let body = rest.strip_prefix('/').and_then(|r| r.rsplit_once('/')).map(|(b, _)| b)?;
        return regex::Regex::new(body).ok();
    }
    glob_regex(pat)
}
