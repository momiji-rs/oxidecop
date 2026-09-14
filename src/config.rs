//! Config: the `.rubocop.yml` subset we parse, and the per-cop SCHEMA that is
//! the single source of truth for parameter defaults / SupportedStyles.
use std::collections::HashMap;

/// Per-cop config schema: parameter defaults and (for style cops) the supported
/// `EnforcedStyle`s + default. This is the ONE place defaults live — no default
/// literals scattered at call sites, EnforcedStyle resolution/validation in one
/// spot. The table itself (`SCHEMA`) is GENERATED from rubocop's own
/// `config/default.yml` plus rubocop-performance's, by `tools/gen_schema.rb`
/// — see `src/schema_gen.rs`.
pub struct Schema {
    pub cop: &'static str,
    /// (param, default-as-string). For style cops, includes `EnforcedStyle`.
    pub params: &'static [(&'static str, &'static str)],
    /// SupportedStyles — used to validate a configured `EnforcedStyle`.
    pub styles: &'static [&'static str],
    /// Default `AllowedMethods` when the config doesn't set one (e.g. rubocop
    /// ships `Style/SymbolProc` with `AllowedMethods: [define_method]`).
    pub allowed_methods: &'static [&'static str],
    /// Default per-cop `Exclude` globs (e.g. Style/NumericPredicate ships
    /// with `spec/**/*`) — apply unless the user config sets its own.
    pub excludes: &'static [&'static str],
    /// The style-guide anchor/URL (default.yml `StyleGuide:`) — appended to
    /// messages under `AllCops: DisplayStyleGuide`.
    pub style_guide: Option<&'static str>,
    /// Reference URLs (default.yml `References:`/legacy `Reference:`) —
    /// appended after the style-guide URL under DisplayStyleGuide.
    pub references: &'static [&'static str],
}
pub use crate::schema_gen::SCHEMA;

/// One plugin gem's `config/default.yml` contribution to CORE configuration:
/// the `AllCops` keys it sets and its overrides of core cops. RuboCop merges a
/// plugin's default.yml into `ConfigLoader.default_configuration`, so these
/// apply to every run that loads the gem — which is why a linter with none of
/// the plugin's cops still has to carry them. The table is GENERATED from the
/// gems themselves by `tools/gen_plugin_config.rb` — see `src/plugin_config_gen.rs`.
pub struct PluginConfig {
    /// The `plugins:` / `require:` spellings that load this gem, gem name first.
    pub names: &'static [&'static str],
    /// (section, key, value, how the value combines with the layers around it).
    pub entries: &'static [(&'static str, &'static str, &'static str, InheritMode)],
}

/// rubocop's per-key `inherit_mode`: `Merge` unions a list value with the layer
/// below it AND with a user value above it (`Array(base) | Array(derived)`),
/// `Override` replaces the layer below and yields to the user.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InheritMode {
    Override,
    Merge,
}
pub use crate::plugin_config_gen::PLUGIN_CONFIGS;

/// The plugin config a `plugins:`/`require:` entry loads, if the table has one.
fn plugin_config<'a>(table: &'a [PluginConfig], name: &str) -> Option<&'a PluginConfig> {
    table.iter().find(|p| p.names.contains(&name))
}

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
    // the block-list accumulator's sentinel form: \u{1}item\u{0}item...
    if let Some(rest) = s.strip_prefix('\u{1}') {
        return rest.split('\u{0}').map(str::to_string).collect();
    }
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

/// True for a value `parse_allowed_list` reads as a list — the block-list
/// accumulator form or a YAML flow sequence.
fn is_list_value(v: &str) -> bool {
    v.starts_with('\u{1}') || v.trim_start().starts_with('[')
}

/// Encode items back into the accumulator form, which (unlike the flow form)
/// survives items containing quotes — `!ruby/regexp /["']/` is a real Exclude.
fn encode_list(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    format!("\u{1}{}", items.join("\u{0}"))
}

/// Union two list-valued entries, rubocop's `Array(base) | Array(derived)`:
/// base order first, derived's new items appended.
pub fn union_list_values(base: &str, derived: &str) -> String {
    let mut items = parse_allowed_list(base);
    for it in parse_allowed_list(derived) {
        if !items.contains(&it) {
            items.push(it);
        }
    }
    encode_list(&items)
}

/// The core default for a LIST-valued cop parameter. Only `Exclude` and
/// `AllowedMethods` are carried in the generated SCHEMA; every other list
/// default (`ContextCreatingMethods`, …) is absent there and reads as empty —
/// exactly what the cops themselves see.
fn schema_list(section: &str, key: &str) -> Vec<String> {
    let Some(s) = schema(section) else { return Vec::new() };
    let items: &[&str] = match key {
        "Exclude" => s.excludes,
        "AllowedMethods" => s.allowed_methods,
        _ => &[],
    };
    items.iter().map(|i| i.to_string()).collect()
}

// ---------------- config (.rubocop.yml, minimal subset) ----------------
pub struct Config {
    // cop/section name -> { key -> value }
    pub(crate) sections: HashMap<String, HashMap<String, String>>,
    pub(crate) all_disabled_by_default: bool,
    // `--only Cop1,Cop2` — when set, ONLY these cops (or departments) run,
    // regardless of Enabled flags, like rubocop's flag.
    pub only: Option<Vec<String>>,
    // `--except Cop1,Cop2` — never run these, whatever else says so.
    pub except: Option<Vec<String>>,
    // `inherit_gem:` targets: (gem name, config paths inside the gem).
    pub inherit_gems: Vec<(String, Vec<String>)>,
    // `inherit_from:` targets, in order (base-most first), relative to the
    // config file's directory. The runner resolves and merges them.
    pub inherits: Vec<String>,
    // Top-level `plugins:` entries (`rubocop-performance`, …). A Performance
    // cop is live only when one of these (or `require:`) names that gem —
    // matching RuboCop, which does not instantiate plugin cops otherwise.
    pub plugins: Vec<String>,
    // Top-level `require:` entries. Older configs load the extension with
    // `require: rubocop-performance` instead of `plugins:`.
    pub requires: Vec<String>,
}

/// Names that mean "load rubocop-performance" on `plugins:` / `require:`.
fn is_performance_plugin(s: &str) -> bool {
    matches!(
        s.trim(),
        "rubocop-performance" | "rubocop/cop/performance" | "rubocop/performance"
    )
}

/// A YAML flow sequence (`[a, b]`) or a single scalar, unquoted.
fn parse_name_list(v: &str) -> Vec<String> {
    let v = v.trim();
    if v.is_empty() {
        return Vec::new();
    }
    if v.starts_with('[') && v.ends_with(']') {
        v[1..v.len() - 1]
            .split(',')
            .map(|s| yaml_unquote(s.trim()))
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![yaml_unquote(v)]
    }
}
/// Decode one YAML scalar the way rubocop's YAML load would: a
/// double-quoted scalar processes escapes (`"\\d"` is the two bytes `\d`),
/// a single-quoted one only doubles quotes, a plain scalar is literal.
fn yaml_unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return s[1..s.len() - 1].replace("''", "'");
    }
    s.to_string()
}

impl Config {
    pub fn parse(text: &str) -> Self {
        let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut cur: Option<String> = None;
        let mut cur_list_key: Option<String> = None;
        let mut inherits: Vec<String> = Vec::new();
        let mut inherit_gems: Vec<(String, Vec<String>)> = Vec::new();
        let mut plugins: Vec<String> = Vec::new();
        let mut requires: Vec<String> = Vec::new();
        let mut in_inherit_list = false;
        let mut in_inherit_gem = false;
        let mut in_plugins_list = false;
        let mut in_require_list = false;
        let mut cur_gem: Option<String> = None;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or(""); // strip comments
            if line.trim().is_empty() {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let t = line.trim();
            if !indented {
                // YAML allows a block sequence at the SAME indentation as its
                // key (`inherit_from:\n- .rubocop/style.yml`) — Psych even
                // dumps that shape by default. A column-0 `- item` while an
                // inherit_from list is open is a list entry, not a new key.
                if in_inherit_list {
                    if let Some(item) = t.strip_prefix("- ") {
                        inherits.push(item.trim().trim_matches(|c| c == '\'' || c == '"').to_string());
                        continue;
                    }
                }
                if in_plugins_list {
                    if let Some(item) = t.strip_prefix("- ") {
                        plugins.push(yaml_unquote(item));
                        continue;
                    }
                }
                if in_require_list {
                    if let Some(item) = t.strip_prefix("- ") {
                        requires.push(yaml_unquote(item));
                        continue;
                    }
                }
                cur_list_key = None;
                in_inherit_list = false;
                in_inherit_gem = false;
                in_plugins_list = false;
                in_require_list = false;
                cur_gem = None;
                // `inherit_from:` — scalar or block list of config paths
                if t == "inherit_from:" {
                    in_inherit_list = true;
                    cur = None;
                    continue;
                }
                // `inherit_gem:` — nested map of gem name -> path(s)
                if t == "inherit_gem:" {
                    in_inherit_gem = true;
                    cur = None;
                    continue;
                }
                if t == "plugins:" {
                    in_plugins_list = true;
                    cur = None;
                    continue;
                }
                if t == "require:" {
                    in_require_list = true;
                    cur = None;
                    continue;
                }
                if let Some(v) = t.strip_prefix("inherit_from:") {
                    inherits.push(v.trim().trim_matches(|c| c == '\'' || c == '"').to_string());
                    cur = None;
                    continue;
                }
                if let Some(v) = t.strip_prefix("plugins:") {
                    plugins.extend(parse_name_list(v));
                    cur = None;
                    continue;
                }
                if let Some(v) = t.strip_prefix("require:") {
                    requires.extend(parse_name_list(v));
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
            } else if in_plugins_list {
                if let Some(item) = t.strip_prefix("- ") {
                    plugins.push(yaml_unquote(item));
                }
            } else if in_require_list {
                if let Some(item) = t.strip_prefix("- ") {
                    requires.push(yaml_unquote(item));
                }
            } else if in_inherit_gem {
                if let Some(item) = t.strip_prefix("- ") {
                    if let Some((_, paths)) = cur_gem.as_ref().and_then(|g| inherit_gems.iter_mut().find(|(n, _)| n == g)) {
                        paths.push(item.trim().trim_matches(|c| c == '\'' || c == '"').to_string());
                    }
                } else if let Some((g, v)) = t.split_once(':') {
                    let g = g.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
                    let v = v.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
                    let paths = if v.is_empty() { Vec::new() } else { vec![v] };
                    cur_gem = Some(g.clone());
                    inherit_gems.push((g, paths));
                }
            } else if let Some(item) = t.strip_prefix("- ") {
                // a block-list item under the last seen key: accumulate
                // under a sentinel-delimited form that survives items
                // containing quotes (`!ruby/regexp /... ["']/`), which the
                // quoted flow form can't represent.
                if let (Some(sec), Some(key)) = (&cur, &cur_list_key) {
                    let map = sections.get_mut(sec).unwrap();
                    let item = &yaml_unquote(item);
                    let entry = map.entry(key.clone()).or_default();
                    if entry.is_empty() || entry == "[]" {
                        *entry = format!("\u{1}{item}");
                    } else if entry.starts_with('\u{1}') {
                        entry.push('\u{0}');
                        entry.push_str(item);
                    }
                }
            } else if let (Some(sec), Some((k, v))) = (&cur, t.split_once(':')) {
                // strip key quotes too — rubocop configs write per-type
                // delimiter keys as `'%w': '()'`.
                let k = k.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
                let v = v.trim().to_string();
                cur_list_key = v.is_empty().then(|| k.clone());
                sections.get_mut(sec).unwrap().insert(k, v);
            }
        }
        let all_disabled_by_default = sections
            .get("AllCops")
            .and_then(|s| s.get("DisabledByDefault"))
            .map(|v| v == "true")
            .unwrap_or(false);
        Config {
            sections,
            all_disabled_by_default,
            only: None,
            except: None,
            inherits,
            inherit_gems,
            plugins,
            requires,
        }
    }
    /// True when this config loaded rubocop-performance via `plugins:` or
    /// `require:` — the only way Performance cops exist in real RuboCop.
    pub fn performance_plugin_loaded(&self) -> bool {
        self.plugins
            .iter()
            .chain(self.requires.iter())
            .any(|s| is_performance_plugin(s))
    }
    /// Layer the loaded plugin gems' own `config/default.yml` overrides of core
    /// cops UNDER this config, the way RuboCop folds a plugin's defaults into
    /// `ConfigLoader.default_configuration` before the user's config is merged
    /// over it. Call once, after the whole `inherit_from` chain has resolved:
    /// a plugin named by an inherited file is loaded just the same.
    ///
    /// Three verified semantics (rubocop 1.86 + rubocop-rails 2.34.3 /
    /// rubocop-rspec 3.9.0, 2026-09-14):
    /// - `AllCops` values from plugins combine with each other (lists union,
    ///   scalars first-in-wins, `merge_all_cop_settings`) but a user `AllCops`
    ///   key replaces the whole plugin-augmented default.
    /// - a cop parameter the plugin marks `inherit_mode: merge:` unions with
    ///   both the core default below and the user's value above (that is how a
    ///   project's own `Metrics/BlockLength: Exclude` keeps rubocop-rspec's
    ///   `**/*_spec.rb`).
    /// - every other cop parameter replaces the core default and yields to the
    ///   user's value.
    ///
    /// `Enabled` is deliberately not carried (see `tools/gen_plugin_config.rb`),
    /// so `DisabledByDefault` needs no recomputing here.
    pub fn apply_plugin_defaults(&mut self) {
        self.apply_plugin_layer(PLUGIN_CONFIGS);
    }
    /// `apply_plugin_defaults` against an explicit table, so the fold rules can
    /// be tested on plugin combinations the installed gems don't happen to form.
    fn apply_plugin_layer(&mut self, table: &[PluginConfig]) {
        // The plugin layer, folded in `plugins:` order so "first-in wins" holds.
        let mut layer: Vec<(&'static str, &'static str, String, InheritMode)> = Vec::new();
        for name in self.plugins.iter().chain(self.requires.iter()) {
            let Some(pc) = plugin_config(table, name.trim()) else { continue };
            for &(section, key, value, mode) in pc.entries {
                let Some(slot) = layer.iter_mut().find(|(s, k, _, _)| *s == section && *k == key)
                else {
                    layer.push((section, key, value.to_string(), mode));
                    continue;
                };
                if section == "AllCops" {
                    // lists union across plugins, scalars keep the first value
                    if is_list_value(value) && is_list_value(&slot.2) {
                        slot.2 = union_list_values(&slot.2, value);
                    }
                } else if mode == InheritMode::Merge {
                    slot.2 = union_list_values(&slot.2, value);
                    slot.3 = InheritMode::Merge;
                } else {
                    slot.2 = value.to_string();
                }
            }
        }
        for (section, key, value, mode) in layer {
            let value = if mode == InheritMode::Merge {
                union_list_values(&encode_list(&schema_list(section, key)), &value)
            } else {
                value
            };
            let sec = self.sections.entry(section.to_string()).or_default();
            match sec.get(key) {
                None => {
                    sec.insert(key.to_string(), value);
                }
                Some(user) if mode == InheritMode::Merge => {
                    let merged = union_list_values(&value, user);
                    sec.insert(key.to_string(), merged);
                }
                Some(_) => {} // the user's value stands
            }
        }
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
                    } else if !v.is_empty() && v != "[]" {
                        *entry = union_list_values(entry, &v);
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
        self.inherit_gems = Vec::new();
        for p in child.plugins {
            if !self.plugins.iter().any(|e| e == &p) {
                self.plugins.push(p);
            }
        }
        for r in child.requires {
            if !self.requires.iter().any(|e| e == &r) {
                self.requires.push(r);
            }
        }
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
        // Plugin cops are absent unless the gem was loaded — even an explicit
        // `Performance/X: Enabled: true` is a no-op without `plugins:` (RuboCop
        // reports an unrecognized cop). `--only Performance/X` still wins, so
        // the oracle / parity harness can force-enable a cop the way they do
        // for core.
        if cop.starts_with("Performance/") && !self.performance_plugin_loaded() {
            return false;
        }
        self.cop_config_enabled(cop)
    }
    /// The cop's raw config-file enablement (`Config#cop_enabled?`: `for_cop(name)['Enabled']`)
    /// — unlike `enabled()`, NOT gated by CLI `--only`/`--except`. Real
    /// rubocop keeps these separate: `--only`/`--except` restrict which cops
    /// the `Team` instantiates as active investigators for the run, but a
    /// DIFFERENT cop's own logic asking "is `Layout/LineLength` enabled?"
    /// (e.g. `StatementModifier#max_line_length`) reads straight off the
    /// `Config` object and is unaffected by the run's `--only` filter.
    pub fn cop_config_enabled(&self, cop: &str) -> bool {
        match self.sections.get(cop).and_then(|s| s.get("Enabled")) {
            Some(v) => v != "false",
            None => {
                // RuboCop: a department `Enabled: false` disables every cop
                // in that department unless the cop itself sets Enabled.
                if let Some(dept) = cop.split('/').next() {
                    if dept != cop
                        && self
                            .sections
                            .get(dept)
                            .and_then(|s| s.get("Enabled"))
                            .is_some_and(|v| v == "false")
                    {
                        return false;
                    }
                }
                !self.all_disabled_by_default
            }
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
        out.push_str("plugins");
        out.push('\u{1}');
        for p in &self.plugins {
            out.push_str(p);
            out.push('\u{2}');
        }
        out.push_str("require");
        out.push('\u{1}');
        for r in &self.requires {
            out.push_str(r);
            out.push('\u{2}');
        }
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
    /// Raw AllCops lookup (user-set values only).
    pub fn get_all_cops(&self, key: &str) -> Option<&str> {
        self.sections.get("AllCops").and_then(|s| s.get(key)).map(String::as_str)
    }
    /// Inject an AllCops value (the TargetRuby detection chain writes here).
    pub fn set_all_cops(&mut self, key: &str, val: String) {
        self.sections.entry("AllCops".to_string()).or_default().insert(key.to_string(), val);
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
    /// The AllCops Include patterns (compiled), when the config sets any.
    /// rubocop UNIONS these with its defaults — they only ever add files.
    pub fn include_matchers(&self) -> Vec<regex::Regex> {
        let Some(v) = self.sections.get("AllCops").and_then(|s| s.get("Include")) else {
            return Vec::new();
        };
        parse_allowed_list(v).iter().filter_map(|p| exclude_regex(p)).collect()
    }
    /// A cop's severity name: the config's `Severity` param, else the
    /// department default (Lint & Security warn, the rest are conventions).
    pub fn severity_word(&self, cop: &str) -> &str {
        // `Lint::Syntax#find_severity` hardcodes `:fatal` — unlike every
        // other cop, its severity is NOT configurable via `Severity:`.
        if cop == "Lint/Syntax" {
            return "fatal";
        }
        if let Some(v) = self.sections.get(cop).and_then(|s| s.get("Severity")) {
            return v;
        }
        if cop.starts_with("Lint/") || cop.starts_with("Security/") {
            "warning"
        } else {
            "convention"
        }
    }
    /// The AllCops Exclude patterns, compiled once. Patterns are
    /// rubocop-style globs (`**` spans directories, `*` doesn't) or
    /// `!ruby/regexp /.../` literals.
    pub fn exclude_matchers(&self) -> Vec<regex::Regex> {
        self.section_exclude_matchers("AllCops")
    }
    /// A section's Exclude patterns (per-cop Exclude), compiled. A user
    /// Exclude REPLACES the default one (rubocop needs `inherit_mode` to
    /// merge); absent that, the schema's default Excludes apply.
    pub fn section_exclude_matchers(&self, section: &str) -> Vec<regex::Regex> {
        match self.sections.get(section).and_then(|s| s.get("Exclude")) {
            Some(v) => parse_allowed_list(v).iter().filter_map(|p| exclude_regex(p)).collect(),
            None => schema(section)
                .map(|sc| sc.excludes.iter().filter_map(|p| exclude_regex(p)).collect())
                .unwrap_or_default(),
        }
    }
    /// A section's Include patterns (per-cop Include), compiled. The
    /// generated schema doesn't carry Include arrays, so the rubocop
    /// default.yml values for filename-scoped cops (Bundler/Gemspec
    /// departments) live in DEFAULT_COP_INCLUDES; a user Include REPLACES
    /// them, mirroring section_exclude_matchers.
    pub fn section_include_matchers(&self, section: &str) -> Vec<regex::Regex> {
        match self.sections.get(section).and_then(|s| s.get("Include")) {
            Some(v) => parse_allowed_list(v).iter().filter_map(|p| exclude_regex(p)).collect(),
            None => DEFAULT_COP_INCLUDES
                .iter()
                .find(|(c, _)| *c == section)
                .map(|(_, pats)| pats.iter().filter_map(|p| exclude_regex(p)).collect())
                .unwrap_or_default(),
        }
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

/// rubocop default.yml per-cop Include globs (filename-scoped cops).
const DEFAULT_COP_INCLUDES: &[(&str, &[&str])] = &[
    ("Bundler/DuplicatedGem", &["**/*.gemfile", "**/Gemfile", "**/gems.rb"]),
    ("Bundler/DuplicatedGroup", &["**/*.gemfile", "**/Gemfile", "**/gems.rb"]),
    ("Bundler/GemFilename", &["**/Gemfile", "**/gems.rb", "**/Gemfile.lock", "**/gems.locked"]),
    ("Bundler/InsecureProtocolSource", &["**/*.gemfile", "**/Gemfile", "**/gems.rb"]),
    ("Bundler/OrderedGems", &["**/*.gemfile", "**/Gemfile", "**/gems.rb"]),
    ("Gemspec/DuplicatedAssignment", &["**/*.gemspec"]),
    ("Gemspec/OrderedDependencies", &["**/*.gemspec"]),
    ("Gemspec/RequiredRubyVersion", &["**/*.gemspec"]),
    ("Gemspec/RubyVersionGlobalsUsage", &["**/*.gemspec"]),
];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugins_scalar_loads_performance() {
        let cfg = Config::parse("plugins: rubocop-performance\n");
        assert_eq!(cfg.plugins, vec!["rubocop-performance"]);
        assert!(cfg.performance_plugin_loaded());
        assert!(cfg.enabled("Performance/ReverseEach"));
    }

    #[test]
    fn plugins_block_list_and_quoted_flow() {
        let block = Config::parse("plugins:\n  - rubocop-rspec\n  - rubocop-performance\n");
        assert!(block.performance_plugin_loaded());
        let flow = Config::parse("plugins: ['rubocop-other', 'rubocop-performance']\n");
        assert!(flow.performance_plugin_loaded());
        assert!(!Config::parse("plugins: rubocop-rspec\n").performance_plugin_loaded());
    }

    #[test]
    fn require_forms_load_performance() {
        assert!(Config::parse("require: rubocop-performance\n").performance_plugin_loaded());
        assert!(Config::parse("require: rubocop/cop/performance\n").performance_plugin_loaded());
        assert!(Config::parse("require:\n  - rubocop/performance\n").performance_plugin_loaded());
        assert!(!Config::parse("require: rubocop-rspec\n").performance_plugin_loaded());
    }

    #[test]
    fn performance_cops_stay_off_without_plugin() {
        let cfg = Config::parse("Performance/ReverseEach:\n  Enabled: true\n");
        assert!(!cfg.performance_plugin_loaded());
        assert!(!cfg.enabled("Performance/ReverseEach"));
        // core cops are unaffected
        assert!(cfg.enabled("Style/Sample"));
    }

    #[test]
    fn only_force_enables_performance_without_plugin() {
        let mut cfg = Config::parse("AllCops:\n  DisabledByDefault: true\n");
        assert!(!cfg.enabled("Performance/ReverseEach"));
        cfg.only = Some(vec!["Performance/ReverseEach".into()]);
        assert!(cfg.enabled("Performance/ReverseEach"));
        assert!(!cfg.enabled("Performance/Size"));
        cfg.only = Some(vec!["Performance".into()]);
        assert!(cfg.enabled("Performance/Size"));
    }

    #[test]
    fn except_still_wins_over_plugin() {
        let mut cfg = Config::parse("plugins: rubocop-performance\n");
        cfg.except = Some(vec!["Performance/ReverseEach".into()]);
        assert!(!cfg.enabled("Performance/ReverseEach"));
        assert!(cfg.enabled("Performance/Size"));
    }

    #[test]
    fn inherit_merge_unions_plugins() {
        let mut base = Config::parse("plugins: rubocop-rspec\n");
        base.merge_child(Config::parse("plugins:\n  - rubocop-performance\n"));
        assert!(base.performance_plugin_loaded());
        assert_eq!(base.plugins.len(), 2);
    }

    #[test]
    fn disabled_by_default_still_applies_with_plugin() {
        let cfg = Config::parse(
            "plugins: rubocop-performance\nAllCops:\n  DisabledByDefault: true\n",
        );
        assert!(cfg.performance_plugin_loaded());
        assert!(!cfg.enabled("Performance/ReverseEach"));
        let cfg = Config::parse(
            "plugins: rubocop-performance\nAllCops:\n  DisabledByDefault: true\n\
             Performance/ReverseEach:\n  Enabled: true\n",
        );
        assert!(cfg.enabled("Performance/ReverseEach"));
        assert!(!cfg.enabled("Performance/Size"));
    }

    /// A config with the plugin layer already folded in, as the runner builds it.
    fn with_plugins(text: &str) -> Config {
        let mut cfg = Config::parse(text);
        cfg.apply_plugin_defaults();
        cfg
    }
    fn excluded(cfg: &Config, section: &str, path: &str) -> bool {
        cfg.section_exclude_matchers(section).iter().any(|re| re.is_match(path))
    }

    #[test]
    fn plugin_defaults_are_off_without_the_plugin() {
        let cfg = with_plugins("AllCops:\n  DisabledByDefault: true\n");
        assert!(!excluded(&cfg, "Metrics/BlockLength", "spec/models/user_spec.rb"));
        assert!(!excluded(&cfg, "Lint/UselessMethodDefinition", "app/controllers/x_controller.rb"));
        assert!(!cfg.active_support());
        // nothing written into the sections: cops read the core defaults out of
        // the SCHEMA (`Engine::new` seeds AllowedMethods from there)
        assert!(cfg.get("Lint/SafeNavigationChain", "AllowedMethods").is_none());
        assert!(cfg.get("Style/SymbolProc", "AllowedMethods").is_none());
    }

    #[test]
    fn rspec_plugin_excludes_block_length_in_specs() {
        let cfg = with_plugins("plugins: rubocop-rspec\n");
        assert!(excluded(&cfg, "Metrics/BlockLength", "spec/models/user_spec.rb"));
        assert!(excluded(&cfg, "Metrics/BlockLength", "spec/support/helper.rb"));
        // the core default (`**/*.gemspec`) survives the merge
        assert!(excluded(&cfg, "Metrics/BlockLength", "oxidecop.gemspec"));
        assert!(!excluded(&cfg, "Metrics/BlockLength", "app/models/user.rb"));
    }

    #[test]
    fn merge_mode_unions_the_users_own_exclude() {
        // rubocop keeps the plugin's globs because the plugin default.yml marks
        // Exclude `inherit_mode: merge:` — a user Exclude adds to them.
        let cfg = with_plugins("plugins: rubocop-rspec\nMetrics/BlockLength:\n  Exclude:\n    - config/routes.rb\n");
        assert!(excluded(&cfg, "Metrics/BlockLength", "config/routes.rb"));
        assert!(excluded(&cfg, "Metrics/BlockLength", "spec/models/user_spec.rb"));
        assert!(excluded(&cfg, "Metrics/BlockLength", "oxidecop.gemspec"));
    }

    #[test]
    fn rails_plugin_sets_active_support_and_core_params() {
        let cfg = with_plugins("plugins:\n  - rubocop-rails\n  - rubocop-rspec\n");
        assert!(cfg.active_support());
        let chain = parse_allowed_list(cfg.get("Lint/SafeNavigationChain", "AllowedMethods").unwrap());
        assert!(chain.contains(&"presence_in".to_string()));
        assert!(excluded(&cfg, "Lint/UselessMethodDefinition", "app/controllers/x_controller.rb"));
        assert!(excluded(&cfg, "Lint/UselessMethodDefinition", "engines/a/app/mailers/x_mailer.rb"));
        assert!(!excluded(&cfg, "Lint/UselessMethodDefinition", "app/models/user.rb"));
        let allowed = parse_allowed_list(cfg.get("Style/SymbolProc", "AllowedMethods").unwrap());
        assert!(allowed.contains(&"mail".to_string()));
        assert!(allowed.contains(&"define_method".to_string()));
        // both gems' entries land, and the rspec one still merges
        assert!(excluded(&cfg, "Metrics/BlockLength", "spec/models/user_spec.rb"));
    }

    #[test]
    fn require_form_loads_a_plugins_defaults() {
        assert!(with_plugins("require: rubocop-rails\n").active_support());
        assert!(with_plugins("require:\n  - rubocop/rails\n").active_support());
        assert!(!with_plugins("require: rubocop-performance\n").active_support());
    }

    #[test]
    fn the_user_config_overrides_a_plugin_default() {
        // Override-mode params: the user's value replaces the plugin's outright.
        let cfg = with_plugins(
            "plugins: rubocop-rails\nAllCops:\n  ActiveSupportExtensionsEnabled: false\n\
             Style/SymbolProc:\n  AllowedMethods:\n    - only_mine\n",
        );
        assert!(!cfg.active_support());
        assert_eq!(
            parse_allowed_list(cfg.get("Style/SymbolProc", "AllowedMethods").unwrap()),
            vec!["only_mine".to_string()]
        );
    }

    #[test]
    fn a_user_all_cops_exclude_replaces_the_plugin_augmented_default() {
        // Verified against rubocop: AllCops Exclude has no merge inherit_mode,
        // so a project that sets one loses rubocop-rails' bin/*, log/**/* …
        let cfg = with_plugins("plugins: rubocop-rails\n");
        assert!(excluded(&cfg, "AllCops", "bin/setup"));
        assert!(excluded(&cfg, "AllCops", "db/structure_schema.rb"));
        let cfg = with_plugins("plugins: rubocop-rails\nAllCops:\n  Exclude:\n    - node_modules/**/*\n");
        assert!(!excluded(&cfg, "AllCops", "bin/setup"));
        assert!(excluded(&cfg, "AllCops", "node_modules/a/b.rb"));
    }

    #[test]
    fn context_creating_methods_merge_with_the_users_list() {
        let cfg = with_plugins(
            "plugins: rubocop-rails\nLint/UselessAccessModifier:\n  ContextCreatingMethods:\n    - my_dsl\n",
        );
        let got = parse_allowed_list(cfg.get("Lint/UselessAccessModifier", "ContextCreatingMethods").unwrap());
        assert!(got.contains(&"concerning".to_string()));
        assert!(got.contains(&"my_dsl".to_string()));
    }

    #[test]
    fn inherited_block_list_excludes_union() {
        // Both sides in the block-list accumulator form (what a real
        // .rubocop.yml writes) — the child's globs must survive the merge.
        let mut base = Config::parse("AllCops:\n  Exclude:\n    - vendor/**/*\n");
        base.merge_child(Config::parse("AllCops:\n  Exclude:\n    - tmp/**/*\n"));
        assert!(excluded(&base, "AllCops", "vendor/bundle/x.rb"));
        assert!(excluded(&base, "AllCops", "tmp/cache/x.rb"));
    }

    #[test]
    fn plugins_from_an_inherited_config_still_apply() {
        let mut base = Config::parse("plugins: rubocop-rspec\n");
        base.merge_child(Config::parse("Metrics/BlockLength:\n  Max: 40\n"));
        base.apply_plugin_defaults();
        assert!(excluded(&base, "Metrics/BlockLength", "spec/models/user_spec.rb"));
    }

    #[test]
    fn applying_the_plugin_layer_twice_is_idempotent() {
        // The runner calls it once per config, but a merge-mode union that ran
        // twice would silently double a list; assert it can't.
        let once = with_plugins("plugins:\n  - rubocop-rails\n  - rubocop-rspec\n");
        let mut twice = with_plugins("plugins:\n  - rubocop-rails\n  - rubocop-rspec\n");
        twice.apply_plugin_defaults();
        assert_eq!(once.identity(), twice.identity());
    }

    #[test]
    fn flow_sequence_plugins_load_every_gem() {
        let cfg = with_plugins("plugins: [rubocop-rails, rubocop-rspec]\n");
        assert!(cfg.active_support());
        assert!(excluded(&cfg, "Metrics/BlockLength", "spec/models/user_spec.rb"));
        // a bare comma list is a plain YAML scalar, not a sequence — rubocop
        // would fail to require it, and we must not read it as two gems
        assert!(!with_plugins("plugins: rubocop-rails, rubocop-rspec\n").active_support());
    }

    #[test]
    fn plugins_declared_by_the_child_config_apply() {
        // The inverse of plugins_from_an_inherited_config_still_apply: the base
        // is the inherited file and the project's own config names the gem.
        let mut base = Config::parse("Metrics/BlockLength:\n  Max: 40\n");
        base.merge_child(Config::parse("plugins: rubocop-rspec\n"));
        base.apply_plugin_defaults();
        assert!(excluded(&base, "Metrics/BlockLength", "spec/models/user_spec.rb"));
    }

    #[test]
    fn merge_child_takes_the_childs_exclude_when_the_base_has_none() {
        let mut base = Config::parse("Metrics/BlockLength:\n  Max: 40\n");
        base.merge_child(Config::parse("Metrics/BlockLength:\n  Exclude:\n    - tmp/**/*\n"));
        assert!(excluded(&base, "Metrics/BlockLength", "tmp/a.rb"));
        // and an empty child list must not wipe the base's globs
        let mut base = Config::parse("AllCops:\n  Exclude:\n    - vendor/**/*\n");
        base.merge_child(Config::parse("AllCops:\n  Exclude: []\n"));
        assert!(excluded(&base, "AllCops", "vendor/bundle/x.rb"));
    }

    #[test]
    fn union_list_values_dedupes_and_keeps_base_order() {
        let got = parse_allowed_list(&union_list_values(
            &encode_list(&["a".into(), "b".into()]),
            "['b', 'c']",
        ));
        assert_eq!(got, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        // an empty side on either end contributes nothing
        assert_eq!(parse_allowed_list(&union_list_values("[]", "['a']")), vec!["a".to_string()]);
        assert_eq!(parse_allowed_list(&union_list_values("['a']", "[]")), vec!["a".to_string()]);
    }

    #[test]
    fn encoded_lists_survive_items_holding_quotes() {
        // Why the accumulator form and not the flow form: rubocop configs really
        // do exclude paths through `!ruby/regexp` patterns containing quotes.
        let items = vec!["a's.rb".to_string(), "\"b\".rb".to_string()];
        assert_eq!(parse_allowed_list(&encode_list(&items)), items);
    }

    // A synthetic table: the installed gems never both configure the same key,
    // so the cross-plugin fold rules need combinations only a fixture can form.
    const FAKE_PLUGINS: &[PluginConfig] = &[
        PluginConfig {
            names: &["fake-one"],
            entries: &[
                ("AllCops", "Exclude", "['one/**/*']", InheritMode::Override),
                ("AllCops", "TargetRubyVersion", "3.1", InheritMode::Override),
                ("Metrics/BlockLength", "Exclude", "['one_spec.rb']", InheritMode::Merge),
                ("Style/AndOr", "EnforcedStyle", "always", InheritMode::Override),
            ],
        },
        PluginConfig {
            names: &["fake-two"],
            entries: &[
                ("AllCops", "Exclude", "['two/**/*', 'one/**/*']", InheritMode::Override),
                ("AllCops", "TargetRubyVersion", "3.4", InheritMode::Override),
                ("Metrics/BlockLength", "Exclude", "['two_spec.rb']", InheritMode::Merge),
                ("Style/AndOr", "EnforcedStyle", "conditionals", InheritMode::Override),
            ],
        },
    ];

    fn with_fake_plugins(text: &str) -> Config {
        let mut cfg = Config::parse(text);
        cfg.apply_plugin_layer(FAKE_PLUGINS);
        cfg
    }

    #[test]
    fn all_cops_lists_union_across_plugins() {
        let cfg = with_fake_plugins("plugins:\n  - fake-one\n  - fake-two\n");
        assert!(excluded(&cfg, "AllCops", "one/a.rb"));
        assert!(excluded(&cfg, "AllCops", "two/a.rb"));
        assert_eq!(
            parse_allowed_list(cfg.get("AllCops", "Exclude").unwrap()),
            vec!["one/**/*".to_string(), "two/**/*".to_string()]
        );
    }

    #[test]
    fn all_cops_scalars_keep_the_first_plugins_value() {
        // rubocop's merge_all_cop_settings is first-in-wins for scalars, so the
        // order of `plugins:` decides — assert both directions.
        let cfg = with_fake_plugins("plugins:\n  - fake-one\n  - fake-two\n");
        assert_eq!(cfg.get("AllCops", "TargetRubyVersion"), Some("3.1"));
        let cfg = with_fake_plugins("plugins:\n  - fake-two\n  - fake-one\n");
        assert_eq!(cfg.get("AllCops", "TargetRubyVersion"), Some("3.4"));
    }

    #[test]
    fn merge_mode_params_union_across_plugins_and_with_the_core_default() {
        let cfg = with_fake_plugins("plugins:\n  - fake-one\n  - fake-two\n");
        let got = parse_allowed_list(cfg.get("Metrics/BlockLength", "Exclude").unwrap());
        assert!(got.contains(&"one_spec.rb".to_string()));
        assert!(got.contains(&"two_spec.rb".to_string()));
        assert!(got.contains(&"**/*.gemspec".to_string()), "core default lost: {got:?}");
    }

    #[test]
    fn override_params_let_the_last_plugin_win() {
        // Not AllCops, so merge_all_cop_settings does not apply: a later plugin
        // simply overwrites the earlier one in the default layer.
        let cfg = with_fake_plugins("plugins:\n  - fake-one\n  - fake-two\n");
        assert_eq!(cfg.get("Style/AndOr", "EnforcedStyle"), Some("conditionals"));
        let cfg = with_fake_plugins("plugins:\n  - fake-two\n  - fake-one\n");
        assert_eq!(cfg.get("Style/AndOr", "EnforcedStyle"), Some("always"));
    }

    #[test]
    fn generated_plugin_configs_stay_within_core() {
        // Guards a regeneration: tools/gen_plugin_config.rb must keep the table
        // to AllCops plus core departments, and must never carry `Enabled`.
        const CORE: &[&str] = &[
            "Bundler", "Gemspec", "Layout", "Lint", "Metrics", "Migration", "Naming", "Security",
            "Style",
        ];
        for pc in PLUGIN_CONFIGS {
            assert!(pc.names[0].starts_with("rubocop-"), "{:?}", pc.names);
            assert!(!pc.entries.is_empty(), "{} has no entries", pc.names[0]);
            let mut seen: Vec<(&str, &str)> = Vec::new();
            for &(section, key, value, mode) in pc.entries {
                assert!(
                    section == "AllCops" || CORE.contains(&section.split('/').next().unwrap()),
                    "{section} is not core"
                );
                assert_ne!(key, "Enabled", "{section} carries Enabled");
                assert!(seen.iter().all(|s| *s != (section, key)), "duplicate {section} {key}");
                assert!(
                    mode == InheritMode::Override || is_list_value(value),
                    "{section} {key} merges a non-list value"
                );
                seen.push((section, key));
            }
        }
    }

    #[test]
    fn department_enabled_false_disables_plugin_cops() {
        let cfg = Config::parse(
            "plugins: rubocop-performance\nPerformance:\n  Enabled: false\n",
        );
        assert!(cfg.performance_plugin_loaded());
        assert!(!cfg.enabled("Performance/ReverseEach"));
        assert!(!cfg.enabled("Performance/Size"));
        assert!(cfg.enabled("Style/Sample"));
    }

    #[test]
    fn department_enabled_false_allows_per_cop_override() {
        let cfg = Config::parse(
            "plugins: rubocop-performance\nPerformance:\n  Enabled: false\n\
             Performance/ReverseEach:\n  Enabled: true\n",
        );
        assert!(cfg.enabled("Performance/ReverseEach"));
        assert!(!cfg.enabled("Performance/Size"));
    }

    #[test]
    fn only_still_wins_over_department_enabled_false() {
        let mut cfg = Config::parse(
            "plugins: rubocop-performance\nPerformance:\n  Enabled: false\n",
        );
        cfg.only = Some(vec!["Performance/Size".into()]);
        assert!(cfg.enabled("Performance/Size"));
        assert!(!cfg.enabled("Performance/ReverseEach"));
    }

    #[test]
    fn identity_includes_plugin_load() {
        let a = Config::parse("Style/Sample:\n  Enabled: true\n");
        let b = Config::parse("plugins: rubocop-performance\nStyle/Sample:\n  Enabled: true\n");
        assert_ne!(a.identity(), b.identity());
    }
}
