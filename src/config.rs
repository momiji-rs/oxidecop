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
}
impl Config {
    pub fn parse(text: &str) -> Self {
        let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut cur: Option<String> = None;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or(""); // strip comments
            if line.trim().is_empty() {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let t = line.trim();
            if !indented {
                // top-level "Section:" (may also be "Section: value" — ignore value)
                if let Some(name) = t.strip_suffix(':') {
                    cur = Some(name.to_string());
                    sections.entry(name.to_string()).or_default();
                } else if let Some((k, _)) = t.split_once(':') {
                    cur = Some(k.trim().to_string());
                    sections.entry(k.trim().to_string()).or_default();
                }
            } else if let (Some(sec), Some((k, v))) = (&cur, t.split_once(':')) {
                sections
                    .get_mut(sec)
                    .unwrap()
                    .insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        let all_disabled_by_default = sections
            .get("AllCops")
            .and_then(|s| s.get("DisabledByDefault"))
            .map(|v| v == "true")
            .unwrap_or(false);
        Config { sections, all_disabled_by_default }
    }
    pub fn enabled(&self, cop: &str) -> bool {
        match self.sections.get(cop).and_then(|s| s.get("Enabled")) {
            Some(v) => v != "false",
            None => !self.all_disabled_by_default,
        }
    }
    pub fn param(&self, cop: &str, key: &str) -> Option<&str> {
        self.sections.get(cop).and_then(|s| s.get(key)).map(|s| s.as_str())
    }
    /// Resolved value: user config if present, else the SCHEMA default.
    pub fn get(&self, cop: &str, key: &str) -> Option<&str> {
        self.param(cop, key).or_else(|| schema_default(cop, key))
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
