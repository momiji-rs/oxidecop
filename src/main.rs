//! rubocop-rs — a fast, native RuboCop-compatible Ruby linter over the Prism
//! AST. Pattern cops are DATA (see the DECLARATIVE table + `nodepattern`);
//! imperative cops are small `Visit` methods. Fidelity is measured against
//! RuboCop's own spec suite via the `oracle/` harness. See README.md.
mod nodepattern;
use nodepattern::Pat;
use ruby_prism::Visit;
use std::collections::HashMap;

/// DECLARATIVE cops — pure DATA: (node-pattern, cop name, message, anchor).
/// This is the whole point of the node-pattern engine: ~266 of rubocop's cops
/// are shaped exactly like this, so porting them is transcription, not coding.
/// `anchor` is the one bit NOT derivable from the pattern — where rubocop's
/// `add_offense` points (matched-node start vs. the send operator/selector).
/// A declarative cop row. The optional last field is an `EnforcedStyle` gate:
/// `Some("comparison")` means the row only fires when the cop's active style is
/// `comparison` (resolved via the SCHEMA); `None` means style-agnostic. This is
/// how one pattern cop expresses multiple styles as data — no imperative branch.
const DECLARATIVE: &[(&str, &str, &str, Anchor, Option<&str>)] = &[
    // NilComparison. Two styles, two rows, gated on EnforcedStyle. Verbatim msgs.
    ("(send _ {:== :===} (nil))", "Style/NilComparison", "Prefer the use of the `nil?` predicate.", Anchor::Op, Some("predicate")),
    ("(send (...) :nil?)", "Style/NilComparison", "Prefer the use of the `==` comparison.", Anchor::Op, Some("comparison")),

    // ZeroLengthPredicate — `empty?` (zero-length) shapes. The `${:size :length}`
    // captures the method so the message interpolates it, exactly like rubocop.
    ("(send (send (...) ${:size :length}) :== (int 0))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `{} == 0`.", Anchor::Node, None),
    ("(send (int 0) :== (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `0 == {}`.", Anchor::Node, None),
    ("(send (send (...) ${:size :length}) :< (int 1))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `{} < 1`.", Anchor::Node, None),
    ("(send (int 1) :> (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `1 > {}`.", Anchor::Node, None),
    ("(send (send (...) ${:size :length}) :zero?)", "Style/ZeroLengthPredicate", "Use `empty?` instead of `{}.zero?`.", Anchor::RecvOp, None),
    // ZeroLengthPredicate — `!empty?` (nonzero-length) shapes.
    ("(send (send (...) ${:size :length}) :> (int 0))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `{} > 0`.", Anchor::Node, None),
    ("(send (int 0) :< (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `0 < {}`.", Anchor::Node, None),
    ("(send (send (...) ${:size :length}) :!= (int 0))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `{} != 0`.", Anchor::Node, None),
    ("(send (int 0) :!= (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `0 != {}`.", Anchor::Node, None),
];

/// Where a declarative offense points. Per-cop metadata, since rubocop's cops
/// pass different nodes to `add_offense`.
#[derive(Clone, Copy)]
enum Anchor {
    Node,   // start of the whole matched node (the default `add_offense(node)`)
    Op,     // the call's operator/selector (`node.loc.selector`)
    RecvOp, // the receiver-call's selector (e.g. the `.length` in `x.length.zero?`)
}

/// Substitute `{}` placeholders in a message template with captures, in order.
fn render(template: &str, caps: &[String]) -> String {
    let mut out = String::new();
    let mut it = caps.iter();
    let mut rest = template;
    while let Some(pos) = rest.find("{}") {
        out.push_str(&rest[..pos]);
        out.push_str(it.next().map(|s| s.as_str()).unwrap_or("{}"));
        rest = &rest[pos + 2..];
    }
    out.push_str(rest);
    out
}

// ---------------- config SCHEMA (single source of truth) ----------------
/// Per-cop config schema: parameter defaults and (for style cops) the supported
/// `EnforcedStyle`s + default. This mirrors the relevant slice of rubocop's
/// `config/default.yml` and is the ONE place defaults live — no default literals
/// scattered at call sites, EnforcedStyle resolution/validation in one spot.
/// Ideally generated from rubocop's own `config/default.yml` (see roadmap).
struct Schema {
    cop: &'static str,
    /// (param, default-as-string). For style cops, includes `EnforcedStyle`.
    params: &'static [(&'static str, &'static str)],
    /// SupportedStyles — used to validate a configured `EnforcedStyle`.
    styles: &'static [&'static str],
}
const SCHEMA: &[Schema] = &[
    Schema { cop: "Layout/LineLength", params: &[("Max", "120")], styles: &[] },
    Schema { cop: "Style/NumericLiterals", params: &[("MinDigits", "5")], styles: &[] },
    Schema { cop: "Layout/TrailingWhitespace", params: &[("AllowInHeredoc", "false")], styles: &[] },
    Schema { cop: "Style/StringLiterals", params: &[("EnforcedStyle", "single_quotes")],
             styles: &["single_quotes", "double_quotes"] },
    Schema { cop: "Style/NilComparison", params: &[("EnforcedStyle", "predicate")],
             styles: &["predicate", "comparison"] },
    Schema { cop: "Style/NumericPredicate", params: &[("EnforcedStyle", "predicate")],
             styles: &["predicate", "comparison"] },
    Schema { cop: "Naming/MethodName", params: &[("EnforcedStyle", "snake_case")],
             styles: &["snake_case", "camelCase"] },
];
fn schema(cop: &str) -> Option<&'static Schema> {
    SCHEMA.iter().find(|s| s.cop == cop)
}
fn schema_default(cop: &str, key: &str) -> Option<&'static str> {
    schema(cop).and_then(|s| s.params.iter().find(|(k, _)| *k == key).map(|(_, v)| *v))
}

/// Parse a YAML flow sequence of patterns (`['\Afoo\z', '^\s*bar']`) into their
/// raw regex sources. Quote-aware so commas inside quotes aren't split points.
/// This backs the cross-cutting `AllowedPatterns` config (see `Cops::allowed`).
fn parse_allowed_list(s: &str) -> Vec<String> {
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
struct Config {
    // cop/section name -> { key -> value }
    sections: HashMap<String, HashMap<String, String>>,
    all_disabled_by_default: bool,
}
impl Config {
    fn parse(text: &str) -> Self {
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
    fn enabled(&self, cop: &str) -> bool {
        match self.sections.get(cop).and_then(|s| s.get("Enabled")) {
            Some(v) => v != "false",
            None => !self.all_disabled_by_default,
        }
    }
    fn param(&self, cop: &str, key: &str) -> Option<&str> {
        self.sections.get(cop).and_then(|s| s.get(key)).map(|s| s.as_str())
    }
    /// Resolved value: user config if present, else the SCHEMA default.
    fn get(&self, cop: &str, key: &str) -> Option<&str> {
        self.param(cop, key).or_else(|| schema_default(cop, key))
    }
    fn int(&self, cop: &str, key: &str) -> usize {
        self.get(cop, key).and_then(|v| v.parse().ok()).unwrap_or(0)
    }
    /// The active `EnforcedStyle`: the configured value if it's a supported
    /// style, otherwise the schema default. One place for style resolution.
    fn enforced_style(&self, cop: &str) -> &str {
        let default = schema_default(cop, "EnforcedStyle").unwrap_or("");
        match self.param(cop, "EnforcedStyle") {
            Some(v) if schema(cop).map(|s| s.styles.contains(&v)).unwrap_or(false) => v,
            _ => default,
        }
    }
}

// ---------------- offense + line index ----------------
struct Offense {
    line: usize,
    col: usize,
    cop: &'static str,
    correctable: bool,
    message: String,
}
struct LineIndex {
    starts: Vec<usize>,
}
impl LineIndex {
    fn new(src: &[u8]) -> Self {
        let mut starts = vec![0usize];
        for (i, &b) in src.iter().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineIndex { starts }
    }
    fn loc(&self, off: usize) -> (usize, usize) {
        let line = match self.starts.binary_search(&off) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (line + 1, off - self.starts[line] + 1)
    }
}

struct Cops<'a> {
    src: &'a [u8],
    idx: &'a LineIndex,
    cfg: &'a Config,
    comment_lines: std::collections::HashSet<usize>,
    offenses: Vec<Offense>,
    // autocorrect edits: (start_byte, end_byte, replacement). Applied
    // right-to-left so earlier offsets stay valid — exactly how rubocop's
    // Corrector composes source rewrites off the AST source-ranges.
    fixes: Vec<(usize, usize, Vec<u8>)>,
    // DECLARATIVE cops: (parsed pattern, cop name, message). Built once from
    // the DECLARATIVE table — the cop "logic" is entirely in the pattern.
    decl: Vec<(Pat, &'static str, &'static str, Anchor, Option<&'static str>)>,
    // Cross-cutting exemptions, mirroring rubocop's `AllowedMethods` mixin: a cop
    // consults `allowed(cop, text)` to suppress an offense whose relevant string
    // (a method name, a source line, …) is either an exact `AllowedMethods` entry
    // or matches an `AllowedPatterns` regex.
    allowed: HashMap<String, Vec<regex::Regex>>,
    allowed_methods: HashMap<String, Vec<String>>,
    // Enclosing call/block method names (outermost first), maintained around the
    // manual recursion in `visit_call_node`. Lets cops consult ancestors (e.g.
    // Style/NumericPredicate's AllowedMethods on a wrapping `where(...)`, and its
    // `!x.zero?` negation) without a parent pointer.
    call_stack: Vec<Vec<u8>>,
    // Ancestor counters for Lint/NestedMethodDefinition: how many enclosing
    // `def`s, and how many enclosing "scoping" blocks/sclass (Class.new,
    // instance_eval, class << self, AllowedMethods, …). A nested def is an
    // offense iff def_depth >= 1 and scoping_depth == 0.
    def_depth: usize,
    scoping_depth: usize,
}
impl<'a> Cops<'a> {
    fn on(&self, cop: &str) -> bool {
        self.cfg.enabled(cop)
    }
    /// Is `text` exempt for `cop` via AllowedMethods (exact) or AllowedPatterns?
    fn allowed(&self, cop: &str, text: &[u8]) -> bool {
        let s = String::from_utf8_lossy(text);
        let by_name = self
            .allowed_methods
            .get(cop)
            .is_some_and(|names| names.iter().any(|n| n.as_bytes() == text));
        let by_pattern = self
            .allowed
            .get(cop)
            .is_some_and(|pats| pats.iter().any(|re| re.is_match(&s)));
        by_name || by_pattern
    }
    fn push(&mut self, off: usize, cop: &'static str, correctable: bool, msg: impl Into<String>) {
        let (line, col) = self.idx.loc(off);
        self.offenses.push(Offense { line, col, cop, correctable, message: msg.into() });
    }
    fn node_src(&self, n: &ruby_prism::Node) -> &'a [u8] {
        let l = n.location();
        &self.src[l.start_offset()..l.end_offset()]
    }
    /// Style/NumericPredicate: under `predicate` style flag `x {==,>,<} 0` (and
    /// inverted) → suggest `x.zero?/positive?/negative?`; under `comparison`
    /// style flag those predicates → suggest the comparison. Returns the offense
    /// (whole-node offset, rendered message) or None. Verbatim rubocop logic.
    fn numeric_predicate(&self, node: &ruby_prism::CallNode) -> Option<(usize, String)> {
        if !self.on("Style/NumericPredicate") {
            return None;
        }
        let name = node.name().as_slice();
        // AllowedMethods/Patterns: the offending method OR any ancestor call/block.
        if self.allowed("Style/NumericPredicate", name)
            || self.call_stack.iter().any(|n| self.allowed("Style/NumericPredicate", n))
        {
            return None;
        }
        let recv = node.receiver();
        let args: Vec<ruby_prism::Node> =
            node.arguments().map(|a| a.arguments().iter().collect()).unwrap_or_default();
        let node_off = node.location().start_offset();
        let current = String::from_utf8_lossy(self.node_src(&node.as_node())).into_owned();

        let prefer = match self.cfg.enforced_style("Style/NumericPredicate") {
            "comparison" => {
                // flag `x.zero?/positive?/negative?` (receiver, no args)
                let r = recv?;
                if !args.is_empty() {
                    return None;
                }
                let op = match name {
                    b"zero?" => "==",
                    b"positive?" => ">",
                    b"negative?" => "<",
                    _ => return None,
                };
                let rsrc = String::from_utf8_lossy(self.node_src(&r));
                let negated = self.call_stack.last().is_some_and(|n| n.as_slice() == b"!");
                if negated {
                    format!("({rsrc} {op} 0)")
                } else {
                    format!("{rsrc} {op} 0")
                }
            }
            _ => {
                // predicate style: flag `x {==,>,<} 0` and the inverted `0 {..} x`
                if args.len() != 1 {
                    return None;
                }
                let op: &[u8] = match name {
                    b"==" => b"==",
                    b">" => b">",
                    b"<" => b"<",
                    _ => return None,
                };
                let r = recv?;
                let arg = &args[0];
                if is_int_zero(arg, self.src) && !is_gvar(&r) {
                    format!("{}.{}", paren_src(&r, self.src), predicate_for(op, false))
                } else if is_int_zero(&r, self.src) && !is_gvar(arg) {
                    format!("{}.{}", paren_src(arg, self.src), predicate_for(op, true))
                } else {
                    return None;
                }
            }
        };
        Some((node_off, format!("Use `{prefer}` instead of `{current}`.")))
    }
    fn check_documentation(&mut self, start_off: usize, kind: &str, name: &ruby_prism::Node) {
        if !self.on("Style/Documentation") {
            return;
        }
        let (line, _) = self.idx.loc(start_off);
        if !self.comment_lines.contains(&(line.wrapping_sub(1))) {
            let nm = String::from_utf8_lossy(self.node_src(name)).to_string();
            self.push(start_off, "Style/Documentation", false,
                format!("Missing top-level documentation comment for `{kind} {nm}`."));
        }
    }
}

/// Strip a trailing `?`/`!`/`=` (predicate/bang/setter) from a method name.
fn name_core(s: &[u8]) -> &[u8] {
    match s.last() {
        Some(b'?') | Some(b'!') | Some(b'=') => &s[..s.len() - 1],
        _ => s,
    }
}
fn is_snake_case(s: &[u8]) -> bool {
    !name_core(s).iter().any(|&c| c.is_ascii_uppercase())
}
fn is_camel_case(s: &[u8]) -> bool {
    // camelCase: no underscores, and doesn't start with an uppercase letter.
    let core = name_core(s);
    !core.contains(&b'_') && core.first().map(|&c| !c.is_ascii_uppercase()).unwrap_or(true)
}
/// Does `name` conform to the active `Naming/MethodName` EnforcedStyle?
fn name_matches_style(name: &[u8], style: &str) -> bool {
    match style {
        "camelCase" => is_camel_case(name),
        _ => is_snake_case(name),
    }
}
// ---- Style/NumericPredicate helpers ----
fn is_int_zero(node: &ruby_prism::Node, src: &[u8]) -> bool {
    node.as_integer_node()
        .map(|i| {
            let l = i.location();
            &src[l.start_offset()..l.end_offset()] == b"0"
        })
        .unwrap_or(false)
}
fn is_gvar(node: &ruby_prism::Node) -> bool {
    node.as_global_variable_read_node().is_some()
}
/// A binary-operator send like `foo - 1` (operator name + receiver + one arg).
fn is_binary_op(node: &ruby_prism::Node) -> bool {
    node.as_call_node()
        .map(|c| {
            c.receiver().is_some()
                && c.arguments().map(|a| a.arguments().iter().count()).unwrap_or(0) == 1
                && c.name().as_slice().first().is_some_and(|b| !b.is_ascii_alphanumeric() && *b != b'_')
        })
        .unwrap_or(false)
}
/// rubocop's `parenthesized_source`: wrap a bare binary operation in parens.
fn paren_src(node: &ruby_prism::Node, src: &[u8]) -> String {
    let l = node.location();
    let s = String::from_utf8_lossy(&src[l.start_offset()..l.end_offset()]);
    if is_binary_op(node) {
        format!("({s})")
    } else {
        s.into_owned()
    }
}
/// The predicate for a comparison operator (`==`→zero?, `>`→positive?, `<`→
/// negative?); when `inverted` (e.g. `0 < x`), `>`/`<` swap first.
fn predicate_for(op: &[u8], inverted: bool) -> &'static str {
    let eff: &[u8] = if inverted {
        match op {
            b">" => b"<",
            b"<" => b">",
            o => o,
        }
    } else {
        op
    };
    match eff {
        b"==" => "zero?",
        b">" => "positive?",
        b"<" => "negative?",
        _ => "",
    }
}

// ---- Lint/NestedMethodDefinition helpers: is this block "scoping"? ----
fn is_eval_exec(node: &ruby_prism::CallNode) -> bool {
    matches!(
        node.name().as_slice(),
        b"instance_eval" | b"class_eval" | b"module_eval" | b"instance_exec" | b"class_exec" | b"module_exec"
    )
}
/// `Class.new` / `Module.new` / `Struct.new` / `Data.define` (incl. `::`-prefixed).
fn is_class_constructor(node: &ruby_prism::CallNode, src: &[u8]) -> bool {
    let Some(r) = node.receiver() else { return false };
    let l = r.location();
    let recv = &src[l.start_offset()..l.end_offset()];
    match node.name().as_slice() {
        b"new" => matches!(recv, b"Class" | b"::Class" | b"Module" | b"::Module" | b"Struct" | b"::Struct"),
        b"define" => matches!(recv, b"Data" | b"::Data"),
        _ => false,
    }
}

/// A method name introduced by a macro argument (attr/alias_method/Struct member):
/// the arg must be a plain symbol or string literal (interpolated ones are
/// skipped). Returns (name bytes, offense anchor = the argument's start offset).
fn method_name_arg<'a>(arg: &ruby_prism::Node, src: &'a [u8]) -> Option<(&'a [u8], usize)> {
    if let Some(sym) = arg.as_symbol_node() {
        let v = sym.value_loc()?;
        Some((&src[v.start_offset()..v.end_offset()], arg.location().start_offset()))
    } else if let Some(st) = arg.as_string_node() {
        let c = st.content_loc();
        Some((&src[c.start_offset()..c.end_offset()], arg.location().start_offset()))
    } else {
        None
    }
}

impl<'pr, 'a> Visit<'pr> for Cops<'a> {
    fn visit_string_node(&mut self, node: &ruby_prism::StringNode<'pr>) {
        if self.on("Style/StringLiterals") {
            if let Some(open) = node.opening_loc() {
                let c = node.content_loc().as_slice();
                let l = node.location();
                // Dispatch on the active EnforcedStyle — resolved once, from the
                // config SCHEMA (see `Config::enforced_style`). Heredocs / %-literals
                // have other openings and fall through untouched.
                match self.cfg.enforced_style("Style/StringLiterals") {
                    // Prefer single quotes: a double-quoted string with no `'` and
                    // no `\` in its content could be single-quoted losslessly.
                    "single_quotes" if open.as_slice() == b"\"" => {
                        if !c.contains(&b'\'') && !c.contains(&b'\\') {
                            self.push(l.start_offset(), "Style/StringLiterals", true,
                                "Prefer single-quoted strings when you don't need string interpolation or special symbols.");
                            // fix: `"c"` -> `'c'`
                            let mut rep = vec![b'\''];
                            rep.extend_from_slice(c);
                            rep.push(b'\'');
                            self.fixes.push((l.start_offset(), l.end_offset(), rep));
                        }
                    }
                    // Prefer double quotes: a single-quoted string is an offense
                    // UNLESS it needs the single quotes — i.e. it contains a `\`
                    // that is NOT part of `\\` or `\'` (those are the only escapes
                    // single quotes interpret; a bare `\x` is a literal backslash
                    // that double quotes would have to escape as `\\x`).
                    "double_quotes" if open.as_slice() == b"'" => {
                        let mut needs_single = false;
                        let mut i = 0;
                        while i < c.len() {
                            if c[i] == b'\\' {
                                match c.get(i + 1) {
                                    Some(b'\\') | Some(b'\'') => { i += 2; continue; }
                                    _ => { needs_single = true; break; }
                                }
                            }
                            i += 1;
                        }
                        if !needs_single {
                            self.push(l.start_offset(), "Style/StringLiterals", true,
                                "Prefer double-quoted strings unless you need single quotes to avoid extra backslashes for escaping.");
                            // fix: `'c'` -> `"c"`, unescaping `\'` -> `'` (`\\` stays)
                            let mut inner = Vec::new();
                            let mut i = 0;
                            while i < c.len() {
                                if c[i] == b'\\' && c.get(i + 1) == Some(&b'\'') {
                                    inner.push(b'\'');
                                    i += 2;
                                } else {
                                    inner.push(c[i]);
                                    i += 1;
                                }
                            }
                            let mut rep = vec![b'"'];
                            rep.extend_from_slice(&inner);
                            rep.push(b'"');
                            self.fixes.push((l.start_offset(), l.end_offset(), rep));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    fn visit_class_node(&mut self, node: &ruby_prism::ClassNode<'pr>) {
        self.check_documentation(node.location().start_offset(), "class", &node.constant_path());
        if let Some(b) = node.body() {
            self.visit(&b);
        }
    }
    fn visit_module_node(&mut self, node: &ruby_prism::ModuleNode<'pr>) {
        self.check_documentation(node.location().start_offset(), "module", &node.constant_path());
        if let Some(b) = node.body() {
            self.visit(&b);
        }
    }
    fn visit_integer_node(&mut self, node: &ruby_prism::IntegerNode<'pr>) {
        if self.on("Style/NumericLiterals") {
            let s = self.node_src(&node.as_node());
            // decimal only, no existing underscore, > configured digit count
            let digits = s.iter().filter(|c| c.is_ascii_digit()).count();
            let min = self.cfg.int("Style/NumericLiterals", "MinDigits");
            if !s.contains(&b'_') && !s.starts_with(b"0x") && !s.starts_with(b"0b") && !s.starts_with(b"0o") && digits >= min {
                self.push(node.location().start_offset(), "Style/NumericLiterals", true,
                    "Use underscores(_) as thousands separator and separate every 3 digits with them.".to_string());
                // fix: group digits in threes from the right (`1000000` -> `1_000_000`)
                let ds: Vec<u8> = s.to_vec();
                let mut grouped = Vec::new();
                for (i, c) in ds.iter().enumerate() {
                    if i > 0 && (ds.len() - i) % 3 == 0 {
                        grouped.push(b'_');
                    }
                    grouped.push(*c);
                }
                let l = node.location();
                self.fixes.push((l.start_offset(), l.end_offset(), grouped));
            }
        }
    }
    fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'pr>) {
        if self.on("Naming/MethodName") {
            let style = self.cfg.enforced_style("Naming/MethodName");
            let name = node.name().as_slice();
            if !name_matches_style(name, style) && !self.allowed("Naming/MethodName", name) {
                self.push(node.name_loc().start_offset(), "Naming/MethodName", false,
                    format!("Use {style} for method names."));
            }
        }
        // Lint/NestedMethodDefinition: a def with an enclosing def and no
        // intervening scoping block/sclass. `def recv.name` where recv is a
        // var/const/call (not `self`) is exempt from being flagged itself.
        if self.on("Lint/NestedMethodDefinition") {
            let exempt = node.receiver().is_some_and(|r| r.as_self_node().is_none());
            if !exempt && self.def_depth >= 1 && self.scoping_depth == 0 {
                self.push(node.location().start_offset(), "Lint/NestedMethodDefinition", false,
                    "Method definitions must not be nested. Use `lambda` instead.");
            }
        }
        // Style/RedundantReturn: body's last statement is a bare `return x`
        if self.on("Style/RedundantReturn") {
            if let Some(ruby_prism::Node::StatementsNode { .. }) = node.body() {
                if let Some(ruby_prism::Node::StatementsNode { .. }) = node.body() {
                    let body = node.body().unwrap();
                    if let Some(stmts) = body.as_statements_node() {
                        if let Some(last) = stmts.body().iter().last() {
                            if let Some(ret) = last.as_return_node() {
                                self.push(ret.location().start_offset(), "Style/RedundantReturn", true,
                                    "Redundant `return` detected.");
                            }
                        }
                    }
                }
            }
        }
        // Descend into the body as one deeper def level (for nested-def detection).
        self.def_depth += 1;
        if let Some(b) = node.body() {
            self.visit(&b);
        }
        self.def_depth -= 1;
    }
    fn visit_singleton_class_node(&mut self, node: &ruby_prism::SingletonClassNode<'pr>) {
        // `class << self` is a scoping context — nested defs inside are allowed.
        self.scoping_depth += 1;
        if let Some(b) = node.body() {
            self.visit(&b);
        }
        self.scoping_depth -= 1;
    }
    fn visit_alias_method_node(&mut self, node: &ruby_prism::AliasMethodNode<'pr>) {
        // `alias new_name old_name` — check the new name against the style.
        if self.on("Naming/MethodName") {
            let style = self.cfg.enforced_style("Naming/MethodName").to_string();
            let nn = node.new_name();
            if let Some((nm, off)) = method_name_arg(&nn, self.src) {
                if !name_matches_style(nm, &style) && !self.allowed("Naming/MethodName", nm) {
                    self.push(off, "Naming/MethodName", false, format!("Use {style} for method names."));
                }
            }
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
        // Naming/MethodName also names methods through macros. Check the relevant
        // symbol/string args of each: attr*, alias_method, and Struct/Data members.
        if self.on("Naming/MethodName") {
            let style = self.cfg.enforced_style("Naming/MethodName").to_string();
            let args: Vec<ruby_prism::Node> = node
                .arguments()
                .map(|a| a.arguments().iter().collect())
                .unwrap_or_default();
            let recv_src = node.receiver().map(|r| {
                let l = r.location();
                self.src[l.start_offset()..l.end_offset()].to_vec()
            });
            // Which args carry method names for this macro?
            let members: &[ruby_prism::Node] = match node.name().as_slice() {
                b"attr" | b"attr_reader" | b"attr_writer" | b"attr_accessor" => &args,
                // alias_method(new, old) — only the new name, and only at arity 2.
                b"alias_method" if args.len() == 2 => &args[0..1],
                // Struct.new(...) — a leading string is the class name, not a member.
                b"new" if matches!(recv_src.as_deref(), Some(b"Struct") | Some(b"::Struct")) => {
                    if args.first().map(|a| a.as_string_node().is_some()).unwrap_or(false) {
                        &args[1..]
                    } else {
                        &args
                    }
                }
                b"define" if matches!(recv_src.as_deref(), Some(b"Data") | Some(b"::Data")) => &args,
                _ => &[],
            };
            let bad: Vec<usize> = members
                .iter()
                .filter_map(|arg| method_name_arg(arg, self.src))
                .filter(|(nm, _)| !name_matches_style(nm, &style) && !self.allowed("Naming/MethodName", nm))
                .map(|(_, off)| off)
                .collect();
            for off in bad {
                self.push(off, "Naming/MethodName", false, format!("Use {style} for method names."));
            }
        }
        // Run every DECLARATIVE send-pattern against this call. The cop is data.
        let n = node.as_node();
        let node_off = node.location().start_offset();
        let op_off = node.message_loc().map(|l| l.start_offset()).unwrap_or(node_off);
        let recv_op_off = node
            .receiver()
            .and_then(|r| r.as_call_node().and_then(|c| c.message_loc()))
            .map(|l| l.start_offset())
            .unwrap_or(node_off);
        for i in 0..self.decl.len() {
            let (pat, cop, msg, anchor, style) = &self.decl[i];
            if !self.on(cop) {
                continue;
            }
            // EnforcedStyle gate: a style-specific row fires only under its style.
            if let Some(s) = style {
                if self.cfg.enforced_style(cop) != *s {
                    continue;
                }
            }
            if let Some(caps) = nodepattern::matches(pat, &n, self.src) {
                let (cop, msg) = (*cop, *msg);
                let off = match anchor {
                    Anchor::Op => op_off,
                    Anchor::Node => node_off,
                    Anchor::RecvOp => recv_op_off,
                };
                self.push(off, cop, false, render(msg, &caps));
            }
        }
        // Style/NumericPredicate (imperative: message interpolates a constructed
        // suggestion). Uses call_stack for AllowedMethods-on-ancestor + negation.
        if let Some((off, msg)) = self.numeric_predicate(node) {
            self.push(off, "Style/NumericPredicate", true, msg);
        }
        // recurse into children (we've overridden the default walk). Push this
        // call's name so descendants can see it as an ancestor.
        self.call_stack.push(node.name().as_slice().to_vec());
        if let Some(r) = node.receiver() {
            self.visit(&r);
        }
        if let Some(a) = node.arguments() {
            for arg in a.arguments().iter() {
                self.visit(&arg);
            }
        }
        if let Some(b) = node.block() {
            // A block is "scoping" (allows nested defs) if it's a class
            // constructor, an (instance|class|module)_(eval|exec), or its method
            // is in AllowedMethods.
            let scoping = self.on("Lint/NestedMethodDefinition")
                && (is_eval_exec(node)
                    || is_class_constructor(node, self.src)
                    || self.allowed("Lint/NestedMethodDefinition", node.name().as_slice()));
            if scoping {
                self.scoping_depth += 1;
            }
            self.visit(&b);
            if scoping {
                self.scoping_depth -= 1;
            }
        }
        self.call_stack.pop();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: rubocop-rs-poc <file.rb> [config.yml]");
    let src = std::fs::read(path).expect("read");

    // config: explicit 2nd arg, else ./.rubocop.yml, else empty
    let cfg_text = args
        .get(2)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::fs::read_to_string(".rubocop.yml").ok())
        .unwrap_or_default();
    let cfg = Config::parse(&cfg_text);

    let result = ruby_prism::parse(&src);
    let idx = LineIndex::new(&src);

    let mut comment_lines = std::collections::HashSet::new();
    let mut has_frozen = false;
    for c in result.comments() {
        let l = c.location();
        comment_lines.insert(idx.loc(l.start_offset()).0);
        let t = &src[l.start_offset()..l.end_offset()];
        if t.windows(22).any(|w| w == b"frozen_string_literal:") {
            has_frozen = true;
        }
    }

    let decl: Vec<(Pat, &'static str, &'static str, Anchor, Option<&'static str>)> = DECLARATIVE
        .iter()
        .map(|(p, cop, msg, a, style)| (nodepattern::parse(p), *cop, *msg, *a, *style))
        .collect();

    // Compile each cop's AllowedPatterns once (invalid regexes dropped); collect
    // AllowedMethods as exact-name lists. Both back `Cops::allowed`.
    let mut allowed: HashMap<String, Vec<regex::Regex>> = HashMap::new();
    let mut allowed_methods: HashMap<String, Vec<String>> = HashMap::new();
    for (sec, kv) in &cfg.sections {
        if let Some(v) = kv.get("AllowedPatterns") {
            let pats = parse_allowed_list(v)
                .into_iter()
                .filter_map(|p| regex::Regex::new(&p).ok())
                .collect();
            allowed.insert(sec.clone(), pats);
        }
        if let Some(v) = kv.get("AllowedMethods") {
            allowed_methods.insert(sec.clone(), parse_allowed_list(v));
        }
    }

    let mut cops = Cops { src: &src, idx: &idx, cfg: &cfg, comment_lines, offenses: Vec::new(), fixes: Vec::new(), decl, allowed, allowed_methods, call_stack: Vec::new(), def_depth: 0, scoping_depth: 0 };

    // ---- text-based cops ----
    if cops.on("Style/FrozenStringLiteralComment") && !has_frozen {
        cops.push(0, "Style/FrozenStringLiteralComment", true, "Missing frozen string literal comment.");
        cops.fixes.push((0, 0, b"# frozen_string_literal: true\n\n".to_vec()));
    }
    if cops.on("Layout/LineLength") {
        let max = cfg.int("Layout/LineLength", "Max");
        for (li, line) in src.split(|&b| b == b'\n').enumerate() {
            let len = String::from_utf8_lossy(line).chars().count();
            if len > max && !cops.allowed("Layout/LineLength", line) {
                let off = idx.starts[li] + line.iter().take(max).count();
                cops.offenses.push(Offense { line: li + 1, col: max + 1, cop: "Layout/LineLength", correctable: false,
                    message: format!("Line is too long. [{len}/{max}]") });
                let _ = off;
            }
        }
    }
    if cops.on("Layout/TrailingWhitespace") {
        for (li, line) in src.split(|&b| b == b'\n').enumerate() {
            let ls = idx.starts[li];
            let (col, trim_start) = match line.iter().rposition(|&c| c != b' ' && c != b'\t') {
                Some(pos) if pos + 1 < line.len() => (pos + 2, ls + pos + 1),
                None if !line.is_empty() => (1, ls),
                _ => continue,
            };
            cops.offenses.push(Offense { line: li + 1, col, cop: "Layout/TrailingWhitespace", correctable: true,
                message: "Trailing whitespace detected.".into() });
            cops.fixes.push((trim_start, ls + line.len(), Vec::new())); // strip the trailing ws
        }
    }

    // ---- AST-based cops ----
    cops.visit(&result.node());

    cops.offenses.sort_by(|a, b| (a.line, a.col, a.cop).cmp(&(b.line, b.col, b.cop)));

    // --fix: apply autocorrect edits right-to-left (non-overlapping) and print
    // the corrected source, like `rubocop -a`.
    if args.iter().any(|a| a == "--fix") {
        let mut out = src.clone();
        let mut fixes = cops.fixes.clone();
        fixes.sort_by(|a, b| b.0.cmp(&a.0)); // descending by start
        for (s, e, rep) in fixes {
            if s <= e && e <= out.len() {
                out.splice(s..e, rep.iter().copied());
            }
        }
        use std::io::Write;
        std::io::stdout().write_all(&out).unwrap();
        return;
    }

    println!("== {path} ==");
    let mut correctable = 0;
    for o in &cops.offenses {
        let c = if o.correctable { correctable += 1; "[Correctable] " } else { "" };
        println!("C:{:>3}:{:>3}: {}{}: {}", o.line, o.col, c, o.cop, o.message);
    }
    let n = cops.offenses.len();
    println!("\n1 file inspected, {n} offense{} detected{}",
        if n == 1 { "" } else { "s" },
        if correctable > 0 { format!(", {correctable} offense{} autocorrectable", if correctable == 1 { "" } else { "s" }) } else { String::new() });
}
