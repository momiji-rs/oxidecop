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
const DECLARATIVE: &[(&str, &str, &str, Anchor)] = &[
    // NilComparison (default `predicate` style). Verbatim from rubocop source.
    ("(send _ {:== :===} (nil))", "Style/NilComparison", "Prefer the use of the `nil?` predicate.", Anchor::Op),

    // ZeroLengthPredicate — `empty?` (zero-length) shapes. The `${:size :length}`
    // captures the method so the message interpolates it, exactly like rubocop.
    ("(send (send (...) ${:size :length}) :== (int 0))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `{} == 0`.", Anchor::Node),
    ("(send (int 0) :== (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `0 == {}`.", Anchor::Node),
    ("(send (send (...) ${:size :length}) :< (int 1))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `{} < 1`.", Anchor::Node),
    ("(send (int 1) :> (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `empty?` instead of `1 > {}`.", Anchor::Node),
    ("(send (send (...) ${:size :length}) :zero?)", "Style/ZeroLengthPredicate", "Use `empty?` instead of `{}.zero?`.", Anchor::RecvOp),
    // ZeroLengthPredicate — `!empty?` (nonzero-length) shapes.
    ("(send (send (...) ${:size :length}) :> (int 0))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `{} > 0`.", Anchor::Node),
    ("(send (int 0) :< (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `0 < {}`.", Anchor::Node),
    ("(send (send (...) ${:size :length}) :!= (int 0))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `{} != 0`.", Anchor::Node),
    ("(send (int 0) :!= (send (...) ${:size :length}))", "Style/ZeroLengthPredicate", "Use `!empty?` instead of `0 != {}`.", Anchor::Node),
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
    Schema { cop: "Naming/MethodName", params: &[("EnforcedStyle", "snake_case")],
             styles: &["snake_case", "camelCase"] },
];
fn schema(cop: &str) -> Option<&'static Schema> {
    SCHEMA.iter().find(|s| s.cop == cop)
}
fn schema_default(cop: &str, key: &str) -> Option<&'static str> {
    schema(cop).and_then(|s| s.params.iter().find(|(k, _)| *k == key).map(|(_, v)| *v))
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
    decl: Vec<(Pat, &'static str, &'static str, Anchor)>,
}
impl<'a> Cops<'a> {
    fn on(&self, cop: &str) -> bool {
        self.cfg.enabled(cop)
    }
    fn push(&mut self, off: usize, cop: &'static str, correctable: bool, msg: impl Into<String>) {
        let (line, col) = self.idx.loc(off);
        self.offenses.push(Offense { line, col, cop, correctable, message: msg.into() });
    }
    fn node_src(&self, n: &ruby_prism::Node) -> &'a [u8] {
        let l = n.location();
        &self.src[l.start_offset()..l.end_offset()]
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

fn is_snake_case(s: &[u8]) -> bool {
    // allow trailing ? ! =, and leading _
    let core: &[u8] = match s.last() {
        Some(b'?') | Some(b'!') | Some(b'=') => &s[..s.len() - 1],
        _ => s,
    };
    !core.iter().any(|&c| c.is_ascii_uppercase())
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
            let name = node.name().as_slice();
            if !is_snake_case(name) {
                self.push(node.name_loc().start_offset(), "Naming/MethodName", false,
                    "Use snake_case for method names.");
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
        if let Some(b) = node.body() {
            self.visit(&b);
        }
    }
    fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'pr>) {
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
            let (pat, cop, msg, anchor) = &self.decl[i];
            if !self.on(cop) {
                continue;
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
        // recurse into children (we've overridden the default walk)
        if let Some(r) = node.receiver() {
            self.visit(&r);
        }
        if let Some(a) = node.arguments() {
            for arg in a.arguments().iter() {
                self.visit(&arg);
            }
        }
        if let Some(b) = node.block() {
            self.visit(&b);
        }
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

    let decl: Vec<(Pat, &'static str, &'static str, Anchor)> = DECLARATIVE
        .iter()
        .map(|(p, cop, msg, a)| (nodepattern::parse(p), *cop, *msg, *a))
        .collect();

    let mut cops = Cops { src: &src, idx: &idx, cfg: &cfg, comment_lines, offenses: Vec::new(), fixes: Vec::new(), decl };

    // ---- text-based cops ----
    if cops.on("Style/FrozenStringLiteralComment") && !has_frozen {
        cops.push(0, "Style/FrozenStringLiteralComment", true, "Missing frozen string literal comment.");
        cops.fixes.push((0, 0, b"# frozen_string_literal: true\n\n".to_vec()));
    }
    if cops.on("Layout/LineLength") {
        let max = cfg.int("Layout/LineLength", "Max");
        for (li, line) in src.split(|&b| b == b'\n').enumerate() {
            let len = String::from_utf8_lossy(line).chars().count();
            if len > max {
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
