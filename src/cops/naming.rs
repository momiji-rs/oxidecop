//! Naming department: Naming/MethodName across all the ways Ruby names a
//! method — `def`, `alias`, `alias_method`, `attr_*`, Struct/Data members.
use super::Cops;

impl<'a> Cops<'a> {
    /// Naming/MethodName on a `def` — the definition's own name.
    pub(crate) fn check_method_name_def(&mut self, node: &ruby_prism::DefNode) {
        if !self.on("Naming/MethodName") {
            return;
        }
        let style = self.cfg.enforced_style("Naming/MethodName");
        let name = node.name().as_slice();
        if !name_matches_style(name, style) && !self.allowed("Naming/MethodName", name) {
            self.push(node.name_loc().start_offset(), "Naming/MethodName", false,
                format!("Use {style} for method names."));
        }
    }

    /// Naming/MethodName on `alias new_name old_name` — the new name only.
    pub(crate) fn check_method_name_alias(&mut self, node: &ruby_prism::AliasMethodNode) {
        if !self.on("Naming/MethodName") {
            return;
        }
        let style = self.cfg.enforced_style("Naming/MethodName").to_string();
        let nn = node.new_name();
        if let Some((nm, off)) = method_name_arg(&nn, self.src) {
            if !name_matches_style(nm, &style) && !self.allowed("Naming/MethodName", nm) {
                self.push(off, "Naming/MethodName", false, format!("Use {style} for method names."));
            }
        }
    }

    /// Naming/MethodName through macros: check the relevant symbol/string args
    /// of attr*, alias_method, and Struct/Data member lists.
    pub(crate) fn check_method_name_macros(&mut self, node: &ruby_prism::CallNode) {
        if !self.on("Naming/MethodName") {
            return;
        }
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
