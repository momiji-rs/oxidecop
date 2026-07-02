//! Mini node-pattern engine — a subset of rubocop's `def_node_matcher` DSL,
//! matched against Prism nodes. The POINT: once this exists, a pattern cop is
//! DATA (pattern string + message), not code — and imperative cops use parsed
//! patterns as matchers, exactly like rubocop's `def_node_matcher`. Supported:
//!   (send RECV :meth ARG...)   (csend ...)   (call ...)  — call = send|csend
//!   nil?   _   :sym   {a b c}   $capture   ...   cbase
//!   (nil)   (int N)   (int $N)   (const SCOPE :Name)
use ruby_prism::Node;

#[derive(Debug, Clone)]
pub enum Pat {
    Any,             // _
    NilRecv,         // nil?  (a nil / absent receiver or scope)
    Sym(String),     // :foo  (a method-name symbol)
    Node { ty: String, children: Vec<Pat> }, // (ty c...)
    Int(i64),        // 0, 42
    Float(f64),      // 1.0, -1.0
    Union(Vec<Pat>), // {a b c}  — any alternative matches
    Capture(Box<Pat>), // $pat  — on match, records the matched text (left-to-right)
    Rest,            // ...  — any remaining children (a send's method+args, or args)
    Cbase,           // cbase — the `::` top-level scope anchor
}

pub fn parse(s: &str) -> Pat {
    let toks = tokenize(s);
    let mut pos = 0;
    parse_one(&toks, &mut pos)
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' | '{' | '}' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(c.to_string());
            }
            ' ' | '\t' | '\n' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Bare words that are node-TYPE matches (rubocop writes `$array`, `str`);
/// everything else bare stays a method-name shorthand for back-compat.
const TYPE_ATOMS: &[&str] =
    &["array", "str", "sym", "hash", "int", "float", "nil", "begin", "const", "send", "csend", "call"];

fn atom(s: &str) -> Pat {
    match s {
        "_" => Pat::Any,
        "nil?" => Pat::NilRecv,
        "..." => Pat::Rest,
        "cbase" => Pat::Cbase,
        _ if s.starts_with(':') => Pat::Sym(s[1..].to_string()),
        _ if s.parse::<i64>().is_ok() => Pat::Int(s.parse().unwrap()),
        _ if s.contains('.') && s.parse::<f64>().is_ok() => Pat::Float(s.parse().unwrap()),
        _ if TYPE_ATOMS.contains(&s) => Pat::Node { ty: s.to_string(), children: Vec::new() },
        _ => Pat::Sym(s.to_string()),
    }
}

fn parse_one(toks: &[String], pos: &mut usize) -> Pat {
    let t = &toks[*pos];
    *pos += 1;
    match t.as_str() {
        "$" => Pat::Capture(Box::new(parse_one(toks, pos))), // `$` then `{...}`/`(...)`
        s if s.starts_with('$') => Pat::Capture(Box::new(atom(&s[1..]))), // `$_`, `$:sym`, `$5`
        "(" => {
            let ty = toks[*pos].clone();
            *pos += 1;
            let mut children = Vec::new();
            while toks[*pos] != ")" {
                children.push(parse_one(toks, pos));
            }
            *pos += 1; // consume ')'
            Pat::Node { ty, children }
        }
        "{" => {
            let mut alts = Vec::new();
            while toks[*pos] != "}" {
                alts.push(parse_one(toks, pos));
            }
            *pos += 1; // consume '}'
            Pat::Union(alts)
        }
        other => atom(other),
    }
}

/// Match `pat` against Prism `node`; on success returns the captured texts
/// (in left-to-right `$` order), else None.
pub fn matches(pat: &Pat, node: &Node, src: &[u8]) -> Option<Vec<String>> {
    let mut caps = Vec::new();
    if m(pat, node, src, &mut caps) {
        Some(caps)
    } else {
        None
    }
}

fn node_text(node: &Node, src: &[u8]) -> String {
    let l = node.location();
    String::from_utf8_lossy(&src[l.start_offset()..l.end_offset()]).into_owned()
}

fn m(pat: &Pat, node: &Node, src: &[u8], caps: &mut Vec<String>) -> bool {
    match pat {
        Pat::Any => true,
        Pat::NilRecv => node.as_nil_node().is_some(),
        Pat::Int(n) => node
            .as_integer_node()
            .map(|i| int_of(&i.as_node(), src) == Some(*n))
            .unwrap_or(false),
        Pat::Float(f) => node
            .as_float_node()
            .map(|n| float_of(&n.as_node(), src) == Some(*f))
            .unwrap_or(false),
        Pat::Sym(_) => false, // a bare sym only meaningful as a send's :meth slot
        Pat::Rest | Pat::Cbase => false, // positional/scope-only; handled by parents
        Pat::Union(alts) => union(alts, caps, |p, caps| m(p, node, src, caps)),
        Pat::Capture(inner) => {
            if m(inner, node, src, caps) {
                caps.push(node_text(node, src));
                true
            } else {
                false
            }
        }
        Pat::Node { ty, children } => match_typed(ty, children, node, src, caps),
    }
}

/// Try alternatives left-to-right, undoing any captures a failed branch made
/// (a branch can capture, then fail on a later slot — without the rollback the
/// stale capture would leak into the winning branch's interpolations).
fn union(alts: &[Pat], caps: &mut Vec<String>, mut f: impl FnMut(&Pat, &mut Vec<String>) -> bool) -> bool {
    alts.iter().any(|p| {
        let mark = caps.len();
        if f(p, caps) {
            true
        } else {
            caps.truncate(mark);
            false
        }
    })
}

/// Match a send's receiver slot, where the receiver may be ABSENT: `nil?`
/// matches absence, and a union like `{(const nil? :Kernel) nil?}` needs the
/// absence case threaded through the alternation.
fn match_recv(pat: &Pat, recv: Option<&Node>, src: &[u8], caps: &mut Vec<String>) -> bool {
    match pat {
        Pat::Any => true,
        Pat::NilRecv => recv.is_none(),
        Pat::Union(alts) => union(alts, caps, |p, caps| match_recv(p, recv, src, caps)),
        Pat::Capture(inner) => {
            if match_recv(inner, recv, src, caps) {
                caps.push(recv.map(|r| node_text(r, src)).unwrap_or_default());
                true
            } else {
                false
            }
        }
        p => recv.map(|r| m(p, r, src, caps)).unwrap_or(false),
    }
}

/// Match a `:meth` slot (Sym / Union-of-Syms / a `$`capture of either).
fn match_meth(pat: &Pat, name: &[u8], caps: &mut Vec<String>) -> bool {
    match pat {
        Pat::Any => true,
        Pat::Sym(s) => s.as_bytes() == name,
        Pat::Union(alts) => union(alts, caps, |p, caps| match_meth(p, name, caps)),
        Pat::Capture(inner) => {
            if match_meth(inner, name, caps) {
                caps.push(String::from_utf8_lossy(name).into_owned());
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn int_of(n: &Node, src: &[u8]) -> Option<i64> {
    let l = n.location();
    std::str::from_utf8(&src[l.start_offset()..l.end_offset()])
        .ok()?
        .replace('_', "")
        .parse()
        .ok()
}

fn float_of(n: &Node, src: &[u8]) -> Option<f64> {
    let l = n.location();
    std::str::from_utf8(&src[l.start_offset()..l.end_offset()])
        .ok()?
        .replace('_', "")
        .parse()
        .ok()
}

/// A constant's scope slot: `File` has scope Nil, `::File` has scope Cbase,
/// `File::Stat`'s scope is the `File` node.
enum ConstScope<'pr> {
    Nil,
    Cbase,
    Parent(Node<'pr>),
}
fn match_const_scope(pat: &Pat, scope: &ConstScope, src: &[u8], caps: &mut Vec<String>) -> bool {
    match pat {
        Pat::Any => true,
        Pat::NilRecv => matches!(scope, ConstScope::Nil),
        Pat::Cbase => matches!(scope, ConstScope::Cbase),
        Pat::Union(alts) => union(alts, caps, |p, caps| match_const_scope(p, scope, src, caps)),
        p => match scope {
            ConstScope::Parent(n) => m(p, n, src, caps),
            _ => false,
        },
    }
}

fn match_typed(ty: &str, children: &[Pat], node: &Node, src: &[u8], caps: &mut Vec<String>) -> bool {
    match ty {
        // `send` is a plain call, `csend` the `&.` safe-navigation form,
        // `call` either (rubocop's alias for `{send csend}`).
        "send" | "csend" | "call" => {
            let Some(call) = node.as_call_node() else { return false };
            match ty {
                "send" if call.is_safe_navigation() => return false,
                "csend" if !call.is_safe_navigation() => return false,
                _ => {}
            }
            // children: [receiver, :method, args...] — `...` anywhere after the
            // receiver consumes the rest (method and/or remaining args).
            if children.is_empty() {
                return false;
            }
            if !match_recv(&children[0], call.receiver().as_ref(), src, caps) {
                return false;
            }
            // method slot: `...` here matches any method + any args.
            let Some(meth_pat) = children.get(1) else { return false };
            if matches!(meth_pat, Pat::Rest) {
                return true;
            }
            if !match_meth(meth_pat, call.name().as_slice(), caps) {
                return false;
            }
            // args, with a trailing `...` matching any remainder (incl. empty)
            let args: Vec<Node> = call
                .arguments()
                .map(|a| a.arguments().iter().collect())
                .unwrap_or_default();
            let arg_pats = &children[2..];
            if let Some(last) = arg_pats.last() {
                if matches!(last, Pat::Rest) {
                    let fixed = &arg_pats[..arg_pats.len() - 1];
                    return fixed.len() <= args.len()
                        && fixed.iter().zip(&args).all(|(p, a)| m(p, a, src, caps));
                }
            }
            arg_pats.len() == args.len() && arg_pats.iter().zip(&args).all(|(p, a)| m(p, a, src, caps))
        }
        // `(...)` — any node that EXISTS. In a receiver slot this requires an
        // explicit receiver (absent receivers never reach here), which is how
        // rubocop distinguishes `foo.size == 0` from a bare `size == 0`.
        "..." => true,
        "nil" => node.as_nil_node().is_some(),
        "int" => {
            if let Some(p) = children.first() {
                node.as_integer_node().is_some() && m(p, node, src, caps)
            } else {
                node.as_integer_node().is_some()
            }
        }
        "float" => {
            if let Some(p) = children.first() {
                node.as_float_node().is_some() && m(p, node, src, caps)
            } else {
                node.as_float_node().is_some()
            }
        }
        "str" => node.as_string_node().is_some(),
        "array" => node.as_array_node().is_some(),
        "hash" => node.as_hash_node().is_some(),
        // `(sym :name)` / `(sym {:a :b})` — the child matches the symbol VALUE.
        "sym" => {
            let Some(sy) = node.as_symbol_node() else { return false };
            match children.first() {
                None => true,
                Some(p) => sy
                    .value_loc()
                    .is_some_and(|v| match_meth(p, &src[v.start_offset()..v.end_offset()], caps)),
            }
        }
        // `(range LEFT RIGHT)` — both endpoints must be present and match.
        "range" | "irange" | "erange" => {
            let Some(r) = node.as_range_node() else { return false };
            match ty {
                "irange" if r.operator_loc().as_slice() != b".." => return false,
                "erange" if r.operator_loc().as_slice() != b"..." => return false,
                _ => {}
            }
            if children.len() != 2 {
                return children.is_empty();
            }
            let ends = [r.left(), r.right()];
            children.iter().zip(ends).all(|(p, end)| match (p, end) {
                (Pat::NilRecv, None) => true,
                (Pat::Any, _) => true,
                (p, Some(n)) => m(p, &n, src, caps),
                _ => false,
            })
        }
        // parser's `(begin X)` — a parenthesized expression wrapping X.
        "begin" => {
            let Some(pn) = node.as_parentheses_node() else { return false };
            match children.first() {
                None => true,
                Some(p) => pn
                    .body()
                    .and_then(|b| b.as_statements_node())
                    .and_then(|st| {
                        let stmts: Vec<Node> = st.body().iter().collect();
                        (stmts.len() == 1).then(|| m(p, &stmts[0], src, caps))
                    })
                    .unwrap_or(false),
            }
        }
        // `(const SCOPE :Name)` — scope: `nil?` (bare `Foo`), `cbase` (`::Foo`),
        // or a nested pattern (`File::Stat`). Without children: any constant.
        "const" => {
            if children.len() != 2 {
                return node.as_constant_read_node().is_some() || node.as_constant_path_node().is_some();
            }
            if let Some(cr) = node.as_constant_read_node() {
                match_const_scope(&children[0], &ConstScope::Nil, src, caps)
                    && match_meth(&children[1], cr.name().as_slice(), caps)
            } else if let Some(cp) = node.as_constant_path_node() {
                let scope = match cp.parent() {
                    None => ConstScope::Cbase,
                    Some(p) => ConstScope::Parent(p),
                };
                match_const_scope(&children[0], &scope, src, caps)
                    && cp.name().is_some_and(|n| match_meth(&children[1], n.as_slice(), caps))
            } else {
                false
            }
        }
        _ => false,
    }
}
