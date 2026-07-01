//! Mini node-pattern engine — a subset of rubocop's `def_node_matcher` DSL,
//! matched against Prism nodes. The POINT: once this exists, a pattern cop is
//! DATA (pattern string + message), not code. Supported subset:
//!   (send RECV :meth ARG...)   nil?   _   :sym   (nil)   (int N)   (const _ :Name)
use ruby_prism::Node;

#[derive(Debug, Clone)]
pub enum Pat {
    Any,             // _
    NilRecv,         // nil?  (a nil / absent receiver)
    Sym(String),     // :foo  (a method-name symbol)
    Node { ty: String, children: Vec<Pat> }, // (ty c...)
    Int(i64),        // 0, 42
    Union(Vec<Pat>), // {a b c}  — any alternative matches
    Capture(Box<Pat>), // $pat  — on match, records the matched text (left-to-right)
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

fn atom(s: &str) -> Pat {
    match s {
        "_" => Pat::Any,
        "nil?" => Pat::NilRecv,
        _ if s.starts_with(':') => Pat::Sym(s[1..].to_string()),
        _ if s.parse::<i64>().is_ok() => Pat::Int(s.parse().unwrap()),
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
        Pat::Sym(_) => false, // a bare sym only meaningful as a send's :meth slot
        Pat::Union(alts) => alts.iter().any(|p| m(p, node, src, caps)),
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

/// Match a `:meth` slot (Sym / Union-of-Syms / a `$`capture of either).
fn match_meth(pat: &Pat, name: &[u8], caps: &mut Vec<String>) -> bool {
    match pat {
        Pat::Any => true,
        Pat::Sym(s) => s.as_bytes() == name,
        Pat::Union(alts) => alts.iter().any(|p| match_meth(p, name, caps)),
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

fn match_typed(ty: &str, children: &[Pat], node: &Node, src: &[u8], caps: &mut Vec<String>) -> bool {
    match ty {
        "send" | "csend" => {
            let Some(call) = node.as_call_node() else { return false };
            // children: [receiver, :method, args...]
            if children.len() < 2 {
                return false;
            }
            // receiver
            let recv_ok = match &children[0] {
                Pat::NilRecv => call.receiver().is_none(),
                Pat::Any => true,
                p => call.receiver().map(|r| m(p, &r, src, caps)).unwrap_or(false),
            };
            if !recv_ok {
                return false;
            }
            // method name (a :sym slot, possibly a {union} of syms or a $capture)
            if !match_meth(&children[1], call.name().as_slice(), caps) {
                return false;
            }
            // args
            let args: Vec<Node> = call
                .arguments()
                .map(|a| a.arguments().iter().collect())
                .unwrap_or_default();
            let arg_pats = &children[2..];
            if arg_pats.len() != args.len() {
                return false;
            }
            arg_pats.iter().zip(&args).all(|(p, a)| m(p, a, src, caps))
        }
        // `(...)` — any node that EXISTS. In a receiver slot this requires an
        // explicit receiver (absent receivers never reach here), which is how
        // rubocop distinguishes `foo.size == 0` from a bare `size == 0`.
        "..." => true,
        "nil" => node.as_nil_node().is_some(),
        "int" => {
            if let Some(Pat::Int(n)) = children.first() {
                node.as_integer_node()
                    .map(|i| int_of(&i.as_node(), src) == Some(*n))
                    .unwrap_or(false)
            } else {
                node.as_integer_node().is_some()
            }
        }
        "const" => node.as_constant_read_node().is_some() || node.as_constant_path_node().is_some(),
        _ => false,
    }
}
