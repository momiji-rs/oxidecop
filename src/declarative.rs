//! DECLARATIVE cops — pure DATA: (node-pattern, cop name, message, anchor).
//! This is the whole point of the node-pattern engine: ~266 of rubocop's cops
//! are shaped exactly like this, so porting them is transcription, not coding.
//! `anchor` is the one bit NOT derivable from the pattern — where rubocop's
//! `add_offense` points (matched-node start vs. the send operator/selector).

/// A declarative cop row. The optional last field is an `EnforcedStyle` gate:
/// `Some("comparison")` means the row only fires when the cop's active style is
/// `comparison` (resolved via the SCHEMA); `None` means style-agnostic. This is
/// how one pattern cop expresses multiple styles as data — no imperative branch.
pub const DECLARATIVE: &[(&str, &str, &str, Anchor, Option<&str>)] = &[
    // NilComparison. Two styles, two rows, gated on EnforcedStyle. Verbatim msgs.
    ("(send _ {:== :===} (nil))", "Style/NilComparison", "Prefer the use of the `nil?` predicate.", Anchor::Op, Some("predicate")),
    ("(send (...) :nil?)", "Style/NilComparison", "Prefer the use of the `==` comparison.", Anchor::Op, Some("comparison")),

    // RandOne — rubocop's rand_one? pattern verbatim; the whole matched call
    // (the `$(...)` capture) interpolates into the message.
    ("$(send {(const {nil? cbase} :Kernel) nil?} :rand {(int {-1 1}) (float {-1.0 1.0})})",
     "Lint/RandOne", "`{}` always returns `0`. Perhaps you meant `rand(2)` or `rand`?", Anchor::Node, None),

    // ArrayJoin — rubocop's join_candidate? pattern; fixed message, offense on
    // the `*` selector.
    ("(send array :* str)", "Style/ArrayJoin", "Favor `Array#join` over `Array#*`.", Anchor::Op, None),

    // BigDecimalNew — deprecation with a fixed message, offense on `new`.
    ("(send (const {nil? cbase} :BigDecimal) :new ...)",
     "Lint/BigDecimalNew", "`BigDecimal.new()` is deprecated. Use `BigDecimal()` instead.", Anchor::Op, None),
];

/// Where a declarative offense points. Per-cop metadata, since rubocop's cops
/// pass different nodes to `add_offense`.
#[derive(Clone, Copy)]
pub enum Anchor {
    Node,   // start of the whole matched node (the default `add_offense(node)`)
    Op,     // the call's operator/selector (`node.loc.selector`)
    // the receiver-call's selector (e.g. the `.length` in `x.length.zero?`);
    // currently unused by the table but part of the anchor vocabulary.
    #[allow(dead_code)]
    RecvOp,
}

/// Substitute `{}` placeholders in a message template with captures, in order.
pub fn render(template: &str, caps: &[String]) -> String {
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
