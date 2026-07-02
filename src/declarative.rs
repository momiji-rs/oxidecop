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
pub enum Anchor {
    Node,   // start of the whole matched node (the default `add_offense(node)`)
    Op,     // the call's operator/selector (`node.loc.selector`)
    RecvOp, // the receiver-call's selector (e.g. the `.length` in `x.length.zero?`)
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
