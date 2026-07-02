//! Layout/LineLength autocorrection: rubocop's CheckLineBreakable mixin plus
//! the SplitStrings corrector. During the AST walk, hooks nominate at most one
//! "breakable" position per long line (collections break before the first
//! element past the limit, strings split at a space / escape boundary /
//! hard cap); check_line_length then turns the nomination for each flagged
//! line into an insertion fix — `"\n"`, or `<delim> \<newline><delim>` for a
//! string split. Precedence mirrors rubocop's hook order: semicolons register
//! first (a later hook skips an occupied line), blocks overwrite everything.
use super::Cops;

/// A heredoc-opened string family node (`<<~X`, `<<-X`, `<<X`, `<<~\`SH\``).
pub(crate) fn is_heredoc_node(node: &ruby_prism::Node<'_>) -> bool {
    let opening = if let Some(n) = node.as_string_node() {
        n.opening_loc()
    } else if let Some(n) = node.as_interpolated_string_node() {
        n.opening_loc()
    } else if let Some(n) = node.as_x_string_node() {
        Some(n.opening_loc())
    } else if let Some(n) = node.as_interpolated_x_string_node() {
        Some(n.opening_loc())
    } else {
        None
    };
    opening.is_some_and(|o| o.as_slice().starts_with(b"<<"))
}

/// Cheap facts for the breakable-collection hook: the processed element
/// count (rubocop's process_args — a trailing braceless hash contributes its
/// pairs), the parenthesization, whether the first raw argument is a heredoc,
/// the first heredoc's index among processed elements, and whether the
/// receiver chain contains a heredoc (which disables the hook entirely). No
/// allocation — call_elements() builds the spans only when actually needed.
pub(crate) fn call_break_facts(node: &ruby_prism::CallNode<'_>) -> (usize, LlCallInfo) {
    let mut count = 0;
    let mut heredoc_arg_index = None;
    let mut first_arg_heredoc = false;
    if let Some(args) = node.arguments() {
        let list = args.arguments();
        let n = list.iter().count();
        for (i, a) in list.iter().enumerate() {
            if i == 0 {
                first_arg_heredoc = is_heredoc_node(&a);
            }
            if i + 1 == n {
                if let Some(kw) = a.as_keyword_hash_node() {
                    count += kw.elements().iter().count();
                    continue;
                }
            }
            if heredoc_arg_index.is_none() && is_heredoc_node(&a) {
                heredoc_arg_index = Some(count);
            }
            count += 1;
        }
    }
    let mut skip_hook = false;
    let mut recv = node.receiver();
    while let Some(r) = recv {
        if is_heredoc_node(&r) {
            skip_hook = true;
            break;
        }
        recv = r.as_call_node().and_then(|c| c.receiver());
    }
    let info = LlCallInfo {
        parenthesized: node.opening_loc().is_some(),
        first_arg_heredoc,
        heredoc_arg_index,
        skip_hook,
    };
    (count, info)
}

/// The processed element spans for a call (see call_break_facts).
pub(crate) fn call_elements(node: &ruby_prism::CallNode<'_>) -> Vec<(usize, usize)> {
    let mut elements = Vec::new();
    if let Some(args) = node.arguments() {
        let list = args.arguments();
        let n = list.iter().count();
        for (i, a) in list.iter().enumerate() {
            if i + 1 == n {
                if let Some(kw) = a.as_keyword_hash_node() {
                    for e in kw.elements().iter() {
                        let l = e.location();
                        elements.push((l.start_offset(), l.end_offset()));
                    }
                    continue;
                }
            }
            let l = a.location();
            elements.push((l.start_offset(), l.end_offset()));
        }
    }
    elements
}

/// A def's parameter count, without building the span list.
pub(crate) fn param_count(p: &ruby_prism::ParametersNode<'_>) -> usize {
    p.requireds().iter().count()
        + p.optionals().iter().count()
        + usize::from(p.rest().is_some())
        + p.posts().iter().count()
        + p.keywords().iter().count()
        + usize::from(p.keyword_rest().is_some())
        + usize::from(p.block().is_some())
}

/// A def's parameters as (start, end) spans, in source order.
pub(crate) fn def_param_spans<'a>(node: &ruby_prism::DefNode<'a>) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if let Some(p) = node.parameters() {
        let mut push = |l: ruby_prism::Location<'_>| out.push((l.start_offset(), l.end_offset()));
        for n in p.requireds().iter() {
            push(n.location());
        }
        for n in p.optionals().iter() {
            push(n.location());
        }
        if let Some(n) = p.rest() {
            push(n.location());
        }
        for n in p.posts().iter() {
            push(n.location());
        }
        for n in p.keywords().iter() {
            push(n.location());
        }
        if let Some(n) = p.keyword_rest() {
            push(n.location());
        }
        if let Some(n) = p.block() {
            push(n.location());
        }
    }
    out
}

impl<'a> Cops<'a> {
    /// Arm the machinery for this file: LineLength enabled and at least one
    /// line over the limit.
    pub(crate) fn ll_prepare(&mut self) {
        const COP: &str = "Layout/LineLength";
        if !self.on(COP) {
            return;
        }
        let max = self.cfg.int(COP, "Max");
        let mut any = false;
        let long: Vec<bool> = self
            .src
            .split(|&b| b == b'\n')
            .map(|raw| {
                let raw = if raw.last() == Some(&b'\r') { &raw[..raw.len() - 1] } else { raw };
                let n = if raw.is_ascii() {
                    raw.len()
                } else {
                    String::from_utf8_lossy(raw).chars().count()
                };
                let l = n > max;
                any |= l;
                l
            })
            .collect();
        if !any {
            return;
        }
        self.ll_max = max;
        self.ll_split = self.cfg.get(COP, "SplitStrings") == Some("true");
        self.ll_long = long;
        self.ll_active = true;
    }

    /// 0-based character column of a byte offset (bytes == chars when the
    /// line prefix is ASCII).
    pub(crate) fn col0(&self, off: usize) -> usize {
        let (line, _) = self.idx.loc(off);
        let prefix = &self.src[self.idx.starts[line - 1]..off];
        if prefix.is_ascii() {
            prefix.len()
        } else {
            String::from_utf8_lossy(prefix).chars().count()
        }
    }

    fn ll_line_of(&self, off: usize) -> usize {
        self.idx.loc(off).0
    }

    fn ll_is_long(&self, line: usize) -> bool {
        self.ll_long.get(line - 1).copied().unwrap_or(false)
    }

    fn line_has_comment(&self, line: usize) -> bool {
        self.comments.iter().any(|(l, _, _)| *l == line)
    }

    // ---- collections (send/csend/def/array/hash) ----

    /// `children_could_be_broken_up?`
    fn ll_could_break(&self, elements: &[(usize, usize)]) -> bool {
        if elements.is_empty() {
            return false;
        }
        let first_line = self.ll_line_of(elements[0].0);
        let last_line = self.ll_line_of(elements[elements.len() - 1].1.saturating_sub(1).max(elements[elements.len() - 1].0));
        if first_line == last_line {
            return false;
        }
        let mut last_seen: isize = -1;
        for (s, e) in elements {
            if last_seen >= self.ll_line_of(*s) as isize {
                return true;
            }
            last_seen = self.ll_line_of((*e).saturating_sub(1).max(*s)) as isize;
        }
        false
    }

    /// Enter a collection node: push its ancestor frame, and nominate a break
    /// position if it qualifies. The element list is built lazily — the frame
    /// itself needs only the node span and element count, so the common case
    /// (short lines) allocates nothing.
    pub(crate) fn ll_enter_collection(
        &mut self,
        node_start: usize,
        node_end: usize,
        count: usize,
        build: impl FnOnce() -> Vec<(usize, usize)>,
        kind: LlKind,
        extra: LlCallInfo,
    ) {
        if !self.ll_active {
            return;
        }
        let first_line = self.ll_line_of(node_start);
        let last_line = self.ll_line_of(node_end.saturating_sub(1).max(node_start));
        let breakable = count >= 2;
        let node_multiline = first_line != last_line;
        let mut build = Some(build);
        let mut elements: Option<Vec<(usize, usize)>> = None;
        // children_could_be_broken_up? — trivially false when the whole node
        // sits on one line
        let could_break = breakable && node_multiline && {
            let els = elements.get_or_insert_with(|| build.take().unwrap()());
            self.ll_could_break(els)
        };
        // hook body — rubocop's check_for_breakable_node
        'hook: {
            if extra.skip_hook || !breakable || !self.ll_is_long(first_line) || self.line_has_comment(first_line) {
                break 'hook;
            }
            if self.ll_break.contains_key(&first_line) || self.ll_semi.contains_key(&first_line) || self.ll_block.contains_key(&first_line) {
                break 'hook;
            }
            let elements = match elements.as_ref() {
                Some(e) => e,
                None => {
                    elements = Some(build.take().unwrap()());
                    elements.as_ref().unwrap()
                }
            };
            // safe_to_ignore?
            let multiline = match kind {
                // def: signature counts, not the body
                LlKind::Def => {
                    let last = elements.last().map(|(_, e)| self.ll_line_of(e.saturating_sub(1))).unwrap_or(first_line);
                    first_line != last
                }
                _ => node_multiline,
            };
            if multiline {
                break 'hook;
            }
            // contained_by_breakable_collection_on_same_line?
            for f in self.ll_coll_stack.iter().rev() {
                if f.first_line != first_line {
                    break;
                }
                if f.breakable {
                    break 'hook;
                }
            }
            // contained_by_multiline_collection_that_could_be_broken_up?
            if let Some(f) = self.ll_coll_stack.iter().rev().find(|f| f.breakable) {
                if f.could_break {
                    break 'hook;
                }
            }
            // extract_first_element_over_column_limit
            let mut elems: &[(usize, usize)] = elements;
            if matches!(kind, LlKind::Call) && !extra.parenthesized && !extra.first_arg_heredoc {
                elems = &elems[1..];
            }
            let mut i = 0;
            while i < elems.len()
                && self.col0(elems[i].0) <= self.ll_max
                && self.ll_line_of(elems[i].0) == first_line
            {
                i += 1;
            }
            // shift_elements_for_heredoc_arg (call/array only)
            if matches!(kind, LlKind::Call | LlKind::Array) {
                if let Some(hi) = extra.heredoc_arg_index {
                    if hi == 0 {
                        break 'hook;
                    }
                    if hi < i {
                        i = hi + 1;
                    }
                }
            }
            let chosen = if i == 0 { elems.first() } else { elems.get(i - 1) };
            if let Some((s, _)) = chosen {
                self.ll_break.insert(first_line, (*s, None));
            }
        }
        self.ll_coll_stack.push(LlFrame { first_line, breakable, could_break });
    }

    pub(crate) fn ll_exit_collection(&mut self) {
        if self.ll_active {
            self.ll_coll_stack.pop();
        }
    }

    /// Single-line block: nominate right after `{` / `do` / the params' `|`.
    /// Overwrites anything already nominated for the line (rubocop's hook has
    /// no existence check).
    pub(crate) fn ll_check_block(&mut self, call: &ruby_prism::CallNode<'_>, block: &ruby_prism::BlockNode<'_>) {
        if !self.ll_active {
            return;
        }
        let bl = block.location();
        let line = self.ll_line_of(bl.start_offset());
        if !self.ll_is_long(line) || self.ll_line_of(bl.end_offset().saturating_sub(1)) != line {
            return;
        }
        // receiver_contains_heredoc?
        let mut recv = call.receiver();
        if let Some(r) = recv.take() {
            if self.ll_node_contains_heredoc(&r) {
                return;
            }
        }
        let is_lambda = call.receiver().is_none() && call.name().as_slice() == b"lambda";
        // numbered (`_1`) and `it` blocks have no argument list to rubocop —
        // they take the opening-keyword path
        let pipe = block
            .parameters()
            .and_then(|p| p.as_block_parameters_node().and_then(|bp| bp.closing_loc().map(|c| c.start_offset())));
        let anchor = match (pipe, is_lambda) {
            (Some(p), false) => p,
            _ => {
                let open = block.opening_loc();
                if open.as_slice() == b"{" {
                    open.start_offset()
                } else {
                    open.start_offset() + 1 // `do` → +1 below lands past `do`
                }
            }
        };
        self.ll_block.insert(line, anchor + 1);
    }

    /// `->(x) { ... }`: rubocop's on_block with `lambda?` true — always the
    /// opening-brace/do path.
    pub(crate) fn ll_check_lambda(&mut self, node: &ruby_prism::LambdaNode<'_>) {
        if !self.ll_active {
            return;
        }
        let l = node.location();
        let line = self.ll_line_of(l.start_offset());
        if !self.ll_is_long(line) || self.ll_line_of(l.end_offset().saturating_sub(1)) != line {
            return;
        }
        let open = node.opening_loc();
        let anchor = if open.as_slice() == b"{" { open.start_offset() } else { open.start_offset() + 1 };
        self.ll_block.insert(line, anchor + 1);
    }

    fn ll_node_contains_heredoc(&self, node: &ruby_prism::Node<'_>) -> bool {
        // a heredoc opener anywhere in the receiver's span
        let l = node.location();
        let (s, e) = (self.ll_line_of(l.start_offset()), self.ll_line_of(l.end_offset().saturating_sub(1).max(l.start_offset())));
        self.heredoc_lines.iter().any(|(hs, he, _, _)| *hs >= s && *he <= e + 1 || (*hs).saturating_sub(1) >= s && (*hs).saturating_sub(1) <= e)
    }

    /// Consecutive statements on one line: nominate right after the first
    /// separating `;` (never a line-trailing one). First nomination wins.
    pub(crate) fn ll_check_semicolons(&mut self, node: &ruby_prism::StatementsNode<'_>) {
        if !self.ll_active {
            return;
        }
        let mut prev_end: Option<usize> = None;
        for stmt in node.body().iter() {
            let l = stmt.location();
            if let Some(pe) = prev_end {
                let line = self.ll_line_of(pe.saturating_sub(1).max(0));
                if self.ll_is_long(line) && !self.ll_semi.contains_key(&line) {
                    for (p, b) in self.src[pe..l.start_offset()].iter().enumerate() {
                        if *b != b';' {
                            continue;
                        }
                        let pos = pe + p + 1;
                        let next = self.src.get(pos);
                        if !matches!(next, None | Some(b'\n') | Some(b'\r') | Some(b';')) && self.ll_line_of(pos) == line {
                            self.ll_semi.insert(line, pos);
                            break;
                        }
                    }
                }
            }
            prev_end = Some(l.end_offset());
        }
    }

    // ---- SplitStrings ----

    /// on_str: a single-line, non-heredoc plain string whose parent isn't a
    /// pair/kwoptarg/array, crossing the limit → split position.
    pub(crate) fn ll_check_str(&mut self, node: &ruby_prism::StringNode<'_>) {
        if !self.ll_active || !self.ll_split {
            return;
        }
        let l = node.location();
        let line = self.ll_line_of(l.start_offset());
        if !self.ll_is_long(line)
            || self.ll_break.contains_key(&line)
            || self.ll_semi.contains_key(&line)
            || self.ll_block.contains_key(&line)
        {
            return;
        }
        if self.ll_line_of(l.end_offset().saturating_sub(1)) != line {
            return; // multi-line
        }
        if self.ll_str_skip.contains(&l.start_offset()) {
            return; // parent is pair / kwoptarg / array
        }
        let delim = match node.opening_loc() {
            Some(o) if o.as_slice() == b"'" || o.as_slice() == b"\"" => o.as_slice()[0],
            Some(_) => return, // %q(...), heredoc, ?c — not splittable
            None => match self.ll_dstr_delim.last() {
                Some(d) => *d,
                None => return,
            },
        };
        let Some(pos) = self.ll_breakable_string_position(l.start_offset(), l.end_offset()) else {
            return;
        };
        self.ll_break.insert(line, (pos, Some(delim)));
    }

    /// on_dstr: an interpolated single-line string with 2+ parts → break
    /// before the first `#{` that straddles the limit.
    pub(crate) fn ll_check_dstr(&mut self, node: &ruby_prism::InterpolatedStringNode<'_>) {
        if !self.ll_active || !self.ll_split {
            return;
        }
        let l = node.location();
        let line = self.ll_line_of(l.start_offset());
        if !self.ll_is_long(line)
            || self.ll_break.contains_key(&line)
            || self.ll_semi.contains_key(&line)
            || self.ll_block.contains_key(&line)
        {
            return;
        }
        if self.ll_line_of(l.end_offset().saturating_sub(1)) != line {
            return;
        }
        if self.ll_str_skip.contains(&l.start_offset()) {
            return;
        }
        let delim = match node.opening_loc() {
            Some(o) if o.as_slice() == b"'" || o.as_slice() == b"\"" => o.as_slice()[0],
            _ => return,
        };
        let parts: Vec<_> = node.parts().iter().collect();
        if parts.len() <= 1 {
            return;
        }
        for p in &parts {
            if p.as_embedded_statements_node().is_some() {
                let ps = p.location().start_offset();
                let c = self.col0(ps);
                let last = self.col0(p.location().end_offset());
                if c < self.ll_max && last >= self.ll_max {
                    self.ll_break.insert(line, (ps, Some(delim)));
                    return;
                }
            }
        }
    }

    /// rubocop's breakable_string_position/breakable_string_range: prefer the
    /// last whitespace inside the largest fitting prefix, else back off a
    /// straddled escape sequence, else cut at max-3.
    fn ll_breakable_string_position(&self, start: usize, end: usize) -> Option<usize> {
        let max = self.ll_max;
        let last_col = self.col0(end);
        if last_col < max {
            return None;
        }
        let source = String::from_utf8_lossy(&self.src[start..end]);
        let chars: Vec<char> = source.chars().collect();
        // largest_possible_string: the parent-column offset approximated by
        // the node's offset from the line's indentation
        let node_col = self.col0(start);
        let line_start = self.idx.starts[self.ll_line_of(start) - 1];
        let indent = self.src[line_start..start].iter().take_while(|b| **b == b' ' || **b == b'\t').count();
        let offset = node_col.saturating_sub(indent);
        let max_len = (max.saturating_sub(3)).saturating_sub(offset);
        let relevant: &[char] = &chars[..max_len.min(chars.len())];

        let cut_chars = if let Some(sp) = relevant.iter().rposition(|c| c.is_whitespace()) {
            sp + 1
        } else if let Some(ep) = Self::ll_trailing_escape(relevant) {
            ep
        } else {
            let adj = max as isize - last_col as isize - 3;
            if adj.unsigned_abs() > chars.len() {
                return None;
            }
            let cc = chars.len() as isize + adj;
            if cc <= 0 {
                return None;
            }
            cc as usize
        };
        if cut_chars == 0 || cut_chars >= chars.len() {
            return None;
        }
        // char count → byte offset
        let bytes: usize = chars[..cut_chars].iter().map(|c| c.len_utf8()).sum();
        Some(start + bytes)
    }

    /// `\\(u[hex]{0,4}|x[hex]{0,2})?\z` — a (possibly partial) escape at the
    /// very end of the window; returns the backslash's char index.
    fn ll_trailing_escape(s: &[char]) -> Option<usize> {
        let n = s.len();
        let mut i = n;
        // optional hex tail
        let hex = |c: char| c.is_ascii_hexdigit();
        let mut j = i;
        while j > 0 && hex(s[j - 1]) && i - (j - 1) <= 4 {
            j -= 1;
        }
        if j > 0 && (s[j - 1] == 'u' && i - j <= 4 || s[j - 1] == 'x' && i - j <= 2) && j > 1 && s[j - 2] == '\\' {
            i = j - 2;
        } else if n > 0 && s[n - 1] == '\\' {
            i = n - 1;
        } else {
            return None;
        }
        Some(i)
    }

    /// The fix for a flagged long line, if a break position was nominated.
    /// Returns whether one was emitted (the offense's correctable flag).
    pub(crate) fn ll_fix_for_line(&mut self, line: usize) -> bool {
        let entry = self
            .ll_block
            .get(&line)
            .map(|p| (*p, None))
            .or_else(|| self.ll_semi.get(&line).map(|p| (*p, None)))
            .or_else(|| self.ll_break.get(&line).copied());
        if let Some((pos, delim)) = entry {
            let ins = match delim {
                Some(d) => {
                    let d = d as char;
                    format!("{d} \\\n{d}").into_bytes()
                }
                None => b"\n".to_vec(),
            };
            self.fixes.push((pos, pos, ins));
            return true;
        }
        false
    }
}

pub(crate) struct LlFrame {
    pub first_line: usize,
    pub breakable: bool,
    pub could_break: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum LlKind {
    Call,
    Def,
    Array,
    Hash,
}

#[derive(Default)]
pub(crate) struct LlCallInfo {
    pub parenthesized: bool,
    pub first_arg_heredoc: bool,
    pub heredoc_arg_index: Option<usize>,
    pub skip_hook: bool,
}
