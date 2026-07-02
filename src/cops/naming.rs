//! Naming department: Naming/MethodName across all the ways Ruby names a
//! method — `def`, `alias`, `alias_method`, `attr_*`, Struct/Data members.
use super::Cops;

impl<'a> Cops<'a> {
    /// Naming/MethodName on a `def` — the definition's own name.
    pub(crate) fn check_method_name_def(&mut self, node: &ruby_prism::DefNode) {
        if !self.hot.method_name {
            return;
        }
        let style = self.hot.method_name_style.clone();
        let style = style.as_str();
        let name = node.name().as_slice();
        // Operator methods (`def +`, `def []=`, `def ~@`) are exempt.
        if matches!(name.first(), Some(c) if c.is_ascii_punctuation()) {
            return;
        }
        // rubocop's class_emitter_method?: a singleton method (`def x.Start`)
        // named after a class defined in an enclosing body is a factory and
        // exempt. (rubocop checks exactly the nearest non-def ancestor body;
        // we scan the whole scope stack — a slight over-acceptance.)
        if node.receiver().is_some()
            && self.class_children_stack.iter().any(|f| f.iter().any(|c| c == name))
        {
            return;
        }
        if !name_matches_style(name, style) && !self.allowed("Naming/MethodName", name) {
            self.push(node.name_loc().start_offset(), "Naming/MethodName", false,
                format!("Use {style} for method names."));
        }
    }

    /// Naming/MethodName on `alias new_name old_name` — the new name only.
    pub(crate) fn check_method_name_alias(&mut self, node: &ruby_prism::AliasMethodNode) {
        if !self.hot.method_name {
            return;
        }
        let style = self.hot.method_name_style.clone();
        let nn = node.new_name();
        if let Some((nm, off)) = method_name_arg(&nn, self.src) {
            // operator methods (`alias << push`) are exempt
            if matches!(nm.first(), Some(c) if c.is_ascii_punctuation()) {
                return;
            }
            if !name_matches_style(nm, &style) && !self.allowed("Naming/MethodName", nm) {
                self.push(off, "Naming/MethodName", false, format!("Use {style} for method names."));
            }
        }
    }

    /// Naming/MethodName through macros: check the relevant symbol/string args
    /// of attr*, alias_method, and Struct/Data member lists.
    pub(crate) fn check_method_name_macros(&mut self, node: &ruby_prism::CallNode) {
        // cheap name prefilter BEFORE the config lookups and arg collection —
        // this runs for every call node in the file
        if !matches!(
            node.name().as_slice(),
            b"attr" | b"attr_reader" | b"attr_writer" | b"attr_accessor" | b"alias_method"
                | b"new" | b"define" | b"define_method" | b"define_singleton_method"
        ) || !self.hot.method_name
        {
            return;
        }
        let style = self.hot.method_name_style.clone();
        let args: Vec<ruby_prism::Node> = node
            .arguments()
            .map(|a| a.arguments().iter().collect())
            .unwrap_or_default();
        let recv_src = node.receiver().map(|r| {
            let l = r.location();
            self.src[l.start_offset()..l.end_offset()].to_vec()
        });
        // Which args carry method names for this macro? attr*/alias_method/
        // define_method are BARE macros (nil receiver) in rubocop's patterns.
        let bare = node.receiver().is_none();
        let members: &[ruby_prism::Node] = match node.name().as_slice() {
            b"attr" | b"attr_reader" | b"attr_writer" | b"attr_accessor" if bare => &args,
            // alias_method(new, old) — only the new name, and only at arity 2.
            b"alias_method" if bare && args.len() == 2 => &args[0..1],
            // define_method(:name) { } / define_singleton_method — first arg.
            b"define_method" | b"define_singleton_method" if bare && !args.is_empty() => &args[0..1],
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
        // Anchoring differs by macro: attr*/alias_method/define_method go
        // through rubocop's range_position on the SEND (right after the
        // selector); Struct.new/Data.define members anchor on the ARG itself.
        let send_anchor = matches!(
            node.name().as_slice(),
            b"attr" | b"attr_reader" | b"attr_writer" | b"attr_accessor" | b"alias_method"
                | b"define_method" | b"define_singleton_method"
        );
        let sel_anchor = node
            .message_loc()
            .map(|l| l.end_offset() + 1)
            .unwrap_or_else(|| node.location().start_offset());
        let bad: Vec<usize> = members
            .iter()
            .filter_map(|arg| method_name_arg(arg, self.src))
            .filter(|(nm, _)| !matches!(nm.first(), Some(c) if c.is_ascii_punctuation()))
            .filter(|(nm, _)| !name_matches_style(nm, &style) && !self.allowed("Naming/MethodName", nm))
            .map(|(_, off)| off)
            .collect();
        for off in bad {
            let anchor = if send_anchor { sel_anchor } else { off };
            self.push(anchor, "Naming/MethodName", false, format!("Use {style} for method names."));
        }
    }
}

impl<'a> Cops<'a> {
    /// Naming/ConstantName — constant assignments want SCREAMING_SNAKE_CASE,
    /// unless the RHS is a method call / const / conditional-with-const
    /// (rubocop treats those as class-factory idioms).
    pub(crate) fn check_constant_name(&mut self, name: &[u8], name_off: usize, value: Option<&ruby_prism::Node>) {
        const COP: &str = "Naming/ConstantName";
        if !self.on(COP) {
            return;
        }
        if String::from_utf8_lossy(name)
            .chars()
            .all(|c| c.is_numeric() || c.is_uppercase() || c == '_')
        {
            return;
        }
        if let Some(v) = value {
            if constant_rhs_allowed(v) {
                return;
            }
        }
        self.push(name_off, COP, false, "Use SCREAMING_SNAKE_CASE for constants.");
    }

    /// Naming/ClassAndModuleCamelCase — no underscores in class/module names
    /// (AllowedNames substrings removed first).
    pub(crate) fn check_camel_case_name(&mut self, constant_path: &ruby_prism::Node) {
        const COP: &str = "Naming/ClassAndModuleCamelCase";
        if !self.on(COP) {
            return;
        }
        // A dynamic parent (`class lvar::MyClass`) isn't part of the checked
        // name — only constant chains are.
        let src = if let Some(cp) = constant_path.as_constant_path_node() {
            match cp.parent() {
                Some(p)
                    if p.as_constant_read_node().is_none()
                        && p.as_constant_path_node().is_none() =>
                {
                    let nl = cp.name_loc();
                    &self.src[nl.start_offset()..nl.end_offset()]
                }
                _ => self.node_src(constant_path),
            }
        } else {
            self.node_src(constant_path)
        };
        if !src.contains(&b'_') {
            return;
        }
        let mut name = String::from_utf8_lossy(src).into_owned();
        if let Some(v) = self.cfg.get(COP, "AllowedNames") {
            for allowed in crate::config::parse_allowed_list(v) {
                name = name.replace(&allowed, "");
            }
        }
        if name.contains('_') {
            self.push(constant_path.location().start_offset(), COP, false,
                "Use CamelCase for classes and modules.");
        }
    }

    /// Naming/BinaryOperatorParameterName — `def ==(other)` etc. must name
    /// the single parameter `other`.
    pub(crate) fn check_binary_operator_parameter(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Naming/BinaryOperatorParameterName";
        if !self.on(COP) {
            return;
        }
        // rubocop's pattern matches `def` only — singleton defs (`def x.==`)
        // are exempt.
        if node.receiver().is_some() {
            return;
        }
        let name = node.name().as_slice();
        const EXCLUDED: &[&[u8]] = &[b"+@", b"-@", b"[]", b"[]=", b"<<", b"===", b"`", b"=~"];
        if EXCLUDED.contains(&name) {
            return;
        }
        let op_like = matches!(name, b"eql?" | b"equal?");
        let word_start = String::from_utf8_lossy(name)
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if word_start && !op_like {
            return;
        }
        // exactly one plain required parameter
        let Some(params) = node.parameters() else { return };
        let reqs: Vec<_> = params.requireds().iter().collect();
        if reqs.len() != 1
            || params.optionals().iter().next().is_some()
            || params.rest().is_some()
            || params.posts().iter().next().is_some()
            || params.keywords().iter().next().is_some()
            || params.keyword_rest().is_some()
            || params.block().is_some()
        {
            return;
        }
        let Some(arg) = reqs[0].as_required_parameter_node() else { return };
        let arg_name = arg.name().as_slice();
        if matches!(arg_name, b"other" | b"_other") {
            return;
        }
        let op = String::from_utf8_lossy(name);
        self.push(arg.location().start_offset(), COP, true,
            format!("When defining the `{op}` operator, name its argument `other`."));
        // rename the parameter and every reference to it in the body
        let al = arg.location();
        self.fixes.push((al.start_offset(), al.end_offset(), b"other".to_vec()));
        if let Some(body) = node.body() {
            let mut spans = Vec::new();
            collect_lvar_spans(&body, arg_name, &mut spans);
            for (s, e) in spans {
                self.fixes.push((s, e, b"other".to_vec()));
            }
        }
    }
}

/// Spans of local-variable reads/writes named `name` within `node`.
fn collect_lvar_spans(node: &ruby_prism::Node, name: &[u8], out: &mut Vec<(usize, usize)>) {
    struct V<'x> {
        name: &'x [u8],
        out: &'x mut Vec<(usize, usize)>,
    }
    impl<'pr, 'x> ruby_prism::Visit<'pr> for V<'x> {
        fn visit_local_variable_read_node(&mut self, n: &ruby_prism::LocalVariableReadNode<'pr>) {
            if n.name().as_slice() == self.name {
                let l = n.location();
                self.out.push((l.start_offset(), l.end_offset()));
            }
        }
        fn visit_local_variable_write_node(&mut self, n: &ruby_prism::LocalVariableWriteNode<'pr>) {
            if n.name().as_slice() == self.name {
                let l = n.name_loc();
                self.out.push((l.start_offset(), l.end_offset()));
            }
            ruby_prism::visit_local_variable_write_node(self, n);
        }
    }
    let mut v = V { name, out };
    use ruby_prism::Visit;
    v.visit(node);
}

/// rubocop's `allowed_assignment?` for Naming/ConstantName.
fn constant_rhs_allowed(v: &ruby_prism::Node) -> bool {
    // blocks / lambdas
    if v.as_lambda_node().is_some() {
        return true;
    }
    if let Some(c) = v.as_call_node() {
        if c.block().is_some() {
            return true;
        }
        // any method call whose receiver is absent or not a literal
        let literal_recv = c.receiver().map(|r| {
            let inner = r
                .as_parentheses_node()
                .and_then(|p| p.body().and_then(|b| b.as_statements_node()).and_then(|s| s.body().iter().last()));
            is_literal(inner.as_ref().unwrap_or(&r))
        });
        return !literal_recv.unwrap_or(false);
    }
    // consts / further casgns
    if v.as_constant_read_node().is_some()
        || v.as_constant_path_node().is_some()
        || v.as_constant_write_node().is_some()
        || v.as_constant_path_write_node().is_some()
    {
        return true;
    }
    // a conditional with a const branch
    if let Some(i) = v.as_if_node() {
        let then_const = i.statements().and_then(|s| s.body().iter().last()).is_some_and(|n| is_const(&n));
        let else_const = i
            .subsequent()
            .and_then(|e| e.as_else_node())
            .and_then(|e| e.statements())
            .and_then(|s| s.body().iter().last())
            .is_some_and(|n| is_const(&n));
        return then_const || else_const;
    }
    false
}
fn is_const(n: &ruby_prism::Node) -> bool {
    n.as_constant_read_node().is_some() || n.as_constant_path_node().is_some()
}
fn is_literal(n: &ruby_prism::Node) -> bool {
    n.as_integer_node().is_some()
        || n.as_float_node().is_some()
        || n.as_string_node().is_some()
        || n.as_symbol_node().is_some()
        || n.as_array_node().is_some()
        || n.as_hash_node().is_some()
        || n.as_true_node().is_some()
        || n.as_false_node().is_some()
        || n.as_nil_node().is_some()
        || n.as_regular_expression_node().is_some()
        || n.as_range_node().is_some()
        || n.as_interpolated_string_node().is_some()
}

/// Does `name` conform to the active `Naming/MethodName` EnforcedStyle?
/// rubocop's ConfigurableNaming::FORMATS verbatim — Unicode-aware, so
/// `última_vista` is valid snake_case.
fn name_matches_style(name: &[u8], style: &str) -> bool {
    static SNAKE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static CAMEL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = match style {
        "camelCase" => CAMEL.get_or_init(|| {
            regex::Regex::new(r"^@{0,2}(?:_|_?\p{Ll}[\d\p{Ll}\p{Lu}]*)[!?=]?$").unwrap()
        }),
        _ => SNAKE
            .get_or_init(|| regex::Regex::new(r"^@{0,2}[\d\p{Ll}_]+[!?=]?$").unwrap()),
    };
    re.is_match(&String::from_utf8_lossy(name))
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

impl<'a> Cops<'a> {
    /// Naming/BlockParameterName — checks block parameter names for length,
    /// case, forbidden names, and number endings. Highly configurable.
    pub(crate) fn check_block_parameter_name(&mut self, block: &ruby_prism::BlockNode) {
        const COP: &str = "Naming/BlockParameterName";
        if !self.on(COP) {
            return;
        }
        let Some(params_node) = block.parameters() else {
            return;
        };
        let Some(params) = params_node.as_block_parameters_node() else {
            return;
        };
        let Some(pn) = params.parameters() else {
            return;
        };

        let min_length = self.cfg.param(COP, "MinNameLength")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);
        let allow_nums = self.cfg.param(COP, "AllowNamesEndingInNumbers")
            == Some("true");
        let allowed_names: Vec<String> = self.cfg.param(COP, "AllowedNames")
            .map(|v| crate::config::parse_allowed_list(v))
            .unwrap_or_default();
        let forbidden_names: Vec<String> = self.cfg.param(COP, "ForbiddenNames")
            .map(|v| crate::config::parse_allowed_list(v))
            .unwrap_or_default();

        // Process required parameters
        for param in pn.requireds().iter() {
            if let Some(rp) = param.as_required_parameter_node() {
                self.check_block_param(rp.name().as_slice(), rp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process optional parameters
        for param in pn.optionals().iter() {
            if let Some(op) = param.as_optional_parameter_node() {
                self.check_block_param(op.name().as_slice(), op.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process rest parameter
        if let Some(rest) = pn.rest() {
            if let Some(rp) = rest.as_rest_parameter_node() {
                if let Some(name) = rp.name() {
                    let loc = rp.location();
                    self.check_block_param(name.as_slice(), loc.start_offset(),
                        min_length, allow_nums, &allowed_names, &forbidden_names);
                }
            }
        }

        // Process post parameters
        for param in pn.posts().iter() {
            if let Some(pp) = param.as_required_parameter_node() {
                self.check_block_param(pp.name().as_slice(), pp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process keyword parameters
        for param in pn.keywords().iter() {
            if let Some(kp) = param.as_optional_keyword_parameter_node() {
                self.check_block_param(kp.name().as_slice(), kp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            } else if let Some(kp) = param.as_required_keyword_parameter_node() {
                self.check_block_param(kp.name().as_slice(), kp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process keyword rest parameter
        if let Some(kwrest) = pn.keyword_rest() {
            if let Some(kw) = kwrest.as_keyword_rest_parameter_node() {
                if let Some(name) = kw.name() {
                    let loc = kw.location();
                    self.check_block_param(name.as_slice(), loc.start_offset(),
                        min_length, allow_nums, &allowed_names, &forbidden_names);
                }
            }
        }

        // Process block parameter
        if let Some(bp) = pn.block() {
            if let Some(name) = bp.name() {
                let loc = bp.location();
                self.check_block_param(name.as_slice(), loc.start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }
    }

    fn check_block_param(&mut self, name_bytes: &[u8], start_off: usize,
                         min_length: usize, allow_nums: bool, allowed_names: &[String],
                         forbidden_names: &[String]) {
        const COP: &str = "Naming/BlockParameterName";

        let full_name = String::from_utf8_lossy(name_bytes).into_owned();

        // Skip if full_name is just "_"
        if full_name == "_" {
            return;
        }

        // Remove leading underscores for name-based checks
        let name = full_name.trim_start_matches('_');

        // Skip if in allowed names
        if allowed_names.contains(&full_name) {
            return;
        }

        // Check forbidden names first
        if forbidden_names.contains(&name.to_string()) {
            let msg = format!("Do not use {name} as a name for a block parameter.");
            self.push(start_off, COP, false, msg);
            return; // Don't check other conditions if forbidden
        }

        // Check for uppercase characters
        if name.chars().any(|c| c.is_uppercase()) {
            self.push(start_off, COP, false,
                "Only use lowercase characters for block parameter.".to_string());
        }

        // Check minimum length
        if name.len() < min_length {
            let msg = format!("Block parameter must be at least {min_length} characters long.");
            self.push(start_off, COP, false, msg);
        }

        // Check for numbers at the end
        if !allow_nums && name.chars().last().is_some_and(|c| c.is_numeric()) {
            self.push(start_off, COP, false,
                "Do not end block parameter with a number.".to_string());
        }
    }
}
