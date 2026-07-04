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
        // cfg.get falls back to the schema default (true for this cop);
        // param() is user-config-only and silently read false here
        let allow_nums = self.cfg.get(COP, "AllowNamesEndingInNumbers") != Some("false");
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


impl<'a> super::Cops<'a> {

    /// Naming/HeredocDelimiterNaming — checks that heredoc delimiters are meaningful
    pub(crate) fn check_heredoc_delimiter_naming(&mut self,
        opening_loc: Option<ruby_prism::Location>,
        closing_loc: Option<ruby_prism::Location>) {
        const COP: &str = "Naming/HeredocDelimiterNaming";
        if !self.on(COP) {
            return;
        }

        // Check if this is a heredoc by looking at opening_loc
        let Some(opening) = opening_loc else {
            return;
        };

        if !opening.as_slice().starts_with(b"<<") {
            return;
        }

        let Some(closing) = closing_loc else {
            return;
        };

        // Extract the delimiter by filtering whitespace from closing_loc
        let delimiter_bytes: Vec<u8> = closing
            .as_slice()
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();

        if delimiter_bytes.is_empty() {
            return;
        }

        let delimiter_str = String::from_utf8_lossy(&delimiter_bytes);

        // Check if delimiter contains word characters (\w)
        let has_word_chars = delimiter_str.chars().any(|c| c.is_alphanumeric() || c == '_');

        if !has_word_chars {
            // Non-word delimiters are always forbidden
            self.push(closing.start_offset(), COP, false,
                "Use meaningful heredoc delimiters.".to_string());
            return;
        }

        // Get the forbidden delimiters from config
        // the default is an ARRAY (not in the flat schema table) — fall back
        // to rubocop's shipped pattern when the config doesn't set one
        let forbidden_patterns = match self.cfg.get(COP, "ForbiddenDelimiters") {
            Some(list) => crate::config::parse_allowed_list(list),
            None => vec![r"(^|\s)(EO[A-Z]{1}|END)(\s|$)".to_string()],
        };
        {

            for pattern_str in forbidden_patterns {
                // Strip Ruby regex wrappers if present
                let pattern = pattern_str
                    .strip_prefix("!ruby/regexp")
                    .map(|s| s.trim())
                    .and_then(|s| s.strip_prefix('/'))
                    .and_then(|s| s.rsplit_once('/').map(|(b, _)| b))
                    .unwrap_or(&pattern_str);

                // Try to compile and match the regex (case-insensitive like Ruby regexes)
                if let Ok(re) = regex::Regex::new(&format!("(?i){pattern}")) {
                    if re.is_match(&delimiter_str) {
                        self.push(closing.start_offset(), COP, false,
                            "Use meaningful heredoc delimiters.".to_string());
                        return;
                    }
                }
            }
        }
    }
}

/// Naming/MethodParameterName's default `AllowedNames` (config/default.yml) —
/// unlike Naming/BlockParameterName, this default is non-empty, and array
/// defaults don't live in the generated `SCHEMA` table (only scalars do), so
/// it's hardcoded here.
const DEFAULT_METHOD_PARAMETER_ALLOWED_NAMES: &[&str] =
    &["as", "at", "by", "cc", "db", "id", "if", "in", "io", "ip", "of", "on", "os", "pp", "to"];

impl<'a> Cops<'a> {
    /// Naming/MethodParameterName — the UncommunicativeName mixin (checks
    /// length, case, forbidden names, and number endings) applied to `def`/
    /// `def self.` parameters. Same logic as `check_block_parameter_name`
    /// above, applied to a `DefNode`'s parameters instead of a block's.
    pub(crate) fn check_method_parameter_name(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Naming/MethodParameterName";
        if !self.on(COP) {
            return;
        }
        let Some(pn) = node.parameters() else {
            return;
        };

        let min_length = self.cfg.param(COP, "MinNameLength")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);
        // cfg.get falls back to the schema default (true for this cop);
        // param() is user-config-only and silently reads false here
        let allow_nums = self.cfg.get(COP, "AllowNamesEndingInNumbers") != Some("false");
        let allowed_names: Vec<String> = self.cfg.param(COP, "AllowedNames")
            .map(crate::config::parse_allowed_list)
            .unwrap_or_else(|| {
                DEFAULT_METHOD_PARAMETER_ALLOWED_NAMES.iter().map(|s| s.to_string()).collect()
            });
        let forbidden_names: Vec<String> = self.cfg.param(COP, "ForbiddenNames")
            .map(crate::config::parse_allowed_list)
            .unwrap_or_default();

        // Process required parameters
        for param in pn.requireds().iter() {
            if let Some(rp) = param.as_required_parameter_node() {
                self.check_method_param(rp.name().as_slice(), rp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process optional parameters
        for param in pn.optionals().iter() {
            if let Some(op) = param.as_optional_parameter_node() {
                self.check_method_param(op.name().as_slice(), op.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process rest parameter
        if let Some(rest) = pn.rest() {
            if let Some(rp) = rest.as_rest_parameter_node() {
                if let Some(name) = rp.name() {
                    let loc = rp.location();
                    self.check_method_param(name.as_slice(), loc.start_offset(),
                        min_length, allow_nums, &allowed_names, &forbidden_names);
                }
            }
        }

        // Process post parameters
        for param in pn.posts().iter() {
            if let Some(pp) = param.as_required_parameter_node() {
                self.check_method_param(pp.name().as_slice(), pp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process keyword parameters
        for param in pn.keywords().iter() {
            if let Some(kp) = param.as_optional_keyword_parameter_node() {
                self.check_method_param(kp.name().as_slice(), kp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            } else if let Some(kp) = param.as_required_keyword_parameter_node() {
                self.check_method_param(kp.name().as_slice(), kp.location().start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }

        // Process keyword rest parameter
        if let Some(kwrest) = pn.keyword_rest() {
            if let Some(kw) = kwrest.as_keyword_rest_parameter_node() {
                if let Some(name) = kw.name() {
                    let loc = kw.location();
                    self.check_method_param(name.as_slice(), loc.start_offset(),
                        min_length, allow_nums, &allowed_names, &forbidden_names);
                }
            }
        }

        // Process block parameter
        if let Some(bp) = pn.block() {
            if let Some(name) = bp.name() {
                let loc = bp.location();
                self.check_method_param(name.as_slice(), loc.start_offset(),
                    min_length, allow_nums, &allowed_names, &forbidden_names);
            }
        }
    }

    /// Applies the UncommunicativeName mixin's checks to a single `def`
    /// parameter. Unlike `check_block_param`'s early `return` after a
    /// forbidden-name hit, the real mixin (`issue_offenses`) evaluates every
    /// condition independently — a name can register more than one offense
    /// (e.g. both forbidden AND uppercase) — so this doesn't short-circuit.
    fn check_method_param(&mut self, name_bytes: &[u8], start_off: usize,
                          min_length: usize, allow_nums: bool, allowed_names: &[String],
                          forbidden_names: &[String]) {
        const COP: &str = "Naming/MethodParameterName";

        // Argument names might be "_" or prefixed with "_" to indicate they
        // are unused. Trim away this prefix and only analyse the basename.
        let full_name = String::from_utf8_lossy(name_bytes).into_owned();
        if full_name == "_" {
            return;
        }
        let name = full_name.trim_start_matches('_');

        // allowed_names/forbidden_names match against the underscore-trimmed
        // name, not the full (possibly `_`-prefixed) name.
        if allowed_names.iter().any(|n| n == name) {
            return;
        }

        if forbidden_names.iter().any(|n| n == name) {
            self.push(start_off, COP, false,
                format!("Do not use {name} as a name for a method parameter."));
        }
        if name.chars().any(|c| c.is_uppercase()) {
            self.push(start_off, COP, false,
                "Only use lowercase characters for method parameter.".to_string());
        }
        if name.chars().count() < min_length {
            self.push(start_off, COP, false,
                format!("Method parameter must be at least {min_length} characters long."));
        }
        if allow_nums {
            return;
        }
        if name.chars().last().is_some_and(|c| c.is_ascii_digit()) {
            self.push(start_off, COP, false,
                "Do not end method parameter with a number.".to_string());
        }
    }
}

/// Naming/AsciiIdentifiers — checks for non-ASCII characters in identifier
/// and constant names.
fn check_ascii_identifier_name(name: &[u8], offset: usize, is_constant: bool, check_constants: bool) -> Option<(usize, bool)> {
    // Skip if not checking constants and this is a constant
    if is_constant && !check_constants {
        return None;
    }

    let name_str = String::from_utf8_lossy(name);

    // Find first non-ASCII character sequence
    for (idx, ch) in name_str.chars().enumerate() {
        if !ch.is_ascii() {
            // Calculate byte offset of this character within the name
            let bytes_before = name_str.chars().take(idx).map(|c| c.len_utf8()).sum::<usize>();
            return Some((offset + bytes_before, is_constant));
        }
    }
    None
}

impl<'a> Cops<'a> {
    /// Naming/AsciiIdentifiers — visitor hook that checks all nodes with names
    pub(crate) fn check_ascii_identifiers_in_name(&mut self, name: &[u8], offset: usize, is_constant: bool) {
        const COP: &str = "Naming/AsciiIdentifiers";
        if !self.on(COP) {
            return;
        }

        let check_constants = self.cfg.get(COP, "AsciiConstants") != Some("false");

        if let Some((offense_offset, is_const)) = check_ascii_identifier_name(name, offset, is_constant, check_constants) {
            let msg = if is_const {
                "Use only ascii symbols in constants."
            } else {
                "Use only ascii symbols in identifiers."
            };
            self.push(offense_offset, COP, false, msg.to_string());
        }
    }
}

impl<'a> super::Cops<'a> {
    // Visitor methods for various identifier-bearing nodes

    pub(crate) fn check_ascii_local_variable_write(&mut self, node: &ruby_prism::LocalVariableWriteNode) {
        self.check_ascii_identifiers_in_name(node.name().as_slice(), node.name_loc().start_offset(), false);
    }

    pub(crate) fn check_ascii_constant_write(&mut self, node: &ruby_prism::ConstantWriteNode) {
        self.check_ascii_identifiers_in_name(node.name().as_slice(), node.name_loc().start_offset(), true);
    }

    pub(crate) fn check_ascii_constant_path_write(&mut self, node: &ruby_prism::ConstantPathWriteNode) {
        // For constant path writes, check the target constant
        let target = node.target();
        // Check just the name part (not the parent) - extract from source
        let name_loc = target.name_loc();
        let name_bytes = &self.src[name_loc.start_offset()..name_loc.end_offset()];
        self.check_ascii_identifiers_in_name(name_bytes, name_loc.start_offset(), true);
    }

    pub(crate) fn check_ascii_def(&mut self, node: &ruby_prism::DefNode) {
        // Method names are identifiers, not constants
        let name = node.name().as_slice();
        let offset = node.name_loc().start_offset();
        self.check_ascii_identifiers_in_name(name, offset, false);
    }

    pub(crate) fn check_ascii_class(&mut self, node: &ruby_prism::ClassNode) {
        // Check the constant name of the class
        let cp = node.constant_path();
        if let Some(const_path) = cp.as_constant_path_node() {
            // For constant paths like Foo::Bar, check just the last component
            let name_loc = const_path.name_loc();
            let name_bytes = &self.src[name_loc.start_offset()..name_loc.end_offset()];
            self.check_ascii_identifiers_in_name(name_bytes, name_loc.start_offset(), true);
        } else if let Some(const_read) = cp.as_constant_read_node() {
            // For simple constants like Foo
            let name = const_read.name().as_slice();
            let offset = const_read.location().start_offset();
            self.check_ascii_identifiers_in_name(name, offset, true);
        }
    }

    pub(crate) fn check_ascii_module(&mut self, node: &ruby_prism::ModuleNode) {
        // Check the constant name of the module
        let cp = node.constant_path();
        if let Some(const_path) = cp.as_constant_path_node() {
            // For constant paths like Foo::Bar, check just the last component
            let name_loc = const_path.name_loc();
            let name_bytes = &self.src[name_loc.start_offset()..name_loc.end_offset()];
            self.check_ascii_identifiers_in_name(name_bytes, name_loc.start_offset(), true);
        } else if let Some(const_read) = cp.as_constant_read_node() {
            // For simple constants like Foo
            let name = const_read.name().as_slice();
            let offset = const_read.location().start_offset();
            self.check_ascii_identifiers_in_name(name, offset, true);
        }
    }

}
impl<'a> super::Cops<'a> {
    /// Naming/AccessorMethodName — avoid get_* and set_* prefixes for
    /// accessor methods. get_x with no args / set_x with one arg naming warnings.
    pub(crate) fn check_accessor_method_name(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Naming/AccessorMethodName";
        if !self.on(COP) {
            return;
        }

        let name = node.name().as_slice();
        let name_str = String::from_utf8_lossy(name);

        // Skip method names ending with !, ?, or =
        if name_str.ends_with('!') || name_str.ends_with('?') || name_str.ends_with('=') {
            return;
        }

        let name_loc = node.name_loc();

        // Check for bad reader: get_* with no arguments
        if name_str.starts_with("get_") {
            let has_args = node.parameters().is_some_and(|p| {
                p.requireds().iter().next().is_some()
                    || p.optionals().iter().next().is_some()
                    || p.rest().is_some()
                    || p.posts().iter().next().is_some()
                    || p.keywords().iter().next().is_some()
                    || p.keyword_rest().is_some()
                    || p.block().is_some()
            });

            if !has_args {
                self.push(
                    name_loc.start_offset(),
                    COP,
                    false,
                    "Do not prefix reader method names with `get_`.".to_string(),
                );
                return;
            }
        }

        // Check for bad writer: set_* with exactly one required argument
        if name_str.starts_with("set_") {
            let Some(p) = node.parameters() else { return };

            // Must have exactly one required argument
            let reqs: Vec<_> = p.requireds().iter().collect();
            if reqs.len() == 1
                && p.optionals().iter().next().is_none()
                && p.rest().is_none()
                && p.posts().iter().next().is_none()
                && p.keywords().iter().next().is_none()
                && p.keyword_rest().is_none()
                && p.block().is_none()
            {
                self.push(
                    name_loc.start_offset(),
                    COP,
                    false,
                    "Do not prefix writer method names with `set_`.".to_string(),
                );
            }
        }
    }

}
impl<'a> super::Cops<'a> {

    /// Naming/HeredocDelimiterCase — checks that heredoc delimiters match the
    /// configured case (uppercase or lowercase).
    pub(crate) fn check_heredoc_delimiter_case(&mut self,
        opening_loc: Option<ruby_prism::Location>,
        closing_loc: Option<ruby_prism::Location>) {
        const COP: &str = "Naming/HeredocDelimiterCase";
        if !self.on(COP) {
            return;
        }

        // Check if this is a heredoc by looking at opening_loc
        let Some(opening) = opening_loc else {
            return;
        };

        if !opening.as_slice().starts_with(b"<<") {
            return;
        }

        let Some(closing) = closing_loc else {
            return;
        };

        // Extract the delimiter from the opening location
        let opening_bytes = opening.as_slice();

        // Use a regex to extract the delimiter name from the opening heredoc
        // Pattern: <<[~-]?['"`]?([^'"`]+)['"`]?
        static OPENING_DELIMITER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let pattern = OPENING_DELIMITER.get_or_init(|| {
            regex::Regex::new(r#"<<[~-]?['"`]?([^'"`]+)['"`]?"#).unwrap()
        });

        let opening_str = String::from_utf8_lossy(opening_bytes);
        let Some(caps) = pattern.captures(&opening_str) else {
            return;
        };

        let Some(delimiter_match) = caps.get(1) else {
            return;
        };

        let delimiter = delimiter_match.as_str();

        // Skip non-word delimiters (like '+')
        if !delimiter.chars().any(|c| c.is_alphanumeric() || c == '_') {
            return;
        }

        // Get the enforced style from config, default to "uppercase"
        let enforced_style = self.cfg.param(COP, "EnforcedStyle")
            .unwrap_or("uppercase");

        // Check if the delimiter matches the enforced style
        let correct = match enforced_style {
            "uppercase" => delimiter.chars().all(|c| !c.is_lowercase()),
            "lowercase" => delimiter.chars().all(|c| !c.is_uppercase()),
            _ => return, // Unknown style, skip
        };

        if correct {
            return; // Delimiter already matches the style
        }

        // Register offense anchored on closing delimiter
        let msg = format!("Use {} heredoc delimiters.", enforced_style);
        self.push(closing.start_offset(), COP, true, msg);

        // Prepare autocorrect: replace opening and closing delimiters
        let corrected_delimiter = match enforced_style {
            "uppercase" => delimiter.to_uppercase(),
            "lowercase" => delimiter.to_lowercase(),
            _ => return,
        };

        // Replace the opening delimiter (including quotes if present)
        // We need to replace just the delimiter part, preserving <<[~-] and quotes

        // Find the position of the delimiter within the opening string
        if let Some(delim_start) = opening_str.find(delimiter) {
            let delim_end = delim_start + delimiter.len();
            let opening_start = opening.start_offset();

            self.fixes.push((
                opening_start + delim_start,
                opening_start + delim_end,
                corrected_delimiter.as_bytes().to_vec(),
            ));
        }

        // Replace the closing delimiter (just the delimiter name on its own line)
        let closing_bytes = closing.as_slice();
        let closing_str = String::from_utf8_lossy(closing_bytes);

        // The closing line is just the delimiter (possibly with leading/trailing whitespace)
        let trimmed = closing_str.trim();
        if trimmed == delimiter {
            // Find the position of the delimiter within the closing line
            if let Some(delim_pos) = closing_str.find(delimiter) {
                self.fixes.push((
                    closing.start_offset() + delim_pos,
                    closing.start_offset() + delim_pos + delimiter.len(),
                    corrected_delimiter.as_bytes().to_vec(),
                ));
            }
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Naming/VariableName — on every `lvasgn`-shaped node (local/instance/
    /// class variable writes and reads, every `def`/block parameter kind,
    /// masgn/rescue/for-loop local-variable targets): AllowedIdentifiers
    /// exempts first (sigil-stripped exact match), then
    /// ForbiddenIdentifiers/ForbiddenPatterns register the `is forbidden`
    /// message, then the EnforcedStyle check (itself exempted by
    /// AllowedPatterns) — mirrors upstream's `on_lvasgn`/`check_name` order
    /// exactly. `class_emitter_method?` (the other `valid_name?` escape
    /// hatch) never applies here: it only fires for `defs_type?` nodes, and
    /// none of the node kinds that reach this are ever a `defs`.
    pub(crate) fn check_variable_name(&mut self, name: &[u8], start: usize) {
        const COP: &str = "Naming/VariableName";
        if !self.on(COP) {
            return;
        }
        if self.vn_allowed_identifier(name) {
            return;
        }
        if let Some(msg) = self.vn_forbidden_message(name) {
            self.push(start, COP, false, msg);
            return;
        }
        let style = self.cfg.enforced_style(COP);
        if name_matches_style(name, style) || self.allowed(COP, name) {
            return;
        }
        self.push(start, COP, false, format!("Use {style} for variable names."));
    }

    /// Naming/VariableName on `gvasgn`-shaped nodes — upstream's `on_gvasgn`
    /// runs ONLY the ForbiddenIdentifiers/ForbiddenPatterns check; globals
    /// are exempt from both the style check and AllowedIdentifiers (upstream
    /// never consults it there).
    pub(crate) fn check_variable_name_gvasgn(&mut self, name: &[u8], start: usize) {
        const COP: &str = "Naming/VariableName";
        if !self.on(COP) {
            return;
        }
        if let Some(msg) = self.vn_forbidden_message(name) {
            self.push(start, COP, false, msg);
        }
    }

    fn vn_list(&self, key: &str) -> Vec<String> {
        match self.cfg.get("Naming/VariableName", key) {
            Some(v) => crate::config::parse_allowed_list(v),
            None => Vec::new(),
        }
    }

    /// `AllowedIdentifiers#allowed_identifier?` — exact match against the
    /// name with its `@`/`@@`/`$` sigil(s) stripped.
    fn vn_allowed_identifier(&self, name: &[u8]) -> bool {
        let ids = self.vn_list("AllowedIdentifiers");
        if ids.is_empty() {
            return false;
        }
        let stripped = vn_strip_sigils(name);
        ids.iter().any(|id| id.as_bytes() == stripped.as_slice())
    }

    /// `ForbiddenIdentifiers#forbidden_identifier?` (sigil-stripped exact
    /// match) OR `ForbiddenPattern#forbidden_pattern?` (raw name, regex,
    /// sigil included, exactly like `AllowedPattern`) — the offense message
    /// when either hits.
    fn vn_forbidden_message(&self, name: &[u8]) -> Option<String> {
        let stripped = vn_strip_sigils(name);
        let by_id = {
            let ids = self.vn_list("ForbiddenIdentifiers");
            !ids.is_empty() && ids.iter().any(|id| id.as_bytes() == stripped.as_slice())
        };
        let hit = by_id || {
            let s = String::from_utf8_lossy(name);
            self.vn_list("ForbiddenPatterns")
                .iter()
                .any(|p| regex::Regex::new(p).map(|re| re.is_match(&s)).unwrap_or(false))
        };
        hit.then(|| format!("`{}` is forbidden, use another name instead.", String::from_utf8_lossy(name)))
    }
}

/// `AllowedIdentifiers::SIGILS` = `'@$'` — ivar/cvar/gvar names carry their
/// sigil(s) in `node.name` (prism's `name()`/`name_loc()` include them too,
/// e.g. `@fooBar`/`@@fooBar`/`$fooBar`), but the Allowed/Forbidden
/// IDENTIFIER lists (not the Pattern ones) compare against the bare name.
fn vn_strip_sigils(name: &[u8]) -> Vec<u8> {
    name.iter().copied().filter(|b| *b != b'@' && *b != b'$').collect()
}


impl<'a> super::Cops<'a> {
    /// Naming/RescuedExceptionsVariableName — `rescue Foo => bad_name` should
    /// name the variable `PreferredName` (default `e`), preserving a leading
    /// `_` (unused-variable convention). Ported from rubocop's `on_resbody` +
    /// `autocorrect`/`correct_node` (see the ruby source doc comment at the
    /// top of this cop's spec for the exact algorithm this mirrors).
    ///
    /// NOTE on prism vs whitequark: a chain of `rescue A => a; rescue B => b`
    /// is FLAT siblings in whitequark (both `resbody` nodes are direct
    /// children of one `:rescue` node) but prism nests them via
    /// `RescueNode::subsequent`. Every helper here that needs
    /// whitequark's "each_ancestor"/"each_descendant" semantics (the nested-
    /// rescue guard, and the shadow check) deliberately does NOT descend
    /// into `.subsequent()` to compensate — see `check_rescued_exceptions_
    /// variable_name`'s hand-rolled `visit_rescue_node` in mod.rs, and
    /// `resbody_reads_lvar` below.
    pub(crate) fn check_rescued_exceptions_variable_name(&mut self, node: &ruby_prism::RescueNode) {
        const COP: &str = "Naming/RescuedExceptionsVariableName";
        if !self.on(COP) {
            return;
        }
        // `return if node.each_ancestor(:resbody).any?` — never consider a
        // resbody nested inside another resbody's own statements (but DO
        // still consider `subsequent` siblings, which `renv_resbody_depth`
        // is never incremented for — see the hand-rolled `visit_rescue_node`).
        if self.renv_resbody_depth > 0 {
            return;
        }
        let Some(reference) = node.reference() else { return };
        // Anything with a rubocop-AST `#name` offends — lvasgn, but also
        // ivasgn/cvasgn/gvasgn/casgn (`rescue => @error`), whose prism
        // names carry their sigils, matching upstream's message text. A
        // writer-method reference (`rescue => storage.exception`) has no
        // `#name` (`respond_to?(:name)` is false) and is silently skipped.
        // Only LOCAL targets get body-reference renames below: upstream's
        // `correct_node` walks `lvar`/`lvasgn`/`masgn` nodes exclusively.
        let (offending, target_loc, is_local) =
            if let Some(t) = reference.as_local_variable_target_node() {
                (t.name(), t.location(), true)
            } else if let Some(t) = reference.as_instance_variable_target_node() {
                (t.name(), t.location(), false)
            } else if let Some(t) = reference.as_class_variable_target_node() {
                (t.name(), t.location(), false)
            } else if let Some(t) = reference.as_global_variable_target_node() {
                (t.name(), t.location(), false)
            } else if let Some(t) = reference.as_constant_target_node() {
                (t.name(), t.location(), false)
            } else {
                return;
            };
        let offending = offending.as_slice();

        let base_preferred = self.cfg.get(COP, "PreferredName").unwrap_or("e");
        let preferred = renv_preferred_name(offending, base_preferred);
        if preferred.as_bytes() == offending {
            return;
        }
        // `shadowed_variable_name?`: skip if the resbody's own subtree
        // (exceptions/reference/statements — NOT `subsequent`) already reads
        // a local variable literally named the BASE preferred name. Upstream
        // reuses `preferred_name` here but passes it a Node, not a String —
        // `node.to_s` is the s-expression dump and never starts with `_`, so
        // the underscore-prefix branch never fires in that call and it
        // always compares against the bare config value, regardless of
        // whether `offending`/`preferred` themselves are `_`-prefixed. That
        // (apparent upstream bug) is replicated verbatim here.
        if resbody_reads_lvar(node, base_preferred.as_bytes()) {
            return;
        }

        let range = target_loc;
        let msg = format!(
            "Use `{preferred}` instead of `{}`.",
            String::from_utf8_lossy(offending)
        );
        self.push(range.start_offset(), COP, true, msg);

        // --- autocorrect ---
        self.fixes.push((range.start_offset(), range.end_offset(), preferred.clone().into_bytes()));
        if !is_local {
            // upstream's correct_node/right-sibling walk only ever matches
            // lvar-family nodes; for a sigiled target nothing else renames.
            return;
        }
        if let Some(body) = node.statements() {
            correct_rescue_refs(&body.as_node(), offending, preferred.as_bytes(), &mut self.fixes);
        }
        // Queue this rename for `kwbegin_node.right_siblings`: if this
        // resbody sits inside an explicit `begin...end`, the nearest
        // enclosing one's accumulator is the top of the stack (consumed by
        // `visit_statements_node` right after that kwbegin's own traversal
        // finishes). No active kwbegin (e.g. a bare `def...rescue...end`) —
        // `last_mut` is `None` and nothing is queued, matching upstream's
        // `return unless (kwbegin_node = ...)`.
        if let Some(top) = self.renv_pending_kwbegin_stack.last_mut() {
            top.push((offending.to_vec(), preferred.into_bytes()));
        }
    }
}

/// rubocop's `preferred_name`: the configured base name, `_`-prefixed when
/// the offending variable itself was `_`-prefixed.
fn renv_preferred_name(offending: &[u8], base: &str) -> String {
    if offending.first() == Some(&b'_') {
        format!("_{base}")
    } else {
        base.to_string()
    }
}

/// Does `node`'s own exceptions/reference/statements (NOT `subsequent`)
/// contain a read of a local variable literally named `name`?
fn resbody_reads_lvar(node: &ruby_prism::RescueNode, name: &[u8]) -> bool {
    struct V<'x> {
        name: &'x [u8],
        found: bool,
    }
    impl<'pr, 'x> ruby_prism::Visit<'pr> for V<'x> {
        fn visit_local_variable_read_node(&mut self, n: &ruby_prism::LocalVariableReadNode<'pr>) {
            if n.name().as_slice() == self.name {
                self.found = true;
            }
        }
        fn visit_rescue_node(&mut self, n: &ruby_prism::RescueNode<'pr>) {
            for ex in &n.exceptions() {
                self.visit(&ex);
            }
            if let Some(r) = n.reference() {
                self.visit(&r);
            }
            if let Some(st) = n.statements() {
                self.visit_statements_node(&st);
            }
            // deliberately skip n.subsequent() — see module doc comment.
        }
    }
    let mut v = V { name, found: false };
    use ruby_prism::Visit;
    v.visit_rescue_node(node);
    v.found
}

/// Does this mlhs target (a `masgn`/`MultiWriteNode` left/rest/right entry,
/// possibly a nested destructure) bind a local variable named `name`? Mirrors
/// upstream's `variable_name_matches?`'s masgn branch (`each_descendant(:lvasgn)`).
fn renv_mlhs_matches(node: &ruby_prism::Node, name: &[u8]) -> bool {
    if let Some(t) = node.as_local_variable_target_node() {
        return t.name().as_slice() == name;
    }
    if let Some(m) = node.as_multi_target_node() {
        return m.lefts().iter().any(|n| renv_mlhs_matches(&n, name))
            || m.rest().is_some_and(|n| renv_mlhs_matches(&n, name))
            || m.rights().iter().any(|n| renv_mlhs_matches(&n, name));
    }
    if let Some(s) = node.as_splat_node() {
        return s.expression().is_some_and(|e| renv_mlhs_matches(&e, name));
    }
    false
}

/// Ports rubocop's `correct_node`: walks `node`'s subtree in the same order
/// as `each_node(:lvar, :lvasgn, :masgn)`, renaming reads of the local
/// variable `name` to `preferred`, and STOPS entirely (no further renames
/// anywhere later in the traversal) the moment it hits a reassignment of
/// `name` — after first recursing into just that reassignment's RHS. An
/// omitted hash value (`do_something(error:)`, prism's `ImplicitNode`) is
/// special-cased to an insertion (`error: e`) rather than a replacement,
/// since replacing its (zero-content) span would eat the key/colon too.
pub(crate) fn correct_rescue_refs(
    node: &ruby_prism::Node,
    name: &[u8],
    preferred: &[u8],
    fixes: &mut Vec<(usize, usize, Vec<u8>)>,
) {
    struct V<'x> {
        name: &'x [u8],
        preferred: &'x [u8],
        fixes: &'x mut Vec<(usize, usize, Vec<u8>)>,
        stop: bool,
    }
    impl<'pr, 'x> ruby_prism::Visit<'pr> for V<'x> {
        fn visit_local_variable_read_node(&mut self, n: &ruby_prism::LocalVariableReadNode<'pr>) {
            if self.stop {
                return;
            }
            if n.name().as_slice() == self.name {
                let l = n.location();
                self.fixes.push((l.start_offset(), l.end_offset(), self.preferred.to_vec()));
            }
        }
        fn visit_implicit_node(&mut self, n: &ruby_prism::ImplicitNode<'pr>) {
            if self.stop {
                return;
            }
            if let Some(lvar) = n.value().as_local_variable_read_node() {
                if lvar.name().as_slice() == self.name {
                    let end = n.location().end_offset();
                    let mut ins = vec![b' '];
                    ins.extend_from_slice(self.preferred);
                    self.fixes.push((end, end, ins));
                }
            }
            // Deliberately never descend — the wrapped read is fully
            // handled (or intentionally left alone) above.
        }
        fn visit_local_variable_write_node(&mut self, n: &ruby_prism::LocalVariableWriteNode<'pr>) {
            if self.stop {
                return;
            }
            if n.name().as_slice() == self.name {
                let mut sub = V { name: self.name, preferred: self.preferred, fixes: self.fixes, stop: false };
                sub.visit(&n.value());
                self.stop = true;
                return;
            }
            ruby_prism::visit_local_variable_write_node(self, n);
        }
        fn visit_multi_write_node(&mut self, n: &ruby_prism::MultiWriteNode<'pr>) {
            if self.stop {
                return;
            }
            let hit = n.lefts().iter().any(|t| renv_mlhs_matches(&t, self.name))
                || n.rest().is_some_and(|t| renv_mlhs_matches(&t, self.name))
                || n.rights().iter().any(|t| renv_mlhs_matches(&t, self.name));
            if hit {
                let mut sub = V { name: self.name, preferred: self.preferred, fixes: self.fixes, stop: false };
                sub.visit(&n.value());
                self.stop = true;
                return;
            }
            ruby_prism::visit_multi_write_node(self, n);
        }
    }
    let mut v = V { name, preferred, fixes, stop: false };
    use ruby_prism::Visit;
    v.visit(node);
}


// ---------------------------------------------------------------------
// Naming/PredicatePrefix
// ---------------------------------------------------------------------
// `NamePrefix`/`ForbiddenPrefixes`/`MethodDefinitionMacros` are all ARRAY
// defaults (config/default.yml), so — like
// `DEFAULT_METHOD_PARAMETER_ALLOWED_NAMES` above — they don't live in the
// generated flat `SCHEMA` table and are hardcoded here as the `cfg.get`
// None-fallback.
const PP_DEFAULT_NAME_PREFIXES: &[&str] = &["is_", "has_", "have_", "does_"];
const PP_DEFAULT_FORBIDDEN_PREFIXES: &[&str] = &["is_", "has_", "have_", "does_"];
const PP_DEFAULT_METHOD_DEFINITION_MACROS: &[&str] = &["define_method", "define_singleton_method"];

fn pp_prefix_list(cfg: &crate::config::Config, cop: &str, key: &str, default: &[&str]) -> Vec<String> {
    match cfg.get(cop, key) {
        Some(v) => crate::config::parse_allowed_list(v),
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

/// rubocop's private `allowed_method_name?`'s cheap first check: does `name`
/// actually start with `prefix` followed by a non-digit? (A quick byte
/// check to avoid allocating a Regexp, per the original comment.)
fn pp_quick_prefix_match(name: &str, prefix: &str) -> bool {
    name.len() > prefix.len()
        && name.as_bytes()[..prefix.len()] == *prefix.as_bytes()
        && !name.as_bytes()[prefix.len()].is_ascii_digit()
}

/// rubocop's private `expected_name`: strip `prefix` (only when it is ALSO
/// listed in `ForbiddenPrefixes`) and ensure a trailing `?`.
fn pp_expected_name(name: &str, prefix: &str, forbidden: &[String]) -> String {
    let mut new_name = if forbidden.iter().any(|p| p == prefix) {
        // Safe: `pp_quick_prefix_match` already confirmed `name`'s first
        // `prefix.len()` BYTES equal `prefix` exactly, and `prefix` (being a
        // valid `&str`) ends on a char boundary — so does `name` at the same
        // byte offset.
        name[prefix.len()..].to_string()
    } else {
        name.to_string()
    };
    if !name.ends_with('?') {
        new_name.push('?');
    }
    new_name
}

/// Naming/PredicatePrefix (`UseSorbetSigs`) — does `node` (a raw prism node,
/// as it sits in an enclosing StatementsNode's body list) look like
/// `sig { ...returns(TYPE) }` / `sig do ... end`? Mirrors rubocop's
/// `sorbet_return_type` node-pattern `(block (send nil? :sig) args (send _
/// :returns $_type))` — written against whitequark's `(block (send ...)
/// ...)` wrapper, whereas prism represents "a call with a block" the other
/// way around: a `CallNode` with a `block` field. Returns TYPE's exact
/// source text.
fn pp_sig_return_type_src<'x>(node: &ruby_prism::Node, src: &'x [u8]) -> Option<&'x [u8]> {
    let call = node.as_call_node()?;
    if call.receiver().is_some() || call.arguments().is_some() || call.name().as_slice() != b"sig" {
        return None;
    }
    let block = call.block()?;
    let block = block.as_block_node()?;
    let stmts = block.body()?;
    let stmts = stmts.as_statements_node()?;
    let body = stmts.body();
    if body.len() != 1 {
        return None;
    }
    let inner = body.first()?;
    let inner = inner.as_call_node()?;
    if inner.name().as_slice() != b"returns" {
        return None;
    }
    let args = inner.arguments()?;
    let arglist = args.arguments();
    if arglist.len() != 1 {
        return None;
    }
    let t = arglist.first()?;
    let l = t.location();
    Some(&src[l.start_offset()..l.end_offset()])
}

impl<'a> Cops<'a> {
    /// Naming/PredicatePrefix's private `allowed_method_name?` — true means
    /// NO offense for this (name, prefix) pair (the prefix check itself,
    /// the "already correct" check, trailing `=` setters, and
    /// `AllowedMethods`).
    fn pp_allowed_method_name(&self, cop: &str, name: &str, prefix: &str, forbidden: &[String]) -> bool {
        if !pp_quick_prefix_match(name, prefix) {
            return true;
        }
        if pp_expected_name(name, prefix, forbidden) == name {
            return true;
        }
        if name.ends_with('=') {
            return true;
        }
        self.allowed(cop, name.as_bytes())
    }

    /// Naming/PredicatePrefix (`UseSorbetSigs` support): scan a
    /// StatementsNode's direct children for a `sig { returns(T::Boolean) }`
    /// (or `sig do...end`) immediately preceding a `def`/`defs` — rubocop's
    /// `node.left_sibling` walks the AST PARENT's children array, which
    /// (whenever that parent is itself a StatementsNode-shaped body: class/
    /// module/program/sclass/method/block) is exactly "the previous element
    /// of this same statements list". Precomputed here, before any child is
    /// visited, and consulted later by `check_predicate_prefix_def`.
    pub(crate) fn check_predicate_prefix_sig_scan(&mut self, node: &ruby_prism::StatementsNode) {
        const COP: &str = "Naming/PredicatePrefix";
        if !self.on(COP) || self.cfg.get(COP, "UseSorbetSigs") != Some("true") {
            return;
        }
        let children: Vec<ruby_prism::Node> = node.body().iter().collect();
        for w in children.windows(2) {
            let Some(def) = w[1].as_def_node() else { continue };
            if pp_sig_return_type_src(&w[0], self.src) == Some(b"T::Boolean") {
                self.pp_sig_ok.insert(def.location().start_offset());
            }
        }
    }

    /// Naming/PredicatePrefix on a `def`/`defs` — prism unifies both into a
    /// single `DefNode` (an optional `receiver()`), so rubocop's `alias
    /// on_defs on_def` needs no special casing here.
    pub(crate) fn check_predicate_prefix_def(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Naming/PredicatePrefix";
        if !self.on(COP) {
            return;
        }
        let name_prefixes = pp_prefix_list(self.cfg, COP, "NamePrefix", PP_DEFAULT_NAME_PREFIXES);
        let forbidden_prefixes = pp_prefix_list(self.cfg, COP, "ForbiddenPrefixes", PP_DEFAULT_FORBIDDEN_PREFIXES);
        let use_sorbet_sigs = self.cfg.get(COP, "UseSorbetSigs") == Some("true");
        let method_name = String::from_utf8_lossy(node.name().as_slice()).into_owned();
        let sig_ok = self.pp_sig_ok.contains(&node.location().start_offset());
        let anchor = node.name_loc().start_offset();
        for prefix in &name_prefixes {
            if self.pp_allowed_method_name(COP, &method_name, prefix, &forbidden_prefixes) {
                continue;
            }
            if use_sorbet_sigs && !sig_ok {
                continue;
            }
            let new_name = pp_expected_name(&method_name, prefix, &forbidden_prefixes);
            self.push(anchor, COP, false, format!("Rename `{method_name}` to `{new_name}`."));
        }
    }

    /// Naming/PredicatePrefix on `define_method(:is_foo) { ... }` / any
    /// configured `MethodDefinitionMacros` — rubocop's `dynamic_method_define`
    /// node-pattern `(send nil? #method_definition_macro? (sym $_) ...)`:
    /// a bare call (no receiver) to one of the configured macros, whose
    /// FIRST argument is a plain symbol literal (not a string, not an
    /// interpolated `:"..."`).
    pub(crate) fn check_predicate_prefix_dynamic(&mut self, node: &ruby_prism::CallNode) {
        const COP: &str = "Naming/PredicatePrefix";
        if !self.on(COP) || node.receiver().is_some() {
            return;
        }
        let macros = pp_prefix_list(self.cfg, COP, "MethodDefinitionMacros", PP_DEFAULT_METHOD_DEFINITION_MACROS);
        if !macros.iter().any(|m| m.as_bytes() == node.name().as_slice()) {
            return;
        }
        let Some(args) = node.arguments() else { return };
        let Some(first) = args.arguments().first() else { return };
        let Some(sym) = first.as_symbol_node() else { return };
        let Some(vloc) = sym.value_loc() else { return };
        let method_name = String::from_utf8_lossy(&self.src[vloc.start_offset()..vloc.end_offset()]).into_owned();
        let name_prefixes = pp_prefix_list(self.cfg, COP, "NamePrefix", PP_DEFAULT_NAME_PREFIXES);
        let forbidden_prefixes = pp_prefix_list(self.cfg, COP, "ForbiddenPrefixes", PP_DEFAULT_FORBIDDEN_PREFIXES);
        let anchor = first.location().start_offset();
        for prefix in &name_prefixes {
            if self.pp_allowed_method_name(COP, &method_name, prefix, &forbidden_prefixes) {
                continue;
            }
            let new_name = pp_expected_name(&method_name, prefix, &forbidden_prefixes);
            self.push(anchor, COP, false, format!("Rename `{method_name}` to `{new_name}`."));
        }
    }
}


impl<'a> super::Cops<'a> {
    /// Naming/MemoizedInstanceVariableName on a `def`/`defs` — checks its
    /// own top-level body for the `@ivar ||= ...` or `defined?`-guarded
    /// memoization shapes. rubocop's `method_definition?` node pattern
    /// matches every `def`/`defs` node unconditionally.
    pub(crate) fn check_memoized_ivar_def(&mut self, node: &ruby_prism::DefNode) {
        let name = node.name().as_slice().to_vec();
        self.check_memoized_ivar_body(&name, node.body());
    }

    /// Naming/MemoizedInstanceVariableName on a dynamically-defined method's
    /// block (`define_method`/`define_singleton_method`) — `method_name` is
    /// the literal symbol/string argument extracted by
    /// `mivn_dynamic_define_name` at the owning call site.
    pub(crate) fn check_memoized_ivar_block(&mut self, method_name: &[u8], node: &ruby_prism::BlockNode) {
        self.check_memoized_ivar_body(method_name, node.body());
    }

    /// Shared body scan for both entry points above. rubocop's `on_or_asgn`/
    /// `on_defined?` walk UP from the ivar node through ancestors
    /// (`each_ancestor(:any_def, :block)`) to find the nearest enclosing
    /// `def`/`defs`/dynamic-define block — transparently skipping any OTHER
    /// kind of block along the way — then require the offending node to sit
    /// EXACTLY at the top level of THAT method's own body (sole statement,
    /// or literally the last element of its statement list). Scanning
    /// top-down from each qualifying def/block's own immediate body,
    /// instead of climbing up from the ivar, gives the identical result: a
    /// nested non-qualifying block (e.g. `[1].each do ... end`) is simply
    /// never itself a scan root, so an `@ivar ||= ...` inside one is
    /// invisible here exactly as it is to rubocop's ancestor climb (the
    /// found def/block's own body never has that nested statement as a
    /// direct child).
    fn check_memoized_ivar_body(&mut self, method_name: &[u8], body: Option<ruby_prism::Node>) {
        const COP: &str = "Naming/MemoizedInstanceVariableName";
        if !self.on(COP) {
            return;
        }
        let Some(body_node) = body else { return };
        // Prism wraps a 2+-statement body in a `StatementsNode`; a
        // `rescue`/`ensure` body is a `BeginNode` instead (its own
        // `statements()` holds the "main" statement list) — see the known
        // prism-vs-whitequark trap. Anything else is a lone non-Statements
        // node — prism's shape for a single-statement body — and is itself
        // the sole top-level "statement".
        let body_is_stmts = body_node.as_statements_node().is_some();
        let stmts: Vec<ruby_prism::Node> = if let Some(sn) = body_node.as_statements_node() {
            sn.body().iter().collect()
        } else if let Some(bn) = body_node.as_begin_node() {
            bn.statements().map(|s| s.body().iter().collect()).unwrap_or_default()
        } else {
            vec![body_node]
        };
        let Some(last) = stmts.last() else { return };

        let style_raw = self.cfg.get(COP, "EnforcedStyleForLeadingUnderscores").unwrap_or("disallowed");
        let style = match style_raw {
            "required" => "required",
            "optional" => "optional",
            _ => "disallowed",
        };

        // `memoized?`: `@ivar ||= ...` as the sole/last top-level statement.
        if let Some(orw) = last.as_instance_variable_or_write_node() {
            self.mivn_check_or_asgn(style, method_name, &orw);
        } else if body_is_stmts && stmts.len() == 1 {
            // upstream accepts `body.children.last == node` too: when the
            // def body is a SINGLE statement, whitequark's `body` IS that
            // statement, and its own last child — a wrapping block's body
            // (`@mutex.synchronize do @x ||= ... end`), an if/case `else`
            // branch, an `unless` primary body, a while/until body, or an
            // explicit begin's last statement — is still "the end of the
            // method" (rails corpus: server_timing.rb, route_set.rb,
            // finder_methods.rb, cache/entry.rb). A MULTI-statement body is
            // whitequark's `:begin`, whose children.last is the last
            // top-level statement — the branch above.
            if let Some(inner) = mivn_children_last(&stmts[0]) {
                if let Some(orw) = inner.as_instance_variable_or_write_node() {
                    self.mivn_check_or_asgn(style, method_name, &orw);
                }
            }
        }

        // `defined_memoized?`: `(begin (if (defined (ivar %1)) (return (ivar
        // %1)) nil?) ... (ivasgn %1 _))` — needs at least 2 top-level
        // statements (a "begin" shape), the FIRST being the if-defined guard
        // and the LAST the matching assignment.
        if stmts.len() >= 2 {
            if let Some(if_node) = stmts[0].as_if_node() {
                if let Some((defined_ivar, return_ivar)) = mivn_defined_shape(&if_node) {
                    if let Some(ivar_assign) = last.as_instance_variable_write_node() {
                        if ivar_assign.name().as_slice() == defined_ivar.name().as_slice() {
                            self.mivn_check_defined(style, method_name, &defined_ivar, &return_ivar, &ivar_assign);
                        }
                    }
                }
            }
        }
    }

    /// `on_or_asgn`'s offense/correction for the `@ivar ||= ...` shape.
    fn mivn_check_or_asgn(
        &mut self,
        style: &str,
        method_name: &[u8],
        node: &ruby_prism::InstanceVariableOrWriteNode,
    ) {
        const COP: &str = "Naming/MemoizedInstanceVariableName";
        let ivar_name = node.name().as_slice().to_vec();
        if mivn_matches(style, method_name, &ivar_name) {
            return;
        }
        let suggested = mivn_suggested_var(style, method_name);
        let msg = mivn_message(style, &ivar_name, &suggested, method_name);
        let loc = node.name_loc();
        self.push(loc.start_offset(), COP, true, msg);
        let mut repl = vec![b'@'];
        repl.extend_from_slice(&suggested);
        self.fixes.push((loc.start_offset(), loc.end_offset(), repl));
    }

    /// `on_defined?`'s three offenses/corrections for the
    /// `return @ivar if defined?(@ivar); @ivar = ...` shape — one each for
    /// the `defined?(...)`'s ivar, the `return`'s ivar, and the
    /// assignment's name (matches upstream's three `add_offense` calls).
    fn mivn_check_defined(
        &mut self,
        style: &str,
        method_name: &[u8],
        defined_ivar: &ruby_prism::InstanceVariableReadNode,
        return_ivar: &ruby_prism::InstanceVariableReadNode,
        ivar_assign: &ruby_prism::InstanceVariableWriteNode,
    ) {
        const COP: &str = "Naming/MemoizedInstanceVariableName";
        let ivar_name = ivar_assign.name().as_slice().to_vec();
        if mivn_matches(style, method_name, &ivar_name) {
            return;
        }
        let suggested = mivn_suggested_var(style, method_name);
        let msg = mivn_message(style, &ivar_name, &suggested, method_name);
        let mut repl = vec![b'@'];
        repl.extend_from_slice(&suggested);

        let dloc = defined_ivar.location();
        self.push(dloc.start_offset(), COP, true, msg.clone());
        self.fixes.push((dloc.start_offset(), dloc.end_offset(), repl.clone()));

        let rloc = return_ivar.location();
        self.push(rloc.start_offset(), COP, true, msg.clone());
        self.fixes.push((rloc.start_offset(), rloc.end_offset(), repl.clone()));

        let aloc = ivar_assign.name_loc();
        self.push(aloc.start_offset(), COP, true, msg);
        self.fixes.push((aloc.start_offset(), aloc.end_offset(), repl));
    }
}

/// rubocop's `method_definition?` node pattern for the dynamic-define arm:
/// `(block (send _ %DYNAMIC_DEFINE_METHODS ({sym str} $_)) ...)` — ANY
/// receiver, a call literally named `define_method`/`define_singleton_method`,
/// with exactly one argument that's a literal symbol or string (a variable
/// or interpolated name doesn't qualify — the block is simply not a method
/// scope, matching upstream's climb skipping straight past it).
pub(crate) fn mivn_dynamic_define_name(call: &ruby_prism::CallNode) -> Option<Vec<u8>> {
    if !matches!(call.name().as_slice(), b"define_method" | b"define_singleton_method") {
        return None;
    }
    let args = call.arguments()?;
    let items: Vec<_> = args.arguments().iter().collect();
    let [arg] = items.as_slice() else { return None };
    if let Some(sym) = arg.as_symbol_node() {
        Some(sym.value_loc()?.as_slice().to_vec())
    } else if let Some(s) = arg.as_string_node() {
        Some(s.content_loc().as_slice().to_vec())
    } else {
        None
    }
}

/// `defined_memoized?`'s first-statement shape: `(if (defined (ivar $ivar))
/// (return (ivar $ivar)) nil?)` — no `elsif`/`else`, the then-branch is
/// EXACTLY a bare `return @ivar` (nothing else), and both ivars name the
/// same variable. Returns the `defined?(...)`'s ivar and the `return`'s
/// ivar (both offense anchors) once matched.
/// whitequark's `node.children.last` for the single-statement-def-body
/// shapes that can hold a memoization as their last child. Returns the
/// child only when whitequark would see the NODE itself there — i.e. a
/// single-statement branch/body (a multi-statement one is a `:begin` node,
/// which can never equal the `or_asgn`); explicit `begin`/parens are
/// themselves the statement group, so their last statement qualifies at any
/// count.
fn mivn_children_last<'pr>(n: &ruby_prism::Node<'pr>) -> Option<ruby_prism::Node<'pr>> {
    fn sole<'pr>(stmts: Option<ruby_prism::StatementsNode<'pr>>) -> Option<ruby_prism::Node<'pr>> {
        let list: Vec<ruby_prism::Node<'pr>> = stmts?.body().iter().collect();
        if list.len() == 1 { list.into_iter().next() } else { None }
    }
    if let Some(call) = n.as_call_node() {
        // (block (send ...) (args) BODY) — children.last is the block body.
        // EXCEPT when the block is itself a literal-name `define_method`/
        // `define_singleton_method`: upstream's `find_definition` climb
        // stops there first (it IS a method definition), so its memoization
        // belongs to THAT name — handled by `check_memoized_ivar_block` at
        // the owning call site, never by the enclosing def.
        if mivn_dynamic_define_name(&call).is_some() {
            return None;
        }
        let block = call.block()?.as_block_node()?;
        return sole(block.body()?.as_statements_node());
    }
    if let Some(i) = n.as_if_node() {
        // (if cond then-branch ELSE-BRANCH) — an elsif chain in the else
        // slot is its own `if` node, never the or_asgn.
        return sole(i.subsequent()?.as_else_node()?.statements());
    }
    if let Some(u) = n.as_unless_node() {
        // whitequark folds `unless` into (if cond else-clause BODY) — the
        // primary body sits in the LAST (else) slot.
        return sole(u.statements());
    }
    if let Some(c) = n.as_case_node() {
        return sole(c.else_clause()?.statements());
    }
    if let Some(c) = n.as_case_match_node() {
        return sole(c.else_clause()?.statements());
    }
    if let Some(w) = n.as_while_node() {
        return sole(w.statements());
    }
    if let Some(w) = n.as_until_node() {
        return sole(w.statements());
    }
    if let Some(b) = n.as_begin_node() {
        // explicit `begin ... end` without rescue/else/ensure is
        // whitequark's `kwbegin`, whose children ARE the statements; any
        // clause turns children.last into the rescue/ensure node instead.
        if b.rescue_clause().is_none() && b.else_clause().is_none() && b.ensure_clause().is_none() {
            return b.statements()?.body().iter().last();
        }
        return None;
    }
    if let Some(p) = n.as_parentheses_node() {
        return p.body()?.as_statements_node()?.body().iter().last();
    }
    None
}

fn mivn_defined_shape<'pr>(
    if_node: &ruby_prism::IfNode<'pr>,
) -> Option<(ruby_prism::InstanceVariableReadNode<'pr>, ruby_prism::InstanceVariableReadNode<'pr>)> {
    if if_node.subsequent().is_some() {
        return None;
    }
    let defined = if_node.predicate().as_defined_node()?;
    let defined_ivar = defined.value().as_instance_variable_read_node()?;
    let then_stmts = if_node.statements()?;
    let then_body: Vec<_> = then_stmts.body().iter().collect();
    let [only] = then_body.as_slice() else { return None };
    let ret = only.as_return_node()?;
    let args = ret.arguments()?;
    let items: Vec<_> = args.arguments().iter().collect();
    let [ret_arg] = items.as_slice() else { return None };
    let return_ivar = ret_arg.as_instance_variable_read_node()?;
    if return_ivar.name().as_slice() != defined_ivar.name().as_slice() {
        return None;
    }
    Some((defined_ivar, return_ivar))
}

/// rubocop's `matches?`: is `ivar_name` (with leading `@`) an acceptable
/// memoization variable for `method_name` under the given
/// `EnforcedStyleForLeadingUnderscores`? `INITIALIZE_METHODS` are always
/// exempt regardless of the ivar chosen.
fn mivn_matches(style: &str, method_name: &[u8], ivar_name: &[u8]) -> bool {
    const INITIALIZE_METHODS: &[&[u8]] =
        &[b"initialize", b"initialize_clone", b"initialize_copy", b"initialize_dup"];
    if INITIALIZE_METHODS.contains(&method_name) {
        return true;
    }
    let stripped_method = mivn_strip_bang_q_eq(method_name);
    let var = ivar_name.strip_prefix(b"@").unwrap_or(ivar_name);
    mivn_variable_name_candidates(style, &stripped_method).iter().any(|c| c.as_slice() == var)
}

/// `method_name.to_s.delete('!?=')` — strips predicate/bang/setter
/// punctuation from a method name (only ever trailing, for real Ruby
/// identifiers).
fn mivn_strip_bang_q_eq(name: &[u8]) -> Vec<u8> {
    name.iter().copied().filter(|&b| b != b'!' && b != b'?' && b != b'=').collect()
}

/// rubocop's `variable_name_candidates` — `method_name` here is already
/// stripped of `!?=`.
fn mivn_variable_name_candidates(style: &str, method_name: &[u8]) -> Vec<Vec<u8>> {
    let no_underscore = method_name.strip_prefix(b"_").unwrap_or(method_name).to_vec();
    let mut with_underscore = Vec::with_capacity(method_name.len() + 1);
    with_underscore.push(b'_');
    with_underscore.extend_from_slice(method_name);
    match style {
        "required" => {
            let mut v = vec![with_underscore];
            if method_name.starts_with(b"_") {
                v.push(method_name.to_vec());
            }
            v
        }
        "optional" => vec![method_name.to_vec(), with_underscore, no_underscore],
        _ => vec![method_name.to_vec(), no_underscore],
    }
}

/// rubocop's `suggested_var`: `method_name_raw` is the RAW (unstripped)
/// method name — the `!?=` stripping happens inside, mirroring upstream's
/// `method_name.to_s.delete('!?=')`.
fn mivn_suggested_var(style: &str, method_name_raw: &[u8]) -> Vec<u8> {
    let stripped = mivn_strip_bang_q_eq(method_name_raw);
    if style == "required" {
        let mut v = vec![b'_'];
        v.extend_from_slice(&stripped);
        v
    } else {
        stripped
    }
}

/// rubocop's `message`: chooses `UNDERSCORE_REQUIRED` only in `required`
/// style when the ACTUAL (offending) ivar doesn't already start with `_`;
/// otherwise the generic mismatch message. `method_name_raw` keeps its
/// punctuation (`foo?`/`foo!`/`foo=`) — only `suggested_var` is stripped.
fn mivn_message(style: &str, ivar_name: &[u8], suggested_var: &[u8], method_name_raw: &[u8]) -> String {
    let ivar_str = String::from_utf8_lossy(ivar_name);
    let suggested_str = String::from_utf8_lossy(suggested_var);
    let var_no_at = ivar_name.strip_prefix(b"@").unwrap_or(ivar_name);
    if style == "required" && !var_no_at.starts_with(b"_") {
        format!("Memoized variable `{ivar_str}` does not start with `_`. Use `@{suggested_str}` instead.")
    } else {
        let method_str = String::from_utf8_lossy(method_name_raw);
        format!(
            "Memoized variable `{ivar_str}` does not match method name `{method_str}`. Use `@{suggested_str}` instead."
        )
    }
}


impl<'a> super::Cops<'a> {
    /// Naming/VariableNumber — upstream's `on_arg` is aliased ONLY to
    /// `on_lvasgn`/`on_ivasgn`/`on_cvasgn`/`on_gvasgn` (unlike
    /// Naming/VariableName, it does NOT alias `on_optarg`/`on_restarg`/
    /// `on_kwarg`/`on_kwoptarg`/`on_kwrestarg`/`on_blockarg`/`on_lvar`), so
    /// only a REQUIRED positional/block parameter (prism's
    /// `RequiredParameterNode`) and the five write-ish node families
    /// (local/instance/class/global var writes, op-writes, `&&=`/`||=`
    /// writes, and multi-assign/rescue/for-loop targets) reach this check —
    /// see each call site in `mod.rs`'s `Visit` impl. Globals get the FULL
    /// style check here (unlike VariableName's gvasgn, which is
    /// forbidden-identifiers-only) because upstream's `on_gvasgn` for THIS
    /// cop is the same `on_arg` alias, not a separate method.
    pub(crate) fn check_variable_number(&mut self, name: &[u8], anchor: usize) {
        const COP: &str = "Naming/VariableNumber";
        if !self.on(COP) {
            return;
        }
        if self.vn2_allowed_identifier(name) {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        if variable_number_matches_style(name, style) || self.allowed(COP, name) {
            return;
        }
        self.push(anchor, COP, false, format!("Use {style} for variable numbers."));
    }

    /// Naming/VariableNumber on a `def`/`defs` — the method's own name,
    /// gated by `CheckMethodNames` (default `true`). Mirrors
    /// `check_method_name_def`'s `class_emitter_method?` escape hatch (a
    /// singleton method named after a sibling class is exempt), which is
    /// the other half of this cop's overridden `valid_name?`.
    pub(crate) fn check_variable_number_def(&mut self, node: &ruby_prism::DefNode) {
        const COP: &str = "Naming/VariableNumber";
        if !self.on(COP) {
            return;
        }
        if self.cfg.get(COP, "CheckMethodNames") == Some("false") {
            return;
        }
        let name = node.name().as_slice();
        if self.vn2_allowed_identifier(name) {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        if variable_number_matches_style(name, style) {
            return;
        }
        if node.receiver().is_some()
            && self.class_children_stack.iter().any(|f| f.iter().any(|c| c == name))
        {
            return;
        }
        if self.allowed(COP, name) {
            return;
        }
        self.push(node.name_loc().start_offset(), COP, false,
            format!("Use {style} for method name numbers."));
    }

    /// Naming/VariableNumber on a `sym` literal, gated by `CheckSymbols`
    /// (default `true`). Anchored on the WHOLE symbol node (`:sym1`, colon
    /// included), matching upstream's `check_name(node, node.value, node)`
    /// passing the node itself (not `node.loc.expression` split out) as the
    /// offense range.
    pub(crate) fn check_variable_number_sym(&mut self, node: &ruby_prism::SymbolNode) {
        const COP: &str = "Naming/VariableNumber";
        if !self.on(COP) {
            return;
        }
        if self.cfg.get(COP, "CheckSymbols") == Some("false") {
            return;
        }
        let name = node.unescaped();
        if self.vn2_allowed_identifier(name) {
            return;
        }
        let style = self.cfg.enforced_style(COP);
        if variable_number_matches_style(name, style) || self.allowed(COP, name) {
            return;
        }
        self.push(node.location().start_offset(), COP, false,
            format!("Use {style} for symbol numbers."));
    }

    /// `AllowedIdentifiers#allowed_identifier?` for this cop specifically
    /// (own `AllowedIdentifiers` config key, sigil-stripped exact match —
    /// same semantics as `vn_allowed_identifier` above, just scoped to
    /// `Naming/VariableNumber`'s own config section rather than
    /// `Naming/VariableName`'s).
    fn vn2_allowed_identifier(&self, name: &[u8]) -> bool {
        let ids = match self.cfg.get("Naming/VariableNumber", "AllowedIdentifiers") {
            Some(v) => crate::config::parse_allowed_list(v),
            None => Vec::new(),
        };
        if ids.is_empty() {
            return false;
        }
        let stripped = vn_strip_sigils(name);
        ids.iter().any(|id| id.as_bytes() == stripped.as_slice())
    }
}

/// `ConfigurableNumbering::FORMATS` — does `name`'s trailing digit run (if
/// any) match the given `EnforcedStyle`? Ported branch-for-branch from the
/// three regexes (`implicit_param = /\A_\d+\z/`):
///   snake_case:  `/(?:\D|_\d+|\A\d+)\z/`
///   normalcase:  `/(?:\D|[^_\d]\d+|\A\d+)\z|#{implicit_param}/`
///   non_integer: `/(\D|\A\d+)\z|#{implicit_param}/`
///
/// Since `\z` anchors the absolute end and `match?` just needs ANY match,
/// every branch reduces to a check on the string's END:
/// - `\A\d+\z` (all three): the WHOLE name is nothing but ASCII digits
///   (how `:"42"` passes every style).
/// - `\D\z` (all three): the LAST character isn't a digit — nothing to
///   check regardless of style.
/// - otherwise the name ends in a digit and isn't all-digits: look at the
///   character immediately before the maximal trailing run of digits.
///   `snake_case` wants it to be `_`; `normalcase` wants it to be anything
///   OTHER than `_` (it can never be a digit by construction of "maximal
///   run"), or the whole-name `implicit_param` escape (`_1`); `non_integer`
///   has no such middle branch at all — ANY trailing digit fails it unless
///   `implicit_param` saves it.
fn variable_number_matches_style(name: &[u8], style: &str) -> bool {
    let s = String::from_utf8_lossy(name);
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return false;
    }
    if chars.iter().all(|c| c.is_ascii_digit()) {
        return true;
    }
    if !chars.last().unwrap().is_ascii_digit() {
        return true;
    }
    let mut i = chars.len();
    while i > 0 && chars[i - 1].is_ascii_digit() {
        i -= 1;
    }
    // `i > 0`: the all-digits case above already handled a trailing run
    // that reaches all the way back to index 0.
    let preceding = chars[i - 1];
    match style {
        "snake_case" => preceding == '_',
        "normalcase" => preceding != '_' || variable_number_implicit_param(&chars),
        "non_integer" => variable_number_implicit_param(&chars),
        _ => false,
    }
}

/// `implicit_param = /\A_\d+\z/` — the WHOLE name (not merely a suffix) is a
/// single leading underscore followed by nothing but (one or more) ASCII
/// digits, e.g. `_1`.
fn variable_number_implicit_param(chars: &[char]) -> bool {
    chars.len() >= 2 && chars[0] == '_' && chars[1..].iter().all(|c| c.is_ascii_digit())
}
