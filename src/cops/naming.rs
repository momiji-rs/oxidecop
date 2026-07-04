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
