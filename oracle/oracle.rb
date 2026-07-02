#!/usr/bin/env ruby
# frozen_string_literal: true

# Spec-suite oracle: drive the native rubocop-rs PoC with rubocop's OWN spec
# fixtures and diff. rubocop specs use the `expect_offense` DSL, which encodes
# the exact expected offense range + message inline as caret annotations:
#
#     x == nil
#       ^^ Prefer the use of the `nil?` predicate.
#
# We parse those, feed the (de-annotated) source through the PoC binary, and
# compare. Two fidelity levels are reported:
#   LOC  — did we flag the right line:col? (detection fidelity)
#   FULL — line:col AND identical message (message fidelity)
#
# Usage: ruby oracle.rb <poc_binary> <Cop/Name> <spec_file.rb>

POC  = ARGV[0] or abort 'need poc binary'
COP  = ARGV[1] or abort 'need cop name'
SPEC = ARGV[2] or abort 'need spec file'

require 'tmpdir'
require 'open3'

# ---- extract examples from the spec file -------------------------------------
# Each example: { kind: :offense|:no_offense, context: "...", src: "...",
#                 expected: [[line,col,msg], ...] }
def dedent(lines)
  indents = lines.reject { |l| l.strip.empty? }
                 .map { |l| l[/\A */].length }
  min = indents.min || 0
  lines.map { |l| l[min..] || '' }
end

# Resolve double-quoted-string escape sequences the way Ruby renders an
# UNQUOTED heredoc (`<<~RUBY`): \\ \t \s \n \uXXXX \u{...} \# etc. The specs
# rely on this (`x = 0\t`, `　`) because editors strip literal trailing
# whitespace; reading the file statically we must render them ourselves.
# Unknown escapes yield the bare char, like Ruby (`\z` -> `z`).
def unescape_dq(s)
  out = +''
  i = 0
  while i < s.length
    c = s[i]
    if c == '\\' && i + 1 < s.length
      n = s[i + 1]
      case n
      when '\\' then out << '\\'
      when 'n' then out << "\n"
      when 't' then out << "\t"
      when 's' then out << ' '
      when 'e' then out << "\e"
      when 'u'
        if (m = s[i..].match(/\A\\u(?:\{([0-9a-fA-F]+)\}|([0-9a-fA-F]{4}))/))
          out << (m[1] || m[2]).to_i(16).chr(Encoding::UTF_8)
          i += m[0].length
          next
        else
          out << n
        end
      else out << n # \# -> #, \" -> ", \z -> z, ...
      end
      i += 2
    else
      out << c
      i += 1
    end
  end
  out
end

def parse_block(raw_lines, raw_heredoc, squiggly)
  # raw_lines: the heredoc body (already the interior). Dedent ONLY for the
  # squiggly `<<~` form — `<<-` keeps its indentation at runtime, and line-
  # length expectations depend on it. Render escapes unless the heredoc was
  # the quoted `<<~'RUBY'` form (raw — no escape processing), THEN split
  # source lines from caret-annotation lines. Escape-rendering before the
  # split is what RSpec sees: a `\n` inside a line legitimately becomes two.
  text = (squiggly ? dedent(raw_lines) : raw_lines).join("\n")
  text = unescape_dq(text) unless raw_heredoc
  src = []
  expected = []
  text.split("\n", -1).each do |ln|
    # `^{}` marks a zero-width offense range (e.g. FrozenStringLiteralComment
    # anchoring at 1:1); the `{}` is annotation syntax, not message text.
    if ln =~ /\A(\s*)(\^+)(?:\{\})?(.*)\z/
      # annotation for the most recent source line
      col = Regexp.last_match(1).length + 1
      msg = Regexp.last_match(3).strip
      line_no = src.length # 1-based index of the preceding source line
      expected << [line_no, col, msg]
    else
      src << ln
    end
  end
  [src.join("\n") + "\n", expected]
end

# Pull the outermost `{...}` hash literal out of a (possibly multi-line)
# `let(:cop_config)` body and collapse whitespace to one line. Returns 'default'
# when there's no hash literal (e.g. a `super().merge(...)` block).
def extract_hash(text)
  s = text[/\{.*\}/m]
  return 'default' unless s

  s.gsub(/\s+/, ' ').strip
end

# Split a hash/array body on top-level commas, respecting quotes and
# []/{}/() nesting (so `['a', 'b']`, nested hashes, and patterns containing
# commas aren't split apart).
def split_top(s)
  parts = []
  cur = +''
  depth = 0
  quote = nil
  s.each_char do |c|
    if quote
      cur << c
      quote = nil if c == quote
    elsif c == "'" || c == '"'
      quote = c
      cur << c
    elsif '[{('.include?(c)
      depth += 1
      cur << c
    elsif ']})'.include?(c)
      depth -= 1
      cur << c
    elsif c == ',' && depth.zero?
      parts << cur
      cur = +''
    else
      cur << c
    end
  end
  parts << cur unless cur.strip.empty?
  parts
end

# The text form of a `let(:cop_config)` body. `super().merge(...)` composes
# with the inherited context's config — emulate by concatenating the pair
# lists (parse_cfg lets later keys win, like Hash#merge).
def resolve_cop_config_text(body, cfg_stack)
  if (m = body.match(/super\(\)\s*\.merge\(\s*(.*?)\s*\)\s*\z/m))
    inner = m[1].sub(/\A\{\s*/, '').sub(/\s*\}\z/, '')
    parent = cfg_stack.last[1]
    base = parent == 'default' ? '' : parent.sub(/\A\{\s*/, '').sub(/\s*\}\z/, '')
    "{ #{[base, inner].reject(&:empty?).join(', ')} }"
  else
    extract_hash(body)
  end
end

# Parse `RuboCop::Config.new('Section' => {...}, ...)` out of a spec block:
# returns { section => [hash_text, merges_cop_config] } or nil.
def parse_config_sections(joined)
  m = joined.match(/RuboCop::Config\.new\((.*)\)/m)
  return nil unless m

  sections = {}
  split_top(m[1]).each do |part|
    next unless part =~ /\A\s*['"]([^'"]+)['"]\s*=>\s*(.*)\z/m

    sec = Regexp.last_match(1)
    val = Regexp.last_match(2).strip
    merges_cop_config = !val.sub!(/\.merge\(cop_config\)\s*\z/, '').nil?
    sections[sec] = [extract_hash(val), merges_cop_config]
  end
  sections.empty? ? nil : sections
end

examples = []
lines = File.readlines(SPEC, chomp: true)
i = 0
cur_ctx = ''
# cop_config is scoped like RSpec `let`: defined in a context, it applies to that
# context AND its nested contexts. Track a stack of [indent, cfg] frames; a new
# `context`/`describe` at indent N pops frames at indent >= N (scopes we left) and
# inherits the enclosing cfg. This is why a single outer `let(:cop_config)` above
# many nested example groups reaches all of them.
# frame = [indent, cfg, skip]. `skip` marks contexts rubocop itself doesn't run
# under Prism (`unsupported_on: :prism`) — not valid fidelity targets for us.
cfg_stack = []
while i < lines.length
  l = lines[i]
  indent = l[/\A */].length
  if l =~ /^\s*(RSpec\.describe|context|describe|shared_examples)\s/
    cur_ctx = l.strip
    cfg_stack.pop while cfg_stack.any? && cfg_stack.last[0] >= indent
    inh_cfg  = cfg_stack.any? ? cfg_stack.last[1] : 'default'
    inh_skip = cfg_stack.any? ? cfg_stack.last[2] : false
    inh_as   = cfg_stack.any? ? cfg_stack.last[3] : nil
    inh_sec  = cfg_stack.any? ? cfg_stack.last[4] : nil
    inh_ovr  = cfg_stack.any? ? cfg_stack.last[5] : nil
    inh_rb   = cfg_stack.any? ? cfg_stack.last[6] : nil
    # a `:rubyXY` context tag pins TargetRubyVersion for its examples
    inh_rb = "#{Regexp.last_match(1)}.#{Regexp.last_match(2)}" if l =~ /,\s*:ruby(\d)(\d)\b/
    # A parameterized shared_examples group (`do |style|`) runs differently
    # per caller — its inline examples are not statically representable.
    parameterized = !(l =~ /^\s*shared_examples\b.*do\s*\|/).nil?
    cfg_stack.push([indent, inh_cfg,
                    inh_skip || l.include?('unsupported_on: :prism') || parameterized,
                    inh_as, inh_sec, inh_ovr, inh_rb])
  elsif l =~ /^\s*(it|specify)\b/
    # An `it` at indent N means every context defined at indent >= N has
    # closed — without this, a trailing top-level example would inherit the
    # previous sibling context's cop_config.
    cfg_stack.pop while cfg_stack.any? && cfg_stack.last[0] >= indent
  end
  # `before { (cur_)cop_config[...][...] = ... }` mutates a NESTED key of the
  # config hash — unrepresentable statically; skip the context.
  if l =~ /before\s*\{\s*(cur_)?cop_config\[[^\]]*\]\[/ && cfg_stack.any?
    cfg_stack.last[2] = true
  end
  # `before { config['Cop/Name'] = { ... } }` mutates the built config: the
  # cop's section becomes EXACTLY that hash (defaults don't apply).
  if l =~ /before\s*\{\s*config\['#{Regexp.escape(COP)}'\]\s*=\s*(\{.*\})\s*\}/ && cfg_stack.any?
    cfg_stack.last[5] = extract_hash(Regexp.last_match(1))
  end
  # `let(:cop_config)` in either single-line `{ {...} }` or multi-line `do..end`
  # form. Capture the raw hash text (quotes preserved, whitespace collapsed) so
  # array values like AllowedPatterns survive; sets the innermost context's cfg.
  if l =~ /let\(:cop_config\)\s*\{(.*)\}\s*\z/
    cfg_stack.last[1] = resolve_cop_config_text(Regexp.last_match(1), cfg_stack) if cfg_stack.any?
  elsif l =~ /let\(:cop_config\)\s*do\s*\z/
    blk = []
    i += 1
    while i < lines.length && lines[i].strip != 'end'
      blk << lines[i]
      i += 1
    end
    cfg_stack.last[1] = resolve_cop_config_text(blk.join(' '), cfg_stack) if cfg_stack.any?
  end
  # `let(:config)` overriding the whole RuboCop::Config replaces the shared
  # context's default-merged config: only the listed sections exist, and only
  # a section written as `{...}.merge(cop_config)` keeps honoring the
  # example's cop_config. Capture the sections (they carry cross-cop settings
  # like Layout/IndentationStyle) and the AllCops dimension we model.
  if l =~ /let\(:config\)\s*(do|\{)/
    blk = [l]
    if l.include?('do') && !l.include?('end')
      i += 1
      while i < lines.length && lines[i].strip != 'end'
        blk << lines[i]
        i += 1
      end
    end
    joined = blk.join(' ')
    if (m = joined.match(/ActiveSupportExtensionsEnabled'\s*=>\s*(true|false)/)) && cfg_stack.any?
      cfg_stack.last[3] = m[1]
    end
    if cfg_stack.any? && (sections = parse_config_sections(joined))
      cfg_stack.last[4] = sections
    end
  end
  # `subject(:cop) { described_class.new(RuboCop::Config.new(...)) }` — another
  # way specs pin a full config; same replacement semantics as let(:config).
  if l =~ /subject\(:cop\)\s*(do|\{)/
    blk = [l]
    if l.include?('do')
      i += 1
      while i < lines.length && lines[i].strip != 'end'
        blk << lines[i]
        i += 1
      end
    end
    if cfg_stack.any? && (sections = parse_config_sections(blk.join(' ')))
      cfg_stack.last[4] = sections
    end
  end
  cur_cfg = cfg_stack.any? ? cfg_stack.last[1] : 'default'
  cur_skip = cfg_stack.any? ? cfg_stack.last[2] : false
  cur_as = cfg_stack.any? ? cfg_stack.last[3] : nil
  cur_sec = cfg_stack.any? ? cfg_stack.last[4] : nil
  cur_ovr = cfg_stack.any? ? cfg_stack.last[5] : nil
  cur_rb  = cfg_stack.any? ? cfg_stack.last[6] : nil
  # Heredoc examples, all forms: `<<~RUBY` (escapes render), `<<~'RUBY'` (raw),
  # `<<-RUBY`, and trailing keyword args (`, identifier: identifier` — those
  # substitute `%{key}` in the body; unresolvable statically, so they fall into
  # the skip column below instead of being silently dropped).
  if l =~ /expect_(offense|no_offenses)\(<<([~-])('?)RUBY\3\s*[,)]/
    kind = Regexp.last_match(1) == 'offense' ? :offense : :no_offense
    squiggly = Regexp.last_match(2) == '~'
    raw_heredoc = Regexp.last_match(3) == "'"
    body = []
    i += 1
    until lines[i].strip == 'RUBY'
      body << lines[i]
      i += 1
    end
    src, expected = parse_block(body, raw_heredoc, squiggly)
    examples << { kind: kind, context: cur_ctx, cfg: cur_cfg, skip: cur_skip, as: cur_as,
                  sections: cur_sec, override: cur_ovr, ruby: cur_rb, src: src, expected: expected }
  elsif l =~ /expect_no_offenses\((['"])(.*?)\1\)/
    quote, body = Regexp.last_match(1), Regexp.last_match(2)
    # A plain string arg renders by its quote's rules: double-quoted like a
    # heredoc; single-quoted only interprets \\ and \'.
    body = quote == '"' ? unescape_dq(body) : body.gsub(/\\([\\'])/, '\1')
    examples << { kind: :no_offense, context: cur_ctx, cfg: cur_cfg, skip: cur_skip, as: cur_as,
                  sections: cur_sec, override: cur_ovr, ruby: cur_rb, src: body + "\n", expected: [] }
  end
  i += 1
end

# ---- run the PoC on each example ---------------------------------------------
# RuboCop's spec suite encodes some source and message text via Ruby string
# interpolation (e.g. `x = 0#{trailing_whitespace}`, `Use #{enforced_style}
# ...`) because editors strip literal trailing whitespace and messages vary by
# EnforcedStyle. The oracle's static parser can't eval Ruby, so we resolve the
# KNOWN-CONSTANT helpers here and treat anything still-interpolated as
# "unrepresentable" (skipped, excluded from the denominator) — that keeps the
# fidelity score honest instead of scoring a harness limitation as a cop miss.
# A cop's default EnforcedStyle, used to resolve `#{enforced_style}` in expected
# messages when the example doesn't override it (the `default` config group).
# Only cops whose MSG interpolates the style need an entry.
COP_DEFAULT_STYLE = {
  'Naming/MethodName' => 'snake_case'
}.freeze

def resolve_interp(text, cfg_hash)
  text = text.gsub(/\#\{trailing_whitespace \* (\d+)\}/) { ' ' * Regexp.last_match(1).to_i }
  text = text.gsub('#{trailing_whitespace}', ' ')
  style = cfg_hash['EnforcedStyle']
  # `enforced_style` (an RSpec variable) can't be resolved statically; fall back
  # to the cop's default so the message still compares meaningfully.
  style = COP_DEFAULT_STYLE[COP] if style.nil? || style == 'enforced_style'
  text = text.gsub('#{enforced_style}', style) if style
  text
end


# Normalize one array item to its raw pattern source: `/re/opts` -> re,
# 'str'/"str" -> str, else as-is.
def normalize_pattern(item)
  item = item.strip
  if (m = item.match(%r{\A/(.*)/[a-z]*\z}m)) then m[1]
  elsif (m = item.match(/\A(['"])(.*)\1\z/m)) then m[2]
  else item
  end
end

# Sentinel prefix marking a value that was an UNQUOTED bare word in the spec —
# an RSpec `let` variable (e.g. `'EnforcedStyle' => enforced_style`), whose
# value varies per loop iteration and cannot be resolved statically.
VAR_SENTINEL = " VAR:"

def parse_val(v)
  v = v.strip
  # hash-form grouped values (`{ 'Pry' => %w[...], 'X' => nil }`) act like
  # rubocop's `config.values.flatten`: the arrays inside, flattened.
  if v.start_with?('{')
    return v.scan(/%[wi]\[([^\]]*)\]/).flat_map { |m| m[0].split(/\s+/) } +
           v.scan(/\[([^\]]*)\]/).flat_map { |m| split_top(m[0]).map { |x| normalize_pattern(x) } }
  end
  if v.start_with?('[')
    inner = v.sub(/\A\[/, '').sub(/\]\s*\z/, '')
    split_top(inner).map { |item| normalize_pattern(item) }
  elsif (m = v.match(/\A%[wi]\[(.*)\]\z/m)) # %w[a b] / %i[a b] word/symbol arrays
    m[1].split(/\s+/).reject(&:empty?)
  elsif v =~ /\A(['"])(.*)\1\z/m
    Regexp.last_match(2)
  elsif v =~ /\A[a-z_][A-Za-z0-9_.]*\z/ && !%w[true false nil].include?(v)
    VAR_SENTINEL + v
  else
    v
  end
end

# Config keys whose value is an RSpec variable are dropped — the engine then
# uses the cop's default, and the example's annotations must hold for every
# loop value anyway (value-dependent expectations interpolate `#{...}` into
# the source or message and are skipped by those checks). EnforcedStyle is the
# exception: the STYLE decides which names/quotes/etc. flag at all, so an
# example with a variable style is genuinely unrepresentable.
def resolve_cfg_variables!(h)
  h.each do |k, v|
    next unless v.is_a?(String) && v.start_with?(VAR_SENTINEL)
    return nil if k == 'EnforcedStyle'

    h.delete(k)
  end
  h
end

# `ex[:cfg]` is the raw `let(:cop_config)` hash text (quotes preserved), e.g.
# "{ 'EnforcedStyle' => single_quotes }" or
# "{ 'Max' => 18, 'AllowedPatterns' => ['^\\s*test\\s'] }" or "default".
def parse_cfg(cfgstr)
  return {} if cfgstr == 'default'

  body = cfgstr.strip.sub(/\A\{/, '').sub(/\}\z/, '')
  h = {}
  split_top(body).each do |pair|
    next unless pair =~ /\A\s*['"]?(\w+)['"]?\s*=>\s*(.*)\z/m

    h[Regexp.last_match(1)] = parse_val(Regexp.last_match(2))
  end
  h
end

# Build the per-example .rubocop.yml: enable only this cop, and pass through the
# example's own cop_config so config-reading cops (Layout/LineLength `Max`,
# Style/NumericLiterals `MinDigits`, AllowedPatterns, …) are exercised faithfully.
# Array values (AllowedPatterns) are emitted as single-quoted YAML flow sequences.
def emit_pairs(lines, h)
  h.each do |k, v|
    if v.is_a?(Array)
      lines << "  #{k}: [#{v.map { |p| "'#{p}'" }.join(', ')}]"
    else
      lines << "  #{k}: #{v}"
    end
  end
end

# `replace: true` mirrors a spec whose `let(:config)` rebuilt the whole
# RuboCop::Config — unspecified cop params are nil there, NOT default.yml
# values, which `__replace_defaults__` tells the engine.
def build_cfg(cop, cfg_hash, as_val = nil, extra_sections = [], replace: false, ruby: nil)
  lines = ['AllCops:', '  DisabledByDefault: true']
  lines << "  ActiveSupportExtensionsEnabled: #{as_val}" if as_val
  lines << "  TargetRubyVersion: #{ruby}" if ruby
  lines += ["#{cop}:", '  Enabled: true']
  lines << '  __replace_defaults__: true' if replace
  emit_pairs(lines, cfg_hash)
  extra_sections.each do |sec, h|
    lines << "#{sec}:"
    emit_pairs(lines, h)
  end
  lines.join("\n") + "\n"
end

def run_poc(poc, src, cfg)
  Dir.mktmpdir do |d|
    rb = File.join(d, 'ex.rb')
    yml = File.join(d, 'c.yml')
    File.write(rb, src)
    File.write(yml, cfg)
    out, = Open3.capture2(poc, rb, yml)
    # parse "C: 4:  8: [Correctable] Cop/Name: message"
    out.lines.filter_map do |line|
      if line =~ /\A[A-Z]:\s*(\d+):\s*(\d+):\s*(?:\[Correctable\]\s*)?(\S+):\s*(.*)/
        [Regexp.last_match(1).to_i, Regexp.last_match(2).to_i, Regexp.last_match(4).strip]
      end
    end
  end
end

# ---- compare + report --------------------------------------------------------
# group tallies by active cop_config so config-gated examples are transparent.
# `skipped` = examples the harness cannot faithfully represent (unresolved
# interpolation in the SOURCE); they're excluded from loc/full/total.
groups = Hash.new { |h, k| h[k] = { loc: 0, full: 0, total: 0, skipped: 0 } }
fails = []
examples.each_with_index do |ex, n|
  g = groups[ex[:override] || ex[:cfg]]

  # Context rubocop skips under Prism (unsupported_on: :prism) — not a valid
  # fidelity target for a Prism-based tool, so exclude rather than score.
  if ex[:skip]
    g[:skipped] += 1
    next
  end

  cfg_hash = resolve_cfg_variables!(parse_cfg(ex[:cfg]))

  # A variable EnforcedStyle varies per loop run — unrepresentable statically,
  # like interpolated source.
  if cfg_hash.nil?
    g[:skipped] += 1
    next
  end

  # A full `let(:config)` override replaces the config: the cop's section is
  # exactly what it lists (merged with cop_config only when the spec wrote
  # `.merge(cop_config)`), other sections ride along, defaults don't apply.
  extra_sections = []
  replace = false
  if ex[:override]
    # a before-block replaced the cop's section outright
    replace = true
    cfg_hash = resolve_cfg_variables!(parse_cfg(ex[:override])) || {}
    if (sections = ex[:sections])
      extra_sections = sections.reject { |k, _| k == COP }
                               .map { |k, (h, _)| [k, resolve_cfg_variables!(parse_cfg(h)) || {}] }
    end
  elsif (sections = ex[:sections])
    replace = true
    base = sections[COP]
    cop_hash = base ? parse_cfg(base[0]) : {}
    cop_hash.merge!(cfg_hash) if base && base[1]
    cfg_hash = resolve_cfg_variables!(cop_hash)
    if cfg_hash.nil?
      g[:skipped] += 1
      next
    end
    extra_sections = sections.reject { |k, _| k == COP }
                             .map { |k, (h, _)| [k, resolve_cfg_variables!(parse_cfg(h)) || {}] }
  end

  src = resolve_interp(ex[:src], cfg_hash)

  # Unrepresentable: source still interpolates a value we can't resolve
  # statically — `#{keyword}`-style RSpec loop vars, or `%{identifier}`
  # expect_offense keyword substitutions. Linting the literal text would be
  # meaningless, so exclude rather than score as a miss.
  if src =~ /\#\{|%\{/
    g[:skipped] += 1
    next
  end

  actual = run_poc(POC, src, build_cfg(COP, cfg_hash, ex[:as], extra_sections, replace: replace, ruby: ex[:ruby]))
  exp = ex[:expected].map { |l, c, m| [l, c, resolve_interp(m, cfg_hash)] }
  g[:total] += 1

  exp_loc = exp.map { |l, c, _| [l, c] }.sort
  act_loc = actual.map { |l, c, _| [l, c] }.sort
  loc_ok = exp_loc == act_loc

  exp_full = exp.map { |l, c, m| [l, c, m] }.sort
  act_full = actual.sort
  # `[...]` in an expect_offense annotation abbreviates the message — any
  # message at the right location matches.
  full_ok = exp_full.size == act_full.size &&
            exp_full.zip(act_full).all? do |(el, ec, em), (al, ac, am)|
              el == al && ec == ac && (em == '[...]' || em == am)
            end

  g[:loc] += 1 if loc_ok
  g[:full] += 1 if full_ok
  next if loc_ok && full_ok

  first = ex[:src].lines.first.to_s.strip
  reason = if !loc_ok
             "LOC  exp=#{exp_loc.inspect} got=#{act_loc.inspect}"
           else
             "MSG  exp=#{exp.map { _1[2] }.inspect}\n            got=#{actual.map { _1[2] }.inspect}"
           end
  fails << format("  #%-2d {%s} `%s`\n       %s", n, ex[:cfg][0, 30], first[0, 40], reason)
end

total     = examples.length
skipped   = groups.values.sum { |g| g[:skipped] }
scored    = total - skipped # representable examples — the honest denominator
puts "== oracle: #{COP} (#{File.basename(SPEC)}) =="
puts "   #{total} examples (#{scored} representable, #{skipped} skipped), grouped by active cop_config:"
groups.each do |cfgname, g|
  skip = g[:skipped].positive? ? "   (#{g[:skipped]} skipped)" : ''
  puts format('     %-34s LOC %d/%d   FULL %d/%d%s', cfgname[0, 34], g[:loc], g[:total], g[:full], g[:total], skip)
end
def_g = groups['default'] || { loc: 0, full: 0, total: 0 }
puts "   >> default-config detection fidelity: #{def_g[:loc]}/#{def_g[:total]} LOC, #{def_g[:full]}/#{def_g[:total]} FULL" if def_g[:total].positive?
unless fails.empty?
  puts '   --- misses ---'
  puts fails.join("\n") unless ENV['ORACLE_QUIET']
end

# machine-readable summary for the leaderboard driver. `total` here is the
# REPRESENTABLE count (skipped excluded) so downstream percentages are honest.
# SUMMARY<TAB>cop<TAB>total<TAB>all_loc<TAB>all_full<TAB>def_total<TAB>def_loc<TAB>def_full<TAB>skipped
all_loc  = groups.values.sum { |g| g[:loc] }
all_full = groups.values.sum { |g| g[:full] }
warn "SUMMARY\t#{COP}\t#{scored}\t#{all_loc}\t#{all_full}\t#{def_g[:total]}\t#{def_g[:loc]}\t#{def_g[:full]}\t#{skipped}"
