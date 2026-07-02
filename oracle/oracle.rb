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

def parse_block(raw_lines, raw_heredoc)
  # raw_lines: the heredoc body (already the interior). Dedent (matches `<<~`,
  # computed on the literal lines), render escapes unless the heredoc was the
  # quoted `<<~'RUBY'` form (raw — no escape processing), THEN split source
  # lines from caret-annotation lines. Escape-rendering before the split is
  # what RSpec sees: a `\n` inside a line legitimately becomes two lines.
  text = dedent(raw_lines).join("\n")
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
  if l =~ /^\s*(context|describe)\s/
    cur_ctx = l.strip
    cfg_stack.pop while cfg_stack.any? && cfg_stack.last[0] >= indent
    inh_cfg  = cfg_stack.any? ? cfg_stack.last[1] : 'default'
    inh_skip = cfg_stack.any? ? cfg_stack.last[2] : false
    inh_as   = cfg_stack.any? ? cfg_stack.last[3] : nil
    cfg_stack.push([indent, inh_cfg, inh_skip || l.include?('unsupported_on: :prism'), inh_as])
  end
  # `let(:cop_config)` in either single-line `{ {...} }` or multi-line `do..end`
  # form. Capture the raw hash text (quotes preserved, whitespace collapsed) so
  # array values like AllowedPatterns survive; sets the innermost context's cfg.
  if l =~ /let\(:cop_config\)\s*\{(.*)\}\s*\z/
    cfg_stack.last[1] = extract_hash(Regexp.last_match(1)) if cfg_stack.any?
  elsif l =~ /let\(:cop_config\)\s*do\s*\z/
    blk = []
    i += 1
    while i < lines.length && lines[i].strip != 'end'
      blk << lines[i]
      i += 1
    end
    cfg_stack.last[1] = extract_hash(blk.join(' ')) if cfg_stack.any?
  end
  # `let(:config)` may set an AllCops dimension we model — capture
  # ActiveSupportExtensionsEnabled and thread it into the generated .rubocop.yml.
  if l =~ /let\(:config\)\s*(do|\{)/
    blk = [l]
    if l.include?('do') && !l.include?('end')
      i += 1
      while i < lines.length && lines[i].strip != 'end'
        blk << lines[i]
        i += 1
      end
    end
    if (m = blk.join(' ').match(/ActiveSupportExtensionsEnabled'\s*=>\s*(true|false)/)) && cfg_stack.any?
      cfg_stack.last[3] = m[1]
    end
  end
  cur_cfg = cfg_stack.any? ? cfg_stack.last[1] : 'default'
  cur_skip = cfg_stack.any? ? cfg_stack.last[2] : false
  cur_as = cfg_stack.any? ? cfg_stack.last[3] : nil
  # Heredoc examples, all forms: `<<~RUBY` (escapes render), `<<~'RUBY'` (raw),
  # `<<-RUBY`, and trailing keyword args (`, identifier: identifier` — those
  # substitute `%{key}` in the body; unresolvable statically, so they fall into
  # the skip column below instead of being silently dropped).
  if l =~ /expect_(offense|no_offenses)\(<<[~-]('?)RUBY\2\s*[,)]/
    kind = Regexp.last_match(1) == 'offense' ? :offense : :no_offense
    raw_heredoc = Regexp.last_match(2) == "'"
    body = []
    i += 1
    until lines[i].strip == 'RUBY'
      body << lines[i]
      i += 1
    end
    src, expected = parse_block(body, raw_heredoc)
    examples << { kind: kind, context: cur_ctx, cfg: cur_cfg, skip: cur_skip, as: cur_as, src: src, expected: expected }
  elsif l =~ /expect_no_offenses\((['"])(.*?)\1\)/
    quote, body = Regexp.last_match(1), Regexp.last_match(2)
    # A plain string arg renders by its quote's rules: double-quoted like a
    # heredoc; single-quoted only interprets \\ and \'.
    body = quote == '"' ? unescape_dq(body) : body.gsub(/\\([\\'])/, '\1')
    examples << { kind: :no_offense, context: cur_ctx, cfg: cur_cfg, skip: cur_skip, as: cur_as, src: body + "\n", expected: [] }
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

# Split a hash/array body on top-level commas, respecting quotes and [] nesting
# (so `['a', 'b']` and patterns containing commas aren't split apart).
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
    elsif c == '['
      depth += 1
      cur << c
    elsif c == ']'
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

# Normalize one array item to its raw pattern source: `/re/opts` -> re,
# 'str'/"str" -> str, else as-is.
def normalize_pattern(item)
  item = item.strip
  if (m = item.match(%r{\A/(.*)/[a-z]*\z}m)) then m[1]
  elsif (m = item.match(/\A(['"])(.*)\1\z/m)) then m[2]
  else item
  end
end

def parse_val(v)
  v = v.strip
  if v.start_with?('[')
    inner = v.sub(/\A\[/, '').sub(/\]\s*\z/, '')
    split_top(inner).map { |item| normalize_pattern(item) }
  elsif (m = v.match(/\A%[wi]\[(.*)\]\z/m)) # %w[a b] / %i[a b] word/symbol arrays
    m[1].split(/\s+/).reject(&:empty?)
  else
    v.sub(/\A(['"])(.*)\1\z/m, '\2')
  end
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
def build_cfg(cop, cfg_hash, as_val = nil)
  lines = ['AllCops:', '  DisabledByDefault: true']
  lines << "  ActiveSupportExtensionsEnabled: #{as_val}" if as_val
  lines += ["#{cop}:", '  Enabled: true']
  cfg_hash.each do |k, v|
    if v.is_a?(Array)
      lines << "  #{k}: [#{v.map { |p| "'#{p}'" }.join(', ')}]"
    else
      lines << "  #{k}: #{v}"
    end
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
      if line =~ /\AC:\s*(\d+):\s*(\d+):\s*(?:\[Correctable\]\s*)?(\S+):\s*(.*)/
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
  g = groups[ex[:cfg]]

  # Context rubocop skips under Prism (unsupported_on: :prism) — not a valid
  # fidelity target for a Prism-based tool, so exclude rather than score.
  if ex[:skip]
    g[:skipped] += 1
    next
  end

  cfg_hash = parse_cfg(ex[:cfg])
  src = resolve_interp(ex[:src], cfg_hash)

  # Unrepresentable: source still interpolates a value we can't resolve
  # statically — `#{keyword}`-style RSpec loop vars, or `%{identifier}`
  # expect_offense keyword substitutions. Linting the literal text would be
  # meaningless, so exclude rather than score as a miss.
  if src =~ /\#\{|%\{/
    g[:skipped] += 1
    next
  end

  actual = run_poc(POC, src, build_cfg(COP, cfg_hash, ex[:as]))
  exp = ex[:expected].map { |l, c, m| [l, c, resolve_interp(m, cfg_hash)] }
  g[:total] += 1

  exp_loc = exp.map { |l, c, _| [l, c] }.sort
  act_loc = actual.map { |l, c, _| [l, c] }.sort
  loc_ok = exp_loc == act_loc

  exp_full = exp.map { |l, c, m| [l, c, m] }.sort
  act_full = actual.sort
  full_ok = exp_full == act_full

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
