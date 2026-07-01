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

def parse_block(raw_lines)
  # raw_lines: the heredoc body (already the interior). Dedent, then split
  # source lines from caret-annotation lines.
  lines = dedent(raw_lines)
  src = []
  expected = []
  lines.each do |ln|
    if ln =~ /\A(\s*)(\^+)(.*)\z/
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
cur_cfg = 'default' # active cop_config; reset on each context, set by let(:cop_config)
while i < lines.length
  l = lines[i]
  if l =~ /^\s*(context|describe)\s/
    cur_ctx = l.strip
    cur_cfg = 'default'
  end
  # `let(:cop_config)` in either single-line `{ {...} }` or multi-line `do..end`
  # form. Capture the raw hash text (quotes preserved, whitespace collapsed) so
  # array values like AllowedPatterns survive; unparseable blocks stay 'default'.
  if l =~ /let\(:cop_config\)\s*\{(.*)\}\s*\z/
    cur_cfg = extract_hash(Regexp.last_match(1))
  elsif l =~ /let\(:cop_config\)\s*do\s*\z/
    blk = []
    i += 1
    while i < lines.length && lines[i].strip != 'end'
      blk << lines[i]
      i += 1
    end
    cur_cfg = extract_hash(blk.join(' '))
  end
  if l =~ /expect_(offense|no_offenses)\(<<[~-]RUBY\)/
    kind = Regexp.last_match(1) == 'offense' ? :offense : :no_offense
    body = []
    i += 1
    until lines[i].strip == 'RUBY'
      body << lines[i]
      i += 1
    end
    src, expected = parse_block(body)
    examples << { kind: kind, context: cur_ctx, cfg: cur_cfg, src: src, expected: expected }
  elsif l =~ /expect_no_offenses\((['"])(.*?)\1\)/
    examples << { kind: :no_offense, context: cur_ctx, cfg: cur_cfg, src: Regexp.last_match(2) + "\n", expected: [] }
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
def build_cfg(cop, cfg_hash)
  lines = ['AllCops:', '  DisabledByDefault: true', "#{cop}:", '  Enabled: true']
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
  cfg_hash = parse_cfg(ex[:cfg])
  src = resolve_interp(ex[:src], cfg_hash)

  # Unrepresentable: source still interpolates a value we can't resolve
  # statically (loop vars like #{keyword}, #{args}, …). Linting the literal
  # `#{...}` text would be meaningless, so exclude rather than score as a miss.
  if src =~ /\#\{/
    g[:skipped] += 1
    next
  end

  actual = run_poc(POC, src, build_cfg(COP, cfg_hash))
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
