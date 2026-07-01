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
  if l =~ /let\(:cop_config\)\s*\{\s*(\{.*\})\s*\}/
    cur_cfg = Regexp.last_match(1).gsub(/['"]/, '').gsub(/\s+/, ' ')
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
cfg = <<~YML
  AllCops:
    DisabledByDefault: true
  #{COP}:
    Enabled: true
YML

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
# group tallies by active cop_config so config-gated examples are transparent
groups = Hash.new { |h, k| h[k] = { loc: 0, full: 0, total: 0 } }
fails = []
examples.each_with_index do |ex, n|
  actual = run_poc(POC, ex[:src], cfg)
  exp = ex[:expected]
  g = groups[ex[:cfg]]
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

total = examples.length
puts "== oracle: #{COP} (#{File.basename(SPEC)}) =="
puts "   #{total} examples, grouped by active cop_config:"
groups.each do |cfgname, g|
  puts format('     %-34s LOC %d/%d   FULL %d/%d', cfgname[0, 34], g[:loc], g[:total], g[:full], g[:total])
end
def_g = groups['default'] || { loc: 0, full: 0, total: 0 }
puts "   >> default-config detection fidelity: #{def_g[:loc]}/#{def_g[:total]} LOC, #{def_g[:full]}/#{def_g[:total]} FULL" if def_g[:total].positive?
unless fails.empty?
  puts '   --- misses ---'
  puts fails.join("\n") unless ENV['ORACLE_QUIET']
end

# machine-readable summary for the leaderboard driver:
# SUMMARY<TAB>cop<TAB>total<TAB>all_loc<TAB>all_full<TAB>def_total<TAB>def_loc<TAB>def_full
all_loc  = groups.values.sum { |g| g[:loc] }
all_full = groups.values.sum { |g| g[:full] }
warn "SUMMARY\t#{COP}\t#{total}\t#{all_loc}\t#{all_full}\t#{def_g[:total]}\t#{def_g[:loc]}\t#{def_g[:full]}"
