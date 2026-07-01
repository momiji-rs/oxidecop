#!/usr/bin/env ruby
# frozen_string_literal: true

# Fidelity leaderboard: for every cop rubocop-rs implements, run rubocop's OWN
# spec suite through the oracle and rank by pass-rate. This is the acceptance
# metric — "what % of rubocop's own tests do we pass, per cop", measured, not
# guessed.
#
# Fixtures are cached in spec_fixtures/ (fetched from rubocop v1.88.0).
# Usage: ruby leaderboard.rb

require 'open3'
require 'fileutils'

REF  = 'v1.88.0'
ROOT = File.expand_path('..', __dir__)
BIN  = File.join(ROOT, 'target/release/rubocop-rs')
DIR  = File.expand_path('spec_fixtures', __dir__)

system('cargo', 'build', '--release', '--manifest-path', File.join(ROOT, 'Cargo.toml'),
       out: File::NULL, err: File::NULL) unless File.exist?(BIN)
abort "build the binary first: cargo build --release" unless File.exist?(BIN)

# cop -> spec path within rubocop's repo (spec/rubocop/cop/<path>_spec.rb)
COPS = {
  'Style/NilComparison'              => 'style/nil_comparison',
  'Style/ZeroLengthPredicate'        => 'style/zero_length_predicate',
  'Style/RedundantReturn'            => 'style/redundant_return',
  'Style/NumericLiterals'            => 'style/numeric_literals',
  'Style/StringLiterals'             => 'style/string_literals',
  'Style/Documentation'              => 'style/documentation',
  'Style/FrozenStringLiteralComment' => 'style/frozen_string_literal_comment',
  'Naming/MethodName'                => 'naming/method_name',
  'Layout/LineLength'                => 'layout/line_length',
  'Layout/TrailingWhitespace'        => 'layout/trailing_whitespace'
}.freeze

FileUtils.mkdir_p(DIR)

def fetch(rel)
  local = File.join(DIR, "#{File.basename(rel)}_spec.rb")
  return local if File.exist?(local)

  url = "https://raw.githubusercontent.com/rubocop/rubocop/#{REF}/spec/rubocop/cop/#{rel}_spec.rb"
  out, st = Open3.capture2('curl', '-fsSL', url)
  if st.success? && !out.empty?
    File.write(local, out)
    warn "  fetched #{rel}"
    local
  else
    warn "  MISSING spec for #{rel}"
    nil
  end
end

rows = []
COPS.each do |cop, rel|
  spec = fetch(rel)
  next unless spec

  _out, err, = Open3.capture3({ 'ORACLE_QUIET' => '1' },
                              'ruby', File.expand_path('oracle.rb', __dir__), BIN, cop, spec)
  line = err.lines.find { |l| l.start_with?('SUMMARY') }
  next unless line

  _, name, total, aloc, afull, = line.chomp.split("\t")
  rows << { cop: name, total: total.to_i, loc: aloc.to_i, full: afull.to_i }
end

# rank by FULL pass-rate across ALL rubocop spec examples for the cop
rows.sort_by! { |r| [-(r[:total].zero? ? 0 : r[:full].to_f / r[:total]), -r[:total]] }

puts
puts '════════════════════════ rubocop-rs fidelity leaderboard ════════════════════════'
puts format('  %-34s %8s  %10s  %10s', 'cop', 'examples', 'LOC', 'FULL')
puts '  ' + ('─' * 76)
tot_full = tot_all = 0
rows.each do |r|
  pct = r[:total].zero? ? 0 : (100.0 * r[:full] / r[:total])
  bar = '█' * (pct / 10).round
  puts format('  %-34s %8d  %4d/%-4d   %4d/%-4d  %5.0f%% %s',
              r[:cop], r[:total], r[:loc], r[:total], r[:full], r[:total], pct, bar)
  tot_full += r[:full]
  tot_all  += r[:total]
end
puts '  ' + ('─' * 76)
overall = tot_all.zero? ? 0 : (100.0 * tot_full / tot_all)
puts format('  %-34s %8d  %10s   %4d/%-4d  %5.0f%%', 'TOTAL (all spec examples)', tot_all, '', tot_full, tot_all, overall)
puts
