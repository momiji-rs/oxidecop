# frozen_string_literal: true

# Strip third-party-plugin configuration out of a corpus checkout so the
# REFERENCE rubocop runs there with only the built-in cops installed.
#
#   ruby tools/prepare_corpus.rb <corpus-dir>
#
# Parity (tools/parity.sh) compares byte-identical output of `--only <the
# implemented built-in cops>`, so plugin cops never participate — but their
# mere PRESENCE in a config file makes rubocop abort with "unrecognized cop
# or department" when the plugin gem isn't installed. This rewrites, IN
# PLACE, every rubocop config file the corpus's `.rubocop.yml` can reach
# (itself, `.rubocop_todo.yml`, anything under `.rubocop/`), dropping:
#
#   - `plugins:` / `require:` / `inherit_gem:` top-level entries (the gem
#     loads themselves, and configs inherited from uninstalled gems);
#   - every section whose department isn't shipped with rubocop core
#     (RSpec/Rails/Performance/Capybara/FactoryBot/I18n/Rake/Minitest/
#     InternalAffairs/...), whether written as `Dept/CopName:` or as a
#     bare department block (`RSpec:`).
#
# Sections of built-in departments, `AllCops`, and the `inherit_*`
# machinery survive untouched, so the built-in-cop verdicts — the only
# thing parity compares — are exactly what the corpus's real config
# produces. YAML is round-tripped (aliases resolved); rubocop reads the
# result identically.
require "yaml"
require "rubocop"

BUILTIN_DEPARTMENTS = %w[
  Bundler Gemspec Layout Lint Metrics Migration Naming Security Style
].freeze

# The installed reference rubocop's own cop registry — plugin gems aren't
# installed, so this is exactly the built-in set. A corpus's CUSTOM cop
# (mastodon's `Style/MiddleDot`, defined by a `require:`d local file we
# strip) lives in a built-in department but is NOT in this registry, and
# would abort the reference run just like a plugin cop.
KNOWN_COPS = RuboCop::Cop::Registry.global.map(&:cop_name).to_set.freeze

# Non-section top-level keys that must survive.
PASSTHROUGH_KEYS = %w[AllCops inherit_from inherit_mode].freeze

DROP_KEYS = %w[plugins require inherit_gem].freeze

def keep_key?(key)
  return true if PASSTHROUGH_KEYS.include?(key)
  return false if DROP_KEYS.include?(key)

  if key.include?("/")
    return KNOWN_COPS.include?(key)
  end

  # a bare department block (`RSpec:`) — keep only built-in departments
  BUILTIN_DEPARTMENTS.include?(key)
end

def clean_config(path)
  data = YAML.unsafe_load_file(path) || {}
  unless data.is_a?(Hash)
    warn "skip (not a mapping): #{path}"
    return
  end
  kept = data.select { |k, _| keep_key?(k.to_s) }
  dropped = data.size - kept.size
  # line_width: -1 — never fold long scalars: a wrapped `!ruby/regexp`
  # changes what a text-level config reader sees (and hides AllowedPatterns).
  File.write(path, YAML.dump(kept, line_width: -1))
  puts "cleaned #{path} (dropped #{dropped} top-level entries)"
end

dir = ARGV.fetch(0) { abort "usage: ruby tools/prepare_corpus.rb <corpus-dir>" }
root = File.join(dir, ".rubocop.yml")
abort "no .rubocop.yml under #{dir}" unless File.exist?(root)

files = [root]
todo = File.join(dir, ".rubocop_todo.yml")
files << todo if File.exist?(todo)
files.concat(Dir[File.join(dir, ".rubocop", "*.yml")])

files.each { |f| clean_config(f) }
