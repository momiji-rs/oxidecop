#!/usr/bin/env bash
# Run the spec-suite oracle: rubocop's OWN spec fixtures vs. oxidecop.
# Fixtures live in spec_fixtures/ (fetched verbatim from rubocop v1.88.0).
set -euo pipefail
cd "$(dirname "$0")"          # -> oracle/
ROOT="$(cd .. && pwd)"

cargo build --release --manifest-path "$ROOT/Cargo.toml" >/dev/null 2>&1
BIN="$ROOT/target/release/oxidecop"

run() { ruby oracle.rb "$BIN" "$1" "spec_fixtures/$2"; echo; }

run Style/NilComparison        nil_comparison_spec.rb
run Style/ZeroLengthPredicate  zero_length_predicate_spec.rb
run Style/RedundantReturn      redundant_return_spec.rb
