#!/bin/sh
# Micro-benchmark: oxidecop vs rubocop, same file, same cops, via hyperfine.
#
# What this measures (and its limits — the binary lints ONE file for now):
#   - single-shot CLI latency on a real-world Ruby file. For rubocop that
#     includes interpreter + gem boot, which is exactly what you pay per
#     invocation (editor save-hooks, pre-commit on one file). `--cache false`
#     keeps rubocop honest (its result cache would skip linting entirely).
#   - rubocop runs `--only` the cops oxidecop implements, so both sides do
#     comparable work. NOT an offense-fidelity comparison — that's the oracle.
#
# corpus/medium.rb = rubocop v1.88.0's lib/rubocop/config.rb (~1.4k lines),
# fetched once and cached. corpus/big.rb = the same file x10 (~14k lines) —
# synthetic, but real code shape, for parse/visit scaling.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR="$ROOT/bench/corpus"
REF=v1.88.0
BIN="$ROOT/target/release/oxidecop"

# Keep in sync with oracle/leaderboard.rb COPS (the implemented set).
COPS="Style/NilComparison,Style/NumericPredicate,Style/ZeroLengthPredicate,Style/RedundantReturn,Style/NumericLiterals,Style/StringLiterals,Style/Documentation,Style/FrozenStringLiteralComment,Style/SymbolProc,Naming/MethodName,Lint/NestedMethodDefinition,Layout/LineLength,Layout/TrailingWhitespace"

mkdir -p "$DIR"
if [ ! -f "$DIR/medium.rb" ]; then
  curl -fsSL "https://raw.githubusercontent.com/rubocop/rubocop/$REF/lib/rubocop/config.rb" > "$DIR/medium.rb"
fi
if [ ! -f "$DIR/big.rb" ]; then
  for _ in 1 2 3 4 5 6 7 8 9 10; do cat "$DIR/medium.rb"; done > "$DIR/big.rb"
fi

cargo build --release --manifest-path "$ROOT/Cargo.toml" --quiet

command -v hyperfine >/dev/null || { echo "hyperfine not found (brew install hyperfine)"; exit 1; }
command -v rubocop >/dev/null || { echo "rubocop not found (gem install rubocop)"; exit 1; }

for f in "$DIR/medium.rb" "$DIR/big.rb"; do
  echo
  echo "== $(basename "$f") ($(wc -l < "$f" | tr -d ' ') lines) =="
  hyperfine -i --warmup 2 \
    -n oxidecop "$BIN $f" \
    -n "rubocop --only <same 13 cops>" "rubocop --only $COPS --cache false -f q $f"
done
