#!/bin/sh
# End-to-end parity check: lint a real Ruby tree with rubocop-rs AND real
# rubocop (restricted to the cops rubocop-rs implements), then diff the
# normalized offense lists. This is the acceptance test for the project's
# actual selling point — same offenses on real code, not just on spec
# fixtures. Exit 0 = byte-identical offense sets.
#
#   tools/parity.sh <ruby-source-dir>
#   tools/parity.sh "$(dirname "$(gem which rubocop)")/rubocop"   # rubocop's own source
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${1:?usage: parity.sh <ruby-source-dir>}
[ -d "$TARGET" ] || { echo "not a directory: $TARGET" >&2; exit 2; }
BIN="$ROOT/target/release/rubocop-rs"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Keep in sync with oracle/leaderboard.rb COPS (the implemented set).
COPS="Style/NilComparison,Style/NumericPredicate,Style/ZeroLengthPredicate,Style/RedundantReturn,Style/NumericLiterals,Style/StringLiterals,Style/Documentation,Style/FrozenStringLiteralComment,Style/SymbolProc,Naming/MethodName,Lint/NestedMethodDefinition,Layout/LineLength,Layout/TrailingWhitespace,Style/EvenOdd,Lint/RandOne,Style/ArrayJoin,Lint/BooleanSymbol,Lint/BigDecimalNew,Style/Dir,Style/StringChars,Style/NestedFileDirname,Lint/UriRegexp"

cargo build --release --manifest-path "$ROOT/Cargo.toml" --quiet

# Normalize both outputs to "file:line:col: Cop: message" (headers folded in,
# [Correctable] tags stripped, absolute paths trimmed to the target-relative).
# Backticks go too: rubocop's simple formatter renders `...` spans as colored
# text (stripping the backticks under --no-color) — presentation, not message.
normalize() {
  awk -v strip="$1" '
    /^== .* ==$/ { f = substr($0, 4, length($0) - 6); sub(strip, "", f); next }
    /^C:/ {
      line = $0
      sub(/^C: */, "", line)
      gsub(/\[Correctable\] /, "", line)
      gsub(/`/, "", line)
      printf "%s:%s\n", f, line
    }
  ' | sort
}

"$BIN" "$TARGET" | normalize "^$TARGET/" > "$WORK/ours.txt" || true
(cd "$TARGET" && rubocop --only "$COPS" --cache false -f simple --no-color . 2>/dev/null) \
  | normalize "^\./" > "$WORK/theirs.txt" || true

if diff -u "$WORK/theirs.txt" "$WORK/ours.txt"; then
  echo "PARITY: $(wc -l < "$WORK/ours.txt" | tr -d ' ') offense lines identical on $TARGET"
else
  echo "DIVERGED (see diff above; - = rubocop only, + = rubocop-rs only)" >&2
  exit 1
fi
