#!/bin/sh
# The scoreboard: median-of-N timings for rubocop-rs vs competing linters on
# fixed corpora, same cops, same protocol (hyperfine, warm caches). Every perf
# change gets judged by THIS script, not ad-hoc runs.
#
#   bench/compare.sh <corpus-dir>...            # e.g. /tmp/jekyll /tmp/rails
#   COMPETITORS="oxicop nitrocop" bench/compare.sh ...
#
# Competitors are picked up when their binary is on PATH (or ~/.cargo/bin);
# rubocop joins when RUBOCOP=1 (slow, needs the corpus config's plugins or a
# cleaned config). Correctness (offense counts) is printed alongside speed —
# a fast wrong answer is not a win.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release/rubocop-rs"
RUNS=${RUNS:-7}
COPS=${COPS:-"Layout/TrailingWhitespace,Style/FrozenStringLiteralComment,Style/StringLiterals,Style/NegatedIf,Lint/Debugger,Naming/MethodName"}

cargo build --release --manifest-path "$ROOT/Cargo.toml" --quiet
command -v hyperfine >/dev/null || { echo "need hyperfine" >&2; exit 1; }

find_bin() {
  command -v "$1" 2>/dev/null && return
  [ -x "$HOME/.cargo/bin/$1" ] && echo "$HOME/.cargo/bin/$1"
}

for corpus in "$@"; do
  [ -d "$corpus" ] || { echo "skip (not a dir): $corpus" >&2; continue; }
  name=$(basename "$corpus")
  echo "== $name =="
  cd "$corpus"

  # correctness column: total offenses each tool reports
  printf '   offenses:  rubocop-rs=%s' "$("$BIN" --only "$COPS" . 2>/dev/null | grep -c '^[A-Z]:' || true)"
  for comp in ${COMPETITORS:-oxicop nitrocop}; do
    cbin=$(find_bin "$comp") || continue
    [ -n "$cbin" ] || continue
    printf '  %s=%s' "$comp" "$("$cbin" --only "$COPS" . 2>/dev/null | grep -c '^ *[0-9]*:[0-9]*:' || true)"
  done
  echo

  set --_dummy
  cmds="-n rubocop-rs '$BIN --only $COPS .'"
  for comp in ${COMPETITORS:-oxicop nitrocop}; do
    cbin=$(find_bin "$comp") || continue
    [ -n "$cbin" ] || continue
    cmds="$cmds -n $comp '$cbin --only $COPS .'"
  done
  if [ "${RUBOCOP:-0}" = "1" ]; then
    cmds="$cmds -n rubocop 'rubocop --only $COPS --cache false -f q .'"
  fi
  eval hyperfine -i -w 2 -r "$RUNS" --export-json /tmp/compare_bench.json "$cmds" >/dev/null 2>&1 || true
  python3 - <<'EOF'
import json
try:
    d = json.load(open('/tmp/compare_bench.json'))
    for r in d['results']:
        name = r.get('command_name') or r['command'].split()[0]
        print(f"   {name:12s} median {r['median']*1000:9.1f} ms")
except Exception as e:
    print(f"   (bench failed: {e})")
EOF
done
