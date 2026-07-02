# Benchmarks

A three-way comparison against **RuboCop v1.88.0** (Ruby 3.4.1) and
**[oxicop](https://github.com/npow/oxicop) v0.2.0**, following oxicop's own
published protocol ([BENCHMARKS.md](https://github.com/npow/oxicop/blob/master/BENCHMARKS.md)):
`--only` the same 6 cops, median of 5 consecutive runs, warm caches, one machine
(Apple Silicon).

Cops: `Layout/TrailingWhitespace, Style/FrozenStringLiteralComment,
Style/StringLiterals, Style/NegatedIf, Lint/Debugger, Naming/MethodName`.

## Speed (median of 5)

| Corpus | files | rubocop-rs | oxicop | vs oxicop | RuboCop (cached) | RuboCop (no cache) |
|---|--:|--:|--:|--:|--:|--:|
| Jekyll | 163 | **14 ms** | 24 ms | 1.7× | 841 ms | 1.78 s |
| RuboCop repo | 1,710 | **44 ms** | 121 ms | 2.8× | 1.51 s | 14.9 s |
| Mastodon | ~3,000 | **83 ms** | 149 ms | 1.8× | — | — |
| Rails | ~3,400 | **103 ms** | 265 ms | 2.6× | — | — |

The engine profile (RUBOCOP_RS_TIMING=1): prism parse now dominates (~63% of
cpu time), the visitor is ~15% — i.e. the overhead over "just parsing Ruby
correctly" is small, while oxicop skips parsing entirely (its Cargo.toml has
NO Ruby parser dependency — it is regex/line-based, which is also why its
offenses are wrong).

## Correctness on the same runs

Speed only matters if the answers are right. Offense counts on the exact same
corpora, with working RuboCop (project config, plugin `require`s stripped so it
can run) as ground truth. For rubocop-rs, "match" means the diff of normalized
offense lines (file:line:col + full message) is empty — not just equal counts:

| Corpus | RuboCop (truth) | rubocop-rs | nitrocop | oxicop |
|---|--:|--:|--:|--:|
| Jekyll | **0** | **0** | 0 | 6,504 |
| RuboCop repo | **0** | **0** | 0 | 2,665 |
| rubygems.org | **0** | **0** | 0 | — |
| Mastodon | **2,100** | **2,100** (0-diff) | 2,100 | 2,915 |
| Rails | **393** | **393** (0-diff) | **1** | — |

Mastodon exercises `inherit_from` chains, `DisplayStyleGuide` message
suffixes, `rubocop:disable all -- reason` trailers, and shebang-only `bin/*`
executables — all reproduced byte-for-byte. Rails (`DisabledByDefault: true`)
exposes that nitrocop's `--only` does not force-enable cops the way RuboCop's
does: it reports 1 offense where RuboCop reports 393; rubocop-rs matches all
393 byte-for-byte.

oxicop's offenses on Jekyll are 6,499 × `Style/StringLiterals` false positives:
it applies the default `single_quotes` style to a codebase whose `.rubocop.yml`
sets `EnforcedStyle: double_quotes`, and scans directories the config excludes
(`benchmark/`, …) — despite advertising `.rubocop.yml` support. rubocop-rs
honors both (`AllCops: Exclude` globs, per-cop styles) and matches RuboCop's
zero exactly. Message-level agreement is verified separately by
`tools/parity.sh` (byte-identical offense lists vs. RuboCop on real trees) and
by the oracle (100% of RuboCop's own representable spec examples for every
implemented cop).

## nitrocop

[nitrocop](https://github.com/6/nitrocop) (v0.0.1-pre12, built from source) is
a much more serious competitor than oxicop: it parses with prism like we do,
implements 915 cops across 7 gems, supports the full config surface
(inherit_from/inherit_gem), and validates against RuboCop on a 5,587-repo
corpus at 99.99% match — note its corpus compares file/line/cop only, not
columns or message text, both of which our oracle and parity check require.

Correctness: on rubygems.org (1,317 files, a config exercising per-cop
Exclude, `!ruby/regexp` excludes and inherit_from), RuboCop, nitrocop and
rubocop-rs all report **zero offenses** — three-way agreement.

Speed (same 6-cop protocol, median of 7):

| Corpus | rubocop-rs | nitrocop (no cache) | vs |
|---|--:|--:|--:|
| Jekyll | **12 ms** | 997 ms | 85× |
| RuboCop repo | **44 ms** | 1,049 ms | 24× |
| Mastodon | **86 ms** | 669 ms | 8× |
| Rails | **103 ms** | 1,603 ms | 16× |
| rubygems.org | **31 ms** | 417 ms | 14× |

nitrocop's warm-cache path on the RuboCop repo still measures 981 ms here —
its fixed per-run overhead (config resolution across 915 cops) dominates at
this cop count. Its own README reports 279 ms uncached on rubygems.org; on
this machine, this protocol, we measure what the table shows.

## A note on oxicop's published RuboCop baseline

oxicop's BENCHMARKS.md reports RuboCop at a near-constant ~775 ms on every
project — Jekyll (22K lines) through Discourse (936K lines). RuboCop cannot
lint 936K lines in 775 ms; that constant is the signature of Ruby boot followed
by an immediate config error (these projects' `.rubocop.yml` files `require`
plugin gems, and RuboCop aborts when they aren't installed) and/or a fully
cached result run. On our machine, RuboCop *actually linting* the RuboCop repo
takes **14.9 s** uncached (1.5 s result-cached) — so the honest speedup story
is much larger than their table suggests, for both tools.

## Reproducing

```sh
C6="Layout/TrailingWhitespace,Style/FrozenStringLiteralComment,Style/StringLiterals,Style/NegatedIf,Lint/Debugger,Naming/MethodName"
git clone --depth 1 https://github.com/jekyll/jekyll.git /tmp/jekyll
cd /tmp/jekyll
hyperfine -i -w 1 -r 5 \
  "rubocop-rs --only $C6 ." \
  "oxicop --only $C6 ." \
  "rubocop --only $C6 --cache false ."   # needs the config's plugin gems installed
```
