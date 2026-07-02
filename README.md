# OxideCop

A fast, native, **RuboCop-compatible** Ruby linter and autocorrector — written
in Rust over the official [Prism](https://github.com/ruby/prism) parser. Think
*ruff, but for Ruby, and bug-compatible with the RuboCop everyone already uses.*

```sh
cargo install oxidecop
oxidecop .        # same offenses, same messages, same exit code — just fast
```

> **Status: early / experimental.** The core idea is proven — the 47
> implemented cops pass **100% of RuboCop's own representable spec examples**,
> detection (1051/1051) *and* autocorrection (477/477, `--fix`), and match
> RuboCop **byte-for-byte on real repos** (Rails, Mastodon, rubygems.org,
> RuboCop's own source — see
> [BENCHMARKS.md](https://github.com/momiji-rs/oxidecop/blob/master/BENCHMARKS.md))
> — but 47 cops is not a shippable linter yet.

## Why

RuboCop is the de-facto Ruby linter, but it runs on CRuby and is dominated by
**parse time in the interpreted `parser` gem**. A native linter that speaks
Prism is an order of magnitude faster while producing **byte-identical
output**, so it drops into existing projects with zero config changes.

The bet only pays off if we are **faithful to RuboCop's actual behavior**, not
"morally equivalent." That is why fidelity is measured against RuboCop's *own*
test suite, not by eyeballing:

| | |
|---|---|
| Whole-tree lint, Rails (~3,400 files) | **57 ms** |
| vs [oxicop](https://crates.io/crates/oxicop) (regex-based, no parser) | 2–5× faster — and correct where it reports thousands of false positives |
| vs [nitrocop](https://github.com/6/nitrocop) (prism-based, 915 cops) | 4–31× faster cold; on RuboCop's own CI-clean repo it reports 17,174 offenses, OxideCop reports the true zero |
| Warm rerun (nothing changed) | **~29 ms** (stat-keyed result cache, no file reads) |

## Fidelity, measured

RuboCop's spec suite encodes exact expectations inline:

```ruby
expect_offense(<<~RUBY)
  x == nil
    ^^ Prefer the use of the `nil?` predicate.
RUBY
```

The **oracle** (`oracle/oracle.rb`) parses those fixtures, runs the
de-annotated source through the `oxidecop` binary under *the example's own*
`cop_config`, and diffs at three levels: **LOC** (right line:col), **FULL**
(line:col *and* identical message), and **FIX** (the `--fix` output against
`expect_correction`).

Current leaderboard (`ruby oracle/leaderboard.rb`), against RuboCop v1.88.0:

```
47 cops implemented — every one at 100% FULL match, 100% FIX (autocorrect).
TOTAL (representable examples)         1051    108               1051/1051    100%   FIX 477/477
```

**Read this honestly:** the score is over *representable* examples only.
RuboCop's specs encode some text dynamically (RSpec loop variables,
`%{identifier}` substitutions, shared_examples that run under a caller's
config); the oracle renders what is static and **skips** what isn't, rather
than scoring a harness limitation as a cop miss — hence the `skip` column.

End-to-end, `tools/parity.sh <ruby-tree>` lints a tree with both linters
(both under `--only` with the implemented cop list, which RuboCop
force-enables) and diffs the normalized offense lists. Byte-identical on all
four corpora: **Rails (12,271 offense lines), Mastodon (4,123), rubygems.org
(772), and RuboCop's own 1,712-file source tree (0 vs 0)**. CI re-verifies the
oracle at 100% and the parity on every push.

## Usage

```sh
oxidecop lib/ spec/              # lint trees in parallel (nearest .rubocop.yml per file)
oxidecop file.rb my.yml          # explicit config
oxidecop -a .                    # autocorrect in place (like rubocop -a)
oxidecop file.rb --fix           # autocorrect a single file -> stdout
oxidecop --only Style/SymbolProc --format json .
```

Output mimics RuboCop's simple formatter (severity letters, `[Correctable]`
tags, per-cop `Severity` config honored); `--format json` emits
RuboCop-compatible JSON. Exit code is 1 when offenses were found.

Config support covers the surface real projects use: `.rubocop.yml` discovery
(nearest config per file), `inherit_from` chains, `inherit_gem`, `AllCops:
DisabledByDefault / Exclude / Include`, per-cop `Enabled` / `Exclude` /
`EnforcedStyle` / `AllowedMethods` / `AllowedPatterns` (including
`!ruby/regexp`), magic-comment `rubocop:disable` directives (with `-- reason`
trailers), and `TargetRubyVersion`. Parameter defaults for **all 606 cops**
are generated from RuboCop's own `config/default.yml` into one schema table,
so a newly ported cop's defaults are already correct.

A result cache (stat-keyed, content-hash fallback) makes unchanged-tree reruns
~2× faster; `--cache false` disables it.

## Repo layout

```
src/main.rs            the runner: argv, file/config discovery, output, --fix loop
src/config.rs          .rubocop.yml subset + the generated per-cop SCHEMA
src/declarative.rs     the DECLARATIVE pattern-cop table (node-pattern rows)
src/nodepattern.rs     RuboCop's node-pattern DSL, parsed and matched over Prism
src/cops/              the visitor + per-department cop logic
src/cops/breakable.rs  Layout/LineLength autocorrection (CheckLineBreakable port)
oracle/                the spec-suite oracle + leaderboard (fidelity measurement)
tools/parity.sh        whole-tree byte-identical diff vs reference RuboCop
bench/compare.sh       the speed scoreboard vs competing linters
```

## How to add / improve a cop

1. **Find RuboCop's real pattern.** Copy the `def_node_matcher` string and
   `MSG` from RuboCop's source *verbatim* — do not paraphrase. (Guessed
   patterns are systematically over-broad; the oracle catches this every time.)
2. **Express it.** A pattern cop -> one row in the `DECLARATIVE` table. A logic
   cop -> a small `Visit` method. If the DSL can't express the pattern yet,
   extend `src/nodepattern.rs`.
3. **Measure.** Map the cop to its spec in `oracle/leaderboard.rb`, run it —
   the miss list is your exact TODO, down to the failing example.
4. **Verify end-to-end.** `tools/parity.sh` against a real tree must stay
   byte-identical.

## Roadmap

- **Widen**: port the next tiers of cops (the schema and node-pattern DSL
  already cover their config surface).
- **Distribution**: prebuilt binaries, `brew install oxidecop`.
- **Close the warm-rerun gap**: cache the directory walk to take no-change
  reruns from ~29 ms toward ~5 ms.

## License

MIT — see [LICENSE](https://github.com/momiji-rs/oxidecop/blob/master/LICENSE).
OxideCop is not affiliated with the RuboCop project; RuboCop is the work of
its authors and contributors, and this project exists to be faithful to it.
