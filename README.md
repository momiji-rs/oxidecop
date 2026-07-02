# rubocop-rs

A fast, native, **RuboCop-compatible** Ruby linter — written in Rust, over the
official [Prism](https://github.com/ruby/prism) parser. Think *ruff, but for
Ruby, and bug-compatible with the RuboCop everyone already uses.*

> **Status: early / experimental.** The core idea is proven (see the fidelity
> numbers below), but only ~10 cops are implemented. This is a working
> foundation, not a shippable linter yet.

---

## Why

RuboCop is the de-facto Ruby linter, but it runs on CRuby and is dominated by
**parse time in the interpreted `parser` gem** (measured ~40× slower than a
native parse on a 600-line file). A native linter that speaks Prism can be an
order of magnitude faster while producing **byte-identical output**, so it drops
into existing projects with zero config changes — the goal is:

```sh
brew install rubocop-rs
rubocop-rs ./          # same offenses, same messages, same exit code — just fast
```

The bet only pays off if we are **faithful to RuboCop's actual behavior**, not
"morally equivalent." That is why fidelity is measured against RuboCop's *own*
test suite (below), not by eyeballing.

## The core idea: cops are (mostly) data

RuboCop has ~600 cops. ~266 of them are *pattern cops* — they match an AST shape
via RuboCop's `def_node_matcher` S-expression DSL and emit a message. In
rubocop-rs those become **table rows, not code**:

```rust
// src/main.rs — the DECLARATIVE table. Each row is a whole cop.
("(send _ {:== :===} (nil))", "Style/NilComparison",
 "Prefer the use of the `nil?` predicate.", Anchor::Op),

("(send (send (...) ${:size :length}) :== (int 0))", "Style/ZeroLengthPredicate",
 "Use `empty?` instead of `{} == 0`.", Anchor::Node),
```

A small **node-pattern engine** (`src/nodepattern.rs`) parses that DSL and
matches it against Prism nodes. Supported so far:

| DSL form | meaning |
|---|---|
| `(send RECV :meth ARG…)` | a call node, mapped onto Prism's `receiver`/`name`/`arguments` |
| `nil?` | absent / nil receiver |
| `_` | any node |
| `(...)` | any **present** node (requires an explicit receiver) |
| `:sym` | a method-name symbol |
| `{a b c}` | union — any alternative matches |
| `$…` | **capture** — records matched text for message interpolation |
| `(nil)` / `(int N)` / `(int _)` | literal nodes |

Two things are **not** derivable from the pattern and live alongside it as data:

- **`Anchor`** — where `add_offense` points (whole node vs. the operator/selector
  vs. the receiver's selector). RuboCop cops choose this per-cop.
- **message template** — `{}` placeholders filled from `$` captures, because
  RuboCop interpolates the offending method/expression into the message.

Cops that need real logic (e.g. `Style/RedundantReturn`, `Naming/MethodName`)
are small imperative `Visit` methods in `src/main.rs`. The dividing line is
explicit and the oracle tells you which side a cop needs to be on.

## Fidelity: measured against RuboCop's own specs

RuboCop's specs use the `expect_offense` DSL, which encodes the exact expected
line:col + message inline as caret annotations:

```ruby
expect_offense(<<~RUBY)
  x == nil
    ^^ Prefer the use of the `nil?` predicate.
RUBY
```

The **oracle** (`oracle/oracle.rb`) parses those fixtures, runs the
de-annotated source through the `rubocop-rs` binary under *the example's own*
`cop_config`, and diffs at two levels: **LOC** (right line:col) and **FULL**
(line:col *and* identical message).

Current leaderboard (`ruby oracle/leaderboard.rb`), against RuboCop v1.88.0:

```
cop                                  scored   skip         LOC        FULL
Style/SymbolProc                         57     13    57/57       57/57      100%
Style/NumericPredicate                   39      4    39/39       39/39      100%
Lint/NestedMethodDefinition              38      0    38/38       38/38      100%
Style/NilComparison                       8      0     8/8         8/8       100%
Naming/MethodName                        48     30    45/48       45/48       94%
Layout/LineLength                       145     41   111/145     111/145      77%
Style/StringLiterals                     49      5    38/49       37/49       76%
Layout/TrailingWhitespace                19      0    13/19       13/19       68%
Style/ZeroLengthPredicate                74      0    49/74       48/74       65%
Style/Documentation                      43      6    22/43       22/43       51%
Style/NumericLiterals                    28      0    14/28       13/28       46%
Style/RedundantReturn                    37      1    19/37       14/37       38%
Style/FrozenStringLiteralComment         88      7    40/88       31/88       35%
────────────────────────────────────────────────────────────────────────────
TOTAL (representable examples)          673    107                476/673      71%
```

**Read this honestly:** the score is over *representable* examples only. RuboCop's
specs encode some text dynamically — escape sequences the heredoc renders
(`x = 0\t`, `　`), loop variables as `#{keyword}`/`#{args}` in
`.each`-generated examples, and `%{identifier}` `expect_offense` substitutions.
The oracle renders what is static (heredoc escapes per Ruby's quoting rules,
the known-constant helpers like `trailing_whitespace`, `#{enforced_style}` from
the active config) and **skips** anything still-dynamic rather than scoring a
harness limitation as a cop miss — hence the `skip` column.

Each example runs under its own `let(:cop_config)`, translated to `.rubocop.yml`.
So a `LineLength` example with `Max: 30, AllowURI: true` is tested at that `Max` —
and its failures then honestly attribute to features rubocop-rs lacks (`AllowURI`,
`AllowedPatterns`, `EnforcedStyle`, …), not to a coincidental default. That is
"config coverage we haven't built," measured where it actually bites.

The value is that **every gap is a named, reproducible spec example**, so
improving a cop is a test-driven grind, and residual failures cluster into
**reusable engine features** (config/`EnforcedStyle` support, receiver-guard
clauses) that lift many cops at once — not one-off hacks.

## Usage

```sh
cargo build --release
./target/release/rubocop-rs path/to/file.rb              # lint (uses ./.rubocop.yml if present)
./target/release/rubocop-rs path/to/file.rb my.yml       # explicit config
./target/release/rubocop-rs path/to/file.rb --fix        # autocorrect → stdout
```

Output mimics RuboCop's simple formatter:

```
C:  4:  8: Style/NilComparison: Prefer the use of the `nil?` predicate.
1 file inspected, 1 offense detected
```

Config support is a minimal `.rubocop.yml` subset: `AllCops: DisabledByDefault`,
per-cop `Enabled`, simple params (`Max`, `MinDigits`, …), and `EnforcedStyle`.
Parameter defaults and each style cop's `SupportedStyles`/default live in one
place — the `SCHEMA` table (`src/schema_gen.rs`), **generated for all 606 cops**
from rubocop's own `config/default.yml` by `tools/gen_schema.rb` (the yml is
vendored under `vendor/`). A cop reads config through
`Config::enforced_style`/`int` instead of hardcoding its own defaults, so a
newly ported cop's defaults are already there. `Style/StringLiterals` dispatches on it (`single_quotes` ↔
`double_quotes`); other style cops just need to be pointed at the same resolver.

`AllowedMethods` / `AllowedPatterns` are a cross-cutting mechanism (rubocop's
shared `AllowedMethods` mixin): a cop calls `Cops::allowed(cop, text)` to suppress
an offense whose relevant string is either an exact `AllowedMethods` entry or
matches an `AllowedPatterns` regex (compiled once via the `regex` crate). It's
wired to the method name for `Naming/MethodName`, the source line for
`Layout/LineLength`, and the operator/predicate (plus any enclosing call, via a
call-name stack) for `Style/NumericPredicate`; adding it to another cop is a
one-line guard. No plugin/require support yet.

## Repo layout

```
src/main.rs          the runner: argv, file/config I/O, output, --fix application
src/config.rs        .rubocop.yml subset + the per-cop SCHEMA (defaults/styles)
src/declarative.rs   the DECLARATIVE pattern-cop table + Anchor + message render
src/cops/mod.rs      the Cops visitor, thin Visit dispatch, lint() entry, tests
src/cops/*.rs        per-department imperative cop logic (style, naming, …)
src/nodepattern.rs   the node-pattern DSL parser + Prism matcher (captures, unions)
oracle/oracle.rb     spec-suite oracle: one cop's fixtures vs. the binary
oracle/leaderboard.rb runs the oracle across all cops, prints the ranked table
oracle/run_oracle.sh  convenience: build + oracle a few cops
oracle/spec_fixtures/ RuboCop's own *_spec.rb, fetched verbatim (v1.88.0)
```

## How to add / improve a cop (the workflow)

1. **Find RuboCop's real pattern.** Copy the `def_node_matcher` string and `MSG`
   from RuboCop's source *verbatim* — do not paraphrase. (Guessed patterns are
   systematically over-broad; the oracle catches this every time.)
2. **Express it.** A pattern cop → add a row to `DECLARATIVE` in `src/main.rs`
   (pattern, cop name, message template, anchor). A logic cop → add a small
   `Visit` method. If the DSL can't express the pattern yet, extend
   `src/nodepattern.rs`.
3. **Measure.** Add the cop → spec mapping in `oracle/leaderboard.rb` (the
   fixture auto-fetches from GitHub), then `ruby oracle/leaderboard.rb`. The
   miss list is your exact TODO.
4. **Iterate** until FULL-match is where you want it. Residual misses that need
   real logic (semantic guards, alternate configs) are legitimate — note them.

## Roadmap

- **Deepen** the top cops toward 100% (config/`EnforcedStyle` support is the
  single biggest lever — it unlocks the "config-gated" failures across the board).
- **Widen**: port the ~266 declarative cops in tiers; the DSL grows to meet them.
- **Autocorrect fidelity**: diff against `rubocop -a` output (an oracle mode).
- **Runner**: multi-file globbing, `.rubocop.yml` inheritance/`require`,
  RuboCop-compatible formatters and exit codes.
- **Distribution**: `brew install rubocop-rs`, prebuilt binaries.

## Provenance

Spun out of experiments in a sibling Ruby-in-Rust project (`rubyrs`). rubocop-rs
has **zero dependency** on that project — it only needs `ruby-prism`.

## License

MIT — see [LICENSE](LICENSE).
