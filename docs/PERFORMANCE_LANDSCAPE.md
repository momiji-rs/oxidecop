# Performance Landscape Analysis

> A skeptical, honest survey of the Ruby performance-lint landscape — fasterer,
> rubyfast, and rubocop-performance — and where OxideCop should (and should not)
> spend the next slice of work.
>
> Compiled September 2026. Sources cited inline. Anything we could not verify
> is explicitly flagged as **[UNVERIFIED]**.

---

## TL;DR

- **Do not ship a standalone fasterer clone.** [fasterer](https://github.com/DamirSvrtan/fasterer)
  is a 19-rule `ruby_parser` CLI last released as **0.11.0 (2023-11)**; last
  commit **2024-01-25**. [rubyfast](https://crates.io/crates/rubyfast) already
  rewrote it in Rust + Prism and *deliberately diverges* (33 vs 74 offenses on
  rubygems.org). Speed is a solved problem. momiji-rs does not ship "morally
  equivalent, faster."
- **The reference is rubocop-performance, not fasterer.** Ruby CI that cares
  about these idioms loads `plugins: rubocop-performance` (52 cops as of
  **v1.27.0**, 2026-08-16). That is the same contract OxideCop already has with
  RuboCop core: oracle against the gem's own `expect_offense` /
  `expect_correction` specs, then whole-tree byte-identical parity.
- **Six Style cops OxideCop already implements cover the fasterer rules that
  migrated into RuboCop core** — `Style/Sample`, `Style/SymbolProc`, `Style/For`,
  `Style/TrivialAccessors`, `Style/HashEachMethods`, `Style/RedundantFetchBlock`.
  Re-implementing them under a fasterer-shaped CLI would double-report or
  desync messages. The *remaining* fasterer overlap lives in Performance
  (`Detect`, `ReverseEach`, `FlatMap`, `RangeInclude`, `StringReplacement`,
  `RedundantMerge`, `RedundantBlockCall`, `Size`, `Count`, `StartWith`/`EndWith`).
- **The first product is a `Performance` department inside OxideCop**, gated on
  the same `plugins:` / `require:` strings RuboCop uses. Turning those cops on
  unconditionally would fire on every Rails tree that does *not* load the
  plugin and immediately break the existing core-cop parity.
- **First slice: infrastructure, then seven Enabled-by-default cops.** Do not
  start with `Enabled: pending` cops, a fasterer-compat facade, or `--fix`
  extras the reference does not have. Detection + autocorrect parity with
  rubocop-performance is the whole bet.

**Don't fool ourselves:** OxideCop at `ba88161` already implements **395** core
cops (the README's "47" figure is stale). The visitor, node-pattern DSL,
oracle, and `tools/parity.sh` exist. Performance is the next *department*, not
a new architecture. Matching rubyfast on wall-clock is table stakes, not a
differentiator — rubyfast's own numbers are **[UNVERIFIED by us]** (maintainer
benchmark, no corpus checked out in this repo).

---

## 1. The three incumbents

### 1a. fasterer (DamirSvrtan/fasterer)

A small static checker inspired by [fast-ruby](https://github.com/fastruby/fast-ruby)
and Sferik's 2014 Baruco talk. Walks a `ruby_parser` sexp, emits
`path:line explanation`.

| Signal | Value | Source |
|---|---|---|
| Latest release | **0.11.0, 2023-11-20** | `lib/fasterer/version.rb` |
| Last commit | **2024-01-25** (revert of `Hash#update` vs `Hash#[]=`) | github commits |
| Parser | `ruby_parser >= 3.19.1` (not Prism) | `fasterer.gemspec` |
| Rule count | 19 named speedups in `Offense::EXPLANATIONS` | `lib/fasterer/offense.rb` |
| Autocorrect | none | source |
| Config | `.fasterer.yml` (`speedups:` + `exclude_paths:`) | README |
| Default caveat | `each_with_index_vs_while` is `false` in the documented example config | README |

The 19 speedups, with where that idea lives today:

| fasterer key | gist | Where it lives in 2026 |
|---|---|---|
| `shuffle_first_vs_sample` | `.shuffle.first` → `.sample` | **OxideCop `Style/Sample`** |
| `block_vs_symbol_to_proc` | `{ \|x\| x.foo }` → `&:foo` | **OxideCop `Style/SymbolProc`** |
| `for_loop_vs_each` | `for` → `#each` | **OxideCop `Style/For`** |
| `getter_vs_attr_reader` / `setter_vs_attr_writer` | trivial accessors | **OxideCop `Style/TrivialAccessors`** |
| `keys_each_vs_each_key` | `Hash#keys.each` | **OxideCop `Style/HashEachMethods`** |
| `fetch_with_argument_vs_block` | `fetch(k, default)` vs block | **OxideCop `Style/RedundantFetchBlock`** (and it is *stricter* about cheap defaults than fasterer) |
| `select_first_vs_detect` / `select_last_vs_reverse_detect` | `select.first` / `.last` | **`Performance/Detect`** |
| `reverse_each_vs_reverse_each` | `.reverse.each` | **`Performance/ReverseEach`** |
| `map_flatten_vs_flat_map` | `.map{}.flatten(1)` | **`Performance/FlatMap`** |
| `include_vs_cover_on_range` | `Range#include?` | **`Performance/RangeInclude`** |
| `gsub_vs_tr` | single-char `gsub` | **`Performance/StringReplacement`** (also `delete`) |
| `hash_merge_bang_vs_hash_brackets` | `merge!({k: v})` | **`Performance/RedundantMerge`** |
| `proc_call_vs_yield` | `block.call` vs `yield` | **`Performance/RedundantBlockCall`** |
| `sort_vs_sort_by` | `sort { }` | `Performance/CompareWithBlock` / `RedundantSortBlock` (pending) — not 1:1 |
| `each_with_index_vs_while` | rewrite as `while` | **nowhere respectable.** fasterer's own README says do not follow this in a Rails app. Default off. |
| `rescue_vs_respond_to` | `rescue NoMethodError` | not a Performance cop; Lint/Style adjacent |
| `module_eval` | string `module_eval` with `def` | not ported; string-eval heuristics |

fasterer's documented TODOs (`count` vs `size`, `match` vs `start_with?`,
`gsub` vs `sub`) are already Performance cops (`Size`, `Count`, `StartWith` /
`EndWith`, `StringReplacement`).

**Reading:** fasterer is a *rule source*, not a *product reference*. Its parser
is a generation behind Prism. Several of its defaults are advice RuboCop
explicitly will not ship (`while` instead of `each_with_index`). Matching it
byte-for-byte would mean matching `ruby_parser` false positives and the
over-broad `fetch(k, nil)` hit that rubyfast already refused.

### 1b. rubyfast (7a6163/rubyfast)

Rust + `ruby-prism`, parallel scan, `.fasterer.yml` compat, `--fix` for 8 of
19 rules, inline `# rubyfast:disable` / `# fasterer:disable`.

Claimed (maintainer benchmark, Apple Silicon, rubygems.org @ `3c8ea0d4c`,
**[UNVERIFIED by us]**):

| Tool | Time | Offenses |
|---|---|---|
| rubyfast v1.4.0 | 64.7 ms | 33 |
| fasterer prism fork | 546 ms | — |
| fasterer 0.11.0 | 4.38 s | 74 |

The 33 vs 74 gap is **intentional**: rubyfast suppresses `fetch` with a cheap
default (`nil`, number, symbol, variable). That is the opposite of OxideCop's
contract. A momiji-rs fasterer clone whose selling point is "we also skip
those 41" is rubyfast with extra steps.

**What rubyfast gets right, and we should steal as *engineering* not as
product:** Prism, parallel file walk, syntax-checked autocorrect applied
back-to-front. OxideCop already does all three for core cops.

### 1c. rubocop-performance (the reference)

An official RuboCop extension. One department, 52 cops. Loaded via:

```yaml
plugins: rubocop-performance          # RuboCop 1.72+
# or, older:
require: rubocop-performance
```

Pinned for this plan: **v1.27.0** (2026-08-16), against OxideCop's existing
RuboCop **v1.88.0** oracle. Compatibility of that pair on a real tree is
**[UNVERIFIED — PR 1 must install both gems and run one cop's spec through
the reference `rubocop`]**. If 1.27.0 demands a newer RuboCop than 1.88.0,
pin the newest performance tag that still loads under 1.88.0 and record it
in `oracle/leaderboard.rb` the same way `REF = 'v1.88.0'` is recorded today.

Inventory from `config/default.yml` (v1.27.0):

| Enabled | Count | Notes |
|---|---|---|
| `true` | **24** | first-slice pool |
| `pending` | **19** | off unless `AllCops: NewCops: enable` |
| `false` | **9** | off; several exist because a microbenchmark was wrong (`ArraySemiInfiniteRangeSlice`, `BlockGivenWithExplicitBlock`, `Casecmp`) |

Enabled-by-default (the 24):

`BindCall`, `Caller`, `CompareWithBlock`, `Count`, `DeletePrefix`,
`DeleteSuffix`, `Detect`, `DoubleStartEndWith`, `EndWith`, `FixedSize`,
`FlatMap`, `InefficientHashSearch`, `RangeInclude`, `RedundantBlockCall`,
`RedundantMatch`, `RedundantMerge`, `RegexpMatch`, `ReverseEach`, `Size`,
`StartWith`, `StringReplacement`, `TimesMap`, `UnfreezeString`,
`UriDefaultParser`.

Unsafe / `SafeAutoCorrect: false` is common (`Detect`, `RangeInclude`,
`RedundantMerge`, `Count`, `StartWith`/`EndWith`, `DeletePrefix`/`Suffix`,
…). Autocorrect still ships; the oracle's FIX column still applies. Do not
invent a "safer" Detect that skips ActiveRecord — the reference does not.

---

## 2. Overlap with cops OxideCop already implements

These are **done**. Do not re-encode them as Performance cops, and do not
build a fasterer CLI that re-emits them under different names.

| OxideCop cop (in `IMPLEMENTED`) | fasterer key | rubocop-performance? |
|---|---|---|
| `Style/Sample` | `shuffle_first_vs_sample` | no (moved to Style) |
| `Style/SymbolProc` | `block_vs_symbol_to_proc` | no |
| `Style/For` | `for_loop_vs_each` | no |
| `Style/TrivialAccessors` | getter/setter vs `attr_*` | no |
| `Style/HashEachMethods` | `keys_each_vs_each_key` | no — also covers unused `|k, v|` → `each_key`/`each_value` |
| `Style/RedundantFetchBlock` | `fetch_with_argument_vs_block` | no — the *block* form with a literal default, inverse of fasterer's "argument vs block" framing |
| `Style/ExplicitBlockArgument` | adjacent to `proc_call_vs_yield` | no — different shape (`yield` → `&block` at the call site) |

`Style/RedundantFetchBlock` vs fasterer's `fetch` rule is the clearest
"same idiom, opposite default" example: fasterer flags `fetch(k, [])` as
"use a block"; RuboCop flags `fetch(k) { [] }` as "the block is redundant
for a cheap default." OxideCop already matched RuboCop. Keep it that way.

`Style/CollectionMethods` is in SCHEMA (Enabled: false, `PreferredMethods`
hash) but **not** in `IMPLEMENTED`. `Performance/Detect` reads
`PreferredMethods['detect']` to decide whether the replacement is `detect`
or `find`. See §4 and PR 5.

---

## 3. Why a Performance department, not a new binary

OxideCop's bet, from the README, verbatim in spirit: *faithful to RuboCop's
actual behavior, not morally equivalent; measured against RuboCop's own
suite; byte-identical on real repos.*

A `fasterer` drop-in would optimize for a config file (`.fasterer.yml`) and
an output format almost no current CI uses, while fighting rubyfast on
speed. A `Performance` department:

- reuses the visitor, `DECLARATIVE` table, `--fix` loop, formatters, cache,
  and `tools/parity.sh`;
- is what `plugins: rubocop-performance` in a real `.rubocop.yml` already
  asks for;
- has a 52-cop ceiling — a department, not another 395-cop mountain;
- includes fasterer's leftover overlap *and* the modern rules fasterer never
  grew (`filter_map`, `delete_prefix`, `sum`, `String#bytesize`, loop
  collection literals).

A fasterer-compat facade (`--fasterer`, read `.fasterer.yml`, one-line
output) is a formatter plus a name map. It is not a second engine. Defer it
until the department exists and someone has a drop-in need. Do not schedule
it in the first batch.

---

## 4. What OxideCop has to grow before the first cop

This is the price of entry. Skipping it is how Performance cops leak onto
trees that never loaded the plugin.

### 4a. Plugin / require gating (correctness, not polish)

Today `src/config.rs` does not parse `plugins:` or `require:`.
`tools/prepare_corpus.rb` **strips** both, plus every non-core department
section (`Performance` included), so that the reference `rubocop` without
plugin gems still starts. That is correct for *core* parity.

RuboCop only instantiates Performance cops when the plugin is loaded.
OxideCop must match:

| Input | Performance cops |
|---|---|
| no `plugins:` / `require:` | **off** (even though default.yml says `Enabled: true`) |
| `plugins: rubocop-performance` or list containing it | on, subject to per-cop Enabled |
| `require: rubocop-performance` or `rubocop/cop/performance` | on, same |
| `--plugin rubocop-performance` | on (CLI; add when we grow argv, not required for slice 1 if config covers CI) |
| `--only Performance/Detect` (oracle / parity) | **on**, matching how `parity.sh` already force-enables core cops |

Without the last row the oracle cannot run. Without the first row, Rails
parity (currently `--only` the core list) is safe *until someone adds
Performance names to that list without also installing the gem on the
reference side.*

A dedicated test: a tree with no plugin string and a `select.first` must
produce **zero** Performance offenses. Core-cop parity.sh must keep
stripping Performance from corpus configs.

### 4b. Schema merge from a second `default.yml`

`tools/gen_schema.rb` reads `vendor/rubocop-default-1.88.0.yml` (606 core
cops). Performance parameter defaults (`EnabledForFlattenWithoutParams`,
`MaxKeyValuePairs`, `SafeMultiline`, `IncludeActiveSupportAliases`) live in
the *other* gem.

Plan: vendor `vendor/rubocop-performance-default-1.27.0.yml` (or whatever
tag PR 1 pins) and concatenate both YAML maps in `gen_schema.rb`. Do not
hand-copy defaults into cop code. The HashEachMethods `AllowedReceivers`
workaround exists because **hashes/arrays other than `SupportedStyles` /
`AllowedMethods` are dropped** — `PreferredMethods` is the same trap (see
4d).

`Enabled` is in `META` and is not encoded in SCHEMA. That is already how
core works: unimplemented cops are simply absent from `IMPLEMENTED`.
Pending-as-enabled is an existing gap (4e); first-slice cops are all
`Enabled: true`, so they match "no explicit false → on" *once the plugin
gate is open*.

### 4c. Oracle fixtures from a second repo

`oracle/leaderboard.rb` fetches
`raw.githubusercontent.com/rubocop/rubocop/#{REF}/spec/rubocop/cop/#{rel}_spec.rb`.

Performance specs live at
`rubocop/rubocop-performance/#{PERF_REF}/spec/rubocop/cop/performance/#{name}_spec.rb`.

Extend `fetch` with a per-cop source repo (core vs performance). Keep
fixtures in `oracle/spec_fixtures/` with names that do not collide
(`detect_spec.rb` is fine — core has no `Performance/Detect`). `run_oracle.sh`
gains one `run Performance/ReverseEach reverse_each_spec.rb` line per cop,
same as today.

`tools/parity.sh` stays core-only until a *second* driver exists
(`tools/parity_performance.sh`) that:

1. installs `rubocop-performance` at `PERF_REF` on the reference side;
2. passes `--plugin rubocop-performance` (or a config that loads it);
3. `--only`s the implemented Performance list, force-enabled both sides.

Do not fold Performance names into the existing `COPS=` string until that
driver is green — `prepare_corpus.rb` dropping `Performance:` is load-bearing
for the core run.

### 4d. `Style/CollectionMethods` PreferredMethods (Detect)

`Performance/Detect#preferred_method`:

```ruby
config.for_cop('Style/CollectionMethods')['PreferredMethods']['detect'] || 'detect'
```

The cop's *own* spec builds a minimal `RuboCop::Config.new` with
`PreferredMethods => { 'detect' => nil }` and therefore messages say
`` `detect` ``. A real merged default.yml has `detect: find`, which would
make production messages say `` `find` ``.

**[UNVERIFIED until PR 5 live-probes it]** whether RuboCop 1.88.0 +
rubocop-performance 1.27.0 on a file with no CollectionMethods override
emits `detect` or `find`. The spec's default path is `detect`. Real-repo
parity must use whichever the reference gem actually prints. SCHEMA
currently stores `Style/CollectionMethods` with `params: &[]` because the
hash was dropped. Detect cannot ship with a hardcoded `"detect"` until that
probe is done. Same class of bug as HashEachMethods' hardcoded
`Thread.current` AllowedReceivers fallback.

### 4e. `Enabled: pending` / `NewCops` (existing gap, do not widen)

OxideCop implements seven core cops whose default.yml says `Enabled: pending`
(`Lint/DuplicateMagicComment`, `Lint/EmptyBlock`, `Lint/EmptyClass`,
`Style/ComparableClamp`, `Style/NestedFileDirname`, `Style/NilLambda`,
`Style/StringChars`) and has **no `AllCops: NewCops` handling**.
`cop_config_enabled` treats a missing `Enabled` as on.

That has not blown core parity on the four corpora (those cops likely do not
fire there, or the corpora enable NewCops — **[UNVERIFIED which]**).
Performance has **19 pending** cops. Porting them under today's enablement
rules would spray offenses onto every plugin-enabled tree. **First batch is
Enabled: true only.** A later infra PR should encode default `Enabled`
(including `pending`) in SCHEMA and honor `NewCops`.

### 4f. Department module

`src/cops/mod.rs` dispatches into `style` / `lint_cops` / `layout` / …
`style.rs` is already huge. Add `src/cops/performance.rs` and a thin
`visit_call_node` hook, same pattern as `bundler.rs` / `gemspec.rs`. Do not
append Performance cops to `style.rs`.

---

## 5. Honest strengths of the incumbents (the bar to clear)

1. **rubocop-performance is the ecosystem default.** Messages, autocorrect,
   `Safe: false` annotations, and `.rubocop.yml` knobs are what reviewers
   already argue about. Matching them is the price of entry.
2. **The specs are the oracle, and they are small.** ReverseEach's spec is
   ~170 lines; Detect's is one file with a `select_methods` loop. This is
   *easier* than Layout/LineLength, not harder.
3. **rubyfast is fast and shipped.** A Performance department that is slower
   than rubyfast on a 1k-file tree, *or* that reports a different set than
   `rubocop --plugin rubocop-performance --only Performance/ReverseEach`, has
   failed. Speed vs rubyfast is a bench (`bench/compare.sh`); correctness vs
   rubocop-performance is the gate.
4. **fasterer is honest about taste.** Its README's "do not follow blindly"
   is why we will not port `each_with_index_vs_while` as a default-on cop
   under any name.

---

## 6. First-slice cop selection (7 cops)

Criteria, in order:

1. `Enabled: true` in rubocop-performance 1.27.0.
2. Prefer fasterer leftover overlap (the original prompt) so the department
   is visibly "the rest of fasterer, done properly."
3. Prefer a `def_node_matcher` plus a small `on_send` over ancestor-heavy
   logic — but do not skip a cop just because Prism has no parent pointer;
   OxideCop already has that idiom (`nle_pending`, `call_stack`, …).
4. Each cop reaches **100% FULL and 100% FIX** on representable spec
   examples before merge. Same ratchet as core.

| # | Cop | fasterer overlap | Why this slice | Known traps |
|---|---|---|---|---|
| 1 | **Performance/ReverseEach** | `reverse_each_vs_reverse_each` | Smallest Enabled cop that is still a chained send. Canary for the department + `csend`. | `use_return_value?` walks ancestors (assignment / send / `return`). Offense range is `reverse.each`, including multiline leading/trailing dots. |
| 2 | **Performance/Size** | fasterer TODO (`count` vs `size`) | Tiny matcher: `count` on array/hash literals and a handful of constructors. | Must *not* fire on `count { }`. Receiver shapes (`to_a` / `Array[]` / `Hash()`) copied verbatim from the matcher, not guessed. |
| 3 | **Performance/RangeInclude** | `include_vs_cover_on_range` | One matcher, one replacement (`cover?`). Unsafe, like upstream. | Only range *literals* (and `(begin range)`). Variables assigned a range are out of scope — the cop's own TODO. |
| 4 | **Performance/FlatMap** | `map_flatten_vs_flat_map` | Chained `map`/`collect` + `flatten(1)`. Config knob `EnabledForFlattenWithoutParams` (default false). | `flatten` without `1` is *not* an offense by default. Block-pass `map(&:x).flatten(1)` is. |
| 5 | **Performance/Detect** | `select_first` / `select_last` | The headline leftover. `select`/`find_all`/`filter` + `first`/`last`/`[0]`/`[-1]`. | Preferred method `detect` vs `find` (§4d). Skip `lazy`. Skip `first(n)`. Safe-nav. Multiline `end.first`. **Unsafe** (Hash / AR). |
| 6 | **Performance/StringReplacement** | `gsub_vs_tr` | `gsub`/`gsub!` → `tr`/`delete` when both sides are single deterministic chars. Broader than fasterer (regex literals, `delete` for empty replacement). | `DETERMINISTIC_REGEX`, escape interpretation, `Regexp.new`. Do not "improve" fasterer's single-char-string-only heuristic — copy this cop. |
| 7 | **Performance/RedundantMerge** | `hash_merge_bang_vs_hash_brackets` | `merge!` of a small hash → `[]=`. `MaxKeyValuePairs` default **2** (fasterer only flagged a *single* pair). | Autocorrect of modifier `if`/`while`, `each_with_object` value-used, kwsplat, impure receiver with 2+ pairs. Unsafe. |

**Explicitly not in the first seven:** `Count` (AR `count` vs block — adjacent
to Size but a bigger safety story), `StartWith`/`EndWith` (regex-anchor
rewrites, `SafeMultiline`), `RedundantBlockCall` (overlap with
`Style/ExplicitBlockArgument` — sequence after Detect is enough yield-adjacent
work for one slice), `CompareWithBlock`, `RegexpMatch`, everything pending.

---

## 7. PR Plan

Each PR is independently reviewable and mergeable. A cop PR is not mergeable
until its oracle row is 100% FULL and 100% FIX on representable examples, and
`tools/parity.sh` on the four core corpora is unchanged (Performance names
still absent from the core `COPS=` list).

### PR 0 — this document

- **Title:** `docs: Performance landscape and first-slice plan`
- **Files:** `docs/PERFORMANCE_LANDSCAPE.md` (this file)
- **Depends on:** nothing
- **Changes:** land the decision record. No code.

### PR 1 — Performance department infrastructure

- **Title:** `feat: gate a Performance department on rubocop-performance plugin load`
- **Files / components:**
  - `vendor/rubocop-performance-default-<ver>.yml` (pinned)
  - `tools/gen_schema.rb` — merge both default.yml files
  - `src/schema_gen.rs` — regenerated
  - `src/config.rs` — parse `plugins:` / `require:`; `performance_plugin` flag;
    `enabled("Performance/…")` false unless flag *or* `--only`
  - `src/cops/performance.rs` — empty module + `Visit` hooks that no-op
  - `src/cops/mod.rs` — `mod performance`; `IMPLEMENTED` unchanged
  - `oracle/leaderboard.rb` — `PERF_REF`; `fetch` knows two remotes
  - tests: no plugin → `select.first` silent; plugin string → department
    considered (still zero cops)
- **Depends on:** PR 0
- **Changes:** make it *possible* to add a Performance cop without leaking
  onto plugin-less trees. Pin the reference gem pair (RuboCop 1.88.0 +
  performance tag) in CI comments the same way core is pinned.
- **Not in this PR:** any real cop; `parity_performance.sh`; `NewCops`.

### PR 2 — Performance/ReverseEach (canary)

- **Title:** `feat: Performance/ReverseEach`
- **Files:** `src/cops/performance.rs`, `IMPLEMENTED`, `oracle/leaderboard.rb`,
  `oracle/run_oracle.sh`, fixture fetch
- **Depends on:** PR 1
- **Changes:** copy `MSG` and `reverse_each?` matcher verbatim. Port
  `use_return_value?` via the existing ancestor-stack idiom, not a parent
  pointer. `on_csend` aliased. Autocorrect replaces the `reverse.each` range,
  including leading/trailing-dot multiline forms from the spec.
- **Exit:** oracle 100/100; core `parity.sh` still green.

### PR 3 — Performance/Size + Performance/RangeInclude

- **Title:** `feat: Performance/Size and Performance/RangeInclude`
- **Files:** `src/cops/performance.rs`, `IMPLEMENTED`, oracle map, fixtures
- **Depends on:** PR 2 (proves the department path; these two are independent
  of ReverseEach logically, but stacked so CI only grows one cop-shaped
  failure mode at a time after the canary)
- **Changes:** two matchers, two selector replacements (`count`→`size`,
  `include?`/`member?`→`cover?`). RangeInclude is `Safe: false` — still
  autocorrect, still report.
- **Why grouped:** both are "replace this send name on a literal-ish
  receiver" and share no config knobs. Splitting is fine if either oracle
  row is messy.

### PR 4 — Performance/FlatMap

- **Title:** `feat: Performance/FlatMap`
- **Files:** performance.rs, SCHEMA already has
  `EnabledForFlattenWithoutParams` after PR 1, oracle
- **Depends on:** PR 2
- **Changes:** `map`/`collect` (block or block-pass) chained to
  `flatten`/`flatten!`. Default: only `flatten(1)`. Do not autocorrect
  parameterless `flatten` even when the extra warning is enabled.

### PR 5 — Performance/Detect

- **Title:** `feat: Performance/Detect`
- **Files:** performance.rs, possibly a tiny `PreferredMethods['detect']`
  reader next to the HashEachMethods AllowedReceivers fallback, oracle
- **Depends on:** PR 4 (same chained-enumerable shape; Detect is the
  highest-traffic leftover)
- **Changes:** `select`/`find_all`/`filter` + `first`/`last`/`[0]`/`[-1]`.
  Skip `lazy`, skip arity-1 `first`/`last`. Honor CollectionMethods
  *after a live probe of 1.88.0 + the pinned performance gem* on a
  no-override file — do not guess `detect` vs `find`. Safe-nav and
  multiline `end.first` are in the spec; they are not optional.

### PR 6 — Performance/StringReplacement

- **Title:** `feat: Performance/StringReplacement`
- **Files:** performance.rs, oracle
- **Depends on:** PR 2
- **Changes:** `gsub`/`gsub!` → `tr`/`tr!`/`delete`/`delete!` per upstream,
  including deterministic regex literals. Fasterer's "both args are 1-char
  Strings" is a subset; we implement the cop, not the subset.

### PR 7 — Performance/RedundantMerge

- **Title:** `feat: Performance/RedundantMerge`
- **Files:** performance.rs, oracle (`MaxKeyValuePairs` already in SCHEMA
  from PR 1)
- **Depends on:** PR 2
- **Changes:** `merge!(hash-literal)` with ≤ N pairs → `[]=` assignments.
  Port modifier-form rewriting and the `each_with_object` inspector rather
  than "only the single-pair case fasterer had." Default N is **2**.

PRs 3–7 after the canary are independent of each other and can land in any
order (or as parallel worktrees) once PR 2 is on master. The numbering is
the recommended review order, not a merge lock.

### After this batch (not scheduled here)

- `tools/parity_performance.sh` + one real tree that actually loads the
  plugin (many apps do; the four current corpora may not after
  `prepare_corpus.rb`).
- Wave 2 Enabled cops: `Count`, `StartWith`, `EndWith`, `DeletePrefix`,
  `DeleteSuffix`, `DoubleStartEndWith`, `CompareWithBlock`,
  `RedundantBlockCall`, `RedundantMatch`, `RegexpMatch`, `TimesMap`,
  `InefficientHashSearch`, `Caller`, `BindCall`, `FixedSize`,
  `UnfreezeString`, `UriDefaultParser`.
- `NewCops` / default-Enabled in SCHEMA, then pending cops.
- Optional `oxidecop --fasterer` facade. Not a department prerequisite.

---

## 8. Key decisions

| Decision | Rationale |
|---|---|
| Reference is **rubocop-performance**, not fasterer | Same fidelity contract as core OxideCop; this is what `.rubocop.yml` already names. |
| No standalone fasterer-rs / rubyfast competitor | rubyfast owns that niche and already diverges on purpose. |
| Performance cops **off** unless plugin/require/`--only` | Otherwise every plugin-less Rails tree grows false offenses and core parity dies. |
| First seven are all `Enabled: true` | Avoid the existing pending-as-enabled gap until SCHEMA stores Enabled. |
| Copy matchers and `MSG` verbatim | Guessed patterns are systematically over-broad; the oracle exists to catch that, not to bless it. |
| Autocorrect in the same PR as detection | Upstream ships it; OxideCop's FIX column is the same gate as core. Unsafe ≠ skip `--fix`. |
| Pin performance gem next to RuboCop 1.88.0 | One pair of versions, recorded in `leaderboard.rb`, same as core `REF`. |
| Defer fasterer CLI facade | Formatter work, not analysis work. |

---

## Appendix: source index

- OxideCop tree measured for this doc: `ba88161`, 395 names in `IMPLEMENTED`, 0 `Performance/*`.
- OxideCop README / oracle / parity — this repo
- `tools/gen_schema.rb`, `src/schema_gen.rs`, `src/config.rs` — schema and enablement
- `tools/prepare_corpus.rb` — strips `plugins` / `require` / `Performance:`
- fasterer README + `lib/fasterer/{offense,analyzer,scanners/method_call_scanner}.rb` — https://github.com/DamirSvrtan/fasterer
- fasterer 0.11.0 / last commit 2024-01-25 — github tags + commits
- rubyfast README / crates.io — https://github.com/7a6163/rubyfast https://crates.io/crates/rubyfast
- rubocop-performance v1.27.0 `config/default.yml` + cop sources + specs — https://github.com/rubocop/rubocop-performance
- rubocop-performance cops index — https://docs.rubocop.org/rubocop-performance/cops.html
- RuboCop `Style/CollectionMethods` default `PreferredMethods` — `vendor/rubocop-default-1.88.0.yml`
- fast-ruby — https://github.com/fastruby/fast-ruby

**Flagged unverified:** rubyfast's 64.7 ms / 33-vs-74 numbers (not reproduced
here); whether RuboCop 1.88.0 loads rubocop-performance 1.27.0 without a
version bump; whether a no-override real run of `Performance/Detect` prints
`detect` or `find`; why the seven pending core cops have not broken corpus
parity (`NewCops` on those trees vs. no hits).
