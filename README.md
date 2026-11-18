# RustyShield

Offline generator for `RustShield.txt`: a deduplicated, classified, rewritten, and verified unified
filter list optimized for Brave's [`adblock-rust`](https://github.com/brave/adblock-rust) engine.

**Status:** M0/M1 reference implementation is runnable. The pinned engine is
`adblock = "=0.13.6"`, and the engine parser is the only semantic oracle. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, including the dialect-aware
rewrite catalog for ABP / AdGuard / uBO syntax, the whole-list fast-native/official/engine-trusted
golden rule, rewrite-to-eligible-or-exclude policy, compiler-friendly output ordering, safety and
verification gates, workspace layout, and remaining milestones.

## Quick start

```sh
cargo test --workspace
cargo run -- build
```

`build` reads `config/sources.toml`, generates artifacts in a staging directory, verifies the
candidate against the admitted baseline with the real engine, and atomically publishes:

- `RustShield.txt`
- `RustShield.txt.sha256`
- `lists.lock`
- `reports/manifest.json`
- `reports/build.json`
- `reports/build.md`
- `reports/analysis.json`
- `reports/rewrites.tsv`
- `reports/dropped.tsv` and `reports/excluded.tsv`
- `reports/dialect_gaps.tsv`
- `reports/verify.json`
- `reports/bench.json`

Verification is a hard publish gate: with `verify.required = true`, any mismatch leaves artifacts
in `out/.staging-<build-id>` and exits with status 2.

## CLI

```sh
cargo run -- analyze
cargo run -- verify
cargo run -- verify --candidate path/to/list.txt
cargo run -- bench
cargo run -- bench --candidate path/to/list.txt
cargo run -- resources
```

Set `RUSTSHIELD_DEBUG_REWRITE=1` to print rewrite candidate diagnostics to stderr.

## Workspace

Stage crates are intentionally short:

- `crates/model` — config, canonical IR, resource snapshot catalog, shared hashing and report types
- `crates/fetch` — offline/local source loading and deterministic `lists.lock`
- `crates/parse` — directive evaluation and engine-backed parsing
- `crates/analyze` — metrics and classification
- `crates/admit` — golden-rule admission and D11 resource trust checks
- `crates/dedup` — exact and semantic deduplication with source-priority retention
- `crates/rewrite` — conservative type/domain/cosmetic union rewrites with reparse and engine checks
- `crates/emit` — deterministic `compiler-friendly-v1` output ordering
- `crates/verify` — differential verification and benchmarks
- `crates/cli` — the `rustshield` binary and staged publishing
