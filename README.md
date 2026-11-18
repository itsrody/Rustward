# RustyShield

Generator for `RustShield.txt`: a deduplicated, classified, rewritten, and verified unified filter
list optimized for Brave's [`adblock-rust`](https://github.com/brave/adblock-rust) engine.

The engine parser is the only semantic oracle. The pinned engine is `adblock = "=0.13.6"`.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design: dialect-aware rewrites for
ABP / AdGuard / uBO syntax, the fast-native/official/engine-trusted golden rule,
rewrite-to-eligible-or-exclude policy, compiler-friendly output ordering, and verification gates.

## Sources

`config/sources.toml` pins 18 upstream lists by SHA-256:

- AdGuard `extension/ublock` optimized filters: `2`, `3`, `14`, `118`, `122`, `123`, `201`, `207`,
  `208`, `250`, `255`, `256`, `257`
- uBO lists: `filters.min.txt`, `badware.min.txt`, `privacy.min.txt`, `annoyances.min.txt`,
  `annoyances-cookies.txt`

Every HTTP(S) source must have a `sha256` pin. Raw bytes are cached in `cache/blobs/sha256/`;
`--offline` builds only from a warm cache. Upstream changes are explicit: run
`cargo run -- update-pins` to refresh pins, then rebuild and review the diff.

## Build output

A successful build publishes all artifacts under `dist/`:

- `dist/RustShield.txt`
- `dist/RustShield.txt.sha256`
- `dist/lists.lock`
- `dist/reports/manifest.json`
- `dist/reports/build.json`
- `dist/reports/build.md`
- `dist/reports/analysis.json`
- `dist/reports/rewrites.tsv`
- `dist/reports/dropped.tsv` and `dist/reports/excluded.tsv`
- `dist/reports/dialect_gaps.tsv`
- `dist/reports/verify.json`
- `dist/reports/bench.json`

Verification is a hard publish gate: with `verify.required = true`, any mismatch beyond
`max_mismatches = 0` leaves artifacts in `out/.staging-<build-id>` and exits with status 2.

## GitHub Actions

[`.github/workflows/build.yml`](.github/workflows/build.yml) is the source of truth for published
output. It runs:

- manually via **Actions → build → Run workflow**
- automatically every 2 days at 00:17 UTC

The workflow refreshes pins, rebuilds with the release profile, verifies, uploads `dist/` as an
artifact, and commits updated `config/sources.toml` plus `dist/` back to the default branch.

## Quick start

```sh
cargo test --workspace
cargo run -- build
cargo run -- build --offline   # requires a warm cache/
```

## CLI

```sh
cargo run -- update-pins
cargo run -- analyze
cargo run -- verify
cargo run -- verify --candidate path/to/list.txt
cargo run -- bench
cargo run -- bench --candidate path/to/list.txt
cargo run -- resources
```

Set `RUSTSHIELD_TIMING=1` to print per-stage timings to stderr. Set
`RUSTSHIELD_DEBUG_REWRITE=1` to print rewrite candidate diagnostics.

## Workspace

Stage crates are intentionally short:

- `crates/model` — config, canonical IR, resource snapshot catalog, shared hashing and report types
- `crates/fetch` — pinned HTTP/local loading, include expansion, cache blobs, `lists.lock`
- `crates/parse` — directive evaluation and engine-backed parsing
- `crates/analyze` — metrics and classification
- `crates/admit` — golden-rule admission and D11 resource trust checks
- `crates/dedup` — exact and semantic deduplication with source-priority retention
- `crates/rewrite` — conservative type/domain/cosmetic union rewrites with reparse and engine checks
- `crates/emit` — deterministic `compiler-friendly-v1` output ordering
- `crates/verify` — differential verification and benchmarks
- `crates/cli` — the `rustshield` binary and staged publishing
