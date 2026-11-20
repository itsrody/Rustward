# Output-quality backlog

Queued from the quality review. Items 1–2 are implemented; the rest are recorded here so they are
not lost.

1. **Literal-anchor regex recovery** — done. `^`-separator patterns (including literal query
   strings) are admitted as the `literal-boundary` class under `admit.literal_boundary_regex`.
   REGEX exclusions fell from 55,994 to 7,834 and the output grew by ~48k rules.
2. **Verification coverage + coverage reporting** — done. 420,588 cases (up from 5,000), per-receipt
   probes, strided cosmetic hosts, and coverage fields in `verify.json` / `build.md`.
3. **Byte-deterministic output metadata** — done. The `! Last modified` header is derived from the
   newest parseable pinned `last_modified` value in `lists.lock` (Unix epoch when absent), recorded
   in `manifest.json` / `build.json`, and covered by a two-build byte-determinism test.
4. **Audit artifacts** — done. `dropped.tsv` now reports the losing rule for every exact/semantic
   dedup with the kept origin in `detail`, while `excluded.tsv` remains policy failures only.
   `build.json` caps receipt count and payload size but records the full count, canonical digest, and
   per-field truncation metadata; complete receipts remain in `rewrites.tsv`.
5. **Scriptlet coverage** — done. The pinned official uBO snapshot already contains the legacy
   aliases used by current lists; the blocker was case-folding in `parse_scriptlet_invocation`,
   which turned case-sensitive names such as `no-setTimeout-if` into unresolvable lowercase forms.
   Names now preserve their official spelling, with parse, catalog, and fixture regression tests.
6. **Hosts parsing hygiene** — done. Every `#` line in a hosts-format source is now a comment, and
   reserved local/broadcast mappings are classified as `Skipped` with `hosts_skips` metrics instead of
   `PARSE_ERROR`. Inline comments on real host mappings still canonicalize to `||host^`.
7. **Config/docs ↔ code alignment** — partially done. D3/D4 network canonicalization is implemented
   as the `network_canonicalization` rewrite pass; D6 literal `contains` normalization is implemented
   as the preparse `d6_literal_contains` pass. `host_semantics`, `ubo_host_semantics`, `regex_fusion`,
   `:-abp-has` normalization, and D8 remain open.
8. **Semantic-gap acceptance policy** — done. `admit.accepted_semantic_gaps` accepts `$all` and
   partially dropped method/scheme values; entity-domain, bare-hostname, and match-case gaps are
   excluded as `SEMANTIC_GAP_POLICY`. Reports split accepted, unresolved, and excluded gaps.
9. **Compression targets** — add CI gates for the documented 30–60% rule-count and ≥20% no-opt
   flatbuffer reductions, and add more union/canonicalization passes after item 1 lands.
10. **Batch slow/complex exclusion** — done. ADMIT supports config-driven family batches, defaulting
    to `nested_procedural`, which removes slow operators adblock folds into native CSS. Literal-arg
    checking now also rejects regex literals with flags (`/ad/i`). Additional families are classified
    but not excluded by default; VERIFY mirrors the gate.
11. **Network hygiene batch** — done. D3/D4 canonicalization, explicit semantic-gap acceptance, and
    removal of ineffective entity-domain/bare-hostname/match-case rules. `$all` stays accepted.
12. **Safe coverage recovery batch** — done. D6 normalizes literal `:contains(...)` /
    `:-abp-contains(...)` to `:has-text(...)` under `admit.literal_contains_rewrite`, with receipts,
    an ABP-extended VERIFY baseline, and procedural-action snapshots in cosmetic equivalence.
    Literal-boundary classification now covers engine-escaped punctuation and path punctuation,
    with redundant escapes removed by `network_canonicalization`; real regex escapes stay excluded.
13. **Index-friendly exception union batch** — done. New `exception_type_union` and
    `exception_domain_union` passes merge per-site `@@` unbreak rules that were previously skipped
    by the union builder. Positive `$domain=`/`$from=` lists only; negated lists, badfilter targets,
    and any structurally or differentially unsafe group remain separate. This reduces exception
    filter objects and token-map entries without weakening any exception.
14. **Resource coverage closure** — done. Redirect priorities such as `noopjs:10` are stripped before
    catalog lookup, matching adblock-rust's own `:N` parsing. Host-only realization probes now strip
    trailing `^`, and `excluded.tsv` records a detail column that distinguishes scriptlets from
    redirect resources. Audited plain missing names against the pinned uBO commit: `gemius`,
    `metrika-yandex-tag`, `metrika-yandex-watch`, and `ati-smarttag` are not in the official assets,
    and `none` is uBO's special "no redirect" keyword; all remain intentional exclusions.
15. **Path-aware redirect realization** — done. Redirect probes now use the parsed literal body for
    exact-path, `^`-boundary, and `*` wildcard patterns instead of the fixed `/rs-probe.js` path.
    Complex regex bodies keep the generic fallback, and the engine still decides whether a probe
    produces a redirect, so no trust or verification gate is relaxed.
16. **Conservative R9 pattern subsumption** — done. `pattern_subsumption` removes a redundant plain
    substring rule only when it is hostname-free, unanchored, non-regex, at least four characters,
    and identical in every parsed field except the body. The shorter body may be either a prefix
    ending at a URL separator or a suffix beginning at one; suffix matches also accept a separator
    immediately before the match. The separator set is `.`, `-`, `_`, `/`, `?`, `&`, `=`, `#`, `:`,
    `;`, `+`, `%`, and `@`. Every removal still passes the engine differential gate.
