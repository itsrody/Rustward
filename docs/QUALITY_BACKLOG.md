# Output-quality backlog

Queued from the quality review. Items 1–2 are implemented; the rest are recorded here so they are
not lost.

1. **Literal-anchor regex recovery** — done. `^`-separator patterns (including literal query
   strings) are admitted as the `literal-boundary` class under `admit.literal_boundary_regex`.
   REGEX exclusions fell from 55,994 to 7,834 and the output grew by ~48k rules.
2. **Verification coverage + coverage reporting** — done. 420,588 cases (up from 5,000), per-receipt
   probes, strided cosmetic hosts, and coverage fields in `verify.json` / `build.md`.
3. **Byte-deterministic output metadata** — replace the wall-clock `! Last modified` header with a
   value derived from pinned inputs; add a two-build determinism test.
4. **Audit artifacts** — make `dropped.tsv` list dedup/subsumption removals (it currently duplicates
   `excluded.tsv`) and cap oversized receipt payloads in `build.json`.
5. **Scriptlet coverage** — explicitly trust official uBO sources where justified and add a pinned
   official legacy uBO scriptlet snapshot for names still used by current lists.
6. **Hosts parsing hygiene** — treat all `#` lines in hosts-format sources as comments and classify
   localhost/broadcast entries as expected skips rather than parse errors.
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
