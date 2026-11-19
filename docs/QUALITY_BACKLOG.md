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
7. **Config/docs ↔ code alignment** — implement or remove the inert `host_semantics`,
   `ubo_host_semantics`, and `regex_fusion` switches, and the documented-but-missing D3/D4/D6/D8
   canonicalization families.
8. **Semantic-gap acceptance policy** — add an explicit allowlist for accepted `SemanticGap` classes
   (notably `$all`) and report accepted vs unresolved gaps.
9. **Compression targets** — add CI gates for the documented 30–60% rule-count and ≥20% no-opt
   flatbuffer reductions, and add more union/canonicalization passes after item 1 lands.
