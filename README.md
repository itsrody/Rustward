# RustyShield

Offline generator for `RustShield.txt`: a deduplicated, classified, rewritten, and verified unified
filter list optimized for Brave's [`adblock-rust`](https://github.com/brave/adblock-rust) engine.

**Status:** architecture/design phase. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
full design, including the engine behaviors it relies on, the dialect-aware rewrite catalog for
ABP / AdGuard / uBO syntax, the whole-list fast-native/official/engine-trusted golden rule,
rewrite-to-eligible-or-exclude policy, compiler-friendly output ordering, safety/verification gates,
workspace layout, and implementation milestones.

No tool code has been implemented yet.
