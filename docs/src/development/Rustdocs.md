# Rust docs

Generate the Rust API docs locally:

```
cd rust && cargo doc --no-deps --workspace --open
```

Key crates worth starting with:

- [`signer`](../rustdocs/signer/index.html) — UniFFI surface; the
  entry point for everything the native apps can call.
- [`navigator`](../rustdocs/navigator/index.html) — screen state
  machine.
- [`transaction_signing`](../rustdocs/transaction_signing/index.html)
  — Penumbra, Zcash, and Substrate signing logic.
- [`transaction_parsing`](../rustdocs/transaction_parsing/index.html)
  — UR / CBOR / PCZT parsers and inspection helpers.
- [`db_handling`](../rustdocs/db_handling/index.html) — encrypted sled
  storage layout.
- [`frost-spend`](https://github.com/rotkonetworks/zcli/tree/master/crates/frost-spend)
  — RedPallas FROST primitives (external repo, shared with `zcli`).
