# Key derivation

A single BIP-39 seed phrase can produce isolated keys across Zcash,
Penumbra, and Substrate. Each chain uses a different derivation
standard, so the keys are cryptographically independent — compromising
one chain's keys does not affect the others.

## Zcash

Zcash uses **ZIP-32** for shielded keys and **BIP-44** for transparent
keys.

| Pool        | Standard | Path                                    |
|-------------|----------|-----------------------------------------|
| Orchard     | ZIP-32   | `m/32'/133'/account'`                   |
| Transparent | BIP-44   | `m/44'/133'/account'/change/index`      |

Zigner exposes the **Unified Full Viewing Key** (UFVK) per ZIP-316,
which encodes the Orchard FVK (and a transparent extended key, if
present) into a single bech32m string starting with `uview1…`. Importing
the UFVK into Zafu or Zashi gives the hot wallet enough information to
scan for received notes and build PCZTs, without ever exposing the
spending key.

For details on PCZT signing flow, see the [Zcash FAQ section](../about/FAQ.md#zcash).

### FROST multisig keys

A FROST Orchard group has a single group spending key that is *never*
reconstructed on any one device. Each Zigner stores a key package from
DKG, and the group's UFVK is derived from the public key package using
the same Orchard ZIP-32 conventions. To zafu/zashi, a FROST group looks
like an ordinary watch-only Orchard account.

## Penumbra

Penumbra uses **BIP-44 coin type 6532**. The Full Viewing Key is bech32m
encoded; export it from Zigner and import into Prax for transaction
construction. Per-spend randomization happens at signing time, derived
from a per-action ChaCha20 stream so signatures are unlinkable.

## Substrate

Substrate uses its own **subkey-style** derivation, distinct from
BIP-32:

- **Soft** derivation: `/path` (single slash). Public keys can be
  derived without the private key.
- **Hard** derivation: `//path` (double slash). Public keys cannot be
  derived without the private key.
- **Password**: a `///password` suffix in the spec; in Zigner, use the
  separate password field — do not append `///` to the path.

Each derived account is bound to a specific Substrate network until you
explicitly add it to another. The root key is available across all
networks by default — don't use it for actual signing unless you know
why.

The encoded path is limited to 32 bytes.

### Sample paths

```
//polkadot                  hard-derived account on Polkadot
//kusama//0                 first hard-derived account on Kusama
//cold//treasury            named hard derivation, useful for multisigs
//signer/0                  hard root with soft sub-account
```

## Notes

- The same seed across chains gives cryptographically isolated keys
  per chain. There is no path-overlap risk between Zcash ZIP-32 and
  Penumbra/Substrate BIP-44 derivations.
- Zigner supports the BIP-39 optional passphrase. Treat it as a second
  factor — losing the passphrase means losing every key derived from
  the (phrase + passphrase) pair.
- For Orchard FROST keys, derivation is replaced by DKG; there is no
  path that produces a FROST group key.

## References

- [ZIP-32 — Shielded Hierarchical Deterministic Wallets](https://zips.z.cash/zip-0032)
- [ZIP-316 — Unified Addresses and Viewing Keys](https://zips.z.cash/zip-0316)
- [BIP-44 — Multi-Account Hierarchy for Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [Substrate subkey](https://docs.substrate.io/reference/command-line-tools/subkey/)
