# Zcash Cold Signer Plan

## Overview

Add Zcash cold signing support to Zigner, enabling air-gapped transaction signing for Zcash's transparent and shielded pools.

## Zcash Transaction Types

| Pool | Address Prefix | Signature Scheme | Complexity |
|------|----------------|------------------|------------|
| Transparent (t-addr) | `t1...` (mainnet) | secp256k1 ECDSA | Simple (like Bitcoin) |
| Sprout (z-addr legacy) | `zc...` | Ed25519 | Deprecated, skip |
| Sapling (z-addr) | `zs...` | RedJubjub | Medium |
| Orchard (UA) | unified address | RedPallas | Medium |

**Recommendation**: Start with **Transparent + Sapling**, add Orchard later.

## Architecture

```
┌─────────────────────────┐              ┌─────────────────────────┐
│   Zcash Wallet App      │              │    Zigner (Phone)       │
│   (Watch-Only)          │              │    (Cold Signer)        │
├─────────────────────────┤              ├─────────────────────────┤
│ Stores:                 │              │ Stores:                 │
│ • Full Viewing Key      │    QR #1     │ • Seed Phrase           │
│ • Unified FVK (UFVK)    │ ◄─────────── │ • Spending Keys         │
│ • Note witnesses        │   (setup)    │ • UFVKs                 │
│                         │              │                         │
│ Can:                    │    QR #2     │ Can:                    │
│ • View all balances     │ ───────────► │ • Sign transparent      │
│ • Build transactions    │ (unsigned tx)│ • Sign Sapling spends   │
│ • Broadcast signed txs  │              │ • Sign Orchard actions  │
│                         │    QR #3     │                         │
│ Cannot:                 │ ◄─────────── │ Cannot:                 │
│ • Sign anything         │ (signatures) │ • See network           │
└─────────────────────────┘              └─────────────────────────┘
```

## Key Derivation (ZIP-32)

### BIP-44 Path for Transparent

```
m/44'/133'/account'/change/index

133 = Zcash coin type
```

### ZIP-32 for Sapling

```
m_sapling / purpose' / coin_type' / account'

Where:
- purpose = 32 (ZIP-32)
- coin_type = 133 (Zcash)

Derivation:
seed phrase
  → BIP-39 seed (64 bytes)
    → ZIP-32 master key
      → derive(32'/133'/0')
        → Sapling extended spending key (ask, nsk, ovk)
          → Full viewing key (ak, nk, ovk)
            → Incoming viewing key (ivk)
              → Diversified addresses (d, pk_d)
```

### ZIP-32 for Orchard

```
m_orchard / purpose' / coin_type' / account'

Similar to Sapling but uses Pallas curve.
```

## Phase 1: Transparent Addresses (Simplest)

### 1.1 Key Derivation

```rust
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath};
use ripemd::Ripemd160;
use sha2::Sha256;

const ZCASH_COIN_TYPE: u32 = 133;

fn derive_transparent_key(seed: &[u8], account: u32, change: u32, index: u32) -> SecretKey {
    let path = format!("m/44'/{}'/{}'/{}/{}", ZCASH_COIN_TYPE, account, change, index);
    let xprv = ExtendedPrivKey::new_master(Network::Bitcoin, seed).unwrap();
    let derived = xprv.derive_priv(&Secp256k1::new(), &path.parse().unwrap()).unwrap();
    derived.private_key
}

fn pubkey_to_t_address(pubkey: &PublicKey) -> String {
    // P2PKH: RIPEMD160(SHA256(pubkey))
    let sha = Sha256::digest(&pubkey.serialize());
    let hash = Ripemd160::digest(&sha);

    // Mainnet t1 prefix: [0x1C, 0xB8]
    // Testnet tm prefix: [0x1D, 0x25]
    let mut payload = vec![0x1C, 0xB8];
    payload.extend_from_slice(&hash);

    bs58::encode(payload).with_check().into_string()
}
```

### 1.2 Transaction Signing (Transparent)

```rust
use secp256k1::{Message, Secp256k1};

fn sign_transparent_input(
    sighash: &[u8; 32],  // SIGHASH_ALL
    secret_key: &SecretKey,
) -> Vec<u8> {
    let secp = Secp256k1::new();
    let message = Message::from_slice(sighash).unwrap();
    let signature = secp.sign_ecdsa(&message, secret_key);

    // DER encode + SIGHASH_ALL byte
    let mut sig = signature.serialize_der().to_vec();
    sig.push(0x01);  // SIGHASH_ALL
    sig
}
```

### 1.3 QR Format for Transparent

**Unsigned Transaction (Wallet → Zigner):**

```
[0x53][0x04][0x01][version][inputs][outputs]

0x53 = substrate compat
0x04 = zcash chain
0x01 = transparent tx type

inputs:
  count: varint
  for each:
    prev_txid: 32 bytes
    prev_index: u32 LE
    script_pubkey: length + bytes (for sighash)
    value: u64 LE (for sighash)
    derivation_path: account/change/index

outputs:
  count: varint
  for each:
    value: u64 LE
    script_pubkey: length + bytes
```

**Signed Transaction (Zigner → Wallet):**

```
[0x53][0x04][0x01][full_signed_tx_bytes]

OR just signatures:

[0x53][0x04][0x01]
[sig_count: varint]
[signatures: DER + sighash_type each]
```

## Phase 2: Sapling Shielded

### 2.1 Key Derivation (ZIP-32)

```rust
use zcash_primitives::zip32::{ExtendedSpendingKey, ExtendedFullViewingKey};
use zcash_primitives::sapling::keys::FullViewingKey;

fn derive_sapling_keys(seed: &[u8], account: u32) -> (ExtendedSpendingKey, ExtendedFullViewingKey) {
    // ZIP-32 derivation: m_sapling / 32' / 133' / account'
    let master = ExtendedSpendingKey::master(seed);
    let esk = master
        .derive_child(ChildIndex::Hardened(32))
        .derive_child(ChildIndex::Hardened(133))
        .derive_child(ChildIndex::Hardened(account));

    let efvk = ExtendedFullViewingKey::from(&esk);

    (esk, efvk)
}
```

### 2.2 Sapling Spend Signing

```rust
use zcash_primitives::sapling::{
    redjubjub::{PrivateKey, PublicKey, Signature},
    spend_sig,
};

fn sign_sapling_spend(
    ask: &PrivateKey,        // Spend authorizing key
    ar: &jubjub::Fr,         // Randomizer (from spend description)
    sighash: &[u8; 32],      // Transaction sighash
    rng: &mut impl RngCore,
) -> Signature {
    // Randomize the key
    let rsk = ask.randomize(ar);

    // Sign with RedJubjub
    spend_sig(rsk, sighash, rng)
}
```

### 2.3 Sapling Transaction Data

For signing, Zigner needs:
- `ask` (spend authorizing key) - derived from seed
- `ar` (randomizer) - from spend description in unsigned tx
- `sighash` - computed from transaction

**QR Format:**

```
[0x53][0x04][0x02][sapling_bundle]

sapling_bundle:
  spend_count: u8
  for each spend:
    cv: 32 bytes (value commitment)
    anchor: 32 bytes
    nullifier: 32 bytes
    rk: 32 bytes (randomized verification key)
    zkproof: 192 bytes (Groth16)
    ar: 32 bytes (randomizer - NEEDED for signing)
    derivation: account index

  output_count: u8
  ... (outputs don't need signing)

  value_balance: i64 LE
  binding_sig: 64 bytes (computed after spend sigs)
```

### 2.4 Signature Response

```
[0x53][0x04][0x02]
[spend_sig_count: u8]
[spend_signatures: 64 bytes (RedJubjub) each]
[binding_signature: 64 bytes]
```

## Phase 3: Orchard (Future)

Similar to Sapling but uses:
- Pallas curve (instead of Jubjub)
- RedPallas signatures (instead of RedJubjub)
- Different circuit (Halo2 instead of Groth16)

```rust
use orchard::keys::{SpendingKey, FullViewingKey, SpendAuthorizingKey};
use pasta_curves::pallas;

fn derive_orchard_keys(seed: &[u8], account: u32) -> SpendingKey {
    SpendingKey::from_zip32_seed(seed, ZCASH_COIN_TYPE, account)
}

fn sign_orchard_action(
    ask: &SpendAuthorizingKey,
    alpha: &pallas::Scalar,  // Randomizer
    sighash: &[u8; 32],
    rng: &mut impl RngCore,
) -> redpallas::Signature<SpendAuth> {
    let rsk = ask.randomize(&alpha);
    rsk.sign(rng, sighash)
}
```

## Dependencies

### Rust Crates

```toml
[dependencies]
# Transparent (Bitcoin-like)
secp256k1 = { version = "0.28", features = ["std"] }
bitcoin = { version = "0.31", features = ["std"] }
bs58 = { version = "0.5", features = ["check"] }

# Sapling
zcash_primitives = "0.14"
jubjub = "0.10"

# Orchard (optional, for future)
orchard = "0.7"
pasta_curves = "0.5"

# Common
bip39 = "2.0"
sha2 = "0.10"
ripemd = "0.1"
rand_core = "0.6"
```

## Implementation Phases

### Phase 1: Transparent Only (1-2 weeks)

**Zigner:**
- [ ] Zcash transparent key derivation (BIP-44)
- [ ] t-address generation (P2PKH)
- [ ] secp256k1 signing
- [ ] QR parsing for unsigned tx
- [ ] QR generation for signed tx
- [ ] UI: display transparent tx details

**Wallet (companion app):**
- [ ] Import transparent viewing key
- [ ] Build unsigned transparent tx
- [ ] Encode to QR
- [ ] Parse signed QR
- [ ] Broadcast

### Phase 2: Sapling Shielded (2-3 weeks)

**Zigner:**
- [ ] ZIP-32 key derivation
- [ ] Sapling FVK export
- [ ] RedJubjub signing
- [ ] Binding signature computation
- [ ] QR parsing for Sapling bundle
- [ ] UI: display shielded tx details

**Wallet:**
- [ ] Import Sapling EFVK
- [ ] Build Sapling transaction (with proofs)
- [ ] Extract randomizers for QR
- [ ] Parse signature QR
- [ ] Assemble final transaction

### Phase 3: Orchard + Unified (3-4 weeks)

**Zigner:**
- [ ] Orchard key derivation
- [ ] RedPallas signing
- [ ] Unified Full Viewing Key export
- [ ] UI for Orchard actions

**Wallet:**
- [ ] UFVK support
- [ ] Orchard transaction building
- [ ] Unified address handling

## QR Code Type Summary

| Code | Type | Direction | Description |
|------|------|-----------|-------------|
| `53 04 00` | Setup | Z → W | Export viewing key(s) |
| `53 04 01` | Transparent | W → Z | Unsigned transparent tx |
| `53 04 01` | Transparent | Z → W | Signed transparent tx |
| `53 04 02` | Sapling | W → Z | Unsigned Sapling bundle |
| `53 04 02` | Sapling | Z → W | Sapling signatures |
| `53 04 03` | Orchard | W → Z | Unsigned Orchard bundle |
| `53 04 03` | Orchard | Z → W | Orchard signatures |
| `53 04 10` | Unified | W → Z | Full transaction (all pools) |
| `53 04 10` | Unified | Z → W | All signatures |

## Comparison: Penumbra vs Zcash

| Aspect | Penumbra | Zcash Sapling |
|--------|----------|---------------|
| Curve | decaf377 | Jubjub |
| Signature | decaf377-rdsa | RedJubjub |
| Key derivation | Custom (Penumbra_ExpndSd) | ZIP-32 |
| Randomizers | In TransactionPlan | In SpendDescription |
| Binding sig | Not needed (different design) | Required |
| Libraries | Limited | Mature (zcash_primitives) |
| Complexity | Medium | Medium |

## Wallet Companion Options

For Zcash, we need a companion wallet. Options:

1. **Zecwallet Lite** - Could add cold signer support
2. **YWallet** - Modern, active development
3. **Zcash CLI** - Reference implementation
4. **Custom Web Wallet** - Build minimal watch-only wallet

**Recommendation**: Partner with YWallet or build minimal web companion.

## Security Notes

### Transparent
- Similar to Bitcoin - simpler threat model
- Private keys derived from seed, stored only on Zigner
- Watch wallet has xpub, can generate addresses

### Sapling/Orchard
- Full viewing key reveals all transaction details
- Spending key NEVER leaves Zigner
- Proofs generated on wallet (expensive), signed on Zigner
- Randomizers must be verified (derived from spend description)

## Resources

- [ZIP-32: Shielded Hierarchical Deterministic Wallets](https://zips.z.cash/zip-0032)
- [ZIP-316: Unified Addresses](https://zips.z.cash/zip-0316)
- [zcash_primitives crate](https://docs.rs/zcash_primitives)
- [orchard crate](https://docs.rs/orchard)
- [Zcash Protocol Spec](https://zips.z.cash/protocol/protocol.pdf)
