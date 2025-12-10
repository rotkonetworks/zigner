# penumbra integration progress

## completed ✓

### 1. research & documentation
- [x] analyzed penumbra protocol specifications
- [x] studied prax wallet airgap signer implementation
- [x] examined ledger penumbra implementation (@zondax/ledger-penumbra@1.0.0)
- [x] sourced full ledger-penumbra source code (~/rotko/ledger-penumbra)
- [x] analyzed pcli source code (~/rotko/penumbra)
- [x] documented qr code protocol format
- [x] created comprehensive integration spec (PENUMBRA_INTEGRATION.md)
- [x] documented complete signing algorithm from both ledger and pcli (PENUMBRA_SIGNING_DETAILS.md)

### 2. rust type system updates
- [x] added `Penumbra` variant to `Encryption` enum (rust/definitions/src/crypto.rs)
- [x] updated `Encryption::show()` to handle penumbra
- [x] updated `Encryption::identicon_style()` to handle penumbra
- [x] updated `Encryption::try_from()` to parse "penumbra" string
- [x] added `Penumbra(H256)` variant to `NetworkSpecsKeyContent` enum (rust/definitions/src/keyring.rs)
- [x] updated `NetworkSpecsKey::from_parts()` to handle penumbra
- [x] updated `NetworkSpecsKey::genesis_hash_encryption()` to handle penumbra
- [x] added penumbra placeholder to `get_multisigner()` (rust/definitions/src/helpers.rs)
- [x] added penumbra placeholder to `base58_or_eth_pubkey_to_multisigner()` (rust/definitions/src/helpers.rs)
- [x] tested compilation - all changes compile successfully ✓

### 3. penumbra signing module (rust/transaction_signing/src/penumbra.rs)
- [x] added penumbra feature flag to Cargo.toml with dependencies:
  - decaf377 v0.10.1
  - decaf377-rdsa v0.11
  - blake2b_simd v1.0.2
  - rand_chacha v0.3.1
  - bip32 v0.5
  - hmac v0.12, sha2 v0.10, pbkdf2 v0.12
- [x] implemented `SpendKeyBytes` type with zeroize on drop
- [x] implemented `from_seed_phrase()` bip44 key derivation (m/44'/6532'/account')
- [x] implemented `expand_ff()` prf function (blake2b with personalization)
- [x] implemented `derive_spend_auth_key()` to get SigningKey<SpendAuth>
- [x] implemented `sign_spend()` with randomized keys (matches ledger-penumbra)
- [x] implemented `PenumbraAuthorizationData` struct with encode() for QR output
- [x] implemented `sign_transaction()` to sign all spend/vote actions
- [x] implemented `EffectHash` type with:
  - `from_proto_effecting_data()` for action hashes
  - `compute_transaction_effect_hash()` for full tx hash
- [x] added personalization constants for all action types
- [x] added `PenumbraNotSubstrate` error to db_handling
- [x] all 6 penumbra tests pass ✓

### 4. full viewing key (FVK) export
- [x] added dependencies: poseidon377 v1.2.0, bech32 v0.11.0
- [x] implemented `NullifierKey` derivation from spend key bytes
- [x] implemented `expand_fq()` for Fq field element expansion
- [x] implemented `FullViewingKey` struct with:
  - `derive_from()` - derives FVK from SpendKeyBytes
  - `to_bytes()` / `from_bytes()` - 64-byte serialization (ak || nk)
  - `wallet_id()` - computes WalletId using poseidon377 hash
  - `to_bech32m()` / `from_bech32m()` - "penumbrafullviewingkey1..." encoding
- [x] implemented `WalletId` struct with:
  - `to_bech32m()` - "penumbrawalletid1..." encoding
  - `to_bytes()` - 32-byte raw format
- [x] implemented `FvkExportData` for QR code export:
  - `from_spend_key()` - creates export data from spend key
  - `encode_qr()` / `decode_qr()` - binary format with prelude `53 03 01`
  - `encode_qr_hex()` / `decode_qr_hex()` - hex string format
- [x] QR format: `[53][03][01][account:4][label_len:1][label][fvk:64][wallet_id:32]`
- [x] all 15 penumbra tests pass ✓

## key findings

### penumbra specs
```
chain:           penumbra-1 (mainnet)
type:            cosmos sdk chain (not substrate)
bip44 path:      m/44'/6532'/0'
address format:  bech32m with prefix "penumbra"
address length:  80 bytes
signatures:      decaf377-rdsa (64 bytes each)
effect hash:     blake2b-512 (64 bytes)
```

### qr protocol format

**outgoing (hot → cold):**
```
[0x53][0x03][0x10][metadata][transaction_plan]

0x53 = substrate format compat
0x03 = penumbra identifier
0x10 = transaction type
metadata = asset names (count + length-prefixed strings)
transaction_plan = protobuf bytes
```

**return (cold → hot):**
```
[0x53][0x03][0x10][effect_hash][signatures]

effect_hash = 64 bytes blake2b-512
signatures = spend_auth + delegator_vote
  - spend_auth_count (2 bytes le)
  - spend_auth_sigs (64 bytes each)
  - vote_count (2 bytes le)
  - vote_sigs (64 bytes each)
```

### 4. transaction parsing (rust/transaction_parsing/src/penumbra.rs) ✓
- [x] add handler for transaction type `0x10` in `rust/transaction_parsing/src/lib.rs`
  - [x] modify `handle_scanner_input()` match statement
  - [x] add case: `"10" => process_penumbra_transaction(database, data_hex)` (gated by penumbra feature)
- [x] create `rust/transaction_parsing/src/penumbra.rs`
  - [x] parse prelude and validate format
  - [x] extract metadata (asset names)
  - [x] create `PenumbraTransactionPlan` struct
  - [x] implement `parse_penumbra_transaction()` handler
  - [x] create transaction display cards (PenumbraSummaryCard)
  - [x] re-export signing types from transaction_signing::penumbra

### 5. uniffi/udl updates ✓
- [x] added `Penumbra` variant to `Encryption` enum in signer.udl
- [x] added penumbra card types to `Card` enum:
  - PenumbraSummaryCard, PenumbraSpendCard, PenumbraOutputCard
  - PenumbraSwapCard, PenumbraDelegateCard, PenumbraVoteCard
- [x] added corresponding dictionary definitions for penumbra types

### 6. generate_message compatibility ✓
- [x] added Penumbra case to `make_message.rs` (returns NotSupported)
- [x] added Penumbra case to `parser.rs` into_sufficient (returns NotSupported)

## remaining work

### 7. protobuf definitions (optional - can parse raw bytes instead)
- [ ] vendor penumbra protobufs or generate from buf.build
  - `penumbra.core.transaction.v1.TransactionPlan`
  - `penumbra.core.transaction.v1.Action`
  - `penumbra.core.transaction.v1.AuthorizationData`
  - `penumbra.crypto.decaf377_rdsa.v1.SpendAuthSignature`

- [ ] add dependencies to rust/Cargo.toml:
  ```toml
  prost = "0.12"  # protobuf decoding
  blake2 = "0.10"  # blake2b-512
  ```

### 6. response generation (✓ mostly done)
- [x] implement authorization qr generation in PenumbraAuthorizationData::encode()
  - [x] encode effect hash (64 bytes)
  - [x] encode spend auth signatures with count
  - [x] encode delegator vote signatures with count
  - [x] encode lqt vote signatures with count
- [ ] add QR prelude formatting: [0x53][0x03][0x10]

### 7. ui integration
- [ ] android (kotlin)
  - transaction display screen
  - show transaction details
  - display effect hash

- [ ] ios (swift)
  - transaction display screen
  - show transaction details
  - display effect hash

### 8. testing
- [ ] unit tests for qr parsing
- [ ] unit tests for effect hash computation
- [ ] unit tests for signature generation
- [ ] integration test with prax wallet
- [ ] end-to-end test: sign real transaction

## notes

### implementation approach
we're NOT adding penumbra as a default network like polkadot/kusama because penumbra is not a substrate chain. instead, we're extending parity signer to support penumbra's signing protocol via qr codes.

the key is recognizing the `0x53 0x03 0x10` prelude and routing to penumbra-specific transaction handling.

### placeholder implementation
currently using ed25519 multisigner as a placeholder for penumbra keys to avoid compilation errors in functions that expect substrate's multisigner type. proper penumbra key handling (decaf377) will be implemented in the crypto phase.

### dependencies needed (from ledger-penumbra)
```toml
# rust/Cargo.toml
[dependencies]
# crypto primitives (use u64_backend for phones, u32 for ledger)
decaf377 = { version = "0.10.1", features = ["u64_backend"] }
decaf377-rdsa = { version = "0.11", features = ["u64_backend"] }
poseidon377 = "1.1.0"

# hashing
blake2b_simd = "1.0.2"

# address encoding
f4jumble = "0.1.0"
bech32 = "0.11.0"

# encryption
chacha20poly1305 = "0.10.1"

# rng
rand_chacha = "0.3.1"

# parsing
prost = "0.12"  # protobuf (or nom for no_std)

# misc
zeroize = { version = "1.7.0", features = ["derive"] }
```

## next steps

1. ~~implement signing with decaf377-rdsa~~ ✓ DONE
2. ~~add transaction type handler `0x10` to routing logic~~ ✓ DONE
3. ~~create penumbra transaction parser module~~ ✓ DONE
4. ~~wire up signing module to transaction parser~~ ✓ DONE (re-exports in place)
5. implement full protobuf parsing for TransactionPlan (extract randomizers)
6. add effect hash computation from parsed plan
7. implement android/ios UI for penumbra cards
8. test with prax wallet

## reference links

### local source code
- prax wallet: `../prax/packages/wallet/src/airgap-signer.ts`
- ledger-penumbra: `~/rotko/ledger-penumbra/app/rust/src/`
  - signing: `ffi/sign.rs`
  - key derivation: `keys/signing_key.rs`, `keys/spend_key.rs`
  - effect hash: `parser/effect_hash.rs`
  - constants: `constants.rs`
- pcli source: `~/rotko/penumbra/crates/core/`
  - transaction auth: `transaction/src/plan/auth.rs`
  - spend key: `keys/src/keys/spend.rs`
  - bip44: `keys/src/keys/bip44.rs`

### external references
- penumbra protocol: https://protocol.penumbra.zone/
- penumbra mainnet: chain-id `penumbra-1`
- decaf377 curve: https://docs.rs/decaf377
- rdsa signatures: https://docs.rs/decaf377-rdsa
