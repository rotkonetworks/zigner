# penumbra integration for parity signer

## overview

add support for signing penumbra transactions via qr codes in parity signer (polkadot vault). penumbra uses decaf377-rdsa signatures, not substrate's sr25519/ed25519.

## penumbra specs

- **chain**: penumbra-1 (mainnet)
- **type**: cosmos sdk chain (not substrate)
- **bip44 path**: m/44'/6532'/0'
- **address format**: bech32m with prefix `penumbra`
- **address length**: 80 bytes
- **signature scheme**: decaf377-rdsa (64 bytes per signature)
- **effect hash**: blake2b-512 (64 bytes)

## qr code protocol

### outgoing qr (hot wallet → cold wallet)

format for transaction plan to be signed:

```
byte 0-2:   prelude (0x53 0x03 0x10)
            0x53 = substrate qr format compatibility
            0x03 = penumbra chain identifier
            0x10 = transaction type

byte 3:     metadata count (uint8)

byte 4+:    length-prefixed asset names
            for each asset:
              - length (uint8)
              - utf-8 string bytes

byte n+:    transactionplan protobuf bytes
```

### return qr (cold wallet → hot wallet)

format for authorization data (signatures):

```
byte 0-2:   prelude (0x53 0x03 0x10)

byte 3-66:  effect hash (64 bytes)
            blake2b-512 hash of the transaction plan

byte 67-68: spend auth signature count (uint16 le)

byte 69+:   spend auth signatures (64 bytes each)

byte m-m+1: delegator vote signature count (uint16 le)

byte m+2+:  vote signatures (64 bytes each)
```

## implementation tasks

### 1. transaction parsing

add new variant to `ContentLoadTypes` enum in `rust/transaction_parsing`:

```rust
pub enum ContentLoadTypes {
    // existing variants...
    LoadPenumbraTransaction,
}
```

parse prelude `0x53 0x03 0x10` to identify penumbra transactions.

### 2. penumbra transaction type

create `rust/transaction_parsing/src/penumbra.rs`:

- parse metadata (asset names)
- decode transactionplan protobuf
- extract spend actions and vote actions
- compute effect hash (blake2b-512)
- display transaction details

### 3. signature generation

penumbra uses decaf377-rdsa signatures:

- **spend auth signatures**: sign with spend authorization key
- **delegator vote signatures**: sign with voting key

need to:
- derive penumbra keys from bip44 path
- implement decaf377 scalar multiplication
- implement rdsa signing

### 4. authorization response

generate return qr with:
- effect hash
- array of spend auth signatures
- array of delegator vote signatures

### 5. ui integration

#### android (kotlin)
- add transaction display screen
- show asset names, amounts, actions
- display effect hash for verification

#### ios (swift)
- add transaction display screen
- show asset names, amounts, actions
- display effect hash for verification

## dependencies

### rust crates needed

```toml
# penumbra crypto
decaf377 = "0.9"  # decaf377 curve operations
decaf377-rdsa = "0.9"  # rdsa signatures

# protobuf
prost = "0.12"  # protobuf decoding

# hashing
blake2 = "0.10"  # blake2b-512

# bip32/bip44
tiny-bip39 = { version = "1.0", default-features = false }
hkdf = "0.12"  # key derivation
```

### protobuf definitions

need to vendor penumbra protobufs or generate from:
```
https://buf.build/penumbra-zone/penumbra
```

key messages:
- `penumbra.core.transaction.v1.TransactionPlan`
- `penumbra.core.transaction.v1.Action`
- `penumbra.core.transaction.v1.AuthorizationData`
- `penumbra.crypto.decaf377_rdsa.v1.SpendAuthSignature`

## key derivation

penumbra uses bip44 with hardened path `m/44'/6532'/0'`:

```
seed phrase
  → bip39 seed
    → bip32 derive m/44'/6532'/0'
      → spending seed (32 bytes)
        → spend authorization key (decaf377 scalar)
```

## testing

1. generate test transaction in prax
2. scan qr with parity signer
3. verify transaction details displayed correctly
4. sign transaction
5. scan return qr in prax
6. verify signature validates
7. broadcast transaction to penumbra-1

## reference implementations

- **ledger**: `@zondax/ledger-penumbra@1.0.0`
- **prax wallet**: `../prax/packages/wallet/src/airgap-signer.ts`
- **penumbra protocol**: https://protocol.penumbra.zone/

## notes

- penumbra is not a substrate chain, so we don't add it to network specs
- signatures are 64 bytes (decaf377-rdsa), not 64 bytes (ed25519/sr25519)
- addresses are 80 bytes (bech32m), not 32 bytes (ss58)
- we're extending parity signer's qr protocol, not substrate's
