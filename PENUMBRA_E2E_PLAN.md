# Penumbra End-to-End Integration Plan

## Architecture Overview

```
┌─────────────────────────┐              ┌─────────────────────────┐
│     Prax Extension      │              │    Zigner (Phone)       │
│     (Watch-Only)        │              │    (Cold Signer)        │
├─────────────────────────┤              ├─────────────────────────┤
│ Stores:                 │              │ Stores:                 │
│ • Full Viewing Key      │    QR #1     │ • Seed Phrase (secure)  │
│ • Account index         │ ◄─────────── │ • Spend Key             │
│ • Sync state            │   (setup)    │ • Full Viewing Key      │
│                         │              │ • Account metadata      │
│ Can:                    │              │                         │
│ • View balances         │    QR #2     │ Can:                    │
│ • Build transaction     │ ───────────► │ • Display tx details    │
│   plans                 │  (tx plan)   │ • Verify addresses      │
│ • Broadcast signed txs  │              │ • Sign transactions     │
│                         │    QR #3     │                         │
│ Cannot:                 │ ◄─────────── │ Cannot:                 │
│ • Sign anything         │ (signatures) │ • Connect to network    │
└─────────────────────────┘              └─────────────────────────┘
```

## Phase 1: Zigner Setup Flow

### 1.1 Create Penumbra Account on Zigner

On the Zigner app (cold device):

1. User creates/imports seed phrase (BIP-39)
2. User selects "Add Penumbra Account"
3. Zigner derives keys from BIP-44 path `m/44'/6532'/account'`:
   ```
   seed phrase
     → pbkdf2(phrase, "mnemonic", 2048) → 64-byte seed
       → bip32_derive(seed, m/44'/6532'/0') → spend_key_bytes
         → expand_ff("Penumbra_ExpndSd", skb, [0]) → spend_auth_key (ask)
         → expand_ff("Penumbra_ExpndSd", skb, [1]) → nullifier_key (nk)
           → full_viewing_key = (ask.verification_key(), nk)
   ```
4. Zigner displays:
   - Full Viewing Key (for export)
   - Penumbra address (bech32m)
   - Account index

### 1.2 Export FVK to Prax

QR code format for FVK export:

```
[0x53][0x03][0x01][full_viewing_key_bytes]

0x53 = substrate compat marker
0x03 = penumbra chain
0x01 = FVK export type (new!)
FVK  = 64 bytes (ak: 32 bytes, nk: 32 bytes)
```

Alternative with metadata:

```
[0x53][0x03][0x01][account_index: u32][label_len: u8][label: utf8][fvk: 64 bytes]
```

### 1.3 Import to Prax Extension

Prax modifications needed:

```typescript
// New custody type
const CUSTODY_TYPES = [
  'encryptedSeedPhrase',
  'encryptedSpendKey',
  'airgapSigner',
  'zignerWatchOnly'     // NEW: only stores FVK, no spend capability
] as const;

// New wallet import function
async function importZignerWallet(fvkQrHex: string, label: string): Promise<Wallet> {
  // 1. Parse QR
  const { accountIndex, fvk } = parseZignerFvkQr(fvkQrHex);

  // 2. Derive wallet ID from FVK
  const walletId = computeWalletId(fvk);

  // 3. Create watch-only wallet (no encrypted spend key!)
  return new Wallet(label, walletId, fvk, {
    zignerWatchOnly: {
      accountIndex,
      // No encrypted keys - we can't sign!
    }
  });
}
```

## Phase 2: Transaction Signing Flow

### 2.1 User Initiates Transaction in Prax

1. User clicks "Send" in Prax
2. Prax builds `TransactionPlan` with:
   - Actions (spend, output, swap, etc.)
   - Transaction parameters (chain_id, expiry)
   - Fee
   - Randomizers for each action
3. Prax encodes plan to QR

### 2.2 QR #2: Transaction Plan (Prax → Zigner)

Format (existing):

```
[0x53][0x03][0x10][metadata][transaction_plan_protobuf]

metadata:
  asset_count: u8
  for each asset:
    name_len: u8
    name: utf8 bytes
```

Prax shows QR code, user scans with Zigner.

### 2.3 Zigner Processes Transaction

On Zigner:

1. Parse QR, validate prelude `53 03 10`
2. Decode transaction plan protobuf
3. Extract and display:
   - Chain ID (penumbra-1)
   - Actions summary:
     - Spends: amount, asset
     - Outputs: recipient address (shortened), amount, asset
     - Swaps: from/to assets, amounts
     - Delegations: validator, amount
   - Fee: amount + asset
   - Expiry height (if set)
4. Extract randomizers for signing:
   - `spend_plans[].randomizer` (32 bytes each)
   - `delegator_vote_plans[].randomizer`
   - `lqt_vote_plans[].randomizer`
5. Compute effect hash (BLAKE2b-512)
6. Display effect hash (first/last 8 bytes) for verification

### 2.4 User Approves on Zigner

1. User reviews transaction details
2. User confirms with PIN/biometric
3. Zigner signs all required actions:
   ```rust
   for (randomizer, plan) in spend_plans {
       let rsk = ask.randomize(&randomizer);
       let sig = rsk.sign(&mut rng, &effect_hash);
       spend_auths.push(sig);
   }
   // same for delegator_vote and lqt_vote
   ```

### 2.5 QR #3: Authorization Data (Zigner → Prax)

Format (existing):

```
[0x53][0x03][0x10]
[effect_hash: 64 bytes]
[spend_auth_count: u16 LE]
[spend_auth_sigs: 64 bytes each]
[delegator_vote_count: u16 LE]
[delegator_vote_sigs: 64 bytes each]
[lqt_vote_count: u16 LE]
[lqt_vote_sigs: 64 bytes each]
```

Zigner displays QR, user scans with Prax (via webcam).

### 2.6 Prax Broadcasts Transaction

1. Parse authorization QR
2. Validate effect hash matches computed hash
3. Validate signature counts match plan
4. Construct full `Transaction` from plan + auth data
5. Broadcast to Penumbra network
6. Display result to user

## Phase 3: Implementation Tasks

### 3.1 Zigner (Rust/Mobile)

#### Already Done ✓
- [x] Key derivation: `SpendKeyBytes::from_seed_phrase()`
- [x] Signing: `sign_spend()`, `sign_transaction()`
- [x] Effect hash: `EffectHash::compute_transaction_effect_hash()`
- [x] QR encoding: `PenumbraAuthorizationData::encode()`
- [x] Transaction parsing: `parse_penumbra_transaction()`

#### TODO
- [ ] **FVK derivation and export**
  - Derive verification key from ask
  - Encode FVK to QR format `53 03 01 ...`

- [ ] **Full protobuf parsing**
  - Add prost + penumbra proto definitions
  - Parse TransactionPlan fields
  - Extract randomizers from action plans

- [ ] **Transaction display UI (Android)**
  - Screen: "Penumbra Transaction"
  - Show: chain, actions, fee, expiry
  - Show: effect hash (truncated)
  - Confirm button with PIN

- [ ] **Transaction display UI (iOS)**
  - Same as Android

- [ ] **QR response with prelude**
  - Add `53 03 10` prefix to auth data

### 3.2 Prax Extension

#### New Files

```
packages/wallet/src/
├── zigner-signer.ts        # Zigner custody implementation
└── zigner-qr.ts            # QR encoding/decoding for Zigner

apps/extension/src/
├── routes/popup/
│   └── settings/
│       └── settings-zigner.tsx    # Zigner settings screen
├── state/
│   └── zigner.ts           # Zigner-specific state
└── components/
    └── zigner/
        ├── import-wallet.tsx      # FVK import flow
        ├── transaction-qr.tsx     # Show tx QR
        └── signature-scanner.tsx  # Scan signature QR
```

#### Modifications

**`packages/wallet/src/custody.ts`**
```typescript
const CUSTODY_TYPES = [
  'encryptedSeedPhrase',
  'encryptedSpendKey',
  'airgapSigner',
  'zignerWatchOnly'  // ADD
] as const;
```

**`packages/wallet/src/wallet.ts`**
```typescript
async custody(passKey: Key): Promise<WalletCustody> {
  return {
    authorizePlan: async (plan: TransactionPlan) => {
      switch (this.custodyType) {
        // ... existing cases ...

        case 'zignerWatchOnly': {
          // This type REQUIRES external signing
          const { zignerAuthorize } = await import('./zigner-signer');
          return zignerAuthorize(plan);
        }
      }
    }
  };
}
```

**`packages/wallet/src/zigner-signer.ts`**
```typescript
import { encodePlanToQR, parseAuthorizationQR, validateAuthorization } from './airgap-signer';

export async function zignerAuthorize(plan: TransactionPlan): Promise<AuthorizationData> {
  // 1. Encode plan to QR hex
  const planHex = encodePlanToQR(plan);

  // 2. Signal UI to show QR (via event/callback)
  const signatureHex = await showQRAndWaitForSignature(planHex);

  // 3. Parse response
  const authData = parseAuthorizationQR(signatureHex);

  // 4. Validate
  validateAuthorization(plan, authData);

  return authData;
}

// UI integration point - will be injected by extension
let uiCallback: ((planHex: string) => Promise<string>) | null = null;

export function setZignerUICallback(cb: typeof uiCallback) {
  uiCallback = cb;
}

async function showQRAndWaitForSignature(planHex: string): Promise<string> {
  if (!uiCallback) {
    throw new Error('Zigner UI not initialized');
  }
  return uiCallback(planHex);
}
```

### 3.3 QR Code Types Summary

| Type | Direction | Prelude | Purpose |
|------|-----------|---------|---------|
| FVK Export | Zigner → Prax | `53 03 01` | Setup: export viewing key |
| Tx Plan | Prax → Zigner | `53 03 10` | Signing: send transaction to sign |
| Auth Data | Zigner → Prax | `53 03 10` | Signing: return signatures |

### 3.4 Testing Checklist

#### Unit Tests
- [ ] FVK derivation matches penumbra-keys crate
- [ ] Effect hash matches penumbra transaction hash
- [ ] Signature verification with known test vectors
- [ ] QR encoding/decoding roundtrip

#### Integration Tests
- [ ] Zigner: generate FVK QR, verify Prax can parse
- [ ] Prax: generate tx QR, verify Zigner can parse
- [ ] Zigner: generate auth QR, verify Prax can parse
- [ ] Full flow: create → sign → broadcast (testnet)

#### E2E Tests
- [ ] Setup: create account on Zigner, import to Prax
- [ ] Send: simple transfer on testnet
- [ ] Swap: DEX swap on testnet
- [ ] Delegate: stake delegation on testnet
- [ ] Vote: governance vote on testnet

## Phase 4: Security Considerations

### 4.1 What Prax Stores (Watch-Only)

```typescript
interface ZignerWalletData {
  fullViewingKey: Uint8Array;  // 64 bytes - CAN view, CANNOT spend
  accountIndex: number;
  label: string;
  // NO spend key, seed phrase, or signing capability
}
```

### 4.2 What Zigner Stores (Cold)

```
secure_enclave/
├── seed_phrase (encrypted with device PIN)
├── spend_key_bytes (derived, cached)
└── account_metadata[]
```

### 4.3 Attack Surface

| Attack | Mitigated By |
|--------|--------------|
| Prax extension compromised | Only has FVK, cannot sign |
| QR code intercepted | Contains plan/signatures, not keys |
| Zigner phone stolen | PIN/biometric required to sign |
| Malicious transaction | User reviews on air-gapped device |

### 4.4 Verification Points

1. **On Zigner** (before signing):
   - Display full recipient address
   - Display exact amounts
   - Display fee
   - Show effect hash prefix for cross-verification

2. **On Prax** (after receiving signatures):
   - Verify effect hash matches
   - Verify signature count matches actions
   - Optionally: verify signatures cryptographically

## Phase 5: Future Enhancements

### 5.1 Multi-Account Support
- Zigner manages multiple Penumbra accounts
- Each account exported separately to Prax
- Prax shows account selector during send

### 5.2 Animated QR Codes
- For large transactions (> 2900 bytes)
- Split into multiple frames
- Zigner/Prax reassemble

### 5.3 Address Book Sync
- Export known addresses from Zigner
- Import to Prax for recipient selection
- Verify addresses on Zigner before signing

### 5.4 Transaction Templates
- Pre-approved transaction types
- Reduced verification friction
- Still requires Zigner confirmation

## Appendix A: Protobuf Definitions Needed

```protobuf
// From buf.build/penumbra-zone/penumbra

message TransactionPlan {
  repeated ActionPlan actions = 1;
  TransactionParameters transaction_parameters = 2;
  DetectionDataPlan detection_data = 4;
  MemoPlan memo = 5;
}

message SpendPlan {
  Note note = 1;
  uint64 position = 2;
  bytes randomizer = 3;  // 32 bytes - NEEDED for signing
  bytes value_blinding = 4;
  bytes proof_blinding_r = 5;
  bytes proof_blinding_s = 6;
}

message DelegatorVotePlan {
  Proposal proposal = 1;
  uint64 start_position = 2;
  Vote vote = 3;
  Note staked_note = 4;
  uint64 staked_note_position = 5;
  bytes unbonded_amount = 6;
  bytes randomizer = 7;  // 32 bytes - NEEDED for signing
  bytes proof_blinding_r = 8;
  bytes proof_blinding_s = 9;
}

message AuthorizationData {
  EffectHash effect_hash = 1;
  repeated SpendAuthSignature spend_auths = 2;
  repeated SpendAuthSignature delegator_vote_auths = 3;
}
```

## Appendix B: Key Derivation Reference

```rust
// Full key derivation from seed phrase to signing key

// 1. Seed phrase to BIP-39 seed
let seed = pbkdf2_hmac_sha512(phrase.as_bytes(), b"mnemonic", 2048);

// 2. BIP-32 derivation to spend key bytes
let spend_key_bytes = bip32_derive(seed, "m/44'/6532'/0'");

// 3. Expand to spend authorization key (ask)
let ask_scalar = blake2b_keyed(
    key: spend_key_bytes,
    personal: b"Penumbra_ExpndSd",
    input: [0u8]
);
let ask = SigningKey::<SpendAuth>::new_from_field(Fr::from_le_bytes_mod_order(ask_scalar));

// 4. For signing: randomize the key
let rsk = ask.randomize(&randomizer_from_plan);

// 5. Sign
let signature = rsk.sign(&mut rng, &effect_hash);
```

## Appendix C: Effect Hash Computation

```rust
// Transaction-level effect hash

let mut state = blake2b_simd::Params::new()
    .personal(b"PenumbraEfHs")  // 12 bytes, padded
    .to_state();

// Hash components in order:
state.update(&transaction_parameters_hash);  // 64 bytes
state.update(&memo_hash);                    // 64 bytes (or zeros)
state.update(&detection_data_hash);          // 64 bytes (or zeros)
state.update(&(num_actions as u32).to_le_bytes());

for action in actions {
    state.update(&action_effect_hash);       // 64 bytes each
}

let effect_hash = state.finalize();          // 64 bytes
```
