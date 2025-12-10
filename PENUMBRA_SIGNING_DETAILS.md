# penumbra signing implementation details

## source analysis from ~/rotko/penumbra

analyzed the official penumbra implementation to understand transaction signing.

## key structures

### TransactionPlan
```rust
// crates/core/transaction/src/plan.rs
pub struct TransactionPlan {
    pub actions: Vec<ActionPlan>,
    pub transaction_parameters: TransactionParameters,
    pub detection_data: Option<DetectionDataPlan>,
    pub memo: Option<MemoPlan>,
}
```

### AuthorizationData
```rust
// crates/core/transaction/src/auth_data.rs
pub struct AuthorizationData {
    pub effect_hash: Option<EffectHash>,
    pub spend_auths: Vec<Signature<SpendAuth>>,           // decaf377-rdsa
    pub delegator_vote_auths: Vec<Signature<SpendAuth>>,  // decaf377-rdsa
    pub lqt_vote_auths: Vec<Signature<SpendAuth>>,        // liquidity tournament votes
}
```

## signing algorithm

### effect hash computation
```rust
// crates/core/transaction/src/plan.rs:70-115
pub fn effect_hash(&self, fvk: &FullViewingKey) -> Result<EffectHash> {
    let mut state = blake2b_simd::Params::new()
        .personal(b"PenumbraEfHs")  // personalization string
        .to_state();

    // hash transaction parameters
    state.update(self.transaction_parameters.effect_hash().as_bytes());

    // hash memo
    let memo_hash = self.memo.map(|m| m.memo().effect_hash()).unwrap_or_default();
    state.update(memo_hash.as_bytes());

    // hash detection data
    let detection_data_hash = self.detection_data
        .map(|d| d.detection_data().effect_hash())
        .unwrap_or_default();
    state.update(detection_data_hash.as_bytes());

    // hash action count
    let num_actions = self.actions.len() as u32;
    state.update(&num_actions.to_le_bytes());

    // hash each action's effecting data
    for action_plan in &self.actions {
        state.update(action_plan.effect_hash(fvk, &memo_key).as_bytes());
    }

    Ok(EffectHash(state.finalize().as_array().clone()))
}
```

### authorization (signing)
```rust
// crates/core/transaction/src/plan/auth.rs:12-46
pub fn authorize<R: RngCore + CryptoRng>(
    &self,
    mut rng: R,
    sk: &SpendKey,
) -> Result<AuthorizationData> {
    // compute effect hash
    let effect_hash = self.effect_hash(sk.full_viewing_key())?;

    let mut spend_auths = Vec::new();
    let mut delegator_vote_auths = Vec::new();
    let mut lqt_vote_auths = Vec::new();

    // sign each spend action
    for spend_plan in self.spend_plans() {
        let rsk = sk.spend_auth_key().randomize(&spend_plan.randomizer);
        let auth_sig = rsk.sign(&mut rng, effect_hash.as_ref());
        spend_auths.push(auth_sig);
    }

    // sign each delegator vote action
    for delegator_vote_plan in self.delegator_vote_plans() {
        let rsk = sk.spend_auth_key()
            .randomize(&delegator_vote_plan.randomizer);
        let auth_sig = rsk.sign(&mut rng, effect_hash.as_ref());
        delegator_vote_auths.push(auth_sig);
    }

    // sign each lqt vote action
    for lqt_vote_plan in self.lqt_vote_plans() {
        let rsk = sk.spend_auth_key().randomize(&lqt_vote_plan.randomizer);
        let auth_sig = rsk.sign(&mut rng, effect_hash.as_ref());
        lqt_vote_auths.push(auth_sig);
    }

    Ok(AuthorizationData {
        effect_hash: Some(effect_hash),
        spend_auths,
        delegator_vote_auths,
        lqt_vote_auths,
    })
}
```

## key derivation

### bip44 path
```rust
// crates/core/keys/src/keys/bip44.rs:3
const PENUMBRA_COIN_TYPE: u32 = 6532;

// path format: m/44'/6532'/0'
pub fn new(account: u32) -> Self {
    Self {
        purpose: 44,
        coin_type: PENUMBRA_COIN_TYPE,  // 6532
        account,
        change: None,
        address_index: None,
    }
}
```

### spend key derivation
```rust
// crates/core/keys/src/keys/spend.rs:107-129
pub fn from_seed_phrase_bip44(seed_phrase: SeedPhrase, path: &Bip44Path) -> Self {
    let password = format!("{seed_phrase}");
    let salt = "mnemonic";
    let mut seed_bytes = [0u8; 64];

    // pbkdf2 with 2048 rounds
    pbkdf2::<Hmac<sha2::Sha512>>(
        password.as_bytes(),
        salt.as_bytes(),
        NUM_PBKDF2_ROUNDS,  // 2048
        &mut seed_bytes,
    );

    // derive child key from bip44 path
    let child_key = XPrv::derive_from_path(
        &seed_bytes[..],
        &path.path().parse()?,  // "m/44'/6532'/0'"
    )?;

    let child_key_bytes = child_key.to_bytes();  // [u8; 32]

    SpendKeyBytes(child_key_bytes).into()
}
```

### spend auth key expansion
```rust
// crates/core/keys/src/keys/spend.rs:67-74
impl From<SpendKeyBytes> for SpendKey {
    fn from(seed: SpendKeyBytes) -> Self {
        // expand seed to spend authorization key
        let ask = SigningKey::new_from_field(
            prf::expand_ff(b"Penumbra_ExpndSd", &seed.0, &[0; 1])
        );

        // expand seed to nullifier key
        let nk = NullifierKey(
            prf::expand_ff(b"Penumbra_ExpndSd", &seed.0, &[1; 1])
        );

        let fvk = FullViewingKey::from_components(ask.into(), nk);

        Self { seed, ask, fvk }
    }
}
```

## signature scheme: decaf377-rdsa

### randomized signatures
```rust
// decaf377-rdsa crate
use decaf377_rdsa::{Signature, SpendAuth, SigningKey};

// sign with randomized key
let rsk = signing_key.randomize(&randomizer);  // randomizer from action plan
let signature = rsk.sign(&mut rng, message);   // message = effect_hash
```

### signature format
- 64 bytes per signature
- decaf377 curve (ristretto255-like)
- rdsa (randomizable deterministic signature algorithm)

## implementation for parity signer

### 1. parse incoming qr
```
[0x53][0x03][0x10][metadata][transaction_plan_bytes]
                              └─ protobuf encoded TransactionPlan
```

### 2. decode transaction plan
```rust
use penumbra_proto::core::transaction::v1::TransactionPlan;

let plan = TransactionPlan::decode(&plan_bytes)?;
```

### 3. compute effect hash
```rust
let effect_hash = compute_effect_hash(&plan, &fvk)?;
// blake2b-512 with personalization "PenumbraEfHs"
```

### 4. derive spend key from seed
```rust
// user inputs seed phrase in parity signer
let seed_phrase = SeedPhrase::from_words(words)?;
let bip44_path = Bip44Path::new(0);  // account 0
let spend_key = SpendKey::from_seed_phrase_bip44(seed_phrase, &bip44_path);
```

### 5. sign actions
```rust
let mut spend_auths = Vec::new();

for spend_plan in plan.spend_actions() {
    let rsk = spend_key.spend_auth_key()
        .randomize(&spend_plan.randomizer);
    let sig = rsk.sign(&mut rng, effect_hash.as_ref());
    spend_auths.push(sig);
}

// same for delegator_vote_auths
```

### 6. encode response qr
```
[0x53][0x03][0x10][effect_hash][signatures]

effect_hash:          64 bytes
spend_auth_count:     2 bytes (le)
spend_auth_sigs:      64 bytes each
vote_auth_count:      2 bytes (le)
vote_auth_sigs:       64 bytes each
lqt_vote_count:       2 bytes (le)
lqt_vote_sigs:        64 bytes each
```

## dependencies needed

```toml
[dependencies]
# penumbra core
penumbra-proto = "0.80"
penumbra-keys = "0.80"
penumbra-transaction = "0.80"

# crypto
decaf377 = "0.9"
decaf377-rdsa = "0.9"
decaf377-fmd = "0.9"

# key derivation
bip32 = "0.5"
bip39 = "2.0"
pbkdf2 = "0.12"
hmac = "0.12"
sha2 = "0.10"

# hashing
blake2b_simd = "1.0"

# encoding
prost = "0.12"
```

## notes

### randomizers
each spend/vote action has a unique randomizer (32 bytes) that is part of the action plan. the randomizer is used to derive a randomized signing key for that specific action. this provides privacy by unlinking signatures from the base spend authorization key.

### effect hash personalization
penumbra uses blake2b-512 with personalization string `"PenumbraEfHs"` (12 bytes). this domain-separates the effect hash from other hashes in the protocol.

### action ordering
actions are hashed in the order they appear in the transaction plan. this order must be preserved when building the actual transaction.

### lqt votes
liquidity tournament votes are a new action type. for now, parity signer can treat them similarly to delegator votes (both use spend auth signatures).

## reference files

- transaction plan: `~/rotko/penumbra/crates/core/transaction/src/plan.rs`
- authorization: `~/rotko/penumbra/crates/core/transaction/src/plan/auth.rs`
- auth data: `~/rotko/penumbra/crates/core/transaction/src/auth_data.rs`
- spend key: `~/rotko/penumbra/crates/core/keys/src/keys/spend.rs`
- bip44: `~/rotko/penumbra/crates/core/keys/src/keys/bip44.rs`

---

## ledger-penumbra analysis (~/rotko/ledger-penumbra)

analyzed the official ledger implementation by zondax for hardware wallet signing.

### key implementation files

```
app/rust/src/
├── keys/
│   ├── signing_key.rs     # Sk wrapper for SigningKey<SpendAuth>
│   ├── spend_key.rs       # SpendKeyBytes and SpendKey
│   ├── fvk.rs             # FullViewingKey derivation
│   ├── nk.rs              # NullifierKey
│   └── dk.rs              # DiversifierKey
├── parser/
│   ├── effect_hash.rs     # EffectHash computation
│   └── plans/
│       └── spend.rs       # SpendPlan effect hash
├── ffi/
│   └── sign.rs            # rs_sign_spend FFI function
└── utils/
    └── prf.rs             # expand_ff functions
```

### signing implementation (ffi/sign.rs)

```rust
// the actual signing function
pub fn sign_spend(
    effect_hash: &BytesC,
    randomizer: &BytesC,
    spend_key: &SpendKeyBytes,
) -> Result<Signature<SpendAuth>, ParserError> {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    // 1. get randomized signing key
    let sk = randomized_signing_key(spend_key, randomizer)?;

    // 2. convert effect_hash to bytes
    let effect_hash = effect_hash.into();

    // 3. create deterministic rng from randomizer
    let seed = randomizer.into_array()?;
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 4. sign with randomized key
    Ok(sk.sign(&mut rng, effect_hash))
}

pub fn randomized_signing_key(
    spend_key: &SpendKeyBytes,
    randomizer: &BytesC,
) -> Result<SigningKey<SpendAuth>, ParserError> {
    // derive base signing key (ask) from spend_key_bytes
    let sk = spend_key.signing_key()?;

    // convert randomizer to Fr field element
    let randomizer: &[u8] = randomizer.into();
    let randomizer = Fr::from_le_bytes_mod_order(randomizer);

    // randomize the key: rsk = ask * randomizer (scalar multiplication)
    Ok(sk.randomize(&randomizer))
}
```

### key derivation (keys/signing_key.rs)

```rust
pub struct Sk(SigningKey<SpendAuth>);

impl Sk {
    pub const LABEL: &'static [u8; 16] = b"Penumbra_ExpndSd";

    pub fn derive_from(spend_bytes: &SpendKeyBytes) -> Result<Self, ParserError> {
        // expand Fr field element from spend key bytes
        // ask = from_le_bytes(blake2b(b"Penumbra_ExpndSd", spend_key_bytes, [0])) mod r
        let ask = expand_ff(Self::LABEL, spend_bytes.key_bytes(), &[0; 1])?;
        let signing_key = SigningKey::new_from_field(ask);
        Ok(Self(signing_key))
    }

    pub fn randomize(&self, randomizer: &Fr) -> SigningKey<SpendAuth> {
        self.0.randomize(randomizer)
    }
}
```

### prf expand (utils/prf.rs)

```rust
// blake2b-512 with personalization and key
pub fn expand(label: &'static [u8; 16], key: &[u8], input: &[u8]) -> Result<[u8; 64], ParserError> {
    let mut params = blake2b_simd::Params::new();
    let mut params = params.personal(label);  // personalization: "Penumbra_ExpndSd"

    if !key.is_empty() {
        params = params.key(key);  // key: spend_key_bytes
    }

    let hash = params.hash(input);  // input: [0] or [1]

    let mut output = [0u8; 64];
    output.copy_from_slice(hash.as_bytes());
    Ok(output)
}

// expand to Fr field element
pub fn expand_ff(label: &'static [u8; 16], key: &[u8], input: &[u8]) -> Result<Fr, ParserError> {
    Ok(Fr::from_le_bytes_mod_order(expand(label, key, input)?.as_ref()))
}
```

### effect hash computation (parser/effect_hash.rs)

```rust
pub struct EffectHash(pub [u8; 64]);

/// blake2b-512 with variable-length personalization
pub fn create_personalized_state(personalization: &str) -> blake2b_simd::State {
    let mut state = blake2b_simd::State::new();

    // prepend personalization length as u64 LE
    let length = personalization.len() as u64;
    state.update(&length.to_le_bytes());
    state.update(personalization.as_bytes());

    state
}

impl EffectHash {
    pub fn from_proto_effecting_data(personalization: &str, data: &[u8]) -> EffectHash {
        let mut state = create_personalized_state(personalization);
        state.update(data);
        EffectHash(*state.finalize().as_array())
    }
}
```

### personalization strings (constants.rs)

```rust
pub const SPEND_PERSONALIZED: &[u8] = b"/penumbra.core.component.shielded_pool.v1.SpendBody";
pub const OUTPUT_PERSONALIZED: &[u8] = b"/penumbra.core.component.shielded_pool.v1.OutputBody";
pub const SWAP_PERSONALIZED: &[u8] = b"/penumbra.core.component.dex.v1.SwapBody";
pub const ICS20_WITHDRAWAL_PERSONALIZED: &[u8] = b"/penumbra.core.component.ibc.v1.Ics20Withdrawal";
pub const DELEGATE_PERSONALIZED: &[u8] = b"/penumbra.core.component.stake.v1.Delegate";
pub const UNDELEGATE_PERSONALIZED: &[u8] = b"/penumbra.core.component.stake.v1.Undelegate";
pub const DELEGATOR_VOTE_PERSONALIZED: &[u8] = b"/penumbra.core.component.governance.v1.DelegatorVoteBody";
// ... more action types
```

### dependencies (Cargo.toml) - no_std compatible!

```toml
[dependencies]
# crypto primitives - use u32_backend for constrained devices
decaf377 = { version = "0.10.1", default-features = false, features = ["u32_backend"] }
decaf377-rdsa = { version = "0.11", default-features = false, features = ["u32_backend"] }
poseidon377 = { version = "1.1.0", default-features = false }

# hashing
blake2b_simd = { version = "1.0.2", default-features = false }

# address encoding
f4jumble = { version = "0.1.0", default-features = false }
bech32 = { version = "0.11.0", default-features = false }

# encryption
aes = { version = "0.8.4", default-features = false }
chacha20poly1305 = { version = "0.10.1", default-features = false }

# rng
rand_chacha = { version = "0.3.1", default-features = false }

# parsing
nom = { version = "7.1.3", default-features = false }

# misc
zeroize = { version = "1.7.0", default-features = false, features = ["derive"] }
```

### c/rust interface (crypto.c)

```c
// signing flow in C
zxerr_t crypto_sign(parser_tx_t *tx_obj, uint8_t *signature, uint16_t signatureMaxlen) {
    keys_t keys = {0};

    // 1. derive spend key from bip44 path
    CATCH_ZX_ERROR(computeSpendKey(&keys));

    bytes_t effect_hash = {.ptr = tx_obj->effect_hash, .len = 64};

    // 2. sign each spend action
    for (uint16_t i = 0; i < tx_obj->plan.actions.qty; i++) {
        if (tx_obj->actions_plan[i].action_type == spend_tag) {
            // call rust signing function
            rs_sign_spend(
                &effect_hash,
                &tx_obj->actions_plan[i].action.spend.randomizer,
                &keys.skb,
                spend_signature,
                64
            );
            nv_write_signature(spend_signature, Spend);
        }
    }

    // 3. return effect_hash + signature counts
    MEMCPY(signature, tx_obj->effect_hash, EFFECT_HASH_LEN);
    // append signature counts...
}

// bip44 key derivation
zxerr_t computeSpendKey(keys_t *keys) {
    uint8_t privateKeyData[32] = {0};
    // derive from m/44'/6532'/0'
    os_derive_bip32_no_throw(CX_CURVE_256K1, hdPath, HDPATH_LEN_DEFAULT, privateKeyData, NULL);
    MEMCPY(keys->skb, privateKeyData, sizeof(keys->skb));
}
```

### key takeaways from ledger implementation

1. **no_std compatible**: uses `default-features = false` everywhere
2. **u32_backend**: uses u32-based field arithmetic (slower but smaller code)
3. **deterministic rng**: uses ChaCha20Rng seeded from randomizer for deterministic signatures
4. **protobuf parsing**: uses nom for parsing, not prost
5. **effect hash**: uses blake2b-512 with length-prefixed personalization
6. **signature storage**: stores signatures in non-volatile memory (nv_signature)
7. **ffi boundary**: rust handles all crypto, c handles apdu protocol

### adaptation for zigner (phone implementation)

for phones we have more resources than ledger, so we can:

1. use `std` features where available
2. use `u64_backend` for faster field arithmetic
3. use prost for protobuf parsing (more convenient)
4. use async for better ui responsiveness

but the core signing logic remains identical:

```rust
// zigner penumbra signing
pub fn sign_penumbra_spend(
    effect_hash: &[u8; 64],
    randomizer: &[u8; 32],
    spend_key_bytes: &[u8; 32],
) -> Result<[u8; 64], Error> {
    // 1. derive ask from spend key bytes
    let ask = expand_ff(b"Penumbra_ExpndSd", spend_key_bytes, &[0])?;
    let signing_key = SigningKey::<SpendAuth>::new_from_field(ask);

    // 2. randomize key
    let randomizer_fr = Fr::from_le_bytes_mod_order(randomizer);
    let rsk = signing_key.randomize(&randomizer_fr);

    // 3. sign effect hash
    let mut rng = ChaCha20Rng::from_seed(*randomizer);
    let sig = rsk.sign(&mut rng, effect_hash);

    Ok(sig.to_bytes())
}
