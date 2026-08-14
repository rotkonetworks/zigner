# Release-key ceremony (zigner firmware OTA trust root)

The device runs a protocol module only if **2 of 3** release keys signed it. This
is the ceremony that mints those 3 keys. Do it **once**, **offline**, and never
again for the life of the trust root - re-keying means re-pinning every device
and shipping a firmware update, so treat these keys as permanent.

Not FROST: three *independent* ed25519 keys held by three people. Any two of them
sign a release (`prepare` -> two holders sign -> `assemble`). No single machine
ever holds two keys - that is the whole point of the split.

## Threat model (why offline)

A zigner module receives the **raw seed** (`module_host` writes the mnemonic into
the loaded module). The 2-of-3 signature is the *only* thing standing between a
malicious module and the user's funds. So:

- The 3 secret keys must be born on a machine that never touches a network.
- No party may ever hold two of them (2-of-3 with one held = 1-of-2 = broken).
- CI holds exactly **one** key. CI compromise must not be able to sign a release
  alone; it needs a human holder's second signature.

## What you need

- An **air-gapped** machine (no wifi, no ethernet - pull the cable / disable the
  radio; a fresh live-USB boot is ideal). Good entropy: let it sit a minute after
  boot, or move the mouse, before generating.
- The `zigner` source on that machine (USB copy). A Rust toolchain to build
  `modpack` offline (`cargo build --offline` if the registry is vendored, else
  build it on a networked machine first and carry the binary over).
- `age` and `shred` installed on the air-gapped machine.
- Each holder's **age recipient** (public key, `age-keygen` output line
  `# public key: age1...`). Collect these *beforehand* - they are public.

## Step 1 - generate (air-gapped)

```
modpack keygen --out-dir release-keys
```

This:
- mints 3 independent ed25519 keypairs from the OS CSPRNG,
- runs a 2-of-3 self-test (signs and verifies with the real verifier for all
  three pairs) and refuses to continue if it fails,
- writes `release-keys/slot{0,1,2}-{ci,manager,backup}.sk` (raw 32-byte secret
  keys, mode 0600),
- prints the 3 **verifying keys** (public - safe to copy), a paste-ready
  `release_keys: [VerifyingKey; 3]` snippet, and the `modpack verify` line.

Copy the printed **verifying keys** down (photograph the screen / write on paper).
They are public; you will pin them in Step 2. The `.sk` files are the secrets.

## Step 2 - pin the public keys (can be done later, online)

The 3 verifying keys are the trust anchor. Pin them in **both** verifiers, in the
same slot order keygen printed:

- **Firmware** - `module_host` `release_keys: [VerifyingKey; 3]` (paste the
  snippet keygen printed).
- **Wallet** - the OTA verifier in zafu (`apps/extension/src/ota/keys.ts` -
  replace the dev placeholder with these three).

Slot order matters: `modpack verify --key 0:.. --key 1:.. --key 2:..` and the
device both index by position. Keep 0=ci, 1=manager, 2=backup consistent.

## Step 3 - encrypt and distribute (still air-gapped)

Encrypt each secret key to its holder's age recipient, then destroy the raw key.
Never let a raw `.sk` leave this machine.

```
age -r <ci-recipient>      -o slot0-ci.sk.age      release-keys/slot0-ci.sk
age -r <manager-recipient> -o slot1-manager.sk.age release-keys/slot1-manager.sk
age -r <backup-recipient>  -o slot2-backup.sk.age   release-keys/slot2-backup.sk
shred -u release-keys/*.sk
```

Carry the three `.age` files off on the USB. Distribution:

- **slot0 (CI)** -> commit `slot0-ci.sk.age` to the repo as `ota/keys/ci-share.age`,
  and store the *CI age identity* (the private key that decrypts it) as the GitHub
  secret `OTA_CI_AGE_IDENTITY`. CI can now decrypt exactly this one share.
- **slot1 (manager)** -> your local machine, kept as `.age` (unlock with your
  age identity / YubiKey only when signing a release).
- **slot2 (backup)** -> a second maintainer / cold storage, offline, for recovery
  if a holder is lost.

## Step 4 - wipe

Wipe the air-gapped machine's disk (or destroy the live-USB). The raw keys were
shredded in Step 3; the `.age` files are the only surviving copies and each is
useless without its holder's age identity.

---

## Using the keys later (a normal release)

Signing never needs the ceremony machine again - it uses the distributed shares:

```
# build host: emit the bytes to be signed
modpack prepare --module module.wasm --version N --changelog NOTES.md \
  --out-prefix prefix.bin --out-payload payload.bin

# two holders, on their own machines, each sign prefix.bin with their key:
#   - device holders scan prefix.bin on their zigner and return 64 bytes
#     (the `ceremony` crate coordinates this - it only shows and collects,
#      it cannot make a holder sign bytes they were not shown).
#   - CI (raw slot0 share) needs a software signer over prefix.bin. That tool
#     is NOT built yet (ota-release.yml TODO) - CI cannot auto-sign until it is.

# build host / CI: join any two signatures into the shippable module
modpack assemble --prefix prefix.bin --payload payload.bin \
  --sig 0:<ci-sig-hex> --sig 1:<manager-sig-hex> --out package.zmod

# verify against the pinned keys BEFORE shipping
modpack verify --package package.zmod \
  --key 0:<vk0> --key 1:<vk1> --key 2:<vk2>
```

CI (`ota-release.yml`) automates the CI side: decrypt slot0, sign the prefix,
`assemble` with the release manager's presigned slot1, `verify`, publish. CI holds
one key and can only ever contribute one of the two required signatures.

## Recovery

- **Lose one key** (e.g. a holder's laptop dies): the other two still sign
  releases (2-of-3). Rotate at leisure: mint a fresh trust root with a new
  ceremony and ship a firmware update that re-pins.
- **Lose two keys**: the trust root is dead - you can no longer sign. This is why
  slot2 lives in cold storage with a *different* person than slot1.
- **CI (slot0) compromised**: attacker has one share, cannot sign alone. Rotate
  the CI key (new ceremony + re-pin) at the next release.
