//! Hexadecimal strings with identicons and qr codes data, as encountered in
//! test jsons throughout the workspace

/// Empty `30x30` transparent PNG image,
/// used in cases when identicon generation failed or public key does not exist
pub fn empty_png() -> Vec<u8> {
    vec![]
}

/// Identicon for Alice key with derivation `//Alice`, `Sr25519` encryption
pub fn alice_sr_alice() -> Vec<u8> {
    hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d").unwrap()
}

/// Identicon for Alice ethereum key with derivation `//polkadot`, `Ethereum` encryption
pub fn alice_ethereum_polkadot() -> String {
    "0xe9267b732a8e9c9444e46f3d04d4610a996d682d".to_string()
}

/// Identicon for Alice key with derivation `//Bob`, aka Bob, `Sr25519` encryption
pub fn bob() -> Vec<u8> {
    hex::decode("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").unwrap()
}
