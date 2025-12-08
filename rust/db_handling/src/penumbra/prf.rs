//! PRF expansion functions for Penumbra key derivation
//! Based on ledger-penumbra implementation

use crate::error::{Error, Result};

/// Blake2b PRF expansion
pub fn expand(label: &[u8; 16], key: &[u8], input: &[u8]) -> Result<[u8; 64]> {
    use blake2b_simd::Params;

    if key.len() > blake2b_simd::KEYBYTES {
        return Err(Error::Other(anyhow::anyhow!("Invalid key length for PRF")));
    }

    let mut params = Params::new();
    params.personal(label);

    // Add key only if not empty
    if !key.is_empty() {
        params.key(key);
    }

    let hash = params.hash(input);
    let mut output = [0u8; 64];
    output.copy_from_slice(hash.as_bytes());

    Ok(output)
}

/// Expand to Fr (scalar field element)
pub fn expand_fr(label: &[u8; 16], key: &[u8], input: &[u8]) -> Result<decaf377::Fr> {
    let bytes = expand(label, key, input)?;
    Ok(decaf377::Fr::from_le_bytes_mod_order(&bytes))
}

/// Expand to Fq (base field element)
pub fn expand_fq(label: &[u8; 16], key: &[u8], input: &[u8]) -> Result<decaf377::Fq> {
    let bytes = expand(label, key, input)?;
    Ok(decaf377::Fq::from_le_bytes_mod_order(&bytes))
}
