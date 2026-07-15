//! QR envelope for PCZT signing requests and responses.
//!
//! Zigner QR payloads open with the prelude `[0x53][crypto_type][tx_type]`.
//! Zcash is crypto_type 0x04; tx_type 0x02 is the legacy digest-signing
//! request. This module adds:
//!
//!   0x03  single redacted PCZT        -> single signed PCZT back
//!   0x04  batch envelope, 1..=35 PCZTs -> batch of signed PCZTs back
//!
//! Old firmware rejects unknown tx_types with a named error (fails closed).
//! The batch cap mirrors vizor's `ZCASH_SIGN_BATCH_MAX_MESSAGES = 35`; the
//! response carries `sha256(signed_pczt)` per message, matching the
//! Keystone integrity rule (a checksum of the PCZT bytes, not the sighash).
//!
//! Wire format (little-endian lengths, deliberately dumb):
//!   single request:  prelude || pczt_bytes
//!   batch request:   prelude || count:u8 ||
//!                    count * ( id_len:u8 || id || pczt_len:u32 || pczt )
//!   single response: prelude || digest:32 || pczt_len:u32 || signed_pczt
//!   batch response:  prelude || count:u8 ||
//!                    count * ( id_len:u8 || id || digest:32 ||
//!                              pczt_len:u32 || signed_pczt )

use sha2::{Digest, Sha256};

pub const PRELUDE: u8 = 0x53;
pub const CRYPTO_TYPE_ZCASH: u8 = 0x04;
pub const TX_TYPE_PCZT_SINGLE: u8 = 0x03;
pub const TX_TYPE_PCZT_BATCH: u8 = 0x04;

/// Keystone/vizor parity: at most 35 messages per QR exchange.
pub const BATCH_MAX_MESSAGES: usize = 35;

#[derive(Debug)]
pub enum EnvelopeError {
    TooShort,
    WrongPrelude,
    WrongCryptoType(u8),
    UnknownTxType(u8),
    BatchCount(usize),
    Truncated(&'static str),
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnvelopeError::TooShort => write!(f, "payload shorter than prelude"),
            EnvelopeError::WrongPrelude => write!(f, "not a zigner payload"),
            EnvelopeError::WrongCryptoType(t) => write!(f, "not a zcash payload (crypto 0x{t:02x})"),
            EnvelopeError::UnknownTxType(t) => write!(f, "unknown zcash tx type 0x{t:02x}"),
            EnvelopeError::BatchCount(n) => write!(f, "batch count {n} outside 1..={BATCH_MAX_MESSAGES}"),
            EnvelopeError::Truncated(what) => write!(f, "truncated payload at {what}"),
        }
    }
}

/// One message of a signing request.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestMessage {
    /// Wallet-chosen opaque id, echoed in the response (batch only; empty
    /// for single requests).
    pub id: Vec<u8>,
    pub pczt_bytes: Vec<u8>,
}

/// A parsed signing request.
#[derive(Debug, Clone, PartialEq)]
pub enum SignRequest {
    Single(RequestMessage),
    Batch(Vec<RequestMessage>),
}

impl SignRequest {
    pub fn messages(&self) -> &[RequestMessage] {
        match self {
            SignRequest::Single(m) => core::slice::from_ref(m),
            SignRequest::Batch(v) => v,
        }
    }
}

/// Parse a scanned payload into a signing request.
pub fn parse_request(payload: &[u8]) -> Result<SignRequest, EnvelopeError> {
    let [p, crypto, tx_type, rest @ ..] = payload else {
        return Err(EnvelopeError::TooShort);
    };
    if *p != PRELUDE {
        return Err(EnvelopeError::WrongPrelude);
    }
    if *crypto != CRYPTO_TYPE_ZCASH {
        return Err(EnvelopeError::WrongCryptoType(*crypto));
    }
    match *tx_type {
        TX_TYPE_PCZT_SINGLE => {
            if rest.is_empty() {
                return Err(EnvelopeError::Truncated("pczt body"));
            }
            Ok(SignRequest::Single(RequestMessage {
                id: Vec::new(),
                pczt_bytes: rest.to_vec(),
            }))
        }
        TX_TYPE_PCZT_BATCH => {
            let (&count, mut rest) = rest.split_first().ok_or(EnvelopeError::Truncated("count"))?;
            let count = count as usize;
            if count == 0 || count > BATCH_MAX_MESSAGES {
                return Err(EnvelopeError::BatchCount(count));
            }
            let mut messages = Vec::with_capacity(count);
            for _ in 0..count {
                let (&id_len, r) = rest.split_first().ok_or(EnvelopeError::Truncated("id len"))?;
                let id_len = id_len as usize;
                if r.len() < id_len + 4 {
                    return Err(EnvelopeError::Truncated("id"));
                }
                let (id, r) = r.split_at(id_len);
                let (len_bytes, r) = r.split_at(4);
                let pczt_len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
                if r.len() < pczt_len {
                    return Err(EnvelopeError::Truncated("pczt body"));
                }
                let (pczt, r) = r.split_at(pczt_len);
                messages.push(RequestMessage { id: id.to_vec(), pczt_bytes: pczt.to_vec() });
                rest = r;
            }
            Ok(SignRequest::Batch(messages))
        }
        other => Err(EnvelopeError::UnknownTxType(other)),
    }
}

/// Wallet-side helper: encode a request (also used by tests + zafu).
pub fn encode_request(request: &SignRequest) -> Result<Vec<u8>, EnvelopeError> {
    let mut out = vec![PRELUDE, CRYPTO_TYPE_ZCASH];
    match request {
        SignRequest::Single(m) => {
            out.push(TX_TYPE_PCZT_SINGLE);
            out.extend_from_slice(&m.pczt_bytes);
        }
        SignRequest::Batch(messages) => {
            if messages.is_empty() || messages.len() > BATCH_MAX_MESSAGES {
                return Err(EnvelopeError::BatchCount(messages.len()));
            }
            out.push(TX_TYPE_PCZT_BATCH);
            out.push(messages.len() as u8);
            for m in messages {
                out.push(m.id.len() as u8);
                out.extend_from_slice(&m.id);
                out.extend_from_slice(&(m.pczt_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&m.pczt_bytes);
            }
        }
    }
    Ok(out)
}

/// One signed message of a response.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseMessage {
    pub id: Vec<u8>,
    /// sha256 of `signed_pczt` - integrity checksum, Keystone parity.
    pub digest: [u8; 32],
    pub signed_pczt: Vec<u8>,
}

/// Device-side: encode signed results back for the wallet's camera.
pub fn encode_response(messages: &[ResponseMessage], batch: bool) -> Result<Vec<u8>, EnvelopeError> {
    let mut out = vec![PRELUDE, CRYPTO_TYPE_ZCASH];
    if batch {
        if messages.is_empty() || messages.len() > BATCH_MAX_MESSAGES {
            return Err(EnvelopeError::BatchCount(messages.len()));
        }
        out.push(TX_TYPE_PCZT_BATCH);
        out.push(messages.len() as u8);
        for m in messages {
            out.push(m.id.len() as u8);
            out.extend_from_slice(&m.id);
            out.extend_from_slice(&m.digest);
            out.extend_from_slice(&(m.signed_pczt.len() as u32).to_le_bytes());
            out.extend_from_slice(&m.signed_pczt);
        }
    } else {
        let [m] = messages else {
            return Err(EnvelopeError::BatchCount(messages.len()));
        };
        out.push(TX_TYPE_PCZT_SINGLE);
        out.extend_from_slice(&m.digest);
        out.extend_from_slice(&(m.signed_pczt.len() as u32).to_le_bytes());
        out.extend_from_slice(&m.signed_pczt);
    }
    Ok(out)
}

/// Wallet-side: parse a device response.
pub fn parse_response(payload: &[u8]) -> Result<Vec<ResponseMessage>, EnvelopeError> {
    let [p, crypto, tx_type, rest @ ..] = payload else {
        return Err(EnvelopeError::TooShort);
    };
    if *p != PRELUDE {
        return Err(EnvelopeError::WrongPrelude);
    }
    if *crypto != CRYPTO_TYPE_ZCASH {
        return Err(EnvelopeError::WrongCryptoType(*crypto));
    }
    let read_one = |r: &[u8], with_id: bool| -> Result<(ResponseMessage, usize), EnvelopeError> {
        let mut pos = 0;
        let id = if with_id {
            let id_len = *r.first().ok_or(EnvelopeError::Truncated("id len"))? as usize;
            pos += 1;
            if r.len() < pos + id_len {
                return Err(EnvelopeError::Truncated("id"));
            }
            let id = r[pos..pos + id_len].to_vec();
            pos += id_len;
            id
        } else {
            Vec::new()
        };
        if r.len() < pos + 36 {
            return Err(EnvelopeError::Truncated("digest"));
        }
        let digest: [u8; 32] = r[pos..pos + 32].try_into().unwrap();
        pos += 32;
        let len = u32::from_le_bytes(r[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if r.len() < pos + len {
            return Err(EnvelopeError::Truncated("signed pczt"));
        }
        let signed_pczt = r[pos..pos + len].to_vec();
        pos += len;
        Ok((ResponseMessage { id, digest, signed_pczt }, pos))
    };
    match *tx_type {
        TX_TYPE_PCZT_SINGLE => {
            let (m, _) = read_one(rest, false)?;
            Ok(vec![m])
        }
        TX_TYPE_PCZT_BATCH => {
            let (&count, mut r) = rest.split_first().ok_or(EnvelopeError::Truncated("count"))?;
            let count = count as usize;
            if count == 0 || count > BATCH_MAX_MESSAGES {
                return Err(EnvelopeError::BatchCount(count));
            }
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                let (m, used) = read_one(r, true)?;
                r = &r[used..];
                out.push(m);
            }
            Ok(out)
        }
        other => Err(EnvelopeError::UnknownTxType(other)),
    }
}

/// Compute the Keystone-parity integrity digest for a signed PCZT.
pub fn integrity_digest(signed_pczt: &[u8]) -> [u8; 32] {
    Sha256::digest(signed_pczt).into()
}
