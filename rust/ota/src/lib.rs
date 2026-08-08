//! Zafu/Zigner firmware OTA wire contract — device side.
//!
//! Implements the frozen wire contract (docs/design/zafu-ota-wire-freeze.md):
//! strict canonical CBOR (RFC 8949), Ed25519 verify/sign over domain-tagged
//! canonical forms, stream verification, A/B staging (pure logic), and the
//! device-signed result/status encoders.
//!
//! Everything here is pure and unit-testable; the Android exposure lives in
//! the `signer` crate (FFI) and `ModuleSlotStore`-style Kotlin adapters.

#![deny(unused_crate_dependencies)]

pub mod result;
pub mod semver;
pub mod slot;
pub mod stream;
pub mod types;
pub mod verifysig;
/// Load and parse the golden test-vector corpus (JSON). Exposed so both the
/// device-side tests and tooling share one parser with the signer.
pub mod corpus {
    use serde_json::Value;
    /// Parse a JSON test-vector corpus file.
    pub fn load(path: &str) -> Result<Value, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    }
}

use std::fmt;

/// Canonical CBOR value tree. Maps keep integer keys; construction orders
/// them ascending (mandatory canonical form).
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    UInt(u64),
    NegInt(u64), // value = -1 - n
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Array(Vec<Cbor>),
    Map(Vec<(u64, Cbor)>), // integer keys, ascending
}

impl Cbor {
    pub fn map() -> MapBuilder {
        MapBuilder(Vec::new())
    }
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Cbor::UInt(u) => Some(*u),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Cbor::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Builder enforcing ascending integer keys.
pub struct MapBuilder(Vec<(u64, Cbor)>);

impl MapBuilder {
    pub fn insert(mut self, key: u64, val: Cbor) -> Self {
        if let Some(last) = self.0.last() {
            assert!(key > last.0, "map keys must be strictly ascending");
        }
        self.0.push((key, val));
        self
    }
    pub fn build(self) -> Cbor {
        Cbor::Map(self.0)
    }
}

/// Wrong canonical-encoding / signature / applicability error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

macro_rules! err {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

// ────────────────────────────────────────────────────────────────────────────
// ENCODE
// ────────────────────────────────────────────────────────────────────────────

/// Encode a value to canonical CBOR.
pub fn encode(v: &Cbor) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

/// Encode a map whose keys are already ascending, appending to `out`.
fn encode_into(v: &Cbor, out: &mut Vec<u8>) -> Result<(), Error> {
    match v {
        Cbor::UInt(n) => encode_uint(*n, 0, out),
        Cbor::NegInt(n) => encode_uint(*n, 1, out),
        Cbor::Bool(true) => out.push(0xf5),
        Cbor::Bool(false) => out.push(0xf4),
        Cbor::Text(s) => {
            encode_length(s.len(), 3, out)?;
            out.extend_from_slice(s.as_bytes());
        }
        Cbor::Bytes(b) => {
            encode_length(b.len(), 2, out)?;
            out.extend_from_slice(b);
        }
        Cbor::Array(items) => {
            encode_length(items.len(), 4, out)?;
            for it in items {
                encode_into(it, out)?;
            }
        }
        Cbor::Map(pairs) => {
            // verify strictly ascending + no dup
            for w in pairs.windows(2) {
                if w[0].0 >= w[1].0 {
                    err!("canonical CBOR requires strictly ascending map keys");
                }
            }
            encode_length(pairs.len(), 5, out)?;
            for (k, val) in pairs {
                encode_uint(*k, 0, out);
                encode_into(val, out)?;
            }
        }
    }
    Ok(())
}

/// Encode a non-negative integer as canonical uint of major type `mt`.
fn encode_uint(n: u64, mt: u8, out: &mut Vec<u8>) {
    let head = mt << 5;
    if n < 24 {
        out.push(head | n as u8);
    } else if n <= 0xff {
        out.push(head | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(head | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(head | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_length(len: usize, mt_byte: u8, out: &mut Vec<u8>) -> Result<(), Error> {
    encode_uint(len as u64, mt_byte, out);
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// DECODE (STRICT)
// ────────────────────────────────────────────────────────────────────────────

/// Strictly decode canonical CBOR. Rejects trailing bytes, duplicate map
/// keys, indefinite lengths, non-minimal ints, and non-minimal length
/// encodings.

/// Decode the first top-level CBOR item, returning it plus the number of
/// bytes consumed. Intended for self-delimiting stream parsing (manifest at
/// offset 0, image wrapper after). Strict canonical rules still apply to the
/// decoded item itself.
pub fn decode_one(data: &[u8]) -> Result<(Cbor, usize), Error> {
    let mut cur = Cursor { data, pos: 0 };
    let v = decode_item(&mut cur)?;
    Ok((v, cur.pos))
}

pub fn decode(data: &[u8]) -> Result<Cbor, Error> {
    let mut cur = Cursor { data, pos: 0 };
    let v = decode_item(&mut cur)?;
    if cur.pos != data.len() {
        err!("trailing bytes after top-level CBOR item");
    }
    Ok(v)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.data.len() {
            err!("unexpected end of input");
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.data.len() {
            err!("unexpected end of input");
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

fn decode_item(cur: &mut Cursor) -> Result<Cbor, Error> {
    let b = cur.byte()?;
    let mt = b >> 5;
    let ai = b & 0x1f;
    match mt {
        0 => Ok(Cbor::UInt(read_uint(cur, ai)?)),
        1 => Ok(Cbor::NegInt(read_uint(cur, ai)?)),
        2 => {
            let len = read_len(cur, ai)?;
            if len == usize::MAX {
                err!("indefinite-length byte string not allowed");
            }
            Ok(Cbor::Bytes(cur.take(len)?.to_vec()))
        }
        3 => {
            let len = read_len(cur, ai)?;
            if len == usize::MAX {
                err!("indefinite-length text string not allowed");
            }
            let s = cur.take(len)?;
            let s = std::str::from_utf8(s).map_err(|_| Error("invalid utf-8 in tstr".into()))?;
            Ok(Cbor::Text(s.to_string()))
        }
        4 => {
            let len = read_len(cur, ai)?;
            if len == usize::MAX {
                // indefinite array: terminator break
                let mut items = Vec::new();
                loop {
                    let nb = cur
                        .byte()
                        .map_err(|_| Error("unterminated indefinite array".into()))?;
                    if nb == 0xff {
                        break;
                    }
                    cur.pos -= 1; // push back
                    items.push(decode_item(cur)?);
                }
                err!("indefinite-length array not allowed");
            }
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_item(cur)?);
            }
            Ok(Cbor::Array(items))
        }
        5 => {
            let len = read_len(cur, ai)?;
            if len == usize::MAX {
                err!("indefinite-length map not allowed");
            }
            let mut pairs: Vec<(u64, Cbor)> = Vec::with_capacity(len);
            for _ in 0..len {
                let k = decode_item(cur)?;
                let kval = match k {
                    Cbor::UInt(u) => u,
                    Cbor::NegInt(_) => err!("negative map keys not supported"),
                    _ => err!("map keys must be unsigned integers (canonical schema)"),
                };
                let val = decode_item(cur)?;
                if pairs.iter().any(|(pk, _)| *pk == kval) {
                    err!("duplicate map key {kval}");
                }
                if let Some((pk, _)) = pairs.last() {
                    if kval < *pk {
                        err!("map keys out of ascending order (non-canonical)");
                    }
                }
                pairs.push((kval, val));
            }
            Ok(Cbor::Map(pairs))
        }
        6 => err!("CBOR tags not allowed in the wire payloads"),
        7 => match ai {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 => err!("null not allowed in canonical payloads"),
            23 => err!("undefined not allowed in canonical payloads"),
            27 => err!("break outside indefinite container"),
            _ => err!("floating point (additional info {ai}) not allowed"),
        },
        _ => unreachable!(),
    }
}

/// Read an unsigned integer for the given additional-info nibble, enforcing
/// minimal encoding.
fn read_uint(cur: &mut Cursor, ai: u8) -> Result<u64, Error> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            let v = cur.byte()? as u64;
            if v < 24 {
                err!("non-minimal uint: one-byte form used for {v}");
            }
            Ok(v)
        }
        25 => {
            let b = cur.take(2)?;
            let v = u16::from_be_bytes([b[0], b[1]]) as u64;
            if v <= 0xff {
                err!("non-minimal uint: two-byte form used for {v}");
            }
            Ok(v)
        }
        26 => {
            let b = cur.take(4)?;
            let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            if v <= 0xffff {
                err!("non-minimal uint: four-byte form used for {v}");
            }
            Ok(v)
        }
        27 => {
            let b = cur.take(8)?;
            let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if v <= 0xffff_ffff {
                err!("non-minimal uint: eight-byte form used for {v}");
            }
            Ok(v)
        }
        28..=30 => err!("reserved additional info {ai}"),
        31 => err!("indefinite length not allowed"),
        _ => unreachable!(),
    }
}

/// Read a length, returning usize::MAX to signal indefinite.
fn read_len(cur: &mut Cursor, ai: u8) -> Result<usize, Error> {
    if ai == 31 {
        return Ok(usize::MAX);
    }
    let v = read_uint(cur, ai)?;
    usize::try_from(v).map_err(|_| Error("length overflows usize".into()))
}
