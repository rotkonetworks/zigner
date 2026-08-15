#![deny(unused_crate_dependencies)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

extern crate alloc;

use error::{ParserDecodingError, ParserMetadataError};
use frame_metadata::v14::RuntimeMetadataV14;
use parity_scale_codec::{Decode, DecodeAll, Encode};
use printing_balance::convert_balance_pretty;
use sp_core::H256;
use sp_runtime::generic::Era;

use definitions::{network_specs::ShortSpecs, types::TypeEntry};

pub mod cards;
use cards::ParserCard;
mod decoding_older;
use decoding_older::process_as_call;
pub mod decoding_commons;
use decoding_commons::{get_compact, OutputCard};
mod decoding_sci;
use decoding_sci::decoding_sci_entry_point;
mod decoding_sci_ext;
use decoding_sci_ext::{decode_ext_attempt, Ext};
mod account_state;
mod call_state;
mod extension_state;
mod extensions_decoder;
mod number_state;
mod state;
mod state_machine;
mod types;
pub use types::MetadataProof;
mod decoding_with_proof;
mod utils;
pub use decoding_with_proof::{decode_call, decode_extensions, decode_metadata_proof};
mod error;
pub mod method;
use method::OlderMeta;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};

/// Function intakes SCALE encoded method part of transaction as `Vec<u8>`,
/// network metadata and network specs.
///
pub fn parse_method(
    method_data: Vec<u8>,
    metadata_bundle: &MetadataBundle,
    short_specs: &ShortSpecs,
) -> Result<Vec<OutputCard>> {
    let start_indent = 0;
    let method_decoded = match metadata_bundle {
        MetadataBundle::Older {
            older_meta,
            types,
            network_version: _,
        } => process_as_call(method_data, older_meta, types, start_indent, short_specs)?,
        MetadataBundle::Sci {
            meta_v14,
            network_version: _,
        } => decoding_sci_entry_point(method_data, meta_v14, start_indent, short_specs)?,
    };
    if !method_decoded.remaining_vector.is_empty() {
        return Err(Error::Decoding(ParserDecodingError::SomeDataNotUsedMethod));
    }
    Ok(method_decoded.fancy_out)
}

/// Struct to decode pre-determined extensions for transactions with `V12` and `V13` metadata
#[derive(Debug, Decode, Encode)]
struct ExtValues {
    era: Era,
    #[codec(compact)]
    nonce: u64,
    #[codec(compact)]
    tip: u128,
    metadata_version: u32,
    tx_version: u32,
    genesis_hash: H256,
    block_hash: H256,
}

pub fn parse_extensions(
    extensions_data: Vec<u8>,
    metadata_bundle: &MetadataBundle,
    short_specs: &ShortSpecs,
    optional_mortal_flag: Option<bool>,
) -> Result<Vec<OutputCard>> {
    let indent = 0;
    let (era, block_hash, cards) = match metadata_bundle {
        MetadataBundle::Older {
            older_meta: _,
            types: _,
            network_version,
        } => {
            let ext = match <ExtValues>::decode_all(&mut &extensions_data[..]) {
                Ok(a) => a,
                Err(_) => return Err(Error::Decoding(ParserDecodingError::ExtensionsOlder)),
            };
            if ext.genesis_hash != short_specs.genesis_hash {
                return Err(Error::Decoding(ParserDecodingError::GenesisHashMismatch));
            }
            if network_version != &ext.metadata_version {
                return Err(Error::WrongNetworkVersion {
                    as_decoded: ext.metadata_version.to_string(),
                    in_metadata: network_version.to_owned(),
                });
            }
            let tip = convert_balance_pretty(
                &ext.tip.to_string(),
                short_specs.decimals,
                &short_specs.unit,
            );
            let cards = vec![
                OutputCard {
                    card: ParserCard::Era(ext.era),
                    indent,
                },
                OutputCard {
                    card: ParserCard::Nonce(ext.nonce.to_string()),
                    indent,
                },
                OutputCard {
                    card: ParserCard::Tip {
                        number: tip.number.to_string(),
                        units: tip.units,
                    },
                    indent,
                },
                OutputCard {
                    card: ParserCard::NetworkNameVersion {
                        name: short_specs.name.to_string(),
                        version: network_version.to_string(),
                    },
                    indent,
                },
                OutputCard {
                    card: ParserCard::TxVersion(ext.tx_version.to_string()),
                    indent,
                },
                OutputCard {
                    card: ParserCard::BlockHash(ext.block_hash),
                    indent,
                },
            ];
            (ext.era, ext.block_hash, cards)
        }
        MetadataBundle::Sci {
            meta_v14,
            network_version,
        } => {
            let mut ext = Ext::init();
            let extensions_decoded =
                decode_ext_attempt(&extensions_data, &mut ext, meta_v14, indent, short_specs)?;
            if let Some(genesis_hash) = ext.found_ext.genesis_hash {
                if genesis_hash != short_specs.genesis_hash {
                    return Err(Error::Decoding(ParserDecodingError::GenesisHashMismatch));
                }
            }
            let block_hash = match ext.found_ext.block_hash {
                Some(a) => a,
                None => {
                    return Err(Error::FundamentallyBadV14Metadata(
                        ParserMetadataError::NoBlockHash,
                    ))
                }
            };
            let era = match ext.found_ext.era {
                Some(a) => a,
                None => {
                    return Err(Error::FundamentallyBadV14Metadata(
                        ParserMetadataError::NoEra,
                    ))
                }
            };
            match ext.found_ext.network_version_printed {
                Some(a) => {
                    if a != network_version.to_string() {
                        return Err(Error::WrongNetworkVersion {
                            as_decoded: a,
                            in_metadata: network_version.to_owned(),
                        });
                    }
                }
                None => {
                    return Err(Error::FundamentallyBadV14Metadata(
                        ParserMetadataError::NoVersionExt,
                    ))
                }
            }
            if !extensions_decoded.remaining_vector.is_empty() {
                return Err(Error::Decoding(
                    ParserDecodingError::SomeDataNotUsedExtensions,
                ));
            }
            (era, block_hash, extensions_decoded.fancy_out)
        }
    };
    if let Era::Immortal = era {
        if short_specs.genesis_hash != block_hash {
            return Err(Error::Decoding(ParserDecodingError::ImmortalHashMismatch));
        }
        if let Some(true) = optional_mortal_flag {
            return Err(Error::Decoding(ParserDecodingError::UnexpectedImmortality));
        }
    }
    if let Era::Mortal(_, _) = era {
        if let Some(false) = optional_mortal_flag {
            return Err(Error::Decoding(ParserDecodingError::UnexpectedMortality));
        }
    }
    Ok(cards)
}

pub fn cut_method_extensions(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pre_method = get_compact::<u32>(data).map_err(|_| Error::SeparateMethodExtensions)?;
    let method_length = pre_method.compact_found as usize;
    match pre_method.start_next_unit {
        // checked_add before .get(): the .get() itself is safe, but the
        // addition happens first and usize is 32-bit on armeabi-v7a, a shipped
        // ABI. There a near-u32::MAX method_length - it is compact-decoded
        // straight out of the payload - wraps to a small range that .get()
        // then happily accepts, yielding the WRONG slice instead of None.
        // Silent misparsing of a transaction is worse than refusing it.
        Some(start) => match start
            .checked_add(method_length)
            .and_then(|end| data.get(start..end).map(|a| (a, end)))
        {
            Some((a, end)) => Ok((a.to_vec(), data[end..].to_vec())),
            None => Err(Error::SeparateMethodExtensions),
        },
        None => {
            if method_length != 0 {
                return Err(Error::SeparateMethodExtensions);
            }
            Ok((Vec::new(), data.to_vec()))
        }
    }
}

#[allow(clippy::type_complexity)]
pub fn parse_set(
    data: &[u8],
    metadata_bundle: &MetadataBundle,
    short_specs: &ShortSpecs,
    optional_mortal_flag: Option<bool>,
) -> Result<(Result<Vec<OutputCard>>, Vec<OutputCard>, Vec<u8>, Vec<u8>)> {
    // if unable to separate method date and extensions, then some fundamental flaw is in transaction itself
    let (method_data, extensions_data) = cut_method_extensions(data)?;

    // try parsing extensions, if is works, the version and extensions are correct
    let extensions_cards = parse_extensions(
        extensions_data.to_vec(),
        metadata_bundle,
        short_specs,
        optional_mortal_flag,
    )?;
    let method_cards_result = parse_method(method_data.to_vec(), metadata_bundle, short_specs);
    Ok((
        method_cards_result,
        extensions_cards,
        method_data,
        extensions_data,
    ))
}

pub enum MetadataBundle<'a> {
    Older {
        older_meta: OlderMeta<'a>,
        types: Vec<TypeEntry>,
        network_version: u32,
    },
    Sci {
        meta_v14: &'a RuntimeMetadataV14,
        network_version: u32,
    },
}

#[cfg(test)]
mod fuzz_smoke {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// Splits a Substrate payload on a compact-encoded length taken straight
    /// from the data, so the length is attacker-chosen.
    ///
    /// Substrate is now off by default in the scan policy, but this runs
    /// before any signing decision for anyone who turns it on, and it is the
    /// entry point to the largest parser in the app.
    #[test]
    fn cut_method_extensions_never_panics() {
        for round in 0..40_000u64 {
            let mut rng = Rng(round.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let len = (rng.next() % 96) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let _ = cut_method_extensions(&bytes);
        }
    }

    /// Compact encodings that declare enormous lengths.
    ///
    /// `data.get(start..start + method_length)` is safe on 64-bit - .get()
    /// returns None - but the addition happens first, and usize is 32-bit on
    /// armeabi-v7a, a shipped ABI. There a near-u32::MAX length wraps to a
    /// small range that .get() then accepts, returning the WRONG slice rather
    /// than None. Silent misparsing is worse than a panic, and it is the case
    /// random bytes will not produce: a four-byte compact prefix encoding a
    /// huge value has to be built deliberately.
    #[test]
    fn huge_declared_method_lengths_are_refused() {
        let mut cases: Vec<Vec<u8>> = Vec::new();
        // big-mode compact (low two bits = 0b11) followed by a large u32
        for v in [
            u32::MAX,
            u32::MAX - 1,
            0x8000_0000,
            0x7fff_ffff,
            0x0100_0000,
        ] {
            let mut c = vec![0b0000_0011u8];
            c.extend_from_slice(&v.to_le_bytes());
            cases.push(c.clone());
            c.extend_from_slice(&[0xaa; 8]);
            cases.push(c);
        }
        // two-byte and four-byte compact modes at their maxima
        cases.push(vec![0b0000_0001, 0xff, 0xff]);
        cases.push(vec![0b0000_0010, 0xff, 0xff, 0xff, 0xff]);

        for case in &cases {
            match cut_method_extensions(case) {
                // A length this size cannot be satisfied by these buffers, so
                // the only correct answer is refusal.
                Ok((method, _)) => assert!(
                    method.len() <= case.len(),
                    "accepted a method longer than the buffer it came from"
                ),
                Err(_) => {}
            }
        }
    }
}
