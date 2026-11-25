//! Utils to communicate with the Vault frontend
use bip39::{Language, Mnemonic};
use definitions::helpers::IdenticonStyle;
use hex;
use sp_core::{sr25519, Pair};
use sp_runtime::MultiSigner;
use std::collections::{HashMap, HashSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

use constants::MAX_WORDS_DISPLAY;
use definitions::navigation::{Identicon, MAddressCard, MKeyAndNetworkCard, MKeysNew, QrData};
use definitions::{
    crypto::Encryption,
    helpers::{
        make_identicon_from_multisigner, multisigner_to_public,
        print_multisigner_as_base58_or_eth_address,
    },
    keyring::{AddressKey, NetworkSpecsKey},
    navigation::{
        Address, DerivationCheck as NavDerivationCheck, DerivationDestination, MKeyDetails,
        MKeysCard, MMNetwork, MNewSeedBackup, MSCNetworkInfo, SeedNameCard,
    },
    users::AddressDetails,
};

use crate::helpers::{get_address_details, get_all_networks, get_network_specs};
use crate::identities::{
    derivation_check, generate_random_phrase, get_addresses_by_seed_name, get_all_addresses,
    DerivationCheck,
};
use crate::{Error, Result};

/// Get display address for a multisigner - checks for stored addresses first
fn get_display_address(
    database: &sled::Db,
    multisigner: &MultiSigner,
    optional_prefix: Option<u16>,
    encryption: Encryption,
    network_name: Option<&str>,
) -> String {
    // For Penumbra, try to get the stored bech32m address
    // Never fall back to another encoding: a key added before zigner#35 shows
    // no address until it is derived again with the seed.
    if encryption == Encryption::Penumbra {
        let key_id_hex = hex::encode(multisigner_to_public(multisigner));
        return crate::penumbra::get_penumbra_address(database, &key_id_hex)
            .ok()
            .flatten()
            .unwrap_or_default();
    }
    // For Zcash, try to get the stored unified address (u1...)
    #[cfg(feature = "zcash")]
    if encryption == Encryption::Zcash {
        let pubkey_hex = hex::encode(multisigner_to_public(multisigner));
        if let Ok(Some(address)) = crate::zcash::get_zcash_address(database, &pubkey_hex) {
            return address;
        }
    }
    // For Cosmos, compute bech32 address on-the-fly from pubkey + chain prefix
    #[cfg(feature = "cosmos")]
    if encryption == Encryption::Cosmos {
        let pubkey_bytes = multisigner_to_public(multisigner);
        if let Ok(address) =
            crate::cosmos::pubkey_to_bech32_address(&pubkey_bytes, network_name.unwrap_or("cosmos"))
        {
            return address;
        }
    }
    // Fall back to default display
    print_multisigner_as_base58_or_eth_address(multisigner, optional_prefix, encryption)
}

/// Return a `Vec` with all seed names with seed key identicons if seed key is
/// available.
///
/// Function processes all seeds known to Vault KMS (which are input as
/// `&[String]`), including seeds without any corresponding addresses currently
/// known to Vault (orphans).
///
/// If the same seed has more than one seed key in the database, i.e. it has
/// been used to create seed keys with more than one
/// [`Encryption`] algorithm, only one
/// identicon is selected, in order of preference: `Sr25519`, `Ed25519`,
/// `Ecdsa`.
pub fn get_all_seed_names_with_identicons(
    database: &sled::Db,
    names_phone_knows: &[String],
) -> Result<Vec<SeedNameCard>> {
    let mut data_set: HashMap<String, Identicon> = HashMap::new();
    let mut derivation_count: HashMap<String, u32> = HashMap::new();
    let mut used_in_networks: HashMap<String, HashSet<String>> = HashMap::new();
    let mut network_names_cache: HashMap<NetworkSpecsKey, String> = HashMap::new();

    for (multisigner, address_details) in get_all_addresses(database)?.into_iter() {
        if address_details.is_root() {
            let identicon =
                make_identicon_from_multisigner(&multisigner, address_details.identicon_style());
            data_set.insert(address_details.seed_name.to_string(), identicon);
        } else {
            if let Some(network) = address_details.network_id {
                if !network_names_cache.contains_key(&network) {
                    let name = get_network_specs(database, &network)?.specs.name;
                    network_names_cache.insert(network.clone(), name);
                }
                if let Some(name) = network_names_cache.get(&network) {
                    used_in_networks
                        .entry(address_details.seed_name.to_string())
                        .or_default()
                        .insert(name.to_string());
                }
            }

            derivation_count
                .entry(address_details.seed_name.to_string())
                .and_modify(|e| *e += 1)
                .or_insert(1);
            if !data_set.contains_key(&address_details.seed_name) {
                data_set.insert(address_details.seed_name.to_string(), Identicon::default());
            }
        }
    }
    for x in names_phone_knows.iter() {
        if !data_set.contains_key(x) {
            data_set.insert(x.to_string(), Identicon::default());
        }
    }
    let mut res: Vec<_> = data_set
        .into_iter()
        .map(|(seed_name, identicon)| {
            let mut used_in_networks = used_in_networks
                .get(&seed_name)
                .cloned()
                .map(|hs| hs.into_iter().collect())
                .unwrap_or_else(Vec::new);
            used_in_networks.sort();
            SeedNameCard {
                seed_name: seed_name.clone(),
                identicon,
                derived_keys_count: *derivation_count.get(&seed_name).unwrap_or(&0),
                used_in_networks,
            }
        })
        .collect();
    res.sort_by(|a, b| a.seed_name.cmp(&b.seed_name));
    Ok(res)
}

pub fn keys_by_seed_name(database: &sled::Db, seed_name: &str) -> Result<MKeysNew> {
    let (root, derived): (Vec<_>, Vec<_>) = get_addresses_by_seed_name(database, seed_name)?
        .into_iter()
        .partition(|(_, address)| address.is_root());

    let root = root.first().map(|root| {
        let address = Address {
            has_pwd: false,
            path: String::new(),
            seed_name: seed_name.to_string(),
            identicon: make_identicon_from_multisigner(&root.0, root.1.identicon_style()),
            secret_exposed: root.1.secret_exposed,
        };
        // TODO: root always prefix 42 for substrate.
        let address_key = hex::encode(AddressKey::new(root.0.clone(), None).key());
        MAddressCard {
            base58: get_display_address(database, &root.0, None, root.1.encryption, None),
            address_key,
            address,
        }
    });

    let mut set = vec![];
    for (multisigner, address_details) in derived.into_iter() {
        if let Some(id) = &address_details.network_id {
            let network_specs = get_network_specs(database, id)?;

            let identicon =
                make_identicon_from_multisigner(&multisigner, address_details.identicon_style());
            let base58 = get_display_address(
                database,
                &multisigner,
                Some(network_specs.specs.base58prefix),
                network_specs.specs.encryption,
                Some(&network_specs.specs.name),
            );
            let address_key = hex::encode(
                AddressKey::new(multisigner.clone(), Some(network_specs.specs.genesis_hash)).key(),
            );
            let address = Address {
                path: address_details.path,
                has_pwd: address_details.has_pwd,
                identicon,
                secret_exposed: address_details.secret_exposed,
                seed_name: seed_name.to_owned(),
            };
            let key = MKeysCard {
                address,
                base58,
                address_key,
                swiped: false,
            };
            let network_specs_key = NetworkSpecsKey::from_parts(
                &network_specs.specs.genesis_hash,
                &network_specs.specs.encryption,
            );
            let network = MSCNetworkInfo {
                network_title: network_specs.specs.name,
                network_logo: network_specs.specs.logo,
                network_specs_key: hex::encode(network_specs_key.key()),
            };

            set.push(MKeyAndNetworkCard { key, network })
        }
    }

    Ok(MKeysNew { root, set })
}

/// Get address-associated public data for all addresses from the Vault
/// database with given seed name and network [`NetworkSpecsKey`].
pub fn addresses_set_seed_name_network(
    database: &sled::Db,
    seed_name: &str,
    network_specs_key: &NetworkSpecsKey,
) -> Result<Vec<(MultiSigner, AddressDetails)>> {
    Ok(get_addresses_by_seed_name(database, seed_name)?
        .into_iter()
        .filter(|(_, address_details)| {
            address_details.network_id.as_ref() == Some(network_specs_key)
        })
        .collect())
}

/// Make `Vec` with network information for all networks in the Vault database,
/// without any selection.
pub fn show_all_networks(database: &sled::Db) -> Result<Vec<MMNetwork>> {
    let networks = get_all_networks(database)?;
    let mut networks = networks
        .into_iter()
        .map(|n| MMNetwork {
            key: hex::encode(
                NetworkSpecsKey::from_parts(&n.specs.genesis_hash, &n.specs.encryption).key(),
            ),
            title: n.specs.name,
            logo: n.specs.logo,
            order: n.order,
            path_id: n.specs.path_id,
        })
        .collect::<Vec<_>>();
    networks.sort_by_key(|a| a.order);

    Ok(networks)
}

/// Prepare export key screen struct [`MKeyDetails`].
///
/// For QR code the address information is put in format
/// `substrate:{address as base58}:0x{network genesis hash}`
/// `ethereum:{address as hex}:0x{network genesis hash}`
/// `cosmos:`, `zcash:` and `penumbra:` wrap the chain's own address string.
/// transformed into bytes, to be compatible with `polkadot-js` interface.
/// Note that no [`Encryption`] algorithm
/// information is contained in the QR code. If there are multiple `Encryption`
/// algorithms supported by the network, the only visible difference in exports
/// would be the identicon.
pub fn export_key(
    database: &sled::Db,
    multisigner: &MultiSigner,
    expected_seed_name: &str,
    network_specs_key: &NetworkSpecsKey,
) -> Result<MKeyDetails> {
    let ordered_network_specs = get_network_specs(database, network_specs_key)?;
    let network_specs = ordered_network_specs.specs;
    let address_key = AddressKey::new(multisigner.clone(), Some(network_specs.genesis_hash));
    let address_details = get_address_details(database, &address_key);
    let address_details = if address_details.is_err() {
        let address_key = AddressKey::new(multisigner.clone(), None);
        get_address_details(database, &address_key)
    } else {
        address_details
    };

    let address_details = address_details?;

    if address_details.seed_name != expected_seed_name {
        return Err(Error::SeedNameNotMatching {
            address_key,
            expected_seed_name: expected_seed_name.to_string(),
            real_seed_name: address_details.seed_name,
        });
    }
    let base58 = get_display_address(
        database,
        multisigner,
        Some(network_specs.base58prefix),
        network_specs.encryption,
        Some(&network_specs.name),
    );

    let public_key = multisigner_to_public(multisigner);
    // a Penumbra key with no address yet gets no address QR
    let no_address = network_specs.encryption == Encryption::Penumbra && base58.is_empty();
    let identicon = make_identicon_from_multisigner(multisigner, address_details.identicon_style());
    let qr = {
        if address_details.network_id.as_ref() == Some(network_specs_key) {
            let prefix = if network_specs.encryption == Encryption::Ethereum {
                "ethereum"
            } else if network_specs.encryption == Encryption::Cosmos {
                "cosmos"
            } else if network_specs.encryption == Encryption::Zcash {
                "zcash"
            } else if network_specs.encryption == Encryption::Penumbra {
                "penumbra"
            } else {
                "substrate"
            };

            QrData::Regular {
                data: if no_address {
                    Vec::new()
                } else {
                    format!(
                        "{}:{}:0x{}",
                        prefix,
                        base58,
                        hex::encode(network_specs.genesis_hash)
                    )
                    .as_bytes()
                    .to_vec()
                },
            }
        } else {
            return Err(Error::NetworkSpecsKeyForAddressNotFound {
                network_specs_key: network_specs_key.to_owned(),
                address_key,
            });
        }
    };
    let address = Address {
        path: address_details.path,
        has_pwd: address_details.has_pwd,
        identicon,
        seed_name: address_details.seed_name,
        secret_exposed: address_details.secret_exposed,
    };

    let network_info = MSCNetworkInfo {
        network_title: network_specs.name,
        network_logo: network_specs.logo,
        network_specs_key: hex::encode(network_specs_key.key()),
    };

    Ok(MKeyDetails {
        qr,
        pubkey: hex::encode(public_key),
        network_info,
        base58,
        address,
    })
}

/// Return [`NavDerivationCheck`] with allowed action details for new key derivation.
///
/// Function is used to dynamically check from the frontend if user is allowed
/// to proceed with the proposed derived key generation.
///
/// User is allowed to try to proceed only if the derivation is valid and, in
/// case of derivations without password, if the derivation does not already
/// exist in the database. Passworded valid derivations are allowed to proceed,
/// but result in an error later on, if the derivation exists.
///
/// Function makes only preliminary check on password-free derivations, it
/// **does not** use seed phrase and does not calculate the [`AddressKey`], i.e.
/// it can't check passworded derivations, and allows them to proceed anyway.
pub fn dynamic_path_check(
    database: &sled::Db,
    seed_name: &str,
    path: &str,
    network_specs_key_hex: &str,
) -> NavDerivationCheck {
    match NetworkSpecsKey::from_hex(network_specs_key_hex) {
        Ok(key) => dynamic_path_check_unhexed(database, seed_name, path, &key),
        Err(e) => NavDerivationCheck {
            error: Some(e.to_string()),
            ..Default::default()
        },
    }
}

fn dynamic_path_check_unhexed(
    database: &sled::Db,
    seed_name: &str,
    path: &str,
    network_specs_key: &NetworkSpecsKey,
) -> NavDerivationCheck {
    match get_network_specs(database, network_specs_key) {
        Ok(ordered_network_specs) => {
            match derivation_check(database, seed_name, path, network_specs_key) {
                Ok(DerivationCheck::BadFormat) => NavDerivationCheck {
                    button_good: false,
                    ..Default::default()
                },
                Ok(DerivationCheck::Password) => NavDerivationCheck {
                    button_good: true,
                    where_to: Some(DerivationDestination::Pwd),
                    ..Default::default()
                },
                Ok(DerivationCheck::NoPassword(None)) => NavDerivationCheck {
                    button_good: true,
                    where_to: Some(DerivationDestination::Pin),
                    ..Default::default()
                },
                Ok(DerivationCheck::NoPassword(Some((multisigner, address_details)))) => {
                    let address_base58 = get_display_address(
                        database,
                        &multisigner,
                        Some(ordered_network_specs.specs.base58prefix),
                        address_details.encryption,
                        Some(&ordered_network_specs.specs.name),
                    );
                    let identicon = make_identicon_from_multisigner(
                        &multisigner,
                        address_details.identicon_style(),
                    );
                    let address_key = hex::encode(
                        AddressKey::new(
                            multisigner,
                            Some(ordered_network_specs.specs.genesis_hash),
                        )
                        .key(),
                    );
                    let collision_display = MAddressCard {
                        base58: address_base58,
                        address_key,
                        address: Address {
                            path: address_details.path,
                            has_pwd: address_details.has_pwd,
                            identicon,
                            seed_name: seed_name.to_string(),
                            secret_exposed: address_details.secret_exposed,
                        },
                    };
                    NavDerivationCheck {
                        button_good: false,
                        collision: Some(collision_display),
                        ..Default::default()
                    }
                }
                Err(e) => NavDerivationCheck {
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            }
        }
        Err(e) => NavDerivationCheck {
            error: Some(e.to_string()),
            ..Default::default()
        },
    }
}

/// Generate new random seed phrase, make identicon for `sr25519` public key,
/// and send to Vault screen.
pub fn print_new_seed(seed_name: &str) -> Result<MNewSeedBackup> {
    let seed_phrase = generate_random_phrase(24)?;
    let sr25519_pair =
        sr25519::Pair::from_string(&seed_phrase, None).map_err(Error::SecretStringError)?;
    let identicon = make_identicon_from_multisigner(
        &MultiSigner::Sr25519(sr25519_pair.public()),
        IdenticonStyle::Dots,
    );
    Ok(MNewSeedBackup {
        seed: seed_name.to_string(),
        seed_phrase,
        identicon,
    })
}

/// Get possible options of English `bip39` words that start with user-entered
/// word part.
///
/// List length limit is [`MAX_WORDS_DISPLAY`].
pub fn guess(word_part: &str) -> Vec<&'static str> {
    let dictionary = Language::English.wordlist();
    let words = dictionary.get_words_by_prefix(word_part);
    if words.len() > MAX_WORDS_DISPLAY {
        words[..MAX_WORDS_DISPLAY].to_vec()
    } else {
        words.to_vec()
    }
}

/// Maximum word count in `bip39` standard.
///
/// See <https://docs.rs/tiny-bip39/0.8.2/src/bip39/mnemonic_type.rs.html#60>
pub const BIP_CAP: usize = 24;

/// Maximum word length in `bip39` standard.
pub const WORD_LENGTH: usize = 8;

/// Zeroizeable seed phrase draft.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SeedDraft {
    /// User-entered word part.
    user_input: String,

    /// Already completed `bip39` words.
    saved: Vec<SeedElement>,
}

/// Zeroizeable wrapper around complete `bip39` word entered by user.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct SeedElement(String);

impl SeedElement {
    /// Make `SeedElement` from checked `bip39` word.
    fn from_checked_str(word: &str) -> Self {
        let mut new = String::with_capacity(WORD_LENGTH);
        new.push_str(word);
        SeedElement(new)
    }

    /// Get `bip39` word from the `SeedElement`.
    fn word(&self) -> &str {
        &self.0
    }
}

impl SeedDraft {
    /// Start new `SeedDraft`
    pub fn initiate() -> Self {
        Self {
            user_input: String::with_capacity(WORD_LENGTH), // capacity corresponds to maximum word length in `bip39` standard;
            saved: Vec::with_capacity(BIP_CAP), // capacity corresponds to maximum word count in `bip39` standard; set here to avoid reallocation;
        }
    }

    /// Modify `SeedDraft` with updated `user_text` from the frontend.
    ///
    /// Note that `user_text` input by default starts with ' ' (space). If user
    /// removes this space, it results in removing whole previous word.
    pub fn text_field_update(&mut self, user_text: &str) {
        if self.saved.len() <= BIP_CAP {
            if user_text.is_empty() {
                // user has removed all text, including the first default symbol
                // if there are words in draft, remove the last one
                self.remove_last();
                // restore the user input to empty one
                self.user_input.clear();
            } else {
                let user_text = user_text.trim_start();

                // ' ' (space) in the end of the word indicates user attempt to
                // submit the word into seed phrase
                if user_text.ends_with(' ') {
                    let word = user_text.trim();
                    if self.added(word, None) {
                        self.user_input.clear() // added the word successfully, clear `user_input`
                    } else if !guess(word).is_empty() {
                        self.user_input = String::from(word) // did not add the word, there are still possible variants, keep trimmed `user_input`
                    }
                } else if !guess(user_text).is_empty() {
                    self.user_input = String::from(user_text)
                }
            }
        } else {
            self.user_input.clear()
        }
    }

    /// User tries to add the word to the `saved` field of the `SeedDraft`.
    /// Output is `true` if addition happens. `SeedDraft` gets modified in the
    /// process.
    ///
    /// Optional `position` input could be used to mark the position in seed
    /// phrase to add the word to.
    pub fn added(&mut self, word: &str, position: Option<u32>) -> bool {
        // maximum number of the words is not reached
        if self.saved.len() < BIP_CAP {
            let guesses = guess(word);
            let definitive_guess = {
                if guesses.len() == 1 {
                    Some(guesses[0]) // only one possible variant
                } else if guesses.contains(&word) {
                    Some(word) // exactly matching variant
                } else {
                    None // no definitive match, no addition
                }
            };
            if let Some(guess) = definitive_guess {
                let new = SeedElement::from_checked_str(guess);
                match position {
                    Some(p) => {
                        let p = p as usize;
                        if p <= self.saved.len() {
                            self.saved.insert(p, new) // position is reasonable, use it
                        } else {
                            self.saved.push(new) // position is **not** reasonable, add word at the end of the list
                        }
                    }
                    None => self.saved.push(new), // no position, add word at the end of the list
                }
                self.user_input.clear();
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Remove word at given position from the saved seed phrase draft.
    pub fn remove(&mut self, position: u32) {
        let position = position as usize;
        if position < self.saved.len() {
            self.saved.remove(position);
        }
    }

    /// Remove last word from the saved seed phrase draft.
    pub fn remove_last(&mut self) {
        if !self.saved.is_empty() {
            self.saved.remove(self.saved.len() - 1);
        }
    }

    /// Make a `String` with a seed phrase draft.
    ///
    /// Returned string contains a secret and should be handled as such.
    pub fn draft(&self) -> Vec<String> {
        self.saved.iter().map(|w| w.word().to_string()).collect()
    }

    /// Combines all draft elements into seed phrase proposal,
    /// and checks its validity.
    /// If valid, outputs secret seed phrase.
    pub fn try_finalize(&self) -> Option<String> {
        let mut seed_phrase_proposal = String::with_capacity((WORD_LENGTH + 1) * BIP_CAP);
        for (i, x) in self.saved.iter().enumerate() {
            if i > 0 {
                seed_phrase_proposal.push(' ');
            }
            seed_phrase_proposal.push_str(x.word());
        }
        if Mnemonic::validate(&seed_phrase_proposal, Language::English).is_ok() {
            Some(seed_phrase_proposal)
        } else {
            seed_phrase_proposal.zeroize();
            None
        }
    }

    /// Output the user input back into user interface.
    pub fn user_input(&self) -> &str {
        &self.user_input
    }
}
