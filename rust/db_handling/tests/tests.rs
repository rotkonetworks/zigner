use constants::test_values::alice_ethereum_polkadot;
use parity_scale_codec::Encode;
use pretty_assertions::{assert_eq, assert_ne};
use sled::{Batch, Tree};
use sp_core::ecdsa::Public as EcdsaPublic;
use sp_core::sr25519::Public;
use sp_core::H256;
use sp_runtime::MultiSigner;
use std::{convert::TryInto, str::FromStr};

use constants::{
    test_values::{alice_sr_alice, empty_png},
    ADDRTREE, ALICE_SEED_PHRASE, SCHEMA_VERSION, SPECSTREE,
};
use db_handling::Error;
use definitions::{
    crypto::Encryption,
    history::{
        all_events_preview, Entry, Event, IdentityHistory, MetaValuesDisplay, MetaValuesExport,
        NetworkSpecsDisplay, NetworkSpecsExport, NetworkVerifierDisplay, SignDisplay,
        SignMessageDisplay, TypesDisplay, TypesExport,
    },
    keyring::{AddressKey, NetworkSpecsKey},
    navigation::{
        Address, DerivationCheck as NavDerivationCheck, DerivationDestination, Identicon,
        MKeyDetails, MMNetwork, MSCNetworkInfo, NetworkSpecs, SeedNameCard,
    },
    network_specs::{OrderedNetworkSpecs, ValidCurrentVerifier, Verifier, VerifierValue},
    users::AddressDetails,
};

use db_handling::identities::{
    create_key_set, generate_test_identities, get_all_addresses, validate_key_password,
};
use db_handling::{
    cold_default::{default_chainspecs as zigner_chainspecs, init_db},
    db_transactions::TrDbCold,
    default_cold_release,
    helpers::{get_danger_status, open_tree},
    identities::{
        create_increment_set, derivation_check, export_secret_key, get_addresses_by_seed_name,
        remove_key, remove_seed, try_create_address, try_create_seed, DerivationCheck,
    },
    interface_signer::{
        addresses_set_seed_name_network, dynamic_path_check, export_key,
        get_all_seed_names_with_identicons, show_all_networks,
    },
    manage_history::{
        device_was_online, enter_events, get_history, get_history_entry_by_order,
        reset_danger_status_to_safe,
    },
};
use definitions::helpers::multisigner_to_public;
use definitions::navigation::MAddressCard;

use db_handling::helpers::assert_db_version;
use tempfile::tempdir;

// Zigner no longer ships Substrate networks, but keys on them stay in the
// identity layer and are what most of these tests derive. The test databases
// below are the shipped defaults plus the three networks 0.12 shipped with
// (and Mythos, for an Ethereum-encryption network).

#[allow(clippy::too_many_arguments)]
fn substrate_specs(
    name: &str,
    title: &str,
    unit: &str,
    base58prefix: u16,
    decimals: u8,
    color: &str,
    genesis_hash: &str,
    encryption: Encryption,
    order: u8,
) -> OrderedNetworkSpecs {
    OrderedNetworkSpecs {
        specs: NetworkSpecs {
            base58prefix,
            color: color.to_string(),
            decimals,
            encryption,
            genesis_hash: H256::from_str(genesis_hash).unwrap(),
            logo: name.to_string(),
            name: name.to_string(),
            path_id: format!("//{name}"),
            secondary_color: String::from("#262626"),
            title: title.to_string(),
            unit: unit.to_string(),
        },
        order,
    }
}

/// The shipped default networks plus Kusama, Polkadot and Westend, in the
/// order 0.12 listed them.
fn default_chainspecs() -> Vec<OrderedNetworkSpecs> {
    let mut out = vec![
        substrate_specs(
            "kusama",
            "Kusama",
            "KSM",
            2,
            12,
            "#000",
            "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
            Encryption::Sr25519,
            0,
        ),
        substrate_specs(
            "polkadot",
            "Polkadot",
            "DOT",
            0,
            10,
            "#E6027A",
            "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            Encryption::Sr25519,
            1,
        ),
        substrate_specs(
            "westend",
            "Westend",
            "WND",
            42,
            12,
            "#660D35",
            "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
            Encryption::Sr25519,
            2,
        ),
    ];
    out.extend(zigner_chainspecs());
    out
}

fn write_specs(db: &sled::Db, specs: &[OrderedNetworkSpecs]) {
    let tree = db.open_tree(SPECSTREE).unwrap();
    for x in specs {
        let key = NetworkSpecsKey::from_parts(&x.specs.genesis_hash, &x.specs.encryption);
        tree.insert(key.key(), x.encode()).unwrap();
    }
}

/// Initiated database with the networks of [`default_chainspecs`], no keys.
fn populate_cold_no_metadata(db: &sled::Db, _verifier: Verifier) -> Result<(), Error> {
    default_cold_release(Some(db))?;
    write_specs(db, &default_chainspecs());
    init_db(db)
}

/// As [`populate_cold_no_metadata`], with Alice's test keys.
fn populate_cold(db: &sled::Db, verifier: Verifier) -> Result<(), Error> {
    populate_cold_no_metadata(db, verifier)?;
    generate_test_identities(db)
}

/// Not initiated database with the networks of [`default_chainspecs`] and
/// Mythos.
fn populate_all_network_specs(db: &sled::Db) -> Result<(), Error> {
    default_cold_release(Some(db))?;
    let mut specs = default_chainspecs();
    let order = specs.iter().map(|x| x.order).max().unwrap() + 1;
    specs.push(substrate_specs(
        "mythos",
        "Mythos",
        "MYTH",
        29972,
        18,
        "#262528",
        "f6ee56e9c5277df5b4ce6ae9983ee88f3cbed27d31beeb98f9f84f997a1ab0b9",
        Encryption::Ethereum,
        order,
    ));
    write_specs(db, &specs);
    Ok(())
}

fn westend_genesis() -> H256 {
    H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap()
}

fn mythos_genesis() -> H256 {
    H256::from_str("f6ee56e9c5277df5b4ce6ae9983ee88f3cbed27d31beeb98f9f84f997a1ab0b9").unwrap()
}

#[test]
fn print_seed_names() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let cards = get_all_seed_names_with_identicons(&db, &[String::from("Alice")]).unwrap();
    let expected_cards = vec![SeedNameCard {
        seed_name: "Alice".to_string(),
        identicon: Identicon::Jdenticon {
            identity: "8PegJD6VsjWwinrP6AfgNqejWYdJ8KqF4xutpyq7AdFJ3W5".to_string(),
        },
        used_in_networks: vec!["westend".to_string()],
        derived_keys_count: 1, // "//Alice"
    }];
    assert_eq!(cards, expected_cards);
}

#[test]
fn print_seed_names_with_orphan() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let cards =
        get_all_seed_names_with_identicons(&db, &[String::from("Alice"), String::from("BobGhost")])
            .unwrap();

    let expected_cards = vec![
        SeedNameCard {
            seed_name: "Alice".to_string(),
            identicon: Identicon::Jdenticon {
                identity: "8PegJD6VsjWwinrP6AfgNqejWYdJ8KqF4xutpyq7AdFJ3W5".to_string(),
            },
            used_in_networks: vec!["westend".to_string()],
            derived_keys_count: 1,
        },
        SeedNameCard {
            seed_name: "BobGhost".to_string(),
            identicon: Identicon::Dots {
                identity: empty_png(),
            },
            used_in_networks: vec![],
            derived_keys_count: 0,
        },
    ];
    assert_eq!(cards, expected_cards);
}

#[test]
fn show_all_networks_no_flag() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let networks = show_all_networks(&db).unwrap();
    let expected_networks = vec![
        MMNetwork {
            key: "01b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe".to_string(),
            title: "kusama".to_string(),
            logo: "kusama".to_string(),
            order: 0,
            path_id: "//kusama".to_string(),
        },
        MMNetwork {
            key: "0191b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3".to_string(),
            title: "polkadot".to_string(),
            logo: "polkadot".to_string(),
            order: 1,
            path_id: "//polkadot".to_string(),
        },
        MMNetwork {
            key: "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e".to_string(),
            title: "westend".to_string(),
            logo: "westend".to_string(),
            order: 2,
            path_id: "//westend".to_string(),
        },
        MMNetwork {
            key: "0500040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08".to_string(),
            title: "zcash".to_string(),
            logo: "zcash".to_string(),
            order: 3,
            path_id: "m/32'/133'/0'".to_string(),
        },
        MMNetwork {
            key: "040000000000000000000000000000000000000000000000000000000000006532".to_string(),
            title: "penumbra".to_string(),
            logo: "penumbra".to_string(),
            order: 4,
            path_id: "m/44'/6532'/0'".to_string(),
        },
        MMNetwork {
            key: "0700000000000000000000000000000000000000006f736d6f7369732d31000001".to_string(),
            title: "osmosis".to_string(),
            logo: "osmosis".to_string(),
            order: 5,
            path_id: "m/44'/118'/0'/0/0".to_string(),
        },
        MMNetwork {
            key: "07000000000000000000000000000000000000000000006e6f626c652d31000001".to_string(),
            title: "noble".to_string(),
            logo: "noble".to_string(),
            order: 6,
            path_id: "m/44'/118'/0'/0/0".to_string(),
        },
        MMNetwork {
            key: "070000000000000000000000000000000000000063656c65737469610000000001".to_string(),
            title: "celestia".to_string(),
            logo: "celestia".to_string(),
            order: 7,
            path_id: "m/44'/118'/0'/0/0".to_string(),
        },
        MMNetwork {
            key: "07000000000000000000000000000000000000636f736d6f736875622d34000001".to_string(),
            title: "cosmos".to_string(),
            logo: "cosmos".to_string(),
            order: 8,
            path_id: "m/44'/118'/0'/0/0".to_string(),
        },
        MMNetwork {
            key: "07000000000000000000000000000000000000000070686f656e69782d31000001".to_string(),
            title: "terra".to_string(),
            logo: "terra".to_string(),
            order: 9,
            path_id: "m/44'/330'/0'/0/0".to_string(),
        },
    ];
    assert_eq!(networks, expected_networks);
}

#[test]
fn export_alice_westend() {
    use definitions::navigation::Identicon;
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();

    let pubkey = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    let public: [u8; 32] = hex::decode(pubkey).unwrap().try_into().unwrap();
    let key = export_key(
        &db,
        &MultiSigner::Sr25519(Public::from_raw(public)),
        "Alice",
        &NetworkSpecsKey::from_parts(
            &H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e")
                .unwrap(),
            &Encryption::Sr25519,
        ),
    )
    .unwrap();

    let expected_addr = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    let westend_genesis = hex::encode(westend_genesis());
    // `subkey inspect "ALICE_SEED_PHRASE"`
    let expected_key = MKeyDetails {
        qr: definitions::navigation::QrData::Regular {
            data: format!("substrate:{expected_addr}:0x{westend_genesis}")
                .as_bytes()
                .to_vec(),
        },
        pubkey: pubkey.to_string(),
        base58: expected_addr.to_string(),
        address: Address {
            identicon: Identicon::Dots {
                identity: alice_sr_alice().to_vec(),
            },
            seed_name: "Alice".to_string(),
            path: "//Alice".to_string(),
            has_pwd: false,
            secret_exposed: false,
        },
        network_info: MSCNetworkInfo {
            network_title: "westend".to_string(),
            network_logo: "westend".to_string(),
            network_specs_key: "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                .to_string(),
        },
    };
    assert_eq!(key, expected_key);
}

#[test]
fn export_alice_mythos() {
    use definitions::navigation::Identicon;
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_all_network_specs(&db).unwrap();

    try_create_seed(&db, "Alice", ALICE_SEED_PHRASE, true).unwrap();

    let derivation_path = "//polkadot";
    let genesis = mythos_genesis();

    try_create_address(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        derivation_path,
        &NetworkSpecsKey::from_parts(&genesis, &Encryption::Ethereum),
    )
    .unwrap();

    let pubkey = "02c08517b1ff9501d42ab480ea6fa1b9b92f0430fb07e4a9575dbb2d5ec6edb6d6";
    let public: [u8; 33] = hex::decode(pubkey).unwrap().try_into().unwrap();
    let key = export_key(
        &db,
        &MultiSigner::Ecdsa(EcdsaPublic::from_raw(public)),
        "Alice",
        &NetworkSpecsKey::from_parts(&genesis, &Encryption::Ethereum),
    )
    .unwrap();

    let expected_addr = "0xe9267b732a8e9c9444e46f3d04d4610a996d682d";
    let hex_genesis = hex::encode(genesis);

    let expected_key = MKeyDetails {
        qr: definitions::navigation::QrData::Regular {
            data: format!("ethereum:{expected_addr}:0x{hex_genesis}")
                .as_bytes()
                .to_vec(),
        },
        pubkey: pubkey.to_string(),
        base58: expected_addr.to_string(),
        address: Address {
            identicon: Identicon::Blockies {
                identity: alice_ethereum_polkadot(),
            },
            seed_name: "Alice".to_string(),
            path: derivation_path.to_string(),
            has_pwd: false,
            secret_exposed: false,
        },
        network_info: MSCNetworkInfo {
            network_title: "mythos".to_string(),
            network_logo: "mythos".to_string(),
            network_specs_key: format!("03{hex_genesis}").to_string(),
        },
    };
    assert_eq!(key, expected_key);
}

#[test]
fn path_is_known() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let check = dynamic_path_check(
        &db,
        "Alice",
        "//Alice",
        "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
    );
    let expected_check = NavDerivationCheck {
        button_good: false,
        where_to: None,
        collision: Some(MAddressCard {
            address_key: concat!(
                "01d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
                "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
            )
            .to_string(),
            base58: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            address: Address {
                path: "//Alice".to_string(),
                has_pwd: false,
                identicon: Identicon::Dots {
                    identity: alice_sr_alice().to_vec(),
                },
                seed_name: "Alice".to_string(),
                secret_exposed: false,
            },
        }),
        error: None,
    };
    assert_eq!(check, expected_check);
}

#[test]
fn path_is_unknown() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let check = dynamic_path_check(
        &db,
        "Alice",
        "//secret",
        "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
    );
    let expected_check = NavDerivationCheck {
        button_good: true,
        where_to: Some(DerivationDestination::Pin),
        collision: None,
        error: None,
    };
    assert_eq!(check, expected_check);
}

#[test]
fn path_is_unknown_passworded() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let check = dynamic_path_check(
        &db,
        "Alice",
        "//secret///abracadabra",
        "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
    );
    let expected_check = NavDerivationCheck {
        button_good: true,
        where_to: Some(DerivationDestination::Pwd),
        collision: None,
        error: None,
    };
    assert_eq!(check, expected_check);
}

#[test]
fn get_danger_status_properly() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    default_cold_release(Some(&db)).unwrap();
    init_db(&db).unwrap();
    assert!(
        !get_danger_status(&db).unwrap(),
        "Expected danger status = false after the database initiation."
    );
    device_was_online(&db).unwrap();
    assert!(
        get_danger_status(&db).unwrap(),
        "Expected danger status = true after the reported exposure."
    );
    reset_danger_status_to_safe(&db).unwrap();
    assert!(
        !get_danger_status(&db).unwrap(),
        "Expected danger status = false after the danger reset."
    );
}

#[test]
fn test_generate_default_addresses_for_alice() {
    let dbname = tempdir().unwrap();
    let db = sled::open(&dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    try_create_seed(&db, "Alice", ALICE_SEED_PHRASE, true).unwrap();
    {
        let addresses = open_tree(&db, ADDRTREE).unwrap();
        assert_eq!(addresses.len(), 1);
    }
    let chainspecs = default_chainspecs();
    let default_addresses = addresses_set_seed_name_network(
        &db,
        "Alice",
        &NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519),
    )
    .unwrap();

    let expected_default_addresses = vec![];

    assert_eq!(default_addresses, expected_default_addresses);

    let identities: Tree = db.open_tree(ADDRTREE).unwrap();
    let test_key = AddressKey::from_parts(
        &hex::decode("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a").unwrap(),
        &Encryption::Sr25519,
        None,
    )
    .unwrap();
    assert!(identities.contains_key(test_key.key()).unwrap());
}

#[test]
fn test_derive() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let specs = default_chainspecs();
    println!(
        "[0]: {:?}, [1]: {:?}",
        specs[0].specs.name, specs[1].specs.name
    );
    let seed_name = "Alice";
    let network_id_0 =
        NetworkSpecsKey::from_parts(&specs[0].specs.genesis_hash, &specs[0].specs.encryption);
    let network_id_1 =
        NetworkSpecsKey::from_parts(&specs[1].specs.genesis_hash, &specs[1].specs.encryption);

    try_create_seed(&db, seed_name, ALICE_SEED_PHRASE, true).unwrap();
    try_create_address(&db, seed_name, ALICE_SEED_PHRASE, "//Alice", &network_id_0).unwrap();
    try_create_address(&db, seed_name, ALICE_SEED_PHRASE, "//Alice", &network_id_1).unwrap();
    try_create_address(
        &db,
        seed_name,
        ALICE_SEED_PHRASE,
        "//Alice/1",
        &network_id_0,
    )
    .unwrap();

    /*
    Since now only one key in one network, this is not needed.
    let _both_networks = vec![network_id_0.to_owned(), network_id_1];
    let _only_one_network = vec![network_id_0];


    let identities = get_addresses_by_seed_name(&db, seed_name).unwrap();
    println!("{:?}", identities);
    let mut flag0 = false;
    let mut flag1 = false;
    for (_, details) in identities {
        flag0 = flag0 || details.network_id == both_networks;
        flag1 = flag1 || details.network_id == only_one_network;
    }
    assert!(flag0, "Something is wrong with //Alice");
    assert!(flag1, "Something is wrong with //Alice/1");
    */
}

#[test]
fn test_identity_deletion() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    try_create_seed(&db, "Alice", ALICE_SEED_PHRASE, true).unwrap();
    let chainspecs = default_chainspecs();
    let network_specs_key_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    try_create_address(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        "//Alice",
        &network_specs_key_0,
    )
    .unwrap();
    // let network_specs_key_1 =
    //    NetworkSpecsKey::from_parts(&chainspecs[1].specs.genesis_hash, &Encryption::Sr25519);
    let mut identities = addresses_set_seed_name_network(&db, "Alice", &network_specs_key_0)
        .expect("Alice should have some addresses by default");
    println!("{identities:?}");
    //let (key0, _) = identities.remove(0); //TODO: this should be root key
    let (key1, _) = identities.remove(0); //TODO: this should be network-specific key
                                          //remove_key(&db, &key0, &network_specs_key_0).expect("delete an address");
    remove_key(&db, &key1, &network_specs_key_0).expect("delete another address");
    let identities = addresses_set_seed_name_network(&db, "Alice", &network_specs_key_0)
        .expect("Alice still should have some addresses after deletion of two");
    for (address_key, _) in identities {
        //assert_ne!(address_key, key0);
        assert_ne!(address_key, key1);
    }
}

#[test]
fn history_with_identities() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    default_cold_release(Some(&db)).unwrap();
    init_db(&db).unwrap();
    let history_printed = get_history(&db).unwrap();
    let element1 = Event::DatabaseInitiated;
    assert!(history_printed
        .iter()
        .any(|e| e.1.events.contains(&element1)));
    // No general verifier any more.
    assert!(!history_printed.iter().any(|e| e
        .1
        .events
        .iter()
        .any(|ev| matches!(ev, Event::GeneralVerifierSet { .. }))));
    try_create_seed(&db, "Alice", ALICE_SEED_PHRASE, true).unwrap();
    let history_printed_after_create_seed: Vec<_> =
        get_history(&db).unwrap().into_iter().map(|e| e.1).collect();

    let element3 = [Event::SeedCreated {
        seed_created: "Alice".to_string(),
    }];

    assert!(entries_contain_event(
        &history_printed_after_create_seed,
        &element1
    ));

    for (i, e) in element3.iter().enumerate() {
        assert!(
            entries_contain_event(&history_printed_after_create_seed, e),
            "{i}-th missing"
        );
    }
}

#[test]
fn remove_seed_history() {
    let seed_name = "Alice";
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    default_cold_release(Some(&db)).unwrap();

    try_create_seed(&db, seed_name, ALICE_SEED_PHRASE, true).unwrap();
    assert!(remove_seed(&db, "Wrong seed name").is_err());
    remove_seed(&db, seed_name).unwrap();

    let history_printed: Vec<_> = get_history(&db).unwrap().into_iter().map(|e| e.1).collect();
    assert!(entries_contain_event(
        &history_printed,
        &Event::SeedRemoved {
            seed_name: seed_name.to_string(),
        }
    ));
}

fn get_multisigner_path_set(database: &sled::Db) -> Vec<(MultiSigner, String)> {
    let identities = open_tree(database, ADDRTREE).unwrap();
    let mut multisigner_path_set: Vec<(MultiSigner, String)> = Vec::new();
    for a in identities.iter().flatten() {
        let (multisigner, address_details) = AddressDetails::process_entry_checked(a).unwrap();
        multisigner_path_set.push((multisigner, address_details.path.to_string()))
    }
    multisigner_path_set
}

#[test]
fn increment_identities_1() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    {
        let identities = open_tree(&db, ADDRTREE).unwrap();
        assert!(identities.is_empty());
    }
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0).unwrap();
    let multisigner_path_set = get_multisigner_path_set(&db);
    assert!(
        multisigner_path_set.len() == 1,
        "Wrong number of identities: {multisigner_path_set:?}"
    );
    println!("{}", multisigner_path_set[0].1);
    create_increment_set(
        &db,
        4,
        &multisigner_path_set[0].0,
        &network_id_0,
        ALICE_SEED_PHRASE,
    )
    .unwrap();
    let multisigner_path_set = get_multisigner_path_set(&db);
    assert!(
        multisigner_path_set.len() == 5,
        "Wrong number of identities after increment: {multisigner_path_set:?}"
    );
    let path_set: Vec<String> = multisigner_path_set
        .iter()
        .map(|(_, path)| path.to_string())
        .collect();
    assert!(path_set.contains(&String::from("//Alice//0")));
    assert!(path_set.contains(&String::from("//Alice//1")));
    assert!(path_set.contains(&String::from("//Alice//2")));
    assert!(path_set.contains(&String::from("//Alice//3")));
}

#[test]
fn increment_identities_2() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    {
        let identities = open_tree(&db, ADDRTREE).unwrap();
        assert!(identities.is_empty());
    }
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0).unwrap();
    try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice//1", &network_id_0).unwrap();
    let multisigner_path_set = get_multisigner_path_set(&db);
    let alice_multisigner_path = multisigner_path_set
        .iter()
        .find(|(_, path)| path == "//Alice")
        .unwrap();
    assert!(
        multisigner_path_set.len() == 2,
        "Wrong number of identities: {multisigner_path_set:?}"
    );
    create_increment_set(
        &db,
        3,
        &alice_multisigner_path.0,
        &network_id_0,
        ALICE_SEED_PHRASE,
    )
    .unwrap();
    let multisigner_path_set = get_multisigner_path_set(&db);
    assert!(
        multisigner_path_set.len() == 5,
        "Wrong number of identities after increment: {multisigner_path_set:?}"
    );
    let path_set: Vec<String> = multisigner_path_set
        .iter()
        .map(|(_, path)| path.to_string())
        .collect();
    assert!(path_set.contains(&String::from("//Alice//2")));
    assert!(path_set.contains(&String::from("//Alice//3")));
    assert!(path_set.contains(&String::from("//Alice//4")));
}

#[test]
fn increment_identities_3() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    {
        let identities = open_tree(&db, ADDRTREE).unwrap();
        assert!(identities.is_empty());
    }
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0).unwrap();
    try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice//1", &network_id_0).unwrap();
    let multisigner_path_set = get_multisigner_path_set(&db);
    let alice_multisigner_path = multisigner_path_set
        .iter()
        .find(|(_, path)| path == "//Alice//1")
        .unwrap();
    assert!(
        multisigner_path_set.len() == 2,
        "Wrong number of identities: {multisigner_path_set:?}"
    );
    create_increment_set(
        &db,
        3,
        &alice_multisigner_path.0,
        &network_id_0,
        ALICE_SEED_PHRASE,
    )
    .unwrap();
    let multisigner_path_set = get_multisigner_path_set(&db);
    assert!(
        multisigner_path_set.len() == 5,
        "Wrong number of identities after increment: {multisigner_path_set:?}"
    );
    let path_set: Vec<String> = multisigner_path_set
        .iter()
        .map(|(_, path)| path.to_string())
        .collect();
    assert!(path_set.contains(&String::from("//Alice//1//0")));
    assert!(path_set.contains(&String::from("//Alice//1//1")));
    assert!(path_set.contains(&String::from("//Alice//1//2")));
}

#[test]
fn creating_derivation_1() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    assert!(
        try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0,).is_ok(),
        "Should be able to create //Alice derivation."
    );
    if let DerivationCheck::NoPassword(Some(_)) =
        derivation_check(&db, "Alice", "//Alice", &network_id_0).unwrap()
    {
        println!("Found existing");
    } else {
        panic!("Derivation should already exist.");
    }
    match try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0) {
        Ok(()) => panic!("Should NOT be able to create //Alice derivation again."),
        Err(e) => {
            if let Error::DerivationExists {
                ref multisigner,
                ref address_details,
                ref network_specs_key,
            } = e
            {
                assert_eq!(address_details.seed_name, "Alice".to_string());

                assert_eq!(
                    hex::encode(multisigner.as_ref()),
                    "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string()
                );

                assert_eq!(
                    hex::encode(network_specs_key.key()),
                    "01b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe"
                        .to_string()
                );
            } else {
                panic!("expected Error::DerivationExists, got {e:?}");
            }
        }
    }
}

#[test]
fn creating_derivation_2() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    assert!(
        try_create_address(
            &db,
            "Alice",
            ALICE_SEED_PHRASE,
            "//Alice///secret",
            &network_id_0,
        )
        .is_ok(),
        "Should be able to create //Alice/// secret derivation."
    );
    if let DerivationCheck::NoPassword(None) =
        derivation_check(&db, "Alice", "//Alice", &network_id_0).unwrap()
    {
        println!("It did well.");
    } else {
        panic!(
            "New derivation has no password, existing derivation has password and is diffenent."
        );
    }
    assert!(
        try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0).is_ok(),
        "Should be able to create //Alice derivation."
    );
}

#[test]
fn creating_derivation_3() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    assert!(
        try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "//Alice", &network_id_0).is_ok(),
        "Should be able to create //Alice derivation."
    );
    if let DerivationCheck::Password =
        derivation_check(&db, "Alice", "//Alice///secret", &network_id_0).unwrap()
    {
        println!("It did well.");
    } else {
        panic!(
            "New derivation has password, existing derivation has no password and is diffenent."
        );
    }
    assert!(
        try_create_address(
            &db,
            "Alice",
            ALICE_SEED_PHRASE,
            "//Alice///secret",
            &network_id_0,
        )
        .is_ok(),
        "Should be able to create //Alice///secret derivation."
    );
}

#[test]
fn creating_derivation_4() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    assert!(
        try_create_address(
            &db,
            "Alice",
            ALICE_SEED_PHRASE,
            "//Alice///secret1",
            &network_id_0,
        )
        .is_ok(),
        "Should be able to create //Alice///secret1 derivation."
    );
    if let DerivationCheck::Password =
        derivation_check(&db, "Alice", "//Alice///secret2", &network_id_0).unwrap()
    {
        println!("It did well.");
    } else {
        panic!("Existing derivation has different password.");
    }
    assert!(
        try_create_address(
            &db,
            "Alice",
            ALICE_SEED_PHRASE,
            "//Alice///secret2",
            &network_id_0,
        )
        .is_ok(),
        "Should be able to create //Alice///secret2 derivation."
    );
}

#[test]
fn creating_derivation_5() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let chainspecs = default_chainspecs();
    let network_id_0 =
        NetworkSpecsKey::from_parts(&chainspecs[0].specs.genesis_hash, &Encryption::Sr25519);
    assert!(
        try_create_address(
            &db,
            "Alice",
            ALICE_SEED_PHRASE,
            "//Alice///secret",
            &network_id_0,
        )
        .is_ok(),
        "Should be able to create //Alice derivation."
    );
    if let DerivationCheck::Password =
        derivation_check(&db, "Alice", "//Alice///secret", &network_id_0).unwrap()
    {
        println!("It did well.");
    } else {
        panic!("Derivation exists, but has password.");
    }
    match try_create_address(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        "//Alice///secret",
        &network_id_0,
    ) {
        Ok(()) => panic!("Should NOT be able to create //Alice///secret derivation again."),
        Err(e) => {
            if let Error::DerivationExists {
                ref multisigner,
                ref address_details,
                ref network_specs_key,
            } = e
            {
                assert_eq!(address_details.seed_name, "Alice".to_string());

                assert_eq!(
                    hex::encode(multisigner.as_ref()),
                    "08a5e583f74f54f3811cb5f7d74e686d473e3a466fd0e95738707a80c3183b15".to_string(),
                );

                assert_eq!(
                    hex::encode(network_specs_key.key()),
                    "01b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe"
                        .to_string()
                );
            } else {
                panic!("expected Error::DerivationExists, got {e:?}");
            }
        }
    }
}

#[test]
fn test_all_events() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let events = all_events_preview();
    enter_events(&db, events).unwrap();
    let entries: Vec<_> = get_history(&db)
        .unwrap()
        .into_iter()
        .map(|(_, a)| a)
        .collect();

    assert!(entries_contain_event(
        &entries,
        &Event::MetadataAdded {
            meta_values_display: MetaValuesDisplay {
                name: "westend".to_string(),
                version: 9000,
                meta_hash: H256::from_str(
                    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
                )
                .unwrap()
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::MetadataRemoved {
            meta_values_display: MetaValuesDisplay {
                name: "westend".to_string(),
                version: 9000,
                meta_hash: H256::from_str(
                    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
                )
                .unwrap()
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::MetadataSigned {
            meta_values_export: MetaValuesExport {
                name: "westend".to_string(),
                version: 9000,
                meta_hash: H256::from_str(
                    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
                )
                .unwrap(),
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::NetworkSpecsAdded {
            network_specs_display: NetworkSpecsDisplay {
                network: OrderedNetworkSpecs {
                    specs: NetworkSpecs{
                    base58prefix: 42,
                    color: "#660D35".to_string(),
                    decimals: 12,
                    encryption: Encryption::Sr25519,
                    genesis_hash: H256::from_str(
                        "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                    )
                    .unwrap(),
                    logo: "westend".to_string(),
                    name: "westend".to_string(),
                    path_id: "//westend".to_string(),
                    secondary_color: "#262626".to_string(),
                    title: "Westend".to_string(),
                    unit: "WND".to_string(),},
                order:3,
                },
                valid_current_verifier: ValidCurrentVerifier::General,
                general_verifier: Verifier {
                    v: Some(
                           VerifierValue::Standard {
                                m: MultiSigner::Sr25519(
                                       Public::try_from(
                                           hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                       )
                                           .unwrap().as_ref()).unwrap())
                    })
                },
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::NetworkSpecsRemoved {
            network_specs_display: NetworkSpecsDisplay {
                network: OrderedNetworkSpecs {
                    specs: NetworkSpecs{
                    base58prefix: 42,
                    color: "#660D35".to_string(),
                    decimals: 12,
                    encryption: Encryption::Sr25519,
                    genesis_hash: H256::from_str(
                        "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                    )
                    .unwrap(),
                    logo: "westend".to_string(),
                    name: "westend".to_string(),
                    path_id: "//westend".to_string(),
                    secondary_color: "#262626".to_string(),
                    title: "Westend".to_string(),
                    unit: "WND".to_string(),},
                    order:3,
                },
                valid_current_verifier: ValidCurrentVerifier::General,
                general_verifier: Verifier {
                    v: Some(VerifierValue::Standard {
                        m: MultiSigner::Sr25519(Public::try_from(
                                   hex::decode(
"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                                   ).unwrap()
                                   .as_ref()
                           ).unwrap())
                    })
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::NetworkSpecsSigned {
            network_specs_export: NetworkSpecsExport {
                specs_to_send: NetworkSpecs {
                    base58prefix: 42,
                    color: "#660D35".to_string(),
                    decimals: 12,
                    encryption: Encryption::Sr25519,
                    genesis_hash: H256::from_str(
                        "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                    )
                    .unwrap(),
                    logo: "westend".to_string(),
                    name: "westend".to_string(),
                    path_id: "//westend".to_string(),
                    secondary_color: "#262626".to_string(),
                    title: "Westend".to_string(),
                    unit: "WND".to_string(),
                },
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::NetworkVerifierSet {
            network_verifier_display: NetworkVerifierDisplay {
                genesis_hash: H256::from_str(
                    "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                )
                .unwrap(),
                valid_current_verifier: ValidCurrentVerifier::General,
                general_verifier: Verifier {
                    v: Some(VerifierValue::Standard {
                        m: MultiSigner::Sr25519(
                               Public::try_from(
                                   hex::decode(
                                    "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                                   ).unwrap().as_ref()
                                   ).unwrap()
                               )
                        }
                    )
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::GeneralVerifierSet {
            verifier: Verifier {
                v: Some(VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                })
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::TypesAdded {
            types_display: TypesDisplay {
                types_hash: H256::from_str(
                    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
                )
                .unwrap(),
                verifier: Verifier {
                    v: Some(VerifierValue::Standard {
                        m: MultiSigner::Sr25519(
                            Public::try_from(hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            ).unwrap().as_ref()).unwrap()
                        )
                    })
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::TypesRemoved {
            types_display: TypesDisplay {
                types_hash: H256::from_str(
                    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
                )
                .unwrap(),
                verifier: Verifier {
                    v: Some(VerifierValue::Standard {
                        m: MultiSigner::Sr25519(
                            Public::try_from(hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            ).unwrap().as_ref()).unwrap()
                        )
                    })
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::TypesSigned {
            types_export: TypesExport {
                types_hash: H256::from_str(
                    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
                )
                .unwrap(),
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                }
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::TransactionSigned {
            sign_display: SignDisplay {
                transaction: vec![],
                network_name: "westend".to_string(),
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                },
                user_comment: "send to Alice".to_string(),
            }
        }
    ));

    // TODO: "error":"wrong_password_entered"
    assert!(entries_contain_event(
        &entries,
        &Event::TransactionSignError {
            sign_display: SignDisplay {
                transaction: vec![],
                network_name: "westend".to_string(),
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                },
                user_comment: "send to Alice".to_string(),
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::MessageSigned {
            sign_message_display: SignMessageDisplay {
                message: "This is Alice\nRoger".to_string(),
                network_name: "westend".to_string(),
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                },
                user_comment: "send to Alice".to_string(),
            }
        }
    ));

    // TODO: "error":"wrong_password_entered"
    assert!(entries_contain_event(
        &entries,
        &Event::MessageSignError {
            sign_message_display: SignMessageDisplay {
                message: "This is Alice\nRoger".to_string(),
                network_name: "westend".to_string(),
                signed_by: VerifierValue::Standard {
                    m: MultiSigner::Sr25519(
                        Public::try_from(
                            hex::decode(
                                "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                            )
                            .unwrap()
                            .as_ref()
                        )
                        .unwrap()
                    )
                },
                user_comment: "send to Alice".to_string(),
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::IdentityAdded {
            identity_history: IdentityHistory {
                seed_name: "Alice".to_string(),
                encryption: Encryption::Sr25519,
                public_key: hex::decode(
                    "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                )
                .unwrap(),
                path: "//".to_string(),
                network_genesis_hash: H256::from_str(
                    "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                )
                .unwrap()
            }
        }
    ));

    assert!(entries_contain_event(
        &entries,
        &Event::IdentityRemoved {
            identity_history: IdentityHistory {
                seed_name: "Alice".to_string(),
                encryption: Encryption::Sr25519,
                public_key: hex::decode(
                    "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
                )
                .unwrap(),
                path: "//".to_string(),
                network_genesis_hash: H256::from_str(
                    "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"
                )
                .unwrap()
            }
        }
    ));

    assert!(entries_contain_event(&entries, &Event::IdentitiesWiped));
    assert!(entries_contain_event(&entries, &Event::DeviceWasOnline));
    assert!(entries_contain_event(&entries, &Event::ResetDangerRecord));
    assert!(entries_contain_event(
        &entries,
        &Event::SeedCreated {
            seed_created: "Alice".to_string()
        }
    ));
    assert!(entries_contain_event(
        &entries,
        &Event::SeedNameWasShown {
            seed_name_was_shown: "AliceSecretSeed".to_string()
        }
    ));
    assert!(entries_contain_event(
        &entries,
        &Event::Warning {
            warning: "Received network information is not verified.".to_string()
        }
    ));
    assert!(entries_contain_event(&entries, &Event::WrongPassword));
    assert!(entries_contain_event(
        &entries,
        &Event::UserEntry {
            user_entry: "Lalala!!!".to_string()
        }
    ));
    assert!(entries_contain_event(
        &entries,
        &Event::SystemEntry {
            system_entry: "Blip blop".to_string()
        }
    ));

    assert!(entries_contain_event(&entries, &Event::HistoryCleared));
    assert!(entries_contain_event(&entries, &Event::DatabaseInitiated));
}

#[test]
fn print_single_event() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let entry = get_history_entry_by_order(&db, 0).unwrap();
    let expected_events = vec![Event::DatabaseInitiated];

    assert_eq!(entry.events, expected_events);
}

fn entries_contain_event(entries: &[Entry], event: &Event) -> bool {
    entries.iter().any(|e| e.events.contains(event))
}

#[test]
fn test_export_secret_key() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_cold(&db, Verifier { v: None }).unwrap();
    let ordered_specs = default_chainspecs();
    let spec = ordered_specs
        .into_iter()
        .find(|spec| spec.specs.name == "westend")
        .unwrap()
        .specs;
    let network_id = NetworkSpecsKey::from_parts(&spec.genesis_hash, &spec.encryption);
    let seed_name = "Alice";

    let (derivation_path, child_path) = ("//Alice", "//Alice//1");
    try_create_address(&db, seed_name, ALICE_SEED_PHRASE, child_path, &network_id).unwrap();
    let identities: Vec<(MultiSigner, AddressDetails)> =
        get_addresses_by_seed_name(&db, seed_name).unwrap();

    let (derivation_multisigner, _) = identities
        .iter()
        .find(|(_, a)| a.path == derivation_path)
        .unwrap();
    let secret_key = export_secret_key(
        &db,
        hex::encode(multisigner_to_public(derivation_multisigner)).as_str(),
        seed_name,
        &hex::encode(network_id.key()),
        ALICE_SEED_PHRASE,
        None,
    )
    .unwrap();

    // `subkey inspect "ALICE_SEED_PHRASE//Alice"`
    assert_eq!(
        String::from_utf8(secret_key.qr.data().to_vec()).unwrap(),
        "secret:0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a:e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e".to_string()
    );
    assert!(secret_key.address.secret_exposed);

    let identities: Vec<(MultiSigner, AddressDetails)> =
        get_addresses_by_seed_name(&db, seed_name).unwrap();
    let (_, child_address) = identities
        .iter()
        .find(|(_, a)| a.path == child_path)
        .unwrap();
    assert!(child_address.secret_exposed);
}

#[test]
fn test_create_key_set_generate_default_addresses() {
    let dbname = tempdir().unwrap();
    let db = sled::open(&dbname).unwrap();

    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();
    let westend_specs_key = "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";
    create_key_set(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        vec![westend_specs_key.to_owned()],
    )
    .unwrap();
    {
        let addresses = open_tree(&db, ADDRTREE).unwrap();
        assert_eq!(addresses.len(), 2);
    }
    let default_addresses = addresses_set_seed_name_network(
        &db,
        "Alice",
        &NetworkSpecsKey::from_hex(westend_specs_key).unwrap(),
    )
    .unwrap();

    let expected_default_addresses = vec![(
        MultiSigner::Sr25519(
            Public::try_from(
                hex::decode("3efeca331d646d8a2986374bb3bb8d6e9e3cfcdd7c45c2b69104fab5d61d3f34")
                    .unwrap()
                    .as_ref(),
            )
            .unwrap(),
        ),
        AddressDetails {
            seed_name: "Alice".to_string(),
            path: "//westend".to_string(),
            has_pwd: false,
            network_id: Some(NetworkSpecsKey::from_parts(
                &westend_genesis(),
                &Encryption::Sr25519,
            )),
            encryption: Encryption::Sr25519,
            secret_exposed: false,
        },
    )];

    assert_eq!(default_addresses, expected_default_addresses);

    let identities: Tree = db.open_tree(ADDRTREE).unwrap();
    let test_key = AddressKey::from_parts(
        &hex::decode("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a").unwrap(),
        &Encryption::Sr25519,
        None,
    )
    .unwrap();
    assert!(identities.contains_key(test_key.key()).unwrap());
}

#[test]
fn test_assert_db_version() {
    let dbname = tempdir().unwrap();
    let db = sled::open(&dbname).unwrap();
    populate_cold(&db, Verifier { v: None }).unwrap();
    assert!(assert_db_version(&db).is_ok());
}

#[test]
fn test_assert_empty_db_version() {
    let dbname = tempdir().unwrap();
    let db = sled::open(&dbname).unwrap();
    assert!(matches!(
        assert_db_version(&db),
        Err(Error::DbSchemaMismatch { found: 0, .. })
    ));
}

#[test]
fn test_assert_wrong_db_version() {
    let dbname = tempdir().unwrap();
    let db = sled::open(&dbname).unwrap();
    let mut batch = Batch::default();
    batch.insert(SCHEMA_VERSION, u32::MAX.to_be_bytes().to_vec());
    TrDbCold::new().set_settings(batch).apply(&db).unwrap();
    assert!(matches!(
        assert_db_version(&db),
        Err(Error::DbSchemaMismatch {
            found: u32::MAX,
            ..
        })
    ));
}

#[test]
fn test_validate_key_password() {
    let dbname = tempdir().unwrap();
    let db = sled::open(&dbname).unwrap();
    populate_cold_no_metadata(&db, Verifier { v: None }).unwrap();

    let westend_hex = "01e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";
    let westend_specs_key = NetworkSpecsKey::from_hex(westend_hex).unwrap();
    create_key_set(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        vec![westend_hex.to_string()],
    )
    .unwrap();
    let address_key = AddressKey::from_parts(
        &hex::decode("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a").unwrap(),
        &Encryption::Sr25519,
        None,
    )
    .unwrap();
    assert!(validate_key_password(&db, &address_key, ALICE_SEED_PHRASE, "").unwrap());

    try_create_address(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        "//Alice///password",
        &westend_specs_key,
    )
    .unwrap();

    let ms = get_all_addresses(&db)
        .unwrap()
        .into_iter()
        .find(|(_, a)| a.path == "//Alice")
        .unwrap()
        .0;
    let address_key = AddressKey::new(ms, Some(westend_genesis()));
    assert!(!validate_key_password(&db, &address_key, ALICE_SEED_PHRASE, "wrong_pass").unwrap());
    assert!(validate_key_password(&db, &address_key, ALICE_SEED_PHRASE, "password").unwrap());
}

#[test]
fn camera_reads_only_what_the_device_holds() {
    use db_handling::scan_policy::{readable, AUTH, BACKUP, FROST_DKG, MODULE, PENUMBRA, ZCASH};

    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();
    populate_all_network_specs(&db).unwrap();
    try_create_seed(&db, "Alice", ALICE_SEED_PHRASE, false).unwrap();

    // empty device: only what turns it into a non-empty one
    assert_eq!(readable(&db).unwrap(), vec![MODULE, BACKUP, FROST_DKG]);

    // a Penumbra key opens Penumbra (and identity), not Zcash
    let penumbra = NetworkSpecsKey::from_parts(
        &H256::from_str("0000000000000000000000000000000000000000000000000000000000006532")
            .unwrap(),
        &Encryption::Penumbra,
    );
    try_create_address(&db, "Alice", ALICE_SEED_PHRASE, "m/44'/6532'/0'", &penumbra).unwrap();
    assert_eq!(
        readable(&db).unwrap(),
        vec![MODULE, BACKUP, FROST_DKG, PENUMBRA, AUTH]
    );

    // a Zcash key opens Zcash
    let zcash = NetworkSpecsKey::from_parts(
        &H256::from_str("00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08")
            .unwrap(),
        &Encryption::Zcash,
    );
    // Zcash derivation takes 24-word seeds only
    let bob = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    try_create_seed(&db, "Bob", bob, false).unwrap();
    try_create_address(&db, "Bob", bob, "m/32'/133'/0'", &zcash).unwrap();
    assert_eq!(
        readable(&db).unwrap(),
        vec![MODULE, BACKUP, FROST_DKG, ZCASH, PENUMBRA, AUTH]
    );
}

#[test]
fn a_frost_wallet_alone_opens_frost_signing_and_zcash() {
    use db_handling::frost::{store_frost_wallet, FrostWalletData};
    use db_handling::scan_policy::{readable, BACKUP, FROST, FROST_DKG, MODULE, ZCASH};

    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();
    store_frost_wallet(
        &db,
        &FrostWalletData {
            key_package_hex: "aabb".to_string(),
            public_key_package_hex: "ccdd".to_string(),
            ephemeral_seed_hex: "eeff".to_string(),
            label: "2-of-3".to_string(),
            min_signers: 2,
            max_signers: 3,
            mainnet: true,
            created_at: 0,
            orchard_fvk_uview: None,
            address: None,
            relay_url: None,
            sealed: None,
            seed_id: None,
        },
    )
    .unwrap();
    assert_eq!(
        readable(&db).unwrap(),
        vec![MODULE, BACKUP, FROST_DKG, FROST, ZCASH]
    );
}

#[test]
fn export_alice_penumbra_is_tagged_penumbra() {
    let dbname = tempdir().unwrap();
    let db = sled::open(dbname).unwrap();

    populate_all_network_specs(&db).unwrap();
    try_create_seed(&db, "Alice", ALICE_SEED_PHRASE, true).unwrap();

    let genesis =
        H256::from_str("0000000000000000000000000000000000000000000000000000000000006532").unwrap();
    let specs_key = NetworkSpecsKey::from_parts(&genesis, &Encryption::Penumbra);
    try_create_address(
        &db,
        "Alice",
        ALICE_SEED_PHRASE,
        "m/44'/6532'/0'",
        &specs_key,
    )
    .unwrap();

    let multisigner = get_addresses_by_seed_name(&db, "Alice")
        .unwrap()
        .into_iter()
        .find(|(_, details)| details.network_id.as_ref() == Some(&specs_key))
        .map(|(multisigner, _)| multisigner)
        .unwrap();
    let key = export_key(&db, &multisigner, "Alice", &specs_key).unwrap();

    assert!(key.base58.starts_with("penumbra1"), "{}", key.base58);
    let definitions::navigation::QrData::Regular { data } = key.qr else {
        panic!("penumbra export is a single QR");
    };
    assert_eq!(
        String::from_utf8(data).unwrap(),
        format!("penumbra:{}:0x{}", key.base58, hex::encode(genesis))
    );
}
