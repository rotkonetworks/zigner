//! A database written by Zigner 0.12 (before Substrate signing was removed)
//! must keep opening.
//!
//! `fixtures/legacy_db` was generated with the 0.12 code: release cold
//! database, initiated with the general verifier, one seed with keys on every
//! default network (Polkadot, Kusama, Westend, Zcash, Penumbra, five Cosmos
//! chains), and history entries for Substrate events that the current code
//! no longer writes (metadata, network specs, types, signed transaction and
//! message, general verifier).
//!
//! Those events are SCALE-encoded enum variants in the `history` tree, and
//! the trees `metadata`, `verifiers`, and the `types` / `general_verifier`
//! settings keys are still on disk. Reading the database must not depend on
//! any of that going away.

use std::path::Path;

use db_handling::{
    helpers::{assert_db_version, get_all_networks, get_danger_status},
    identities::get_all_addresses,
    interface_signer::keys_by_seed_name,
    manage_history::{entry_events_with_signers, get_history, get_history_entry_by_order},
    scan_policy,
};
use definitions::{crypto::Encryption, history::Event};

fn open_fixture() -> (tempfile::TempDir, sled::Db) {
    let dir = tempfile::tempdir().unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy_db");
    for name in ["conf", "db"] {
        std::fs::copy(src.join(name), dir.path().join(name)).unwrap();
    }
    let db = sled::open(dir.path()).unwrap();
    (dir, db)
}

#[test]
fn legacy_db_opens_with_keys_and_history() {
    let (_dir, db) = open_fixture();

    assert_db_version(&db).unwrap();
    assert!(
        get_danger_status(&db).unwrap(),
        "device-was-online recorded"
    );

    let networks = get_all_networks(&db).unwrap();
    assert_eq!(networks.len(), 10);

    let addresses = get_all_addresses(&db).unwrap();
    let count = |e: Encryption| {
        addresses
            .iter()
            .filter(|(_, d)| d.encryption == e && d.network_id.is_some())
            .count()
    };
    assert_eq!(count(Encryption::Sr25519), 3);
    assert_eq!(count(Encryption::Zcash), 1);
    assert_eq!(count(Encryption::Penumbra), 1);
    assert_eq!(count(Encryption::Cosmos), 5);
    assert!(addresses.iter().all(|(_, d)| d.seed_name == "Alice"));

    let readable = scan_policy::readable(&db).unwrap();
    for kind in [scan_policy::ZCASH, scan_policy::PENUMBRA, scan_policy::AUTH] {
        assert!(readable.contains(&kind), "{kind} readable");
    }

    let history = get_history(&db).unwrap();
    let events: Vec<Event> = history
        .iter()
        .flat_map(|(_, entry)| entry.events.clone())
        .collect();
    let has = |f: fn(&Event) -> bool| events.iter().any(f);
    assert!(has(|e| matches!(e, Event::DatabaseInitiated)));
    assert!(has(|e| matches!(e, Event::GeneralVerifierSet { .. })));
    assert!(has(|e| matches!(e, Event::MetadataAdded { .. })));
    assert!(has(|e| matches!(e, Event::NetworkSpecsAdded { .. })));
    assert!(has(|e| matches!(e, Event::TypesAdded { .. })));
    assert!(has(|e| matches!(e, Event::TransactionSigned { .. })));
    assert!(has(|e| matches!(e, Event::MessageSigned { .. })));
    assert!(has(|e| matches!(e, Event::IdentityAdded { .. })));
    assert!(has(|e| matches!(e, Event::DeviceWasOnline)));

    // Log details: every entry opens; the old signed transaction still
    // shows its verifier. (The fixture signed with the seed's root key, which
    // has no network, so there is no address card for it.)
    let mut signer_shown = false;
    for (order, _) in &history {
        let entry = get_history_entry_by_order(&db, order.stamp()).unwrap();
        for e in entry_events_with_signers(&db, entry).unwrap() {
            if matches!(e.event, Event::TransactionSigned { .. }) {
                assert!(e.signed_by.is_none());
                assert!(e.verifier_details.is_some());
                signer_shown = true;
            }
        }
    }
    assert!(signer_shown);
}

/// Keys still list for their seed, the Substrate ones included.
#[test]
fn legacy_keys_list_for_seed() {
    let (_dir, db) = open_fixture();

    let keys = keys_by_seed_name(&db, "Alice").unwrap();
    assert!(keys.root.is_some());
    let mut got: Vec<(String, String, String)> = keys
        .set
        .iter()
        .map(|c| {
            (
                c.network.network_title.clone(),
                c.key.address.path.clone(),
                c.key.base58.clone(),
            )
        })
        .collect();
    got.sort();
    // Captured from the 0.12 code on the same fixture.
    let expected = [
        ("celestia", "m/44'/118'/0'/0/0", "celestia1r5v5srda7xfth3hn2s26txvrcrntldju2pktdj"),
        ("cosmos", "m/44'/118'/0'/0/0", "cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhl"),
        ("kusama", "//kusama", "CdZJ4DkyiXZrFSKSrSPPwkM78iJzTwtdb15aqfNTp6fwg4X"),
        ("noble", "m/44'/118'/0'/0/0", "noble1r5v5srda7xfth3hn2s26txvrcrntldjungjn03"),
        ("osmosis", "m/44'/118'/0'/0/0", "osmo1r5v5srda7xfth3hn2s26txvrcrntldjuns5tpd"),
        ("penumbra", "m/44'/6532'/0'", "penumbra1hqvtzemdxmfhfvktl99l0nhsvw22fcm0krq897frk3du6dskjmpver2ha22l7yt97l84e0ewlmmts7kdndzm2vvtzk096rhxjhujqy88q3nnyarrj4c6anl0k3xfwaker8mds9"),
        ("polkadot", "//polkadot", "1R32yD5X8qHzvAP6x2NGV2HwrZGMpFHhwqEHvxmBLzkx8r1"),
        ("terra", "m/44'/330'/0'/0/0", "terra1uag78r7hn6we00ddudd9juv2f5nvapf0qtuskg"),
        ("westend", "//westend", "5D7w7v4biWTaZnXQiyF5nxYbfErTxaX566VCskrmXNGUJynZ"),
        ("zcash", "m/32'/133'/0'", "u1gsqvqxx6lmmqg05uvx57gjdg5j3a54nxw09z4vq4z0yp7dfdcjrqk5wq64quwzrufmujd5e8xu5jn7cyewjaptxc8lsqwa2lk559u4cd"),
    ]
    .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()));
    assert_eq!(got, expected);
}
