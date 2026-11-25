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
    manage_history::{get_history, get_history_entry_by_order},
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

    for (order, _) in &history {
        get_history_entry_by_order(&db, order.stamp()).unwrap();
    }
}
