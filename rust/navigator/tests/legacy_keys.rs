//! Keys in a database written by Zigner 0.12 (see
//! `db_handling/tests/legacy_db.rs`) still list for their seed, including
//! the Substrate ones, after Substrate signing was removed.

#[test]
fn legacy_keys_list_for_seed() {
    let dir = tempfile::tempdir().unwrap();
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../db_handling/tests/fixtures/legacy_db");
    for name in ["conf", "db"] {
        std::fs::copy(src.join(name), dir.path().join(name)).unwrap();
    }
    let db = sled::open(dir.path()).unwrap();

    let keys = navigator::keys_by_seed_name(&db, "Alice").unwrap();
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
