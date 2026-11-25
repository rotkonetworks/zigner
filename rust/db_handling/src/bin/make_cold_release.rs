//! Build the cold database the app ships with.
//!
//! Writes to `../database/database_cold_release` relative to the working
//! directory, or to the path given as the only argument. Run from this crate
//! by `android/generate_database.sh`.

fn main() {
    let db = std::env::args().nth(1).map(|path| match sled::open(&path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("cannot open {path}: {e}");
            std::process::exit(1);
        }
    });
    if let Err(e) = db_handling::default_cold_release(db.as_ref()) {
        eprintln!("An error occurred: {e}");
        std::process::exit(1);
    }
}
