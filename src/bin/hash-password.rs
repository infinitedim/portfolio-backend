use bcrypt::{hash, DEFAULT_COST};
use std::env;

fn main() {
    let password = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: cargo run --bin hash-password <PASSWORD>");
        std::process::exit(1);
    });

    match hash(&password, DEFAULT_COST) {
        Ok(hashed) => {
            println!("\nPassword : {}", password);
            println!("Cost     : {}", DEFAULT_COST);
            println!("Hash     : {}\n", hashed);
            println!("# Paste this into your .env:");
            println!("ADMIN_HASH_PASSWORD={}", hashed);
        }
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            std::process::exit(1);
        }
    }
}
