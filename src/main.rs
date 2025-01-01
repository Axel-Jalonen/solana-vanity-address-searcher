use std::cell;
use std::thread;

use ed25519_dalek::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256Plus;

fn generate_ed25519_compatible_key() -> [u8; 32] {
    thread_local! {
        static THREAD_RNG: cell::RefCell<Xoshiro256Plus> = cell::RefCell::new(
            Xoshiro256Plus::seed_from_u64(OsRng.next_u64())
        );
    }

    THREAD_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        // Clamp the key to meet Ed25519 requirements
        key[0] &= 248; // Clear the lowest 3 bits of the first byte
        key[31] &= 127; // Clear the highest bit of the last byte
        key[31] |= 64; // Set the second-highest bit of the last byte

        key
    })
}

fn derive_public_key(private_key_bytes: [u8; 32]) -> [u8; 32] {
    let secret_key = SecretKey::from_bytes(&private_key_bytes)
        .expect("Failed to create secret key from private key bytes");
    let public_key: PublicKey = PublicKey::from(&secret_key);
    public_key.to_bytes()
}

fn get_random_keypair() -> ([u8; 32], [u8; 32]) {
    let private_key = generate_ed25519_compatible_key();
    let public_key = derive_public_key(private_key);

    (private_key, public_key)
}

fn make_key_pair(public_key: [u8; 32], private_key: [u8; 32]) -> [u8; 64] {
    let mut key_pair = [0u8; 64];
    let (one, two) = key_pair.split_at_mut(private_key.len());
    one.copy_from_slice(&private_key);
    two.copy_from_slice(&public_key);
    key_pair
}

fn main() {
    let prefix = b"base58pref1x";
    let num_threads = 8;
    let prefix_clone = prefix.to_vec();
    let mut handles = vec![];

    for _ in 0..num_threads {
        let prefix_clone = prefix_clone.clone();

        let handle = thread::spawn(move || {
            let mut counter = 0;
            let start_time = std::time::Instant::now();
            loop {
                let (private_key, public_key) = get_random_keypair();
                let mut encoded = Vec::new();
                bs58::encode(&public_key).onto(&mut encoded).unwrap();
                counter += 1;
                let elapsed = start_time.elapsed().as_secs();

                if counter % 1_000_000 == 0 {
                    println!(
                        "Checked {} keys. Generating approx {} keys/sec",
                        counter,
                        counter / elapsed
                    );
                }
                if encoded.starts_with(&prefix_clone) {
                    println!(
                        "\x1b[32m Found key pair: {:?}\x1b[0m",
                        make_key_pair(public_key, private_key)
                    );
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
