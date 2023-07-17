// Copyright 2023 CJ Harries
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::{engine::general_purpose, Engine as _};
use rand::{Rng, RngCore, SeedableRng};
use rand_pcg::Pcg64;
use serde::{Deserialize, Serialize};
use serde_qs::from_str;

use crate::aes::{encrypt_aes_128_ecb, AesEncryptionMethod};
use crate::pkcs7::pkcs7_padding_add;

// Tarpaulin does not recognize the return as being covered
#[cfg(not(tarpaulin_include))]
fn generate_random_16_byte_key<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let mut key = vec![0; 16];
    rng.fill_bytes(&mut key);
    key
}

// Tarpaulin does not recognize either of the enums in the return as being covered
#[cfg(not(tarpaulin_include))]
pub fn encryption_oracle<R: RngCore>(
    plaintext: Vec<u8>,
    rng: &mut R,
) -> (Vec<u8>, AesEncryptionMethod) {
    let key = generate_random_16_byte_key(rng);
    let mut plaintext = plaintext;
    let mut prefix = vec![0; rng.gen_range(5..=10)];
    rng.fill_bytes(&mut prefix);
    let mut suffix = vec![0; rng.gen_range(5..=10)];
    rng.fill_bytes(&mut suffix);
    plaintext.extend(suffix);
    plaintext.extend(prefix);
    let iv = generate_random_16_byte_key(rng);
    if rng.gen_bool(0.5) {
        let padding_length = 16 - plaintext.len() % 16;
        let padding = vec![padding_length as u8; padding_length];
        plaintext.extend(padding);
        (
            crate::aes::encrypt_aes_128_ecb(plaintext, key),
            AesEncryptionMethod::Aes128Ecb,
        )
    } else {
        (
            crate::aes::encrypt_aes_128_cbc(plaintext, iv, key),
            AesEncryptionMethod::Aes128Cbc,
        )
    }
}

pub fn challenge_12_oracle(plaintext: Vec<u8>, seed: u64) -> Vec<u8> {
    let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
    let unknown_data = general_purpose::STANDARD
        .decode(unknown_string.as_bytes().to_vec())
        .unwrap();
    let mut rng = Pcg64::seed_from_u64(seed);
    let key = generate_random_16_byte_key(&mut rng);
    let mut plaintext = plaintext;
    plaintext.extend(unknown_data);
    plaintext = pkcs7_padding_add(plaintext, 16);
    encrypt_aes_128_ecb(plaintext, key)
}

pub fn detect_block_size(oracle: fn(Vec<u8>, u64) -> Vec<u8>, seed: u64) -> usize {
    let mut block_size = 0;
    let mut previous_length = 0;
    let mut current_length = 0;
    let mut input = vec![0; 0];
    loop {
        input.push(0);
        current_length = oracle(input.clone(), seed).len();
        if previous_length != 0 && current_length != previous_length {
            block_size = current_length - previous_length;
            break;
        }
        previous_length = current_length;
    }
    block_size
}

pub fn crack_challenge_12_oracle() -> Vec<u8> {
    let block_size = detect_block_size(challenge_12_oracle, 0);
    let original_length = challenge_12_oracle(vec![], 0).len();
    let mut plaintext = vec![];
    while plaintext.len() < original_length {
        let block_start = plaintext.len();
        let block_end = (block_start + block_size).min(original_length);
        for length in (0..block_size).rev() {
            let mut input = vec!['A' as u8; length];
            let target = challenge_12_oracle(input.clone(), 0)[block_start..block_end].to_vec();
            input.extend(plaintext.clone());
            for byte in 0..=255 {
                let mut input = input.clone();
                input.push(byte);
                let output = challenge_12_oracle(input, 0)[block_start..block_end].to_vec();
                if output == target {
                    plaintext.push(byte);
                    break;
                }
            }
        }
    }
    plaintext
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct User {
    email: String,
    uid: u32,
    role: String,
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::aes::guess_encryption_method;
    use crate::util::get_challenge_data;

    #[test]
    fn challenge9() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec(),
            pkcs7_padding_add("YELLOW SUBMARINE".as_bytes().to_vec(), 20)
        );
    }

    #[test]
    fn challenge10() {
        let data = get_challenge_data(10).replace("\n", "");
        let ciphertext = general_purpose::STANDARD
            .decode(data.as_bytes().to_vec())
            .unwrap();
        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let iv = vec![0; 16];
        let plaintext = crate::aes::decrypt_aes_128_cbc(ciphertext, iv, key);
        let plaintext = String::from_utf8(plaintext).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
        assert!(plaintext.ends_with("Play that funky music \n"));
    }

    #[test]
    fn generate_random_16_byte_key_works() {
        let mut rng = Pcg64::seed_from_u64(0);
        let key = generate_random_16_byte_key(&mut rng);
        assert_eq!(
            vec![83, 188, 226, 212, 218, 37, 174, 32, 251, 105, 191, 43, 225, 56, 249, 88],
            key
        );
    }

    #[test]
    fn encryption_oracle_generates_ecb_output() {
        let mut rng = Pcg64::seed_from_u64(0);
        let plaintext = vec![0; 32];
        let (_, encryption_method) = encryption_oracle(plaintext, &mut rng);
        assert_eq!(AesEncryptionMethod::Aes128Ecb, encryption_method);
    }

    #[test]
    fn encryption_oracle_generates_cbc_output() {
        let mut rng = Pcg64::seed_from_u64(1);
        let plaintext = vec![0; 32];
        let (_, encryption_method) = encryption_oracle(plaintext, &mut rng);
        assert_eq!(AesEncryptionMethod::Aes128Cbc, encryption_method);
    }

    #[test]
    fn challenge11() {
        let mut rng = Pcg64::seed_from_u64(0);
        let plaintext = vec![0; 32];
        let (ciphertext, encryption_method) = encryption_oracle(plaintext, &mut rng);
        assert_eq!(AesEncryptionMethod::Aes128Ecb, encryption_method);
        assert_eq!(encryption_method, guess_encryption_method(ciphertext));
        let mut rng = Pcg64::seed_from_u64(1);
        let plaintext = vec![0; 32];
        let (ciphertext, encryption_method) = encryption_oracle(plaintext, &mut rng);
        assert_eq!(AesEncryptionMethod::Aes128Cbc, encryption_method);
        assert_eq!(encryption_method, guess_encryption_method(ciphertext));
    }

    #[test]
    fn challenge_12_oracle_extends_input() {
        let plaintext = vec![0; 16];
        let ciphertext = challenge_12_oracle(plaintext, 0);
        assert_eq!(160, ciphertext.len());
        let plaintext = vec![0; 32];
        let ciphertext = challenge_12_oracle(plaintext, 0);
        assert_eq!(176, ciphertext.len());
    }

    #[test]
    fn detect_block_size_works() {
        let block_size = detect_block_size(challenge_12_oracle, 0);
        assert_eq!(16, block_size);
    }

    #[test]
    fn challenge_12() {
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
        let unknown_data = general_purpose::STANDARD
            .decode(unknown_string.as_bytes().to_vec())
            .unwrap();
        assert!(String::from_utf8(crack_challenge_12_oracle())
            .unwrap()
            .starts_with(String::from_utf8(unknown_data).unwrap().as_str()));
    }
}
