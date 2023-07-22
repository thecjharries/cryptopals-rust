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
use rand::seq::SliceRandom;
use rand::RngCore;
use rand::SeedableRng;
use rand_pcg::Pcg64;

use crate::aes::decrypt_aes_128_cbc;
use crate::aes::{encrypt_aes_128_cbc, encrypt_aes_128_ecb};
use crate::util::generate_random_16_byte_key;

// Tarpaulin doesn't recognize the unwrap return
#[cfg(not(tarpaulin_include))]
fn get_plaintext<R: RngCore>(rng: &mut R) -> (String, Vec<u8>) {
    let plaintexts = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let choice = plaintexts.choose(rng).unwrap();
    (
        choice.to_string(),
        general_purpose::STANDARD
            .decode(choice.as_bytes().to_vec())
            .unwrap(),
    )
}

pub fn challenge_17_oracle(seed: u64) -> (Vec<u8>, Vec<u8>, String) {
    let mut rng = Pcg64::seed_from_u64(seed);
    let key = generate_random_16_byte_key(&mut rng);
    let (plaintext, plaintext_decoded) = get_plaintext(&mut rng);
    let iv = generate_random_16_byte_key(&mut rng);
    let ciphertext = encrypt_aes_128_cbc(plaintext_decoded, iv.clone(), key);
    (ciphertext, iv, plaintext)
}

pub fn challenge_17_valid_decryption_padding(
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    key: Vec<u8>,
) -> bool {
    decrypt_aes_128_cbc(ciphertext, iv, key).is_ok()
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_plaintext() {
        let mut rng = Pcg64::seed_from_u64(0);
        let (plaintext, plaintext_decoded) = get_plaintext(&mut rng);
        assert_eq!(plaintext, "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=");
        assert_eq!(
            vec![
                48, 48, 48, 48, 48, 56, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121,
                32, 102, 105, 118, 101, 32, 112, 111, 105, 110, 116, 32, 111, 104
            ],
            plaintext_decoded
        )
    }

    #[test]
    fn challenge_17_oracle_encrypts_and_returns_proper() {
        let (ciphertext, iv, plaintext) = challenge_17_oracle(0);
        assert_eq!(
            vec![
                167, 45, 21, 252, 25, 73, 200, 132, 184, 198, 144, 157, 18, 35, 123, 15, 208, 168,
                100, 95, 254, 57, 76, 61, 49, 42, 93, 39, 80, 132, 34, 29, 148, 74, 242, 41, 81,
                17, 32, 141, 177, 43, 190, 251, 140, 42, 180, 4
            ],
            ciphertext
        );
        assert_eq!(
            vec![218, 167, 25, 176, 226, 30, 247, 9, 94, 26, 140, 200, 50, 123, 51, 219],
            iv
        );
        assert_eq!(
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".to_string(),
            plaintext
        );
    }

    #[test]
    fn challenge_17_valid_decryption_padding_checks_padding() {
        let (ciphertext, iv, _) = challenge_17_oracle(0);
        assert!(challenge_17_valid_decryption_padding(
            ciphertext.clone(),
            iv.clone(),
            generate_random_16_byte_key(&mut Pcg64::seed_from_u64(0))
        ));
        assert!(!challenge_17_valid_decryption_padding(
            generate_random_16_byte_key(&mut Pcg64::seed_from_u64(0)),
            iv.clone(),
            generate_random_16_byte_key(&mut Pcg64::seed_from_u64(0))
        ));
    }
}
