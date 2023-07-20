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

use rand::SeedableRng;
use rand_pcg::Pcg64;
use serde::__private::de;
use urlencoding::encode_binary;

use crate::aes::{decrypt_aes_128_cbc, encrypt_aes_128_cbc};
use crate::set2::generate_random_16_byte_key;
use crate::util::fixed_xor;

pub fn challenge_16_oracle(userdata: Vec<u8>, seed: u64) -> Vec<u8> {
    let mut rng = Pcg64::seed_from_u64(seed);
    let key = generate_random_16_byte_key(&mut rng);
    let iv = generate_random_16_byte_key(&mut rng);
    let mut plaintext = b"comment1=cooking%20MCs;userdata=".to_vec();
    plaintext.extend(encode_binary(&userdata).as_bytes());
    plaintext.extend(b";comment2=%20like%20a%20pound%20of%20bacon".to_vec());
    encrypt_aes_128_cbc(plaintext, iv, key)
}

pub fn inject_admin() -> Vec<u8> {
    let seed = 0;
    let desired_length = ";admin=true".len();
    let filler = vec!['A' as u8; desired_length];
    let flipped = fixed_xor(b";admin=true".to_vec(), filler.clone());
    let mut ciphertext = challenge_16_oracle(filler, seed);
    let mut xor_input = vec![0u8; 16];
    xor_input.extend(flipped);
    xor_input.extend(vec![0u8; ciphertext.len() - xor_input.len()]);
    ciphertext = fixed_xor(ciphertext, xor_input);
    let mut rng = Pcg64::seed_from_u64(seed);
    let key = generate_random_16_byte_key(&mut rng);
    let iv = generate_random_16_byte_key(&mut rng);
    decrypt_aes_128_cbc(ciphertext, iv, key)
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_16_oracle_provides_expected_wrapping() {
        let mut rng = Pcg64::seed_from_u64(0);
        let key = generate_random_16_byte_key(&mut rng);
        let iv = generate_random_16_byte_key(&mut rng);
        let ciphertext = challenge_16_oracle(vec![], 0);
        let plaintext = decrypt_aes_128_cbc(ciphertext, iv, key);
        assert_eq!(
            b"comment1=cooking%20MCs;userdata=;comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
            plaintext
        );
    }

    #[test]
    fn challenge_16_oracle_encodes_special_characters() {
        let mut rng = Pcg64::seed_from_u64(0);
        let key = generate_random_16_byte_key(&mut rng);
        let iv = generate_random_16_byte_key(&mut rng);
        let ciphertext = challenge_16_oracle(b";admin=true".to_vec(), 0);
        let plaintext = decrypt_aes_128_cbc(ciphertext, iv, key);
        assert_eq!(
            b"comment1=cooking%20MCs;userdata=%3Badmin%3Dtrue;comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
            plaintext
        );
    }

    #[test]
    fn challenge_16() {
        let result = inject_admin();
        let result_string = String::from_utf8_lossy(&result);
        println!("{}", result_string);
        assert!(result_string.contains(";admin=true;"));
    }
}
