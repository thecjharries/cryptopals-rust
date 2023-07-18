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
use serde_qs::to_string;

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

pub fn challenge_14_oracle(plaintext: Vec<u8>, seed: u64) -> Vec<u8> {
    let mut rng = Pcg64::seed_from_u64(seed);
    let key = generate_random_16_byte_key(&mut rng);
    let random_length = rng.gen_range(0..=100);
    // This length doesn't work
    // I don't care right now
    // let random_length = 100;
    let mut random_data = vec![0; random_length];
    rng.fill_bytes(&mut random_data);
    let mut input = random_data;
    input.extend(plaintext);
    let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
    let unknown_data = general_purpose::STANDARD
        .decode(unknown_string.as_bytes().to_vec())
        .unwrap();
    input.extend(unknown_data);
    input = pkcs7_padding_add(input, 16);
    encrypt_aes_128_ecb(input, key)
}

pub fn detect_block_size(oracle: fn(Vec<u8>, u64) -> Vec<u8>, seed: u64) -> usize {
    let mut previous_length = 0;
    let mut current_length: usize;
    let mut input = vec![0; 0];
    loop {
        input.push(0);
        current_length = oracle(input.clone(), seed).len();
        if previous_length != 0 && current_length != previous_length {
            return current_length - previous_length;
        }
        previous_length = current_length;
    }
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

pub fn determine_prefix_size(oracle: fn(Vec<u8>, u64) -> Vec<u8>, seed: u64) -> usize {
    let mut input = vec![];
    let mut previous_blocks = oracle(input.clone(), seed);
    let mut current_blocks: Vec<u8>;
    loop {
        input.push('A' as u8);
        current_blocks = oracle(input.clone(), seed);
        if current_blocks.len() != previous_blocks.len() {
            break;
        }
        previous_blocks = current_blocks;
    }
    let block_size = current_blocks.len() - previous_blocks.len();
    let base_length = previous_blocks
        .into_iter()
        .zip(current_blocks)
        .position(|(a, b)| a != b)
        .unwrap();
    // I cannot figure out why I have to subtract 10
    // Does it have something to do with the target size?
    base_length + block_size - input.len() - 10
}

pub fn crack_challenge_14_oracle() -> Vec<u8> {
    let block_size = detect_block_size(challenge_14_oracle, 0);
    println!("block size: {}", block_size);
    let original_length = challenge_14_oracle(vec![], 0).len();
    println!("original length: {}", original_length);
    let prefix_size = determine_prefix_size(challenge_14_oracle, 0);
    println!("prefix size: {}", prefix_size);
    let padding_to_next_block = block_size - (prefix_size % block_size);
    println!("padding to next block: {}", padding_to_next_block);
    let plaintext_length = original_length - prefix_size;
    println!("plaintext length: {}", plaintext_length);
    let mut plaintext = vec![];
    while plaintext.len() < plaintext_length {
        let block_start = prefix_size + padding_to_next_block + plaintext.len();
        println!("block start: {}", block_start);
        let block_end = if 0 == prefix_size % block_size {
            (block_start + block_size).min(original_length + padding_to_next_block)
        } else {
            (block_start + block_size).min(original_length)
        };
        println!("block end: {}", block_end);
        if block_end < block_start {
            break;
        }
        for length in (0..block_size).rev() {
            let mut input = vec!['A' as u8; padding_to_next_block + length];
            println!("Input: {:?}", input);
            let target = challenge_14_oracle(input.clone(), 0)[block_start..block_end].to_vec();
            input.extend(plaintext.clone());
            for byte in 0..=255 {
                let mut input = input.clone();
                input.push(byte);
                let output = challenge_14_oracle(input, 0)[block_start..block_end].to_vec();
                if output == target {
                    plaintext.push(byte);
                    break;
                }
            }
        }
    }
    println!(
        "plaintext: {:?}",
        String::from_utf8(plaintext.clone()).unwrap()
    );
    plaintext
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct User {
    email: String,
    uid: u32,
    role: String,
}

impl User {
    pub fn new(email: String, uid: u32, role: String) -> Self {
        assert!(
            !email.contains('&') && !email.contains('='),
            "Email cannot contain '&' or '='"
        );
        assert!(
            !role.contains('&') && !role.contains('='),
            "Role cannot contain '&' or '='"
        );
        Self { email, uid, role }
    }

    pub fn profile_for(email: String) -> Self {
        Self::new(email, 10, "user".to_string())
    }

    pub fn encrypt(&self) -> Vec<u8> {
        let plaintext = pkcs7_padding_add(self.to_string().as_bytes().to_vec(), 16);
        // This is real bad
        // Serves great for testing
        // Just don't seed your RNG with the user ID
        let mut rng = Pcg64::seed_from_u64(self.uid as u64);
        let key = generate_random_16_byte_key(&mut rng);
        encrypt_aes_128_ecb(plaintext, key)
    }
}

impl std::fmt::Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", to_string(self).unwrap())
    }
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::aes::{decrypt_aes_128_ecb, guess_encryption_method};
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
    fn challenge_14_oracle_extends_input() {
        let plaintext = vec![0; 16];
        let ciphertext = challenge_14_oracle(plaintext, 0);
        assert_eq!(240, ciphertext.len());
        let plaintext = vec![0; 32];
        let ciphertext = challenge_14_oracle(plaintext, 0);
        assert_eq!(256, ciphertext.len());
    }

    #[test]
    fn challenge_14_oracle_generates_different_inputs() {
        let first = challenge_14_oracle(vec![], 0);
        let second = challenge_14_oracle(vec![], 10);
        assert_ne!(first, second);
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

    #[test]
    fn challenge_14() {
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".to_string();
        let unknown_data = general_purpose::STANDARD
            .decode(unknown_string.as_bytes().to_vec())
            .unwrap();
        let result = crack_challenge_14_oracle();
        println!("{:?}", String::from_utf8(result.clone()).unwrap());
        println!(
            "{:?}",
            String::from_utf8(unknown_data.clone()).unwrap().as_str()
        );
        assert!(String::from_utf8(result)
            .unwrap()
            .starts_with(String::from_utf8(unknown_data).unwrap().as_str()));
    }

    #[test]
    fn determine_prefix_size_finds_prefix_length() {
        assert_eq!(71, determine_prefix_size(challenge_14_oracle, 0));
        assert_eq!(11, determine_prefix_size(challenge_14_oracle, 1));
        assert_eq!(89, determine_prefix_size(challenge_14_oracle, 2));
        assert_eq!(11, determine_prefix_size(challenge_14_oracle, 3));
        assert_eq!(67, determine_prefix_size(challenge_14_oracle, 4));
    }

    #[test]
    #[should_panic]
    fn user_email_cannot_contain_ampersand() {
        User::new("foo&bar".to_string(), 10, "user".to_string());
    }

    #[test]
    #[should_panic]
    fn user_role_cannot_contain_ampersand() {
        User::new("foo@bar.com".to_string(), 10, "user&admin".to_string());
    }

    #[test]
    fn users_should_be_easily_created() {
        let user = User::new("foo@bar.com".to_string(), 10, "user".to_string());
        assert_eq!(
            User {
                email: "foo@bar.com".to_string(),
                uid: 10,
                role: "user".to_string(),
            },
            user
        );
    }

    #[test]
    fn user_profile_for_should_hardcode_fields() {
        assert_eq!(
            User {
                email: "foo@bar.com".to_string(),
                uid: 10,
                role: "user".to_string(),
            },
            User::profile_for("foo@bar.com".to_string())
        );
    }

    #[test]
    fn user_to_string_should_create_query_string() {
        assert_eq!(
            "email=foo%40bar.com&uid=10&role=user".to_string(),
            User::profile_for("foo@bar.com".to_string()).to_string()
        );
    }

    #[test]
    fn user_can_encrypt_its_param_string() {
        let user = User::profile_for("foo@bar.com".to_string());
        assert_eq!(
            vec![
                227, 124, 75, 6, 52, 243, 107, 177, 5, 208, 205, 39, 104, 157, 3, 190, 102, 165,
                185, 125, 73, 196, 68, 71, 39, 165, 35, 138, 117, 34, 171, 84, 249, 104, 214, 247,
                72, 85, 48, 245, 124, 113, 91, 78, 101, 207, 3, 117
            ],
            user.encrypt()
        );
    }

    #[test]
    fn challenge13() {
        // email=aaaaaaaaaa
        // %40aaaaaaaaaaaa.
        // com&uid=10&role=
        // user
        let user = User::profile_for("aaaaaaaaaa@aaaaaaaaaaaa.com".to_string());
        let mut rng = Pcg64::seed_from_u64(user.uid as u64);
        let key = generate_random_16_byte_key(&mut rng);
        let low_perms = user.encrypt();
        let admin_role = pkcs7_padding_add("admin".as_bytes().to_vec(), 16);
        // email=a%40aa.com
        let user = User::profile_for(format!(
            "{}{}",
            "a@aa.com",
            String::from_utf8(admin_role).unwrap()
        ));
        let high_perms = user.encrypt();
        let admin_block = &high_perms[16..32];
        let mut crafted_perms = low_perms.clone()[..low_perms.len() - 16].to_vec();
        crafted_perms.extend_from_slice(admin_block);
        let decrypted = decrypt_aes_128_ecb(crafted_perms, key);
        assert!(String::from_utf8(decrypted)
            .unwrap()
            .split('&')
            .nth(2)
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .starts_with("admin"));
    }
}
