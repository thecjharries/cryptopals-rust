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

use rand::{Rng, RngCore};

use crate::aes::AesEncryptionMethod;

fn generate_random_16_byte_key<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let mut key = vec![0; 16];
    rng.fill_bytes(&mut key);
    key
}

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

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::pkcs7::pkcs7_padding_add;
    use crate::util::get_challenge_data;
    use base64::{engine::general_purpose, Engine as _};
    use rand::SeedableRng;
    use rand_pcg::Pcg64;

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
}
