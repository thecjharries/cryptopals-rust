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

use std::collections::HashSet;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;

pub fn decrypt_aes_128_ecb(ciphertext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let key = GenericArray::from_slice(&key);
    let mut blocks = Vec::new();
    for block in ciphertext.chunks(16) {
        blocks.push(GenericArray::clone_from_slice(block));
    }
    let cipher = Aes128::new(&key);
    cipher.decrypt_blocks(&mut blocks);
    blocks
        .iter()
        .map(|block| block.to_vec())
        .flatten()
        .collect::<Vec<u8>>()
}

pub fn guess_was_aes_ecb_used(ciphertext: Vec<u8>) -> bool {
    let mut blocks = HashSet::new();
    for block in ciphertext.chunks(16) {
        if blocks.contains(block) {
            return true;
        }
        blocks.insert(block);
    }
    false
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};

    #[test]
    // https://docs.rs/aes/latest/aes/index.html#examples
    fn decrypt_aes_128_ecb_should_properly_decrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(decrypted, decrypt_aes_128_ecb(block.to_vec(), key.to_vec()));
    }

    #[test]
    fn guess_was_aes_ecb_used_should_return_true_when_duplicate_blocks() {
        let ciphertext = b"YELLOW SUBMARINEYELLOW SUBMARINE".to_vec();
        assert!(guess_was_aes_ecb_used(ciphertext));
    }
}
