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

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use std::collections::HashSet;

pub fn encrypt_aes_128_ecb_block(block: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut block = GenericArray::clone_from_slice(&block);
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

pub fn decrypt_aes_128_ecb_block(block: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut blocks = GenericArray::clone_from_slice(&block);
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    cipher.decrypt_block(&mut blocks);
    blocks.to_vec()
}

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

pub fn decrypt_aes_128_cbc(ciphertext: Vec<u8>, iv: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut blocks = Vec::new();
    for block in ciphertext.chunks(16) {
        blocks.push(GenericArray::clone_from_slice(block));
    }
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    let mut previous_block = GenericArray::clone_from_slice(&iv);
    let mut decrypted = Vec::new();
    for block in blocks {
        let mut decrypted_block = block.clone();
        cipher.decrypt_block(&mut decrypted_block);
        for (index, byte) in decrypted_block.iter_mut().enumerate() {
            *byte ^= previous_block[index];
        }
        decrypted.append(&mut decrypted_block.to_vec());
        previous_block = block;
    }
    decrypted
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
    fn encrypt_aes_128_ecb_block_should_properly_encrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block.to_vec(),
            encrypt_aes_128_ecb_block(decrypted, key.to_vec())
        );
    }

    #[test]
    fn decrypt_aes_128_ecb_block_should_properly_decrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            decrypted,
            decrypt_aes_128_ecb_block(block.to_vec(), key.to_vec())
        );
    }

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
    fn decrypt_aes_128_cbc_should_properly_decrypt() {
        let key = GenericArray::from([0u8; 16]);
        let iv = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            decrypted,
            decrypt_aes_128_cbc(block.to_vec(), iv.to_vec(), key.to_vec())
        );
    }

    #[test]
    fn guess_was_aes_ecb_used_should_return_true_when_duplicate_blocks() {
        let ciphertext = b"YELLOW SUBMARINEYELLOW SUBMARINE".to_vec();
        assert!(guess_was_aes_ecb_used(ciphertext));
    }
}
