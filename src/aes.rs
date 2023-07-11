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

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;
}
