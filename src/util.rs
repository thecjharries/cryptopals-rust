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
use hex;

pub fn hex_to_base64(hex: &str) -> String {
    let bytes = hex::decode(hex).unwrap();
    general_purpose::STANDARD.encode(&bytes)
}

pub fn fixed_xor(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
    if first.len() != second.len() {
        panic!("Cannot xor vectors of different lengths");
    }
    first
        .iter()
        .zip(second.iter())
        .map(|(first_byte, second_byte)| first_byte ^ second_byte)
        .collect()
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_base64_works() {
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
             aWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            hex_to_base64(
                "49276d206b696c6c696e6720796f7572\
                 20627261696e206c696b65206120706f\
                 69736f6e6f7573206d757368726f6f6d"
            )
        );
    }

    #[test]
    fn fixed_xor_should_xor_same_length_vecs() {
        let result = fixed_xor(
            hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
            hex::decode("686974207468652062756c6c277320657965").unwrap(),
        );
        assert_eq!(
            hex::decode("746865206b696420646f6e277420706c6179").unwrap(),
            result
        );
    }

    #[test]
    #[should_panic]
    fn fixed_xor_should_panic_on_different_length_vecs() {
        fixed_xor(
            hex::decode("1c0111001f010100061a024b53535009181").unwrap(),
            hex::decode("686974207468652062756c6c2773206579651").unwrap(),
        );
    }
}
