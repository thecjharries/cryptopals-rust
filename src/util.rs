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

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut hex_iter = hex.chars();
    while let (Some(first), Some(second)) = (hex_iter.next(), hex_iter.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", first, second), 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

pub fn hex_to_base64(hex: &str) -> String {
    let bytes = hex_to_bytes(hex);
    general_purpose::STANDARD.encode(&bytes)
}

pub fn fixed_xor(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
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
    fn hex_converts_properly() {
        assert_eq!(vec![0x01, 0x02, 0x03], hex_to_bytes("010203"));
    }

    #[test]
    fn odd_length_hex_should_drop_final_character() {
        assert_eq!(vec![0x01, 0x02, 0x03], hex_to_bytes("010203"));
    }

    #[test]
    #[should_panic]
    fn invalid_hex_should_panic() {
        hex_to_bytes("0102G3");
    }

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
}
