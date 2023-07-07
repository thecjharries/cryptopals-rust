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

fn single_byte_xor(input: Vec<u8>, key: u8) -> Vec<u8> {
    input.iter().map(|byte| byte ^ key).collect()
}

fn generate_possible_single_xor_plaintexts(input: Vec<u8>) -> Vec<Vec<u8>> {
    (u8::MIN..=u8::MAX)
        .map(|key| single_byte_xor(input.clone(), key))
        .collect()
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{fixed_xor, hex_to_base64};
    use hex;

    #[test]
    fn single_byte_xor_works() {
        assert_eq!(
            vec![0x00, 0x01, 0x02, 0x03],
            single_byte_xor(vec![0x01, 0x00, 0x03, 0x02], 0x01)
        );
    }

    #[test]
    fn generate_possible_single_xor_plaintexts_works() {
        let possible_plaintexts =
            generate_possible_single_xor_plaintexts(vec![0x01, 0x00, 0x03, 0x02]);
        assert_eq!(256, possible_plaintexts.len());
    }

    #[test]
    fn challenge1() {
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
    fn challenge2() {
        let result = fixed_xor(
            hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
            hex::decode("686974207468652062756c6c277320657965").unwrap(),
        );
        assert_eq!(
            hex::decode("746865206b696420646f6e277420706c6179").unwrap(),
            result
        );
    }
}
