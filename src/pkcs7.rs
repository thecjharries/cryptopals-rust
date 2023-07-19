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

pub fn pkcs7_padding_add(input: Vec<u8>, block_size: usize) -> Vec<u8> {
    let mut output = input.clone();
    let padding = block_size - (input.len() % block_size);
    for _ in 0..padding {
        output.push(padding as u8);
    }
    output
}

pub fn pkcs7_padding_remove(input: Vec<u8>) -> Vec<u8> {
    let mut output = input.clone();
    let padding = *input.last().unwrap() as usize;
    for _ in 0..padding {
        output.pop();
    }
    output
}

pub fn pkcs7_padding_validation(input: Vec<u8>) -> Result<Vec<u8>, String> {
    todo!()
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding_add_pads_full_block_when_multiple_of_block_size() {
        assert_eq!(
            "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
                .as_bytes()
                .to_vec(),
            pkcs7_padding_add("YELLOW SUBMARINE".as_bytes().to_vec(), 16)
        )
    }

    #[test]
    fn pkcs7_padding_add_pads_number_when_not_multiple_of_blocksize() {
        assert_eq!(
            "YELLOW SUBMARINE\x01".as_bytes().to_vec(),
            pkcs7_padding_add("YELLOW SUBMARINE".as_bytes().to_vec(), 17)
        );
        assert_eq!(
            "YELLOW SUBMARINE\x02\x02".as_bytes().to_vec(),
            pkcs7_padding_add("YELLOW SUBMARINE".as_bytes().to_vec(), 18)
        );
    }

    #[test]
    fn pkcs7_padding_remove_removes_full_block_when_multiple_of_block_size() {
        assert_eq!(
            "YELLOW SUBMARINE".as_bytes().to_vec(),
            pkcs7_padding_remove(pkcs7_padding_add(
                "YELLOW SUBMARINE".as_bytes().to_vec(),
                16
            ))
        )
    }

    #[test]
    fn pkcs7_padding_validation_strips_padding_when_valid() {
        assert_eq!(
            "ICE ICE BABY".as_bytes().to_vec(),
            pkcs7_padding_validation(pkcs7_padding_add("ICE ICE BABY".as_bytes().to_vec(), 16))
                .unwrap()
        );
    }

    #[test]
    fn pkcs7_padding_validation_errors_when_padding_is_longer_than_input() {
        let mut input = "ICE ICE BABY".as_bytes().to_vec();
        input.push(255);
        assert_eq!(
            Err("Padding is longer than input".to_string()),
            pkcs7_padding_validation(input)
        );
    }

    #[test]
    fn pkcs7_padding_validation_errors_when_padding_is_not_valid() {
        let mut input = "ICE ICE BABY".as_bytes().to_vec();
        input.push(5);
        input.push(5);
        input.push(5);
        input.push(5);
        assert_eq!(
            Err("Padding is not valid".to_string()),
            pkcs7_padding_validation(input)
        );
        let mut input = "ICE ICE BABY".as_bytes().to_vec();
        input.push(1);
        input.push(2);
        input.push(3);
        input.push(4);
        assert_eq!(
            Err("Padding is not valid".to_string()),
            pkcs7_padding_validation(input)
        );
    }
}
