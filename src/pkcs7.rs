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

pub fn pkcs7_padding(input: Vec<u8>, block_size: usize) -> Vec<u8> {
    todo!()
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding_pads_nothing_when_multiple_of_block_size() {
        assert_eq!(
            "YELLOW SUBMARINE".as_bytes().to_vec(),
            pkcs7_padding("YELLOW SUBMARINE".as_bytes().to_vec(), 16)
        )
    }

    #[test]
    fn pkcs7_padding_pads_number_when_not_multiple_of_blocksize() {
        assert_eq!(
            "YELLOW SUBMARINE\x01".as_bytes().to_vec(),
            pkcs7_padding("YELLOW SUBMARINE".as_bytes().to_vec(), 17)
        );
        assert_eq!(
            "YELLOW SUBMARINE\x02\x02".as_bytes().to_vec(),
            pkcs7_padding("YELLOW SUBMARINE".as_bytes().to_vec(), 18)
        );
    }
}
