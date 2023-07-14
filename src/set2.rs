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

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    // use super::*;

    use crate::pkcs7::pkcs7_padding;
    use crate::util::get_challenge_data;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn challenge9() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec(),
            pkcs7_padding("YELLOW SUBMARINE".as_bytes().to_vec(), 20)
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
}
