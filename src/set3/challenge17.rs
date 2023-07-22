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

use rand::seq::SliceRandom;
use rand::RngCore;

fn get_plaintext<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let plaintexts = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
            .as_bytes()
            .to_vec(),
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
            .as_bytes()
            .to_vec(),
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
            .as_bytes()
            .to_vec(),
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
            .as_bytes()
            .to_vec(),
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
            .as_bytes()
            .to_vec(),
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
            .as_bytes()
            .to_vec(),
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
            .as_bytes()
            .to_vec(),
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
            .as_bytes()
            .to_vec(),
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
            .as_bytes()
            .to_vec(),
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
            .as_bytes()
            .to_vec(),
    ];
    let choice = plaintexts.choose(rng).unwrap();
    (
        choice.to_string(),
        general_purpose::STANDARD
            .decode(choice.as_bytes().to_vec())
            .unwrap(),
    )
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;
    use rand_pcg::Pcg64;

    #[test]
    fn test_get_plaintext() {
        let mut rng = Pcg64::seed_from_u64(0);
        let (plaintext, plaintext_decoded) = get_plaintext(&mut rng);
        assert_eq!(plaintext, "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=");
        assert_eq!(
            vec![
                48, 48, 48, 48, 48, 56, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121,
                32, 102, 105, 118, 101, 32, 112, 111, 105, 110, 116, 32, 111, 104
            ],
            plaintext_decoded
        )
    }
}
