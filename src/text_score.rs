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

pub fn get_character_weight(character: u8) -> u32 {
    match char::from(character) {
        'u' | 'U' => 2,
        'l' | 'L' => 3,
        'd' | 'D' => 4,
        'r' | 'R' => 5,
        'h' | 'H' => 6,
        's' | 'S' => 7,
        ' ' => 8,
        'n' | 'N' => 9,
        'i' | 'I' => 10,
        'o' | 'O' => 11,
        'a' | 'A' => 12,
        't' | 'T' => 13,
        'e' | 'E' => 14,
        _ => 0,
    }
}

pub fn compute_score(input: Vec<u8>) -> u32 {
    input
        .iter()
        .fold(0, |acc, character| acc + get_character_weight(*character))
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_characters_score_positive() {
        assert_eq!(14, get_character_weight('e' as u8));
    }

    #[test]
    fn unknown_characters_score_zero() {
        assert_eq!(0, get_character_weight('!' as u8));
    }

    #[test]
    fn the_score_should_be_computed_correctly() {
        let input = "this is a test".as_bytes().to_vec();
        let output = compute_score(input);
        assert_eq!(136, output);
    }
}
