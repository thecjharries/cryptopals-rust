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

use lazy_static::lazy_static;
use std::collections::BTreeMap;

lazy_static! {
    pub static ref LETTER_FREQUENCY_MAP: BTreeMap<u8, f32> = BTreeMap::from_iter(vec![
        // https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
        ('e' as u8, 0.111607),
        ('a' as u8, 0.084966),
        ('r' as u8, 0.075809),
        ('i' as u8, 0.075448),
        ('o' as u8, 0.071635),
        ('t' as u8, 0.069509),
        ('n' as u8, 0.066544),
        ('s' as u8, 0.057351),
        ('l' as u8, 0.054893),
        ('c' as u8, 0.045388),
        ('u' as u8, 0.036308),
        ('d' as u8, 0.033844),
        ('p' as u8, 0.031671),
        ('m' as u8, 0.030129),
        ('h' as u8, 0.030034),
        ('g' as u8, 0.024705),
        ('b' as u8, 0.020720),
        ('f' as u8, 0.018121),
        ('y' as u8, 0.017779),
        ('w' as u8, 0.012899),
        ('k' as u8, 0.011016),
        ('v' as u8, 0.010074),
        ('x' as u8, 0.002902),
        ('z' as u8, 0.002722),
        ('j' as u8, 0.001965),
        ('q' as u8, 0.001962),
        ('E' as u8, 0.111607),
        ('A' as u8, 0.084966),
        ('R' as u8, 0.075809),
        ('I' as u8, 0.075448),
        ('O' as u8, 0.071635),
        ('T' as u8, 0.069509),
        ('N' as u8, 0.066544),
        ('S' as u8, 0.057351),
        ('L' as u8, 0.054893),
        ('C' as u8, 0.045388),
        ('U' as u8, 0.036308),
        ('D' as u8, 0.033844),
        ('P' as u8, 0.031671),
        ('M' as u8, 0.030129),
        ('H' as u8, 0.030034),
        ('G' as u8, 0.024705),
        ('B' as u8, 0.020720),
        ('F' as u8, 0.018121),
        ('Y' as u8, 0.017779),
        ('W' as u8, 0.012899),
        ('K' as u8, 0.011016),
        ('V' as u8, 0.010074),
        ('X' as u8, 0.002902),
        ('Z' as u8, 0.002722),
        ('J' as u8, 0.001965),
        ('Q' as u8, 0.001962),
    ]);
}

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

pub fn generate_frequency_map(input: Vec<u8>) -> BTreeMap<u8, f32> {
    let length = input.len() as f32;
    let mut output = BTreeMap::new();
    for character in input {
        *output.entry(character).or_insert(0.0) += 1.0;
    }
    for (_, value) in output.iter_mut() {
        *value /= length;
    }
    output
}

pub fn compute_mean_absolute_difference(input: BTreeMap<u8, f32>) -> f32 {
    input.iter().fold(0.0, |acc, (key, value)| {
        acc + (LETTER_FREQUENCY_MAP.get(key).unwrap_or(&0.0) - value).abs()
    }) / input.len() as f32
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
    fn the_frequency_map_should_be_generated_correctly() {
        let input = "this is a test".as_bytes().to_vec();
        let output = generate_frequency_map(input);
        assert_eq!(&0.21428572, output.get(&('t' as u8)).unwrap_or(&0.0));
        assert_eq!(&0.071428575, output.get(&('h' as u8)).unwrap_or(&0.0));
        assert_eq!(&0.14285715, output.get(&('i' as u8)).unwrap_or(&0.0));
        assert_eq!(&0.21428572, output.get(&('s' as u8)).unwrap_or(&0.0));
        assert_eq!(&0.071428575, output.get(&('a' as u8)).unwrap_or(&0.0));
        assert_eq!(&0.071428575, output.get(&('e' as u8)).unwrap_or(&0.0));
    }

    #[test]
    fn the_const_freq_map_should_have_zero_mean_absolute_difference() {
        assert_eq!(
            0.0,
            compute_mean_absolute_difference(LETTER_FREQUENCY_MAP.clone())
        );
    }
}
