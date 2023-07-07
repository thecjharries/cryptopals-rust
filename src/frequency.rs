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
    static ref LETTER_FREQUENCY_MAP: BTreeMap<char, f32> = BTreeMap::from_iter(vec![
        // https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
        ('e', 0.111607),
        ('a', 0.084966),
        ('r', 0.075809),
        ('i', 0.075448),
        ('o', 0.071635),
        ('t', 0.069509),
        ('n', 0.066544),
        ('s', 0.057351),
        ('l', 0.054893),
        ('c', 0.045388),
        ('u', 0.036308),
        ('d', 0.033844),
        ('p', 0.031671),
        ('m', 0.030129),
        ('h', 0.030034),
        ('g', 0.024705),
        ('b', 0.020720),
        ('f', 0.018121),
        ('y', 0.017779),
        ('w', 0.012899),
        ('k', 0.011016),
        ('v', 0.010074),
        ('x', 0.002902),
        ('z', 0.002722),
        ('j', 0.001965),
        ('q', 0.001962),
    ])
}
