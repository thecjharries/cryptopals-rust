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

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use std::collections::HashSet;

use crate::pkcs7::{pkcs7_padding_add, pkcs7_padding_remove};

pub fn encrypt_aes_128_ecb_block(block: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut block = GenericArray::clone_from_slice(&block);
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

pub fn decrypt_aes_128_ecb_block(block: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut blocks = GenericArray::clone_from_slice(&block);
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    cipher.decrypt_block(&mut blocks);
    blocks.to_vec()
}

pub fn encrypt_aes_128_ecb(plaintext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut blocks = Vec::new();
    for block in plaintext.chunks(16) {
        blocks.push(GenericArray::clone_from_slice(block));
    }
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    cipher.encrypt_blocks(&mut blocks);
    blocks
        .iter()
        .map(|block| block.to_vec())
        .flatten()
        .collect::<Vec<u8>>()
}

pub fn decrypt_aes_128_ecb(ciphertext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let key = GenericArray::from_slice(&key);
    let mut blocks = Vec::new();
    for block in ciphertext.chunks(16) {
        blocks.push(GenericArray::clone_from_slice(block));
    }
    let cipher = Aes128::new(&key);
    cipher.decrypt_blocks(&mut blocks);
    blocks
        .iter()
        .map(|block| block.to_vec())
        .flatten()
        .collect::<Vec<u8>>()
}

pub fn encrypt_aes_128_cbc(plaintext: Vec<u8>, iv: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let plaintext = pkcs7_padding_add(plaintext, 16);
    let mut blocks = Vec::new();
    for block in plaintext.chunks(16) {
        blocks.push(GenericArray::clone_from_slice(block));
    }
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    let mut previous_block = GenericArray::clone_from_slice(&iv);
    let mut ciphertext = Vec::new();
    for block in blocks {
        let mut encrypted_block = block.clone();
        for (index, byte) in encrypted_block.iter_mut().enumerate() {
            *byte ^= previous_block[index];
        }
        cipher.encrypt_block(&mut encrypted_block);
        ciphertext.append(&mut encrypted_block.to_vec());
        previous_block = encrypted_block;
    }
    ciphertext
}

pub fn decrypt_aes_128_cbc(ciphertext: Vec<u8>, iv: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut blocks = Vec::new();
    for block in ciphertext.chunks(16) {
        blocks.push(GenericArray::clone_from_slice(block));
    }
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);
    let mut previous_block = GenericArray::clone_from_slice(&iv);
    let mut decrypted = Vec::new();
    for block in blocks {
        let mut decrypted_block = block.clone();
        cipher.decrypt_block(&mut decrypted_block);
        for (index, byte) in decrypted_block.iter_mut().enumerate() {
            *byte ^= previous_block[index];
        }
        decrypted.append(&mut decrypted_block.to_vec());
        previous_block = block;
    }
    pkcs7_padding_remove(decrypted)
}

pub fn guess_was_aes_ecb_used(ciphertext: Vec<u8>) -> bool {
    let mut blocks = HashSet::new();
    for block in ciphertext.chunks(16) {
        if blocks.contains(block) {
            return true;
        }
        blocks.insert(block);
    }
    false
}

#[cfg(not(tarpaulin_include))]
#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use base64::{engine::general_purpose, Engine as _};

    use crate::util::get_challenge_data;

    #[test]
    fn encrypt_aes_128_ecb_block_should_properly_encrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block.to_vec(),
            encrypt_aes_128_ecb_block(decrypted, key.to_vec())
        );
    }

    #[test]
    fn decrypt_aes_128_ecb_block_should_properly_decrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            decrypted,
            decrypt_aes_128_ecb_block(block.to_vec(), key.to_vec())
        );
    }

    #[test]
    fn encrypt_aes_128_ecb_should_properly_encrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), encrypt_aes_128_ecb(decrypted, key.to_vec()));
    }

    #[test]
    // https://docs.rs/aes/latest/aes/index.html#examples
    fn decrypt_aes_128_ecb_should_properly_decrypt() {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let decrypted = block.clone().to_vec();
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(decrypted, decrypt_aes_128_ecb(block.to_vec(), key.to_vec()));
    }

    #[test]
    fn encrypt_aes_128_cbc_should_properly_encrypt() {
        let data = get_challenge_data(10).replace("\n", "");
        let ciphertext = general_purpose::STANDARD
            .decode(data.as_bytes().to_vec())
            .unwrap();
        let plaintext = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\
                   \x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(
            ciphertext,
            encrypt_aes_128_cbc(plaintext.to_vec(), iv.to_vec(), key.to_vec())
        );
    }

    #[test]
    fn decrypt_aes_128_cbc_should_properly_decrypt() {
        let data = get_challenge_data(10).replace("\n", "");
        let ciphertext = general_purpose::STANDARD
            .decode(data.as_bytes().to_vec())
            .unwrap();
        let plaintext = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\
                   \x00\x00\x00\x00\x00\x00\x00\x00";
        let decrypted = String::from_utf8(decrypt_aes_128_cbc(
            ciphertext.clone(),
            iv.to_vec(),
            key.to_vec(),
        ))
        .unwrap();
        for line in decrypted.lines() {
            println!("'{}'", line);
        }
        assert_eq!(
            plaintext.to_vec(),
            decrypt_aes_128_cbc(ciphertext, iv.to_vec(), key.to_vec())
        );
    }

    #[test]
    fn guess_was_aes_ecb_used_should_return_true_when_duplicate_blocks() {
        let ciphertext = b"YELLOW SUBMARINEYELLOW SUBMARINE".to_vec();
        assert!(guess_was_aes_ecb_used(ciphertext));
    }
}
