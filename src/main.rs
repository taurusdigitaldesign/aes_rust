
extern crate crypto;
extern crate base64;

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;

use std::str;
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};

use base64::{encode};

fn main() {
    // 输出
    println!("Hello, world!");

    // Base64:encode
    let a = b"abc";
    println!("{}", encode(a));

    // Base64:decode
    let b = String::from("eyJhIjoiYiIsImIiOiJjIn0=");
    let tmp = base64::decode(b).unwrap();
    let msg = str::from_utf8(&tmp).unwrap();
    println!("{}", msg);

    // SHA加密
    let mut hasher = Sha3::sha3_256();
    hasher.input_str("abc");
    let hex = hasher.result_str();
    println!("\nBlake3 Hash: {}", hex);

    // 字符串转u8
    let key = String::from("abc");
    let msg = str::from_utf8(key.as_bytes()).unwrap();
    println!("{}", msg);
    println!("abc = {:?}", key.as_bytes());



    let key = String::from("axb2c3e4f5$6e7%8");
    let iv = String::from("a1b2c3d4e5f6g7h8");

    // AES加密
    let data = String::from("abc");
    let encrypted_data = encrypt(data.as_bytes(), key.as_bytes(), iv.as_bytes()).ok().unwrap();
    println!(
        "message->encrypted:{:?} byte_len:{}",
        encrypted_data,
        encrypted_data.len()
    );
    println!("{}", base64::encode(&encrypted_data));

    // AES解密
    let endata = String::from("bbWrOxhQQsC13jv3OKRF+Q==");
    let bytes = base64::decode(&endata).unwrap();
    let decrypted_data = decrypt(&bytes, key.as_bytes(), iv.as_bytes()).ok().unwrap();
    println!(
        "message->decrypted:{:?} byte_len:{}",
        decrypted_data,
        decrypted_data.len()
    );
    println!("{}", str::from_utf8(&decrypted_data).unwrap());
}

fn encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8]
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize128, key, iv, blockmodes::PkcsPadding);
    
    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn decrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8]
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize128, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}


