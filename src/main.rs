mod structurs;

extern crate crypto;
extern crate rand;

use std::fs::{copy, File};
use std::io::{BufReader, Read, stdout, Write};
use std::path::Path;
use std::string::FromUtf8Error;
use crypto::{symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use inquire::{CustomType, InquireError, required, Select, Text};
use inquire::validator::Validation;
use console::Term;
use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use crate::structurs::FileStruct;

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = r#try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = r#try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn bytes_to_string(bytes: Vec::<u8>) -> Result<String, FromUtf8Error> {
    String::from_utf8(bytes)
}

fn main() {
    let term = Term::stdout();
    term.set_title("File decryptor and cryptor");
    let file_text = CustomType::<String>::new("File:")
        .with_help_message("File for decrypt\\encrypt")
        .with_error_message("Please type a valid file")
        .with_validator(|val: &String| {
            let path = Path::new(val);
            if path.exists() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "File does not exist".into(),
                ))
            }
        })
        .prompt();

    match file_text {
        Ok(file_text) => {
            let file_text2 = file_text.clone();

            let key_text = CustomType::<String>::new("Key:")
                .with_help_message("Key for file")
                .with_error_message("Please type a valid key")
                .with_placeholder("key")
                .with_validator(|val: &String| {
                    if val.len() != 32 {
                        Ok(Validation::Invalid(
                            "Invalid key".into(),
                        ))
                    } else {
                        if val.as_bytes().len() != 32 {
                            Ok(Validation::Invalid(
                                "Invalid key".into(),
                            ))
                        }
                        else {
                            Ok(Validation::Valid)
                        }
                    }
                })
                .prompt();

            let iv_text = CustomType::<String>::new("IV:")
                .with_help_message("IV for file")
                .with_error_message("Please type a valid IV")
                .with_validator(|val: &String| {
                    if val.len() != 16 {
                        Ok(Validation::Invalid(
                            "Invalid IV".into(),
                        ))
                    } else {
                        if val.as_bytes().len() != 16 {
                            Ok(Validation::Invalid(
                                "Invalid IV".into(),
                            ))
                        }
                        else {
                            Ok(Validation::Valid)
                        }
                    }
                })
                .prompt();

            match key_text {
                Ok(key_text) => {
                    match iv_text {
                        Ok(iv_text) => {
                            let key = key_text.as_bytes();
                            let iv = iv_text.as_bytes();
                            let mut f = File::open(file_text);
                            match f {
                                Ok(mut file) => {
                                    let mut buffer = Vec::<u8>::new();
                                    // read the whole file
                                    let readed = file.read_to_end(&mut buffer);
                                    match readed {
                                        Ok(_) => {
                                            let options: Vec<&str> = vec!["Decrypt", "Encrypt"];

                                            let ans: Result<&str, InquireError> = Select::new("What action to take?", options).prompt();
                                            let extension = Path::new(&file_text2);

                                            match ans {
                                                Ok(choice) => {
                                                    if choice == "Decrypt" {
                                                        let decompressed = decompress_to_vec_with_limit(buffer.as_slice(), usize::MAX).expect("Failed to decompress!");
                                                        let decrypted_data = decrypt(decompressed.as_slice(), &key, &iv).ok().unwrap();

                                                        let json = bytes_to_string(decrypted_data);
                                                        match json {
                                                            Ok(json) => {
                                                                let file_struct = serde_json::from_str::<FileStruct>(json.as_str());
//
                                                                match file_struct {
                                                                    Ok(mut FileStruct) => {
                                                                        println!("{}", extension.file_stem().unwrap().to_str().unwrap());
                                                                        let mut f = File::create(format!("{}.{}",  extension.file_stem().unwrap().to_str().unwrap(), FileStruct.format));
                                                                        match f {
                                                                            Ok(mut file) => {
                                                                                let decompressed = decompress_to_vec_with_limit(FileStruct.file.as_slice(), usize::MAX).expect("Failed to decompress!");
                                                                                file.write_all(decompressed.as_slice()).expect("Error writing encrypted file");
                                                                            }
                                                                            Err(_) => println!("Error creating file"),
                                                                        }
                                                                    }
                                                                    Err(_) => println!("Error reading file"),
                                                                }

                                                            }
                                                            Err(_) => println!("Error reading file"),
                                                        }


                                                    }
                                                    else if choice == "Encrypt" {
                                                        let compressed = compress_to_vec(buffer.as_slice(), 6);
                                                        let filest = FileStruct {
                                                            format: extension.extension().unwrap().to_str().unwrap().to_string(),
                                                            file: compressed,
                                                        };
                                                        let json = serde_json::to_string(&filest);
                                                        match json {
                                                            Ok(json) => {
                                                                let mut encrypted_data = encrypt(json.as_bytes(), &key, &iv).ok().unwrap();

                                                                let compressed = compress_to_vec(encrypted_data.as_slice(), 6);

                                                                let mut f = File::create(format!("{}.pt",  extension.file_stem().unwrap().to_str().unwrap()));
                                                                match f {
                                                                    Ok(mut file) => {
                                                                        file.write_all(compressed.as_slice()).expect("Error writing encrypted file");
                                                                    }
                                                                    Err(_) => println!("Error creating file"),
                                                                }
                                                            }
                                                            Err(_) => println!("Error creating file"),
                                                        }



                                                    }
                                                },
                                                Err(_) => println!("There was an error, please try again"),
                                            }

                                        }
                                        Err(_) => println!("Failed to open file"),
                                    }
                                }
                                Err(_) => println!("Failed to open file"),
                            }
                        },
                        Err(_) => println!("Failed to read the key"),
                    }
                },
                Err(_) => println!("Failed to read the key"),
            }

        },
        Err(_) => println!("File not found"),
    }
}