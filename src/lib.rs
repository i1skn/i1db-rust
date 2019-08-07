// Copyright 2019 Ivan Sorokin.
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

//!Simple key-value store with transparent encryption.
//!## Quick Start
//!```
//!use hex::FromHex;
//!use i1db::{AESAlgo, EncryptedStore, MemoryStorage, Result};
//!
//!let key =
//!<[u8; 32]>::from_hex("3c37a0b33a0b364d58955a71550661d44403da007a638fdf19d494adb0986a3d")
//!    .unwrap();
//!
//!let mut algorithm = AESAlgo::new(key);
//!let mut storage = MemoryStorage::<String>::new();
//!let mut store = EncryptedStore::new(&mut storage, &mut algorithm);
//!
//!store.set("key1".to_owned(), "value1".to_owned()).unwrap();
//!println!("{}", store.get("key1".to_owned()).unwrap());
//!
//!```

#![crate_name = "i1db"]

extern crate rand;

use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::{aes, blockmodes, symmetriccipher};
use failure::Fail;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{de, Serialize};
use serde_json;
use std::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Fail, Debug)]
/// Error type
pub enum Error {
    #[fail(display = "Key doesn't exist: {}", _0)]
    KeyDoesNotExist(String),

    #[fail(display = "Encrption/Decryption error: {}", _0)]
    EncryptionDecryptionError(String),

    #[fail(display = "Serde error: {}", _0)]
    SerdeError(#[fail(cause)] serde_json::error::Error),

    #[fail(display = "UTF8 error: {}", _0)]
    Utf8Error(#[fail(cause)] std::string::FromUtf8Error),
}
/// Result type
pub type Result<T> = std::result::Result<T, Error>;

type AESIV = [u8; 16];

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        Error::SerdeError(err)
    }
}

impl From<symmetriccipher::SymmetricCipherError> for Error {
    fn from(err: symmetriccipher::SymmetricCipherError) -> Error {
        Error::EncryptionDecryptionError(match err {
            symmetriccipher::SymmetricCipherError::InvalidLength => "Invalid length".to_owned(),
            symmetriccipher::SymmetricCipherError::InvalidPadding => "Invalid padding".to_owned(),
        })
    }
}

/// Trait for implementing encryption/decryption
pub trait Algorithm<E, P: Serialize, N> {
    fn encrypt(&mut self, nonce: &N, plain: &P) -> Result<E>;
    fn decrypt(&mut self, nonce: &N, encrypted: &E) -> Result<P>;
}

/// AES implementation for Algorithm trait
pub struct AESAlgo {
    cryptic_key: [u8; 32],
}

impl AESAlgo {
    pub fn new(cryptic_key: [u8; 32]) -> AESAlgo {
        AESAlgo { cryptic_key }
    }
}

impl<P> Algorithm<Vec<u8>, P, AESIV> for AESAlgo
where
    P: Serialize + de::DeserializeOwned,
{
    fn encrypt(&mut self, iv: &AESIV, plain: &P) -> Result<Vec<u8>> {
        let data = serde_json::to_string(plain).map_err(|e| Error::from(e))?;

        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &self.cryptic_key,
            iv,
            blockmodes::PkcsPadding,
        );

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = RefReadBuffer::new(data.as_bytes());
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        loop {
            let result = encryptor
                .encrypt(&mut read_buffer, &mut write_buffer, true)
                .map_err(|e| Error::from(e))?;

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
    fn decrypt(&mut self, iv: &AESIV, encrypted: &Vec<u8>) -> Result<P> {
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            &self.cryptic_key,
            iv,
            blockmodes::PkcsPadding,
        );

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = RefReadBuffer::new(encrypted);
        let mut buffer = [0; 4096];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        loop {
            let result = decryptor
                .decrypt(&mut read_buffer, &mut write_buffer, true)
                .map_err(|e| Error::from(e))?;
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

        let value = String::from_utf8(final_result).map_err(|e| Error::from(e))?;
        let res: P = serde_json::from_str(&value).map_err(|e| Error::from(e))?;
        Ok(res)
    }
}

/// Trait to store the encrypted data
pub trait Storage<K: Eq, V, N> {
    fn generate_nonce(&self, key: &K) -> N;
    fn get(&self, key: K) -> Result<&V>;
    fn set(&mut self, key: K, value: V) -> Result<()>;
}

/// In-memory implementation for Storage trait
pub struct MemoryStorage<K: Hash + Eq> {
    map: HashMap<K, (Vec<u8>, AESIV)>,
}

impl<'a, K: Hash + Eq> MemoryStorage<K> {
    pub fn new() -> MemoryStorage<K> {
        MemoryStorage {
            map: HashMap::new(),
        }
    }
}

impl<K> Storage<K, (Vec<u8>, AESIV), AESIV> for MemoryStorage<K>
where
    K: Hash + Eq + ToString,
{
    fn generate_nonce(&self, _key: &K) -> AESIV {
        let mut iv: AESIV = [0; 16];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    fn get(&self, key: K) -> Result<&(Vec<u8>, AESIV)> {
        if let Some(value) = self.map.get(&key) {
            return Ok(value);
        }
        Err(Error::KeyDoesNotExist(key.to_string()))
    }
    fn set(&mut self, key: K, value: (Vec<u8>, AESIV)) -> Result<()> {
        self.map.insert(key, value);
        Ok(())
    }
}

/// Key-Value store with encryption
pub struct EncryptedStore<'a, E, P, N, K> {
    storage: &'a mut Storage<K, (E, N), N>,
    algorithm: &'a mut Algorithm<E, P, N>,
}

impl<'a, E, P, N, K> EncryptedStore<'a, E, P, N, K> {
    /// Create a new store
    pub fn new(
        storage: &'a mut Storage<K, (E, N), N>,
        algorithm: &'a mut Algorithm<E, P, N>,
    ) -> EncryptedStore<'a, E, P, N, K> {
        EncryptedStore { storage, algorithm }
    }

    pub fn set(&mut self, key: K, value: P) -> Result<()>
    where
        P: Serialize,
        K: Eq + Hash + Clone,
    {
        let iv = self.storage.generate_nonce(&key);
        let encrypted = self.algorithm.encrypt(&iv, &value)?;
        self.storage.set(key, (encrypted, iv))
    }

    pub fn get(&mut self, key: K) -> Result<P>
    where
        P: Serialize,
        K: Eq + Hash,
    {
        let (encrypted, iv) = self.storage.get(key)?;
        self.algorithm.decrypt(iv, encrypted)
    }
}
