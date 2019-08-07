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

use i1db::{AESAlgo, EncryptedStore, MemoryStorage, Result};
use rand::rngs::OsRng;
use rand::RngCore;

#[test]
fn get_stored_value() -> Result<()> {
    let mut key: [u8; 32] = [0; 32];
    OsRng.fill_bytes(&mut key);

    let mut algorithm = AESAlgo::new(key);
    let mut storage = MemoryStorage::<String>::new();

    let mut store: EncryptedStore<_, String, _, _> =
        EncryptedStore::new(&mut storage, &mut algorithm);

    assert!(store.get("key1".to_owned()).is_err());

    store.set("key1".to_owned(), "value1".to_owned())?;
    store.set("key2".to_owned(), "value2".to_owned())?;

    assert_eq!(store.get("key1".to_owned())?, "value1".to_owned());
    assert_eq!(store.get("key2".to_owned())?, "value2".to_owned());

    Ok(())
}

#[test]
fn wrong_key() -> Result<()> {
    let mut key: [u8; 32] = [0; 32];
    OsRng.fill_bytes(&mut key);
    let mut algorithm = AESAlgo::new(key);

    let mut storage = MemoryStorage::<String>::new();

    let mut store: EncryptedStore<_, String, _, _> =
        EncryptedStore::new(&mut storage, &mut algorithm);

    store.set("key1".to_owned(), "value1".to_owned())?;

    assert_eq!(store.get("key1".to_owned())?, "value1".to_owned());

    drop(store);
    drop(algorithm);
    OsRng.fill_bytes(&mut key);
    let mut algorithm = AESAlgo::new(key);

    let mut store: EncryptedStore<_, String, _, _> =
        EncryptedStore::new(&mut storage, &mut algorithm);

    assert!(store.get("key1".to_owned()).is_err());

    Ok(())
}
