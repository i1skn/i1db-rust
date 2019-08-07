# i1db

Simple key-value store with transparent encryption.
## Quick Start
```
use hex::FromHex;
use i1db::{AESAlgo, EncryptedStore, MemoryStorage, Result};

let key =
<[u8; 32]>::from_hex("3c37a0b33a0b364d58955a71550661d44403da007a638fdf19d494adb0986a3d")
    .unwrap();

let mut algorithm = AESAlgo::new(key);
let mut storage = MemoryStorage::<String>::new();
let mut store = EncryptedStore::new(&mut storage, &mut algorithm);

store.set("key1".to_owned(), "value1".to_owned()).unwrap();
println!("{}", store.get("key1".to_owned()).unwrap());

```
## Documentation

`cargo doc --open`

## Test

`cargo test`

## License

Apache License v2.0.
