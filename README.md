[![Documentation](https://docs.rs/detached-jws/badge.svg)](https://docs.rs/detached-jws)
[![crates.io](https://img.shields.io/crates/v/detached-jws.svg)](https://crates.io/crates/detached-jws)

# detached-jws

Encoding, decoding, signing and verification ([Detached JWS](https://medium.com/gin-and-tonic/implementing-detached-json-web-signature-9ca5665ddcfc))

Signing and verifying is done through the [`Sign`] and [`Verify`] traits.

## Example with writer:
```rust
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::{hash::MessageDigest};
use openssl::{
    rsa::Padding,
    sign::{Signer, Verifier},
};
use serde_json::{json, Map, Value};
use std::io::{Write};
use detached_jws::{SerializeJwsWriter, DeserializeJwsWriter};

let keypair = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

let mut header = Map::new();
header.insert("custom".to_owned(), json!("custom_value"));

let mut writer = SerializeJwsWriter::new(Vec::new(),
       "PS256".to_owned(),
       header,
       signer).unwrap();
writer.write_all(&[0, 1, 2, 3]);
writer.write_all(&[4, 5, 6]);

let jws = writer.finish().unwrap();

let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

let mut writer = DeserializeJwsWriter::new(&jws,
    |h| Some(verifier)
).unwrap();
writer.write_all(&[0, 1, 2, 3]);
writer.write_all(&[4, 5, 6]);

let verified_headers = writer.finish().unwrap();

assert_eq!(
    verified_headers.get("custom").unwrap().as_str().unwrap(),
    "custom_value"
);
```

## Simple example:
```rust
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::{hash::MessageDigest};
use openssl::{
    rsa::Padding,
    sign::{Signer, Verifier},
};
use serde_json::{json, Map, Value};

let keypair = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

let mut header = Map::new();
header.insert("custom".to_owned(), json!("custom_value"));

let payload = vec![0, 1, 2, 3, 4, 5, 6];

let jws = detached_jws::serialize(
    "PS256".to_owned(),
    header,
    &mut payload.as_slice(),
    signer,
)
.unwrap();

let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

let verified_headers =
    detached_jws::deserialize(&jws, &mut payload.as_slice(), verifier).unwrap();

assert_eq!(
    verified_headers.get("custom").unwrap().as_str().unwrap(),
    "custom_value"
);
```
