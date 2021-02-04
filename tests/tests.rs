extern crate detached_jws;
#[macro_use]
extern crate lazy_static;

use anyhow::Result;
use detached_jws::{Sign, Verify};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::{hash::MessageDigest, pkey::Private};
use openssl::{
    rsa::Padding,
    sign::{Signer, Verifier},
};
use serde_json::{json, Map, Value};
use std::{io::Write, vec};

type JwsHeader = Map<String, Value>;

#[derive(Default)]
pub struct DummySigner(Vec<u8>);

impl Sign for DummySigner {
    fn get_sign(&self) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

impl Write for DummySigner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct DummyVerifier(Vec<u8>);

impl Verify for DummyVerifier {
    fn verify(&self, signature: &[u8]) -> Result<bool> {
        Ok(signature.eq(&self.0))
    }
}

impl Write for DummyVerifier {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn dummy_signer() {
    let mut header = Map::new();
    header.insert("custom".to_owned(), json!("custom_value"));

    let payload = vec![0, 1, 2, 3, 4, 5, 6];

    let jws = detached_jws::serialize(
        "test_algorithm".to_owned(),
        header,
        &mut payload.as_slice(),
        &mut DummySigner::default(),
    )
    .unwrap();

    let verified_headers =
        detached_jws::deserialize(&jws, &mut payload.as_slice(), &mut DummyVerifier::default())
            .unwrap();

    assert_eq!(
        verified_headers.get("custom").unwrap().as_str().unwrap(),
        "custom_value"
    );
}

#[test]
fn select_dummy_signer() {
    let mut header = Map::new();
    header.insert("custom".to_owned(), json!("custom_value"));
    header.insert("signer".to_owned(), json!("this"));

    let payload = vec![0, 1, 2, 3, 4, 5, 6];

    let jws = detached_jws::serialize(
        "test_algorithm".to_owned(),
        header,
        &mut payload.as_slice(),
        &mut DummySigner::default(),
    )
    .unwrap();

    let verified_headers = detached_jws::deserialize_selector(&jws, &mut payload.as_slice(), |h| {
        match h.get("signer").unwrap() {
            Value::String(ref v) if v == "this" => Some(Box::new(DummyVerifier::default())),
            _ => None,
        }
    })
    .unwrap();

    assert_eq!(
        verified_headers.get("custom").unwrap().as_str().unwrap(),
        "custom_value"
    );
}

#[test]
fn openssl_ps256() {
    let keypair = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

    let payload = vec![0, 1, 2, 3, 4, 5, 6];

    let jws = detached_jws::serialize(
        "PS256".to_owned(),
        Map::new(),
        &mut payload.as_slice(),
        &mut signer,
    )
    .unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

    detached_jws::deserialize(&jws, &mut payload.as_slice(), &mut verifier).unwrap();
}

#[test]
fn selector_openssl() {
    lazy_static! {
        static ref KEYPAIR_RS256: PKey<Private> =
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        static ref KEYPAIR_PS256: PKey<Private> =
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    }

    let selector = |h: &JwsHeader| -> Option<Box<dyn Verify>> {
        match h.get("alg").unwrap() {
            Value::String(ref v) if v == "RS256" => {
                let mut verifier =
                    Box::new(Verifier::new(MessageDigest::sha256(), &KEYPAIR_RS256).unwrap());
                verifier.set_rsa_padding(Padding::PKCS1).unwrap();
                Some(verifier)
            }
            Value::String(ref v) if v == "PS256" => {
                let mut verifier =
                    Box::new(Verifier::new(MessageDigest::sha256(), &KEYPAIR_PS256).unwrap());
                verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                Some(verifier)
            }
            _ => None,
        }
    };

    let payload = vec![0, 1, 2, 3, 4, 5, 6];

    {
        let mut signer = Signer::new(MessageDigest::sha256(), &KEYPAIR_RS256).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();

        let jws = signer
            .form_detached_jws("RS256".to_owned(), Map::new(), &mut payload.as_slice())
            .unwrap();

        detached_jws::deserialize_selector(&jws, &mut payload.as_slice(), selector).unwrap();
    }

    {
        let mut signer = Signer::new(MessageDigest::sha256(), &KEYPAIR_PS256).unwrap();
        signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();

        let jws = signer
            .form_detached_jws("PS256".to_owned(), Map::new(), &mut payload.as_slice())
            .unwrap();

        detached_jws::deserialize_selector(&jws, &mut payload.as_slice(), selector).unwrap();
    }
}
