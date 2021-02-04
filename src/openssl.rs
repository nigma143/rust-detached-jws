//! [openssl](https://crates.io/crates/openssl) implementations for [`Verify`] and [`Sign`]

use anyhow::Result;
use openssl::sign::{Signer, Verifier};

use crate::{Sign, Verify};

impl<'a> Verify for Verifier<'a> {
    fn verify(&self, signature: &[u8]) -> Result<bool> {
        Ok(self.verify(signature)?)
    }
}

impl<'a> Sign for Signer<'a> {
    fn get_sign(&self) -> Result<Vec<u8>> {
        Ok(self.sign_to_vec()?)
    }
}
