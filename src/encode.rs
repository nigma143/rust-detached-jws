//! Serialize and sign Detached-Jws

use anyhow::Result;
use base64::write::EncoderWriter;
use serde_json::{value::Value};
use std::io::{Read, Write};

use crate::{JwsHeader, Sign};

/// Serialize to detached jws
///
/// # Examples
///
/// ```
/// extern crate detached_jws;
/// extern crate anyhow;
/// extern crate serde_json;
///
/// use std::io::{Write};
/// use anyhow::Result;
/// use serde_json::{json, Map};
/// use detached_jws::{Sign};
///
///#[derive(Default)]
/// pub struct DummySigner(Vec<u8>);
///
/// impl Sign for DummySigner {
///     fn get_sign(&self) -> Result<Vec<u8>> {
///         Ok(self.0.clone())
///     }
/// }
///
/// impl Write for DummySigner {
///     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
///         self.0.write(buf)
///     }
///     fn flush(&mut self) -> std::io::Result<()> {
///        Ok(())
///     }
/// }
///
/// let mut header = Map::new();
/// header.insert("custom".to_owned(), json!("custom_value"));
///
/// let detached_jws = detached_jws::serialize(
///        "test_algorithm".to_owned(),
///        header,
///        &mut vec![0, 1, 2, 3, 4, 5, 6].as_slice(),
///        &mut DummySigner::default()).unwrap();
///
/// assert_eq!(
///        String::from_utf8(detached_jws).unwrap(),
///        "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn");
/// ```
pub fn serialize(
    algorithm: String,
    mut header: JwsHeader,
    payload: &mut impl Read,
    signer: &mut impl Sign,
) -> Result<Vec<u8>> {
    static DOT_ARRAY: &[u8] = ".".as_bytes();

    header.insert("alg".to_owned(), Value::String(algorithm));

    let encoded_header = {
        let mut encoder = EncoderWriter::new(Vec::new(), base64::URL_SAFE_NO_PAD);
        serde_json::to_writer(&mut encoder, &header)?;
        encoder.finish()?
    };

    signer.write_all(&encoded_header)?;
    signer.write_all(DOT_ARRAY)?;

    let mut payload_encoder = EncoderWriter::new(signer, base64::URL_SAFE_NO_PAD);
    std::io::copy(payload, &mut payload_encoder)?;
    let signer = payload_encoder.finish()?;

    let signature = signer.get_sign()?;

    let encoded_signature = {
        let mut encoder = EncoderWriter::new(Vec::new(), base64::URL_SAFE_NO_PAD);
        encoder.write_all(&signature)?;
        encoder.finish()?
    };

    Ok([&encoded_header, DOT_ARRAY, DOT_ARRAY, &encoded_signature].concat())
}
