//! Verify and deserialize Detached-Jws

use anyhow::{bail, Context, Result};
use base64::{read::DecoderReader, write::EncoderWriter};
use serde_json::{Map, Value};
use std::{io::Read};

use crate::Verify;

type JwsHeader = Map<String, Value>;

static DOT_BYTE: u8 = b'.';

/// Deserialize and verify detached jws
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
/// use serde_json::{Map, Value};
/// use detached_jws::{Verify};
///
///#[derive(Default)]
/// pub struct DummyVerifier;
///
/// impl Verify for DummyVerifier {
///     fn verify(&self, signature: &[u8]) -> Result<bool> {
///         Ok(true)
///     }
/// }
///
/// impl Write for DummyVerifier {
///     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
///         Ok(buf.len())
///     }
///     fn flush(&mut self) -> std::io::Result<()> {
///        Ok(())
///     }
/// }
///
/// let detached_jws =  "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn".as_bytes();
///
/// let verified_headers = detached_jws::deserialize_selector(
///     &detached_jws,
///     &mut vec![0, 1, 2, 3, 4, 5, 6].as_slice(),
///     |h| {
///         match h.get("alg").unwrap() {
///             Value::String(ref v) if v == "test_algorithm" => Some(Box::new(DummyVerifier::default())),
///             _ => None,
///         }
/// }).unwrap();
///
/// assert_eq!(
///     verified_headers.get("custom").unwrap().as_str().unwrap(),
///     "custom_value"
/// );
/// ```
pub fn deserialize_selector<F>(
    jws: &impl AsRef<[u8]>,
    payload: &mut impl Read,
    selector: F,
) -> Result<JwsHeader>
where
    F: Fn(&JwsHeader) -> Option<Box<dyn Verify>>,
{
    let headers = exact_jws_header(jws)?;

    let mut verifier = selector(&headers).context("verifier is not found")?;

    verify(jws, payload, &mut *verifier)?;

    Ok(headers)
}

/// Deserialize and verify detached jws.
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
/// use serde_json::{Map};
/// use detached_jws::{Verify};
///
///#[derive(Default)]
/// pub struct DummyVerifier;
///
/// impl Verify for DummyVerifier {
///     fn verify(&self, signature: &[u8]) -> Result<bool> {
///         Ok(true)
///     }
/// }
///
/// impl Write for DummyVerifier {
///     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
///         Ok(buf.len())
///     }
///     fn flush(&mut self) -> std::io::Result<()> {
///        Ok(())
///     }
/// }
///
/// let detached_jws =  "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn".as_bytes();
///
/// let verified_headers = detached_jws::deserialize(
///     &detached_jws,
///     &mut vec![0, 1, 2, 3, 4, 5, 6].as_slice(),
///     &mut DummyVerifier::default()).unwrap();
///
/// assert_eq!(
///     verified_headers.get("custom").unwrap().as_str().unwrap(),
///     "custom_value"
/// );
/// ```
pub fn deserialize(
    jws: &impl AsRef<[u8]>,
    payload: &mut impl Read,
    verifier: &mut (impl Verify + ?Sized),
) -> Result<JwsHeader> {
    let headers = exact_jws_header(jws)?;

    verify(jws, payload, verifier)?;

    Ok(headers)
}

fn exact_jws_header(jws: &impl AsRef<[u8]>) -> Result<JwsHeader> {
    let input = jws.as_ref();

    let mut splits = input.split(|e| e == &DOT_BYTE);

    let mut part1 = splits.next().context("wrong jws format")?;
    let decoder = DecoderReader::new(&mut part1, base64::URL_SAFE_NO_PAD);
    serde_json::from_reader(decoder).context("wrong jws header format")
}

fn verify(
    jws: &impl AsRef<[u8]>,
    payload: &mut impl Read,
    verifier: &mut (impl Verify + ?Sized),
) -> Result<()> {
    let input = jws.as_ref();

    let mut splits = input.split(|e| e == &DOT_BYTE);

    let headers = splits.next().context("wrong jws format")?;
    let mut splits = splits.skip(1); //detached payload skip
    let signature = {
        let mut part3 = splits.next().context("wrong jws format")?;
        base64::decode_config(&mut part3, base64::URL_SAFE_NO_PAD)
            .context("wrong jws signature format")?
    };

    verifier.write_all(headers)?;
    verifier.write_all(&[DOT_BYTE])?;

    let mut payload_encoder = EncoderWriter::new(verifier, base64::URL_SAFE_NO_PAD);
    std::io::copy(payload, &mut payload_encoder)?;
    let verifier = payload_encoder.finish()?;

    match verifier.verify(&signature)? {
        true => Ok(()),
        false => bail!("incorrect signature"),
    }
}
