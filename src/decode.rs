//! Verify and deserialize Detached-Jws

use anyhow::{bail, Context, Result};
use base64::{read::DecoderReader, write::EncoderWriter};
use serde_json::{Map, Value};
use std::io::{Read, Write};

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
/// let jws =  "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn".as_bytes();
///
/// let verified_headers = detached_jws::deserialize_selector(
///     &jws,
///     &mut vec![0, 1, 2, 3, 4, 5, 6].as_slice(),
///     |h| {
///         match h.get("alg").unwrap() {
///             Value::String(ref v) if v == "test_algorithm" => Some(DummyVerifier::default()),
///             _ => None,
///         }
/// }).unwrap();
///
/// assert_eq!(
///     verified_headers.get("custom").unwrap().as_str().unwrap(),
///     "custom_value"
/// );
/// ```
pub fn deserialize_selector<F, V>(
    jws: &impl AsRef<[u8]>,
    payload: &mut impl Read,
    selector: F,
) -> Result<JwsHeader>
where
    F: Fn(&JwsHeader) -> Option<V>,
    V: Verify,
{
    let mut writer = DeserializeJwsWriter::new(jws, selector)?;
    std::io::copy(payload, &mut writer)?;
    writer.finish()
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
///     DummyVerifier::default()).unwrap();
///
/// assert_eq!(
///     verified_headers.get("custom").unwrap().as_str().unwrap(),
///     "custom_value"
/// );
/// ```
pub fn deserialize<V>(
    jws: &impl AsRef<[u8]>,
    payload: &mut impl Read,
    verifier: V,
) -> Result<JwsHeader>
where
    V: Verify,
{
    let mut writer = DeserializeJwsWriter::new(jws, move |_| Some(verifier))?;
    std::io::copy(payload, &mut writer)?;
    writer.finish()
}

/// A `Write` implementation deserialize and verify detached jws
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
/// use detached_jws::{Verify, DeserializeJwsWriter};
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
/// let jws =  "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn".as_bytes();
///
/// let mut writer = DeserializeJwsWriter::new(&jws,
///     |h| Some(DummyVerifier::default())
/// ).unwrap();
/// writer.write_all(&[0, 1, 2, 3]);
/// writer.write_all(&[4, 5, 6]);
///
/// let verified_headers = writer.finish().unwrap();
///
/// assert_eq!(
///     verified_headers.get("custom").unwrap().as_str().unwrap(),
///     "custom_value"
/// );
/// ```
pub struct DeserializeJwsWriter<V: Write> {
    encoder: EncoderWriter<V>,
    header: Option<JwsHeader>,
    signature: Vec<u8>,
}

impl<V> DeserializeJwsWriter<V>
where
    V: Verify,
{
    pub fn new<S>(jws: &impl AsRef<[u8]>, selector: S) -> Result<Self>
    where
        S: FnOnce(&JwsHeader) -> Option<V>,
    {
        let input = jws.as_ref();

        let mut splits = input.split(|e| e == &DOT_BYTE);

        let encoded_header = splits.next().context("wrong jws format")?.to_vec();

        let header = {
            let mut slice = encoded_header.as_slice();
            let decoder = DecoderReader::new(&mut slice, base64::URL_SAFE_NO_PAD);
            serde_json::from_reader(decoder).context("wrong jws header format")?
        };

        let mut splits = splits.skip(1); //detached payload skip

        let signature = {
            let mut part3 = splits.next().context("wrong jws format")?;
            base64::decode_config(&mut part3, base64::URL_SAFE_NO_PAD)
                .context("wrong jws signature format")?
        };

        let mut verifier = selector(&header).context("verifier is not found")?;

        verifier.write_all(encoded_header.as_slice())?;
        verifier.write_all(&[DOT_BYTE])?;

        Ok(Self {
            encoder: EncoderWriter::new(verifier, base64::URL_SAFE_NO_PAD),
            header: Some(header),
            signature: signature,
        })
    }

    pub fn finish(&mut self) -> Result<JwsHeader> {
        if self.header.is_none() {
            bail!("Derializer has already had finish() called")
        };

        let verifier = self.encoder.finish()?;

        match verifier.verify(&self.signature)? {
            true => Ok(self.header.take().unwrap()),
            false => bail!("incorrect signature"),
        }
    }
}

impl<V> Write for DeserializeJwsWriter<V>
where
    V: Verify,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encoder.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.encoder.flush()
    }
}
