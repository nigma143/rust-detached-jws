//! Serialize and sign Detached-Jws

use anyhow::{bail, Context, Result};
use base64::write::EncoderWriter;
use serde_json::value::Value;
use std::io::{Read, Write};

use crate::{JwsHeader, Sign};

static DOT_ARRAY: &[u8] = ".".as_bytes();

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
/// let jws = detached_jws::serialize(
///        "test_algorithm".to_owned(),
///        header,
///        &mut vec![0, 1, 2, 3, 4, 5, 6].as_slice(),
///        DummySigner::default()).unwrap();
///
/// assert_eq!(
///        String::from_utf8(jws).unwrap(),
///        "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn");
/// ```
pub fn serialize(
    algorithm: String,
    header: JwsHeader,
    payload: &mut impl Read,
    signer: impl Sign,
) -> Result<Vec<u8>> {
    let mut writer = SerializeJwsWriter::new(Vec::new(), algorithm, header, signer)?;
    std::io::copy(payload, &mut writer)?;
    writer.finish()
}

/// A `Write` implementation serialize to detached jws
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
/// use detached_jws::{SerializeJwsWriter, Sign};
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
/// let mut writer = SerializeJwsWriter::new(Vec::new(),
///        "test_algorithm".to_owned(),
///        header,
///        DummySigner::default()).unwrap();
/// writer.write_all(&[0, 1, 2, 3]);
/// writer.write_all(&[4, 5, 6]);
///
/// let jws = writer.finish().unwrap();
///
/// assert_eq!(
///        String::from_utf8(jws).unwrap(),
///        "eyJhbGciOiJ0ZXN0X2FsZ29yaXRobSIsImN1c3RvbSI6ImN1c3RvbV92YWx1ZSJ9..ZXlKaGJHY2lPaUowWlhOMFgyRnNaMjl5YVhSb2JTSXNJbU4xYzNSdmJTSTZJbU4xYzNSdmJWOTJZV3gxWlNKOS5BQUVDQXdRRkJn");
/// ```
pub struct SerializeJwsWriter<W, S: Write> {
    delegate: Option<W>,
    encoder: EncoderWriter<S>,
}

impl<W, S> SerializeJwsWriter<W, S>
where
    W: Write,
    S: Sign,
{
    pub fn new(
        mut writer: W,
        algorithm: String,
        mut header: JwsHeader,
        mut signer: S,
    ) -> Result<Self> {
        header.insert("alg".to_owned(), Value::String(algorithm));

        let encoded_header = {
            let mut encoder = EncoderWriter::new(Vec::new(), base64::URL_SAFE_NO_PAD);
            serde_json::to_writer(&mut encoder, &header)?;
            encoder.finish()?
        };

        signer.write_all(&encoded_header)?;
        signer.write_all(DOT_ARRAY)?;

        writer.write_all(&encoded_header)?;
        writer.write_all(DOT_ARRAY)?;
        writer.write_all(DOT_ARRAY)?;

        Ok(Self {
            delegate: Some(writer),
            encoder: EncoderWriter::new(signer, base64::URL_SAFE_NO_PAD),
        })
    }

    pub fn finish(&mut self) -> Result<W> {
        if self.delegate.is_none() {
            bail!("Serializer has already had finish() called")
        };

        let signer = self.encoder.finish()?;

        let signature = signer.get_sign()?;

        let encoded_signature = {
            let mut encoder = EncoderWriter::new(Vec::new(), base64::URL_SAFE_NO_PAD);
            encoder.write_all(&signature)?;
            encoder.finish()?
        };

        self.delegate
            .as_mut()
            .unwrap()
            .write_all(&encoded_signature)?;

        Ok(self.delegate.take().context("Writer must be present")?)
    }
}

impl<W, S> Write for SerializeJwsWriter<W, S>
where
    S: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encoder.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.encoder.flush()
    }
}
