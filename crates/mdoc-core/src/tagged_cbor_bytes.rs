use minicbor::{Encode, Encoder, Decode, Decoder};
use minicbor::data::Tagged;
use minicbor::decode::{Error as DecodeError};
use minicbor::encode::{Error as EncodeError, Write};
use std::fmt;
use std::marker::PhantomData;

#[derive(Clone, PartialEq, Eq)]
pub struct CborAny(Vec<u8>);

impl CborAny {
    pub fn new(raw_cbor_bytes: impl Into<Vec<u8>>) -> Self {
        Self(raw_cbor_bytes.into())
    }

    pub fn raw_cbor_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn decode<T>(&self) -> Result<T, DecodeError>
    where
        T: for<'a> Decode<'a, ()>,
    {
        minicbor::decode(&self.0)
    }
}

impl fmt::Debug for CborAny {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CborAny").field(&self.0).finish()
    }
}

impl<C> Encode<C> for CborAny {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.writer_mut()
            .write_all(&self.0)
            .map_err(EncodeError::write)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for CborAny {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(Self::new(d.input()[start..end].to_vec()))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CborBytes<T> {
    raw: CborAny,
    marker: PhantomData<fn() -> T>,
}

impl<T> CborBytes<T> {
    pub fn from_raw_bytes(raw_cbor_bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            raw: CborAny::new(raw_cbor_bytes),
            marker: PhantomData,
        }
    }

    pub fn raw_cbor_bytes(&self) -> &[u8] {
        self.raw.raw_cbor_bytes()
    }

    pub fn decode(&self) -> Result<T, DecodeError>
    where
        T: for<'a> Decode<'a, ()>,
    {
        self.raw.decode()
    }
}

impl<T> fmt::Debug for CborBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CborBytes")
            .field("raw_cbor_bytes", &self.raw_cbor_bytes())
            .finish()
    }
}

impl<T> From<&T> for CborBytes<T>
where
    T: Encode<()>,
{
    fn from(value: &T) -> Self {
        Self::from_raw_bytes(
            minicbor::to_vec(value).expect("encoding CborBytes inner value should not fail"),
        )
    }
}

impl<T, C> Encode<C> for CborBytes<T>
where
    T: Encode<()>,
{
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.bytes(self.raw_cbor_bytes())?;
        Ok(())
    }
}

impl<'b, T, C> Decode<'b, C> for CborBytes<T>
where
    T: for<'a> Decode<'a, ()> + Encode<()>,
{
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?;
        Ok(Self::from_raw_bytes(bytes.to_vec()))
    }
}

#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(transparent)]
pub struct TaggedCborBytes<T: Encode<()> + for<'a> Decode<'a, ()>>(Tagged<24, CborBytes<T>>);

impl<T> TaggedCborBytes<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    pub fn value(&self) -> &CborBytes<T> {
        self.0.value()
    }

    pub fn raw_cbor_bytes(&self) -> &[u8] {
        self.value().raw_cbor_bytes()
    }

    pub fn decode(&self) -> Result<T, DecodeError>
    {
        self.value().decode()
    }
}

impl<T> fmt::Debug for TaggedCborBytes<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaggedCborBytes")
            .field("raw_cbor_bytes", &self.raw_cbor_bytes())
            .finish()
    }
}

impl<T> From<&T> for TaggedCborBytes<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn from(value: &T) -> Self {
        Self(Tagged::from(CborBytes::from(value)))
    }
}

impl<T> From<CborBytes<T>> for TaggedCborBytes<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn from(value: CborBytes<T>) -> Self {
        Self(Tagged::from(value))
    }
}

pub type ElementValue = CborAny;
pub type FullDate = Tagged<1004, String>;

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::bytes::ByteVec;
    use minicbor::{Decode, Encode};

    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct {
        #[n(0)]
        pub version: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct2 {
        #[n(0)]
        pub tagged: TaggedCborBytes<TestStruct>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct3 {
        #[n(0)]
        pub tagged: Tagged<24, ByteVec>,
    }

    #[test]
    fn cbor_any_round_trips_raw_item() {
        let encoded = minicbor::to_vec(Tagged::<1004, &str>::from("2026-04-04")).unwrap();
        let value: CborAny = minicbor::decode(&encoded).unwrap();

        assert_eq!(value.raw_cbor_bytes(), encoded);

        let re_encoded = minicbor::to_vec(&value).unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn tagged_cbor_bytes_is_tagged24() -> anyhow::Result<()> {
        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let value: Tagged<24, ByteVec> = Tagged::from(ByteVec::from(minicbor::to_vec(&raw)?));
        let value2: TaggedCborBytes<TestStruct> = TaggedCborBytes::from(&raw);

        let encoded = minicbor::to_vec(&value).expect("failed to encode");
        let encoded_value2 = minicbor::to_vec(&value2).expect("failed to encode value2");

        assert_eq!(encoded, encoded_value2);

        Ok(())
    }

    #[test]
    fn test_tag24_cbor() -> anyhow::Result<()> {
        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let value2 = TestStruct2 {
            tagged: TaggedCborBytes::from(&raw),
        };
        let value3 = TestStruct3 {
            tagged: Tagged::from(ByteVec::from(minicbor::to_vec(&raw)?)),
        };
        let encoded_value2 = minicbor::to_vec(&value2).expect("failed to encode value2");
        let encoded_value3 = minicbor::to_vec(&value3).expect("failed to encode value3");

        assert_eq!(encoded_value2, encoded_value3);
        Ok(())
    }

    #[test]
    fn tagged_cbor_bytes_decodes_on_demand() {
        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let tagged: TaggedCborBytes<TestStruct> = TaggedCborBytes::from(&raw);

        assert_eq!(tagged.decode().unwrap().version, raw.version);
    }
}
