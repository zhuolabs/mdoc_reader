use minicbor::bytes::ByteVec;
use minicbor::data::Tagged;
use minicbor::decode::{Decode, Decoder, Error as DecodeError};
use minicbor::encode::{Encode, Encoder, Error as EncodeError, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedCborBytes<T>(pub T);

impl<T> From<T> for TaggedCborBytes<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T, C> Encode<C> for TaggedCborBytes<T>
where
    T: Encode<()>,
{
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        let inner = minicbor::to_vec(&self.0)
            .map_err(|_| EncodeError::message("failed to encode tag24 inner value"))?;
        Tagged::<24, ByteVec>::from(ByteVec::from(inner)).encode(e, &mut ())
    }
}

impl<'b, T, C> Decode<'b, C> for TaggedCborBytes<T>
where
    T: for<'a> Decode<'a, ()>,
{
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let tagged: Tagged<24, ByteVec> = d.decode()?;
        let value = minicbor::decode::<T>((*tagged).as_slice())
            .map_err(|_| DecodeError::message("failed to decode tag24 inner value"))?;
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::{Decode, Encode};

    #[derive(Debug, Clone, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct {
        #[n(0)]
        pub version: String,
    }

    #[derive(Debug, Clone, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct2 {
        #[n(0)]
        pub tagged: TaggedCborBytes<TestStruct>,
    }

    #[derive(Debug, Clone, Encode, Decode)]
    #[cbor(array)]
    struct TestStruct3 {
        #[n(0)]
        pub tagged: Tagged<24, ByteVec>,
    }

    #[test]
    fn tagged_cbor_bytes_is_tagged24() -> anyhow::Result<()> {
        // type Tagged24<T> = Tagged<24, T>;

        let raw = TestStruct {
            version: "1.0".to_string(),
        };

        let value: Tagged<24, ByteVec> = Tagged::from(ByteVec::from(minicbor::to_vec(&raw)?));
        let value2: TaggedCborBytes<TestStruct> = TaggedCborBytes::from(raw.clone());

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
            tagged: TaggedCborBytes::from(raw.clone()),
        };
        let value3 = TestStruct3 {
            tagged: Tagged::from(ByteVec::from(minicbor::to_vec(&raw)?)),
        };
        let encoded_value2 = minicbor::to_vec(&value2).expect("failed to encode value2");
        let encoded_value3 = minicbor::to_vec(&value3).expect("failed to encode value3");

        assert_eq!(encoded_value2, encoded_value3);
        Ok(())
    }
}
