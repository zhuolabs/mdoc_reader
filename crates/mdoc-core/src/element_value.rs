use chrono::NaiveDate;
use minicbor::bytes::ByteVec;
use minicbor::data::Tagged;
use minicbor::{decode, encode, Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementValue(Vec<u8>);

impl ElementValue {
    pub fn new(raw_cbor_bytes: Vec<u8>) -> Self {
        Self(raw_cbor_bytes)
    }

    pub fn raw_cbor_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn string(&self) -> Option<String> {
        self.decode_as::<String>()
    }

    pub fn full_date(&self) -> Option<NaiveDate> {
        let tagged = self.decode_as::<Tagged<1004, String>>()?;
        NaiveDate::parse_from_str(tagged.value(), "%Y-%m-%d").ok()
    }

    pub fn bool(&self) -> Option<bool> {
        self.decode_as::<bool>()
    }

    pub fn u64(&self) -> Option<u64> {
        self.decode_as::<u64>()
    }

    pub fn bytes(&self) -> Option<ByteVec> {
        self.decode_as::<ByteVec>()
    }

    pub fn from_string(value: impl Into<String>) -> Self {
        Self::encode_from(value.into())
    }

    pub fn from_full_date(value: impl AsRef<str>) -> Self {
        Self::encode_from(Tagged::<1004, String>::from(value.as_ref().to_string()))
    }

    pub fn from_bool(value: bool) -> Self {
        Self::encode_from(value)
    }

    pub fn from_u64(value: u64) -> Self {
        Self::encode_from(value)
    }

    pub fn from_bytes(value: impl Into<ByteVec>) -> Self {
        Self::encode_from(value.into())
    }

    fn decode_as<T>(&self) -> Option<T>
    where
        for<'b> T: decode::Decode<'b, ()>,
    {
        minicbor::decode(&self.0).ok()
    }

    fn encode_from<T>(value: T) -> Self
    where
        T: encode::Encode<()>,
    {
        Self(minicbor::to_vec(value).expect("encoding ElementValue should not fail"))
    }
}

impl<C> encode::Encode<C> for ElementValue {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), encode::Error<W::Error>> {
        e.writer_mut()
            .write_all(&self.0)
            .map_err(encode::Error::write)?;
        Ok(())
    }
}

impl<'b, C> decode::Decode<'b, C> for ElementValue {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(Self(d.input()[start..end].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full_date_tagged_string() {
        let encoded = minicbor::to_vec(Tagged::<1004, &str>::from("2026-04-04")).unwrap();

        let value: ElementValue = minicbor::decode(&encoded).unwrap();

        assert_eq!(value.raw_cbor_bytes(), encoded);
        assert_eq!(value.full_date(), NaiveDate::from_ymd_opt(2026, 4, 4));
    }

    #[test]
    fn encodes_full_date_as_tagged_string() {
        let value = ElementValue::from_full_date("2026-04-04");

        let encoded = minicbor::to_vec(&value).unwrap();
        let expected = minicbor::to_vec(Tagged::<1004, &str>::from("2026-04-04")).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn decodes_supported_helpers() {
        assert_eq!(
            ElementValue::from_string("hello").string().as_deref(),
            Some("hello")
        );
        assert_eq!(ElementValue::from_bool(true).bool(), Some(true));
        assert_eq!(ElementValue::from_u64(42).u64(), Some(42));
        assert_eq!(
            ElementValue::from_bytes(vec![1, 2, 3]).bytes(),
            Some(ByteVec::from(vec![1, 2, 3]))
        );
    }
}
