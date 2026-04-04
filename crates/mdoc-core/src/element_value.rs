use minicbor::bytes::ByteVec;
use minicbor::data::Tagged;
use minicbor::{decode, encode, Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElementValue {
    String(String),
    FullDate(Tagged<1004, String>),
    Bool(bool),
    U64(u64),
    Bytes(ByteVec),
    RawCborBytes(Vec<u8>),
}

impl<C> encode::Encode<C> for ElementValue {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> core::result::Result<(), encode::Error<W::Error>> {
        match self {
            Self::String(value) => {
                value.encode(e, ctx)?;
            }
            Self::FullDate(value) => {
                value.encode(e, ctx)?;
            }
            Self::Bool(value) => {
                value.encode(e, ctx)?;
            }
            Self::U64(value) => {
                value.encode(e, ctx)?;
            }
            Self::Bytes(value) => {
                value.encode(e, ctx)?;
            }
            Self::RawCborBytes(value) => {
                e.writer_mut()
                    .write_all(value)
                    .map_err(encode::Error::write)?;
            }
        };
        Ok(())
    }
}

impl<'b, C> decode::Decode<'b, C> for ElementValue {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        if let Some(value) = try_decode::<String>(d) {
            return Ok(Self::String(value));
        }
        if let Some(value) = try_decode::<Tagged<1004, String>>(d) {
            return Ok(Self::FullDate(value));
        }
        if let Some(value) = try_decode::<bool>(d) {
            return Ok(Self::Bool(value));
        }
        if let Some(value) = try_decode::<u64>(d) {
            return Ok(Self::U64(value));
        }
        if let Some(value) = try_decode::<ByteVec>(d) {
            return Ok(Self::Bytes(value));
        }

        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(Self::RawCborBytes(d.input()[start..end].to_vec()))
    }
}

fn try_decode<'b, T>(
    d: &mut Decoder<'b>,
) -> Option<T> where
    T: decode::Decode<'b, ()>,
{
    let mut probe = d.probe();
    let value: Option<T> = probe.decode().ok();
    match value {
        Some(value) => {
            let position = probe.position();
            drop(probe);
            d.set_position(position);
            Some(value)
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full_date_tagged_string() {
        let encoded = minicbor::to_vec(Tagged::<1004, &str>::from("2026-04-04")).unwrap();

        let value: ElementValue = minicbor::decode(&encoded).unwrap();

        assert_eq!(
            value,
            ElementValue::FullDate(Tagged::from("2026-04-04".to_string()))
        );
    }

    #[test]
    fn encodes_full_date_as_tagged_string() {
        let value = ElementValue::FullDate(Tagged::from("2026-04-04".to_string()));

        let encoded = minicbor::to_vec(&value).unwrap();
        let expected = minicbor::to_vec(Tagged::<1004, &str>::from("2026-04-04")).unwrap();

        assert_eq!(encoded, expected);
    }
}
