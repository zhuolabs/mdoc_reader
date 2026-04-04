use minicbor::data::Tagged;
use minicbor::{decode, encode, Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElementValue {
    String(String),
    FullDate(Tagged<1004, String>),
    Bool(bool),
    U64(u64),
    Bytes(Vec<u8>),
    RawBytes(Vec<u8>),
}

impl<C> encode::Encode<C> for ElementValue {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), encode::Error<W::Error>> {
        match self {
            Self::String(value) => {
                e.str(value)?;
            }
            Self::FullDate(value) => {
                value.encode(e, _ctx)?;
            }
            Self::Bool(value) => {
                e.bool(*value)?;
            }
            Self::U64(value) => {
                e.u64(*value)?;
            }
            Self::Bytes(value) => {
                e.bytes(value)?;
            }
            Self::RawBytes(value) => {
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
        if let Some(value) = try_decode(d, |probe| {
            let value: Tagged<1004, String> = probe.decode()?;
            Ok(Self::FullDate(value))
        })? {
            return Ok(value);
        }

        if let Some(value) = try_decode(d, |probe| Ok(Self::String(probe.str()?.to_string())))? {
            return Ok(value);
        }

        if let Some(value) = try_decode(d, |probe| Ok(Self::Bool(probe.bool()?)))? {
            return Ok(value);
        }

        if let Some(value) = try_decode(d, |probe| Ok(Self::U64(probe.u64()?)))? {
            return Ok(value);
        }

        if let Some(value) = try_decode(d, |probe| Ok(Self::Bytes(probe.bytes()?.to_vec())))? {
            return Ok(value);
        }

        let start = d.position();
        d.skip()?;
        let end = d.position();
        Ok(Self::RawBytes(d.input()[start..end].to_vec()))
    }
}

fn try_decode<'b, T>(
    d: &mut Decoder<'b>,
    f: impl FnOnce(&mut Decoder<'b>) -> Result<T, decode::Error>,
) -> Result<Option<T>, decode::Error> {
    let mut probe = d.probe();
    match f(&mut probe) {
        Ok(value) => {
            let position = probe.position();
            drop(probe);
            d.set_position(position);
            Ok(Some(value))
        }
        Err(_) => Ok(None),
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
