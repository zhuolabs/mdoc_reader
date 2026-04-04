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

macro_rules! element_value_codec {
    ($( $variant:ident($type:ty), )* $(,)?) => {
        impl<C> encode::Encode<C> for ElementValue {
            fn encode<W: encode::Write>(
                &self,
                e: &mut Encoder<W>,
                ctx: &mut C,
            ) -> core::result::Result<(), encode::Error<W::Error>> {
                match self {
                    $( Self::$variant(value) => value.encode(e, ctx)?, )*
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
            fn decode(
                d: &mut Decoder<'b>,
                _ctx: &mut C,
            ) -> core::result::Result<Self, decode::Error> {
                $(
                    if let Some(value) = try_decode::<$type>(d) {
                        return Ok(Self::$variant(value));
                    }
                )*

                let start = d.position();
                d.skip()?;
                let end = d.position();
                Ok(Self::RawCborBytes(d.input()[start..end].to_vec()))
            }
        }
    };
}

element_value_codec! {
    String(String),
    FullDate(Tagged<1004, String>),
    Bool(bool),
    U64(u64),
    Bytes(ByteVec),
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
