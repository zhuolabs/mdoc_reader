use anyhow::Result;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Decoder, Encode, Encoder};
use x509_cert::der::{Decode as DerDecode, Encode as DerEncode};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct CoseSign1 {
    #[n(0)]
    pub protected: ProtectedHeaderMap,
    #[n(1)]
    pub unprotected: HeaderMap,
    #[n(2)]
    pub payload: Option<ByteVec>,
    #[n(3)]
    pub signature: ByteVec,
}

#[derive(Debug, Clone, Decode, PartialEq, Eq, Encode, Default)]
#[cbor(map)]
pub struct HeaderMap {
    #[n(1)]
    pub alg: Option<CoseAlg>,
    #[n(33)]
    pub x5chain: Option<X509Certificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectedHeaderMap(pub Option<HeaderMap>);

#[derive(Decode, Debug, Encode, PartialEq, Eq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum CoseAlg {
    #[n(-3)]
    A128KW,
    #[n(-5)]
    A256KW,
    #[n(-29)]
    ECDHESA128KW,
    #[n(-9)]
    ES256P256,
    #[n(-7)]
    ES256,
    #[n(-19)]
    ED25519,
    #[n(-46)]
    HSSLMS,
    #[n(4)]
    HMAC25664,
    #[n(5)]
    HMAC256256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Certificate(x509_cert::Certificate);

impl<'a> From<&'a X509Certificate> for &'a x509_cert::Certificate {
    fn from(value: &'a X509Certificate) -> Self {
        &value.0
    }
}

impl<C> Encode<C> for X509Certificate {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        let der = self.0.to_der().map_err(|_| {
            minicbor::encode::Error::message("failed to encode x5chain certificate to DER")
        })?;
        e.bytes(&der)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for X509Certificate {
    fn decode(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
        let der = d.bytes()?;
        let cert = x509_cert::Certificate::from_der(der).map_err(|_| {
            minicbor::decode::Error::message("x5chain certificate is not valid DER X.509")
        })?;
        Ok(Self(cert))
    }
}

impl<C> Encode<C> for ProtectedHeaderMap {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match &self.0 {
            None => {
                e.bytes(&[])?;
            }
            Some(map) => {
                let bytes = minicbor::to_vec(map).map_err(|_| {
                    minicbor::encode::Error::message("failed to encode protected header_map")
                })?;
                e.bytes(&bytes)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for ProtectedHeaderMap {
    fn decode(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
        let bytes = d.bytes()?;
        if bytes.is_empty() {
            return Ok(Self(None));
        }
        let map = minicbor::decode::<HeaderMap>(bytes).map_err(|_| {
            minicbor::decode::Error::message(
                "protected header must be bstr.cbor header_map or bstr size 0",
            )
        })?;
        Ok(Self(Some(map)))
    }
}


impl CoseSign1 {
    pub fn decode_payload_cbor<T>(&self) -> Result<T>
    where
        for<'a> T: Decode<'a, ()>,
    {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 payload is missing"))?;
        let decoded = minicbor::decode(payload.as_slice())?;
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_header_map_accepts_empty_bstr() {
        let encoded = minicbor::to_vec(ProtectedHeaderMap(None)).unwrap();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, ProtectedHeaderMap(None));
    }

    #[test]
    fn protected_header_map_maps_h_a0_to_some_empty_map() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0xA0]).unwrap();
        let encoded = e.into_writer();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, ProtectedHeaderMap(Some(HeaderMap::default())));
    }

    #[test]
    fn protected_header_map_rejects_non_map_cbor() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0x01]).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<ProtectedHeaderMap>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn x5chain_rejects_non_x509_der() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0x30, 0x03, 0x02, 0x01, 0x01]).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<X509Certificate>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn x5chain_rejects_array_form() {
        let mut e = Encoder::new(Vec::new());
        e.array(2).unwrap();
        e.bytes(&[0x30, 0x03, 0x02, 0x01, 0x01]).unwrap();
        e.bytes(&[0x30, 0x03, 0x02, 0x01, 0x02]).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<X509Certificate>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn decode_payload_cbor_decodes_payload() {
        let sign1 = CoseSign1 {
            protected: ProtectedHeaderMap(None),
            unprotected: HeaderMap::default(),
            payload: Some(ByteVec::from(minicbor::to_vec("hello").unwrap())),
            signature: ByteVec::from(vec![0; 64]),
        };

        let payload: String = sign1.decode_payload_cbor().unwrap();
        assert_eq!(payload, "hello");
    }

    #[test]
    fn decode_payload_cbor_rejects_missing_payload() {
        let sign1 = CoseSign1 {
            protected: ProtectedHeaderMap(None),
            unprotected: HeaderMap::default(),
            payload: None,
            signature: ByteVec::from(vec![0; 64]),
        };

        let result = sign1.decode_payload_cbor::<String>();
        assert!(result.is_err());
    }
}
