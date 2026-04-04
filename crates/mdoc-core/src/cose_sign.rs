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

#[derive(Debug, Clone, PartialEq, Eq, Default, Decode, Encode)]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct SigStructureSignature1 {
    #[n(0)]
    pub context: String,
    #[n(1)]
    pub body_protected: ByteVec,
    #[n(2)]
    pub external_aad: ByteVec,
    #[n(3)]
    pub payload: ByteVec,
}

impl SigStructureSignature1 {
    pub fn new(body_protected: Vec<u8>, external_aad: &[u8], payload: &[u8]) -> Self {
        Self {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(body_protected),
            external_aad: ByteVec::from(external_aad.to_vec()),
            payload: ByteVec::from(payload.to_vec()),
        }
    }
}

#[derive(Debug, Clone, Decode, PartialEq, Eq, Encode, Default)]
#[cbor(map)]
pub struct HeaderMap {
    #[n(1)]
    pub alg: Option<CoseAlg>,
    #[n(33)]
    pub x5chain: Option<X5Chain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct X5Chain(Vec<X509Certificate>);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectedHeaderMap(pub Option<HeaderMap>);

impl HeaderMap {
    pub fn document_signer_cert(&self) -> Option<&X509Certificate> {
        self.x5chain
            .as_ref()
            .and_then(|chain| chain.as_slice().first())
    }

    pub fn intermediate_certs(&self) -> &[X509Certificate] {
        self.x5chain
            .as_deref()
            .map(|chain| chain.get(1..).unwrap_or(&[]))
            .unwrap_or(&[])
    }
}

impl X5Chain {
    pub fn as_slice(&self) -> &[X509Certificate] {
        &self.0
    }
}

impl AsRef<[X509Certificate]> for X5Chain {
    fn as_ref(&self) -> &[X509Certificate] {
        self.as_slice()
    }
}

impl core::ops::Deref for X5Chain {
    type Target = [X509Certificate];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

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

impl<C> Encode<C> for X5Chain {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self.0.len() {
            0 => {
                return Err(minicbor::encode::Error::message(
                    "x5chain must contain at least one certificate",
                ));
            }
            1 => {
                e.encode(&self.0[0])?;
            }
            _ => {
                e.array(self.0.len() as u64)?;
                for cert in &self.0 {
                    e.encode(cert)?;
                }
            }
        };

        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for X5Chain {
    fn decode(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::Bytes => Ok(Self(vec![d.decode::<X509Certificate>()?])),
            minicbor::data::Type::Array => {
                let len = d.array()?.ok_or_else(|| {
                    minicbor::decode::Error::message("x5chain array must be definite-length")
                })?;
                if len == 0 {
                    return Err(minicbor::decode::Error::message(
                        "x5chain array must contain at least one certificate",
                    ));
                }
                let mut certs = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    certs.push(d.decode::<X509Certificate>()?);
                }
                Ok(Self(certs))
            }
            _ => Err(minicbor::decode::Error::message(
                "x5chain must be a bstr certificate or array of bstr certificates",
            )),
        }
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

    pub fn build_sig_structure_signature1(&self, external_aad: &[u8]) -> Result<Vec<u8>> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 payload is missing"))?;
        build_sig_structure_signature1(&self.protected, external_aad, payload)
    }
}

fn protected_header_bytes(protected: &ProtectedHeaderMap) -> Result<Vec<u8>> {
    let bytes = match &protected.0 {
        None => vec![],
        Some(map) => minicbor::to_vec(map)?,
    };
    Ok(bytes)
}

pub fn build_sig_structure_signature1(
    protected: &ProtectedHeaderMap,
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let body_protected = protected_header_bytes(protected)?;
    let sig_structure = SigStructureSignature1::new(body_protected, external_aad, payload);
    Ok(minicbor::to_vec(sig_structure)?)
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
    fn x5chain_rejects_empty_array_form() {
        let mut e = Encoder::new(Vec::new());
        e.map(1).unwrap();
        e.i8(33).unwrap();
        e.array(0).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<HeaderMap>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn x5chain_rejects_invalid_der_in_array_form() {
        let mut e = Encoder::new(Vec::new());
        e.map(1).unwrap();
        e.i8(33).unwrap();
        e.array(1).unwrap();
        e.bytes(&[0x30, 0x03, 0x02, 0x01, 0x01]).unwrap();
        let encoded = e.into_writer();
        let result = minicbor::decode::<HeaderMap>(&encoded);
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

    #[test]
    fn sig_structure_signature1_roundtrip() {
        let sig_structure = SigStructureSignature1::new(vec![], b"", b"payload");
        let encoded = minicbor::to_vec(&sig_structure).unwrap();
        let decoded: SigStructureSignature1 = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, sig_structure);
        assert_eq!(decoded.context, "Signature1");
        assert_eq!(decoded.external_aad.as_slice(), b"");
    }

    #[test]
    fn sig_structure_signature1_encoding_matches_expected() {
        let sig_structure = SigStructureSignature1::new(vec![], b"", b"\x01\x02\x03");
        let encoded = minicbor::to_vec(&sig_structure).unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x40, 0x40,
            0x43, 0x01, 0x02, 0x03,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn build_sig_structure_signature1_builds_signature_input() {
        let payload = b"\xAA\xBB";
        let encoded =
            build_sig_structure_signature1(&ProtectedHeaderMap(None), b"", payload).unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x40, 0x40,
            0x42, 0xAA, 0xBB,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn cose_sign1_build_sig_structure_signature1_uses_payload() {
        let sign1 = CoseSign1 {
            protected: ProtectedHeaderMap(None),
            unprotected: HeaderMap::default(),
            payload: Some(ByteVec::from(vec![0x01, 0x02])),
            signature: ByteVec::from(vec![0; 64]),
        };
        let encoded = sign1.build_sig_structure_signature1(b"").unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x40, 0x40,
            0x42, 0x01, 0x02,
        ];
        assert_eq!(encoded, expected);
    }
}
