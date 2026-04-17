use anyhow::Result;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;

use crate::{CborAny, CborBytes, X5Chain};

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct CoseSign1<T = CborAny>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    #[n(0)]
    protected: CborBytes<HeaderMap>,
    #[n(1)]
    unprotected: HeaderMap,
    #[n(2)]
    payload: Option<CborBytes<T>>,
    #[n(3)]
    signature: ByteVec,
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
struct SigStructureSignature1 {
    #[n(0)]
    context: String,
    #[n(1)]
    body_protected: ByteVec,
    #[n(2)]
    external_aad: ByteVec,
    #[n(3)]
    payload: ByteVec,
}

#[derive(Debug, Clone, Decode, PartialEq, Eq, Encode, Default)]
#[cbor(map)]
pub struct HeaderMap {
    #[n(1)]
    pub alg: Option<CoseAlg>,
    #[n(33)]
    pub x5chain: Option<X5Chain>,
}

pub type ProtectedHeaderMap = CborBytes<HeaderMap>;

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

pub trait GetCoseAlg {
    fn alg(&self) -> Result<CoseAlg>;
}

pub trait GetCosePayload {
    type Payload: Encode<()> + for<'a> Decode<'a, ()>;

    fn payload(&self) -> Option<&CborBytes<Self::Payload>>;
}

pub trait CoseVerify<K> {
    fn verify(&self, key: &K, external_aad: &[u8]) -> Result<()>;
}

impl<K, T> CoseVerify<K> for T
where
    T: CoseVerifyDedicatedPayload<K> + GetCosePayload,
{
    fn verify(&self, key: &K, external_aad: &[u8]) -> Result<()> {
        let payload = self
            .payload()
            .ok_or_else(|| anyhow::anyhow!("COSE payload is missing"))?
            .raw_cbor_bytes();
        self.verify_with(key, external_aad, payload)
    }
}

pub trait CoseVerifyDedicatedPayload<K> {
    fn verify_with(&self, key: &K, external_aad: &[u8], payload: &[u8]) -> Result<()>;
}

impl<T> GetCoseAlg for CoseSign1<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn alg(&self) -> Result<CoseAlg> {
        self.protected
            .decode()
            .map_err(|_| anyhow::anyhow!("protected header must be bstr.cbor header_map"))?
            .alg
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 algorithm is missing from protected header"))
    }
}

impl<T> GetCosePayload for CoseSign1<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    type Payload = T;

    fn payload(&self) -> Option<&CborBytes<Self::Payload>> {
        self.payload.as_ref()
    }
}

impl<T> CoseVerifyDedicatedPayload<VerifyingKey> for CoseSign1<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn verify_with(&self, key: &VerifyingKey, external_aad: &[u8], payload: &[u8]) -> Result<()> {
        match self.alg()? {
            CoseAlg::ES256 | CoseAlg::ES256P256 => {
                let sig_structure = minicbor::to_vec(SigStructureSignature1 {
                    context: "Signature1".to_string(),
                    body_protected: ByteVec::from(self.protected.raw_cbor_bytes().to_vec()),
                    external_aad: ByteVec::from(external_aad.to_vec()),
                    payload: ByteVec::from(payload.to_vec()),
                })?;
                let signature = p256::ecdsa::Signature::from_slice(self.signature.as_slice())
                    .map_err(|_| anyhow::anyhow!("invalid ES256 signature bytes"))?;
                key.verify(&sig_structure, &signature)
                    .map_err(|_| anyhow::anyhow!("COSE_Sign1 signature verification failed"))
            }
            alg => anyhow::bail!("unsupported COSE algorithm for signature verification: {alg:?}"),
        }
    }
}

impl<T> CoseVerifyDedicatedPayload<x509_cert::Certificate> for CoseSign1<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn verify_with(
        &self,
        certificate: &x509_cert::Certificate,
        external_aad: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        let sec1_bytes = certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("certificate public key is not byte-aligned"))?;
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_bytes)
            .map_err(|_| anyhow::anyhow!("certificate public key is not a valid P-256 key"))?;
        self.verify_with(&verifying_key, external_aad, payload)
    }
}

impl<T> CoseSign1<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    pub fn new(
        protected: ProtectedHeaderMap,
        unprotected: HeaderMap,
        payload: Option<CborBytes<T>>,
        signature: ByteVec,
    ) -> Self {
        Self {
            protected,
            unprotected,
            payload,
            signature,
        }
    }

    pub fn x5chain(&self) -> Option<&[x509_cert::Certificate]> {
        self.unprotected.x5chain.as_ref().map(|v| v.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::Encoder;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    #[test]
    fn protected_header_map_roundtrips_non_empty_bstr() {
        let protected = CborBytes::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let encoded = minicbor::to_vec(&protected).unwrap();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, protected);
    }

    #[test]
    fn protected_header_map_decodes_inner_header_map() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0xA0]).unwrap();
        let encoded = e.into_writer();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded.decode().unwrap(), HeaderMap::default());
    }

    #[test]
    fn protected_header_map_allows_later_validation_of_non_map_cbor() {
        let mut e = Encoder::new(Vec::new());
        e.bytes(&[0x01]).unwrap();
        let encoded = e.into_writer();
        let decoded: ProtectedHeaderMap = minicbor::decode(&encoded).unwrap();
        assert!(decoded.decode().is_err());
    }

    #[test]
    fn decode_payload_cbor_decodes_payload() {
        let sign1 = CoseSign1::<String> {
            protected: CborBytes::from(&HeaderMap::default()),
            unprotected: HeaderMap::default(),
            payload: Some(CborBytes::from(&"hello".to_string())),
            signature: ByteVec::from(vec![0; 64]),
        };

        let payload = sign1.payload.as_ref().unwrap().decode().unwrap();
        assert_eq!(payload, "hello");
    }

    #[test]
    fn sig_structure_signature1_roundtrip() {
        let sig_structure = SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(Vec::<u8>::new()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(b"payload".to_vec()),
        };
        let encoded = minicbor::to_vec(&sig_structure).unwrap();
        let decoded: SigStructureSignature1 = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, sig_structure);
        assert_eq!(decoded.context, "Signature1");
        assert_eq!(decoded.external_aad.as_slice(), b"");
    }

    #[test]
    fn sig_structure_signature1_encoding_matches_expected() {
        let sig_structure = SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(Vec::<u8>::new()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(b"\x01\x02\x03".to_vec()),
        };
        let encoded = minicbor::to_vec(&sig_structure).unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x40, 0x40,
            0x43, 0x01, 0x02, 0x03,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn sig_structure_signature1_builds_signature_input() {
        let payload = b"\xAA\xBB";
        let encoded = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(
                CborBytes::from(&HeaderMap::default())
                    .raw_cbor_bytes()
                    .to_vec(),
            ),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(payload.to_vec()),
        })
        .unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x41, 0xA0,
            0x40, 0x42, 0xAA, 0xBB,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn verify_signature_input_uses_payload() {
        let sign1 = CoseSign1::<CborAny> {
            protected: CborBytes::from(&HeaderMap::default()),
            unprotected: HeaderMap::default(),
            payload: Some(CborBytes::from_raw_bytes(vec![0x01, 0x02])),
            signature: ByteVec::from(vec![0; 64]),
        };
        let encoded = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(sign1.protected.raw_cbor_bytes().to_vec()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(sign1.payload.as_ref().unwrap().raw_cbor_bytes().to_vec()),
        })
        .unwrap();
        let expected = vec![
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x41, 0xA0,
            0x40, 0x42, 0x01, 0x02,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn alg_uses_protected_only() {
        let sign1 = CoseSign1::<CborAny> {
            protected: CborBytes::from(&HeaderMap {
                alg: Some(CoseAlg::ES256),
                x5chain: None,
            }),
            unprotected: HeaderMap {
                alg: Some(CoseAlg::ED25519),
                x5chain: None,
            },
            payload: Some(CborBytes::from_raw_bytes(vec![0x01])),
            signature: ByteVec::from(vec![0; 64]),
        };

        assert_eq!(sign1.alg().unwrap(), CoseAlg::ES256);
    }

    #[test]
    fn verify_signature_with_public_key_accepts_valid_es256_signature() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let payload = CborBytes::from_raw_bytes(vec![0x01, 0x02, 0x03]);
        let protected = CborBytes::from(&HeaderMap {
            alg: Some(CoseAlg::ES256),
            x5chain: None,
        });
        let sig_structure = minicbor::to_vec(SigStructureSignature1 {
            context: "Signature1".to_string(),
            body_protected: ByteVec::from(protected.raw_cbor_bytes().to_vec()),
            external_aad: ByteVec::from(Vec::<u8>::new()),
            payload: ByteVec::from(payload.raw_cbor_bytes().to_vec()),
        })
        .unwrap();
        let signature: p256::ecdsa::Signature = signing_key.sign(&sig_structure);
        let sign1 = CoseSign1::<CborAny> {
            protected,
            unprotected: HeaderMap::default(),
            payload: Some(payload),
            signature: ByteVec::from(signature.to_bytes().to_vec()),
        };
        let verifying_key = signing_key.verifying_key();
        sign1.verify(verifying_key, b"").unwrap();
    }
}
