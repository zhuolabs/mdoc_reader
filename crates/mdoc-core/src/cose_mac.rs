use anyhow::Result;
use hmac::{Hmac, Mac};
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use sha2::Sha256;

use crate::cose_sign::CoseDecodePayload;
use crate::{CborAny, CborBytes, CoseAlg, CoseVerify, GetCoseAlg, HeaderMap, ProtectedHeaderMap};

type HmacSha256 = Hmac<Sha256>;

pub const MAC0_CONTEXT: &str = "MAC0";

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct CoseMac0<T = CborAny>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    #[n(0)]
    pub protected: ProtectedHeaderMap,
    #[n(1)]
    pub unprotected: HeaderMap,
    #[n(2)]
    pub payload: Option<CborBytes<T>>,
    #[n(3)]
    pub tag: ByteVec,
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(array)]
pub struct MacStructure {
    #[n(0)]
    pub context: String,
    #[n(1)]
    pub body_protected: ByteVec,
    #[n(2)]
    pub external_aad: ByteVec,
    #[n(3)]
    pub payload: ByteVec,
}

impl<T> GetCoseAlg for CoseMac0<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn alg(&self) -> Result<CoseAlg> {
        self.protected
            .decode()
            .map_err(|_| anyhow::anyhow!("protected header must be bstr.cbor header_map"))?
            .alg
            .ok_or_else(|| anyhow::anyhow!("COSE_Mac0 algorithm is missing from protected header"))
    }
}

impl<T> CoseDecodePayload<T> for CoseMac0<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn decode_payload(&self) -> Result<T>
    where
        for<'a> T: Decode<'a, ()>,
    {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Mac0 payload is missing"))?;
        Ok(payload.decode()?)
    }
}

impl<T> CoseVerify<[u8; 32]> for CoseMac0<T>
where
    T: Encode<()> + for<'a> Decode<'a, ()>,
{
    fn verify(&self, key: &[u8; 32], external_aad: &[u8]) -> Result<()> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("COSE_Mac0 payload is missing"))?;
        match self.alg()? {
            CoseAlg::HMAC256256 => {
                let mac_structure = minicbor::to_vec(MacStructure {
                    context: MAC0_CONTEXT.to_string(),
                    body_protected: ByteVec::from(self.protected.raw_cbor_bytes().to_vec()),
                    external_aad: ByteVec::from(external_aad.to_vec()),
                    payload: ByteVec::from(payload.raw_cbor_bytes().to_vec()),
                })?;
                let mut hmac = HmacSha256::new_from_slice(key)
                    .map_err(|_| anyhow::anyhow!("invalid HMAC key bytes"))?;
                hmac.update(&mac_structure);
                hmac.verify_slice(self.tag.as_slice())
                    .map_err(|_| anyhow::anyhow!("COSE_Mac0 tag verification failed"))
            }
            alg => anyhow::bail!("unsupported COSE algorithm for MAC verification: {alg:?}"),
        }
    }
}
