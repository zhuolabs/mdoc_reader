use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use p256::ecdsa::VerifyingKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::EncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
#[cbor(index_only)]
pub enum KeyType {
    #[n(2)]
    Ec2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
#[cbor(index_only)]
pub enum Curve {
    #[n(1)]
    P256,
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(map)]
pub struct CoseKeyPublic {
    #[n(1)]
    pub kty: KeyType,
    #[b(-1)]
    pub crv: Curve,
    #[n(-2)]
    pub x: ByteVec,
    #[n(-3)]
    pub y: ByteVec,
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
#[cbor(map)]
pub struct CoseKeyPrivate {
    #[n(1)]
    pub kty: KeyType,
    #[b(-1)]
    pub crv: Curve,
    #[n(-2)]
    pub x: ByteVec,
    #[n(-3)]
    pub y: ByteVec,
    #[n(-4)]
    pub d: ByteVec,
}

impl CoseKeyPrivate {
    pub fn new() -> anyhow::Result<CoseKeyPrivate> {
        Self::try_from(&SecretKey::random(&mut OsRng))
    }

    pub fn to_public(&self) -> CoseKeyPublic {
        CoseKeyPublic {
            kty: self.kty,
            crv: self.crv,
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }
}

impl TryFrom<&PublicKey> for CoseKeyPublic {
    type Error = anyhow::Error;

    fn try_from(public_key: &PublicKey) -> Result<Self, Self::Error> {
        let encoded_point = public_key.to_encoded_point(false);
        let x = encoded_point
            .x()
            .ok_or_else(|| anyhow::anyhow!("P-256 public key x-coordinate missing"))?;
        let y = encoded_point
            .y()
            .ok_or_else(|| anyhow::anyhow!("P-256 public key y-coordinate missing"))?;

        Ok(Self {
            kty: KeyType::Ec2,
            crv: Curve::P256,
            x: ByteVec::from(x.to_vec()),
            y: ByteVec::from(y.to_vec()),
        })
    }
}

impl TryFrom<&CoseKeyPublic> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(key: &CoseKeyPublic) -> Result<Self, Self::Error> {
        let encoded_point = EncodedPoint::from_affine_coordinates(
            key.x.as_slice().into(),
            key.y.as_slice().into(),
            false,
        );
        PublicKey::from_sec1_bytes(encoded_point.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid P-256 public key: {}", e))
    }
}

impl TryFrom<&CoseKeyPublic> for VerifyingKey {
    type Error = anyhow::Error;

    fn try_from(key: &CoseKeyPublic) -> Result<Self, Self::Error> {
        let public_key = PublicKey::try_from(key)?;
        Ok(VerifyingKey::from(public_key))
    }
}

impl TryFrom<CoseKeyPublic> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(key: CoseKeyPublic) -> Result<Self, Self::Error> {
        Self::try_from(&key)
    }
}

impl TryFrom<&SecretKey> for CoseKeyPrivate {
    type Error = anyhow::Error;

    fn try_from(secret_key: &SecretKey) -> Result<Self, Self::Error> {
        let public = CoseKeyPublic::try_from(&secret_key.public_key())?;
        let d = secret_key.to_bytes();

        Ok(Self {
            kty: KeyType::Ec2,
            crv: Curve::P256,
            x: public.x,
            y: public.y,
            d: ByteVec::from(d.to_vec()),
        })
    }
}

impl TryFrom<&CoseKeyPrivate> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(key: &CoseKeyPrivate) -> Result<Self, Self::Error> {
        SecretKey::from_bytes(key.d.as_slice().into())
            .map_err(|e| anyhow::anyhow!("invalid P-256 private key: {}", e))
    }
}
