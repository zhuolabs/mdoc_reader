use crate::tagged_cbor_bytes::TaggedCborBytes;
use crate::{CoseKeyPublic, DeviceEngagement};
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use ndef_rs::NdefMessage;

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
pub struct SessionTranscript(
    #[n(0)] pub Option<TaggedCborBytes<DeviceEngagement>>,
    #[n(1)] pub TaggedCborBytes<CoseKeyPublic>,
    #[n(2)] pub NFCHandover,
);

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
pub struct NFCHandover(
    /// HandoverSelect message bytes (NDEF).
    #[n(0)]
    pub HandoverSelectBytes,
    /// HandoverRequest message bytes (NDEF).
    #[n(1)]
    pub Option<HandoverRequestBytes>,
);

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(transparent)]
pub struct HandoverSelectBytes(ByteVec);

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(transparent)]
pub struct HandoverRequestBytes(ByteVec);

impl TryFrom<&NdefMessage> for HandoverSelectBytes {
    type Error = anyhow::Error;

    fn try_from(ndef_message: &NdefMessage) -> Result<Self, Self::Error> {
        let bytes = ndef_message.to_buffer()?;
        Ok(Self(bytes.into()))
    }
}

impl TryFrom<&NdefMessage> for HandoverRequestBytes {
    type Error = anyhow::Error;

    fn try_from(ndef_message: &NdefMessage) -> Result<Self, Self::Error> {
        let bytes = ndef_message.to_buffer()?;
        Ok(Self(bytes.into()))
    }
}
