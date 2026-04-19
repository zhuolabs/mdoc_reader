use crate::CoseKeyPublic;
use crate::cbor_bytes::TaggedCborBytes;
use anyhow::Result;
use minicbor::bytes::ByteVec;
use minicbor::decode;
use minicbor::encode;
use minicbor::{Decode, Decoder, Encode, Encoder};
use ndef_rs::payload::ExternalPayload;
use ndef_rs::{NdefRecord, TNF};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use uuid::Uuid;

const VERSION_1_0: &str = "1.0";
const VERSION_1_1: &str = "1.1";
pub const DEVICE_ENGAGEMENT_RECORD_TYPE: &[u8] = b"iso.org:18013:deviceengagement";
pub const DEVICE_ENGAGEMENT_ID: &[u8] = b"mdoc";

pub type OriginInfo = ByteVec;

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(map)]
pub struct DeviceEngagement {
    #[n(0)]
    pub version: String,

    #[n(1)]
    pub security: Security,

    #[n(2)]
    pub device_retrieval_methods: Option<Vec<RetrievalMethod>>,

    #[n(5)]
    pub origin_infos: Option<Vec<OriginInfo>>,

    #[n(6)]
    pub capabilities: Option<Capabilities>,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
pub struct Security(#[n(0)] pub i64, #[n(1)] pub TaggedCborBytes<CoseKeyPublic>);

#[derive(Debug, Clone, Default, Encode, Decode)]
#[cbor(map)]
pub struct Capabilities {
    #[n(2)]
    #[cbor(skip_if = "Option::is_none")]
    pub handover_session_establishment_support: Option<bool>,

    #[n(3)]
    #[cbor(skip_if = "Option::is_none")]
    pub reader_auth_all_support: Option<bool>,

    #[n(4)]
    #[cbor(skip_if = "Option::is_none")]
    pub extended_request_support: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalOptions {
    Wifi(WifiOptions),
    Ble(BleOptions),
    Nfc(NfcOptions),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct WifiOptions {
    #[n(0)]
    #[cbor(skip_if = "Option::is_none")]
    pub pass_phrase: Option<String>,

    #[n(1)]
    #[cbor(skip_if = "Option::is_none")]
    pub operating_class: Option<u64>,

    #[n(2)]
    #[cbor(skip_if = "Option::is_none")]
    pub channel_number: Option<u64>,

    #[n(3)]
    #[cbor(skip_if = "Option::is_none")]
    pub supported_bands: Option<ByteVec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct BleOptions {
    #[n(0)]
    pub supports_peripheral_server_mode: bool,

    #[n(1)]
    pub supports_central_client_mode: bool,

    #[n(10)]
    #[cbor(skip_if = "Option::is_none")]
    pub peripheral_server_mode_uuid: Option<ByteVec>,

    #[n(11)]
    #[cbor(skip_if = "Option::is_none")]
    pub central_client_mode_uuid: Option<ByteVec>,

    #[n(20)]
    #[cbor(skip_if = "Option::is_none")]
    pub peripheral_server_mode_ble_device_address: Option<ByteVec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct NfcOptions {
    #[n(0)]
    pub max_command_data_field_length: u64,

    #[n(1)]
    pub max_response_data_field_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalMethod {
    pub method_type: u64,
    pub version: u64,
    pub options: RetrievalOptions,
}

impl<C> encode::Encode<C> for RetrievalMethod {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> core::result::Result<(), encode::Error<W::Error>> {
        e.array(3)?;
        e.u64(self.method_type)?;
        e.u64(self.version)?;

        match (&self.method_type, &self.options) {
            (1, RetrievalOptions::Nfc(v)) => v.encode(e, ctx)?,
            (2, RetrievalOptions::Ble(v)) => v.encode(e, ctx)?,
            (3, RetrievalOptions::Wifi(v)) => v.encode(e, ctx)?,
            _ => {
                return Err(encode::Error::message(
                    "method_type and options variant mismatch",
                ));
            }
        }

        Ok(())
    }
}

impl<'b, C> decode::Decode<'b, C> for RetrievalMethod {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> core::result::Result<Self, decode::Error> {
        let len = d.array()?;
        if let Some(n) = len {
            if n != 3 {
                return Err(decode::Error::message(
                    "ReaderRetrievalMethod must be a 3-element array",
                ));
            }
        }

        let method_type = d.u64()?;
        let version = d.u64()?;
        let options = match method_type {
            1 => RetrievalOptions::Nfc(NfcOptions::decode(d, ctx)?),
            2 => RetrievalOptions::Ble(BleOptions::decode(d, ctx)?),
            3 => RetrievalOptions::Wifi(WifiOptions::decode(d, ctx)?),
            _ => {
                return Err(decode::Error::message(
                    "unsupported ReaderRetrievalMethod type",
                ));
            }
        };

        Ok(Self {
            method_type,
            version,
            options,
        })
    }
}

impl DeviceEngagement {
    fn validate(&self) -> Result<()> {
        if self.origin_infos.is_some() || self.capabilities.is_some() {
            anyhow::ensure!(
                self.version == VERSION_1_1,
                "Version must be '{}' when key 5 or 6 is present",
                VERSION_1_1
            );
        } else {
            anyhow::ensure!(
                self.version == VERSION_1_0,
                "Version must be '{}' when key 5 and 6 are absent",
                VERSION_1_0
            );
        }

        anyhow::ensure!(
            !self
                .device_retrieval_methods
                .as_ref()
                .map(|v| v.is_empty())
                .unwrap_or(false),
            "DeviceRetrievalMethods must contain one or more entries when present"
        );

        if let Some(methods) = self.device_retrieval_methods.as_ref() {
            let mut seen = BTreeSet::<(u64, u64)>::new();
            for method in methods {
                anyhow::ensure!(
                    seen.insert((method.method_type, method.version)),
                    "Duplicate DeviceRetrievalMethod type/version pair: ({}, {})",
                    method.method_type,
                    method.version
                );
            }
        }

        Ok(())
    }

    pub fn security_cipher_suite(&self) -> i64 {
        self.security.0
    }

    pub fn e_device_key_bytes(&self) -> &TaggedCborBytes<CoseKeyPublic> {
        &self.security.1
    }

    pub fn first_ble_service_uuid(&self) -> Option<Uuid> {
        let methods = self.device_retrieval_methods.as_deref()?;
        for method in methods {
            let RetrievalOptions::Ble(ble) = &method.options else {
                continue;
            };
            if let Some(uuid) = ble
                .peripheral_server_mode_uuid
                .as_deref()
                .and_then(|b| Uuid::from_slice(b).ok())
            {
                return Some(uuid);
            }
            if let Some(uuid) = ble
                .central_client_mode_uuid
                .as_deref()
                .and_then(|b| Uuid::from_slice(b).ok())
            {
                return Some(uuid);
            }
        }
        None
    }
}

impl TryFrom<&NdefRecord> for DeviceEngagement {
    type Error = anyhow::Error;

    fn try_from(record: &NdefRecord) -> Result<Self> {
        anyhow::ensure!(
            record.tnf() == TNF::External
                && record.record_type() == DEVICE_ENGAGEMENT_RECORD_TYPE
                && record.id() == Some(DEVICE_ENGAGEMENT_ID),
            "record is not iso.org:18013:deviceengagement"
        );
        let engagement: DeviceEngagement = minicbor::decode(record.payload())
            .map_err(|e| anyhow::anyhow!("DeviceEngagement decode failed: {}", e))?;
        engagement.validate()?;
        Ok(engagement)
    }
}

impl TryFrom<&DeviceEngagement> for NdefRecord {
    type Error = anyhow::Error;

    fn try_from(value: &DeviceEngagement) -> Result<Self> {
        value.validate()?;
        let payload = minicbor::to_vec(value)
            .map_err(|e| anyhow::anyhow!("DeviceEngagement encode failed: {}", e))?;
        let raw = ExternalPayload::from_raw(DEVICE_ENGAGEMENT_RECORD_TYPE.to_vec(), payload);

        NdefRecord::builder()
            .tnf(TNF::External)
            .id(DEVICE_ENGAGEMENT_ID.to_vec())
            .payload(&raw)
            .build()
            .map_err(|e| anyhow::anyhow!("DeviceEngagement NDEF record build failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_cbor_given_hex_payload() {
        let payload = hex_to_bytes(
            r#"
            a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5f
            a444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281
            830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917
            "#,
        )
        .expect("hex decode should succeed");

        let engagement: DeviceEngagement =
            minicbor::decode(&payload).expect("minicbor::decode should parse provided payload");
        engagement.validate().expect("validate should pass");

        assert_eq!(engagement.version, "1.0");
        assert_eq!(engagement.security_cipher_suite(), 1);
        assert_eq!(
            engagement
                .device_retrieval_methods
                .as_ref()
                .map(|v| v.len()),
            Some(1)
        );
    }

    #[test]
    fn round_trips_ndef_record() {
        let payload = hex_to_bytes(
                r#"
                a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5f
                a444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281
                830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917
                "#,
            )
            .unwrap();
        let engagement: DeviceEngagement = minicbor::decode(&payload).unwrap();
        engagement.validate().unwrap();

        let record: NdefRecord = (&engagement).try_into().unwrap();
        let parsed = DeviceEngagement::try_from(&record).unwrap();

        assert_eq!(record.tnf(), TNF::External);
        assert_eq!(record.record_type(), DEVICE_ENGAGEMENT_RECORD_TYPE);
        assert_eq!(record.id(), Some(DEVICE_ENGAGEMENT_ID));
        assert_eq!(parsed.version, engagement.version);

        assert_eq!(
            parsed.device_retrieval_methods,
            engagement.device_retrieval_methods
        );
    }

    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
        let normalized: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        anyhow::ensure!(
            normalized.len() % 2 == 0,
            "hex length must be even, got {}",
            normalized.len()
        );
        let mut out = Vec::with_capacity(normalized.len() / 2);
        for i in (0..normalized.len()).step_by(2) {
            let b = u8::from_str_radix(&normalized[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex at {}: {}", i, e))?;
            out.push(b);
        }
        Ok(out)
    }
}
