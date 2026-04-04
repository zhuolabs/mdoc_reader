use std::collections::HashMap;
use std::convert::TryFrom;

use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};
use minicbor::{Decode, Encode};
use ndef_rs::payload::ExternalPayload;
use ndef_rs::{NdefMessage, NdefRecord, TNF};

use crate::alternative_carrier::AlternativeCarrier;
pub use crate::connection_handover_types::Error;
use crate::connection_handover_types::{CarrierPowerState, CarrierRecord};

pub const CONNECTION_HANDOVER_SERVICE_NAME: &str = "urn:nfc:sn:handover";

#[derive(Debug, Clone)]
pub struct HandoverRequest {
    version: u8,
    collision_resolution: Option<u16>,
    carriers: Vec<CarrierRecord>,
}

impl Default for HandoverRequest {
    fn default() -> Self {
        Self {
            version: 0x15,
            collision_resolution: None,
            carriers: Vec::new(),
        }
    }
}

impl HandoverRequest {
    pub fn new<C, A, I, CE, AE>(carrier: C, auxiliary: I) -> anyhow::Result<Self>
    where
        C: TryInto<NdefRecord, Error = CE>,
        I: IntoIterator<Item = A>,
        A: TryInto<NdefRecord, Error = AE>,
        CE: Into<anyhow::Error>,
        AE: Into<anyhow::Error>,
    {
        let carrier = carrier.try_into().map_err(Into::into)?;
        let auxiliary = auxiliary
            .into_iter()
            .map(|a| a.try_into().map_err(Into::into))
            .collect::<anyhow::Result<Vec<NdefRecord>>>()?;

        Ok(Self {
            carriers: vec![CarrierRecord {
                cps: CarrierPowerState::Active,
                carrier,
                auxiliary,
            }],
            ..Self::default()
        })
    }
}

#[derive(Debug, Clone)]
pub struct HandoverSelect {
    version: u8,
    carriers: Vec<CarrierRecord>,
}

impl HandoverSelect {
    pub fn find_carrier_auxiliary<'a, TC, TA, FC, FA>(
        &'a self,
        mut carrier_predicate: FC,
        mut auxiliary_predicate: FA,
    ) -> Option<(TC, TA)>
    where
        FC: FnMut(&'a NdefRecord) -> Option<TC>,
        FA: FnMut(&'a NdefRecord) -> Option<TA>,
    {
        self.carriers.iter().find_map(|carrier| {
            carrier_predicate(&carrier.carrier).and_then(|carrier_value| {
                carrier
                    .find_auxiliary(|record| auxiliary_predicate(record))
                    .map(|auxiliary_value| (carrier_value, auxiliary_value))
            })
        })
    }
}

struct ParsedHandoverMessage {
    version: u8,
    collision_resolution: Option<u16>,
    carriers: Vec<CarrierRecord>,
}

fn encode_handover_message(
    header_type: &[u8],
    version: u8,
    collision_resolution: Option<u16>,
    carriers: Vec<CarrierRecord>,
) -> NdefMessage {
    let mut embedded_records = Vec::new();
    if let Some(value) = collision_resolution {
        embedded_records.push(build_record(
            TNF::WellKnown,
            b"cr",
            None,
            value.to_be_bytes().to_vec(),
        ));
    }

    let mut outer_records = Vec::new();
    for (carrier_index, carrier_record) in carriers.into_iter().enumerate() {
        let carrier_id = carrier_record
            .carrier
            .id()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{carrier_index}").into_bytes());

        let carrier = clone_record_with_id(&carrier_record.carrier, Some(carrier_id.clone()));

        let mut auxiliary = Vec::new();
        let mut auxiliary_refs = Vec::new();
        for aux_record in &carrier_record.auxiliary {
            let aux_id = aux_record
                .id()
                .map(ToOwned::to_owned)
                .expect("auxiliary record must have an id");
            auxiliary_refs.push(aux_id.clone());
            auxiliary.push(aux_record.clone());
        }

        let ac = AlternativeCarrier {
            cps: carrier_record.cps,
            carrier_data_reference: carrier_id,
            auxiliary_data_reference: auxiliary_refs,
        };
        embedded_records.push(build_record(TNF::WellKnown, b"ac", None, ac.encode()));

        outer_records.push(carrier);
        outer_records.extend(auxiliary);
    }

    let embedded_message = NdefMessage::from(embedded_records.as_slice())
        .to_buffer()
        .expect("embedded handover NDEF encoding must succeed");
    let mut header_payload = vec![version];
    header_payload.extend_from_slice(&embedded_message);

    let mut records = Vec::with_capacity(1 + outer_records.len());
    records.push(build_record(
        TNF::WellKnown,
        header_type,
        None,
        header_payload,
    ));
    records.extend(outer_records);

    NdefMessage::from(records.as_slice())
}

fn parse_handover_message(
    message: &NdefMessage,
    header_type: &[u8],
) -> Result<ParsedHandoverMessage, Error> {
    let records = message.records();
    let header = records.first().ok_or(Error::InvalidMessage)?;
    if header.tnf() != TNF::WellKnown || header.record_type() != header_type {
        return Err(Error::InvalidHeader);
    }

    let payload = header.payload();
    let Some((&version, embedded_bytes)) = payload.split_first() else {
        return Err(Error::InvalidHeader);
    };

    let embedded_message = if embedded_bytes.is_empty() {
        NdefMessage::default()
    } else {
        NdefMessage::decode(embedded_bytes).map_err(|_| Error::InvalidEmbeddedMessage)?
    };

    let mut alternative_carriers = Vec::new();
    let mut collision_resolution = None;
    for record in embedded_message.records() {
        if record.tnf() != TNF::WellKnown {
            continue;
        }
        match record.record_type() {
            b"ac" => {
                let (ac, rest) = AlternativeCarrier::parse(record.payload())?;
                if !rest.is_empty() {
                    return Err(Error::InvalidEmbeddedMessage);
                }
                alternative_carriers.push(ac);
            }
            b"cr" if record.payload().len() == 2 => {
                collision_resolution = Some(u16::from_be_bytes([
                    record.payload()[0],
                    record.payload()[1],
                ]));
            }
            _ => {}
        }
    }

    let mut record_map = HashMap::new();
    for record in &records[1..] {
        if let Some(id) = record.id() {
            record_map.insert(id.to_vec(), record.clone());
        }
    }

    let mut carriers = Vec::with_capacity(alternative_carriers.len());
    for ac in alternative_carriers {
        let carrier = record_map
            .remove(&ac.carrier_data_reference)
            .ok_or(Error::CarrierNotFound)?;

        let mut auxiliary = Vec::with_capacity(ac.auxiliary_data_reference.len());
        for aux_ref in ac.auxiliary_data_reference {
            let aux = record_map
                .remove(&aux_ref)
                .ok_or(Error::AuxiliaryNotFound)?;
            auxiliary.push(aux);
        }

        carriers.push(CarrierRecord {
            cps: ac.cps,
            carrier,
            auxiliary,
        });
    }

    Ok(ParsedHandoverMessage {
        version,
        collision_resolution,
        carriers,
    })
}

fn build_record(tnf: TNF, record_type: &[u8], id: Option<Vec<u8>>, payload: Vec<u8>) -> NdefRecord {
    let raw = ExternalPayload::from_raw(record_type.to_vec(), payload);
    let mut builder = NdefRecord::builder().tnf(tnf).payload(&raw);
    if let Some(id) = id.filter(|id| !id.is_empty()) {
        builder = builder.id(id);
    }
    builder.build().expect("NDEF record encoding must succeed")
}

fn clone_record_with_id(record: &NdefRecord, id: Option<Vec<u8>>) -> NdefRecord {
    build_record(
        record.tnf(),
        record.record_type(),
        id.or_else(|| record.id().map(ToOwned::to_owned)),
        record.payload().to_vec(),
    )
}

impl From<&HandoverSelect> for NdefMessage {
    fn from(value: &HandoverSelect) -> Self {
        encode_handover_message(b"Hs", value.version, None, value.carriers.clone())
    }
}

impl From<&HandoverRequest> for NdefMessage {
    fn from(value: &HandoverRequest) -> Self {
        encode_handover_message(
            b"Hr",
            value.version,
            value.collision_resolution,
            value.carriers.clone(),
        )
    }
}

impl TryFrom<&NdefMessage> for HandoverSelect {
    type Error = Error;

    fn try_from(message: &NdefMessage) -> Result<Self, Self::Error> {
        let parsed = parse_handover_message(message, b"Hs")?;
        Ok(Self {
            version: parsed.version,
            carriers: parsed.carriers,
        })
    }
}

impl TryFrom<&NdefMessage> for HandoverRequest {
    type Error = Error;

    fn try_from(message: &NdefMessage) -> Result<Self, Self::Error> {
        let parsed = parse_handover_message(message, b"Hr")?;
        Ok(Self {
            version: parsed.version,
            collision_resolution: parsed.collision_resolution,
            carriers: parsed.carriers,
        })
    }
}

impl<C> Encode<C> for HandoverSelect {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        let message: NdefMessage = self.into();
        let bytes = message
            .to_buffer()
            .map_err(|_| EncodeError::message("failed to encode HandoverSelect as NDEF"))?;
        e.bytes(&bytes)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for HandoverSelect {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?;
        let message = NdefMessage::decode(bytes)
            .map_err(|_| DecodeError::message("invalid HandoverSelect NDEF bytes"))?;
        HandoverSelect::try_from(&message)
            .map_err(|_| DecodeError::message("failed to parse HandoverSelect from NDEF"))
    }
}

impl<C> Encode<C> for HandoverRequest {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        let message: NdefMessage = self.into();
        let bytes = message
            .to_buffer()
            .map_err(|_| EncodeError::message("failed to encode HandoverRequest as NDEF"))?;
        e.bytes(&bytes)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for HandoverRequest {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?;
        let message = NdefMessage::decode(bytes)
            .map_err(|_| DecodeError::message("invalid HandoverRequest NDEF bytes"))?;
        HandoverRequest::try_from(&message)
            .map_err(|_| DecodeError::message("failed to parse HandoverRequest from NDEF"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndef_rs::payload::ExternalPayload;

    fn build_external_record(
        tnf: TNF,
        record_type: &[u8],
        id: &[u8],
        payload: &[u8],
    ) -> NdefRecord {
        let raw = ExternalPayload::from_raw(record_type.to_vec(), payload.to_vec());
        let mut builder = NdefRecord::builder().tnf(tnf).payload(&raw);
        if !id.is_empty() {
            builder = builder.id(id.to_vec());
        }
        builder.build().unwrap()
    }

    #[test]
    fn round_trips_handover_select() {
        let select = HandoverSelect {
            version: 0x15,
            carriers: vec![CarrierRecord {
                cps: CarrierPowerState::Active,
                carrier: build_external_record(
                    TNF::MimeMedia,
                    b"application/vnd.bluetooth.le.oob",
                    b"0",
                    b"\x02\x1c\x00",
                ),
                auxiliary: vec![build_external_record(
                    TNF::External,
                    b"iso.org:18013:deviceengagement",
                    b"mdoc",
                    b"\xa1",
                )],
            }],
        };

        let encoded: NdefMessage = (&select).into();
        let parsed = HandoverSelect::try_from(&encoded).unwrap();

        assert_eq!(parsed.version, 0x15);
        assert_eq!(parsed.carriers.len(), 1);
        assert_eq!(parsed.carriers[0].cps, CarrierPowerState::Active);
        assert_eq!(
            parsed.carriers[0].carrier.record_type(),
            b"application/vnd.bluetooth.le.oob"
        );
        assert_eq!(parsed.carriers[0].auxiliary.len(), 1);
        assert_eq!(
            parsed.carriers[0].auxiliary[0].record_type(),
            b"iso.org:18013:deviceengagement"
        );
    }

    #[test]
    fn round_trips_handover_request_with_collision_resolution() {
        let request = HandoverRequest {
            collision_resolution: Some(0x0102),
            carriers: vec![CarrierRecord {
                cps: CarrierPowerState::Active,
                carrier: build_external_record(
                    TNF::MimeMedia,
                    b"application/vnd.bluetooth.le.oob",
                    b"ble",
                    b"\x02\x1c\x00",
                ),
                auxiliary: vec![],
            }],
            ..HandoverRequest::default()
        };

        let encoded: NdefMessage = (&request).into();
        let parsed = HandoverRequest::try_from(&encoded).unwrap();

        assert_eq!(parsed.version, 0x15);
        assert_eq!(parsed.collision_resolution, Some(0x0102));
        assert_eq!(parsed.carriers.len(), 1);
        assert_eq!(parsed.carriers[0].carrier.id(), Some(&b"ble"[..]));
    }

    #[test]
    fn find_helpers_return_first_mapped_value() {
        let select = HandoverSelect {
            version: 0x15,
            carriers: vec![
                CarrierRecord {
                    cps: CarrierPowerState::Inactive,
                    carrier: build_external_record(TNF::MimeMedia, b"first", b"c0", b""),
                    auxiliary: vec![build_external_record(TNF::External, b"skip", b"a0", b"")],
                },
                CarrierRecord {
                    cps: CarrierPowerState::Active,
                    carrier: build_external_record(TNF::MimeMedia, b"target", b"c1", b""),
                    auxiliary: vec![build_external_record(
                        TNF::External,
                        b"iso.org:18013:deviceengagement",
                        b"a1",
                        b"",
                    )],
                },
            ],
        };

        let carrier_type = select.carriers.iter().find_map(|carrier| {
            (carrier.carrier.record_type() == b"target").then(|| carrier.carrier.record_type())
        });
        let auxiliary_type = select.carriers[1].find_auxiliary(|record| {
            (record.tnf() == TNF::External
                && record.record_type() == b"iso.org:18013:deviceengagement")
                .then(|| record.record_type())
        });
        let combined = select.find_carrier_auxiliary(
            |carrier| (carrier.record_type() == b"target").then_some(carrier.record_type()),
            |record| {
                (record.tnf() == TNF::External
                    && record.record_type() == b"iso.org:18013:deviceengagement")
                    .then_some(record.record_type())
            },
        );

        assert_eq!(carrier_type, Some(&b"target"[..]));
        assert_eq!(auxiliary_type, Some(&b"iso.org:18013:deviceengagement"[..]));
        assert_eq!(
            combined,
            Some((&b"target"[..], &b"iso.org:18013:deviceengagement"[..]))
        );
    }
}
