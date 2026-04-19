use anyhow::{Result, bail, ensure};
use ndef_rs::payload::MimePayload;
use ndef_rs::{NdefRecord, TNF};
use std::convert::TryFrom;
use uuid::Uuid;

pub const BLE_OOB_MIME_TYPE: &str = "application/vnd.bluetooth.le.oob";
const BLUETOOTH_BASE_UUID_SUFFIX: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleLeRole {
    OnlyPeripheral,
    OnlyCentral,
    PeripheralPreferred,
    CentralPreferred,
    Unknown(u8),
}

impl From<u8> for BleLeRole {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::OnlyPeripheral,
            0x01 => Self::OnlyCentral,
            0x02 => Self::PeripheralPreferred,
            0x03 => Self::CentralPreferred,
            other => Self::Unknown(other),
        }
    }
}

impl From<BleLeRole> for u8 {
    fn from(value: BleLeRole) -> Self {
        match value {
            BleLeRole::OnlyPeripheral => 0x00,
            BleLeRole::OnlyCentral => 0x01,
            BleLeRole::PeripheralPreferred => 0x02,
            BleLeRole::CentralPreferred => 0x03,
            BleLeRole::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleAddressType {
    Public,
    Random,
    Unknown(u8),
}

impl From<u8> for BleAddressType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Public,
            0x01 => Self::Random,
            other => Self::Unknown(other),
        }
    }
}

impl From<BleAddressType> for u8 {
    fn from(value: BleAddressType) -> Self {
        match value {
            BleAddressType::Public => 0x00,
            BleAddressType::Random => 0x01,
            BleAddressType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleLeDeviceAddress {
    pub address: [u8; 6],
    pub address_type: BleAddressType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleAdStructure {
    IncompleteUuid16List(Vec<u16>),
    CompleteUuid16List(Vec<u16>),
    ShortenedLocalName(Vec<u8>),
    CompleteLocalName(Vec<u8>),
    IncompleteUuid128List(Vec<Uuid>),
    CompleteUuid128List(Vec<Uuid>),
    LeBluetoothDeviceAddress(BleLeDeviceAddress),
    LeRole(BleLeRole),
    UnknownAdStructure { ad_type: u8, data: Vec<u8> },
}

impl BleAdStructure {
    fn le_role(&self) -> Option<BleLeRole> {
        match self {
            Self::LeRole(role) => Some(*role),
            _ => None,
        }
    }

    fn le_device_address(&self) -> Option<&BleLeDeviceAddress> {
        match self {
            Self::LeBluetoothDeviceAddress(device_address) => Some(device_address),
            _ => None,
        }
    }

    fn first_service_uuid_128(&self) -> Option<Uuid> {
        match self {
            Self::CompleteUuid128List(uuids) => uuids.first().copied(),
            Self::IncompleteUuid128List(uuids) => uuids.first().copied(),
            _ => None,
        }
    }
}

impl TryFrom<Vec<u8>> for BleAdStructure {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        let Some((&ad_type, data)) = value.split_first() else {
            bail!("BLE OOB AD structure is missing type");
        };

        match ad_type {
            0x02 => {
                ensure!(
                    data.len() % 2 == 0,
                    "16-bit Service UUID AD structure must be a multiple of 2 bytes"
                );
                Ok(Self::IncompleteUuid16List(
                    data.chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect(),
                ))
            }
            0x03 => {
                ensure!(
                    data.len() % 2 == 0,
                    "16-bit Service UUID AD structure must be a multiple of 2 bytes"
                );
                Ok(Self::CompleteUuid16List(
                    data.chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect(),
                ))
            }
            0x06 => {
                ensure!(
                    data.len() % 16 == 0,
                    "128-bit Service UUID AD structure must be a multiple of 16 bytes"
                );
                Ok(Self::IncompleteUuid128List(parse_uuid128_list(data)?))
            }
            0x07 => {
                ensure!(
                    data.len() % 16 == 0,
                    "128-bit Service UUID AD structure must be a multiple of 16 bytes"
                );
                Ok(Self::CompleteUuid128List(parse_uuid128_list(data)?))
            }
            0x08 => Ok(Self::ShortenedLocalName(data.to_vec())),
            0x09 => Ok(Self::CompleteLocalName(data.to_vec())),
            0x1B => {
                ensure!(
                    data.len() == 7,
                    "LE Bluetooth Device Address AD structure must be 7 bytes"
                );
                let mut address = [0u8; 6];
                address.copy_from_slice(&data[..6]);
                Ok(Self::LeBluetoothDeviceAddress(BleLeDeviceAddress {
                    address,
                    address_type: BleAddressType::from(data[6]),
                }))
            }
            0x1C => {
                ensure!(data.len() == 1, "LE Role AD structure must be 1 byte");
                Ok(Self::LeRole(BleLeRole::from(data[0])))
            }
            _ => Ok(Self::UnknownAdStructure {
                ad_type,
                data: data.to_vec(),
            }),
        }
    }
}

impl TryFrom<&BleAdStructure> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: &BleAdStructure) -> Result<Self> {
        match value {
            BleAdStructure::IncompleteUuid16List(uuids) => {
                encode_ad_structure(0x02, &encode_uuid16_list(uuids))
            }
            BleAdStructure::CompleteUuid16List(uuids) => {
                encode_ad_structure(0x03, &encode_uuid16_list(uuids))
            }
            BleAdStructure::ShortenedLocalName(data) => encode_ad_structure(0x08, data),
            BleAdStructure::CompleteLocalName(data) => encode_ad_structure(0x09, data),
            BleAdStructure::IncompleteUuid128List(uuids) => {
                encode_ad_structure(0x06, &encode_uuid128_list(uuids))
            }
            BleAdStructure::CompleteUuid128List(uuids) => {
                encode_ad_structure(0x07, &encode_uuid128_list(uuids))
            }
            BleAdStructure::LeBluetoothDeviceAddress(device_address) => {
                let mut data = Vec::with_capacity(7);
                data.extend_from_slice(&device_address.address);
                data.push(u8::from(device_address.address_type));
                encode_ad_structure(0x1B, &data)
            }
            BleAdStructure::LeRole(role) => encode_ad_structure(0x1C, &[u8::from(*role)]),
            BleAdStructure::UnknownAdStructure { ad_type, data } => {
                encode_ad_structure(*ad_type, data)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BleOobRecord {
    pub ad_structures: Vec<BleAdStructure>,
}

impl TryFrom<&NdefRecord> for BleOobRecord {
    type Error = anyhow::Error;

    fn try_from(record: &NdefRecord) -> Result<Self> {
        if record.tnf() != TNF::MimeMedia || record.record_type() != BLE_OOB_MIME_TYPE.as_bytes() {
            bail!("record is not application/vnd.bluetooth.le.oob");
        }

        let mut ble_oob = Self {
            ad_structures: Vec::new(),
        };

        let mut cursor = 0usize;
        let payload = record.payload();
        while cursor < payload.len() {
            let structure_len = payload[cursor] as usize;
            cursor += 1;

            if structure_len == 0 {
                continue;
            }

            ensure!(
                cursor + structure_len <= payload.len(),
                "BLE OOB AD structure exceeds payload length"
            );

            let structure = payload[cursor..cursor + structure_len].to_vec();
            ble_oob
                .ad_structures
                .push(BleAdStructure::try_from(structure)?);
            cursor += structure_len;
        }

        Ok(ble_oob)
    }
}

impl TryFrom<&BleOobRecord> for NdefRecord {
    type Error = anyhow::Error;

    fn try_from(value: &BleOobRecord) -> Result<Self> {
        let payload = value
            .ad_structures
            .iter()
            .map(Vec::<u8>::try_from)
            .collect::<Result<Vec<_>>>()?
            .concat();

        let raw = MimePayload::from_mime(
            BLE_OOB_MIME_TYPE
                .parse()
                .expect("BLE OOB MIME type must be valid"),
            payload,
        );
        Ok(NdefRecord::builder()
            .tnf(TNF::MimeMedia)
            .payload(&raw)
            .build()?)
    }
}

impl BleOobRecord {
    pub fn le_role(&self) -> Option<BleLeRole> {
        self.ad_structures.iter().find_map(BleAdStructure::le_role)
    }

    pub fn le_device_address(&self) -> Option<&BleLeDeviceAddress> {
        self.ad_structures
            .iter()
            .find_map(BleAdStructure::le_device_address)
    }

    pub fn first_service_uuid_128(&self) -> Option<Uuid> {
        self.ad_structures
            .iter()
            .find_map(BleAdStructure::first_service_uuid_128)
    }

    pub fn bluetooth_base_uuid_to_uuid16(uuid: Uuid) -> Option<u16> {
        let bytes = uuid.as_bytes();
        if bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[4..] == BLUETOOTH_BASE_UUID_SUFFIX {
            Some(u16::from_be_bytes([bytes[2], bytes[3]]))
        } else {
            None
        }
    }
}

fn parse_uuid128_list(data: &[u8]) -> Result<Vec<Uuid>> {
    data.chunks_exact(16)
        .map(|chunk| {
            let mut uuid = chunk.to_vec();
            uuid.reverse();
            Uuid::from_slice(&uuid).map_err(Into::into)
        })
        .collect()
}

fn encode_uuid16_list(uuids: &[u16]) -> Vec<u8> {
    let mut data = Vec::with_capacity(uuids.len() * 2);
    for uuid in uuids {
        data.extend_from_slice(&uuid.to_le_bytes());
    }
    data
}

fn encode_uuid128_list(uuids: &[Uuid]) -> Vec<u8> {
    let mut data = Vec::with_capacity(uuids.len() * 16);
    for uuid in uuids {
        let mut bytes = uuid.as_bytes().to_vec();
        bytes.reverse();
        data.extend_from_slice(&bytes);
    }
    data
}

fn encode_ad_structure(ad_type: u8, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        data.len() < u8::MAX as usize,
        "BLE OOB AD structure data too large: {} bytes",
        data.len()
    );
    let mut encoded = Vec::with_capacity(data.len() + 2);
    encoded.push((data.len() + 1) as u8);
    encoded.push(ad_type);
    encoded.extend_from_slice(data);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_ble_oob_record() {
        let uuid = Uuid::parse_str("45efef74-2b2c-4837-a9a3-b0e1d05a6917").unwrap();
        let ble_oob = BleOobRecord {
            ad_structures: vec![
                BleAdStructure::LeBluetoothDeviceAddress(BleLeDeviceAddress {
                    address: [1, 2, 3, 4, 5, 6],
                    address_type: BleAddressType::Random,
                }),
                BleAdStructure::LeRole(BleLeRole::OnlyPeripheral),
                BleAdStructure::CompleteUuid16List(vec![0x180D]),
                BleAdStructure::CompleteUuid128List(vec![uuid]),
                BleAdStructure::CompleteLocalName(b"mdoc".to_vec()),
            ],
        };

        let record: NdefRecord = (&ble_oob).try_into().unwrap();
        let parsed: BleOobRecord = (&record).try_into().unwrap();

        assert_eq!(parsed, ble_oob);
    }

    #[test]
    fn parses_existing_handover_payload_shape() {
        let uuid = Uuid::parse_str("45efef74-2b2c-4837-a9a3-b0e1d05a6917").unwrap();
        let payload = vec![
            0x02, 0x1C, 0x00, 0x03, 0x03, 0x0D, 0x18, 0x11, 0x07, 0x17, 0x69, 0x5A, 0xD0, 0xE1,
            0xB0, 0xA3, 0xA9, 0x37, 0x48, 0x2C, 0x2B, 0x74, 0xEF, 0xEF, 0x45,
        ];
        let raw = MimePayload::from_mime(
            BLE_OOB_MIME_TYPE
                .parse()
                .expect("BLE OOB MIME type must be valid"),
            payload,
        );
        let record = NdefRecord::builder()
            .tnf(TNF::MimeMedia)
            .id(b"0".to_vec())
            .payload(&raw)
            .build()
            .unwrap();

        let parsed: BleOobRecord = (&record).try_into().unwrap();

        assert_eq!(parsed.le_role(), Some(BleLeRole::OnlyPeripheral));
        assert_eq!(
            parsed.ad_structures,
            vec![
                BleAdStructure::LeRole(BleLeRole::OnlyPeripheral),
                BleAdStructure::CompleteUuid16List(vec![0x180D]),
                BleAdStructure::CompleteUuid128List(vec![uuid]),
            ]
        );
    }

    #[test]
    fn keeps_incomplete_and_complete_uuid_lists_distinct() {
        let complete_uuid = Uuid::parse_str("45efef74-2b2c-4837-a9a3-b0e1d05a6917").unwrap();
        let incomplete_uuid = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        let ble_oob = BleOobRecord {
            ad_structures: vec![
                BleAdStructure::IncompleteUuid16List(vec![0x180F]),
                BleAdStructure::CompleteUuid16List(vec![0x180D]),
                BleAdStructure::IncompleteUuid128List(vec![incomplete_uuid]),
                BleAdStructure::CompleteUuid128List(vec![complete_uuid]),
            ],
        };

        let record: NdefRecord = (&ble_oob).try_into().unwrap();
        let parsed: BleOobRecord = (&record).try_into().unwrap();

        assert_eq!(parsed, ble_oob);
    }

    #[test]
    fn derives_16bit_uuid_only_for_bluetooth_base_uuid() {
        let heart_rate = Uuid::parse_str("0000180d-0000-1000-8000-00805f9b34fb").unwrap();
        let custom = Uuid::parse_str("45efef74-2b2c-4837-a9a3-b0e1d05a6917").unwrap();

        assert_eq!(
            BleOobRecord::bluetooth_base_uuid_to_uuid16(heart_rate),
            Some(0x180D)
        );
        assert_eq!(BleOobRecord::bluetooth_base_uuid_to_uuid16(custom), None);
    }
}
