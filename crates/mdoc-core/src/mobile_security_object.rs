use crate::cbor_string_map_struct::cbor_string_map_struct;
use crate::CoseKeyPublic;
use minicbor::bytes::ByteVec;
use minicbor::data::Tagged;
use std::collections::BTreeMap;

pub type DigestIds = BTreeMap<u64, ByteVec>;
pub type ValueDigests = BTreeMap<String, DigestIds>;
pub type DataElementIdentifiers = Vec<String>;
pub type DataElements = BTreeMap<String, DataElementIdentifiers>;
pub type TDate = Tagged<0, String>;
pub type Identifier = ByteVec;
pub type URI = String;
pub type Certificate = ByteVec;

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MobileSecurityObject {
        required {
            pub version: String => "version",
            pub digest_algorithm: String => "digestAlgorithm",
            pub value_digests: ValueDigests => "valueDigests",
            pub device_key_info: DeviceKeyInfo => "deviceKeyInfo",
            pub doc_type: String => "docType",
            pub validity_info: ValidityInfo => "validityInfo",
        }
        optional {
            pub status: Status => "status",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ValidityInfo {
        required {
            pub signed: TDate => "signed",
            pub valid_from: TDate => "validFrom",
            pub valid_until: TDate => "validUntil",
        }
        optional {
            pub expected_update: TDate => "expectedUpdate",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Status {
        required {
        }
        optional {
            pub identifier_list: IdentifierListInfo => "identifier_list",
            pub status_list: StatusListInfo => "status_list",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IdentifierListInfo {
        required {
            pub id: Identifier => "id",
            pub uri: URI => "uri",
        }
        optional {
            pub certificate: Certificate => "certificate",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StatusListInfo {
        required {
            pub idx: u64 => "idx",
            pub uri: URI => "uri",
        }
        optional {
            pub certificate: Certificate => "certificate",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceKeyInfo {
        required {
            pub device_key: CoseKeyPublic => "deviceKey",
        }
        optional {
            pub key_authorizations: KeyAuthorizations => "keyAuthorizations",
            pub key_info: KeyInfo => "keyInfo",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct KeyAuthorizations {
        required {
        }
        optional {
            pub name_spaces: Vec<String> => "nameSpaces",
            pub data_elements: DataElements => "dataElements",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct KeyInfo {
        required {
        }
        optional {
            pub key_usage: String => "keyUsage",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose_key::{Curve, KeyType};

    #[test]
    fn mobile_security_object_roundtrip() {
        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: BTreeMap::from([(
                "org.iso.18013.5.1".to_string(),
                BTreeMap::from([(0_u64, ByteVec::from(vec![0x11; 32]))]),
            )]),
            device_key_info: DeviceKeyInfo {
                device_key: CoseKeyPublic {
                    kty: KeyType::Ec2,
                    crv: Curve::P256,
                    x: ByteVec::from(vec![1u8; 32]),
                    y: ByteVec::from(vec![2u8; 32]),
                },
                key_authorizations: Some(KeyAuthorizations {
                    name_spaces: Some(vec!["org.iso.18013.5.1".to_string()]),
                    data_elements: Some(BTreeMap::from([(
                        "org.iso.18013.5.1".to_string(),
                        vec!["family_name".to_string()],
                    )])),
                }),
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: TDate::from("2026-01-01T00:00:00Z".to_string()),
                valid_from: TDate::from("2026-01-01T00:00:00Z".to_string()),
                valid_until: TDate::from("2027-01-01T00:00:00Z".to_string()),
                expected_update: None,
            },
            status: None,
        };

        let encoded = minicbor::to_vec(&mso).unwrap();
        let decoded: MobileSecurityObject = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, mso);
    }

    #[test]
    fn mobile_security_object_roundtrips_status() {
        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: BTreeMap::from([(
                "org.iso.18013.5.1".to_string(),
                BTreeMap::from([(0_u64, ByteVec::from(vec![0x11; 32]))]),
            )]),
            device_key_info: DeviceKeyInfo {
                device_key: CoseKeyPublic {
                    kty: KeyType::Ec2,
                    crv: Curve::P256,
                    x: ByteVec::from(vec![1u8; 32]),
                    y: ByteVec::from(vec![2u8; 32]),
                },
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: TDate::from("2026-01-01T00:00:00Z".to_string()),
                valid_from: TDate::from("2026-01-01T00:00:00Z".to_string()),
                valid_until: TDate::from("2027-01-01T00:00:00Z".to_string()),
                expected_update: None,
            },
            status: Some(Status {
                identifier_list: Some(IdentifierListInfo {
                    id: ByteVec::from(vec![0xAA; 32]),
                    uri: "https://example.com/identifier-list".to_string(),
                    certificate: Some(ByteVec::from(vec![0x01, 0x02])),
                }),
                status_list: Some(StatusListInfo {
                    idx: 7,
                    uri: "https://example.com/status-list".to_string(),
                    certificate: None,
                }),
            }),
        };

        let encoded = minicbor::to_vec(&mso).unwrap();
        let decoded: MobileSecurityObject = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded.status, mso.status);
    }
}
