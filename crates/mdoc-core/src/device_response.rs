use crate::cbor_string_map_struct::cbor_string_map_struct;
use crate::{CoseSign1, ElementValue, TaggedCborBytes};
use anyhow::Result;
use minicbor::bytes::ByteVec;
use std::collections::BTreeMap;

pub const DEVICE_RESPONSE_STATUS_OK: u64 = 0;
pub const DEVICE_RESPONSE_STATUS_GENERAL_ERROR: u64 = 10;
pub const DEVICE_RESPONSE_STATUS_CBOR_DECODING_ERROR: u64 = 11;
pub const DEVICE_RESPONSE_STATUS_CBOR_VALIDATION_ERROR: u64 = 12;

pub type DocumentError = BTreeMap<String, i64>;
pub type ErrorItems = BTreeMap<String, i64>;
pub type Errors = BTreeMap<String, ErrorItems>;
pub type DeviceSignedItems = BTreeMap<String, ElementValue>;
pub type DeviceNameSpaces = BTreeMap<String, DeviceSignedItems>;
pub type IssuerNameSpaces = BTreeMap<String, Vec<TaggedCborBytes<IssuerSignedItem>>>;

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceResponse {
        required {
            pub version: String => "version",
            pub status: u64 => "status",
        }
        optional {
            pub documents: Vec<MdocDocument> => "documents",
            pub document_errors: Vec<DocumentError> => "documentErrors",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MdocDocument {
        required {
            pub doc_type: String => "docType",
            pub issuer_signed: IssuerSigned => "issuerSigned",
            pub device_signed: DeviceSigned => "deviceSigned",
        }
        optional {
            pub errors: Errors => "errors",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IssuerSigned {
        required {
            pub issuer_auth: CoseSign1 => "issuerAuth",
        }
        optional {
            pub name_spaces: IssuerNameSpaces => "nameSpaces",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IssuerSignedItem {
        required {
            pub digest_id: u64 => "digestID",
            pub random: ByteVec => "random",
            pub element_identifier: String => "elementIdentifier",
            pub element_value: ElementValue => "elementValue",
        }
        optional {
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceSigned {
        required {
            pub name_spaces: TaggedCborBytes<DeviceNameSpaces> => "nameSpaces",
            pub device_auth: DeviceAuth => "deviceAuth",
        }
        optional {
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceAuth {
        required {
        }
        optional {
            pub device_signature: CoseSign1 => "deviceSignature",
            pub device_mac: ElementValue => "deviceMac",
        }
    }
}

pub fn find_element_value<'a>(
    items: &'a [TaggedCborBytes<IssuerSignedItem>],
    key: &str,
) -> Option<&'a ElementValue> {
    items
        .iter()
        .find(|item| item.0.element_identifier == key)
        .map(|item| &item.0.element_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::Encoder;

    #[test]
    fn parses_card_response() {
        let response = DeviceResponse {
            version: "1.0".to_string(),
            status: DEVICE_RESPONSE_STATUS_OK,
            documents: Some(vec![MdocDocument {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                issuer_signed: IssuerSigned {
                    issuer_auth: dummy_cose_sign1(),
                    name_spaces: Some(BTreeMap::from([
                        (
                            "org.iso.18013.5.1".to_string(),
                            vec![
                                issuer_signed_item("family_name", string_value("Mustermann")),
                                issuer_signed_item("portrait", bytes_value(&[1, 2, 3, 4])),
                            ],
                        ),
                        (
                            "org.iso.18013.5.1.aamva".to_string(),
                            vec![
                                issuer_signed_item("age_over_20", bool_value(true)),
                                issuer_signed_item("age_in_years", u64_value(20)),
                            ],
                        ),
                    ])),
                },
                device_signed: DeviceSigned {
                    name_spaces: TaggedCborBytes(BTreeMap::new()),
                    device_auth: DeviceAuth {
                        device_signature: Some(dummy_cose_sign1()),
                        device_mac: None,
                    },
                },
                errors: None,
            }]),
            document_errors: None,
        };

        let encoded = minicbor::to_vec(&response).unwrap();
        let decoded: DeviceResponse = minicbor::decode(&encoded).unwrap();
        let signed_data = decoded.documents.as_ref().unwrap()[0]
            .issuer_signed
            .name_spaces
            .as_ref()
            .unwrap()
            .get("org.iso.18013.5.1")
            .unwrap();

        assert_eq!(decoded, response);
        assert_eq!(
            find_element_value(&signed_data, "family_name"),
            Some(&ElementValue::String("Mustermann".to_string()))
        );
        assert_eq!(
            find_element_value(&signed_data, "portrait"),
            Some(&ElementValue::Bytes(vec![1, 2, 3, 4]))
        );
    }

    #[test]
    fn decodes_unsupported_element_value_as_raw_bytes() {
        let mut e = Encoder::new(Vec::new());
        e.null().unwrap();
        let encoded_null = e.into_writer();

        let value: ElementValue = minicbor::decode(&encoded_null).unwrap();
        assert_eq!(value, ElementValue::RawBytes(encoded_null.clone()));
        let re_encoded = minicbor::to_vec(&value).unwrap();
        assert_eq!(re_encoded, encoded_null);
    }

    fn issuer_signed_item(
        identifier: &str,
        element_value: ElementValue,
    ) -> TaggedCborBytes<IssuerSignedItem> {
        TaggedCborBytes(IssuerSignedItem {
            digest_id: 0,
            random: ByteVec::from(vec![0]),
            element_identifier: identifier.to_string(),
            element_value,
        })
    }

    fn dummy_cose_sign1() -> CoseSign1 {
        CoseSign1 {
            protected: crate::ProtectedHeaderMap(None),
            unprotected: crate::HeaderMap::default(),
            payload: None,
            signature: ByteVec::from(vec![0u8; 64]),
        }
    }

    fn string_value(value: &str) -> ElementValue {
        ElementValue::String(value.to_string())
    }

    fn bool_value(value: bool) -> ElementValue {
        ElementValue::Bool(value)
    }

    fn u64_value(value: u64) -> ElementValue {
        ElementValue::U64(value)
    }

    fn bytes_value(value: &[u8]) -> ElementValue {
        ElementValue::Bytes(value.to_vec())
    }
}
