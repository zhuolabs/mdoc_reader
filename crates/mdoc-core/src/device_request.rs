use crate::TaggedCborBytes;
use crate::cbor_string_map_struct::cbor_string_map_struct;
use minicbor::bytes::ByteVec;
use std::collections::BTreeMap;

pub const DEVICE_REQUEST_VERSION_1_0: &str = "1.0";

pub type NameSpaces = BTreeMap<String, BTreeMap<String, bool>>;
pub type DeviceRequestInfo = BTreeMap<String, ByteVec>;
pub type DocRequestInfo = BTreeMap<String, ByteVec>;

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DeviceRequest {
        required {
            pub version: String => "version",
            pub doc_requests: Vec<DocRequest> => "docRequests",
        }
        optional {
            pub device_request_info: TaggedCborBytes<DeviceRequestInfo> => "deviceRequestInfo",
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DocRequest {
        required {
            pub items_request: TaggedCborBytes<ItemRequest> => "itemsRequest",
        }
        optional {
        }
    }
}

cbor_string_map_struct! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ItemRequest {
        required {
            pub doc_type: String => "docType",
            pub name_spaces: NameSpaces => "nameSpaces",
        }
        optional {
            pub request_info: DocRequestInfo => "requestInfo",
        }
    }
}

pub struct DeviceRequestBuilder {
    version: String,
    doc_requests: Vec<DocRequest>,
    device_request_info: Option<TaggedCborBytes<DeviceRequestInfo>>,
}

impl DeviceRequest {
    pub fn builder() -> DeviceRequestBuilder {
        DeviceRequestBuilder {
            version: DEVICE_REQUEST_VERSION_1_0.to_string(),
            doc_requests: Vec::new(),
            device_request_info: None,
        }
    }
}

impl DeviceRequestBuilder {
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn device_request_info(mut self, info: &DeviceRequestInfo) -> Self {
        self.device_request_info = Some(TaggedCborBytes::from(info));
        self
    }

    pub fn add_doc_request(
        mut self,
        doc_type: impl Into<String>,
        name_spaces: NameSpaces,
        doc_request_info: Option<DocRequestInfo>,
    ) -> Self {
        let doc_type = doc_type.into();
        let items_request = ItemRequest {
            doc_type: doc_type.clone(),
            name_spaces: name_spaces.clone(),
            request_info: doc_request_info.clone(),
        };
        let items_request = TaggedCborBytes::from(&items_request);
        self.doc_requests.push(DocRequest { items_request });
        self
    }

    pub fn build(self) -> DeviceRequest {
        DeviceRequest {
            version: self.version,
            doc_requests: self.doc_requests,
            device_request_info: self.device_request_info,
        }
    }
}
