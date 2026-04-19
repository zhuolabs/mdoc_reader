mod alternative_carrier;
mod ble_oob_record;
mod connection_handover;
mod connection_handover_types;

pub use ble_oob_record::{
    BLE_OOB_MIME_TYPE, BleAdStructure, BleAddressType, BleLeDeviceAddress, BleLeRole, BleOobRecord,
};
pub use connection_handover::{CONNECTION_HANDOVER_SERVICE_NAME, HandoverRequest, HandoverSelect};
