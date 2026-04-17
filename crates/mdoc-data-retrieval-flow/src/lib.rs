use async_trait::async_trait;
use mdoc_core::{CoseKeyPrivate, DeviceRequest, DeviceResponse, SessionTranscript};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngagementMethod {
    Nfc,
    QrCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Ble,
    Wifi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRetrievalFlowEvent {
    WaitingForEngagement(EngagementMethod),
    EngagementConnected(EngagementMethod),
    TransportConnected(TransportKind),
    WaitingForUserApproval,
    DeviceResponseReceived,
}

pub trait DataRetrievalFlowObserver {
    fn on_event(&self, event: DataRetrievalFlowEvent);
}

#[derive(Debug, Clone)]
pub struct DataRetrievalResult {
    pub device_response: DeviceResponse,
    pub session_transcript: SessionTranscript,
}

#[async_trait(?Send)]
pub trait DataRetrievalFlow {
    type Error;

    async fn retrieve_data(
        &mut self,
        device_request: &DeviceRequest,
        e_reader_key_private: &CoseKeyPrivate,
        observer: Option<&dyn DataRetrievalFlowObserver>,
    ) -> Result<DataRetrievalResult, Self::Error>;
}
