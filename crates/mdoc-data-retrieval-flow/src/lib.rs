use async_trait::async_trait;
use mdoc_core::{DeviceRequest, DeviceResponse, SessionTranscript, TaggedCborBytes};

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
    pub session_transcript: TaggedCborBytes<SessionTranscript>,
}

#[async_trait(?Send)]
pub trait DataRetrievalFlow {
    type Error;

    async fn retrieve_data(
        &mut self,
        device_request: &DeviceRequest,
        observer: Option<&dyn DataRetrievalFlowObserver>,
    ) -> Result<DataRetrievalResult, Self::Error>;
}
