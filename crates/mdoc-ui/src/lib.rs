use mdoc_core::DeviceResponse;
use mdoc_data_retrieval_flow::DataRetrievalFlowEvent;

pub trait MdocResultUi<V> {
    type Error;

    fn render_result(
        &mut self,
        response: &DeviceResponse,
        validation: &V,
    ) -> Result<(), Self::Error>;
}

pub trait FlowEventUi {
    type Error;

    fn on_flow_event(&self, event: DataRetrievalFlowEvent) -> Result<(), Self::Error>;
}
