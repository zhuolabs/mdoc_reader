use mdoc_core::{CoseKeyPrivate, DeviceRequest, DeviceResponse};
use mdoc_data_retrieval_flow::{DataRetrievalFlow, DataRetrievalFlowObserver};
use mdoc_data_retrieval_flow_nfc_ble::NfcBleDataRetrievalFlow;
use mdoc_transport::{BleTransportParams, MdocTransportConnector};
use nfc_reader::NfcReader;
use uuid::Uuid;

mod validation;
use validation::validate_device_response;

pub async fn read_mdoc<T, F>(
    nfc: &mut T,
    transport: &F,
    e_reader_key_private: &CoseKeyPrivate,
    device_request: &DeviceRequest,
    ignore_crl: bool,
    ignore_mso_revocation_check: bool,
    observer: Option<&dyn DataRetrievalFlowObserver>,
    iaca_cert: Option<&x509_cert::Certificate>,
    service_uuid: Option<Uuid>,
) -> anyhow::Result<DeviceResponse>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = BleTransportParams> + ?Sized,
{
    let mut flow = NfcBleDataRetrievalFlow::new(nfc, transport, service_uuid);
    let result = flow
        .retrieve_data(device_request, e_reader_key_private, observer)
        .await?;

    validate_device_response(
        &result.device_response,
        e_reader_key_private,
        &result.session_transcript,
        iaca_cert,
        ignore_crl,
        ignore_mso_revocation_check,
    )
    .await?;

    Ok(result.device_response)
}
