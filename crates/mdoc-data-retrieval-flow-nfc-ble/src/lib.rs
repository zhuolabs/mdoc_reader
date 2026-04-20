use anyhow::{Context, Result};
use async_trait::async_trait;
use connection_handover::{
    BleAdStructure, BleLeRole, BleOobRecord, CONNECTION_HANDOVER_SERVICE_NAME, HandoverRequest,
    HandoverSelect,
};
use mdoc_core::{
    CoseKeyPrivate, CoseKeyPublic, DeviceEngagement, DeviceRequest, DeviceResponse, NFCHandover,
    ReaderEngagement, SessionData, SessionEstablishment, SessionTranscript, TaggedCborBytes,
    ble_ident,
};
use mdoc_data_retrieval_flow::{
    DataRetrievalFlow, DataRetrievalFlowEvent, DataRetrievalFlowObserver, DataRetrievalResult,
    EngagementMethod, TransportKind,
};
use mdoc_security::{MdocRole, SessionEncryption};
use mdoc_transport::{BleTransportParams, MdocTransport, MdocTransportConnector};
use nfc_reader::NfcReader;
use packet_reorder_workaround::try_decode_and_decrypt_session_data;
use std::convert::TryFrom;
use tnep::TnepClient;
use uuid::Uuid;

mod packet_reorder_workaround;

const SESSION_DATA_STATUS_SESSION_TERMINATION: u64 = 20;

pub struct NfcBleDataRetrievalFlow<'a, T, F>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = BleTransportParams> + ?Sized,
{
    reader: &'a mut T,
    transport_factory: &'a F,
    service_uuid: Option<Uuid>,
}

impl<'a, T, F> NfcBleDataRetrievalFlow<'a, T, F>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = BleTransportParams> + ?Sized,
{
    pub fn new(reader: &'a mut T, transport_factory: &'a F, service_uuid: Option<Uuid>) -> Self {
        Self {
            reader,
            transport_factory,
            service_uuid,
        }
    }
}

#[async_trait(?Send)]
impl<T, F> DataRetrievalFlow for NfcBleDataRetrievalFlow<'_, T, F>
where
    T: NfcReader + ?Sized,
    F: MdocTransportConnector<Params = BleTransportParams> + ?Sized,
{
    type Error = anyhow::Error;

    async fn retrieve_data(
        &mut self,
        device_request: &DeviceRequest,
        e_reader_key_private: &CoseKeyPrivate,
        observer: Option<&dyn DataRetrievalFlowObserver>,
    ) -> Result<DataRetrievalResult> {
        let service_uuid = self.service_uuid.unwrap_or_else(Uuid::new_v4);

        notify_event(
            observer,
            DataRetrievalFlowEvent::WaitingForEngagement(EngagementMethod::Nfc),
        );

        let mut nfc = self
            .reader
            .connect(std::time::Duration::from_secs(120))
            .await?
            .ok_or_else(|| anyhow::anyhow!("NFC card was not detected within timeout"))?;

        notify_event(
            observer,
            DataRetrievalFlowEvent::EngagementConnected(EngagementMethod::Nfc),
        );

        let mut tnep = TnepClient::new(&mut nfc)
            .await
            .context("failed to initialize TNEP client")?;
        let mut handover_service = tnep
            .select(CONNECTION_HANDOVER_SERVICE_NAME)
            .await
            .context("failed to select TNEP handover service")?;

        let reader_engagement_record = &ReaderEngagement::default();
        let ble_oob_record = &BleOobRecord {
            ad_structures: vec![
                BleAdStructure::LeRole(BleLeRole::OnlyPeripheral),
                BleAdStructure::CompleteUuid128List(vec![service_uuid]),
            ],
        };
        let handover_request =
            HandoverRequest::new(ble_oob_record, vec![reader_engagement_record])?;

        let handover_request_message = (&handover_request).into();
        let handover_select_message = handover_service
            .exchange(&handover_request_message)
            .await
            .context("TNEP handover exchange failed")?;

        let handover_select: HandoverSelect = (&handover_select_message)
            .try_into()
            .map_err(|_| anyhow::anyhow!("Handover Select message parse failed"))?;

        let (_, device_engagement) = handover_select
            .find_carrier_auxiliary(
                |record| BleOobRecord::try_from(record).ok(),
                |record| DeviceEngagement::try_from(record).ok(),
            )
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "BleOob carrier with DeviceEngagement auxiliary record not found in Handover Select"
                )
            })?;

        let e_device_key_bytes = device_engagement.e_device_key_bytes();
        let ident = ble_ident(e_device_key_bytes)?;
        let e_reader_key = e_reader_key_private.to_public();
        let session_transcript = SessionTranscript(
            Some(TaggedCborBytes::from(&device_engagement)),
            TaggedCborBytes::from(&e_reader_key),
            NFCHandover(
                (&handover_select_message).try_into()?,
                Some((&handover_request_message).try_into()?),
            ),
        );

        let mut transport = self
            .transport_factory
            .connect(BleTransportParams {
                service_uuid,
                ident,
            })
            .await?;

        notify_event(
            observer,
            DataRetrievalFlowEvent::TransportConnected(TransportKind::Ble),
        );

        let device_response = do_reader_flow_with_transport(
            &mut transport,
            &e_device_key_bytes.decode()?,
            &session_transcript,
            e_reader_key_private,
            device_request,
            observer,
        )
        .await?;

        Ok(DataRetrievalResult {
            device_response,
            session_transcript,
        })
    }
}

async fn do_reader_flow_with_transport<T>(
    transport: &mut T,
    e_device_key: &CoseKeyPublic,
    session_transcript: &SessionTranscript,
    e_reader_key_private: &CoseKeyPrivate,
    device_request: &DeviceRequest,
    observer: Option<&dyn DataRetrievalFlowObserver>,
) -> Result<DeviceResponse>
where
    T: MdocTransport + ?Sized,
{
    let e_reader_key_public = e_reader_key_private.to_public();
    let encoded_device_request = minicbor::to_vec(device_request)?;
    let session_transcript_bytes = TaggedCborBytes::from(session_transcript);

    let session_encryption = SessionEncryption::new(
        MdocRole::Reader,
        e_reader_key_private,
        e_device_key,
        &session_transcript_bytes,
    )?;
    let encrypt_counter = 1u32;
    let encrypted_request =
        session_encryption.encrypt_data(&encoded_device_request, encrypt_counter)?;
    let session_establishment = SessionEstablishment {
        e_reader_key: TaggedCborBytes::from(&e_reader_key_public),
        data: encrypted_request.into(),
    };
    let encoded_session_establishment = minicbor::to_vec(session_establishment)?;
    transport.send(&encoded_session_establishment).await?;
    notify_event(observer, DataRetrievalFlowEvent::WaitingForUserApproval);

    let session_data_packets = transport.receive_packets().await?;
    let decrypt_counter = 1u32;
    let decoded = try_decode_and_decrypt_session_data(&session_data_packets, |joined| {
        decode_and_decrypt_session_data(joined, &session_encryption, decrypt_counter)
    })?;
    if decoded.message.is_empty() {
        anyhow::bail!("device did not return SessionData");
    }

    let device_response = minicbor::decode(&decoded.message)?;
    notify_event(observer, DataRetrievalFlowEvent::DeviceResponseReceived);

    if decoded.parsed.status != Some(SESSION_DATA_STATUS_SESSION_TERMINATION) {
        let termination = minicbor::to_vec(SessionData {
            data: None,
            status: Some(SESSION_DATA_STATUS_SESSION_TERMINATION),
        })?;
        transport.send(&termination).await?;
    }

    Ok(device_response)
}

fn notify_event(observer: Option<&dyn DataRetrievalFlowObserver>, event: DataRetrievalFlowEvent) {
    if let Some(observer) = observer {
        observer.on_event(event);
    }
}

fn head_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(16)
        .map(|b| format!("{:02X}", b))
        .collect()
}

struct DecodedSessionData {
    parsed: SessionData,
    message: Vec<u8>,
}

fn decode_and_decrypt_session_data(
    session_data: &[u8],
    session_encryption: &SessionEncryption,
    decrypt_counter: u32,
) -> Result<DecodedSessionData> {
    let parsed: SessionData = minicbor::decode(session_data).with_context(|| {
        format!(
            "failed to decode session data: len={} head={}",
            session_data.len(),
            head_hex(session_data)
        )
    })?;

    let ciphertext = parsed
        .data
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("session data does not include encrypted data"))?;
    let message = session_encryption
        .decrypt_data(ciphertext.as_slice(), decrypt_counter)
        .with_context(|| {
            format!(
                "failed to decrypt session message: len={} head={}",
                session_data.len(),
                head_hex(session_data)
            )
        })?;
    Ok(DecodedSessionData { parsed, message })
}
