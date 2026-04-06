use anyhow::{Context, Result};
use connection_handover::{
    BleAdStructure, BleLeRole, BleOobRecord, HandoverRequest, HandoverSelect,
    CONNECTION_HANDOVER_SERVICE_NAME,
};
use mdoc_core::{
    ble_ident, CoseKeyPrivate, CoseKeyPublic, DeviceEngagement, DeviceRequest, DeviceResponse,
    MdocRole, NFCHandover, ReaderEngagement, SessionData, SessionEncryption, SessionEstablishment,
    SessionTranscript, TaggedCborBytes,
};
use mdoc_reader_flow::{EngagementMethod, ReaderFlowEvent, ReaderFlowObserver, TransportKind};
use mdoc_reader_transport::{BleTransportParams, ReaderTransport, ReaderTransportConnector};
use nfc_reader::NfcReader;
use packet_reorder_workaround::try_decode_and_decrypt_session_data;
use std::convert::TryFrom;
use tnep::TnepClient;
use uuid::Uuid;

mod packet_reorder_workaround;

const SESSION_DATA_STATUS_SESSION_TERMINATION: u64 = 20;

#[derive(Debug, Clone)]
pub struct ReadMdocResult {
    pub device_response: DeviceResponse,
    pub session_transcript: TaggedCborBytes<SessionTranscript>,
}

pub async fn read_mdoc<T, F>(
    reader: &mut T,
    transport_factory: &F,
    device_request: &DeviceRequest,
    service_uuid: Option<Uuid>,
    observer: Option<&dyn ReaderFlowObserver>,
) -> Result<ReadMdocResult>
where
    T: NfcReader + ?Sized,
    F: ReaderTransportConnector<Params = BleTransportParams> + ?Sized,
{
    let service_uuid = service_uuid.unwrap_or_else(Uuid::new_v4);

    notify_event(
        observer,
        ReaderFlowEvent::WaitingForEngagement(EngagementMethod::Nfc),
    );

    let mut nfc = reader
        .connect(std::time::Duration::from_secs(120))
        .await?
        .ok_or_else(|| anyhow::anyhow!("NFC card was not detected within timeout"))?;

    notify_event(
        observer,
        ReaderFlowEvent::EngagementConnected(EngagementMethod::Nfc),
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
    let handover_request = HandoverRequest::new(ble_oob_record, vec![reader_engagement_record])?;

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
    let e_reader_key_private = CoseKeyPrivate::new()?;
    let e_reader_key = e_reader_key_private.to_public();
    let session_transcript = TaggedCborBytes::from(&SessionTranscript(
        Some(TaggedCborBytes::from(&device_engagement)),
        TaggedCborBytes::from(&e_reader_key),
        NFCHandover(
            (&handover_select_message).try_into()?,
            Some((&handover_request_message).try_into()?),
        ),
    ));

    let mut transport = transport_factory
        .connect(BleTransportParams {
            service_uuid,
            ident,
        })
        .await?;
    notify_event(
        observer,
        ReaderFlowEvent::TransportConnected(TransportKind::Ble),
    );

    do_reader_flow_with_transport(
        &mut transport,
        &e_device_key_bytes.decode()?,
        &session_transcript,
        &e_reader_key_private,
        device_request,
        observer,
    )
    .await
}

async fn do_reader_flow_with_transport<T>(
    transport: &mut T,
    e_device_key: &CoseKeyPublic,
    session_transcript: &TaggedCborBytes<SessionTranscript>,
    e_reader_key_private: &CoseKeyPrivate,
    device_request: &DeviceRequest,
    observer: Option<&dyn ReaderFlowObserver>,
) -> Result<ReadMdocResult>
where
    T: ReaderTransport + ?Sized,
{
    let e_reader_key_public = e_reader_key_private.to_public();
    let encoded_device_request = minicbor::to_vec(device_request)?;
    let session_encryption = SessionEncryption::new(
        MdocRole::Reader,
        e_reader_key_private,
        e_device_key,
        session_transcript,
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
    notify_event(observer, ReaderFlowEvent::WaitingForUserApproval);

    let session_data_packets = transport.receive_packets().await?;
    let decrypt_counter = 1u32;
    let decoded = try_decode_and_decrypt_session_data(&session_data_packets, |joined| {
        decode_and_decrypt_session_data(joined, &session_encryption, decrypt_counter)
    })?;
    if decoded.message.is_empty() {
        anyhow::bail!("device did not return SessionData");
    }

    let device_response: DeviceResponse = minicbor::decode(&decoded.message)?;
    notify_event(observer, ReaderFlowEvent::DeviceResponseReceived);

    if decoded.parsed.status != Some(SESSION_DATA_STATUS_SESSION_TERMINATION) {
        let termination = minicbor::to_vec(SessionData {
            data: None,
            status: Some(SESSION_DATA_STATUS_SESSION_TERMINATION),
        })?;
        transport.send(&termination).await?;
    }

    Ok(ReadMdocResult {
        device_response,
        session_transcript: session_transcript.clone(),
    })
}

fn notify_event(observer: Option<&dyn ReaderFlowObserver>, event: ReaderFlowEvent) {
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
