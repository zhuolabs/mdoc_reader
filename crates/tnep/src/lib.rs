pub mod client;
pub mod error;
pub mod record;
pub mod service;

pub use client::TnepClient;
pub use service::TnepService;

pub use error::{Error, Result};

use ndef_rs::payload::ExternalPayload;
use ndef_rs::{NdefMessage, NdefRecord, TNF};
use nfc_reader::NfcTag;
use std::time::Duration;

use crate::record::ServiceParameterRecord;

const APDU_CLA_ISO7816: u8 = 0x00;
const INS_SELECT: u8 = 0xA4;
const INS_READ_BINARY: u8 = 0xB0;
const INS_UPDATE_BINARY: u8 = 0xD6;
const P1_SELECT_BY_NAME: u8 = 0x04;
const P1_SELECT_BY_FILE_ID: u8 = 0x00;
const P2_SELECT_FIRST_OR_ONLY: u8 = 0x00;
const P2_SELECT_NO_FCI: u8 = 0x0C;
const SW_SUCCESS_1: u8 = 0x90;
const SW_SUCCESS_2: u8 = 0x00;

const NDEF_TAG_APP_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
const NDEF_CC_FILE_ID: u16 = 0xE103;
const NDEF_NLEN_OFFSET: u16 = 0x0000;
const NDEF_NLEN_SIZE: usize = 2;
const SHORT_APDU_MAX_LC: usize = 0x100;

const CC_LEN_FIELD_SIZE: usize = 2;
const CC_MIN_LEN: usize = 15;
const CC_MAPPING_VERSION_OFFSET: usize = 2;
const CC_MLE_OFFSET: usize = 3;
const CC_MLC_OFFSET: usize = 5;
const CC_TLV_START_OFFSET: usize = 7;
const CC_TLV_NDEF_FILE_CONTROL: u8 = 0x04;
const CC_TLV_NDEF_FILE_CONTROL_MIN_LEN: usize = 6;
const NDEF_FILE_ID_OFFSET_IN_TLV: usize = 0;
const NDEF_MAX_SIZE_OFFSET_IN_TLV: usize = 2;
const NDEF_READ_ACCESS_OFFSET_IN_TLV: usize = 4;
const NDEF_WRITE_ACCESS_OFFSET_IN_TLV: usize = 5;

#[derive(Debug, Clone)]
struct Cc {
    mapping_version: u8,
    m_le: u16,
    m_lc: u16,
    ndef_file_id: u16,
    max_ndef_size: u16,
    read_access: u8,
    write_access: u8,
}

impl Cc {
    fn read_chunk_size(&self) -> usize {
        let mle = usize::from(self.m_le);
        if mle == 0 { SHORT_APDU_MAX_LC } else { mle }
    }

    fn write_chunk_size(&self) -> usize {
        let mlc = usize::from(self.m_lc);
        if mlc == 0 { SHORT_APDU_MAX_LC } else { mlc }
    }
}

/// Parse Service Parameter Records from NDEF Message.
fn parse_service_parameters(msg: &NdefMessage) -> Vec<ServiceParameterRecord> {
    msg.records()
        .iter()
        .filter_map(|record| ServiceParameterRecord::from_record(record).ok())
        .collect()
}

fn build_service_select_message(service_name: &str) -> Result<NdefMessage> {
    let service = service_name.as_bytes();
    if service.len() > u8::MAX as usize {
        return Err(Error::invalid_message());
    }

    let mut payload = Vec::with_capacity(1 + service.len());
    payload.push(service.len() as u8);
    payload.extend_from_slice(service);

    let record_payload = ExternalPayload::from_raw(b"Ts", payload);
    let record = NdefRecord::builder()
        .tnf(TNF::WellKnown)
        .payload(&record_payload)
        .build()
        .map_err(|_| Error::invalid_message())?;
    Ok(NdefMessage::from(record))
}

fn parse_status(message: &NdefMessage) -> Option<u8> {
    for r in message.records() {
        if r.tnf() == TNF::WellKnown && r.record_type() == b"Te" && r.payload().len() == 1 {
            return Some(r.payload()[0]);
        }
    }
    None
}

fn wt_int_to_duration(wt_int: u8) -> Duration {
    let exponent = (wt_int as f64 / 4.0) - 1.0;
    let seconds = 2f64.powf(exponent) / 1000.0;
    Duration::from_secs_f64(seconds.max(0.001))
}

async fn ndef_transact_with_params<T>(
    tag: &mut T,
    cc: &Cc,
    message: &NdefMessage,
    n_wait: u8,
    wt_int: u8,
) -> Result<NdefMessage>
where
    T: NfcTag + ?Sized,
{
    write_ndef_message_selected(tag, cc, message).await?;
    receive_ndef_message_selected(tag, cc, n_wait, wt_int).await
}

async fn read_cc<T>(tag: &mut T) -> Result<Cc>
where
    T: NfcTag + ?Sized,
{
    select_file(tag, NDEF_CC_FILE_ID).await?;

    let cc_len_field = read_binary(tag, 0x0000, CC_LEN_FIELD_SIZE as u8).await?;
    if cc_len_field.len() != CC_LEN_FIELD_SIZE {
        return Err(Error::protocol_error());
    }
    let cc_len = u16::from_be_bytes([cc_len_field[0], cc_len_field[1]]) as usize;
    if cc_len < CC_MIN_LEN {
        return Err(Error::protocol_error());
    }

    let mut cc = Vec::with_capacity(cc_len);
    let mut offset = 0usize;
    while offset < cc_len {
        let chunk = (cc_len - offset).min(SHORT_APDU_MAX_LC);
        let chunk_data = read_binary(tag, offset as u16, chunk as u8).await?;
        if chunk_data.len() != chunk {
            return Err(Error::protocol_error());
        }
        cc.extend_from_slice(&chunk_data);
        offset += chunk;
    }

    parse_cc(&cc)
}

fn parse_cc(cc: &[u8]) -> Result<Cc> {
    if cc.len() < CC_MIN_LEN {
        return Err(Error::protocol_error());
    }

    let mapping_version = cc[CC_MAPPING_VERSION_OFFSET];
    if mapping_version == 0 {
        return Err(Error::protocol_error());
    }

    let m_le = u16::from_be_bytes([cc[CC_MLE_OFFSET], cc[CC_MLE_OFFSET + 1]]);
    let m_lc = u16::from_be_bytes([cc[CC_MLC_OFFSET], cc[CC_MLC_OFFSET + 1]]);

    let mut i = CC_TLV_START_OFFSET;
    while i + 1 < cc.len() {
        let tlv_t = cc[i];
        let tlv_l = cc[i + 1] as usize;
        i += 2;

        if i + tlv_l > cc.len() {
            break;
        }

        if tlv_t == CC_TLV_NDEF_FILE_CONTROL && tlv_l >= CC_TLV_NDEF_FILE_CONTROL_MIN_LEN {
            let ndef_file_id = u16::from_be_bytes([
                cc[i + NDEF_FILE_ID_OFFSET_IN_TLV],
                cc[i + NDEF_FILE_ID_OFFSET_IN_TLV + 1],
            ]);
            let max_ndef_size = u16::from_be_bytes([
                cc[i + NDEF_MAX_SIZE_OFFSET_IN_TLV],
                cc[i + NDEF_MAX_SIZE_OFFSET_IN_TLV + 1],
            ]);
            let read_access = cc[i + NDEF_READ_ACCESS_OFFSET_IN_TLV];
            let write_access = cc[i + NDEF_WRITE_ACCESS_OFFSET_IN_TLV];

            return Ok(Cc {
                mapping_version,
                m_le,
                m_lc,
                ndef_file_id,
                max_ndef_size,
                read_access,
                write_access,
            });
        }

        i += tlv_l;
    }

    Err(Error::protocol_error())
}

async fn receive_ndef_message_selected<T>(
    tag: &mut T,
    cc: &Cc,
    n_wait: u8,
    wt_int: u8,
) -> Result<NdefMessage>
where
    T: NfcTag + ?Sized,
{
    if (cc.mapping_version >> 4) == 0 {
        return Err(Error::protocol_error());
    }
    if cc.read_access == 0xFF {
        return Err(Error::protocol_error());
    }

    for _ in 0..=n_wait {
        tokio::time::sleep(wt_int_to_duration(wt_int)).await;
        if let Some(message) = read_ndef_message_selected(tag, cc).await? {
            return Ok(message);
        }
    }

    Err(Error::protocol_error())
}

async fn read_ndef_message<T>(tag: &mut T, cc: &Cc) -> Result<NdefMessage>
where
    T: NfcTag + ?Sized,
{
    select_file(tag, cc.ndef_file_id).await?;

    read_ndef_message_selected(tag, cc)
        .await?
        .ok_or_else(|| Error::protocol_error())
}

async fn read_ndef_message_selected<T>(tag: &mut T, cc: &Cc) -> Result<Option<NdefMessage>>
where
    T: NfcTag + ?Sized,
{
    if (cc.mapping_version >> 4) == 0 {
        return Err(Error::protocol_error());
    }

    if cc.read_access == 0xFF {
        return Err(Error::protocol_error());
    }

    let nlen = read_binary(tag, NDEF_NLEN_OFFSET, NDEF_NLEN_SIZE as u8).await?;
    if nlen.len() != NDEF_NLEN_SIZE {
        return Err(Error::protocol_error());
    }

    let ndef_len = u16::from_be_bytes([nlen[0], nlen[1]]) as usize;
    if ndef_len == 0 {
        return Ok(None);
    }

    let mut out = Vec::with_capacity(ndef_len);
    let mut read_offset = NDEF_NLEN_SIZE as u16;
    let max_read_chunk = cc.read_chunk_size();
    while out.len() < ndef_len {
        let remain = ndef_len - out.len();
        let chunk = remain.min(max_read_chunk);
        let chunk_data = read_binary(tag, read_offset, chunk as u8).await?;
        if chunk_data.len() != chunk {
            return Err(Error::protocol_error());
        }
        out.extend_from_slice(&chunk_data);
        read_offset += chunk as u16;
    }

    Ok(Some(
        NdefMessage::decode(&out).map_err(|_| Error::invalid_message())?,
    ))
}

async fn write_ndef_message_selected<T>(tag: &mut T, cc: &Cc, message: &NdefMessage) -> Result<()>
where
    T: NfcTag + ?Sized,
{
    if cc.write_access == 0xFF {
        return Err(Error::protocol_error());
    }

    let message_bytes = message.to_buffer().map_err(|_| Error::invalid_message())?;
    let len = message_bytes.len();
    if len == 0 || len > usize::from(cc.max_ndef_size) {
        return Err(Error::invalid_message());
    }

    let max_write_chunk = cc.write_chunk_size();

    if len + NDEF_NLEN_SIZE <= max_write_chunk {
        let mut payload = Vec::with_capacity(NDEF_NLEN_SIZE + len);
        payload.extend_from_slice(&(len as u16).to_be_bytes());
        payload.extend_from_slice(&message_bytes);
        update_binary(tag, NDEF_NLEN_OFFSET, &payload).await?;
        return Ok(());
    }

    update_binary(tag, NDEF_NLEN_OFFSET, &[0x00, 0x00]).await?;

    let mut offset = 0usize;
    while offset < len {
        let end = (offset + max_write_chunk).min(len);
        update_binary(
            tag,
            (NDEF_NLEN_SIZE + offset) as u16,
            &message_bytes[offset..end],
        )
        .await?;
        offset = end;
    }

    update_binary(tag, NDEF_NLEN_OFFSET, &(len as u16).to_be_bytes()).await?;
    Ok(())
}

fn build_select_by_file_id_apdu(file_id: u16) -> [u8; 7] {
    [
        APDU_CLA_ISO7816,
        INS_SELECT,
        P1_SELECT_BY_FILE_ID,
        P2_SELECT_NO_FCI,
        0x02,
        (file_id >> 8) as u8,
        (file_id & 0xFF) as u8,
    ]
}

fn build_select_by_name_apdu(aid: &[u8]) -> Vec<u8> {
    let mut apdu = Vec::with_capacity(6 + aid.len());
    apdu.push(APDU_CLA_ISO7816);
    apdu.push(INS_SELECT);
    apdu.push(P1_SELECT_BY_NAME);
    apdu.push(P2_SELECT_FIRST_OR_ONLY);
    apdu.push(aid.len() as u8);
    apdu.extend_from_slice(aid);
    apdu.push(0x00);
    apdu
}

fn build_read_binary_apdu(offset: u16, le: u8) -> [u8; 5] {
    [
        APDU_CLA_ISO7816,
        INS_READ_BINARY,
        (offset >> 8) as u8,
        (offset & 0xFF) as u8,
        le,
    ]
}

fn build_update_binary_apdu(offset: u16, data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() > SHORT_APDU_MAX_LC {
        return Err(Error::invalid_message());
    }

    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.push(APDU_CLA_ISO7816);
    apdu.push(INS_UPDATE_BINARY);
    apdu.push((offset >> 8) as u8);
    apdu.push((offset & 0xFF) as u8);
    apdu.push(data.len() as u8);
    apdu.extend_from_slice(data);
    Ok(apdu)
}

async fn select_file<T>(tag: &mut T, file_id: u16) -> Result<()>
where
    T: NfcTag + ?Sized,
{
    let apdu = build_select_by_file_id_apdu(file_id);
    let _ = transceive_checked(tag, &apdu).await?;
    Ok(())
}

async fn select_by_name<T>(tag: &mut T, aid: &[u8]) -> Result<()>
where
    T: NfcTag + ?Sized,
{
    let apdu = build_select_by_name_apdu(aid);
    let _ = transceive_checked(tag, &apdu).await?;
    Ok(())
}

async fn read_binary<T>(tag: &mut T, offset: u16, le: u8) -> Result<Vec<u8>>
where
    T: NfcTag + ?Sized,
{
    let apdu = build_read_binary_apdu(offset, le);
    transceive_checked(tag, &apdu).await
}

async fn update_binary<T>(tag: &mut T, offset: u16, data: &[u8]) -> Result<()>
where
    T: NfcTag + ?Sized,
{
    let apdu = build_update_binary_apdu(offset, data)?;
    let _ = transceive_checked(tag, &apdu).await?;
    Ok(())
}

async fn transceive_checked<T>(tag: &mut T, apdu: &[u8]) -> Result<Vec<u8>>
where
    T: NfcTag + ?Sized,
{
    let resp = tag.transceive(apdu).await.map_err(Error::transport)?;

    if resp.len() < NDEF_NLEN_SIZE {
        return Err(Error::protocol_error());
    }

    let sw1 = resp[resp.len() - NDEF_NLEN_SIZE];
    let sw2 = resp[resp.len() - 1];
    if sw1 != SW_SUCCESS_1 || sw2 != SW_SUCCESS_2 {
        return Err(Error::protocol_error());
    }

    Ok(resp[..resp.len() - NDEF_NLEN_SIZE].to_vec())
}
