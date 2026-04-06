use anyhow::{bail, Context, Result};
use log::debug;
use mdoc_transport::{BleTransportParams, MdocTransport, MdocTransportConnector};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;
use windows::core::{IInspectable, Ref, GUID};
use windows::Devices::Bluetooth::BluetoothError;
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattLocalService, GattProtectionLevel, GattServiceProvider,
    GattServiceProviderAdvertisingParameters, GattWriteRequestedEventArgs,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};

const STATE_UUID: &str = "00000005-a123-48ce-896b-4c76973373e6";
const C2S_UUID: &str = "00000006-a123-48ce-896b-4c76973373e6";
const S2C_UUID: &str = "00000007-a123-48ce-896b-4c76973373e6";
const IDENT_UUID: &str = "00000008-a123-48ce-896b-4c76973373e6";

const STATE_START: u8 = 0x01;
const STATE_END: u8 = 0x02;
const CHUNK_LAST: u8 = 0x00;
const CHUNK_MORE: u8 = 0x01;
const MAX_CHUNK: usize = 180;

enum Event {
    StateWrite(Vec<u8>),
    C2sWrite(Vec<u8>),
    S2cSubscribed(bool),
}

pub struct WinRtBleMdocTransport {
    service_provider: GattServiceProvider,
    s2c_char: GattLocalCharacteristic,
    event_rx: mpsc::UnboundedReceiver<Event>,
    incoming_packets: Vec<Vec<u8>>,
    pending: VecDeque<Vec<Vec<u8>>>,
    advertising_started: bool,
    connect_timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct WinRtBleMdocTransportFactory;

fn uuid_to_guid(uuid: Uuid) -> GUID {
    let (d1, d2, d3, d4) = uuid.as_fields();
    GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: *d4,
    }
}

fn bytes_to_ibuf(bytes: &[u8]) -> Result<IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;
    Ok(writer.DetachBuffer()?)
}

fn ibuf_to_bytes(buf: &IBuffer) -> Result<Vec<u8>> {
    let len = buf.Length()? as usize;
    let reader = DataReader::FromBuffer(buf)?;
    let mut bytes = vec![0u8; len];
    reader.ReadBytes(&mut bytes)?;
    Ok(bytes)
}

async fn create_char(
    service: &GattLocalService,
    uuid_str: &str,
    props: GattCharacteristicProperties,
    static_value: Option<&[u8]>,
) -> Result<GattLocalCharacteristic> {
    let params = GattLocalCharacteristicParameters::new()?;
    params.SetCharacteristicProperties(props)?;
    params.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    params.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
    if let Some(val) = static_value {
        params.SetStaticValue(&bytes_to_ibuf(val)?)?;
    }
    let r = service
        .CreateCharacteristicAsync(uuid_to_guid(Uuid::parse_str(uuid_str)?), &params)
        .with_context(|| format!("CreateCharacteristicAsync {}", uuid_str))?
        .await
        .with_context(|| format!("wait CreateCharacteristic {}", uuid_str))?;
    if r.Error()? != BluetoothError::Success {
        bail!("CreateCharacteristic {} error: {:?}", uuid_str, r.Error()?);
    }
    Ok(r.Characteristic()?)
}

fn register_write_handler(
    char: &GattLocalCharacteristic,
    tx: mpsc::UnboundedSender<Event>,
    make_event: fn(Vec<u8>) -> Event,
) -> Result<()> {
    char.WriteRequested(&TypedEventHandler::new(
        move |_: Ref<'_, GattLocalCharacteristic>, args: Ref<'_, GattWriteRequestedEventArgs>| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            // GetDeferral before any async work — WinRT will not deliver the next
            // WriteRequested event until Complete() is called, ensuring sequential delivery.
            let deferral = args.GetDeferral()?;
            futures::executor::block_on(async {
                let req = args.GetRequestAsync()?.await?;
                let ibuf = req.Value()?;
                let bytes = ibuf_to_bytes(&ibuf).unwrap_or_default();
                debug!(
                    "WriteRequested tid={:?} len={}",
                    std::thread::current().id(),
                    bytes.len()
                );
                let _ = tx.send(make_event(bytes));
                Ok::<(), windows::core::Error>(())
            })?;
            let _ = deferral.Complete();
            Ok(())
        },
    ))?;
    Ok(())
}

impl WinRtBleMdocTransport {
    async fn wait_until_session_ready(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        let mut s2c_subscribed = false;
        let mut state_started = false;

        loop {
            if s2c_subscribed && state_started {
                break;
            }
            let elapsed = start.elapsed();
            if elapsed >= self.connect_timeout {
                bail!(
                    "Timeout waiting for BLE session readiness after {}s",
                    elapsed.as_secs()
                );
            }
            let remaining = self.connect_timeout.saturating_sub(elapsed);
            let wait = remaining.min(Duration::from_millis(500));
            match tokio::time::timeout(wait, self.event_rx.recv()).await {
                Ok(Some(Event::S2cSubscribed(sub))) => {
                    s2c_subscribed = sub;
                }
                Ok(Some(Event::StateWrite(payload))) => {
                    if payload.as_slice() == [STATE_START] {
                        state_started = true;
                    }
                }
                Ok(Some(Event::C2sWrite(payload))) => {
                    if let Some(msg_packets) = self.handle_chunk(&payload).await? {
                        self.pending.push_back(msg_packets);
                    }
                }
                Ok(None) => bail!("BLE event channel closed"),
                Err(_) => {}
            }
        }

        Ok(())
    }

    async fn handle_chunk(&mut self, chunk: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
        if chunk.is_empty() {
            bail!("Empty c2s chunk");
        }
        match chunk[0] {
            CHUNK_MORE => {
                self.incoming_packets.push(chunk[1..].to_vec());
                Ok(None)
            }
            CHUNK_LAST => {
                self.incoming_packets.push(chunk[1..].to_vec());
                match tokio::time::timeout(Duration::from_millis(30), self.event_rx.recv()).await {
                    Ok(Some(Event::C2sWrite(late_chunk)))
                        if !late_chunk.is_empty() && late_chunk[0] == CHUNK_MORE =>
                    {
                        let insert_at = self.incoming_packets.len().saturating_sub(1);
                        self.incoming_packets
                            .insert(insert_at, late_chunk[1..].to_vec());
                    }
                    Ok(Some(_)) | Ok(None) | Err(_) => {}
                }
                Ok(Some(std::mem::take(&mut self.incoming_packets)))
            }
            other => bail!("Invalid chunk first byte: {}", other),
        }
    }
}

#[allow(async_fn_in_trait)]
impl MdocTransportConnector for WinRtBleMdocTransportFactory {
    type Transport = WinRtBleMdocTransport;
    type Params = BleTransportParams;

    async fn connect(&self, params: Self::Params) -> Result<Self::Transport> {
        let (tx, event_rx) = mpsc::unbounded_channel::<Event>();

        let sp_result = GattServiceProvider::CreateAsync(uuid_to_guid(params.service_uuid))
            .context("GattServiceProvider::CreateAsync")?
            .await
            .context("wait GattServiceProvider::CreateAsync")?;
        if sp_result.Error()? != BluetoothError::Success {
            bail!(
                "GattServiceProvider::CreateAsync error: {:?}",
                sp_result.Error()?
            );
        }
        let service_provider = sp_result.ServiceProvider()?;
        let service = service_provider.Service()?;

        let state_char = create_char(
            &service,
            STATE_UUID,
            GattCharacteristicProperties::WriteWithoutResponse
                | GattCharacteristicProperties::Notify,
            None,
        )
        .await?;

        let c2s_char = create_char(
            &service,
            C2S_UUID,
            GattCharacteristicProperties::WriteWithoutResponse,
            None,
        )
        .await?;

        let s2c_char = create_char(
            &service,
            S2C_UUID,
            GattCharacteristicProperties::Notify,
            None,
        )
        .await?;

        create_char(
            &service,
            IDENT_UUID,
            GattCharacteristicProperties::Read,
            Some(&params.ident),
        )
        .await?;

        register_write_handler(&state_char, tx.clone(), Event::StateWrite)?;
        register_write_handler(&c2s_char, tx.clone(), Event::C2sWrite)?;

        {
            let tx = tx.clone();
            s2c_char.SubscribedClientsChanged(&TypedEventHandler::new(
                move |sender: Ref<'_, GattLocalCharacteristic>, _: Ref<'_, IInspectable>| {
                    let count = sender
                        .as_ref()
                        .and_then(|c| c.SubscribedClients().ok())
                        .and_then(|v| v.Size().ok())
                        .unwrap_or(0);
                    let _ = tx.send(Event::S2cSubscribed(count > 0));
                    Ok(())
                },
            ))?;
        }

        let mut transport = WinRtBleMdocTransport {
            service_provider,
            s2c_char,
            event_rx,
            incoming_packets: Vec::new(),
            pending: VecDeque::new(),
            advertising_started: false,
            connect_timeout: Duration::from_secs(120),
        };

        let advertising_params = GattServiceProviderAdvertisingParameters::new()?;
        advertising_params.SetIsConnectable(true)?;
        advertising_params.SetIsDiscoverable(true)?;
        transport
            .service_provider
            .StartAdvertisingWithParameters(&advertising_params)?;
        transport.advertising_started = true;
        transport.wait_until_session_ready().await?;

        Ok(transport)
    }
}

#[allow(async_fn_in_trait)]
impl MdocTransport for WinRtBleMdocTransport {
    async fn send(&mut self, message: &[u8]) -> Result<()> {
        if message.is_empty() {
            let ibuf = bytes_to_ibuf(&[CHUNK_LAST])?;
            self.s2c_char
                .NotifyValueAsync(&ibuf)?
                .await
                .context("NotifyValueAsync")?;
            return Ok(());
        }
        let max = MAX_CHUNK - 1;
        let mut offset = 0;
        while offset < message.len() {
            let size = (message.len() - offset).min(max);
            let is_last = offset + size == message.len();
            let mut chunk = Vec::with_capacity(size + 1);
            chunk.push(if is_last { CHUNK_LAST } else { CHUNK_MORE });
            chunk.extend_from_slice(&message[offset..offset + size]);
            self.s2c_char
                .NotifyValueAsync(&bytes_to_ibuf(&chunk)?)?
                .await
                .context("NotifyValueAsync")?;
            offset += size;
        }
        Ok(())
    }

    async fn receive_packets(&mut self) -> Result<Vec<Vec<u8>>> {
        if let Some(msg_packets) = self.pending.pop_front() {
            return Ok(msg_packets);
        }
        let mut last_log_sec = 0u64;
        let start = std::time::Instant::now();
        loop {
            let elapsed_sec = start.elapsed().as_secs();
            if elapsed_sec >= last_log_sec + 5 {
                last_log_sec = elapsed_sec;
                debug!("Waiting for message... elapsed={}s", elapsed_sec);
            }
            match tokio::time::timeout(Duration::from_millis(500), self.event_rx.recv()).await {
                Ok(Some(Event::C2sWrite(payload))) => {
                    if let Some(msg_packets) = self.handle_chunk(&payload).await? {
                        return Ok(msg_packets);
                    }
                }
                Ok(Some(Event::StateWrite(payload))) if payload.as_slice() == [STATE_END] => {
                    return Ok(Vec::new());
                }
                Ok(Some(_)) => {}
                Ok(None) => bail!("BLE event channel closed"),
                Err(_) => {}
            }
        }
    }
}

impl Drop for WinRtBleMdocTransport {
    fn drop(&mut self) {
        if self.advertising_started {
            let _ = self.service_provider.StopAdvertising();
            self.advertising_started = false;
        }
    }
}
