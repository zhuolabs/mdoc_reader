use anyhow::{Context, Result};
use chrono::NaiveDate;
use hayro_jpeg2000::{DecodeSettings, Image as Jpeg2000Image};
use image::{DynamicImage, ImageFormat};
use log::info;
use mdoc_core::{DeviceResponse, ElementValue, FullDate};
use mdoc_data_retrieval_flow::{DataRetrievalFlowEvent, EngagementMethod, TransportKind};
use mdoc_ui::{FlowEventUi, MdocResultUi};
use minicbor::bytes::ByteVec;

const PORTRAIT_WIDTH_CELLS: u32 = 30;

#[derive(Default)]
pub struct ConsoleMdocUi;

impl MdocResultUi<()> for ConsoleMdocUi {
    type Error = anyhow::Error;

    fn render_result(&mut self, response: &DeviceResponse, _validation: &()) -> Result<()> {
        print_issuer_signed_data(response)?;
        Ok(())
    }
}

impl FlowEventUi for ConsoleMdocUi {
    type Error = anyhow::Error;

    fn on_flow_event(&self, event: DataRetrievalFlowEvent) -> Result<()> {
        print_flow_event(event);
        Ok(())
    }
}

fn print_flow_event(event: DataRetrievalFlowEvent) {
    match event {
        DataRetrievalFlowEvent::WaitingForEngagement(method) => {
            println!(
                "[FLOW] Waiting for engagement ({})",
                format_engagement_method(method)
            )
        }
        DataRetrievalFlowEvent::EngagementConnected(method) => {
            println!(
                "[FLOW] Engagement connected ({})",
                format_engagement_method(method)
            )
        }
        DataRetrievalFlowEvent::TransportConnected(transport) => {
            println!(
                "[FLOW] Transport connected ({})",
                format_transport_kind(transport)
            )
        }
        DataRetrievalFlowEvent::WaitingForUserApproval => {
            println!("[FLOW] Waiting for user approval on mdoc device")
        }
        DataRetrievalFlowEvent::DeviceResponseReceived => {
            println!("[FLOW] DeviceResponse received")
        }
    }
}

fn format_engagement_method(method: EngagementMethod) -> &'static str {
    match method {
        EngagementMethod::Nfc => "nfc",
        EngagementMethod::QrCode => "qr_code",
    }
}

fn format_transport_kind(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Ble => "ble",
        TransportKind::Wifi => "wifi",
    }
}

fn render_portrait(portrait: &ElementValue) -> Result<()> {
    let bytes = portrait
        .decode::<ByteVec>()
        .context("portrait element value is not bytes")?;
    let image = decode_portrait(&bytes)?;
    print_portrait(&image)
}

fn decode_portrait(bytes: &[u8]) -> Result<DynamicImage> {
    match decode_jpeg2000(bytes) {
        Ok(image) => Ok(image),
        Err(jpeg2000_err) => {
            info!("[WARN] Failed to decode portrait as JPEG2000, trying JPEG...");
            decode_jpeg(bytes).with_context(|| {
                format!(
                    "failed to decode portrait as JPEG (after JPEG2000 failed: {jpeg2000_err:#})"
                )
            })
        }
    }
}

fn decode_jpeg2000(bytes: &[u8]) -> Result<DynamicImage> {
    let decoder = Jpeg2000Image::new(bytes, &DecodeSettings::default())
        .context("failed to parse portrait as JPEG2000")?;

    DynamicImage::from_decoder(decoder).context("failed to decode JPEG2000 portrait")
}

fn decode_jpeg(bytes: &[u8]) -> Result<DynamicImage> {
    image::load_from_memory_with_format(bytes, ImageFormat::Jpeg)
        .context("failed to decode JPEG portrait")
}

fn print_portrait(image: &DynamicImage) -> Result<()> {
    let config = viuer::Config {
        transparent: true,
        width: Some(PORTRAIT_WIDTH_CELLS),
        restore_cursor: false,
        absolute_offset: false,
        x: 0,
        y: 1,
        truecolor: true,
        use_kitty: false,
        use_iterm: false,
        use_sixel: true,
        ..Default::default()
    };

    viuer::print(image, &config).context("failed to print portrait in the terminal")?;
    println!();
    Ok(())
}

fn print_issuer_signed_data(response: &DeviceResponse) -> Result<()> {
    let Some(documents) = &response.documents else {
        info!("No documents in DeviceResponse");
        return Ok(());
    };

    for doc in documents.iter() {
        let Some(name_spaces) = &doc.issuer_signed.name_spaces else {
            info!("issuerSigned.nameSpaces is absent");
            continue;
        };

        for (ns, items) in name_spaces {
            println!("nameSpace={ns}");
            for item in items {
                let item = item.decode()?;
                println!(
                    " {} = {}",
                    item.element_identifier,
                    format_element_value(&item.element_value)
                );

                if item.element_identifier == "portrait" {
                    render_portrait(&item.element_value)?;
                }
            }
        }
    }

    Ok(())
}

fn format_element_value(value: &ElementValue) -> String {
    if let Ok(v) = value.decode::<String>() {
        return format!("str({v})");
    }
    if let Ok(v) = value.decode::<FullDate>() {
        if let Ok(date) = NaiveDate::parse_from_str(v.value(), "%Y-%m-%d") {
            return format!("full-date({})", date.format("%Y-%m-%d"));
        }
    }
    if let Ok(v) = value.decode::<bool>() {
        return format!("bool({v})");
    }
    if let Ok(v) = value.decode::<u64>() {
        return format!("u64({v})");
    }
    if let Ok(v) = value.decode::<ByteVec>() {
        return format!("bytes(len={})", v.len());
    }

    format!("cbor({:02X?})", value.raw_cbor_bytes())
}
