use anyhow::{Context, Result};
use hayro_jpeg2000::{DecodeSettings, Image as Jpeg2000Image};
use image::{DynamicImage, ImageFormat};
use mdoc_core::{DeviceResponse, ElementValue, X509Certificate};
use mdoc_reader_flow::{EngagementMethod, ReaderFlowEvent, TransportKind};
use mdoc_ui::{FlowEventUi, MdocResultUi};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{CrlDistributionPoints, IssuerAltName};

const PORTRAIT_WIDTH_CELLS: u32 = 30;

#[derive(Default)]
pub struct ConsoleReaderFlowObserver;

impl mdoc_reader_flow::ReaderFlowObserver for ConsoleReaderFlowObserver {
    fn on_event(&self, event: ReaderFlowEvent) {
        let ui = ConsoleMdocUi;
        let _ = ui.on_flow_event(event);
    }
}

#[derive(Default)]
pub struct ConsoleMdocUi;

impl MdocResultUi<()> for ConsoleMdocUi {
    type Error = anyhow::Error;

    fn render_result(&mut self, response: &DeviceResponse, _validation: &()) -> Result<()> {
        render_response_summary(response);
        print_issuer_signed_data(response)?;
        Ok(())
    }
}

impl FlowEventUi for ConsoleMdocUi {
    type Error = anyhow::Error;

    fn on_flow_event(&self, event: ReaderFlowEvent) -> Result<()> {
        print_flow_event(event);
        Ok(())
    }
}

pub fn print_flow_event(event: ReaderFlowEvent) {
    match event {
        ReaderFlowEvent::WaitingForEngagement(method) => {
            println!(
                "[FLOW] Waiting for engagement ({})",
                format_engagement_method(method)
            )
        }
        ReaderFlowEvent::EngagementConnected(method) => {
            println!(
                "[FLOW] Engagement connected ({})",
                format_engagement_method(method)
            )
        }
        ReaderFlowEvent::TransportConnected(transport) => {
            println!(
                "[FLOW] Transport connected ({})",
                format_transport_kind(transport)
            )
        }
        ReaderFlowEvent::WaitingForUserApproval => {
            println!("[FLOW] Waiting for user approval on mdoc device")
        }
        ReaderFlowEvent::DeviceResponseReceived => println!("[FLOW] DeviceResponse received"),
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

pub fn render_device_response(response: &DeviceResponse) -> Result<()> {
    let mut ui = ConsoleMdocUi;
    ui.render_result(response, &())
}

fn render_response_summary(response: &DeviceResponse) {
    println!(
        "[OK] Parsed DeviceResponse status={} documents={}",
        response.status,
        response.documents.as_ref().map_or(0, Vec::len)
    );
}

pub fn render_portrait(portrait: &ElementValue) -> Result<()> {
    let ElementValue::Bytes(bytes) = portrait else {
        anyhow::bail!("portrait element value is not bytes");
    };
    let image = decode_portrait(&bytes)?;
    print_portrait(&image)
}

pub fn decode_portrait(bytes: &[u8]) -> Result<DynamicImage> {
    match decode_jpeg2000(bytes) {
        Ok(image) => Ok(image),
        Err(jpeg2000_err) => {
            println!("[WARN] Failed to decode portrait as JPEG2000, trying JPEG...");
            decode_jpeg(bytes).with_context(|| {
                format!(
                    "failed to decode portrait as JPEG (after JPEG2000 failed: {jpeg2000_err:#})"
                )
            })
        }
    }
}

pub fn decode_jpeg2000(bytes: &[u8]) -> Result<DynamicImage> {
    let decoder = Jpeg2000Image::new(bytes, &DecodeSettings::default())
        .context("failed to parse portrait as JPEG2000")?;

    DynamicImage::from_decoder(decoder).context("failed to decode JPEG2000 portrait")
}

pub fn decode_jpeg(bytes: &[u8]) -> Result<DynamicImage> {
    image::load_from_memory_with_format(bytes, ImageFormat::Jpeg)
        .context("failed to decode JPEG portrait")
}

pub fn print_portrait(image: &DynamicImage) -> Result<()> {
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
        println!("[INFO] No documents in DeviceResponse");
        return Ok(());
    };

    for (doc_idx, doc) in documents.iter().enumerate() {
        println!(
            "[INFO] Document[{doc_idx}] docType={}",
            doc.doc_type
        );
        if let Some(x5chain) = &doc.issuer_signed.issuer_auth.unprotected.x5chain {
            println!("[INFO]   issuerAuth.x5chain certs=1");
            print_x509_certificate_info(x5chain);
        }

        let Some(name_spaces) = &doc.issuer_signed.name_spaces else {
            println!("[INFO]   issuerSigned.nameSpaces is absent");
            continue;
        };

        for (ns, items) in name_spaces {
            println!("[INFO]   nameSpace={ns}");
            for item in items {
                println!(
                    "[INFO]     {} = {}",
                    item.0.element_identifier,
                    format_element_value(&item.0.element_value)
                );

                if item.0.element_identifier == "portrait" {
                    render_portrait(&item.0.element_value)?;
                }
            }
        }
    }

    Ok(())
}

fn format_element_value(value: &ElementValue) -> String {
    match value {
        ElementValue::String(v) => format!("str({v})"),
        ElementValue::FullDate(v) => format!("full-date({})", v.value()),
        ElementValue::Bool(v) => format!("bool({v})"),
        ElementValue::U64(v) => format!("u64({v})"),
        ElementValue::Bytes(v) => format!("bytes(len={})", v.len()),
        ElementValue::RawBytes(v) => format!("cbor({:02X?})", v),
    }
}

fn print_x509_certificate_info(cert: &X509Certificate) {
    let cert: &x509_cert::Certificate = cert.into();
    let tbs = &cert.tbs_certificate;

    println!("[INFO]     x509.version={:?}", tbs.version);
    println!(
        "[INFO]     x509.serial_number={}",
        tbs.serial_number
    );
    println!("[INFO]     x509.issuer={}", tbs.issuer);
    println!("[INFO]     x509.subject={}", tbs.subject);
    println!(
        "[INFO]     x509.validity.not_before={}",
        tbs.validity.not_before
    );
    println!(
        "[INFO]     x509.validity.not_after={}",
        tbs.validity.not_after
    );

    match tbs.get::<IssuerAltName>() {
        Ok(Some((critical, issuer_alt_name))) => {
            println!("[INFO]     x509.issuer_alt_name.critical={critical}");
            for (idx, name) in issuer_alt_name.0.iter().enumerate() {
                println!(
                    "[INFO]       x509.issuer_alt_name[{idx}]={}",
                    format_general_name(name)
                );
            }
        }
        Ok(None) => {
            println!("[INFO]     x509.issuer_alt_name=none");
        }
        Err(err) => {
            println!("[WARN]     x509.issuer_alt_name decode failed: {err}");
        }
    }

    match tbs.get::<CrlDistributionPoints>() {
        Ok(Some((critical, crl_dp))) => {
            println!("[INFO]     x509.crl_distribution_points.critical={critical}");
            for (idx, dp) in crl_dp.0.iter().enumerate() {
                match &dp.distribution_point {
                    Some(DistributionPointName::FullName(names)) => {
                        for (name_idx, name) in names.iter().enumerate() {
                            println!(
                                "[INFO]       x509.crl_distribution_points[{idx}].full_name[{name_idx}]={}",
                                format_general_name(name)
                            );
                        }
                    }
                    Some(DistributionPointName::NameRelativeToCRLIssuer(rdn)) => {
                        println!(
                            "[INFO]       x509.crl_distribution_points[{idx}].name_relative_to_crl_issuer={rdn:?}"
                        );
                    }
                    None => {
                        println!(
                            "[INFO]       x509.crl_distribution_points[{idx}].distribution_point=none"
                        );
                    }
                }

                if let Some(reasons) = &dp.reasons {
                    println!(
                        "[INFO]       x509.crl_distribution_points[{idx}].reasons={reasons:?}"
                    );
                }
                if let Some(crl_issuer) = &dp.crl_issuer {
                    for (issuer_idx, issuer_name) in crl_issuer.iter().enumerate() {
                        println!(
                            "[INFO]       x509.crl_distribution_points[{idx}].crl_issuer[{issuer_idx}]={}",
                            format_general_name(issuer_name)
                        );
                    }
                }
            }
        }
        Ok(None) => {
            println!("[INFO]     x509.crl_distribution_points=none");
        }
        Err(err) => {
            println!("[WARN]     x509.crl_distribution_points decode failed: {err}");
        }
    }
}

fn format_general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::OtherName(v) => {
            format!("otherName(type_id={}, value={:?})", v.type_id, v.value)
        }
        GeneralName::Rfc822Name(v) => format!("rfc822Name({v})"),
        GeneralName::DnsName(v) => format!("dNSName({v})"),
        GeneralName::DirectoryName(v) => format!("directoryName({v})"),
        GeneralName::EdiPartyName(v) => format!("ediPartyName({v:?})"),
        GeneralName::UniformResourceIdentifier(v) => format!("uniformResourceIdentifier({v})"),
        GeneralName::IpAddress(v) => format!("iPAddress({:02X?})", v.as_bytes()),
        GeneralName::RegisteredId(v) => format!("registeredID({v})"),
    }
}
