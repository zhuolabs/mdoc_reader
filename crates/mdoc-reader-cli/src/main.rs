use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use clap::Parser;
use log::info;
use mdoc_core::{
    CoseKeyPrivate, CoseVerify, DeviceRequest, DeviceResponse, NameSpaces, SessionTranscript,
    TaggedCborBytes,
};
use mdoc_data_retrieval_flow::DataRetrievalFlow;
use mdoc_data_retrieval_flow_nfc_ble::NfcBleDataRetrievalFlow;
use mdoc_security::{IssuerDataAuthContext, MdocDeviceAuthContext, VerifiedMso};
use mdoc_transport_ble_winrt::WinRtBleMdocTransportFactory;
use mdoc_ui_cli::{render_device_response, ConsoleDataRetrievalFlowObserver};
use nfc_reader_pcsc::PcscReader;
use serde_json::Value;
use std::{fs, path::Path, time::SystemTime};
use uuid::Uuid;
use x509_cert::der::Encode as _;

const DEFAULT_REQUEST_JSON: &str = include_str!("../../../request.example.json");
const DEFAULT_REQUEST_HELP: &str = concat!(
    "Default request JSON embedded in this binary:\n\n",
    include_str!("../../../request.example.json")
);

#[derive(Debug, Parser)]
#[command(about = "Read mdoc via NFC + BLE", after_help = DEFAULT_REQUEST_HELP)]
struct Cli {
    #[arg(long, value_name = "PATH", help = "Read request JSON from file")]
    config: Option<String>,

    #[arg(long, value_name = "UUID", help = "BLE service UUID")]
    service_uuid: Option<Uuid>,

    #[arg(
        long,
        alias = "iaca-cert-der",
        value_name = "PATH",
        help = "Path to IACA certificate in PEM or DER used for certificate validation"
    )]
    iaca_cert: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct DeviceResponseValidation {
    documents: Vec<DocumentValidation>,
}

#[derive(Debug, Clone)]
struct DocumentValidation {
    doc_type: String,
    cose_sign1: Result<(), String>,
    issuer_data_auth: Result<VerifiedMso, String>,
    mdoc_device_auth: Result<(), String>,
    certificate_validation: Option<Result<(), String>>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let config_json = load_config_json(&cli)?;

    let mut nfc = PcscReader::new();
    let observer = ConsoleDataRetrievalFlowObserver;

    let device_request = build_device_request_from_json(&config_json)?;
    info!("DeviceRequest={:?}", device_request);
    let iaca_cert_der = cli
        .iaca_cert
        .as_ref()
        .map(load_certificate_file)
        .transpose()?;

    let transport_factory = WinRtBleMdocTransportFactory;
    info!("BLE transport factory selected");
    let mut flow = NfcBleDataRetrievalFlow::new(&mut nfc, &transport_factory, cli.service_uuid);
    let e_reader_key_private = CoseKeyPrivate::new()?;
    let result = flow
        .retrieve_data(&device_request, &e_reader_key_private, Some(&observer))
        .await?;

    let validation = validate_device_response(
        &result.device_response,
        &e_reader_key_private,
        &result.session_transcript,
        iaca_cert_der.as_deref(),
    )
    .await;
    print_validation_summary(&validation);
    render_device_response(&result.device_response)
}

fn load_config_json(cli: &Cli) -> anyhow::Result<Value> {
    match &cli.config {
        Some(path) => load_json_file(path),
        None => parse_json(DEFAULT_REQUEST_JSON, "embedded default JSON"),
    }
}

fn load_json_file(path: impl AsRef<Path>) -> anyhow::Result<Value> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    parse_json(&raw, &path.display().to_string())
}

fn load_certificate_file(path: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
    let path = path.as_ref();
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read certificate file: {}", path.display()))?;

    if bytes.starts_with(b"-----BEGIN ") {
        decode_pem_certificate(&bytes)
            .with_context(|| format!("failed to parse PEM certificate: {}", path.display()))
    } else {
        Ok(bytes)
    }
}

fn decode_pem_certificate(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pem = std::str::from_utf8(bytes).context("PEM file is not valid UTF-8 text")?;
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let begin = pem
        .find(begin_marker)
        .ok_or_else(|| anyhow!("PEM certificate header not found"))?;
    let rest = &pem[begin + begin_marker.len()..];
    let end = rest
        .find(end_marker)
        .ok_or_else(|| anyhow!("PEM certificate footer not found"))?;
    let base64_body: String = rest[..end].lines().map(str::trim).collect();

    STANDARD
        .decode(base64_body)
        .context("PEM certificate body is not valid base64")
}

fn parse_json(raw: &str, source: &str) -> anyhow::Result<Value> {
    serde_json::from_str(raw).with_context(|| format!("failed to parse JSON config: {}", source))
}

fn build_device_request_from_json(json: &Value) -> anyhow::Result<DeviceRequest> {
    let mut builder = DeviceRequest::builder();

    if let Some(version) = json.get("version").and_then(Value::as_str) {
        builder = builder.version(version.to_string());
    }

    let doc_requests = json
        .get("docRequests")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("docRequests must be an array"))?;

    for (idx, doc_request) in doc_requests.iter().enumerate() {
        let items_request = doc_request
            .get("itemsRequest")
            .ok_or_else(|| anyhow!("docRequests[{}].itemsRequest is required", idx))?;
        let doc_type = items_request
            .get("docType")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("docRequests[{}].itemsRequest.docType must be a string", idx))?;
        let namespaces = build_namespaces_from_json(items_request, idx)?;

        builder = builder.add_doc_request(doc_type.to_string(), namespaces, None);
    }

    Ok(builder.build())
}

fn build_namespaces_from_json(items_request: &Value, idx: usize) -> anyhow::Result<NameSpaces> {
    let namespaces_value = items_request
        .get("nameSpaces")
        .ok_or_else(|| anyhow!("docRequests[{}].itemsRequest.nameSpaces is required", idx))?
        .clone();
    serde_json::from_value(namespaces_value).with_context(|| {
        format!(
            "docRequests[{}].itemsRequest.nameSpaces must match NameSpaces shape",
            idx
        )
    })
}

async fn validate_device_response(
    response: &DeviceResponse,
    e_self_private_key: &CoseKeyPrivate,
    session_transcript: &TaggedCborBytes<SessionTranscript>,
    iaca_cert_der: Option<&[u8]>,
) -> DeviceResponseValidation {
    let mut documents = Vec::new();

    if let Some(response_documents) = response.documents.as_ref() {
        for doc in response_documents {
            let issuer_cert = doc
                .issuer_signed
                .issuer_auth
                .x5chain()
                .and_then(|chain| chain.first())
                .cloned()
                .ok_or_else(|| {
                    "issuerAuth did not contain a document signer certificate".to_string()
                });

            let certificate_validation = match iaca_cert_der {
                Some(der) => Some(
                    validate_certificate_chain_with_iaca(&doc.issuer_signed.issuer_auth, der).await,
                ),
                None => None,
            };

            let cose_sign1 = issuer_cert.as_ref().map_or_else(
                |err| Err(err.clone()),
                |cert| {
                    doc.issuer_signed
                        .issuer_auth
                        .verify(cert, b"")
                        .map_err(|err| err.to_string())
                },
            );

            let issuer_data_auth = mdoc_security::verify_issuer_data_auth(
                doc,
                &IssuerDataAuthContext {
                    now: Utc::now(),
                    expected_doc_type: Some(doc.doc_type.clone()),
                },
            );
            let mdoc_device_auth = match &issuer_data_auth {
                Ok(verified_mso) => match (
                    doc.device_signed.device_auth.device_signature.as_ref(),
                    doc.device_signed.device_auth.device_mac.as_ref(),
                ) {
                    (Some(_), None) => mdoc_security::verify_mdoc_device_auth(
                        doc,
                        &MdocDeviceAuthContext {
                            session_transcript: session_transcript.clone(),
                            verified_mso: verified_mso.clone(),
                        },
                    )
                    .map_err(|err| err.to_string()),
                    (None, Some(_)) => mdoc_security::verify_mdoc_mac_auth(
                        doc,
                        e_self_private_key,
                        &MdocDeviceAuthContext {
                            session_transcript: session_transcript.clone(),
                            verified_mso: verified_mso.clone(),
                        },
                    )
                    .map_err(|err| err.to_string()),
                    _ => mdoc_security::verify_mdoc_device_auth(
                        doc,
                        &MdocDeviceAuthContext {
                            session_transcript: session_transcript.clone(),
                            verified_mso: verified_mso.clone(),
                        },
                    )
                    .map_err(|err| err.to_string()),
                },
                Err(err) => Err(err.to_string()),
            };
            let issuer_data_auth = issuer_data_auth.map_err(|err| err.to_string());

            documents.push(DocumentValidation {
                doc_type: doc.doc_type.clone(),
                cose_sign1,
                issuer_data_auth,
                mdoc_device_auth,
                certificate_validation,
            });
        }
    }

    DeviceResponseValidation { documents }
}

async fn validate_certificate_chain_with_iaca(
    issuer_auth: &mdoc_core::CoseSign1<TaggedCborBytes<mdoc_core::MobileSecurityObject>>,
    iaca_cert_der: &[u8],
) -> Result<(), String> {
    let x5chain = issuer_auth
        .x5chain()
        .ok_or_else(|| "issuerAuth x5chain is missing".to_string())?;
    let chain_der = x5chain
        .iter()
        .map(|cert| {
            cert.to_der()
                .map_err(|err| format!("failed to encode x5chain certificate to DER: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let crl_der = match mdoc_security::extract_crl_distribution_point(iaca_cert_der) {
        Ok(Some(crl_url)) => {
            info!("certificate_validation: CRL distribution point found url={crl_url}");
            Some(
                mdoc_security::download_crl_der(&crl_url)
                    .await
                    .map_err(|err| err.to_string())?,
            )
        }
        Ok(None) => {
            info!("certificate_validation: no CRL distribution point found in IACA certificate");
            None
        }
        Err(err) => return Err(err.to_string()),
    };

    mdoc_security::validate_reader_auth_certificate(
        iaca_cert_der,
        &chain_der,
        crl_der.as_deref(),
        SystemTime::now(),
    )
    .map(|_| ())
    .map_err(|err| err.to_string())
}

fn print_validation_summary(validation: &DeviceResponseValidation) {
    if validation.documents.is_empty() {
        println!("[INFO] Validation skipped: no documents");
        return;
    }

    for (idx, doc) in validation.documents.iter().enumerate() {
        match &doc.cose_sign1 {
            Ok(()) => println!(
                "[OK] Document[{idx}] COSE_Sign1 verified docType={}",
                doc.doc_type
            ),
            Err(err) => println!(
                "[ERR] Document[{idx}] COSE_Sign1 verification failed docType={} error={err}",
                doc.doc_type
            ),
        }

        match &doc.issuer_data_auth {
            Ok(verified) => println!(
                "[OK] Document[{idx}] issuer_data_auth verified docType={} mso.docType={}",
                doc.doc_type, verified.mso.doc_type
            ),
            Err(err) => println!(
                "[ERR] Document[{idx}] issuer_data_auth verification failed docType={} error={err}",
                doc.doc_type
            ),
        }

        match &doc.mdoc_device_auth {
            Ok(()) => println!(
                "[OK] Document[{idx}] mdoc_device_auth verified docType={}",
                doc.doc_type
            ),
            Err(err) => println!(
                "[ERR] Document[{idx}] mdoc_device_auth verification failed docType={} error={err}",
                doc.doc_type
            ),
        }

        if let Some(result) = &doc.certificate_validation {
            match result {
                Ok(()) => println!(
                    "[OK] Document[{idx}] certificate_validation passed docType={}",
                    doc.doc_type
                ),
                Err(err) => println!(
                    "[ERR] Document[{idx}] certificate_validation failed docType={} error={err}",
                    doc.doc_type
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_pem_certificate;

    #[test]
    fn decode_pem_certificate_extracts_der_body() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n";
        let der = decode_pem_certificate(pem).expect("PEM should decode");
        assert_eq!(der, vec![0x01, 0x02, 0x03, 0x04]);
    }
}
