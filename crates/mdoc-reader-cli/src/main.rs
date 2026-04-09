use anyhow::{anyhow, Context};
use chrono::Utc;
use clap::Parser;
use log::info;
use mdoc_core::{
    DeviceRequest, DeviceResponse, IssuerDataAuthContext, MdocDeviceAuthContext, NameSpaces,
    SessionTranscript, TaggedCborBytes, VerifiedMso,
};
use mdoc_data_retrieval_flow::DataRetrievalFlow;
use mdoc_data_retrieval_flow_nfc_ble::NfcBleDataRetrievalFlow;
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
        value_name = "PATH",
        help = "Path to IACA certificate DER used for certificate validation"
    )]
    iaca_cert_der: Option<String>,
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
    let iaca_cert_der = cli.iaca_cert_der.as_ref().map(load_der_file).transpose()?;

    let transport_factory = WinRtBleMdocTransportFactory;
    info!("BLE transport factory selected");
    let mut flow = NfcBleDataRetrievalFlow::new(&mut nfc, &transport_factory, cli.service_uuid);
    let result = flow.retrieve_data(&device_request, Some(&observer)).await?;

    let validation = validate_device_response(
        &result.device_response,
        &result.session_transcript,
        iaca_cert_der.as_deref(),
    );
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

fn load_der_file(path: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
    let path = path.as_ref();
    fs::read(path).with_context(|| format!("failed to read DER file: {}", path.display()))
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

fn validate_device_response(
    response: &DeviceResponse,
    session_transcript: &TaggedCborBytes<SessionTranscript>,
    iaca_cert_der: Option<&[u8]>,
) -> DeviceResponseValidation {
    let documents = response
        .documents
        .as_ref()
        .map(|documents| {
            documents
                .iter()
                .map(|doc| {
                    let issuer_cert = doc
                        .issuer_signed
                        .issuer_auth
                        .resolved_document_signer_cert()
                        .map_err(|err| err.to_string())
                        .and_then(|cert| {
                            cert.cloned().ok_or_else(|| {
                                "issuerAuth did not contain a document signer certificate"
                                    .to_string()
                            })
                        });

                    let cose_sign1 = issuer_cert.as_ref().map_or_else(
                        |err| Err(err.clone()),
                        |cert| {
                            doc.issuer_signed
                                .issuer_auth
                                .verify_with_certificate(cert, b"")
                                .map_err(|err| err.to_string())
                        },
                    );

                    let issuer_data_auth = mdoc_core::verify_issuer_data_auth(
                        doc,
                        &IssuerDataAuthContext {
                            now: Utc::now(),
                            expected_doc_type: Some(doc.doc_type.clone()),
                        },
                    );
                    let mdoc_device_auth = match &issuer_data_auth {
                        Ok(verified_mso) => mdoc_core::verify_mdoc_device_auth(
                            doc,
                            &MdocDeviceAuthContext {
                                session_transcript: session_transcript.clone(),
                                verified_mso: verified_mso.clone(),
                            },
                        )
                        .map_err(|err| err.to_string()),
                        Err(err) => Err(err.to_string()),
                    };
                    let issuer_data_auth = issuer_data_auth.map_err(|err| err.to_string());
                    let certificate_validation = iaca_cert_der.map(|der| {
                        validate_certificate_chain_with_iaca(&doc.issuer_signed.issuer_auth, der)
                    });

                    DocumentValidation {
                        doc_type: doc.doc_type.clone(),
                        cose_sign1,
                        issuer_data_auth,
                        mdoc_device_auth,
                        certificate_validation,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    DeviceResponseValidation { documents }
}

fn validate_certificate_chain_with_iaca(
    issuer_auth: &mdoc_core::CoseSign1<TaggedCborBytes<mdoc_core::MobileSecurityObject>>,
    iaca_cert_der: &[u8],
) -> Result<(), String> {
    let x5chain = issuer_auth
        .unprotected
        .x5chain
        .as_ref()
        .ok_or_else(|| "issuerAuth x5chain is missing".to_string())?;
    let chain_der = x5chain
        .as_slice()
        .iter()
        .map(|cert| {
            cert.to_der()
                .map_err(|err| format!("failed to encode x5chain certificate to DER: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    mdoc_validation::validate_reader_auth_certificate(iaca_cert_der, &chain_der, SystemTime::now())
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
