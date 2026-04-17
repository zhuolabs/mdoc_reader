use anyhow::{anyhow, Context};
use chrono::Utc;
use clap::Parser;
use log::info;
use mdoc_core::{
    CoseKeyPrivate, DeviceRequest, DeviceResponse, NameSpaces, SessionTranscript,
};
use mdoc_data_retrieval_flow::DataRetrievalFlow;
use mdoc_data_retrieval_flow_nfc_ble::NfcBleDataRetrievalFlow;
use mdoc_security::{IssuerDataAuthContext, VerifiedMso};
use mdoc_transport_ble_winrt::WinRtBleMdocTransportFactory;
use mdoc_ui_cli::{render_device_response, ConsoleDataRetrievalFlowObserver};
use nfc_reader_pcsc::PcscReader;
use serde_json::Value;
use std::{fs, path::Path, time::SystemTime};
use url::Url;
use uuid::Uuid;

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
        value_name = "PATH_OR_URL",
        help = "Path or HTTPS URL to root certificate in PEM or DER used for certificate validation"
    )]
    iaca_cert: Option<String>,

    #[arg(
        long,
        help = "Skip CRL download and revocation check during certificate validation"
    )]
    skip_crl: bool,
}

#[derive(Debug, Clone, Default)]
struct DeviceResponseValidation {
    documents: Vec<DocumentValidation>,
}

#[derive(Debug, Clone)]
struct DocumentValidation {
    doc_type: String,
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
    let iaca_cert = match cli.iaca_cert.as_ref() {
        Some(source) => Some(load_certificate_from_file_or_url(source).await?),
        None => None,
    };

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
        iaca_cert.as_ref(),
        cli.skip_crl,
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

async fn load_certificate_from_file_or_url(
    source: &str,
) -> anyhow::Result<x509_cert::Certificate> {
    if let Some(url) = parse_remote_certificate_url(source)? {
        return mdoc_security::download_x509_certificate(&url)
            .await
            .map_err(Into::into);
    }

    mdoc_security::load_x509_certificate_from_file(source).map_err(Into::into)
}

fn parse_remote_certificate_url(source: &str) -> anyhow::Result<Option<Url>> {
    match Url::parse(source) {
        Ok(url) if url.scheme() == "https" => Ok(Some(url)),
        Ok(url) if source.contains("://") => Err(anyhow!(
            "unsupported certificate URL scheme: {}",
            url.scheme()
        )),
        Ok(_) | Err(url::ParseError::RelativeUrlWithoutBase) => Ok(None),
        Err(err) => Err(anyhow!("failed to parse certificate URL: {err}")),
    }
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
    session_transcript: &SessionTranscript,
    iaca_cert: Option<&x509_cert::Certificate>,
    skip_crl: bool,
) -> DeviceResponseValidation {
    let mut documents = Vec::new();

    if let Some(response_documents) = response.documents.as_ref() {
        for doc in response_documents {
            let certificate_validation = match iaca_cert {
                Some(cert) => Some(
                    mdoc_security::validate_document_x5chain(
                        &doc.issuer_signed.issuer_auth,
                        cert,
                        skip_crl,
                        SystemTime::now(),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string()),
                ),
                None => None,
            };

            let issuer_data_auth = mdoc_security::verify_issuer_data_auth(
                doc,
                &IssuerDataAuthContext {
                    now: Utc::now(),
                    expected_doc_type: Some(doc.doc_type.clone()),
                },
            )
            .map_err(|err| err.to_string());

            let mso = match &issuer_data_auth {
                Ok(verified) => &verified.mso,
                Err(err) => {
                    documents.push(DocumentValidation {
                        doc_type: doc.doc_type.clone(),
                        issuer_data_auth: Err(err.to_string()),
                        mdoc_device_auth: Err("skipped due to issuer_data_auth failure".to_string()),
                        certificate_validation: certificate_validation.clone(),
                    });
                    continue;
                }
            };

            let mdoc_device_auth = mdoc_security::verify_mdoc_device_auth(
                &doc.device_signed,
                &mso.device_key_info,
                e_self_private_key,
                session_transcript,
                &doc.doc_type,
            )
            .map_err(|err| format!("failed to decode session transcript: {err}"));

            documents.push(DocumentValidation {
                doc_type: doc.doc_type.clone(),
                issuer_data_auth,
                mdoc_device_auth,
                certificate_validation,
            });
        }
    }

    DeviceResponseValidation { documents }
}
fn print_validation_summary(validation: &DeviceResponseValidation) {
    if validation.documents.is_empty() {
        println!("[INFO] Validation skipped: no documents");
        return;
    }

    for (idx, doc) in validation.documents.iter().enumerate() {
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
