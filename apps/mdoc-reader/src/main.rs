use anyhow::{Context, anyhow};
use clap::Parser;
use log::info;
use mdoc_core::{CoseKeyPrivate, DeviceRequest, NameSpaces};
use mdoc_data_retrieval_flow::{DataRetrievalFlowEvent, DataRetrievalFlowObserver};
use mdoc_reader_flow::read_mdoc;
use mdoc_transport_ble_winrt::WinRtBleMdocTransportFactory;
use mdoc_ui::{FlowEventUi, MdocResultUi};
use mdoc_ui_cli::ConsoleMdocUi;
use nfc_reader_pcsc::PcscReader;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(about = "Read mdoc via NFC + BLE")]
struct Cli {
    #[arg(
        long,
        value_name = "PATH",
        help = "Read request JSON from file",
        required = true
    )]
    request: String,

    #[arg(long, value_name = "UUID", help = "BLE service UUID")]
    service_uuid: Option<Uuid>,

    #[arg(
        long,
        help = "Skip CRL download and revocation check during certificate validation"
    )]
    skip_crl_check: bool,

    #[arg(long, help = "Skip MSO revocation check")]
    ignore_mso_revocation_check: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let request_config = load_request_config(&cli)?;

    let mut nfc = PcscReader::new();
    let observer_ui = ConsoleMdocUi;
    let observer = UiFlowObserver { ui: &observer_ui };

    let device_request = build_device_request_from_json(&request_config.json)?;
    info!("DeviceRequest={:?}", device_request);
    let iaca_cert = load_iaca_cert_from_request(&request_config).await?;

    let transport_factory = WinRtBleMdocTransportFactory;
    info!("BLE transport factory selected");
    let e_reader_key_private = CoseKeyPrivate::new()?;
    let response = read_mdoc(
        &mut nfc,
        &transport_factory,
        &e_reader_key_private,
        &device_request,
        cli.skip_crl_check,
        cli.ignore_mso_revocation_check,
        Some(&observer),
        iaca_cert.as_ref(),
        cli.service_uuid,
    )
    .await?;
    let mut result_ui = ConsoleMdocUi;
    result_ui.render_result(&response, &()).map_err(Into::into)
}

struct UiFlowObserver<'a, U> {
    ui: &'a U,
}

impl<U> DataRetrievalFlowObserver for UiFlowObserver<'_, U>
where
    U: FlowEventUi,
{
    fn on_event(&self, event: DataRetrievalFlowEvent) {
        if self.ui.on_flow_event(event).is_err() {
            info!("failed to render flow event");
        }
    }
}

struct RequestConfig {
    json: Value,
    base_dir: PathBuf,
}

fn load_request_config(cli: &Cli) -> anyhow::Result<RequestConfig> {
    load_request_file(&cli.request)
}

fn load_request_file(path: impl AsRef<Path>) -> anyhow::Result<RequestConfig> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read request: {}", path.display()))?;
    let json = parse_json(&raw, &path.display().to_string())?;
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize request path: {}", path.display()))?;
    let base_dir = canonical_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            anyhow!(
                "failed to resolve request base directory: {}",
                canonical_path.display()
            )
        })?;

    Ok(RequestConfig { json, base_dir })
}

async fn load_certificate_from_file_or_url(
    source: &str,
    base_dir: &Path,
) -> anyhow::Result<x509_cert::Certificate> {
    if let Some(url) = parse_remote_certificate_url(source)? {
        return mdoc_security::download_x509_certificate(&url)
            .await
            .map_err(Into::into);
    }

    let cert_path = resolve_request_relative_path(source, base_dir)?;
    mdoc_security::load_x509_certificate_from_file(&cert_path).map_err(Into::into)
}

async fn load_iaca_cert_from_request(
    request_config: &RequestConfig,
) -> anyhow::Result<Option<x509_cert::Certificate>> {
    let source = match request_config.json.get("iacaCert") {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| anyhow!("iacaCert must be a string"))?,
        ),
        None => None,
    };

    match source {
        Some(source) => load_certificate_from_file_or_url(source, &request_config.base_dir)
            .await
            .map(Some),
        None => Ok(None),
    }
}

fn resolve_request_relative_path(source: &str, base_dir: &Path) -> anyhow::Result<PathBuf> {
    let path = Path::new(source);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(base_dir.join(path))
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
    serde_json::from_str(raw).with_context(|| format!("failed to parse JSON request: {}", source))
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
