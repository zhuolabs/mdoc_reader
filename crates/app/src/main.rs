use anyhow::{anyhow, Context};
use clap::Parser;
use log::info;
use mdoc_core::{DeviceRequest, NameSpaces};
use mdoc_reader_flow_nfc_ble::read_mdoc;
use mdoc_reader_transport_ble_winrt::WinRtBleReaderTransportFactory;
use mdoc_ui_cli::{render_device_response, ConsoleReaderFlowObserver};
use nfc_reader_pcsc::PcscReader;
use serde_json::Value;
use std::{fs, path::Path};
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
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let config_json = load_config_json(&cli)?;

    let mut nfc = PcscReader::new();
    let observer = ConsoleReaderFlowObserver;

    let device_request = build_device_request_from_json(&config_json)?;
    info!("DeviceRequest={:?}", device_request);

    let transport_factory = WinRtBleReaderTransportFactory;
    info!("BLE transport factory selected");
    let response = read_mdoc(
        &mut nfc,
        &transport_factory,
        &device_request,
        cli.service_uuid,
        Some(&observer),
    )
    .await?;

    render_device_response(&response)
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
