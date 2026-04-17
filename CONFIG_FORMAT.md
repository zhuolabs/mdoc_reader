# Config format (simple JSON -> DeviceRequest)

`mdoc-reader-cli` builds `DeviceRequest` from a JSON file passed via `--request PATH`, using `DeviceRequest` / `ItemRequest` naming.

## JSON shape

- `version: String` (optional, default is builder default)
- `iacaCert: String` (optional)
- `docRequests: [ ... ]` (required)
  - `itemsRequest` (required)
    - `docType: String` (required)
    - `nameSpaces: BTreeMap<String, BTreeMap<String, bool>>` (required)

`iacaCert` accepts either:
- an HTTPS URL
- an absolute filesystem path
- a relative filesystem path, resolved from the request JSON file location

Example:

```json
{
  "iacaCert": "certs/iaca.pem",
  "docRequests": [
    {
      "itemsRequest": {
        "docType": "org.iso.18013.5.1.mDL",
        "nameSpaces": {
          "org.iso.18013.5.1": {
            "age_over_18": false,
            "portrait": false
          }
        }
      }
    }
  ]
}
```

## Building `DeviceRequest` directly in Rust

If you do not want to go through JSON, build `mdoc_core::DeviceRequest` directly with the builder API.
This is the recommended style because `DocRequest` stores `itemsRequest` as `TaggedCborBytes<ItemRequest>`.

```rust
use mdoc_core::{DeviceRequest, NameSpaces};
use std::collections::BTreeMap;

let name_spaces: NameSpaces = BTreeMap::from([
    (
        "org.iso.18013.5.1".to_string(),
        BTreeMap::from([
            ("age_over_18".to_string(), false),
            ("sex".to_string(), false),
            ("given_name".to_string(), false),
            ("issue_date".to_string(), false),
            ("expiry_date".to_string(), false),
            ("family_name".to_string(), false),
            ("document_number".to_string(), false),
            ("issuing_authority".to_string(), false),
            ("portrait".to_string(), false),
            ("resident_address".to_string(), true),
            ("resident_city".to_string(), true),
            ("resident_state".to_string(), true),
            ("resident_postal_code".to_string(), true),
            ("resident_country".to_string(), true),
        ]),
    ),
    (
        "org.iso.18013.5.1.aamva".to_string(),
        BTreeMap::from([
            ("resident_county".to_string(), true),
            ("DHS_compliance".to_string(), false),
            ("EDL_credential".to_string(), false),
        ]),
    ),
]);

let device_request = DeviceRequest::builder()
    .add_doc_request("org.iso.18013.5.1.mDL", name_spaces, None)
    .build();
```

- `version` is optional; the builder default is `1.0`.
- `doc_request_info` and `device_request_info` only need to be set when you have extra request metadata.
- A full struct literal is possible, but it requires constructing `TaggedCborBytes<ItemRequest>` manually.

`nameSpaces` is parsed by `serde_json::from_value` into `NameSpaces`, so app module (`apps/mdoc-reader`) is the only place that depends on `serde_json`.
