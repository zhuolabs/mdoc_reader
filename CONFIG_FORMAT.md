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

`nameSpaces` is parsed by `serde_json::from_value` into `NameSpaces`, so app module (`crates/mdoc-reader-cli`) is the only place that depends on `serde_json`.
