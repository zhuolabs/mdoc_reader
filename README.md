# mdoc-reader

`mdoc-reader` is an experimental tool for reading and verifying mobile documents (mdoc), such as mobile driver's licenses (mDL), on Windows. It uses NFC and Bluetooth Low Energy (BLE) for device engagement and data retrieval, requests selected identity attributes, and verifies the received data based on ISO/IEC 18013-5.

This implementation was built with reference to the ISO/IEC 18013-5 second-edition working draft:

- ISO working draft: https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v4.pdf

It is intended for evaluation and experimentation.
If you are considering production use or need customization, please feel free to contact me.
zhuo@zhuolabs.com

## Target Environment

- Windows 11
- A PC with Bluetooth Low Energy (BLE) support
- A PC/SC-compatible contactless card reader

Prebuilt `mdoc-reader.exe` binaries are available from the GitHub Releases page:

- https://github.com/zhuolabs/mdoc_reader/releases

## Usage

### Device Request

In the ISO/IEC 18013-5 data retrieval flow, the reader sends a `DeviceRequest`.
Before using this tool, you need to know the request definition for the target mdoc.

For each mdoc type, you need at least:

- the `docType`
- the available namespace names
- the data element identifiers in each namespace

You should obtain this information from the issuer or from documentation provided for the mdoc you want to read.
For some document types, Apple also publishes related identifier information here:

- https://developer.apple.com/documentation/passkit/pkidentitydriverslicensedescriptor/
- https://developer.apple.com/documentation/passkit/pkidentitynationalidcarddescriptor/

After that, create a `request.json` file and pass it with `--request`.

### IACA Certificate

The IACA certificate is the root-of-trust certificate used to validate that an mdoc was issued by the expected issuer.
This certificate is also typically provided by the issuer.

For mdocs that can be provisioned into Apple Wallet, Apple provides information here:

- https://developer.apple.com/wallet/get-started-with-verify-with-wallet/

In this implementation, `iacaCert` is optional.
However, in normal usage it is required if you want to verify that the mdoc was actually issued by the issuer.
`iacaCert` can be specified either as an HTTPS URL or as a local file path. Relative paths are resolved relative to the location of `request.json`.

### Request JSON

See [request.example.json](./request.example.json) for a complete example.

```json
{
  "iacaCert": "https://trust.dmv.ca.gov/certificates/ca-dmv-iaca-root-ca-crt.cer",
  "docRequests": [
    {
      "itemsRequest": {
        "docType": "org.iso.18013.5.1.mDL",
        "nameSpaces": {
          "org.iso.18013.5.1": {
            "age_over_18": false,
            "given_name": false,
            "family_name": false,
            "portrait": false,
            "resident_address": false
          },
          "org.iso.18013.5.1.aamva": {
            "resident_county": false
          }
        }
      }
    }
  ]
}
```

This example requests multiple elements from two namespaces for `org.iso.18013.5.1.mDL`.
It also specifies an `iacaCert` URL for issuer validation.
The boolean value is `intentToRetain`: `false` means no intent to retain, and `true` means intent to retain.

Run examples (PowerShell):

```powershell
.\mdoc-reader --request .\request.example.json
```

```powershell
$env:RUST_LOG="debug"; .\mdoc-reader --request .\request.example.json
```

Optional verification flags:

- `--skip-crl-check`: skips CRL download and CRL-based certificate revocation checks.
- `--ignore-mso-revocation-check`: skips MSO revocation checks.

## Implemented Features

The current implementation includes the following items aligned with the ISO/IEC 18013-5 second-edition working draft:

- Draft reference: https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v4.pdf
- `9.2`, `13.2`: NFC negotiated handover
- `11.1`, `13.2`: BLE GATT-based data retrieval
- `11.1`, `13.2`: mdoc central client mode
  - The reader operates as the BLE GATT server/peripheral and the mdoc device acts as the BLE GATT client/central.
- `12.3`, `12.8`: issuer data authentication
- `12.4`, `12.8`: mdoc authentication
- `12.8`, `13.3`: certificate validation
- `12.8`, `13.3`: CRL checking
- `12.3`: MSO revocation using `identifier_list`

## Windows BLE Note

### GATT Server Packet Reordering Issue

This implementation uses the WinRT BLE GATT Server API, which is the practical way to run a BLE GATT server on a Windows PC.

In mdoc reader mode, the mdoc device sends fragmented data to the reader as `WriteWithoutResponse` packets.
On Windows, these packets can be delivered to the GATT server out of order via `WriteRequested` events.

This appears to be a problem in the WinRT BLE implementation itself.
It was reported on Stack Overflow around 2019 and does not appear to have been fixed.

Reference:

- https://stackoverflow.com/questions/56712103/writewithoutresponse-writerequested-event-raised-out-of-sequence-on-windows-devi

To work around this issue, this implementation applies two complementary measures:

1. **Transport-side late-packet handling**  
   In `crates/mdoc-transport-ble-winrt/src/lib.rs`, after receiving the
   final chunk (`CHUNK_LAST`), the transport waits up to 30 ms for an additional
   late chunk. If a late `CHUNK_MORE` arrives, it is inserted immediately before
   the final packet.

2. **Reader-flow reorder retry**  
   In `crates/mdoc-reader-flow-nfc-ble/src/packet_reorder_workaround.rs`, the
   reader retries packet order permutations up to inversion count 2 (single
   adjacent swap and inversion-2 permutations) before giving up.

### Service UUID Restrictions on Managed PCs

On some enterprise-managed Windows PCs, Bluetooth service usage is restricted by policy.
This is often done to limit scenarios such as Bluetooth file transfer.

Reference:

- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-bluetooth

In particular, the `ServicesAllowedList` policy can restrict which Bluetooth service UUIDs are allowed.
In this implementation, the default service UUID is generated randomly with `Uuid::new_v4()`.
On PCs where `ServicesAllowedList` is configured, that default UUID can cause a permission error when the GATT server is created.

To work around this, use the `--service-uuid` option and specify an allowed UUID:

```powershell
.\mdoc-reader --request .\request.example.json --service-uuid 00001200-0000-1000-8000-00805F9B34FB
```

You can check the allowed UUIDs in the following registry key:

```text
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth\ServicesAllowedList
```
