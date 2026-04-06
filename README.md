# mdoc_reader

## Logging

This workspace now emits logs via the `log` facade.
Initialize the logger only at binary entry points (for example `crates/app/src/main.rs`) and control verbosity with `RUST_LOG`.

Examples:

```bash
RUST_LOG=info cargo run -p mdoc_reader -- --config request.example.json
```

```bash
RUST_LOG=debug cargo run -p mdoc_reader -- --config request.example.json
```

## Windows BLE packet reordering workaround

Some Windows BLE stacks can deliver `WriteRequested` events out of sequence for
`WriteWithoutResponse`. This behavior was reported in 2019 and is still not
fully fixed, which makes complete avoidance difficult in user space.

Reference:
- https://stackoverflow.com/questions/56712103/writewithoutresponse-writerequested-event-raised-out-of-sequence-on-windows-devi

To reduce the frequency of decode/decrypt failures caused by this issue, this
repository applies two complementary workarounds:

1. **Transport-side late-packet handling**  
   In `crates/mdoc-reader-transport-ble-winrt/src/lib.rs`, after receiving the
   final chunk (`CHUNK_LAST`), the transport waits up to 30 ms for an additional
   late chunk. If a late `CHUNK_MORE` arrives, it is inserted immediately before
   the final packet.

2. **Reader-flow reorder retry**  
   In `crates/mdoc-reader-flow-nfc-ble/src/packet_reorder_workaround.rs`, the
   reader retries packet order permutations up to inversion count 2 (single
   adjacent swap and inversion-2 permutations) before giving up.
