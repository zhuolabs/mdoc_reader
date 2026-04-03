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
