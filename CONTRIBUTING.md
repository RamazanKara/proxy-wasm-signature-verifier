# Contributing

Thanks for improving proxy-wasm-signature-verifier.

## Local Checks

Run the Rust checks before opening a change:

```bash
cargo fmt --all --check
cargo test --all
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo build --release --target wasm32-unknown-unknown
```

To verify behavior against vmod-wasm:

```bash
VMOD_WASM_REPO=../vmod-wasm ./scripts/test-vmod-wasm.sh
```

## Security Changes

Changes to canonicalization, key selection, timestamp validation, header
stripping, or failure mode should include both unit tests and a VTC integration
case.

