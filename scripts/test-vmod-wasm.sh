#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VMOD_WASM_REPO="${VMOD_WASM_REPO:-$(cd "${ROOT_DIR}/../vmod-wasm" && pwd)}"
VMOD_WASM_IMAGE="${VMOD_WASM_IMAGE:-vmod-wasm-ci}"

docker build -t "${VMOD_WASM_IMAGE}" "${VMOD_WASM_REPO}"

docker run --rm \
  -v "${ROOT_DIR}:/module" \
  -w /module \
  "${VMOD_WASM_IMAGE}" \
  sh -ceu '
    cargo fmt --all --check
    cargo test --all
    cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
    cargo build --release --target wasm32-unknown-unknown
    varnishtest -t 120 \
      -Dvmod_wasm=/src/src/.libs/libvmod_wasm.so \
      -Dsignature_filter=/module/target/wasm32-unknown-unknown/release/proxy_wasm_signature_verifier.wasm \
      /module/tests/vmod_wasm_signature_verifier.vtc
  '

