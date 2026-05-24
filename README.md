# proxy-wasm-signature-verifier

Proxy-Wasm HMAC-SHA256 request signature verifier for
[vmod-wasm](https://github.com/RamazanKara/vmod-wasm) and other Proxy-Wasm
hosts.

The module verifies signed edge requests without network callouts. It is meant
for webhooks, partner APIs, signed internal service traffic, and private cache
tiers where Varnish should reject tampered requests before backend fetch.

## Signature Scheme

Clients sign this canonical string with HMAC-SHA256:

```text
v1
<HTTP method uppercase>
<path and query>
<timestamp>
<sha256 hex of request body>
<signed-header-name>:<normalized signed-header-value>
...
```

Defaults:

| Setting | Default |
|---------|---------|
| Signature header | `X-Signature` |
| Timestamp header | `X-Signature-Timestamp` |
| Key id header | `X-Signature-Key-Id` |
| Signed headers | `host` |
| Timestamp skew | `300` seconds |
| Mode | `enforce` |

The signature header accepts raw hex, `v1=<hex>`, `sha256=<hex>`, or
`hmac-sha256=<hex>`.

## Example

Plugin configuration:

```json
{
  "keys": [
    {"id": "test-key", "secret": "topsecret"}
  ],
  "signed_headers": ["host"],
  "max_skew_seconds": 300,
  "mode": "enforce"
}
```

Canonical string for `GET /signed?item=1` with `Host: example.test`,
timestamp `1700000000`, and an empty body:

```text
v1
GET
/signed?item=1
1700000000
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
host:example.test
```

Signature with secret `topsecret`:

```text
e2cedc28442baab59a9be8b5b4436d63e390e197daee39300baddd3c64a9f936
```

## Varnish / vmod-wasm

```vcl
import wasm;

sub vcl_init {
    wasm.load("sig", "/etc/varnish/wasm/proxy_wasm_signature_verifier.wasm");
    wasm.set_epoch_deadline(100);
    wasm.set_memory_limit(8388608);
}

sub vcl_recv {
    set req.http.X-Wasm-Action =
        wasm.proxy_wasm_on_request_configured("sig", "",
            {"{"keys":[{"id":"primary","secret":"topsecret" }],"signed_headers":["host"],"max_skew_seconds":300,"mode":"enforce" }"});

    if (req.http.X-Wasm-Action != "0") {
        return (synth(401, "Bad signature"));
    }
}
```

On success, the module adds:

- `X-Signature-Status: verified`
- `X-Signature-Verified: true`
- `X-Verified-Signature-Key: <key id>`

By default it strips `X-Signature`, `X-Signature-Timestamp`, and
`X-Signature-Key-Id` before the request reaches the backend.

## Configuration

| Field | Type | Description |
|-------|------|-------------|
| `keys` | array | Signing keys with `id` and raw UTF-8 `secret`. |
| `signature_header` | string | Header containing the HMAC digest. |
| `timestamp_header` | string | Header containing Unix epoch seconds. |
| `key_id_header` | string | Header selecting a key. |
| `signed_headers` | array | Headers included in the canonical string, in order. |
| `max_skew_seconds` | integer | Maximum clock skew. `0` disables age checks for tests. |
| `mode` | string | `enforce` blocks failures; `report` annotates and allows. |
| `require_key_id` | boolean | Require `key_id_header` even when one key is configured. |
| `emit_headers` | boolean | Emit verification status headers. |
| `strip_signature_headers` | boolean | Remove client signature headers before backend fetch. |

No configured keys is treated as fail-closed.

## Build

```bash
cargo build --release --target wasm32-unknown-unknown
```

The Wasm artifact is:

```text
target/wasm32-unknown-unknown/release/proxy_wasm_signature_verifier.wasm
```

## Test

Rust checks:

```bash
cargo fmt --all --check
cargo test --all
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
```

Integration test against a sibling `vmod-wasm` checkout:

```bash
VMOD_WASM_REPO=../vmod-wasm ./scripts/test-vmod-wasm.sh
```
