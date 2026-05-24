# Security Policy

Please report vulnerabilities privately by opening a GitHub security advisory or
emailing the repository maintainer.

This module verifies request signatures inside the Proxy-Wasm sandbox. Treat it
as one control in an edge security design:

- Keep signing secrets out of source control.
- Prefer short timestamp windows in production.
- Rotate keys with `X-Signature-Key-Id`.
- Run in `enforce` mode for protected routes and reserve `report` mode for
  migrations or audits.

