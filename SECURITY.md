# Security

Report vulnerabilities privately through GitHub Security Advisories for this repository.

The DSH and CLI verifier is read-only with respect to source evidence. It reads only explicit workspace-relative regular files, rejects symlinks and path escape, bounds file size and parsed structure, performs no network requests or child processes, and writes only one content-addressed index beneath the explicit artifact directory with read-back verification. Evidence bodies are never copied into tool output or the generated index. Secret-shaped fields are forbidden in the manifest.

The MCP companion is proof-only. It has no filesystem, network, subprocess or write operation and accepts only an inline manifest plus structural receipts. Secret-, raw-value-, content-, prompt-, message-, stdout- and stderr-shaped fields are rejected. It verifies receipt hashes and bindings but explicitly does not verify evidence contents. This plugin proves only supplied hashes, subject/revision bindings, assertions and declared control coverage; it does not sign evidence, enforce policy, or provide a compliance certification.
