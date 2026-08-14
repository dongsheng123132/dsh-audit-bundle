# Security

Report vulnerabilities privately through GitHub Security Advisories for this repository.

The verifier is read-only with respect to source evidence. It reads only explicit workspace-relative regular files, rejects symlinks and path escape, bounds file size and parsed structure, performs no network requests or child processes, and writes only one content-addressed index beneath the explicit artifact directory with read-back verification. Evidence bodies are never copied into tool output or the generated index. Secret-shaped fields are forbidden in the manifest. This plugin proves only the supplied hashes, subject/revision bindings, assertions and declared control coverage; it does not sign evidence, enforce policy, or provide a compliance certification.
