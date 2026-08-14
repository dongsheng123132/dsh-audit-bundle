# dsh-audit-bundle

Content-addressed audit indexes across independent [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) evidence producers.

This plugin is not an SBOM scanner, signer, audit logger, policy engine or archive. Existing tools already scan dependencies and individual 2Origin plugins already produce release, runtime, recovery, lineage and policy evidence. The missing layer is a small verifier that proves a particular subject/revision has enough pinned evidence from allowed, independent producers to cover declared controls.

## Contract

An explicit manifest declares:

- one subject ID and revision;
- required controls with minimum eligible evidence, minimum distinct producers and allowed evidence types;
- evidence files pinned by SHA-256;
- JSON Pointers that bind every evidence file to the subject and revision;
- value-hash assertions, so expected or observed values never enter the audit index.

Verification fails closed for missing, stale or invalid JSON evidence, subject/revision mismatch, failed assertions, disallowed types, insufficient evidence or insufficient independent producers. The output contains IDs, types, producers, paths into JSON, hashes, statuses, coverage and a deterministic SHA-256 pair-tree Merkle root. It never copies evidence bodies or assertion values.

Files must be workspace-relative regular files. Symlinks, path escape, oversized input and excessive structure are rejected. The plugin performs no network calls or child processes and writes only a content-addressed JSON index under the explicit `artifactDir`, followed by read-back verification.

## CLI

```sh
node bin/dsh-audit-bundle.mjs inspect --workspace examples/basic --manifest audit.manifest.json
node bin/dsh-audit-bundle.mjs verify --workspace examples/basic --manifest audit.manifest.json --artifactDir artifacts
```

The CLI emits one JSON object. A failed audit verdict exits `2`; invalid usage exits `1`.

## DeepSeek Harness and MCP

The DSH bundle registers `dsh_audit_bundle_inspect` and `dsh_audit_bundle_verify`. The companion stdio MCP server registers `audit_bundle_inspect` and `audit_bundle_verify` through `.mcp.json`.

```sh
dsh plugin --profile audit-bundle add github:dongsheng123132/dsh-audit-bundle#<commit>
dsh --profile audit-bundle --dump-config
```

## Verification

```sh
npm ci
npm test
npm run check
npm run smoke:mcp
DSH_CHECKOUT=/path/to/built/deepseek-harness npm run smoke:dsh
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

CI runs on Ubuntu and Windows. Node.js 22 or newer. MIT licensed.
