# dsh-audit-bundle

[![CI](https://github.com/dongsheng123132/dsh-audit-bundle/actions/workflows/check.yml/badge.svg)](https://github.com/dongsheng123132/dsh-audit-bundle/actions/workflows/check.yml)
[![MIT license](https://img.shields.io/github/license/dongsheng123132/dsh-audit-bundle)](LICENSE)
[![Node.js 22+](https://img.shields.io/badge/Node.js-%E2%89%A522-339933?logo=nodedotjs&logoColor=white)](package.json)
[![Awesome DSH Plugins](https://img.shields.io/badge/Awesome_DSH-verified_lab-0969da)](https://github.com/dongsheng123132/awesome-dsh-plugins#2origin-plugin-lab)

Content-addressed audit indexes across independent [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) evidence producers.

Version 0.2 adds a formal proof-only Codex MCP surface, host-neutral DSH ToolDefinitions, real ToolRuntime calls and a stock Web Loader regression test. The package exposes namespace exports only and does not bundle a second DSH runtime.

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

The DSH bundle registers `dsh_audit_bundle_inspect` and `dsh_audit_bundle_verify`. These workspace-bounded tools dereference pinned evidence and can write the content-addressed index. The companion stdio MCP server registers `audit_bundle_inspect` and `audit_bundle_verify` through `.mcp.json`, but accepts only an inline manifest and structural JSONL receipts containing IDs, hashes, producer/subject bindings and assertion digests. MCP never reads files, dereferences evidence, executes actions or writes artifacts; it reports `evidenceContentVerification: not-performed`. Use DSH or CLI for real evidence-content verification.

```sh
dsh plugin --profile audit-bundle add github:dongsheng123132/dsh-audit-bundle#<commit>
dsh --profile audit-bundle --dump-config
```

## Verification

```sh
npm ci
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
DSH_CHECKOUT=/path/to/built/deepseek-harness npm run smoke:dsh
DSH_CHECKOUT=/path/to/built/deepseek-harness DSH_HOME=/path/to/isolated-home npm run smoke:web-loader
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

CI runs on Ubuntu and Windows. Node.js 22 or newer. MIT licensed.
