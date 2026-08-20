import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'

const manifestJson = await readFile(new URL('../examples/basic/audit.manifest.json', import.meta.url), 'utf8')
const manifest = JSON.parse(manifestJson)
const receiptsJsonl = manifest.evidence.map((item) => JSON.stringify({ receiptVersion: 1, evidenceId: item.id, observedSha256: item.sha256, producer: item.producer, subject: manifest.subject, assertions: item.assertions.map(({ id, expectedValueSha256 }) => ({ id, actualValueSha256: expectedValueSha256 })) })).join('\n')
const child = spawn(process.execPath, ['mcp-server.mjs'], { cwd: new URL('../', import.meta.url), shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } })
let buffer = ''; const responses = []
child.stdout.setEncoding('utf8'); child.stdout.on('data', (chunk) => { buffer += chunk; let index; while ((index = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, index); buffer = buffer.slice(index + 1); if (line) responses.push(JSON.parse(line)) } })
const send = (id, method, params = {}) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
send(1, 'initialize', { protocolVersion: '2025-06-18' })
send(2, 'tools/list')
send(3, 'tools/call', { name: 'audit_bundle_inspect', arguments: { manifestJson } })
send(4, 'tools/call', { name: 'audit_bundle_verify', arguments: { manifestJson, receiptsJsonl } })
send(5, 'tools/call', { name: 'audit_bundle_verify', arguments: { manifestJson, receiptsJsonl: `${receiptsJsonl}\n${JSON.stringify({ apiToken: 'must-not-echo' })}` } })
const deadline = Date.now() + 5000; while (responses.length < 5 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20))
child.stdin.end(); if (!child.killed) child.kill()
assert.equal(responses.length, 5); assert.equal(responses[0].result.serverInfo.version, '0.2.0'); assert.deepEqual(responses[1].result.tools.map(({ name }) => name), ['audit_bundle_inspect', 'audit_bundle_verify']); assert.equal(responses[2].result.structuredContent.filesystemAccess, false); assert.equal(responses[3].result.structuredContent.status, 'structurally-verified'); assert.equal(responses[4].error.data.code, 'FORBIDDEN_FIELD'); assert.ok(!JSON.stringify(responses[4]).includes('must-not-echo'))
process.stdout.write(`${JSON.stringify({ ok: true, protocol: '2025-06-18', tools: 2, proofOnly: true, secretFieldRejected: true })}\n`)
