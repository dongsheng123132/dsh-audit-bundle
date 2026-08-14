import assert from 'node:assert/strict'
import { createDefinitions } from '../index.js'
const tools = createDefinitions({}, {}).map(({ name }) => name); assert.deepEqual(tools, ['dsh_audit_bundle_inspect', 'dsh_audit_bundle_verify']); process.stdout.write(`${JSON.stringify({ ok: true, tools })}\n`)
