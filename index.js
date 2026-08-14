import { defineTool } from '@deepseek-ai/dsh-tools'
import { inspectAuditBundle, verifyAuditBundle } from './lib/audit-bundle.mjs'

export const name = 'dsh-audit-bundle'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const base = (config, args) => ({ workspaceRoot: config.workspaceRoot ?? process.cwd(), manifestPath: args.manifestPath, artifactDir: args.artifactDir })
export function createDefinitions(_ctx, config = {}) {
  return [
    defineTool({ name: 'dsh_audit_bundle_inspect', description: 'Inspect subject, required controls and evidence identities without reading or returning evidence bodies.', parameters: { manifestPath: { type: 'string', required: true } }, output: { schema: { type: 'json' }, render: renderJson }, execute(args) { return inspectAuditBundle(base(config, args)) } }),
    defineTool({ name: 'dsh_audit_bundle_verify', description: 'Verify pinned multi-producer evidence and emit a content-addressed Merkle audit index without copying evidence bodies.', parameters: { manifestPath: { type: 'string', required: true }, artifactDir: { type: 'string', required: true } }, output: { schema: { type: 'json' }, render: renderJson }, execute(args) { return verifyAuditBundle(base(config, args)) } })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
export default apply
