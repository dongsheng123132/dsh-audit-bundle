import { inspectAuditBundle, verifyAuditBundle } from './lib/audit-bundle.mjs'

export const name = 'dsh-audit-bundle'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const base = (config, args) => ({ workspaceRoot: config.workspaceRoot ?? process.cwd(), manifestPath: args.manifestPath, artifactDir: args.artifactDir })
const defineJsonTool = ({ name, description, parameters, execute }) => ({
  name,
  description,
  parameters: {
    type: 'object',
    properties: Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, { type: 'string', description: value.description }])),
    required: Object.entries(parameters).filter(([, value]) => value.required).map(([key]) => key),
    additionalProperties: false
  },
  output: { schema: {}, render: renderJson },
  execute(args) {
    for (const [key, value] of Object.entries(parameters)) if (value.required && (typeof args?.[key] !== 'string' || args[key].length === 0)) throw new TypeError(`${key} must be a non-empty string`)
    return execute(args)
  }
})
export function createDefinitions(_ctx, config = {}) {
  return [
    defineJsonTool({ name: 'dsh_audit_bundle_inspect', description: 'Inspect subject, required controls and evidence identities without reading or returning evidence bodies.', parameters: { manifestPath: { required: true, description: 'Audit manifest relative to workspaceRoot.' } }, execute(args) { return inspectAuditBundle(base(config, args)) } }),
    defineJsonTool({ name: 'dsh_audit_bundle_verify', description: 'Verify pinned multi-producer evidence and emit a content-addressed Merkle audit index without copying evidence bodies.', parameters: { manifestPath: { required: true, description: 'Audit manifest relative to workspaceRoot.' }, artifactDir: { required: true, description: 'Only report directory that may be written, relative to workspaceRoot.' } }, execute(args) { return verifyAuditBundle(base(config, args)) } })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
