import { createHash, randomUUID } from 'node:crypto'
import { link, lstat, mkdir, readFile, realpath, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'

const MAX_BYTES = 4_194_304
const MAX_NODES = 30_000
const ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/
const HASH = /^[a-f0-9]{64}$/
const FORBIDDEN_MANIFEST_KEYS = /(authorization|api.?key|secret|token|password|credential|cookie|private.?key|stdout|stderr|raw.?value|content|prompt|message)/i
const sha = (value) => createHash('sha256').update(value).digest('hex')
const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value
const stableJson = (value) => `${JSON.stringify(stable(value), null, 2)}\n`
const valueDigest = (value) => sha(JSON.stringify(stable(value)) ?? '"__undefined__"')

export class AuditBundleError extends Error { constructor(code, message) { super(message); this.name = 'AuditBundleError'; this.code = code } }
function object(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AuditBundleError('INVALID_SCHEMA', `${label} must be an object`) }
function safeTree(value, at = '$', counter = { count: 0 }, forbidKeys = false) {
  counter.count += 1; if (counter.count > MAX_NODES) throw new AuditBundleError('INPUT_TOO_COMPLEX', `input exceeds ${MAX_NODES} nodes`)
  if (typeof value === 'string' && value.length > 2048) throw new AuditBundleError('VALUE_TOO_LARGE', `string at ${at} exceeds 2048 characters`)
  if (Array.isArray(value)) { if (value.length > 2000) throw new AuditBundleError('VALUE_TOO_LARGE', `array at ${at} exceeds 2000 items`); value.forEach((child, i) => safeTree(child, `${at}[${i}]`, counter, forbidKeys)); return }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) { if (forbidKeys && FORBIDDEN_MANIFEST_KEYS.test(key)) throw new AuditBundleError('FORBIDDEN_FIELD', `secret or raw-output shaped manifest field at ${at}.${key}`); safeTree(child, `${at}.${key}`, counter, forbidKeys) }
}

async function rootDirectory(rootValue) { const root = await realpath(rootValue); const info = await lstat(root); if (!info.isDirectory() || info.isSymbolicLink()) throw new AuditBundleError('UNSAFE_PATH', 'workspaceRoot must be a real directory'); return root }
async function safeFile(rootValue, relativePath, label, optional = false) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) throw new AuditBundleError('UNSAFE_PATH', `${label} must be workspace-relative`)
  const root = await rootDirectory(rootValue); const target = path.resolve(root, relativePath); const rel = path.relative(root, target)
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new AuditBundleError('UNSAFE_PATH', `${label} escapes workspaceRoot`)
  let info; try { info = await lstat(target) } catch (error) { if (optional && error.code === 'ENOENT') return { root, missing: true, target }; throw error }
  if (!info.isFile() || info.isSymbolicLink()) throw new AuditBundleError('UNSAFE_PATH', `${label} must be a regular non-symlink file`)
  if (info.size > MAX_BYTES) throw new AuditBundleError('INPUT_TOO_LARGE', `${label} exceeds ${MAX_BYTES} bytes`)
  const resolved = await realpath(target); const resolvedRel = path.relative(root, resolved); if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new AuditBundleError('UNSAFE_PATH', `${label} resolves outside workspaceRoot`)
  return { root, missing: false, target: resolved }
}
async function artifactDirectory(rootValue, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) throw new AuditBundleError('UNSAFE_PATH', 'artifactDir must be workspace-relative')
  const root = await rootDirectory(rootValue); const target = path.resolve(root, relativePath); const rel = path.relative(root, target); if (rel.startsWith('..') || path.isAbsolute(rel)) throw new AuditBundleError('UNSAFE_PATH', 'artifactDir escapes workspaceRoot')
  await mkdir(target, { recursive: true }); const info = await lstat(target); if (!info.isDirectory() || info.isSymbolicLink()) throw new AuditBundleError('UNSAFE_PATH', 'artifactDir must be a real directory')
  const resolved = await realpath(target); const resolvedRel = path.relative(root, resolved); if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new AuditBundleError('UNSAFE_PATH', 'artifactDir resolves outside workspaceRoot')
  return { root, target: resolved }
}

function pointer(value, raw) { if (typeof raw !== 'string' || !raw.startsWith('/') || raw.includes('//') || raw.endsWith('/')) throw new AuditBundleError('INVALID_SCHEMA', 'JSON pointers must be absolute and canonical'); return raw.slice(1).split('/').map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~')).reduce((current, key) => current === undefined ? undefined : current?.[key], value) }
function validatePointer(raw, label) { try { pointer({}, raw) } catch { throw new AuditBundleError('INVALID_SCHEMA', `${label} is not a canonical JSON pointer`) } }

function validateManifest(manifest) {
  object(manifest, 'manifest'); safeTree(manifest, '$', { count: 0 }, true)
  if (manifest.schemaVersion !== 1 || !ID.test(manifest.bundleId)) throw new AuditBundleError('INVALID_SCHEMA', 'schemaVersion must be 1 and bundleId must be stable')
  object(manifest.subject, 'subject'); if (!ID.test(manifest.subject.id) || typeof manifest.subject.revision !== 'string' || !manifest.subject.revision || manifest.subject.revision.length > 256) throw new AuditBundleError('INVALID_SCHEMA', 'subject id or revision is invalid')
  if (!Array.isArray(manifest.requiredControls) || !manifest.requiredControls.length || !Array.isArray(manifest.evidence) || !manifest.evidence.length) throw new AuditBundleError('INVALID_SCHEMA', 'requiredControls and evidence must be non-empty arrays')
  const controls = new Map()
  for (const [i, control] of manifest.requiredControls.entries()) {
    object(control, `requiredControls[${i}]`)
    if (!ID.test(control.id) || controls.has(control.id) || !Number.isSafeInteger(control.minEvidence) || control.minEvidence < 1 || control.minEvidence > 100 || !Number.isSafeInteger(control.minProducers) || control.minProducers < 1 || control.minProducers > control.minEvidence || !Array.isArray(control.allowedTypes) || !control.allowedTypes.length || control.allowedTypes.some((type) => !ID.test(type)) || new Set(control.allowedTypes).size !== control.allowedTypes.length) throw new AuditBundleError('INVALID_SCHEMA', `requiredControls[${i}] is invalid`)
    controls.set(control.id, control)
  }
  const evidenceIds = new Set()
  for (const [i, item] of manifest.evidence.entries()) {
    object(item, `evidence[${i}]`); object(item.subjectPointers, `evidence[${i}].subjectPointers`)
    if (!ID.test(item.id) || evidenceIds.has(item.id) || !ID.test(item.type) || !ID.test(item.producer) || typeof item.path !== 'string' || !HASH.test(item.sha256) || !Array.isArray(item.controls) || !item.controls.length || item.controls.some((id) => !controls.has(id)) || new Set(item.controls).size !== item.controls.length) throw new AuditBundleError('INVALID_SCHEMA', `evidence[${i}] identity, path, hash or controls are invalid`)
    validatePointer(item.subjectPointers.id, `evidence[${i}].subjectPointers.id`); validatePointer(item.subjectPointers.revision, `evidence[${i}].subjectPointers.revision`)
    if (!Array.isArray(item.assertions) || item.assertions.length > 50) throw new AuditBundleError('INVALID_SCHEMA', `evidence[${i}].assertions must be an array with at most 50 items`)
    const assertionIds = new Set(); for (const [j, assertion] of item.assertions.entries()) { object(assertion, `evidence[${i}].assertions[${j}]`); if (!ID.test(assertion.id) || assertionIds.has(assertion.id) || !HASH.test(assertion.expectedValueSha256)) throw new AuditBundleError('INVALID_SCHEMA', `evidence[${i}].assertions[${j}] is invalid`); validatePointer(assertion.pointer, `evidence[${i}].assertions[${j}].pointer`); assertionIds.add(assertion.id) }
    evidenceIds.add(item.id)
  }
  return { manifest, controls }
}

async function loadManifest(root, manifestPath) { const { target } = await safeFile(root, manifestPath, 'manifestPath'); const bytes = await readFile(target); let value; try { value = JSON.parse(bytes.toString('utf8')) } catch { throw new AuditBundleError('INVALID_JSON', 'manifestPath is not valid JSON') }; return { ...validateManifest(value), manifestSha256: sha(bytes) } }

function parseManifestJson(manifestJson) {
  if (typeof manifestJson !== 'string' || !manifestJson || Buffer.byteLength(manifestJson) > MAX_BYTES) throw new AuditBundleError('INPUT_TOO_LARGE', `manifestJson must be a non-empty string of at most ${MAX_BYTES} bytes`)
  let value
  try { value = JSON.parse(manifestJson) } catch { throw new AuditBundleError('INVALID_JSON', 'manifestJson is not valid JSON') }
  return { ...validateManifest(value), manifestSha256: sha(manifestJson) }
}

async function evaluateEvidence(root, item, subject) {
  const located = await safeFile(root, item.path, `evidence ${item.id}.path`, true)
  if (located.missing) return { id: item.id, type: item.type, producer: item.producer, controls: item.controls, inputStatus: 'missing', expectedSha256: item.sha256, actualSha256: null, subjectStatus: 'unknown', assertions: [], eligible: false }
  const bytes = await readFile(located.target); const actualSha256 = sha(bytes); let value
  try { value = JSON.parse(bytes.toString('utf8')); safeTree(value) } catch { return { id: item.id, type: item.type, producer: item.producer, controls: item.controls, inputStatus: 'invalid-json', expectedSha256: item.sha256, actualSha256, subjectStatus: 'unknown', assertions: [], eligible: false } }
  const observedId = pointer(value, item.subjectPointers.id); const observedRevision = pointer(value, item.subjectPointers.revision)
  const subjectStatus = observedId === subject.id && observedRevision === subject.revision ? 'matched' : 'mismatched'
  const assertions = item.assertions.map((assertion) => { const actualValueSha256 = valueDigest(pointer(value, assertion.pointer)); return { id: assertion.id, pointer: assertion.pointer, expectedValueSha256: assertion.expectedValueSha256, actualValueSha256, status: actualValueSha256 === assertion.expectedValueSha256 ? 'passed' : 'failed' } })
  const inputStatus = actualSha256 === item.sha256 ? 'current' : 'stale'; const eligible = inputStatus === 'current' && subjectStatus === 'matched' && assertions.every(({ status }) => status === 'passed')
  return { id: item.id, type: item.type, producer: item.producer, controls: item.controls, inputStatus, expectedSha256: item.sha256, actualSha256, subjectStatus, assertions, eligible }
}

function merkleRoot(leaves) { let level = leaves.length ? [...leaves].sort() : [sha('')]; while (level.length > 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(sha(`${level[i]}${level[i + 1] ?? level[i]}`)); level = next } return level[0] }
function controlCoverage(controls, evidence) {
  return [...controls.values()].map((control) => {
    const eligible = evidence.filter((item) => item.eligible && item.controls.includes(control.id) && control.allowedTypes.includes(item.type)); const producers = new Set(eligible.map(({ producer }) => producer))
    return { id: control.id, minEvidence: control.minEvidence, minProducers: control.minProducers, allowedTypes: control.allowedTypes, eligibleEvidenceIds: eligible.map(({ id }) => id).sort(), producerCount: producers.size, status: eligible.length >= control.minEvidence && producers.size >= control.minProducers ? 'satisfied' : 'gap' }
  })
}
async function writeReport(rootValue, artifactDir, report) {
  const { root, target: directory } = await artifactDirectory(rootValue, artifactDir); const body = stableJson(report); const reportSha256 = sha(body); const filename = `audit-bundle-${reportSha256}.json`; const target = path.join(directory, filename); const temporary = path.join(directory, `.${filename}.${randomUUID()}.tmp`)
  try { await writeFile(temporary, body, { encoding: 'utf8', flag: 'wx' }); try { await link(temporary, target) } catch (error) { if (error.code !== 'EEXIST') throw error }; const reread = await readFile(target, 'utf8'); if (reread !== body || sha(reread) !== reportSha256) throw new AuditBundleError('WRITE_VERIFY_FAILED', 'audit index read-back verification failed'); return { path: path.relative(root, target).replaceAll(path.sep, '/'), sha256: reportSha256, bytes: Buffer.byteLength(body), verifiedByReadBack: true } } finally { try { await unlink(temporary) } catch {} }
}

export async function inspectAuditBundle({ workspaceRoot: root = process.cwd(), manifestPath }) {
  const { manifest, manifestSha256 } = await loadManifest(root, manifestPath)
  return { schemaVersion: 1, operation: 'inspect', returnsEvidenceBodies: false, bundleId: manifest.bundleId, subject: manifest.subject, manifestSha256, requiredControls: manifest.requiredControls, evidence: manifest.evidence.map(({ id, type, producer, sha256, controls, assertions }) => ({ id, type, producer, expectedSha256: sha256, controls, assertionIds: assertions.map(({ id: assertionId }) => assertionId) })) }
}
export async function verifyAuditBundle({ workspaceRoot: root = process.cwd(), manifestPath, artifactDir }) {
  const { manifest, controls, manifestSha256 } = await loadManifest(root, manifestPath); const evidence = []
  for (const item of manifest.evidence) evidence.push(await evaluateEvidence(root, item, manifest.subject))
  const coverage = controlCoverage(controls, evidence); const leafDigests = evidence.map((item) => sha(stableJson(item))); const rootSha256 = merkleRoot(leafDigests)
  const failedEvidenceIds = evidence.filter(({ eligible }) => !eligible).map(({ id }) => id); const gapControlIds = coverage.filter(({ status }) => status === 'gap').map(({ id }) => id); const pass = !failedEvidenceIds.length && !gapControlIds.length
  const report = { schemaVersion: 1, operation: 'verify', returnsEvidenceBodies: false, bundleId: manifest.bundleId, subject: manifest.subject, manifestSha256, status: pass ? 'verified' : 'failed', verdict: pass ? 'pass' : 'fail', merkle: { algorithm: 'sha256-pair-v1', leafCount: leafDigests.length, rootSha256 }, disclosure: { missingEvidenceIds: evidence.filter(({ inputStatus }) => inputStatus === 'missing').map(({ id }) => id), staleEvidenceIds: evidence.filter(({ inputStatus }) => inputStatus === 'stale').map(({ id }) => id), invalidEvidenceIds: evidence.filter(({ inputStatus }) => inputStatus === 'invalid-json').map(({ id }) => id), failedEvidenceIds, gapControlIds }, evidence, coverage }
  const artifact = await writeReport(root, artifactDir, report); return { ...report, artifact }
}

function parseReceiptsJsonl(receiptsJsonl, manifest) {
  if (typeof receiptsJsonl !== 'string' || !receiptsJsonl || Buffer.byteLength(receiptsJsonl) > MAX_BYTES) throw new AuditBundleError('INPUT_TOO_LARGE', `receiptsJsonl must be a non-empty string of at most ${MAX_BYTES} bytes`)
  const records = []
  for (const [lineIndex, line] of receiptsJsonl.split(/\r?\n/).entries()) {
    if (!line.trim()) continue
    let receipt
    try { receipt = JSON.parse(line) } catch { throw new AuditBundleError('INVALID_JSON', `receiptsJsonl line ${lineIndex + 1} is not valid JSON`) }
    object(receipt, `receiptsJsonl line ${lineIndex + 1}`); safeTree(receipt, `$[${lineIndex}]`, { count: 0 }, true)
    object(receipt.subject, `receipt ${lineIndex + 1}.subject`)
    if (receipt.receiptVersion !== 1 || !ID.test(receipt.evidenceId) || !HASH.test(receipt.observedSha256) || !ID.test(receipt.producer) || typeof receipt.subject.id !== 'string' || typeof receipt.subject.revision !== 'string' || !Array.isArray(receipt.assertions)) throw new AuditBundleError('INVALID_SCHEMA', `receipt line ${lineIndex + 1} is invalid`)
    if (receipt.assertions.length > 50) throw new AuditBundleError('INVALID_SCHEMA', `receipt line ${lineIndex + 1} has too many assertions`)
    const assertions = new Map()
    for (const [assertionIndex, assertion] of receipt.assertions.entries()) {
      object(assertion, `receipt ${lineIndex + 1}.assertions[${assertionIndex}]`)
      if (!ID.test(assertion.id) || assertions.has(assertion.id) || !HASH.test(assertion.actualValueSha256)) throw new AuditBundleError('INVALID_SCHEMA', `receipt line ${lineIndex + 1} assertion is invalid`)
      assertions.set(assertion.id, assertion.actualValueSha256)
    }
    if (!manifest.evidence.some(({ id }) => id === receipt.evidenceId)) throw new AuditBundleError('UNKNOWN_EVIDENCE', `receipt line ${lineIndex + 1} references unknown evidenceId`)
    if (records.some(({ evidenceId }) => evidenceId === receipt.evidenceId)) throw new AuditBundleError('DUPLICATE_EVIDENCE', `duplicate receipt for evidenceId ${receipt.evidenceId}`)
    records.push({ ...receipt, assertions })
  }
  return records
}

function evaluateReceipts(manifest, records) {
  return manifest.evidence.map((item) => {
    const receipt = records.find(({ evidenceId }) => evidenceId === item.id)
    if (!receipt) return { id: item.id, type: item.type, producer: item.producer, controls: item.controls, inputStatus: 'missing', expectedSha256: item.sha256, actualSha256: null, subjectStatus: 'unknown', producerStatus: 'unknown', assertions: [], eligible: false }
    const inputStatus = receipt.observedSha256 === item.sha256 ? 'current' : 'stale'
    const subjectStatus = receipt.subject.id === manifest.subject.id && receipt.subject.revision === manifest.subject.revision ? 'matched' : 'mismatched'
    const producerStatus = receipt.producer === item.producer ? 'matched' : 'mismatched'
    const assertions = item.assertions.map((assertion) => {
      const actualValueSha256 = receipt.assertions.get(assertion.id) ?? null
      return { id: assertion.id, pointer: assertion.pointer, expectedValueSha256: assertion.expectedValueSha256, actualValueSha256, status: actualValueSha256 === assertion.expectedValueSha256 ? 'passed' : 'failed' }
    })
    return { id: item.id, type: item.type, producer: item.producer, controls: item.controls, inputStatus, expectedSha256: item.sha256, actualSha256: receipt.observedSha256, subjectStatus, producerStatus, assertions, eligible: inputStatus === 'current' && subjectStatus === 'matched' && producerStatus === 'matched' && assertions.every(({ status }) => status === 'passed') }
  })
}

export function inspectAuditBundleManifestJson(manifestJson) {
  const { manifest, manifestSha256 } = parseManifestJson(manifestJson)
  return { schemaVersion: 1, operation: 'inspect-inline-manifest', proofOnly: true, filesystemAccess: false, executesActions: false, returnsEvidenceBodies: false, evidenceContentVerification: 'not-performed', bundleId: manifest.bundleId, subject: manifest.subject, manifestSha256, requiredControls: manifest.requiredControls, evidence: manifest.evidence.map(({ id, type, producer, sha256, controls, assertions }) => ({ id, type, producer, expectedSha256: sha256, controls, assertionIds: assertions.map(({ id: assertionId }) => assertionId) })) }
}

export function verifyAuditBundleReceiptsJsonl(manifestJson, receiptsJsonl) {
  const { manifest, controls, manifestSha256 } = parseManifestJson(manifestJson)
  const receipts = parseReceiptsJsonl(receiptsJsonl, manifest)
  const evidence = evaluateReceipts(manifest, receipts)
  const coverage = controlCoverage(controls, evidence)
  const leafDigests = evidence.map((item) => sha(stableJson(item)))
  const failedEvidenceIds = evidence.filter(({ eligible }) => !eligible).map(({ id }) => id)
  const gapControlIds = coverage.filter(({ status }) => status === 'gap').map(({ id }) => id)
  const pass = !failedEvidenceIds.length && !gapControlIds.length
  return { schemaVersion: 1, operation: 'verify-inline-receipts', proofOnly: true, filesystemAccess: false, executesActions: false, returnsEvidenceBodies: false, evidenceContentVerification: 'not-performed', bundleId: manifest.bundleId, subject: manifest.subject, manifestSha256, status: pass ? 'structurally-verified' : 'failed', verdict: pass ? 'pass' : 'fail', merkle: { algorithm: 'sha256-pair-v1', leafCount: leafDigests.length, rootSha256: merkleRoot(leafDigests) }, disclosure: { missingEvidenceIds: evidence.filter(({ inputStatus }) => inputStatus === 'missing').map(({ id }) => id), staleEvidenceIds: evidence.filter(({ inputStatus }) => inputStatus === 'stale').map(({ id }) => id), failedEvidenceIds, gapControlIds }, evidence, coverage }
}
