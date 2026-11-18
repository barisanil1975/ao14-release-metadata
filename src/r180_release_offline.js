'use strict';
/**
 * AO14 R186: R180-compatible Ed25519 RELEASE signature *format* (offline-only).
 * No workflow, token, secret store, remote call, production grant or lease.
 * Synthetic test signatures ONLY. Not independent custody or L4 authority.
 */
const crypto = require('node:crypto');

const SCHEMA = 'aios.ao14.r180.r175-install-approval.v1';
const CANDIDATE_SHA = 'a47637dcc0e46f610f3ea8d7f43109c21094a5ada3264f157354acb71925dea8';
const HOST = 'ai-orchestra-n8n-fra1-01';
const DROPLET = 603086247;
const DOMAIN = Buffer.from('AIOS-AO14-R180-R175-APPROVAL-V1\0', 'utf8');
const HEX64 = /^[a-f0-9]{64}$/;
const HEX40 = /^[a-f0-9]{40}$/;
const NONCE = /^[a-f0-9]{32,128}$/;
const SCOPE = /^[A-Z0-9][A-Z0-9_.:-]{11,127}$/;
const EFFECT_FIELDS = Object.freeze([
  'activate_allowed', 'delete_allowed', 'publish_allowed',
  'secrets_access_allowed', 'paid_resource_allowed',
  'prod_install_allowed', 'offsite_upload_allowed',
  'registry_write_allowed',
]);
const APPROVAL_FIELDS = Object.freeze([
  'schema', 'scope_id', 'action', 'host_id', 'droplet_id',
  'candidate_sha256', 'source_sha256', 'host_state_sha256',
  'issued_utc', 'expires_utc', 'nonce', 'max_executions',
  'data_class', 'risk_lane', 'owner_principal', 'release_principal',
  'owner_custody_domain', 'release_custody_domain',
  'custody_evidence_sha256', 'candidate_commit_sha',
  'human_approval_text_sha256', ...EFFECT_FIELDS,
]);
function fail(code) { throw new Error('HOLD_' + code); }
function need(ok, code) { if (!ok) fail(code); }
function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function exactKeys(value, fields, code) {
  need(isObject(value), code);
  const keys = Object.keys(value);
  need(keys.length === fields.length && fields.every((k) => Object.hasOwn(value, k)), code);
}
function named(value) {
  return typeof value === 'string' && value.length >= 3 && value.length <= 128 &&
    value.trim() === value;
}
function utcMilliseconds(value) {
  need(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value),
    'BAD_UTC_DATE');
  const n = Date.parse(value);
  need(Number.isFinite(n) && new Date(n).toISOString().startsWith(value.slice(0,19)), 'BAD_UTC_DATE');
  return n;
}
/** Exactly compatible with Python json.dumps(sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
 * for this strict approval schema (strings, booleans, null, and safe integers only).
 * No floats, arrays, buffers, prototypes or implicit key coercions are permitted.
 */
function canonicalAscii(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    need(Number.isSafeInteger(value) && !Object.is(value, -0), 'UNSUPPORTED_JSON_NUMBER');
    return String(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (c) =>
      '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  need(isObject(value), 'UNSUPPORTED_JSON_TYPE');
  const keys = Object.keys(value).sort();
  return '{' + keys.map((key) => canonicalAscii(key) + ':' + canonicalAscii(value[key])).join(',') + '}';
}
function sha256(data) { return crypto.createHash('sha256').update(data).digest('hex'); }
/**
 * binding: a separate, independently trusted state input. Never compute binding
 * by merely reading back fields from the same untrusted payload in live usage.
 * nowUtc: externally verified clock; cannot prove native authority by itself.
 */
function checkApproval(payload, binding, nowUtc) {
  exactKeys(payload, APPROVAL_FIELDS, 'APPROVAL_FIELDS');
  exactKeys(binding, ['scope_id','source_sha256','host_state_sha256',
    'human_approval_text_sha256','candidate_commit_sha'], 'BINDING_FIELDS');
  need(payload.schema === SCHEMA, 'APPROVAL_SCHEMA');
  need(payload.action === 'INSTALL_R175_REGISTRAR', 'ACTION_DRIFT');
  need(payload.host_id === HOST && payload.droplet_id === DROPLET,
    'HOST_MISMATCH');
  need(payload.candidate_sha256 === CANDIDATE_SHA, 'CANDIDATE_SHA_MISMATCH');
  need(typeof binding.scope_id === 'string' && SCOPE.test(binding.scope_id) &&
    payload.scope_id === binding.scope_id, 'APPROVAL_SCOPE_MISMATCH');
  for (const field of ['source_sha256','host_state_sha256','human_approval_text_sha256']) {
    need(typeof binding[field] === 'string' && HEX64.test(binding[field]) &&
      payload[field] === binding[field], field.toUpperCase() + '_MISMATCH');
  }
  need((binding.candidate_commit_sha === null ||
    (typeof binding.candidate_commit_sha === 'string' && HEX40.test(binding.candidate_commit_sha))) &&
    payload.candidate_commit_sha === binding.candidate_commit_sha, 'GIT_COMMIT_SHA_MISMATCH');
  need(payload.risk_lane === 'L4' && payload.data_class === 'CONFIDENTIAL',
    'RISK_OR_DATA_CLASS_MISMATCH');
  need(payload.max_executions === 1, 'MAX_EXECUTIONS');
  need(typeof payload.nonce === 'string' && NONCE.test(payload.nonce), 'NONCE_INVALID');
  for (const k of EFFECT_FIELDS) need(payload[k] === false, 'EFFECT_NOT_ALLOWED:' + k);
  need(named(payload.owner_principal) && named(payload.release_principal) &&
    payload.owner_principal !== payload.release_principal, 'SIGNER_PRINCIPALS_NOT_SEPARATE');
  need(named(payload.owner_custody_domain) && named(payload.release_custody_domain) &&
    payload.owner_custody_domain !== payload.release_custody_domain,
    'CUSTODY_DOMAINS_NOT_SEPARATE');
  need(typeof payload.custody_evidence_sha256 === 'string' &&
    HEX64.test(payload.custody_evidence_sha256), 'CUSTODY_EVIDENCE_UNPINNED');
  const issued = utcMilliseconds(payload.issued_utc);
  const expires = utcMilliseconds(payload.expires_utc);
  const now = utcMilliseconds(nowUtc);
  need(issued <= now && now < expires && expires - issued > 0 &&
    expires - issued <= 15 * 60 * 1000, 'APPROVAL_WINDOW_INVALID');
  return Object.freeze({
    candidate_sha256: CANDIDATE_SHA,
    approval_payload_sha256: sha256(Buffer.from(canonicalAscii(payload), 'ascii')),
    gate: 'R186_OFFLINE_FORMAT_VALID_ONLY',
    native_granted: false,
    native_lease_acquired: false,
  });
}
function messageForR180(payload, binding, nowUtc) {
  checkApproval(payload, binding, nowUtc);
  return Buffer.concat([DOMAIN, Buffer.from(canonicalAscii(payload), 'ascii')]);
}
/**
 * This code path is restricted to synthetic test scopes by construction.
 * Future live key custody/attestation requires a separately reviewed implementation.
 * privateKey must be an in-memory Ed25519 KeyObject; no key file/env/secret input.
 */
function signSyntheticR180(payload, binding, nowUtc, privateKey) {
  need(typeof payload?.scope_id === 'string' &&
    /^APV-AO14-R186-SYNTHETIC-[A-Z0-9-]+$/.test(payload.scope_id),
    'R186_SYNTHETIC_ONLY');
  need(privateKey instanceof crypto.KeyObject && privateKey.type === 'private' &&
    privateKey.asymmetricKeyType === 'ed25519', 'SYNTHETIC_ED25519_KEY_REQUIRED');
  const msg = messageForR180(payload, binding, nowUtc);
  const signature = crypto.sign(null, msg, privateKey);
  need(signature.length === 64, 'SIGNATURE_LENGTH');
  return Object.freeze({
    signature_b64: signature.toString('base64'),
    signed_message_sha256: sha256(msg),
    approval_payload_sha256: sha256(Buffer.from(canonicalAscii(payload), 'ascii')),
    gate: 'SYNTHETIC_SIGNATURE_ONLY',
    native_granted: false,
    native_lease_acquired: false,
    real_release_credential_used: false,
  });
}
function verifySyntheticR180(payload, binding, nowUtc, signatureB64, publicKey) {
  need(publicKey instanceof crypto.KeyObject && publicKey.type === 'public' &&
    publicKey.asymmetricKeyType === 'ed25519', 'PUBLIC_ED25519_KEY_REQUIRED');
  need(typeof signatureB64 === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signatureB64),
    'SIGNATURE_ENCODING');
  const msg = messageForR180(payload, binding, nowUtc);
  const sig = Buffer.from(signatureB64, 'base64');
  need(sig.length === 64, 'SIGNATURE_LENGTH');
  return crypto.verify(null, msg, publicKey, sig);
}
module.exports = Object.freeze({
  SCHEMA, CANDIDATE_SHA, HOST, DROPLET, DOMAIN, APPROVAL_FIELDS,
  EFFECT_FIELDS, canonicalAscii, checkApproval, messageForR180,
  signSyntheticR180, verifySyntheticR180,
});
