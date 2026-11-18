'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const r = require('../src/r180_release_offline.js');
const payload = require('./fixtures/r180_synthetic_approval.json');
const clock = '2026-11-18T11:45:00Z';
const binding = Object.freeze({
  scope_id: payload.scope_id,
  source_sha256: 'b'.repeat(64),
  host_state_sha256: 'c'.repeat(64),
  human_approval_text_sha256: 'd'.repeat(64),
  candidate_commit_sha: null,
});
const clone = () => structuredClone(payload);
const keys = crypto.generateKeyPairSync('ed25519'); // only ephemeral TEST key
function rejected(fn, code) {
  assert.throws(fn, (e) => e.message.startsWith('HOLD_' + code));
}
const fixtures = [
  ['old R171 schema', (p) => {p.schema = 'aios.ao14.r171.release-digest-signature.v1';}, 'APPROVAL_SCHEMA'],
  ['old candidate', (p) => {p.candidate_sha256 = '0'.repeat(64);}, 'CANDIDATE_SHA_MISMATCH'],
  ['wrong host', (p) => {p.host_id = 'other-host';}, 'HOST_MISMATCH'],
  ['wrong droplet', (p) => {p.droplet_id = 1;}, 'HOST_MISMATCH'],
  ['bool droplet', (p) => {p.droplet_id = true;}, 'HOST_MISMATCH'],
  ['wrong action', (p) => {p.action = 'DELETE_ARCHIVE';}, 'ACTION_DRIFT'],
  ['scope drift', (p) => {p.scope_id = 'APV-AO14-R186-SYNTHETIC-OTHER';}, 'APPROVAL_SCOPE_MISMATCH'],
  ['source mismatch', (p) => {p.source_sha256 = 'a'.repeat(64);}, 'SOURCE_SHA256_MISMATCH'],
  ['host state mismatch', (p) => {p.host_state_sha256 = 'a'.repeat(64);}, 'HOST_STATE_SHA256_MISMATCH'],
  ['human approval drift', (p) => {p.human_approval_text_sha256 = 'a'.repeat(64);}, 'HUMAN_APPROVAL_TEXT_SHA256_MISMATCH'],
  ['git commit ZIP SHA invalid', (p) => {p.candidate_commit_sha = 'a'.repeat(64);}, 'GIT_COMMIT_SHA_MISMATCH'],
  ['risk downgrade', (p) => {p.risk_lane = 'L1';}, 'RISK_OR_DATA_CLASS_MISMATCH'],
  ['class downgrade', (p) => {p.data_class = 'PUBLIC';}, 'RISK_OR_DATA_CLASS_MISMATCH'],
  ['double execution', (p) => {p.max_executions = 2;}, 'MAX_EXECUTIONS'],
  ['malformed nonce', (p) => {p.nonce = 'z'.repeat(64);}, 'NONCE_INVALID'],
  ['identical principal', (p) => {p.release_principal = p.owner_principal;}, 'SIGNER_PRINCIPALS_NOT_SEPARATE'],
  ['identical custody', (p) => {p.release_custody_domain = p.owner_custody_domain;}, 'CUSTODY_DOMAINS_NOT_SEPARATE'],
  ['missing custody digest', (p) => {p.custody_evidence_sha256 = '';}, 'CUSTODY_EVIDENCE_UNPINNED'],
  ['expired', (p) => {p.expires_utc = '2026-11-18T11:44:59Z';}, 'APPROVAL_WINDOW_INVALID'],
  ['long expiry', (p) => {p.expires_utc = '2026-11-18T12:20:00Z';}, 'APPROVAL_WINDOW_INVALID'],
  ['issued in future', (p) => {p.issued_utc = '2026-11-18T11:46:00Z';}, 'APPROVAL_WINDOW_INVALID'],
  ['untrusted date', (p) => {p.issued_utc = 'yesterday';}, 'BAD_UTC_DATE'],
  ['extra field', (p) => {p.inject = true;}, 'APPROVAL_FIELDS'],
  ['missing field', (p) => {delete p.action;}, 'APPROVAL_FIELDS'],
];
test('Python R180 canonical JSON exact golden vector (synthetic)', () => {
  assert.equal(crypto.createHash('sha256').update(Buffer.from(r.canonicalAscii(payload),'ascii')).digest('hex'),
    '54d58a83ecf52f991d9dcb5f53adddee77f4e02a955361f5734bebb3a10c4205');
});
test('Python R180 domain + canonical payload golden vector', () => {
  const msg = r.messageForR180(payload,binding,clock);
  assert.equal(crypto.createHash('sha256').update(msg).digest('hex'),
    'be5ff31690a528c7c31d2ba28a4afbbca90abfbd3cd483cd7306ff6547897754');
});
test('Python ensure_ascii=True canonical Unicode vector', () => {
  const p = clone(); p.owner_principal='OWNER-ÖRNEK-SYNTHETIC';
  assert.equal(crypto.createHash('sha256').update(Buffer.from(r.canonicalAscii(p),'ascii')).digest('hex'),
    '3f1d927c34fdf19a2d43cc3206e3a2a476c85b783db7b6555a5d6d76d3561e75');
});
test('R180 approval schema exactly 29 fields', () => assert.equal(Object.keys(payload).length,29));
test('synthetic sign, verify, tamper, and R171 domain rejection', () => {
  const receipt=r.signSyntheticR180(payload,binding,clock,keys.privateKey);
  assert.equal(receipt.gate,'SYNTHETIC_SIGNATURE_ONLY');
  assert.equal(receipt.native_granted,false);
  assert.equal(receipt.native_lease_acquired,false);
  assert.equal(Buffer.from(receipt.signature_b64,'base64').length,64);
  assert.equal(r.verifySyntheticR180(payload,binding,clock,receipt.signature_b64,keys.publicKey),true);
  const changed=clone();changed.nonce='a'.repeat(64);
  assert.equal(r.verifySyntheticR180(changed,binding,clock,receipt.signature_b64,keys.publicKey),false);
  const legacy=Buffer.from('AIOS.AO14.R171.RELEASE.DIGESTS.V1\0'+'a'.repeat(64)+'\n'+'b'.repeat(64)+'\n');
  assert.equal(crypto.verify(null,legacy,keys.publicKey,Buffer.from(receipt.signature_b64,'base64')),false);
});
test('reject real scope signing (R186 synthetic only)',()=>{
  const p=clone();p.scope_id='APV-AO14-R180-LIVE-NOT-APPROVED';
  rejected(()=>r.signSyntheticR180(p,{...binding,scope_id:p.scope_id},clock,keys.privateKey),'R186_SYNTHETIC_ONLY');
});
test('reject wrong key algorithm',()=>{
  const other=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
  rejected(()=>r.signSyntheticR180(payload,binding,clock,other.privateKey),'SYNTHETIC_ED25519_KEY_REQUIRED');
});
test('reject missing binding',()=>rejected(()=>r.checkApproval(payload,{},clock),'BINDING_FIELDS'));
test('binding without independent source is not implied',()=>{
  const b={...binding,source_sha256:'a'.repeat(64)};
  rejected(()=>r.checkApproval(payload,b,clock),'SOURCE_SHA256_MISMATCH');
});
test('reject ZIP sha placed into 40hex Git field',()=>{
  const b={...binding,candidate_commit_sha:r.CANDIDATE_SHA};
  rejected(()=>r.checkApproval(payload,b,clock),'GIT_COMMIT_SHA_MISMATCH');
});
test('reject all prohibited effects',()=>{
  for (const field of r.EFFECT_FIELDS) {
    const p=clone();p[field]=true;
    rejected(()=>r.checkApproval(p,binding,clock),'EFFECT_NOT_ALLOWED:'+field);
  }
});
test('JSON canonicalizer forbids floats/arrays/prototypes',()=>{
  for(const x of [1.2,NaN,Infinity,[],new Date(),-0])rejected(()=>r.canonicalAscii(x),'UNSUPPORTED_JSON_');
});
test('zero I/O and no secret-bearing environment interface',()=>{
  const fs=require('node:fs');const src=fs.readFileSync(require.resolve('../src/r180_release_offline.js'),'utf8');
  for(const x of ['process.env','fetch(','https.request','http.request','fs.readFile','child_process','workflow_dispatch','SECRET_PKCS8']){
    assert.equal(src.includes(x),false,x);
  }
});
for(const [title,mutate,code] of fixtures){test('HOLD: '+title,()=>{const p=clone();mutate(p);rejected(()=>r.checkApproval(p,binding,clock),code);});}
