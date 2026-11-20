'use strict';
/**
 * AO14 Docker L4 stage, VERIFY-ONLY wire-compatible offline reference.
 * Zero key generation, no sign(), no secrets, no SQL, no service execution.
 * This code cannot itself grant an Approval Scope or acquire a Lease.
 * Trust pins/clock/nonce consumption require independent production components.
 */
const crypto = require('node:crypto');
const P = Object.freeze({
  schema:'aios.ao14.l4.docker-stage-v1',
  host:'host_2f4fb8189204a537', droplet:603086247,
  action:'STAGE_EXACT_DOCKER_SOCKET_DROPIN_ONLY',
  zip:'ec436366fd205e431e0b2e5c0b535394250438a985cd441764424d69c3d00d80',
  approval:'3b343d88b3ddc4d3eb2dfd9eddfa90137081ba42dbc7d0a8ed993b9157e89de9',
  file:'86290046a524cff63452237c94a9e7d869730f9774a0fc923a21f800f5cccf25',
  path:'/etc/systemd/system/docker.socket.d/10-ao14-root-only.conf',
  domain:Buffer.from('AIOS.AO14.L4.DOCKER.STAGE.V1\0','utf8'),
  hostDomain:Buffer.from('AIOS.AO14.L4.HOST_READBACK.V2\0','utf8'),
  hostSchema:'aios.ao14.l4.host-readback-attestation-v2',
  hostIssuer:'AO14_HOST_ATTESTOR_PINNED'
});
const PAYLOAD_KEYS = [
  'schema','action','host_id','droplet_id','candidate_zip_sha256',
  'approval_payload_sha256','new_file_sha256','target_path',
  'signing_time_readback_sha256','nonce','issued_at','expires_at',
  'max_executions','data_class'
];
const RECEIPT_KEYS=['schema','issuer_key_id','host_id','droplet_id',
 'readback_sha256','nonce','issued_at'];
const HEX64=/^[a-f0-9]{64}$/;
const HEX32=/^[a-f0-9]{32}$/;
const UTC=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const SPKI_PREFIX=Buffer.from('302a300506032b6570032100','hex');
function hold(code){throw new Error('HOLD_'+code);}
function check(ok,code){if(!ok)hold(code);}
function plainObject(o){return o!==null && typeof o==='object' && !Array.isArray(o) &&
  (Object.getPrototypeOf(o)===Object.prototype || Object.getPrototypeOf(o)===null);}
function exact(o,keys,code){check(plainObject(o) && Object.keys(o).length===keys.length &&
  keys.every(k=>Object.prototype.hasOwnProperty.call(o,k)),code);}
function ascii(v){return typeof v==='string' && /^[\x20-\x7e]*$/.test(v);}
function canonical(o){
  check(plainObject(o),'CANONICAL_OBJECT_REQUIRED');
  for(const v of Object.values(o))check(ascii(v) || typeof v==='boolean' ||
    (typeof v==='number' && Number.isSafeInteger(v)) || v===null,'CANONICAL_TYPE_NOT_SUPPORTED');
  return Buffer.from('{'+Object.keys(o).sort().map(k=>{
    check(ascii(k),'CANONICAL_KEY');
    return JSON.stringify(k)+':'+JSON.stringify(o[k]);
  }).join(',')+'}','utf8');
}
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
function epoch(s){
  check(UTC.test(s),'TIME_FORMAT');
  const d=Date.parse(s);
  check(Number.isFinite(d) && new Date(d).toISOString().slice(0,19)===s.slice(0,19),'TIME_INVALID');
  return d;
}
function pub(raw){
  check(Buffer.isBuffer(raw) && raw.length===32,'TRUST_PIN_MISSING');
  try{return crypto.createPublicKey({key:Buffer.concat([SPKI_PREFIX,raw]),format:'der',type:'spki'});}
  catch {hold('TRUST_PIN_INVALID');}
}
function sigBytes(s){
  check(typeof s==='string' && /^[A-Za-z0-9+/]{86}==$/.test(s),'SIG_ENCODING');
  const b=Buffer.from(s,'base64');
  check(b.length===64 && b.toString('base64')===s,'SIG_BYTES_INVALID');
  return b;
}
function verify(sig,pin,data,which){
  check(crypto.verify(null,data,pub(pin),sigBytes(sig)),which+'_SIGNATURE_INVALID');
}
function checkPayload(p,nowMs){
  exact(p,PAYLOAD_KEYS,'DOCKER_PAYLOAD_SCHEMA');
  check(p.schema===P.schema && p.action===P.action,'DOCKER_ACTION_SCHEMA');
  check(p.host_id===P.host && p.droplet_id===P.droplet,'DOCKER_HOST');
  check(p.candidate_zip_sha256===P.zip && p.approval_payload_sha256===P.approval,'DOCKER_ZIP_BINDING');
  check(p.new_file_sha256===P.file && p.target_path===P.path,'DOCKER_TARGET_BINDING');
  check(p.data_class==='INTERNAL' && p.max_executions===1,'DOCKER_POLICY');
  check(HEX64.test(p.signing_time_readback_sha256),'DOCKER_READBACK_HASH');
  check(HEX32.test(p.nonce),'DOCKER_NONCE');
  const i=epoch(p.issued_at),e=epoch(p.expires_at);
  check(e-i>=1000 && e-i<=900000,'DOCKER_900S_WINDOW');
  check(nowMs>=i-15000 && nowMs<e,'DOCKER_EXPIRED_OR_NOT_YET_VALID');
  return i;
}
function checkReadback(raw,p,issuedMs,nowMs){
  check(Buffer.isBuffer(raw),'RAW_READBACK_NOT_BYTES');
  check(sha(raw)===p.signing_time_readback_sha256,'DOCKER_READBACK_HASH_MISMATCH');
  let o;
  try {o=JSON.parse(raw.toString('utf8'));}
  catch {hold('RAW_READBACK_JSON_INVALID');}
  check(plainObject(o),'READBACK_NOT_OBJECT');
  check(o.host_id===P.host && o.droplet_id===P.droplet,'READBACK_HOST');
  check(o.target_path===P.path && o.target_absent===true,'READBACK_TARGET_STATE');
  check(o.docker_socket_owner==='root:docker' && o.docker_socket_mode==='0660','READBACK_DOCKER_BASELINE');
  check(o.docker_socket_active===true && o.ao14_ops_path_active===true,'READBACK_SERVICE_STATE');
  check(HEX64.test(o.postgres_hba_sha256) && HEX64.test(o.postgres_ident_sha256),'READBACK_PG_HASH');
  check(o.nonce===p.nonce,'READBACK_NONCE');
  const captured=epoch(o.captured_at);
  check(issuedMs>=captured && issuedMs-captured<=120000 && captured<=nowMs+15000,'READBACK_NOT_FRESH');
  return captured;
}
function checkReceipt(r,hostSignature,hostPin,raw,p,issuedMs,capturedMs,nowMs){
  exact(r,RECEIPT_KEYS,'HOST_RECEIPT_SCHEMA');
  check(r.schema===P.hostSchema && r.issuer_key_id===P.hostIssuer,'HOST_RECEIPT_ISSUER');
  check(r.host_id===P.host && r.droplet_id===P.droplet,'HOST_RECEIPT_HOST');
  check(r.nonce===p.nonce && r.readback_sha256===sha(raw),'HOST_RECEIPT_BINDING');
  const at=epoch(r.issued_at);
  check(at>=capturedMs && at-capturedMs<=30000 && issuedMs>=at &&
    issuedMs-at<=120000 && at<=nowMs+15000,'HOST_RECEIPT_NOT_FRESH');
  verify(hostSignature,hostPin,Buffer.concat([P.hostDomain,canonical(r)]),'HOST');
}
function verifyOffline(bundle,trustPins,nowUtc){
  exact(bundle,['payload','signatures','raw_readback','host_receipt','host_signature'],'BUNDLE_SCHEMA');
  exact(trustPins,['OWNER','RELEASE','HOST'],'TRUST_PIN_SET');
  check(['OWNER','RELEASE','HOST'].every(k=>Buffer.isBuffer(trustPins[k]) && trustPins[k].length===32),
    'TRUST_PIN_MISSING');
  check(!trustPins.OWNER.equals(trustPins.RELEASE) && !trustPins.OWNER.equals(trustPins.HOST) &&
    !trustPins.RELEASE.equals(trustPins.HOST),'TRUST_PIN_COLLISION');
  exact(bundle.signatures,['OWNER','RELEASE'],'ROLE_SIGNATURE_SET');
  const nowMs=epoch(nowUtc);
  const issued=checkPayload(bundle.payload,nowMs);
  const captured=checkReadback(bundle.raw_readback,bundle.payload,issued,nowMs);
  checkReceipt(bundle.host_receipt,bundle.host_signature,trustPins.HOST,
    bundle.raw_readback,bundle.payload,issued,captured,nowMs);
  const msg=canonical(bundle.payload);
  verify(bundle.signatures.OWNER,trustPins.OWNER,
    Buffer.concat([P.domain,Buffer.from('OWNER\0'),msg]),'OWNER');
  verify(bundle.signatures.RELEASE,trustPins.RELEASE,
    Buffer.concat([P.domain,Buffer.from('RELEASE\0'),msg]),'RELEASE');
  return Object.freeze({gate:'OFFLINE_CRYPTO_FORMAT_PASS__NOT_AUTHORITY',
    payload_sha256:sha(msg),host_receipt_sha256:sha(canonical(bundle.host_receipt)),
    docker_candidate_zip_sha256:P.zip, native_granted:false,native_lease_acquired:false,execution_enabled:false});
}
module.exports=Object.freeze({verifyOffline,canonical,P});
