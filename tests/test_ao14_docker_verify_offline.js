'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const crypto=require('node:crypto');
const m=require('../src/ao14_docker_verify_offline.js');
const now='2026-11-20T13:00:20Z';
function keys(){return Object.fromEntries(['OWNER','RELEASE','HOST'].map(k=>[k,crypto.generateKeyPairSync('ed25519')]));}
function pubkey(k){return k.publicKey.export({format:'der',type:'spki'}).subarray(12);}
function toB64(buf){return buf.toString('base64');}
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
function fixture(){
  const k=keys(), pins=Object.fromEntries(Object.entries(k).map(([r,v])=>[r,pubkey(v)]));
  const rawData={captured_at:'2026-11-20T13:00:00Z',nonce:'c'.repeat(32),host_id:m.P.host,
    droplet_id:m.P.droplet,target_path:m.P.path,target_absent:true,
    docker_socket_owner:'root:docker',docker_socket_mode:'0660',docker_socket_active:true,
    ao14_ops_path_active:true,postgres_hba_sha256:'a'.repeat(64),postgres_ident_sha256:'b'.repeat(64)};
  const raw_readback=m.canonical(rawData);
  const payload={schema:m.P.schema,action:m.P.action,host_id:m.P.host,droplet_id:m.P.droplet,
    candidate_zip_sha256:m.P.zip,approval_payload_sha256:m.P.approval,new_file_sha256:m.P.file,
    target_path:m.P.path,signing_time_readback_sha256:sha(raw_readback),nonce:'c'.repeat(32),
    issued_at:'2026-11-20T13:00:10Z',expires_at:'2026-11-20T13:15:10Z',max_executions:1,data_class:'INTERNAL'};
  const host_receipt={schema:m.P.hostSchema,issuer_key_id:m.P.hostIssuer,host_id:m.P.host,
    droplet_id:m.P.droplet,readback_sha256:sha(raw_readback),nonce:'c'.repeat(32),issued_at:'2026-11-20T13:00:05Z'};
  const sign=(role)=>toB64(crypto.sign(null,Buffer.concat([m.P.domain,Buffer.from(role+'\0'),m.canonical(payload)]),k[role].privateKey));
  const hostSignature=()=>toB64(crypto.sign(null,Buffer.concat([m.P.hostDomain,m.canonical(host_receipt)]),k.HOST.privateKey));
  const bundle={payload,signatures:{OWNER:sign('OWNER'),RELEASE:sign('RELEASE')},raw_readback,
    host_receipt,host_signature:hostSignature()};
  return {k,pins,bundle,sign,hostSignature};
}
function pass(){let f=fixture();return m.verifyOffline(f.bundle,f.pins,now);}
function fail(title,mutate,code){test(title,()=>{
  const f=fixture();mutate(f);
  assert.throws(()=>m.verifyOffline(f.bundle,f.pins,now),x=>x.message.includes('HOLD_'+code));
});}
test('valid synthetic tripartite signature and exact Docker action',()=>{
 const result=pass();assert.equal(result.gate,'OFFLINE_CRYPTO_FORMAT_PASS__NOT_AUTHORITY');
 assert.equal(result.native_granted,false);assert.equal(result.execution_enabled,false);
});
fail('reject R175 candidate even if used as a replacement',f=>{f.bundle.payload.candidate_zip_sha256='a47637dcc0e46f610f3ea8d7f43109c21094a5ada3264f157354acb71925dea8';},'DOCKER_ZIP_BINDING');
fail('reject R175 registrar action',f=>{f.bundle.payload.action='INSTALL_R175_REGISTRAR';},'DOCKER_ACTION_SCHEMA');
fail('reject wrong Docker drop-in SHA',f=>{f.bundle.payload.new_file_sha256='0'.repeat(64);},'DOCKER_TARGET_BINDING');
fail('reject wrong target path',f=>{f.bundle.payload.target_path='/etc/systemd/system/docker.service';},'DOCKER_TARGET_BINDING');
fail('reject data class deviation',f=>{f.bundle.payload.data_class='PUBLIC';},'DOCKER_POLICY');
fail('reject 2 executions',f=>{f.bundle.payload.max_executions=2;},'DOCKER_POLICY');
fail('reject malformed nonce',f=>{f.bundle.payload.nonce='1';},'DOCKER_NONCE');
fail('reject 901 sec scope',f=>{f.bundle.payload.expires_at='2026-11-20T13:15:11Z';},'DOCKER_900S_WINDOW');
test('reject expired scope',()=>{const f=fixture();assert.throws(()=>m.verifyOffline(f.bundle,f.pins,'2026-11-20T13:15:10Z'),/HOLD_DOCKER_EXPIRED/);});
fail('reject payload extra field',f=>{f.bundle.payload.release_authorized=true;},'DOCKER_PAYLOAD_SCHEMA');
fail('reject supplied forged trusted-readback prefix',f=>{f.bundle.host_receipt='trusted-readback:user-supplied';},'HOST_RECEIPT_SCHEMA');
fail('reject altered raw readback hash',f=>{f.bundle.raw_readback=Buffer.concat([f.bundle.raw_readback,Buffer.from(' ')]);},'DOCKER_READBACK_HASH_MISMATCH');
fail('reject modified readback nonce',f=>{const d=JSON.parse(f.bundle.raw_readback);d.nonce='b'.repeat(32);f.bundle.raw_readback=m.canonical(d);f.bundle.payload.signing_time_readback_sha256=sha(f.bundle.raw_readback);f.bundle.host_receipt.readback_sha256=sha(f.bundle.raw_readback);},'READBACK_NONCE');
fail('reject preexisting target',f=>{const d=JSON.parse(f.bundle.raw_readback);d.target_absent=false;f.bundle.raw_readback=m.canonical(d);f.bundle.payload.signing_time_readback_sha256=sha(f.bundle.raw_readback);f.bundle.host_receipt.readback_sha256=sha(f.bundle.raw_readback);},'READBACK_TARGET_STATE');
fail('reject host receipt unsigned',f=>{f.bundle.host_signature='';},'SIG_ENCODING');
fail('reject host receipt signature from wrong key',f=>{f.bundle.host_signature=toB64(crypto.sign(null,Buffer.concat([m.P.hostDomain,m.canonical(f.bundle.host_receipt)]),f.k.OWNER.privateKey));},'HOST_SIGNATURE_INVALID');
fail('reject corrupted RELEASE signature',f=>{f.bundle.signatures.RELEASE=f.bundle.signatures.OWNER;},'RELEASE_SIGNATURE_INVALID');
fail('reject corrupted OWNER signature',f=>{f.bundle.signatures.OWNER=f.bundle.signatures.RELEASE;},'OWNER_SIGNATURE_INVALID');
fail('reject missing RELEASE signature',f=>{delete f.bundle.signatures.RELEASE;},'ROLE_SIGNATURE_SET');
fail('reject role key collision',f=>{f.pins.RELEASE=f.pins.OWNER;},'TRUST_PIN_COLLISION');
fail('reject HOST / OWNER key collision',f=>{f.pins.HOST=f.pins.OWNER;},'TRUST_PIN_COLLISION');
fail('reject payload tamper after both signatures',f=>{f.bundle.payload.nonce='d'.repeat(32);},'READBACK_NONCE');
fail('reject host receipt wrong signed nonce',f=>{f.bundle.host_receipt.nonce='d'.repeat(32);},'HOST_RECEIPT_BINDING');
fail('reject host receipt different host',f=>{f.bundle.host_receipt.host_id='intruder';},'HOST_RECEIPT_HOST');
fail('reject future host receipt',f=>{f.bundle.host_receipt.issued_at='2026-11-20T13:01:05Z';},'HOST_RECEIPT_NOT_FRESH');
fail('reject raw PG hash omitted',f=>{const d=JSON.parse(f.bundle.raw_readback);delete d.postgres_hba_sha256;f.bundle.raw_readback=m.canonical(d);f.bundle.payload.signing_time_readback_sha256=sha(f.bundle.raw_readback);f.bundle.host_receipt.readback_sha256=sha(f.bundle.raw_readback);},'READBACK_PG_HASH');
fail('reject malformed data type',f=>{f.bundle.payload.droplet_id='603086247';},'DOCKER_HOST');
fail('reject owner signed using R175 domain',f=>{f.bundle.signatures.OWNER=toB64(crypto.sign(null,Buffer.concat([Buffer.from('AIOS-AO14-R180-R175-APPROVAL-V1\0'),m.canonical(f.bundle.payload)]),f.k.OWNER.privateKey));},'OWNER_SIGNATURE_INVALID');
