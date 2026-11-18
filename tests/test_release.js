'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const c=require('node:crypto');
const {messageFor,sign}=require('../src/release_sign.js');const {verify}=require('../src/release_verify.js');
const sha=(v)=>c.createHash('sha256').update(v).digest('hex');
const a='a'.repeat(64), b='b'.repeat(64);
function material(){let k=c.generateKeyPairSync('ed25519');let raw=k.publicKey.export({format:'der',type:'spki'});return {...k,fp:sha(raw.subarray(12)),pem:k.publicKey.export({format:'pem',type:'spki'})};}
test('R171 synthetic positive valid digest signature',()=>{let k=material();let receipt=sign(a,b,k.privateKey,k.fp);assert.equal(verify(receipt,k.pem,a,b,k.fp),true);});
test('reject approval digest drift',()=>{let k=material(),r=sign(a,b,k.privateKey,k.fp);assert.equal(verify(r,k.pem,'c'.repeat(64),b,k.fp),false)});
test('reject archive digest drift',()=>{let k=material(),r=sign(a,b,k.privateKey,k.fp);assert.equal(verify(r,k.pem,a,'c'.repeat(64),k.fp),false)});
test('reject wrong public key',()=>{let k=material(),q=material(),r=sign(a,b,k.privateKey,k.fp);assert.equal(verify(r,q.pem,a,b,q.fp),false)});
test('reject trust fingerprint mismatch at signer',()=>{let k=material();assert.throws(()=>sign(a,b,k.privateKey,'0'.repeat(64)),/HOLD_KEY_TRUST_MISMATCH/)});
test('reject malformed approval digest',()=>assert.throws(()=>messageFor('ABC',b),/HOLD_APPROVAL_SHA256_INVALID/));
test('reject malformed archive digest',()=>assert.throws(()=>messageFor(a,'B'.repeat(64)),/HOLD_ARCHIVE_SHA256_INVALID/));
test('reject signature tamper',()=>{let k=material(),r=sign(a,b,k.privateKey,k.fp);r.signature_b64=Buffer.alloc(64,4).toString('base64');assert.equal(verify(r,k.pem,a,b,k.fp),false)});
test('reject extra authority claims',()=>{let k=material(),r=sign(a,b,k.privateKey,k.fp);r.status='GRANTED';assert.equal(verify(r,k.pem,a,b,k.fp),false)});
test('reject false grant flag',()=>{let k=material(),r=sign(a,b,k.privateKey,k.fp);r.grant_created=true;assert.equal(verify(r,k.pem,a,b,k.fp),false)});
test('reject no/github main run',()=>{const {spawnSync}=require('node:child_process');let p=spawnSync(process.execPath,['src/release_sign.js'],{cwd:require('node:path').resolve(__dirname,'..'),env:{...process.env,GITHUB_ACTIONS:'false'},encoding:'utf8'});assert.equal(p.status,73);assert.match(p.stderr,/HOLD_ONLY_REVIEWED_GITHUB_MAIN_RUN/)});
test('reject unpinned repository',()=>{const {spawnSync}=require('node:child_process');let p=spawnSync(process.execPath,['src/release_sign.js'],{cwd:require('node:path').resolve(__dirname,'..'),env:{...process.env,GITHUB_ACTIONS:'true',GITHUB_REF:'refs/heads/main',AO14_RELEASE_REPO:'different/repo'},encoding:'utf8'});assert.equal(p.status,73);assert.match(p.stderr,/HOLD_REPOSITORY_NOT_PINNED/)});
