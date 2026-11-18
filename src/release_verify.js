'use strict';
// R171 integration contract, NOT an authorization verifier. Checks only detached RELEASE signature.
const crypto=require('node:crypto');
const {messageFor}=require('./release_sign.js');
const HEX=/^[a-f0-9]{64}$/;
function verify(data, releasePublicSpkiPem, expectedApproval, expectedArchive, expectedFingerprint) {
  if (!data || typeof data!=='object' || Array.isArray(data) ||
      Object.keys(data).sort().join(',')!==[
       'approval_sha256','archive_sha256','domain','grant_created','lease_acquired',
       'note','production_modified','release_public_fingerprint_sha256',
       'schema','signature_b64'].sort().join(',')) return false;
  if (data.schema!=='aios.ao14.r171.release-digest-signature.v1' ||
      data.domain!=='AIOS.AO14.R171.RELEASE.DIGESTS.V1' ||
      data.approval_sha256!==expectedApproval || data.archive_sha256!==expectedArchive ||
      data.release_public_fingerprint_sha256!==expectedFingerprint || !HEX.test(expectedFingerprint) ||
      data.grant_created!==false || data.lease_acquired!==false || data.production_modified!==false ||
      data.note!=='PUBLIC_DIGEST_SIGNATURE_ONLY__NOT_A_NATIVE_L4_GRANT' ||
      typeof data.signature_b64!=='string'|| !/^[A-Za-z0-9+/]{86}==$/.test(data.signature_b64)) return false;
  try {
    const pub=crypto.createPublicKey(releasePublicSpkiPem);
    if(pub.asymmetricKeyType!=='ed25519')return false;
    const raw=pub.export({format:'der',type:'spki'});
    const prefix=Buffer.from('302a300506032b6570032100','hex');
    if (raw.length!==44 || !raw.subarray(0,12).equals(prefix))return false;
    if(crypto.createHash('sha256').update(raw.subarray(12)).digest('hex')!==expectedFingerprint)return false;
    const signature=Buffer.from(data.signature_b64,'base64');
    return signature.length===64 && crypto.verify(null,messageFor(expectedApproval,expectedArchive),pub,signature);
  } catch {return false;}
}
module.exports={verify};
