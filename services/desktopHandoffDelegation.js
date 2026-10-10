'use strict';
// Versioned parent authorization + child proof of possession. No private key
// crosses a process boundary. The enclosing authenticated transport supplies
// the server-issued canonical; its digest binds role, build, session and expiry.
const crypto=require('node:crypto');
const VERSION=3,MARKER='GAME-HANDOFF-V3',FIELDS=['handoffVersion','childPublicKey','childKeyId','childNonce','delegationSignature'];
const sha512=value=>crypto.createHash('sha512').update(value).digest('hex');
function Fail(code='BOOTSTRAP_PROOF_INVALID',status=401){require('./desktopBootstrap').Fail(code,status);}
// This is a compatibility declaration, never evidence of runtime protection.
// Only initialized PE section bytes count: an appended marker, certificate or
// overlay cannot upgrade a legacy template. Exact file approval still applies.
function ArtifactVersion(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<64)Fail('BOOTSTRAP_PE_INVALID',400);
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24)Fail('BOOTSTRAP_PE_INVALID',400);
 const count=bytes.readUInt16LE(pe+6),table=pe+24+bytes.readUInt16LE(pe+20);if(count<1||count>96||table>bytes.length-count*40)Fail('BOOTSTRAP_PE_INVALID',400);
 for(let i=0;i<count;i++){const p=table+i*40,size=bytes.readUInt32LE(p+16),offset=bytes.readUInt32LE(p+20),flags=bytes.readUInt32LE(p+36);if(size>bytes.length||offset>bytes.length-size)Fail('BOOTSTRAP_PE_INVALID',400);if(!(flags&0x40000000))continue;const section=bytes.subarray(offset,offset+size);if(section.includes(Buffer.from(MARKER))||section.includes(Buffer.from(MARKER,'utf16le')))return VERSION;}
 return 1;
}
function Version(row){return row?.handoffVersion===undefined?1:row.handoffVersion;}
function RequirePair(...rows){const present=rows.filter(Boolean),version=Version(present[0]);if(![1,VERSION].includes(version)||present.some(r=>Version(r)!==version))Fail('BOOTSTRAP_HANDOFF_VERSION_MISMATCH',409);return version;}
function Canonical(kind,role,canonical,keyId,nonce){if(!['DELEGATION','CLAIM'].includes(kind)||!['B','O'].includes(role))throw Error('HANDOFF_DOMAIN_INVALID');return ['GAME-HANDOFF-'+kind+'-V3',role,sha512(Buffer.from(canonical,'utf8')),keyId,nonce].join('\n');}
function Parent(row){return {deviceId:row.parentDeviceId||row.deviceId,publicKey:row.parentPublicKey||row.publicKey};}
function Check(row,body,role,canonical){
 if(Version(row)!==VERSION){if(FIELDS.some(k=>body[k]!==undefined))Fail('BOOTSTRAP_HANDOFF_VERSION_MISMATCH',409);require('./desktopBootstrap').Verify(row,canonical,body.signature);return null;}
 if(body.handoffVersion!==VERSION)Fail('BOOTSTRAP_HANDOFF_VERSION_MISMATCH',409);
 if(!/^[A-F0-9]{64}$/.test(body.childKeyId||'')||!/^[A-F0-9]{64}$/.test(body.childNonce||''))Fail();
 const child=require('./desktopLicenses').ParseKey(body.childPublicKey),parent=Parent(row);
 if(child.deviceId!==body.childKeyId||child.deviceId===parent.deviceId)Fail();
 require('./desktopBootstrap').Verify(parent,Canonical('DELEGATION',role,canonical,child.deviceId,body.childNonce),body.delegationSignature);
 require('./desktopBootstrap').Verify(child,Canonical('CLAIM',role,canonical,child.deviceId,body.childNonce),body.signature);
 return {publicKey:child.publicKey,deviceId:child.deviceId,nonce:body.childNonce};
}
function Fingerprint(body){return sha512(JSON.stringify([body.handoffVersion,body.childPublicKey,body.childKeyId,body.childNonce,body.delegationSignature,body.signature,body.binarySha512,body.crc64,body.bCodeSha512||body.oCodeSha512,body.bCodeCrc64||body.oCodeCrc64]));}
function ValidateIdentity(row){
 if(![1,VERSION].includes(Version(row)))throw Error('HANDOFF_STORE_INVALID');
 if(Version(row)===1){if(['parentDeviceId','parentPublicKey','childNonce','delegatedClaimFingerprint','delegatedClaimRecoveryUntil'].some(k=>row[k]!==undefined))throw Error('HANDOFF_STORE_INVALID');return;}
 const key=require('./desktopLicenses').ParseKey(row.publicKey),parent=require('./desktopLicenses').ParseKey(row.parentPublicKey);
 if(key.deviceId!==row.deviceId||parent.deviceId!==row.parentDeviceId)throw Error('HANDOFF_STORE_INVALID');
 const delegated=row.childNonce!==undefined;
 if(delegated){if(!/^[A-F0-9]{64}$/.test(row.childNonce)||row.deviceId===row.parentDeviceId||!/^[a-f0-9]{128}$/.test(row.delegatedClaimFingerprint||'')||!Number.isSafeInteger(row.delegatedClaimRecoveryUntil)||row.delegatedClaimRecoveryUntil<row.claimedAt||row.delegatedClaimRecoveryUntil>Math.min(row.handoffExpiresAt||row.expiresAt,row.claimedAt+30000))throw Error('HANDOFF_STORE_INVALID');}
 else if(row.deviceId!==row.parentDeviceId||row.publicKey!==row.parentPublicKey||row.delegatedClaimFingerprint!==undefined||row.delegatedClaimRecoveryUntil!==undefined||row.status==='CLAIMED')throw Error('HANDOFF_STORE_INVALID');
}
module.exports={VERSION,MARKER,FIELDS,ArtifactVersion,Version,RequirePair,Canonical,Parent,Check,Fingerprint,ValidateIdentity};
