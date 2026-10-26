'use strict';
// Authenticated pure int32 policy operations. No code upload, native execution,
// private-policy projection, session renewal or side-effecting VM instructions.
const crypto = require('node:crypto');
const deadline = require('../runtime/peace.desktop-deadline');
const store = require('../bootstrap/peace.desktop-bootstrap-store');
const registry = require('./peace.server-policy-registry');
const policy = require('../artifacts/peace.server-policy-protection');
const DOMAIN = 'COZY-SERVER-OPERATION-V1', TTL = 30000, MAX_PENDING = 256, MAX_CONTEXTS = 1024;
const pending = new Map(), rates = new Map(), epoch = crypto.randomBytes(24).toString('hex');
const COMMON = ['action','stage','sessionId','sessionToken','machineId','requestId','policyId','functionId','args'];
const sha = input => crypto.createHash('sha512').update(input).digest('hex');
function Fail(reason, status = 403) { const e = Error('COZY_OPERATION_' + reason); e.desktopError = true; e.status = status; throw e; }
function Fields(body, invoke = false) {
  const names = invoke ? [...COMMON,'challengeId','signature'] : COMMON;
  if (!body || Object.getPrototypeOf(body) !== Object.prototype || Object.keys(body).length !== names.length || names.some(k => !Object.hasOwn(body,k)) ||
      body.action !== (invoke ? 'invoke' : 'challenge') || !['A','B','O'].includes(body.stage) ||
      typeof body.sessionId !== 'string' || !/^[A-F0-9]{24}$/.test(body.sessionId) ||
      typeof body.sessionToken !== 'string' || body.sessionToken.length < 16 || body.sessionToken.length > 200 ||
      typeof body.machineId !== 'string' || !/^[A-F0-9]{64}$/.test(body.machineId) ||
      typeof body.requestId !== 'string' || !/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId) ||
      typeof body.policyId !== 'string' || !/^[a-f0-9]{64}$/.test(body.policyId) ||
      !Number.isInteger(body.functionId) || body.functionId < 2 || body.functionId > 65535 ||
      !Array.isArray(body.args) || body.args.length > 8 || !body.args.every(n => Number.isInteger(n) && n >= -2147483648 && n <= 2147483647) ||
      invoke && (typeof body.challengeId !== 'string' || !/^[a-f0-9]{48}$/.test(body.challengeId) ||
        typeof body.signature !== 'string' || !/^[A-Za-z0-9+/]{342}==$/.test(body.signature))) Fail('INPUT_INVALID',400);
}
function Context(body) { return body.stage + ':' + body.sessionId; }
function ArgsHash(body) { return sha(JSON.stringify(body.args)); }
function Binding(body) { return sha([DOMAIN,body.stage,body.sessionId,body.machineId,body.policyId,String(body.functionId),body.requestId,ArgsHash(body)].join('\n')); }
function Canonical(body, c) { return [DOMAIN,body.stage,body.sessionId,body.machineId,body.policyId,String(body.functionId),body.requestId,ArgsHash(body),Binding(body),c.challengeId,c.nonce,c.epoch,String(c.revision),String(c.operationsRevision),String(c.expiresAt)].join('\n'); }
function Expired(c) { return !c || Date.now() < c.issuedAt || deadline.Expired(c); }
function Maintain() {
  for (const [id,c] of pending) if (Expired(c)) pending.delete(id);
  for (const [id,r] of rates) if (Expired(r)) rates.delete(id);
}
function Current(body, fresh) {
  const boot = require('../bootstrap/peace.desktop-bootstrap'); boot.EnsureSecurityAvailable();
  const row = boot.AuthenticateIntegrityReport(body), db = store.Load();
  require('../devices/peace.desktop-device-identity').AssertSession(row,body.stage);
  if (body.stage !== 'O') boot.RequireFlowPair(row);
  const record = registry.InvocationRecord(db,row,body.stage,body.policyId,body.functionId,body.args);
  if (body.stage === 'B') {
    const license = require('../licensing/peace.desktop-licenses').DB().licenses[row.licenseId], now = Date.now();
    if (!license || !license.consumed || license.status !== 'USED' || license.releasedAt ||
        license.deviceId !== row.deviceId || license.bootstrapSessionId !== row.sessionId ||
        license.expiresAt && license.expiresAt <= now || now < license.activatedAt ||
        !Number.isSafeInteger(row.licenseLeaseExpiresAt) || row.licenseLeaseExpiresAt <= now || now < (row.lastVerifiedAt || 0)) Fail('LICENSE_REQUIRED');
  }
  // O authentication already checks the live exact parent/license cohort.
  const authority = require('./peace.desktop-security-authority');
  const artifact = db.artifacts[body.stage === 'A' ? db.launchers[row.launcherId].artifactId : row.releaseId];
  authority.RequireArtifact(artifact);
  if (fresh) {
    require('../integrity/peace.desktop-integrity-reports').RequireSnapshot(row,body.stage);
    authority.RequireFresh(row,body.stage,'observe',Binding(body));
  }
  return {row,record,artifact};
}
function Revisions() { return {revision:require('./peace.desktop-security-authority').Policy().revision,operationsRevision:require('./peace.desktop-security-operations').Revision()}; }
function Challenge(body) {
  Fields(body); Maintain(); const {row,artifact} = Current(body,false), context = Context(body);
  let rate = rates.get(context);
  if (!rate) { if (rates.size >= MAX_CONTEXTS) Fail('CAPACITY',429); rate = {count:0,issuedAt:Date.now(),...deadline.After(60000)}; rates.set(context,rate); }
  if (++rate.count > 32 || pending.size >= MAX_PENDING || [...pending.values()].filter(c => c.context === context).length >= 4) Fail('RATE_LIMIT',429);
  // One request ID cannot have parallel challenges for different arguments.
  if ([...pending.values()].some(c => c.context === context && c.requestId === body.requestId)) Fail('REQUEST_REUSED',409);
  const c = {challengeId:crypto.randomBytes(24).toString('hex'),nonce:crypto.randomBytes(24).toString('hex'),epoch,
    ...Revisions(),issuedAt:Date.now(),...deadline.After(TTL),context,requestId:body.requestId,binding:Binding(body),
    artifactId:artifact.id,artifactSha512:artifact.sha512,publicKeyHash:sha(row.publicKey),proofQueued:false};
  pending.set(c.challengeId,c);
  return {version:1,challengeId:c.challengeId,nonce:c.nonce,epoch,revision:c.revision,operationsRevision:c.operationsRevision,
    expiresAt:c.expiresAt,binding:c.binding,argsSha512:ArgsHash(body)};
}
function Pending(body, current) {
  Maintain(); const c = pending.get(body.challengeId), rev = Revisions();
  if (!c || Expired(c) || c.context !== Context(body) || c.binding !== Binding(body) ||
      c.revision !== rev.revision || c.operationsRevision !== rev.operationsRevision ||
      c.artifactId !== current.artifact.id || c.artifactSha512 !== current.artifact.sha512 || c.publicKeyHash !== sha(current.row.publicKey)) Fail('CHALLENGE_INVALID',401);
  return c;
}
function ProofTasks(body) {
  if (body?.action !== 'invoke') return [];
  Fields(body,true); const current = Current(body,false), c = Pending(body,current);
  if (c.proofQueued) Fail('REQUEST_REUSED',409);
  const job = require('../integrity/peace.desktop-proof-work').Job(current.row.publicKey,Canonical(body,c),body.signature);
  c.proofQueued = true; // A timed-out queued proof cannot be replayed or retried.
  return [job];
}
function Invoke(body) {
  Fields(body,true); const current = Current(body,false), c = Pending(body,current);
  pending.delete(c.challengeId); // Exactly one attempt; no cached result capability.
  if (!require('../integrity/peace.desktop-proof-work').Verify(current.row.publicKey,Canonical(body,c),body.signature)) Fail('SIGNATURE_INVALID',401);
  const checked = Current(body,true);
  if (Expired(c) || checked.artifact.id !== c.artifactId || checked.artifact.sha512 !== c.artifactSha512) Fail('CHALLENGE_INVALID',401);
  // Deliberately bounded synchronous commit: <=1024 VM steps, <=8 int32 args,
  // <=16 functions and <=3952 program bytes. No await can outlive authorization.
  const result = policy.EvaluateServerPolicy(checked.record,body.functionId,body.args);
  Current(body,true); if (Expired(c)) Fail('CHALLENGE_INVALID',401);
  if (!Number.isInteger(result) || result < -2147483648 || result > 2147483647) Fail('RESULT_INVALID',503);
  return {version:1,requestId:body.requestId,policyId:body.policyId,functionId:body.functionId,result};
}
function Execute(body) {
  require('../protocol/peace.desktop-request-protocol').Resolve('policy',body?.action);
  return body.action === 'challenge' ? Challenge(body) : Invoke(body);
}
function RetireContext(row,stage) { const context = stage + ':' + (stage === 'A' ? row.id : row.sessionId); for (const [id,c] of pending) if (c.context === context) pending.delete(id); rates.delete(context); }
function Stop() { pending.clear(); rates.clear(); }
module.exports = { DOMAIN, Binding, Canonical, Execute, ProofTasks, Maintain, RetireContext, Stop };
