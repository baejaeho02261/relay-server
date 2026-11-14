'use strict';
// Each path has its own challenge, replay window, signed purpose and receipts.
// Each path independently adjudicates typed evidence and actor capabilities.
// Client reports are not a hardware observation or a license/lease grant.
const crypto = require('node:crypto');
const deadline = require('../runtime/peace.desktop-deadline');
const proof = require('../integrity/peace.desktop-proof-work');
const protocol = require('../protocol/peace.desktop-request-protocol');
const detections = require('./peace.security-detections');
const peers = require('./peace.nhw-peer-context');
const channels = ['trust', 'driver', 'integrity'];
const states = new Map(channels.map(channel => [channel, {
  pending: new Map(), order: new Map(), rates: new Map(),
  receipts: protocol.CreateReceipts({conflict: 'SECURITY_NHW_RESPONSE_REUSED'})
}]));
const AUTH = ['action', 'stage', 'sessionId', 'sessionToken', 'machineId', 'binding'];
const sha = value => crypto.createHash('sha512').update(value).digest('hex');
const plain = value => !!value && Object.getPrototypeOf(value) === Object.prototype;
function Fail(code = 'SECURITY_NHW_RESPONSE_INVALID', status = 400) {
  throw Object.assign(Error(code), {desktopError: true, status});
}
function Fields(value, names) {
  if (!plain(value) || Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) Fail();
}
function ParseAction(action) {
  const m = /^nhw(Trust|Driver|Integrity)(Challenge|Submit)$/.exec(action || '');
  return m ? {channel: m[1].toLowerCase(), verb: m[2].toLowerCase()} : null;
}
function Domain(channel) { return 'COZY-NHW-' + channel.toUpperCase() + '-RESPONSE-V1'; }
function Context(row, stage) { return stage + ':' + (stage === 'A' ? row.id : row.sessionId) + ':' + row.createdAt; }
function Authenticate(body) {
  if (!['A','B','O'].includes(body.stage) || typeof body.machineId !== 'string' || !/^[A-F0-9]{64}$/.test(body.machineId) ||
      typeof body.binding !== 'string' || !/^[a-f0-9]{128}$/.test(body.binding)) Fail();
  const boot=require('../bootstrap/peace.desktop-bootstrap');
  let row;
  try { row=boot.AuthenticateIntegrityReport(body); } catch(error) {
    // The only terminal exception is a fresh, signed diagnostic batch for an
    // exact NHW-revoked cohort. No normal authority endpoint uses this path.
    try { row=boot.AuthenticateIntegrityReceipt(body);if(!detections.TerminalAllowed(row,body.stage))throw error; } catch(_) { throw error; }
  }
  require('../devices/peace.desktop-device-identity').AssertSession(row, body.stage);
  const db = require('../bootstrap/peace.desktop-bootstrap-store').Load();
  const artifact = db.artifacts[body.stage === 'A' ? db.launchers[row.launcherId]?.artifactId : row.releaseId];
  require('./peace.desktop-security-authority').RequireArtifact(artifact,{row,stage:body.stage});
  if(!Number.isSafeInteger(row.createdAt)||row.createdAt<1)Fail();
  return row;
}
function Prune() {
  const clock = deadline.Now();
  for (const state of states.values()) {
    for (const map of [state.pending, state.rates])
      for (const [key, value] of map) if (deadline.Expired(value, clock)) map.delete(key);
    // RetireContext removes replay order when the role is retired. Never expire
    // ordering while its session remains live and allow a producer replay.
    state.receipts.prune();
  }
}
function Challenge(body, channel) {
  Fields(body, AUTH);
  const row = Authenticate(body), state = states.get(channel), context = Context(row, body.stage);
  Prune();
  let rate = state.rates.get(context);
  if (!rate) { if (state.rates.size >= 4096) Fail('SECURITY_CAPACITY',503); rate = {count:0,...deadline.After(60000)}; state.rates.set(context,rate); }
  if (++rate.count > 60 || state.pending.size >= 1024) Fail('SECURITY_RATE_LIMIT',429);
  for (const [id, previous] of state.pending) if (previous.context === context) state.pending.delete(id);
  const item = {version:1, channel, challengeId:crypto.randomBytes(24).toString('hex'),
    nonce:crypto.randomBytes(24).toString('hex'), epoch:String(row.createdAt), context, stage:body.stage,
    sessionId:body.sessionId, binding:body.binding, ...deadline.After(15000)};
  state.pending.set(item.challengeId,item);
  return {version:1,channel,challengeId:item.challengeId,nonce:item.nonce,epoch:item.epoch,expiresAt:item.expiresAt};
}
function Canonical(body, challenge, channel) {
  return [Domain(channel),body.stage,body.sessionId,body.machineId,body.binding,
    challenge.challengeId,challenge.nonce,challenge.epoch,String(challenge.expiresAt),sha(body.payload)].join('\n');
}
function Payload(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16384) Fail();
  let value; try { value = require('../protocol/peace.strict-json').Parse(text); } catch (_) { Fail(); }
  Fields(value,['version','sequence','tick','digest','confirmed','trust',...(value?.version>=2?['detections']:[]),...(value?.version>=3?['peer']:[])]);
  if (![1,2,3,4,5].includes(value.version) || typeof value.confirmed !== 'boolean' || !Number.isInteger(value.trust) || value.trust < 0 || value.trust > 3 ||
      value.version===1 && value.confirmed && value.trust !== 3) Fail();
  for (const key of ['sequence','tick','digest']) if (typeof value[key] !== 'string' || !/^[a-f0-9]{16}$/.test(value[key]) || /^0+$/.test(value[key])) Fail();
  if(value.version>=2){detections.ParseRecords(value.detections,value.tick,value.version);if(value.digest!==sha(JSON.stringify(value.detections)).slice(0,16))Fail('SECURITY_DETECTION_DIGEST_INVALID');}
  if(value.version>=3)peers.ParseEnrollment(value.peer);
  return value;
}
function Submit(body, channel) {
  Fields(body,[...AUTH,'challengeId','payload','signature']);
  const state=states.get(channel), row=Authenticate(body), context=Context(row,body.stage);
  Prune();
  const purpose='nhw.'+channel+'.submit', receipt=state.receipts.get(body.challengeId,purpose,body);
  if (receipt) { if (receipt.meta.context !== context) Fail(); return receipt.response; }
  const challenge=state.pending.get(body.challengeId);
  if (!challenge || challenge.context!==context || challenge.binding!==body.binding || deadline.Expired(challenge)) Fail('SECURITY_CHALLENGE_INVALID',401);
  const value=Payload(body.payload);
  if (sha(body.payload)!==body.binding) Fail();
  if (typeof body.signature!=='string' || !/^[A-Za-z0-9+/]{342}==$/.test(body.signature) ||
      Buffer.from(body.signature,'base64').toString('base64')!==body.signature ||
      !proof.Verify(row.publicKey,Canonical(body,challenge,channel),body.signature)) Fail('SECURITY_SIGNATURE_INVALID',401);
  state.pending.delete(body.challengeId);
  if (deadline.Expired(challenge)) Fail('SECURITY_CHALLENGE_INVALID',401);
  const recovered=detections.RecoverBatch(row,body.stage,channel,value);
  if(!recovered){
    detections.CheckOrder(row,body.stage,channel,value);
    if(value.version>=2) detections.CheckCounters(row,body.stage,channel,value.detections);
  }
  const previous=state.order.get(context);
  if (!recovered && previous && (BigInt('0x'+value.sequence)<=previous.sequence || BigInt('0x'+value.tick)<previous.tick)) Fail('SECURITY_OBSERVATION_REPLAY',409);
  if (!previous && state.order.size>=4096) Fail('SECURITY_CAPACITY',503);
  let peerContext=null;
  try{if(value.version>=3)peerContext=peers.Enroll(row,body.stage,value.peer,value.sequence,{channel,recover:!!recovered});}
  catch(error){
    if(['SECURITY_PEER_IMAGE_MISMATCH','SECURITY_PEER_IDENTITY_CHANGED'].includes(error.message)){
      require('../bootstrap/peace.desktop-bootstrap').Revoke(row.sessionId,{reason:error.message},'SECURITY_AUTHORITY');
      detections.RecordServer({row,stage:body.stage,id:error.message,source:'peace.nhw-peer-context',invalidated:true});
    }
    else if(error.message==='SECURITY_PEER_ENROLLMENT_REPLAY')detections.RecordServer({row,stage:body.stage,id:error.message,source:'peace.nhw-peer-context',confidence:0,correlation:false,invalidated:false});
    throw error;
  }
  state.order.set(context,{sequence:BigInt('0x'+value.sequence),tick:BigInt('0x'+(recovered?.tick||value.tick))});
  // Legacy envelopes remain authenticated and replay-checked. Only typed
  // evidence can receive a new stop decision.
  const terminal=detections.TerminalAllowed(row,body.stage);
  if(terminal&&value.version<2)Fail('SECURITY_NHW_RESPONSE_INVALID');
  const decision=value.version>=2?(recovered?recovered.stopDecision||null:detections.StopDecision(body.stage,channel,value,row)):null;
  const stopped=terminal||!!decision;
  const response={version:1,channel,sequence:value.sequence,digest:value.digest,epoch:challenge.epoch,
    accepted:true,stopped,scope:'OWNED_A_B_O',attested:false,...(value.version>=3?{peerContext:stopped?null:peerContext}: {})};
  const contributors=decision?[{channel,keys:decision.keys}]:[];
  // Persist every accepted observation, including local-only/unsupported
  // evidence. Persistence also keeps producer high-watermarks across restart.
  // A telemetry failure cannot bypass an already-made exact-cohort decision.
  let recordError;
  try { if(!recovered)detections.RecordPath(row,body.stage,channel,value,terminal?null:decision); } catch(error) { recordError=error; }
  if (stopped&&!terminal) {
    // Existing revoke follows exact stored parent/child links, never a caller
    // supplied target ID, and retires the whole authorized cohort.
    const reason=decision.reason;
    require('../bootstrap/peace.desktop-bootstrap').Revoke(row.sessionId,{reason},'SECURITY_AUTHORITY');
    if(value.version>=2) detections.CommitInvalidation(row,body.stage,contributors,reason);
  }
  if(recordError) {
    if(!stopped){if(previous)state.order.set(context,previous);else state.order.delete(context);}
    throw recordError;
  }
  state.receipts.put(body.challengeId,purpose,body,response,{context});
  return response;
}
function Execute(body) {
  const action=ParseAction(body?.action); if (!action) Fail();
  require('../bootstrap/peace.desktop-bootstrap').EnsureSecurityAvailable();
  protocol.Purpose('nhw.'+action.channel+'.'+action.verb);
  return action.verb==='challenge'?Challenge(body,action.channel):Submit(body,action.channel);
}
function ProofTasks(body) {
  const action=ParseAction(body?.action);if(!action||action.verb!=='submit')return [];
  const item=states.get(action.channel).pending.get(body.challengeId);if(!item)return [];
  const row=Authenticate(body);
  return [proof.Job(row.publicKey,Canonical(body,item,action.channel),body.signature)];
}
function RetireContext(row,stage) {
  const context=Context(row,stage);
  for (const state of states.values()) {
    for(const [id,value] of state.pending)if(value.context===context)state.pending.delete(id);
    state.order.delete(context);state.rates.delete(context);
    state.receipts.deleteWhere(meta=>meta.context===context);
  }
}
function Clear() { for(const state of states.values()){for(const key of ['pending','order','rates'])state[key].clear();state.receipts.clear();} peers.Clear(); }
module.exports={ParseAction,Domain,Canonical,Payload,Execute,ProofTasks,RetireContext,Clear};
