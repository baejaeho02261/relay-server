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
  pending: new Map(), order: new Map(), votes: new Map(), rates: new Map(),
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
function AssertTerminalWindow(row,stage) {
  if(detections.TerminalAllowed(row,stage))return;
  if(row.status==='REVOKED')Fail('SECURITY_NHW_SESSION_REVOKED',403);
  Fail('BOOTSTRAP_SESSION_CLOSED',403);
}
function IsHandoffReporter(row,stage,db) {
  // Exact role credentials are checked by AuthenticateIntegrityReceipt.
  // These existing recovery bounds only authorize signed security reports.
  if(stage==='A'&&row.status==='CLAIMED')
    return !deadline.persistent.expired('B.claim-recovery:'+row.id,row.claimedAt,row.delegatedClaimRecoveryUntil);
  if(stage==='B'&&row.status==='CLOSED'&&row.closedByOverlay===true){
    const child=db.overlays?.[row.transferredOverlayId];
    return child?.status==='CLAIMED'&&child.parentFlowId===row.id&&child.parentSessionId===row.sessionId&&
      child.transferredAt===row.transferredAt&&child.sessionExpiresAt>Date.now();
  }
  return false;
}
function Authenticate(body) {
  if (!['A','B','O'].includes(body.stage) || typeof body.machineId !== 'string' || !/^[A-F0-9]{64}$/.test(body.machineId) ||
      typeof body.binding !== 'string' || !/^[a-f0-9]{128}$/.test(body.binding)) Fail();
  const boot=require('../bootstrap/peace.desktop-bootstrap');
  const db=require('../bootstrap/peace.desktop-bootstrap-store').Load();
  let row,terminal=false,handoff=false;
  try { row=boot.AuthenticateIntegrityReport(body); } catch(error) {
    try { row=boot.AuthenticateIntegrityReceipt(body); } catch(_) { throw error; }
    terminal=detections.TerminalAllowed(row,body.stage);
    if(!terminal){
      if(row.status==='REVOKED')Fail('SECURITY_NHW_SESSION_REVOKED',403);
      handoff=IsHandoffReporter(row,body.stage,db);
      if(!handoff)throw error;
      require('../recovery/peace.desktop-recovery').Assert(row,db);
      require('../bootstrap/peace.issued-a-keyring').AssertLauncher(db.launchers[row.launcherId],db);
      require('../devices/peace.desktop-device-registry').AssertMachineAllowed(row.machineId,db);
      require('../devices/peace.desktop-machine-policy').AssertAllowed(row.machineId,row.machinePolicyGeneration,row.sessionId);
      if(body.stage==='A')boot.AssertFlowLifetime(row);
    }
  }
  try {
    require('../devices/peace.desktop-device-identity').AssertSession(row, body.stage);
    const artifact = db.artifacts[body.stage === 'A' ? db.launchers[row.launcherId]?.artifactId : row.releaseId];
    require('./peace.desktop-security-authority').RequireArtifact(artifact,{row,stage:body.stage});
  } catch(error) {
    // The exact retired credential can receive a denial even when current
    // policy prevents admitting its signed diagnostic report.
    if(terminal&&row.status==='REVOKED')Fail('SECURITY_NHW_SESSION_REVOKED',403);
    throw error;
  }
  if(!Number.isSafeInteger(row.createdAt)||row.createdAt<1)Fail();
  return {row,terminal,handoff};
}
function Prune() {
  const clock = deadline.Now();
  for (const state of states.values()) {
    for (const map of [state.pending, state.votes, state.rates])
      for (const [key, value] of map) if (deadline.Expired(value, clock)) map.delete(key);
    // RetireContext removes replay order when the role is retired. Never expire
    // ordering while its session remains live and allow a producer replay.
    state.receipts.prune();
  }
}
function Challenge(body, channel) {
  Fields(body, AUTH);
  const {row,terminal} = Authenticate(body), state = states.get(channel), context = Context(row, body.stage);
  Prune();
  if(terminal)AssertTerminalWindow(row,body.stage);
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
  if (![1,2,3,5].includes(value.version) || typeof value.confirmed !== 'boolean' || !Number.isInteger(value.trust) || value.trust < 0 || value.trust > 3 ||
      value.version===1 && value.confirmed && value.trust !== 3) Fail();
  for (const key of ['sequence','tick','digest']) if (typeof value[key] !== 'string' || !/^[a-f0-9]{16}$/.test(value[key]) || /^0+$/.test(value[key])) Fail();
  if(value.version>=2){detections.ParseRecords(value.detections,value.tick,value.version);if(value.digest!==sha(JSON.stringify(value.detections)).slice(0,16))Fail('SECURITY_DETECTION_DIGEST_INVALID');}
  if(value.version>=3)peers.ParseEnrollment(value.peer);
  return value;
}
function Submit(body, channel) {
  Fields(body,[...AUTH,'challengeId','payload','signature']);
  const state=states.get(channel), {row,terminal,handoff}=Authenticate(body), context=Context(row,body.stage);
  Prune();
  if(terminal)AssertTerminalWindow(row,body.stage);
  const purpose='nhw.'+channel+'.submit', receipt=state.receipts.get(body.challengeId,purpose,body);
  if (receipt) {
    if (receipt.meta.context !== context) Fail();
    if (handoff&&receipt.meta.version!==5)Fail('BOOTSTRAP_SESSION_CLOSED',403);
    if (!terminal || receipt.response.stopped) return handoff?{...receipt.response,peerContext:null}:receipt.response;
  }
  const challenge=state.pending.get(body.challengeId);
  if (!challenge || challenge.context!==context || challenge.binding!==body.binding || deadline.Expired(challenge)) Fail('SECURITY_CHALLENGE_INVALID',401);
  const value=Payload(body.payload);
  if(handoff&&value.version!==5)Fail('BOOTSTRAP_SESSION_CLOSED',403);
  if(terminal&&value.version<2)Fail('SECURITY_NHW_RESPONSE_INVALID');
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
  const previous=state.order.get(context),previousVote=state.votes.get(context);
  const live=!terminal&&!handoff;
  if (live&&!recovered&&previous&&(BigInt('0x'+value.sequence)<=previous.sequence || BigInt('0x'+value.tick)<previous.tick)) Fail('SECURITY_OBSERVATION_REPLAY',409);
  if (live&&!previous&&state.order.size>=4096) Fail('SECURITY_CAPACITY',503);
  if(live&&!recovered) detections.CapturePrimaryTokenContexts(row,body.stage,value);
  let peerContext=null;
  try{if(live&&value.version>=3)peerContext=peers.Enroll(row,body.stage,value.peer,value.sequence,{channel,recover:!!recovered});}
  catch(error){
    if(['SECURITY_PEER_IMAGE_MISMATCH','SECURITY_PEER_IDENTITY_CHANGED'].includes(error.message)){
      require('../bootstrap/peace.desktop-bootstrap').Revoke(row.sessionId,{reason:error.message},'SECURITY_AUTHORITY',
        (db,origin)=>detections.RecordServerIn(db,{row:origin,stage:body.stage,id:error.message,source:'peace.nhw-peer-context',invalidated:true}));
    }
    else if(error.message==='SECURITY_PEER_ENROLLMENT_REPLAY')detections.RecordServer({row,stage:body.stage,id:error.message,source:'peace.nhw-peer-context',confidence:0,correlation:false,invalidated:false});
    throw error;
  }
  if(live)state.order.set(context,{sequence:BigInt('0x'+value.sequence),tick:BigInt('0x'+(recovered?.tick||value.tick))});
  // v1 is retained only for deployed pre-catalog clients. v2 final policy is
  // computed here from actual named evidence, not the client confirmed bit.
  const confirmed=value.version===1&&value.confirmed;
  if (confirmed) state.votes.set(context,{digest:value.digest,ids:value.version>=2?detections.QualifiedIds(value.detections,value.tick):[],...deadline.After(90000)});
  else state.votes.delete(context);
  const voteMask=channels.reduce((mask,name,i)=>mask|(states.get(name).votes.has(context)?1<<i:0),0);
  const decision=!terminal&&value.version>=2?(recovered?recovered.stopDecision||null:detections.StopDecision(body.stage,channel,value,row)):null;
  const stopped=terminal||!!decision||(value.version===1&&(voteMask===3||voteMask===5||voteMask===6||voteMask===7));
  const response={version:1,channel,sequence:value.sequence,digest:value.digest,epoch:challenge.epoch,
    accepted:true,stopped,scope:'OWNED_A_B_O',attested:false,...(value.version>=3?{peerContext:stopped?null:peerContext}: {})};
  const contributors=decision?[{channel,keys:decision.keys}]:[];
  try {
    if(handoff){
      const db=require('../bootstrap/peace.desktop-bootstrap-store').Load();
      if(!IsHandoffReporter(row,body.stage,db))Fail('BOOTSTRAP_SESSION_CLOSED',403);
      if(body.stage==='B')require('../overlay/peace.desktop-overlay').AuthenticateTransferCleanup(row,body.sessionToken);
    }
    if(stopped&&!terminal){
      // The named event, producer order and cohort revoke share the same
      // durable commit. An exact legacy recovery already has its event.
      const reason=decision?.reason||'SECURITY_SESSION_STOP';
      const recordRevocation=recovered?undefined:(db,origin)=>detections.RecordPathIn(db,origin,body.stage,channel,value,decision);
      const revoked=require('../bootstrap/peace.desktop-bootstrap').Revoke(row.sessionId,{reason},'SECURITY_AUTHORITY',recordRevocation);
      if(revoked.status!=='REVOKED')Fail('SECURITY_DETECTION_CONTEXT_INVALID',409);
      if(value.version>=2) detections.CommitInvalidation(row,body.stage,contributors,reason);
    }else{
      if(terminal)AssertTerminalWindow(row,body.stage);
      if(!recovered)detections.RecordPath(row,body.stage,channel,value);
    }
  }catch(error){
    if(previous)state.order.set(context,previous);else state.order.delete(context);
    if(previousVote)state.votes.set(context,previousVote);else state.votes.delete(context);
    throw error;
  }
  if(!stopped||value.version>=2) state.receipts.put(body.challengeId,purpose,body,response,{context,version:value.version});
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
  const {row}=Authenticate(body);
  return [proof.Job(row.publicKey,Canonical(body,item,action.channel),body.signature)];
}
function RetireContext(row,stage) {
  const context=Context(row,stage);
  for (const state of states.values()) {
    for(const [id,value] of state.pending)if(value.context===context)state.pending.delete(id);
    state.order.delete(context);state.votes.delete(context);state.rates.delete(context);
    state.receipts.deleteWhere(meta=>meta.context===context);
  }
}
function Clear() { for(const state of states.values()){for(const key of ['pending','order','votes','rates'])state[key].clear();state.receipts.clear();} peers.Clear(); }
module.exports={ParseAction,Domain,Canonical,Payload,Execute,ProofTasks,RetireContext,Clear};
