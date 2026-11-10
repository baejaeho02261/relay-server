'use strict';
// Server-owned cohort identity and least-privilege decisions. Windows PID,
// creation time and image measurement are signed client observations, not a
// server observation of the OS or a hardware attestation. Raw PID/creation
// pairs live only in this bounded RAM cache; durable records retain aliases.
const crypto=require('node:crypto'),store=require('../bootstrap/peace.desktop-bootstrap-store'),clock=require('../runtime/peace.desktop-deadline');
const TTL=30000,HANDOFF_TTL={B:45000,O:110000},MAX_LIVE=4096,live=new Map(),terminal=new Set(['CLOSED','REVOKED','EXPIRED']);
const ROLES=['A','B','O'],CHANNELS=['trust','driver','integrity'];
const PHASES=Object.freeze(['A_BOOTSTRAP','A_ATTESTED','A_ISSUANCE','A_HANDOFF_TO_B','A_SHUTDOWN','B_BOOTSTRAP','B_ATTESTED','B_RUNTIME','B_HANDOFF_TO_O','B_SHUTDOWN','O_BOOTSTRAP','O_ATTESTED','O_RUNTIME','O_SHUTDOWN']);
const CAPABILITIES=Object.freeze(['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS','TOKEN_STATE','SELF_MEMORY','MODULE_STATE','IPC','ETW_STATE','KERNEL_STATE','UNKNOWN']);
const sha=x=>crypto.createHash('sha256').update(x).digest('hex'),hex=(s,n)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s),plain=x=>!!x&&Object.getPrototypeOf(x)===Object.prototype;
function Fail(code='SECURITY_PEER_CONTEXT_INVALID',status=400){throw Object.assign(Error(code),{desktopError:true,status});}
function Fields(x,keys){if(!plain(x)||Object.keys(x).length!==keys.length||keys.some(k=>!Object.hasOwn(x,k)))Fail();}
function ParseEnrollment(peer){
 if(peer===null)return null;
 Fields(peer,['pid','creationTime','imageSha256','imageSha512','parentIdentity','phase']);
 if(!Number.isInteger(peer.pid)||peer.pid<1||peer.pid>0xffffffff||!hex(peer.creationTime,16)||/^0+$/.test(peer.creationTime)||!hex(peer.imageSha256,64)||!hex(peer.imageSha512,128)||peer.parentIdentity!==''&&!hex(peer.parentIdentity,64)||!PHASES.includes(peer.phase))Fail();
 return peer;
}
function StableIdentity(peer){return sha(['COZY-NHW-PROCESS-V1',String(peer.pid),peer.creationTime,peer.imageSha256].join('\n'));}
function Binding(db,row,stage){
 if(!ROLES.includes(stage)||!row)return null;
 const flow=stage==='O'?db.flows?.[row.parentFlowId]:db.flows?.[row.id],owner=stage==='O'?db.overlays?.[row.id]:flow;
 if(!flow||!owner||owner.createdAt!==row.createdAt)return null;
 const artifact=db.artifacts?.[stage==='A'?db.launchers?.[flow.launcherId]?.artifactId:owner.releaseId];
 if(!artifact||artifact.component!==stage)return null;
 return {flow,owner,artifact,handoffPrepared:Object.values(db.overlays||{}).some(o=>o.parentFlowId===flow.id&&['PREPARED','READY','CLAIMED'].includes(o.status)),downloadComplete:(flow.chunkOffsets||[]).length===Math.ceil((db.artifacts?.[flow.releaseId]?.size||1)/262144),role:stage,epoch:String(owner.createdAt),cohort:sha([flow.id,String(flow.createdAt),String(flow.serverEpoch||0)].join('\n')),sessionId:stage==='A'?flow.id:owner.sessionId};
}
function Active(b){return !!b&&!terminal.has(b.owner.status)&&(!terminal.has(b.flow.status)||b.role==='O'&&b.flow.closedByOverlay&&b.flow.transferredOverlayId===b.owner.id&&b.flow.status==='CLOSED');}
function CurrentPhase(b,phase){
 if(!PHASES.includes(phase)||!phase.startsWith(b.role+'_'))return false;
 if(phase.endsWith('_SHUTDOWN'))return true;
 if(b.role==='A')return b.owner.status==='STARTED'&&(['A_BOOTSTRAP','A_ATTESTED','A_ISSUANCE'].includes(phase)||phase==='A_HANDOFF_TO_B'&&b.downloadComplete)||b.owner.status==='DOWNLOADED'&&phase==='A_HANDOFF_TO_B';
 if(b.role==='B')return b.owner.status==='CLAIMED'&&(['B_BOOTSTRAP','B_ATTESTED'].includes(phase)||phase==='B_RUNTIME'&&!!b.owner.licenseId||phase==='B_HANDOFF_TO_O'&&b.handoffPrepared);
 return b.owner.status==='CLAIMED';
}
function Expired(p){return !p||clock.persistent.expired('nhw.peer:'+p.peerId,p.updatedAt,p.expiresAt);}
function Prune(){for(const [k,v]of live)if(clock.Expired(v))live.delete(k);}
function AllPeers(db,b){
 const peers=[];for(const role of ['A','B']){const p=b.flow.nhwPeerBindings?.[role];if(p)peers.push(p);}
 for(const o of Object.values(db.overlays||{}))if(o.parentFlowId===b.flow.id&&o.nhwPeerBindings?.O)peers.push(o.nhwPeerBindings.O);
 return peers;
}
function FindPeer(db,b,identity,peerId=''){
 if(!hex(identity,64))return null;
 return AllPeers(db,b).find(p=>p.identity===identity&&p.cohort===b.cohort&&(!peerId||p.peerId===peerId)&&!p.retiredAt&&!Expired(p)&&live.has(p.peerId)&&!clock.Expired(live.get(p.peerId)))||null;
}
function ArtifactIdentity(b){
 const a=b.artifact,l=b.role==='A'?b.flow.launcherId:'';
 return {artifactId:a.id,artifactSha512:a.sha512,packageId:a.deploymentManifestId||'',signerId:a.releaseApproval?.keyId||'',versionLabel:a.version||'',issuanceId:l||b.flow.launcherId,buildIdentity:sha([a.id,a.sha512,a.version||'',a.deploymentManifestId||''].join('\n'))};
}
function ExpectedImage(db,b){
 const issuer=db.launchers[b.flow.launcherId];
 return b.role==='A'?{sha512:b.flow.launcherSha512,sha256:issuer?.peerImageSha256||''}:{sha512:b.artifact.sha512,sha256:b.artifact.legacyRevocationSha256||''};
}
function MakeGrant(db,row,targetRole){
 const sourceRole=targetRole==='B'?'A':'B',flow=targetRole==='B'?row:db.flows[row.parentFlowId],source=flow?.nhwPeerBindings?.[sourceRole],artifact=db.artifacts[row.releaseId];
 // No source peer enrollment means no first-party exemption. Existing signed
 // handoff still functions and all sensors continue with UNKNOWN context.
 if(!source||source.retiredAt||Expired(source)||!live.has(source.peerId)||clock.Expired(live.get(source.peerId))||!artifact||artifact.component!==targetRole)return null;
 const rawNonce=targetRole==='B'?row.handoffNonce:row.ticketNonce;
 if(typeof rawNonce!=='string'||!rawNonce)return null;
 const at=Date.now(),end=Math.min(targetRole==='B'?row.handoffExpiresAt:row.expiresAt,at+HANDOFF_TTL[targetRole]);
 if(!Number.isSafeInteger(end)||end<=at)return null;
 const g={version:1,id:crypto.randomBytes(24).toString('hex'),sourceRole,targetRole,sourceIdentity:source.identity,sourcePeerId:source.peerId,sourceEpoch:source.epoch,targetArtifactId:artifact.id,targetImageSha512:artifact.sha512,cohort:source.cohort,sessionId:targetRole==='B'?flow.sessionId:row.sessionId,epoch:String(row.createdAt),sequence:source.serverSequence,nonceHash:sha(rawNonce),allowedProcessMask:0x00101001,allowedThreadMask:0x00100840,allowedActions:['QUERY','SYNCHRONIZE','HANDOFF_IPC','FAILED_CHILD_TERMINATE'],issuedAt:at,expiresAt:end,consumedAt:0,childKeyId:'',claimDigest:''};
 row.nhwHandoffGrant=g;source.phase=sourceRole==='A'?'A_HANDOFF_TO_B':'B_HANDOFF_TO_O';return g;
}
function ConsumeGrant(db,row,targetRole,child,claimDigest){
 const g=row.nhwHandoffGrant;if(!g)return;
 if(g.consumedAt)throw Object.assign(Error('SECURITY_HANDOFF_GRANT_REUSED'),{desktopError:true,status:409,nhwGrantSourceRole:g.sourceRole,nhwGrantFlowId:targetRole==='B'?row.id:row.parentFlowId});
 if(!child||g.targetRole!==targetRole||g.targetArtifactId!==row.releaseId||g.consumedAt||clock.persistent.expired('nhw.grant:'+g.id,g.issuedAt,g.expiresAt)){
  // A late/legacy claim retains its ordinary handoff semantics but receives no
  // first-party capability. It cannot revive or consume this expired grant.
  row.nhwHandoffGrantUnavailable=true;return;
 }
 g.consumedAt=Date.now();g.childKeyId=child.deviceId;g.claimDigest=claimDigest;
}
function ParentAuthorized(b,peer){
 if(b.role==='A')return peer.parentIdentity==='';
 const g=b.owner.nhwHandoffGrant;
 return !!g&&!b.owner.nhwHandoffGrantUnavailable&&g.targetRole===b.role&&g.targetArtifactId===b.artifact.id&&g.targetImageSha512===peer.imageSha512&&g.cohort===b.cohort&&g.epoch===b.epoch&&g.sessionId===b.sessionId&&g.consumedAt>0&&g.childKeyId===b.owner.deviceId&&g.claimDigest===b.owner.delegatedClaimFingerprint&&g.sourceIdentity===peer.parentIdentity;
}
function Enroll(row,stage,peer,sequence,{channel='integrity',recover=false}={}){
 ParseEnrollment(peer);if(!hex(sequence,16)||/^0+$/.test(sequence)||!CHANNELS.includes(channel))Fail();
 if(recover)return Receipt(row,stage,sequence);
 if(peer===null)return null;
 const db=store.Load(),b=Binding(db,row,stage);if(!Active(b))return null;
 if(!CurrentPhase(b,peer.phase))return null;
 const image=ExpectedImage(db,b);
 if(peer.imageSha512!==image.sha512||image.sha256&&peer.imageSha256!==image.sha256)Fail('SECURITY_PEER_IMAGE_MISMATCH',403);
 // Existing issued A binaries lack a SHA-256 issuance receipt. Do not turn a
 // client-selected SHA-256 into a server-approved image identity for them.
 if(!image.sha256||!ParentAuthorized(b,peer))return null;
 const identity=StableIdentity(peer),old=b.owner.nhwPeerBindings?.[stage];
 if(old&&(old.identity!==identity||old.imageSha512!==peer.imageSha512||old.parentIdentity!==peer.parentIdentity))Fail('SECURITY_PEER_IDENTITY_CHANGED',409);
 if(old?.retiredAt)return null;
 const fingerprint=sha(JSON.stringify(peer)),priorReport=old?.reports?.[channel];
 if(priorReport&&BigInt('0x'+sequence)<=BigInt('0x'+priorReport.sequence)){if(sequence!==priorReport.sequence||fingerprint!==priorReport.digest)Fail('SECURITY_PEER_ENROLLMENT_REPLAY',409);return Receipt(row,stage);}
 if(old&&BigInt('0x'+old.serverSequence)>=0xffffffffffffffffn)Fail('SECURITY_CAPACITY',503);
 const at=Date.now(),peerId=old?.peerId||crypto.randomBytes(24).toString('hex');
 Prune();if(!live.has(peerId)&&live.size>=MAX_LIVE)Fail('SECURITY_CAPACITY',503);
 let saved;
 store.Atomic(next=>{const bind=Binding(next,row,stage);if(!Active(bind)||!CurrentPhase(bind,peer.phase)||!ParentAuthorized(bind,peer))Fail('SECURITY_PEER_CONTEXT_RETIRED',409);
  const previous=bind.owner.nhwPeerBindings?.[stage];if(previous&&previous.identity!==identity)Fail('SECURITY_PEER_IDENTITY_CHANGED',409);
  saved={version:1,peerId,identity,role:stage,cohort:bind.cohort,sessionId:bind.sessionId,epoch:bind.epoch,imageSha256:peer.imageSha256,imageSha512:peer.imageSha512,parentIdentity:peer.parentIdentity,grantId:bind.owner.nhwHandoffGrant?.id||'',phase:peer.phase,...ArtifactIdentity(bind),serverSequence:(BigInt('0x'+(previous?.serverSequence||'0'))+1n).toString(16).padStart(16,'0'),reports:{...(previous?.reports||{}),[channel]:{sequence,digest:fingerprint}},channel,createdAt:previous?.createdAt||at,updatedAt:at,expiresAt:at+TTL};
  (bind.owner.nhwPeerBindings||(bind.owner.nhwPeerBindings={}))[stage]=saved;
 });
 live.set(peerId,{pid:peer.pid,creationTime:peer.creationTime,identity,...clock.After(TTL)});
 return Receipt(row,stage,sequence);
}
function Receipt(row,stage,sequence){
 const db=store.Load(),b=Binding(db,row,stage);if(!Active(b))return null;
 const self=b.owner.nhwPeerBindings?.[stage];if(!self||self.retiredAt||Expired(self))return null;
 Prune();const peers=AllPeers(db,b).filter(p=>!p.retiredAt&&!Expired(p)&&live.has(p.peerId)).map(p=>{const raw=live.get(p.peerId);return {peerId:p.peerId,role:p.role,phase:p.phase,identity:p.identity,pid:raw.pid,creationTime:raw.creationTime,imageSha256:p.imageSha256,imageSha512:p.imageSha512,grantId:(b.owner.nhwHandoffGrant?.sourceIdentity===p.identity&&b.owner.nhwHandoffGrant?.targetRole===stage?b.owner.nhwHandoffGrant.id:p.identity===self.identity?p.grantId:''),expiresAt:p.expiresAt,ttlMs:Math.max(0,Math.min(TTL,p.expiresAt-Date.now(),Math.floor(raw.deadline-clock.Now().tick)))};}).filter(p=>p.ttlMs>0);
 if(!peers.some(p=>p.peerId===self.peerId))return null;
 return {version:1,selfPeerId:self.peerId,selfIdentity:self.identity,epoch:b.epoch,serverSequence:self.serverSequence,expiresAt:self.expiresAt,ttlMs:Math.min(TTL,self.expiresAt-Date.now()),scope:'SERVER_BOUND_CLIENT_OBSERVATION',peers};
}
const MATRIX=Object.freeze(Object.fromEntries(PHASES.map(phase=>[phase,Object.freeze({processQueryMask:0x00101000,threadQueryMask:0x00100840,tokenQueryMask:0x18,selfMemory:true,moduleBaseline:true,tokenBaseline:true,etwObservation:true,handoff:phase==='A_HANDOFF_TO_B'||phase==='B_HANDOFF_TO_O',cleanup:phase.endsWith('_SHUTDOWN'),sources:['Cozy.Handoff.pas:LaunchWithHandoff','Cozy.Handoff.Restricted.pas:VerifyChildToken','Cozy.NHW.Security.pas:ExamineLocalState','Cozy.NHW.Engine.pas:Run']})])));
function GrantFor(db,b,actor,target,id){
 if(!id||!actor||!target)return null;
 const rows=[b.flow,...Object.values(db.overlays||{}).filter(o=>o.parentFlowId===b.flow.id)];
 return rows.map(o=>o.nhwHandoffGrant).find(g=>g&&g.id===id&&g.cohort===b.cohort&&g.sourceIdentity===actor.identity&&g.targetRole===target.role&&g.targetImageSha512===target.imageSha512&&g.consumedAt>0&&target.grantId===g.id&&!clock.persistent.expired('nhw.grant:'+g.id,g.issuedAt,g.expiresAt))||null;
}
function ResolveContext(row,stage,context){
 if(!context)return null;
 const db=store.Load(),b=Binding(db,row,stage),out={...context,actorClass:context.actorClass==='EXTERNAL'||context.actorIdentity?'EXTERNAL':'UNKNOWN',actorRole:'?',targetRole:'?',peerId:'',grantId:'',capabilityDecision:'OBSERVE',firstPartyAttested:false,serverBound:false,sameSession:false,bindingScope:'UNVERIFIED_CLIENT_OBSERVATION',expected:false,forbidden:false};
 const processDanger=0x0000002a,threadDanger=0x00000010,tokenDanger=0x000001e7;
 if(context.capability==='PROCESS_ACCESS'&&(context.accessMask&processDanger)||context.capability==='THREAD_ACCESS'&&(context.accessMask&threadDanger)||context.capability==='TOKEN_ACCESS'&&(context.accessMask&tokenDanger)||(context.tokenDelta&255)){out.capabilityDecision='FORBIDDEN';out.forbidden=true;}
 if(!Active(b)||context.contextMixed)return out;
 const self=b.owner.nhwPeerBindings?.[stage],actor=FindPeer(db,b,context.actorIdentity,context.peerId||''),target=FindPeer(db,b,context.targetIdentity);
 if(!actor||!target||!self||target.identity!==self.identity)return out;
 if(context.actorClass==='SELF'){if(actor.identity!==self.identity)return out;}
 else if(context.actorClass!=='TRUSTED_'+actor.role||!context.peerId||context.peerId!==actor.peerId)return out;
 out.actorClass=actor.identity===self?.identity?'SELF':'TRUSTED_'+actor.role;out.actorRole=actor.role;out.targetRole=target.role;out.peerId=actor.peerId;out.firstPartyAttested=true;out.serverBound=true;out.sameSession=true;out.bindingScope='SERVER_BOUND_CLIENT_OBSERVATION';
 const grant=GrantFor(db,b,actor,target,context.grantId),same=actor.identity===target.identity;
 const phaseAllowed=context.phase===actor.phase||!!grant&&[actor.role+'_HANDOFF_TO_'+target.role,actor.role+'_SHUTDOWN'].includes(context.phase);
 const m=MATRIX[context.phase];
 if(grant)out.grantId=grant.id;
 if(out.forbidden||!m)return out;
 if(!phaseAllowed){out.capabilityDecision='SUSPICIOUS';return out;}
 let allowed=false;
 switch(context.capability){
 case 'PROCESS_ACCESS':allowed=(context.accessMask&~m.processQueryMask)===0||!!grant&&(m.handoff||m.cleanup)&&(context.accessMask&~grant.allowedProcessMask)===0;break;
 case 'THREAD_ACCESS':allowed=(context.accessMask&~m.threadQueryMask)===0;break;
 case 'TOKEN_ACCESS':allowed=(context.accessMask&~m.tokenQueryMask)===0;break;
 case 'TOKEN_STATE':allowed=same&&context.tokenDelta===0&&context.baseline===true;break;
 case 'SELF_MEMORY':case 'MODULE_STATE':allowed=same&&context.baseline===true;break;
 case 'ETW_STATE':allowed=same&&context.coverage==='COMPLETE';break;
 case 'IPC':allowed=same||!!grant&&m.handoff;break;
 }
 if(allowed){out.capabilityDecision='EXPECTED';out.expected=true;}
 else if(['PROCESS_ACCESS','THREAD_ACCESS','TOKEN_ACCESS'].includes(context.capability)){
  // Both identities and the current phase were resolved above. A known peer
  // exceeding its exact role/grant capability is a violation, not uncertainty.
  out.capabilityDecision='FORBIDDEN';out.forbidden=true;
 }else out.capabilityDecision='SUSPICIOUS';
 return out;
}
function Retire(row,stage){const p=row?.nhwPeerBindings?.[stage];if(p){live.delete(p.peerId);clock.persistent.forget('nhw.peer:'+p.peerId);}}
function Clear(){for(const id of live.keys())clock.persistent.forget('nhw.peer:'+id);live.clear();}
function ObserveTransitions(before,next){
 for(const [collection,roles]of [['flows',['A','B']],['overlays',['O']]])for(const [id,row]of Object.entries(next[collection]||{})){
  const previous=before[collection]?.[id];if(previous&&!terminal.has(previous.status)&&terminal.has(row.status)){for(const role of roles)if(row.nhwPeerBindings?.[role])row.nhwPeerBindings[role].retiredAt=Date.now();store.AfterCommit(()=>{for(const role of roles)Retire(row,role);});}
 }
 for(const [id,row]of Object.entries(before.flows||{}))if(!next.flows?.[id])store.AfterCommit(()=>{Retire(row,'A');Retire(row,'B');});
 for(const [id,row]of Object.entries(before.overlays||{}))if(!next.overlays?.[id])store.AfterCommit(()=>Retire(row,'O'));
}
function ProcessExited(db,flowId,role,sessionId){
 const owner=role==='O'?Object.values(db.overlays||{}).find(o=>o.parentFlowId===flowId&&o.sessionId===sessionId):db.flows[flowId];
 if(owner&&(role==='A'?owner.id===sessionId:owner.sessionId===sessionId)){if(owner.nhwPeerBindings?.[role])owner.nhwPeerBindings[role].retiredAt=Date.now();store.AfterCommit(()=>Retire(owner,role));}
}
function RecordGrantRejection(error){
 // Called only outside the authenticated Claim transaction, after rollback.
 // Exact claim retries return their receipt before ConsumeGrant is reached.
 if(error?.message!=='SECURITY_HANDOFF_GRANT_REUSED'||!['A','B'].includes(error.nhwGrantSourceRole)||!/^[A-F0-9]{24}$/.test(error.nhwGrantFlowId||''))return;
 const row=store.Load().flows?.[error.nhwGrantFlowId];if(!row)return;
 try{require('./peace.security-detections').RecordServer({row,stage:error.nhwGrantSourceRole,id:'SECURITY_HANDOFF_GRANT_REUSED',source:'peace.nhw-peer-context',confidence:0,correlation:false,invalidated:false});}
 catch(_){console.error('SECURITY_DETECTION_RECORD_FAILED');}
}
function Validate(row,db){
 const bad=()=>Fail('SECURITY_PEER_STORAGE_INVALID',503),id=x=>typeof x==='string'&&/^[A-F0-9]{24}$/.test(x),text=x=>typeof x==='string'&&x.length<=256&&!/[\x00-\x1f\x7f]/.test(x),keys=(x,names)=>plain(x)&&Object.keys(x).length===names.length&&names.every(k=>Object.hasOwn(x,k));
 const bindings=row.nhwPeerBindings;
 if(bindings!==undefined){
  if(!plain(bindings)||Object.keys(bindings).some(k=>!ROLES.includes(k)))bad();
  for(const [role,p]of Object.entries(bindings)){
   if(!keys(p,['version','peerId','identity','role','cohort','sessionId','epoch','imageSha256','imageSha512','parentIdentity','grantId','phase','artifactId','artifactSha512','packageId','signerId','versionLabel','issuanceId','buildIdentity','serverSequence','reports','channel','createdAt','updatedAt','expiresAt',...(p.retiredAt!==undefined?['retiredAt']:[])])||p.version!==1||p.role!==role||!hex(p.peerId,48)||!hex(p.identity,64)||!hex(p.cohort,64)||!hex(p.imageSha256,64)||!hex(p.imageSha512,128)||!hex(p.artifactSha512,128)||!hex(p.buildIdentity,64)||!hex(p.serverSequence,16)||/^0+$/.test(p.serverSequence)||!CHANNELS.includes(p.channel)||!PHASES.includes(p.phase)||!p.phase.startsWith(role+'_')||p.parentIdentity!==''&&!hex(p.parentIdentity,64)||p.grantId!==''&&!hex(p.grantId,48)||typeof p.epoch!=='string'||!/^[1-9][0-9]{0,15}$/.test(p.epoch)||!id(p.sessionId)||!id(p.artifactId)||!id(p.issuanceId)||!text(p.packageId)||!text(p.signerId)||!text(p.versionLabel)||!Number.isSafeInteger(p.createdAt)||p.createdAt<1||!Number.isSafeInteger(p.updatedAt)||p.updatedAt<p.createdAt||p.expiresAt!==p.updatedAt+TTL||p.retiredAt!==undefined&&(!Number.isSafeInteger(p.retiredAt)||p.retiredAt<p.createdAt)||!plain(p.reports)||Object.keys(p.reports).length>3||Object.keys(p.reports).some(k=>!CHANNELS.includes(k)))bad();
   for(const r of Object.values(p.reports))if(!keys(r,['sequence','digest'])||!hex(r.sequence,16)||/^0+$/.test(r.sequence)||!hex(r.digest,64))bad();
   if(db){const b=Binding(db,row,role);if(!b||p.cohort!==b.cohort||p.epoch!==b.epoch||p.sessionId!==b.sessionId||p.artifactId!==b.artifact.id||p.artifactSha512!==b.artifact.sha512||p.issuanceId!==b.flow.launcherId||p.imageSha512!==ExpectedImage(db,b).sha512||p.imageSha256!==ExpectedImage(db,b).sha256)bad();}
  }
 }
 const g=row.nhwHandoffGrant;
 if(g!==undefined){
  if(!keys(g,['version','id','sourceRole','targetRole','sourceIdentity','sourcePeerId','sourceEpoch','targetArtifactId','targetImageSha512','cohort','sessionId','epoch','sequence','nonceHash','allowedProcessMask','allowedThreadMask','allowedActions','issuedAt','expiresAt','consumedAt','childKeyId','claimDigest'])||g.version!==1||!hex(g.id,48)||!hex(g.sourceIdentity,64)||!hex(g.sourcePeerId,48)||typeof g.sourceEpoch!=='string'||!/^[1-9][0-9]{0,15}$/.test(g.sourceEpoch)||!hex(g.cohort,64)||!hex(g.targetImageSha512,128)||!hex(g.nonceHash,64)||!hex(g.sequence,16)||!['A:B','B:O'].includes(g.sourceRole+':'+g.targetRole)||g.allowedProcessMask!==0x00101001||g.allowedThreadMask!==0x00100840||JSON.stringify(g.allowedActions)!==JSON.stringify(['QUERY','SYNCHRONIZE','HANDOFF_IPC','FAILED_CHILD_TERMINATE'])||!id(g.targetArtifactId)||!id(g.sessionId)||typeof g.epoch!=='string'||!/^[1-9][0-9]{0,15}$/.test(g.epoch)||!Number.isSafeInteger(g.issuedAt)||g.issuedAt<1||!Number.isSafeInteger(g.expiresAt)||g.expiresAt<=g.issuedAt||g.expiresAt>g.issuedAt+HANDOFF_TTL[g.targetRole]||!Number.isSafeInteger(g.consumedAt)||g.consumedAt<0||g.consumedAt>g.expiresAt||g.consumedAt>0&&(!/^[A-F0-9]{64}$/.test(g.childKeyId)||!hex(g.claimDigest,128))||g.consumedAt===0&&(g.childKeyId!==''||g.claimDigest!==''))bad();
  if(db){const b=Binding(db,row,g.targetRole),source=b?.flow.nhwPeerBindings?.[g.sourceRole];if(!b||g.cohort!==b.cohort||g.epoch!==b.epoch||g.sessionId!==b.sessionId||g.targetArtifactId!==b.artifact.id||g.targetImageSha512!==b.artifact.sha512||!source||source.identity!==g.sourceIdentity||source.peerId!==g.sourcePeerId||source.epoch!==g.sourceEpoch)bad();}
 }
 if(row.nhwHandoffGrantUnavailable!==undefined&&row.nhwHandoffGrantUnavailable!==true)bad();
}
module.exports={TTL,PHASES,CAPABILITIES,MATRIX,ParseEnrollment,StableIdentity,Enroll,Receipt,ResolveContext,MakeGrant,ConsumeGrant,Validate,Retire,Clear,ObserveTransitions,ProcessExited,RecordGrantRejection};
