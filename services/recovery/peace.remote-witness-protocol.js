"use strict";
const {ValidHead,EqualHead}=require('./peace.recovery-witness-file');
const DOMAINS=Object.freeze(['DESKTOP_BOOTSTRAP','DESKTOP_JOURNAL','DESKTOP_MACHINE_POLICY','DESKTOP_INTEGRITY']);
const ID=/^[a-f0-9]{64}$/;
function Body(value){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).some(k=>!['version','installationId','action','name','current','next'].includes(k))||value.version!==1||!ID.test(value.installationId||'')||!['status','head','open','prepare','settle'].includes(value.action))throw Error('RECOVERY_WITNESS_REQUEST_INVALID');
 if(value.action!=='status'&&!DOMAINS.includes(value.name))throw Error('RECOVERY_WITNESS_DOMAIN_INVALID');
 if(['open','prepare','settle'].includes(value.action)&&!ValidHead(value.current)||value.action==='prepare'&&!ValidHead(value.next))throw Error('RECOVERY_WITNESS_HEAD_INVALID');
 return value;
}
function Dispatch(witness,value){
 const b=Body(value),status=witness.status();
 if(status.installationId!==b.installationId)throw Error('RECOVERY_WITNESS_INSTALLATION_MISMATCH');
 if(b.action==='status')return status;
 const h=witness.head(b.name);
 if(b.action==='head')return h;
 if(b.action==='prepare'){
  // Safe exact retry after a transport interruption. No new sequence is minted.
  if(!(EqualHead(h.current,b.current)&&EqualHead(h.pending,b.next)))witness.prepare(b.name,b.current,b.next);
 }else if(b.action==='open'){
  // An ambiguous prepared write may contain a revocation. Never bless the old
  // backup just because it matches the pre-write head. Recovery must supply
  // the durable pending state or a separately reviewed incident procedure.
  if(h.pending&&!EqualHead(h.pending,b.current))throw Error('RECOVERY_WITNESS_UNRESOLVED_WRITE');
  witness.open(b.name,b.current);
 }
 else if(b.action==='settle'){
  // During normal commit do not allow a pending append to be rewound. Only
  // explicit startup/open may reconcile an unacknowledged ambiguous write.
  if(h.pending&&!EqualHead(h.pending,b.current))throw Error('RECOVERY_WITNESS_CONFLICT');
  witness.settle(b.name,b.current);
 }
 return {ok:true};
}
module.exports={DOMAINS,ID,Body,Dispatch};
