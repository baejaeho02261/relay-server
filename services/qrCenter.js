'use strict';
const entry=require('./qrApproval'),store=require('./member/store');
function EntryRecord(row,index=require('./member/identity').MemberIndex()){const p=index.get(row.clientId);return {...row,purpose:'ENTRY',memberHandle:p?'@'+store.Handle(p):'',memberName:p?.nickname||''};}
function List(){const members=require('./member/identity').MemberIndex();return entry.List().map(x=>EntryRecord(x,members)).sort((a,b)=>b.issuedAt-a.issuedAt);}
function Summary(){return entry.Summary();}
function Scan(imageData){
 const payload=require('./qrImageDecoder').DecodeQrImage(imageData);
 const result=entry.InspectPayload(payload);return {...result,purpose:'ENTRY',request:EntryRecord(result.request)};
}
function ValidatePurpose(body){
 if((body.purpose&&body.purpose!=='ENTRY')||!/^QRA-[A-F0-9]{24}$/.test(body.requestId||''))store.Fail('QR_PURPOSE_MISMATCH');
}
function Approve(body,actor){
 ValidatePurpose(body);
 return {...entry.Approve(body.requestId,body.approvalToken,{memo:body.memo,tags:body.tags},actor),purpose:'ENTRY'};
}
function Reject(body,actor){ValidatePurpose(body);return entry.Reject(body.requestId,body.reason,actor);}
module.exports={List,Summary,Scan,Approve,Reject};
