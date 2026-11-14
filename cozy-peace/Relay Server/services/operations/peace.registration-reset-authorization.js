'use strict';
// Web authorization is persisted in the authenticated bootstrap authority.
// Its private capability is enabled only around the pre-listener startup reset;
// a pending flag alone never authorizes a live request to mutate every store.
const SCOPE='ABO_LICENSES_ISSUANCE_OPERATIONS_V1',ID=/^[a-f0-9]{64}$/;
const FIELDS=['version','id','scope','requestedAt','actorHash','requestSha512','expectedEpoch'];
let startupWebId='';
function Fail(code){throw Error('REGISTRATION_RESET_'+code);}
function Validate(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).length!==FIELDS.length||FIELDS.some(k=>!Object.hasOwn(value,k))||value.version!==1||typeof value.id!=='string'||!ID.test(value.id)||value.scope!==SCOPE||!Number.isSafeInteger(value.requestedAt)||value.requestedAt<1||typeof value.actorHash!=='string'||!ID.test(value.actorHash)||typeof value.requestSha512!=='string'||!/^[a-f0-9]{128}$/.test(value.requestSha512)||!Number.isSafeInteger(value.expectedEpoch)||value.expectedEpoch<0)Fail('WEB_AUTHORIZATION_INVALID');
 return value;
}
function WebRequest(){const value=require('../bootstrap/peace.desktop-bootstrap-store').Load().registrationResetAuthorization;return value===undefined?null:structuredClone(Validate(value));}
function Assert(id){
 if(typeof id!=='string'||!ID.test(id))Fail('ID_INVALID');
 if(process.env.COZY_REGISTRATION_RESET_ID===id&&process.env.COZY_REGISTRATION_RESET_SCOPE===SCOPE)return;
 if(startupWebId===id&&WebRequest()?.id===id)return;
 Fail('NOT_AUTHORIZED');
}
function DuringStartup(id,operation){
 if(startupWebId||typeof operation!=='function'||WebRequest()?.id!==id)Fail('NOT_AUTHORIZED');
 startupWebId=id;try{return operation();}finally{startupWebId='';}
}
module.exports={SCOPE,Validate,WebRequest,Assert,DuringStartup};
