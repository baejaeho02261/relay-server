'use strict';
// Verify the private startup capability boundary without touching a DATA_DIR.
const test=require('node:test'),assert=require('node:assert/strict');
const authFile=require.resolve('../../services/operations/peace.registration-reset-authorization');
const bootstrapFile=require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store');
const ID='a'.repeat(64),OTHER='b'.repeat(64);
function Fixture(operation){
 const oldBootstrap=require.cache[bootstrapFile],oldAuth=require.cache[authFile];
 const oldId=process.env.COZY_REGISTRATION_RESET_ID,oldScope=process.env.COZY_REGISTRATION_RESET_SCOPE;
 const db={};require.cache[bootstrapFile]={id:bootstrapFile,filename:bootstrapFile,loaded:true,exports:{Load:()=>db}};
 delete require.cache[authFile];delete process.env.COZY_REGISTRATION_RESET_ID;delete process.env.COZY_REGISTRATION_RESET_SCOPE;
 try{const permission=require(authFile);return operation(permission,db);}
 finally{if(oldBootstrap)require.cache[bootstrapFile]=oldBootstrap;else delete require.cache[bootstrapFile];if(oldAuth)require.cache[authFile]=oldAuth;else delete require.cache[authFile];if(oldId===undefined)delete process.env.COZY_REGISTRATION_RESET_ID;else process.env.COZY_REGISTRATION_RESET_ID=oldId;if(oldScope===undefined)delete process.env.COZY_REGISTRATION_RESET_SCOPE;else process.env.COZY_REGISTRATION_RESET_SCOPE=oldScope;}
}
function Grant(){return {version:1,id:ID,scope:'ABO_LICENSES_ISSUANCE_OPERATIONS_V1',requestedAt:1,actorHash:'c'.repeat(64),requestSha512:'d'.repeat(128),expectedEpoch:0};}
test('persisted web intent alone never authorizes live reset helpers',()=>Fixture((permission,db)=>{
 assert.equal(permission.WebRequest(),null);assert.throws(()=>permission.Assert(ID),/NOT_AUTHORIZED/);
 db.registrationResetAuthorization=Grant();assert.throws(()=>permission.Assert(ID),/NOT_AUTHORIZED/);
 permission.DuringStartup(ID,()=>{permission.Assert(ID);assert.throws(()=>permission.Assert(OTHER),/NOT_AUTHORIZED/);assert.throws(()=>permission.DuringStartup(ID,()=>{}),/NOT_AUTHORIZED/);});
 assert.throws(()=>permission.Assert(ID),/NOT_AUTHORIZED/);assert.equal(process.env.COZY_REGISTRATION_RESET_ID,undefined);assert.equal(process.env.COZY_REGISTRATION_RESET_SCOPE,undefined);
}));
test('startup capability is revoked after failure and grant changes',()=>Fixture((permission,db)=>{
 db.registrationResetAuthorization=Grant();assert.throws(()=>permission.DuringStartup(ID,()=>{permission.Assert(ID);throw Error('SYNTHETIC_FAILURE');}),/SYNTHETIC_FAILURE/);
 assert.throws(()=>permission.Assert(ID),/NOT_AUTHORIZED/);
 permission.DuringStartup(ID,()=>{db.registrationResetAuthorization.id=OTHER;assert.throws(()=>permission.Assert(ID),/NOT_AUTHORIZED/);});
 assert.throws(()=>permission.DuringStartup(ID,()=>{}),/NOT_AUTHORIZED/);
}));
test('authenticated request shape is exact and returned data cannot mutate authority',()=>Fixture((permission,db)=>{
 db.registrationResetAuthorization=Grant();const copy=permission.WebRequest();copy.id=OTHER;assert.equal(db.registrationResetAuthorization.id,ID);
 for(const patch of [{version:2},{id:[ID]},{actorHash:['c'.repeat(64)]},{requestSha512:['d'.repeat(128)]},{expectedEpoch:-1},{expectedEpoch:Number.MAX_SAFE_INTEGER+1},{scope:'ALL'},{requestedAt:0},{extra:true}])assert.throws(()=>permission.Validate({...Grant(),...patch}),/WEB_AUTHORIZATION_INVALID/);
 const missing=Grant();delete missing.requestSha512;assert.throws(()=>permission.Validate(missing),/WEB_AUTHORIZATION_INVALID/);
 db.registrationResetAuthorization={...Grant(),scope:'MALFORMED'};assert.throws(()=>permission.WebRequest(),/WEB_AUTHORIZATION_INVALID/);
}));
test('operator maintenance still requires exact environment nonce and scope',()=>Fixture(permission=>{
 process.env.COZY_REGISTRATION_RESET_ID=ID;process.env.COZY_REGISTRATION_RESET_SCOPE=permission.SCOPE;permission.Assert(ID);
 assert.throws(()=>permission.Assert(OTHER),/NOT_AUTHORIZED/);process.env.COZY_REGISTRATION_RESET_SCOPE='WRONG';assert.throws(()=>permission.Assert(ID),/NOT_AUTHORIZED/);assert.throws(()=>permission.Assert('../invalid'),/ID_INVALID/);
}));
