'use strict';
// Real metadata storage, budget and raw-upload route; synthetic DLL bytes and
// authenticated admin boundary fixtures. No production data or native process.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{EventEmitter}=require('node:events');
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'module-baseline-space-'));process.env.DATA_DIR=temporary;process.env.STORAGE_ENGINE='json';
const {Budget,MiB}=require('../../services/runtime/spacex.server-resource-budget'),reports=require('../../services/integrity/spacex.desktop-integrity-reports'),{Isolated}=require('../fixtures/protocol/spacex.completion-6-10-fixture');
const OVERHEAD=128*1024,MAX_STORE=64*MiB;
test.after(()=>fs.rmSync(temporary,{recursive:true,force:true}));
function DLL(padding=0){const bytes=require('../fixtures/bootstrap/spacex.desktop-bootstrap-fixture').PE('B','SYNTHETIC DLL'),pe=bytes.readUInt32LE(0x3c);bytes.writeUInt16LE(bytes.readUInt16LE(pe+22)|0x2000,pe+22);return padding?Buffer.concat([bytes,Buffer.alloc(padding)]):bytes;}
function BudgetWithSpace(free){const b=new Budget({clock:()=>100,memory:()=>0,signal:()=>{}});b.diskRequired=true;b.sampleDisk(free,true,1024*MiB);return b;}
async function Upload({name='route.dll',bytes=DLL(),budget,prepare=async()=>{},pathname='/api/desktop/bootstrap/module-baselines',contentLength=true,register=reports.RegisterBaseline,stage=()=>({id:'artifact'})}={}){
 const reservations=[],ops={sha512:()=> 'a'.repeat(128),AuditIntent:()=>{},Stage:stage,Revision:()=>1},response={};
 const Json=(_res,status,body)=>{response.status=status;response.body=body;};
 const route=Isolated('web/routes/bootstrap/spacex.desktop-bootstrap-routes.js',[],{
  '../../../services/bootstrap/spacex.desktop-bootstrap':{MAX_ARTIFACT_BYTES:64*MiB,messages:{},Fail(code,status=400){const e=Error(code);e.desktopError=true;e.status=status;throw e;}},
  '../../http/spacex.api-context':{RequireAdmin:()=>true,Json,ApiError:(_res,status,error)=>Json(_res,status,{ok:false,error})},
  '../../authentication/spacex.web-auth':{ValidateCsrf:()=>true},'../../../services/network/spacex.ha-coordinator':{CanAcceptTraffic:()=>true},
  '../../../services/authentication/spacex.desktop-admin-guard':{CheckSession:()=>({ok:true}),Authorize:()=>({ok:true})},
  '../../../services/runtime/spacex.server-resource-budget':{Admit(kind,options){reservations.push({...options});return budget.admit(kind,options);}},
  '../../../services/integrity/spacex.desktop-integrity-reports':{BaselineWriteReservation:reports.BaselineWriteReservation,RegisterBaseline:register},
  '../../../services/artifacts/spacex.desktop-pe-cache':{Prepare:prepare},'../../../services/operations/spacex.registration-reset':{AssertAvailable:()=>{}},
  '../../../services/security/spacex.desktop-security-operations':ops,'../../../services/security/spacex.desktop-security-authority':{Policy:()=>({revision:1})},
  '../../../services/licensing/spacex.desktop-licenses':{messages:{}}
 });
 const req=new EventEmitter();req.headers={'content-type':'application/octet-stream',...(contentLength?{'content-length':String(bytes.length)}:{})};req.resume=()=>{};
 const url=new URL('https://fixture.invalid'+pathname+'?fileName='+name+'&component=B&version=1.0.0'),pending=route.HandleUpload({method:'POST',pathname,url,req,res:{},session:{role:'ADMIN',id:'owner'}});
 req.emit('data',bytes);req.emit('end');await pending;return {...response,reservations};
}
test('initial reservation reads size without creating or modifying the store',()=>{assert.equal(reports.BaselineWriteReservation(),OVERHEAD);assert.equal(fs.existsSync(path.dirname(reports.FILE)),false);reports.Baselines();const before=fs.readFileSync(reports.FILE);assert.equal(reports.BaselineWriteReservation(),before.length+OVERHEAD);assert.deepEqual(fs.readFileSync(reports.FILE),before);});
test('metadata-only DLL upload succeeds with less free space than raw DLL size plus reserve',async()=>{const bytes=DLL(2*MiB),initial=reports.BaselineWriteReservation(),budget=BudgetWithSpace(256*MiB+initial+16384),result=await Upload({bytes,budget});assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(result.reservations[0].bytes,4*bytes.length);assert.equal(result.reservations[0].diskBytes,initial);assert(initial<bytes.length);assert(fs.statSync(reports.FILE).size<16384);assert.equal(budget.snapshot().active,0);assert.equal(budget.snapshot().reservedDiskBytes,0);});
test('report growth during async parsing is rechecked before atomic write and head update',async()=>{const initial=reports.BaselineWriteReservation(),budget=BudgetWithSpace(256*MiB+initial),count=reports.Baselines().items.length;let store,head;
 const result=await Upload({name:'growth.dll',budget,prepare:async()=>{reports.Record({stage:'A',check:'OWN_IMAGE',status:'CLIENT_DIAGNOSTIC',reason:'PERIODIC'});store=fs.readFileSync(reports.FILE);head=fs.readFileSync(reports.FILE+'.head');}});
 assert.equal(result.status,429);assert.equal(result.body.error,'RESOURCE_DISK_RESERVE');assert(result.body.resource.requestedDiskBytes>initial);assert(result.body.resource.shortfallBytes>0);assert.equal(reports.Baselines().items.length,count);assert.deepEqual(fs.readFileSync(reports.FILE),store);assert.deepEqual(fs.readFileSync(reports.FILE+'.head'),head);assert.equal(budget.snapshot().reservedDiskBytes,0);
});
test('final reservation failure rolls back baseline upgrades as well as new rows',()=>{const legacy=reports.RegisterBaseline('legacy.dll','synthetic',DLL(),'ADMIN');delete legacy.exportTableStatus;const before=fs.readFileSync(reports.FILE),head=fs.readFileSync(reports.FILE+'.head');assert.throws(()=>reports.RegisterBaseline('legacy.dll','synthetic',DLL(),'ADMIN',()=>{throw Error('TEST_SPACE_REJECTED');}),/TEST_SPACE_REJECTED/);assert.equal(Object.hasOwn(legacy,'exportTableStatus'),false);assert.deepEqual(fs.readFileSync(reports.FILE),before);assert.deepEqual(fs.readFileSync(reports.FILE+'.head'),head);reports.RegisterBaseline('legacy.dll','synthetic',DLL(),'ADMIN');});
test('unknown Content-Length uses the bounded RAM limit but only metadata disk space',async()=>{const initial=reports.BaselineWriteReservation(),budget=BudgetWithSpace(512*MiB),result=await Upload({name:'chunked.dll',budget,contentLength:false});assert.equal(result.status,200);assert.equal(result.reservations[0].bytes,4*32*MiB);assert.equal(result.reservations[0].diskBytes,initial);});
test('executable artifacts still reserve their raw bytes on disk',async()=>{const bytes=Buffer.alloc(4096),budget=BudgetWithSpace(512*MiB),result=await Upload({name:'B.exe',bytes,budget,pathname:'/api/desktop/bootstrap/artifacts'});assert.equal(result.status,200);assert.equal(result.reservations[0].diskBytes,bytes.length);});
test('unsafe or oversized metadata files are rejected before upload',()=>{for(const stat of [{isFile:()=>false,isSymbolicLink:()=>false,nlink:1,size:1},{isFile:()=>true,isSymbolicLink:()=>true,nlink:1,size:1},{isFile:()=>true,isSymbolicLink:()=>false,nlink:2,size:1},{isFile:()=>true,isSymbolicLink:()=>false,nlink:1,size:MAX_STORE+1}]){const isolated=Isolated('services/integrity/spacex.desktop-integrity-reports.js',[],{'node:fs':{lstatSync:()=>stat}});assert.throws(()=>isolated.BaselineWriteReservation(),/INTEGRITY_REPORT_STORAGE_INVALID/);}});
