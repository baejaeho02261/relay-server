'use strict';
// Exercise the real administrator session guard and route parser. Domain
// services are replaced only to isolate read authorization from disk fixtures.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-state-read-routes-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'SYNTHETIC-STATE-ROUTES'});
const route=require('../web/routes/desktopServerStateRoutes'),auth=require('../web/webAuth');
const verification=require('../services/desktopManualVerification'),lifecycle=require('../services/desktopLifecycleTrace'),audit=require('../services/desktopOperationAudit');
const performance=require('../services/desktopPerformanceMetrics');
const saved={context:verification.Context,overview:lifecycle.Overview,snapshot:performance.Snapshot,access:audit.RecordAccess};
let calls=0,reads=0;
verification.Context=manifestId=>{calls++;return {manifestId,publicationApproval:false};};
lifecycle.Overview=options=>{calls++;return {options,authorityGranted:false};};
performance.Snapshot=options=>{calls++;return {options,scope:'OPERATIONAL_OBSERVATION_NOT_AUTHORITY'};};
audit.RecordAccess=(kind)=>{assert.equal(kind,'ADMIN_STORAGE_READ');reads++;};
const prefix='/api/desktop/bootstrap/server-state',req={headers:{},socket:{remoteAddress:'127.0.0.1',encrypted:true}};
async function request(suffix,session,method='GET'){
 const url=new URL(prefix+suffix,'http://localhost');let code,body;
 const res={writeHead(c){code=c;},end(text){body=JSON.parse(text);}};
 assert.equal(await route.Handle({method,pathname:url.pathname,url,req,res,session}),true);
 return {code,body};
}
(async()=>{try{
 const manifest='a'.repeat(128),flow='B'.repeat(24),license='C'.repeat(24),admin=auth.CreateSession(req,'admin');
 for(const suffix of ['/verification-context?manifestId='+manifest,'/lifecycle','/performance']){
  assert.equal((await request(suffix,null)).code,403);
  assert.equal((await request(suffix,{id:'viewer',role:'viewer'})).code,403);
 }
 assert.equal(calls,0);
 const context=await request('/verification-context?manifestId='+manifest,admin);
 assert.equal(context.code,200);assert.equal(context.body.manifestId,manifest);assert.equal(context.body.publicationApproval,false);
 const overview=await request('/lifecycle?flowId='+flow+'&licenseId='+license+'&limit=50',admin);
 assert.equal(overview.code,200);assert.deepEqual(overview.body.options,{flowId:flow,licenseId:license,limit:50});
 assert.equal((await request('/lifecycle',admin)).body.options.limit,20);
 assert.equal((await request('/lifecycle?flowId=BF-'+flow+'&licenseId=DL-'+license,admin)).code,200);
 const metrics=await request('/performance?resolution=day&limit=365',admin);
 assert.equal(metrics.code,200);assert.deepEqual(metrics.body.options,{resolution:'day',limit:365});
 assert.equal(metrics.body.scope,'OPERATIONAL_OBSERVATION_NOT_AUTHORITY');
 assert.deepEqual((await request('/performance',admin)).body.options,{resolution:'hour',limit:24});
 assert.deepEqual((await request('/performance?resolution=day',admin)).body.options,{resolution:'day',limit:30});
 assert.equal((await request('/performance?resolution=hour&limit=720',admin)).code,200);
 const validCalls=calls,validReads=reads;
 for(const suffix of [
  '/verification-context','/verification-context?manifestId=','/verification-context?manifestId='+manifest.toUpperCase(),
  '/verification-context?manifestId='+manifest+'&manifestId='+manifest,'/verification-context?manifestId='+manifest+'&approved=true',
  '/lifecycle?flowId=','/lifecycle?flowId='+flow.toLowerCase(),'/lifecycle?flowId='+flow+'&flowId='+flow,
  '/lifecycle?licenseId=bad','/lifecycle?limit=0','/lifecycle?limit=51','/lifecycle?limit=01',
  '/lifecycle?limit=1e1','/lifecycle?limit=20&limit=20','/lifecycle?limit[]=20','/lifecycle?__proto__=x',
  '/lifecycle?flowId='+encodeURIComponent(flow+'\n'),
  '/performance?resolution=minute','/performance?resolution=','/performance?resolution=hour&resolution=hour',
  '/performance?limit=0','/performance?limit=01','/performance?limit=1e2','/performance?limit=721',
  '/performance?resolution=day&limit=366','/performance?limit=10&limit=10','/performance?from=1',
  '/performance?__proto__=x','/performance?limit='+encodeURIComponent('24\n')
 ])assert.equal((await request(suffix,admin)).code,400,suffix);
 assert.equal(calls,validCalls);assert.equal(reads,validReads);
 // Reads are permitted after the short reauthentication window, while the
 // session remains live. Import/mutation rules are tested in their own suite.
 const realNow=Date.now,now=realNow();try{
  Date.now=()=>now+auth.REAUTH_MS+1;
  assert.equal((await request('/lifecycle',admin)).code,200);
 }finally{Date.now=realNow;}
 auth.RevokeAllSessions();const before=calls;
 assert.equal((await request('/lifecycle',admin)).code,401);assert.equal((await request('/performance',admin)).code,401);assert.equal(calls,before);
 console.log('Server-state read routes: admin/role/revocation, exact queries, bounded filters and read-only service calls PASS.');
}finally{
 verification.Context=saved.context;lifecycle.Overview=saved.overview;performance.Snapshot=saved.snapshot;audit.RecordAccess=saved.access;
 fs.rmSync(temp,{recursive:true,force:true});
}})().catch(error=>{console.error(error);process.exitCode=1;});
