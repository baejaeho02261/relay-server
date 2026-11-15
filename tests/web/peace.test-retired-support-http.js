'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-retired-support-http-'));
Object.assign(process.env,{DATA_DIR:directory,HA_ENABLED:'0',COZY_DESKTOP_MODE:'1',STORAGE_ENGINE:'sqlite'});
const {RequestHandler}=require('../../web/http/peace.web-server');
const server=http.createServer((req,res)=>{Promise.resolve(RequestHandler(req,res)).catch(error=>{res.statusCode=500;res.end(error.message);});});
const id='A'.repeat(24),paths=['/diagnostics','/diagnostics.html','/api/diagnostic-capture/status','/api/diagnostic-capture/upload',`/api/desktop/members/${id}/captures`,`/api/desktop/members/${id}/captures/${id}/image`,`/api/desktop/members/${id}/captures/${id}/revoke`,`/support-captures/${id}.enc`,'/scripts/diagnostics/peace.diagnostic-capture.js','/scripts/desktop/peace.admin-desktop-captures.js','/styles/diagnostics.css'];
function Request(route,method){return new Promise((resolve,reject)=>{const req=http.request({hostname:'127.0.0.1',port:server.address().port,path:route,method,agent:false,timeout:2000},res=>{let body='';res.setEncoding('utf8');res.on('data',chunk=>body+=chunk);res.once('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));});req.once('timeout',()=>req.destroy(Error('TEST_TIMEOUT')));req.once('error',reject);req.end(method==='POST'?'{}':undefined);});}
(async()=>{try{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 for(const route of paths)for(const method of ['GET','POST','HEAD']){
  const res=await Request(route,method);assert.equal(res.status,410,method+' '+route);assert.match(res.headers['cache-control'],/no-store/);assert.match(res.headers['permissions-policy'],/display-capture=\(\)/);assert.doesNotMatch(res.headers['content-type']||'',/image\//);if(method!=='HEAD')assert.equal(JSON.parse(res.body).error,'FEATURE_REMOVED');
 }
 assert.equal(fs.existsSync(path.join(directory,'support-captures')),false);
 const root=path.resolve(__dirname,'../..');for(const file of ['public/diagnostics.html','public/scripts/diagnostics/peace.diagnostic-capture.js','public/scripts/desktop/peace.admin-desktop-captures.js','services/diagnostics/peace.support-captures.js','services/diagnostics/peace.strict-png.js','web/routes/licensing/peace.desktop-capture-routes.js','web/http/peace.diagnostic-capture-public.js'])assert.equal(fs.existsSync(path.join(root,file)),false,file);
 console.log('RETIRED SUPPORT HTTP PASS: old document, code, image, list and upload routes return410/no-store for GET/POST/HEAD without authentication or capture storage.');
}finally{await new Promise(resolve=>server.close(resolve));fs.rmSync(directory,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
