'use strict';
// Run on a SEPARATE, restricted packing machine/container. Never on the
// production licensing/signing host. This runs the configured VMProtect CLI,
// not the uploaded PE. No private release keys are accepted or accessed.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),https=require('node:https'),{spawn}=require('node:child_process');
const p=require("../../services/artifacts/peace.desktop-packing-protocol");
function Trusted(file,digest,maximum){
 if(!path.isAbsolute(file||'')||!p.IsDigest(digest))throw Error('PACKER_TRUST_CONFIG_INVALID');
 const bytes=require("../../services/artifacts/peace.bounded-artifact-read").Read(file,maximum);
 if(!p.Equal(p.Sha512(bytes),digest))throw Error('PACKER_TRUST_FILE_CHANGED');return bytes;
}
function Config(){
 require("../../services/security/peace.service-isolation").Check('packer');
 const e=process.env;
 if(['ADMIN_SECRET','GAME_RELEASE_APPROVAL_KEY_B64','QR_APPROVAL_SECRET'].some(k=>e[k]))throw Error('PACKER_ISOLATION_REQUIRED');
 const profiles={};for(const c of ['A','B','O']){profiles[c]={file:e['PACKER_PROFILE_'+c+'_FILE'],sha512:e['PACKER_PROFILE_'+c+'_SHA512'],inputSha512:e['PACKER_INPUT_'+c+'_SHA512']};if(!p.IsDigest(profiles[c].inputSha512))throw Error('PACKER_PROFILE_INPUT_REQUIRED');Trusted(profiles[c].file,profiles[c].sha512,1024*1024);}
 Trusted(e.PACKER_TOOL_FILE,e.PACKER_TOOL_SHA512,p.MAX_BYTES);
 if(!p.IsDigest(e.PACKER_CLIENT_SPKI_SHA512))throw Error('PACKER_CLIENT_PIN_INVALID');
 return {tool:e.PACKER_TOOL_FILE,toolSha512:e.PACKER_TOOL_SHA512,profiles,clientPin:e.PACKER_CLIENT_SPKI_SHA512};
}
function DiskUsage(dir,limit=512*1024*1024){let bytes=0,count=0;function walk(d,depth){if(depth>8)throw Error('PACKER_DISK_LIMIT');for(const n of fs.readdirSync(d)){if(++count>1024)throw Error('PACKER_DISK_LIMIT');const p=path.join(d,n),s=fs.lstatSync(p);if(s.isSymbolicLink())throw Error('PACKER_TEMP_LINK_FORBIDDEN');if(s.isDirectory())walk(p,depth+1);else if(!s.isFile()||s.nlink!==1||(bytes+=s.size)>limit)throw Error('PACKER_DISK_LIMIT');}}walk(dir,0);return bytes;}
function RunTool(tool,args,cwd){return new Promise((resolve,reject)=>{
 let finished=false,total=0,failure;const child=spawn(tool,args,{cwd,shell:false,windowsHide:true,env:require("../../services/security/peace.service-isolation").ChildEnvironment(),stdio:['ignore','pipe','pipe']});
 const timer=setTimeout(()=>{failure=Error('PACKER_TIMEOUT');child.kill('SIGKILL');},120000);timer.unref();
 const diskTimer=setInterval(()=>{try{DiskUsage(cwd);}catch(e){if(!failure){failure=e;child.kill('SIGKILL');}}},250);diskTimer.unref();
 for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{total+=b.length;if(total>1048576&&!failure){failure=Error('PACKER_OUTPUT_LIMIT');child.kill('SIGKILL');}});
 function end(e){if(finished)return;finished=true;clearTimeout(timer);clearInterval(diskTimer);e?reject(e):resolve();}
 child.once('error',end);child.once('close',(code,signal)=>end(failure||(code!==0||signal?Error('PACKER_PROCESS_FAILED'):null)));
 });}
function CreateServer(c,options){let busy=false;const seen=new Map();
 const server=https.createServer({...options,minVersion:'TLSv1.2',requestCert:true,rejectUnauthorized:true},async(req,res)=>{
  let dir,output,ownsSlot=false;function error(code,status=400){req.resume();if(res.headersSent){res.destroy();return;}res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({ok:false,error:code}));}
  try{
   if(!req.socket.authorized||!p.Equal(p.Spki(req.socket.getPeerCertificate().raw),c.clientPin))return error('PACKER_CLIENT_DENIED',403);
   const m=/^\/v1\/pack\/([ABO])$/.exec(req.url);if(req.method!=='POST'||!m)return error('PACKER_ROUTE_INVALID',404);
   if(busy)return error('PACKER_BUSY',429);
   const id=req.headers['x-packing-id'],inputHash=req.headers['x-input-sha512'],profile=c.profiles[m[1]];
   if(!/^[a-f0-9]{32}$/.test(id||'')||!p.Equal(inputHash,profile.inputSha512)||req.headers['content-type']!=='application/octet-stream'||!p.Equal(req.headers['x-profile-sha512'],profile.sha512)||!p.Equal(req.headers['x-tool-sha512'],c.toolSha512))return error('PACKER_REQUEST_INVALID');
   for(const [key,at]of seen)if(at<Date.now()-600000)seen.delete(key);
   if(seen.has(id)||seen.size>=64)return error('PACKER_REPLAY_OR_LIMIT',409);
   busy=true;ownsSlot=true;seen.set(id,Date.now());
   const input=await p.ReadBody(req);p.Pe(input);if(!p.Equal(p.Sha512(input),inputHash))throw Error('PACKER_INPUT_CHANGED');
   // The profiles and tool are operator-installed/pinned. They cannot be chosen
   // by a browser path, command string or uploaded project/script.
   Trusted(c.tool,c.toolSha512,p.MAX_BYTES);const profileBytes=Trusted(profile.file,profile.sha512,1024*1024);
   const disk=await fs.promises.statfs(os.tmpdir(),{bigint:true});if(disk.bavail*disk.bsize<BigInt(256*1024*1024+input.length))throw Error('PACKER_DISK_RESERVE');
   dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-packer-'));fs.chmodSync(dir,0o700);
   const source=path.join(dir,'input.exe'),target=path.join(dir,'output.exe');
   fs.writeFileSync(source,input,{flag:'wx',mode:0o600});input.fill(0);
   // Keep the original reviewed profile path so its approved relative references
   // remain valid. Worker filesystem/network isolation is an operator requirement.
   await RunTool(c.tool,[source,target,'-pf',profile.file,'-we'],dir);
   Trusted(c.tool,c.toolSha512,p.MAX_BYTES);if(!p.Equal(p.Sha512(Trusted(profile.file,profile.sha512,1024*1024)),p.Sha512(profileBytes)))throw Error('PACKER_PROFILE_CHANGED');
   DiskUsage(dir);output=require("../../services/artifacts/peace.bounded-artifact-read").Read(target,p.MAX_BYTES);p.Pe(output);if(require("../../services/artifacts/peace.release-exposure").ScanBytes(output).status!=='PASS')throw Error('PACKER_EXPOSURE_BLOCKED');const hash=p.Sha512(output);if(hash===inputHash)throw Error('PACKER_OUTPUT_UNCHANGED');
   res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':output.length,'Cache-Control':'no-store','X-Packing-Id':id,'X-Input-Sha512':inputHash,'X-Output-Sha512':hash,'X-Profile-Sha512':profile.sha512,'X-Tool-Sha512':c.toolSha512});
   await new Promise((resolve,reject)=>{res.once('error',reject);res.end(output,resolve);});
  }catch(e){error(/^PACK(?:ER|ING)_[A-Z_]+$/.test(e.message)?e.message:'PACKER_FAILED',422);}
  finally{output?.fill(0);try{if(dir)fs.rmSync(dir,{recursive:true,force:true});}catch(_){console.error('PACKER_TEMP_CLEANUP_FAILED');}if(ownsSlot)busy=false;}
 });server.requestTimeout=30000;server.headersTimeout=10000;server.maxConnections=8;return server;
}
if(require.main===module){try{const listener=require('../../config/peace.runtime-environment').ReadListener('packer');const c=Config(),e=process.env;const server=CreateServer(c,{ca:fs.readFileSync(e.PACKER_TLS_CA_FILE),cert:fs.readFileSync(e.PACKER_TLS_CERT_FILE),key:fs.readFileSync(e.PACKER_TLS_KEY_FILE)});server.listen(listener.port,listener.host,()=>console.log('PACKER_READY: mTLS required; final outputs remain unapproved'));server.once('error',()=>{console.error('PACKER_LISTEN_FAILED');process.exitCode=1;});}catch(e){console.error(/^(?:PACKER|RUNTIME_CONFIG)_[A-Z_]+$/.test(e.message)?e.message:'PACKER_START_FAILED');process.exitCode=1;}}
module.exports={Trusted,Config,CreateServer,DiskUsage};
