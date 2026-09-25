'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const s=require('./store'),config=require('../../config/config'),releases=require('../releaseManager');
const MAX_BYTES=256*1024*1024,TTL=120000,ROOT=path.join(config.DATA_DIR,'game-artifacts'),verified=new Map();
const fail=code=>s.Fail(code);
function SafeKey(value){if(!['PUBG','VALORANT'].includes(value))fail('GAME_ARTIFACT_INVALID');return value;}
function SafeName(value){const raw=String(value||'');if(!/^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}\.exe$/i.test(raw))fail('GAME_FILENAME_INVALID');return raw.replace(/ /g,'_');}
function Artifact(id){
 if(!/^[a-f0-9]{48}$/.test(String(id||'')))return null;
 try{const meta=JSON.parse(fs.readFileSync(path.join(ROOT,id+'.json'),'utf8')),file=path.join(ROOT,id+'.exe');
  if(meta.id!==id||!['PUBG','VALORANT'].includes(meta.gameKey)||!/^[a-f0-9]{64}$/.test(meta.sha256)||!Number.isSafeInteger(meta.bytes)||meta.bytes<64||meta.bytes>MAX_BYTES)return null;
  SafeName(meta.fileName);const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size!==meta.bytes)return null;return {...meta,file,stat:st};
 }catch(_){return null;}
}
function PublicArtifact(id,key){const a=Artifact(id);return a&&(!key||a.gameKey===key)?{id:a.id,gameKey:a.gameKey,fileName:a.fileName,sha256:a.sha256,bytes:a.bytes}:null;}
function ResolveArtifact(value,key,previous=''){
 const id=value===undefined?previous:String(value||'');if(!id)return '';
 if(!PublicArtifact(id,key))fail('GAME_ARTIFACT_UNAVAILABLE');return id;
}
function CheckPE(file,size){
 const fd=fs.openSync(file,'r');try{const head=Buffer.alloc(64);if(fs.readSync(fd,head,0,64,0)!==64||head[0]!==77||head[1]!==90)fail('GAME_EXE_INVALID');
  const offset=head.readUInt32LE(60);if(offset<64||offset>Math.min(size-4,4*1024*1024))fail('GAME_EXE_INVALID');
  const signature=Buffer.alloc(4);fs.readSync(fd,signature,0,4,offset);if(!signature.equals(Buffer.from([80,69,0,0])))fail('GAME_EXE_INVALID');
 }finally{fs.closeSync(fd);}
}
async function Upload(req,key,name){
 SafeKey(key);name=SafeName(name);fs.mkdirSync(ROOT,{recursive:true,mode:0o700});
 const id=crypto.randomBytes(24).toString('hex'),tmp=path.join(ROOT,id+'.tmp'),out=fs.createWriteStream(tmp,{flags:'wx',mode:0o600});
 let bytes=0;const hash=crypto.createHash('sha256');
 try{
  await new Promise((resolve,reject)=>{let stopped=false;const stop=err=>{if(stopped)return;stopped=true;out.destroy();reject(err);};
   out.on('error',stop);req.on('aborted',()=>stop(Error('GAME_UPLOAD_ABORTED')));req.on('error',stop);
   req.on('data',chunk=>{if(stopped)return;bytes+=chunk.length;if(bytes>MAX_BYTES){stop(Error('GAME_FILE_TOO_LARGE'));req.resume();return;}hash.update(chunk);if(!out.write(chunk)){req.pause();out.once('drain',()=>req.resume());}});
   req.on('end',()=>{if(!stopped)out.end(resolve);});
  });
  CheckPE(tmp,bytes);const meta={id,gameKey:key,fileName:name,bytes,sha256:hash.digest('hex'),at:Date.now()};
  fs.renameSync(tmp,path.join(ROOT,id+'.exe'));fs.writeFileSync(path.join(ROOT,id+'.json'),JSON.stringify(meta),{flag:'wx',mode:0o600});return meta;
 }catch(error){try{fs.unlinkSync(tmp);}catch(_){}try{fs.unlinkSync(path.join(ROOT,id+'.exe'));}catch(_){}throw error;}
}
function Entitlement(accountId,orderId){
 const p=s.ProfileById(accountId),o=s.DB().orders[orderId];
 if(!p||p.blocked||!o||o.accountId!==accountId||o.mergedInto||!['PAID','ACTIVE'].includes(o.status)||(o.expiresAt>0&&o.expiresAt<=Date.now()))fail('GAME_DOWNLOAD_FORBIDDEN');
 return {p,o};
}
function Sign(payload){return crypto.createHmac('sha256',releases.SigningSecret()).update('game-download-v1|'+payload).digest('base64url');}
function Issue(p,c,body){
 const {o}=Entitlement(p.id,String(body.orderId||''));const product=s.DB().products[o.productId],artifact=product&&PublicArtifact(product.artifactId,require('./commerce').GameKey(product));
 if(!artifact)fail('GAME_ARTIFACT_UNAVAILABLE');
 let origin;try{origin=new URL(config.UPDATE_BASE_URL);if(origin.protocol!=='https:'||origin.username||origin.password||origin.search||origin.hash)fail('GAME_DOWNLOAD_URL_INVALID');}catch(_){fail('GAME_DOWNLOAD_URL_INVALID');}
 const expiresAt=Date.now()+TTL,payload=Buffer.from(JSON.stringify({v:1,account:p.id,order:o.id,artifact:artifact.id,exp:expiresAt})).toString('base64url');
 return {download:{accountId:p.id,orderId:o.id,status:o.status,gameKey:artifact.gameKey,fileName:artifact.fileName,sha256:artifact.sha256,bytes:artifact.bytes,expiresAt,url:origin.origin+'/game-download/'+payload+'.'+Sign(payload)}};
}
function Verify(token){
 const [payload,sig,...extra]=String(token||'').split('.');if(extra.length||!payload||payload.length>1200||!sig)fail('GAME_DOWNLOAD_FORBIDDEN');
 const expected=Buffer.from(Sign(payload)),actual=Buffer.from(sig);if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual))fail('GAME_DOWNLOAD_FORBIDDEN');
 const value=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));if(value.v!==1||!Number.isSafeInteger(value.exp)||value.exp<=Date.now()||value.exp>Date.now()+TTL)fail('GAME_DOWNLOAD_FORBIDDEN');
 const {o}=Entitlement(value.account,value.order),product=s.DB().products[o.productId];
 if(!product||product.artifactId!==value.artifact)fail('GAME_ARTIFACT_UNAVAILABLE');
 const artifact=Artifact(value.artifact);if(!artifact||artifact.gameKey!==require('./commerce').GameKey(product))fail('GAME_ARTIFACT_UNAVAILABLE');return artifact;
}
async function VerifyBytes(a){
 const key=a.id+'|'+a.sha256+'|'+a.stat.size+'|'+a.stat.mtimeMs+'|'+a.stat.ctimeMs;
 if(verified.has(key))return;
 const hash=crypto.createHash('sha256');for await(const chunk of fs.createReadStream(a.file))hash.update(chunk);
 if(hash.digest('hex')!==a.sha256)fail('GAME_CHECKSUM_MISMATCH');CheckPE(a.file,a.bytes);
 if(verified.size>64)verified.clear();verified.set(key,true);
}
async function Serve(req,res,pathname,url){
 if(!pathname.startsWith('/game-download/'))return false;
 const method=String(req.method||'GET').toUpperCase();res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');
 if(!['GET','HEAD'].includes(method)){res.writeHead(405);res.end();return true;}
 try{
  const a=Verify(pathname.slice('/game-download/'.length));await VerifyBytes(a);
  let start=0,end=a.bytes-1,status=200;
  if(req.headers.range){const m=/^bytes=(\d+)-(\d*)$/.exec(req.headers.range);if(!m)fail('GAME_RANGE_INVALID');start=Number(m[1]);if(m[2])end=Number(m[2]);if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start>end||end>=a.bytes)fail('GAME_RANGE_INVALID');status=206;}
  const headers={'Content-Type':'application/octet-stream','Content-Length':end-start+1,'Accept-Ranges':'bytes','Content-Disposition':`attachment; filename="${a.fileName}"`,'X-Content-SHA256':a.sha256};
  if(status===206)headers['Content-Range']=`bytes ${start}-${end}/${a.bytes}`;
  res.writeHead(status,headers);if(method==='HEAD'){res.end();return true;}
  const input=fs.createReadStream(a.file,{start,end});input.on('error',()=>res.destroy());res.once('close',()=>input.destroy());input.pipe(res);return true;
 }catch(error){res.writeHead(error.message==='GAME_RANGE_INVALID'?416:403,{'Content-Type':'text/plain; charset=utf-8'});res.end('Download unavailable');return true;}
}
module.exports={MAX_BYTES,Upload,Artifact,PublicArtifact,ResolveArtifact,Issue,Verify,VerifyBytes,Serve};
