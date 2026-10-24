"use strict";
// Optional ingress-only service. No DB, admin secret, release key, local session
// store or filesystem uploads. Stream requests to one pinned mTLS authority.
const http=require('node:http'),https=require('node:https'),net=require('node:net');
const tls=require("../../services/network/peace.server-peer-tls");
const HEADERS=['accept','content-type','content-length','cookie','origin','referer','user-agent','range','if-none-match','x-csrf-token','x-admin-action','x-approval-ticket','x-admin-enrollment-token','x-game-release-key-id','x-game-release-signature'];
const HOP=new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
function Config(e=process.env){
 require("../../services/security/peace.service-isolation").Check('gateway',e);
 const upstream=tls.Endpoint(e.GATEWAY_UPSTREAM),origin=new URL(e.GATEWAY_PUBLIC_ORIGIN);
 if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw Error('GATEWAY_ORIGIN_INVALID');
 const mode=e.GATEWAY_MODE||'railway';if(!['railway','direct'].includes(mode))throw Error('GATEWAY_MODE_INVALID');
 if(mode==='railway'&&(e.GATEWAY_EDGE_ONLY!=='1'||!e.RAILWAY_PROJECT_ID||!e.RAILWAY_ENVIRONMENT_ID||!e.RAILWAY_SERVICE_ID))throw Error('GATEWAY_EDGE_CONTEXT_REQUIRED');
 const client=tls.Client({ca:e.GATEWAY_CA_FILE,cert:e.GATEWAY_CERT_FILE,key:e.GATEWAY_KEY_FILE,pin:e.GATEWAY_AUTHORITY_SPKI_SHA512});
 return {upstream,origin,mode,client,maxBytes:64*1024*1024};
}
function CreateServer(c,serverTls){
 const handler=(req,res)=>{
  const fail=(status,code)=>{req.resume();if(res.headersSent){res.destroy();return;}res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({ok:false,error:code}));};
  if(!['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].includes(req.method)||!/^\/(?!\/)/.test(req.url)||/[\x00-\x20\\]/.test(req.url))return fail(400,'GATEWAY_REQUEST_INVALID');
  const health=req.url==='/readyz'&&['GET','HEAD'].includes(req.method)&&req.headers.host==='healthcheck.railway.app';
  if(!health&&req.headers.host!==c.origin.host)return fail(421,'GATEWAY_HOST_INVALID');
  let ip=req.socket.remoteAddress,secure=!!req.socket.encrypted;
  if(c.mode==='railway'){
   ip=req.headers['x-real-ip'];secure=req.headers['x-forwarded-proto']==='https'&&req.headers['x-forwarded-host']===c.origin.host&&typeof req.headers['x-railway-request-id']==='string';
   if(health){ip=req.socket.remoteAddress;secure=true;}
  }
  if(!secure||typeof ip!=='string'||!net.isIP(ip))return fail(403,'GATEWAY_HTTPS_REQUIRED');
  if(req.headers['content-length']&&(!/^\d{1,9}$/.test(req.headers['content-length'])||Number(req.headers['content-length'])>c.maxBytes))return fail(413,'GATEWAY_BODY_LIMIT');
  const nominated=new Set(String(req.headers.connection||'').toLowerCase().split(',').map(x=>x.trim()));
  if([...nominated].some(k=>HEADERS.includes(k)||k==='host'))return fail(400,'GATEWAY_CONNECTION_HEADER_INVALID');
  const identity=c.upstream.hostname.replace(/^\[|\]$/g,'');
  const peerOptions={...c.client,servername:net.isIP(identity)?'':identity,checkServerIdentity:(_host,cert)=>c.client.checkServerIdentity(identity,cert)};
  const headers={host:c.origin.host,'x-game-client-ip':ip,'x-game-client-proto':'https'};
  for(const k of HEADERS)if(req.headers[k]!==undefined)headers[k]=req.headers[k];
  let size=0,done=false;const upstream=https.request(c.upstream,{...peerOptions,path:req.url,method:req.method,headers},r=>{
   const responseHeaders={};const hop=new Set([...HOP,...String(r.headers.connection||'').toLowerCase().split(',').map(x=>x.trim())]);
   for(const [k,v]of Object.entries(r.headers))if(!hop.has(k))responseHeaders[k]=v;
   res.writeHead(r.statusCode,responseHeaders);r.on('error',()=>res.destroy());r.pipe(res);
  });
  const timeout=setTimeout(()=>{upstream.destroy();fail(504,'GATEWAY_UPSTREAM_TIMEOUT');},180000);timeout.unref();
  const end=()=>{if(done)return;done=true;clearTimeout(timeout);};
  upstream.on('error',()=>{end();fail(502,'GATEWAY_UPSTREAM_UNAVAILABLE');});
  res.on('close',()=>{end();upstream.destroy();});req.on('aborted',()=>{end();upstream.destroy();});req.on('error',()=>upstream.destroy());
  req.on('data',b=>{size+=b.length;if(size>c.maxBytes){upstream.destroy();fail(413,'GATEWAY_BODY_LIMIT');}});req.pipe(upstream);
 };
 const server=c.mode==='direct'?https.createServer(serverTls,handler):http.createServer(handler);
 server.headersTimeout=15000;server.requestTimeout=180000;server.maxConnections=256;
 server.on('upgrade',(_req,s)=>s.destroy());server.on('connect',(_req,s)=>s.destroy());return server;
}
if(require.main===module){try{const listener=require('../../config/peace.runtime-environment').ReadListener('gateway');const c=Config(),e=process.env;
 const server=CreateServer(c,c.mode==='direct'?{cert:tls.Pem(e.GATEWAY_PUBLIC_CERT_FILE),key:tls.Pem(e.GATEWAY_PUBLIC_KEY_FILE),minVersion:'TLSv1.2'}:undefined);
 server.once('error',()=>{console.error('GATEWAY_LISTEN_FAILED');process.exitCode=1;});server.listen(listener.port,listener.host,()=>console.log('ADMIN_GATEWAY_READY: pinned mTLS authority; no local DB'));
 }catch(e){console.error(/^[A-Z_]+$/.test(e.message)?e.message:'GATEWAY_START_FAILED');process.exitCode=1;}}
module.exports={Config,CreateServer};
