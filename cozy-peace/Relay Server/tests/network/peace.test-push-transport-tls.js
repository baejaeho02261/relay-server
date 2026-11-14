'use strict';
// Real loopback HTTPS, certificate trust and hostname checking. Test-only CA,
// route and ciphertext fixture; never a public push service or production key.
const test=require('node:test'),assert=require('node:assert/strict'),https=require('node:https'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const {Isolated}=require("../fixtures/protocol/peace.completion-6-10-fixture");
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'push-tls-test-'));
function Certificate(name){const prefix=path.join(dir,name.replace(/\./g,'_'));child.execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',prefix+'.key','-out',prefix+'.crt','-subj','/CN='+name,'-addext','subjectAltName=DNS:'+name],{stdio:'ignore'});return {key:fs.readFileSync(prefix+'.key'),cert:fs.readFileSync(prefix+'.crt')};}
let good,bad;
test.before(()=>{good=Certificate('fcm.googleapis.com');bad=Certificate('wrong.invalid');});
test.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
async function Run(identity,status=201){
 let requests=0,received='';const server=https.createServer(identity,(req,res)=>{requests++;assert.equal(req.headers.host,'fcm.googleapis.com');assert.equal(req.socket.servername,'fcm.googleapis.com');req.on('data',b=>received+=b.toString());req.on('end',()=>{res.writeHead(status,{...(status===302?{Location:'https://127.0.0.1/private'}:{})});res.end('OK');});});
 server.on('tlsClientError',()=>{});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const target={endpoint:'https://fcm.googleapis.com/wp/test',hostname:'fcm.googleapis.com',path:'/wp/test',address:'127.0.0.1',family:4};
 const productionDestination=require("../../services/network/peace.push-destination");
 const transport=Isolated("services/network/peace.push-transport.js",[],{
  './peace.push-destination':{...productionDestination,ResolveEndpoint:async()=>target,PeerMatches:(peer,t)=>peer===t.address},
  'node:https':{request(options,cb){assert.equal(options.rejectUnauthorized,true);assert.equal(options.agent,false);return https.request({...options,port:server.address().port,ca:identity.cert},cb);}}
 });
 const webPush={generateRequestDetails:()=>({endpoint:target.endpoint,method:'POST',headers:{'Content-Length':Buffer.byteLength('CIPHERTEXT_TEST!')},body:Buffer.from('CIPHERTEXT_TEST!')})};
 try{return {value:await transport.Send(webPush,{endpoint:target.endpoint},'test'),requests,received};}
 catch(error){error.requests=requests;throw error;}
 finally{await new Promise(resolve=>server.close(resolve));}
}
test('real TLS valid original hostname sends body only after handshake',async()=>{const result=await Run(good);assert.equal(result.value.statusCode,201);assert.equal(result.requests,1);assert.equal(result.received,'CIPHERTEXT_TEST!');});
test('trusted certificate with wrong original hostname sends no HTTP request',async()=>{await assert.rejects(Run(bad),e=>e.message==='PUSH_NETWORK_FAILED'&&e.requests===0);});
test('real HTTPS redirect does not cause a second or internal request',async()=>{await assert.rejects(Run(good,302),e=>e.message==='PUSH_REDIRECT_BLOCKED'&&e.requests===1);});
