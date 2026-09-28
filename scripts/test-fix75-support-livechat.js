'use strict';
const assert=require('node:assert/strict'),net=require('node:net');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'relay-fix75-support-'));
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';
require('../core/utils').EnsureDirs();
const state=require('../core/state'),db=require('../storage/database');
const closed=[],peers=[];
const server=net.createServer(socket=>{closed.push(new Promise(resolve=>socket.once('close',resolve)));require('../core/connection').CreateConnection(socket);});
function connect(){return new Promise((resolve,reject)=>{
 const socket=net.createConnection({port:server.address().port,host:'127.0.0.1'}),lines=[],waiters=[];let buffer='';
 const peer={socket,send:line=>socket.write(line+'\n'),wait(prefix){const i=lines.findIndex(x=>x.startsWith(prefix));if(i>=0)return Promise.resolve(lines.splice(i,1)[0]);return new Promise((res,rej)=>{const item={prefix,res,rej,timer:setTimeout(()=>rej(Error('Timeout: '+prefix)),4000)};waiters.push(item);});},close(){for(const w of waiters){clearTimeout(w.timer);w.rej(Error('Connection closed'));}waiters.length=0;socket.destroy();}};
 peers.push(peer);socket.on('data',data=>{buffer+=data;let i;while((i=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,i).trim();buffer=buffer.slice(i+1);if(line.startsWith('PING|')){peer.send(line.replace('PING|','PONG|'));continue;}const n=waiters.findIndex(x=>line.startsWith(x.prefix));if(n<0)lines.push(line);else{const w=waiters.splice(n,1)[0];clearTimeout(w.timer);w.res(line);}}});
 socket.once('error',reject);socket.once('connect',()=>resolve(peer));
});}
async function login(device='LIVE-SUPPORT-'+peers.length){
 const p=await connect();p.send('CONNECT|2|7.1.0|'+device);
 const id=(await p.wait('CONNECTED|')).split('|')[1];p.c=state.clients.get(id);
 Object.assign(p.c,{permissionsGranted:true,deviceAuthVerified:true,biometricVerified:true,licenseAuthorized:true,deviceAuthChallengeId:'AUTH-FIX75-'+id});
 return p;
}
const support=require('../services/supportCenter');
async function supportFrame(peer,command){const line=await peer.wait(command+'|');return JSON.parse(Buffer.from(line.split('|')[1],'base64').toString());}
async function api(role,method,url,body){
 const {Readable}=require('node:stream'),req=Readable.from(body?[Buffer.from(JSON.stringify(body))]:[]);
 Object.assign(req,{method,url,headers:{},socket:{remoteAddress:'127.0.0.1'}});
 const response={writeHead(status){this.status=status;},end(text){this.body=JSON.parse(text);}};
 await require('../web/webApi').HandleApiRequest(req,response,{role,ip:'127.0.0.1'});return response;
}
let regressionCompleted=false;process.once('exit',()=>{if(!regressionCompleted){console.error('TCP regression ended before completing assertions');process.exitCode=1;}});
(async()=>{try{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let a=await login('LIVE-SUPPORT-OWNER');const b=await login('LIVE-SUPPORT-OTHER');
 // Removed operations cannot create a conversation, expose content or mutate it.
 for(const retired of ['SUPPORT_HELP','SUPPORT_BOT_OPEN']){
  a.send(retired+'|'+a.c.clientId);assert.equal(await a.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|INVALID_MESSAGE');
 }
 assert.equal(state.supportThreads.size,0);
 a.send('SUPPORT_SYNC|'+b.c.clientId+'||0');assert.equal(await a.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|CLIENT_NOT_OWNER');
 a.send('SUPPORT_SYNC|'+a.c.clientId+'||0');let info=await supportFrame(a,'SUPPORT_INFO');const id=info.roomId;
 assert.equal(info.mode,'HUMAN');assert.equal(info.adminOnline,false);
 await supportFrame(a,'SUPPORT_RESET');assert.equal((await supportFrame(a,'SUPPORT_PAGE')).lastSeq,0);
 assert.equal(support.Read(id).total,0,'opening never fabricates a counselor message');
 const send=(rid,text,revision=info.revision)=>a.send('SUPPORT_SEND_V2|'+rid+'|'+revision+'|'+Buffer.from(text).toString('base64'));
 send('LIVE_QUESTION_01','한\n직접 문의 😀 <script>');const mine=await supportFrame(a,'SUPPORT_MESSAGE');info=await supportFrame(a,'SUPPORT_INFO');
 assert.equal(mine.role,'CLIENT');assert.equal(mine.seq,1);assert.equal(mine.text,'한\n직접 문의 😀 <script>');
 assert.equal(support.Read(id).total,1);assert.equal(support.List().find(x=>x.clientId===id).unreadAdmin,1);
 send('LIVE_QUESTION_01',mine.text);assert.deepEqual(await supportFrame(a,'SUPPORT_MESSAGE'),mine);await supportFrame(a,'SUPPORT_INFO');
 assert.equal(support.Read(id).total,1,'a retry creates no duplicate or automated response');
 send('LIVE_QUESTION_01','다른 본문');assert.equal(await a.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|MESSAGE_ID_CONFLICT');
 const save=db.SaveDatabase;a.c.lastSupportSendAt=0;const before=JSON.stringify(state.supportThreads.get(id));
 try{db.SaveDatabase=()=>false;send('LIVE_ROLLBACK_01','재전송 문의');assert.equal(await a.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|STORAGE_SAVE_FAILED');}finally{db.SaveDatabase=save;}
 assert.equal(JSON.stringify(state.supportThreads.get(id)),before);
 send('LIVE_ROLLBACK_01','재전송 문의');await supportFrame(a,'SUPPORT_MESSAGE');await supportFrame(a,'SUPPORT_INFO');assert.equal(support.Read(id).total,2);
 for(const role of ['viewer','operator'])assert.equal((await api(role,'POST','/api/support/knowledge',{})).status,403);
 for(const endpoint of ['/api/support/knowledge','/api/support/knowledge/delete'])assert.equal((await api('admin','POST',endpoint,{})).status,404);
 const listing=await api('admin','GET','/api/support');assert.equal(listing.status,200);assert.equal('knowledge' in listing.body,false);
 assert.equal(support.Availability({role:'admin',id:'LIVE_STAFF'},'ONLINE').ok,true);assert.equal((await supportFrame(a,'SUPPORT_INFO')).adminOnline,true);
 assert.equal(support.Reply(id,'실제 상담원 답변','LIVE_ADMIN_REPLY',info.revision).ok,true);await supportFrame(a,'SUPPORT_INFO');const reply=await supportFrame(a,'SUPPORT_MESSAGE');assert.equal(reply.role,'ADMIN');
 const cursor=reply.seq,epoch=info.epoch,ownerClient=a.c.clientId;
 a.close();await closed[0];assert.equal(support.Reply(id,'접속하지 않아도 보관된 답변','LIVE_OFFLINE_REPLY',info.revision).ok,true);
 a=await login('LIVE-SUPPORT-OWNER');assert.equal(a.c.clientId,ownerClient);
 a.send('SUPPORT_SYNC|'+a.c.clientId+'|'+epoch+'|'+cursor);info=await supportFrame(a,'SUPPORT_INFO');const restored=await supportFrame(a,'SUPPORT_MESSAGE');
 assert.equal(restored.text,'접속하지 않아도 보관된 답변');assert.equal(restored.role,'ADMIN');assert.equal((await supportFrame(a,'SUPPORT_PAGE')).lastSeq,restored.seq);
 b.send('SUPPORT_SYNC|'+a.c.clientId+'|'+epoch+'|0');assert.equal(await b.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|CLIENT_NOT_OWNER');
 // Old automatic history is retained as historical data, with all new work human.
 const snapshot=db.BuildDatabaseObject(),raw=snapshot.supportThreads[id];
 const historic={seq:raw.nextSeq++,id:'HISTORIC_AUTO_01',role:'BOT',text:'이전에 저장된 자동 안내',at:Date.now(),epoch:raw.epoch};
 raw.messages.push(historic);raw.mode='BOT';raw.botStarted=true;snapshot.supportSettings.knowledge={items:[{id:'OLD',answer:'retired'}]};
 assert.equal(db.ImportDatabaseObject(snapshot),true);assert.equal(support.Read(id).mode,'HUMAN');assert.ok(support.Read(id).messages.some(x=>x.id===historic.id));assert.equal('knowledge' in state.supportSettings,false);
 a.c.lastSupportSendAt=0;send('LIVE_AFTER_IMPORT','새로운 문의');assert.equal((await supportFrame(a,'SUPPORT_MESSAGE')).role,'CLIENT');info=await supportFrame(a,'SUPPORT_INFO');
 assert.equal(support.Read(id).messages.at(-1).id,'LIVE_AFTER_IMPORT');assert.equal(support.Read(id).total,6);
 support.Change(id,'close',info.revision);assert.equal((await supportFrame(a,'SUPPORT_MESSAGE')).role,'SYSTEM');await supportFrame(a,'SUPPORT_INFO');
 a.c.lastSupportSendAt=0;send('LIVE_REOPEN_0001','이어지는 문의');assert.equal((await supportFrame(a,'SUPPORT_MESSAGE')).role,'CLIENT');info=await supportFrame(a,'SUPPORT_INFO');assert.equal(info.status,'OPEN');assert.equal(info.mode,'HUMAN');
 const count=support.Read(id).total;a.c.deviceAuthVerified=false;send('LIVE_NO_AUTH_01','권한 없음');assert.equal(await a.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|AUTH_REQUIRED');assert.equal(support.Read(id).total,count);a.c.deviceAuthVerified=true;
 support.Change(id,'delete',info.revision);await supportFrame(a,'SUPPORT_RESET');info=await supportFrame(a,'SUPPORT_INFO');
 a.c.lastSupportSendAt=0;send('LIVE_STALE_0001','이전 요청',info.revision-1);assert.equal(await a.wait('SUPPORT_ERROR|'),'SUPPORT_ERROR|HISTORY_CHANGED');assert.equal(support.Read(id).total,0);
 console.log('FIX75 LIVE SUPPORT PASS: real TCP direct entry, no fabricated replies, staff queue, retries/rollback, live/offline replies, reconnect cursors, history migration, retired APIs and authorization isolation');
 regressionCompleted=true;
}catch(e){console.error(e);process.exitCode=1;}finally{for(const p of peers)p.close();await Promise.all(closed);await new Promise(resolve=>server.close(resolve));fs.rmSync(temp,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
