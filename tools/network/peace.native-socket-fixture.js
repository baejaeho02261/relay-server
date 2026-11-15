'use strict';
const tls=require('node:tls');
function Cases(){return [
 {id:'ipv4-fragmented',host:'127.0.0.1',received:true,fragment:1,delay:2},
 {id:'dns-dual-stack-fallback',host:'localhost',received:true,fragment:1,delay:2},
 {id:'ipv6-fragmented',host:'::1',received:true,fragment:1,delay:2},
 {id:'cancel-before-dns',host:'127.0.0.1',connected:false,cancelAfter:0,received:false},
 {id:'cancel-during-receive',host:'127.0.0.1',stall:true,cancelAfter:300,received:false},
 {id:'close-during-receive',host:'127.0.0.1',stall:true,closeAfter:100,received:false},
 {id:'whole-deadline-fragments',host:'127.0.0.1',fragment:1,delay:100,received:false},
 {id:'oversized-line',host:'127.0.0.1',oversized:true,received:false},
 {id:'wrong-pin-ipv6',host:'::1',wrongPin:true,connected:false,received:false},
 {id:'wrong-pin-ipv4',host:'127.0.0.1',wrongPin:true,connected:false,received:false},
 ].map(x=>({budget:1400,connected:true,cancelAfter:-1,closeAfter:-1,...x}));}
async function Serve(row,identity,nonce){
 const sockets=new Set(),timers=new Set(),wire={connections:0,tlsAccepted:0,requestAccepted:false,fragments:0};
 const body=Buffer.from(row.oversized?'x'.repeat(1025)+'\n':JSON.stringify({value:'한글',nonce})+'\n');
 const server=tls.createServer({...identity,handshakeTimeout:2000},socket=>{
  wire.tlsAccepted++;socket.setNoDelay(true);let request=Buffer.alloc(0),handled=false;
  socket.on('data',chunk=>{if(handled)return;request=Buffer.concat([request,chunk]);if(request.length>128){socket.destroy();return;}if(!request.includes(10))return;
   handled=true;if(request.toString('utf8')!==JSON.stringify({nonce})+'\n'){socket.destroy();return;}
   wire.requestAccepted=true;if(row.stall)return;let at=0;
   const send=()=>{if(socket.destroyed)return;if(at>=body.length)return;const size=row.fragment||body.length;socket.write(body.subarray(at,at+size));at+=size;wire.fragments++;
    if(at<body.length){const timer=setTimeout(()=>{timers.delete(timer);send();},row.delay||0);timers.add(timer);}};send();
  });
 });
 server.on('tlsClientError',()=>{});server.on('connection',socket=>{wire.connections++;sockets.add(socket);socket.on('error',()=>{});socket.once('close',()=>sockets.delete(socket));});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen({host:row.host==='::1'?'::1':'127.0.0.1',port:0,ipv6Only:true},resolve);});
 return {port:server.address().port,wire,async close(){for(const timer of timers)clearTimeout(timer);for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
}
function Evaluate(row,observed,wire,nonce){
 if(!observed||observed.version!==1||observed.nativeSocketExecuted!==true||observed.caseId!==row.id||observed.nonce!==nonce)throw Error('SOCKET_RESULT_BINDING');
 if(observed.connected!==row.connected||observed.received!==row.received)throw Error('SOCKET_RESULT_BOUNDARY');
 if(!Number.isSafeInteger(observed.elapsedMs)||observed.elapsedMs<0||observed.elapsedMs>row.budget+1000)throw Error('SOCKET_REQUEST_DEADLINE');
 if(!row.received&&observed.closed!==true)throw Error('SOCKET_FAILED_TRANSPORT_OPEN');
 if(row.cancelAfter===0){if(wire.connections!==0)throw Error('SOCKET_CANCELLED_PHASE_STARTED');}
 else if(row.connected){if(!wire.requestAccepted||observed.sent!==true)throw Error('SOCKET_FIXTURE_NOT_EXERCISED');}
 if(row.received){let value;try{value=JSON.parse(observed.line);}catch{throw Error('SOCKET_RESPONSE_INVALID');}if(value.value!=='한글'||value.nonce!==nonce||wire.fragments<2)throw Error('SOCKET_FRAGMENT_BINDING');}
 if(row.wrongPin&&wire.requestAccepted)throw Error('SOCKET_PIN_BYPASSED');
 return {id:row.id,outcome:'PASS',observed,wire:{...wire}};
}
module.exports={Cases,Serve,Evaluate};
