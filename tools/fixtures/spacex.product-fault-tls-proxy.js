'use strict';
// Only the fixture owns this loopback listener and its upstream. It never
// decrypts, logs, or fabricates a product message. The caller must configure
// its isolated upstream server for TLS 1.2, then Arm only after actual transfer.
const net=require('node:net');
async function Start(upstreamPort,onEvent){
 if(!Number.isInteger(upstreamPort)||upstreamPort<1||upstreamPort>65535||typeof onEvent!=='function')throw Error('PRODUCT_TLS_PROXY_ARGUMENTS');
 const sockets=new Set();let armed=false,used=false,closed=false,nextConnection=0;
 const emit=event=>onEvent({version:1,...event});
 function track(socket){sockets.add(socket);socket.on('error',()=>{});socket.once('close',()=>sockets.delete(socket));return socket;}
 const server=net.createServer(client=>{
  track(client);const connection=++nextConnection,upstream=track(net.connect(upstreamPort,'127.0.0.1'));let pending=Buffer.alloc(0);
  client.pipe(upstream);
  upstream.on('data',chunk=>{
   pending=Buffer.concat([pending,chunk]);
   if(pending.length>128*1024){emit({event:'tls-proxy-buffer-rejected',connection});client.destroy();upstream.destroy();return;}
   while(pending.length>=5){
    const size=5+pending.readUInt16BE(3);if(pending.length<size)break;
    const record=Buffer.from(pending.subarray(0,size));pending=pending.subarray(size);
    if(armed&&!used&&record[0]===23){
     // TLS 1.2 application data always carries authenticated encrypted bytes.
     // Flip one byte after the complete record arrived, preserving all lengths.
     if(record[1]!==3||record[2]!==3||record.length<22){emit({event:'tls-proxy-record-rejected',connection});client.destroy();upstream.destroy();return;}
     used=true;record[record.length-1]^=1;
     client.write(record,error=>{if(!error)emit({event:'tls-record-corrupted',connection,recordType:23,recordVersion:'TLS1.2',bytes:record.length,mutationCount:1});});
    }else client.write(record);
   }
  });
  upstream.on('end',()=>{client.end(pending);pending=Buffer.alloc(0);});
  upstream.on('error',()=>client.destroy());
  client.once('close',()=>{upstream.destroy();pending.fill(0);pending=Buffer.alloc(0);});
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 return {port:server.address().port,
  Arm(){if(closed||armed||used)throw Error('PRODUCT_TLS_PROXY_ARM_INVALID');armed=true;emit({event:'tls-proxy-armed'});},
  async Close(){if(closed)return;closed=true;for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));},
 };
}
module.exports={Start};
