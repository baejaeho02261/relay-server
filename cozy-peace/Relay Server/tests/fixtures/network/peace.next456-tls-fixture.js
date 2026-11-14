'use strict';
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
function Certificates(dir){
 const run=(...a)=>cp.execFileSync('openssl',a,{cwd:dir,stdio:'pipe'});
 run('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Next456 Test CA');
 function leaf(name,usage){
  run('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
  fs.writeFileSync(path.join(dir,name+'.ext'),`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${usage}\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n`);
  run('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','1','-extfile',name+'.ext');
  return {cert:path.join(dir,name+'.pem'),key:path.join(dir,name+'.key')};
 }
 const server=leaf('server','serverAuth'),client=leaf('client','clientAuth'),stranger=leaf('stranger','clientAuth');
 return {ca:path.join(dir,'ca.pem'),server,client,stranger};
}
module.exports={Certificates};
